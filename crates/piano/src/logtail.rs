//! `piano log tail`: the end of the access log file, filtered, optionally followed.
//!
//! Reads the file rather than asking the daemon: the file holds the whole history and
//! stays readable when the daemon is down.

use crate::render::Color;
use serde_json::Value;
use std::collections::VecDeque;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Seek, Write};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::Duration;

/// How often a followed file is checked for new lines and for having been rotated.
const POLL: Duration = Duration::from_millis(500);
/// Paths longer than this are cut in text output; `--json` keeps them whole.
const MAX_PATH_CHARS: usize = 120;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StatusMatch {
    /// `5xx`: the hundreds digit.
    Class(u64),
    Exact(u64),
}

/// Which lines to show; every given condition must hold.
#[derive(Debug, Default)]
pub struct Filter {
    site: Option<String>,
    status: Option<StatusMatch>,
    class: Option<String>,
}

impl Filter {
    /// `status` is a class such as `5xx` or an exact code such as `404`.
    pub fn new(
        site: Option<String>,
        status: Option<&str>,
        class: Option<String>,
    ) -> Result<Self, String> {
        let status = status
            .map(|s| {
                let bad = || {
                    format!("--status {s:?}: expected a code such as 404 or a class such as 5xx")
                };
                match s.as_bytes() {
                    [d @ b'1'..=b'5', b'x' | b'X', b'x' | b'X'] => {
                        Ok(StatusMatch::Class(u64::from(d - b'0')))
                    }
                    _ => s.parse().map(StatusMatch::Exact).map_err(|_| bad()),
                }
            })
            .transpose()?;
        Ok(Self {
            site,
            status,
            class,
        })
    }

    fn matches(&self, v: &Value) -> bool {
        let field = |k: &str| v.get(k).and_then(Value::as_str);
        if let Some(site) = &self.site
            && field("site") != Some(site.as_str())
        {
            return false;
        }
        if let Some(class) = &self.class
            && field("class") != Some(class.as_str())
        {
            return false;
        }
        match (self.status, v.get("status").and_then(Value::as_u64)) {
            (None, _) => true,
            (Some(StatusMatch::Class(c)), Some(s)) => s / 100 == c,
            (Some(StatusMatch::Exact(e)), Some(s)) => s == e,
            (Some(_), None) => false,
        }
    }
}

pub struct Output {
    pub json: bool,
    pub color: Color,
}

impl Output {
    fn line(&self, raw: &str, v: &Value) -> String {
        if self.json {
            raw.to_owned()
        } else {
            human(v, self.color)
        }
    }
}

fn clip(s: &str, max: usize) -> String {
    match s.char_indices().nth(max) {
        Some((i, _)) => format!("{}…", &s[..i]),
        None => s.to_owned(),
    }
}

/// One request as a line of text: time, site, status, method, path, duration, client,
/// and how it ended unless normally.
fn human(v: &Value, color: Color) -> String {
    let s = |k: &str| v.get(k).and_then(Value::as_str);
    let ts = s("ts")
        .map(|t| t.get(5..19).unwrap_or(t).replacen('T', " ", 1))
        .unwrap_or_default();
    let status = v.get("status").and_then(Value::as_u64);
    let status_text = status.map_or_else(|| "-".to_owned(), |n| n.to_string());
    let status_text = match status {
        Some(500..) => color.red(&status_text),
        Some(400..500) => color.yellow(&status_text),
        _ => status_text,
    };
    let dur = v
        .get("dur_ms")
        .and_then(Value::as_u64)
        .map_or_else(String::new, |d| format!(" {d}ms"));
    let mut line = format!(
        "{ts} {:<6} {status_text:>3} {} {}{dur} {}",
        s("site").unwrap_or("-"),
        s("method").unwrap_or("-"),
        clip(s("path").unwrap_or("-"), MAX_PATH_CHARS),
        s("client").unwrap_or("-"),
    );
    if let Some(end) = s("end").filter(|e| *e != "ok") {
        line.push(' ');
        line.push_str(&color.yellow(&format!("end={end}")));
    }
    if let Some(err) = s("err") {
        line.push_str(&format!(" err={err}"));
    }
    line
}

/// Reads complete lines from `reader`, passing each to `each`. A line still being
/// written stays in `pending` for the next call.
fn drain(
    reader: &mut impl BufRead,
    pending: &mut String,
    mut each: impl FnMut(&str) -> io::Result<()>,
) -> io::Result<()> {
    loop {
        if reader.read_line(pending)? == 0 {
            return Ok(());
        }
        if pending.ends_with('\n') {
            each(pending.trim_end())?;
            pending.clear();
        }
    }
}

/// Prints the last `n` lines of `path` that pass `filter`, then, with `follow`,
/// every new one until interrupted, across log rotation.
pub fn tail(path: &Path, n: usize, follow: bool, filter: &Filter, out: &Output) -> io::Result<()> {
    let stdout = io::stdout();
    let mut w = stdout.lock();
    let mut file = File::open(path)?;
    let mut reader = BufReader::new(file.try_clone()?);
    let mut pending = String::new();
    let mut last: VecDeque<String> = VecDeque::with_capacity(n.min(4096));
    drain(&mut reader, &mut pending, |raw| {
        if let Ok(v) = serde_json::from_str::<Value>(raw)
            && filter.matches(&v)
        {
            if last.len() == n {
                last.pop_front();
            }
            if n > 0 {
                last.push_back(out.line(raw, &v));
            }
        }
        Ok(())
    })?;
    for l in &last {
        writeln!(w, "{l}")?;
    }
    w.flush()?;
    if !follow {
        return Ok(());
    }
    let mut emit = |raw: &str| -> io::Result<()> {
        if let Ok(v) = serde_json::from_str::<Value>(raw)
            && filter.matches(&v)
        {
            writeln!(w, "{}", out.line(raw, &v))?;
            w.flush()?;
        }
        Ok(())
    };
    loop {
        std::thread::sleep(POLL);
        drain(&mut reader, &mut pending, &mut emit)?;
        // logrotate moved the file away and the daemon started a new one, or the file
        // was truncated in place.
        let current = file.metadata()?;
        let replaced = match std::fs::metadata(path) {
            Ok(m) => m.ino() != current.ino() || m.dev() != current.dev(),
            Err(_) => false,
        };
        let pos = reader.stream_position()?;
        if replaced || current.len() < pos {
            drain(&mut reader, &mut pending, &mut emit)?;
            pending.clear();
            file = File::open(path)?;
            reader = BufReader::new(file.try_clone()?);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(site: &str, status: Option<u64>, class: &str) -> Value {
        serde_json::json!({"site": site, "status": status, "class": class})
    }

    #[test]
    fn filters() {
        let f = Filter::new(Some("a".into()), Some("5xx"), None).unwrap();
        assert!(f.matches(&line("a", Some(502), "api")));
        assert!(!f.matches(&line("a", Some(404), "api")));
        assert!(!f.matches(&line("b", Some(502), "api")));
        assert!(!f.matches(&line("a", None, "api")));
        let f = Filter::new(None, Some("404"), Some("image".into())).unwrap();
        assert!(f.matches(&line("x", Some(404), "image")));
        assert!(!f.matches(&line("x", Some(404), "media")));
        assert!(Filter::new(None, Some("6xx"), None).is_err());
        assert!(Filter::new(None, Some("bad"), None).is_err());
    }

    #[test]
    fn human_line() {
        let v = serde_json::json!({
            "ts": "2026-11-20T08:01:02.345Z", "site": "uhd", "status": 502,
            "method": "GET", "path": "/emby/Videos/1/stream", "dur_ms": 12,
            "client": "192.0.2.7", "end": "redirect_refused", "err": "no"
        });
        assert_eq!(
            human(&v, crate::render::color(true)),
            "11-20 08:01:02 uhd    502 GET /emby/Videos/1/stream 12ms 192.0.2.7 end=redirect_refused err=no"
        );
        assert_eq!(clip("abcdef", 3), "abc…");
    }

    #[test]
    fn drain_keeps_a_partial_line() {
        let mut pending = String::new();
        let mut seen = Vec::new();
        drain(&mut "a\nb".as_bytes(), &mut pending, |l| {
            seen.push(l.to_owned());
            Ok(())
        })
        .unwrap();
        assert_eq!(seen, ["a"]);
        assert_eq!(pending, "b");
        drain(&mut "c\n".as_bytes(), &mut pending, |l| {
            seen.push(l.to_owned());
            Ok(())
        })
        .unwrap();
        assert_eq!(seen, ["a", "bc"]);
    }
}
