//! `piano log tail`: the end of the access log file, filtered, optionally followed.
//!
//! Reads the file rather than asking the daemon: the file holds the whole history and
//! stays readable when the daemon is down.

use crate::render::{Color, local_time};
use piano_proxy::route::RouteClass;
use serde_json::Value;
use std::borrow::Cow;
use std::collections::VecDeque;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Seek, SeekFrom, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
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
            escaped(raw)
        } else {
            human(v, self.color)
        }
    }
}

/// A warning when `class` is no route class this version logs; lines of another
/// version may still carry it.
pub fn unknown_class(class: &str) -> Option<String> {
    if RouteClass::ALL.iter().any(|k| k.as_str() == class) {
        return None;
    }
    let all: Vec<&str> = RouteClass::ALL.iter().map(|k| k.as_str()).collect();
    Some(format!(
        "warning: --class {class:?} is none of {}",
        all.join(", ")
    ))
}

/// Characters a terminal acts on or that reorder the text around them; logged fields
/// come from clients and upstreams.
fn unsafe_char(c: char) -> bool {
    c.is_control()
        || matches!(c, '\u{61c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

/// `s` with [`unsafe_char`]s replaced, for text output.
fn printable(s: &str) -> Cow<'_, str> {
    if s.contains(unsafe_char) {
        Cow::Owned(
            s.chars()
                .map(|c| if unsafe_char(c) { '\u{fffd}' } else { c })
                .collect(),
        )
    } else {
        Cow::Borrowed(s)
    }
}

/// A logged JSON line with [`unsafe_char`]s written as escapes: the same JSON value, as
/// the log writer puts such characters only inside strings, and nothing a terminal
/// acts on.
fn escaped(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for c in raw.chars() {
        if unsafe_char(c) {
            out.push_str(&format!("\\u{:04x}", u32::from(c)));
        } else {
            out.push(c);
        }
    }
    out
}

fn clip(s: &str, max: usize) -> String {
    match s.char_indices().nth(max) {
        Some((i, _)) => format!("{}…", &s[..i]),
        None => s.to_owned(),
    }
}

/// One request as a line of text: local time, site, status, method, path, duration,
/// client, and how it ended unless normally.
fn human(v: &Value, color: Color) -> String {
    let s = |k: &str| v.get(k).and_then(Value::as_str).map(printable);
    let ts = s("ts")
        .map(|t| {
            local_time(&t, "%m-%d %H:%M:%S")
                .unwrap_or_else(|| t.get(5..19).unwrap_or(&t).replacen('T', " ", 1))
        })
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
        s("site").as_deref().unwrap_or("-"),
        s("method").as_deref().unwrap_or("-"),
        clip(s("path").as_deref().unwrap_or("-"), MAX_PATH_CHARS),
        s("client").as_deref().unwrap_or("-"),
    );
    if let Some(end) = s("end").filter(|e| e != "ok") {
        line.push(' ');
        line.push_str(&color.yellow(&format!("end={end}")));
    }
    if let Some(err) = s("err") {
        line.push_str(&format!(" err={err}"));
    }
    line
}

/// Reads complete lines from `reader`, passing each to `each`. A line still being
/// written stays in `pending` for the next call. Lines are read as bytes and a line
/// that is not UTF-8 is skipped like any other line that is no log line: a write cut
/// short by a full disk leaves one, and a read can catch a write half-way through a
/// character.
fn drain(
    reader: &mut impl BufRead,
    pending: &mut Vec<u8>,
    mut each: impl FnMut(&str) -> io::Result<()>,
) -> io::Result<()> {
    loop {
        if reader.read_until(b'\n', pending)? == 0 {
            return Ok(());
        }
        if pending.ends_with(b"\n") {
            if let Ok(line) = std::str::from_utf8(pending) {
                each(line.trim_end())?;
            }
            pending.clear();
        }
    }
}

/// Reads a log file as it grows, across rotation: when the path names another file or
/// the file shrinks, the rest of the old one is read and the new one opened.
pub struct Follower {
    path: PathBuf,
    file: File,
    reader: BufReader<File>,
    pending: Vec<u8>,
}

impl Follower {
    /// Opens `path` at its start, or with `last` at about that many bytes before its
    /// end, from the next whole line.
    pub fn open(path: &Path, last: Option<u64>) -> io::Result<Self> {
        let file = File::open(path)?;
        let mut reader = BufReader::new(file.try_clone()?);
        let mut pending = Vec::new();
        if let Some(n) = last {
            let len = file.metadata()?.len();
            if len > n {
                // From the byte before, so that a line starting right at `len - n`
                // is kept: what is read up to the next newline ends the line before.
                reader.seek(SeekFrom::Start(len - n - 1))?;
                reader.read_until(b'\n', &mut pending)?;
                pending.clear();
            }
        }
        Ok(Self {
            path: path.to_owned(),
            file,
            reader,
            pending,
        })
    }

    /// Passes each complete line written since the last call to `each`.
    pub fn read(&mut self, each: impl FnMut(&str) -> io::Result<()>) -> io::Result<()> {
        drain(&mut self.reader, &mut self.pending, each)
    }

    /// Like [`Self::read`], then switches to a new file if the log was rotated or
    /// truncated.
    pub fn poll(&mut self, mut each: impl FnMut(&str) -> io::Result<()>) -> io::Result<()> {
        self.read(&mut each)?;
        let current = self.file.metadata()?;
        let replaced = match std::fs::metadata(&self.path) {
            Ok(m) => m.ino() != current.ino() || m.dev() != current.dev(),
            Err(_) => false,
        };
        let pos = self.reader.stream_position()?;
        if replaced || current.len() < pos {
            self.read(&mut each)?;
            self.pending.clear();
            self.file = File::open(&self.path)?;
            self.reader = BufReader::new(self.file.try_clone()?);
        }
        Ok(())
    }
}

/// The last `n` lines `log` has now that pass `filter`, as `out` writes them.
fn last(
    log: &mut Follower,
    n: usize,
    filter: &Filter,
    out: &Output,
) -> io::Result<VecDeque<String>> {
    let mut last = VecDeque::with_capacity(n.min(4096));
    if n == 0 {
        log.read(|_| Ok(()))?;
        return Ok(last);
    }
    log.read(|raw| {
        if let Ok(v) = serde_json::from_str::<Value>(raw)
            && filter.matches(&v)
        {
            if last.len() == n {
                last.pop_front();
            }
            last.push_back(out.line(raw, &v));
        }
        Ok(())
    })?;
    Ok(last)
}

/// Prints the last `n` lines of `path` that pass `filter`, then, with `follow`,
/// every new one until interrupted, across log rotation.
pub fn tail(path: &Path, n: usize, follow: bool, filter: &Filter, out: &Output) -> io::Result<()> {
    let stdout = io::stdout();
    let mut w = stdout.lock();
    let mut log = Follower::open(path, None)?;
    for l in &last(&mut log, n, filter, out)? {
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
        log.poll(&mut emit)?;
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
        for class in RouteClass::ALL {
            assert_eq!(unknown_class(class.as_str()), None);
        }
        let e = unknown_class("vidoe").unwrap();
        assert!(e.contains("media, subtitle"), "{e}");
    }

    #[test]
    fn human_line() {
        let v = serde_json::json!({
            "ts": "2026-11-20T08:01:02.345Z", "site": "uhd", "status": 502,
            "method": "GET", "path": "/emby/Videos/1/stream", "dur_ms": 12,
            "client": "192.0.2.7", "end": "redirect_refused", "err": "no"
        });
        let ts = local_time("2026-11-20T08:01:02.345Z", "%m-%d %H:%M:%S").unwrap();
        assert_eq!(
            human(&v, crate::render::color(true)),
            format!(
                "{ts} uhd    502 GET /emby/Videos/1/stream 12ms 192.0.2.7 end=redirect_refused err=no"
            )
        );
        assert_eq!(clip("abcdef", 3), "abc…");
    }

    #[test]
    fn control_characters_do_not_reach_the_terminal() {
        let v = serde_json::json!({
            "path": "/a\u{9b}31m\u{1b}[2J", "err": "x\u{1b}]0;t\u{7}", "end": "upstream_timeout"
        });
        let line = human(&v, crate::render::color(true));
        assert!(!line.contains(char::is_control), "{line:?}");
        assert!(line.contains("/a\u{fffd}31m\u{fffd}[2J"), "{line:?}");
        assert_eq!(printable("ok é"), "ok é");
        assert_eq!(printable("/x\u{202e}gnp.exe"), "/x\u{fffd}gnp.exe");
        let raw = "{\"path\":\"/a\u{9b}2J\u{7f}\u{202e}\"}";
        let json = escaped(raw);
        let bs = "\\";
        assert_eq!(
            json,
            format!("{{\"path\":\"/a{bs}u009b2J{bs}u007f{bs}u202e\"}}")
        );
        let back: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(back, serde_json::from_str::<Value>(raw).unwrap());
    }

    #[test]
    fn a_follower_can_start_near_the_end_and_follows_rotation() {
        let dir = std::env::temp_dir().join(format!("piano-follow-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("access.log");
        std::fs::write(
            &path,
            "first line
second
third
",
        )
        .unwrap();
        let mut f = Follower::open(&path, Some(10)).unwrap();
        let mut seen = Vec::new();
        f.poll(|l| {
            seen.push(l.to_owned());
            Ok(())
        })
        .unwrap();
        assert_eq!(seen, ["third"]);
        std::fs::write(
            dir.join("next"),
            "after rotation
",
        )
        .unwrap();
        std::fs::rename(dir.join("next"), &path).unwrap();
        // The first poll notices the new file, the next reads it.
        for _ in 0..2 {
            f.poll(|l| {
                seen.push(l.to_owned());
                Ok(())
            })
            .unwrap();
        }
        assert_eq!(seen, ["third", "after rotation"]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("piano-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn the_last_lines_that_pass_the_filter() {
        let dir = temp_dir("last");
        let path = dir.join("access.log");
        let line = |i: u32, site: &str| format!("{{\"site\":\"{site}\",\"status\":{i}}}\n");
        let text = [
            line(1, "a"),
            "not json\n".into(),
            line(2, "b"),
            line(3, "a"),
            line(4, "a"),
        ]
        .concat();
        std::fs::write(&path, text).unwrap();
        let out = Output {
            json: true,
            color: crate::render::color(true),
        };
        let a = Filter::new(Some("a".into()), None, None).unwrap();
        let tail = |n, filter: &Filter| {
            let mut log = Follower::open(&path, None).unwrap();
            let got: Vec<String> = last(&mut log, n, filter, &out).unwrap().into();
            // What follows starts after everything read.
            let mut rest = Vec::new();
            log.read(|l| {
                rest.push(l.to_owned());
                Ok(())
            })
            .unwrap();
            assert!(rest.is_empty(), "{rest:?}");
            got
        };
        assert_eq!(
            tail(2, &a),
            [line(3, "a").trim_end(), line(4, "a").trim_end()]
        );
        assert_eq!(tail(10, &a).len(), 3);
        assert_eq!(tail(10, &Filter::default()).len(), 4);
        assert!(tail(0, &a).is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_follower_starts_over_when_the_file_is_truncated() {
        let dir = temp_dir("truncate");
        let path = dir.join("access.log");
        std::fs::write(&path, "one\ntwo\n").unwrap();
        // Asked for as much as the file holds, it reads the first line too.
        let mut f = Follower::open(&path, Some(8)).unwrap();
        let mut seen = Vec::new();
        let mut each = |l: &str| {
            seen.push(l.to_owned());
            Ok(())
        };
        f.poll(&mut each).unwrap();
        std::fs::write(&path, "new\n").unwrap();
        f.poll(&mut each).unwrap();
        f.poll(&mut each).unwrap();
        assert_eq!(seen, ["one", "two", "new"]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_follower_keeps_a_line_that_starts_where_it_starts() {
        let dir = temp_dir("boundary");
        let path = dir.join("access.log");
        std::fs::write(&path, "aa\nbb\ncc\n").unwrap();
        for (last, want) in [(6, &["bb", "cc"][..]), (5, &["cc"]), (2, &[])] {
            let mut f = Follower::open(&path, Some(last)).unwrap();
            let mut seen = Vec::new();
            f.read(|l| {
                seen.push(l.to_owned());
                Ok(())
            })
            .unwrap();
            assert_eq!(seen, want, "{last}");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn lines_that_are_not_utf8_are_skipped() {
        let mut pending = Vec::new();
        let mut seen = Vec::new();
        let mut each = |l: &str| {
            seen.push(l.to_owned());
            Ok(())
        };
        drain(&mut &b"a\n\xe4\xb8\nb\n"[..], &mut pending, &mut each).unwrap();
        // Half of a character at the end is a line still being written.
        drain(&mut &"c\u{4e2d}".as_bytes()[..2], &mut pending, &mut each).unwrap();
        drain(&mut &"c\u{4e2d}\n".as_bytes()[2..], &mut pending, &mut each).unwrap();
        assert_eq!(seen, ["a", "b", "c\u{4e2d}"]);
    }

    #[test]
    fn drain_keeps_a_partial_line() {
        let mut pending = Vec::new();
        let mut seen = Vec::new();
        drain(&mut "a\nb".as_bytes(), &mut pending, |l| {
            seen.push(l.to_owned());
            Ok(())
        })
        .unwrap();
        assert_eq!(seen, ["a"]);
        assert_eq!(pending, b"b");
        drain(&mut "c\n".as_bytes(), &mut pending, |l| {
            seen.push(l.to_owned());
            Ok(())
        })
        .unwrap();
        assert_eq!(seen, ["a", "bc"]);
    }
}
