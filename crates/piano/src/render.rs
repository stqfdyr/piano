//! Text output of the management commands.

use piano_ctl::proto::{Counts, Level, ReloadReply, Status};
use piano_telemetry::metrics::End;
use std::fmt::Write;
use std::io::IsTerminal;
use std::time::{Duration, UNIX_EPOCH};

/// Whether text output uses ANSI colours.
#[derive(Debug, Clone, Copy)]
pub struct Color(bool);

pub fn color(no_color: bool) -> Color {
    Color(!no_color && std::env::var_os("NO_COLOR").is_none() && std::io::stdout().is_terminal())
}

impl Color {
    fn paint(self, code: &str, s: &str) -> String {
        if self.0 {
            format!("\x1b[{code}m{s}\x1b[0m")
        } else {
            s.to_owned()
        }
    }

    pub fn red(self, s: &str) -> String {
        self.paint("31", s)
    }

    pub fn yellow(self, s: &str) -> String {
        self.paint("33", s)
    }

    fn level(self, level: Level, s: &str) -> String {
        match level {
            Level::Warn => self.paint("33", s),
            Level::Error => self.paint("31", s),
        }
    }
}

/// `3d 4h`, `2h 5m`, `5m`, `40s`.
fn duration(secs: u64) -> String {
    let (d, h, m) = (secs / 86_400, secs / 3600 % 24, secs / 60 % 60);
    match () {
        () if d > 0 => format!("{d}d {h}h"),
        () if h > 0 => format!("{h}h {m}m"),
        () if m > 0 => format!("{m}m"),
        () => format!("{secs}s"),
    }
}

fn ago(now: u64, then: u64) -> String {
    duration(now.saturating_sub(then))
}

fn mib(bytes: u64) -> String {
    format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
}

fn date(unix: i64) -> String {
    let t = UNIX_EPOCH + Duration::from_secs(u64::try_from(unix).unwrap_or(0));
    let mut s = piano_telemetry::logger::utc_timestamp(t);
    s.truncate(10);
    s
}

fn opt(v: Option<u64>) -> String {
    v.map_or_else(|| "?".to_owned(), |v| v.to_string())
}

/// Requests that failed on the upstream side or inside piano.
fn failed(c: &Counts) -> u64 {
    End::ALL
        .iter()
        .filter(|e| e.is_upstream_failure() || **e == End::Internal)
        .map(|e| c.end(e.as_str()))
        .sum()
}

fn reuse(c: &Counts) -> String {
    match c.upstream_attempts {
        0 => "-".to_owned(),
        n => format!("{}%", c.reused * 100 / n),
    }
}

pub fn status(s: &Status, color: Color) -> String {
    let now = s.started + s.uptime_secs;
    let errors = s
        .findings
        .iter()
        .filter(|f| f.level == Level::Error)
        .count();
    let warnings = s.findings.len() - errors;
    let health = match (errors, warnings) {
        (0, 0) => color.paint("32", "● healthy"),
        (0, w) => color.level(Level::Warn, &format!("● {w} warning{}", plural(w))),
        (e, _) => color.level(Level::Error, &format!("● {e} error{}", plural(e))),
    };
    let mut o = String::new();
    let _ = writeln!(
        o,
        "piano {} · up {} · pid {}   {health}",
        s.version,
        duration(s.uptime_secs),
        s.pid
    );
    let mut config = format!(
        "{} · loaded {} ago",
        s.config.path,
        ago(now, s.config.loaded)
    );
    if let Some(r) = s.config.last_reload.as_ref().filter(|r| !r.ok) {
        let _ = write!(config, " · last reload failed {} ago", ago(now, r.at));
    }
    let _ = writeln!(o, "  config   {config}");
    let p = &s.process;
    let _ = writeln!(
        o,
        "  process  RSS {} · {} threads · fd {}/{}",
        p.rss_bytes.map_or_else(|| "?".to_owned(), mib),
        opt(p.threads),
        opt(p.open_files),
        opt(p.max_open_files)
    );
    let c = &s.connections;
    let _ = writeln!(
        o,
        "  conns    {} open of {} · {} in handshake · {} media streams · since start: {} \
         denied, {} handshake timeouts, {} handshake errors, {} closed at limit",
        c.open,
        c.limit,
        c.handshaking,
        c.media_streams,
        c.denied,
        c.handshake_timeouts,
        c.handshake_errors,
        c.closed_at_limit
    );
    let cert = &s.certificate;
    let names = match cert.names.as_slice() {
        [] => "?".to_owned(),
        [one] => one.clone(),
        [first, rest @ ..] => format!("{first} +{}", rest.len()),
    };
    let expiry = cert.not_after.map_or_else(
        || "expiry unknown".to_owned(),
        |t| {
            let days = (t - i64::try_from(now).unwrap_or(i64::MAX)).div_euclid(86_400);
            format!("expires {} ({days} days)", date(t))
        },
    );
    let _ = writeln!(o, "  cert     {names} · {expiry}");
    let log = &s.access_log;
    let _ = writeln!(
        o,
        "  log      {}{}",
        log.path.as_deref().unwrap_or("off"),
        if log.dropped > 0 {
            format!(" · {} lines dropped", log.dropped)
        } else {
            String::new()
        }
    );

    let total: u64 = s
        .sites
        .iter()
        .map(|x| x.traffic.total.requests)
        .sum::<u64>()
        + s.unrouted.total.requests;
    let _ = writeln!(
        o,
        "\n  last {}, {total} requests since start",
        duration(s.recent_secs.max(1))
    );
    let mut rows: Vec<(&str, &Counts, String)> = s
        .sites
        .iter()
        .map(|x| {
            let ip = x
                .address
                .rsplit_once(':')
                .map_or(x.address.as_str(), |(ip, _)| ip);
            (
                x.name.as_str(),
                &x.traffic.recent,
                format!("{} → {ip}", x.upstream),
            )
        })
        .collect();
    if s.unrouted.recent.requests > 0 {
        rows.push(("(other)", &s.unrouted.recent, "host is no site".to_owned()));
    }
    let w = rows.iter().map(|r| r.0.len()).max().unwrap_or(0).max(4);
    let _ = writeln!(
        o,
        "  {:<w$} {:>8} {:>6} {:>6} {:>6} {:>6} {:>6} {:>5}  upstream",
        "site", "requests", "2xx", "3xx", "4xx", "5xx", "failed", "reuse"
    );
    for (name, r, upstream) in rows {
        let _ = writeln!(
            o,
            "  {name:<w$} {:>8} {:>6} {:>6} {:>6} {:>6} {:>6} {:>5}  {upstream}",
            r.requests,
            r.status("2xx"),
            r.status("3xx"),
            r.status("4xx"),
            r.status("5xx"),
            failed(r),
            reuse(r),
        );
    }
    if !s.findings.is_empty() {
        o.push('\n');
    }
    for f in &s.findings {
        let mark = match f.level {
            Level::Warn => "!",
            Level::Error => "x",
        };
        let _ = writeln!(o, "  {} {}", color.level(f.level, mark), f.message);
        if let Some(h) = &f.hint {
            let _ = writeln!(o, "    → {h}");
        }
    }
    o
}

fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

pub fn reload(r: &ReloadReply) -> String {
    let mut o = String::new();
    if r.ok {
        o.push_str("reloaded\n");
        for w in &r.warnings {
            let _ = writeln!(o, "warning: {w}");
        }
        if !r.restart_needed.is_empty() {
            let _ = writeln!(o, "restart needed for: {}", r.restart_needed.join(", "));
        }
    } else {
        let _ = writeln!(
            o,
            "reload failed; the running configuration is unchanged:\n{}",
            r.error.as_deref().unwrap_or("unknown error")
        );
    }
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(duration(40), "40s");
        assert_eq!(duration(300), "5m");
        assert_eq!(duration(7500), "2h 5m");
        assert_eq!(duration(3 * 86_400 + 4 * 3600 + 59), "3d 4h");
        assert_eq!(date(0), "1970-01-01");
    }
}
