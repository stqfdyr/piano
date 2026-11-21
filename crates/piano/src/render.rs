//! Text output of the management commands.

use chrono::{Days, FixedOffset, NaiveDate};
use piano::traffic::{Record, SiteBytes, sum_since};
use piano_ctl::proto::{CacheStats, Counts, Latency, Level, ReloadReply, Status, UpgradeReply};
use piano_telemetry::Kind;
use piano_telemetry::metrics::End;
use std::collections::BTreeMap;
use std::fmt::Write;
use std::io::IsTerminal;
use std::time::{Duration, UNIX_EPOCH};

/// Whether text output uses ANSI colours.
#[derive(Debug, Clone, Copy)]
pub struct Color(bool);

/// A logged UTC timestamp in local time as `format` writes it; `None` when it is no
/// RFC 3339 time. Text for people shows local time; JSON keeps UTC.
pub fn local_time(ts: &str, format: &str) -> Option<String> {
    time_in(ts, &chrono::Local, format)
}

fn time_in<Tz: chrono::TimeZone>(ts: &str, tz: &Tz, format: &str) -> Option<String>
where
    Tz::Offset: std::fmt::Display,
{
    let t = chrono::DateTime::parse_from_rfc3339(ts).ok()?;
    Some(t.with_timezone(tz).format(format).to_string())
}

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
pub fn duration(secs: u64) -> String {
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

/// `812 B`, `3.4 KiB` … `1.24 TiB`.
pub fn size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = bytes as f64;
    let mut unit = 0;
    while v >= 1024.0 && unit < UNITS.len() - 1 {
        v /= 1024.0;
        unit += 1;
    }
    match unit {
        0 => format!("{bytes} B"),
        _ if v < 10.0 => format!("{v:.2} {}", UNITS[unit]),
        _ => format!("{v:.1} {}", UNITS[unit]),
    }
}

/// `85ms`, `1.3s`, `12s`.
pub fn millis(v: f64) -> String {
    match v {
        v if v < 1000.0 => format!("{v:.0}ms"),
        v if v < 10_000.0 => format!("{:.1}s", v / 1000.0),
        v => format!("{:.0}s", v / 1000.0),
    }
}

/// `piano doctor`: checks under their group, problems coloured.
pub fn doctor(r: &piano::doctor::Report, color: Color) -> String {
    use piano::doctor::Level;
    let mut out = String::new();
    let mut group = "";
    for c in &r.checks {
        if c.group != group {
            if !group.is_empty() {
                out.push('\n');
            }
            let _ = writeln!(out, "{}", c.group);
            group = c.group;
        }
        let tag = match c.level {
            Level::Ok => "ok".to_owned(),
            Level::Skip => "skip".to_owned(),
            Level::Warn => color.yellow("warn"),
            Level::Error => color.red("error"),
        };
        // Pad the plain word so colour codes do not shift the columns.
        let pad = " ".repeat(6usize.saturating_sub(match c.level {
            Level::Ok => 2,
            Level::Skip => 4,
            Level::Warn => 4,
            Level::Error => 5,
        }));
        let line = if c.detail.is_empty() {
            format!("  {tag}{pad}{}", c.what)
        } else {
            format!("  {tag}{pad}{}  {}", c.what, c.detail)
        };
        let _ = writeln!(out, "{}", line.trim_end());
    }
    let count = |l: Level| r.checks.iter().filter(|c| c.level == l).count();
    let (errors, warnings) = (count(Level::Error), count(Level::Warn));
    let _ = writeln!(out);
    match (errors, warnings) {
        (0, 0) => {
            let _ = writeln!(out, "no problems found");
        }
        (0, w) => {
            let _ = writeln!(
                out,
                "{}",
                color.yellow(&format!("{w} warning{}", plural(w)))
            );
        }
        (e, w) => {
            let _ = writeln!(
                out,
                "{}",
                color.red(&format!("{e} error{}, {w} warning{}", plural(e), plural(w)))
            );
        }
    }
    out
}

/// `piano probe`: one line per step, grouped by User-Agent when there are several.
pub fn probe(r: &piano::probe::Report, color: Color) -> String {
    let mut out = format!(
        "{} via {} {} ({})\n",
        r.site, r.via, r.address, r.server_name
    );
    let several = r
        .steps
        .iter()
        .any(|s| s.user_agent != r.steps[0].user_agent);
    let mut current: Option<&str> = None;
    for s in &r.steps {
        if several && current != Some(s.user_agent.as_str()) {
            let _ = writeln!(out, "\n  {}", s.user_agent);
            current = Some(&s.user_agent);
        }
        let status = s.status.map_or_else(|| "-".to_owned(), |c| c.to_string());
        let first = s
            .first_byte_ms
            .map_or_else(|| "-".to_owned(), |v| millis(v as f64));
        let total = if s.status.is_some() || s.total_ms > 0 {
            millis(s.total_ms as f64)
        } else {
            "-".to_owned()
        };
        let line = format!(
            "  {:<9} {:>4} {:>10} {:>7} {:>7}  {}",
            s.name,
            status,
            if s.status.is_some() {
                size(s.bytes)
            } else {
                "-".to_owned()
            },
            first,
            total,
            s.note
        );
        let line = line.trim_end();
        if s.ok {
            let _ = writeln!(out, "{line}");
        } else {
            let _ = writeln!(out, "{}", color.red(line));
        }
    }
    let failed = r.steps.iter().filter(|s| !s.ok).count();
    if failed == 0 {
        let _ = writeln!(out, "\nall {} steps ok", r.steps.len());
    } else {
        let _ = writeln!(
            out,
            "\n{}",
            color.red(&format!("{failed} of {} steps failed", r.steps.len()))
        );
    }
    out
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
pub fn failed(c: &Counts) -> u64 {
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
                .as_deref()
                .map_or("unresolved", |a| a.rsplit_once(':').map_or(a, |(ip, _)| ip));
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
        "  {:<w$} {:>8} {:>6} {:>6} {:>6} {:>6} {:>6} {:>5} {:>10} {:>10}  upstream",
        "site", "requests", "2xx", "3xx", "4xx", "5xx", "failed", "reuse", "sent", "fetched"
    );
    for (name, r, upstream) in rows {
        let _ = writeln!(
            o,
            "  {name:<w$} {:>8} {:>6} {:>6} {:>6} {:>6} {:>6} {:>5} {:>10} {:>10}  {upstream}",
            r.requests,
            r.status("2xx"),
            r.status("3xx"),
            r.status("4xx"),
            r.status("5xx"),
            failed(r),
            reuse(r),
            size(r.bytes_sent),
            size(r.bytes_fetched),
        );
    }
    let timed = s.sites.iter().any(|x| x.ttfb.values().any(|l| l.count > 0));
    if timed {
        let _ = writeln!(
            o,
            "\n  time to first byte, p50 / p95, last {}",
            duration(s.ttfb_secs.max(1))
        );
        let _ = writeln!(
            o,
            "  {:<w$} {:>15} {:>15} {:>15}",
            "site", "browse", "image", "media"
        );
        for x in &s.sites {
            let cell = |k: &str| match x.ttfb.get(k) {
                Some(Latency {
                    p50_ms: Some(a),
                    p95_ms: Some(b),
                    ..
                }) => format!("{} / {}", millis(*a), millis(*b)),
                _ => "-".to_owned(),
            };
            let _ = writeln!(
                o,
                "  {:<w$} {:>15} {:>15} {:>15}",
                x.name,
                cell("browse"),
                cell("image"),
                cell("media")
            );
        }
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

pub fn cache(c: &CacheStats) -> String {
    let mut o = String::new();
    let _ = writeln!(
        o,
        "images   {} stored · {} of {} · {} misses and {} redirects remembered",
        c.images,
        mib(c.bytes),
        mib(c.capacity),
        c.missing,
        c.redirects
    );
    let answered =
        c.hits + c.misses + c.coalesced + c.stale + c.revalidated + c.missing_hits + c.shed;
    let share = |n: u64| match answered {
        0 => "-".to_owned(),
        a => format!("{}%", n * 100 / a),
    };
    let _ = writeln!(
        o,
        "since start  {answered} requests · from memory {} ({}) · upstream {} · shared {} · \
         stale {} · revalidated {} · remembered 404 {} · shed 429 {} · via remembered redirect {}",
        c.hits,
        share(c.hits),
        c.misses,
        c.coalesced,
        c.stale,
        c.revalidated,
        c.missing_hits,
        c.shed,
        c.redirect_hits
    );
    for u in &c.upstreams {
        let limit = match (u.burst, u.per_sec) {
            (Some(b), Some(r)) => format!("limit {b} + {r}/s, {:.0} left", u.tokens),
            _ => "no limit set".to_owned(),
        };
        let paused = u
            .paused_secs
            .map_or_else(String::new, |s| format!(" · paused {s:.0}s"));
        let _ = writeln!(
            o,
            "upstream {} · {limit} · {} × 429 since start{paused}",
            u.upstream, u.limited
        );
    }
    o
}

/// `piano traffic`: today, the last 7 and 30 days per site, the last 30 days by kind,
/// and the last `days` days one by one. `now` is Unix seconds.
pub fn traffic(
    record: &Record,
    path: &str,
    today: NaiveDate,
    offset: FixedOffset,
    now: u64,
    days: usize,
) -> String {
    let mut o = String::new();
    let _ = writeln!(
        o,
        "{path} · updated {} ago · local days; this host is now at UTC{offset}",
        ago(now, record.updated)
    );
    o.push_str(
        "response bodies only; the network interface also carries headers, TLS and TCP \
         overhead and other traffic of the machine\n",
    );
    let back = |n: u64| today.checked_sub_days(Days::new(n)).unwrap_or(today);
    let spans = [
        ("today", sum_since(record, today)),
        ("last 7 days", sum_since(record, back(6))),
        ("last 30 days", sum_since(record, back(29))),
    ];
    let mut names: Vec<&String> = spans[2].1.keys().collect();
    names.sort_by_key(|n| std::cmp::Reverse(spans[2].1[*n].sent.total()));
    let w = names.iter().map(|n| n.len()).max().unwrap_or(0).max(5);
    let _ = writeln!(
        o,
        "\n  {:<w$} {:>21}  {:>21}  {:>21}",
        "", spans[0].0, spans[1].0, spans[2].0
    );
    let _ = writeln!(
        o,
        "  {:<w$} {:>10} {:>10}  {:>10} {:>10}  {:>10} {:>10}",
        "site", "sent", "fetched", "sent", "fetched", "sent", "fetched"
    );
    let total = |m: &BTreeMap<String, SiteBytes>| {
        let mut t = SiteBytes::default();
        for b in m.values() {
            t.add(b);
        }
        t
    };
    let mut row = |name: &str, cells: [SiteBytes; 3]| {
        let _ = writeln!(
            o,
            "  {name:<w$} {:>10} {:>10}  {:>10} {:>10}  {:>10} {:>10}",
            size(cells[0].sent.total()),
            size(cells[0].fetched.total()),
            size(cells[1].sent.total()),
            size(cells[1].fetched.total()),
            size(cells[2].sent.total()),
            size(cells[2].fetched.total()),
        );
    };
    for name in &names {
        row(
            name,
            spans
                .each_ref()
                .map(|(_, m)| m.get(*name).copied().unwrap_or_default()),
        );
    }
    if names.len() > 1 {
        row("total", spans.each_ref().map(|(_, m)| total(m)));
    }

    let _ = writeln!(o, "\n  last 30 days by kind, sent / fetched");
    let _ = write!(o, "  {:<w$}", "site");
    for k in Kind::ALL {
        let _ = write!(o, " {:>21}", k.as_str());
    }
    o.push('\n');
    for name in &names {
        let b = spans[2].1[*name];
        let _ = write!(o, "  {name:<w$}");
        for k in Kind::ALL {
            let _ = write!(
                o,
                " {:>21}",
                format!("{} / {}", size(b.sent.get(k)), size(b.fetched.get(k)))
            );
        }
        o.push('\n');
    }

    if days > 0 {
        let _ = writeln!(
            o,
            "\n  {:<10}  {:<w$} {:>10} {:>10}",
            "date", "site", "sent", "fetched"
        );
        for (date, sites) in record.days.iter().rev().take(days) {
            let mut first = true;
            for (name, b) in sites {
                let d = if first { date.as_str() } else { "" };
                first = false;
                let _ = writeln!(
                    o,
                    "  {d:<10}  {name:<w$} {:>10} {:>10}",
                    size(b.sent.total()),
                    size(b.fetched.total())
                );
            }
        }
    }
    o
}

pub fn upgrade(r: &UpgradeReply) -> String {
    let mut o = String::new();
    if r.ok {
        let _ = writeln!(
            o,
            "upgraded to {}: pid {} serves (ready after {} ms)",
            r.version.as_deref().unwrap_or("?"),
            r.new_pid.unwrap_or_default(),
            r.ready_ms.unwrap_or_default()
        );
        let _ = writeln!(
            o,
            "pid {} keeps {} media streams until they end, {} at most",
            r.old_pid,
            r.draining_streams,
            duration(r.drain_limit_secs)
        );
    } else {
        let _ = writeln!(
            o,
            "upgrade failed; pid {} still serves:
{}",
            r.old_pid,
            r.error.as_deref().unwrap_or("unknown error")
        );
    }
    o
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
    fn logged_times_in_another_zone() {
        let east8 = FixedOffset::east_opt(8 * 3600).unwrap();
        let ts = "2026-11-20T20:01:02.345Z";
        assert_eq!(
            time_in(ts, &east8, "%m-%d %H:%M:%S").as_deref(),
            Some("11-21 04:01:02")
        );
        assert_eq!(time_in("garbled", &east8, "%H:%M:%S"), None);
    }

    #[test]
    fn durations() {
        assert_eq!(duration(40), "40s");
        assert_eq!(duration(300), "5m");
        assert_eq!(duration(7500), "2h 5m");
        assert_eq!(duration(3 * 86_400 + 4 * 3600 + 59), "3d 4h");
        assert_eq!(date(0), "1970-01-01");
    }

    #[test]
    fn traffic_spans_and_kinds() {
        use piano::traffic::{ByteKinds, Record};
        let bytes = |media, other| SiteBytes {
            sent: ByteKinds {
                media,
                other,
                ..ByteKinds::default()
            },
            fetched: ByteKinds {
                media,
                other,
                ..ByteKinds::default()
            },
        };
        let mut r = Record {
            updated: 1000,
            ..Record::default()
        };
        for (d, n) in [
            ("2026-11-20", 1),
            ("2026-11-15", 10),
            ("2026-10-25", 100),
            ("2026-10-01", 1000),
        ] {
            r.days.insert(
                d.into(),
                [
                    ("alpha".to_owned(), bytes(n, 1)),
                    ("beta".to_owned(), bytes(0, n)),
                ]
                .into(),
            );
        }
        let today = NaiveDate::from_ymd_opt(2026, 11, 20).unwrap();
        let offset = FixedOffset::east_opt(8 * 3600).unwrap();
        let out = traffic(&r, "/x/traffic.json", today, offset, 1060, 2);
        let line = |name: &str| {
            out.lines()
                .find(|l| l.trim_start().starts_with(name))
                .unwrap_or_else(|| panic!("{out}"))
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
        };
        assert!(
            out.starts_with(
                "/x/traffic.json · updated 1m ago · local days; this host is now at UTC+08:00"
            ),
            "{out}"
        );
        // today / 7 days / 30 days; 2026-10-01 is outside all of them.
        assert_eq!(
            line("alpha"),
            "alpha 2 B 2 B 13 B 13 B 114 B 114 B",
            "{out}"
        );
        assert_eq!(line("total"), "total 3 B 3 B 24 B 24 B 225 B 225 B");
        assert!(out.contains("2026-11-20  alpha"), "{out}");
        assert!(!out.contains("2026-10-25  "), "{out}");
    }

    #[test]
    fn sizes() {
        assert_eq!(size(812), "812 B");
        assert_eq!(size(3500), "3.42 KiB");
        assert_eq!(
            size(41 * 1024 * 1024 * 1024 + 300 * 1024 * 1024),
            "41.3 GiB"
        );
        assert_eq!(size(1 << 50), "1024.0 TiB");
    }
}
