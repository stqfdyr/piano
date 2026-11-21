//! Diagnostic log to stderr, one line per record:
//! `<UTC time> <LEVEL> <target>: <message> key=value ...`.
//!
//! Every line passes through [`redact`], whatever produced it. Levels mean:
//! ERROR, something an operator has to fix; WARN, something went wrong and was handled
//! (a request failed, a reload was refused); INFO, lifecycle events; DEBUG and TRACE,
//! per-request detail. Targets in [`AGGREGATED`] report events that outsiders can
//! cause at any rate: the first record in a minute is written, later ones are only
//! counted and summed up in one line.

use crate::redact::redact;
use log::kv::{self, Key, Value, VisitSource};
use log::{Level, LevelFilter, Log, Metadata, Record};
use std::fmt::Write as _;
use std::io::Write as _;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Failed downstream TLS handshakes (scanners, unknown server names); set by the
/// pingora fork.
pub const HANDSHAKE: &str = "pingora_core::handshake";
/// Connections refused by the allow list.
pub const REFUSED: &str = "piano::refused";
/// Targets whose records are rate limited.
pub const AGGREGATED: [&str; 2] = [HANDSHAKE, REFUSED];
/// Length of one counting window for aggregated targets.
pub const WINDOW: Duration = Duration::from_secs(60);

#[derive(Debug, Default)]
struct Tally {
    /// Start of the current window; `None` before the first record.
    since: Option<Instant>,
    suppressed: u64,
    /// Level of the last suppressed record; `None` while nothing was suppressed.
    level: Option<Level>,
}

/// Records suppressed in a window that has ended.
#[derive(Debug, PartialEq, Eq)]
struct Suppressed {
    count: u64,
    level: Level,
    /// Length of the window, in whole seconds.
    secs: u64,
}

/// What to do with a record of an aggregated target.
#[derive(Debug, PartialEq, Eq)]
enum Admit {
    Suppress,
    /// Write it, after the summary of the window it ends, if that suppressed anything.
    Write(Option<Suppressed>),
}

impl Tally {
    /// Counts a record seen at `now`; the first one in a window is written.
    fn admit(&mut self, level: Level, now: Instant) -> Admit {
        if self.since.is_some_and(|s| now.duration_since(s) < WINDOW) {
            self.suppressed += 1;
            self.level = Some(level);
            return Admit::Suppress;
        }
        let ended = self.take(now);
        self.since = Some(now);
        Admit::Write(ended)
    }

    /// Ends the window if it is over at `now`, or with `all` whatever its age.
    fn close(&mut self, now: Instant, all: bool) -> Option<Suppressed> {
        let since = self.since?;
        if !all && now.duration_since(since) < WINDOW {
            return None;
        }
        self.take(now)
    }

    /// Resets the tally, returning what its window suppressed.
    fn take(&mut self, now: Instant) -> Option<Suppressed> {
        let t = std::mem::take(self);
        Some(Suppressed {
            count: t.suppressed,
            level: t.level?,
            secs: now.duration_since(t.since?).as_secs(),
        })
    }
}

struct StderrLogger {
    tallies: Mutex<[Tally; AGGREGATED.len()]>,
}

fn aggregated(target: &str) -> Option<usize> {
    AGGREGATED.iter().position(|&t| t == target)
}

impl Log for StderrLogger {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        enabled(metadata, log::max_level())
    }

    fn log(&self, record: &Record<'_>) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let now = SystemTime::now();
        if let Some(i) = aggregated(record.target()) {
            let mut tallies = self.tallies.lock().unwrap_or_else(PoisonError::into_inner);
            match tallies[i].admit(record.level(), Instant::now()) {
                Admit::Suppress => return,
                Admit::Write(ended) => {
                    if let Some(s) = ended {
                        emit(&summary(record.target(), &s, now));
                    }
                }
            }
        }
        emit(&format_record(record, now));
    }

    fn flush(&self) {}
}

fn enabled(metadata: &Metadata<'_>, max: LevelFilter) -> bool {
    let target = metadata.target();
    if aggregated(target).is_some() {
        return metadata.level() <= max;
    }
    // pingora's info records are per-connection noise.
    if target.starts_with("pingora") && max < LevelFilter::Debug {
        return metadata.level() <= Level::Warn;
    }
    metadata.level() <= max
}

fn emit(line: &str) {
    // A failed write to stderr has nowhere to be reported.
    let _ = std::io::stderr().lock().write_all(line.as_bytes());
}

fn summary(target: &str, s: &Suppressed, now: SystemTime) -> String {
    format!(
        "{} {:<5} {target}: {} more like this in the last {} s\n",
        utc_timestamp(now),
        s.level,
        s.count,
        s.secs
    )
}

/// One line for `record`, with credentials removed.
fn format_record(record: &Record<'_>, now: SystemTime) -> String {
    let mut line = format!(
        "{} {:<5} {}: {}",
        utc_timestamp(now),
        record.level(),
        record.target(),
        record.args()
    );
    let _ = record.key_values().visit(&mut Pairs(&mut line));
    line.push('\n');
    match redact(&line) {
        std::borrow::Cow::Borrowed(_) => line,
        std::borrow::Cow::Owned(clean) => clean,
    }
}

/// Appends ` key=value` pairs; values with spaces, quotes or `=` are quoted.
struct Pairs<'a>(&'a mut String);

impl<'kvs> VisitSource<'kvs> for Pairs<'_> {
    fn visit_pair(&mut self, key: Key<'kvs>, value: Value<'kvs>) -> Result<(), kv::Error> {
        let v = value.to_string();
        let plain = !v.is_empty()
            && !v
                .bytes()
                .any(|b| b.is_ascii_whitespace() || matches!(b, b'"' | b'=' | b'\\'));
        if plain {
            let _ = write!(self.0, " {key}={v}");
        } else {
            let _ = write!(self.0, " {key}={v:?}");
        }
        Ok(())
    }
}

/// Writes out summaries for aggregated targets whose window has ended, or for all of
/// them with `all` (at exit). Call about once per [`WINDOW`] so that a burst is reported
/// even when nothing follows it.
pub fn flush_aggregated(all: bool) {
    let Some(logger) = installed() else {
        return;
    };
    let mut tallies = logger
        .tallies
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let now = Instant::now();
    for (t, target) in tallies.iter_mut().zip(AGGREGATED) {
        if let Some(s) = t.close(now, all) {
            emit(&summary(target, &s, SystemTime::now()));
        }
    }
}

static LOGGER: std::sync::OnceLock<&'static StderrLogger> = std::sync::OnceLock::new();

fn installed() -> Option<&'static StderrLogger> {
    LOGGER.get().copied()
}

/// Installs the logger at `level`. Records from pingora below `warn` are dropped unless
/// the level is `debug` or finer.
pub fn init(level: LevelFilter) -> Result<(), log::SetLoggerError> {
    let logger: &'static StderrLogger = Box::leak(Box::new(StderrLogger {
        tallies: Mutex::new(Default::default()),
    }));
    log::set_logger(logger)?;
    let _ = LOGGER.set(logger);
    log::set_max_level(level);
    Ok(())
}

/// Changes the level of the installed logger.
pub fn set_level(level: LevelFilter) {
    log::set_max_level(level);
}

/// Parses a level name as used in the configuration and on the command line.
pub fn parse_level(s: &str) -> Option<LevelFilter> {
    s.parse().ok()
}

/// Formats `t` as `YYYY-MM-DDTHH:MM:SS.mmmZ`.
pub fn utc_timestamp(t: SystemTime) -> String {
    let d = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = d.as_secs();
    let (y, m, day) = civil_from_days((secs / 86_400) as i64);
    let s = secs % 86_400;
    format!(
        "{y:04}-{m:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        s / 3600,
        s / 60 % 60,
        s % 60,
        d.subsec_millis()
    )
}

/// Days since 1970-01-01 to a proleptic Gregorian date (Howard Hinnant's algorithm).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(target: &str, level: Level) -> Metadata<'_> {
        Metadata::builder().target(target).level(level).build()
    }

    #[test]
    fn framework_info_is_quiet_unless_debugging() {
        let info = LevelFilter::Info;
        assert!(enabled(&meta("piano", Level::Info), info));
        assert!(!enabled(
            &meta("pingora_core::listeners", Level::Info),
            info
        ));
        assert!(enabled(&meta("pingora_proxy", Level::Warn), info));
        assert!(enabled(&meta(HANDSHAKE, Level::Info), info));
        assert!(!enabled(&meta(HANDSHAKE, Level::Info), LevelFilter::Warn));
        assert!(enabled(
            &meta("pingora_core", Level::Debug),
            LevelFilter::Debug
        ));
    }

    #[test]
    fn lines_carry_pairs_and_no_credentials() {
        let pairs = [("rid", "00000000000000ab"), ("note", "two words")];
        let record = Record::builder()
            .args(format_args!("GET /x?api_key=s3cret failed"))
            .level(Level::Warn)
            .target("piano_proxy::relay")
            .key_values(&pairs)
            .build();
        let line = format_record(&record, UNIX_EPOCH);
        assert_eq!(
            line,
            "1970-01-01T00:00:00.000Z WARN  piano_proxy::relay: GET /x?api_key=REDACTED failed \
             rid=00000000000000ab note=\"two words\"\n"
        );
    }

    #[test]
    fn one_record_a_minute_is_written_and_the_rest_counted() {
        let t0 = Instant::now();
        let at = |s: u64| t0 + Duration::from_secs(s);
        let mut t = Tally::default();
        assert_eq!(t.admit(Level::Info, at(0)), Admit::Write(None));
        assert_eq!(t.admit(Level::Info, at(1)), Admit::Suppress);
        assert_eq!(t.admit(Level::Warn, at(59)), Admit::Suppress);
        let ended = Suppressed {
            count: 2,
            level: Level::Warn,
            secs: 61,
        };
        assert_eq!(t.admit(Level::Info, at(61)), Admit::Write(Some(ended)));
        // A window that suppressed nothing ends without a summary.
        assert_eq!(t.admit(Level::Info, at(121)), Admit::Write(None));
        assert_eq!(t.admit(Level::Info, at(122)), Admit::Suppress);
    }

    #[test]
    fn windows_are_closed_when_over_or_at_exit() {
        let t0 = Instant::now();
        let at = |s: u64| t0 + Duration::from_secs(s);
        let mut t = Tally::default();
        assert_eq!(t.close(at(0), true), None);
        t.admit(Level::Info, at(0));
        t.admit(Level::Info, at(10));
        assert_eq!(t.close(at(59), false), None);
        let ended = Suppressed {
            count: 1,
            level: Level::Info,
            secs: 60,
        };
        assert_eq!(t.close(at(60), false), Some(ended));
        // The next record opens a new window and is written.
        assert_eq!(t.admit(Level::Info, at(70)), Admit::Write(None));
        t.admit(Level::Info, at(71));
        let ended = Suppressed {
            count: 1,
            level: Level::Info,
            secs: 5,
        };
        assert_eq!(t.close(at(75), true), Some(ended));
        assert_eq!(t.admit(Level::Info, at(76)), Admit::Write(None));
    }

    #[test]
    fn summary_line() {
        let s = Suppressed {
            count: 41,
            level: Level::Warn,
            secs: 60,
        };
        assert_eq!(
            summary(HANDSHAKE, &s, UNIX_EPOCH),
            "1970-01-01T00:00:00.000Z WARN  pingora_core::handshake: 41 more like this in \
             the last 60 s\n"
        );
    }

    #[test]
    fn dates_match_a_day_by_day_count() {
        let (mut y, mut m, mut d) = (1970_i64, 1_u32, 1_u32);
        for z in 0..(2500 - 1970) * 366 {
            assert_eq!(civil_from_days(z), (y, m, d), "day {z}");
            let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
            let len = match m {
                2 if leap => 29,
                2 => 28,
                4 | 6 | 9 | 11 => 30,
                _ => 31,
            };
            d += 1;
            if d > len {
                (d, m) = (1, m + 1);
                if m > 12 {
                    (m, y) = (1, y + 1);
                }
            }
        }
    }

    #[test]
    fn formats_known_instants() {
        assert_eq!(utc_timestamp(UNIX_EPOCH), "1970-01-01T00:00:00.000Z");
        let t = UNIX_EPOCH + Duration::from_millis(951_782_400_123); // leap day 2000
        assert_eq!(utc_timestamp(t), "2000-02-29T00:00:00.123Z");
        let t = UNIX_EPOCH + Duration::from_secs(1_795_046_399);
        assert_eq!(utc_timestamp(t), "2026-11-18T23:59:59.000Z");
    }
}
