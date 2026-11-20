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
    level: Option<Level>,
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
            let t = &mut tallies[i];
            let instant = Instant::now();
            match t.since {
                Some(since) if instant.duration_since(since) < WINDOW => {
                    t.suppressed += 1;
                    t.level = Some(record.level());
                    return;
                }
                _ => {
                    if t.suppressed > 0 {
                        emit(&summary(record.target(), t, now));
                    }
                    *t = Tally {
                        since: Some(instant),
                        ..Tally::default()
                    };
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

fn summary(target: &str, t: &Tally, now: SystemTime) -> String {
    let level = t.level.unwrap_or(Level::Info);
    let secs = t.since.map_or(0, |s| s.elapsed().as_secs());
    format!(
        "{} {level:<5} {target}: {} more like this in the last {secs} s\n",
        utc_timestamp(now),
        t.suppressed
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
    for (t, target) in tallies.iter_mut().zip(AGGREGATED) {
        let ended = t.since.is_some_and(|s| all || s.elapsed() >= WINDOW);
        if ended {
            if t.suppressed > 0 {
                emit(&summary(target, t, SystemTime::now()));
            }
            *t = Tally::default();
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
    fn formats_known_instants() {
        assert_eq!(utc_timestamp(UNIX_EPOCH), "1970-01-01T00:00:00.000Z");
        let t = UNIX_EPOCH + Duration::from_millis(951_782_400_123); // leap day 2000
        assert_eq!(utc_timestamp(t), "2000-02-29T00:00:00.123Z");
        let t = UNIX_EPOCH + Duration::from_secs(1_795_046_399);
        assert_eq!(utc_timestamp(t), "2026-11-18T23:59:59.000Z");
    }
}
