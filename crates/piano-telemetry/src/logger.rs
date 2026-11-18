//! Diagnostic log to stderr: one line per record with a UTC timestamp, level and target.

use log::{Level, LevelFilter, Log, Metadata, Record};
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

struct StderrLogger {
    level: LevelFilter,
}

impl Log for StderrLogger {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        let quiet_framework =
            metadata.target().starts_with("pingora") && self.level < LevelFilter::Debug;
        if quiet_framework {
            metadata.level() <= Level::Warn
        } else {
            metadata.level() <= self.level
        }
    }

    fn log(&self, record: &Record<'_>) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let line = format!(
            "{} {:<5} {}: {}\n",
            utc_timestamp(SystemTime::now()),
            record.level(),
            record.target(),
            record.args()
        );
        // A failed write to stderr has nowhere to be reported.
        let _ = std::io::stderr().lock().write_all(line.as_bytes());
    }

    fn flush(&self) {}
}

/// Installs the logger. Records from pingora below `warn` are dropped unless `level`
/// is `debug` or finer, since its `info` output is per-connection noise.
pub fn init(level: LevelFilter) -> Result<(), log::SetLoggerError> {
    log::set_boxed_logger(Box::new(StderrLogger { level }))?;
    log::set_max_level(level);
    Ok(())
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
    use std::time::Duration;

    #[test]
    fn framework_info_is_quiet_unless_debugging() {
        let meta = |target, level| Metadata::builder().target(target).level(level).build();
        let info = StderrLogger {
            level: LevelFilter::Info,
        };
        assert!(info.enabled(&meta("piano", Level::Info)));
        assert!(!info.enabled(&meta("pingora_core::listeners", Level::Info)));
        assert!(info.enabled(&meta("pingora_proxy", Level::Warn)));
        let debug = StderrLogger {
            level: LevelFilter::Debug,
        };
        assert!(debug.enabled(&meta("pingora_core", Level::Debug)));
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
