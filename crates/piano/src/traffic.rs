//! The traffic record: response body bytes per local day, site and kind, kept in a
//! file across restarts.
//!
//! The record attributes traffic; it does not meter a quota. Providers meter the
//! network interface, which also carries headers, TLS and TCP overhead and whatever
//! else the machine sends.

use chrono::{Days, NaiveDate};
use piano_telemetry::Kind;
use piano_telemetry::metrics::{ByKind, Counts};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};

/// Version of [`Record`].
pub const SCHEMA: u32 = 1;

/// Days kept, today included: two of the longest months, so the current billing period
/// and the one before it are always there whatever day it resets on.
pub const KEEP_DAYS: u64 = 62;

/// Bytes by kind.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ByteKinds {
    pub media: u64,
    pub image: u64,
    pub socket: u64,
    pub other: u64,
}

impl ByteKinds {
    fn get_mut(&mut self, kind: Kind) -> &mut u64 {
        match kind {
            Kind::Media => &mut self.media,
            Kind::Image => &mut self.image,
            Kind::Socket => &mut self.socket,
            Kind::Other => &mut self.other,
        }
    }

    pub fn get(&self, kind: Kind) -> u64 {
        match kind {
            Kind::Media => self.media,
            Kind::Image => self.image,
            Kind::Socket => self.socket,
            Kind::Other => self.other,
        }
    }

    pub fn total(&self) -> u64 {
        Kind::ALL.iter().map(|k| self.get(*k)).sum()
    }

    pub fn add(&mut self, other: &ByteKinds) {
        for k in Kind::ALL {
            *self.get_mut(k) = self.get(k).saturating_add(other.get(k));
        }
    }

    fn add_counts(&mut self, n: &ByKind) {
        for (k, n) in Kind::ALL.iter().zip(n) {
            let v = self.get_mut(*k);
            *v = v.saturating_add(*n);
        }
    }

    fn is_zero(&self) -> bool {
        *self == Self::default()
    }
}

/// One site's bytes on one day.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SiteBytes {
    /// Written to clients.
    pub sent: ByteKinds,
    /// Read from upstreams, retried and hedged requests included.
    pub fetched: ByteKinds,
}

impl SiteBytes {
    pub fn add(&mut self, other: &SiteBytes) {
        self.sent.add(&other.sent);
        self.fetched.add(&other.fetched);
    }
}

/// The file's content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    pub schema: u32,
    /// Unix seconds of the last write.
    pub updated: u64,
    /// By local date (`YYYY-MM-DD`), then site name.
    pub days: BTreeMap<String, BTreeMap<String, SiteBytes>>,
}

impl Default for Record {
    fn default() -> Self {
        Self {
            schema: SCHEMA,
            updated: 0,
            days: BTreeMap::new(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[error("{path}: not a traffic record: {source}")]
    Parse {
        path: String,
        source: serde_json::Error,
    },
    #[error("{path}: schema {found}, this version reads {SCHEMA}")]
    Schema { path: String, found: u32 },
}

fn io(path: &Path, source: std::io::Error) -> Error {
    Error::Io {
        path: path.display().to_string(),
        source,
    }
}

/// Reads the record at `path`; `None` when there is no file.
pub fn read(path: &Path) -> Result<Option<Record>, Error> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(io(path, e)),
    };
    let record: Record = serde_json::from_str(&text).map_err(|source| Error::Parse {
        path: path.display().to_string(),
        source,
    })?;
    if record.schema != SCHEMA {
        return Err(Error::Schema {
            path: path.display().to_string(),
            found: record.schema,
        });
    }
    Ok(Some(record))
}

/// Replaces the file at `path` with `record`: written next to it, synced, then renamed
/// over it, so a crash leaves either the old or the new record.
fn write_atomically(path: &Path, record: &Record) -> Result<(), Error> {
    let dir = path.parent().filter(|d| !d.as_os_str().is_empty());
    if let Some(dir) = dir {
        std::fs::create_dir_all(dir).map_err(|e| io(dir, e))?;
    }
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let text = serde_json::to_vec(record).map_err(|e| io(path, e.into()))?;
    let mut f = std::fs::File::create(&tmp).map_err(|e| io(&tmp, e))?;
    f.write_all(&text).map_err(|e| io(&tmp, e))?;
    f.sync_all().map_err(|e| io(&tmp, e))?;
    std::fs::rename(&tmp, path).map_err(|e| io(path, e))?;
    if let Some(dir) = dir
        && let Ok(d) = std::fs::File::open(dir)
    {
        // Makes the rename itself durable; a failure leaves the old record at worst.
        let _ = d.sync_all();
    }
    Ok(())
}

#[derive(Debug)]
struct State {
    record: Record,
    /// Counter readings already added, by site.
    seen: BTreeMap<String, (ByKind, ByKind)>,
    dirty: bool,
    /// Why the last write failed, until one succeeds.
    error: Option<String>,
}

/// The record of a running daemon.
#[derive(Debug)]
pub struct Ledger {
    path: Option<PathBuf>,
    state: Mutex<State>,
}

impl Ledger {
    /// Takes up the record at `path`, or keeps none when it is `None`. A file that is not a
    /// record is moved aside to `<path>.bad` and a new record started; one that cannot be
    /// read is left alone and nothing is recorded, rather than overwriting it. Returns
    /// what went wrong, to be logged.
    pub fn open(path: Option<&Path>) -> (Self, Option<String>) {
        let mut warning = None;
        let mut keep = path.map(Path::to_owned);
        let record = match path.map(read) {
            None | Some(Ok(None)) => Record::default(),
            Some(Ok(Some(r))) => r,
            Some(Err(e @ (Error::Parse { .. } | Error::Schema { .. }))) => {
                let mut bad = path.unwrap_or(Path::new("")).as_os_str().to_owned();
                bad.push(".bad");
                warning = Some(match path.map(|p| std::fs::rename(p, &bad)) {
                    Some(Ok(())) => format!(
                        "{e}; moved to {} and started a new record",
                        Path::new(&bad).display()
                    ),
                    Some(Err(m)) => {
                        keep = None;
                        format!("{e}; cannot move it aside ({m}), so traffic is not recorded")
                    }
                    None => e.to_string(),
                });
                Record::default()
            }
            Some(Err(e)) => {
                keep = None;
                warning = Some(format!("{e}; traffic is not recorded"));
                Record::default()
            }
        };
        let ledger = Self {
            path: keep,
            state: Mutex::new(State {
                record,
                seen: BTreeMap::new(),
                dirty: false,
                error: None,
            }),
        };
        (ledger, warning)
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Adds what the counters in `totals` gained since the last call to day `date`, and
    /// drops the days that fell out of [`KEEP_DAYS`].
    pub fn add(&self, totals: &BTreeMap<String, Counts>, date: NaiveDate) {
        let mut st = self.state();
        let st = &mut *st;
        let day = date.format("%Y-%m-%d").to_string();
        for (site, c) in totals {
            let (sent0, fetched0) = st.seen.get(site).copied().unwrap_or_default();
            let gained = SiteBytes {
                sent: delta(&c.sent, &sent0),
                fetched: delta(&c.fetched, &fetched0),
            };
            st.seen.insert(site.clone(), (c.sent, c.fetched));
            if gained.sent.is_zero() && gained.fetched.is_zero() {
                continue;
            }
            st.record
                .days
                .entry(day.clone())
                .or_default()
                .entry(site.clone())
                .or_default()
                .add(&gained);
            st.dirty = true;
        }
        let cutoff = date.checked_sub_days(Days::new(KEEP_DAYS));
        let before = st.record.days.len();
        st.record.days.retain(|d, _| {
            NaiveDate::parse_from_str(d, "%Y-%m-%d").is_ok_and(|d| cutoff.is_none_or(|c| d > c))
        });
        st.dirty |= st.record.days.len() != before;
    }

    /// Writes the record if it changed since the last write. `now` is Unix seconds.
    pub fn save(&self, now: u64) -> Result<bool, Error> {
        let Some(path) = &self.path else {
            return Ok(false);
        };
        let mut st = self.state();
        if !st.dirty {
            return Ok(false);
        }
        st.record.updated = now;
        match write_atomically(path, &st.record) {
            Ok(()) => {
                st.dirty = false;
                st.error = None;
                Ok(true)
            }
            Err(e) => {
                st.error = Some(e.to_string());
                Err(e)
            }
        }
    }

    /// Why the last write failed, while writes keep failing.
    pub fn error(&self) -> Option<String> {
        self.state().error.clone()
    }

    /// The record as it stands, unsaved additions included.
    pub fn record(&self) -> Record {
        self.state().record.clone()
    }
}

fn delta(now: &ByKind, before: &ByKind) -> ByteKinds {
    let mut out = ByteKinds::default();
    let d: ByKind = std::array::from_fn(|i| now[i].saturating_sub(before[i]));
    out.add_counts(&d);
    out
}

/// Sums of a record over dates, by site.
pub fn sum_since(record: &Record, first: NaiveDate) -> BTreeMap<String, SiteBytes> {
    let first = first.format("%Y-%m-%d").to_string();
    let mut out: BTreeMap<String, SiteBytes> = BTreeMap::new();
    for (_, sites) in record.days.range(first..) {
        for (site, b) in sites {
            out.entry(site.clone()).or_default().add(b);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn counts(sent: ByKind, fetched: ByKind) -> Counts {
        Counts {
            sent,
            fetched,
            ..Counts::default()
        }
    }

    fn totals(list: &[(&str, ByKind, ByKind)]) -> BTreeMap<String, Counts> {
        list.iter()
            .map(|(n, s, f)| ((*n).to_owned(), counts(*s, *f)))
            .collect()
    }

    fn day(s: &str) -> NaiveDate {
        NaiveDate::parse_from_str(s, "%Y-%m-%d").unwrap()
    }

    struct Dir(PathBuf);

    impl Dir {
        fn new(name: &str) -> Self {
            let p =
                std::env::temp_dir().join(format!("piano-traffic-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            Self(p)
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn adds_what_the_counters_gained_to_the_day() {
        let (l, w) = Ledger::open(None);
        assert!(w.is_none());
        l.add(
            &totals(&[("a", [100, 5, 0, 1], [120, 5, 0, 1])]),
            day("2026-11-20"),
        );
        l.add(
            &totals(&[("a", [150, 5, 0, 1], [170, 5, 0, 1])]),
            day("2026-11-20"),
        );
        l.add(
            &totals(&[
                ("a", [160, 5, 0, 1], [170, 5, 0, 1]),
                ("b", [0, 0, 3, 0], [0, 0, 3, 0]),
            ]),
            day("2026-11-21"),
        );
        let r = l.record();
        let d20 = &r.days["2026-11-20"]["a"];
        assert_eq!(
            (d20.sent.media, d20.sent.image, d20.sent.other),
            (150, 5, 1)
        );
        assert_eq!(d20.fetched.media, 170);
        let d21 = &r.days["2026-11-21"];
        assert_eq!(d21["a"].sent.media, 10);
        assert_eq!(d21["a"].fetched.total(), 0);
        assert_eq!(d21["b"].sent.socket, 3);
        let sums = sum_since(&r, day("2026-11-21"));
        assert_eq!(sums["a"].sent.total(), 10);
        assert_eq!(sum_since(&r, day("2026-11-01"))["a"].sent.total(), 166);
    }

    #[test]
    fn days_older_than_kept_are_dropped() {
        let (l, _) = Ledger::open(None);
        l.add(&totals(&[("a", [1, 0, 0, 0], [0; 4])]), day("2026-09-19"));
        l.add(&totals(&[("a", [2, 0, 0, 0], [0; 4])]), day("2026-09-20"));
        // 62 days kept, today included: 2026-11-20 back to 2026-09-20.
        l.add(&totals(&[("a", [3, 0, 0, 0], [0; 4])]), day("2026-11-20"));
        let days: Vec<String> = l.record().days.into_keys().collect();
        assert_eq!(days, ["2026-09-20", "2026-11-20"]);
    }

    #[test]
    fn saves_only_changes_and_reads_back_after_a_restart() {
        let dir = Dir::new("save");
        let path = dir.0.join("sub").join("traffic.json");
        let (l, w) = Ledger::open(Some(&path));
        assert!(w.is_none());
        assert!(!l.save(1).unwrap());
        l.add(
            &totals(&[("a", [10, 0, 0, 0], [12, 0, 0, 0])]),
            day("2026-11-20"),
        );
        assert!(l.save(2).unwrap());
        assert!(!l.save(3).unwrap());
        l.add(
            &totals(&[("a", [10, 0, 0, 0], [12, 0, 0, 0])]),
            day("2026-11-20"),
        );
        assert!(!l.save(4).unwrap());

        // A new process starts its counters from zero and adds to the same day.
        let (l, w) = Ledger::open(Some(&path));
        assert!(w.is_none());
        l.add(
            &totals(&[("a", [5, 0, 0, 0], [5, 0, 0, 0])]),
            day("2026-11-20"),
        );
        assert!(l.save(5).unwrap());
        let r = read(&path).unwrap().unwrap();
        assert_eq!(r.updated, 5);
        assert_eq!(r.days["2026-11-20"]["a"].sent.media, 15);
        assert_eq!(r.days["2026-11-20"]["a"].fetched.media, 17);
        assert!(!dir.0.join("sub").join("traffic.json.tmp").exists());
    }

    #[test]
    fn an_unreadable_file_is_left_alone() {
        let dir = Dir::new("unreadable");
        std::fs::create_dir_all(&dir.0).unwrap();
        let blocker = dir.0.join("blocker");
        std::fs::write(&blocker, "").unwrap();
        let (l, w) = Ledger::open(Some(&blocker.join("traffic.json")));
        assert!(w.unwrap().contains("not recorded"));
        assert!(l.path().is_none());
    }

    #[test]
    fn a_damaged_file_is_moved_aside() {
        let dir = Dir::new("bad");
        std::fs::create_dir_all(&dir.0).unwrap();
        let path = dir.0.join("traffic.json");
        std::fs::write(&path, r#"{"schema":1,"#).unwrap();
        let (l, w) = Ledger::open(Some(&path));
        assert!(w.unwrap().contains("traffic.json.bad"));
        assert!(dir.0.join("traffic.json.bad").exists());
        l.add(&totals(&[("a", [1, 0, 0, 0], [0; 4])]), day("2026-11-20"));
        assert!(l.save(1).unwrap());
        assert!(read(&path).unwrap().is_some());

        std::fs::write(&path, r#"{"schema":9,"updated":0,"days":{}}"#).unwrap();
        let (_, w) = Ledger::open(Some(&path));
        assert!(w.unwrap().contains("schema 9"));
    }

    #[test]
    fn a_failed_write_is_reported_until_one_succeeds() {
        let dir = Dir::new("fail");
        std::fs::create_dir_all(&dir.0).unwrap();
        let blocker = dir.0.join("blocker");
        let (l, w) = Ledger::open(Some(&blocker.join("traffic.json")));
        assert!(w.is_none());
        // A file where the directory should be.
        std::fs::write(&blocker, "").unwrap();
        l.add(&totals(&[("a", [1, 0, 0, 0], [0; 4])]), day("2026-11-20"));
        assert!(l.save(1).is_err());
        assert!(l.error().is_some());
        std::fs::remove_file(&blocker).unwrap();
        assert!(l.save(2).unwrap());
        assert!(l.error().is_none());
    }
}
