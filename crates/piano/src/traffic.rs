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
    #[error("{path}: not a traffic record ({why}) and cannot be moved aside: {source}")]
    Stuck {
        path: String,
        why: serde_json::Error,
        source: std::io::Error,
    },
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
/// over it, so a crash leaves either the old or the new record. The directory exists.
fn write_atomically(path: &Path, record: &Record) -> Result<(), Error> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let text = serde_json::to_vec(record).map_err(|e| io(path, e.into()))?;
    let mut f = std::fs::File::create(&tmp).map_err(|e| io(&tmp, e))?;
    f.write_all(&text).map_err(|e| io(&tmp, e))?;
    f.sync_all().map_err(|e| io(&tmp, e))?;
    std::fs::rename(&tmp, path).map_err(|e| io(path, e))?;
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty())
        && let Ok(d) = std::fs::File::open(dir)
    {
        // Makes the rename itself durable; a failure leaves the old record at worst.
        let _ = d.sync_all();
    }
    Ok(())
}

#[derive(Debug)]
struct State {
    /// Additions not written yet; a write adds them to the file as it is then, which
    /// another process (one draining after an upgrade) may have written too.
    pending: BTreeMap<String, BTreeMap<String, SiteBytes>>,
    /// Days before this one are dropped.
    cutoff: Option<NaiveDate>,
    /// Counter readings already added, by site.
    seen: BTreeMap<String, (ByKind, ByKind)>,
    /// The cutoff moved since the last write, so the file holds days to drop.
    prune_due: bool,
}

/// The record of a running daemon.
#[derive(Debug)]
pub struct Ledger {
    path: Option<PathBuf>,
    /// Held across the file IO of a write.
    state: Mutex<State>,
    /// Why the file cannot be read or written, until a write succeeds. Apart from
    /// `state` so that `status` never waits for a write.
    error: Mutex<Option<String>>,
}

impl Ledger {
    /// Keeps the record at `path`, or none when it is `None`, and writes it at once so that
    /// problems show at startup (see [`merge_into_file`]). `now` is Unix seconds. Returns
    /// what went wrong, to be logged.
    pub fn open(path: Option<&Path>, now: u64) -> (Self, Option<String>) {
        let (warning, error) = match path.map(|p| merge_into_file(p, &BTreeMap::new(), None, now)) {
            None | Some(Ok(None)) => (None, None),
            Some(Ok(Some(moved))) => (Some(moved), None),
            Some(Err(e)) => (
                Some(format!("{e}; nothing is written until that is fixed")),
                Some(e.to_string()),
            ),
        };
        let ledger = Self {
            path: path.map(Path::to_owned),
            state: Mutex::new(State {
                pending: BTreeMap::new(),
                cutoff: None,
                seen: BTreeMap::new(),
                prune_due: false,
            }),
            error: Mutex::new(error),
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
            st.pending
                .entry(day.clone())
                .or_default()
                .entry(site.clone())
                .or_default()
                .add(&gained);
        }
        let cutoff = date.checked_sub_days(Days::new(KEEP_DAYS));
        if cutoff != st.cutoff {
            st.cutoff = cutoff;
            st.prune_due = true;
        }
        prune(&mut st.pending, st.cutoff);
    }

    /// Writes the additions since the last write, if there are any, days fell out of
    /// [`KEEP_DAYS`] or the last attempt failed. `now` is Unix seconds.
    pub fn save(&self, now: u64) -> Result<bool, Error> {
        let Some(path) = &self.path else {
            return Ok(false);
        };
        let mut st = self.state();
        if st.pending.is_empty() && !st.prune_due && self.error().is_none() {
            return Ok(false);
        }
        match merge_into_file(path, &st.pending, st.cutoff, now) {
            Ok(moved) => {
                if let Some(moved) = moved {
                    log::warn!("traffic record {moved}");
                }
                st.pending.clear();
                st.prune_due = false;
                self.set_error(None);
                Ok(true)
            }
            Err(e) => {
                self.set_error(Some(e.to_string()));
                Err(e)
            }
        }
    }

    /// Why the file cannot be read or written, until a write succeeds.
    pub fn error(&self) -> Option<String> {
        self.error
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn set_error(&self, error: Option<String>) {
        *self.error.lock().unwrap_or_else(PoisonError::into_inner) = error;
    }
}

/// Drops the days before `cutoff` and keys that are not dates.
fn prune(days: &mut BTreeMap<String, BTreeMap<String, SiteBytes>>, cutoff: Option<NaiveDate>) {
    days.retain(|d, _| {
        NaiveDate::parse_from_str(d, "%Y-%m-%d").is_ok_and(|d| cutoff.is_none_or(|c| d > c))
    });
}

/// Adds `pending` to the record in the file at `path` and writes it, holding a lock
/// beside it so that two processes do not lose each other's additions. A file that is
/// not a record is moved aside to `<path>.bad` and a new record started; returns what
/// was done then. One that cannot be read, or that a newer version wrote, is left alone
/// and nothing is written.
fn merge_into_file(
    path: &Path,
    pending: &BTreeMap<String, BTreeMap<String, SiteBytes>>,
    cutoff: Option<NaiveDate>,
    now: u64,
) -> Result<Option<String>, Error> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir).map_err(|e| io(dir, e))?;
    }
    let mut lock_path = path.as_os_str().to_owned();
    lock_path.push(".lock");
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock_path)
        .map_err(|e| io(Path::new(&lock_path), e))?;
    lock.lock().map_err(|e| io(Path::new(&lock_path), e))?;
    let (mut record, moved) = match read(path) {
        Ok(r) => (r.unwrap_or_default(), None),
        Err(Error::Parse { path: p, source }) => {
            let mut bad = path.as_os_str().to_owned();
            bad.push(".bad");
            if let Err(e) = std::fs::rename(path, &bad) {
                return Err(Error::Stuck {
                    path: p,
                    why: source,
                    source: e,
                });
            }
            let moved = format!(
                "{p}: not a traffic record ({source}); moved to {} and started a new record",
                Path::new(&bad).display()
            );
            (Record::default(), Some(moved))
        }
        Err(e) => return Err(e),
    };
    for (day, sites) in pending {
        let into = record.days.entry(day.clone()).or_default();
        for (site, bytes) in sites {
            into.entry(site.clone()).or_default().add(bytes);
        }
    }
    prune(&mut record.days, cutoff);
    record.updated = now;
    write_atomically(path, &record)?;
    Ok(moved)
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
        let dir = Dir::new("gained");
        let path = dir.0.join("traffic.json");
        let (l, w) = Ledger::open(Some(&path), 0);
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
        assert!(l.save(1).unwrap());
        let r = read(&path).unwrap().unwrap();
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
    fn two_processes_writing_one_record_keep_both_additions() {
        let dir = Dir::new("two");
        let path = dir.0.join("traffic.json");
        let (old, _) = Ledger::open(Some(&path), 0);
        old.add(&totals(&[("a", [100, 0, 0, 0], [0; 4])]), day("2026-11-20"));
        assert!(old.save(1).unwrap());
        // The successor takes over the file, then both keep adding.
        let (new, _) = Ledger::open(Some(&path), 0);
        new.add(&totals(&[("a", [50, 0, 0, 0], [0; 4])]), day("2026-11-20"));
        old.add(&totals(&[("a", [130, 0, 0, 0], [0; 4])]), day("2026-11-20"));
        assert!(new.save(2).unwrap());
        assert!(old.save(3).unwrap());
        let r = read(&path).unwrap().unwrap();
        assert_eq!(r.days["2026-11-20"]["a"].sent.media, 180);
        assert_eq!(r.updated, 3);
    }

    #[test]
    fn days_older_than_kept_are_dropped() {
        let dir = Dir::new("old");
        let path = dir.0.join("traffic.json");
        let (l, _) = Ledger::open(Some(&path), 0);
        for (n, d) in [(1, "2026-09-19"), (2, "2026-09-20"), (3, "2026-11-20")] {
            l.add(&totals(&[("a", [n, 0, 0, 0], [0; 4])]), day(d));
            assert!(l.save(n).unwrap());
        }
        // 62 days kept, today included: 2026-11-20 back to 2026-09-20.
        let days: Vec<String> = read(&path).unwrap().unwrap().days.into_keys().collect();
        assert_eq!(days, ["2026-09-20", "2026-11-20"]);
    }

    #[test]
    fn a_new_day_drops_old_days_without_new_traffic() {
        let dir = Dir::new("newday");
        let path = dir.0.join("traffic.json");
        let (l, _) = Ledger::open(Some(&path), 0);
        l.add(&totals(&[("a", [1, 0, 0, 0], [0; 4])]), day("2026-09-20"));
        assert!(l.save(1).unwrap());
        l.add(&totals(&[("a", [1, 0, 0, 0], [0; 4])]), day("2026-09-20"));
        assert!(!l.save(2).unwrap());
        l.add(&totals(&[("a", [1, 0, 0, 0], [0; 4])]), day("2026-11-21"));
        assert!(l.save(3).unwrap());
        assert!(read(&path).unwrap().unwrap().days.is_empty());
    }

    #[test]
    fn saves_only_changes_and_reads_back_after_a_restart() {
        let dir = Dir::new("save");
        let path = dir.0.join("sub").join("traffic.json");
        let (l, w) = Ledger::open(Some(&path), 0);
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
        let (l, w) = Ledger::open(Some(&path), 0);
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
    fn an_unreadable_file_is_left_alone_until_it_can_be_read() {
        let dir = Dir::new("unreadable");
        let path = dir.0.join("traffic.json");
        // A directory where the file should be: it cannot be read as a record.
        std::fs::create_dir_all(&path).unwrap();
        let (l, w) = Ledger::open(Some(&path), 0);
        assert!(w.unwrap().contains("until that is fixed"));
        assert!(l.error().is_some());
        assert_eq!(l.path(), Some(path.as_path()));
        l.add(&totals(&[("a", [7, 0, 0, 0], [0; 4])]), day("2026-11-20"));
        assert!(l.save(1).is_err());
        assert!(path.is_dir());
        // Once it can be read, the additions made meanwhile are written.
        std::fs::remove_dir(&path).unwrap();
        assert!(l.save(2).unwrap());
        assert!(l.error().is_none());
        assert_eq!(
            read(&path).unwrap().unwrap().days["2026-11-20"]["a"]
                .sent
                .media,
            7
        );
    }

    #[test]
    fn the_error_is_read_while_a_write_waits_on_the_file() {
        let dir = Dir::new("waiting");
        let path = dir.0.join("traffic.json");
        let (l, _) = Ledger::open(Some(&path), 0);
        let l = std::sync::Arc::new(l);
        l.add(&totals(&[("a", [1, 0, 0, 0], [0; 4])]), day("2026-11-20"));
        // Another process holds the record, so the write waits with `state` held.
        let held = std::fs::File::open(dir.0.join("traffic.json.lock")).unwrap();
        held.lock().unwrap();
        let writer = std::thread::spawn({
            let l = std::sync::Arc::clone(&l);
            move || l.save(1).unwrap()
        });
        while !writer.is_finished() && l.state.try_lock().is_ok() {
            std::thread::yield_now();
        }
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn({
            let l = std::sync::Arc::clone(&l);
            move || tx.send(l.error()).unwrap()
        });
        let error = rx.recv_timeout(std::time::Duration::from_secs(5));
        drop(held);
        assert!(writer.join().unwrap());
        assert_eq!(error, Ok(None));
    }

    #[test]
    fn a_damaged_file_is_moved_aside() {
        let dir = Dir::new("bad");
        std::fs::create_dir_all(&dir.0).unwrap();
        let path = dir.0.join("traffic.json");
        let bad = dir.0.join("traffic.json.bad");
        std::fs::write(&path, r#"{"schema":1,"#).unwrap();
        let (l, w) = Ledger::open(Some(&path), 0);
        assert!(w.unwrap().contains("traffic.json.bad"));
        assert_eq!(std::fs::read_to_string(&bad).unwrap(), r#"{"schema":1,"#);
        assert!(read(&path).unwrap().is_some());

        // Damaged while running: moved aside by the next write.
        std::fs::write(&path, "x").unwrap();
        l.add(&totals(&[("a", [1, 0, 0, 0], [0; 4])]), day("2026-11-20"));
        assert!(l.save(1).unwrap());
        assert_eq!(std::fs::read_to_string(&bad).unwrap(), "x");
        let r = read(&path).unwrap().unwrap();
        assert_eq!(r.days["2026-11-20"]["a"].sent.media, 1);
    }

    #[test]
    fn a_record_of_a_newer_version_is_left_alone() {
        let dir = Dir::new("newer");
        std::fs::create_dir_all(&dir.0).unwrap();
        let path = dir.0.join("traffic.json");
        let newer = r#"{"schema":9,"updated":0,"days":{}}"#;
        std::fs::write(&path, newer).unwrap();
        let (l, w) = Ledger::open(Some(&path), 0);
        assert!(w.unwrap().contains("schema 9"));
        l.add(&totals(&[("a", [1, 0, 0, 0], [0; 4])]), day("2026-11-20"));
        assert!(l.save(1).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), newer);
        assert!(!dir.0.join("traffic.json.bad").exists());
    }

    #[test]
    fn a_failed_write_is_reported_until_one_succeeds() {
        let dir = Dir::new("fail");
        std::fs::create_dir_all(&dir.0).unwrap();
        let blocker = dir.0.join("blocker");
        let (l, w) = Ledger::open(Some(&blocker.join("traffic.json")), 0);
        assert!(w.is_none());
        // A file where the directory should be.
        std::fs::remove_dir_all(&blocker).unwrap();
        std::fs::write(&blocker, "").unwrap();
        l.add(&totals(&[("a", [1, 0, 0, 0], [0; 4])]), day("2026-11-20"));
        assert!(l.save(1).is_err());
        assert!(l.error().is_some());
        std::fs::remove_file(&blocker).unwrap();
        assert!(l.save(2).unwrap());
        assert!(l.error().is_none());
    }
}
