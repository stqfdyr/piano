//! Request and byte counters per site, and how they grew over the last hour.
//!
//! Requests add to plain atomic counters when they end; nothing is allocated or locked
//! on that path. Once a minute a snapshot is kept, so a reader can tell what happened
//! recently from what happened since start.

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use crate::latency::{self, Buckets, Histogram, Ttfb};

labelled! {
    /// How a request ended; logged as `end`.
    pub enum End {
        /// Finished normally, whatever status the upstream sent.
        Ok => "ok",
        ClientClosed => "client_closed",
        ClientTimeout => "client_timeout",
        /// A redirect the relay would not follow; the client got 502.
        RedirectRefused => "redirect_refused",
        ConnectTimeout => "connect_timeout",
        ConnectFailed => "connect_failed",
        UpstreamTimeout => "upstream_timeout",
        UpstreamClosed => "upstream_closed",
        UpstreamError => "upstream_error",
        /// Ended because the process stops: a media stream or websocket on terminate.
        Shutdown => "shutdown",
        Internal => "internal",
    }
}

impl End {
    /// Ends caused by the upstream side, which a client can do nothing about.
    pub fn is_upstream_failure(self) -> bool {
        matches!(
            self,
            End::RedirectRefused
                | End::ConnectTimeout
                | End::ConnectFailed
                | End::UpstreamTimeout
                | End::UpstreamClosed
                | End::UpstreamError
        )
    }
}

labelled! {
    /// What the bytes of a request carried, as traffic is broken down.
    pub enum Kind {
        Media => "media",
        Image => "image",
        Socket => "socket",
        /// API calls, subtitles and everything else.
        Other => "other",
    }
}

/// Byte counts by [`Kind::ALL`] index.
pub type ByKind = [u64; Kind::ALL.len()];

/// Labels of the status classes counted, by index: no response sent, then 1xx to 5xx.
pub const STATUS_CLASSES: [&str; 6] = ["none", "1xx", "2xx", "3xx", "4xx", "5xx"];

fn status_index(status: Option<u16>) -> usize {
    match status {
        Some(s @ 100..=599) => usize::from(s / 100),
        _ => 0,
    }
}

/// Counters of one site, added to as its requests end.
#[derive(Debug, Default)]
pub struct SiteCounters {
    requests: AtomicU64,
    status: [AtomicU64; STATUS_CLASSES.len()],
    ends: [AtomicU64; End::ALL.len()],
    attempts: AtomicU64,
    reused: AtomicU64,
    sent: [AtomicU64; Kind::ALL.len()],
    fetched: [AtomicU64; Kind::ALL.len()],
    ttfb: [Histogram; Ttfb::ALL.len()],
}

/// Time-to-first-byte histograms by [`Ttfb::ALL`] index.
pub type TtfbBuckets = [Buckets; Ttfb::ALL.len()];

impl SiteCounters {
    /// Counts a finished request: the status sent to the client, how it ended, its
    /// upstream attempts and how many of them used a pooled connection.
    pub fn record(&self, status: Option<u16>, end: End, attempts: usize, reused: usize) {
        self.requests.fetch_add(1, Ordering::Relaxed);
        self.status[status_index(status)].fetch_add(1, Ordering::Relaxed);
        self.ends[end.index()].fetch_add(1, Ordering::Relaxed);
        self.attempts.fetch_add(attempts as u64, Ordering::Relaxed);
        self.reused.fetch_add(reused as u64, Ordering::Relaxed);
    }

    /// Counts response body bytes written to a client.
    pub fn add_sent(&self, kind: Kind, n: u64) {
        self.sent[kind.index()].fetch_add(n, Ordering::Relaxed);
    }

    /// Counts response body bytes read from an upstream.
    pub fn add_fetched(&self, kind: Kind, n: u64) {
        self.fetched[kind.index()].fetch_add(n, Ordering::Relaxed);
    }

    /// Counts the time from a request to the response head its client got.
    pub fn record_ttfb(&self, kind: Ttfb, d: Duration) {
        self.ttfb[kind.index()].record(d);
    }

    pub fn ttfb(&self) -> TtfbBuckets {
        self.ttfb.each_ref().map(Histogram::read)
    }

    pub fn counts(&self) -> Counts {
        let load = |a: &AtomicU64| a.load(Ordering::Relaxed);
        Counts {
            requests: load(&self.requests),
            status: self.status.each_ref().map(load),
            ends: self.ends.each_ref().map(load),
            attempts: load(&self.attempts),
            reused: load(&self.reused),
            sent: self.sent.each_ref().map(load),
            fetched: self.fetched.each_ref().map(load),
        }
    }
}

/// A reading of [`SiteCounters`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    pub requests: u64,
    /// By [`STATUS_CLASSES`] index.
    pub status: [u64; STATUS_CLASSES.len()],
    /// By [`End::ALL`] index.
    pub ends: [u64; End::ALL.len()],
    /// Upstream attempts: redirects followed and retries each add one.
    pub attempts: u64,
    /// Attempts that used a pooled connection.
    pub reused: u64,
    /// Response body bytes written to clients and read from upstreams. Request bodies
    /// are left out: clients send a few KiB at most.
    pub sent: ByKind,
    pub fetched: ByKind,
}

impl Counts {
    /// What was added between `earlier` and this reading.
    pub fn since(&self, earlier: &Counts) -> Counts {
        let sub = |a: u64, b: u64| a.saturating_sub(b);
        Counts {
            requests: sub(self.requests, earlier.requests),
            status: std::array::from_fn(|i| sub(self.status[i], earlier.status[i])),
            ends: std::array::from_fn(|i| sub(self.ends[i], earlier.ends[i])),
            attempts: sub(self.attempts, earlier.attempts),
            reused: sub(self.reused, earlier.reused),
            sent: std::array::from_fn(|i| sub(self.sent[i], earlier.sent[i])),
            fetched: std::array::from_fn(|i| sub(self.fetched[i], earlier.fetched[i])),
        }
    }

    pub fn end(&self, end: End) -> u64 {
        self.ends[end.index()]
    }
}

/// How far back the recent counts reach.
pub const RECENT: Duration = Duration::from_secs(3600);

/// How often histograms are kept for the recent percentiles. Every five minutes keeps
/// about 13 sets per site instead of 61; the recent span is then 60 to 65 minutes.
const TTFB_EVERY: Duration = Duration::from_secs(300);

#[derive(Debug)]
struct Snapshot<T> {
    at: Instant,
    sites: BTreeMap<String, T>,
    unrouted: T,
}

/// Keeps `snap` and drops snapshots no longer needed: the newest one at least
/// [`RECENT`] old stays, with every later one.
fn keep<T>(history: &mut VecDeque<Snapshot<T>>, snap: Snapshot<T>) {
    let now = snap.at;
    history.push_back(snap);
    while history
        .get(1)
        .is_some_and(|s| now.saturating_duration_since(s.at) >= RECENT)
    {
        history.pop_front();
    }
}

/// Since-start and recent counts of one site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiteReport {
    pub name: String,
    pub total: Counts,
    /// Counts over [`Report::span`].
    pub recent: Counts,
    /// Time-to-first-byte histograms over [`Report::ttfb_span`].
    pub ttfb_recent: TtfbBuckets,
}

/// All counters, read at once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// How far back `recent` reaches: [`RECENT`] once the process has run that long.
    pub span: Duration,
    /// How far back `ttfb_recent` reaches, a little longer than `span`.
    pub ttfb_span: Duration,
    pub sites: Vec<SiteReport>,
    /// Requests for a host that is no site.
    pub unrouted: SiteReport,
}

/// The counters of every site by name, and their snapshots of the last hour. A site
/// keeps its counters across reloads as long as its name stays the same.
#[derive(Debug)]
pub struct Metrics {
    sites: Mutex<BTreeMap<String, Arc<SiteCounters>>>,
    unrouted: Arc<SiteCounters>,
    history: Mutex<VecDeque<Snapshot<Counts>>>,
    ttfb_history: Mutex<VecDeque<Snapshot<TtfbBuckets>>>,
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    pub fn new() -> Self {
        let m = Self {
            sites: Mutex::new(BTreeMap::new()),
            unrouted: Arc::new(SiteCounters::default()),
            history: Mutex::new(VecDeque::new()),
            ttfb_history: Mutex::new(VecDeque::new()),
        };
        m.tick();
        m
    }

    /// The counters of site `name`, created on first use.
    pub fn site(&self, name: &str) -> Arc<SiteCounters> {
        let mut sites = self.sites.lock().unwrap_or_else(PoisonError::into_inner);
        Arc::clone(sites.entry(name.to_owned()).or_default())
    }

    /// The counters of requests for a host that is no site.
    pub fn unrouted(&self) -> Arc<SiteCounters> {
        Arc::clone(&self.unrouted)
    }

    /// The counts of every site since start, by name.
    pub fn totals(&self) -> BTreeMap<String, Counts> {
        self.read().0
    }

    /// The counts and histograms of every site since start, by name.
    pub fn live(&self) -> BTreeMap<String, (Counts, TtfbBuckets)> {
        let sites = self.sites.lock().unwrap_or_else(PoisonError::into_inner);
        sites
            .iter()
            .map(|(n, c)| (n.clone(), (c.counts(), c.ttfb())))
            .collect()
    }

    fn read_ttfb(&self) -> BTreeMap<String, TtfbBuckets> {
        let sites = self.sites.lock().unwrap_or_else(PoisonError::into_inner);
        sites.iter().map(|(n, c)| (n.clone(), c.ttfb())).collect()
    }

    fn read(&self) -> (BTreeMap<String, Counts>, Counts) {
        let sites = self.sites.lock().unwrap_or_else(PoisonError::into_inner);
        let counts = sites.iter().map(|(n, c)| (n.clone(), c.counts())).collect();
        (counts, self.unrouted.counts())
    }

    /// Keeps a snapshot for the recent counts; call about once a minute. Keeps the
    /// newest snapshot at least [`RECENT`] old and every later one.
    pub fn tick(&self) {
        self.tick_at(Instant::now());
    }

    fn tick_at(&self, now: Instant) {
        let (sites, unrouted) = self.read();
        let mut history = self.history.lock().unwrap_or_else(PoisonError::into_inner);
        keep(
            &mut history,
            Snapshot {
                at: now,
                sites,
                unrouted,
            },
        );
        drop(history);
        let mut ttfb = self
            .ttfb_history
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let due = ttfb
            .back()
            .is_none_or(|s| now.saturating_duration_since(s.at) >= TTFB_EVERY);
        if due {
            let sites = self.read_ttfb();
            keep(
                &mut ttfb,
                Snapshot {
                    at: now,
                    sites,
                    unrouted: self.unrouted.ttfb(),
                },
            );
        }
    }

    pub fn report(&self) -> Report {
        self.report_at(Instant::now())
    }

    fn report_at(&self, now: Instant) -> Report {
        let (sites, unrouted) = self.read();
        let ttfb_now = self.read_ttfb();
        let history = self.history.lock().unwrap_or_else(PoisonError::into_inner);
        let ttfb_history = self
            .ttfb_history
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let base = history.front();
        let ttfb_base = ttfb_history.front();
        let span = base.map_or(Duration::ZERO, |b| now.saturating_duration_since(b.at));
        let ttfb_span = ttfb_base.map_or(Duration::ZERO, |b| now.saturating_duration_since(b.at));
        let zero = Counts::default();
        let no_ttfb: TtfbBuckets = [[0; latency::BUCKETS]; Ttfb::ALL.len()];
        let sites = sites
            .into_iter()
            .map(|(name, total)| {
                let before = base.and_then(|b| b.sites.get(&name)).unwrap_or(&zero);
                let ttfb_before = ttfb_base
                    .and_then(|b| b.sites.get(&name))
                    .unwrap_or(&no_ttfb);
                let ttfb_total = ttfb_now.get(&name).unwrap_or(&no_ttfb);
                SiteReport {
                    recent: total.since(before),
                    ttfb_recent: std::array::from_fn(|i| {
                        latency::since(&ttfb_total[i], &ttfb_before[i])
                    }),
                    name,
                    total,
                }
            })
            .collect();
        let before = base.map_or(&zero, |b| &b.unrouted);
        Report {
            span,
            ttfb_span,
            sites,
            unrouted: SiteReport {
                name: String::new(),
                recent: unrouted.since(before),
                total: unrouted,
                ttfb_recent: no_ttfb,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_are_the_logged_and_stored_names() {
        // The access log's `end` and the traffic record's keys; renaming one breaks
        // readers of old lines and files.
        assert_eq!(
            End::ALL.map(End::as_str),
            [
                "ok",
                "client_closed",
                "client_timeout",
                "redirect_refused",
                "connect_timeout",
                "connect_failed",
                "upstream_timeout",
                "upstream_closed",
                "upstream_error",
                "shutdown",
                "internal",
            ]
        );
        assert_eq!(
            Kind::ALL.map(Kind::as_str),
            ["media", "image", "socket", "other"]
        );
        assert_eq!(Ttfb::ALL.map(Ttfb::as_str), ["browse", "image", "media"]);
        for (i, e) in End::ALL.iter().enumerate() {
            assert_eq!(e.index(), i);
        }
    }

    #[test]
    fn bytes_add_up_by_kind_and_recent_ones_subtract() {
        let m = Metrics::new();
        let t0 = Instant::now();
        let a = m.site("a");
        a.add_sent(Kind::Media, 100);
        a.add_fetched(Kind::Media, 150);
        a.add_sent(Kind::Image, 7);
        m.tick_at(t0 + Duration::from_secs(1));
        a.add_sent(Kind::Media, 10);
        m.tick_at(t0 + RECENT + Duration::from_secs(2));
        let r = m.report_at(t0 + RECENT + Duration::from_secs(3));
        assert_eq!(r.sites[0].total.sent, [110, 7, 0, 0]);
        assert_eq!(r.sites[0].total.fetched, [150, 0, 0, 0]);
        assert_eq!(r.sites[0].recent.sent, [10, 0, 0, 0]);
        assert_eq!(m.totals()["a"].sent, [110, 7, 0, 0]);
    }

    #[test]
    fn records_status_class_end_and_attempts() {
        let c = SiteCounters::default();
        c.record(Some(206), End::Ok, 1, 1);
        c.record(Some(502), End::RedirectRefused, 2, 0);
        c.record(None, End::ClientClosed, 1, 0);
        c.record(Some(101), End::Ok, 1, 0);
        let n = c.counts();
        assert_eq!(n.requests, 4);
        assert_eq!(n.status, [1, 1, 1, 0, 0, 1]);
        assert_eq!(n.end(End::Ok), 2);
        assert_eq!(n.end(End::RedirectRefused), 1);
        assert_eq!(n.end(End::ClientClosed), 1);
        assert_eq!((n.attempts, n.reused), (5, 1));
    }

    #[test]
    fn recent_counts_start_from_the_snapshot_an_hour_back() {
        let m = Metrics::new();
        let t0 = Instant::now();
        let a = m.site("a");
        a.record(Some(200), End::Ok, 1, 0);
        // Snapshots every minute for 70 minutes, one request after each.
        for minute in 1..=70u64 {
            m.tick_at(t0 + Duration::from_secs(minute * 60));
            a.record(Some(200), End::Ok, 1, 1);
        }
        let now = t0 + Duration::from_secs(70 * 60 + 30);
        let r = m.report_at(now);
        assert_eq!(r.span, Duration::from_secs(60 * 60 + 30));
        let a = &r.sites[0];
        assert_eq!(a.name, "a");
        assert_eq!(a.total.requests, 71);
        // Requests after the ticks of minutes 10 to 70.
        assert_eq!(a.recent.requests, 61);
        assert_eq!(a.recent.reused, 61);
    }

    #[test]
    fn a_site_added_later_counts_everything_as_recent() {
        let m = Metrics::new();
        m.tick();
        m.site("late").record(Some(404), End::Ok, 1, 0);
        m.unrouted().record(Some(421), End::Ok, 0, 0);
        let r = m.report();
        assert_eq!(r.sites[0].recent.requests, 1);
        assert_eq!(r.sites[0].recent.status[4], 1);
        assert_eq!(r.unrouted.recent.requests, 1);
    }

    #[test]
    fn recent_histograms_come_from_snapshots_five_minutes_apart() {
        let m = Metrics::new();
        let t0 = Instant::now();
        let a = m.site("a");
        a.record_ttfb(Ttfb::Media, Duration::from_millis(200));
        for minute in 1..=72u64 {
            m.tick_at(t0 + Duration::from_secs(minute * 60));
            a.record_ttfb(Ttfb::Browse, Duration::from_millis(50));
        }
        let r = m.report_at(t0 + Duration::from_secs(72 * 60 + 30));
        // Histograms kept at minutes 0, 5, … 70; the newest an hour old is minute 10,
        // where one kept every minute would give minute 12.
        assert_eq!(r.ttfb_span, Duration::from_secs(62 * 60 + 30));
        let recent = &r.sites[0].ttfb_recent;
        // Recorded after the ticks of minutes 10 to 72.
        assert_eq!(recent[Ttfb::Browse.index()].iter().sum::<u64>(), 63);
        assert_eq!(recent[Ttfb::Media.index()].iter().sum::<u64>(), 0);
        assert_eq!(a.ttfb()[Ttfb::Media.index()].iter().sum::<u64>(), 1);
    }

    #[test]
    fn counters_survive_lookup_by_the_same_name() {
        let m = Metrics::new();
        m.site("a").record(Some(200), End::Ok, 1, 0);
        m.site("a").record(Some(200), End::Ok, 1, 0);
        assert_eq!(m.report().sites[0].total.requests, 2);
    }
}
