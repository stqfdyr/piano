//! The table of media streams being relayed, for live views.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// Why an upstream request of a stream started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Request {
    First,
    /// The body stalled; another request for the same bytes.
    Hedge,
    /// The previous request failed or ended early.
    Resume,
}

/// Marks a counter that has no value yet.
const UNSET: u64 = u64::MAX;

/// How soon after a try ended before its response head the same request counts as the
/// next try of one wait. Players ask again within a second of giving up and wait 9–17 s
/// each time; a request after a minute is a new wait.
const RETRY_WINDOW: Duration = Duration::from_secs(60);

/// Waits remembered at once. Each holds a capped path and Range, so this bounds the
/// table to a few hundred KiB; households have a handful of players.
const MAX_TRIES: usize = 256;

/// One media stream. The descriptive fields are fixed at registration; the counters
/// are updated while it runs.
#[derive(Debug)]
pub struct Stream {
    /// The request id, as logged.
    pub rid: String,
    pub site: String,
    pub client: Option<std::net::IpAddr>,
    /// Request target and Range header as the access log has them: credentials removed,
    /// length capped, so that a listing of all streams stays bounded.
    pub path: String,
    pub range: Option<String>,
    pub started: Instant,
    sent: AtomicU64,
    /// Upstream requests started for this stream: the first, hedges and resumes.
    requests: AtomicU32,
    hedges: AtomicU32,
    resumes: AtomicU32,
    /// Upstream requests in flight now.
    sources: AtomicU32,
    /// Milliseconds to the response head the client got; [`UNSET`] until then.
    ttfb_ms: AtomicU64,
    /// Milliseconds from the start to the last bytes written to the client.
    progress_ms: AtomicU64,
    /// Offset in the whole representation of the next byte for the client, and the
    /// representation's length, when the response says.
    position: AtomicU64,
    size: AtomicU64,
    /// Host of the upstream request the bytes come from.
    upstream: Mutex<Option<String>>,
    /// Bytes are waiting for the client to take them: a paused player or a slow link,
    /// rather than the upstream, holds the stream.
    writing: AtomicBool,
    /// Which try of the client this stream is (1 for the first), and when the first try
    /// started: a client that gives up before the response head asks again for the same
    /// bytes, and those requests are one wait for whoever watches.
    attempt: u32,
    first_try: Instant,
}

fn millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(UNSET - 1)
}

fn known(v: u64) -> Option<u64> {
    (v != UNSET).then_some(v)
}

impl Stream {
    pub fn new(
        rid: String,
        site: String,
        client: Option<std::net::IpAddr>,
        path: String,
        range: Option<String>,
    ) -> Self {
        Self {
            rid,
            site,
            client,
            path,
            range,
            started: Instant::now(),
            sent: AtomicU64::new(0),
            requests: AtomicU32::new(0),
            hedges: AtomicU32::new(0),
            resumes: AtomicU32::new(0),
            sources: AtomicU32::new(0),
            ttfb_ms: AtomicU64::new(UNSET),
            progress_ms: AtomicU64::new(0),
            position: AtomicU64::new(UNSET),
            size: AtomicU64::new(UNSET),
            upstream: Mutex::new(None),
            writing: AtomicBool::new(false),
            attempt: 1,
            first_try: Instant::now(),
        }
    }

    /// Marks the stream as try `attempt` of a wait that began at `first_try`.
    #[must_use]
    pub fn tried(mut self, attempt: u32, first_try: Instant) -> Self {
        self.attempt = attempt;
        self.first_try = first_try;
        self
    }

    pub fn attempt(&self) -> u32 {
        self.attempt
    }

    pub fn first_try(&self) -> Instant {
        self.first_try
    }

    pub fn set_writing(&self, on: bool) {
        self.writing.store(on, Ordering::Relaxed);
    }

    pub fn writing(&self) -> bool {
        self.writing.load(Ordering::Relaxed)
    }

    /// Counts body bytes written to the client.
    pub fn add_sent(&self, n: u64) {
        self.sent.fetch_add(n, Ordering::Relaxed);
        let _ = self
            .position
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |p| {
                known(p).map(|p| p.saturating_add(n))
            });
        self.progress_ms
            .store(millis(self.started.elapsed()), Ordering::Relaxed);
    }

    /// Body bytes written to the client so far.
    pub fn sent(&self) -> u64 {
        self.sent.load(Ordering::Relaxed)
    }

    pub fn add_request(&self, why: Request) {
        self.requests.fetch_add(1, Ordering::Relaxed);
        match why {
            Request::First => {}
            Request::Hedge => {
                self.hedges.fetch_add(1, Ordering::Relaxed);
            }
            Request::Resume => {
                self.resumes.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn requests(&self) -> u32 {
        self.requests.load(Ordering::Relaxed)
    }

    pub fn hedges(&self) -> u32 {
        self.hedges.load(Ordering::Relaxed)
    }

    pub fn resumes(&self) -> u32 {
        self.resumes.load(Ordering::Relaxed)
    }

    pub fn set_sources(&self, n: usize) {
        self.sources
            .store(u32::try_from(n).unwrap_or(u32::MAX), Ordering::Relaxed);
    }

    pub fn sources(&self) -> u32 {
        self.sources.load(Ordering::Relaxed)
    }

    pub fn set_ttfb(&self, d: Duration) {
        self.ttfb_ms.store(millis(d), Ordering::Relaxed);
    }

    pub fn ttfb(&self) -> Option<Duration> {
        known(self.ttfb_ms.load(Ordering::Relaxed)).map(Duration::from_millis)
    }

    /// Where the client's body starts in the representation and how long that is.
    pub fn set_span(&self, start: u64, size: Option<u64>) {
        self.position.store(start, Ordering::Relaxed);
        self.size.store(size.unwrap_or(UNSET), Ordering::Relaxed);
    }

    pub fn position(&self) -> Option<u64> {
        known(self.position.load(Ordering::Relaxed))
    }

    pub fn size(&self) -> Option<u64> {
        known(self.size.load(Ordering::Relaxed))
    }

    /// Time since bytes last reached the client, or since the start before any did.
    pub fn idle(&self) -> Duration {
        let last = Duration::from_millis(self.progress_ms.load(Ordering::Relaxed));
        self.started.elapsed().saturating_sub(last)
    }

    fn host(&self) -> MutexGuard<'_, Option<String>> {
        // A plain value; a panic elsewhere cannot leave it inconsistent.
        self.upstream.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn set_upstream(&self, host: &str) {
        let mut h = self.host();
        if h.as_deref() != Some(host) {
            *h = Some(host.to_owned());
        }
    }

    pub fn upstream(&self) -> Option<String> {
        self.host().clone()
    }
}

/// Streams being relayed; each is removed when its [`StreamGuard`] drops.
#[derive(Debug, Default)]
pub struct Streams {
    next: AtomicU64,
    table: Mutex<HashMap<u64, Arc<Stream>>>,
    /// Waits whose latest try ended before its response head, by [`try_key`].
    tries: Mutex<HashMap<String, Tried>>,
}

#[derive(Debug, Clone, Copy)]
struct Tried {
    attempt: u32,
    first: Instant,
    ended: Instant,
}

/// What makes two requests tries of one wait: the same client asking the same site for
/// the same target and range. `path` and `range` are as logged, credentials removed.
pub fn try_key(
    client: Option<std::net::IpAddr>,
    site: &str,
    path: &str,
    range: Option<&str>,
) -> String {
    let client = client.map(|c| c.to_string()).unwrap_or_default();
    format!("{client} {site} {} {path}", range.unwrap_or("-"))
}

impl Streams {
    pub fn register(self: &Arc<Self>, stream: Stream) -> StreamGuard {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let stream = Arc::new(stream);
        self.lock().insert(id, Arc::clone(&stream));
        StreamGuard {
            streams: Arc::clone(self),
            id,
            stream,
        }
    }

    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Which try a new request for `key` is, and when its wait began.
    pub fn next_try(&self, key: &str, now: Instant) -> (u32, Instant) {
        match self.tries().get(key) {
            Some(t) if now.saturating_duration_since(t.ended) <= RETRY_WINDOW => {
                (t.attempt.saturating_add(1), t.first)
            }
            _ => (1, now),
        }
    }

    /// Notes that try `attempt` of the wait for `key` that began at `first` ended
    /// before its response head.
    pub fn gave_up(&self, key: String, attempt: u32, first: Instant, now: Instant) {
        let mut tries = self.tries();
        if tries.len() >= MAX_TRIES && !tries.contains_key(&key) {
            tries.retain(|_, t| now.saturating_duration_since(t.ended) <= RETRY_WINDOW);
            if tries.len() >= MAX_TRIES {
                let oldest = tries
                    .iter()
                    .min_by_key(|(_, t)| t.ended)
                    .map(|(k, _)| k.clone());
                if let Some(k) = oldest {
                    tries.remove(&k);
                }
            }
        }
        tries.insert(
            key,
            Tried {
                attempt,
                first,
                ended: now,
            },
        );
    }

    /// Ends the wait for `key`: a try got its response head.
    pub fn answered(&self, key: &str) {
        self.tries().remove(key);
    }

    fn tries(&self) -> MutexGuard<'_, HashMap<String, Tried>> {
        // Plain data, as the table.
        self.tries.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The streams running now, oldest first.
    pub fn snapshot(&self) -> Vec<Arc<Stream>> {
        let mut all: Vec<Arc<Stream>> = self.lock().values().cloned().collect();
        all.sort_by_key(|s| s.started);
        all
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<u64, Arc<Stream>>> {
        // The map holds plain data, so a panic elsewhere cannot leave it inconsistent.
        self.table.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Keeps a stream in the table while it lives.
#[derive(Debug)]
pub struct StreamGuard {
    streams: Arc<Streams>,
    id: u64,
    stream: Arc<Stream>,
}

impl std::ops::Deref for StreamGuard {
    type Target = Stream;

    fn deref(&self) -> &Stream {
        &self.stream
    }
}

impl Drop for StreamGuard {
    fn drop(&mut self) {
        self.streams.lock().remove(&self.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guards_keep_streams_listed() {
        let streams = Arc::new(Streams::default());
        let a = streams.register(Stream::new("1".into(), "s".into(), None, "/a".into(), None));
        let b = streams.register(Stream::new("2".into(), "s".into(), None, "/b".into(), None));
        a.add_sent(10);
        a.add_request(Request::First);
        assert_eq!(a.ttfb(), None);
        a.set_ttfb(Duration::from_millis(5));
        assert_eq!(a.ttfb(), Some(Duration::from_millis(5)));
        let snap = streams.snapshot();
        assert_eq!(snap.len(), 2);
        assert_eq!(
            (snap[0].path.as_str(), snap[0].sent(), snap[0].requests()),
            ("/a", 10, 1)
        );
        drop(a);
        assert_eq!(streams.len(), 1);
        drop(b);
        assert!(streams.is_empty());
    }

    #[test]
    fn tries_of_one_wait_are_counted_until_one_is_answered() {
        let streams = Streams::default();
        let t0 = Instant::now();
        let key = try_key(None, "s", "/v", Some("bytes=5-"));
        assert_eq!(streams.next_try(&key, t0), (1, t0));
        streams.gave_up(key.clone(), 1, t0, t0 + Duration::from_secs(9));
        let t1 = t0 + Duration::from_secs(10);
        assert_eq!(streams.next_try(&key, t1), (2, t0));
        assert_eq!(
            streams.next_try(&try_key(None, "s", "/v", Some("bytes=6-")), t1),
            (1, t1),
            "another range is another wait"
        );
        streams.gave_up(key.clone(), 2, t0, t1 + Duration::from_secs(9));
        let late = t1 + Duration::from_secs(9) + RETRY_WINDOW + Duration::from_secs(1);
        assert_eq!(
            streams.next_try(&key, late),
            (1, late),
            "a new wait after a minute"
        );
        streams.answered(&key);
        assert_eq!(streams.next_try(&key, t1), (1, t1));
    }

    #[test]
    fn the_tries_table_is_bounded() {
        let streams = Streams::default();
        let t0 = Instant::now();
        for i in 0..MAX_TRIES + 10 {
            let at = t0 + Duration::from_millis(i as u64);
            streams.gave_up(format!("k{i}"), 1, at, at);
        }
        assert_eq!(streams.tries().len(), MAX_TRIES);
        let at = t0 + Duration::from_secs(1);
        assert_eq!(streams.next_try("k0", at), (1, at), "the oldest made room");
        assert_eq!(streams.next_try(&format!("k{}", MAX_TRIES + 9), at).0, 2);
    }

    #[test]
    fn position_follows_the_bytes_sent() {
        let s = Stream::new("1".into(), "s".into(), None, "/a".into(), None);
        s.add_sent(5);
        assert_eq!(s.position(), None);
        s.set_span(100, Some(1000));
        s.add_sent(50);
        assert_eq!(
            (s.position(), s.size(), s.sent()),
            (Some(150), Some(1000), 55)
        );
        s.add_request(Request::First);
        s.add_request(Request::Hedge);
        s.add_request(Request::Resume);
        s.add_request(Request::Resume);
        assert_eq!((s.requests(), s.hedges(), s.resumes()), (4, 1, 2));
        assert_eq!(s.upstream(), None);
        s.set_upstream("cdn.example.com");
        assert_eq!(s.upstream().as_deref(), Some("cdn.example.com"));
        assert!(s.idle() < Duration::from_secs(1));
    }
}
