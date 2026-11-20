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

/// One media stream. The descriptive fields are fixed at registration; the counters
/// are updated while it runs.
#[derive(Debug)]
pub struct Stream {
    /// The request id, as logged.
    pub rid: String,
    pub site: String,
    pub client: Option<std::net::IpAddr>,
    /// Request target with credentials removed.
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
        }
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
