//! The table of media streams being relayed, for live views.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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
    /// Milliseconds to the response head the client got; `u64::MAX` until then.
    ttfb_ms: AtomicU64,
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
            ttfb_ms: AtomicU64::new(u64::MAX),
        }
    }

    pub fn add_sent(&self, n: u64) {
        self.sent.fetch_add(n, Ordering::Relaxed);
    }

    /// Body bytes written to the client so far.
    pub fn sent(&self) -> u64 {
        self.sent.load(Ordering::Relaxed)
    }

    pub fn add_request(&self) {
        self.requests.fetch_add(1, Ordering::Relaxed);
    }

    pub fn requests(&self) -> u32 {
        self.requests.load(Ordering::Relaxed)
    }

    pub fn set_ttfb(&self, d: Duration) {
        let ms = u64::try_from(d.as_millis()).unwrap_or(u64::MAX - 1);
        self.ttfb_ms.store(ms, Ordering::Relaxed);
    }

    pub fn ttfb(&self) -> Option<Duration> {
        match self.ttfb_ms.load(Ordering::Relaxed) {
            u64::MAX => None,
            ms => Some(Duration::from_millis(ms)),
        }
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

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<u64, Arc<Stream>>> {
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
        a.add_request();
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
}
