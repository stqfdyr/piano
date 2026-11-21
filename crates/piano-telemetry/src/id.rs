//! Identifiers that tie log records together.
//!
//! An id is 64 bits: the process start time in seconds in the high half and a counter in
//! the low half, so ids stay unique across restarts without a random source. Written as
//! 16 lowercase hex digits.

use std::fmt;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// A request or connection id.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Id(pub u64);

impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:016x}", self.0)
    }
}

static START: LazyLock<u64> = LazyLock::new(|| {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    (secs & 0xffff_ffff) << 32
});

static REQUESTS: AtomicU32 = AtomicU32::new(0);
static CONNECTIONS: AtomicU32 = AtomicU32::new(0);

fn next(counter: &AtomicU32) -> Id {
    let n = counter.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
    Id(*START | u64::from(n))
}

/// A fresh id for a request: one per HTTP/1 request or HTTP/2 stream.
pub fn request() -> Id {
    next(&REQUESTS)
}

/// A fresh id for a downstream connection that completed its TLS handshake.
pub fn connection() -> Id {
    next(&CONNECTIONS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_distinct_and_share_the_start() {
        let a = request();
        let b = request();
        assert_ne!(a, b);
        assert_eq!(a.0 >> 32, b.0 >> 32);
        assert_eq!(a.to_string().len(), 16);
        assert_eq!(Id(0xab).to_string(), "00000000000000ab");
        // The high half is the start time, which keeps ids apart across restarts.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!((a.0 >> 32).abs_diff(now & 0xffff_ffff) < 60);
        let c = connection();
        assert_ne!(c, connection());
        assert_eq!(c.0 >> 32, a.0 >> 32);
    }
}
