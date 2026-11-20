//! Time-to-first-byte histograms with fixed buckets.
//!
//! Upstream heads arrive 3 ms to 60 s after the request (the read timeout caps them) and
//! answers piano gives itself take under 2 ms, so the buckets span 1 ms to 65 s. Bounds
//! grow by √2, which keeps an interpolated percentile within about 19 % of the true
//! value. Recording is one atomic add; a histogram is 34 counters.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Buckets per histogram; the last one holds everything above the last bound.
pub const BUCKETS: usize = 34;

/// Upper bound of bucket `i`, in microseconds: 1 ms × 2^(i/2).
pub const BOUNDS_US: [u64; BUCKETS - 1] = bounds();

const fn bounds() -> [u64; BUCKETS - 1] {
    let mut b = [0; BUCKETS - 1];
    let mut i = 0;
    while i < BUCKETS - 1 {
        b[i] = if i % 2 == 0 {
            1000 << (i / 2)
        } else {
            (1_414_214 << (i / 2)) / 1000
        };
        i += 1;
    }
    b
}

/// Counts by bucket.
pub type Buckets = [u64; BUCKETS];

/// What a time to first byte is about; requests of other kinds are not timed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ttfb {
    /// GET requests of the API, server information and playback information: what a
    /// client waits for while browsing.
    Browse,
    Image,
    /// The first byte of a media stream: the wait before playback starts.
    Media,
}

impl Ttfb {
    pub const ALL: [Ttfb; 3] = [Ttfb::Browse, Ttfb::Image, Ttfb::Media];

    pub fn as_str(self) -> &'static str {
        match self {
            Ttfb::Browse => "browse",
            Ttfb::Image => "image",
            Ttfb::Media => "media",
        }
    }

    pub(crate) fn index(self) -> usize {
        self as usize
    }
}

/// The bucket `d` falls in.
pub fn bucket(d: Duration) -> usize {
    let us = d.as_micros();
    BOUNDS_US.partition_point(|&b| u128::from(b) < us)
}

#[derive(Debug)]
pub struct Histogram {
    counts: [AtomicU64; BUCKETS],
}

impl Default for Histogram {
    fn default() -> Self {
        Self {
            counts: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }
}

impl Histogram {
    pub fn record(&self, d: Duration) {
        self.counts[bucket(d)].fetch_add(1, Ordering::Relaxed);
    }

    pub fn read(&self) -> Buckets {
        self.counts.each_ref().map(|a| a.load(Ordering::Relaxed))
    }
}

/// What was added between `earlier` and `later`.
pub fn since(later: &Buckets, earlier: &Buckets) -> Buckets {
    std::array::from_fn(|i| later[i].saturating_sub(earlier[i]))
}

/// The `q` quantile (0 to 1) of the values counted in `counts`, interpolated within its
/// bucket on a log scale (linearly in the first). `None` without values or when
/// `counts` does not have [`BUCKETS`] entries. Values past the last bound read as
/// that bound.
pub fn quantile(counts: &[u64], q: f64) -> Option<Duration> {
    if counts.len() != BUCKETS {
        return None;
    }
    let total: u64 = counts.iter().sum();
    if total == 0 {
        return None;
    }
    let rank = (q.clamp(0.0, 1.0) * total as f64).max(1.0);
    let mut below = 0u64;
    for (i, &n) in counts.iter().enumerate() {
        if n == 0 {
            continue;
        }
        if (below + n) as f64 >= rank {
            let Some(&hi) = BOUNDS_US.get(i) else {
                return Some(Duration::from_micros(BOUNDS_US[BUCKETS - 2]));
            };
            let hi = hi as f64;
            let frac = (rank - below as f64) / n as f64;
            let us = match i {
                0 => hi * frac,
                _ => {
                    let lo = BOUNDS_US[i - 1] as f64;
                    lo * (hi / lo).powf(frac)
                }
            };
            return Some(Duration::from_micros(us as u64));
        }
        below += n;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn bounds_double_every_two_buckets() {
        assert_eq!(BOUNDS_US[0], 1000);
        assert_eq!(BOUNDS_US[1], 1414);
        assert_eq!(BOUNDS_US[2], 2000);
        assert_eq!(BOUNDS_US[20], 1_024_000);
        assert_eq!(BOUNDS_US[32], 65_536_000);
        assert!(BOUNDS_US.windows(2).all(|w| w[0] < w[1]));
    }

    #[test]
    fn values_land_in_the_bucket_their_bound_covers() {
        assert_eq!(bucket(Duration::ZERO), 0);
        assert_eq!(bucket(ms(1)), 0);
        assert_eq!(bucket(Duration::from_micros(1001)), 1);
        assert_eq!(bucket(ms(3)), 4);
        assert_eq!(bucket(ms(65_536)), 32);
        assert_eq!(bucket(ms(70_000)), 33);
    }

    #[test]
    fn quantiles_stay_within_a_bucket_of_the_truth() {
        let h = Histogram::default();
        for v in 1..=1000u64 {
            h.record(ms(v));
        }
        let b = h.read();
        for (q, truth) in [(0.5, 500.0), (0.95, 950.0), (0.99, 990.0)] {
            let got = quantile(&b, q).unwrap().as_secs_f64() * 1000.0;
            assert!((got / truth - 1.0).abs() < 0.2, "q{q}: {got} ms");
        }
        assert_eq!(quantile(&[0; BUCKETS], 0.5), None);
        assert_eq!(quantile(&[1, 2], 0.5), None);
    }

    #[test]
    fn overflow_reads_as_the_last_bound() {
        let h = Histogram::default();
        h.record(ms(90_000));
        assert_eq!(quantile(&h.read(), 0.5), Some(ms(65_536)));
    }

    #[test]
    fn differences_count_what_came_later() {
        let h = Histogram::default();
        h.record(ms(5));
        let a = h.read();
        h.record(ms(5));
        h.record(ms(500));
        let d = since(&h.read(), &a);
        assert_eq!(d.iter().sum::<u64>(), 2);
        assert_eq!(d[bucket(ms(5))], 1);
    }
}
