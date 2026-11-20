//! The request budget of one upstream: a token bucket mirroring the upstream's own rate
//! limit, so that images queue in the relay instead of using up the limit that browsing
//! and playback share with them.

use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Share of the bucket that image requests leave to other requests. Browsing issues up
/// to about 90 API requests in 10 s (99th percentile at both relays); with the upstream
/// refilling 2–3 a second, a quarter of a 200-request bucket covers that.
const RESERVE: f64 = 0.25;

/// An upstream's request limit: `burst` requests at once, refilled at `per_sec`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Rate {
    pub burst: f64,
    pub per_sec: f64,
}

/// Whether an image request may go upstream now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wait {
    Go,
    /// Not before this much time has passed.
    For(Duration),
}

/// A snapshot for status output.
#[derive(Debug, Clone, PartialEq)]
pub struct BudgetState {
    pub rate: Option<Rate>,
    /// Requests the bucket allows now; negative after other requests overdrew it.
    pub tokens: f64,
    /// Time left of a pause the upstream asked for.
    pub paused_for: Option<Duration>,
    /// Times the upstream answered 429.
    pub limited: u64,
}

#[derive(Debug)]
struct Inner {
    rate: Option<Rate>,
    tokens: f64,
    at: Instant,
    paused_until: Option<Instant>,
    limited: u64,
}

impl Inner {
    fn refill(&mut self, now: Instant) {
        if let Some(r) = self.rate {
            let dt = now.saturating_duration_since(self.at).as_secs_f64();
            self.tokens = (self.tokens + dt * r.per_sec).min(r.burst);
        }
        self.at = now;
    }

    fn paused_for(&self, now: Instant) -> Option<Duration> {
        self.paused_until
            .filter(|u| *u > now)
            .map(|u| u.duration_since(now))
    }
}

#[derive(Debug)]
pub struct Budget {
    inner: Mutex<Inner>,
}

impl Budget {
    /// Without a rate, only pauses the upstream asks for hold image requests back.
    pub fn new(rate: Option<Rate>, now: Instant) -> Self {
        Self {
            inner: Mutex::new(Inner {
                rate,
                tokens: rate.map_or(0.0, |r| r.burst),
                at: now,
                paused_until: None,
                limited: 0,
            }),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        // Plain numbers; a panic elsewhere cannot leave them inconsistent.
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Changes the rate, keeping what was spent.
    pub fn set_rate(&self, rate: Option<Rate>, now: Instant) {
        let mut s = self.lock();
        if s.rate == rate {
            return;
        }
        s.refill(now);
        s.tokens = match (s.rate, rate) {
            (_, None) => 0.0,
            (None, Some(r)) => r.burst,
            (Some(_), Some(r)) => s.tokens.min(r.burst),
        };
        s.rate = rate;
    }

    /// Counts a request that is not an image, which goes upstream whatever the budget.
    pub fn charge(&self, now: Instant) {
        let mut s = self.lock();
        let Some(r) = s.rate else {
            return;
        };
        s.refill(now);
        s.tokens = (s.tokens - 1.0).max(-r.burst);
    }

    /// Takes a token for an image request if one is spare beyond the reserve.
    pub fn admit(&self, now: Instant) -> Wait {
        let mut s = self.lock();
        if let Some(d) = s.paused_for(now) {
            return Wait::For(d);
        }
        let Some(r) = s.rate else {
            return Wait::Go;
        };
        s.refill(now);
        let floor = r.burst * RESERVE + 1.0;
        if s.tokens >= floor {
            s.tokens -= 1.0;
            return Wait::Go;
        }
        Wait::For(Duration::from_secs_f64((floor - s.tokens) / r.per_sec))
    }

    /// How long image requests that cost the upstream nothing must still wait: a request
    /// during a pause would only prolong it.
    pub fn paused_for(&self, now: Instant) -> Option<Duration> {
        self.lock().paused_for(now)
    }

    /// The upstream answered 429: no image requests for `d`, and the bucket empties.
    pub fn pause(&self, now: Instant, d: Duration) {
        let mut s = self.lock();
        s.refill(now);
        let until = now + d;
        s.paused_until = Some(s.paused_until.map_or(until, |u| u.max(until)));
        s.tokens = s.tokens.min(0.0);
        s.limited += 1;
    }

    pub fn state(&self, now: Instant) -> BudgetState {
        let mut s = self.lock();
        s.refill(now);
        BudgetState {
            rate: s.rate,
            tokens: s.tokens,
            paused_for: s.paused_for(now),
            limited: s.limited,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RATE: Rate = Rate {
        burst: 8.0,
        per_sec: 2.0,
    };

    fn secs(s: f64) -> Duration {
        Duration::from_secs_f64(s)
    }

    #[test]
    fn images_leave_the_reserve_to_other_requests() {
        let t = Instant::now();
        let b = Budget::new(Some(RATE), t);
        // Reserve 2 of 8: six images go at once.
        for _ in 0..6 {
            assert_eq!(b.admit(t), Wait::Go);
        }
        assert_eq!(b.admit(t), Wait::For(secs(0.5)));
        // Other requests still go and may overdraw.
        b.charge(t);
        b.charge(t);
        assert_eq!(b.state(t).tokens, 0.0);
        assert_eq!(b.admit(t), Wait::For(secs(1.5)));
        assert_eq!(b.admit(t + secs(1.5)), Wait::Go);
        for _ in 0..20 {
            b.charge(t + secs(1.5));
        }
        assert_eq!(b.state(t + secs(1.5)).tokens, -8.0, "debt is bounded");
    }

    #[test]
    fn a_pause_holds_images_and_empties_the_bucket() {
        let t = Instant::now();
        let b = Budget::new(Some(RATE), t);
        b.pause(t, secs(10.0));
        assert_eq!(b.admit(t + secs(4.0)), Wait::For(secs(6.0)));
        assert_eq!(b.paused_for(t + secs(4.0)), Some(secs(6.0)));
        b.pause(t + secs(1.0), secs(2.0));
        assert_eq!(
            b.paused_for(t + secs(4.0)),
            Some(secs(6.0)),
            "a shorter pause does not cut a longer one"
        );
        // After the pause the bucket refilled from zero at the pause: 10 s × 2/s, capped.
        assert_eq!(b.admit(t + secs(10.0)), Wait::Go);
        assert_eq!(b.state(t + secs(10.0)).limited, 2);
    }

    #[test]
    fn without_a_rate_only_pauses_count() {
        let t = Instant::now();
        let b = Budget::new(None, t);
        for _ in 0..1000 {
            b.charge(t);
            assert_eq!(b.admit(t), Wait::Go);
        }
        b.pause(t, secs(1.0));
        assert_eq!(b.admit(t), Wait::For(secs(1.0)));
        assert_eq!(b.admit(t + secs(1.0)), Wait::Go);
    }

    #[test]
    fn changing_the_rate_keeps_what_was_spent() {
        let t = Instant::now();
        let b = Budget::new(None, t);
        b.set_rate(Some(RATE), t);
        assert_eq!(b.state(t).tokens, 8.0);
        for _ in 0..6 {
            b.charge(t);
        }
        b.set_rate(
            Some(Rate {
                burst: 4.0,
                per_sec: 1.0,
            }),
            t,
        );
        assert_eq!(b.state(t).tokens, 2.0);
        b.set_rate(None, t);
        assert_eq!(b.admit(t), Wait::Go);
    }
}
