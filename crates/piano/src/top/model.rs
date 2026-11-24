//! What `piano top` shows, worked out from successive `live` replies: rates come from
//! the difference of two replies, recent counts and percentiles from the difference
//! with the reply about a minute older.

use crate::render::failed;
use piano_ctl::proto::{Counts, Live, StreamLive};
use piano_telemetry::{Ttfb, latency};
use serde_json::Value;
use std::collections::VecDeque;
use std::net::IpAddr;

/// Span of the recent counts and percentiles. Relays see a few requests a minute, so a
/// shorter span leaves percentiles without values most of the time.
pub const WINDOW_MS: u64 = 60_000;
/// Span of a stream's rate: long enough to smooth over 32 KiB reads.
const RATE_MS: u64 = 5_000;
/// A body without progress for this long counts as stalled; the media engine starts
/// another request at the same point.
pub const STALL_MS: u64 = 3_000;
/// Problems kept for display.
const PROBLEMS: usize = 100;

/// Replies of the last minute, oldest first.
#[derive(Debug, Default)]
pub struct History {
    samples: VecDeque<Live>,
}

impl History {
    /// Adds a reply. A reply from another process, or from a restarted one, starts over.
    pub fn push(&mut self, live: Live) {
        if let Some(last) = self.samples.back()
            && (last.pid != live.pid || live.uptime_ms < last.uptime_ms)
        {
            self.samples.clear();
        }
        let newest = live.uptime_ms;
        self.samples.push_back(live);
        while self
            .samples
            .get(1)
            .is_some_and(|s| newest.saturating_sub(s.uptime_ms) >= WINDOW_MS)
        {
            self.samples.pop_front();
        }
    }

    pub fn latest(&self) -> Option<&Live> {
        self.samples.back()
    }

    /// The newest reply at least `ms` older than the latest, else the oldest.
    fn ago(&self, ms: u64) -> Option<&Live> {
        let newest = self.latest()?.uptime_ms;
        self.samples
            .iter()
            .rev()
            .find(|s| newest.saturating_sub(s.uptime_ms) >= ms)
            .or_else(|| self.samples.front())
    }

    fn previous(&self) -> Option<&Live> {
        let n = self.samples.len();
        (n >= 2).then(|| &self.samples[n - 2])
    }

    /// Bytes per second written to clients between successive replies, oldest first.
    pub fn sent_series(&self) -> Vec<u64> {
        self.rates(|l| l.sites.iter().map(|s| s.total.bytes_sent).sum())
    }

    /// Per-second change of a counter between successive replies, oldest first.
    fn rates(&self, f: impl Fn(&Live) -> u64) -> Vec<u64> {
        self.samples
            .iter()
            .zip(self.samples.iter().skip(1))
            .map(|(a, b)| per_sec(f(b).saturating_sub(f(a)), b.uptime_ms - a.uptime_ms) as u64)
            .collect()
    }

    /// A level at each reply, oldest first.
    fn levels(&self, f: impl Fn(&Live) -> u64) -> Vec<u64> {
        self.samples.iter().map(f).collect()
    }

    /// Bytes per second a stream sent between successive replies that both list it,
    /// oldest first.
    fn stream_series(&self, rid: &str) -> Vec<u64> {
        let sent = |l: &Live| l.streams.iter().find(|s| s.rid == rid).map(|s| s.sent);
        self.samples
            .iter()
            .zip(self.samples.iter().skip(1))
            .filter_map(|(a, b)| {
                let (x, y) = (sent(a)?, sent(b)?);
                Some(per_sec(y.saturating_sub(x), b.uptime_ms - a.uptime_ms) as u64)
            })
            .collect()
    }
}

fn per_sec(n: u64, ms: u64) -> f64 {
    if ms == 0 {
        0.0
    } else {
        n as f64 * 1000.0 / ms as f64
    }
}

/// What a stream is doing.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum State {
    /// No response head yet: waited this many milliseconds since the client's first try,
    /// and this is its `attempt`-th try.
    Waiting {
        ms: u64,
        attempt: u32,
    },
    Playing,
    /// Bytes wait for the client: a paused player or a slow link.
    Held(u64),
    /// No body bytes from the upstream for this long; `hedging` when a second request is
    /// in flight.
    Stalled {
        ms: u64,
        hedging: bool,
    },
}

impl State {
    fn of(s: &StreamLive) -> Self {
        match s.ttfb_ms {
            None => State::Waiting {
                ms: s.waited_ms.max(s.age_ms),
                attempt: s.attempt,
            },
            Some(_) if s.idle_ms < STALL_MS => State::Playing,
            Some(_) if s.client_holds => State::Held(s.idle_ms),
            Some(_) => State::Stalled {
                ms: s.idle_ms,
                hedging: s.in_flight >= 2,
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct StreamRow {
    pub client: Option<String>,
    pub site: String,
    pub item: String,
    pub position: Option<u64>,
    pub size: Option<u64>,
    pub sent: u64,
    /// Bytes per second over the last few seconds.
    pub rate: f64,
    pub ttfb_ms: Option<u64>,
    pub state: State,
    pub hedges: u32,
    pub resumes: u32,
    pub upstream: Option<String>,
    pub age_ms: u64,
    /// Upstream requests made for the stream, and those in flight now.
    pub requests: u32,
    pub in_flight: u32,
    /// Which try of the client this is.
    pub attempt: u32,
    /// Offset in the file where this response began, when the position is known.
    pub start: Option<u64>,
    /// Bytes per second between successive replies, oldest first.
    pub series: Vec<u64>,
}

/// p50 and p95 in milliseconds.
pub type Percentiles = Option<(f64, f64)>;

#[derive(Debug, Clone, PartialEq)]
pub struct SiteRow {
    pub name: String,
    /// Over the window.
    pub requests: u64,
    /// 2xx to 5xx over the window.
    pub status: [u64; 4],
    pub failed: u64,
    /// Bytes per second between the last two replies.
    pub sent_rate: f64,
    pub fetched_rate: f64,
    /// By [`Ttfb::ALL`], over the window.
    pub ttfb: [Percentiles; 3],
    /// Time to first byte bucket counts by [`Ttfb::ALL`] over the window, as
    /// [`latency::BOUNDS_US`]; empty when the daemon sent none.
    pub histograms: [Vec<u64>; 3],
    /// Share of upstream attempts over the window that reused a pooled connection.
    pub reuse: Option<f64>,
    /// Media requests over the window whose client left before the response head, and
    /// those that got one.
    pub gave_up: u64,
    pub answered: u64,
    /// How requests over the window failed, most frequent first; normal ends left out.
    pub failures: Vec<(String, u64)>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BudgetRow {
    pub upstream: String,
    pub tokens: f64,
    pub burst: Option<f64>,
    pub waiting: u64,
    pub paused_secs: Option<f64>,
    /// Upstream 429 answers over the window.
    pub limited: u64,
    /// Requests the budget gains per second.
    pub per_sec: Option<f64>,
    /// Requests the budget allowed at each reply, oldest first.
    pub series: Vec<u64>,
}

/// Client connections: levels now, and counts over the window with their rates per reply.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Edge {
    pub open: u64,
    pub handshaking: u64,
    pub limit: u64,
    pub open_series: Vec<u64>,
    /// Handshakes that failed or timed out.
    pub failed: u64,
    pub failed_series: Vec<u64>,
    /// Refused by the allow list.
    pub denied: u64,
    pub denied_series: Vec<u64>,
    /// Closed because the limit was reached.
    pub closed: u64,
    pub closed_series: Vec<u64>,
}

/// What the image engine remembers, and how often that saved a request over the window.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Memory {
    /// Permanent redirects remembered now, and requests that went straight to one.
    pub redirects: u64,
    pub redirect_hits: u64,
    /// Upstream 404s remembered now.
    pub missing: u64,
}

/// Image requests over the window.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Images {
    pub answered: u64,
    /// Answered with a remembered miss: no upstream request.
    pub local: u64,
    pub fetched: u64,
    pub shared: u64,
    pub refused: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct View {
    pub version: String,
    pub uptime_secs: u64,
    pub connections: u64,
    /// Requests per second and body bytes per second, between the last two replies.
    pub requests_rate: f64,
    pub sent_rate: f64,
    pub fetched_rate: f64,
    /// How far back the recent counts reach, up to the window.
    pub window_secs: u64,
    pub streams: Vec<StreamRow>,
    pub sites: Vec<SiteRow>,
    pub budgets: Vec<BudgetRow>,
    pub images: Images,
    pub edge: Edge,
    pub memory: Memory,
    pub access_log: Option<String>,
}

fn status_delta(now: &Counts, then: Option<&Counts>, class: &str) -> u64 {
    now.status(class)
        .saturating_sub(then.map_or(0, |c| c.status(class)))
}

impl View {
    pub fn of(h: &History) -> Option<Self> {
        let now = h.latest()?;
        let prev = h.previous();
        // A daemon younger than the window counts from its start.
        let base = if now.uptime_ms <= WINDOW_MS {
            None
        } else {
            h.ago(WINDOW_MS)
        };
        let step_ms = prev.map_or(0, |p| now.uptime_ms - p.uptime_ms);
        let window_ms = base.map_or(now.uptime_ms, |b| now.uptime_ms - b.uptime_ms);
        let site_in = |l: Option<&Live>, name: &str| {
            l.and_then(|l| l.sites.iter().find(|s| s.name == name).cloned())
        };
        let total =
            |l: &Live, f: fn(&Counts) -> u64| l.sites.iter().map(|s| f(&s.total)).sum::<u64>();
        let rate = |f: fn(&Counts) -> u64| match prev {
            Some(p) => per_sec(total(now, f).saturating_sub(total(p, f)), step_ms),
            None => 0.0,
        };
        let sites = now
            .sites
            .iter()
            .map(|s| {
                let b = site_in(base, &s.name);
                let p = site_in(prev, &s.name);
                let bt = b.as_ref().map(|b| &b.total);
                let step = |f: fn(&Counts) -> u64| {
                    let before = p.as_ref().map_or(f(&s.total), |p| f(&p.total));
                    per_sec(f(&s.total).saturating_sub(before), step_ms)
                };
                let delta = |f: fn(&Counts) -> u64| f(&s.total).saturating_sub(bt.map_or(0, f));
                let histograms = Ttfb::ALL.map(|k| {
                    let Some(later) = s.ttfb.get(k.as_str()) else {
                        return Vec::new();
                    };
                    let earlier = b.as_ref().and_then(|b| b.ttfb.get(k.as_str()));
                    later
                        .iter()
                        .enumerate()
                        .map(|(i, n)| {
                            n.saturating_sub(earlier.and_then(|e| e.get(i)).copied().unwrap_or(0))
                        })
                        .collect::<Vec<u64>>()
                });
                let ttfb = histograms.each_ref().map(|d| {
                    let ms = |q| latency::quantile(d, q).map(|t| t.as_secs_f64() * 1000.0);
                    Some((ms(0.5)?, ms(0.95)?))
                });
                let attempts = delta(|c| c.upstream_attempts);
                let mut failures: Vec<(String, u64)> = s
                    .total
                    .ends
                    .iter()
                    .filter(|(end, _)| *end != "ok" && *end != "client_closed")
                    .map(|(end, &n)| {
                        let before = bt.and_then(|c| c.ends.get(end)).copied().unwrap_or(0);
                        (end.clone(), n.saturating_sub(before))
                    })
                    .filter(|(_, n)| *n > 0)
                    .collect();
                failures.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
                SiteRow {
                    name: s.name.clone(),
                    requests: s.total.requests - bt.map_or(0, |c| c.requests.min(s.total.requests)),
                    status: ["2xx", "3xx", "4xx", "5xx"].map(|c| status_delta(&s.total, bt, c)),
                    failed: failed(&s.total).saturating_sub(bt.map_or(0, failed)),
                    sent_rate: step(|c| c.bytes_sent),
                    fetched_rate: step(|c| c.bytes_fetched),
                    ttfb,
                    histograms,
                    reuse: (attempts > 0).then(|| delta(|c| c.reused) as f64 / attempts as f64),
                    gave_up: delta(|c| c.media_gave_up),
                    answered: delta(|c| c.media_answered),
                    failures,
                }
            })
            .collect();
        let rate_base = h.ago(RATE_MS);
        let streams = now
            .streams
            .iter()
            .map(|s| {
                let before = rate_base
                    .filter(|b| b.uptime_ms < now.uptime_ms)
                    .and_then(|b| b.streams.iter().find(|o| o.rid == s.rid).map(|o| (b, o)));
                let rate = match before {
                    Some((b, o)) => {
                        per_sec(s.sent.saturating_sub(o.sent), now.uptime_ms - b.uptime_ms)
                    }
                    None => per_sec(s.sent, s.age_ms),
                };
                StreamRow {
                    client: s.client.clone(),
                    site: s.site.clone(),
                    item: item(&s.path),
                    position: s.position,
                    size: s.size,
                    sent: s.sent,
                    rate,
                    ttfb_ms: s.ttfb_ms,
                    state: State::of(s),
                    hedges: s.hedges,
                    resumes: s.resumes,
                    upstream: s.upstream.clone(),
                    age_ms: s.age_ms,
                    requests: s.requests,
                    in_flight: s.in_flight,
                    attempt: s.attempt,
                    start: s.position.map(|p| p.saturating_sub(s.sent)),
                    series: h.stream_series(&s.rid),
                }
            })
            .collect();
        let limited_before = |u: &str| {
            base.and_then(|b| b.cache.upstreams.iter().find(|x| x.upstream == u))
                .map_or(0, |x| x.limited)
        };
        let budgets = now
            .cache
            .upstreams
            .iter()
            .map(|u| BudgetRow {
                upstream: u.upstream.clone(),
                tokens: u.tokens,
                burst: u.burst,
                waiting: u.waiting,
                paused_secs: u.paused_secs,
                limited: u.limited.saturating_sub(limited_before(&u.upstream)),
                per_sec: u.per_sec,
                series: h.levels(|l| {
                    l.cache
                        .upstreams
                        .iter()
                        .find(|x| x.upstream == u.upstream)
                        .map_or(0, |x| x.tokens.max(0.0).round() as u64)
                }),
            })
            .collect();
        let c = &now.cache;
        let d = |f: fn(&piano_ctl::proto::CacheStats) -> u64| {
            f(c).saturating_sub(base.map_or(0, |b| f(&b.cache)))
        };
        let images = Images {
            local: d(|c| c.missing_hits),
            fetched: d(|c| c.fetched),
            shared: d(|c| c.coalesced),
            refused: d(|c| c.shed),
            answered: 0,
        };
        let images = Images {
            answered: images.local + images.fetched + images.shared + images.refused,
            ..images
        };
        let conn = &now.connections;
        let since = |f: fn(&Live) -> u64| f(now).saturating_sub(base.map_or(0, f));
        let handshakes =
            |l: &Live| l.connections.handshake_errors + l.connections.handshake_timeouts;
        let edge = Edge {
            open: conn.open,
            handshaking: conn.handshaking,
            limit: conn.limit,
            open_series: h.levels(|l| l.connections.open),
            failed: since(handshakes),
            failed_series: h.rates(handshakes),
            denied: since(|l| l.connections.denied),
            denied_series: h.rates(|l| l.connections.denied),
            closed: since(|l| l.connections.closed_at_limit),
            closed_series: h.rates(|l| l.connections.closed_at_limit),
        };
        let memory = Memory {
            redirects: c.redirects,
            redirect_hits: d(|c| c.redirect_hits),
            missing: c.missing,
        };
        Some(View {
            version: now.version.clone(),
            uptime_secs: now.uptime_ms / 1000,
            connections: now.connections.open,
            requests_rate: rate(|c| c.requests),
            sent_rate: rate(|c| c.bytes_sent),
            fetched_rate: rate(|c| c.bytes_fetched),
            window_secs: window_ms / 1000,
            streams,
            sites,
            budgets,
            images,
            edge,
            memory,
            access_log: now.access_log.clone(),
        })
    }
}

/// The item a media path is about: the id after `videos`, `audio` or `items`, else
/// the last path segment.
pub fn item(path: &str) -> String {
    let path = path.split('?').next().unwrap_or(path);
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    for w in segs.windows(2) {
        if ["videos", "audio", "items"]
            .iter()
            .any(|k| w[0].eq_ignore_ascii_case(k))
        {
            return w[1].to_owned();
        }
    }
    segs.last().map_or_else(String::new, |s| (*s).to_owned())
}

/// A client address with only its network part: `203.0.*.*`, `2001:db8:…`.
pub fn mask(addr: &str) -> String {
    match addr.parse::<IpAddr>() {
        Ok(IpAddr::V4(a)) => {
            let o = a.octets();
            format!("{}.{}.*.*", o[0], o[1])
        }
        Ok(IpAddr::V6(a)) => {
            let s = a.segments();
            format!("{:x}:{:x}:…", s[0], s[1])
        }
        Err(_) => addr.to_owned(),
    }
}

/// A request from the access log that went wrong.
#[derive(Debug, Clone, PartialEq)]
pub struct Problem {
    /// UTC timestamp as logged.
    pub ts: String,
    pub site: String,
    pub status: Option<u64>,
    pub path: String,
    /// How it ended when not normally, with the error.
    pub end: Option<String>,
    pub err: Option<String>,
}

impl Problem {
    /// A line worth showing: failed on the upstream side or inside piano, or answered
    /// 5xx or 429. Clients closing streams, which players do on every seek, and 4xx
    /// answers that are the upstream's business are left out.
    pub fn of(raw: &str) -> Option<Self> {
        let v: Value = serde_json::from_str(raw).ok()?;
        let s = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_owned);
        let status = v.get("status").and_then(Value::as_u64);
        let end = s("end").filter(|e| e != "ok" && e != "client_closed");
        let bad_status = status.is_some_and(|c| c >= 500 || c == 429);
        if end.is_none() && !bad_status {
            return None;
        }
        Some(Self {
            ts: s("ts").unwrap_or_default(),
            site: s("site").unwrap_or_else(|| "-".into()),
            status,
            path: s("path").unwrap_or_default(),
            end,
            err: s("err"),
        })
    }
}

/// The newest problems, newest last.
#[derive(Debug, Default)]
pub struct Problems {
    pub list: VecDeque<Problem>,
    /// Added since the viewer last looked at them, at most the number kept.
    pub unseen: usize,
}

impl Problems {
    pub fn add(&mut self, raw: &str) {
        if let Some(p) = Problem::of(raw) {
            if self.list.len() == PROBLEMS {
                self.list.pop_front();
            }
            self.list.push_back(p);
            self.unseen = (self.unseen + 1).min(PROBLEMS);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use piano_ctl::proto::{CacheStats, Connections, SiteLive, UpstreamBudget};
    use std::collections::BTreeMap;

    fn counts(requests: u64, ok: u64, bad: u64, sent: u64) -> Counts {
        let mut c = Counts {
            requests,
            bytes_sent: sent,
            ..Counts::default()
        };
        c.status.insert("2xx".into(), ok);
        c.status.insert("5xx".into(), bad);
        c.ends.insert("upstream_error".into(), bad);
        c
    }

    fn stream(rid: &str, sent: u64, idle_ms: u64) -> StreamLive {
        StreamLive {
            rid: rid.into(),
            site: "a".into(),
            client: Some("2001:db8:1:2::7".into()),
            path: "/emby/videos/424242/stream.mkv?Static=true".into(),
            range: None,
            age_ms: 20_000,
            sent,
            position: Some(sent),
            size: Some(10_000_000),
            ttfb_ms: Some(180),
            idle_ms,
            requests: 2,
            hedges: 1,
            resumes: 0,
            in_flight: 1,
            client_holds: false,
            upstream: Some("cdn.example.com".into()),
            attempt: 1,
            waited_ms: 180,
        }
    }

    fn live(
        uptime_ms: u64,
        c: Counts,
        ttfb_ms: &[u64],
        streams: Vec<StreamLive>,
        limited: u64,
    ) -> Live {
        let mut browse = vec![0; latency::BUCKETS];
        for &t in ttfb_ms {
            browse[latency::bucket(std::time::Duration::from_millis(t))] += 1;
        }
        let ttfb: BTreeMap<String, Vec<u64>> = [
            ("browse".to_owned(), browse),
            ("image".to_owned(), vec![0; latency::BUCKETS]),
            ("media".to_owned(), vec![0; latency::BUCKETS]),
        ]
        .into();
        Live {
            schema: 2,
            version: "0.1.0".into(),
            pid: 7,
            uptime_ms,
            connections: Connections {
                open: 3,
                handshaking: 0,
                limit: 1024,
                closed_at_limit: 0,
                handshake_timeouts: 0,
                handshake_errors: 0,
                denied: 0,
                media_streams: streams.len() as u64,
            },
            access_log: None,
            ttfb_bounds_ms: Vec::new(),
            sites: vec![SiteLive {
                name: "a".into(),
                total: c,
                ttfb,
            }],
            streams,
            cache: CacheStats {
                schema: 2,
                missing: 0,
                redirects: 0,
                fetched: 0,
                coalesced: 0,
                missing_hits: 0,
                shed: 0,
                redirect_hits: 0,
                upstreams: vec![UpstreamBudget {
                    upstream: "emby.example.net:443".into(),
                    burst: Some(200.0),
                    per_sec: Some(2.5),
                    tokens: 150.0,
                    paused_secs: None,
                    limited,
                    waiting: 0,
                }],
            },
        }
    }

    #[test]
    fn rates_come_from_the_last_step_and_counts_from_the_window() {
        let mut h = History::default();
        // A minute and a half of replies, one a second: 1 request and 1 MiB each.
        for s in 0..=90u64 {
            let ttfb: Vec<u64> = (0..s).map(|i| 10 + i).collect();
            h.push(live(
                s * 1000,
                counts(s, s, 0, s << 20),
                &ttfb,
                Vec::new(),
                s / 10,
            ));
        }
        let v = View::of(&h).unwrap();
        assert_eq!(v.window_secs, 60);
        assert!((v.requests_rate - 1.0).abs() < 1e-9);
        assert!((v.sent_rate - f64::from(1u32 << 20)).abs() < 1.0);
        let a = &v.sites[0];
        assert_eq!((a.requests, a.status[0], a.failed), (60, 60, 0));
        // The window holds the values 40 to 99 ms.
        let (p50, p95) = a.ttfb[0].unwrap();
        assert!((60.0..85.0).contains(&p50), "{p50}");
        assert!((80.0..120.0).contains(&p95), "{p95}");
        assert_eq!(a.ttfb[1], None);
        assert_eq!(v.budgets[0].limited, 6);
        assert_eq!(h.sent_series().len(), 60);
    }

    #[test]
    fn a_restarted_daemon_starts_the_history_over() {
        let mut h = History::default();
        h.push(live(50_000, counts(100, 100, 0, 0), &[], Vec::new(), 0));
        h.push(live(1_000, counts(1, 0, 1, 0), &[], Vec::new(), 0));
        let v = View::of(&h).unwrap();
        assert_eq!(v.sites[0].requests, 1);
        assert_eq!(v.sites[0].failed, 1);
        assert_eq!(v.requests_rate, 0.0);
    }

    #[test]
    fn stream_rate_and_state() {
        let mut h = History::default();
        for s in 0..=10u64 {
            h.push(live(
                s * 1000,
                Counts::default(),
                &[],
                vec![stream("r", s * 1_000_000, 100)],
                0,
            ));
        }
        let v = View::of(&h).unwrap();
        let r = &v.streams[0];
        assert!((r.rate - 1_000_000.0).abs() < 1.0, "{}", r.rate);
        assert_eq!(r.item, "424242");
        assert_eq!(r.state, State::Playing);
        let mut s = stream("r", 0, 5000);
        assert_eq!(
            State::of(&s),
            State::Stalled {
                ms: 5000,
                hedging: false
            }
        );
        s.in_flight = 2;
        assert_eq!(
            State::of(&s),
            State::Stalled {
                ms: 5000,
                hedging: true
            }
        );
        s.client_holds = true;
        assert_eq!(State::of(&s), State::Held(5000));
        s.ttfb_ms = None;
        assert_eq!(
            State::of(&s),
            State::Waiting {
                ms: 20_000,
                attempt: 1
            }
        );
        // A later try counts from the first one.
        (s.attempt, s.waited_ms) = (3, 31_000);
        assert_eq!(
            State::of(&s),
            State::Waiting {
                ms: 31_000,
                attempt: 3
            }
        );
    }

    #[test]
    fn items_and_masks() {
        assert_eq!(item("/emby/Videos/42/stream.mkv?api_key=x"), "42");
        assert_eq!(item("/Audio/7/universal"), "7");
        assert_eq!(item("/__cdn/play/abc.mp4"), "abc.mp4");
        assert_eq!(mask("203.0.113.9"), "203.0.*.*");
        assert_eq!(mask("2001:db8::1"), "2001:db8:…");
        assert_eq!(mask("bogus"), "bogus");
    }

    #[test]
    fn problems_leave_out_normal_ends() {
        let line = |status: u64, end: &str| {
            format!(
                r#"{{"ts":"2026-11-20T08:01:02.345Z","site":"a","status":{status},"path":"/x","end":"{end}","err":null}}"#
            )
        };
        assert!(Problem::of(&line(200, "ok")).is_none());
        assert!(Problem::of(&line(404, "ok")).is_none());
        assert!(Problem::of(&line(206, "client_closed")).is_none());
        assert!(Problem::of(&line(429, "ok")).is_some());
        assert!(Problem::of(&line(502, "ok")).is_some());
        let p = Problem::of(&line(200, "upstream_timeout")).unwrap();
        assert_eq!(p.end.as_deref(), Some("upstream_timeout"));
        let mut list = Problems::default();
        for _ in 0..150 {
            list.add(&line(502, "redirect_refused"));
        }
        assert_eq!(list.list.len(), PROBLEMS);
    }
}
