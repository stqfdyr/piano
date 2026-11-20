//! The image engine: answers image requests from memory where it can and spends the
//! upstream's request limit carefully where it cannot.
//!
//! Upstreams rate-limit per client address, and the relay is one address for all its
//! clients. A client opening a poster wall asks for a few hundred images within
//! seconds, so image requests (1) are answered from stored bodies while fresh, and from
//! stale ones when the upstream fails; (2) remember permanent redirects, since one
//! upstream answers every image with a 301 that it does not let be cached and that costs
//! a request against its limit, while the redirect target is served by its CDN;
//! (3) remember images the upstream does not have; (4) share one upstream request among
//! concurrent requests for the same image; and (5) wait for the site's request budget
//! ([`Budget`]) instead of running into 429, which would also fail browsing requests.

use crate::follow::{self, Target, TargetKind};
use crate::headers;
use crate::media;
use crate::reach::{self, AttemptLog, CONNECT_RETRIES, Hop, MAX_ATTEMPTS, Reach};
use crate::relay::Ctx;
use crate::{Relay, Site, Sites};
use bytes::{Bytes, BytesMut};
use http::header::{
    ACCEPT_ENCODING, AGE, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, ETAG, IF_MODIFIED_SINCE,
    IF_NONE_MATCH, IF_RANGE, LAST_MODIFIED, LOCATION, RANGE, RETRY_AFTER, SET_COOKIE, UPGRADE,
    VARY,
};
use http::{HeaderName, HeaderValue, Method};
use piano_cache::{Budget, BudgetState, Lru, Wait, Weigh, image_key, shared_ttl};
use pingora_error::{Error, ErrorSource, ErrorType, Result};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::Session;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use tokio::sync::watch;

/// Largest image body kept in memory. Posters at the upstreams are 20–400 KB and
/// backdrops a few MB; a larger body is relayed as it comes, without caching.
const MAX_IMAGE: usize = 8 * 1024 * 1024;

/// Longest a stored image counts as fresh, whatever the upstream allows.
const MAX_TTL: Duration = Duration::from_secs(30 * 86_400);

/// How long past its freshness a stored image may still stand in for an upstream that
/// fails or rate-limits. Images rarely change; one upstream lets its CDN keep them 7 days.
const STALE_FOR: Duration = Duration::from_secs(7 * 86_400);

/// How long a 404 for an image is remembered. Clients ask again for images an item
/// lists but the upstream lacks, up to hundreds of times an hour; an image added
/// upstream shows up after this long.
const MISSING_TTL: Duration = Duration::from_secs(600);

/// How long a permanent redirect of an image is remembered. Its target names the image
/// by item and kind and the key includes the image tag, so the target changes only when
/// the upstream reorganises its paths; a day bounds that.
const MOVED_TTL: Duration = Duration::from_secs(86_400);

/// Memory for remembered redirects and missing images: about 200 bytes each, so tens of
/// thousands of entries, more than the distinct images seen at a relay in two months.
const MOVED_MEMORY: usize = 8 * 1024 * 1024;
const MISSING_MEMORY: usize = 2 * 1024 * 1024;

/// Longest an image request waits for the budget before it is answered 429 itself.
/// Clients give up on a request after 10–14 s; an answer before that lets them retry
/// on their own schedule instead of piling up.
const MAX_WAIT: Duration = Duration::from_secs(10);

/// Pause after an upstream 429 without a usable Retry-After: when one upstream's limit
/// is used up, requests 7 s later still fail and requests 14 s later pass.
const DEFAULT_PAUSE: Duration = Duration::from_secs(10);
/// Longest pause honoured; image requests during a pause are answered locally.
const MAX_PAUSE: Duration = Duration::from_secs(60);

/// Response fields not stored with an image: about the connection, or recomputed.
const NOT_STORED: [&str; 10] = [
    "connection",
    "keep-alive",
    "transfer-encoding",
    "content-length",
    "date",
    "age",
    "proxy-connection",
    "trailer",
    "upgrade",
    "set-cookie",
];

/// An upstream answer, buffered.
#[derive(Debug)]
pub(crate) struct Stored {
    status: u16,
    headers: Vec<(HeaderName, HeaderValue)>,
    body: Bytes,
    stored_at: Instant,
    fresh_until: Instant,
    keep_until: Instant,
}

impl Weigh for Stored {
    fn weight(&self) -> usize {
        let h: usize = self
            .headers
            .iter()
            .map(|(k, v)| k.as_str().len() + v.len() + 32)
            .sum();
        self.body.len() + h + 128
    }
}

impl Stored {
    fn header(&self, name: &HeaderName) -> Option<&HeaderValue> {
        self.headers.iter().find(|(k, _)| k == name).map(|(_, v)| v)
    }
}

#[derive(Debug)]
struct Missing {
    until: Instant,
}

impl Weigh for Missing {
    fn weight(&self) -> usize {
        64
    }
}

#[derive(Debug)]
struct Moved {
    target: Target,
    until: Instant,
}

impl Weigh for Moved {
    fn weight(&self) -> usize {
        self.target.host.len() + self.target.path.len() + 96
    }
}

/// What an upstream fetch came to; shared by every request that waited for it.
#[derive(Debug)]
enum Fetched {
    Response(Arc<Stored>),
    /// The stored image was confirmed and is fresh again.
    NotModified,
    /// The budget did not allow a request in time; retry after this long.
    Shed(Duration),
    Failed(ErrorType, String),
    /// Too large to buffer; relayed by the plain proxy instead.
    TooLarge,
}

type Flight = watch::Receiver<Option<Arc<Fetched>>>;

#[derive(Debug)]
struct State {
    bodies: Lru<Arc<Stored>>,
    missing: Lru<Missing>,
    moved: Lru<Moved>,
}

/// Counters since start.
#[derive(Debug, Default)]
struct Counters {
    hits: AtomicU64,
    misses: AtomicU64,
    coalesced: AtomicU64,
    stale: AtomicU64,
    revalidated: AtomicU64,
    missing: AtomicU64,
    shed: AtomicU64,
    moved: AtomicU64,
}

/// A snapshot of the image engine for status output.
#[derive(Debug, Clone)]
pub struct ImageStats {
    pub bytes: u64,
    pub capacity: u64,
    pub images: u64,
    pub missing: u64,
    pub moved: u64,
    pub hits: u64,
    pub misses: u64,
    pub coalesced: u64,
    pub stale: u64,
    pub revalidated: u64,
    pub missing_hits: u64,
    pub shed: u64,
    pub moved_hits: u64,
    /// Budget per upstream `host:port`.
    pub budgets: Vec<(String, BudgetState)>,
}

/// What a purge removed.
#[derive(Debug, Clone, Copy)]
pub struct Purged {
    pub images: u64,
    pub missing: u64,
    pub moved: u64,
}

/// Stored images, remembered redirects and misses, fetches in flight and the request
/// budget of each upstream. Shared by all requests and kept across reloads.
#[derive(Debug)]
pub struct Images {
    state: Mutex<State>,
    flights: Mutex<HashMap<String, Flight>>,
    budgets: Mutex<HashMap<String, Arc<Budget>>>,
    counters: Counters,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // Each critical section leaves the data consistent before anything can panic.
    m.lock().unwrap_or_else(|e| e.into_inner())
}

enum Look {
    Fresh(Arc<Stored>),
    Missing,
    Stale(Arc<Stored>),
    None,
}

impl Images {
    /// `capacity` is the memory for image bodies in bytes.
    pub fn new(capacity: usize) -> Self {
        Self {
            state: Mutex::new(State {
                bodies: Lru::new(capacity),
                missing: Lru::new(MISSING_MEMORY),
                moved: Lru::new(MOVED_MEMORY),
            }),
            flights: Mutex::new(HashMap::new()),
            budgets: Mutex::new(HashMap::new()),
            counters: Counters::default(),
        }
    }

    pub fn set_capacity(&self, capacity: usize) {
        lock(&self.state).bodies.set_capacity(capacity);
    }

    /// The request budget of `site`'s upstream, with the site's configured rate.
    pub(crate) fn budget(&self, site: &Site) -> Arc<Budget> {
        let rate = site.policy.upstream_limit;
        let now = Instant::now();
        let key = site.origin.authority();
        let b = Arc::clone(
            lock(&self.budgets)
                .entry(key)
                .or_insert_with(|| Arc::new(Budget::new(rate, now))),
        );
        b.set_rate(rate, now);
        b
    }

    /// Removes stored images, remembered redirects and misses.
    pub fn purge(&self) -> Purged {
        let mut s = lock(&self.state);
        Purged {
            images: s.bodies.clear() as u64,
            missing: s.missing.clear() as u64,
            moved: s.moved.clear() as u64,
        }
    }

    pub fn stats(&self) -> ImageStats {
        let now = Instant::now();
        let (bytes, capacity, images, missing, moved) = {
            let s = lock(&self.state);
            (
                s.bodies.used() as u64,
                s.bodies.capacity() as u64,
                s.bodies.len() as u64,
                s.missing.len() as u64,
                s.moved.len() as u64,
            )
        };
        let mut budgets: Vec<(String, BudgetState)> = lock(&self.budgets)
            .iter()
            .map(|(k, b)| (k.clone(), b.state(now)))
            .collect();
        budgets.sort_by(|a, b| a.0.cmp(&b.0));
        let c = &self.counters;
        let n = |a: &AtomicU64| a.load(Ordering::Relaxed);
        ImageStats {
            bytes,
            capacity,
            images,
            missing,
            moved,
            hits: n(&c.hits),
            misses: n(&c.misses),
            coalesced: n(&c.coalesced),
            stale: n(&c.stale),
            revalidated: n(&c.revalidated),
            missing_hits: n(&c.missing),
            shed: n(&c.shed),
            moved_hits: n(&c.moved),
            budgets,
        }
    }

    fn look(&self, key: &str, now: Instant) -> Look {
        let mut s = lock(&self.state);
        if let Some(m) = s.missing.get(key) {
            if m.until > now {
                return Look::Missing;
            }
            s.missing.remove(key);
        }
        let Some(stored) = s.bodies.get(key).cloned() else {
            return Look::None;
        };
        if stored.fresh_until > now {
            Look::Fresh(stored)
        } else if stored.keep_until > now {
            Look::Stale(stored)
        } else {
            s.bodies.remove(key);
            Look::None
        }
    }

    fn moved(&self, key: &str, now: Instant) -> Option<Target> {
        let mut s = lock(&self.state);
        let m = s.moved.get(key)?;
        if m.until > now {
            return Some(m.target.clone());
        }
        s.moved.remove(key);
        None
    }

    fn remember_moved(&self, key: &str, target: Target, now: Instant) {
        lock(&self.state).moved.insert(
            key.to_owned(),
            Moved {
                target,
                until: now + MOVED_TTL,
            },
        );
    }

    fn forget_moved(&self, key: &str) {
        lock(&self.state).moved.remove(key);
    }

    fn store(&self, key: &str, stored: Arc<Stored>) {
        let mut s = lock(&self.state);
        s.missing.remove(key);
        s.bodies.insert(key.to_owned(), stored);
    }

    fn remember_missing(&self, key: &str, now: Instant) {
        let mut s = lock(&self.state);
        s.bodies.remove(key);
        s.missing.insert(
            key.to_owned(),
            Missing {
                until: now + MISSING_TTL,
            },
        );
    }

    /// Marks the stored image fresh again for `ttl` (by default its previous lifetime),
    /// after the upstream confirmed it.
    fn refresh(&self, key: &str, ttl: Option<Duration>, now: Instant) -> bool {
        let mut s = lock(&self.state);
        let Some(old) = s.bodies.get(key).cloned() else {
            return false;
        };
        let ttl = ttl.unwrap_or_else(|| old.fresh_until.saturating_duration_since(old.stored_at));
        s.bodies.insert(
            key.to_owned(),
            Arc::new(Stored {
                status: old.status,
                headers: old.headers.clone(),
                body: old.body.clone(),
                stored_at: now,
                fresh_until: now + ttl,
                keep_until: now + ttl + STALE_FOR,
            }),
        );
        true
    }
}

/// Whether the engine answers this request: a GET without a body for the whole image.
pub(crate) fn takes(session: &mut Session) -> bool {
    let req = session.req_header();
    req.method == Method::GET
        && !req.headers.contains_key(RANGE)
        && !req.headers.contains_key(UPGRADE)
        && session.as_downstream_mut().is_body_empty()
}

/// Answers the image request in `session`. `Ok(false)` hands it back to the plain proxy.
pub(crate) async fn serve(relay: &Relay, session: &mut Session, ctx: &mut Ctx) -> Result<bool> {
    let images = Arc::clone(&relay.images);
    let site = ctx.site()?;
    let key = image_key(&site.name, session.req_header().raw_path());
    let now = Instant::now();
    let stale = match images.look(&key, now) {
        Look::Fresh(s) => {
            images.counters.hits.fetch_add(1, Ordering::Relaxed);
            ctx.cache = Some("hit");
            write(session, ctx, &s, true).await?;
            return Ok(true);
        }
        Look::Missing => {
            images.counters.missing.fetch_add(1, Ordering::Relaxed);
            ctx.cache = Some("missing");
            respond_status(session, ctx, 404, None).await?;
            return Ok(true);
        }
        Look::Stale(s) => Some(s),
        Look::None => None,
    };

    let (flight, spec) = {
        let mut flights = lock(&images.flights);
        // A fetch whose task ended without an answer has a closed channel; start anew.
        match flights.get(&key).filter(|f| f.has_changed().is_ok()) {
            Some(f) => (f.clone(), None),
            None => {
                let (tx, rx) = watch::channel(None);
                flights.insert(key.clone(), rx.clone());
                let spec = Arc::new(Spec {
                    images: Arc::clone(&images),
                    reach: Arc::clone(&relay.reach),
                    sites: ctx
                        .sites
                        .clone()
                        .ok_or_else(|| Error::explain(ErrorType::InternalError, "no sites"))?,
                    site: ctx.site,
                    budget: images.budget(site),
                    req: fetch_request(session.req_header(), stale.as_deref())?,
                    client_path: session.req_header().raw_path().to_vec(),
                    start: ctx.hop.clone(),
                    key: key.clone(),
                    log: Mutex::new(Vec::new()),
                });
                tokio::spawn(run(Arc::clone(&spec), tx));
                (rx, Some(spec))
            }
        }
    };
    let leader = spec.is_some();
    let fetched = wait(flight).await;
    if let Some(spec) = &spec {
        ctx.attempts = std::mem::take(&mut *lock(&spec.log));
    }
    let Some(fetched) = fetched else {
        return Ok(false);
    };
    let counters = &images.counters;
    if leader {
        counters.misses.fetch_add(1, Ordering::Relaxed);
    } else {
        counters.coalesced.fetch_add(1, Ordering::Relaxed);
    }
    let label = if leader { "miss" } else { "coalesced" };
    match (&*fetched, stale) {
        (Fetched::Response(r), Some(s)) if r.status == 429 || r.status >= 500 => {
            serve_stale(session, ctx, counters, &s).await?;
        }
        (Fetched::Shed(_) | Fetched::Failed(..), Some(s)) => {
            serve_stale(session, ctx, counters, &s).await?;
        }
        (Fetched::Response(r), _) => {
            ctx.cache = Some(label);
            write(session, ctx, r, false).await?;
        }
        (Fetched::NotModified, stale) => match (images.look(&key, Instant::now()), stale) {
            (Look::Fresh(s), _) => {
                counters.revalidated.fetch_add(1, Ordering::Relaxed);
                ctx.cache = Some("revalidated");
                write(session, ctx, &s, true).await?;
            }
            (_, Some(s)) => serve_stale(session, ctx, counters, &s).await?,
            _ => return Ok(false),
        },
        (Fetched::Shed(after), None) => {
            counters.shed.fetch_add(1, Ordering::Relaxed);
            ctx.cache = Some("shed");
            respond_status(session, ctx, 429, Some(*after)).await?;
        }
        (Fetched::Failed(etype, msg), None) => {
            ctx.cache = Some(label);
            return Err(Error::create(
                etype.clone(),
                ErrorSource::Upstream,
                Some(msg.clone().into()),
                None,
            ));
        }
        (Fetched::TooLarge, _) => return Ok(false),
    }
    Ok(true)
}

async fn serve_stale(
    session: &mut Session,
    ctx: &mut Ctx,
    counters: &Counters,
    s: &Stored,
) -> Result<()> {
    counters.stale.fetch_add(1, Ordering::Relaxed);
    ctx.cache = Some("stale");
    write(session, ctx, s, true).await
}

async fn wait(mut flight: Flight) -> Option<Arc<Fetched>> {
    let got = flight.wait_for(Option::is_some).await.ok()?;
    got.clone()
}

/// The client's request as sent for an image: no conditions of the client's (the
/// relay answers those from the whole image), uncompressed, and with the stored
/// image's validators when it is being revalidated.
fn fetch_request(req: &RequestHeader, stale: Option<&Stored>) -> Result<RequestHeader> {
    let mut up = media::upstream_request(req)?;
    for name in [IF_NONE_MATCH, IF_MODIFIED_SINCE, IF_RANGE] {
        up.remove_header(&name);
    }
    up.insert_header(ACCEPT_ENCODING, "identity")?;
    if let Some(s) = stale {
        if let Some(v) = s.header(&ETAG) {
            up.insert_header(IF_NONE_MATCH, v.clone())?;
        }
        if let Some(v) = s.header(&LAST_MODIFIED) {
            up.insert_header(IF_MODIFIED_SINCE, v.clone())?;
        }
    }
    Ok(up)
}

/// What one image fetch needs; the fetch outlives the request that started it.
struct Spec {
    images: Arc<Images>,
    reach: Arc<Reach>,
    sites: Arc<Sites>,
    site: usize,
    budget: Arc<Budget>,
    req: RequestHeader,
    client_path: Vec<u8>,
    /// A mounted host, or the site's upstream when `None`.
    start: Option<Hop>,
    key: String,
    log: Mutex<Vec<AttemptLog>>,
}

impl Spec {
    fn site(&self) -> Result<&Site> {
        self.sites
            .get(self.site)
            .ok_or_else(|| Error::explain(ErrorType::InternalError, "no site selected"))
    }
}

async fn run(spec: Arc<Spec>, tx: watch::Sender<Option<Arc<Fetched>>>) {
    let fetched = Arc::new(fetch(&spec).await);
    lock(&spec.images.flights).remove(&spec.key);
    let _ = tx.send(Some(fetched));
}

async fn fetch(spec: &Spec) -> Fetched {
    if let Some(target) = spec.images.moved(&spec.key, Instant::now()) {
        let hop = Hop {
            target,
            kind: TargetKind::Upstream,
        };
        if let Err(after) = admit(&spec.budget, true).await {
            return Fetched::Shed(after);
        }
        match exchange(spec, Some(hop), false).await {
            // The target is gone; ask the upstream where the image is now.
            Ok(Got::Response(r)) if r.status == 404 => spec.images.forget_moved(&spec.key),
            other => {
                spec.images.counters.moved.fetch_add(1, Ordering::Relaxed);
                return conclude(spec, other);
            }
        }
    }
    if let Err(after) = admit(&spec.budget, false).await {
        return Fetched::Shed(after);
    }
    conclude(spec, exchange(spec, spec.start.clone(), true).await)
}

/// Waits until the budget lets an image request go, or says when to retry. A request
/// to a remembered redirect target only waits out pauses: the target is served by a
/// CDN and costs the upstream nothing.
async fn admit(budget: &Budget, free: bool) -> std::result::Result<(), Duration> {
    let deadline = Instant::now() + MAX_WAIT;
    loop {
        let now = Instant::now();
        let wait = if free {
            budget.paused_for(now).map_or(Wait::Go, Wait::For)
        } else {
            budget.admit(now)
        };
        match wait {
            Wait::Go => return Ok(()),
            Wait::For(d) if now + d > deadline => return Err(d),
            Wait::For(d) => tokio::time::sleep(d).await,
        }
    }
}

enum Got {
    Response(Arc<Stored>),
    NotModified(Option<Duration>),
    TooLarge,
}

/// Turns an exchange's outcome into what waiting requests get, updating the store.
fn conclude(spec: &Spec, got: Result<Got>) -> Fetched {
    let now = Instant::now();
    match got {
        Ok(Got::Response(r)) => {
            if r.status == 404 {
                spec.images.remember_missing(&spec.key, now);
            } else if r.fresh_until > now {
                spec.images.store(&spec.key, Arc::clone(&r));
            }
            Fetched::Response(r)
        }
        Ok(Got::NotModified(ttl)) => {
            if spec.images.refresh(&spec.key, ttl, now) {
                Fetched::NotModified
            } else {
                Fetched::Failed(ErrorType::InternalError, "revalidated image gone".into())
            }
        }
        Ok(Got::TooLarge) => Fetched::TooLarge,
        Err(e) => Fetched::Failed(e.etype().clone(), e.to_string()),
    }
}

/// The delay an upstream 429 asks for.
fn pause_of(resp: &ResponseHeader) -> Duration {
    resp.headers
        .get(RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map_or(DEFAULT_PAUSE, Duration::from_secs)
        .min(MAX_PAUSE)
}

/// Whether a request towards `hop` reaches the site's upstream server itself.
pub(crate) fn at_origin(site: &Site, hop: Option<&Hop>) -> bool {
    hop.is_none_or(|h| h.target.host == site.origin.host && h.target.port == site.origin.port)
}

/// Notes an upstream response that counts against the site's budget.
pub(crate) fn note_upstream(budget: &Budget, resp: &ResponseHeader) {
    if resp.status.as_u16() == 429 {
        budget.pause(Instant::now(), pause_of(resp));
    }
}

/// One upstream request for the image, following redirects, with the body buffered.
/// `remember` records a first permanent redirect to the upstream service.
async fn exchange(spec: &Spec, start: Option<Hop>, remember: bool) -> Result<Got> {
    let site = spec.site()?;
    let mut hop = start;
    let mut hops = 0u8;
    let mut connect_retries = 0u8;
    let mut last = None;
    for _ in 0..MAX_ATTEMPTS {
        let host = reach::host_of(site, hop.as_ref()).to_owned();
        let (peer, addrs, addr) = spec.reach.peer(site, hop.as_ref()).await?;
        let entry = {
            let mut log = lock(&spec.log);
            log.push(AttemptLog::new(0, host.clone(), addr));
            log.len() - 1
        };
        let note = |f: &dyn Fn(&mut AttemptLog)| {
            if let Some(a) = lock(&spec.log).get_mut(entry) {
                f(a);
            }
        };
        let (mut http, reused) = match spec.reach.media.get_http_session(&peer).await {
            Ok(c) => c,
            Err(e) => {
                note(&|a| a.error = Some(e.etype().as_str()));
                if reach::is_connect_failure(e.etype()) {
                    addrs.failed(addr);
                    let untried = usize::from(connect_retries) + 1 < addrs.len();
                    if untried && connect_retries < CONNECT_RETRIES {
                        connect_retries += 1;
                        last = Some(e);
                        continue;
                    }
                }
                return Err(e.into_up());
            }
        };
        note(&|a| a.connected(reused));
        http.read_timeout = peer.options.read_timeout;
        http.write_timeout = peer.options.write_timeout;
        let mut req = spec.req.clone();
        reach::prepare_request(site, hop.as_ref(), &mut req)?;
        let resp = match media::exchange(&mut http, req).await {
            Ok(r) => r,
            Err(e) => {
                note(&|a| a.error = Some(e.etype().as_str()));
                let stale = matches!(
                    e.etype(),
                    ErrorType::ConnectionClosed | ErrorType::ReadError | ErrorType::WriteError
                );
                if reused && stale {
                    last = Some(e);
                    continue;
                }
                return Err(e.into_up());
            }
        };
        let status = resp.status.as_u16();
        note(&|a| a.status = Some(status));
        if at_origin(site, hop.as_ref()) {
            note_upstream(&spec.budget, &resp);
        }
        let location = follow::is_redirect(status)
            .then(|| resp.headers.get(LOCATION))
            .flatten();
        if let Some(location) = location {
            let next = reach::redirect(
                &spec.sites,
                site,
                &Method::GET,
                hops,
                hop.as_ref(),
                &spec.client_path,
                location.as_bytes(),
            )?;
            let permanent = status == 301 || status == 308;
            if remember && hops == 0 && permanent && next.kind == TargetKind::Upstream {
                spec.images
                    .remember_moved(&spec.key, next.target.clone(), Instant::now());
            }
            hops += 1;
            tokio::spawn(media::drain(Arc::clone(&spec.reach), http, peer));
            hop = Some(next);
            continue;
        }
        if status == 304 {
            let ttl = shared_ttl(
                resp.headers.get(CACHE_CONTROL).map(|v| v.as_bytes()),
                MAX_TTL,
            );
            let idle = peer.options.idle_timeout;
            spec.reach
                .media
                .release_http_session(http, &peer, idle)
                .await;
            return Ok(Got::NotModified(ttl));
        }
        let announced = resp
            .headers
            .get(CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());
        if announced.is_some_and(|n| n > MAX_IMAGE as u64) {
            return Ok(Got::TooLarge);
        }
        let mut body = BytesMut::new();
        loop {
            match http.read_body_bytes().await {
                Ok(Some(data)) => {
                    if body.len() + data.len() > MAX_IMAGE {
                        return Ok(Got::TooLarge);
                    }
                    body.extend_from_slice(&data);
                }
                Ok(None) => break,
                Err(e) => {
                    note(&|a| a.error = Some(e.etype().as_str()));
                    return Err(e.into_up());
                }
            }
        }
        let idle = peer.options.idle_timeout;
        spec.reach
            .media
            .release_http_session(http, &peer, idle)
            .await;
        return Ok(Got::Response(Arc::new(stored(
            site,
            &host,
            resp,
            body.freeze(),
        )?)));
    }
    Err(last
        .unwrap_or_else(|| Error::explain(ErrorType::InternalError, "no upstream attempt"))
        .into_up())
}

/// The upstream's answer as kept and replayed; fresh for as long as it may be cached.
fn stored(site: &Site, host: &str, mut resp: ResponseHeader, body: Bytes) -> Result<Stored> {
    headers::scrub_response(&mut resp, host, &site.host)?;
    let now = Instant::now();
    let ttl = cacheable(&resp, body.len())
        .then(|| {
            shared_ttl(
                resp.headers.get(CACHE_CONTROL).map(|v| v.as_bytes()),
                MAX_TTL,
            )
        })
        .flatten();
    let headers = resp
        .headers
        .iter()
        .filter(|(k, _)| !NOT_STORED.contains(&k.as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    Ok(Stored {
        status: resp.status.as_u16(),
        headers,
        body,
        stored_at: now,
        fresh_until: now + ttl.unwrap_or_default(),
        keep_until: now + ttl.map_or(Duration::ZERO, |t| t + STALE_FOR),
    })
}

/// A whole image, the same for every client.
fn cacheable(resp: &ResponseHeader, len: usize) -> bool {
    let h = |name| resp.headers.get(name).map(HeaderValue::as_bytes);
    let image =
        h(CONTENT_TYPE).is_some_and(|v| v.len() >= 6 && v[..6].eq_ignore_ascii_case(b"image/"));
    // Bodies are fetched uncompressed, so only a Vary on encoding is harmless.
    let vary_ok = resp.headers.get_all(VARY).iter().all(|v| {
        v.as_bytes()
            .split(|&b| b == b',')
            .all(|t| t.trim_ascii().eq_ignore_ascii_case(b"accept-encoding"))
    });
    resp.status.as_u16() == 200
        && image
        && vary_ok
        && !resp.headers.contains_key(SET_COOKIE)
        && len <= MAX_IMAGE
}

/// Whether the client already has `s`, by its conditional request.
fn not_modified(req: &RequestHeader, s: &Stored) -> bool {
    if s.status != 200 {
        return false;
    }
    if let Some(inm) = req.headers.get(IF_NONE_MATCH) {
        let Some(etag) = s.header(&ETAG) else {
            return false;
        };
        let weak = |t: &[u8]| t.strip_prefix(b"W/").unwrap_or(t).to_owned();
        let ours = weak(etag.as_bytes().trim_ascii());
        return inm
            .as_bytes()
            .split(|&b| b == b',')
            .map(<[u8]>::trim_ascii)
            .any(|t| t == b"*" || weak(t) == ours);
    }
    match (req.headers.get(IF_MODIFIED_SINCE), s.header(&LAST_MODIFIED)) {
        (Some(ims), Some(lm)) => ims.as_bytes().trim_ascii() == lm.as_bytes().trim_ascii(),
        _ => false,
    }
}

/// Writes `s` to the client; `from_store` adds its age.
async fn write(session: &mut Session, ctx: &mut Ctx, s: &Stored, from_store: bool) -> Result<()> {
    let unchanged = not_modified(session.req_header(), s);
    let status = if unchanged { 304 } else { s.status };
    let mut resp = ResponseHeader::build(status, Some(s.headers.len() + 3))?;
    for (k, v) in &s.headers {
        resp.append_header(k.clone(), v.clone())?;
    }
    if from_store {
        resp.insert_header(AGE, s.stored_at.elapsed().as_secs())?;
    }
    ctx.ttfb = ctx.start.map(|t| t.elapsed());
    if unchanged {
        resp.remove_header(&CONTENT_TYPE);
        return session
            .write_response_header(Box::new(resp), true)
            .await
            .map_err(|e| e.into_down());
    }
    resp.insert_header(CONTENT_LENGTH, s.body.len())?;
    session
        .write_response_header(Box::new(resp), false)
        .await
        .map_err(|e| e.into_down())?;
    session
        .write_response_body(Some(s.body.clone()), true)
        .await
        .map_err(|e| e.into_down())
}

/// A local answer without a body: a remembered 404, or a 429 while the budget is spent.
async fn respond_status(
    session: &mut Session,
    ctx: &mut Ctx,
    status: u16,
    retry_after: Option<Duration>,
) -> Result<()> {
    let mut resp = ResponseHeader::build(status, Some(3))?;
    resp.insert_header(CONTENT_LENGTH, 0)?;
    if let Some(d) = retry_after {
        resp.insert_header(RETRY_AFTER, d.as_secs().saturating_add(1))?;
    }
    headers::add_hsts(&mut resp)?;
    ctx.ttfb = ctx.start.map(|t| t.elapsed());
    session
        .write_response_header(Box::new(resp), true)
        .await
        .map_err(|e| e.into_down())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stored(headers: &[(&str, &str)]) -> Stored {
        let now = Instant::now();
        Stored {
            status: 200,
            headers: headers
                .iter()
                .map(|(k, v)| {
                    (
                        HeaderName::from_bytes(k.as_bytes()).unwrap(),
                        HeaderValue::from_str(v).unwrap(),
                    )
                })
                .collect(),
            body: Bytes::new(),
            stored_at: now,
            fresh_until: now,
            keep_until: now,
        }
    }

    fn req(headers: &[(&str, &str)]) -> RequestHeader {
        let mut r = RequestHeader::build("GET", b"/x", None).unwrap();
        for (k, v) in headers {
            r.append_header(k.to_string(), *v).unwrap();
        }
        r
    }

    #[test]
    fn conditional_requests() {
        let lm = "Sun, 23 Nov 2025 02:39:49 GMT";
        let s = stored(&[("etag", "\"a\""), ("last-modified", lm)]);
        assert!(not_modified(&req(&[("if-none-match", "\"a\"")]), &s));
        assert!(not_modified(
            &req(&[("if-none-match", "\"b\", W/\"a\"")]),
            &s
        ));
        assert!(not_modified(&req(&[("if-none-match", "*")]), &s));
        assert!(!not_modified(&req(&[("if-none-match", "\"b\"")]), &s));
        // If-None-Match takes precedence over a matching date.
        assert!(!not_modified(
            &req(&[("if-none-match", "\"b\""), ("if-modified-since", lm)]),
            &s
        ));
        assert!(not_modified(&req(&[("if-modified-since", lm)]), &s));
        assert!(!not_modified(
            &req(&[("if-modified-since", "Mon, 24 Nov 2025 00:00:00 GMT")]),
            &s
        ));
        assert!(!not_modified(&req(&[]), &s));
        assert!(!not_modified(
            &req(&[("if-none-match", "\"a\"")]),
            &stored(&[])
        ));
    }

    fn resp(status: u16, h: &[(&str, &str)]) -> ResponseHeader {
        let mut r = ResponseHeader::build(status, None).unwrap();
        for (k, v) in h {
            r.append_header(k.to_string(), *v).unwrap();
        }
        r
    }

    #[test]
    fn what_is_cacheable() {
        let jpeg = [("content-type", "image/jpeg")];
        assert!(cacheable(&resp(200, &jpeg), 10));
        assert!(cacheable(
            &resp(
                200,
                &[("content-type", "IMAGE/webp"), ("vary", "Accept-Encoding")]
            ),
            10
        ));
        assert!(!cacheable(&resp(200, &[("content-type", "text/html")]), 10));
        assert!(!cacheable(&resp(206, &jpeg), 10));
        assert!(!cacheable(
            &resp(200, &[("content-type", "image/jpeg"), ("vary", "Cookie")]),
            10
        ));
        assert!(!cacheable(
            &resp(
                200,
                &[("content-type", "image/jpeg"), ("set-cookie", "a=b")]
            ),
            10
        ));
        assert!(!cacheable(&resp(200, &jpeg), MAX_IMAGE + 1));
    }

    #[test]
    fn retry_after_is_bounded() {
        let r = |v: &[(&str, &str)]| pause_of(&resp(429, v));
        assert_eq!(r(&[("retry-after", "3")]), Duration::from_secs(3));
        assert_eq!(r(&[("retry-after", "3600")]), MAX_PAUSE);
        assert_eq!(r(&[]), DEFAULT_PAUSE);
        assert_eq!(
            r(&[("retry-after", "Wed, 21 Oct 2015 07:28:00 GMT")]),
            DEFAULT_PAUSE
        );
    }
}
