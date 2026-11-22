//! The image engine: spends the upstream's request limit carefully on image requests.
//!
//! Upstreams rate-limit per client address, and the relay is one address for all its
//! clients. A client opening a poster wall asks for a few hundred images within
//! seconds, so image requests (1) remember permanent redirects, since one upstream
//! answers every image with a 301 that it does not let be cached and that costs a
//! request against its limit, while the redirect target is served by its CDN;
//! (2) remember images the upstream does not have; (3) share one upstream request among
//! concurrent requests for the same image; and (4) wait for the site's request budget
//! ([`Budget`]) instead of running into 429, which would also fail browsing requests.
//! Image bodies are not kept: clients keep their own copies.

use crate::follow::{self, Target, TargetKind};
use crate::headers;
use crate::media;
use crate::reach::{self, AttemptLog, CONNECT_RETRIES, Hop, MAX_ATTEMPTS, Reach};
use crate::relay::Ctx;
use crate::{Relay, Site, Sites};
use bytes::{Bytes, BytesMut};
use http::header::{
    ACCEPT, ACCEPT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, ETAG, IF_MODIFIED_SINCE, IF_NONE_MATCH,
    IF_RANGE, LAST_MODIFIED, LOCATION, RANGE, RETRY_AFTER, UPGRADE, VARY,
};
use http::{HeaderName, HeaderValue, Method};
use piano_cache::{Budget, BudgetState, Lru, Wait, Weigh, image_key, variant_key};
use piano_telemetry::Kind;
use pingora_core::protocols::http::client::HttpSession;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_error::{Error, ErrorSource, ErrorType, Result};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::Session;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use tokio::sync::watch;

/// Largest image body buffered to share among the requests waiting for it. Posters at
/// the upstreams are 20–400 KB and backdrops a few MB; a larger body is relayed by the
/// plain proxy as it comes.
const MAX_IMAGE: usize = 8 * 1024 * 1024;

/// How long a 404 for an image is remembered. Clients ask again for images an item
/// lists but the upstream lacks, up to hundreds of times an hour; an image added
/// upstream shows up after this long.
const MISSING_TTL: Duration = Duration::from_secs(600);

/// How long a permanent redirect of an image is remembered. Its target names the image
/// by item and kind and the key includes the image tag, so the target changes only when
/// the upstream reorganises its paths; a day bounds that.
const MOVED_TTL: Duration = Duration::from_secs(86_400);

/// Memory for remembered redirects and missing images: about 300 bytes each with the
/// key, so thousands to tens of thousands of entries, more than the distinct images seen
/// at a relay in two months.
const MOVED_MEMORY: usize = 8 * 1024 * 1024;
const MISSING_MEMORY: usize = 2 * 1024 * 1024;
/// Memory for the images known to vary by `Accept`, which are fetched per variant: one
/// forgotten costs a request handed back to the plain proxy, never a wrong image.
const VARIES_MEMORY: usize = 2 * 1024 * 1024;

/// Longest an image request waits for the budget before it is answered 429 itself.
/// Clients give up on a request after 10–14 s; an answer before that lets them retry
/// on their own schedule instead of piling up.
const MAX_WAIT: Duration = Duration::from_secs(10);

/// Pause after an upstream 429 without a usable Retry-After: when one upstream's limit
/// is used up, requests 7 s later still fail and requests 14 s later pass.
const DEFAULT_PAUSE: Duration = Duration::from_secs(10);
/// Longest pause honoured; image requests during a pause are answered locally.
const MAX_PAUSE: Duration = Duration::from_secs(60);

/// Response fields not passed on with a shared answer: about the connection, recomputed,
/// or meant for one client only (a session cookie, which does not change the image).
const NOT_SHARED: [&str; 8] = [
    "connection",
    "keep-alive",
    "transfer-encoding",
    "content-length",
    "proxy-connection",
    "trailer",
    "upgrade",
    "set-cookie",
];

/// An upstream answer, buffered for every request waiting for it.
#[derive(Debug)]
struct Answer {
    status: u16,
    headers: Vec<(HeaderName, HeaderValue)>,
    body: Bytes,
}

impl Answer {
    fn header(&self, name: &HeaderName) -> Option<&HeaderValue> {
        self.headers.iter().find(|(k, _)| k == name).map(|(_, v)| v)
    }

    /// Whether this response is one of several chosen by the request's `Accept`.
    fn varies(&self) -> bool {
        names_accept(
            self.headers
                .iter()
                .filter(|(k, _)| *k == VARY)
                .map(|(_, v)| v),
        )
    }
}

/// Marks an image fetched per variant.
#[derive(Debug)]
struct Varies;

impl Weigh for Varies {
    fn weight(&self) -> usize {
        0
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
    Response(Answer),
    /// The budget did not allow a request in time; retry after this long.
    Shed(Duration),
    Failed(ErrorType, String),
    /// Too large to buffer; relayed by the plain proxy instead.
    TooLarge,
}

type Flight = watch::Receiver<Option<Arc<Fetched>>>;

#[derive(Debug)]
struct State {
    missing: Lru<Missing>,
    moved: Lru<Moved>,
    /// Images whose last response said `Vary: Accept`.
    varies: Lru<Varies>,
}

/// Counters since start.
#[derive(Debug, Default)]
struct Counters {
    fetched: AtomicU64,
    coalesced: AtomicU64,
    missing: AtomicU64,
    shed: AtomicU64,
    moved: AtomicU64,
}

/// A snapshot of the image engine for status output.
#[derive(Debug, Clone)]
pub struct ImageStats {
    pub missing: u64,
    pub moved: u64,
    pub fetched: u64,
    pub coalesced: u64,
    pub missing_hits: u64,
    pub shed: u64,
    pub moved_hits: u64,
    /// Budget per upstream `host:port`.
    pub budgets: Vec<(String, BudgetState)>,
}

/// What a purge removed.
#[derive(Debug, Clone, Copy)]
pub struct Purged {
    pub missing: u64,
    pub moved: u64,
}

/// Remembered redirects and misses, fetches in flight and the request budget of each
/// upstream. Shared by all requests and kept across reloads.
#[derive(Debug)]
pub struct Images {
    state: Mutex<State>,
    /// Fetches in progress, by image key or, for an image known to vary, variant key;
    /// with the variant key of the request that started each.
    flights: Mutex<HashMap<String, (Flight, Arc<str>)>>,
    budgets: Mutex<HashMap<String, Arc<Budget>>>,
    counters: Counters,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // Each critical section leaves the data consistent before anything can panic.
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Default for Images {
    fn default() -> Self {
        Self::new()
    }
}

impl Images {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(State {
                missing: Lru::new(MISSING_MEMORY),
                moved: Lru::new(MOVED_MEMORY),
                varies: Lru::new(VARIES_MEMORY),
            }),
            flights: Mutex::new(HashMap::new()),
            budgets: Mutex::new(HashMap::new()),
            counters: Counters::default(),
        }
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

    /// Forgets remembered redirects and misses.
    pub fn purge(&self) -> Purged {
        let mut s = lock(&self.state);
        s.varies.clear();
        Purged {
            missing: s.missing.clear() as u64,
            moved: s.moved.clear() as u64,
        }
    }

    pub fn stats(&self) -> ImageStats {
        let now = Instant::now();
        let (missing, moved) = {
            let s = lock(&self.state);
            (s.missing.len() as u64, s.moved.len() as u64)
        };
        let mut budgets: Vec<(String, BudgetState)> = lock(&self.budgets)
            .iter()
            .map(|(k, b)| (k.clone(), b.state(now)))
            .collect();
        budgets.sort_by(|a, b| a.0.cmp(&b.0));
        let c = &self.counters;
        let n = |a: &AtomicU64| a.load(Ordering::Relaxed);
        ImageStats {
            missing,
            moved,
            fetched: n(&c.fetched),
            coalesced: n(&c.coalesced),
            missing_hits: n(&c.missing),
            shed: n(&c.shed),
            moved_hits: n(&c.moved),
            budgets,
        }
    }

    /// Whether image `key` is remembered as missing.
    fn is_missing(&self, key: &str, now: Instant) -> bool {
        let mut s = lock(&self.state);
        let Some(m) = s.missing.get(key) else {
            return false;
        };
        if m.until > now {
            return true;
        }
        s.missing.remove(key);
        false
    }

    /// Whether image `key` is fetched per variant.
    fn varies(&self, key: &str) -> bool {
        lock(&self.state).varies.get(key).is_some()
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

    /// Notes what the upstream answered for image `key` other than 404: whether later
    /// requests for it are fetched per variant.
    fn found(&self, key: &str, varies: bool) {
        let mut s = lock(&self.state);
        s.missing.remove(key);
        if varies {
            s.varies.insert(key.to_owned(), Varies);
        } else {
            s.varies.remove(key);
        }
    }

    /// Remembers that image `key` is missing; once that is forgotten it is fetched
    /// for all variants again until a response says otherwise.
    fn remember_missing(&self, key: &str, now: Instant) {
        let mut s = lock(&self.state);
        s.varies.remove(key);
        s.missing.insert(
            key.to_owned(),
            Missing {
                until: now + MISSING_TTL,
            },
        );
    }
}

/// Whether `Vary` field lines name `Accept`.
fn names_accept<'a>(vary: impl IntoIterator<Item = &'a HeaderValue>) -> bool {
    vary.into_iter().any(|v| {
        v.as_bytes()
            .split(|&b| b == b',')
            .any(|t| t.trim_ascii().eq_ignore_ascii_case(b"accept"))
    })
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
    let req = session.req_header();
    let key = image_key(&site.name, req.raw_path());
    let variant = variant_key(
        &key,
        req.headers.get_all(ACCEPT).iter().map(|v| v.as_bytes()),
    );
    if images.is_missing(&key, Instant::now()) {
        images.counters.missing.fetch_add(1, Ordering::Relaxed);
        ctx.cache = Some("missing");
        respond_status(session, ctx, 404, None).await?;
        return Ok(true);
    }

    let (flight, spec) = {
        let mut flights = lock(&images.flights);
        // A fetch whose task ended without an answer has a closed channel; start anew.
        // An image known to vary is fetched per variant; one not known to is fetched once
        // for all, and a waiter that gets a variant for another Accept goes its own way.
        let flight = if images.varies(&key) {
            variant.clone()
        } else {
            key.clone()
        };
        match flights
            .get(&flight)
            .filter(|(f, _)| f.has_changed().is_ok())
        {
            Some((f, by)) => ((f.clone(), Arc::clone(by)), None),
            None => {
                let (tx, rx) = watch::channel(None);
                let by: Arc<str> = variant.as_str().into();
                flights.insert(flight.clone(), (rx.clone(), Arc::clone(&by)));
                let spec = Arc::new(Spec {
                    images: Arc::clone(&images),
                    reach: Arc::clone(&relay.reach),
                    sites: ctx
                        .sites
                        .clone()
                        .ok_or_else(|| Error::explain(ErrorType::InternalError, "no sites"))?,
                    site: ctx.site,
                    budget: images.budget(site),
                    req: fetch_request(session.req_header())?,
                    client_path: session.req_header().raw_path().to_vec(),
                    start: ctx.hop.clone(),
                    key: key.clone(),
                    flight,
                    log: Mutex::new(Vec::new()),
                });
                tokio::spawn(run(Arc::clone(&spec), tx));
                ((rx, by), Some(spec))
            }
        }
    };
    let leader = spec.is_some();
    let (flight, by) = flight;
    let fetched = wait(flight).await;
    if let Some(spec) = &spec {
        ctx.attempts = std::mem::take(&mut *lock(&spec.log));
    }
    let Some(fetched) = fetched else {
        return Ok(false);
    };
    if let Fetched::Response(r) = &*fetched
        && r.varies()
        && *by != *variant
    {
        return Ok(false);
    }
    let counters = &images.counters;
    if leader {
        counters.fetched.fetch_add(1, Ordering::Relaxed);
    } else {
        counters.coalesced.fetch_add(1, Ordering::Relaxed);
    }
    let label = if leader { "fetched" } else { "coalesced" };
    match &*fetched {
        Fetched::Response(r) => {
            ctx.cache = Some(label);
            write(session, ctx, r).await?;
        }
        Fetched::Shed(after) => {
            counters.shed.fetch_add(1, Ordering::Relaxed);
            ctx.cache = Some("shed");
            respond_status(session, ctx, 429, Some(*after)).await?;
        }
        Fetched::Failed(etype, msg) => {
            ctx.cache = Some(label);
            return Err(Error::create(
                etype.clone(),
                ErrorSource::Upstream,
                Some(msg.clone().into()),
                None,
            ));
        }
        Fetched::TooLarge => return Ok(false),
    }
    Ok(true)
}

async fn wait(mut flight: Flight) -> Option<Arc<Fetched>> {
    let got = flight.wait_for(Option::is_some).await.ok()?;
    got.clone()
}

/// The client's request as sent for an image: no conditions of the client's (the
/// answer is shared; the relay answers conditions from the whole image), uncompressed.
fn fetch_request(req: &RequestHeader) -> Result<RequestHeader> {
    let mut up = media::upstream_request(req)?;
    for name in [IF_NONE_MATCH, IF_MODIFIED_SINCE, IF_RANGE] {
        up.remove_header(&name);
    }
    up.insert_header(ACCEPT_ENCODING, "identity")?;
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
    /// The image, for remembered redirects and misses.
    key: String,
    /// What the fetch is listed under in `flights`.
    flight: String,
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
    lock(&spec.images.flights).remove(&spec.flight);
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
    let mut queued = None;
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
            Wait::For(d) => {
                queued.get_or_insert_with(|| budget.queue());
                tokio::time::sleep(d).await;
            }
        }
    }
}

enum Got {
    Response(Answer),
    TooLarge,
}

/// Turns an exchange's outcome into what waiting requests get, noting what it says
/// about the image.
fn conclude(spec: &Spec, got: Result<Got>) -> Fetched {
    match got {
        Ok(Got::Response(r)) => {
            if r.status == 404 {
                spec.images.remember_missing(&spec.key, Instant::now());
            } else {
                spec.images.found(&spec.key, r.varies());
            }
            Fetched::Response(r)
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
        let (mut peer, addrs, addr) = spec.reach.peer(site, hop.as_ref()).await?;
        if site.origin.options.h2 {
            piano_upstream::offer_h2(&mut peer);
        }
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
        let (mut http, reused) = match spec.reach.images.get_http_session(&peer).await {
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
        http.set_read_timeout(peer.options.read_timeout);
        http.set_write_timeout(peer.options.write_timeout);
        let mut req = spec.req.clone();
        reach::prepare_request(site, hop.as_ref(), &mut req)?;
        let resp = match request(&mut http, req).await {
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
        let proto = if http.as_http2().is_some() {
            "h2"
        } else {
            "h1"
        };
        note(&|a| {
            a.status = Some(status);
            a.proto = Some(proto);
        });
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
            // A redirect chosen by Accept would send other clients to another format.
            let shared = !names_accept(resp.headers.get_all(VARY));
            if remember && hops == 0 && permanent && shared && next.kind == TargetKind::Upstream {
                spec.images
                    .remember_moved(&spec.key, next.target.clone(), Instant::now());
            }
            hops += 1;
            tokio::spawn(drain(Arc::clone(&spec.reach), http, peer));
            hop = Some(next);
            continue;
        }
        if status == 304 {
            return Error::e_explain(
                ErrorType::InvalidHTTPHeader,
                "304 to an unconditional request",
            );
        }
        let announced = resp
            .headers
            .get(CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());
        if announced.is_some_and(|n| n > MAX_IMAGE as u64) {
            return Ok(Got::TooLarge);
        }
        // Within MAX_IMAGE by the check above.
        let presize = announced.and_then(|n| usize::try_from(n).ok());
        let mut body = BytesMut::with_capacity(presize.unwrap_or(0));
        loop {
            match http.read_response_body().await {
                Ok(Some(data)) => {
                    site.counters.add_fetched(Kind::Image, data.len() as u64);
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
            .images
            .release_http_session(http, &peer, idle)
            .await;
        return Ok(Got::Response(answer(site, &host, resp, body)?));
    }
    Err(last
        .unwrap_or_else(|| Error::explain(ErrorType::InternalError, "no upstream attempt"))
        .into_up())
}

/// Sends a bodiless request and reads the response header.
async fn request(http: &mut HttpSession, req: RequestHeader) -> Result<ResponseHeader> {
    http.write_request_header(Box::new(req)).await?;
    http.finish_request_body().await?;
    http.read_response_header().await?;
    let resp = http
        .response_header()
        .ok_or_else(|| Error::explain(ErrorType::InvalidHTTPHeader, "no response header"))?;
    if resp.status.is_informational() {
        return Error::e_explain(
            ErrorType::InvalidHTTPHeader,
            "informational response to an image request",
        );
    }
    Ok(resp.clone())
}

/// Reads the rest of a redirect's body so its connection or stream can be reused.
async fn drain(reach: Arc<Reach>, mut http: HttpSession, peer: HttpPeer) {
    let read = tokio::time::timeout(media::DRAIN_TIMEOUT, async {
        let mut n = 0;
        while let Some(b) = http.read_response_body().await? {
            n += b.len();
            if n > media::DRAIN_MAX {
                return Ok(false);
            }
        }
        Ok::<_, Box<Error>>(true)
    })
    .await;
    if matches!(read, Ok(Ok(true))) {
        let idle = peer.options.idle_timeout;
        reach.images.release_http_session(http, &peer, idle).await;
    }
}

/// The upstream's answer as passed on to every waiting request.
fn answer(site: &Site, host: &str, mut resp: ResponseHeader, body: BytesMut) -> Result<Answer> {
    headers::scrub_response(&mut resp, host, &site.host)?;
    let headers = resp
        .headers
        .iter()
        .filter(|(k, _)| !NOT_SHARED.contains(&k.as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    Ok(Answer {
        status: resp.status.as_u16(),
        headers,
        body: body.freeze(),
    })
}

/// Whether the client already has `a`, by its conditional request.
fn not_modified(req: &RequestHeader, a: &Answer) -> bool {
    if a.status != 200 {
        return false;
    }
    if let Some(inm) = req.headers.get(IF_NONE_MATCH) {
        let Some(etag) = a.header(&ETAG) else {
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
    match (req.headers.get(IF_MODIFIED_SINCE), a.header(&LAST_MODIFIED)) {
        (Some(ims), Some(lm)) => ims.as_bytes().trim_ascii() == lm.as_bytes().trim_ascii(),
        _ => false,
    }
}

/// Writes `a` to the client, or 304 when its conditional request matches.
async fn write(session: &mut Session, ctx: &mut Ctx, a: &Answer) -> Result<()> {
    let unchanged = not_modified(session.req_header(), a);
    let status = if unchanged { 304 } else { a.status };
    let mut resp = ResponseHeader::build(status, Some(a.headers.len() + 2))?;
    for (k, v) in &a.headers {
        resp.append_header(k.clone(), v.clone())?;
    }
    ctx.ttfb = ctx.start.map(|t| t.elapsed());
    if unchanged {
        resp.remove_header(&CONTENT_TYPE);
        return session
            .write_response_header(Box::new(resp), true)
            .await
            .map_err(|e| e.into_down());
    }
    resp.insert_header(CONTENT_LENGTH, a.body.len())?;
    session
        .write_response_header(Box::new(resp), false)
        .await
        .map_err(|e| e.into_down())?;
    session
        .write_response_body(Some(a.body.clone()), true)
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

    fn answer(headers: &[(&str, &str)]) -> Answer {
        Answer {
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
        let a = answer(&[("etag", "\"a\""), ("last-modified", lm)]);
        assert!(not_modified(&req(&[("if-none-match", "\"a\"")]), &a));
        assert!(not_modified(
            &req(&[("if-none-match", "\"b\", W/\"a\"")]),
            &a
        ));
        assert!(not_modified(&req(&[("if-none-match", "*")]), &a));
        assert!(!not_modified(&req(&[("if-none-match", "\"b\"")]), &a));
        // If-None-Match takes precedence over a matching date.
        assert!(!not_modified(
            &req(&[("if-none-match", "\"b\""), ("if-modified-since", lm)]),
            &a
        ));
        assert!(not_modified(&req(&[("if-modified-since", lm)]), &a));
        assert!(!not_modified(
            &req(&[("if-modified-since", "Mon, 24 Nov 2025 00:00:00 GMT")]),
            &a
        ));
        assert!(!not_modified(&req(&[]), &a));
        assert!(!not_modified(
            &req(&[("if-none-match", "\"a\"")]),
            &answer(&[])
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

    #[test]
    fn memories_are_bounded() {
        let images = Images::new();
        let now = Instant::now();
        for i in 0..40_000 {
            let k = format!("{i:05}");
            images.remember_missing(&k, now);
        }
        assert_eq!(
            images.stats().missing as usize,
            MISSING_MEMORY / (64 + 5 + piano_cache::ENTRY)
        );
        let target = |i: usize| Target {
            host: "img.example.net".into(),
            port: 443,
            path: format!("/img/{i:04}").into_bytes(),
        };
        for i in 0..100_000 {
            images.remember_moved(&format!("{i:06}"), target(i % 10_000), now);
        }
        let per = "img.example.net".len() + "/img/0000".len() + 96 + 6 + piano_cache::ENTRY;
        assert_eq!(images.stats().moved as usize, MOVED_MEMORY / per);
    }

    #[test]
    fn what_the_upstream_says_decides_per_variant_fetches() {
        let images = Images::new();
        let now = Instant::now();
        assert!(!images.varies("a"));
        images.found("a", true);
        assert!(images.varies("a"));
        images.found("a", false);
        assert!(!images.varies("a"));
        // A miss ends per-variant fetching, also once it is forgotten.
        images.found("a", true);
        images.remember_missing("a", now);
        assert!(images.is_missing("a", now));
        assert!(!images.varies("a"));
        let later = now + MISSING_TTL + Duration::from_secs(1);
        assert!(!images.is_missing("a", later));
        // An answer other than 404 ends a remembered miss.
        images.remember_missing("b", now);
        images.found("b", false);
        assert!(!images.is_missing("b", now));
    }
}
