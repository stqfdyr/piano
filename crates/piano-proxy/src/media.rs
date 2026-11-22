//! The media engine: relays a media request with upstream requests of its own, so that a
//! body that stalls or breaks can be continued from another request.
//!
//! The client gets the head of the first response. When that body is resumable (see
//! [`Resume::of`]) and makes no progress for [`HEDGE_AFTER`], a second request for the
//! same bytes starts; an upstream request that fails is replaced. Whichever request
//! delivers the next bytes first carries on and the others are dropped. Every request
//! walks the redirect chain from the client's own URL again, since redirect targets carry
//! signatures that expire, unless the same target led somewhere in the last minutes
//! ([`memo`]): then it goes there, and walks the chain again if that fails. A body that
//! is not resumable is relayed as it comes: no further requests, and an upstream
//! failure ends it.

use crate::follow;
use crate::memo;
use crate::reach::{self, AttemptLog, CONNECT_RETRIES, Hop, MAX_ATTEMPTS, Reach};
use crate::relay::{Ctx, logged_path, logged_range};
use crate::{Relay, Site, Sites, TERMINATED, headers};
use bytes::Bytes;
use http::header::{
    ACCEPT_RANGES, CONNECTION, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_RANGE, ETAG, IF_RANGE,
    LAST_MODIFIED, LOCATION, RANGE, UPGRADE,
};
use http::{HeaderName, HeaderValue, Method, Version};
use log::{debug, warn};
use piano_cache::Budget;
use piano_edge::acl::canonical;
use piano_media::{ByteRange, Head, Request, Resume, Stream, StreamGuard};
use piano_telemetry::{Id, Kind, SiteCounters, Ttfb};
use pingora_core::protocols::http::v1::client::HttpSession;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_error::{Error, ErrorType, Result};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::Session;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

/// A resumable body that has not progressed for this long gets another request for the
/// same bytes. Cold reads at one upstream leave the first request's body stalled for
/// 10–50 s, while a second request delivers within seconds of the first one's head; a
/// redirected request normally has its first byte within 3 s, so a healthy stream
/// rarely triggers this.
const HEDGE_AFTER: Duration = Duration::from_secs(3);

/// Upstream requests in flight for one stream at most.
const MAX_SOURCES: usize = 2;

/// Upstream requests started for a stream with no progress in between; bounds a stream
/// whose upstream fails every request.
const MAX_UNPRODUCTIVE: u8 = 4;

/// Messages queued from the requests of one stream. Bodies are read 32 KiB at a time,
/// so a stream holds a few reads in the queue and one in each request's buffer.
const QUEUE: usize = 2;

/// Shortest pause in the body, with the client ready for more, counted as starving it.
/// Shorter pauses are the upstream's pacing; players buffer seconds ahead.
const STARVED_GAP: Duration = Duration::from_secs(1);

/// What the access log says about a media stream beyond what every request has.
#[derive(Debug, Clone, Copy)]
pub(crate) struct MediaLog {
    /// Which try of the client this was (1 for the first).
    pub attempt: u32,
    /// From the client's first try to the response head, or to the end without one.
    pub waited: Duration,
    /// Pauses of at least [`STARVED_GAP`] in the body while the client could take more.
    pub starved: Duration,
    /// Time spent handing bytes to the client: a full player buffer or a slow link.
    pub blocked: Duration,
}

/// A redirect's connection is reused if its body arrives within this time and size.
pub(crate) const DRAIN_TIMEOUT: Duration = Duration::from_secs(2);
pub(crate) const DRAIN_MAX: usize = 64 * 1024;

/// A request with a resumed or hedged response whose head cannot continue the body.
const MISMATCH: ErrorType = ErrorType::Custom("ResumeMismatch");

/// Fields of a client request that concern only its hop to the relay.
const HOP_BY_HOP: [&str; 12] = [
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "http2-settings",
    "content-length",
    "expect",
];

/// Whether the engine relays this request: a GET without a body that asks for the whole
/// representation or a single byte range.
pub(crate) fn takes(session: &mut Session) -> bool {
    let req = session.req_header();
    if req.method != Method::GET || req.headers.contains_key(UPGRADE) {
        return false;
    }
    let mut ranges = req.headers.get_all(RANGE).iter();
    let range_ok = match (ranges.next(), ranges.next()) {
        (None, _) => true,
        (Some(v), None) => ByteRange::parse(v.as_bytes()).is_some(),
        _ => false,
    };
    range_ok && session.as_downstream_mut().is_body_empty()
}

/// Relays the media request in `session` to the end. The response is written when this
/// returns `Ok`; on error, whatever was written stands and the caller ends the request.
pub(crate) async fn relay(relay: &Relay, session: &mut Session, ctx: &mut Ctx) -> Result<()> {
    let sites = ctx
        .sites
        .clone()
        .ok_or_else(|| Error::explain(ErrorType::InternalError, "no site selected"))?;
    let site = ctx.site()?;
    let req = session.req_header();
    let client = session
        .as_downstream()
        .client_addr()
        .and_then(|a| a.as_inet())
        .map(|a| canonical(a.ip()));
    let range = req.headers.get(RANGE).cloned();
    let (path, logged) = (logged_path(req), logged_range(req));
    let key = relay
        .streams
        .try_key(client, &site.name, req.raw_path(), logged.as_deref());
    let (attempt, first_try) = relay.streams.next_try(key, Instant::now());
    let stream = relay.streams.register(
        Stream::new(ctx.rid.to_string(), site.name.clone(), client, path, logged)
            .tried(attempt, first_try),
    );
    let spec = Arc::new(Spec {
        reach: Arc::clone(&relay.reach),
        stop: relay.stop.watch(),
        budget: relay.images.budget(site),
        stall: site.origin.options.read_timeout,
        req: upstream_request(req)?,
        client_path: req.raw_path().to_vec(),
        memo: memo::key(&site.name, ctx.hop.as_ref(), req),
        start: ctx.hop.clone(),
        site: ctx.site,
        sites,
        counters: Arc::clone(&site.counters),
        log: Mutex::new(Vec::new()),
    });
    ctx.sent_counted = true;
    let (tx, rx) = mpsc::channel(QUEUE);
    let now = Instant::now();
    let mut engine = Engine {
        spec: Arc::clone(&spec),
        tx,
        rx,
        sources: Vec::new(),
        started: 0,
        head_sent: false,
        resume: None,
        pos: 0,
        progress: now,
        launched: now,
        unproductive: 0,
        changed: false,
        error: None,
        stream,
        serving: None,
        rid: ctx.rid,
        stop: relay.stop.watch(),
        client_left: false,
        stopped: false,
        head_at: None,
        last_write: None,
        starved: Duration::ZERO,
        blocked: Duration::ZERO,
    };
    engine.launch(range, Request::First);
    let result = engine.run(session, ctx).await;
    let end = Instant::now();
    if engine.head_sent {
        relay.streams.answered(key);
        if result.is_err() && !engine.stopped {
            // Ended without the rest of the body. A wait for bytes counts up to here,
            // unless the client left in what may have been the upstream's pacing.
            let gap = engine
                .last_write
                .map_or(Duration::ZERO, |w| end.saturating_duration_since(w));
            if !engine.client_left || gap >= HEDGE_AFTER {
                engine.starve_until(end);
            }
        }
    } else {
        // The player asks again after a failure as after giving up.
        relay.streams.unanswered(key, attempt, first_try, end);
        if engine.client_left {
            spec.counters.record_media_gave_up();
        }
    }
    ctx.media = Some(MediaLog {
        attempt,
        waited: engine
            .head_at
            .unwrap_or(end)
            .saturating_duration_since(first_try),
        starved: engine.starved,
        blocked: engine.blocked,
    });
    // Requests still running are dropped with the engine; their log entries so far
    // belong to this request.
    drop(engine);
    ctx.attempts = std::mem::take(&mut *spec.log());
    result
}

/// The client's request made fit to send upstream: HTTP/1.1, without hop-by-hop fields
/// and without `Range`, which each request sets itself. The target is already in
/// origin-form; setting it again drops the scheme and authority an HTTP/2 client's URI
/// carries, which would otherwise name the site rather than the upstream.
pub(crate) fn upstream_request(req: &RequestHeader) -> Result<RequestHeader> {
    let mut up = req.clone();
    up.set_version(Version::HTTP_11);
    debug_assert!(req.raw_path().starts_with(b"/"));
    up.set_raw_path(req.raw_path())?;
    let nominated: Vec<HeaderName> = req
        .headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|t| HeaderName::from_bytes(t.trim().as_bytes()).ok())
        .collect();
    for name in &nominated {
        up.remove_header(name);
    }
    for name in HOP_BY_HOP {
        up.remove_header(name);
    }
    up.remove_header(&RANGE);
    Ok(up)
}

/// What every upstream request of one stream shares.
struct Spec {
    reach: Arc<Reach>,
    /// Set at shutdown, when nothing will use a replaced connection.
    stop: watch::Receiver<bool>,
    /// The site's upstream request budget, which requests to the upstream itself count
    /// against.
    budget: Arc<Budget>,
    sites: Arc<Sites>,
    site: usize,
    req: RequestHeader,
    /// The client's request target, where redirects from the upstream itself start.
    client_path: Vec<u8>,
    /// What the request's redirect target is remembered under; `None` when not kept.
    memo: Option<Vec<u8>>,
    /// Where requests go first: a mounted host, or the site's upstream when `None`.
    start: Option<Hop>,
    /// Longest wait for the upstream: for each read of a request, and for the stream's
    /// next body bytes overall.
    stall: Duration,
    /// The site's counters; a long stream counts its bytes as they pass, not at its end.
    counters: Arc<SiteCounters>,
    log: Mutex<Vec<AttemptLog>>,
}

impl Spec {
    fn site(&self) -> Result<&Site> {
        self.sites
            .get(self.site)
            .ok_or_else(|| Error::explain(ErrorType::InternalError, "no site selected"))
    }

    fn log(&self) -> MutexGuard<'_, Vec<AttemptLog>> {
        // The log holds plain data, so a panic elsewhere cannot leave it inconsistent.
        self.log.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn push(&self, entry: AttemptLog) -> usize {
        let mut log = self.log();
        log.push(entry);
        log.len() - 1
    }

    fn note(&self, entry: usize, f: impl FnOnce(&mut AttemptLog)) {
        if let Some(a) = self.log().get_mut(entry) {
            f(a);
        }
    }
}

enum Msg {
    /// The final response head of a request, and the host that sent it.
    Head(Box<ResponseHeader>, String),
    Data(Bytes),
    /// The body is complete.
    Done,
    Failed(Box<Error>),
}

/// An upstream request of the stream.
struct Source {
    id: u32,
    task: Option<JoinHandle<()>>,
    /// Absolute offset of its next body byte, once its head is accepted.
    at: Option<u64>,
    /// Absolute end of the bytes its response covers.
    end: u64,
    /// The host that answered, once its head arrived.
    host: Option<String>,
}

impl Source {
    /// Lets the request run to its end, so its connection can go back to the pool.
    fn detach(mut self) {
        self.task = None;
    }
}

impl Drop for Source {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

enum Event {
    Msg(Option<(u32, Msg)>),
    /// The client went away, or sent something it should not have.
    Client(Option<Box<Error>>),
    /// The process terminates.
    Stop,
    Timer,
}

struct Engine {
    spec: Arc<Spec>,
    /// Resolves once the process terminates.
    stop: watch::Receiver<bool>,
    tx: mpsc::Sender<(u32, Msg)>,
    rx: mpsc::Receiver<(u32, Msg)>,
    sources: Vec<Source>,
    /// Requests started so far; the next one's id.
    started: u32,
    head_sent: bool,
    /// Set with the head when the body can be continued from another request.
    resume: Option<Resume>,
    /// Absolute offset of the next byte for the client (from 0 when not resumable).
    pos: u64,
    /// When body bytes last reached the client, or the stream started.
    progress: Instant,
    launched: Instant,
    unproductive: u8,
    /// The upstream representation changed under the stream: nothing can continue it.
    changed: bool,
    /// The last request failure, reported if the stream cannot go on.
    error: Option<Box<Error>>,
    stream: StreamGuard,
    /// The request whose bytes the client got last.
    serving: Option<u32>,
    rid: Id,
    /// The client went away; before the head, it gave up waiting.
    client_left: bool,
    /// The process stopped the stream.
    stopped: bool,
    head_at: Option<Instant>,
    /// When the last write to the client ended, the head's included.
    last_write: Option<Instant>,
    starved: Duration,
    blocked: Duration,
}

impl Engine {
    fn launch(&mut self, range: Option<HeaderValue>, why: Request) {
        let id = self.started;
        self.started += 1;
        let task = tokio::spawn(fetch(Arc::clone(&self.spec), id, range, self.tx.clone()));
        self.sources.push(Source {
            id,
            task: Some(task),
            at: None,
            end: u64::MAX,
            host: None,
        });
        self.launched = Instant::now();
        self.unproductive += 1;
        self.stream.add_request(why);
    }

    /// Whether another request may start now that the head is out.
    fn can_add(&self) -> bool {
        self.head_sent
            && !self.changed
            && self.resume.as_ref().is_some_and(|r| self.pos < r.end)
            && self.sources.len() < MAX_SOURCES
            && self.unproductive < MAX_UNPRODUCTIVE
    }

    fn hedge_at(&self) -> Instant {
        self.progress.max(self.launched) + HEDGE_AFTER
    }

    async fn run(&mut self, session: &mut Session, ctx: &mut Ctx) -> Result<()> {
        loop {
            self.stream.set_sources(self.sources.len());
            if self.can_add() && (self.sources.is_empty() || Instant::now() >= self.hedge_at()) {
                let range = self.resume.as_ref().map(|r| r.range_from(self.pos));
                let range = range
                    .map(HeaderValue::try_from)
                    .transpose()
                    .map_err(|e| Error::because(ErrorType::InternalError, "range value", e))?;
                debug!(
                    rid:% = self.rid;
                    "media: request {} for the body from byte {} ({})",
                    self.started,
                    self.pos,
                    if self.sources.is_empty() { "resume" } else { "hedge" }
                );
                let why = if self.sources.is_empty() {
                    Request::Resume
                } else {
                    Request::Hedge
                };
                self.launch(range, why);
                continue;
            }
            if self.sources.is_empty() {
                return Err(self.error.take().unwrap_or_else(|| {
                    Error::explain(ErrorType::InternalError, "media stream without a request")
                }));
            }
            let stall_at = self.progress + self.spec.stall;
            let wake = if self.can_add() {
                stall_at.min(self.hedge_at())
            } else {
                stall_at
            };
            let event = tokio::select! {
                m = self.rx.recv() => Event::Msg(m),
                r = session.as_downstream_mut().read_body_or_idle(true) => Event::Client(r.err()),
                () = tokio::time::sleep_until(wake.into()) => Event::Timer,
                _ = self.stop.wait_for(|t| *t) => Event::Stop,
            };
            match event {
                Event::Msg(Some((id, msg))) => {
                    if self.on_msg(session, ctx, id, msg).await? {
                        return Ok(());
                    }
                }
                Event::Msg(None) => {
                    return Err(Error::explain(
                        ErrorType::InternalError,
                        "media queue closed",
                    ));
                }
                Event::Client(e) => {
                    // A read error is the client closing; data is a protocol error.
                    self.client_left = e.is_some();
                    let e = e.unwrap_or_else(|| {
                        Error::explain(ErrorType::ConnectionClosed, "client sent data mid-response")
                    });
                    return Err(e.into_down());
                }
                Event::Stop => {
                    self.stopped = true;
                    return Error::e_explain(TERMINATED, "media stream ended at shutdown");
                }
                Event::Timer if Instant::now() >= stall_at => {
                    let what = if self.head_sent { "body" } else { "response" };
                    return Err(Error::explain(
                        ErrorType::ReadTimedout,
                        format!("no media {what} from upstream for {:?}", self.spec.stall),
                    )
                    .into_up());
                }
                Event::Timer => {}
            }
        }
    }

    /// Handles a message from request `id`; `Ok(true)` when the response is complete.
    async fn on_msg(
        &mut self,
        session: &mut Session,
        ctx: &mut Ctx,
        id: u32,
        msg: Msg,
    ) -> Result<bool> {
        // Messages of a dropped request may still be queued.
        let Some(i) = self.sources.iter().position(|s| s.id == id) else {
            return Ok(false);
        };
        match msg {
            Msg::Head(resp, host) => {
                self.sources[i].host = Some(host.clone());
                if self.head_sent {
                    self.accept(i, &resp, &host);
                } else {
                    self.send_head(session, ctx, resp, &host).await?;
                    self.serving = Some(id);
                    self.stream.set_upstream(&host);
                    self.sources[i].at = Some(self.pos);
                    self.sources[i].end = self.resume.as_ref().map_or(u64::MAX, |r| r.end);
                }
                Ok(false)
            }
            Msg::Data(data) => self.on_data(session, i, data).await,
            Msg::Done => {
                self.sources.swap_remove(i).detach();
                if self.resume.is_some() {
                    // The response covered less than asked; another request continues.
                    return Ok(false);
                }
                until_stop(&mut self.stop, finish(session)).await?;
                Ok(true)
            }
            Msg::Failed(e) => {
                self.sources.swap_remove(i);
                if !self.head_sent || self.resume.is_none() {
                    return Err(e);
                }
                debug!(
                    rid:% = self.rid;
                    "media: request {id} failed at byte {}: {e}", self.pos
                );
                self.error = Some(e);
                Ok(false)
            }
        }
    }

    async fn send_head(
        &mut self,
        session: &mut Session,
        ctx: &mut Ctx,
        mut resp: Box<ResponseHeader>,
        host: &str,
    ) -> Result<()> {
        headers::scrub_response(&mut resp, host, &self.spec.site()?.host)?;
        self.resume = Resume::of(&head(&resp));
        self.pos = self.resume.as_ref().map_or(0, |r| r.start);
        let size = match &self.resume {
            Some(r) => Some(r.complete),
            None => resp
                .headers
                .get(CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse().ok()),
        };
        self.stream.set_span(self.pos, size);
        ctx.ttfb = ctx.start.map(|s| s.elapsed());
        if let Some(t) = ctx.ttfb {
            self.stream.set_ttfb(t);
            self.spec.counters.record_ttfb(Ttfb::Media, t);
            ctx.ttfb_counted = true;
        }
        ctx.cf_ray = resp.headers.get("cf-ray").cloned();
        self.head_sent = true;
        let start = Instant::now();
        self.head_at = Some(start);
        let written = until_stop(&mut self.stop, async {
            session
                .write_response_header(resp, false)
                .await
                .map_err(|e| e.into_down())
        })
        .await;
        let done = Instant::now();
        self.blocked += done.saturating_duration_since(start);
        self.last_write = Some(done);
        written
    }

    /// Counts the time since the last write as starving the client, if long enough.
    fn starve_until(&mut self, now: Instant) {
        if let Some(last) = self.last_write {
            let gap = now.saturating_duration_since(last);
            if gap >= STARVED_GAP {
                self.starved += gap;
            }
        }
    }

    /// Takes the head of a later request if it continues the body; drops the request
    /// otherwise.
    fn accept(&mut self, i: usize, resp: &ResponseHeader, host: &str) {
        let Some(resume) = &self.resume else {
            self.sources.swap_remove(i);
            return;
        };
        match resume.check(&head(resp), self.pos) {
            Ok((first, end)) => {
                self.sources[i].at = Some(first);
                self.sources[i].end = end;
            }
            Err(m) => {
                warn!(
                    rid:% = self.rid;
                    "media: response from {host} cannot continue the stream at byte {}: {m}",
                    self.pos
                );
                self.changed |= m.is_changed();
                self.sources.swap_remove(i);
                self.error = Some(Error::explain(MISMATCH, format!("{host}: {m}")).into_up());
            }
        }
    }

    async fn on_data(&mut self, session: &mut Session, i: usize, data: Bytes) -> Result<bool> {
        let Some(end) = self.resume.as_ref().map(|r| r.end) else {
            self.write(session, data).await?;
            return Ok(false);
        };
        let Some(at) = self.sources[i].at else {
            return Ok(false);
        };
        let len = data.len() as u64;
        let upto = at.saturating_add(len);
        self.sources[i].at = Some(upto);
        if at > self.pos || upto > self.sources[i].end {
            // A gap, or more bytes than its Content-Range announced.
            self.sources.swap_remove(i);
            self.error = Some(
                Error::explain(ErrorType::InvalidHTTPHeader, "media response off its range")
                    .into_up(),
            );
            return Ok(false);
        }
        if upto <= self.pos {
            // Bytes the client already has.
            return Ok(false);
        }
        // The first request to deliver the next bytes carries on alone.
        let winner = self.sources.swap_remove(i);
        if self.serving != Some(winner.id) {
            self.serving = Some(winner.id);
            if let Some(host) = &winner.host {
                self.stream.set_upstream(host);
            }
        }
        self.sources.clear();
        self.sources.push(winner);
        let skip = usize::try_from(self.pos - at).unwrap_or(usize::MAX);
        let take = usize::try_from(upto.min(end) - self.pos).unwrap_or(usize::MAX);
        self.write(session, data.slice(skip..skip + take)).await?;
        if self.pos < end {
            return Ok(false);
        }
        if let Some(s) = self.sources.pop() {
            s.detach();
        }
        until_stop(&mut self.stop, finish(session)).await?;
        Ok(true)
    }

    async fn write(&mut self, session: &mut Session, data: Bytes) -> Result<()> {
        let n = data.len() as u64;
        let start = Instant::now();
        self.starve_until(start);
        self.stream.set_writing(true);
        let written = until_stop(&mut self.stop, async {
            session
                .write_response_body(Some(data), false)
                .await
                .map_err(|e| e.into_down())
        })
        .await;
        self.stream.set_writing(false);
        let done = Instant::now();
        self.blocked += done.saturating_duration_since(start);
        self.last_write = Some(done);
        written?;
        self.pos += n;
        self.stream.add_sent(n);
        self.spec.counters.add_sent(Kind::Media, n);
        self.progress = Instant::now();
        self.unproductive = 0;
        Ok(())
    }
}

/// Awaits a write to the client unless the process terminates first: a client that
/// stopped reading holds a write for up to the downstream write timeout. A write that
/// completes in the same poll as the signal still counts.
async fn until_stop<T>(
    stop: &mut watch::Receiver<bool>,
    io: impl Future<Output = Result<T>>,
) -> Result<T> {
    tokio::select! {
        biased;
        r = io => r,
        _ = stop.wait_for(|t| *t) => Error::e_explain(TERMINATED, "media stream ended at shutdown"),
    }
}

async fn finish(session: &mut Session) -> Result<()> {
    session
        .write_response_body(None, true)
        .await
        .map_err(|e| e.into_down())
}

fn head(resp: &ResponseHeader) -> Head<'_> {
    let h = |name| resp.headers.get(name).map(HeaderValue::as_bytes);
    Head {
        status: resp.status.as_u16(),
        content_range: h(CONTENT_RANGE),
        content_length: h(CONTENT_LENGTH),
        accept_ranges: h(ACCEPT_RANGES),
        content_encoding: h(CONTENT_ENCODING),
        etag: h(ETAG),
        last_modified: h(LAST_MODIFIED),
    }
}

/// One upstream request of a stream, run as its own task.
async fn fetch(spec: Arc<Spec>, id: u32, range: Option<HeaderValue>, tx: mpsc::Sender<(u32, Msg)>) {
    if let Err(e) = request(&spec, id, range, &tx).await {
        let _ = tx.send((id, Msg::Failed(e))).await;
    }
}

/// The engine is gone; nothing reads this request's messages any more.
fn abandoned() -> Box<Error> {
    Error::explain(ErrorType::InternalError, "media stream ended")
}

/// The connection a media request is using, replaced in the background if the request
/// ends while the connection is still in use: the stream no longer wants the body, or
/// the task was aborted.
struct Held {
    reach: Arc<Reach>,
    stop: watch::Receiver<bool>,
    conn: Option<(String, HttpPeer)>,
}

impl Drop for Held {
    fn drop(&mut self) {
        if let Some((host, peer)) = self.conn.take()
            && !*self.stop.borrow()
        {
            self.reach.replace(&host, peer);
        }
    }
}

async fn request(
    spec: &Spec,
    id: u32,
    range: Option<HeaderValue>,
    tx: &mpsc::Sender<(u32, Msg)>,
) -> Result<()> {
    let mut held = Held {
        reach: Arc::clone(&spec.reach),
        stop: spec.stop.clone(),
        conn: None,
    };
    attempts(spec, id, range, tx, &mut held).await
}

async fn attempts(
    spec: &Spec,
    id: u32,
    range: Option<HeaderValue>,
    tx: &mpsc::Sender<(u32, Msg)>,
    held: &mut Held,
) -> Result<()> {
    let site = spec.site()?;
    let remembered = spec
        .memo
        .as_deref()
        .and_then(|k| spec.reach.redirects.get(k, &spec.sites, Instant::now()));
    // Whether this attempt goes to a remembered target. One that fails is forgotten and
    // the chain walked from the start with attempts of its own.
    let mut at_memo = remembered.is_some();
    let mut hop = remembered.or_else(|| spec.start.clone());
    let mut hops = 0u8;
    let mut connect_retries = 0u8;
    let mut last = None;
    let mut left = MAX_ATTEMPTS;
    let forget = |hop: &mut Option<Hop>, at_memo: &mut bool, retries: &mut u8, left: &mut usize| {
        if let (Some(k), Some(used)) = (&spec.memo, hop.as_ref()) {
            spec.reach.redirects.forget(k, used);
        }
        *at_memo = false;
        *hop = spec.start.clone();
        *retries = 0;
        *left = MAX_ATTEMPTS;
    };
    while left > 0 {
        left -= 1;
        // A connection from an earlier attempt went to the pool, to a drain, or broke.
        held.conn = None;
        let host = reach::host_of(site, hop.as_ref()).to_owned();
        let (mut peer, addrs, addr) = spec.reach.peer(site, hop.as_ref()).await?;
        peer.options.read_timeout = Some(spec.stall);
        let entry = spec.push(AttemptLog::new(id, host.clone(), addr));
        if at_memo {
            spec.note(entry, |a| a.memo = true);
        }
        let origin = crate::image::at_origin(site, hop.as_ref());
        if origin {
            spec.budget.charge(Instant::now());
        }
        let asked = Instant::now();
        let (mut http, reused) = match spec.reach.media.get_http_session(&peer).await {
            Ok(c) => c,
            Err(e) => {
                spec.note(entry, |a| a.error = Some(e.etype().as_str()));
                if reach::is_connect_failure(e.etype()) {
                    addrs.failed(addr);
                    // Retrying only makes sense on an address not tried yet.
                    let untried = usize::from(connect_retries) + 1 < addrs.len();
                    if untried && connect_retries < CONNECT_RETRIES {
                        connect_retries += 1;
                        last = Some(e);
                        continue;
                    }
                }
                if at_memo {
                    forget(&mut hop, &mut at_memo, &mut connect_retries, &mut left);
                    last = Some(e);
                    continue;
                }
                return Err(e.into_up());
            }
        };
        spec.note(entry, |a| a.connected(reused));
        let key = format!("{host}:{}", addr.port());
        if !reused {
            spec.reach.spares.note(&key, asked.elapsed());
        }
        http.read_timeout = peer.options.read_timeout;
        http.write_timeout = peer.options.write_timeout;
        let mut req = spec.req.clone();
        if id > 0 {
            // Later requests are checked against the first response by `Resume::check`;
            // a client's If-Range that did not match then would only turn them into
            // full 200 responses that cannot continue the body.
            req.remove_header(&IF_RANGE);
        }
        reach::prepare_request(site, hop.as_ref(), &mut req)?;
        if let Some(r) = &range {
            req.insert_header(RANGE, r.clone())?;
        }
        held.conn = Some((key, peer.clone()));
        let resp = match exchange(&mut http, req).await {
            Ok(r) => r,
            Err(e) => {
                // Broken, not dropped: a replacement would most likely fail the same way.
                held.conn = None;
                spec.note(entry, |a| a.error = Some(e.etype().as_str()));
                // A pooled connection that the server closed meanwhile; try another.
                let stale = matches!(
                    e.etype(),
                    ErrorType::ConnectionClosed | ErrorType::ReadError | ErrorType::WriteError
                );
                if reused && stale {
                    last = Some(e);
                    continue;
                }
                if at_memo {
                    forget(&mut hop, &mut at_memo, &mut connect_retries, &mut left);
                    last = Some(e);
                    continue;
                }
                return Err(e.into_up());
            }
        };
        let status = resp.status.as_u16();
        spec.note(entry, |a| {
            a.status = Some(status);
            a.proto = Some("h1");
        });
        if origin {
            crate::image::note_upstream(&spec.budget, &resp);
        }
        if at_memo && matches!(status, 401 | 403 | 404 | 410 | 500..=599) {
            // An expired signature, a moved file, a failing host: ask the upstream again.
            // Other answers are the request's own (416 past the end) and stand.
            tokio::spawn(drain(Arc::clone(&spec.reach), http, peer));
            forget(&mut hop, &mut at_memo, &mut connect_retries, &mut left);
            last = Some(
                Error::explain(
                    ErrorType::HTTPStatus(status),
                    "remembered redirect target refused",
                )
                .into_up(),
            );
            continue;
        }
        at_memo = false;
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
            )
            .inspect_err(|_| held.conn = None)?;
            hops += 1;
            tokio::spawn(drain(Arc::clone(&spec.reach), http, peer));
            hop = Some(next);
            continue;
        }
        if hops > 0
            && (200..300).contains(&status)
            && let (Some(k), Some(h)) = (&spec.memo, &hop)
        {
            spec.reach
                .redirects
                .put(k.clone(), h.clone(), &spec.sites, Instant::now());
        }
        tx.send((id, Msg::Head(Box::new(resp), host)))
            .await
            .map_err(|_| abandoned())?;
        loop {
            match http.read_body_bytes().await {
                Ok(Some(data)) => {
                    spec.counters.add_fetched(Kind::Media, data.len() as u64);
                    tx.send((id, Msg::Data(data)))
                        .await
                        .map_err(|_| abandoned())?;
                }
                Ok(None) => break,
                Err(e) => {
                    held.conn = None;
                    spec.note(entry, |a| a.error = Some(e.etype().as_str()));
                    return Err(e.into_up());
                }
            }
        }
        held.conn = None;
        let idle = peer.options.idle_timeout;
        spec.reach
            .media
            .release_http_session(http, &peer, idle)
            .await;
        let _ = tx.send((id, Msg::Done)).await;
        return Ok(());
    }
    Err(last
        .unwrap_or_else(|| Error::explain(ErrorType::InternalError, "no upstream attempt"))
        .into_up())
}

pub(crate) async fn exchange(http: &mut HttpSession, req: RequestHeader) -> Result<ResponseHeader> {
    http.write_request_header(Box::new(req)).await?;
    http.finish_body().await?;
    http.read_response().await?;
    let resp = http
        .resp_header()
        .ok_or_else(|| Error::explain(ErrorType::InvalidHTTPHeader, "no response header"))?;
    if resp.status.is_informational() {
        return Error::e_explain(
            ErrorType::InvalidHTTPHeader,
            "informational response to a media request",
        );
    }
    Ok(resp.clone())
}

/// Reads the rest of a redirect's body so its connection can be reused.
pub(crate) async fn drain(reach: Arc<Reach>, mut http: HttpSession, peer: HttpPeer) {
    let read = tokio::time::timeout(DRAIN_TIMEOUT, async {
        let mut n = 0;
        while let Some(b) = http.read_body_ref().await? {
            n += b.len();
            if n > DRAIN_MAX {
                return Ok(false);
            }
        }
        Ok::<_, Box<Error>>(true)
    })
    .await;
    if matches!(read, Ok(Ok(true))) {
        let idle = peer.options.idle_timeout;
        reach.media.release_http_session(http, &peer, idle).await;
    }
}
