//! The `ProxyHttp` implementation.

use crate::follow::{self, Target, TargetKind};
use crate::headers;
use crate::image::{self, Images};
use crate::media;
use crate::reach::{
    self, AttemptLog, CONNECT_RETRIES, Hop, REFUSED, Reach, clip, is_connect_failure, proto_of,
};
use crate::rewrite::MAX_BODY;
use crate::route::{self, HEALTH_PATH, RouteClass};
use crate::{Site, Sites, Stop, TERMINATED};
use arc_swap::ArcSwap;
use async_trait::async_trait;
use bytes::Bytes;
use http::HeaderValue;
use http::Method;
use http::header::{
    ACCEPT_ENCODING, CACHE_CONTROL, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, ETAG, HOST,
    LOCATION, TRANSFER_ENCODING,
};
use log::{debug, error, warn};
use piano_config::ServerDomains;
use piano_edge::acl::canonical;
use piano_edge::tls::Conn;
use piano_media::Streams;
use piano_telemetry::json::JsonLine;
use piano_telemetry::logger::utc_timestamp;
use piano_telemetry::{AccessLog, End, Id, SiteCounters, redact};
use piano_upstream::{Addrs, Resolver};
use pingora_core::connectors::ConnectorOptions;
use pingora_core::modules::http::compression::ResponseCompression;
use pingora_core::protocols::Digest;
use pingora_core::protocols::http::compression::Algorithm;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_error::{Error, ErrorSource, ErrorType, Result};
use pingora_http::authority::{RawTargetAuthority, raw_target_authority};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::{FailToProxy, ProxyHttp, ProxyWarnLogContext, SHUTDOWN_ENDED, Session};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime};

/// Marks the error that makes pingora run another attempt towards a redirect target.
const FOLLOW: ErrorType = ErrorType::Custom("FollowRedirect");
/// One in this many GET requests of the `api` class is rewritten like server
/// information, to notice when the upstream starts naming itself in responses that are
/// otherwise passed on unchanged. Such a request fetches the uncompressed body, about ten
/// times the bytes, so only a sample is taken; at the observed rate of about 500 browsing
/// requests a day per relay that is a few checks a day.
const PROBE_EVERY: u64 = 100;

/// Longest path, User-Agent, Range and error text written to the access log, in bytes.
const MAX_PATH: usize = 2048;
const MAX_UA: usize = 256;
const MAX_RANGE: usize = 128;
const MAX_ERR: usize = 512;
/// Compression levels for rewritten bodies, which can no longer pass on the upstream's
/// compressed bytes.
const GZIP_LEVEL: u32 = 6;
const BROTLI_LEVEL: u32 = 5;

/// The address the current attempt connects to.
#[derive(Debug)]
struct Attempt {
    addrs: Arc<Addrs>,
    addr: SocketAddr,
}

/// A response body being collected for rewriting.
#[derive(Debug)]
struct Rewrite {
    /// A sampled response of a class that is not rewritten by default; see [`PROBE_EVERY`].
    probe: bool,
    /// The site as the client addressed it: host, and port unless 443.
    authority: String,
    /// Set once the response qualifies; cleared when the body turns out too large.
    collecting: bool,
    body: Vec<u8>,
}

/// Per-request state; one per HTTP/2 stream or HTTP/1 request.
#[derive(Debug, Default)]
pub struct Ctx {
    pub rid: Id,
    /// When the request header had been read.
    pub(crate) start: Option<Instant>,
    /// Every upstream attempt, in order.
    pub(crate) attempts: Vec<AttemptLog>,
    /// From the request to the upstream response header the client got.
    pub(crate) ttfb: Option<Duration>,
    pub(crate) cf_ray: Option<HeaderValue>,
    /// The site table taken when the request started; a reload does not change it.
    pub(crate) sites: Option<Arc<Sites>>,
    pub(crate) site: usize,
    pub class: RouteClass,
    pub(crate) hop: Option<Hop>,
    /// Redirects followed so far.
    pub hops: u8,
    attempt: Option<Attempt>,
    /// Attempts repeated because connecting failed.
    pub connect_retries: u8,
    rewrite: Option<Rewrite>,
    /// Addresses replaced in the response body, once a collected body was rewritten.
    rewritten: Option<usize>,
    /// How the image engine answered: hit, miss, coalesced, stale, revalidated, missing
    /// or shed.
    pub(crate) cache: Option<&'static str>,
    /// The bytes sent to the client were counted as they went, by the media engine.
    pub(crate) sent_counted: bool,
    /// The time to first byte was counted when the head went out, by the media engine,
    /// so that a stream lasting hours shows in the percentiles at once.
    pub(crate) ttfb_counted: bool,
}

impl Ctx {
    pub(crate) fn site(&self) -> Result<&Site> {
        self.sites
            .as_deref()
            .and_then(|s| s.get(self.site))
            .ok_or_else(|| Error::explain(ErrorType::InternalError, "no site selected"))
    }

    fn site_name(&self) -> Option<&str> {
        self.site().ok().map(|s| s.name.as_str())
    }

    /// The host the current attempt goes to.
    fn target_host(&self) -> Result<&str> {
        match &self.hop {
            Some(h) => Ok(&h.target.host),
            None => Ok(&self.site()?.origin.host),
        }
    }
}

/// Relays each request to the origin of the site named by its host.
#[derive(Debug)]
pub struct Relay {
    sites: Arc<ArcSwap<Sites>>,
    pub(crate) reach: Arc<Reach>,
    pub(crate) streams: Arc<Streams>,
    pub(crate) images: Arc<Images>,
    access: Arc<AccessLog>,
    /// Requests for a host that is no site.
    unrouted: Arc<SiteCounters>,
    /// GET requests of the `api` class so far, for sampling probes.
    api_gets: AtomicU64,
    pub(crate) stop: Arc<Stop>,
}

impl Relay {
    /// `client` configures the connections the relay makes itself, for media streams
    /// and images; `streams` lists those streams while they run.
    pub fn new(
        sites: Arc<ArcSwap<Sites>>,
        resolver: Resolver,
        client: ConnectorOptions,
        streams: Arc<Streams>,
        images: Arc<Images>,
        access: Arc<AccessLog>,
        unrouted: Arc<SiteCounters>,
    ) -> Self {
        Self {
            sites,
            reach: Arc::new(Reach::new(resolver, client)),
            streams,
            images,
            access,
            unrouted,
            api_gets: AtomicU64::new(0),
            stop: Arc::default(),
        }
    }

    /// Ends media streams once `stop` terminates.
    #[must_use]
    pub fn with_stop(mut self, stop: Arc<Stop>) -> Self {
        self.stop = stop;
        self
    }

    fn probe_due(&self) -> bool {
        (self.api_gets.fetch_add(1, Ordering::Relaxed) + 1).is_multiple_of(PROBE_EVERY)
    }
}

/// `host` with the port of the client's `authority`, unless that is 443 or absent.
fn public_authority(host: &str, authority: &[u8]) -> String {
    let port = authority
        .iter()
        .rposition(|&b| b == b':')
        .and_then(|i| std::str::from_utf8(&authority[i + 1..]).ok())
        .and_then(|p| p.parse::<u16>().ok());
    match port {
        Some(p) if p != 443 => format!("{host}:{p}"),
        _ => host.to_owned(),
    }
}

/// Turns on gzip and brotli for this response, as the client accepts them.
fn enable_compression(session: &mut Session) {
    let req = session.req_header().clone();
    if let Some(c) = session
        .downstream_modules_ctx
        .get_mut::<ResponseCompression>()
    {
        c.adjust_algorithm_level(Algorithm::Gzip, GZIP_LEVEL);
        c.adjust_algorithm_level(Algorithm::Brotli, BROTLI_LEVEL);
        // The module read Accept-Encoding before this request was known to need it.
        c.request_filter(&req);
    }
}

/// A rewritten body is no longer byte-identical to what a strong ETag promised.
fn weaken_etag(resp: &mut ResponseHeader) -> Result<()> {
    let Some(etag) = resp.headers.get(ETAG) else {
        return Ok(());
    };
    if etag.as_bytes().starts_with(b"W/") {
        return Ok(());
    }
    let weak = [b"W/", etag.as_bytes()].concat();
    resp.insert_header(ETAG, weak)
}

/// Rewrites an absolute-form request target (RFC 9112 §3.2.2) to origin-form, keeping
/// the original bytes. Ingress already required `Host` to equal its authority, so
/// nothing is lost, and mounts, image keys, redirects and upstream requests all see a
/// path. False for any other target without a path, such as `*` or `x:/a`: its URI
/// reads as `/` while the raw bytes would go upstream, so routing could not judge it.
fn to_origin_form(req: &mut RequestHeader) -> Result<bool> {
    let RawTargetAuthority::Absolute { path_and_query, .. } = raw_target_authority(req.raw_path())
    else {
        return Ok(req.raw_path().starts_with(b"/"));
    };
    let mut target = Vec::with_capacity(path_and_query.len() + 1);
    if !path_and_query.starts_with(b"/") {
        target.push(b'/');
    }
    target.extend_from_slice(path_and_query);
    req.set_raw_path(&target)?;
    Ok(true)
}

fn request_authority(req: &RequestHeader) -> Option<&[u8]> {
    req.uri
        .authority()
        .map(|a| a.as_str().as_bytes())
        .or_else(|| req.headers.get(HOST).map(|v| v.as_bytes()))
}

/// What the TLS handshake recorded about the connection.
fn conn(session: &Session) -> Option<&Conn> {
    let digest = session.as_downstream().digest()?.ssl_digest.as_ref()?;
    digest.extension.get::<Conn>()
}

/// The SNI name recorded on the connection, if any.
fn sni(session: &Session) -> Option<&str> {
    conn(session)?.sni.as_deref()
}

/// Answers locally with a small text body. Unlike `respond_error`, the connection
/// stays open for further requests.
async fn respond_local(session: &mut Session, status: u16, body: &'static [u8]) -> Result<()> {
    let mut resp = ResponseHeader::build(status, Some(3))?;
    resp.insert_header(CONTENT_TYPE, "text/plain")?;
    resp.insert_header(CONTENT_LENGTH, body.len())?;
    resp.insert_header(CACHE_CONTROL, "no-store")?;
    headers::add_hsts(&mut resp)?;
    session.write_response_header(Box::new(resp), false).await?;
    session
        .write_response_body(Some(Bytes::from_static(body)), true)
        .await
}

fn is_json(resp: &ResponseHeader) -> bool {
    resp.headers.get(CONTENT_TYPE).is_some_and(|v| {
        let v = v.as_bytes();
        v.len() >= 16 && v[..16].eq_ignore_ascii_case(b"application/json")
    })
}

/// How a request ended, as logged in `end`.
fn end_reason(e: Option<&Error>) -> End {
    use ErrorType::*;
    let Some(e) = e else {
        return End::Ok;
    };
    if *e.etype() == REFUSED {
        return End::RedirectRefused;
    }
    if *e.etype() == TERMINATED || *e.etype() == SHUTDOWN_ENDED {
        return End::Shutdown;
    }
    match (e.esource(), e.etype()) {
        (ErrorSource::Downstream, ReadTimedout | WriteTimedout) => End::ClientTimeout,
        (ErrorSource::Downstream, _) => End::ClientClosed,
        (ErrorSource::Upstream, ConnectTimedout | TLSHandshakeTimedout) => End::ConnectTimeout,
        (
            ErrorSource::Upstream,
            ConnectRefused | ConnectNoRoute | ConnectError | TLSHandshakeFailure | InvalidCert
            | HandshakeError | TLSWantX509Lookup | SocketError,
        ) => End::ConnectFailed,
        (ErrorSource::Upstream, ReadTimedout | WriteTimedout) => End::UpstreamTimeout,
        (ErrorSource::Upstream, ConnectionClosed | ReadError | WriteError) => End::UpstreamClosed,
        (ErrorSource::Upstream, _) => End::UpstreamError,
        _ => End::Internal,
    }
}

fn header_text(req: &RequestHeader, name: http::header::HeaderName, max: usize) -> Option<String> {
    let v = req.headers.get(name)?;
    Some(clip(&String::from_utf8_lossy(v.as_bytes()), max).to_owned())
}

/// The request target as logged: credentials removed, length capped.
fn logged_path(req: &RequestHeader) -> String {
    let raw = String::from_utf8_lossy(req.raw_path());
    redact(clip(&raw, MAX_PATH)).into_owned()
}

fn opt_str(j: &mut JsonLine, k: &str, v: Option<&str>) {
    match v {
        Some(v) => j.str(k, v),
        None => j.null(k),
    };
}

fn opt_num(j: &mut JsonLine, k: &str, v: Option<u64>) {
    match v {
        Some(v) => j.num(k, v),
        None => j.null(k),
    };
}

fn millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// The access log line for a finished request. Field meanings are documented with the
/// log format; every key is always present, `null` when unknown.
fn access_line(session: &Session, e: Option<&Error>, end: End, ctx: &Ctx) -> String {
    let req = session.req_header();
    let down = session.as_downstream();
    let mut j = JsonLine::with_capacity(640);
    j.str("ts", &utc_timestamp(SystemTime::now()));
    j.str("rid", &ctx.rid.to_string());
    opt_str(
        &mut j,
        "cid",
        conn(session).map(|c| c.id.to_string()).as_deref(),
    );
    opt_str(&mut j, "site", ctx.site_name());
    let client = down
        .client_addr()
        .and_then(|a| a.as_inet())
        .map(|a| canonical(a.ip()).to_string());
    opt_str(&mut j, "client", client.as_deref());
    j.str("proto", if down.is_http2() { "h2" } else { "h1" });
    j.str("method", req.method.as_str());
    j.str("path", &logged_path(req));
    j.str("class", ctx.class.as_str());
    let status = session
        .response_written()
        .map(|r| u64::from(r.status.as_u16()));
    opt_num(&mut j, "status", status);
    j.num("bytes_out", down.body_bytes_sent() as u64);
    j.num("bytes_in", down.body_bytes_read() as u64);
    opt_num(&mut j, "dur_ms", ctx.start.map(|s| millis(s.elapsed())));
    opt_num(&mut j, "ttfb_ms", ctx.ttfb.map(millis));
    opt_num(&mut j, "rewrite", ctx.rewritten.map(|n| n as u64));
    opt_str(&mut j, "cache", ctx.cache);
    j.str("end", end.as_str());
    let err = e.map(|e| redact(clip(&e.to_string(), MAX_ERR)).into_owned());
    opt_str(&mut j, "err", err.as_deref());
    j.array("up");
    for a in &ctx.attempts {
        j.object();
        j.num("src", u64::from(a.src));
        j.str("host", &a.host).str("addr", &a.addr.to_string());
        match a.reused {
            Some(r) => j.bool("reused", r),
            None => j.null("reused"),
        };
        opt_num(&mut j, "connect_ms", a.connect.map(millis));
        opt_str(&mut j, "proto", a.proto);
        opt_num(&mut j, "status", a.status.map(u64::from));
        opt_str(&mut j, "error", a.error);
        j.end_object();
    }
    j.end_array();
    opt_str(
        &mut j,
        "ua",
        header_text(req, http::header::USER_AGENT, MAX_UA).as_deref(),
    );
    opt_str(
        &mut j,
        "range",
        header_text(req, http::header::RANGE, MAX_RANGE).as_deref(),
    );
    let ray = ctx.cf_ray.as_ref().and_then(|v| v.to_str().ok());
    opt_str(&mut j, "cf_ray", ray);
    j.finish()
}

#[async_trait]
impl ProxyHttp for Relay {
    type CTX = Ctx;

    fn new_ctx(&self) -> Ctx {
        Ctx {
            rid: piano_telemetry::id::request(),
            start: Some(Instant::now()),
            ..Ctx::default()
        }
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Ctx) -> Result<bool> {
        let sites = self.sites.load_full();
        let Some(index) = request_authority(session.req_header()).and_then(|a| sites.find(a))
        else {
            ctx.class = RouteClass::Local;
            session.respond_error(421).await?;
            return Ok(true);
        };
        // A connection is bound to the site it was opened for: a certificate covering
        // several sites must not let one site's connection reach another.
        if sni(session).is_some_and(|name| sites.find(name.as_bytes()) != Some(index)) {
            ctx.class = RouteClass::Local;
            session.respond_error(421).await?;
            return Ok(true);
        }
        if !to_origin_form(session.req_header_mut())? {
            ctx.class = RouteClass::Local;
            session.respond_error(400).await?;
            return Ok(true);
        }
        ctx.sites = Some(Arc::clone(&sites));
        ctx.site = index;
        let site = ctx.site()?;
        let server_domains = site.policy.server_domains;

        let path = session.req_header().uri.path();
        // A mounted prefix names another host of the upstream service; the rest of the
        // path is what that host serves, so it is also what routing looks at.
        let (path, mount) = match site.policy.mounts.find(path.as_bytes()) {
            Some((host, len)) => {
                let target = Target {
                    host: host.to_owned(),
                    port: site.origin.port,
                    path: session.req_header().raw_path()[len..].to_vec(),
                };
                (&path[len..], Some(target))
            }
            None => (path, None),
        };
        if path == HEALTH_PATH {
            ctx.class = RouteClass::Local;
            respond_local(session, 200, b"ok\n").await?;
            return Ok(true);
        }
        if site.policy.block.blocks(path) {
            ctx.class = RouteClass::Local;
            respond_local(session, 404, b"").await?;
            return Ok(true);
        }
        ctx.class = route::classify(path);
        ctx.hop = mount.map(|target| Hop {
            target,
            kind: TargetKind::Upstream,
        });
        // Whether the response body is collected for rewriting, and if so as a probe.
        let probe = if matches!(ctx.class, RouteClass::Info | RouteClass::PlaybackInfo) {
            let mode = if route::is_server_domains(path) {
                server_domains
            } else {
                ServerDomains::Rewrite
            };
            match mode {
                ServerDomains::Block => {
                    ctx.class = RouteClass::Local;
                    respond_local(session, 404, b"").await?;
                    return Ok(true);
                }
                ServerDomains::Pass => None,
                ServerDomains::Rewrite => Some(false),
            }
        } else if ctx.class == RouteClass::Api
            && session.req_header().method == Method::GET
            && self.probe_due()
        {
            Some(true)
        } else {
            None
        };
        if let Some(probe) = probe {
            let authority = request_authority(session.req_header()).unwrap_or_default();
            ctx.rewrite = Some(Rewrite {
                probe,
                authority: public_authority(&ctx.site()?.host, authority),
                collecting: false,
                body: Vec::new(),
            });
            enable_compression(session);
        }
        let downstream = session.as_downstream_mut();
        downstream.set_write_timeout(Some(ctx.class.downstream_write_timeout()));
        if ctx.class.may_idle() {
            downstream.set_read_timeout(None);
        }
        if ctx.class == RouteClass::Media && media::takes(session) {
            media::relay(self, session, ctx).await?;
            return Ok(true);
        }
        if ctx.class == RouteClass::Image && image::takes(session) {
            return image::serve(self, session, ctx).await;
        }
        Ok(false)
    }

    async fn upstream_peer(&self, _session: &mut Session, ctx: &mut Ctx) -> Result<Box<HttpPeer>> {
        let host = ctx.target_host()?.to_owned();
        let site = ctx.site()?;
        let (mut peer, addrs, addr) = self.reach.peer(site, ctx.hop.as_ref()).await?;
        if image::at_origin(site, ctx.hop.as_ref()) {
            self.images.budget(site).charge(Instant::now());
        }
        if ctx.class.may_idle() {
            peer.options.read_timeout = None;
            peer.options.write_timeout = None;
        }
        if site.origin.options.h2 && ctx.class.multiplexed() {
            piano_upstream::offer_h2(&mut peer);
        }
        ctx.attempt = Some(Attempt { addrs, addr });
        ctx.attempts.push(AttemptLog::new(0, host, addr));
        Ok(Box::new(peer))
    }

    async fn connected_to_upstream(
        &self,
        _session: &mut Session,
        reused: bool,
        _peer: &HttpPeer,
        _fd: std::os::unix::io::RawFd,
        _digest: Option<&Digest>,
        ctx: &mut Ctx,
    ) -> Result<()> {
        if let Some(a) = ctx.attempts.last_mut() {
            a.connected(reused);
        }
        Ok(())
    }

    fn fail_to_connect(
        &self,
        _session: &mut Session,
        _peer: &HttpPeer,
        ctx: &mut Ctx,
        mut e: Box<Error>,
    ) -> Box<Error> {
        if let Some(a) = ctx.attempts.last_mut() {
            a.error = Some(e.etype().as_str());
        }
        if !is_connect_failure(e.etype()) {
            return e;
        }
        // Retrying only makes sense on an address not tried yet for this request.
        let untried = ctx.attempt.take().is_some_and(|a| {
            a.addrs.failed(a.addr);
            usize::from(ctx.connect_retries) + 1 < a.addrs.len()
        });
        // Nothing reached the upstream, so any method may be retried.
        if untried && ctx.connect_retries < CONNECT_RETRIES {
            ctx.connect_retries += 1;
            e.set_retry(true);
        }
        e
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Ctx,
    ) -> Result<()> {
        reach::prepare_request(ctx.site()?, ctx.hop.as_ref(), upstream_request)?;
        if ctx.rewrite.is_some() {
            upstream_request.insert_header(ACCEPT_ENCODING, "identity")?;
        }
        Ok(())
    }

    async fn upstream_response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Ctx,
    ) -> Result<()> {
        let status = upstream_response.status.as_u16();
        if let Some(a) = ctx.attempts.last_mut() {
            a.status = Some(status);
            a.proto = Some(proto_of(upstream_response.version));
        }
        ctx.ttfb = ctx.start.map(|s| s.elapsed());
        ctx.cf_ray = upstream_response.headers.get("cf-ray").cloned();
        let site = ctx.site()?;
        if image::at_origin(site, ctx.hop.as_ref()) {
            image::note_upstream(&self.images.budget(site), upstream_response);
        }
        if !follow::is_redirect(status) {
            return Ok(());
        }
        let Some(location) = upstream_response.headers.get(LOCATION) else {
            return Ok(());
        };
        let hop = reach::redirect(
            ctx.sites
                .as_deref()
                .ok_or_else(|| Error::explain(ErrorType::InternalError, "no sites"))?,
            ctx.site()?,
            &session.req_header().method,
            ctx.hops,
            ctx.hop.as_ref(),
            session.req_header().raw_path(),
            location.as_bytes(),
        )?;
        ctx.hop = Some(hop);
        ctx.hops += 1;
        let mut e = Error::new(FOLLOW);
        e.set_retry(true);
        Err(e)
    }

    async fn response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Ctx,
    ) -> Result<()> {
        let site_host = ctx.site()?.host.clone();
        headers::scrub_response(upstream_response, ctx.target_host()?, &site_host)?;
        let Some(rewrite) = ctx.rewrite.as_mut() else {
            return Ok(());
        };
        let encoded = upstream_response
            .headers
            .get(CONTENT_ENCODING)
            .is_some_and(|v| !v.as_bytes().eq_ignore_ascii_case(b"identity"));
        if encoded {
            warn!(
                rid:% = ctx.rid;
                "site {site_host}: upstream compressed {} despite Accept-Encoding: identity; \
                 passed on without rewriting",
                session.req_header().uri.path()
            );
            return Ok(());
        }
        if upstream_response.status != 200 {
            return Ok(());
        }
        if rewrite.probe && !is_json(upstream_response) {
            return Ok(());
        }
        // HEAD describes what GET would send: no body to collect, the same headers.
        rewrite.collecting = session.req_header().method != Method::HEAD;
        upstream_response.remove_header(&CONTENT_LENGTH);
        upstream_response.insert_header(TRANSFER_ENCODING, "chunked")?;
        weaken_etag(upstream_response)
    }

    async fn upstream_response_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
        ctx: &mut Ctx,
    ) -> Result<Option<Duration>> {
        if let (Some(b), Ok(site)) = (body.as_ref(), ctx.site()) {
            site.counters.add_fetched(ctx.class.kind(), b.len() as u64);
        }
        Ok(None)
    }

    async fn response_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Ctx,
    ) -> Result<Option<Duration>> {
        let Some(rewrite) = ctx.rewrite.as_mut().filter(|r| r.collecting) else {
            return Ok(None);
        };
        if let Some(chunk) = body.take() {
            if rewrite.body.len() + chunk.len() > MAX_BODY {
                warn!(
                    rid:% = ctx.rid;
                    "{} is larger than {MAX_BODY} bytes; passed on without rewriting",
                    session.req_header().uri.path()
                );
                rewrite.collecting = false;
                let mut all = std::mem::take(&mut rewrite.body);
                all.extend_from_slice(&chunk);
                *body = Some(Bytes::from(all));
                return Ok(None);
            }
            rewrite.body.extend_from_slice(&chunk);
        }
        if !end_of_stream {
            return Ok(None);
        }
        rewrite.collecting = false;
        let probe = rewrite.probe;
        let collected = std::mem::take(&mut rewrite.body);
        let authority = std::mem::take(&mut rewrite.authority);
        let site = ctx.site()?;
        let (out, n) = site
            .policy
            .rewriter
            .rewrite(&collected, &site.host, &authority)
            .unwrap_or((collected, 0));
        if probe && n > 0 {
            warn!(
                rid:% = ctx.rid, site = site.name.as_str();
                "upstream named itself in {}, a response passed on unchanged by default; \
                 {n} addresses replaced in this sampled copy",
                logged_path(session.req_header())
            );
        }
        ctx.rewritten = Some(n);
        *body = Some(Bytes::from(out));
        Ok(None)
    }

    fn error_while_proxy(
        &self,
        peer: &HttpPeer,
        session: &mut Session,
        e: Box<Error>,
        ctx: &mut Ctx,
        client_reused: bool,
    ) -> Box<Error> {
        if *e.etype() == FOLLOW {
            return e;
        }
        if let Some(a) = ctx.attempts.last_mut().filter(|a| a.error.is_none()) {
            a.error = Some(e.etype().as_str());
        }
        let mut e = e.more_context(format!("Peer: {peer}"));
        // Once the response has started, another attempt would append a second body.
        if session.response_written().is_some()
            || !session.req_header().method.is_idempotent()
            || session.as_ref().retry_buffer_truncated()
        {
            e.set_retry(false);
        } else {
            e.retry.decide_reuse(client_reused);
        }
        e
    }

    /// Each attempt's outcome is in the access log; the final error is logged by
    /// [`Self::logging`] with the request id and a level that follows its cause.
    async fn fail_to_proxy(&self, session: &mut Session, e: &Error, _ctx: &mut Ctx) -> FailToProxy {
        use ErrorType::*;
        let code = match e.etype() {
            HTTPStatus(code) => *code,
            // Retryable at once: the next process is about to listen.
            _ if *e.etype() == TERMINATED => 503,
            _ => match e.esource() {
                ErrorSource::Upstream => 502,
                ErrorSource::Downstream => match e.etype() {
                    WriteError | ReadError | ConnectionClosed => 0,
                    _ => 400,
                },
                ErrorSource::Internal | ErrorSource::Unset => 500,
            },
        };
        if code > 0 && session.response_written().is_none() {
            let _ = session.respond_error(code).await;
        }
        FailToProxy {
            error_code: code,
            can_reuse_downstream: false,
        }
    }

    fn suppress_proxy_warn_log(
        &self,
        _session: &Session,
        _ctx: &Ctx,
        _error: &Error,
        _context: ProxyWarnLogContext,
    ) -> bool {
        true
    }

    fn suppress_error_log(&self, _session: &Session, _ctx: &Ctx, _error: &Error) -> bool {
        true
    }

    fn request_summary(&self, session: &Session, ctx: &Ctx) -> String {
        let req = session.req_header();
        format!("rid={} {} {}", ctx.rid, req.method, logged_path(req))
    }

    async fn logging(&self, session: &mut Session, e: Option<&Error>, ctx: &mut Ctx) {
        let end = end_reason(e);
        let status = session.response_written().map(|r| r.status.as_u16());
        let reused = ctx
            .attempts
            .iter()
            .filter(|a| a.reused == Some(true))
            .count();
        let counters = match ctx.site() {
            Ok(site) => &site.counters,
            Err(_) => &self.unrouted,
        };
        if !ctx.sent_counted {
            let sent = session.as_downstream().body_bytes_sent() as u64;
            counters.add_sent(ctx.class.kind(), sent);
        }
        counters.record(status, end, ctx.attempts.len(), reused);
        if !ctx.ttfb_counted
            && let (Some(t), Some(kind)) = (ctx.ttfb, ctx.class.ttfb(&session.req_header().method))
        {
            counters.record_ttfb(kind, t);
        }
        if let Some(e) = e {
            let site = ctx.site_name().unwrap_or("-");
            let path = logged_path(session.req_header());
            let reason = end.as_str();
            match end {
                End::ClientClosed | End::ClientTimeout | End::Shutdown => {
                    debug!(rid:% = ctx.rid, site, end = reason; "{path}: {e}");
                }
                End::Internal => error!(rid:% = ctx.rid, site, end = reason; "{path}: {e}"),
                _ => warn!(rid:% = ctx.rid, site, end = reason; "{path}: {e}"),
            }
        }
        if self.access.enabled() {
            self.access.write(access_line(session, e, end, ctx));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absolute_form_becomes_origin_form() {
        for (target, want) in [
            (
                &b"https://media.example.com:8443/a/b?c=1"[..],
                &b"/a/b?c=1"[..],
            ),
            (b"http://media.example.com?q=1", b"/?q=1"),
            (b"https://media.example.com", b"/"),
            (b"https://media.example.com/a\xffb", b"/a\xffb"),
            (b"/already/origin?x", b"/already/origin?x"),
        ] {
            let mut req = RequestHeader::build("GET", target, None).unwrap();
            assert!(to_origin_form(&mut req).unwrap());
            assert_eq!(req.raw_path(), want, "{}", String::from_utf8_lossy(target));
        }
        for target in [&b"*"[..], b"x:/emby/System/Info", b"urn:x"] {
            let mut req = RequestHeader::build("OPTIONS", target, None).unwrap();
            assert!(
                !to_origin_form(&mut req).unwrap(),
                "{}",
                String::from_utf8_lossy(target)
            );
        }
    }
}
