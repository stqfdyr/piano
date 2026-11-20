//! The `ProxyHttp` implementation.

use crate::follow::{self, MAX_HOPS, Target, TargetKind};
use crate::headers;
use crate::rewrite::MAX_BODY;
use crate::route::{self, HEALTH_PATH, RouteClass};
use crate::{Site, Sites};
use arc_swap::ArcSwap;
use async_trait::async_trait;
use bytes::Bytes;
use http::HeaderValue;
use http::Method;
use http::header::{
    ACCEPT_ENCODING, AUTHORIZATION, CACHE_CONTROL, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE,
    COOKIE, ETAG, HOST, LOCATION, TRANSFER_ENCODING,
};
use log::{debug, error, warn};
use piano_config::ServerDomains;
use piano_edge::acl::canonical;
use piano_edge::tls::Conn;
use piano_telemetry::json::JsonLine;
use piano_telemetry::logger::utc_timestamp;
use piano_telemetry::{AccessLog, Id, redact};
use piano_upstream::{AddrCache, Addrs, Origin, Resolver};
use pingora_core::modules::http::compression::ResponseCompression;
use pingora_core::protocols::Digest;
use pingora_core::protocols::http::compression::Algorithm;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_error::{Error, ErrorSource, ErrorType, Result};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::{ProxyHttp, ProxyWarnLogContext, Session};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

/// Further attempts after failing to connect, each to the host's next address.
const CONNECT_RETRIES: u8 = 2;

/// Total upstream attempts per request: the first, every redirect hop and every
/// connection retry. A status the upstream answered with is never retried: the
/// upstreams sit behind a CDN whose 502, 503 and 504 report the state of the server
/// behind it, which an immediate repeat does not change. Failures on a reused pooled
/// connection are retried by pingora itself and also count here.
pub const MAX_ATTEMPTS: usize = 1 + MAX_HOPS as usize + CONNECT_RETRIES as usize;

/// How long a redirect target keeps the address it was first resolved to.
const FOLLOW_ADDR_TTL: Duration = Duration::from_secs(300);

/// Marks the error that makes pingora run another attempt towards a redirect target.
const FOLLOW: ErrorType = ErrorType::Custom("FollowRedirect");
/// A redirect that is not followed; the client gets 502.
const REFUSED: ErrorType = ErrorType::Custom("RedirectRefused");

/// Longest path, User-Agent, Range and error text written to the access log, in bytes.
const MAX_PATH: usize = 2048;
const MAX_UA: usize = 256;
const MAX_RANGE: usize = 128;
const MAX_ERR: usize = 512;
/// Compression levels for rewritten bodies, which can no longer pass on the upstream's
/// compressed bytes.
const GZIP_LEVEL: u32 = 6;
const BROTLI_LEVEL: u32 = 5;

/// Client credentials, sent only to the upstream server itself.
const CREDENTIAL_HEADERS: [&str; 3] = [
    "x-emby-authorization",
    "x-emby-token",
    "x-mediabrowser-token",
];

/// A redirect being followed.
#[derive(Debug)]
struct Hop {
    target: Target,
    kind: TargetKind,
}

/// The address the current attempt connects to.
#[derive(Debug)]
struct Attempt {
    addrs: Arc<Addrs>,
    addr: SocketAddr,
}

/// What one upstream attempt did, for the access log.
#[derive(Debug)]
struct AttemptLog {
    host: String,
    addr: SocketAddr,
    issued: Instant,
    /// Unset until a connection was obtained.
    reused: Option<bool>,
    /// Time to set up a new connection, TCP and TLS.
    connect: Option<Duration>,
    /// Status of the response header the upstream sent.
    status: Option<u16>,
    /// What ended the attempt, if it failed.
    error: Option<&'static str>,
}

/// A response body being collected for rewriting.
#[derive(Debug)]
struct Rewrite {
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
    start: Option<Instant>,
    /// Every upstream attempt, in order.
    attempts: Vec<AttemptLog>,
    /// From the request to the upstream response header the client got.
    ttfb: Option<Duration>,
    cf_ray: Option<HeaderValue>,
    /// The site table taken when the request started; a reload does not change it.
    sites: Option<Arc<Sites>>,
    site: usize,
    pub class: RouteClass,
    hop: Option<Hop>,
    /// Redirects followed so far.
    pub hops: u8,
    attempt: Option<Attempt>,
    /// Attempts repeated because connecting failed.
    pub connect_retries: u8,
    rewrite: Option<Rewrite>,
}

impl Ctx {
    fn site(&self) -> Result<&Site> {
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
    resolver: Resolver,
    follow_addrs: AddrCache,
    access: Arc<AccessLog>,
}

impl Relay {
    pub fn new(sites: Arc<ArcSwap<Sites>>, resolver: Resolver, access: Arc<AccessLog>) -> Self {
        Self {
            sites,
            resolver,
            follow_addrs: AddrCache::new(FOLLOW_ADDR_TTL),
            access,
        }
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

/// Failures to reach the address at all, as opposed to failures of TLS with a server
/// that answered.
fn is_connect_failure(e: &ErrorType) -> bool {
    matches!(
        e,
        ErrorType::ConnectTimedout
            | ErrorType::ConnectRefused
            | ErrorType::ConnectNoRoute
            | ErrorType::ConnectError
            | ErrorType::TLSHandshakeTimedout
    )
}

/// A redirect that will not be followed: the client gets 502, never the Location.
/// The reason ends up in the access log and the diagnostic log; it must name hosts
/// only, since redirect targets carry signed paths.
fn refuse_redirect(reason: String) -> Box<Error> {
    Error::create(REFUSED, ErrorSource::Upstream, Some(reason.into()), None)
}

/// How a request ended, as logged in `end`.
fn end_reason(e: Option<&Error>) -> &'static str {
    use ErrorType::*;
    let Some(e) = e else {
        return "ok";
    };
    if *e.etype() == REFUSED {
        return "redirect_refused";
    }
    match (e.esource(), e.etype()) {
        (ErrorSource::Downstream, ReadTimedout | WriteTimedout) => "client_timeout",
        (ErrorSource::Downstream, _) => "client_closed",
        (ErrorSource::Upstream, ConnectTimedout | TLSHandshakeTimedout) => "connect_timeout",
        (
            ErrorSource::Upstream,
            ConnectRefused | ConnectNoRoute | ConnectError | TLSHandshakeFailure | InvalidCert
            | HandshakeError | TLSWantX509Lookup | SocketError,
        ) => "connect_failed",
        (ErrorSource::Upstream, ReadTimedout | WriteTimedout) => "upstream_timeout",
        (ErrorSource::Upstream, ConnectionClosed | ReadError | WriteError) => "upstream_closed",
        (ErrorSource::Upstream, _) => "upstream_error",
        _ => "internal",
    }
}

/// The longest prefix of `s` within `max` bytes that ends on a char boundary.
fn clip(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
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
fn access_line(session: &Session, e: Option<&Error>, end: &str, ctx: &Ctx) -> String {
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
    j.str("end", end);
    let err = e.map(|e| redact(clip(&e.to_string(), MAX_ERR)).into_owned());
    opt_str(&mut j, "err", err.as_deref());
    j.array("up");
    for a in &ctx.attempts {
        j.object();
        j.str("host", &a.host).str("addr", &a.addr.to_string());
        match a.reused {
            Some(r) => j.bool("reused", r),
            None => j.null("reused"),
        };
        opt_num(&mut j, "connect_ms", a.connect.map(millis));
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
        ctx.sites = Some(Arc::clone(&sites));
        ctx.site = index;
        let site = ctx.site()?;
        let authority = request_authority(session.req_header()).unwrap_or_default();
        let public = public_authority(&site.host, authority);
        let server_domains = site.policy.server_domains;

        let path = session.req_header().uri.path();
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
        if matches!(ctx.class, RouteClass::Info | RouteClass::PlaybackInfo) {
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
                ServerDomains::Pass => {}
                ServerDomains::Rewrite => {
                    ctx.rewrite = Some(Rewrite {
                        authority: public,
                        collecting: false,
                        body: Vec::new(),
                    });
                    enable_compression(session);
                }
            }
        }
        let downstream = session.as_downstream_mut();
        downstream.set_write_timeout(Some(ctx.class.downstream_write_timeout()));
        if ctx.class.may_idle() {
            downstream.set_read_timeout(None);
        }
        Ok(false)
    }

    async fn upstream_peer(&self, _session: &mut Session, ctx: &mut Ctx) -> Result<Box<HttpPeer>> {
        let host = ctx.target_host()?.to_owned();
        let site = ctx.site()?;
        let (mut peer, addrs, addr) = match &ctx.hop {
            None => {
                let addr = site.origin.addrs.current();
                let peer = site.origin.peer(addr)?;
                (peer, Arc::clone(&site.origin.addrs), addr)
            }
            Some(hop) => {
                let t = &hop.target;
                let addrs = if t.host == site.origin.host && t.port == site.origin.port {
                    Arc::clone(&site.origin.addrs)
                } else {
                    self.follow_addrs
                        .get(&self.resolver, &t.host, t.port)
                        .await
                        .map_err(|e| refuse_redirect(format!("{}: {e}", t.host)))?
                };
                let origin = Origin {
                    host: t.host.clone(),
                    port: t.port,
                    addrs,
                    options: site.origin.options,
                };
                let addr = origin.addrs.current();
                (origin.peer(addr)?, origin.addrs, addr)
            }
        };
        if ctx.class.may_idle() {
            peer.options.read_timeout = None;
            peer.options.write_timeout = None;
        }
        ctx.attempt = Some(Attempt { addrs, addr });
        ctx.attempts.push(AttemptLog {
            host,
            addr,
            issued: Instant::now(),
            reused: None,
            connect: None,
            status: None,
            error: None,
        });
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
            a.reused = Some(reused);
            if !reused {
                a.connect = Some(a.issued.elapsed());
            }
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
        if let Some(a) = ctx.attempt.take() {
            a.addrs.failed(a.addr);
        }
        // Nothing reached the upstream, so any method may be retried.
        if ctx.connect_retries < CONNECT_RETRIES {
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
        let site = ctx.site()?;
        match &ctx.hop {
            None => upstream_request.insert_header(HOST, site.upstream_host.clone())?,
            Some(hop) => {
                upstream_request.set_raw_path(&hop.target.path)?;
                upstream_request.insert_header(HOST, hop.target.authority())?;
                if hop.kind == TargetKind::Follow {
                    upstream_request.remove_header(&COOKIE);
                    upstream_request.remove_header(&AUTHORIZATION);
                    for name in CREDENTIAL_HEADERS {
                        upstream_request.remove_header(name);
                    }
                }
            }
        }
        if ctx.rewrite.is_some() {
            upstream_request.insert_header(ACCEPT_ENCODING, "identity")?;
        }
        headers::scrub_request(upstream_request);
        headers::rewrite_user_agent(&site.policy.ua, upstream_request)?;
        headers::join_cookies(upstream_request)?;
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
        }
        ctx.ttfb = ctx.start.map(|s| s.elapsed());
        ctx.cf_ray = upstream_response.headers.get("cf-ray").cloned();
        if !follow::is_redirect(status) {
            return Ok(());
        }
        let Some(location) = upstream_response.headers.get(LOCATION) else {
            return Ok(());
        };
        let site = ctx.site()?;
        let method = &session.req_header().method;
        if method != Method::GET && method != Method::HEAD {
            return Err(refuse_redirect(format!("{} request redirected", method)));
        }
        if ctx.hops >= MAX_HOPS {
            return Err(refuse_redirect(format!("more than {MAX_HOPS} redirects")));
        }
        let base = match &ctx.hop {
            Some(h) => h.target.clone(),
            None => Target {
                host: site.origin.host.clone(),
                port: site.origin.port,
                path: session.req_header().raw_path().to_vec(),
            },
        };
        let target = follow::resolve(location.as_bytes(), &base).map_err(|e| {
            let shown = String::from_utf8_lossy(location.as_bytes());
            refuse_redirect(format!("{e}: {:?}", clip(&shown, 200)))
        })?;
        // A site of this relay would receive the request again and could loop.
        if ctx
            .sites
            .as_deref()
            .is_some_and(|s| s.find(target.host.as_bytes()).is_some())
        {
            return Err(refuse_redirect(format!(
                "site {}: redirect to {}, a site of this relay",
                site.name, target.host
            )));
        }
        let Some(kind) = site.policy.follow.kind(&target.host) else {
            return Err(refuse_redirect(format!(
                "site {}: {} is not in follow",
                site.name, target.host
            )));
        };
        ctx.hop = Some(Hop { target, kind });
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
        if upstream_response.status != 200 || session.req_header().method == Method::HEAD {
            return Ok(());
        }
        rewrite.collecting = true;
        upstream_response.remove_header(&CONTENT_LENGTH);
        upstream_response.insert_header(TRANSFER_ENCODING, "chunked")?;
        weaken_etag(upstream_response)
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
        let collected = std::mem::take(&mut rewrite.body);
        let authority = std::mem::take(&mut rewrite.authority);
        let site = ctx.site()?;
        let out = site
            .policy
            .rewriter
            .rewrite(&collected, &site.host, &authority)
            .unwrap_or(collected);
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
        if let Some(e) = e {
            let site = ctx.site_name().unwrap_or("-");
            let path = logged_path(session.req_header());
            match end {
                "client_closed" | "client_timeout" => {
                    debug!(rid:% = ctx.rid, site, end; "{path}: {e}");
                }
                "internal" => error!(rid:% = ctx.rid, site, end; "{path}: {e}"),
                _ => warn!(rid:% = ctx.rid, site, end; "{path}: {e}"),
            }
        }
        if self.access.enabled() {
            self.access.write(access_line(session, e, end, ctx));
        }
    }
}
