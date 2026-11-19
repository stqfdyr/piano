//! The `ProxyHttp` implementation.

use crate::follow::{self, MAX_HOPS, Target, TargetKind};
use crate::headers;
use crate::route::{self, HEALTH_PATH, RouteClass};
use crate::{Site, Sites};
use arc_swap::ArcSwap;
use async_trait::async_trait;
use bytes::Bytes;
use http::Method;
use http::header::{
    AUTHORIZATION, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, COOKIE, HOST, LOCATION,
};
use log::warn;
use piano_edge::tls::Sni;
use piano_upstream::{AddrCache, Addrs, Origin, Resolver};
use pingora_core::upstreams::peer::HttpPeer;
use pingora_error::{Error, ErrorType, Result};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::{ProxyHttp, ProxyWarnLogContext, Session};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

/// Further attempts after failing to connect, each to the host's next address.
const CONNECT_RETRIES: u8 = 2;

/// Further attempts after the upstream answers 502 or 504. Never after 503: upstreams
/// use it for deliberate refusals that a retry would only repeat.
const STATUS_RETRIES: u8 = 1;

/// Total upstream attempts per request: the first, every redirect hop and every retry.
pub const MAX_ATTEMPTS: usize =
    1 + MAX_HOPS as usize + CONNECT_RETRIES as usize + STATUS_RETRIES as usize;

/// How long a redirect target keeps the address it was first resolved to.
const FOLLOW_ADDR_TTL: Duration = Duration::from_secs(300);

/// Marks the error that makes pingora run another attempt towards a redirect target.
const FOLLOW: ErrorType = ErrorType::Custom("FollowRedirect");

/// Marks the error that makes pingora repeat an attempt the upstream answered with 502
/// or 504.
const STATUS_RETRY: ErrorType = ErrorType::Custom("UpstreamStatusRetry");

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

/// Per-request state; one per HTTP/2 stream or HTTP/1 request.
#[derive(Debug, Default)]
pub struct Ctx {
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
    /// Attempts repeated because the upstream answered 502 or 504.
    pub status_retries: u8,
}

impl Ctx {
    fn site(&self) -> Result<&Site> {
        self.sites
            .as_deref()
            .and_then(|s| s.get(self.site))
            .ok_or_else(|| Error::explain(ErrorType::InternalError, "no site selected"))
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
}

impl Relay {
    pub fn new(sites: Arc<ArcSwap<Sites>>, resolver: Resolver) -> Self {
        Self {
            sites,
            resolver,
            follow_addrs: AddrCache::new(FOLLOW_ADDR_TTL),
        }
    }
}

fn request_authority(req: &RequestHeader) -> Option<&[u8]> {
    req.uri
        .authority()
        .map(|a| a.as_str().as_bytes())
        .or_else(|| req.headers.get(HOST).map(|v| v.as_bytes()))
}

/// The SNI name recorded on the connection, if any.
fn sni(session: &Session) -> Option<&str> {
    let digest = session.as_downstream().digest()?.ssl_digest.as_ref()?;
    digest.extension.get::<Sni>().map(|s| s.0.as_str())
}

/// Answers locally with a small text body. Unlike `respond_error`, the connection
/// stays open for further requests.
async fn respond_local(session: &mut Session, status: u16, body: &'static [u8]) -> Result<()> {
    let mut resp = ResponseHeader::build(status, Some(3))?;
    resp.insert_header(CONTENT_TYPE, "text/plain")?;
    resp.insert_header(CONTENT_LENGTH, body.len())?;
    resp.insert_header(CACHE_CONTROL, "no-store")?;
    headers::add_security_headers(&mut resp)?;
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
fn refuse_redirect(reason: String) -> Box<Error> {
    warn!("refused upstream redirect: {reason}");
    Error::explain(ErrorType::HTTPStatus(502), reason)
}

#[async_trait]
impl ProxyHttp for Relay {
    type CTX = Ctx;

    fn new_ctx(&self) -> Ctx {
        Ctx::default()
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Ctx) -> Result<bool> {
        let sites = self.sites.load_full();
        let Some(index) = request_authority(session.req_header()).and_then(|a| sites.find(a))
        else {
            session.respond_error(421).await?;
            return Ok(true);
        };
        // A connection is bound to the site it was opened for: a certificate covering
        // several sites must not let one site's connection reach another.
        if sni(session).is_some_and(|name| sites.find(name.as_bytes()) != Some(index)) {
            session.respond_error(421).await?;
            return Ok(true);
        }
        ctx.sites = Some(Arc::clone(&sites));
        ctx.site = index;
        let site = ctx.site()?;

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
        session
            .as_downstream_mut()
            .set_write_timeout(Some(ctx.class.downstream_write_timeout()));
        Ok(false)
    }

    async fn upstream_peer(&self, _session: &mut Session, ctx: &mut Ctx) -> Result<Box<HttpPeer>> {
        let site = ctx.site()?;
        let (peer, addrs, addr) = match &ctx.hop {
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
        ctx.attempt = Some(Attempt { addrs, addr });
        Ok(Box::new(peer))
    }

    fn fail_to_connect(
        &self,
        _session: &mut Session,
        _peer: &HttpPeer,
        ctx: &mut Ctx,
        mut e: Box<Error>,
    ) -> Box<Error> {
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
        headers::scrub_request(upstream_request);
        headers::rewrite_user_agent(&site.policy.ua, upstream_request)?;
        headers::strip_cookies(&site.policy.strip_cookies, upstream_request)?;
        Ok(())
    }

    async fn upstream_response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Ctx,
    ) -> Result<()> {
        let status = upstream_response.status.as_u16();
        if matches!(status, 502 | 504)
            && ctx.status_retries < STATUS_RETRIES
            && session.req_header().method.is_idempotent()
        {
            ctx.status_retries += 1;
            let mut e = Error::explain(STATUS_RETRY, format!("upstream answered {status}"));
            e.set_retry(true);
            return Err(e);
        }
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
        let target = follow::resolve(location.as_bytes(), &base)
            .map_err(|e| refuse_redirect(format!("{e}: {:?}", location)))?;
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
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Ctx,
    ) -> Result<()> {
        let site_host = ctx.site()?.host.clone();
        headers::scrub_response(upstream_response, ctx.target_host()?, &site_host)
    }

    fn error_while_proxy(
        &self,
        peer: &HttpPeer,
        session: &mut Session,
        e: Box<Error>,
        _ctx: &mut Ctx,
        client_reused: bool,
    ) -> Box<Error> {
        if *e.etype() == FOLLOW {
            return e;
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

    fn suppress_proxy_warn_log(
        &self,
        _session: &Session,
        _ctx: &Ctx,
        error: &Error,
        _context: ProxyWarnLogContext,
    ) -> bool {
        *error.etype() == FOLLOW
    }
}
