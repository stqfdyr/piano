//! The `ProxyHttp` implementation.

use crate::route::{self, HEALTH_PATH, RouteClass};
use crate::{Site, Sites};
use arc_swap::ArcSwap;
use async_trait::async_trait;
use bytes::Bytes;
use http::header::{CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, HOST};
use piano_edge::tls::Sni;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_error::{Error, ErrorType, Result};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::{ProxyHttp, Session};
use std::sync::Arc;

/// Per-request state; one per HTTP/2 stream or HTTP/1 request.
#[derive(Debug, Default)]
pub struct Ctx {
    /// The site table taken when the request started; a reload does not change it.
    sites: Option<Arc<Sites>>,
    site: usize,
    pub class: RouteClass,
}

impl Ctx {
    fn site(&self) -> Result<&Site> {
        self.sites
            .as_deref()
            .and_then(|s| s.get(self.site))
            .ok_or_else(|| Error::explain(ErrorType::InternalError, "no site selected"))
    }
}

/// Relays each request to the origin of the site named by its host.
#[derive(Debug)]
pub struct Relay {
    sites: Arc<ArcSwap<Sites>>,
}

impl Relay {
    pub fn new(sites: Arc<ArcSwap<Sites>>) -> Self {
        Self { sites }
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
    session.write_response_header(Box::new(resp), false).await?;
    session
        .write_response_body(Some(Bytes::from_static(body)), true)
        .await
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
        if site.block.blocks(path) {
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
        Ok(Box::new(ctx.site()?.origin.peer()?))
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Ctx,
    ) -> Result<()> {
        upstream_request.insert_header(HOST, ctx.site()?.upstream_host.clone())?;
        Ok(())
    }
}
