//! The `ProxyHttp` implementation.

use crate::Sites;
use async_trait::async_trait;
use http::header::HOST;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_error::{Error, ErrorType, Result};
use pingora_http::RequestHeader;
use pingora_proxy::{ProxyHttp, Session};
use std::sync::Arc;

/// Per-request state; one per HTTP/2 stream or HTTP/1 request.
#[derive(Debug, Default)]
pub struct Ctx {
    site: Option<usize>,
}

/// Relays each request to the origin of the site named by its host.
#[derive(Debug)]
pub struct Relay {
    sites: Arc<Sites>,
}

impl Relay {
    pub fn new(sites: Arc<Sites>) -> Self {
        Self { sites }
    }
}

fn request_authority(req: &RequestHeader) -> Option<&[u8]> {
    req.uri
        .authority()
        .map(|a| a.as_str().as_bytes())
        .or_else(|| req.headers.get(HOST).map(|v| v.as_bytes()))
}

#[async_trait]
impl ProxyHttp for Relay {
    type CTX = Ctx;

    fn new_ctx(&self) -> Ctx {
        Ctx::default()
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Ctx) -> Result<bool> {
        ctx.site = request_authority(session.req_header()).and_then(|a| self.sites.find(a));
        if ctx.site.is_none() {
            session.respond_error(421).await?;
            return Ok(true);
        }
        Ok(false)
    }

    async fn upstream_peer(&self, _session: &mut Session, ctx: &mut Ctx) -> Result<Box<HttpPeer>> {
        let site = ctx
            .site
            .and_then(|i| self.sites.get(i))
            .ok_or_else(|| Error::explain(ErrorType::InternalError, "no site selected"))?;
        Ok(Box::new(site.origin.peer()?))
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Ctx,
    ) -> Result<()> {
        let site = ctx
            .site
            .and_then(|i| self.sites.get(i))
            .ok_or_else(|| Error::explain(ErrorType::InternalError, "no site selected"))?;
        upstream_request.insert_header(HOST, site.upstream_host.clone())?;
        Ok(())
    }
}
