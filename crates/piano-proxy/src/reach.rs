//! Reaching upstreams: the peer for each attempt, the request policy and redirects.
//! Shared by the relay's own attempts and the media engine's requests.

use crate::follow::{self, MAX_HOPS, Target, TargetKind};
use crate::headers;
use crate::{Site, Sites};
use http::Method;
use http::header::{AUTHORIZATION, COOKIE, HOST};
use piano_upstream::{AddrCache, Addrs, Origin, Resolver};
use pingora_core::connectors::ConnectorOptions;
use pingora_core::connectors::http::v1::Connector;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_error::{Error, ErrorSource, ErrorType, Result};
use pingora_http::RequestHeader;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Further attempts after failing to connect, each to the host's next address.
pub(crate) const CONNECT_RETRIES: u8 = 2;

/// Total upstream attempts per request: the first, every redirect hop and every
/// connection retry. A status the upstream answered with is never retried: the
/// upstreams sit behind a CDN whose 502, 503 and 504 report the state of the server
/// behind it, which an immediate repeat does not change. Failures on a reused pooled
/// connection are retried too and also count here.
pub const MAX_ATTEMPTS: usize = 1 + MAX_HOPS as usize + CONNECT_RETRIES as usize;

/// How long a redirect target keeps the address it was first resolved to.
const FOLLOW_ADDR_TTL: Duration = Duration::from_secs(300);

/// A redirect that is not followed; the client gets 502.
pub(crate) const REFUSED: ErrorType = ErrorType::Custom("RedirectRefused");

/// Client credentials, sent only to the upstream server itself.
const CREDENTIAL_HEADERS: [&str; 3] = [
    "x-emby-authorization",
    "x-emby-token",
    "x-mediabrowser-token",
];

/// A redirect being followed, or a mounted host.
#[derive(Debug, Clone)]
pub(crate) struct Hop {
    pub target: Target,
    pub kind: TargetKind,
}

/// What one upstream attempt did, for the access log.
#[derive(Debug, Clone)]
pub(crate) struct AttemptLog {
    /// Which upstream request of a media stream the attempt belongs to; 0 elsewhere.
    pub src: u32,
    pub host: String,
    pub addr: SocketAddr,
    pub issued: Instant,
    /// Unset until a connection was obtained.
    pub reused: Option<bool>,
    /// Time to set up a new connection, TCP and TLS.
    pub connect: Option<Duration>,
    /// Status of the response header the upstream sent.
    pub status: Option<u16>,
    /// What ended the attempt, if it failed.
    pub error: Option<&'static str>,
}

impl AttemptLog {
    pub fn new(src: u32, host: String, addr: SocketAddr) -> Self {
        Self {
            src,
            host,
            addr,
            issued: Instant::now(),
            reused: None,
            connect: None,
            status: None,
            error: None,
        }
    }

    /// Records the connection the attempt got.
    pub fn connected(&mut self, reused: bool) {
        self.reused = Some(reused);
        if !reused {
            self.connect = Some(self.issued.elapsed());
        }
    }
}

/// Address lookups and the media engine's connections.
pub(crate) struct Reach {
    pub resolver: Resolver,
    pub follow_addrs: AddrCache,
    /// Connections for the requests the relay makes itself: media streams and image
    /// fetches. A pool of its own: the relay's pool belongs to pingora's proxy loop,
    /// which offers no way to borrow from it.
    pub media: Connector,
}

impl std::fmt::Debug for Reach {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Reach")
            .field("resolver", &self.resolver)
            .finish_non_exhaustive()
    }
}

impl Reach {
    pub fn new(resolver: Resolver, client: ConnectorOptions) -> Self {
        Self {
            resolver,
            follow_addrs: AddrCache::new(FOLLOW_ADDR_TTL),
            media: Connector::new(Some(client)),
        }
    }

    /// A peer for the next attempt towards `hop` (the site's upstream when `None`),
    /// with the address table it was taken from and the address chosen.
    pub async fn peer(
        &self,
        site: &Site,
        hop: Option<&Hop>,
    ) -> Result<(HttpPeer, Arc<Addrs>, SocketAddr)> {
        let Some(hop) = hop else {
            let addr = site.origin.addrs.current();
            let peer = site.origin.peer(addr)?;
            return Ok((peer, Arc::clone(&site.origin.addrs), addr));
        };
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
        Ok((origin.peer(addr)?, origin.addrs, addr))
    }
}

/// The host an attempt towards `hop` goes to.
pub(crate) fn host_of<'a>(site: &'a Site, hop: Option<&'a Hop>) -> &'a str {
    hop.map_or(&site.origin.host, |h| &h.target.host)
}

/// Applies the request policy for an attempt towards `hop` (the site's upstream when
/// `None`): target, `Host`, credentials, client address headers, User-Agent, cookies.
pub(crate) fn prepare_request(
    site: &Site,
    hop: Option<&Hop>,
    req: &mut RequestHeader,
) -> Result<()> {
    match hop {
        None => req.insert_header(HOST, site.upstream_host.clone())?,
        Some(hop) => {
            req.set_raw_path(&hop.target.path)?;
            req.insert_header(HOST, hop.target.authority())?;
            if hop.kind == TargetKind::Follow {
                req.remove_header(&COOKIE);
                req.remove_header(&AUTHORIZATION);
                for name in CREDENTIAL_HEADERS {
                    req.remove_header(name);
                }
            }
        }
    }
    headers::scrub_request(req);
    headers::rewrite_user_agent(&site.policy.ua, req)?;
    headers::join_cookies(req)
}

/// The next hop for a redirect to `location`, received after `hops` redirects from
/// an attempt towards `hop`; `client_path` is the client's request target, where the
/// chain started. Errors are refusals: the client gets 502, never the Location.
pub(crate) fn redirect(
    sites: &Sites,
    site: &Site,
    method: &Method,
    hops: u8,
    hop: Option<&Hop>,
    client_path: &[u8],
    location: &[u8],
) -> Result<Hop> {
    if method != Method::GET && method != Method::HEAD {
        return Err(refuse_redirect(format!("{method} request redirected")));
    }
    if hops >= MAX_HOPS {
        return Err(refuse_redirect(format!("more than {MAX_HOPS} redirects")));
    }
    let base = match hop {
        Some(h) => h.target.clone(),
        None => Target {
            host: site.origin.host.clone(),
            port: site.origin.port,
            path: client_path.to_vec(),
        },
    };
    let target = follow::resolve(location, &base).map_err(|e| {
        let shown = String::from_utf8_lossy(location);
        refuse_redirect(format!("{e}: {:?}", clip(&shown, 200)))
    })?;
    // A site of this relay would receive the request again and could loop.
    if sites.find(target.host.as_bytes()).is_some() {
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
    Ok(Hop { target, kind })
}

/// A redirect that will not be followed. The reason ends up in the access log and the
/// diagnostic log; it must name hosts only, since redirect targets carry signed paths.
pub(crate) fn refuse_redirect(reason: String) -> Box<Error> {
    Error::create(REFUSED, ErrorSource::Upstream, Some(reason.into()), None)
}

/// Failures to reach the address at all, as opposed to failures of TLS with a server
/// that answered.
pub(crate) fn is_connect_failure(e: &ErrorType) -> bool {
    matches!(
        e,
        ErrorType::ConnectTimedout
            | ErrorType::ConnectRefused
            | ErrorType::ConnectNoRoute
            | ErrorType::ConnectError
            | ErrorType::TLSHandshakeTimedout
    )
}

/// The longest prefix of `s` within `max` bytes that ends on a char boundary.
pub(crate) fn clip(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}
