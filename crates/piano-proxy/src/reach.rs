//! Reaching upstreams: the peer for each attempt, the request policy and redirects.
//! Shared by the relay's own attempts and the media engine's requests.

use crate::follow::{self, MAX_HOPS, Target, TargetKind};
use crate::headers;
use crate::{Site, Sites};
use http::Method;
use http::header::{AUTHORIZATION, COOKIE, HOST};
use piano_upstream::{AddrCache, Addrs, Origin, Resolver};
use pingora_core::connectors::ConnectorOptions;
use pingora_core::connectors::http::Connector as HttpConnector;
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

/// A new connection at least this slow gets a replacement when a media request drops
/// one mid-way. A file host far from the relay takes about 290 ms to connect, one at
/// the same CDN as the relay 7–14 ms.
const SPARE_COST: Duration = Duration::from_millis(100);

/// Replacements being set up at once, and hosts remembered. Each replaces a connection
/// just closed, and one that finds an idle connection in the pool sets up none, so the
/// connections to a host do not grow.
const MAX_SPARING: usize = 8;
const MAX_HOSTS: usize = 64;

#[derive(Debug, Default)]
struct SpareState {
    /// By host and port: how long the last new connection took to set up.
    hosts: std::collections::HashMap<String, Duration>,
    in_flight: usize,
}

/// Replaces media connections that are slow to set up when a request drops one: a
/// player that seeks closes the request it no longer wants, and an HTTP/1.1 connection
/// cannot be reused in the middle of a body.
#[derive(Debug, Default)]
pub(crate) struct Spares {
    state: std::sync::Mutex<SpareState>,
}

impl Spares {
    fn lock(&self) -> std::sync::MutexGuard<'_, SpareState> {
        // Plain data; a panic elsewhere cannot leave it inconsistent.
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Notes what setting up a new connection to `host` took.
    pub fn note(&self, host: &str, took: Duration) {
        let mut s = self.lock();
        if s.hosts.len() >= MAX_HOSTS && !s.hosts.contains_key(host) {
            s.hosts.clear();
        }
        s.hosts.insert(host.to_owned(), took);
    }

    /// Whether to set up a replacement for a connection to `host` dropped now; counts
    /// it as started.
    fn claim(&self, host: &str) -> bool {
        let mut s = self.lock();
        let slow = s.hosts.get(host).is_some_and(|c| *c >= SPARE_COST);
        if !slow || s.in_flight >= MAX_SPARING {
            return false;
        }
        s.in_flight += 1;
        true
    }

    fn done(&self) {
        let mut s = self.lock();
        s.in_flight = s.in_flight.saturating_sub(1);
    }
}

impl Reach {
    /// A media request dropped its connection to `peer` (at `host`) mid-way: when that host is
    /// slow to connect to, sets up another in the background and leaves it in the pool,
    /// unless the pool has one already.
    pub fn replace(self: &Arc<Self>, host: &str, peer: HttpPeer) {
        if !self.spares.claim(host) {
            return;
        }
        let Ok(rt) = tokio::runtime::Handle::try_current() else {
            self.spares.done();
            return;
        };
        let reach = Arc::clone(self);
        rt.spawn(async move {
            if let Ok((http, _)) = reach.media.get_http_session(&peer).await {
                let idle = peer.options.idle_timeout;
                reach.media.release_http_session(http, &peer, idle).await;
            }
            reach.spares.done();
        });
    }
}

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
    /// Protocol of the response, `h1` or `h2`.
    pub proto: Option<&'static str>,
    /// Status of the response header the upstream sent.
    pub status: Option<u16>,
    /// What ended the attempt, if it failed.
    pub error: Option<&'static str>,
    /// The attempt went to a remembered redirect target instead of walking the chain.
    pub memo: bool,
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
            proto: None,
            status: None,
            error: None,
            memo: false,
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
    /// Connections for media streams. Pools of their own, here and below: the relay's
    /// pool belongs to pingora's proxy loop, which offers no way to borrow from it.
    pub media: Connector,
    /// Connections for image fetches, HTTP/2 where the upstream offers it.
    pub images: HttpConnector,
    /// Where media requests' redirects led.
    pub redirects: crate::memo::Redirects,
    /// What a new media connection costs per host, for replacing dropped ones.
    pub spares: Spares,
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
            media: Connector::new(Some(client.clone())),
            images: HttpConnector::new(Some(client)),
            redirects: crate::memo::Redirects::default(),
            spares: Spares::default(),
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
            let addr = current(&site.origin)?;
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
        let addr = current(&origin)?;
        Ok((origin.peer(addr)?, origin.addrs, addr))
    }
}

/// The address to connect to `origin` at; an upstream that has not resolved since startup
/// fails like an address that cannot be reached.
fn current(origin: &Origin) -> Result<SocketAddr> {
    origin.addrs.current().ok_or_else(|| {
        Error::explain(
            ErrorType::ConnectNoRoute,
            format!("{} does not resolve yet", origin.host),
        )
        .into_up()
    })
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
    let target = follow::resolve(location, &base)
        .map_err(|e| refuse_redirect(format!("{e}: {:?}", location_origin(location))))?;
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

/// The scheme and host of a `Location`, as a refusal reason may show it: the path and
/// query can carry signatures and the user info a password. A Location with an `@`
/// anywhere, or whose host part is not plainly a host, shows at most its scheme.
fn location_origin(location: &[u8]) -> String {
    let s = String::from_utf8_lossy(location.trim_ascii());
    let scheme_end = s.find(':').filter(|&c| {
        let scheme = s[..c].as_bytes();
        scheme.first().is_some_and(u8::is_ascii_alphabetic)
            && scheme
                .iter()
                .all(|&b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
    });
    let (scheme, rest) = match scheme_end {
        Some(c) => (&s[..=c], &s[c + 1..]),
        None => ("", &s[..]),
    };
    let Some(after) = rest.strip_prefix("//") else {
        // Without `//`, what looks like a scheme can be a user name.
        let shown = if s.contains('@') { "" } else { scheme };
        return clip(shown, 100).to_owned();
    };
    let host = &after[..after.find(['/', '?', '#', '\\']).unwrap_or(after.len())];
    let plain =
        |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b':' | b'[' | b']');
    let host = if s.contains('@') || !host.bytes().all(plain) {
        ""
    } else {
        host
    };
    clip(&format!("{scheme}//{host}"), 100).to_owned()
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

/// The access log's name for an upstream response's protocol.
pub(crate) fn proto_of(version: http::Version) -> &'static str {
    if version == http::Version::HTTP_2 {
        "h2"
    } else {
        "h1"
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clipping_keeps_whole_characters() {
        assert_eq!(clip("abc", 3), "abc");
        assert_eq!(clip("abc", 2), "ab");
        // "é" takes bytes 1 and 2.
        assert_eq!(clip("aéb", 2), "a");
        assert_eq!(clip("aéb", 3), "aé");
        assert_eq!(clip("é", 1), "");
    }

    #[test]
    fn refusals_show_only_scheme_and_host() {
        for (location, shown) in [
            ("https://u:pw@cdn.example.net/f?md5=abc", "https://"),
            (
                "http://192.0.2.1:5244/d/a.mkv?sign=x",
                "http://192.0.2.1:5244",
            ),
            ("https://cdn.example.net\\@evil.example.org/x", "https://"),
            ("//a.example.net:0?expires=1", "//a.example.net:0"),
            ("ftp://a.example.net/x?api_key=k", "ftp://a.example.net"),
            ("javascript:alert(1)", "javascript:"),
            ("https:a.example.net/p?sign=x", "https:"),
            ("/relative/path?sign=x", ""),
            ("https:admin:hunter2@cdn.example.net//x?sign=s", ""),
            ("admin:hunter2@cdn.example.net//x", ""),
            ("https://user:p/ss@cdn.example.net/f?sign=x", "https://"),
            ("https://user:secret#@cdn.example.net/", "https://"),
            ("https://cdn.example.net/f?next=a@b", "https://"),
            ("https://cdn%2Eexample.net/x", "https://"),
        ] {
            assert_eq!(location_origin(location.as_bytes()), shown, "{location}");
        }
    }
}
