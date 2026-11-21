//! `piano probe`: one Emby client's round through a site, step by step and timed.
//!
//! Through the relay, requests go to the first listening address (an unspecified address
//! is reached on loopback, which `access.loopback` lets in) with the site's name as SNI
//! and `Host`. With `direct` they go to the upstream itself and bypass the site's rules, to
//! see what the upstream does with a given User-Agent. Every request opens its own
//! connection, so the times include connecting and the TLS handshake. Directly, a stream
//! URL on another host is fetched from that host and redirects pass, as a client goes
//! there itself; through the relay both must stay on the site.

use piano_config::{Config, Site};
use piano_proxy::follow;
use piano_telemetry::redact;
use piano_upstream::Resolver;
use piano_upstream::resolve::is_public;
use piano_upstream::tls::client_config;
use pingora_core::connectors::ConnectorOptions;
use pingora_core::connectors::http::v1::Connector;
use pingora_core::protocols::ALPN;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_http::RequestHeader;
use serde::Serialize;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

pub const PROBE_SCHEMA: u32 = 1;

/// Longest a step may take, connecting included.
const STEP_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Largest JSON answer read; a longer one is reported, not parsed.
const MAX_JSON: usize = 4 << 20;
/// Largest image read.
const MAX_IMAGE: usize = 16 << 20;
/// What the media step asks for, as a player starting playback does.
const RANGE_BYTES: u64 = 1 << 20;
/// Items listed to find one with a primary image.
const LATEST_ITEMS: usize = 5;

/// What to probe.
pub struct Args {
    /// A site's name or host.
    pub site: String,
    pub login: Option<Credentials>,
    pub direct: bool,
    /// User-Agents to run the steps with; empty means piano's own.
    pub user_agents: Vec<String>,
}

pub struct Credentials {
    pub user: String,
    pub password: String,
}

/// What the probe found.
#[derive(Debug, Serialize)]
pub struct Report {
    pub schema: u32,
    pub site: String,
    /// "relay" or "direct".
    pub via: &'static str,
    /// The address connected to and the name sent as SNI.
    pub address: String,
    pub server_name: String,
    pub steps: Vec<Step>,
}

impl Report {
    pub fn ok(&self) -> bool {
        self.steps.iter().all(|s| s.ok)
    }
}

#[derive(Debug, Serialize)]
pub struct Step {
    pub user_agent: String,
    pub name: &'static str,
    pub ok: bool,
    pub status: Option<u16>,
    pub bytes: u64,
    /// From starting the request (connecting included) to the response header.
    pub first_byte_ms: Option<u64>,
    pub total_ms: u64,
    /// What the step learned, or why it failed. Never a token, user name or id.
    pub note: String,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("no site is named {0} or serves it")]
    UnknownSite(String),
    #[error("cannot probe through the relay: {0}")]
    Listen(String),
    #[error(transparent)]
    Tls(#[from] piano_upstream::tls::Error),
    #[error(transparent)]
    Resolve(#[from] piano_upstream::resolve::Error),
}

/// Runs the probe described by `args` against `config`; `resolver` finds the upstream for
/// `direct`.
pub async fn run(config: &Config, resolver: &Resolver, args: &Args) -> Result<Report, Error> {
    let site = config
        .sites
        .iter()
        .find(|s| s.name == args.site || s.host.eq_ignore_ascii_case(&args.site))
        .ok_or_else(|| Error::UnknownSite(args.site.clone()))?;
    let tls = client_config(&config.upstream.extra_roots)?;
    let mut options = ConnectorOptions::new(0);
    options.rustls_client_config = Some((tls.config, tls.roots));
    let target = if args.direct {
        let url = site
            .upstream_url
            .as_ref()
            .ok_or_else(|| Error::UnknownSite(args.site.clone()))?;
        let addr = resolver
            .resolve_blocking(&url.host, url.port)?
            .current()
            .ok_or_else(|| piano_upstream::resolve::Error::NoAddress(url.host.clone()))?;
        Target::new(addr, &url.host, true)
    } else {
        Target::new(relay_address(&config.server.listen)?, &site.host, true)
    };
    let client = Client {
        connector: Connector::new(Some(options)),
    };
    let own_agent = args.user_agents.is_empty();
    let mut probe = Probe {
        client: &client,
        target: &target,
        resolver,
        site,
        direct: args.direct,
        own_agent,
        session: None,
        steps: Vec::new(),
    };
    let agents = if own_agent {
        vec![format!("piano/{}", env!("CARGO_PKG_VERSION"))]
    } else {
        args.user_agents.clone()
    };
    if let Some(credentials) = &args.login {
        for ua in &agents {
            if !probe.login(ua, credentials).await {
                break;
            }
        }
    }
    for ua in &agents {
        probe.round(ua).await;
    }
    if let Some(session) = probe.session.take() {
        probe.logout(&session).await;
    }
    Ok(Report {
        schema: PROBE_SCHEMA,
        site: site.name.clone(),
        via: if args.direct { "direct" } else { "relay" },
        address: target.addr.to_string(),
        server_name: target.name.clone(),
        steps: probe.steps,
    })
}

/// Where the relay is reached from this host: the first listening address, an
/// unspecified one replaced by loopback of the same family.
fn relay_address(listen: &[String]) -> Result<SocketAddr, Error> {
    let first = listen
        .first()
        .ok_or_else(|| Error::Listen("server.listen is empty".into()))?;
    let mut addr: SocketAddr = first
        .parse()
        .map_err(|e| Error::Listen(format!("{first}: {e}")))?;
    if addr.ip().is_unspecified() {
        addr.set_ip(match addr.ip() {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::LOCALHOST),
        });
    }
    Ok(addr)
}

struct Target {
    addr: SocketAddr,
    /// SNI, and with the port the `Host`.
    name: String,
    authority: String,
    tls: bool,
}

impl Target {
    fn new(addr: SocketAddr, name: &str, tls: bool) -> Self {
        let name = name.to_ascii_lowercase();
        let host = if name.contains(':') {
            format!("[{name}]")
        } else {
            name.clone()
        };
        let authority = if addr.port() == if tls { 443 } else { 80 } {
            host
        } else {
            format!("{host}:{}", addr.port())
        };
        Self {
            addr,
            name,
            authority,
            tls,
        }
    }
}

struct Client {
    connector: Connector,
}

/// One answer, its body read up to a limit.
struct Answer {
    status: u16,
    /// The status code's standard phrase.
    reason: &'static str,
    content_type: String,
    location: Option<String>,
    content_range: Option<String>,
    body: Vec<u8>,
    /// The body was longer than the limit.
    cut: bool,
    first_byte: Duration,
    total: Duration,
}

impl Client {
    async fn send(
        &self,
        target: &Target,
        method: &str,
        path: &str,
        headers: &[(&'static str, String)],
        body: Option<&[u8]>,
        max_body: usize,
    ) -> Result<Answer, String> {
        tokio::time::timeout(
            STEP_TIMEOUT,
            self.exchange(target, method, path, headers, body, max_body),
        )
        .await
        .map_err(|_| format!("no answer within {}s", STEP_TIMEOUT.as_secs()))?
    }

    async fn exchange(
        &self,
        target: &Target,
        method: &str,
        path: &str,
        headers: &[(&'static str, String)],
        body: Option<&[u8]>,
        max_body: usize,
    ) -> Result<Answer, String> {
        let start = Instant::now();
        let mut peer = HttpPeer::new(target.addr, target.tls, target.name.clone())
            .map_err(|e| e.to_string())?;
        let o = &mut peer.options;
        o.alpn = ALPN::H1;
        o.verify_cert = true;
        o.verify_hostname = true;
        o.connection_timeout = Some(CONNECT_TIMEOUT);
        o.total_connection_timeout = Some(CONNECT_TIMEOUT);
        o.read_timeout = Some(STEP_TIMEOUT);
        o.write_timeout = Some(STEP_TIMEOUT);
        let (mut http, _) = self
            .connector
            .get_http_session(&peer)
            .await
            .map_err(|e| describe(&e))?;
        let mut req =
            RequestHeader::build(method, path.as_bytes(), None).map_err(|e| e.to_string())?;
        let fixed = [
            ("host", target.authority.clone()),
            ("accept", "application/json, */*".to_owned()),
            ("accept-encoding", "identity".to_owned()),
        ];
        for (name, value) in fixed.iter().chain(headers) {
            req.insert_header(*name, value.as_str())
                .map_err(|e| e.to_string())?;
        }
        if let Some(b) = body {
            req.insert_header("content-type", "application/json")
                .map_err(|e| e.to_string())?;
            req.insert_header("content-length", b.len().to_string())
                .map_err(|e| e.to_string())?;
        }
        http.write_request_header(Box::new(req))
            .await
            .map_err(|e| describe(&e))?;
        if let Some(b) = body {
            http.write_body(b).await.map_err(|e| describe(&e))?;
        }
        http.finish_body().await.map_err(|e| describe(&e))?;
        http.read_response().await.map_err(|e| describe(&e))?;
        let first_byte = start.elapsed();
        let resp = http
            .resp_header()
            .ok_or_else(|| "no response header".to_owned())?;
        let header = |name: &str| {
            resp.headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
        };
        let status = resp.status.as_u16();
        let reason = resp.status.canonical_reason().unwrap_or_default();
        let content_type = header("content-type").unwrap_or_default();
        let location = header("location");
        let content_range = header("content-range");
        let mut data = Vec::new();
        while data.len() <= max_body {
            match http.read_body_bytes().await.map_err(|e| describe(&e))? {
                Some(chunk) => data.extend_from_slice(&chunk),
                None => break,
            }
        }
        let cut = data.len() > max_body;
        data.truncate(max_body);
        http.shutdown().await;
        Ok(Answer {
            status,
            reason,
            content_type,
            location,
            content_range,
            body: data,
            cut,
            first_byte,
            total: start.elapsed(),
        })
    }
}

/// A pingora error without its context chain.
pub(crate) fn describe(e: &pingora_core::Error) -> String {
    match &e.cause {
        Some(cause) => format!("{}: {cause}", e.etype().as_str()),
        None => e.etype().as_str().to_owned(),
    }
}

/// A logged-in user.
struct Session {
    token: String,
    user_id: String,
    /// The User-Agent that logged in, which also logs out.
    user_agent: String,
}

struct Probe<'a> {
    client: &'a Client,
    target: &'a Target,
    resolver: &'a Resolver,
    site: &'a Site,
    direct: bool,
    /// No `--ua` was given, so piano's own User-Agent is sent.
    own_agent: bool,
    session: Option<Session>,
    steps: Vec<Step>,
}

/// Item ids a round found, for the steps after.
#[derive(Default)]
struct Latest {
    item: Option<String>,
    image: Option<(String, String)>,
}

impl Probe<'_> {
    fn headers(&self, ua: &str) -> Vec<(&'static str, String)> {
        let mut h = vec![
            ("user-agent", ua.to_owned()),
            (
                "x-emby-authorization",
                format!(
                    r#"MediaBrowser Client="piano", Device="piano probe", DeviceId="piano-probe", Version="{}""#,
                    env!("CARGO_PKG_VERSION")
                ),
            ),
        ];
        if let Some(s) = &self.session {
            h.push(("x-emby-token", s.token.clone()));
        }
        h
    }

    /// Runs one request as step `name` on the probe's target.
    async fn step<T>(
        &mut self,
        ua: &str,
        name: &'static str,
        request: (&str, &str, Option<&[u8]>, usize),
        extra: &[(&'static str, String)],
        judge: impl FnOnce(&Answer) -> (bool, String, T),
    ) -> Option<T> {
        self.step_at(None, ua, name, request, extra, judge).await
    }

    /// Runs one request as step `name` on `elsewhere`, else the probe's target;
    /// `judge` decides on the answer and writes the note. Another host gets no session
    /// or client identity, as a player fetching a stream URL there sends none.
    async fn step_at<T>(
        &mut self,
        elsewhere: Option<&Target>,
        ua: &str,
        name: &'static str,
        request: (&str, &str, Option<&[u8]>, usize),
        extra: &[(&'static str, String)],
        judge: impl FnOnce(&Answer) -> (bool, String, T),
    ) -> Option<T> {
        let (method, path, body, max) = request;
        let (target, mut headers) = match elsewhere {
            Some(t) => (t, vec![("user-agent", ua.to_owned())]),
            None => (self.target, self.headers(ua)),
        };
        headers.extend_from_slice(extra);
        let start = Instant::now();
        let step = match self
            .client
            .send(target, method, path, &headers, body, max)
            .await
        {
            Ok(a) => {
                let (ok, mut note, found) = judge(&a);
                // Upstreams that let in only the clients they know refuse piano's name.
                if !ok && a.status == 403 && self.own_agent && elsewhere.is_none() {
                    if !note.is_empty() {
                        note.push_str(" · ");
                    }
                    note.push_str("the upstream may refuse piano's User-Agent; try --ua");
                }
                let step = Step {
                    user_agent: ua.to_owned(),
                    name,
                    ok,
                    status: Some(a.status),
                    bytes: a.body.len() as u64,
                    first_byte_ms: Some(ms(a.first_byte)),
                    total_ms: ms(a.total),
                    note,
                };
                self.steps.push(step);
                return ok.then_some(found);
            }
            Err(e) => Step {
                user_agent: ua.to_owned(),
                name,
                ok: false,
                status: None,
                bytes: 0,
                first_byte_ms: None,
                total_ms: ms(start.elapsed()),
                note: e,
            },
        };
        self.steps.push(step);
        None
    }

    /// Where a client fetches the stream at `url`: `None` for the probe's target, with
    /// the request path. Relative URLs are under `/emby`; directly, a URL on another
    /// host is fetched from that host, resolved as the relay resolves redirect targets.
    async fn stream_at(&self, url: &str) -> Result<(Option<Target>, String), String> {
        if absolute_host(url).is_none() {
            return Ok((None, stream_path(url)));
        }
        let s = StreamUrl::parse(url)?;
        if !self.direct || s.is_at(self.target) {
            return Ok((None, s.path));
        }
        let ip = if s.host.eq_ignore_ascii_case(&self.target.name) {
            self.target.addr.ip()
        } else if let Some(ip) = s.address()? {
            ip
        } else {
            self.resolver
                .resolve_public(s.host, s.port)
                .await
                .map_err(|e| e.to_string())?
                .current()
                .ok_or_else(|| format!("{} has no address", s.host))?
                .ip()
        };
        let target = Target::new(SocketAddr::new(ip, s.port), s.host, s.tls);
        Ok((Some(target), s.path))
    }

    /// A step that failed before its request was sent.
    fn failed(&mut self, ua: &str, name: &'static str, why: String) {
        self.steps.push(Step {
            user_agent: ua.to_owned(),
            name,
            ok: false,
            status: None,
            bytes: 0,
            first_byte_ms: None,
            total_ms: 0,
            note: why,
        });
    }

    /// A step that could not run; whatever stopped it was reported by an earlier step.
    fn skipped(&mut self, ua: &str, name: &'static str, why: &str) {
        self.steps.push(Step {
            user_agent: ua.to_owned(),
            name,
            ok: true,
            status: None,
            bytes: 0,
            first_byte_ms: None,
            total_ms: 0,
            note: why.to_owned(),
        });
    }

    /// Logs in with `ua`. Returns whether another User-Agent is worth trying: the upstream
    /// refused this one by its policy (403), not the credentials (401), which repeated
    /// attempts could get locked.
    async fn login(&mut self, ua: &str, c: &Credentials) -> bool {
        let body = serde_json::json!({ "Username": c.user, "Pw": c.password }).to_string();
        let session = self
            .step(
                ua,
                "login",
                (
                    "POST",
                    "/emby/Users/AuthenticateByName",
                    Some(body.as_bytes()),
                    MAX_JSON,
                ),
                &[],
                |a| {
                    if a.status != 200 {
                        return (false, refused(a), None);
                    }
                    let v = match json(a) {
                        Ok(v) => v,
                        Err(e) => return (false, e, None),
                    };
                    match (v["AccessToken"].as_str(), v["User"]["Id"].as_str()) {
                        (Some(t), Some(u)) => (
                            true,
                            String::new(),
                            Some(Session {
                                token: t.to_owned(),
                                user_id: u.to_owned(),
                                user_agent: ua.to_owned(),
                            }),
                        ),
                        _ => (false, "no access token in the answer".into(), None),
                    }
                },
            )
            .await
            .flatten();
        self.session = session;
        self.session.is_none() && self.steps.last().and_then(|s| s.status) == Some(403)
    }

    /// Ends `session`, whose token `headers` no longer adds.
    async fn logout(&self, session: &Session) {
        let mut headers = self.headers(&session.user_agent);
        headers.push(("x-emby-token", session.token.clone()));
        let _ = self
            .client
            .send(
                self.target,
                "POST",
                "/emby/Sessions/Logout",
                &headers,
                Some(b""),
                0,
            )
            .await;
    }

    /// The steps for one User-Agent.
    async fn round(&mut self, ua: &str) {
        let leaks = self.upstream_names();
        let site_host = self.site.host.to_ascii_lowercase();
        let direct = self.direct;
        self.step(
            ua,
            "public",
            ("GET", "/emby/System/Info/Public", None, MAX_JSON),
            &[],
            |a| {
                if a.status != 200 {
                    return (false, refused(a), ());
                }
                let v = match json(a) {
                    Ok(v) => v,
                    Err(e) => return (false, e, ()),
                };
                let mut note = match v["Version"].as_str() {
                    Some(version) => format!("Emby {version}"),
                    None => "not an Emby answer".to_owned(),
                };
                let local = v["LocalAddress"].as_str().unwrap_or_default();
                if !local.is_empty() {
                    note.push_str(&format!(" · LocalAddress {}", url_host(local)));
                }
                let leaked = leaked(&a.body, &leaks);
                if !direct && !leaked.is_empty() {
                    note.push_str(&format!(" · names the upstream: {}", leaked.join(", ")));
                    return (false, note, ());
                }
                (v["Version"].is_string(), note, ())
            },
        )
        .await;
        let Some(user_id) = self.session.as_ref().map(|s| s.user_id.clone()) else {
            return;
        };
        self.step(
            ua,
            "views",
            (
                "GET",
                &format!("/emby/Users/{user_id}/Views"),
                None,
                MAX_JSON,
            ),
            &[],
            |a| {
                if a.status != 200 {
                    return (false, refused(a), ());
                }
                let v = match json(a) {
                    Ok(v) => v,
                    Err(e) => return (false, e, ()),
                };
                match v["Items"].as_array() {
                    Some(items) => (true, format!("{} libraries", items.len()), ()),
                    None => (false, "no Items in the answer".into(), ()),
                }
            },
        )
        .await;
        let latest = self
            .step(
                ua,
                "latest",
                (
                    "GET",
                    &format!(
                        "/emby/Users/{user_id}/Items?Recursive=true&IncludeItemTypes=Movie,Episode\
                         &SortBy=DateCreated&SortOrder=Descending&Limit={LATEST_ITEMS}\
                         &Fields=SeriesPrimaryImage"
                    ),
                    None,
                    MAX_JSON,
                ),
                &[],
                |a| {
                    if a.status != 200 {
                        return (false, refused(a), Latest::default());
                    }
                    let v = match json(a) {
                        Ok(v) => v,
                        Err(e) => return (false, e, Latest::default()),
                    };
                    let items = v["Items"].as_array().cloned().unwrap_or_default();
                    let id = |i: &serde_json::Value| i["Id"].as_str().map(str::to_owned);
                    let found = Latest {
                        item: items.first().and_then(id),
                        image: items.iter().find_map(primary_image),
                    };
                    match items.first() {
                        Some(i) => (true, i["Type"].as_str().unwrap_or("item").to_owned(), found),
                        None => (false, "the library is empty".into(), found),
                    }
                },
            )
            .await
            .unwrap_or_default();
        match &latest.image {
            Some((id, tag)) => {
                self.step(
                    ua,
                    "image",
                    (
                        "GET",
                        &format!("/emby/Items/{id}/Images/Primary?maxWidth=300&tag={tag}"),
                        None,
                        MAX_IMAGE,
                    ),
                    &[],
                    |a| {
                        if let Some(to) = followed(direct, a) {
                            return (true, to, ());
                        }
                        let image = a.content_type.starts_with("image/");
                        let ok = a.status == 200 && image;
                        let note = if ok {
                            a.content_type.clone()
                        } else if a.status == 200 {
                            format!("not an image: {}", a.content_type)
                        } else {
                            refused(a)
                        };
                        (ok, note, ())
                    },
                )
                .await;
            }
            None => self.skipped(ua, "image", "no recent item has a primary image"),
        }
        let Some(item) = latest.item else {
            self.skipped(ua, "playback", "no item to play");
            return;
        };
        let stream = self
            .step(
                ua,
                "playback",
                (
                    "POST",
                    &format!(
                        "/emby/Items/{item}/PlaybackInfo?UserId={user_id}&StartTimeTicks=0\
                         &IsPlayback=false&AutoOpenLiveStream=false&MaxStreamingBitrate=200000000"
                    ),
                    Some(b"{}"),
                    MAX_JSON,
                ),
                &[],
                |a| {
                    if a.status != 200 {
                        return (false, refused(a), None);
                    }
                    let v = match json(a) {
                        Ok(v) => v,
                        Err(e) => return (false, e, None),
                    };
                    let url = v["MediaSources"][0]["DirectStreamUrl"]
                        .as_str()
                        .map(str::to_owned);
                    let leaked = leaked(&a.body, &leaks);
                    let (ok, mut note) = match url.as_deref() {
                        None => (false, "no direct stream URL".to_owned()),
                        Some(u) if absolute_host(u).is_none() => {
                            (true, "direct stream: relative".into())
                        }
                        Some(u) => {
                            let host = url_host(u);
                            if host.eq_ignore_ascii_case(&site_host)
                                || host
                                    .to_ascii_lowercase()
                                    .starts_with(&format!("{site_host}:"))
                            {
                                (true, "direct stream: this site".into())
                            } else {
                                (direct, format!("direct stream: {host}"))
                            }
                        }
                    };
                    if !direct && !leaked.is_empty() {
                        note.push_str(&format!(" · names the upstream: {}", leaked.join(", ")));
                        return (false, note, url);
                    }
                    (ok, note, url)
                },
            )
            .await
            .flatten();
        let Some(url) = stream else {
            self.skipped(ua, "media", "no stream to read");
            return;
        };
        let (elsewhere, path) = match self.stream_at(&url).await {
            Ok(at) => at,
            Err(e) => {
                self.failed(ua, "media", e);
                return;
            }
        };
        let range = [("range", format!("bytes=0-{}", RANGE_BYTES - 1))];
        self.step_at(
            elsewhere.as_ref(),
            ua,
            "media",
            ("GET", &path, None, RANGE_BYTES as usize),
            &range,
            |a| {
                let total = a
                    .content_range
                    .as_deref()
                    .and_then(|r| r.rsplit('/').next())
                    .and_then(|t| t.parse::<u64>().ok());
                match a.status {
                    206 => (
                        !a.body.is_empty(),
                        total.map_or_else(String::new, |t| format!("of {t} bytes")),
                        (),
                    ),
                    200 => (
                        false,
                        "the range was ignored: 200 with the whole file".into(),
                        (),
                    ),
                    _ => match followed(direct, a) {
                        Some(to) => (true, to, ()),
                        None => (false, refused(a), ()),
                    },
                }
            },
        )
        .await;
    }

    /// Upstream host names a relayed answer must not contain.
    fn upstream_names(&self) -> Vec<String> {
        let site = self.site;
        site.upstream_url
            .iter()
            .map(|u| u.host.clone())
            .chain(site.aliases.iter().cloned())
            .chain(site.mounts.values().cloned())
            .map(|h| h.to_ascii_lowercase())
            .filter(|h| !h.is_empty())
            .collect()
    }
}

/// An item's primary image, or for an episode without one its series' image, as
/// clients show it: (item id, image tag).
fn primary_image(item: &serde_json::Value) -> Option<(String, String)> {
    let own = item["Id"]
        .as_str()
        .zip(item["ImageTags"]["Primary"].as_str());
    let series = item["SeriesId"]
        .as_str()
        .zip(item["SeriesPrimaryImageTag"].as_str());
    own.or(series)
        .map(|(id, tag)| (id.to_owned(), tag.to_owned()))
}

fn ms(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// An absolute stream URL, as a client reaches it.
struct StreamUrl<'u> {
    tls: bool,
    /// Without brackets around an IPv6 address.
    host: &'u str,
    port: u16,
    /// Path and query.
    path: String,
}

impl<'u> StreamUrl<'u> {
    /// Parses an `http`, `https` or scheme-relative (https, as the probe's own requests)
    /// URL; user information is dropped.
    fn parse(url: &'u str) -> Result<Self, String> {
        let (tls, rest) = match url.strip_prefix("//") {
            Some(rest) => (true, rest),
            None => {
                let (scheme, rest) = url
                    .split_once("://")
                    .ok_or_else(|| "the stream URL is not absolute".to_owned())?;
                match scheme.to_ascii_lowercase().as_str() {
                    "https" => (true, rest),
                    "http" => (false, rest),
                    other => return Err(format!("stream URL scheme {other}")),
                }
            }
        };
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let (authority, tail) = rest.split_at(end);
        let authority = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) if !port.contains(']') => (
                host,
                port.parse::<u16>()
                    .ok()
                    .filter(|&p| p != 0)
                    .ok_or_else(|| format!("stream URL port {port}"))?,
            ),
            _ => (authority, if tls { 443 } else { 80 }),
        };
        let host = host.trim_start_matches('[').trim_end_matches(']');
        if host.is_empty() {
            return Err("the stream URL has no host".into());
        }
        let tail = tail.split('#').next().unwrap_or_default();
        let path = if tail.starts_with('/') {
            tail.to_owned()
        } else {
            format!("/{tail}")
        };
        Ok(Self {
            tls,
            host,
            port,
            path,
        })
    }

    /// Whether the URL is on `target` itself: same host, port and https. Through the
    /// relay only this matters for the path, as the playback step has refused other
    /// hosts and the site is reached on the relay's address.
    fn is_at(&self, target: &Target) -> bool {
        self.tls && self.port == target.addr.port() && self.host.eq_ignore_ascii_case(&target.name)
    }

    /// The host as an address when it is one; a client could not reach a non-public one.
    fn address(&self) -> Result<Option<IpAddr>, String> {
        match self.host.parse::<IpAddr>() {
            Ok(ip) if !is_public(ip) => Err(format!("stream on a non-public address {ip}")),
            Ok(ip) => Ok(Some(ip)),
            Err(_) => Ok(None),
        }
    }
}

/// The answer as JSON, or why it is not.
fn json(a: &Answer) -> Result<serde_json::Value, String> {
    if a.cut {
        return Err(format!("answer over {} MiB, not read", MAX_JSON >> 20));
    }
    serde_json::from_slice(&a.body).map_err(|_| "not JSON".to_owned())
}

/// Directly, a redirect passes as a client follows it: the note naming where it goes.
/// Through the relay the relay follows, so a redirect reaching the probe is a failure.
fn followed(direct: bool, a: &Answer) -> Option<String> {
    let location = a
        .location
        .as_deref()
        .filter(|_| direct && follow::is_redirect(a.status))?;
    Some(match absolute_host(location) {
        Some(host) => format!("redirects to {host}"),
        None => "redirects on the same host".to_owned(),
    })
}

/// The note for an unexpected status: a short text of the answer, else the status's
/// standard phrase.
fn refused(a: &Answer) -> String {
    let body = String::from_utf8_lossy(&a.body);
    let text = if a.content_type.starts_with("text/html") {
        html_title(&body)
    } else if a.content_type.starts_with("text/") || a.content_type.contains("json") {
        Some(body.into_owned())
    } else {
        None
    };
    // Redacted whole, then shortened.
    let text = text.map_or_else(String::new, |t| {
        redact(&t)
            .chars()
            .filter(|c| !c.is_control())
            .take(60)
            .collect::<String>()
            .trim()
            .to_owned()
    });
    if text.is_empty() {
        a.reason.to_owned()
    } else {
        text
    }
}

/// The text of an HTML page's `<title>`, as error pages put their status there.
fn html_title(page: &str) -> Option<String> {
    let lower = page.to_ascii_lowercase();
    let start = lower.find("<title>")? + "<title>".len();
    let end = start + lower[start..].find("</title>")?;
    Some(page.get(start..end)?.trim().to_owned())
}

/// The host (and port) of an absolute or scheme-relative URL, without any user
/// information; `None` for a path.
fn absolute_host(url: &str) -> Option<&str> {
    let rest = match url.find("://") {
        Some(i) if !url[..i].contains(['/', '?', '#']) => &url[i + 3..],
        _ => url.strip_prefix("//")?,
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    Some(
        authority
            .rsplit_once('@')
            .map_or(authority, |(_, host)| host),
    )
}

/// The host (and port) of an absolute URL, or the text itself.
fn url_host(url: &str) -> &str {
    absolute_host(url).unwrap_or(url)
}

/// Which of `names` appear in `body`, ignoring ASCII case.
fn leaked(body: &[u8], names: &[String]) -> Vec<String> {
    let text = String::from_utf8_lossy(body).to_ascii_lowercase();
    names
        .iter()
        .filter(|n| text.contains(n.as_str()))
        .cloned()
        .collect()
}

/// The request path for a relative direct stream URL: under `/emby` like every API
/// path.
fn stream_path(url: &str) -> String {
    let url = if url.starts_with('/') {
        url.to_owned()
    } else {
        format!("/{url}")
    };
    if url.to_ascii_lowercase().starts_with("/emby/") {
        url
    } else {
        format!("/emby{url}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_address_uses_loopback_for_any() {
        let a = |s: &str| relay_address(&[s.to_owned()]).unwrap().to_string();
        assert_eq!(a("[::]:8443"), "[::1]:8443");
        assert_eq!(a("0.0.0.0:443"), "127.0.0.1:443");
        assert_eq!(a("192.0.2.1:443"), "192.0.2.1:443");
        assert!(relay_address(&[]).is_err());
    }

    #[test]
    fn stream_paths_and_hosts() {
        assert_eq!(
            stream_path("/videos/1/stream?x=1"),
            "/emby/videos/1/stream?x=1"
        );
        assert_eq!(stream_path("/emby/videos/1"), "/emby/videos/1");
        assert_eq!(stream_path("videos/1"), "/emby/videos/1");
        assert_eq!(
            url_host("https://a.example.com:8443/x"),
            "a.example.com:8443"
        );
        assert_eq!(url_host("http://172.17.0.1:8096"), "172.17.0.1:8096");
        assert_eq!(url_host("https://u:p@cdn.example.net/x"), "cdn.example.net");
        assert_eq!(
            absolute_host("//cdn.example.net/x?a"),
            Some("cdn.example.net")
        );
        assert_eq!(absolute_host("/videos/1?next=https://x.example.net/"), None);
        assert_eq!(absolute_host("relative/x"), None);
        assert_eq!(
            html_title("<html><head><TITLE>403 Forbidden</TITLE></head>").as_deref(),
            Some("403 Forbidden")
        );
        assert_eq!(html_title("<p>no title</p>"), None);
    }

    fn answer(status: u16, content_type: &str, body: &str) -> Answer {
        Answer {
            status,
            reason: pingora_http::StatusCode::from_u16(status)
                .ok()
                .and_then(|s| s.canonical_reason())
                .unwrap_or_default(),
            content_type: content_type.to_owned(),
            location: None,
            content_range: None,
            body: body.as_bytes().to_vec(),
            cut: false,
            first_byte: Duration::ZERO,
            total: Duration::ZERO,
        }
    }

    #[test]
    fn notes_for_refusals_are_short_and_carry_no_credentials() {
        assert_eq!(refused(&answer(403, "video/mp4", "")), "Forbidden");
        assert_eq!(refused(&answer(404, "application/json", "")), "Not Found");
        let note = refused(&answer(
            500,
            "text/plain",
            "cannot open /videos/1/stream?api_key=0123456789abcdef&x=1 gone",
        ));
        assert_eq!(
            note,
            "cannot open /videos/1/stream?api_key=REDACTED&x=1 gone"
        );
        // Kept to 60 characters.
        let long = "y".repeat(100);
        assert_eq!(refused(&answer(500, "text/plain", &long)).len(), 60);
        assert_eq!(
            refused(&answer(502, "text/html", "<title>502 Bad Gateway</title>")),
            "502 Bad Gateway"
        );
    }

    #[test]
    fn cut_answers_are_not_parsed() {
        let mut a = answer(200, "application/json", "{\"Items\":[");
        assert_eq!(json(&a).unwrap_err(), "not JSON");
        a.cut = true;
        assert_eq!(json(&a).unwrap_err(), "answer over 4 MiB, not read");
    }

    #[test]
    fn only_direct_probes_follow_redirects() {
        let mut a = answer(301, "text/html", "");
        a.location = Some("https://img.example.net/i/1".into());
        assert_eq!(
            followed(true, &a).as_deref(),
            Some("redirects to img.example.net")
        );
        assert_eq!(followed(false, &a), None);
        a.location = Some("/img/1".into());
        assert_eq!(
            followed(true, &a).as_deref(),
            Some("redirects on the same host")
        );
        a.status = 200;
        assert_eq!(followed(true, &a), None);
    }

    #[test]
    fn stream_urls_as_a_client_reaches_them() {
        let p = |u: &str| StreamUrl::parse(u).map(|s| (s.tls, s.host.to_owned(), s.port, s.path));
        assert_eq!(
            p("http://192.0.2.5:8096/videos/1/stream.mkv?api_key=k"),
            Ok((
                false,
                "192.0.2.5".into(),
                8096,
                "/videos/1/stream.mkv?api_key=k".into()
            ))
        );
        assert_eq!(
            p("HTTP://cdn.example.net/v/1"),
            Ok((false, "cdn.example.net".into(), 80, "/v/1".into()))
        );
        assert_eq!(
            p("https://u:p@cdn.example.net?x=1#f"),
            Ok((true, "cdn.example.net".into(), 443, "/?x=1".into()))
        );
        assert_eq!(
            p("//[2001:db8::1]:8920/v"),
            Ok((true, "2001:db8::1".into(), 8920, "/v".into()))
        );
        assert_eq!(
            p("//[2001:db8::1]/v"),
            Ok((true, "2001:db8::1".into(), 443, "/v".into()))
        );
        assert!(p("ftp://cdn.example.net/v").is_err());
        assert!(p("https://cdn.example.net:0/v").is_err());
        assert!(p("https:///v").is_err());
        assert_eq!(
            Target::new("[2001:db8::1]:8920".parse().unwrap(), "2001:db8::1", true).authority,
            "[2001:db8::1]:8920"
        );
        assert_eq!(
            Target::new("192.0.2.5:80".parse().unwrap(), "cdn.example.net", false).authority,
            "cdn.example.net"
        );
    }

    #[test]
    fn where_a_direct_probe_reads_a_stream() {
        let upstream = Target::new("203.0.113.7:443".parse().unwrap(), "emby.example.net", true);
        let at = |u: &str| StreamUrl::parse(u).unwrap().is_at(&upstream);
        assert!(at("https://EMBY.example.net/v"));
        assert!(!at("https://emby.example.net:8920/v"));
        assert!(!at("http://emby.example.net:443/v"));
        assert!(!at("https://vod.example.net/v"));
        let address = |u: &str| StreamUrl::parse(u).unwrap().address();
        assert_eq!(address("https://vod.example.net/v"), Ok(None));
        assert_eq!(
            address("http://203.0.113.9:8096/v"),
            Err("stream on a non-public address 203.0.113.9".into())
        );
        assert_eq!(
            address("http://1.1.1.1:8096/v"),
            Ok(Some("1.1.1.1".parse().unwrap()))
        );
        assert!(address("http://[::1]/v").is_err());
    }

    #[test]
    fn names_a_relayed_answer_must_not_contain() {
        let config = piano_config::parse(
            r#"[tls]
cert = "/etc/piano/fullchain.pem"
key = "/etc/piano/privkey.pem"

[access]
allow = ["192.0.2.7"]

[[site]]
host = "media.example.com"
upstream = "https://Origin.example.net"
aliases = ["alias.example.net"]
mounts = { "/__v" = "vod.example.net" }
"#,
        );
        let Ok(config) = config else {
            panic!("{config:?}")
        };
        let client = Client {
            connector: Connector::new(None),
        };
        let target = Target::new("127.0.0.1:443".parse().unwrap(), "media.example.com", true);
        let resolver = Resolver::system();
        let probe = Probe {
            client: &client,
            target: &target,
            resolver: &resolver,
            site: &config.sites[0],
            direct: false,
            own_agent: true,
            session: None,
            steps: Vec::new(),
        };
        assert_eq!(
            probe.upstream_names(),
            ["origin.example.net", "alias.example.net", "vod.example.net"]
        );
    }

    #[test]
    fn episodes_fall_back_to_the_series_image() {
        let v = |s: &str| serde_json::from_str::<serde_json::Value>(s).unwrap();
        assert_eq!(
            primary_image(&v(
                r#"{"Id":"1","ImageTags":{"Primary":"a"},"SeriesId":"9","SeriesPrimaryImageTag":"s"}"#
            )),
            Some(("1".into(), "a".into()))
        );
        assert_eq!(
            primary_image(&v(
                r#"{"Id":"1","ImageTags":{},"SeriesId":"9","SeriesPrimaryImageTag":"s"}"#
            )),
            Some(("9".into(), "s".into()))
        );
        assert_eq!(primary_image(&v(r#"{"Id":"1"}"#)), None);
    }

    #[test]
    fn finds_names_in_any_case() {
        let names = vec![
            "origin.example.net".to_owned(),
            "alias.example.net".to_owned(),
        ];
        assert_eq!(
            leaked(br#"{"a":"https://ORIGIN.example.NET/x"}"#, &names),
            vec!["origin.example.net"]
        );
        assert!(leaked(b"{}", &names).is_empty());
    }
}
