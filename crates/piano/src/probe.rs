//! `piano probe`: one Emby client's round through a site, step by step and timed.
//!
//! Through the relay, requests go to the first listening address (an unspecified address
//! is reached on loopback, which `access.loopback` lets in) with the site's name as SNI
//! and `Host`. With `direct` they go to the upstream itself and bypass the site's rules, to
//! see what the upstream does with a given User-Agent. Every request opens its own
//! connection, so the times include connecting and the TLS handshake.

use piano_config::{Config, Site};
use piano_upstream::Resolver;
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
/// Largest JSON answer read.
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
        let addrs = resolver.resolve_blocking(&url.host, url.port)?;
        Target::new(addrs.current(), &url.host)
    } else {
        Target::new(relay_address(&config.server.listen)?, &site.host)
    };
    let client = Client {
        connector: Connector::new(Some(options)),
        target,
    };
    let mut probe = Probe {
        client: &client,
        site,
        direct: args.direct,
        session: None,
        steps: Vec::new(),
    };
    let agents = if args.user_agents.is_empty() {
        vec![format!("piano/{}", env!("CARGO_PKG_VERSION"))]
    } else {
        args.user_agents.clone()
    };
    if let Some(credentials) = &args.login {
        probe.login(&agents[0], credentials).await;
    }
    for ua in &agents {
        probe.round(ua).await;
    }
    if probe.session.is_some() {
        probe.logout(&agents[0]).await;
    }
    Ok(Report {
        schema: PROBE_SCHEMA,
        site: site.name.clone(),
        via: if args.direct { "direct" } else { "relay" },
        address: client.target.addr.to_string(),
        server_name: client.target.name.clone(),
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
}

impl Target {
    fn new(addr: SocketAddr, name: &str) -> Self {
        let name = name.to_ascii_lowercase();
        let authority = if addr.port() == 443 {
            name.clone()
        } else {
            format!("{name}:{}", addr.port())
        };
        Self {
            addr,
            name,
            authority,
        }
    }
}

struct Client {
    connector: Connector,
    target: Target,
}

/// One answer, its body read up to a limit.
struct Answer {
    status: u16,
    content_type: String,
    location: Option<String>,
    content_range: Option<String>,
    body: Vec<u8>,
    first_byte: Duration,
    total: Duration,
}

impl Client {
    async fn send(
        &self,
        method: &str,
        path: &str,
        headers: &[(&'static str, String)],
        body: Option<&[u8]>,
        max_body: usize,
    ) -> Result<Answer, String> {
        tokio::time::timeout(
            STEP_TIMEOUT,
            self.exchange(method, path, headers, body, max_body),
        )
        .await
        .map_err(|_| format!("no answer within {}s", STEP_TIMEOUT.as_secs()))?
    }

    async fn exchange(
        &self,
        method: &str,
        path: &str,
        headers: &[(&'static str, String)],
        body: Option<&[u8]>,
        max_body: usize,
    ) -> Result<Answer, String> {
        let start = Instant::now();
        let mut peer = HttpPeer::new(self.target.addr, true, self.target.name.clone())
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
            ("host", self.target.authority.clone()),
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
        let content_type = header("content-type").unwrap_or_default();
        let location = header("location");
        let content_range = header("content-range");
        let mut data = Vec::new();
        while data.len() < max_body {
            match http.read_body_bytes().await.map_err(|e| describe(&e))? {
                Some(chunk) => data.extend_from_slice(&chunk),
                None => break,
            }
        }
        data.truncate(max_body);
        http.shutdown().await;
        Ok(Answer {
            status,
            content_type,
            location,
            content_range,
            body: data,
            first_byte,
            total: start.elapsed(),
        })
    }
}

/// A pingora error without its context chain.
fn describe(e: &pingora_core::Error) -> String {
    match &e.cause {
        Some(cause) => format!("{}: {cause}", e.etype().as_str()),
        None => e.etype().as_str().to_owned(),
    }
}

/// A logged-in user.
struct Session {
    token: String,
    user_id: String,
}

struct Probe<'a> {
    client: &'a Client,
    site: &'a Site,
    direct: bool,
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

    /// Runs one request as step `name`; `judge` decides on the answer and writes the note.
    async fn step<T>(
        &mut self,
        ua: &str,
        name: &'static str,
        request: (&str, &str, Option<&[u8]>, usize),
        extra: &[(&'static str, String)],
        judge: impl FnOnce(&Answer) -> (bool, String, T),
    ) -> Option<T> {
        let (method, path, body, max) = request;
        let mut headers = self.headers(ua);
        headers.extend_from_slice(extra);
        let start = Instant::now();
        let step = match self.client.send(method, path, &headers, body, max).await {
            Ok(a) => {
                let (ok, note, found) = judge(&a);
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

    async fn login(&mut self, ua: &str, c: &Credentials) {
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
                    let v: serde_json::Value = serde_json::from_slice(&a.body).unwrap_or_default();
                    match (v["AccessToken"].as_str(), v["User"]["Id"].as_str()) {
                        (Some(t), Some(u)) => (
                            true,
                            String::new(),
                            Some(Session {
                                token: t.to_owned(),
                                user_id: u.to_owned(),
                            }),
                        ),
                        _ => (false, "no access token in the answer".into(), None),
                    }
                },
            )
            .await
            .flatten();
        self.session = session;
    }

    async fn logout(&mut self, ua: &str) {
        let headers = self.headers(ua);
        let _ = self
            .client
            .send("POST", "/emby/Sessions/Logout", &headers, Some(b""), 0)
            .await;
        self.session = None;
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
                let v: serde_json::Value = serde_json::from_slice(&a.body).unwrap_or_default();
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
                let v: serde_json::Value = serde_json::from_slice(&a.body).unwrap_or_default();
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
                    let v: serde_json::Value = serde_json::from_slice(&a.body).unwrap_or_default();
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
                    let v: serde_json::Value = serde_json::from_slice(&a.body).unwrap_or_default();
                    let url = v["MediaSources"][0]["DirectStreamUrl"]
                        .as_str()
                        .map(str::to_owned);
                    let leaked = leaked(&a.body, &leaks);
                    let (ok, mut note) = match url.as_deref() {
                        None => (false, "no direct stream URL".to_owned()),
                        Some(u) if !u.contains("://") => (true, "direct stream: relative".into()),
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
        let path = stream_path(&url);
        let range = [("range", format!("bytes=0-{}", RANGE_BYTES - 1))];
        self.step(
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
                    301 | 302 | 307 | 308 if direct => (
                        true,
                        format!(
                            "redirects to {}",
                            url_host(a.location.as_deref().unwrap_or_default())
                        ),
                        (),
                    ),
                    _ => (false, refused(a), ()),
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
            .chain(site.mounts.values().map(|m| url_host(m).to_owned()))
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

/// The note for an unexpected status: the status line's meaning and a short body.
fn refused(a: &Answer) -> String {
    let text: String = String::from_utf8_lossy(&a.body)
        .chars()
        .filter(|c| !c.is_control())
        .take(60)
        .collect();
    if a.content_type.starts_with("text/html") {
        html_title(&String::from_utf8_lossy(&a.body)).unwrap_or_default()
    } else if a.content_type.starts_with("text/") || a.content_type.contains("json") {
        text.trim().to_owned()
    } else {
        String::new()
    }
}

/// The text of an HTML page's `<title>`, as error pages put their status there.
fn html_title(page: &str) -> Option<String> {
    let lower = page.to_ascii_lowercase();
    let start = lower.find("<title>")? + "<title>".len();
    let end = start + lower[start..].find("</title>")?;
    Some(page.get(start..end)?.trim().to_owned())
}

/// The host (and port) of an absolute URL, or the text itself.
fn url_host(url: &str) -> &str {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    rest.split(['/', '?', '#']).next().unwrap_or(rest)
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

/// The request path for a direct stream URL: relative ones are under `/emby` like
/// every API path; absolute ones on the site keep their path.
fn stream_path(url: &str) -> String {
    if let Some((_, rest)) = url.split_once("://") {
        return rest
            .find('/')
            .map_or_else(|| "/".to_owned(), |i| rest[i..].to_owned());
    }
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
        assert_eq!(
            stream_path("https://a.example.com:8443/__m/v/1?x"),
            "/__m/v/1?x"
        );
        assert_eq!(
            url_host("https://a.example.com:8443/x"),
            "a.example.com:8443"
        );
        assert_eq!(url_host("http://172.17.0.1:8096"), "172.17.0.1:8096");
        assert_eq!(
            html_title("<html><head><TITLE>403 Forbidden</TITLE></head>").as_deref(),
            Some("403 Forbidden")
        );
        assert_eq!(html_title("<p>no title</p>"), None);
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
