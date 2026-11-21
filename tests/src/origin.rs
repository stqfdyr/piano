//! A fake Emby origin over TLS, speaking HTTP/1.1 and HTTP/2.
//!
//! Routes:
//! - `/System/Info/Public`: a fixed JSON document, like Emby's; also `/__info`, which
//!   the relay does not rewrite.
//! - `/__echo…`: the request line and headers as text, for header assertions; any
//!   path starting with `/__echo`.
//! - `/__redirect?to=LOCATION[&status=N]`: status N (default 302) with the
//!   percent-decoded `to` as `Location`.
//! - `/__loop/N`: 302 to `/__loop/N-1`, until `/__loop/0` answers 200 `done`.
//! - `/__cdn`: an empty 200 carrying the headers a CDN-fronted Emby sends (`server`,
//!   `cf-ray`, `alt-svc`, `nel`, `report-to`, `reporting-endpoints`,
//!   `speculation-rules`, its own HSTS and frame policy) and two
//!   cookies, one scoped to the origin host.
//! - `/__seq/{key}/{codes}`: the n-th request for `key` gets the n-th status of the
//!   comma-separated `codes` (the last one repeats) and `n` as its body.
//! - `…/PlaybackInfo` and `/__json…`: [`json_doc`] for the request's `Host`, with
//!   `x-seen-accept-encoding` echoing the request header and a strong `ETag`. Query
//!   `pad=N` adds N bytes of padding; `gzip=1` compresses the body whatever the
//!   request accepts.
//! - `/System/Ext/ServerDomains`: the origin's name and `alias.example.net`.
//! - `/embywebsocket`: with `Upgrade: websocket`, 101 and then every byte echoed back
//!   (no websocket framing); without, 400.
//! - `/__bytes/{len}`: `len` bytes of [`pattern_byte`], generated while streaming, with
//!   single-range `Range` support; stands in for a media file.
//! - `/videos/{key}/…` and `/__file/{key}`: a scripted media file of `len` pattern bytes
//!   (query `len=N`), with single-range support (a Range whose `If-Range` does not match
//!   the ETag is ignored); see [`Plan`] for `plan=…`. With
//!   `redirect=1`, `/videos/…` answers 302 to `/__file/{key}` with the other
//!   parameters. [`Origin::seen`] lists the `Range` of each file request per key.
//! - `/Items/{key}/Images/{kind}` (also under `/emby`) and `/img/{key}`: an image
//!   `image {key}` with ETag `"{key}"`, answering a matching If-None-Match with 304.
//!   Query: `ttl=N` sets `max-age` (default 60, 0 omits Cache-Control; `/img/` always
//!   86400), `codes=…` answers the n-th request of the path with the n-th status (the
//!   last repeats; 429 carries `Retry-After` from `retry=N`, default 1), `moved=1` answers
//!   301 to `/img/{key}` with the same query (`moved=302`: 302), `size=N` pads the body
//!   with dots to N bytes, `delay_ms=N` waits first. [`Origin::hits`] counts requests per
//!   path.
//! - A small Emby API for `piano probe` under `/emby`: `Users/AuthenticateByName` (POST,
//!   accepts [`PROBE_USER`] / [`PROBE_PASSWORD`]), `Users/{PROBE_USER_ID}/Views` and `…/Items`,
//!   `Items/{PROBE_ITEM}/PlaybackInfo` (a direct stream URL to `/videos/{PROBE_ITEM}/…`),
//!   `Sessions/Logout`. Without the token they answer 401; a User-Agent starting with
//!   [`BLOCKED_UA`] gets 403 on all but `System/Info/Public`, as an upstream's UA policy;
//!   one starting with [`ELSEWHERE_UA`] gets the stream URL on [`STREAM_HOST`] and images
//!   moved, as some upstreams answer some players. `/videos/` media paths are also served
//!   under `/emby`.
//! - anything else: 404.

use crate::pki::Leaf;
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper::header::{ACCEPT_RANGES, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, RANGE};
use hyper::service::service_fn;
use hyper::{HeaderMap, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::Sleep;
use tokio_rustls::TlsAcceptor;

/// The body of `/System/Ext/ServerDomains`.
pub const SERVER_DOMAINS: &str = r#"{"Domains":["origin.example.net","alias.example.net"]}"#;

/// A JSON document naming its server `host` (as in `Host`) in several ways, with
/// `pad` bytes of padding.
pub fn json_doc(host: &str, pad: usize) -> String {
    let mut doc = format!(
        concat!(
            r#"{{"LocalAddress":"http://172.17.0.1:8096","Url":"https://{host}/emby/x","#,
            r#""Esc":"https:\/\/{upper}\/y","Rel":"//alias.example.net/z","#,
            r#""Bare":"origin.example.net","Other":"https://vod.example.net/a","#,
            r#""Near":"https://origin.example.net.evil.example/b","#,
            r#""Path":"/videos/1/stream?api_key=k""#
        ),
        host = host,
        upper = host.to_ascii_uppercase(),
    );
    if pad > 0 {
        doc.push_str(r#","Pad":""#);
        doc.push_str(&"a".repeat(pad));
        doc.push('"');
    }
    doc.push('}');
    doc
}

pub const PROBE_USER: &str = "probe";
pub const PROBE_PASSWORD: &str = "secret";
pub const PROBE_TOKEN: &str = "probe-token";
pub const PROBE_USER_ID: &str = "probe-user";
pub const PROBE_ITEM: &str = "probe1";
/// Length of the probe item's media file.
pub const PROBE_MEDIA_LEN: u64 = 3_000_000;
/// User-Agent prefix the fake Emby API refuses with 403.
pub const BLOCKED_UA: &str = "Blocked/";
/// User-Agent prefix that gets an absolute stream URL on [`STREAM_HOST`] and `/Items`
/// images as 301.
pub const ELSEWHERE_UA: &str = "Elsewhere/";
/// The host of the stream URL [`ELSEWHERE_UA`] gets; this origin serves it too.
pub const STREAM_HOST: &str = "vod.example.net";

pub const INFO_PUBLIC: &str = r#"{"LocalAddress":"https://origin.example.net","ServerName":"fake","Version":"4.8.10.0","Id":"0123456789abcdef"}"#;

/// Bytes per body frame of `/__bytes`.
const CHUNK: usize = 64 * 1024;
/// Prime period, so the pattern does not line up with power-of-two buffer sizes.
const PERIOD: u64 = 251;

/// The byte at `offset` of every `/__bytes` body.
pub fn pattern_byte(offset: u64) -> u8 {
    (offset % PERIOD) as u8
}

static PATTERN: LazyLock<Vec<u8>> =
    LazyLock::new(|| (0..CHUNK as u64 + PERIOD).map(pattern_byte).collect());

type ResBody = BoxBody<Bytes, std::io::Error>;

/// Requests seen per `/__seq` key, and per scripted media key (`key#r` for its redirects).
type Seqs = Arc<Mutex<HashMap<String, usize>>>;

/// The `Range` header of every scripted media file request, per key.
type Seen = Arc<Mutex<HashMap<String, Vec<Option<String>>>>>;

#[derive(Clone)]
struct State {
    seqs: Seqs,
    seen: Seen,
    /// Changes to closed when the [`Origin`] is dropped; connection tasks end then.
    closed: watch::Receiver<()>,
}

pub struct Origin {
    pub addr: SocketAddr,
    requests: Arc<AtomicUsize>,
    /// TLS connections accepted, by negotiated protocol: HTTP/1.1, HTTP/2.
    conns: Arc<[AtomicUsize; 2]>,
    /// TLS connections open now.
    open: Arc<AtomicUsize>,
    state: State,
    task: JoinHandle<()>,
    /// Dropped with the origin, which ends every connection still open.
    _close: watch::Sender<()>,
}

impl Origin {
    /// Starts the origin on a free loopback port with `leaf` as its certificate.
    pub async fn start(leaf: &Leaf) -> Self {
        Self::start_on(leaf, SocketAddr::from(([127, 0, 0, 1], 0))).await
    }

    /// Starts the origin on `bind` with `leaf` as its certificate.
    pub async fn start_on(leaf: &Leaf, bind: SocketAddr) -> Self {
        Self::start_with(leaf, bind, true).await
    }

    /// Starts an origin on a free loopback port that offers only HTTP/1.1.
    pub async fn start_h1_only(leaf: &Leaf) -> Self {
        Self::start_with(leaf, SocketAddr::from(([127, 0, 0, 1], 0)), false).await
    }

    async fn start_with(leaf: &Leaf, bind: SocketAddr, h2: bool) -> Self {
        let chain = CertificateDer::pem_slice_iter(leaf.cert_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let key = PrivateKeyDer::from_pem_slice(leaf.key_pem.as_bytes()).unwrap();
        let mut tls =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(chain, key)
                .unwrap();
        tls.alpn_protocols = if h2 {
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        } else {
            vec![b"http/1.1".to_vec()]
        };
        let acceptor = TlsAcceptor::from(Arc::new(tls));

        let listener = TcpListener::bind(bind).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&requests);
        let conns: Arc<[AtomicUsize; 2]> = Arc::default();
        let conn_counter = Arc::clone(&conns);
        let open = Arc::new(AtomicUsize::new(0));
        let open_counter = Arc::clone(&open);
        let (close, closed) = watch::channel(());
        let state = State {
            seqs: Seqs::default(),
            seen: Seen::default(),
            closed,
        };
        let shared = state.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                let counter = Arc::clone(&counter);
                let conn_counter = Arc::clone(&conn_counter);
                let open = Arc::clone(&open_counter);
                let state = shared.clone();
                let mut closed = state.closed.clone();
                let serve = async move {
                    let Ok(tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let is_h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
                    conn_counter[usize::from(is_h2)].fetch_add(1, Ordering::Relaxed);
                    let _open = Open::count(open);
                    let service = service_fn(move |req| {
                        counter.fetch_add(1, Ordering::Relaxed);
                        let head = req.method() == hyper::Method::HEAD;
                        let response = handle(req, state.clone());
                        async move {
                            let mut response = response.await?;
                            // HTTP/1 drops the body of a HEAD response, but HTTP/2 sends
                            // whatever it is given, which the client treats as a
                            // protocol error.
                            if head {
                                if let Some(n) = response.body().size_hint().exact()
                                    && !response.headers().contains_key(CONTENT_LENGTH)
                                    && !matches!(response.status().as_u16(), 100..=199 | 204 | 304)
                                {
                                    response.headers_mut().insert(CONTENT_LENGTH, n.into());
                                }
                                *response.body_mut() = full(Bytes::new());
                            }
                            Ok::<_, Infallible>(response)
                        }
                    });
                    let builder = auto::Builder::new(TokioExecutor::new());
                    let _ = builder
                        .serve_connection_with_upgrades(TokioIo::new(tls), service)
                        .await;
                };
                tokio::spawn(async move {
                    tokio::select! {
                        () = serve => {}
                        _ = closed.changed() => {}
                    }
                });
            }
        });
        Self {
            addr,
            requests,
            conns,
            open,
            state,
            task,
            _close: close,
        }
    }

    /// Requests served so far.
    pub fn requests(&self) -> usize {
        self.requests.load(Ordering::Relaxed)
    }

    /// TLS connections accepted so far: (HTTP/1.1, HTTP/2).
    pub fn connections(&self) -> (usize, usize) {
        (
            self.conns[0].load(Ordering::Relaxed),
            self.conns[1].load(Ordering::Relaxed),
        )
    }

    /// TLS connections open now.
    pub fn open_connections(&self) -> usize {
        self.open.load(Ordering::Relaxed)
    }

    /// The `Range` header of each scripted media file request for `key`, in order.
    pub fn seen(&self, key: &str) -> Vec<Option<String>> {
        let seen = self.state.seen.lock().unwrap();
        seen.get(key).cloned().unwrap_or_default()
    }

    /// Requests for image path `path` (without query).
    pub fn hits(&self, path: &str) -> usize {
        let seqs = self.state.seqs.lock().unwrap();
        seqs.get(&format!("img:{path}")).copied().unwrap_or(0)
    }

    /// Requests for scripted media `key` naming `host` (without port) in `Host`.
    pub fn media_requests_to(&self, key: &str, host: &str) -> usize {
        let seqs = self.state.seqs.lock().unwrap();
        seqs.get(&format!("{key}@{host}")).copied().unwrap_or(0)
    }

    /// Redirects answered for scripted media `key`.
    pub fn redirects(&self, key: &str) -> usize {
        let seqs = self.state.seqs.lock().unwrap();
        seqs.get(&format!("{key}#r")).copied().unwrap_or(0)
    }
}

/// Counts a connection as open while it lives.
struct Open(Arc<AtomicUsize>);

impl Open {
    fn count(open: Arc<AtomicUsize>) -> Self {
        open.fetch_add(1, Ordering::Relaxed);
        Self(open)
    }
}

impl Drop for Open {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

impl Drop for Origin {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn full(body: impl Into<Bytes>) -> ResBody {
    Full::new(body.into())
        .map_err(|never: Infallible| match never {})
        .boxed()
}

async fn handle(mut req: Request<Incoming>, state: State) -> Result<Response<ResBody>, Infallible> {
    // HTTP/2 carries the host as :authority; routes and echoes read it as Host.
    if !req.headers().contains_key(hyper::header::HOST)
        && let Some(authority) = req.uri().authority()
        && let Ok(v) = hyper::header::HeaderValue::from_str(authority.as_str())
    {
        req.headers_mut().insert(hyper::header::HOST, v);
    }
    if req.uri().path().eq_ignore_ascii_case("/embywebsocket") {
        return Ok(websocket(&mut req, state.closed.clone()));
    }
    if let Some(response) = emby(&mut req).await {
        return Ok(response);
    }
    if let Some(key) = media_key(req.uri().path()) {
        return Ok(media(&req, key.to_owned(), &state).await);
    }
    if let Some(response) = image(&req, &state).await {
        return Ok(response);
    }
    let seqs = state.seqs;
    let path = req.uri().path();
    let response = if path.eq_ignore_ascii_case("/System/Info/Public")
        || path.eq_ignore_ascii_case("/emby/System/Info/Public")
        || path == "/__info"
    {
        Response::builder()
            .header(CONTENT_TYPE, "application/json; charset=utf-8")
            .body(full(INFO_PUBLIC))
    } else if path.starts_with("/__echo") {
        let mut text = format!(
            "{} {} {:?}\n",
            req.method(),
            req.uri().path_and_query().map_or("/", |p| p.as_str()),
            req.version()
        );
        for (name, value) in req.headers() {
            text.push_str(&format!(
                "{name}: {}\n",
                String::from_utf8_lossy(value.as_bytes())
            ));
        }
        Response::builder()
            .header(CONTENT_TYPE, "text/plain")
            .body(full(text))
    } else if path == "/__redirect" {
        let query = req.uri().query().unwrap_or_default();
        let param = |name: &str| {
            query
                .split('&')
                .find_map(|kv| kv.strip_prefix(name)?.strip_prefix('='))
                .map(percent_decode)
        };
        let status = param("status")
            .and_then(|s| String::from_utf8(s).ok()?.parse().ok())
            .unwrap_or(302);
        Response::builder()
            .status(status)
            .header("location", param("to").unwrap_or_default())
            .body(full("redirect body"))
    } else if let Some(n) = path
        .strip_prefix("/__loop/")
        .and_then(|n| n.parse::<u32>().ok())
    {
        if n == 0 {
            Response::builder().body(full("done"))
        } else {
            Response::builder()
                .status(StatusCode::FOUND)
                .header("location", format!("/__loop/{}", n - 1))
                .body(full(Bytes::new()))
        }
    } else if let Some((key, codes)) = path
        .strip_prefix("/__seq/")
        .and_then(|rest| rest.split_once('/'))
    {
        let n = {
            let mut seqs = seqs.lock().unwrap();
            let n = seqs.entry(key.to_owned()).or_default();
            *n += 1;
            *n
        };
        let codes: Vec<u16> = codes.split(',').map(|c| c.parse().unwrap()).collect();
        Response::builder()
            .status(codes[(n - 1).min(codes.len() - 1)])
            .body(full(n.to_string()))
    } else if path.to_ascii_lowercase().ends_with("/playbackinfo") || path.starts_with("/__json") {
        let query = req.uri().query().unwrap_or_default();
        let param = |name: &str| {
            query
                .split('&')
                .find_map(|kv| kv.strip_prefix(name)?.strip_prefix('='))
        };
        let host = req
            .headers()
            .get("host")
            .and_then(|h| h.to_str().ok())
            .unwrap_or_default();
        let pad = param("pad").and_then(|p| p.parse().ok()).unwrap_or(0);
        let doc = json_doc(host, pad);
        let seen = req
            .headers()
            .get("accept-encoding")
            .cloned()
            .unwrap_or_else(|| hyper::header::HeaderValue::from_static(""));
        let builder = Response::builder()
            .header(CONTENT_TYPE, "application/json; charset=utf-8")
            .header("etag", "\"v1\"")
            .header("x-seen-accept-encoding", seen);
        if param("gzip") == Some("1") {
            builder
                .header("content-encoding", "gzip")
                .body(full(gzip(doc.as_bytes())))
        } else {
            builder.body(full(doc))
        }
    } else if path.eq_ignore_ascii_case("/System/Ext/ServerDomains")
        || path.eq_ignore_ascii_case("/emby/System/Ext/ServerDomains")
    {
        Response::builder()
            .header(CONTENT_TYPE, "application/json")
            .body(full(SERVER_DOMAINS))
    } else if path == "/__cdn" {
        Response::builder()
            .header("server", "cloudflare")
            .header("cf-ray", "0123456789abcdef-LAX")
            .header("alt-svc", "h3=\":443\"; ma=86400")
            .header("via", "1.1 cdn")
            .header("strict-transport-security", "max-age=1")
            .header("nel", r#"{"report_to":"cf-nel","max_age":604800}"#)
            .header(
                "report-to",
                r#"{"group":"cf-nel","endpoints":[{"url":"https://a.nel.example.net/report"}]}"#,
            )
            .header("reporting-endpoints", "default=\"https://a.example.net/r\"")
            .header("speculation-rules", "\"/rules.json\"")
            .header("x-frame-options", "DENY")
            .header("set-cookie", "s=1; Path=/; Domain=origin.example.net")
            .header("set-cookie", "t=2; Path=/")
            .body(full(Bytes::new()))
    } else if let Some(len) = path.strip_prefix("/__bytes/").and_then(|n| n.parse().ok()) {
        return Ok(bytes_response(len, req.headers()));
    } else {
        Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(full(Bytes::new()))
    };
    Ok(response.unwrap())
}

/// The Emby API routes for `piano probe`; `None` for other paths.
async fn emby(req: &mut Request<Incoming>) -> Option<Response<ResBody>> {
    let path = req.uri().path().to_owned();
    let lower = path.to_ascii_lowercase();
    let users = format!("/emby/users/{PROBE_USER_ID}/");
    let item = format!("/emby/items/{PROBE_ITEM}/playbackinfo");
    let known = lower == "/emby/users/authenticatebyname"
        || lower == "/emby/sessions/logout"
        || lower == item
        || lower.starts_with(&users);
    if !known {
        return None;
    }
    let json = |status: StatusCode, body: String| {
        Some(
            Response::builder()
                .status(status)
                .header(CONTENT_TYPE, "application/json; charset=utf-8")
                .body(full(body))
                .unwrap(),
        )
    };
    let ua = req
        .headers()
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    if ua.starts_with(BLOCKED_UA) {
        return json(StatusCode::FORBIDDEN, "API policy denied".into());
    }
    if lower == "/emby/users/authenticatebyname" {
        let body = req
            .body_mut()
            .collect()
            .await
            .map(|b| b.to_bytes())
            .unwrap_or_default();
        let login: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
        if login["Username"] != PROBE_USER || login["Pw"] != PROBE_PASSWORD {
            return json(
                StatusCode::UNAUTHORIZED,
                "Invalid username or password".into(),
            );
        }
        return json(
            StatusCode::OK,
            format!(
                r#"{{"AccessToken":"{PROBE_TOKEN}","User":{{"Id":"{PROBE_USER_ID}","Name":"{PROBE_USER}"}}}}"#
            ),
        );
    }
    let token = req
        .headers()
        .get("x-emby-token")
        .and_then(|v| v.to_str().ok());
    if token != Some(PROBE_TOKEN) {
        return json(
            StatusCode::UNAUTHORIZED,
            "Access token is invalid or expired.".into(),
        );
    }
    if lower == "/emby/sessions/logout" {
        return Some(
            Response::builder()
                .status(StatusCode::NO_CONTENT)
                .body(full(Bytes::new()))
                .unwrap(),
        );
    }
    if lower == item {
        return json(
            StatusCode::OK,
            format!(
                concat!(
                    r#"{{"MediaSources":[{{"Path":"https://{origin}/media/{item}.mkv","#,
                    r#""DirectStreamUrl":"{base}/videos/{item}/stream.mkv?len={len}&api_key={token}"}}],"#,
                    r#""PlaySessionId":"s1"}}"#
                ),
                origin = crate::ORIGIN_HOST,
                // The port is this origin's, which the request names in Host.
                base = if ua.starts_with(ELSEWHERE_UA) {
                    let port = req
                        .headers()
                        .get("host")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|h| h.rsplit_once(':'))
                        .map_or_else(String::new, |(_, p)| format!(":{p}"));
                    format!("https://{STREAM_HOST}{port}")
                } else {
                    String::new()
                },
                item = PROBE_ITEM,
                len = PROBE_MEDIA_LEN,
                token = PROBE_TOKEN,
            ),
        );
    }
    match lower.strip_prefix(&users) {
        Some("views") => json(
            StatusCode::OK,
            r#"{"Items":[{"Name":"Movies"},{"Name":"Shows"}],"TotalRecordCount":2}"#.into(),
        ),
        Some("items") => json(
            StatusCode::OK,
            format!(
                r#"{{"Items":[{{"Id":"{PROBE_ITEM}","Type":"Movie","ImageTags":{{"Primary":"t1"}}}}],"TotalRecordCount":1}}"#
            ),
        ),
        _ => json(StatusCode::NOT_FOUND, String::new()),
    }
}

/// The image routes; `None` for other paths.
async fn image(req: &Request<Incoming>, state: &State) -> Option<Response<ResBody>> {
    let path = req.uri().path();
    let p = path.strip_prefix("/emby").unwrap_or(path);
    let (key, target) = match p.strip_prefix("/Items/") {
        Some(rest) => {
            let (key, tail) = rest.split_once('/')?;
            if !tail.starts_with("Images/") {
                return None;
            }
            (key, false)
        }
        None => (p.strip_prefix("/img/")?, true),
    };
    let n = {
        let mut seqs = state.seqs.lock().unwrap();
        let n = seqs.entry(format!("img:{path}")).or_default();
        *n += 1;
        *n
    };
    let query = req.uri().query().unwrap_or_default();
    let param = |name: &str| {
        query
            .split('&')
            .find_map(|kv| kv.strip_prefix(name)?.strip_prefix('='))
    };
    if let Some(ms) = param("delay_ms").and_then(|v| v.parse().ok()) {
        tokio::time::sleep(Duration::from_millis(ms)).await;
    }
    let code: u16 = match param("codes") {
        Some(c) => {
            let codes: Vec<u16> = c.split(',').map(|c| c.parse().unwrap()).collect();
            codes[(n - 1).min(codes.len() - 1)]
        }
        None => 200,
    };
    let elsewhere = req
        .headers()
        .get("user-agent")
        .is_some_and(|v| v.as_bytes().starts_with(ELSEWHERE_UA.as_bytes()));
    let moved = match param("moved") {
        Some("1") => Some(StatusCode::MOVED_PERMANENTLY),
        _ if elsewhere => Some(StatusCode::MOVED_PERMANENTLY),
        Some("302") => Some(StatusCode::FOUND),
        _ => None,
    };
    if let Some(status) = moved.filter(|_| !target && code == 200) {
        return Some(
            Response::builder()
                .status(status)
                .header("location", format!("/img/{key}?{query}"))
                .body(full("moved"))
                .unwrap(),
        );
    }
    let ttl: u64 = if target {
        86_400
    } else {
        param("ttl").and_then(|v| v.parse().ok()).unwrap_or(60)
    };
    let etag = format!("\"{key}\"");
    let mut body = format!("image {key}");
    let size = param("size").and_then(|v| v.parse::<usize>().ok());
    body.extend(std::iter::repeat_n(
        '.',
        size.unwrap_or(0).saturating_sub(body.len()),
    ));
    let mut builder = Response::builder().status(code);
    if ttl > 0 {
        builder = builder.header("cache-control", format!("public, max-age={ttl}"));
    }
    if code == 429 {
        builder = builder.header("retry-after", param("retry").unwrap_or("1"));
    }
    if code != 200 {
        return Some(builder.body(full(Bytes::new())).unwrap());
    }
    let builder = builder.header("etag", &etag);
    if req
        .headers()
        .get("if-none-match")
        .is_some_and(|v| v.as_bytes() == etag.as_bytes())
    {
        return Some(
            builder
                .status(StatusCode::NOT_MODIFIED)
                .body(full(Bytes::new()))
                .unwrap(),
        );
    }
    Some(
        builder
            .header(CONTENT_TYPE, "image/jpeg")
            .header("last-modified", "Sun, 23 Nov 2025 02:39:49 GMT")
            .body(full(body))
            .unwrap(),
    )
}

/// Answers an upgrade request with 101 and echoes the upgraded stream.
fn websocket(req: &mut Request<Incoming>, closed: watch::Receiver<()>) -> Response<ResBody> {
    let wants = req
        .headers()
        .get("upgrade")
        .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"websocket"));
    if !wants {
        return Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(full(Bytes::new()))
            .unwrap();
    }
    let upgrade = hyper::upgrade::on(req);
    let mut closed = closed;
    tokio::spawn(async move {
        let Ok(upgraded) = upgrade.await else {
            return;
        };
        let (mut rd, mut wr) = tokio::io::split(TokioIo::new(upgraded));
        tokio::select! {
            _ = tokio::io::copy(&mut rd, &mut wr) => {}
            _ = closed.changed() => {}
        }
    });
    Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header("upgrade", "websocket")
        .header("connection", "upgrade")
        .header("sec-websocket-accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
        .body(full(Bytes::new()))
        .unwrap()
}

pub fn gzip(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

/// Decompresses one gzip stream that must span all of `data`.
pub fn gunzip(data: &[u8]) -> Vec<u8> {
    use std::io::Read;
    let mut out = Vec::new();
    let mut dec = flate2::bufread::GzDecoder::new(data);
    dec.read_to_end(&mut out).unwrap();
    assert!(dec.into_inner().is_empty(), "bytes after the gzip stream");
    out
}

/// Decompresses one brotli stream that must span all of `data`.
pub fn unbrotli(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    brotli::BrotliDecompress(&mut &data[..], &mut out).unwrap();
    // The decoder ignores what follows the stream; a stream that still decodes without
    // its last byte had bytes after it.
    let short = &data[..data.len().saturating_sub(1)];
    assert!(
        brotli::BrotliDecompress(&mut &short[..], &mut Vec::new()).is_err(),
        "bytes after the brotli stream"
    );
    out
}

fn bytes_response(total: u64, headers: &HeaderMap) -> Response<ResBody> {
    let builder = Response::builder()
        .header(CONTENT_TYPE, "application/octet-stream")
        .header(ACCEPT_RANGES, "bytes");
    let range = headers.get(RANGE).and_then(|v| v.to_str().ok());
    let response = match range.map(|r| parse_range(r, total)) {
        None => builder
            .header(CONTENT_LENGTH, total)
            .body(pattern(0, total)),
        Some(Some((start, end))) => builder
            .status(StatusCode::PARTIAL_CONTENT)
            .header(CONTENT_LENGTH, end - start)
            .header(CONTENT_RANGE, format!("bytes {start}-{}/{total}", end - 1))
            .body(pattern(start, end)),
        Some(None) => builder
            .status(StatusCode::RANGE_NOT_SATISFIABLE)
            .header(CONTENT_RANGE, format!("bytes */{total}"))
            .body(full(Bytes::new())),
    };
    response.unwrap()
}

fn pattern(pos: u64, end: u64) -> ResBody {
    Pattern { pos, end }
        .map_err(|never: Infallible| match never {})
        .boxed()
}

/// The key of a scripted media path: `/videos/{key}/…` or `/__file/{key}`.
fn media_key(path: &str) -> Option<&str> {
    let rest = path
        .strip_prefix("/emby")
        .unwrap_or(path)
        .strip_prefix("/videos/")
        .or_else(|| path.strip_prefix("/__file/"))?;
    let key = rest.split('/').next()?;
    (!key.is_empty()).then_some(key)
}

/// What one request of a scripted media file does; `plan=` holds one per request,
/// comma-separated, the last repeating. Tokens, dot-separated: `hMS` waits before the
/// head, `bMS` before the first body byte; `cN` breaks the connection at file offset
/// N; `sN:MS` pauses at file offset N; `eTAG` sets the ETag (default `v1`); `x`
/// ignores `Range` and does not advertise ranges; `u` sends no length (like a live
/// transcode); `-` is a plain request.
#[derive(Debug, Default, Clone)]
struct Plan {
    head_delay: u64,
    body_delay: u64,
    cut: Option<u64>,
    pause: Option<(u64, u64)>,
    etag: Option<String>,
    no_ranges: bool,
    unknown_length: bool,
}

impl Plan {
    fn parse(spec: &str) -> Self {
        let mut p = Plan::default();
        for t in spec.split('.').filter(|t| !t.is_empty() && *t != "-") {
            let (k, v) = t.split_at(1);
            match k {
                "h" => p.head_delay = v.parse().unwrap(),
                "b" => p.body_delay = v.parse().unwrap(),
                "c" => p.cut = Some(v.parse().unwrap()),
                "s" => {
                    let (at, ms) = v.split_once(':').unwrap();
                    p.pause = Some((at.parse().unwrap(), ms.parse().unwrap()));
                }
                "e" => p.etag = Some(v.to_owned()),
                "x" if v.is_empty() => p.no_ranges = true,
                "u" if v.is_empty() => p.unknown_length = true,
                _ => panic!("unknown plan token {t}"),
            }
        }
        p
    }
}

async fn media(req: &Request<Incoming>, key: String, state: &State) -> Response<ResBody> {
    let host = req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .and_then(|h| h.split(':').next())
        .unwrap_or_default();
    *state
        .seqs
        .lock()
        .unwrap()
        .entry(format!("{key}@{host}"))
        .or_default() += 1;
    let query = req.uri().query().unwrap_or_default();
    let param = |name: &str| {
        query
            .split('&')
            .find_map(|kv| kv.strip_prefix(name)?.strip_prefix('='))
    };
    if req.uri().path().starts_with("/videos/") && param("redirect") == Some("1") {
        *state
            .seqs
            .lock()
            .unwrap()
            .entry(format!("{key}#r"))
            .or_default() += 1;
        let rest: Vec<&str> = query
            .split('&')
            .filter(|kv| !kv.starts_with("redirect="))
            .collect();
        return Response::builder()
            .status(StatusCode::FOUND)
            .header("location", format!("/__file/{key}?{}", rest.join("&")))
            .body(full("moved"))
            .unwrap();
    }
    let total: u64 = param("len").and_then(|l| l.parse().ok()).unwrap_or(1 << 20);
    let range = req
        .headers()
        .get(RANGE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let n = {
        let mut seen = state.seen.lock().unwrap();
        let list = seen.entry(key).or_default();
        list.push(range.clone());
        list.len()
    };
    let plans: Vec<&str> = param("plan").unwrap_or("-").split(',').collect();
    let plan = Plan::parse(plans[(n - 1).min(plans.len() - 1)]);
    if plan.head_delay > 0 {
        tokio::time::sleep(Duration::from_millis(plan.head_delay)).await;
    }
    let etag = format!("\"{}\"", plan.etag.as_deref().unwrap_or("v1"));
    // RFC 9110 §13.1.5: a Range whose If-Range does not match is ignored.
    let current = req
        .headers()
        .get("if-range")
        .is_none_or(|v| v.as_bytes() == etag.as_bytes());
    let mut builder = Response::builder()
        .header(CONTENT_TYPE, "video/x-matroska")
        .header("etag", etag);
    if !plan.no_ranges && !plan.unknown_length {
        builder = builder.header(ACCEPT_RANGES, "bytes");
    }
    let wanted = range.filter(|_| current && !plan.no_ranges && !plan.unknown_length);
    let (start, end) = match wanted.map(|r| parse_range(&r, total)) {
        None => (0, total),
        Some(Some(r)) => {
            builder = builder
                .status(StatusCode::PARTIAL_CONTENT)
                .header(CONTENT_RANGE, format!("bytes {}-{}/{total}", r.0, r.1 - 1));
            r
        }
        Some(None) => {
            return builder
                .status(StatusCode::RANGE_NOT_SATISFIABLE)
                .header(CONTENT_RANGE, format!("bytes */{total}"))
                .body(full(Bytes::new()))
                .unwrap();
        }
    };
    let body = Scripted {
        pos: start,
        end,
        first_delay: (plan.body_delay > 0).then(|| Duration::from_millis(plan.body_delay)),
        cut: plan.cut,
        flushed: false,
        pause: plan.pause,
        exact: !plan.unknown_length,
        sleep: None,
    };
    builder.body(body.boxed()).unwrap()
}

/// Pattern bytes in `[pos, end)` delivered as a [`Plan`] says.
struct Scripted {
    pos: u64,
    end: u64,
    first_delay: Option<Duration>,
    cut: Option<u64>,
    /// Set once the bytes before the cut had time to leave.
    flushed: bool,
    pause: Option<(u64, u64)>,
    exact: bool,
    sleep: Option<Pin<Box<Sleep>>>,
}

impl Body for Scripted {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, std::io::Error>>> {
        loop {
            if let Some(s) = self.sleep.as_mut() {
                if s.as_mut().poll(cx).is_pending() {
                    return Poll::Pending;
                }
                self.sleep = None;
            }
            if let Some(d) = self.first_delay.take() {
                self.sleep = Some(Box::pin(tokio::time::sleep(d)));
                continue;
            }
            // Without a pause the server would drop bytes still in its buffer.
            if !self.flushed && self.cut.is_some_and(|c| c <= self.pos) {
                self.flushed = true;
                self.sleep = Some(Box::pin(tokio::time::sleep(Duration::from_millis(100))));
                continue;
            }
            if self.pause.is_some_and(|(at, _)| at <= self.pos) {
                let (_, ms) = self.pause.take().unwrap();
                self.sleep = Some(Box::pin(tokio::time::sleep(Duration::from_millis(ms))));
                continue;
            }
            break;
        }
        if self.pos >= self.end {
            return Poll::Ready(None);
        }
        if self.cut.is_some_and(|c| c <= self.pos) {
            return Poll::Ready(Some(Err(std::io::Error::other("scripted cut"))));
        }
        let mut stop = self.end;
        for at in [self.cut, self.pause.map(|p| p.0)].into_iter().flatten() {
            if at > self.pos {
                stop = stop.min(at);
            }
        }
        let len = (stop - self.pos).min(CHUNK as u64) as usize;
        let from = (self.pos % PERIOD) as usize;
        let chunk = Bytes::copy_from_slice(&PATTERN[from..from + len]);
        self.pos += len as u64;
        Poll::Ready(Some(Ok(Frame::data(chunk))))
    }

    fn is_end_stream(&self) -> bool {
        self.pos >= self.end
    }

    fn size_hint(&self) -> SizeHint {
        if self.exact {
            SizeHint::with_exact(self.end - self.pos)
        } else {
            SizeHint::default()
        }
    }
}

/// Decodes `%XX` escapes; anything else is kept as is.
fn percent_decode(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex = |c: u8| (c as char).to_digit(16);
        match (
            b[i],
            b.get(i + 1).copied().and_then(hex),
            b.get(i + 2).copied().and_then(hex),
        ) {
            (b'%', Some(h), Some(l)) => {
                out.push((h * 16 + l) as u8);
                i += 3;
            }
            (c, _, _) => {
                out.push(c);
                i += 1;
            }
        }
    }
    out
}

/// Parses a single `bytes=a-b`, `bytes=a-` or `bytes=-n` range into a half-open
/// interval within `total`.
pub fn parse_range(value: &str, total: u64) -> Option<(u64, u64)> {
    let spec = value.strip_prefix("bytes=")?;
    let (a, b) = spec.split_once('-')?;
    let (start, end) = match (a.parse::<u64>().ok(), b.parse::<u64>().ok()) {
        (Some(a), Some(b)) if a <= b => (a, b.saturating_add(1).min(total)),
        (Some(a), None) if b.is_empty() => (a, total),
        (None, Some(n)) if a.is_empty() && n > 0 => (total.saturating_sub(n), total),
        _ => return None,
    };
    (start < end).then_some((start, end))
}

/// A body of pattern bytes in `[pos, end)`, produced one frame at a time.
struct Pattern {
    pos: u64,
    end: u64,
}

impl Body for Pattern {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        if self.pos >= self.end {
            return Poll::Ready(None);
        }
        let len = (self.end - self.pos).min(CHUNK as u64) as usize;
        let from = (self.pos % PERIOD) as usize;
        let chunk = Bytes::copy_from_slice(&PATTERN[from..from + len]);
        self.pos += len as u64;
        Poll::Ready(Some(Ok(Frame::data(chunk))))
    }

    fn is_end_stream(&self) -> bool {
        self.pos >= self.end
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.end - self.pos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges() {
        assert_eq!(parse_range("bytes=0-99", 1000), Some((0, 100)));
        assert_eq!(parse_range("bytes=900-", 1000), Some((900, 1000)));
        assert_eq!(parse_range("bytes=-100", 1000), Some((900, 1000)));
        assert_eq!(parse_range("bytes=990-2000", 1000), Some((990, 1000)));
        assert_eq!(parse_range("bytes=1000-", 1000), None);
        assert_eq!(parse_range("bytes=5-4", 1000), None);
        assert_eq!(parse_range("bytes=0-1,5-6", 1000), None);
        assert_eq!(parse_range("items=0-1", 1000), None);
    }

    #[test]
    fn pattern_table_matches_function() {
        assert!(
            PATTERN
                .iter()
                .enumerate()
                .all(|(i, &b)| b == pattern_byte(i as u64))
        );
    }
}

#[cfg(test)]
mod codec_tests {
    use super::*;

    fn brotli(data: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut out = Vec::new();
        let mut enc = brotli::CompressorWriter::new(&mut out, 4096, 5, 22);
        enc.write_all(data).unwrap();
        drop(enc);
        out
    }

    #[test]
    fn decompressors_round_trip() {
        assert_eq!(gunzip(&gzip(b"hello")), b"hello");
        assert_eq!(unbrotli(&brotli(b"hello")), b"hello");
    }

    #[test]
    #[should_panic(expected = "bytes after the gzip stream")]
    fn gunzip_refuses_trailing_bytes() {
        let mut z = gzip(b"hello");
        z.extend_from_slice(b"junk");
        gunzip(&z);
    }

    #[test]
    #[should_panic(expected = "bytes after the brotli stream")]
    fn unbrotli_refuses_trailing_bytes() {
        let mut z = brotli(b"hello");
        z.extend_from_slice(b"junk");
        unbrotli(&z);
    }

    #[test]
    #[should_panic]
    fn unbrotli_refuses_a_truncated_stream() {
        let z = brotli(b"hello");
        let _ = unbrotli(&z[..z.len() - 1]);
    }

    #[test]
    #[should_panic]
    fn gunzip_refuses_a_truncated_stream() {
        let z = gzip(b"hello");
        gunzip(&z[..z.len() - 3]);
    }
}
