//! A fake Emby origin over TLS, speaking HTTP/1.1 and HTTP/2.
//!
//! Routes:
//! - `/System/Info/Public`: a fixed JSON document, like Emby's.
//! - `/__echo`: the request line and headers as text, for header assertions.
//! - `/__cdn`: an empty 200 carrying the headers a CDN-fronted Emby sends (`server`,
//!   `cf-ray`, `alt-svc`, its own HSTS) and two cookies, one scoped to the origin host.
//! - `/__bytes/{len}`: `len` bytes of [`pattern_byte`], generated while streaming, with
//!   single-range `Range` support; stands in for a media file.
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
use std::convert::Infallible;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock};
use std::task::{Context, Poll};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

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

type ResBody = BoxBody<Bytes, Infallible>;

pub struct Origin {
    pub addr: SocketAddr,
    requests: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl Origin {
    /// Starts the origin on a free loopback port with `leaf` as its certificate.
    pub async fn start(leaf: &Leaf) -> Self {
        Self::start_on(leaf, SocketAddr::from(([127, 0, 0, 1], 0))).await
    }

    /// Starts the origin on `bind` with `leaf` as its certificate.
    pub async fn start_on(leaf: &Leaf, bind: SocketAddr) -> Self {
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
        tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(tls));

        let listener = TcpListener::bind(bind).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&requests);
        let task = tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                let counter = Arc::clone(&counter);
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let service = service_fn(move |req| {
                        counter.fetch_add(1, Ordering::Relaxed);
                        handle(req)
                    });
                    let _ = auto::Builder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(tls), service)
                        .await;
                });
            }
        });
        Self {
            addr,
            requests,
            task,
        }
    }

    /// Requests served so far.
    pub fn requests(&self) -> usize {
        self.requests.load(Ordering::Relaxed)
    }
}

impl Drop for Origin {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn full(body: impl Into<Bytes>) -> ResBody {
    Full::new(body.into()).boxed()
}

async fn handle(req: Request<Incoming>) -> Result<Response<ResBody>, Infallible> {
    let path = req.uri().path();
    let response = if path.eq_ignore_ascii_case("/System/Info/Public")
        || path.eq_ignore_ascii_case("/emby/System/Info/Public")
    {
        Response::builder()
            .header(CONTENT_TYPE, "application/json; charset=utf-8")
            .body(full(INFO_PUBLIC))
    } else if path == "/__echo" {
        let mut text = format!("{} {} {:?}\n", req.method(), req.uri(), req.version());
        for (name, value) in req.headers() {
            text.push_str(&format!(
                "{name}: {}\n",
                String::from_utf8_lossy(value.as_bytes())
            ));
        }
        Response::builder()
            .header(CONTENT_TYPE, "text/plain")
            .body(full(text))
    } else if path == "/__cdn" {
        Response::builder()
            .header("server", "cloudflare")
            .header("cf-ray", "0123456789abcdef-LAX")
            .header("alt-svc", "h3=\":443\"; ma=86400")
            .header("via", "1.1 cdn")
            .header("strict-transport-security", "max-age=1")
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

fn bytes_response(total: u64, headers: &HeaderMap) -> Response<ResBody> {
    let builder = Response::builder()
        .header(CONTENT_TYPE, "application/octet-stream")
        .header(ACCEPT_RANGES, "bytes");
    let range = headers.get(RANGE).and_then(|v| v.to_str().ok());
    let response = match range.map(|r| parse_range(r, total)) {
        None => builder
            .header(CONTENT_LENGTH, total)
            .body(Pattern { pos: 0, end: total }.boxed()),
        Some(Some((start, end))) => builder
            .status(StatusCode::PARTIAL_CONTENT)
            .header(CONTENT_LENGTH, end - start)
            .header(CONTENT_RANGE, format!("bytes {start}-{}/{total}", end - 1))
            .body(Pattern { pos: start, end }.boxed()),
        Some(None) => builder
            .status(StatusCode::RANGE_NOT_SATISFIABLE)
            .header(CONTENT_RANGE, format!("bytes */{total}"))
            .body(full(Bytes::new())),
    };
    response.unwrap()
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
