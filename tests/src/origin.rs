//! A fake Emby origin over TLS, speaking HTTP/1.1 and HTTP/2.
//!
//! Routes:
//! - `/System/Info/Public`: a fixed JSON document, like Emby's.
//! - `/__echo`: the request line and headers as JSON-ish text, for header assertions.
//! - anything else: 404.

use crate::pki::Leaf;
use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

pub const INFO_PUBLIC: &str = r#"{"LocalAddress":"https://origin.example.net","ServerName":"fake","Version":"4.8.10.0","Id":"0123456789abcdef"}"#;

pub struct Origin {
    pub addr: SocketAddr,
    requests: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl Origin {
    /// Starts the origin on a free loopback port with `leaf` as its certificate.
    pub async fn start(leaf: &Leaf) -> Self {
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

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
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

async fn handle(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    let path = req.uri().path();
    let response = if path.eq_ignore_ascii_case("/System/Info/Public")
        || path.eq_ignore_ascii_case("/emby/System/Info/Public")
    {
        Response::builder()
            .header("content-type", "application/json; charset=utf-8")
            .body(Full::new(Bytes::from_static(INFO_PUBLIC.as_bytes())))
    } else if path == "/__echo" {
        let mut text = format!("{} {} {:?}\n", req.method(), req.uri(), req.version());
        for (name, value) in req.headers() {
            text.push_str(&format!(
                "{name}: {}\n",
                String::from_utf8_lossy(value.as_bytes())
            ));
        }
        Response::builder()
            .header("content-type", "text/plain")
            .body(Full::new(Bytes::from(text)))
    } else {
        Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::new()))
    };
    Ok(response.unwrap())
}
