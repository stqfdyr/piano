//! An HTTPS client that trusts the test CA and dials the relay for every name.

use rustls::pki_types::{CertificateDer, ServerName};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

/// Which application protocol the client offers.
#[derive(Clone, Copy, Debug)]
pub enum Proto {
    H1,
    H2,
}

fn tls_config(root: CertificateDer<'static>, proto: Proto) -> rustls::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(root).unwrap();
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    tls.alpn_protocols = match proto {
        Proto::H1 => vec![b"http/1.1".to_vec()],
        Proto::H2 => vec![b"h2".to_vec()],
    };
    tls
}

/// A client whose TLS trusts `root` only and whose DNS answers `relay` for `host`.
pub fn client(
    root: CertificateDer<'static>,
    host: &str,
    relay: SocketAddr,
    proto: Proto,
) -> reqwest::Client {
    reqwest::Client::builder()
        .use_preconfigured_tls(tls_config(root, proto))
        .resolve(host, relay)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap()
}

/// How long a raw connection may wait for the relay before the test fails.
pub const IO_TIMEOUT: Duration = Duration::from_secs(10);

/// A raw TLS connection to `relay` for `host`, for tests that control the bytes on the wire.
pub async fn connect(
    root: CertificateDer<'static>,
    host: &str,
    relay: SocketAddr,
    proto: Proto,
) -> TlsStream<TcpStream> {
    let name = ServerName::try_from(host.to_owned()).unwrap();
    let tls = TlsConnector::from(Arc::new(tls_config(root, proto)));
    tokio::time::timeout(IO_TIMEOUT, async {
        let tcp = TcpStream::connect(relay).await.unwrap();
        tls.connect(name, tcp).await.unwrap()
    })
    .await
    .unwrap_or_else(|_| panic!("no TLS connection to {relay} within {IO_TIMEOUT:?}"))
}

/// A plain TCP connection to `relay`, for tests that never reach TLS.
pub async fn connect_tcp(relay: SocketAddr) -> TcpStream {
    tokio::time::timeout(IO_TIMEOUT, TcpStream::connect(relay))
        .await
        .unwrap_or_else(|_| panic!("no TCP connection to {relay} within {IO_TIMEOUT:?}"))
        .unwrap()
}

/// Reads up to the end of a response header, byte by byte so nothing after it is
/// consumed.
pub async fn read_head(io: &mut (impl AsyncRead + Unpin)) -> String {
    let head = tokio::time::timeout(IO_TIMEOUT, async {
        let mut buf = Vec::new();
        while !buf.ends_with(b"\r\n\r\n") {
            let mut b = [0u8; 1];
            assert_eq!(
                io.read(&mut b).await.unwrap(),
                1,
                "closed inside the header"
            );
            buf.push(b[0]);
        }
        buf
    })
    .await
    .unwrap_or_else(|_| panic!("no response header within {IO_TIMEOUT:?}"));
    String::from_utf8(head).unwrap()
}

/// Reads one HTTP/1.1 response with a `content-length` body.
pub async fn read_response(io: &mut (impl AsyncRead + Unpin)) -> (String, Vec<u8>) {
    tokio::time::timeout(IO_TIMEOUT, read_response_unbounded(io))
        .await
        .unwrap_or_else(|_| panic!("no complete response within {IO_TIMEOUT:?}"))
}

async fn read_response_unbounded(io: &mut (impl AsyncRead + Unpin)) -> (String, Vec<u8>) {
    let mut buf = Vec::new();
    let head_end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        let mut chunk = [0u8; 4096];
        let n = io.read(&mut chunk).await.unwrap();
        assert!(n > 0, "connection closed inside the response header");
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8(buf[..head_end].to_vec()).unwrap();
    let len: usize = head
        .lines()
        .find_map(|l| {
            l.to_ascii_lowercase()
                .strip_prefix("content-length:")
                .map(|v| v.trim().parse().unwrap())
        })
        .expect("content-length");
    let mut body = buf.split_off(head_end);
    while body.len() < len {
        let mut chunk = [0u8; 4096];
        let n = io.read(&mut chunk).await.unwrap();
        assert!(n > 0, "connection closed inside the body");
        body.extend_from_slice(&chunk[..n]);
    }
    assert_eq!(body.len(), len, "bytes beyond the body");
    (head, body)
}
