//! An HTTPS client that trusts the test CA and dials the relay for every name.

use rustls::pki_types::{CertificateDer, ServerName};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
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
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap()
}

/// A raw TLS connection to `relay` for `host`, for tests that control the bytes on the wire.
pub async fn connect(
    root: CertificateDer<'static>,
    host: &str,
    relay: SocketAddr,
    proto: Proto,
) -> TlsStream<TcpStream> {
    let tcp = TcpStream::connect(relay).await.unwrap();
    let name = ServerName::try_from(host.to_owned()).unwrap();
    TlsConnector::from(Arc::new(tls_config(root, proto)))
        .connect(name, tcp)
        .await
        .unwrap()
}
