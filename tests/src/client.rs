//! An HTTPS client that trusts the test CA and dials the relay for every name.

use rustls::pki_types::CertificateDer;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

/// Which application protocol the client offers.
#[derive(Clone, Copy, Debug)]
pub enum Proto {
    H1,
    H2,
}

/// A client whose TLS trusts `root` only and whose DNS answers `relay` for `host`.
pub fn client(
    root: CertificateDer<'static>,
    host: &str,
    relay: SocketAddr,
    proto: Proto,
) -> reqwest::Client {
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
    reqwest::Client::builder()
        .use_preconfigured_tls(tls)
        .resolve(host, relay)
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap()
}
