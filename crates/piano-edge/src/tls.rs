//! Downstream TLS.
//!
//! Certificates are chosen by SNI from the configured site hosts only. A handshake
//! without SNI, or for a name that is not a site, finds no certificate and fails, so
//! scanners probing by IP never see which names this host serves.

use piano_config::Config;
use rustls::crypto::ring::default_provider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::ResolvesServerCertUsingSni;
use rustls::sign::CertifiedKey;
use rustls::{ServerConfig, version};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// ALPN identifiers offered to clients, most preferred first.
pub const ALPN: [&[u8]; 2] = [b"h2", b"http/1.1"];

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("cannot read certificate chain {path}: {source}")]
    Chain {
        path: PathBuf,
        source: rustls::pki_types::pem::Error,
    },
    #[error("certificate chain {0} is empty")]
    EmptyChain(PathBuf),
    #[error("cannot read private key {path}: {source}")]
    Key {
        path: PathBuf,
        source: rustls::pki_types::pem::Error,
    },
    #[error("private key {path} is unusable: {source}")]
    BadKey {
        path: PathBuf,
        source: rustls::Error,
    },
    #[error("certificate {cert} does not cover host {host}: {source}")]
    NotCovered {
        cert: PathBuf,
        host: String,
        source: rustls::Error,
    },
    #[error("TLS setup failed: {0}")]
    Rustls(#[from] rustls::Error),
}

/// Builds the downstream `ServerConfig` for all sites in `config`.
pub fn server_config(config: &Config) -> Result<Arc<ServerConfig>, Error> {
    let provider = Arc::new(default_provider());
    let key = load_certified_key(&config.tls.cert, &config.tls.key, &provider)?;
    let mut resolver = ResolvesServerCertUsingSni::new();
    for site in &config.sites {
        resolver
            .add(&site.host, key.clone())
            .map_err(|source| Error::NotCovered {
                cert: config.tls.cert.clone(),
                host: site.host.clone(),
                source,
            })?;
    }
    let mut server = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&version::TLS13, &version::TLS12])?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver));
    server.alpn_protocols = ALPN.iter().map(|p| p.to_vec()).collect();
    Ok(Arc::new(server))
}

fn load_certified_key(
    cert: &Path,
    key: &Path,
    provider: &rustls::crypto::CryptoProvider,
) -> Result<CertifiedKey, Error> {
    let chain = CertificateDer::pem_file_iter(cert)
        .and_then(|it| it.collect::<Result<Vec<_>, _>>())
        .map_err(|source| Error::Chain {
            path: cert.to_owned(),
            source,
        })?;
    if chain.is_empty() {
        return Err(Error::EmptyChain(cert.to_owned()));
    }
    let der = PrivateKeyDer::from_pem_file(key).map_err(|source| Error::Key {
        path: key.to_owned(),
        source,
    })?;
    CertifiedKey::from_der(chain, der, provider).map_err(|source| Error::BadKey {
        path: key.to_owned(),
        source,
    })
}
