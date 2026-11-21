//! Downstream TLS.
//!
//! Certificates are chosen by SNI from the configured site hosts only. A handshake
//! without SNI, or for a name that is not a site, finds no certificate and fails, so
//! scanners probing by IP never see which names this host serves.

use arc_swap::ArcSwap;
use async_trait::async_trait;
use piano_config::Config;
use piano_telemetry::Id;
use pingora_core::listeners::TlsAccept;
use pingora_core::protocols::tls::TlsRef;
use rustls::crypto::ring::default_provider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert, ResolvesServerCertUsingSni};
use rustls::sign::CertifiedKey;
use rustls::{ServerConfig, version};
use std::any::Any;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

/// Why a chain with [`CertInfo::incomplete_chain`] is a problem.
pub const INCOMPLETE_CHAIN: &str = "the certificate file lacks the certificate that issued the \
     leaf (an intermediate, or a private root); clients that do not fetch it refuse the \
     connection";

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

/// Facts about a downstream connection, attached to its TLS digest by [`SniRecorder`]
/// when the handshake completes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conn {
    /// Ties together the log records of the requests on this connection.
    pub id: Id,
    /// The server name from the ClientHello, lowercased.
    pub sni: Option<String>,
}

/// Handshake callback that records the connection id and SNI name, so the HTTP layer
/// can log them and check that a request's host belongs to the same site.
#[derive(Debug)]
pub struct SniRecorder;

#[async_trait]
impl TlsAccept for SniRecorder {
    async fn handshake_complete_callback(
        &self,
        tls: &TlsRef,
    ) -> Option<Arc<dyn Any + Send + Sync>> {
        Some(Arc::new(Conn {
            id: piano_telemetry::id::connection(),
            sni: tls.server_name().map(str::to_ascii_lowercase),
        }))
    }
}

/// What the served certificate says about itself, for status reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertInfo {
    /// DNS names in the subject alternative names.
    pub names: Vec<String>,
    /// End of validity, Unix seconds; `None` if the certificate could not be read for it.
    pub not_after: Option<i64>,
    /// When the files were loaded.
    pub loaded: SystemTime,
    /// Another certificate issued the leaf, and the chain does not hold it: clients that
    /// do not fetch it refuse the chain.
    pub incomplete_chain: bool,
}

impl CertInfo {
    /// Describes `chain`, whose first certificate is the leaf.
    fn of(chain: &[CertificateDer<'_>]) -> Option<Self> {
        let leaf = chain.first()?;
        let parsed = x509_parser::parse_x509_certificate(leaf.as_ref()).ok();
        let incomplete_chain = parsed.as_ref().is_some_and(|(_, leaf)| {
            leaf.issuer() != leaf.subject()
                && !chain[1..].iter().any(|c| {
                    x509_parser::parse_x509_certificate(c.as_ref())
                        .is_ok_and(|(_, c)| c.subject() == leaf.issuer())
                })
        });
        let names = parsed
            .as_ref()
            .and_then(|(_, c)| c.subject_alternative_name().ok().flatten())
            .map(|san| {
                san.value
                    .general_names
                    .iter()
                    .filter_map(|n| match n {
                        x509_parser::extensions::GeneralName::DNSName(d) => Some((*d).to_owned()),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default();
        Some(Self {
            names,
            not_after: parsed.map(|(_, c)| c.validity().not_after.timestamp()),
            loaded: SystemTime::now(),
            incomplete_chain,
        })
    }
}

/// Certificates by SNI name, loaded from the files named in a configuration.
#[derive(Debug)]
pub struct SniTable {
    resolver: ResolvesServerCertUsingSni,
    info: CertInfo,
}

impl SniTable {
    /// Loads the certificate and maps every site host to it; fails if it does not cover
    /// one of them.
    pub fn load(config: &Config) -> Result<Self, Error> {
        let hosts: Vec<&str> = config.sites.iter().map(|s| s.host.as_str()).collect();
        Self::from_files(&config.tls.cert, &config.tls.key, &hosts)
    }

    /// Loads the certificate chain `cert` with private key `key` and maps each of
    /// `hosts` to it; fails if it does not cover one of them.
    pub fn from_files(cert: &Path, key: &Path, hosts: &[&str]) -> Result<Self, Error> {
        let provider = default_provider();
        let certified = load_certified_key(cert, key, &provider)?;
        let info =
            CertInfo::of(&certified.cert).ok_or_else(|| Error::EmptyChain(cert.to_owned()))?;
        let mut resolver = ResolvesServerCertUsingSni::new();
        for host in hosts {
            resolver
                .add(host, certified.clone())
                .map_err(|source| Error::NotCovered {
                    cert: cert.to_owned(),
                    host: (*host).to_owned(),
                    source,
                })?;
        }
        Ok(Self { resolver, info })
    }

    pub fn info(&self) -> &CertInfo {
        &self.info
    }
}

/// The certificate table in use, replaced as a whole on reload. A handshake uses the
/// table that was current when its ClientHello arrived.
#[derive(Debug)]
pub struct CertStore {
    table: ArcSwap<SniTable>,
}

impl CertStore {
    pub fn new(table: SniTable) -> Self {
        Self {
            table: ArcSwap::from_pointee(table),
        }
    }

    pub fn replace(&self, table: SniTable) {
        self.table.store(Arc::new(table));
    }

    /// The certificate currently served.
    pub fn info(&self) -> CertInfo {
        self.table.load().info.clone()
    }
}

impl ResolvesServerCert for CertStore {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.table.load().resolver.resolve(hello)
    }
}

/// Builds the downstream `ServerConfig` around `certs`.
pub fn server_config(certs: Arc<CertStore>) -> Result<Arc<ServerConfig>, Error> {
    let mut server = ServerConfig::builder_with_provider(Arc::new(default_provider()))
        .with_protocol_versions(&[&version::TLS13, &version::TLS12])?
        .with_no_client_auth()
        .with_cert_resolver(certs);
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

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};

    fn params(names: &[&str]) -> CertificateParams {
        CertificateParams::new(names.iter().map(|n| (*n).to_owned()).collect::<Vec<_>>()).unwrap()
    }

    #[test]
    fn a_leaf_without_its_issuer_is_an_incomplete_chain() {
        let mut ca = params(&[]);
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca.distinguished_name
            .push(rcgen::DnType::CommonName, "issuer");
        let ca = CertifiedIssuer::self_signed(ca, KeyPair::generate().unwrap()).unwrap();
        let leaf = params(&["media.example.com"])
            .signed_by(&KeyPair::generate().unwrap(), &ca)
            .unwrap();
        let leaf = leaf.der().clone();
        let full = [leaf.clone(), ca.der().clone()];
        let unrelated = params(&[])
            .self_signed(&KeyPair::generate().unwrap())
            .unwrap();
        let wrong = [leaf.clone(), unrelated.der().clone()];
        assert!(CertInfo::of(&[leaf]).unwrap().incomplete_chain);
        assert!(CertInfo::of(&wrong).unwrap().incomplete_chain);
        assert!(!CertInfo::of(&full).unwrap().incomplete_chain);
        assert_eq!(CertInfo::of(&full).unwrap().names, ["media.example.com"]);
    }

    #[test]
    fn a_self_signed_leaf_is_complete() {
        let leaf = params(&["media.example.com"])
            .self_signed(&KeyPair::generate().unwrap())
            .unwrap();
        assert!(
            !CertInfo::of(&[leaf.der().clone()])
                .unwrap()
                .incomplete_chain
        );
        assert!(CertInfo::of(&[]).is_none());
    }
}
