//! Upstream TLS client configuration.
//!
//! Trust anchors are the system roots plus any configured extra roots; extra roots are
//! added, never substituted. Certificate verification cannot be turned off.

use log::warn;
use rustls::crypto::ring::default_provider;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use rustls::{ClientConfig, RootCertStore, version};
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("cannot read root certificates {path}: {source}")]
    Read {
        path: PathBuf,
        source: rustls::pki_types::pem::Error,
    },
    #[error("no PEM CERTIFICATE section in {path}")]
    NoCertificate { path: PathBuf },
    #[error("root certificate in {path} is unusable: {source}")]
    BadRoot {
        path: PathBuf,
        source: rustls::Error,
    },
    #[error("no trusted root certificates")]
    NoRoots,
    #[error("TLS setup failed: {0}")]
    Rustls(#[from] rustls::Error),
}

/// A client config and the root store it verifies against.
pub struct ClientTls {
    pub config: Arc<ClientConfig>,
    pub roots: Arc<RootCertStore>,
}

/// Builds the upstream client config from the system roots and `extra_roots`.
pub fn client_config(extra_roots: &[PathBuf]) -> Result<ClientTls, Error> {
    let mut roots = RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    for e in &native.errors {
        warn!("system root certificates: {e}");
    }
    let (added, ignored) = roots.add_parsable_certificates(native.certs);
    if ignored > 0 {
        warn!("ignored {ignored} unparsable system root certificates ({added} loaded)");
    }
    for path in extra_roots {
        add_pem_roots(&mut roots, path)?;
    }
    if roots.is_empty() {
        return Err(Error::NoRoots);
    }
    let roots = Arc::new(roots);
    let config = ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_protocol_versions(&[&version::TLS13, &version::TLS12])?
        .with_root_certificates(Arc::clone(&roots))
        .with_no_client_auth();
    Ok(ClientTls {
        config: Arc::new(config),
        roots,
    })
}

/// Adds every certificate in the PEM file at `path`. Sections of other kinds are
/// skipped, so a file without any certificate (empty, DER, a key) is an error rather
/// than a silent no-op.
fn add_pem_roots(roots: &mut RootCertStore, path: &Path) -> Result<(), Error> {
    let certs = CertificateDer::pem_file_iter(path)
        .and_then(|it| it.collect::<Result<Vec<_>, _>>())
        .map_err(|source| Error::Read {
            path: path.to_owned(),
            source,
        })?;
    if certs.is_empty() {
        return Err(Error::NoCertificate {
            path: path.to_owned(),
        });
    }
    for cert in certs {
        roots.add(cert).map_err(|source| Error::BadRoot {
            path: path.to_owned(),
            source,
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A directory of its own, removed when dropped, so a failing test leaves nothing.
    struct Dir(PathBuf);

    impl Dir {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("piano-upstream-tls-{}", std::process::id()));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn file(&self, name: &str, content: &[u8]) -> PathBuf {
            let path = self.0.join(name);
            std::fs::write(&path, content).unwrap();
            path
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn extra_roots_without_a_certificate_are_refused() {
        let dir = Dir::new();
        let key = b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n";
        let bad = b"-----BEGIN CERTIFICATE-----\n%%%%\n-----END CERTIFICATE-----\n";
        let mut roots = RootCertStore::empty();
        for path in [
            dir.file("empty.pem", b""),
            dir.file("root.der", &[0x30, 0x82, 0x01, 0x0a]),
            dir.file("key.pem", key),
        ] {
            let e = add_pem_roots(&mut roots, &path).unwrap_err();
            assert!(matches!(e, Error::NoCertificate { .. }), "{e}");
        }
        for path in [dir.file("bad.pem", bad), dir.0.join("missing.pem")] {
            let e = add_pem_roots(&mut roots, &path).unwrap_err();
            assert!(matches!(e, Error::Read { .. }), "{e}");
        }
    }
}
