//! A throwaway certificate authority.

use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};

pub struct Ca {
    issuer: CertifiedIssuer<'static, KeyPair>,
}

/// A certificate chain and its leaf's key, PEM encoded.
pub struct Leaf {
    pub cert_pem: String,
    pub key_pem: String,
}

impl Ca {
    pub fn new(name: &str) -> Self {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);
        let issuer = CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap();
        Self { issuer }
    }

    pub fn cert_pem(&self) -> String {
        self.issuer.pem()
    }

    pub fn cert_der(&self) -> rustls::pki_types::CertificateDer<'static> {
        self.issuer.der().clone()
    }

    /// Issues a leaf for `names`; the PEM chain holds the leaf and then this CA, as a
    /// full chain file does.
    pub fn leaf(&self, names: &[&str]) -> Leaf {
        let key = KeyPair::generate().unwrap();
        let params =
            CertificateParams::new(names.iter().map(|n| (*n).to_owned()).collect::<Vec<_>>())
                .unwrap();
        let cert = params.signed_by(&key, &self.issuer).unwrap();
        Leaf {
            cert_pem: cert.pem() + &self.issuer.pem(),
            key_pem: key.serialize_pem(),
        }
    }
}
