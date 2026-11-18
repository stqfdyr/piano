//! Host name resolution.
//!
//! Resolution currently happens once at startup through the system resolver.

use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("cannot resolve {host}: {source}")]
    Lookup {
        host: String,
        source: std::io::Error,
    },
    #[error("{0} has no address")]
    NoAddress(String),
}

/// Maps host names to addresses.
#[derive(Debug, Default, Clone)]
pub struct Resolver {
    #[cfg(feature = "test-support")]
    overrides: std::collections::HashMap<String, IpAddr>,
}

impl Resolver {
    /// The system resolver.
    pub fn system() -> Self {
        Self::default()
    }

    /// Answers `host` with `ip` instead of asking the system resolver.
    #[cfg(feature = "test-support")]
    pub fn with_override(mut self, host: &str, ip: IpAddr) -> Self {
        self.overrides.insert(host.to_owned(), ip);
        self
    }

    /// Resolves `host` and picks one address, preferring IPv4.
    ///
    /// The same host always maps to the same address, so its pooled connections stay
    /// in one bucket.
    pub fn resolve_blocking(&self, host: &str, port: u16) -> Result<SocketAddr, Error> {
        #[cfg(feature = "test-support")]
        if let Some(ip) = self.overrides.get(host) {
            return Ok(SocketAddr::new(*ip, port));
        }
        let addrs: Vec<SocketAddr> = (host, port)
            .to_socket_addrs()
            .map_err(|source| Error::Lookup {
                host: host.to_owned(),
                source,
            })?
            .collect();
        pick(&addrs).ok_or_else(|| Error::NoAddress(host.to_owned()))
    }
}

fn pick(addrs: &[SocketAddr]) -> Option<SocketAddr> {
    addrs
        .iter()
        .find(|a| matches!(a.ip(), IpAddr::V4(_)))
        .or_else(|| addrs.first())
        .copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefers_ipv4() {
        let v6: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let v4: SocketAddr = "192.0.2.1:443".parse().unwrap();
        assert_eq!(pick(&[v6, v4]), Some(v4));
        assert_eq!(pick(&[v6]), Some(v6));
        assert_eq!(pick(&[]), None);
    }
}
