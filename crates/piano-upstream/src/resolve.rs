//! Host name resolution.
//!
//! Configured upstreams are resolved once when the site table is built. Redirect
//! targets are resolved when first followed, must resolve to public addresses, and keep
//! their address for a while so their pooled connections stay in one bucket.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("cannot resolve {host}: {source}")]
    Lookup {
        host: String,
        source: std::io::Error,
    },
    #[error("{0} has no address")]
    NoAddress(String),
    #[error("{host} resolves to {ip}, which is not a public address")]
    NotPublic { host: String, ip: IpAddr },
}

/// Maps host names to addresses.
#[derive(Debug, Default, Clone)]
pub struct Resolver {
    #[cfg(feature = "test-support")]
    overrides: HashMap<String, IpAddr>,
}

impl Resolver {
    /// The system resolver.
    pub fn system() -> Self {
        Self::default()
    }

    /// Answers `host` with `ip` instead of asking the system resolver. Overridden
    /// answers skip the public-address check.
    #[cfg(feature = "test-support")]
    pub fn with_override(mut self, host: &str, ip: IpAddr) -> Self {
        self.overrides.insert(host.to_owned(), ip);
        self
    }

    #[cfg(feature = "test-support")]
    fn overridden(&self, host: &str, port: u16) -> Option<SocketAddr> {
        self.overrides
            .get(host)
            .map(|ip| SocketAddr::new(*ip, port))
    }

    #[cfg(not(feature = "test-support"))]
    fn overridden(&self, _host: &str, _port: u16) -> Option<SocketAddr> {
        None
    }

    /// Resolves `host` and picks one address, preferring IPv4.
    pub fn resolve_blocking(&self, host: &str, port: u16) -> Result<SocketAddr, Error> {
        if let Some(a) = self.overridden(host, port) {
            return Ok(a);
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

    /// Resolves `host` without blocking the runtime and picks one public address,
    /// preferring IPv4. Fails if the chosen address is not public: a redirect target's
    /// owner controls its DNS and could point it at this host's private services.
    pub async fn resolve_public(&self, host: &str, port: u16) -> Result<SocketAddr, Error> {
        if let Some(a) = self.overridden(host, port) {
            return Ok(a);
        }
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
            .await
            .map_err(|source| Error::Lookup {
                host: host.to_owned(),
                source,
            })?
            .collect();
        let addr = pick(&addrs).ok_or_else(|| Error::NoAddress(host.to_owned()))?;
        if !is_public(addr.ip()) {
            return Err(Error::NotPublic {
                host: host.to_owned(),
                ip: addr.ip(),
            });
        }
        Ok(addr)
    }
}

fn pick(addrs: &[SocketAddr]) -> Option<SocketAddr> {
    addrs
        .iter()
        .find(|a| matches!(a.ip(), IpAddr::V4(_)))
        .or_else(|| addrs.first())
        .copied()
}

fn in_v4(ip: Ipv4Addr, net: [u8; 4], prefix: u32) -> bool {
    let mask = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
    u32::from(ip) & mask == u32::from(Ipv4Addr::from(net))
}

/// Whether `ip` is a globally routable unicast address.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => is_public_v6(v6),
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    const NOT_PUBLIC: [([u8; 4], u32); 15] = [
        ([0, 0, 0, 0], 8),
        ([10, 0, 0, 0], 8),
        ([100, 64, 0, 0], 10),
        ([127, 0, 0, 0], 8),
        ([169, 254, 0, 0], 16),
        ([172, 16, 0, 0], 12),
        ([192, 0, 0, 0], 24),
        ([192, 0, 2, 0], 24),
        ([192, 88, 99, 0], 24),
        ([192, 168, 0, 0], 16),
        ([198, 18, 0, 0], 15),
        ([198, 51, 100, 0], 24),
        ([203, 0, 113, 0], 24),
        ([224, 0, 0, 0], 4),
        ([240, 0, 0, 0], 4),
    ];
    !NOT_PUBLIC.iter().any(|&(net, p)| in_v4(ip, net, p))
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_public_v4(v4);
    }
    let bits = u128::from(ip);
    let in_net =
        |net: u128, prefix: u32| bits & u128::MAX.checked_shl(128 - prefix).unwrap_or(0) == net;
    // Global unicast is 2000::/3; within it, exclude documentation, Teredo, 6to4 and
    // NAT64, which can embed private IPv4 addresses.
    in_net(0x2000 << 112, 3)
        && !in_net(0x2001_0db8 << 96, 32)
        && !in_net(0x2001_0000 << 96, 32)
        && !in_net(0x2002 << 112, 16)
        && !in_net(0x0064_ff9b << 96, 32)
}

/// Addresses chosen for redirect targets, kept for `ttl` after the first lookup.
#[derive(Debug)]
pub struct AddrCache {
    ttl: Duration,
    entries: Mutex<HashMap<(String, u16), (SocketAddr, Instant)>>,
}

impl AddrCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// The cached address of `host:port`, or a fresh public one from `resolver`.
    pub async fn get(
        &self,
        resolver: &Resolver,
        host: &str,
        port: u16,
    ) -> Result<SocketAddr, Error> {
        let key = (host.to_owned(), port);
        let cached = self.lock().get(&key).copied();
        if let Some((addr, at)) = cached
            && at.elapsed() < self.ttl
        {
            return Ok(addr);
        }
        let addr = resolver.resolve_public(host, port).await?;
        let mut entries = self.lock();
        let now = Instant::now();
        entries.retain(|_, (_, at)| now.duration_since(*at) < self.ttl);
        entries.insert(key, (addr, now));
        Ok(addr)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<(String, u16), (SocketAddr, Instant)>> {
        // The map holds plain data, so a panic elsewhere cannot leave it inconsistent.
        self.entries.lock().unwrap_or_else(|e| e.into_inner())
    }
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

    #[test]
    fn public_addresses() {
        for ip in [
            "1.1.1.1",
            "104.16.0.1",
            "2606:4700::1",
            "2a01:4f8::1",
            "::ffff:8.8.8.8",
        ] {
            assert!(is_public(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "0.0.0.0",
            "10.1.2.3",
            "100.64.0.1",
            "127.0.0.2",
            "169.254.169.254",
            "172.20.0.1",
            "192.168.1.1",
            "192.0.2.1",
            "198.18.0.1",
            "203.0.113.9",
            "224.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "::ffff:127.0.0.1",
            "fe80::1",
            "fc00::1",
            "fd12::1",
            "ff02::1",
            "2001:db8::1",
            "2002:7f00:1::",
            "64:ff9b::7f00:1",
            "2001::1",
        ] {
            assert!(!is_public(ip.parse().unwrap()), "{ip}");
        }
    }
}
