//! Connection-level access control: client addresses checked before the TLS handshake.

use arc_swap::ArcSwap;
use async_trait::async_trait;
use log::info;
use piano_config::{IpNet, mask_v4, mask_v6};
use piano_telemetry::logger::REFUSED;
use pingora_core::listeners::ConnectionFilter;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// A compiled allow list.
#[derive(Debug, Default)]
pub struct Acl {
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
    /// Loopback addresses are allowed whatever the list says.
    loopback: bool,
}

impl Acl {
    pub fn new(allow: &[IpNet], loopback: bool) -> Self {
        let mut acl = Self {
            loopback,
            ..Self::default()
        };
        for net in allow {
            match net.addr() {
                IpAddr::V4(a) => acl.v4.push((u32::from(a), mask_v4(net.prefix()))),
                IpAddr::V6(a) => acl.v6.push((u128::from(a), mask_v6(net.prefix()))),
            }
        }
        acl
    }

    /// Whether `ip` is allowed. IPv4-mapped IPv6 addresses are matched as IPv4.
    pub fn allows(&self, ip: IpAddr) -> bool {
        let ip = canonical(ip);
        if self.loopback && ip.is_loopback() {
            return true;
        }
        match ip {
            IpAddr::V4(a) => {
                let a = u32::from(a);
                self.v4.iter().any(|&(net, mask)| a & mask == net)
            }
            IpAddr::V6(a) => {
                let a = u128::from(a);
                self.v6.iter().any(|&(net, mask)| a & mask == net)
            }
        }
    }
}

/// The form a client address is matched and logged in.
pub fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    }
}

/// The listener's connection filter. The list is swapped on reload; connections already
/// accepted are not re-checked.
#[derive(Debug)]
pub struct AccessFilter {
    acl: ArcSwap<Acl>,
    denied: AtomicU64,
}

impl AccessFilter {
    pub fn new(acl: Acl) -> Self {
        Self {
            acl: ArcSwap::from_pointee(acl),
            denied: AtomicU64::new(0),
        }
    }

    pub fn replace(&self, acl: Acl) {
        self.acl.store(Arc::new(acl));
    }

    /// Connections refused since start.
    pub fn denied(&self) -> u64 {
        self.denied.load(Ordering::Relaxed)
    }
}

#[async_trait]
impl ConnectionFilter for AccessFilter {
    async fn should_accept(&self, addr: Option<&SocketAddr>) -> bool {
        // An address that cannot be read is refused: the list is the only gate.
        let ip = addr.map(SocketAddr::ip);
        let allowed = ip.is_some_and(|ip| self.acl.load().allows(ip));
        if !allowed {
            self.denied.fetch_add(1, Ordering::Relaxed);
            match ip {
                Some(ip) => info!(target: REFUSED, "refused connection from {}", canonical(ip)),
                None => info!(target: REFUSED, "refused connection without a peer address"),
            }
        }
        allowed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acl(nets: &[&str]) -> Acl {
        let nets: Vec<IpNet> = nets.iter().map(|n| n.parse().unwrap()).collect();
        Acl::new(&nets, false)
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn loopback_is_allowed_only_when_asked() {
        let nets: Vec<IpNet> = vec!["192.0.2.7".parse().unwrap()];
        for lo in ["127.0.0.1", "127.3.2.1", "::1", "::ffff:127.0.0.1"] {
            assert!(Acl::new(&nets, true).allows(ip(lo)), "{lo}");
            assert!(!Acl::new(&nets, false).allows(ip(lo)), "{lo}");
        }
        assert!(!Acl::new(&nets, true).allows(ip("192.0.2.8")));
    }

    #[test]
    fn matches_hosts_and_prefixes() {
        let a = acl(&["192.0.2.7", "198.51.100.0/24", "2001:db8:1:2::/64"]);
        assert!(a.allows(ip("192.0.2.7")));
        assert!(!a.allows(ip("192.0.2.8")));
        assert!(a.allows(ip("198.51.100.200")));
        assert!(!a.allows(ip("198.51.101.1")));
        assert!(a.allows(ip("2001:db8:1:2:ffff::1")));
        assert!(!a.allows(ip("2001:db8:1:3::1")));
    }

    #[test]
    fn mapped_clients_match_ipv4_entries() {
        let a = acl(&["192.0.2.7", "::ffff:198.51.100.0/120"]);
        assert!(a.allows(ip("::ffff:192.0.2.7")));
        assert!(a.allows(ip("::ffff:198.51.100.9")));
        assert!(!a.allows(ip("::ffff:192.0.2.8")));
    }

    #[test]
    fn everything_entries_cover_their_family_only() {
        let a = acl(&["0.0.0.0/0"]);
        assert!(a.allows(ip("203.0.113.1")));
        assert!(a.allows(ip("::ffff:203.0.113.1")));
        assert!(!a.allows(ip("2001:db8::1")));
        assert!(acl(&["::/0"]).allows(ip("2001:db8::1")));
    }

    #[test]
    fn empty_list_allows_nothing() {
        assert!(!Acl::default().allows(ip("192.0.2.1")));
    }

    #[tokio::test]
    async fn filter_counts_refusals_and_follows_replacement() {
        let f = AccessFilter::new(acl(&["192.0.2.7"]));
        let addr = |s: &str| s.parse::<SocketAddr>().unwrap();
        assert!(f.should_accept(Some(&addr("192.0.2.7:5000"))).await);
        assert!(!f.should_accept(Some(&addr("192.0.2.8:5000"))).await);
        assert!(!f.should_accept(None).await);
        assert_eq!(f.denied(), 2);
        f.replace(acl(&["192.0.2.8"]));
        assert!(
            f.should_accept(Some(&addr("[::ffff:192.0.2.8]:5000")))
                .await
        );
        assert!(!f.should_accept(Some(&addr("192.0.2.7:5000"))).await);
    }
}
