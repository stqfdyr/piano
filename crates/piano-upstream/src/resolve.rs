//! Host name resolution.
//!
//! Configured upstreams are resolved when the site table is built and looked up again
//! from time to time ([`Addrs::update`]). Redirect targets are resolved when first
//! followed, must resolve to public addresses, and keep their addresses for a while. A
//! host keeps using one address, so its pooled connections stay in one bucket, until
//! connecting to that address fails or a new lookup no longer lists it.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
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
    overrides: HashMap<String, Vec<IpAddr>>,
}

impl Resolver {
    /// The system resolver.
    pub fn system() -> Self {
        Self::default()
    }

    /// Answers `host` with `ips`, in that order, instead of asking the system resolver;
    /// with none, `host` has no address. Overridden answers skip the public-address check.
    #[cfg(feature = "test-support")]
    pub fn with_override(mut self, host: &str, ips: &[IpAddr]) -> Self {
        self.overrides.insert(host.to_owned(), ips.to_vec());
        self
    }

    #[cfg(feature = "test-support")]
    fn overridden(&self, host: &str, port: u16) -> Option<Result<Addrs, Error>> {
        let ips = self.overrides.get(host)?;
        Some(
            Addrs::new(ips.iter().map(|ip| SocketAddr::new(*ip, port)).collect())
                .ok_or_else(|| Error::NoAddress(host.to_owned())),
        )
    }

    #[cfg(not(feature = "test-support"))]
    fn overridden(&self, _host: &str, _port: u16) -> Option<Result<Addrs, Error>> {
        None
    }

    /// Resolves `host`; IPv4 addresses come first.
    pub fn resolve_blocking(&self, host: &str, port: u16) -> Result<Addrs, Error> {
        if let Some(a) = self.overridden(host, port) {
            return a;
        }
        let addrs: Vec<SocketAddr> = (host, port)
            .to_socket_addrs()
            .map_err(|source| Error::Lookup {
                host: host.to_owned(),
                source,
            })?
            .collect();
        Addrs::new(ipv4_first(addrs)).ok_or_else(|| Error::NoAddress(host.to_owned()))
    }

    /// Resolves `host` without blocking the runtime and keeps only public addresses,
    /// IPv4 first. A redirect target's owner controls its DNS and could point it at
    /// this host's private services.
    pub async fn resolve_public(&self, host: &str, port: u16) -> Result<Addrs, Error> {
        if let Some(a) = self.overridden(host, port) {
            return a;
        }
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
            .await
            .map_err(|source| Error::Lookup {
                host: host.to_owned(),
                source,
            })?
            .collect();
        keep_public(host, addrs)
    }
}

/// The public addresses among the answers for `host`, IPv4 first.
fn keep_public(host: &str, addrs: Vec<SocketAddr>) -> Result<Addrs, Error> {
    let first = addrs
        .first()
        .copied()
        .ok_or_else(|| Error::NoAddress(host.to_owned()))?;
    let public = addrs.into_iter().filter(|a| is_public(a.ip())).collect();
    Addrs::new(ipv4_first(public)).ok_or_else(|| Error::NotPublic {
        host: host.to_owned(),
        ip: first.ip(),
    })
}

/// Stable order with IPv4 addresses before IPv6 ones, without duplicates.
fn ipv4_first(mut addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
    addrs.sort_by_key(SocketAddr::is_ipv6);
    let mut unique = Vec::with_capacity(addrs.len());
    for a in addrs {
        if !unique.contains(&a) {
            unique.push(a);
        }
    }
    unique
}

/// The addresses of one host in order of preference, and the one in use. Shared by
/// every request to the host, so a failed address is skipped by later requests too.
#[derive(Debug)]
pub struct Addrs {
    /// Empty only until a host that did not resolve at startup first does. Replaced only
    /// by [`Addrs::update`].
    list: RwLock<Box<[SocketAddr]>>,
    current: AtomicUsize,
}

impl Addrs {
    /// `None` if `list` is empty.
    pub fn new(list: Vec<SocketAddr>) -> Option<Self> {
        if list.is_empty() {
            return None;
        }
        Some(Self {
            list: RwLock::new(list.into_boxed_slice()),
            current: AtomicUsize::new(0),
        })
    }

    /// A host that does not resolve yet; [`Addrs::update`] fills it in once it does.
    pub fn unresolved() -> Self {
        Self {
            list: RwLock::new(Box::default()),
            current: AtomicUsize::new(0),
        }
    }

    fn list(&self) -> std::sync::RwLockReadGuard<'_, Box<[SocketAddr]>> {
        // The list is replaced whole, so a panic elsewhere cannot leave it inconsistent.
        self.list.read().unwrap_or_else(PoisonError::into_inner)
    }

    /// The address to connect to; `None` while the host does not resolve.
    pub fn current(&self) -> Option<SocketAddr> {
        let list = self.list();
        let i = self.current.load(Ordering::Relaxed);
        list.get(i.checked_rem(list.len())?).copied()
    }

    /// Number of distinct addresses.
    pub fn len(&self) -> usize {
        self.list().len()
    }

    /// Whether the host does not resolve yet.
    pub fn is_empty(&self) -> bool {
        self.list().is_empty()
    }

    /// Moves on to the next address after connecting to `failed` did not work. When
    /// several requests fail on the same address at once, only the first moves on.
    pub fn failed(&self, failed: SocketAddr) {
        let list = self.list();
        let i = self.current.load(Ordering::Relaxed);
        if list.get(i.checked_rem(list.len()).unwrap_or(0)) == Some(&failed) {
            let next = (i + 1) % list.len();
            let _ = self
                .current
                .compare_exchange(i, next, Ordering::Relaxed, Ordering::Relaxed);
        }
    }

    /// Takes the addresses of `fresh`, a new lookup of the same host, if they differ
    /// from the current ones as a set. The address in use stays in use while it is
    /// still listed, so its pooled connections are kept. Returns the old and new lists
    /// when they differed.
    pub fn update(&self, fresh: Addrs) -> Option<(Vec<SocketAddr>, Vec<SocketAddr>)> {
        let fresh = fresh
            .list
            .into_inner()
            .unwrap_or_else(PoisonError::into_inner);
        let mut list = self.list.write().unwrap_or_else(PoisonError::into_inner);
        let sorted = |l: &[SocketAddr]| {
            let mut l = l.to_vec();
            l.sort_unstable();
            l
        };
        if sorted(&list) == sorted(&fresh) {
            return None;
        }
        let in_use = self
            .current
            .load(Ordering::Relaxed)
            .checked_rem(list.len())
            .map(|i| list[i]);
        let next = fresh.iter().position(|&a| Some(a) == in_use).unwrap_or(0);
        let old = std::mem::replace(&mut *list, fresh);
        self.current.store(next, Ordering::Relaxed);
        Some((old.into_vec(), list.to_vec()))
    }
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
    // Global unicast is 2000::/3, which leaves out NAT64 (64:ff9b::/96). Within it,
    // exclude documentation, SRv6 segment identifiers, the IETF protocol block (Teredo,
    // benchmarking, ORCHID) and 6to4; Teredo and 6to4 can embed private IPv4 addresses.
    in_net(0x2000 << 112, 3)
        && !in_net(0x2001_0db8 << 96, 32)
        && !in_net(0x3fff << 112, 20)
        && !in_net(0x5f00 << 112, 16)
        && !in_net(0x2001 << 112, 23)
        && !in_net(0x2002 << 112, 16)
}

type Entries = HashMap<(String, u16), (Arc<Addrs>, Instant)>;

/// Addresses of redirect targets, kept for `ttl` after the first lookup.
#[derive(Debug)]
pub struct AddrCache {
    ttl: Duration,
    entries: Mutex<Entries>,
}

impl AddrCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// The cached addresses of `host:port`, or fresh public ones from `resolver`.
    pub async fn get(
        &self,
        resolver: &Resolver,
        host: &str,
        port: u16,
    ) -> Result<Arc<Addrs>, Error> {
        let key = (host.to_owned(), port);
        let cached = self
            .lock()
            .get(&key)
            .filter(|(_, at)| at.elapsed() < self.ttl)
            .map(|(addrs, _)| Arc::clone(addrs));
        if let Some(addrs) = cached {
            return Ok(addrs);
        }
        let addrs = Arc::new(resolver.resolve_public(host, port).await?);
        log::info!(
            "redirect target {host}:{port} resolved to {}",
            addrs.current().map(|a| a.to_string()).unwrap_or_default()
        );
        let mut entries = self.lock();
        let now = Instant::now();
        entries.retain(|_, (_, at)| now.duration_since(*at) < self.ttl);
        entries.insert(key, (Arc::clone(&addrs), now));
        Ok(addrs)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Entries> {
        // The map holds plain data, so a panic elsewhere cannot leave it inconsistent.
        self.entries.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn ipv4_comes_first() {
        let (a6, b6) = (sa("[2001:db8::1]:443"), sa("[2001:db8::2]:443"));
        let (a4, b4) = (sa("192.0.2.1:443"), sa("192.0.2.2:443"));
        assert_eq!(ipv4_first(vec![a6, a4, b6, b4, a4]), [a4, b4, a6, b6]);
        assert!(Addrs::new(vec![]).is_none());
    }

    #[test]
    fn failed_address_moves_on_once() {
        let (a, b, c) = (
            sa("192.0.2.1:443"),
            sa("192.0.2.2:443"),
            sa("192.0.2.3:443"),
        );
        let addrs = Addrs::new(vec![a, b, c]).unwrap();
        assert_eq!(addrs.current(), Some(a));
        addrs.failed(a);
        // A second request that also failed on `a` does not skip `b`.
        addrs.failed(a);
        assert_eq!(addrs.current(), Some(b));
        addrs.failed(b);
        addrs.failed(c);
        assert_eq!(addrs.current(), Some(a));
    }

    #[test]
    fn lookups_keep_only_public_addresses() {
        let private = sa("127.0.0.1:443");
        let e = keep_public("a.example.net", vec![private]).unwrap_err();
        assert!(matches!(e, Error::NotPublic { .. }), "{e}");
        let pub6 = sa("[2606:4700::1]:443");
        let kept = keep_public("a.example.net", vec![pub6, private, sa("1.1.1.1:443")]).unwrap();
        assert_eq!((kept.len(), kept.current()), (2, Some(sa("1.1.1.1:443"))));
        assert!(matches!(
            keep_public("a.example.net", vec![]),
            Err(Error::NoAddress(_))
        ));
    }

    #[test]
    fn an_unresolved_host_takes_its_first_addresses() {
        let (a, b) = (sa("192.0.2.1:443"), sa("192.0.2.2:443"));
        let addrs = Addrs::unresolved();
        assert_eq!((addrs.current(), addrs.len()), (None, 0));
        // Nothing to move on from.
        addrs.failed(a);
        assert_eq!(addrs.current(), None);
        let (old, new) = addrs.update(Addrs::new(vec![a, b]).unwrap()).unwrap();
        assert_eq!((old, new), (vec![], vec![a, b]));
        assert_eq!(addrs.current(), Some(a));
    }

    #[test]
    fn updates_keep_the_address_in_use_while_it_is_listed() {
        let (a, b, c) = (
            sa("192.0.2.1:443"),
            sa("192.0.2.2:443"),
            sa("192.0.2.3:443"),
        );
        let addrs = Addrs::new(vec![a, b]).unwrap();
        addrs.failed(a);
        assert_eq!(addrs.current(), Some(b));
        // The same set in another order is no change.
        assert!(addrs.update(Addrs::new(vec![b, a]).unwrap()).is_none());
        assert_eq!(addrs.current(), Some(b));
        // `b` is still listed: it stays in use at its new position.
        let (old, new) = addrs.update(Addrs::new(vec![c, b]).unwrap()).unwrap();
        assert_eq!((old, new), (vec![a, b], vec![c, b]));
        assert_eq!((addrs.current(), addrs.len()), (Some(b), 2));
        addrs.failed(b);
        assert_eq!(addrs.current(), Some(c));
        // The address in use is gone: the first of the new list takes over.
        addrs.update(Addrs::new(vec![a]).unwrap()).unwrap();
        assert_eq!((addrs.current(), addrs.len()), (Some(a), 1));
    }

    #[test]
    fn public_addresses() {
        for ip in [
            "1.1.1.1",
            "104.16.0.1",
            "2606:4700::1",
            "2a01:4f8::1",
            "3ffe::1",
            "3fff:1000::1",
            "2001:200::1",
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
            "3fff::1",
            "3fff:fff::1",
            "5f00::1",
            "2001:2::1",
            "2001:20::1",
            "2001:1ff::1",
        ] {
            assert!(!is_public(ip.parse().unwrap()), "{ip}");
        }
    }
}
