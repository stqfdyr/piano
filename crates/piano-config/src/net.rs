use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// An IPv4 or IPv6 network in CIDR form; a bare address is a single host.
///
/// IPv4-mapped IPv6 networks (`::ffff:a.b.c.d/n`, n ≥ 96) are stored as their IPv4
/// equivalent, because clients of a dual-stack listener are matched in IPv4 form.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IpNet {
    addr: IpAddr,
    prefix: u8,
}

/// A network string that is not a valid address or CIDR.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid network {input:?}: {reason}")]
pub struct ParseIpNetError {
    input: String,
    reason: &'static str,
}

impl IpNet {
    /// The network address (host bits are zero).
    pub fn addr(&self) -> IpAddr {
        self.addr
    }

    /// Prefix length in bits.
    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    /// Whether this network covers its whole address family.
    pub fn is_everything(&self) -> bool {
        self.prefix == 0
    }
}

/// Mask with the top `prefix` bits set.
pub fn mask_v4(prefix: u8) -> u32 {
    u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0)
}

pub fn mask_v6(prefix: u8) -> u128 {
    u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0)
}

impl FromStr for IpNet {
    type Err = ParseIpNetError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = |reason| ParseIpNetError {
            input: s.to_owned(),
            reason,
        };
        let (addr, prefix) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let addr: IpAddr = addr.parse().map_err(|_| err("not an IP address"))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            None => max,
            Some(p) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => p
                .parse::<u8>()
                .map_err(|_| err("prefix length too large"))?,
            Some(_) => return Err(err("prefix length must be a number")),
        };
        if prefix > max {
            return Err(err("prefix length too large"));
        }
        let (addr, prefix) = match addr {
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) if prefix >= 96 => (IpAddr::V4(v4), prefix - 96),
                Some(_) => return Err(err("IPv4-mapped networks must be /96 or longer")),
                None => (addr, prefix),
            },
            IpAddr::V4(_) => (addr, prefix),
        };
        let host_bits = match addr {
            IpAddr::V4(a) => u32::from(a) & !mask_v4(prefix) != 0,
            IpAddr::V6(a) => u128::from(a) & !mask_v6(prefix) != 0,
        };
        if host_bits {
            return Err(err("address has bits set beyond the prefix length"));
        }
        Ok(Self { addr, prefix })
    }
}

impl fmt::Display for IpNet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

impl Serialize for IpNet {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for IpNet {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(de::Error::custom)
    }
}

impl From<Ipv4Addr> for IpNet {
    fn from(a: Ipv4Addr) -> Self {
        Self {
            addr: IpAddr::V4(a),
            prefix: 32,
        }
    }
}

impl From<Ipv6Addr> for IpNet {
    fn from(a: Ipv6Addr) -> Self {
        match a.to_ipv4_mapped() {
            Some(v4) => v4.into(),
            None => Self {
                addr: IpAddr::V6(a),
                prefix: 128,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    #[test]
    fn parses_hosts_and_networks() {
        assert_eq!(net("192.0.2.7").to_string(), "192.0.2.7/32");
        assert_eq!(net("192.0.2.0/24").to_string(), "192.0.2.0/24");
        assert_eq!(net("2001:db8:1:2::/64").to_string(), "2001:db8:1:2::/64");
        assert_eq!(net("2001:db8::1").prefix(), 128);
        assert!(net("0.0.0.0/0").is_everything());
        assert!(net("::/0").is_everything());
    }

    #[test]
    fn mapped_ipv4_becomes_ipv4() {
        assert_eq!(net("::ffff:192.0.2.7"), net("192.0.2.7"));
        assert_eq!(net("::ffff:192.0.2.0/120"), net("192.0.2.0/24"));
        assert!("::ffff:0.0.0.0/80".parse::<IpNet>().is_err());
    }

    #[test]
    fn rejects_malformed() {
        for s in [
            "",
            "example.com",
            "192.0.2.0/",
            "192.0.2.0/33",
            // A valid network but for the sign, which `u8` parsing would accept.
            "192.0.0.0/+8",
            "192.0.2.0/ 8",
            "2001:db8::/129",
            "192.0.2.5/24",
            "2001:db8::1/64",
            "192.0.2.0/24/1",
        ] {
            assert!(s.parse::<IpNet>().is_err(), "{s}");
        }
    }
}
