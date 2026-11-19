//! Site lookup by request host.

use http::HeaderValue;
use piano_upstream::Origin;

/// One public host and the origin behind it.
#[derive(Debug)]
pub struct Site {
    pub name: String,
    pub host: String,
    pub origin: Origin,
    /// Precomputed upstream `Host` header value.
    pub upstream_host: HeaderValue,
}

impl Site {
    pub fn new(
        name: String,
        host: String,
        origin: Origin,
    ) -> Result<Self, http::header::InvalidHeaderValue> {
        let upstream_host = HeaderValue::from_str(&origin.authority())?;
        Ok(Self {
            name,
            host,
            origin,
            upstream_host,
        })
    }
}

/// All sites, looked up by the request's host.
#[derive(Debug, Default)]
pub struct Sites {
    sites: Vec<Site>,
}

impl Sites {
    pub fn new(sites: Vec<Site>) -> Self {
        Self { sites }
    }

    pub fn get(&self, index: usize) -> Option<&Site> {
        self.sites.get(index)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Site> {
        self.sites.iter()
    }

    /// Finds the site for a `Host` header or `:authority` value. Matching ignores ASCII
    /// case, a trailing dot and any port.
    pub fn find(&self, authority: &[u8]) -> Option<usize> {
        let host = strip_port(authority);
        let host = host.strip_suffix(b".").unwrap_or(host);
        self.sites
            .iter()
            .position(|s| s.host.as_bytes().eq_ignore_ascii_case(host))
    }
}

fn strip_port(authority: &[u8]) -> &[u8] {
    match authority.iter().rposition(|&b| b == b':') {
        Some(i) if authority[i + 1..].iter().all(u8::is_ascii_digit) => &authority[..i],
        _ => authority,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use piano_upstream::PeerOptions;
    use std::time::Duration;

    fn site(host: &str) -> Site {
        let d = Duration::from_secs(1);
        let origin = Origin {
            host: "emby.example.net".into(),
            port: 443,
            addr: "192.0.2.1:443".parse().unwrap(),
            options: PeerOptions {
                connect_timeout: d,
                read_timeout: d,
                idle_timeout: d,
            },
        };
        Site::new(host.into(), host.into(), origin).unwrap()
    }

    #[test]
    fn finds_by_host_ignoring_case_port_and_trailing_dot() {
        let sites = Sites::new(vec![site("a.example.com"), site("b.example.com")]);
        assert_eq!(sites.find(b"b.example.com"), Some(1));
        assert_eq!(sites.find(b"B.Example.COM:443"), Some(1));
        assert_eq!(sites.find(b"a.example.com."), Some(0));
        assert_eq!(sites.find(b"c.example.com"), None);
        assert_eq!(sites.find(b""), None);
        assert_eq!(sites.find(b"a.example.com:x"), None);
    }
}
