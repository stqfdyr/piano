//! Site lookup by request host.

use crate::follow::FollowRules;
use crate::headers::{UaRuleError, UaRules};
use crate::rewrite::Rewriter;
use crate::route::BlockList;
use http::HeaderValue;
use piano_config::ServerDomains;
use piano_upstream::Origin;

/// One public host and the origin behind it.
#[derive(Debug)]
pub struct Site {
    pub name: String,
    pub host: String,
    pub origin: Origin,
    /// Precomputed upstream `Host` header value.
    pub upstream_host: HeaderValue,
    pub policy: Policy,
}

/// Per-site request handling taken from the configuration.
#[derive(Debug)]
pub struct Policy {
    pub follow: FollowRules,
    pub block: BlockList,
    pub ua: UaRules,
    pub rewriter: Rewriter,
    pub server_domains: ServerDomains,
}

#[derive(Debug, thiserror::Error)]
pub enum SiteError {
    #[error("invalid upstream host header: {0}")]
    Host(#[from] http::header::InvalidHeaderValue),
    #[error("ua rule: {0}")]
    Ua(#[from] UaRuleError),
    #[error("rewrite patterns: {0}")]
    Rewrite(#[from] aho_corasick::BuildError),
}

impl Policy {
    pub fn from_config(site: &piano_config::Site) -> Result<Self, SiteError> {
        let upstream = site
            .upstream_url
            .as_ref()
            .map(|u| u.host.clone())
            .unwrap_or_default();
        let names = std::iter::once(upstream.clone())
            .chain(site.aliases.iter().cloned())
            .collect();
        let follow = FollowRules {
            upstream,
            aliases: site.aliases.clone(),
            follow: site.follow.clone(),
        };
        Ok(Self {
            follow,
            block: BlockList::new(&site.block),
            ua: UaRules::new(&site.ua)?,
            rewriter: Rewriter::new(names)?,
            server_domains: site.server_domains,
        })
    }
}

impl Site {
    pub fn new(
        name: String,
        host: String,
        origin: Origin,
        policy: Policy,
    ) -> Result<Self, SiteError> {
        let upstream_host = HeaderValue::from_str(&origin.authority())?;
        Ok(Self {
            name,
            host,
            origin,
            upstream_host,
            policy,
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
    use piano_upstream::{Addrs, PeerOptions};
    use std::sync::Arc;
    use std::time::Duration;

    fn site(host: &str) -> Site {
        let d = Duration::from_secs(1);
        let origin = Origin {
            host: "emby.example.net".into(),
            port: 443,
            addrs: Arc::new(Addrs::new(vec!["192.0.2.1:443".parse().unwrap()]).unwrap()),
            options: PeerOptions {
                connect_timeout: d,
                read_timeout: d,
                idle_timeout: d,
            },
        };
        let policy = Policy {
            follow: FollowRules::default(),
            block: BlockList::default(),
            ua: UaRules::default(),
            rewriter: Rewriter::new(Vec::new()).unwrap(),
            server_domains: ServerDomains::default(),
        };
        Site::new(host.into(), host.into(), origin, policy).unwrap()
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
