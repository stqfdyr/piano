//! Site lookup by request host.

use crate::follow::FollowRules;
use crate::headers::{UaRuleError, UaRules};
use crate::rewrite::Rewriter;
use crate::route::BlockList;
use http::HeaderValue;
use piano_cache::Rate;
use piano_config::ServerDomains;
use piano_telemetry::SiteCounters;
use piano_upstream::Origin;
use std::sync::Arc;

/// One public host and the origin behind it.
#[derive(Debug)]
pub struct Site {
    pub name: String,
    pub host: String,
    pub origin: Origin,
    /// Precomputed upstream `Host` header value.
    pub upstream_host: HeaderValue,
    pub policy: Policy,
    /// Kept by name across reloads.
    pub counters: Arc<SiteCounters>,
}

/// Per-site request handling taken from the configuration.
#[derive(Debug)]
pub struct Policy {
    pub follow: FollowRules,
    pub block: BlockList,
    pub ua: UaRules,
    pub rewriter: Rewriter,
    pub server_domains: ServerDomains,
    pub mounts: Mounts,
    /// The upstream's request limit, which image requests keep a share of free.
    pub upstream_limit: Option<Rate>,
}

/// Path prefixes relayed to other hosts of the upstream service.
#[derive(Debug, Default)]
pub struct Mounts {
    /// Prefix and lowercase host, longest prefix first.
    list: Vec<(String, String)>,
}

impl Mounts {
    pub fn new(mounts: &std::collections::BTreeMap<String, String>) -> Self {
        let mut list: Vec<(String, String)> =
            mounts.iter().map(|(p, h)| (p.clone(), h.clone())).collect();
        list.sort_by_key(|(p, _)| std::cmp::Reverse(p.len()));
        Self { list }
    }

    /// The host for `path` and the length of its mount prefix, when `path` continues
    /// after the prefix with `/`. Matching ignores ASCII case.
    pub fn find(&self, path: &[u8]) -> Option<(&str, usize)> {
        self.list.iter().find_map(|(prefix, host)| {
            let p = prefix.as_bytes();
            let hit = path.len() > p.len()
                && path[..p.len()].eq_ignore_ascii_case(p)
                && path[p.len()] == b'/';
            hit.then_some((host.as_str(), p.len()))
        })
    }
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
        // Mounted hosts belong to the upstream service: redirects to them keep the
        // client's credentials, like redirects to an alias.
        let follow = FollowRules {
            upstream,
            aliases: site
                .aliases
                .iter()
                .chain(site.mounts.values())
                .cloned()
                .collect(),
            follow: site.follow.clone(),
        };
        let mounted = site
            .mounts
            .iter()
            .map(|(p, h)| (h.clone(), p.clone()))
            .collect();
        Ok(Self {
            follow,
            block: BlockList::new(&site.block),
            ua: UaRules::new(&site.ua)?,
            rewriter: Rewriter::new(names, mounted)?,
            server_domains: site.server_domains,
            mounts: Mounts::new(&site.mounts),
            upstream_limit: site.upstream_limit.map(|l| Rate {
                burst: l.burst,
                per_sec: l.per_sec,
            }),
        })
    }
}

impl Site {
    pub fn new(
        name: String,
        host: String,
        origin: Origin,
        policy: Policy,
        counters: Arc<SiteCounters>,
    ) -> Result<Self, SiteError> {
        let upstream_host = HeaderValue::from_str(&origin.authority())?;
        Ok(Self {
            name,
            host,
            origin,
            upstream_host,
            policy,
            counters,
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
            rewriter: Rewriter::new(Vec::new(), Vec::new()).unwrap(),
            server_domains: ServerDomains::default(),
            mounts: Mounts::default(),
            upstream_limit: None,
        };
        Site::new(host.into(), host.into(), origin, policy, Arc::default()).unwrap()
    }

    #[test]
    fn mounts_match_whole_segments_longest_first() {
        let m = Mounts::new(
            &[
                ("/__v".to_owned(), "a.example.net".to_owned()),
                ("/__v/2".to_owned(), "b.example.net".to_owned()),
            ]
            .into(),
        );
        assert_eq!(m.find(b"/__v/x"), Some(("a.example.net", 4)));
        assert_eq!(m.find(b"/__V/2/play"), Some(("b.example.net", 6)));
        assert_eq!(m.find(b"/__v/2"), Some(("a.example.net", 4)));
        assert_eq!(m.find(b"/__v"), None);
        assert_eq!(m.find(b"/__vx/1"), None);
        assert_eq!(m.find(b"/__v?x=/"), None);
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
