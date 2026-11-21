use crate::{Config, UpstreamLimit};
use std::collections::HashSet;

/// One problem found while validating a configuration.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ValidationError {
    #[error("server.listen is empty")]
    NoListen,
    #[error("no [[site]] configured")]
    NoSites,
    #[error(
        "access.allow is empty; list the client addresses, or write \
         allow = [\"0.0.0.0/0\", \"::/0\"] to serve everyone"
    )]
    NoAccess,
    #[error("site {site:?}: host {host:?} is not a valid lowercase DNS name")]
    BadHost { site: String, host: String },
    #[error("host {0:?} is used by more than one site")]
    DuplicateHost(String),
    #[error("site name {0:?} is used by more than one site")]
    DuplicateName(String),
    #[error("site {site:?}: alias {host:?} is not a valid lowercase DNS name")]
    BadAlias { site: String, host: String },
    #[error(
        "site {site:?}: follow entry {entry:?} must be a lowercase DNS name or *.<domain> \
         with at least two labels after *."
    )]
    BadFollow { site: String, entry: String },
    #[error("site {site:?}: {entry:?} covers the public host of site {other:?}")]
    FollowCoversSite {
        site: String,
        entry: String,
        other: String,
    },
    #[error("site {site:?}: block entry {path:?} must start with / and have no query")]
    BadBlock { site: String, path: String },
    #[error("site {site:?}: ua rule {index}: {reason}")]
    BadUaRule {
        site: String,
        index: usize,
        reason: String,
    },
    #[error("site {site:?}: mount {prefix:?} must start with /, not end with / and have no query")]
    BadMountPrefix { site: String, prefix: String },
    #[error("site {site:?}: mount {prefix:?}: host {host:?} is not a valid lowercase DNS name")]
    BadMountHost {
        site: String,
        prefix: String,
        host: String,
    },
    #[error("limits.{name} {reason}")]
    BadLimit {
        name: &'static str,
        reason: &'static str,
    },
    #[error("log.access {0:?} must be an absolute path")]
    RelativeAccessLog(std::path::PathBuf),
    #[error("control.socket {0:?} must be an absolute path")]
    RelativeSocket(std::path::PathBuf),
    #[error("traffic.file {0:?} must be an absolute path")]
    RelativeTrafficFile(std::path::PathBuf),
    #[error("site {site:?}: upstream_limit {reason}")]
    BadUpstreamLimit { site: String, reason: &'static str },
    #[error(
        "site {site:?}: upstream_limit differs from site {other:?}, which has the same \
         upstream {upstream}; the limit is the upstream's and both sites share it"
    )]
    UpstreamLimitDiffers {
        site: String,
        other: String,
        upstream: String,
    },
    #[error("site {site:?}: upstream {url:?}: {reason}")]
    BadUpstream {
        site: String,
        url: String,
        reason: &'static str,
    },
}

/// Something valid but probably unintended.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Warning {
    #[error("access.allow contains {0}: every address of that family may connect")]
    OpenAccess(crate::IpNet),
}

/// Warnings for a configuration that passed validation.
pub fn warnings(config: &Config) -> Vec<Warning> {
    config
        .access
        .allow
        .iter()
        .filter(|n| n.is_everything())
        .map(|n| Warning::OpenAccess(*n))
        .collect()
}

/// A parsed upstream URL: always https, always a DNS name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamUrl {
    pub host: String,
    pub port: u16,
}

impl UpstreamUrl {
    /// The value for the upstream `Host` header.
    pub fn authority(&self) -> String {
        if self.port == 443 {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    /// Parses `https://host[:port][/]`.
    pub fn parse(url: &str) -> Result<Self, &'static str> {
        let rest = url
            .strip_prefix("https://")
            .ok_or("must start with https://")?;
        let rest = rest.strip_suffix('/').unwrap_or(rest);
        if rest.contains(['/', '?', '#', '@']) {
            return Err("must not contain a path, query or credentials");
        }
        let (host, port) = match rest.rsplit_once(':') {
            Some((h, p)) => {
                let port: u16 = p.parse().map_err(|_| "invalid port")?;
                if port == 0 {
                    return Err("invalid port");
                }
                (h, port)
            }
            None => (rest, 443),
        };
        let host = host.to_ascii_lowercase();
        if !is_dns_name(&host) {
            return Err("host must be a DNS name (IP literals cannot carry SNI)");
        }
        Ok(Self { host, port })
    }
}

/// Lowercase LDH labels, at least two of them, last one not all digits.
pub fn is_dns_name(s: &str) -> bool {
    if s.is_empty() || s.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = s.split('.').collect();
    let label_ok = |l: &&str| {
        !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    };
    labels.len() >= 2
        && labels.iter().all(label_ok)
        && labels
            .last()
            .is_some_and(|tld| !tld.bytes().all(|b| b.is_ascii_digit()))
}

/// Whether follow entry `pattern` (a name or `*.<domain>`) matches lowercase `host`.
/// The wildcard stands for exactly one label.
pub fn host_matches(pattern: &str, host: &str) -> bool {
    match pattern.strip_prefix("*.") {
        Some(domain) => host
            .strip_suffix(domain)
            .and_then(|h| h.strip_suffix('.'))
            .is_some_and(|label| !label.is_empty() && !label.contains('.')),
        None => pattern == host,
    }
}

pub(crate) fn validate(config: &mut Config) -> Result<(), Vec<ValidationError>> {
    let mut errors = Vec::new();
    if config.server.listen.is_empty() {
        errors.push(ValidationError::NoListen);
    }
    if config.log.access_path().is_some_and(|p| !p.is_absolute()) {
        errors.push(ValidationError::RelativeAccessLog(
            config.log.access.clone(),
        ));
    }
    if config
        .control
        .socket_path()
        .is_some_and(|p| !p.is_absolute())
    {
        errors.push(ValidationError::RelativeSocket(
            config.control.socket.clone(),
        ));
    }
    if config.traffic.file_path().is_some_and(|p| !p.is_absolute()) {
        errors.push(ValidationError::RelativeTrafficFile(
            config.traffic.file.clone(),
        ));
    }
    if config.sites.is_empty() {
        errors.push(ValidationError::NoSites);
    }
    if config.access.allow.is_empty() {
        errors.push(ValidationError::NoAccess);
    }
    let limits = &config.limits;
    for (name, d) in [
        ("handshake_timeout", limits.handshake_timeout),
        ("keepalive_timeout", limits.keepalive_timeout),
    ] {
        if d.get() < std::time::Duration::from_secs(1) {
            errors.push(ValidationError::BadLimit {
                name,
                reason: "must be at least 1s",
            });
        }
    }
    if limits.max_connections == 0 {
        errors.push(ValidationError::BadLimit {
            name: "max_connections",
            reason: "must be at least 1",
        });
    }
    let site_hosts: Vec<(String, String)> = config
        .sites
        .iter()
        .map(|s| (s.name.clone(), s.host.clone()))
        .collect();
    let mut hosts = HashSet::new();
    let mut names = HashSet::new();
    for site in &mut config.sites {
        if site.name.is_empty() {
            site.name = site.host.split('.').next().unwrap_or_default().to_owned();
        }
        if !is_dns_name(&site.host) {
            errors.push(ValidationError::BadHost {
                site: site.name.clone(),
                host: site.host.clone(),
            });
        }
        if !hosts.insert(site.host.clone()) {
            errors.push(ValidationError::DuplicateHost(site.host.clone()));
        }
        if !names.insert(site.name.clone()) {
            errors.push(ValidationError::DuplicateName(site.name.clone()));
        }
        for alias in &site.aliases {
            if !is_dns_name(alias) {
                errors.push(ValidationError::BadAlias {
                    site: site.name.clone(),
                    host: alias.clone(),
                });
            }
        }
        for entry in &site.follow {
            let ok = match entry.strip_prefix("*.") {
                Some(domain) => is_dns_name(domain),
                None => is_dns_name(entry),
            };
            if !ok {
                errors.push(ValidationError::BadFollow {
                    site: site.name.clone(),
                    entry: entry.clone(),
                });
            }
        }
        for (prefix, host) in &site.mounts {
            let ok = prefix.len() > 1
                && prefix.starts_with('/')
                && !prefix.ends_with('/')
                && !prefix.contains(['?', '#'])
                && !prefix.contains("//");
            if !ok {
                errors.push(ValidationError::BadMountPrefix {
                    site: site.name.clone(),
                    prefix: prefix.clone(),
                });
            }
            if !is_dns_name(host) {
                errors.push(ValidationError::BadMountHost {
                    site: site.name.clone(),
                    prefix: prefix.clone(),
                    host: host.clone(),
                });
            }
        }
        // Following a redirect to a public site host would loop through the relay.
        for entry in site
            .aliases
            .iter()
            .chain(&site.follow)
            .chain(site.mounts.values())
        {
            for (other_name, other_host) in &site_hosts {
                if host_matches(entry, other_host) {
                    errors.push(ValidationError::FollowCoversSite {
                        site: site.name.clone(),
                        entry: entry.clone(),
                        other: other_name.clone(),
                    });
                }
            }
        }
        if let Some(l) = site.upstream_limit {
            let reason = if !(l.burst >= 1.0 && l.burst.is_finite()) {
                Some("burst must be at least 1")
            } else if !(l.per_sec > 0.0 && l.per_sec.is_finite()) {
                Some("per_sec must be above 0")
            } else {
                None
            };
            if let Some(reason) = reason {
                errors.push(ValidationError::BadUpstreamLimit {
                    site: site.name.clone(),
                    reason,
                });
            }
        }
        for path in &site.block {
            if !path.starts_with('/') || path.contains(['?', '#']) {
                errors.push(ValidationError::BadBlock {
                    site: site.name.clone(),
                    path: path.clone(),
                });
            }
        }
        for (index, rule) in site.ua.iter().enumerate() {
            let reason = if let Err(e) = regex::Regex::new(&rule.pattern) {
                Some(e.to_string())
            } else if rule.set.is_empty() || !rule.set.bytes().all(|b| (0x20..0x7f).contains(&b)) {
                Some("set must be non-empty printable ASCII".to_owned())
            } else {
                None
            };
            if let Some(reason) = reason {
                errors.push(ValidationError::BadUaRule {
                    site: site.name.clone(),
                    index,
                    reason,
                });
            }
        }
        match UpstreamUrl::parse(&site.upstream) {
            Ok(origin) => site.upstream_url = Some(origin),
            Err(reason) => errors.push(ValidationError::BadUpstream {
                site: site.name.clone(),
                url: site.upstream.clone(),
                reason,
            }),
        }
    }
    // Sites with one upstream share its request budget, so they must agree on its limit.
    let mut limits: Vec<(&UpstreamUrl, &str, Option<UpstreamLimit>)> = Vec::new();
    for site in &config.sites {
        let Some(url) = &site.upstream_url else {
            continue;
        };
        match limits.iter().find(|(u, ..)| *u == url) {
            Some((_, other, limit)) if *limit != site.upstream_limit => {
                errors.push(ValidationError::UpstreamLimitDiffers {
                    site: site.name.clone(),
                    other: (*other).to_owned(),
                    upstream: url.authority(),
                });
            }
            Some(_) => {}
            None => limits.push((url, &site.name, site.upstream_limit)),
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Error, parse};

    const MINIMAL: &str = r#"
        [tls]
        cert = "/etc/piano/fullchain.pem"
        key  = "/etc/piano/privkey.pem"

        [access]
        allow = ["192.0.2.7", "2001:db8:1:2::/64"]

        [[site]]
        host     = "media.example.com"
        upstream = "https://emby.example.net"
    "#;

    fn errors(text: &str) -> Vec<ValidationError> {
        match parse(text) {
            Err(Error::Invalid { errors, .. }) => errors,
            other => panic!("expected validation errors, got {other:?}"),
        }
    }

    #[test]
    fn log_defaults_and_paths() {
        let c = parse(MINIMAL).unwrap();
        assert_eq!(
            c.log.access_path(),
            Some(std::path::Path::new("/var/log/piano/access.log"))
        );
        assert_eq!(c.log.level, crate::LogLevel::Info);
        let off = parse(&format!(
            "{MINIMAL}\n[log]\naccess = \"\"\nlevel = \"debug\""
        ))
        .unwrap();
        assert_eq!(off.log.access_path(), None);
        assert_eq!(off.log.level, crate::LogLevel::Debug);
        assert_eq!(
            errors(&format!("{MINIMAL}\n[log]\naccess = \"piano.log\"")),
            [ValidationError::RelativeAccessLog("piano.log".into())]
        );
    }

    #[test]
    fn effective_configuration_round_trips() {
        let text = format!(
            "{MINIMAL}\n[[site.ua]]\nmatch = \"^$\"\nset = \"EmbyMini/1\"\n[site.mounts]\n\"/__v\" = \"v.example.net\""
        );
        let shown = parse(&text).unwrap().effective_toml().unwrap();
        assert!(shown.contains("keepalive_timeout = \"10m\""), "{shown}");
        assert!(shown.contains("[[site]]"), "{shown}");
        let again = parse(&shown).unwrap().effective_toml().unwrap();
        assert_eq!(shown, again);
    }

    #[test]
    fn control_socket_default_and_paths() {
        let c = parse(MINIMAL).unwrap();
        assert_eq!(
            c.control.socket_path(),
            Some(std::path::Path::new(crate::DEFAULT_SOCKET))
        );
        let off = parse(&format!("{MINIMAL}\n[control]\nsocket = \"\"")).unwrap();
        assert_eq!(off.control.socket_path(), None);
        assert_eq!(
            errors(&format!("{MINIMAL}\n[control]\nsocket = \"ctl.sock\"")),
            [ValidationError::RelativeSocket("ctl.sock".into())]
        );
    }

    #[test]
    fn traffic_file_default_off_and_absolute() {
        let c = parse(MINIMAL).unwrap();
        assert_eq!(
            c.traffic.file_path(),
            Some(std::path::Path::new(crate::DEFAULT_TRAFFIC_FILE))
        );
        let off = parse(&format!("{MINIMAL}\n[traffic]\nfile = \"\"")).unwrap();
        assert_eq!(off.traffic.file_path(), None);
        assert_eq!(
            errors(&format!("{MINIMAL}\n[traffic]\nfile = \"traffic.json\"")),
            [ValidationError::RelativeTrafficFile("traffic.json".into())]
        );
    }

    #[test]
    fn minimal_config_gets_defaults() {
        let c = parse(MINIMAL).unwrap();
        assert_eq!(c.server.listen, ["[::]:443"]);
        assert_eq!(c.upstream.connect_timeout.get().as_secs(), 3);
        let site = &c.sites[0];
        assert_eq!(site.name, "media");
        assert_eq!(
            site.upstream_url,
            Some(UpstreamUrl {
                host: "emby.example.net".into(),
                port: 443
            })
        );
    }

    #[test]
    fn unknown_keys_are_rejected() {
        let text = format!("{MINIMAL}\nupstrem = 1\n");
        assert!(matches!(parse(&text), Err(Error::Parse { .. })));
    }

    #[test]
    fn upstream_forms() {
        let ok = |u: &str| UpstreamUrl::parse(u).unwrap();
        assert_eq!(
            ok("https://Emby.Example.net/").authority(),
            "emby.example.net"
        );
        assert_eq!(
            ok("https://emby.example.net:8920").authority(),
            "emby.example.net:8920"
        );
        for bad in [
            "http://emby.example.net",
            "https://emby.example.net/emby",
            "https://user@emby.example.net",
            "https://192.0.2.1",
            "https://[2001:db8::1]",
            "https://localhost",
            "https://emby.example.net:0",
            "https://emby.example.net:99999",
        ] {
            assert!(UpstreamUrl::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn duplicate_hosts_and_bad_hosts_are_reported_together() {
        let text = format!(
            "{MINIMAL}\n[[site]]\nname = \"b\"\nhost = \"media.example.com\"\nupstream = \"https://emby.example.net\"\n\
             [[site]]\nhost = \"Bad_Host\"\nupstream = \"ftp://x\"\n"
        );
        let errs = errors(&text);
        assert!(errs.contains(&ValidationError::DuplicateHost("media.example.com".into())));
        assert!(
            errs.iter()
                .any(|e| matches!(e, ValidationError::BadHost { .. }))
        );
        assert!(
            errs.iter()
                .any(|e| matches!(e, ValidationError::BadUpstream { .. }))
        );
    }

    #[test]
    fn empty_sites_and_access_are_errors() {
        let text = "[tls]\ncert = \"a\"\nkey = \"b\"\n";
        assert_eq!(
            errors(text),
            [ValidationError::NoSites, ValidationError::NoAccess]
        );
    }

    #[test]
    fn open_access_is_a_warning() {
        let c = parse(MINIMAL).unwrap();
        assert!(c.warnings().is_empty());
        let text = MINIMAL.replace(
            r#"allow = ["192.0.2.7", "2001:db8:1:2::/64"]"#,
            r#"allow = ["0.0.0.0/0", "::/0"]"#,
        );
        let c = parse(&text).unwrap();
        assert_eq!(c.warnings().len(), 2);
    }

    #[test]
    fn site_header_rules() {
        let text =
            format!("{MINIMAL}[[site.ua]]\nmatch = '^$|(?i)mozilla/'\nset = \"EmbyMini/0.1.0\"\n");
        let c = parse(&text).unwrap();
        assert_eq!(c.sites[0].ua[0].set, "EmbyMini/0.1.0");

        let text = format!(
            "{MINIMAL}[[site.ua]]\nmatch = '('\nset = \"x\"\n\
             [[site.ua]]\nmatch = 'x'\nset = \"\"\n"
        );
        let errs = errors(&text);
        assert_eq!(errs.len(), 2, "{errs:?}");
    }

    #[test]
    fn limits() {
        let c = parse(MINIMAL).unwrap();
        assert_eq!(c.limits.handshake_timeout.get().as_secs(), 10);
        assert_eq!(c.limits.keepalive_timeout.get().as_secs(), 600);
        assert_eq!(c.limits.max_connections, 1024);
        let text = format!(
            "{MINIMAL}
[limits]
handshake_timeout = \"500ms\"
keepalive_timeout = \"0s\"
max_connections = 0
"
        );
        let errs = errors(&text);
        assert_eq!(errs.len(), 3, "{errs:?}");
    }

    #[test]
    fn cache_and_upstream_limit() {
        let c = parse(MINIMAL).unwrap();
        assert_eq!(c.cache.image_memory_mib, 128);
        assert_eq!(c.sites[0].upstream_limit, None);
        let ok = format!(
            "{MINIMAL}upstream_limit = {{ burst = 200, per_sec = 2.5 }}\n[cache]\nimage_memory_mib = 0\n"
        );
        let c = parse(&ok).unwrap();
        assert_eq!(c.cache.image_memory_mib, 0);
        let l = c.sites[0].upstream_limit.unwrap();
        assert_eq!((l.burst, l.per_sec), (200.0, 2.5));
        let shown = c.effective_toml().unwrap();
        assert!(shown.contains("per_sec = 2.5"), "{shown}");
        for bad in [
            "{ burst = 0, per_sec = 1 }",
            "{ burst = 5, per_sec = 0 }",
            "{ burst = nan, per_sec = 1 }",
        ] {
            let errs = errors(&format!("{MINIMAL}upstream_limit = {bad}\n"));
            assert!(
                matches!(errs[..], [ValidationError::BadUpstreamLimit { .. }]),
                "{bad}: {errs:?}"
            );
        }
    }

    #[test]
    fn sites_with_one_upstream_share_its_limit() {
        let site = |host: &str, upstream: &str, limit: &str| {
            format!("\n[[site]]\nhost = {host:?}\nupstream = {upstream:?}\n{limit}\n")
        };
        let limit = "upstream_limit = { burst = 150, per_sec = 2.5 }";
        let same = "https://emby.example.net";
        let ok = format!(
            "{MINIMAL}{limit}\n{}{}",
            site("b.example.com", same, limit),
            site("c.example.com", "https://emby.example.net:8443", "")
        );
        parse(&ok).unwrap();
        for other in ["", "upstream_limit = { burst = 150, per_sec = 3 }"] {
            let errs = errors(&format!(
                "{MINIMAL}{limit}\n{}",
                site("b.example.com", "https://EMBY.example.net/", other)
            ));
            assert!(
                matches!(&errs[..], [ValidationError::UpstreamLimitDiffers { site, other, upstream }]
                    if site == "b" && other == "media" && upstream == "emby.example.net"),
                "{errs:?}"
            );
        }
    }

    #[test]
    fn mounts() {
        let ok = format!(
            "{MINIMAL}mounts = {{ \"/__v/1\" = \"vod1.example.net\", \"/__v/2\" = \"vod2.example.net\" }}
"
        );
        let c = parse(&ok).unwrap();
        assert_eq!(c.sites[0].mounts["/__v/1"], "vod1.example.net");
        for (prefix, host) in [
            ("/", "vod.example.net"),
            ("v", "vod.example.net"),
            ("/v/", "vod.example.net"),
            ("/v?x", "vod.example.net"),
            ("/v", "VOD.example.net"),
            ("/v", "media.example.com"),
        ] {
            let text = format!(
                "{MINIMAL}mounts = {{ {prefix:?} = {host:?} }}
"
            );
            assert_eq!(errors(&text).len(), 1, "{prefix} {host}");
        }
    }

    #[test]
    fn follow_patterns() {
        assert!(host_matches("*.example.net", "a1.example.net"));
        assert!(!host_matches("*.example.net", "example.net"));
        assert!(!host_matches("*.example.net", "a.b.example.net"));
        assert!(!host_matches("*.example.net", "aexample.net"));
        assert!(host_matches("vod.example.net", "vod.example.net"));
        assert!(!host_matches("vod.example.net", "x.vod.example.net"));

        let ok = format!(
            "{MINIMAL}aliases = [\"emby2.example.net\"]\nfollow = [\"vod.example.net\", \"*.files.example.net\"]\n"
        );
        assert_eq!(parse(&ok).unwrap().sites[0].follow.len(), 2);
        for (entry, n) in [
            ("follow = [\"*.net\"]", 1),
            ("follow = [\"*\"]", 1),
            ("follow = [\"Vod.example.net\"]", 1),
            ("follow = [\"*.example.com\"]", 1),
            ("aliases = [\"media.example.com\"]", 1),
        ] {
            let errs = errors(&format!("{MINIMAL}{entry}\n"));
            assert_eq!(errs.len(), n, "{entry}: {errs:?}");
        }
    }

    #[test]
    fn server_domains_modes() {
        use crate::ServerDomains;
        assert_eq!(
            parse(MINIMAL).unwrap().sites[0].server_domains,
            ServerDomains::Rewrite
        );
        for (value, mode) in [
            ("rewrite", ServerDomains::Rewrite),
            ("block", ServerDomains::Block),
            ("pass", ServerDomains::Pass),
        ] {
            let text = format!("{MINIMAL}server_domains = \"{value}\"\n");
            assert_eq!(parse(&text).unwrap().sites[0].server_domains, mode);
        }
        let text = format!("{MINIMAL}server_domains = \"drop\"\n");
        assert!(matches!(parse(&text), Err(Error::Parse { .. })));
    }

    #[test]
    fn bad_networks_fail_parsing() {
        let text = MINIMAL.replace(r#""192.0.2.7""#, r#""192.0.2.7/24""#);
        assert!(matches!(parse(&text), Err(Error::Parse { .. })));
    }
}
