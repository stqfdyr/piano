use crate::Config;
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
    #[error("log.access {0:?} must be an absolute path")]
    RelativeAccessLog(std::path::PathBuf),
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
    if config.sites.is_empty() {
        errors.push(ValidationError::NoSites);
    }
    if config.access.allow.is_empty() {
        errors.push(ValidationError::NoAccess);
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
        // Following a redirect to a public site host would loop through the relay.
        for entry in site.aliases.iter().chain(&site.follow) {
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
