use crate::{Config, UpstreamLimit};
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};

/// One problem found while validating a configuration.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ValidationError {
    #[error("server.listen is empty")]
    NoListen,
    #[error("server.listen entry {0:?} must be an IP address and port, such as \"[::]:443\"")]
    BadListen(String),
    #[error(
        "server.listen entries {0:?} and {1:?} cannot both be bound: same port, and the \
         address of one covers the other (\"[::]\" takes IPv4 too)"
    )]
    OverlappingListen(String, String),
    #[error("version {0} is not supported; this piano reads version 1")]
    BadVersion(u32),
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
    #[error(
        "site name {0:?} is used by more than one site; give the sites distinct names \
         (a name left out is the first label of the host)"
    )]
    DuplicateName(String),
    #[error(
        "site name {0:?} must be 1 to 64 ASCII letters, digits, '_' or '-', starting with a \
         letter or digit"
    )]
    BadName(String),
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
    #[error("{name} {reason}")]
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
    #[error(
        "site {site:?}: upstream {host:?} is the public host of site {other:?}; requests \
         would come back to the relay"
    )]
    UpstreamIsSite {
        site: String,
        host: String,
        other: String,
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

/// ASCII letters, digits, `_` and `-`, starting with a letter or digit: site names go
/// into `key=value` log records, the traffic record and command arguments, where they
/// must not read as an option or be mistaken for a host.
fn is_site_name(s: &str) -> bool {
    s.len() <= 64
        && s.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

/// Whether two listening addresses cannot both be bound: the same port, and the same
/// address or a wildcard covering the other. Listeners are dual-stack, so the IPv6
/// wildcard covers IPv4 too.
fn overlaps(a: SocketAddr, b: SocketAddr) -> bool {
    let covers = |wild: IpAddr, other: IpAddr| match wild {
        IpAddr::V6(w) => w.is_unspecified(),
        IpAddr::V4(w) => w.is_unspecified() && other.is_ipv4(),
    };
    let (x, y) = (a.ip().to_canonical(), b.ip().to_canonical());
    a.port() == b.port() && (x == y || covers(x, y) || covers(y, x))
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

/// Equal as written, so that two invalid limits (NaN) written alike are not reported
/// as differing on top of being invalid.
fn same_limit(a: Option<UpstreamLimit>, b: Option<UpstreamLimit>) -> bool {
    let bits = |l: Option<UpstreamLimit>| l.map(|l| (l.burst.to_bits(), l.per_sec.to_bits()));
    bits(a) == bits(b)
}

pub(crate) fn validate(config: &mut Config) -> Result<(), Vec<ValidationError>> {
    let mut errors = Vec::new();
    if let Some(version) = config.version
        && version != 1
    {
        errors.push(ValidationError::BadVersion(version));
    }
    if config.server.listen.is_empty() {
        errors.push(ValidationError::NoListen);
    }
    let mut listen: Vec<(&String, SocketAddr)> = Vec::new();
    for entry in &config.server.listen {
        let Ok(addr) = entry.parse::<SocketAddr>() else {
            errors.push(ValidationError::BadListen(entry.clone()));
            continue;
        };
        if let Some((other, _)) = listen.iter().find(|(_, a)| overlaps(*a, addr)) {
            errors.push(ValidationError::OverlappingListen(
                (*other).clone(),
                entry.clone(),
            ));
        }
        listen.push((entry, addr));
    }
    // Clients reach the site hosts on 443, wherever the relay listens.
    let relay_ports: HashSet<u16> = listen.iter().map(|(_, a)| a.port()).chain([443]).collect();
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
    let (limits, upstream) = (&config.limits, &config.upstream);
    // Zero is an immediate timeout, not the absence of one.
    for (name, d) in [
        ("limits.handshake_timeout", limits.handshake_timeout),
        ("limits.keepalive_timeout", limits.keepalive_timeout),
        ("upstream.connect_timeout", upstream.connect_timeout),
        ("upstream.read_timeout", upstream.read_timeout),
        ("upstream.idle_timeout", upstream.idle_timeout),
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
            name: "limits.max_connections",
            reason: "must be at least 1",
        });
    }
    let mut named = Vec::with_capacity(config.sites.len());
    for site in &mut config.sites {
        named.push(!site.name.is_empty());
        if site.name.is_empty() {
            site.name = site.host.split('.').next().unwrap_or_default().to_owned();
        }
    }
    let site_hosts: Vec<(String, String)> = config
        .sites
        .iter()
        .map(|s| (s.name.clone(), s.host.clone()))
        .collect();
    let mut hosts = HashSet::new();
    let mut names = HashSet::new();
    for (site, named) in config.sites.iter_mut().zip(named) {
        // A name taken from an invalid host is reported as the host.
        if named && !is_site_name(&site.name) {
            errors.push(ValidationError::BadName(site.name.clone()));
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
            let ok = prefix.starts_with('/')
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
            let reason = if let Err(e) = rule.regex() {
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
            Ok(origin) => {
                for (other_name, other_host) in &site_hosts {
                    if origin.host == *other_host && relay_ports.contains(&origin.port) {
                        errors.push(ValidationError::UpstreamIsSite {
                            site: site.name.clone(),
                            host: origin.host.clone(),
                            other: other_name.clone(),
                        });
                    }
                }
                site.upstream_url = Some(origin);
            }
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
            Some((_, other, limit)) if !same_limit(*limit, site.upstream_limit) => {
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
            "{MINIMAL}upstream_limit = {{ burst = 200, per_sec = 0.1 }}\nh2 = false\nserver_domains = \"pass\"\n\
             block = [\"/a\\\"b\", \"/c\\\\d\", \"/é\"]\n\
             [[site.ua]]\nmatch = '^$|(?i)\\(.*Pot\"Player/'\nset = \"Emby'Mini/1\"\n\
             [site.mounts]\n\"/__v\" = \"v.example.net\"\n\"/__w\" = \"w.example.net\""
        );
        let shown = parse(&text).unwrap().effective_toml().unwrap();
        assert!(shown.contains("keepalive_timeout = \"10m\""), "{shown}");
        assert!(shown.contains("[[site]]"), "{shown}");
        let again = parse(&shown).unwrap().effective_toml().unwrap();
        assert_eq!(shown, again);
        // The command-line tool's own reading of [control] knows every section.
        assert!(crate::parse_control(&shown).is_ok());
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

        // Patterns match header bytes, which need not be UTF-8.
        parse(&format!(
            "{MINIMAL}[[site.ua]]\nmatch = '(?-u)\\xff'\nset = \"x\"\n"
        ))
        .unwrap();
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
        let at_least = format!(
            "{MINIMAL}[limits]\nhandshake_timeout = \"1s\"\nkeepalive_timeout = \"1s\"\nmax_connections = 1\n"
        );
        parse(&at_least).unwrap();
    }

    #[test]
    fn upstream_timeouts_are_at_least_a_second() {
        let text = format!(
            "{MINIMAL}[upstream]\nconnect_timeout = \"0s\"\nread_timeout = \"999ms\"\nidle_timeout = \"0ms\"\n"
        );
        let names: Vec<&str> = errors(&text)
            .iter()
            .map(|e| match e {
                ValidationError::BadLimit { name, .. } => *name,
                other => panic!("{other:?}"),
            })
            .collect();
        assert_eq!(
            names,
            [
                "upstream.connect_timeout",
                "upstream.read_timeout",
                "upstream.idle_timeout"
            ]
        );
        parse(&format!(
            "{MINIMAL}[upstream]\nconnect_timeout = \"1s\"\nread_timeout = \"1s\"\nidle_timeout = \"1s\"\n"
        ))
        .unwrap();
    }

    #[test]
    fn listen_entries_are_distinct_addresses() {
        let c = parse(&format!(
            "{MINIMAL}[server]\nlisten = [\"0.0.0.0:443\", \"[::]:8443\", \"192.0.2.1:8443\"]\n"
        ));
        assert!(c.is_err(), "[::] covers IPv4");
        let c = parse(&format!(
            "{MINIMAL}[server]\nlisten = [\"192.0.2.1:443\", \"192.0.2.2:443\", \"[2001:db8::1]:443\", \"0.0.0.0:8443\", \"[2001:db8::1]:8443\"]\n"
        ))
        .unwrap();
        assert_eq!(c.server.listen.len(), 5);
        for (a, b) in [
            ("0.0.0.0:443", "192.0.2.1:443"),
            ("[::]:443", "0.0.0.0:443"),
            ("[::ffff:192.0.2.1]:443", "192.0.2.1:443"),
        ] {
            let text = format!("{MINIMAL}[server]\nlisten = [\"{a}\", \"{b}\"]\n");
            assert_eq!(
                errors(&text),
                [ValidationError::OverlappingListen(a.into(), b.into())]
            );
        }
        let text = format!(
            "{MINIMAL}[server]\nlisten = [\"443\", \"localhost:443\", \"[::]:443\", \"[0::]:443\"]\n"
        );
        assert_eq!(
            errors(&text),
            [
                ValidationError::BadListen("443".into()),
                ValidationError::BadListen("localhost:443".into()),
                ValidationError::OverlappingListen("[::]:443".into(), "[0::]:443".into()),
            ]
        );
    }

    #[test]
    fn only_version_one_is_read() {
        parse(&format!("version = 1\n{MINIMAL}")).unwrap();
        assert_eq!(
            errors(&format!("version = 2\n{MINIMAL}")),
            [ValidationError::BadVersion(2)]
        );
    }

    #[test]
    fn site_names() {
        let named = |name: &str| format!("{MINIMAL}name = \"{name}\"\n");
        parse(&named("uhd-2_main")).unwrap();
        parse(&named(&"a".repeat(64))).unwrap();
        for bad in ["a b", "a=b", "é", "-x", "tv.example.com", &"a".repeat(65)] {
            assert_eq!(
                errors(&named(bad)),
                [ValidationError::BadName(bad.into())],
                "{bad}"
            );
        }
        // Names left out are the first label of the host, before any check uses them.
        let text = format!(
            "{MINIMAL}\n[[site]]\nhost = \"media.example.org\"\nupstream = \"https://up.example.net\"\n\
             [[site]]\nhost = \"tv.example.org\"\nupstream = \"https://up.example.net\"\nfollow = [\"*.example.com\"]\n"
        );
        let errs = errors(&text);
        assert_eq!(
            errs,
            [
                ValidationError::DuplicateName("media".into()),
                ValidationError::FollowCoversSite {
                    site: "tv".into(),
                    entry: "*.example.com".into(),
                    other: "media".into(),
                },
            ]
        );
        assert!(
            errs[0].to_string().contains("distinct names"),
            "{}",
            errs[0]
        );
    }

    #[test]
    fn upstream_must_not_be_a_site() {
        let tv = |port: u16, listen: &str| {
            format!(
                "{MINIMAL}\n[[site]]\nhost = \"tv.example.com\"\nupstream = \"https://media.example.com:{port}\"\n\
                 [server]\nlisten = [\"{listen}\"]\n"
            )
        };
        // Another server on the relay's host, on a port the relay does not serve.
        parse(&tv(8920, "[::]:443")).unwrap();
        assert_eq!(errors(&tv(443, "[::]:8443")).len(), 1);
        let text = tv(8920, "[::]:8920");
        assert_eq!(
            errors(&text),
            [ValidationError::UpstreamIsSite {
                site: "tv".into(),
                host: "media.example.com".into(),
                other: "media".into(),
            }]
        );
        let own = MINIMAL.replace("https://emby.example.net", "https://media.example.com");
        assert!(matches!(
            errors(&own)[..],
            [ValidationError::UpstreamIsSite { .. }]
        ));
    }

    #[test]
    fn dns_name_lengths() {
        let label = "a".repeat(63);
        let name = |n: usize| format!("{label}.{label}.{label}.{}", "b".repeat(n));
        assert_eq!(name(61).len(), 253);
        assert!(is_dns_name(&name(61)));
        assert!(!is_dns_name(&name(62)));
        assert!(!is_dns_name(""));
        assert!(!is_dns_name(&format!("{}.com", "a".repeat(64))));
    }

    #[test]
    fn block_entries() {
        let with = |path: &str| format!("{MINIMAL}block = [\"{path}\"]\n");
        parse(&with("/emby/api/danmu/")).unwrap();
        for bad in ["emby/api", "/a?b", "/a#b"] {
            assert_eq!(
                errors(&with(bad)),
                [ValidationError::BadBlock {
                    site: "media".into(),
                    path: bad.into()
                }],
                "{bad}"
            );
        }
    }

    #[test]
    fn invalid_configurations_list_every_error() {
        let text =
            format!("{MINIMAL}[limits]\nmax_connections = 0\n[upstream]\nread_timeout = \"0s\"\n");
        let shown = parse(&text).unwrap_err().to_string();
        assert_eq!(
            shown,
            "invalid configuration in :\n  - upstream.read_timeout must be at least 1s\n  - \
             limits.max_connections must be at least 1"
        );
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
        let nan = "upstream_limit = { burst = nan, per_sec = 1 }";
        let errs = errors(&format!(
            "{MINIMAL}{nan}\n{}",
            site("b.example.com", same, nan)
        ));
        assert!(
            errs.iter()
                .all(|e| matches!(e, ValidationError::BadUpstreamLimit { .. })),
            "{errs:?}"
        );
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
