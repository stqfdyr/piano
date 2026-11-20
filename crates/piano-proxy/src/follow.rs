//! Following upstream redirects inside the relay.
//!
//! A redirect is never passed to the client: either its target is one the site allows
//! and the relay requests it itself, or the client gets 502. Path and query bytes are
//! kept exactly as the upstream sent them.

use piano_config::{host_matches, is_dns_name};

/// Most redirects followed for one request.
pub const MAX_HOPS: u8 = 5;

/// Statuses that are followed.
pub fn is_redirect(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

/// Where a request goes: lowercase host, port, and the request target (path and query)
/// as raw bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub host: String,
    pub port: u16,
    pub path: Vec<u8>,
}

impl Target {
    /// The value for the `Host` header.
    pub fn authority(&self) -> String {
        if self.port == 443 {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LocationError {
    #[error("empty Location")]
    Empty,
    #[error("Location carries credentials")]
    Credentials,
    #[error("Location host is not a DNS name")]
    Host,
    #[error("Location port is invalid")]
    Port,
    #[error("Location scheme is not http or https")]
    Scheme,
}

fn strip_prefix_ci<'a>(s: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    s.get(..prefix.len())
        .filter(|p| p.eq_ignore_ascii_case(prefix))
        .map(|_| &s[prefix.len()..])
}

/// Resolves a `Location` value against the target that returned it. `http://` is
/// followed over TLS like `https://`; upstreams are only reached over TLS.
pub fn resolve(location: &[u8], base: &Target) -> Result<Target, LocationError> {
    let location = location.trim_ascii();
    let location = match location.iter().position(|&b| b == b'#') {
        Some(i) => &location[..i],
        None => location,
    };
    if location.is_empty() {
        return Err(LocationError::Empty);
    }
    let after_scheme = strip_prefix_ci(location, b"https://")
        .or_else(|| strip_prefix_ci(location, b"http://"))
        .or_else(|| location.strip_prefix(b"//"));
    if let Some(rest) = after_scheme {
        let end = rest
            .iter()
            .position(|&b| b == b'/' || b == b'?')
            .unwrap_or(rest.len());
        let (authority, path) = rest.split_at(end);
        if authority.contains(&b'@') {
            return Err(LocationError::Credentials);
        }
        let (host, port) = match authority.iter().rposition(|&b| b == b':') {
            Some(i) => {
                let port = std::str::from_utf8(&authority[i + 1..])
                    .ok()
                    .and_then(|p| p.parse::<u16>().ok())
                    .filter(|&p| p != 0)
                    .ok_or(LocationError::Port)?;
                (&authority[..i], port)
            }
            None => (authority, 443),
        };
        let host = std::str::from_utf8(host)
            .map_err(|_| LocationError::Host)?
            .to_ascii_lowercase();
        let host = host.strip_suffix('.').unwrap_or(&host).to_owned();
        if !is_dns_name(&host) {
            return Err(LocationError::Host);
        }
        let mut target = Vec::with_capacity(path.len() + 1);
        if !path.starts_with(b"/") {
            target.push(b'/');
        }
        target.extend_from_slice(path);
        return Ok(Target {
            host,
            port,
            path: target,
        });
    }
    let first_delim = location.iter().position(|&b| matches!(b, b'/' | b'?'));
    if location[..first_delim.unwrap_or(location.len())].contains(&b':') {
        return Err(LocationError::Scheme);
    }
    let base_path = match base.path.iter().position(|&b| b == b'?') {
        Some(i) => &base.path[..i],
        None => &base.path[..],
    };
    let path = if location.starts_with(b"/") {
        location.to_vec()
    } else if location.starts_with(b"?") {
        [base_path, location].concat()
    } else {
        let dir_end = base_path
            .iter()
            .rposition(|&b| b == b'/')
            .map_or(0, |i| i + 1);
        let mut p = Vec::with_capacity(dir_end + location.len() + 1);
        if dir_end == 0 {
            p.push(b'/');
        }
        p.extend_from_slice(&base_path[..dir_end]);
        p.extend_from_slice(location);
        p
    };
    Ok(Target {
        host: base.host.clone(),
        port: base.port,
        path,
    })
}

/// How the relay treats a redirect target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetKind {
    /// The upstream server under its own name or an alias: gets the client's cookies
    /// and credentials.
    Upstream,
    /// A host from the follow list: gets neither.
    Follow,
}

/// Which hosts a site follows redirects to.
#[derive(Debug, Default, Clone)]
pub struct FollowRules {
    pub upstream: String,
    pub aliases: Vec<String>,
    /// When not empty, the only other hosts followed.
    pub follow: Vec<String>,
}

impl FollowRules {
    /// The kind of `host` (lowercase), or `None` if redirects to it are refused.
    pub fn kind(&self, host: &str) -> Option<TargetKind> {
        if host == self.upstream || self.aliases.iter().any(|a| a == host) {
            Some(TargetKind::Upstream)
        } else if self.follow.is_empty() || self.follow.iter().any(|p| host_matches(p, host)) {
            Some(TargetKind::Follow)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Target {
        Target {
            host: "emby.example.net".into(),
            port: 443,
            path: b"/emby/videos/1/stream.mkv?api_key=k".to_vec(),
        }
    }

    fn ok(loc: &str) -> (String, u16, String) {
        let t = resolve(loc.as_bytes(), &base()).unwrap();
        (t.host, t.port, String::from_utf8(t.path).unwrap())
    }

    #[test]
    fn absolute_locations() {
        assert_eq!(
            ok("https://VOD1.Example.NET/emby/play/video/x?api_key=k"),
            (
                "vod1.example.net".into(),
                443,
                "/emby/play/video/x?api_key=k".into()
            )
        );
        assert_eq!(
            ok("http://files.example.net:8443/mnt/%E6%B5%8B.mkv?expires=1&md5=Ab"),
            (
                "files.example.net".into(),
                8443,
                "/mnt/%E6%B5%8B.mkv?expires=1&md5=Ab".into()
            )
        );
        assert_eq!(
            ok("//cdn.example.net?x=1"),
            ("cdn.example.net".into(), 443, "/?x=1".into())
        );
        assert_eq!(
            ok("https://cdn.example.net."),
            ("cdn.example.net".into(), 443, "/".into())
        );
        assert_eq!(
            ok(" https://cdn.example.net/a#frag "),
            ("cdn.example.net".into(), 443, "/a".into())
        );
    }

    #[test]
    fn relative_locations_keep_the_current_target() {
        assert_eq!(
            ok("/img/i/poster/1"),
            ("emby.example.net".into(), 443, "/img/i/poster/1".into())
        );
        assert_eq!(
            ok("original.mkv?a=%2F"),
            (
                "emby.example.net".into(),
                443,
                "/emby/videos/1/original.mkv?a=%2F".into()
            )
        );
        assert_eq!(
            ok("?b=2"),
            (
                "emby.example.net".into(),
                443,
                "/emby/videos/1/stream.mkv?b=2".into()
            )
        );
        let root = Target {
            path: b"/x".to_vec(),
            ..base()
        };
        assert_eq!(resolve(b"y", &root).unwrap().path, b"/y");
    }

    #[test]
    fn bad_locations() {
        for (loc, err) in [
            ("", LocationError::Empty),
            ("#x", LocationError::Empty),
            (
                "https://user:pw@evil.example.net/",
                LocationError::Credentials,
            ),
            ("https://192.0.2.1/x", LocationError::Host),
            ("https://[2001:db8::1]/x", LocationError::Port),
            ("https://localhost/x", LocationError::Host),
            ("https://a.example.net:0/", LocationError::Port),
            ("https://a.example.net:99999/", LocationError::Port),
            ("ftp://a.example.net/", LocationError::Scheme),
            ("javascript:alert(1)", LocationError::Scheme),
        ] {
            assert_eq!(resolve(loc.as_bytes(), &base()), Err(err), "{loc}");
        }
    }

    #[test]
    fn target_kinds() {
        let rules = FollowRules {
            upstream: "emby.example.net".into(),
            aliases: vec!["emby2.example.net".into()],
            follow: vec!["vod1.example.net".into(), "*.files.example.net".into()],
        };
        assert_eq!(rules.kind("emby.example.net"), Some(TargetKind::Upstream));
        assert_eq!(rules.kind("emby2.example.net"), Some(TargetKind::Upstream));
        assert_eq!(rules.kind("vod1.example.net"), Some(TargetKind::Follow));
        assert_eq!(
            rules.kind("fw1csvwe.files.example.net"),
            Some(TargetKind::Follow)
        );
        assert_eq!(rules.kind("a.b.files.example.net"), None);
        assert_eq!(rules.kind("evil.example.net"), None);
        let open = FollowRules {
            follow: Vec::new(),
            ..rules
        };
        assert_eq!(open.kind("emby2.example.net"), Some(TargetKind::Upstream));
        assert_eq!(open.kind("any.example.org"), Some(TargetKind::Follow));
    }
}
