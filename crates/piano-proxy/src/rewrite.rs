//! Rewriting upstream addresses in JSON bodies.
//!
//! A few Emby responses name the upstream server, or an address it believes it has; a
//! client that used them would leave the relay. Each such address is replaced by the
//! relay's own. Everything else is kept byte for byte: the body is scanned, not parsed,
//! so field order and formatting do not change.

use aho_corasick::{AhoCorasick, BuildError, MatchKind};
use std::net::{Ipv4Addr, Ipv6Addr};

/// Largest body buffered for rewriting; a larger one is passed on unchanged.
pub const MAX_BODY: usize = 4 << 20;

/// Where an address may start.
#[derive(Debug, Clone, Copy)]
enum Anchor {
    /// `http://` or `https://`; also matches IP literals.
    Scheme { escaped: bool },
    /// `//`, a scheme-relative URL.
    Relative { escaped: bool },
    /// A configured name as a whole JSON string.
    Quoted,
}

const ANCHORS: [(&str, Anchor); 6] = [
    ("https://", Anchor::Scheme { escaped: false }),
    ("http://", Anchor::Scheme { escaped: false }),
    ("//", Anchor::Relative { escaped: false }),
    (r"https:\/\/", Anchor::Scheme { escaped: true }),
    (r"http:\/\/", Anchor::Scheme { escaped: true }),
    (r"\/\/", Anchor::Relative { escaped: true }),
];

/// One name of the upstream service and the site path its URLs move to.
#[derive(Debug)]
struct Name {
    host: String,
    /// Empty for the upstream server itself; a mount prefix for another of its hosts.
    prefix: String,
    /// `prefix` with each `/` written as `\/`, for JSON-escaped URLs.
    escaped_prefix: String,
}

/// Replaces the names of one upstream service in response bodies.
#[derive(Debug)]
pub struct Rewriter {
    anchors: AhoCorasick,
    names: Vec<Name>,
}

impl Rewriter {
    /// `hosts`: the upstream's lowercase names, replaced by the site; `mounts`: other
    /// lowercase hosts with the site path prefix their URLs move under.
    pub fn new(hosts: Vec<String>, mounts: Vec<(String, String)>) -> Result<Self, BuildError> {
        let names: Vec<Name> = hosts
            .into_iter()
            .map(|h| (h, String::new()))
            .chain(mounts)
            .map(|(host, prefix)| Name {
                escaped_prefix: prefix.replace('/', r"\/"),
                host,
                prefix,
            })
            .collect();
        let patterns: Vec<String> = ANCHORS
            .iter()
            .map(|(p, _)| (*p).to_owned())
            .chain(names.iter().map(|n| format!("\"{}\"", n.host)))
            .collect();
        let anchors = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::LeftmostLongest)
            .build(&patterns)?;
        Ok(Self { anchors, names })
    }

    fn name(&self, host: &[u8]) -> Option<&Name> {
        let host = host.strip_suffix(b".").unwrap_or(host);
        self.names
            .iter()
            .find(|n| n.host.as_bytes().eq_ignore_ascii_case(host))
    }

    /// `body` with every URL authority naming the upstream, or an IP literal after
    /// `http(s)://`, replaced by `authority` (scheme and escaping kept, `http` becoming
    /// `https`) followed by the name's mount prefix, and every upstream name standing
    /// alone as a JSON string replaced by `host`; with the number of replacements.
    /// `None` if nothing was replaced.
    pub fn rewrite(&self, body: &[u8], host: &str, authority: &str) -> Option<(Vec<u8>, usize)> {
        let mut out = Vec::new();
        let mut copied = 0;
        let mut count = 0;
        for m in self.anchors.find_iter(body) {
            if m.start() < copied {
                continue;
            }
            let anchor = ANCHORS
                .get(m.pattern().as_usize())
                .map_or(Anchor::Quoted, |(_, a)| *a);
            let (end, prefix) = match anchor {
                Anchor::Quoted => (m.end(), ""),
                Anchor::Scheme { escaped } | Anchor::Relative { escaped } => {
                    let (name, end) = url_authority(body, m.end());
                    let prefix = match self.name(name) {
                        Some(n) if escaped => n.escaped_prefix.as_str(),
                        Some(n) => n.prefix.as_str(),
                        None if matches!(anchor, Anchor::Scheme { .. }) && is_ip_literal(name) => {
                            ""
                        }
                        None => continue,
                    };
                    (end, prefix)
                }
            };
            if out.is_empty() {
                out.reserve(body.len() + 256);
            }
            out.extend_from_slice(&body[copied..m.start()]);
            let replacement: [&str; 3] = match anchor {
                Anchor::Scheme { escaped: false } => ["https://", authority, prefix],
                Anchor::Scheme { escaped: true } => [r"https:\/\/", authority, prefix],
                Anchor::Relative { escaped: false } => ["//", authority, prefix],
                Anchor::Relative { escaped: true } => [r"\/\/", authority, prefix],
                Anchor::Quoted => ["\"", host, "\""],
            };
            for part in replacement {
                out.extend_from_slice(part.as_bytes());
            }
            copied = end;
            count += 1;
        }
        if count == 0 {
            return None;
        }
        out.extend_from_slice(&body[copied..]);
        Some((out, count))
    }
}

/// The host of the URL authority starting at `start`, and where the authority (with
/// any port) ends.
fn url_authority(body: &[u8], start: usize) -> (&[u8], usize) {
    let rest = body.get(start..).unwrap_or_default();
    let host_len = if rest.first() == Some(&b'[') {
        rest.iter().position(|&b| b == b']').map_or(0, |i| i + 1)
    } else {
        rest.iter()
            .take_while(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
            .count()
    };
    let mut end = start + host_len;
    if body.get(end) == Some(&b':') {
        let digits = body[end + 1..]
            .iter()
            .take_while(|b| b.is_ascii_digit())
            .count();
        if (1..=5).contains(&digits) {
            end += 1 + digits;
        }
    }
    (&rest[..host_len], end)
}

fn is_ip_literal(host: &[u8]) -> bool {
    let Ok(host) = std::str::from_utf8(host) else {
        return false;
    };
    match host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        Some(v6) => v6.parse::<Ipv6Addr>().is_ok(),
        None => host.parse::<Ipv4Addr>().is_ok(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST: &str = "media.example.com";
    const PUBLIC: &str = "media.example.com:8443";

    fn rewriter() -> Rewriter {
        Rewriter::new(
            vec!["emby.example.net".into(), "emby2.example.net".into()],
            vec![("vod.example.net".into(), "/__vod".into())],
        )
        .unwrap()
    }

    fn rw(body: &str) -> String {
        let out = rewriter().rewrite(body.as_bytes(), HOST, PUBLIC);
        String::from_utf8(out.map_or_else(|| body.as_bytes().to_vec(), |(b, _)| b)).unwrap()
    }

    #[test]
    fn counts_replacements() {
        let body =
            r#"{"a":"https://emby.example.net/x","b":"emby.example.net","c":"http://192.0.2.1"}"#;
        let (_, n) = rewriter().rewrite(body.as_bytes(), HOST, PUBLIC).unwrap();
        assert_eq!(n, 3);
    }

    #[test]
    fn replaces_every_form_of_the_upstream() {
        for (from, to) in [
            (
                r#"{"a":"https://emby.example.net/x"}"#,
                r#"{"a":"https://media.example.com:8443/x"}"#,
            ),
            (
                r#"{"a":"http://EMBY.Example.NET:8096"}"#,
                r#"{"a":"https://media.example.com:8443"}"#,
            ),
            (
                r#"{"a":"//emby2.example.net?q"}"#,
                r#"{"a":"//media.example.com:8443?q"}"#,
            ),
            (
                r#"{"a":"https:\/\/emby.example.net\/x"}"#,
                r#"{"a":"https:\/\/media.example.com:8443\/x"}"#,
            ),
            (
                r#"{"a":"\/\/emby.example.net.\/x"}"#,
                r#"{"a":"\/\/media.example.com:8443\/x"}"#,
            ),
            (
                r#"["emby.example.net","Emby2.example.net"]"#,
                r#"["media.example.com","media.example.com"]"#,
            ),
            (
                r#"see https://emby.example.net and https://emby2.example.net:443/"#,
                r#"see https://media.example.com:8443 and https://media.example.com:8443/"#,
            ),
        ] {
            assert_eq!(rw(from), to, "{from}");
        }
    }

    #[test]
    fn moves_mounted_hosts_under_their_prefix() {
        for (from, to) in [
            (
                r#"{"u":"https://vod.example.net/play/video/1?api_key=k"}"#,
                r#"{"u":"https://media.example.com:8443/__vod/play/video/1?api_key=k"}"#,
            ),
            (
                r#"{"u":"http:\/\/VOD.example.net\/play"}"#,
                r#"{"u":"https:\/\/media.example.com:8443\/__vod\/play"}"#,
            ),
            (
                r#"{"u":"//vod.example.net/play","h":"vod.example.net"}"#,
                r#"{"u":"//media.example.com:8443/__vod/play","h":"media.example.com"}"#,
            ),
        ] {
            assert_eq!(rw(from), to, "{from}");
        }
    }

    #[test]
    fn replaces_ip_literals_after_a_scheme() {
        assert_eq!(
            rw(r#"{"LocalAddress":"http://172.17.0.1:8096","Wan":"https://[2001:db8::1]:8920/w"}"#),
            r#"{"LocalAddress":"https://media.example.com:8443","Wan":"https://media.example.com:8443/w"}"#
        );
        assert_eq!(
            rw(r#"{"a":"\/\/192.0.2.1\/x"}"#),
            r#"{"a":"\/\/192.0.2.1\/x"}"#
        );
    }

    #[test]
    fn leaves_other_names_alone() {
        let r = rewriter();
        for body in [
            r#"{"a":"https://vod2.example.net/x"}"#,
            r#"{"a":"https://emby.example.net.evil.example/x"}"#,
            r#"{"a":"https://xemby.example.net/x"}"#,
            r#"{"a":"https://emby.example.network/x"}"#,
            r#"{"a":"emby.example.net is here","b":"/videos/1/stream?api_key=k"}"#,
            r#"{"a":"https://192.0.2.1.example/x","b":"https://256.0.0.1/"}"#,
            "",
            "//",
            "https://",
        ] {
            assert_eq!(r.rewrite(body.as_bytes(), HOST, PUBLIC), None, "{body}");
        }
    }

    #[test]
    fn replaces_adjacent_names() {
        assert_eq!(
            rw(r#""emby.example.net""emby.example.net"https://emby.example.net"#),
            r#""media.example.com""media.example.com"https://media.example.com:8443"#
        );
    }

    #[test]
    fn skips_anchors_inside_a_replaced_authority() {
        // A name ending in "http" holds the start of an "http://" anchor.
        let r = Rewriter::new(vec!["cdn.myhttp".into()], Vec::new()).unwrap();
        let (out, n) = r.rewrite(b"https://cdn.myhttp://x", HOST, PUBLIC).unwrap();
        assert_eq!(out, b"https://media.example.com:8443://x");
        assert_eq!(n, 1);
    }

    #[test]
    fn keeps_the_bytes_around_replacements() {
        let body = "\u{4e2d}\"emby.example.net\"\u{6587}\n\t//emby.example.net";
        assert_eq!(
            rw(body),
            "\u{4e2d}\"media.example.com\"\u{6587}\n\t//media.example.com:8443"
        );
    }
}
