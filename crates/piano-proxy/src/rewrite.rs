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

/// Replaces the names of one upstream server in response bodies.
#[derive(Debug)]
pub struct Rewriter {
    anchors: AhoCorasick,
    hosts: Vec<String>,
}

impl Rewriter {
    /// `hosts`: the upstream's lowercase names.
    pub fn new(hosts: Vec<String>) -> Result<Self, BuildError> {
        let patterns: Vec<String> = ANCHORS
            .iter()
            .map(|(p, _)| (*p).to_owned())
            .chain(hosts.iter().map(|h| format!("\"{h}\"")))
            .collect();
        let anchors = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::LeftmostLongest)
            .build(&patterns)?;
        Ok(Self { anchors, hosts })
    }

    fn is_upstream(&self, host: &[u8]) -> bool {
        let host = host.strip_suffix(b".").unwrap_or(host);
        self.hosts
            .iter()
            .any(|h| h.as_bytes().eq_ignore_ascii_case(host))
    }

    /// `body` with every URL authority naming the upstream, or an IP literal after
    /// `http(s)://`, replaced by `authority` (scheme and escaping kept, `http` becoming
    /// `https`), and every upstream name standing alone as a JSON string replaced by
    /// `host`. `None` if nothing was replaced.
    pub fn rewrite(&self, body: &[u8], host: &str, authority: &str) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        let mut copied = 0;
        for m in self.anchors.find_iter(body) {
            if m.start() < copied {
                continue;
            }
            let anchor = ANCHORS
                .get(m.pattern().as_usize())
                .map_or(Anchor::Quoted, |(_, a)| *a);
            let end = match anchor {
                Anchor::Quoted => m.end(),
                Anchor::Scheme { .. } | Anchor::Relative { .. } => {
                    let (name, end) = url_authority(body, m.end());
                    let ours = self.is_upstream(name)
                        || (matches!(anchor, Anchor::Scheme { .. }) && is_ip_literal(name));
                    if !ours {
                        continue;
                    }
                    end
                }
            };
            if out.is_empty() {
                out.reserve(body.len() + 256);
            }
            out.extend_from_slice(&body[copied..m.start()]);
            let replacement: [&str; 3] = match anchor {
                Anchor::Scheme { escaped: false } => ["https://", authority, ""],
                Anchor::Scheme { escaped: true } => [r"https:\/\/", authority, ""],
                Anchor::Relative { escaped: false } => ["//", authority, ""],
                Anchor::Relative { escaped: true } => [r"\/\/", authority, ""],
                Anchor::Quoted => ["\"", host, "\""],
            };
            for part in replacement {
                out.extend_from_slice(part.as_bytes());
            }
            copied = end;
        }
        if copied == 0 {
            return None;
        }
        out.extend_from_slice(&body[copied..]);
        Some(out)
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
        Rewriter::new(vec!["emby.example.net".into(), "emby2.example.net".into()]).unwrap()
    }

    fn rw(body: &str) -> String {
        let out = rewriter().rewrite(body.as_bytes(), HOST, PUBLIC);
        String::from_utf8(out.unwrap_or_else(|| body.as_bytes().to_vec())).unwrap()
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
            r#"{"a":"https://vod.example.net/x"}"#,
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
    fn keeps_the_bytes_around_replacements() {
        let body = "\u{4e2d}\"emby.example.net\"\u{6587}\n\t//emby.example.net";
        assert_eq!(
            rw(body),
            "\u{4e2d}\"media.example.com\"\u{6587}\n\t//media.example.com:8443"
        );
    }
}
