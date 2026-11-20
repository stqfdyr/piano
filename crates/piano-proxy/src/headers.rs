//! Header policy: what is removed, rewritten or added on the way up and down.

use http::HeaderValue;
use http::header::{COOKIE, SET_COOKIE, USER_AGENT};
use pingora_error::{ErrorType, OrErr, Result};
use pingora_http::{RequestHeader, ResponseHeader};
use regex::bytes::Regex;

/// Request headers that would tell the upstream who the client is; never forwarded.
pub const CLIENT_IP_HEADERS: [&str; 12] = [
    "x-real-ip",
    "x-forwarded-for",
    "x-forwarded-proto",
    "x-forwarded-host",
    "x-forwarded-port",
    "x-forwarded-server",
    "forwarded",
    "true-client-ip",
    "cf-connecting-ip",
    "x-client-ip",
    "x-cluster-client-ip",
    "fastly-client-ip",
];

/// Upstream response headers not passed to clients. Each is removed for a reason of
/// the relay's own; every other header reaches the client as the upstream sent it.
pub const HIDDEN_RESPONSE_HEADERS: [&str; 6] = [
    // Advertises protocols on the site's host that the relay does not serve.
    "alt-svc",
    // Make browsers send error reports, which carry their addresses, to an endpoint
    // the upstream chooses.
    "nel",
    "report-to",
    "reporting-endpoints",
    // Makes browsers fetch a URL the upstream chooses, possibly on its own host.
    "speculation-rules",
    // Transport policy for the site's host is the relay's to set; see `HSTS`.
    "strict-transport-security",
];

/// Strict-Transport-Security for every response, local answers included. The site is
/// only served over TLS. One year is the shortest lifetime the browsers' preload lists
/// accept, the common floor for a policy meant to stay.
pub const HSTS: &str = "max-age=31536000; includeSubDomains";

/// Ordered User-Agent rewrites; the first matching rule wins.
#[derive(Debug, Default)]
pub struct UaRules(Vec<(Regex, HeaderValue)>);

#[derive(Debug, thiserror::Error)]
pub enum UaRuleError {
    #[error("invalid pattern: {0}")]
    Pattern(#[from] regex::Error),
    #[error("invalid replacement: {0}")]
    Value(#[from] http::header::InvalidHeaderValue),
}

impl UaRules {
    pub fn new(rules: &[piano_config::UaRule]) -> Result<Self, UaRuleError> {
        rules
            .iter()
            .map(|r| Ok((Regex::new(&r.pattern)?, HeaderValue::from_str(&r.set)?)))
            .collect::<Result<Vec<_>, UaRuleError>>()
            .map(Self)
    }

    /// The replacement for a client User-Agent (empty when absent), if any rule matches.
    pub fn rewrite(&self, ua: &[u8]) -> Option<&HeaderValue> {
        self.0
            .iter()
            .find(|(re, _)| re.is_match(ua))
            .map(|(_, v)| v)
    }
}

pub fn scrub_request(req: &mut RequestHeader) {
    for name in CLIENT_IP_HEADERS {
        req.remove_header(name);
    }
}

pub fn rewrite_user_agent(rules: &UaRules, req: &mut RequestHeader) -> Result<()> {
    let ua = req
        .headers
        .get(USER_AGENT)
        .map_or(&b""[..], |v| v.as_bytes());
    if let Some(v) = rules.rewrite(ua) {
        req.insert_header(USER_AGENT, v.clone())?;
    }
    Ok(())
}

fn trim(b: &[u8]) -> &[u8] {
    b.trim_ascii()
}

/// Removes the named cookies. Several `Cookie` headers (as HTTP/2 clients send them) are
/// joined into one, which is the only form HTTP/1.1 upstreams must accept.
pub fn strip_cookies(names: &[String], req: &mut RequestHeader) -> Result<()> {
    if names.is_empty() {
        return Ok(());
    }
    let mut values = req.headers.get_all(COOKIE).iter().peekable();
    if values.peek().is_none() {
        return Ok(());
    }
    let mut changed = req.headers.get_all(COOKIE).iter().count() > 1;
    let mut kept = Vec::new();
    for value in values {
        for pair in value.as_bytes().split(|&b| b == b';').map(trim) {
            let name = pair
                .split(|&b| b == b'=')
                .next()
                .map(trim)
                .unwrap_or_default();
            if pair.is_empty() || names.iter().any(|n| n.as_bytes() == name) {
                changed = true;
                continue;
            }
            if !kept.is_empty() {
                kept.extend_from_slice(b"; ");
            }
            kept.extend_from_slice(pair);
        }
    }
    if !changed {
        return Ok(());
    }
    req.remove_header(&COOKIE);
    if !kept.is_empty() {
        let joined = HeaderValue::from_bytes(&kept)
            .or_err(ErrorType::InvalidHTTPHeader, "joining cookies")?;
        req.insert_header(COOKIE, joined)?;
    }
    Ok(())
}

/// `Domain=<from>` (with or without a leading dot, any case) becomes `Domain=<to>`.
fn rewrite_cookie_domain(value: &[u8], from: &str, to: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(value.len() + to.len());
    let mut changed = false;
    for (i, part) in value.split(|&b| b == b';').enumerate() {
        if i > 0 {
            out.push(b';');
        }
        let attr = trim(part);
        let domain = attr
            .get(..7)
            .filter(|p| p.eq_ignore_ascii_case(b"domain="))
            .map(|_| trim(&attr[7..]));
        match domain {
            Some(d) if i > 0 => {
                let (dot, host) = match d.strip_prefix(b".") {
                    Some(h) => (".", h),
                    None => ("", d),
                };
                if host.eq_ignore_ascii_case(from.as_bytes()) {
                    out.extend_from_slice(b" Domain=");
                    out.extend_from_slice(dot.as_bytes());
                    out.extend_from_slice(to.as_bytes());
                    changed = true;
                } else {
                    out.extend_from_slice(part);
                }
            }
            _ => out.extend_from_slice(part),
        }
    }
    changed.then_some(out)
}

/// Applies the response policy to an upstream response: removes the hidden headers,
/// moves cookies set for the upstream host to the site host, and sets HSTS.
pub fn scrub_response(
    resp: &mut ResponseHeader,
    upstream_host: &str,
    site_host: &str,
) -> Result<()> {
    for name in HIDDEN_RESPONSE_HEADERS {
        resp.remove_header(name);
    }
    let rewritten: Vec<Option<Vec<u8>>> = resp
        .headers
        .get_all(SET_COOKIE)
        .iter()
        .map(|v| rewrite_cookie_domain(v.as_bytes(), upstream_host, site_host))
        .collect();
    if rewritten.iter().any(Option::is_some) {
        let originals: Vec<HeaderValue> =
            resp.headers.get_all(SET_COOKIE).iter().cloned().collect();
        resp.remove_header(&SET_COOKIE);
        for (orig, new) in originals.into_iter().zip(rewritten) {
            let v = match new {
                Some(b) => HeaderValue::from_bytes(&b)
                    .or_err(ErrorType::InvalidHTTPHeader, "rewriting a cookie domain")?,
                None => orig,
            };
            resp.append_header(SET_COOKIE, v)?;
        }
    }
    add_hsts(resp)
}

pub fn add_hsts(resp: &mut ResponseHeader) -> Result<()> {
    resp.insert_header(http::header::STRICT_TRANSPORT_SECURITY, HSTS)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(headers: &[(&str, &str)]) -> RequestHeader {
        let mut r = RequestHeader::build("GET", b"/", None).unwrap();
        for (k, v) in headers {
            r.append_header(k.to_string(), *v).unwrap();
        }
        r
    }

    fn values<'a>(r: &'a RequestHeader, name: &str) -> Vec<&'a str> {
        r.headers
            .get_all(name)
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect()
    }

    #[test]
    fn client_ip_headers_are_removed() {
        let mut r = req(&[
            ("X-Forwarded-For", "192.0.2.1"),
            ("cf-connecting-ip", "192.0.2.1"),
            ("Forwarded", "for=192.0.2.1"),
            ("accept", "*/*"),
        ]);
        scrub_request(&mut r);
        assert_eq!(r.headers.len(), 1);
        assert_eq!(values(&r, "accept"), ["*/*"]);
    }

    #[test]
    fn user_agent_rules_apply_in_order() {
        let rules = UaRules::new(&[
            piano_config::UaRule {
                pattern: "^$|(?i)^(curl/|winamp)".into(),
                set: "EmbyMini/0.1.0".into(),
            },
            piano_config::UaRule {
                pattern: "(?i)mozilla/".into(),
                set: "Other/1".into(),
            },
        ])
        .unwrap();
        for (ua, want) in [
            (None, Some("EmbyMini/0.1.0")),
            (Some("curl/8.0"), Some("EmbyMini/0.1.0")),
            (Some("Mozilla/5.0 (X11)"), Some("Other/1")),
            (Some("SenPlayer/5"), None),
        ] {
            let mut r = req(&ua.map(|u| vec![("user-agent", u)]).unwrap_or_default());
            rewrite_user_agent(&rules, &mut r).unwrap();
            let got = values(&r, "user-agent");
            match want {
                Some(w) => assert_eq!(got, [w], "{ua:?}"),
                None => assert_eq!(got, [ua.unwrap()], "{ua:?}"),
            }
        }
    }

    #[test]
    fn named_cookies_are_stripped_and_headers_joined() {
        let strip = vec!["upstream_session".to_owned()];
        for (input, want) in [
            (vec!["a=1; upstream_session=x; b=2"], vec!["a=1; b=2"]),
            (vec!["upstream_session=x"], vec![]),
            (vec!["a=1", "upstream_session=x", "b=2"], vec!["a=1; b=2"]),
            (vec!["a=1;b=2"], vec!["a=1;b=2"]),
            (vec!["a=1", "b=2"], vec!["a=1; b=2"]),
            (vec!["upstream_session2=y"], vec!["upstream_session2=y"]),
        ] {
            let headers: Vec<(&str, &str)> = input.iter().map(|v| ("cookie", *v)).collect();
            let mut r = req(&headers);
            strip_cookies(&strip, &mut r).unwrap();
            assert_eq!(values(&r, "cookie"), want, "{input:?}");
        }
        let mut r = req(&[("cookie", "a=1"), ("cookie", "b=2")]);
        strip_cookies(&[], &mut r).unwrap();
        assert_eq!(values(&r, "cookie"), ["a=1", "b=2"]);
    }

    #[test]
    fn cookie_domains_move_to_the_site() {
        let up = "emby.example.net";
        let site = "media.example.com";
        for (input, want) in [
            (
                "s=1; Path=/; Domain=emby.example.net; HttpOnly",
                Some("s=1; Path=/; Domain=media.example.com; HttpOnly"),
            ),
            (
                "s=1; domain=.EMBY.example.net",
                Some("s=1; Domain=.media.example.com"),
            ),
            ("s=1; Domain=other.example.net", None),
            ("domain=emby.example.net", None),
            ("s=1; Path=/", None),
        ] {
            let got = rewrite_cookie_domain(input.as_bytes(), up, site);
            assert_eq!(
                got.as_deref().map(|b| std::str::from_utf8(b).unwrap()),
                want,
                "{input}"
            );
        }
    }

    #[test]
    fn response_policy() {
        let mut resp = ResponseHeader::build(200, None).unwrap();
        for (k, v) in [
            ("Server", "cloudflare"),
            ("CF-RAY", "x"),
            ("alt-svc", "h3"),
            ("NEL", "{}"),
            ("x-frame-options", "DENY"),
            ("strict-transport-security", "max-age=1"),
            ("set-cookie", "a=1; Domain=emby.example.net"),
            ("set-cookie", "b=2"),
            ("content-type", "application/json"),
        ] {
            resp.append_header(k.to_string(), v).unwrap();
        }
        scrub_response(&mut resp, "emby.example.net", "media.example.com").unwrap();
        let h = &resp.headers;
        assert!(h.get("alt-svc").is_none() && h.get("nel").is_none());
        assert_eq!(h["server"], "cloudflare");
        assert_eq!(h["cf-ray"], "x");
        assert_eq!(h["x-frame-options"], "DENY");
        assert_eq!(h["strict-transport-security"], HSTS);
        let cookies: Vec<_> = h.get_all("set-cookie").iter().collect();
        assert_eq!(cookies, ["a=1; Domain=media.example.com", "b=2"]);
        assert_eq!(h["content-type"], "application/json");
    }
}
