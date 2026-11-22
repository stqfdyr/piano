//! Where a media request's redirects led, so that the next request for the same target
//! goes straight there.
//!
//! At one upstream the first hop computes a signed file URL, 0.15–1.5 s per request,
//! and a player sends several requests for one file within seconds (start, end of file,
//! resume point, each seek). The signed URL is good for about an hour. A request that
//! goes to a remembered target skips the upstream's own check of its credentials, so
//! only a request carrying credentials is remembered, under all of them: a revoked
//! token keeps playing what it already played for up to [`TTL`].

use crate::Sites;
use crate::reach::Hop;
use http::header::{AUTHORIZATION, COOKIE, USER_AGENT};
use http::{HeaderName, HeaderValue};
use pingora_http::RequestHeader;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::{Duration, Instant};

/// How long a redirect target is used without asking again: a tenth of the hour one
/// upstream signs its file URLs for. A target that refuses, is gone, fails or cannot be
/// reached is forgotten and the chain walked again at once.
pub(crate) const TTL: Duration = Duration::from_secs(600);

/// Targets remembered at once: a household plays a few files at a time.
const MAX: usize = 512;

/// Longest key remembered; a request with a longer target walks the chain every time.
const MAX_KEY: usize = 4096;

#[derive(Debug)]
struct Entry {
    target: Hop,
    /// The site table the chain was walked with; after a reload the rules that allowed
    /// the target may be gone.
    sites: Weak<Sites>,
    at: Instant,
}

/// Redirect targets by what was asked for.
#[derive(Debug, Default)]
pub(crate) struct Redirects {
    map: Mutex<HashMap<Vec<u8>, Entry>>,
}

/// Query parameters and header fields that carry a client's credentials.
const CREDENTIAL_PARAMS: [&str; 4] = [
    "api_key",
    "x-emby-token",
    "x-emby-authorization",
    "x-mediabrowser-token",
];
const CREDENTIAL_FIELDS: [HeaderName; 5] = [
    HeaderName::from_static("x-emby-token"),
    HeaderName::from_static("x-emby-authorization"),
    HeaderName::from_static("x-mediabrowser-token"),
    AUTHORIZATION,
    COOKIE,
];

/// What makes two requests lead to the same target: the site, the host the request
/// starts at (a mount, or the upstream), the request target, the User-Agent and every
/// credential field. `None` for a request without credentials, or too long to keep.
pub(crate) fn key(site: &str, start: Option<&Hop>, req: &RequestHeader) -> Option<Vec<u8>> {
    let target = req.raw_path();
    let query = target
        .iter()
        .position(|&b| b == b'?')
        .map_or(&b""[..], |i| &target[i + 1..]);
    let in_query = query.split(|&b| b == b'&').any(|p| {
        let name = p.split(|&b| b == b'=').next().unwrap_or_default();
        CREDENTIAL_PARAMS
            .iter()
            .any(|c| c.as_bytes().eq_ignore_ascii_case(name))
    });
    let fields: Vec<&[u8]> = CREDENTIAL_FIELDS
        .iter()
        .flat_map(|n| req.headers.get_all(n).iter().map(HeaderValue::as_bytes))
        .collect();
    if !in_query && fields.is_empty() {
        return None;
    }
    let start = start.map_or("", |h| h.target.host.as_str());
    let ua = req
        .headers
        .get(USER_AGENT)
        .map(HeaderValue::as_bytes)
        .unwrap_or_default();
    let mut k = Vec::new();
    for part in [site.as_bytes(), start.as_bytes(), target, ua]
        .into_iter()
        .chain(fields)
    {
        if k.len() + part.len() + 1 > MAX_KEY {
            return None;
        }
        k.extend_from_slice(part);
        k.push(0);
    }
    Some(k)
}

impl Redirects {
    /// The target remembered for `key`, if it is recent and was found with `sites`.
    pub(crate) fn get(&self, key: &[u8], sites: &Arc<Sites>, now: Instant) -> Option<Hop> {
        let mut map = self.lock();
        let e = map.get(key)?;
        if now.saturating_duration_since(e.at) < TTL
            && Weak::ptr_eq(&e.sites, &Arc::downgrade(sites))
        {
            return Some(e.target.clone());
        }
        map.remove(key);
        None
    }

    pub(crate) fn put(&self, key: Vec<u8>, target: Hop, sites: &Arc<Sites>, now: Instant) {
        let mut map = self.lock();
        if map.len() >= MAX && !map.contains_key(&key) {
            map.retain(|_, e| now.saturating_duration_since(e.at) < TTL);
            if map.len() >= MAX {
                let oldest = map.iter().min_by_key(|(_, e)| e.at).map(|(k, _)| k.clone());
                if let Some(k) = oldest {
                    map.remove(&k);
                }
            }
        }
        map.insert(
            key,
            Entry {
                target,
                sites: Arc::downgrade(sites),
                at: now,
            },
        );
    }

    /// Forgets `used` as the target for `key`; a newer one another request stored meanwhile
    /// stays.
    pub(crate) fn forget(&self, key: &[u8], used: &Hop) {
        let mut map = self.lock();
        if map.get(key).is_some_and(|e| e.target.target == used.target) {
            map.remove(key);
        }
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<Vec<u8>, Entry>> {
        // Plain data; a panic elsewhere cannot leave it inconsistent.
        self.map.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::follow::{Target, TargetKind};

    fn hop(path: &str) -> Hop {
        Hop {
            target: Target {
                host: "files.example.net".into(),
                port: 443,
                path: path.as_bytes().to_vec(),
            },
            kind: TargetKind::Follow,
        }
    }

    fn sites() -> Arc<Sites> {
        Arc::new(Sites::default())
    }

    fn req(target: &str, fields: &[(&str, &str)]) -> RequestHeader {
        let mut r = RequestHeader::build("GET", target.as_bytes(), None).unwrap();
        for (k, v) in fields {
            r.append_header(k.to_string(), *v).unwrap();
        }
        r
    }

    #[test]
    fn a_target_is_used_until_it_expires_or_the_sites_change() {
        let r = Redirects::default();
        let (s, t0) = (sites(), Instant::now());
        let k = key("a", None, &req("/v/1?api_key=x", &[])).unwrap();
        assert!(r.get(&k, &s, t0).is_none());
        r.put(k.clone(), hop("/f/1"), &s, t0);
        let got = r.get(&k, &s, t0 + TTL - Duration::from_secs(1)).unwrap();
        assert_eq!(got.target.path, b"/f/1");
        assert!(r.get(&k, &sites(), t0).is_none(), "another site table");
        r.put(k.clone(), hop("/f/1"), &s, t0);
        assert!(r.get(&k, &s, t0 + TTL).is_none(), "expired");
        r.put(k.clone(), hop("/f/2"), &s, t0);
        r.forget(&k, &hop("/f/1"));
        assert!(r.get(&k, &s, t0).is_some(), "a newer target stays");
        r.forget(&k, &hop("/f/2"));
        assert!(r.get(&k, &s, t0).is_none());
    }

    #[test]
    fn only_requests_with_credentials_are_kept_and_apart() {
        let k = |t: &str, f: &[(&str, &str)]| key("a", None, &req(t, f));
        assert!(k("/v", &[]).is_none(), "nothing to tell who asks");
        assert!(k("/v", &[("user-agent", "P/1")]).is_none());
        let base = k("/v?API_KEY=x", &[]).unwrap();
        assert_ne!(Some(base.clone()), k("/v?api_key=y", &[]));
        assert_ne!(
            Some(base.clone()),
            k("/v?API_KEY=x", &[("user-agent", "P/2")])
        );
        let tok = k("/v", &[("x-emby-token", "A")]).unwrap();
        assert_ne!(Some(tok.clone()), k("/v", &[("x-emby-token", "B")]));
        assert_ne!(
            Some(tok),
            k("/v", &[("x-emby-token", "A"), ("cookie", "s=1")])
        );
        assert!(k("/v", &[("authorization", "Bearer t")]).is_some());
        assert_ne!(
            key("a", None, &req("/v?api_key=x", &[])),
            key("a", Some(&hop("/")), &req("/v?api_key=x", &[]))
        );
        // Separators keep one part from running into the next.
        assert_ne!(
            key("ab", None, &req("/v?api_key=x", &[])),
            key("a", None, &req("b/v?api_key=x", &[]))
        );
        let long = format!("/v?api_key=x&p={}", "x".repeat(MAX_KEY));
        assert!(k(&long, &[]).is_none());
    }

    #[test]
    fn the_memory_is_bounded() {
        let (r, s, t0) = (Redirects::default(), sites(), Instant::now());
        for i in 0..MAX + 5 {
            let at = t0 + Duration::from_millis(i as u64);
            r.put(format!("k{i}").into_bytes(), hop("/f"), &s, at);
        }
        assert_eq!(r.lock().len(), MAX);
        let at = t0 + Duration::from_secs(1);
        assert!(r.get(b"k0", &s, at).is_none(), "the oldest made room");
        assert!(r.get(format!("k{}", MAX + 4).as_bytes(), &s, at).is_some());
    }
}
