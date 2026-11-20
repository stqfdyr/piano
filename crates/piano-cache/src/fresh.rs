//! Freshness from `Cache-Control`, as a shared cache sees it.

use std::time::Duration;

/// How long a response may be served from a shared cache, capped at `max`; `None` when
/// it must not be stored or revalidated before every use. `s-maxage` wins over
/// `max-age`; without either nothing is stored, since image endpoints that want caching
/// say so.
pub fn shared_ttl(cache_control: Option<&[u8]>, max: Duration) -> Option<Duration> {
    let value = cache_control?;
    let mut max_age = None;
    let mut s_maxage = None;
    for directive in value.split(|&b| b == b',') {
        let directive = directive.trim_ascii();
        let (name, arg) = match directive.iter().position(|&b| b == b'=') {
            Some(i) => (&directive[..i], Some(directive[i + 1..].trim_ascii())),
            None => (directive, None),
        };
        let name = name.trim_ascii();
        let is = |n: &str| name.eq_ignore_ascii_case(n.as_bytes());
        if is("no-store") || is("private") || is("no-cache") {
            return None;
        }
        let secs = || {
            let a = arg?;
            let a = a.strip_prefix(b"\"").unwrap_or(a);
            let a = a.strip_suffix(b"\"").unwrap_or(a);
            std::str::from_utf8(a).ok()?.parse::<u64>().ok()
        };
        if is("max-age") {
            max_age = secs();
        } else if is("s-maxage") {
            s_maxage = secs();
        }
    }
    let secs = s_maxage.or(max_age)?;
    (secs > 0).then(|| Duration::from_secs(secs).min(max))
}

#[cfg(test)]
mod tests {
    use super::shared_ttl;
    use std::time::Duration;

    const MAX: Duration = Duration::from_secs(30 * 86_400);

    fn ttl(v: &str) -> Option<u64> {
        shared_ttl(Some(v.as_bytes()), MAX).map(|d| d.as_secs())
    }

    #[test]
    fn shared_cache_reading() {
        assert_eq!(
            ttl("public, max-age=86400, s-maxage=604800, stale-while-revalidate=86400"),
            Some(604_800)
        );
        assert_eq!(ttl("public, max-age=31536000"), Some(30 * 86_400));
        assert_eq!(ttl("max-age=\"60\""), Some(60));
        assert_eq!(ttl("Max-Age = 5"), Some(5));
        assert_eq!(ttl("public"), None);
        assert_eq!(ttl("max-age=0"), None);
        assert_eq!(ttl("max-age=60, private"), None);
        assert_eq!(ttl("no-store, max-age=60"), None);
        assert_eq!(ttl("no-cache"), None);
        assert_eq!(ttl("max-age=x"), None);
        assert_eq!(shared_ttl(None, MAX), None);
    }
}
