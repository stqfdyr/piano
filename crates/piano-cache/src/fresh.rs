//! Freshness from `Cache-Control`, as a shared cache sees it.

use std::time::Duration;

/// What a response allows a shared cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    /// No lifetime given.
    Unstated,
    /// Not to be stored, or stale at once.
    Never,
    /// Fresh for this long; zero when it arrived stale (its `Age` used up its lifetime),
    /// which may still be stored and confirmed before use.
    For(Duration),
}

impl Freshness {
    /// The lifetime of a response that may be stored.
    pub fn ttl(self) -> Option<Duration> {
        match self {
            Self::For(d) => Some(d),
            Self::Unstated | Self::Never => None,
        }
    }
}

/// How long a response may be served from a shared cache, capped at `max`.
/// `cache_control` holds every `Cache-Control` field line, which together form one list;
/// `age` is the response's `Age`, the time it already spent in caches upstream, which
/// its lifetime includes (RFC 9111 §4.2.3). `s-maxage` wins over `max-age`; image
/// endpoints that want caching say so, so a response without either is not stored.
pub fn shared_ttl<'a>(
    cache_control: impl IntoIterator<Item = &'a [u8]>,
    age: Duration,
    max: Duration,
) -> Freshness {
    let mut max_age = None;
    let mut s_maxage = None;
    let directives = cache_control
        .into_iter()
        .flat_map(|line| line.split(|&b| b == b','));
    for directive in directives {
        let directive = directive.trim_ascii();
        let (name, arg) = match directive.iter().position(|&b| b == b'=') {
            Some(i) => (&directive[..i], Some(directive[i + 1..].trim_ascii())),
            None => (directive, None),
        };
        let name = name.trim_ascii();
        let is = |n: &str| name.eq_ignore_ascii_case(n.as_bytes());
        if is("no-store") || is("private") || is("no-cache") {
            return Freshness::Never;
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
    match s_maxage.or(max_age) {
        None => Freshness::Unstated,
        Some(0) => Freshness::Never,
        Some(secs) => Freshness::For(Duration::from_secs(secs).saturating_sub(age).min(max)),
    }
}

#[cfg(test)]
mod tests {
    use super::{Freshness, shared_ttl};
    use std::time::Duration;

    const MAX: Duration = Duration::from_secs(30 * 86_400);

    fn ttl(v: &str) -> Option<u64> {
        shared_ttl([v.as_bytes()], Duration::ZERO, MAX)
            .ttl()
            .map(|d| d.as_secs())
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
        assert_eq!(
            shared_ttl(std::iter::empty(), Duration::ZERO, MAX),
            Freshness::Unstated
        );
        let f = |v: &str| shared_ttl([v.as_bytes()], Duration::ZERO, MAX);
        assert_eq!(f("public"), Freshness::Unstated);
        assert_eq!(f("max-age=x"), Freshness::Unstated);
        assert_eq!(f("max-age=0"), Freshness::Never);
        assert_eq!(f("s-maxage=0, max-age=60"), Freshness::Never);
        assert_eq!(f("max-age=60, private"), Freshness::Never);
    }

    #[test]
    fn field_lines_form_one_list() {
        let lines = |l: &[&'static str]| {
            shared_ttl(l.iter().map(|s| s.as_bytes()), Duration::ZERO, MAX)
                .ttl()
                .map(|d| d.as_secs())
        };
        assert_eq!(lines(&["public, max-age=60", "private"]), None);
        assert_eq!(lines(&["max-age=60", "s-maxage=600"]), Some(600));
    }

    #[test]
    fn time_spent_upstream_counts() {
        let f = |v: &str, age: u64| shared_ttl([v.as_bytes()], Duration::from_secs(age), MAX);
        assert_eq!(
            f("max-age=600", 100),
            Freshness::For(Duration::from_secs(500))
        );
        // The cap applies to what is left, not to the whole lifetime.
        assert_eq!(f("max-age=31536000", 86_400), Freshness::For(MAX));
        assert_eq!(
            f("max-age=2592100", 200),
            Freshness::For(Duration::from_secs(2_591_900))
        );
        // Arrived stale: kept, to be confirmed before use.
        assert_eq!(f("max-age=600", 600), Freshness::For(Duration::ZERO));
        assert_eq!(f("max-age=600", 900), Freshness::For(Duration::ZERO));
        assert_eq!(f("max-age=0", 0), Freshness::Never);
        assert_eq!(f("public", 900), Freshness::Unstated);
    }
}
