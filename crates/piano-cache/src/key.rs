//! Cache keys for image requests.

/// Query parameters that carry client credentials. Images are the same for every
/// client of a site, so these must not split the cache, and they must not be kept.
const CREDENTIALS: [&str; 4] = [
    "api_key",
    "x-emby-token",
    "x-emby-authorization",
    "x-mediabrowser-token",
];

/// The cache key of an image request: the site, the path as sent and the query
/// parameters other than credentials, sorted. Path bytes are not decoded, so two
/// spellings of one path are two keys, which costs a miss and never serves a wrong image.
pub fn image_key(site: &str, target: &[u8]) -> String {
    let (path, query) = match target.iter().position(|&b| b == b'?') {
        Some(i) => (&target[..i], &target[i + 1..]),
        None => (target, &b""[..]),
    };
    let mut params: Vec<&[u8]> = query
        .split(|&b| b == b'&')
        .filter(|p| !p.is_empty())
        .filter(|p| {
            let name = p.split(|&b| b == b'=').next().unwrap_or_default();
            !CREDENTIALS
                .iter()
                .any(|c| c.as_bytes().eq_ignore_ascii_case(name))
        })
        .collect();
    params.sort_unstable();
    let mut key = String::with_capacity(site.len() + target.len() + 2);
    key.push_str(site);
    key.push(' ');
    key.push_str(&String::from_utf8_lossy(path));
    if !params.is_empty() {
        key.push('?');
        for (i, p) in params.iter().enumerate() {
            if i > 0 {
                key.push('&');
            }
            key.push_str(&String::from_utf8_lossy(p));
        }
    }
    key
}

/// The key of the copy of image `key` for a request with these `Accept` lines, for
/// images whose response says `Vary: Accept` (an image endpoint may answer WebP to a
/// client that lists it). Whitespace and case, which do not change what the lines mean,
/// are dropped; bytes outside printable ASCII are escaped so distinct values stay apart.
pub fn variant_key<'a>(key: &str, accept: impl IntoIterator<Item = &'a [u8]>) -> String {
    let mut v = String::from(key);
    v.push('\n');
    for (i, line) in accept.into_iter().enumerate() {
        if i > 0 {
            v.push(',');
        }
        let kept: Vec<u8> = line
            .iter()
            .filter(|b| !matches!(b, b' ' | b'\t'))
            .map(u8::to_ascii_lowercase)
            .collect();
        v.push_str(&kept.escape_ascii().to_string());
    }
    v
}

#[cfg(test)]
mod tests {
    use super::{image_key, variant_key};

    #[test]
    fn variants_differ_by_what_accept_says() {
        let k = "s /x?tag=1";
        let v = |lines: &[&[u8]]| variant_key(k, lines.iter().copied());
        assert_eq!(v(&[b"image/webp,image/*"]), v(&[b"Image/WebP, image/*"]));
        assert_ne!(v(&[b"image/webp,image/*"]), v(&[b"image/*"]));
        assert_ne!(v(&[b"image/*"]), v(&[]));
        assert_eq!(v(&[]), "s /x?tag=1\n");
        assert_eq!(v(&[b"image/webp", b" */*"]), "s /x?tag=1\nimage/webp,*/*");
        assert_ne!(v(&[b"image/webp\xff"]), v(&[b"image/webp\xfe"]));
        assert_ne!(v(&[b"image/webp\xff"]), v(&[b"image/webp\\xff"]));
        assert_ne!(variant_key("s /y", [&b"image/*"[..]]), v(&[b"image/*"]));
    }

    #[test]
    fn credentials_are_dropped_and_parameters_sorted() {
        let a = image_key(
            "s",
            b"/Items/1/Images/Primary?maxWidth=300&api_key=AAA&tag=t1",
        );
        let b = image_key(
            "s",
            b"/Items/1/Images/Primary?tag=t1&X-Emby-Token=BBB&maxWidth=300",
        );
        assert_eq!(a, b);
        assert_eq!(a, "s /Items/1/Images/Primary?maxWidth=300&tag=t1");
        assert!(!a.contains("AAA"));
    }

    #[test]
    fn sites_paths_and_values_stay_apart() {
        let k = |s, t: &[u8]| image_key(s, t);
        assert_ne!(k("a", b"/x"), k("b", b"/x"));
        assert_ne!(k("a", b"/x?tag=1"), k("a", b"/x?tag=2"));
        assert_ne!(k("a", b"/x"), k("a", b"/X"));
        assert_eq!(k("a", b"/x"), k("a", b"/x?api_key=1"));
        assert_eq!(k("a", b"/x?"), "a /x");
        assert_eq!(k("a", b"/x?&&tag=1&"), "a /x?tag=1");
    }
}
