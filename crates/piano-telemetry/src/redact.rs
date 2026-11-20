//! Credential removal applied to everything piano logs.
//!
//! Clients authenticate to Emby with query parameters (`api_key`, `X-Emby-Token`, ...)
//! and with headers whose values look like `Token="..."`. Any `name=value` pair whose
//! name marks a credential has its value replaced, wherever it appears in the text.

use std::borrow::Cow;

/// What a credential is replaced with.
pub const REDACTED: &str = "REDACTED";

/// Whether a parameter of this name carries a credential: `api_key`, `apikey`, or any name
/// ending in `token` or `authorization`, compared after percent-decoding and ignoring
/// ASCII case, as the server compares them.
pub fn is_secret_name(name: &[u8]) -> bool {
    let name = decode_lower(name);
    name == b"api_key"
        || name == b"apikey"
        || name.ends_with(b"token")
        || name.ends_with(b"authorization")
}

/// `s` with the value of every credential parameter replaced by [`REDACTED`]. A value
/// starts after `=` and ends at the next delimiter; a value in double quotes ends at the
/// closing quote.
pub fn redact(s: &str) -> Cow<'_, str> {
    let b = s.as_bytes();
    let mut out: Option<String> = None;
    let mut copied = 0;
    let mut i = 0;
    while let Some(off) = b[i..].iter().position(|&c| c == b'=') {
        let eq = i + off;
        let start = b[..eq]
            .iter()
            .rposition(|&c| !is_name_byte(c))
            .map_or(0, |p| p + 1);
        i = eq + 1;
        if start == eq || !is_secret_name(&b[start..eq]) {
            continue;
        }
        let value = eq + 1;
        let end = if b.get(value) == Some(&b'"') {
            b[value + 1..]
                .iter()
                .position(|&c| c == b'"')
                .map_or(b.len(), |p| value + 1 + p + 1)
        } else {
            b[value..]
                .iter()
                .position(|&c| is_delimiter(c))
                .map_or(b.len(), |p| value + p)
        };
        if end == value {
            continue;
        }
        let o = out.get_or_insert_with(|| String::with_capacity(s.len()));
        // Both ends sit next to ASCII bytes, so they are char boundaries.
        o.push_str(&s[copied..value]);
        o.push_str(REDACTED);
        copied = end;
        i = end;
    }
    match out {
        None => Cow::Borrowed(s),
        Some(mut o) => {
            o.push_str(&s[copied..]);
            Cow::Owned(o)
        }
    }
}

fn is_name_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.' | b'%')
}

fn is_delimiter(c: u8) -> bool {
    c.is_ascii_whitespace()
        || matches!(
            c,
            b'&' | b'#' | b'"' | b'\'' | b',' | b';' | b'<' | b'>' | b'\\' | b')' | b']' | b'}'
        )
}

fn decode_lower(name: &[u8]) -> Vec<u8> {
    let hex = |c: u8| (c as char).to_digit(16);
    let mut out = Vec::with_capacity(name.len());
    let mut i = 0;
    while i < name.len() {
        let decoded = if name[i] == b'%' {
            name.get(i + 1)
                .and_then(|&h| hex(h))
                .zip(name.get(i + 2).and_then(|&l| hex(l)))
                .map(|(h, l)| (h * 16 + l) as u8)
        } else {
            None
        };
        match decoded {
            Some(c) => {
                out.push(c.to_ascii_lowercase());
                i += 3;
            }
            None => {
                out.push(name[i].to_ascii_lowercase());
                i += 1;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_credentials_are_replaced() {
        let cases = [
            (
                "/emby/videos/1/stream?api_key=abc123&Static=true",
                "/emby/videos/1/stream?api_key=REDACTED&Static=true",
            ),
            ("/x?X-Emby-Token=t0k&y=1", "/x?X-Emby-Token=REDACTED&y=1"),
            ("/x?a=1&API_KEY=zz", "/x?a=1&API_KEY=REDACTED"),
            ("/x?api%5Fkey=zz#f", "/x?api%5Fkey=REDACTED#f"),
            (
                "/x?x-mediabrowser-token=q",
                "/x?x-mediabrowser-token=REDACTED",
            ),
            (
                "/x?AccessToken=q&token=r",
                "/x?AccessToken=REDACTED&token=REDACTED",
            ),
        ];
        for (input, want) in cases {
            assert_eq!(redact(input), want, "{input}");
        }
    }

    #[test]
    fn credentials_inside_free_text_are_replaced() {
        assert_eq!(
            redact("bad Location \"https://a.example.net/p?api_key=k1\": scheme"),
            "bad Location \"https://a.example.net/p?api_key=REDACTED\": scheme"
        );
        assert_eq!(
            redact("MediaBrowser Client=\"x\", Token=\"abc def\", Version=\"1\""),
            "MediaBrowser Client=\"x\", Token=REDACTED, Version=\"1\""
        );
        assert_eq!(
            redact("X-Emby-Authorization=a b"),
            "X-Emby-Authorization=REDACTED b"
        );
    }

    #[test]
    fn other_text_is_borrowed_unchanged() {
        for s in [
            "/emby/Items?ParentId=1&Fields=a,b",
            "/x?PlaySessionId=9&MediaSourceId=2",
            "a == b",
            "=leading",
            "api_key=",
            "",
        ] {
            assert!(matches!(redact(s), Cow::Borrowed(_)), "{s}");
        }
    }

    #[test]
    fn secret_names() {
        for n in [
            "api_key",
            "ApiKey",
            "token",
            "X-Emby-Token",
            "x%2Demby%2dtoken",
        ] {
            assert!(is_secret_name(n.as_bytes()), "{n}");
        }
        for n in ["key", "tokens", "api", "PlaySessionId", "%zz"] {
            assert!(!is_secret_name(n.as_bytes()), "{n}");
        }
    }
}
