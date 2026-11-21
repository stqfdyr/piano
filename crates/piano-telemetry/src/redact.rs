//! Credential removal applied to everything piano logs.
//!
//! Clients authenticate to Emby with query parameters (`api_key`, `X-Emby-Token`, ...)
//! and with headers (`X-Emby-Token: ...`, `X-Emby-Authorization: ... Token="..."`).
//! Any `name=value` or `name: value` pair whose name marks a credential has its value
//! replaced, wherever it appears in the text, including inside Debug output, where
//! names are quoted and quotes in values are escaped.

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
/// follows `=`, `: ` or `":`; a value in double quotes (escaped ones included) ends at
/// the closing quote, any other at the next delimiter. An authorization value that is a
/// scheme followed by a credential (`Bearer ...`) is replaced whole; one followed by
/// parameters (`MediaBrowser Token="..."`) loses the scheme, and its parameters are
/// judged by name.
pub fn redact(s: &str) -> Cow<'_, str> {
    let b = s.as_bytes();
    let mut out: Option<String> = None;
    let mut copied = 0;
    let mut i = 0;
    while let Some(off) = b[i..].iter().position(|&c| c == b'=' || c == b':') {
        let sep = i + off;
        i = sep + 1;
        let value = match b[sep] {
            b':' if b.get(sep + 1) == Some(&b' ') => sep + 2,
            // A quoted name, as in compact JSON.
            b':' if sep > 0 && b[sep - 1] == b'"' => sep + 1,
            b':' => continue,
            _ => sep + 1,
        };
        let name = name_before(b, sep);
        if !is_secret_name(name) {
            continue;
        }
        let end = value_end(b, value, decode_lower(name).ends_with(b"authorization"));
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

/// The name ending at `sep`, without the quotes Debug output puts around it; empty if
/// none.
fn name_before(b: &[u8], sep: usize) -> &[u8] {
    let mut end = sep;
    if end > 0 && b[end - 1] == b'"' {
        end -= 1;
        if end > 0 && b[end - 1] == b'\\' {
            end -= 1;
        }
    }
    let start = b[..end]
        .iter()
        .rposition(|&c| !is_name_byte(c))
        .map_or(0, |p| p + 1);
    &b[start..end]
}

/// Where the value starting at `v` ends.
fn value_end(b: &[u8], v: usize, authorization: bool) -> usize {
    let rest = &b[v..];
    if rest.starts_with(br#"\""#) {
        // Quoted inside an escaped string: the closing quote is escaped too.
        return rest[2..]
            .windows(2)
            .position(|w| w == br#"\""#)
            .map_or(b.len(), |p| v + 2 + p + 2);
    }
    if rest.first() == Some(&b'"') {
        let mut j = 1;
        while j < rest.len() {
            match rest[j] {
                b'\\' => j += 2,
                b'"' => return v + j + 1,
                _ => j += 1,
            }
        }
        return b.len();
    }
    let word_end = |from: usize| {
        b[from..]
            .iter()
            .position(|&c| is_delimiter(c))
            .map_or(b.len(), |p| from + p)
    };
    let end = word_end(v);
    if authorization && b.get(end) == Some(&b' ') {
        let next = word_end(end + 1);
        if is_token68(&b[end + 1..next], &b[next..]) {
            return next;
        }
    }
    end
}

/// Whether `word`, after an authorization scheme and a space, is the credential (RFC
/// 9110 token68: no `=` but trailing padding) rather than a `name=` parameter.
fn is_token68(word: &[u8], after: &[u8]) -> bool {
    let padding = word.iter().rev().take_while(|&&c| c == b'=').count();
    let opens_value = after.first() == Some(&b'"') || after.starts_with(br#"\""#);
    padding < word.len()
        && !word[..word.len() - padding].contains(&b'=')
        && !(padding > 0 && opens_value)
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
            redact("X-Emby-Authorization=a b, c=1"),
            "X-Emby-Authorization=REDACTED, c=1"
        );
    }

    #[test]
    fn header_forms_are_replaced() {
        let cases = [
            ("X-Emby-Token: t0k\r\n", "X-Emby-Token: REDACTED\r\n"),
            (
                "Authorization: Bearer abc.def\r\n",
                "Authorization: REDACTED\r\n",
            ),
            (
                "Authorization: Basic dXNlcjpw==\r\n",
                "Authorization: REDACTED\r\n",
            ),
            (
                r#"X-Emby-Authorization: MediaBrowser Client="c", Token="t0k""#,
                r#"X-Emby-Authorization: REDACTED Client="c", Token=REDACTED"#,
            ),
            (
                r#"X-Emby-Authorization: MediaBrowser Token="t0k""#,
                r#"X-Emby-Authorization: REDACTED Token=REDACTED"#,
            ),
            // The fields the logger appends after the message stay.
            (
                "authorization=abc rid=12 cid=3",
                "authorization=REDACTED rid=12 cid=3",
            ),
            // A quote left open runs to the end.
            (r#"token="abc"#, "token=REDACTED"),
            (r#"token="ab\"#, "token=REDACTED"),
            (
                r#"{"AccessToken":"t0k","User":"u"}"#,
                r#"{"AccessToken":REDACTED,"User":"u"}"#,
            ),
            // Debug output of a header map: quoted names, escaped quotes in values.
            (
                r#"{"x-emby-token": "t0k", "accept": "*/*"}"#,
                r#"{"x-emby-token": REDACTED, "accept": "*/*"}"#,
            ),
            (
                r#"{"x-emby-authorization": "MediaBrowser Client=\"c\", Token=\"t0k\"", "a": "b"}"#,
                r#"{"x-emby-authorization": REDACTED, "a": "b"}"#,
            ),
            (
                r#"note="Token=\"t0k\"" x=1"#,
                r#"note="Token=REDACTED" x=1"#,
            ),
            (
                r#"note="{\"x-emby-token\": \"t0k\"}""#,
                r#"note="{\"x-emby-token\": REDACTED}""#,
            ),
            // Debug output of raw request bytes.
            (
                r#"b"GET / HTTP/1.1\r\nX-Emby-Token: t0k\r\nX-Emby-Authorization: MediaBrowser Token=\"t1\"\r\n""#,
                r#"b"GET / HTTP/1.1\r\nX-Emby-Token: REDACTED\r\nX-Emby-Authorization: REDACTED Token=REDACTED\r\n""#,
            ),
        ];
        for (input, want) in cases {
            assert_eq!(redact(input), want, "{input}");
        }
    }

    #[test]
    fn debug_output_of_a_request_has_no_credentials() {
        let targets: [&[u8]; 3] = [
            b"/x?api_key=s1",
            b"https://example.com/x?api_key=s1",
            b"/x\xff?api_key=s1",
        ];
        for target in targets {
            let mut req = pingora_http::RequestHeader::build("GET", target, None).unwrap();
            req.insert_header("X-Emby-Token", "s2").unwrap();
            req.insert_header(
                "X-Emby-Authorization",
                r#"MediaBrowser Client="c", Token="s3""#,
            )
            .unwrap();
            req.insert_header("Authorization", "Bearer s4").unwrap();
            let line = redact(&format!("{req:?}")).into_owned();
            for secret in ["s1", "s2", "s3", "s4"] {
                // Also as a list of byte values, as a derived Debug prints a byte slice.
                let as_bytes = secret.bytes().map(|b| b.to_string()).collect::<Vec<_>>();
                assert!(!line.contains(secret), "{secret} in {line}");
                assert!(!line.contains(&as_bytes.join(", ")), "{secret} in {line}");
            }
        }
    }

    #[test]
    fn other_text_is_borrowed_unchanged() {
        for s in [
            "/emby/Items?ParentId=1&Fields=a,b",
            "/x?PlaySessionId=9&MediaSourceId=2",
            "a == b",
            "/emby/token:abc/x",
            "https://token.example.net:8443/x",
            "token:",
            ":x",
            "\"=x",
            "\\\"=x",
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
