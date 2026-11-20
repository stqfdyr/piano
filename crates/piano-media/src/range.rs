//! Byte ranges and the checks that let a body continue from another response.

/// The single byte range of a `Range: bytes=…` request header. Ends are inclusive, as
/// written on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ByteRange {
    /// `bytes=first-` or `bytes=first-last`.
    From { first: u64, last: Option<u64> },
    /// `bytes=-len`: the last `len` bytes.
    Suffix(u64),
}

impl ByteRange {
    /// Parses a `Range` value holding exactly one byte range; several ranges, other
    /// units and malformed values give `None`.
    pub fn parse(value: &[u8]) -> Option<Self> {
        let value = std::str::from_utf8(value).ok()?.trim();
        let spec = strip_prefix_ci(value, "bytes=")?.trim();
        if spec.contains(',') {
            return None;
        }
        let (a, b) = spec.split_once('-')?;
        let (a, b) = (a.trim(), b.trim());
        match (a.is_empty(), b.is_empty()) {
            (false, true) => Some(Self::From {
                first: number(a)?,
                last: None,
            }),
            (false, false) => {
                let (first, last) = (number(a)?, number(b)?);
                (first <= last).then_some(Self::From {
                    first,
                    last: Some(last),
                })
            }
            (true, false) => Some(Self::Suffix(number(b)?)).filter(|r| *r != Self::Suffix(0)),
            (true, true) => None,
        }
    }
}

/// A satisfied `Content-Range: bytes first-last/complete`; `complete` is `None` for `*`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContentRange {
    pub first: u64,
    pub last: u64,
    pub complete: Option<u64>,
}

impl ContentRange {
    pub fn parse(value: &[u8]) -> Option<Self> {
        let value = std::str::from_utf8(value).ok()?.trim();
        let rest = strip_prefix_ci(value, "bytes ")?.trim_start();
        let (range, complete) = rest.split_once('/')?;
        let complete = match complete.trim() {
            "*" => None,
            c => Some(number(c)?),
        };
        let (first, last) = range.trim().split_once('-')?;
        let (first, last) = (number(first)?, number(last)?);
        if first > last || complete.is_some_and(|c| last >= c) {
            return None;
        }
        Some(Self {
            first,
            last,
            complete,
        })
    }
}

/// The parts of a response head that decide whether its body can be continued.
#[derive(Debug, Clone, Copy, Default)]
pub struct Head<'a> {
    pub status: u16,
    pub content_range: Option<&'a [u8]>,
    pub content_length: Option<&'a [u8]>,
    pub accept_ranges: Option<&'a [u8]>,
    pub content_encoding: Option<&'a [u8]>,
    pub etag: Option<&'a [u8]>,
    pub last_modified: Option<&'a [u8]>,
}

/// Why a response cannot continue the body being sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Mismatch {
    #[error("status {0} instead of 206")]
    Status(u16),
    #[error("no satisfied Content-Range, or a length that disagrees with it")]
    ContentRange,
    #[error("range does not cover the resume offset")]
    Offset,
    #[error("complete length differs")]
    Length,
    #[error("ETag differs")]
    ETag,
    #[error("Last-Modified differs")]
    LastModified,
    #[error("Content-Encoding differs")]
    Encoding,
}

impl Mismatch {
    /// The upstream now serves a different representation, so no later response can
    /// continue the body either.
    pub fn is_changed(self) -> bool {
        matches!(
            self,
            Self::Length | Self::ETag | Self::LastModified | Self::Encoding
        )
    }
}

/// Where the body a client is receiving lies in the upstream representation, and what
/// identifies that representation. Built from the response head the client got.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resume {
    /// Offsets of the client's body in the representation: `[start, end)`.
    pub start: u64,
    pub end: u64,
    pub complete: u64,
    etag: Option<Vec<u8>>,
    last_modified: Option<Vec<u8>>,
    encoding: Option<Vec<u8>>,
}

impl Resume {
    /// `Some` when the body can be continued by a range request: a 206 with a known
    /// complete length, or a 200 with a length from a server that accepts byte ranges.
    /// A body of unknown length (a live transcode) has no stable offsets to resume at.
    pub fn of(head: &Head<'_>) -> Option<Self> {
        let length = match head.content_length {
            Some(v) => Some(parse_number(v)?),
            None => None,
        };
        let (start, end, complete) = match head.status {
            206 => {
                let cr = ContentRange::parse(head.content_range?)?;
                let complete = cr.complete?;
                if length.is_some_and(|l| l != cr.last - cr.first + 1) {
                    return None;
                }
                (cr.first, cr.last + 1, complete)
            }
            200 => {
                let ranges = head.accept_ranges?.trim_ascii();
                if !ranges.eq_ignore_ascii_case(b"bytes") {
                    return None;
                }
                let length = length?;
                (0, length, length)
            }
            _ => return None,
        };
        (start < end).then(|| Self {
            start,
            end,
            complete,
            etag: head.etag.map(<[u8]>::to_vec),
            last_modified: head.last_modified.map(<[u8]>::to_vec),
            encoding: head.content_encoding.map(<[u8]>::to_vec),
        })
    }

    /// The `Range` value for the rest of the body from absolute offset `pos`.
    pub fn range_from(&self, pos: u64) -> String {
        format!("bytes={pos}-{}", self.end - 1)
    }

    /// Checks the head of the response to [`Self::range_from`]`(pos)`. Returns the
    /// absolute offsets `[first, end)` its body covers. A validator the first response
    /// carried must come back unchanged; without validators only the complete length is
    /// compared.
    pub fn check(&self, head: &Head<'_>, pos: u64) -> Result<(u64, u64), Mismatch> {
        if head.status != 206 {
            return Err(Mismatch::Status(head.status));
        }
        let cr = head
            .content_range
            .and_then(ContentRange::parse)
            .ok_or(Mismatch::ContentRange)?;
        let length = match head.content_length {
            Some(v) => Some(parse_number(v).ok_or(Mismatch::ContentRange)?),
            None => None,
        };
        if length.is_some_and(|l| l != cr.last - cr.first + 1) {
            return Err(Mismatch::ContentRange);
        }
        if cr.complete != Some(self.complete) {
            return Err(Mismatch::Length);
        }
        if self.etag.is_some() && self.etag.as_deref() != head.etag {
            return Err(Mismatch::ETag);
        }
        if self.last_modified.is_some() && self.last_modified.as_deref() != head.last_modified {
            return Err(Mismatch::LastModified);
        }
        if self.encoding.as_deref() != head.content_encoding {
            return Err(Mismatch::Encoding);
        }
        if cr.first > pos || cr.last < pos {
            return Err(Mismatch::Offset);
        }
        Ok((cr.first, cr.last + 1))
    }
}

fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    s.get(..prefix.len())
        .filter(|p| p.eq_ignore_ascii_case(prefix))
        .map(|_| &s[prefix.len()..])
}

fn number(s: &str) -> Option<u64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

fn parse_number(v: &[u8]) -> Option<u64> {
    number(std::str::from_utf8(v).ok()?.trim())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_ranges() {
        let from = |first, last| Some(ByteRange::From { first, last });
        assert_eq!(ByteRange::parse(b"bytes=0-"), from(0, None));
        assert_eq!(ByteRange::parse(b"bytes=10-19"), from(10, Some(19)));
        assert_eq!(ByteRange::parse(b"Bytes= 5 - 5 "), from(5, Some(5)));
        assert_eq!(
            ByteRange::parse(b"bytes=-500"),
            Some(ByteRange::Suffix(500))
        );
        for bad in [
            &b"bytes=-0"[..],
            b"bytes=-",
            b"bytes=5-4",
            b"bytes=0-1,5-6",
            b"items=0-1",
            b"bytes=+1-2",
            b"bytes=a-",
            b"bytes=99999999999999999999-",
        ] {
            assert_eq!(ByteRange::parse(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn content_ranges() {
        assert_eq!(
            ContentRange::parse(b"bytes 0-99/1000"),
            Some(ContentRange {
                first: 0,
                last: 99,
                complete: Some(1000)
            })
        );
        assert_eq!(
            ContentRange::parse(b"bytes 5-9/*").map(|c| c.complete),
            Some(None)
        );
        for bad in [
            &b"bytes */1000"[..],
            b"bytes 9-5/1000",
            b"bytes 0-1000/1000",
            b"bytes 0-1",
            b"items 0-1/2",
        ] {
            assert_eq!(ContentRange::parse(bad), None, "{bad:?}");
        }
    }

    fn partial<'a>(cr: &'a [u8], etag: Option<&'a [u8]>) -> Head<'a> {
        Head {
            status: 206,
            content_range: Some(cr),
            etag,
            ..Head::default()
        }
    }

    #[test]
    fn resumable_heads() {
        let r = Resume::of(&partial(b"bytes 100-199/1000", Some(b"\"a\""))).unwrap();
        assert_eq!((r.start, r.end, r.complete), (100, 200, 1000));
        assert_eq!(r.range_from(150), "bytes=150-199");

        let whole = Head {
            status: 200,
            content_length: Some(b"1000"),
            accept_ranges: Some(b"bytes"),
            ..Head::default()
        };
        let r = Resume::of(&whole).unwrap();
        assert_eq!((r.start, r.end, r.complete), (0, 1000, 1000));

        // Unknown length, no range support, unknown complete length, wrong length.
        let live = Head {
            status: 200,
            accept_ranges: Some(b"bytes"),
            ..Head::default()
        };
        let no_ranges = Head {
            accept_ranges: Some(b"none"),
            ..whole
        };
        let star = partial(b"bytes 0-9/*", None);
        let short = Head {
            content_length: Some(b"5"),
            ..partial(b"bytes 0-9/100", None)
        };
        for h in [live, no_ranges, star, short] {
            assert_eq!(Resume::of(&h), None, "{h:?}");
        }
        assert_eq!(
            Resume::of(&Head {
                status: 404,
                ..whole
            }),
            None
        );
    }

    #[test]
    fn continuation_checks() {
        let r = Resume::of(&partial(b"bytes 100-199/1000", Some(b"\"a\""))).unwrap();
        assert_eq!(
            r.check(&partial(b"bytes 150-199/1000", Some(b"\"a\"")), 150),
            Ok((150, 200))
        );
        // A response starting before the offset is usable: the overlap is skipped.
        assert_eq!(
            r.check(&partial(b"bytes 140-999/1000", Some(b"\"a\"")), 150),
            Ok((140, 1000))
        );
        let long = Head {
            content_length: Some(b"51"),
            ..partial(b"bytes 150-199/1000", Some(b"\"a\""))
        };
        assert_eq!(r.check(&long, 150), Err(Mismatch::ContentRange));
        let cases: [(Head<'_>, Mismatch); 6] = [
            (
                Head {
                    status: 200,
                    ..Head::default()
                },
                Mismatch::Status(200),
            ),
            (partial(b"garbage", Some(b"\"a\"")), Mismatch::ContentRange),
            (
                partial(b"bytes 151-199/1000", Some(b"\"a\"")),
                Mismatch::Offset,
            ),
            (
                partial(b"bytes 150-199/1001", Some(b"\"a\"")),
                Mismatch::Length,
            ),
            (
                partial(b"bytes 150-199/1000", Some(b"\"b\"")),
                Mismatch::ETag,
            ),
            (partial(b"bytes 150-199/1000", None), Mismatch::ETag),
        ];
        for (head, want) in cases {
            assert_eq!(r.check(&head, 150), Err(want), "{head:?}");
        }
        assert!(Mismatch::ETag.is_changed());
        assert!(!Mismatch::Status(503).is_changed());

        // Without validators the complete length is all there is to compare.
        let bare = Resume::of(&partial(b"bytes 0-9/10", None)).unwrap();
        assert_eq!(
            bare.check(&partial(b"bytes 5-9/10", Some(b"\"x\"")), 5),
            Ok((5, 10))
        );
        let lm = Resume::of(&Head {
            last_modified: Some(b"Tue, 01 Jan 2030 00:00:00 GMT"),
            ..partial(b"bytes 0-9/10", None)
        })
        .unwrap();
        assert_eq!(
            lm.check(&partial(b"bytes 5-9/10", None), 5),
            Err(Mismatch::LastModified)
        );
    }
}
