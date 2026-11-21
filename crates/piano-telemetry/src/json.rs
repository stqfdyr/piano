//! A JSON object written as one line, without a serializer.

use std::fmt::Write as _;

/// One JSON object under construction. Keys are written as given; callers pass
/// constant names that need no escaping.
#[derive(Debug)]
pub struct JsonLine {
    buf: String,
    /// Whether the next member or element needs a comma before it.
    comma: bool,
}

impl JsonLine {
    pub fn with_capacity(n: usize) -> Self {
        let mut buf = String::with_capacity(n);
        buf.push('{');
        Self { buf, comma: false }
    }

    fn key(&mut self, k: &str) {
        self.sep();
        self.buf.push('"');
        self.buf.push_str(k);
        self.buf.push_str("\":");
    }

    fn sep(&mut self) {
        if self.comma {
            self.buf.push(',');
        }
        self.comma = true;
    }

    pub fn str(&mut self, k: &str, v: &str) -> &mut Self {
        self.key(k);
        escape_into(&mut self.buf, v);
        self
    }

    /// Bytes that should be text; invalid UTF-8 is replaced.
    pub fn bytes(&mut self, k: &str, v: &[u8]) -> &mut Self {
        self.str(k, &String::from_utf8_lossy(v))
    }

    pub fn num(&mut self, k: &str, v: u64) -> &mut Self {
        self.key(k);
        let _ = write!(self.buf, "{v}");
        self
    }

    pub fn bool(&mut self, k: &str, v: bool) -> &mut Self {
        self.key(k);
        self.buf.push_str(if v { "true" } else { "false" });
        self
    }

    pub fn null(&mut self, k: &str) -> &mut Self {
        self.key(k);
        self.buf.push_str("null");
        self
    }

    /// Opens an array member; close it with [`Self::end_array`].
    pub fn array(&mut self, k: &str) -> &mut Self {
        self.key(k);
        self.buf.push('[');
        self.comma = false;
        self
    }

    pub fn end_array(&mut self) -> &mut Self {
        self.buf.push(']');
        self.comma = true;
        self
    }

    /// Opens an object element of the current array; close it with [`Self::end_object`].
    pub fn object(&mut self) -> &mut Self {
        self.sep();
        self.buf.push('{');
        self.comma = false;
        self
    }

    pub fn end_object(&mut self) -> &mut Self {
        self.buf.push('}');
        self.comma = true;
        self
    }

    /// The finished object followed by a newline.
    pub fn finish(mut self) -> String {
        self.buf.push_str("}\n");
        self.buf
    }
}

/// Appends `s` as a JSON string literal.
pub fn escape_into(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            // C1 controls too: a terminal showing the log acts on them.
            c if c.is_control() => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_nested_members() {
        let mut j = JsonLine::with_capacity(64);
        j.str("a", "x").num("n", 7).null("z").array("up");
        j.object().num("s", 302).end_object();
        j.object().bool("r", true).end_object();
        j.end_array().bytes("b", b"\xff!");
        assert_eq!(
            j.finish(),
            "{\"a\":\"x\",\"n\":7,\"z\":null,\"up\":[{\"s\":302},{\"r\":true}],\"b\":\"\u{fffd}!\"}\n"
        );
    }

    #[test]
    fn escapes_strings() {
        let mut s = String::new();
        escape_into(&mut s, "q\"b\\n\nc\x01\x7fé ~");
        assert_eq!(s, "\"q\\\"b\\\\n\\nc\\u0001\\u007fé ~\"");
    }

    #[test]
    fn escapes_c1_controls() {
        let mut s = String::new();
        escape_into(&mut s, "\u{9b}");
        assert_eq!(s, format!("\"{}u009b\"", '\\'));
    }

    #[test]
    fn empty_array() {
        let mut j = JsonLine::with_capacity(8);
        j.array("a").end_array().num("b", 1);
        assert_eq!(j.finish(), "{\"a\":[],\"b\":1}\n");
    }
}
