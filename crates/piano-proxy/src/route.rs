//! Route classes: what a request path is, by Emby semantics.
//!
//! Matching ignores ASCII case and an optional leading `/emby` segment, and does not
//! allocate.

use std::time::Duration;

/// What a request is; decides timeouts, retries, caching and rewriting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RouteClass {
    /// Video and audio streams and downloads.
    Media,
    Subtitle,
    Image,
    PlaybackInfo,
    /// Server information that carries upstream host names.
    Info,
    /// The Emby websocket.
    Socket,
    #[default]
    Api,
    /// Answered by piano itself.
    Local,
}

impl RouteClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Media => "media",
            Self::Subtitle => "subtitle",
            Self::Image => "image",
            Self::PlaybackInfo => "playback_info",
            Self::Info => "info",
            Self::Socket => "socket",
            Self::Api => "api",
            Self::Local => "local",
        }
    }

    /// Longest wait for the client to accept more response bytes.
    pub fn downstream_write_timeout(self) -> Duration {
        match self {
            Self::Media => Duration::from_secs(300),
            _ => Duration::from_secs(60),
        }
    }

    /// Whether either side may legitimately stay silent for any length of time, so
    /// silence must not end the request. Only a dead peer does, which TCP keepalive
    /// detects.
    pub fn may_idle(self) -> bool {
        matches!(self, Self::Socket)
    }
}

/// Health check answered locally on every site.
pub const HEALTH_PATH: &str = "/__piano/health";

/// Up to five path segments, without the leading `/emby` and a trailing empty segment.
fn segments(path: &str) -> ([&str; 5], usize) {
    let path = path.strip_prefix('/').unwrap_or(path);
    let path = path.strip_suffix('/').unwrap_or(path);
    let mut out = [""; 5];
    let mut n = 0;
    let mut iter = path.split('/').peekable();
    if iter.peek().is_some_and(|s| s.eq_ignore_ascii_case("emby")) {
        iter.next();
    }
    for s in iter {
        if n == out.len() {
            break;
        }
        out[n] = s;
        n += 1;
    }
    (out, n)
}

fn is(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

fn starts(a: &str, prefix: &str) -> bool {
    a.get(..prefix.len())
        .is_some_and(|p| p.eq_ignore_ascii_case(prefix))
}

/// Classifies a request path (without query). `Local` is never returned here; blocking
/// and the health check are decided per site.
pub fn classify(path: &str) -> RouteClass {
    let (s, n) = segments(path);
    match (s[0], n) {
        ("", _) | (_, 0) => RouteClass::Api,
        (v, _) if is(v, "videos") && n >= 3 => {
            if is(s[2], "subtitles") || (n >= 4 && is(s[3], "subtitles")) {
                RouteClass::Subtitle
            } else if ["stream", "original", "master", "main", "live", "hls"]
                .iter()
                .any(|p| starts(s[2], p))
            {
                RouteClass::Media
            } else {
                RouteClass::Api
            }
        }
        (a, _) if is(a, "audio") && n >= 3 => RouteClass::Media,
        (i, _) if is(i, "items") && n >= 3 && is(s[2], "download") => RouteClass::Media,
        (i, 3) if is(i, "items") && is(s[2], "playbackinfo") => RouteClass::PlaybackInfo,
        (p, _) if is(p, "play") && n >= 3 && is(s[1], "video") => RouteClass::Media,
        (p, _) if is(p, "play") && n >= 3 && is(s[1], "subtitle") => RouteClass::Subtitle,
        (sys, 2) if is(sys, "system") && is(s[1], "info") => RouteClass::Info,
        (sys, 3)
            if is(sys, "system")
                && ((is(s[1], "info") && is(s[2], "public"))
                    || (is(s[1], "ext") && is(s[2], "serverdomains"))) =>
        {
            RouteClass::Info
        }
        (w, 1) if is(w, "embywebsocket") || is(w, "socket") => RouteClass::Socket,
        // /Items/{id}/Images/..., /Users/{id}/Images/..., /Persons/{name}/Images/...
        (_, _) if n >= 3 && is(s[2], "images") => RouteClass::Image,
        _ => RouteClass::Api,
    }
}

/// Whether `path` is the endpoint listing the upstream's own domain names.
pub fn is_server_domains(path: &str) -> bool {
    let (s, n) = segments(path);
    n == 3 && is(s[0], "system") && is(s[1], "ext") && is(s[2], "serverdomains")
}

/// Path prefixes a site answers with 404, stored without a leading `/emby`.
#[derive(Debug, Default, Clone)]
pub struct BlockList(Vec<String>);

/// `path` without a leading `/emby` segment.
fn strip_emby(path: &str) -> &str {
    match path.get(..5) {
        Some(p) if p.eq_ignore_ascii_case("/emby") => match path.as_bytes().get(5) {
            None => "/",
            Some(b'/') => &path[5..],
            Some(_) => path,
        },
        _ => path,
    }
}

impl BlockList {
    pub fn new<S: AsRef<str>>(prefixes: &[S]) -> Self {
        Self(
            prefixes
                .iter()
                .map(|p| strip_emby(p.as_ref()).to_owned())
                .collect(),
        )
    }

    pub fn blocks(&self, path: &str) -> bool {
        let path = strip_emby(path);
        self.0.iter().any(|p| starts(path, p))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use RouteClass::*;

    #[test]
    fn classifies_emby_paths() {
        for (path, class) in [
            ("/emby/Videos/123/stream.mkv", Media),
            ("/Videos/123/stream", Media),
            ("/videos/123/original.mp4", Media),
            ("/emby/videos/123/master.m3u8", Media),
            ("/videos/123/hls1/main/0.ts", Media),
            ("/Audio/9/universal", Media),
            ("/emby/Items/5/Download", Media),
            ("/emby/Play/video/abc/stream", Media),
            ("/emby/Videos/1/ms1/Subtitles/3/Stream.srt", Subtitle),
            ("/Videos/1/Subtitles/3/Stream.srt", Subtitle),
            ("/play/subtitle/a/b", Subtitle),
            ("/emby/Items/5/Images/Primary", Image),
            ("/Users/u1/Images/Primary", Image),
            ("/emby/Items/5/PlaybackInfo", PlaybackInfo),
            ("/emby/System/Info", Info),
            ("/System/Info/Public", Info),
            ("/system/info/public/", Info),
            ("/emby/System/Ext/ServerDomains", Info),
            ("/embywebsocket", Socket),
            ("/socket", Socket),
            ("/emby/Users/u1/Items", Api),
            ("/emby/Videos/1/AdditionalParts", Api),
            ("/System/Info/Other", Api),
            ("/emby", Api),
            ("/", Api),
            ("", Api),
            ("/videos", Api),
            ("/embyx/Videos/1/stream", Api),
        ] {
            assert_eq!(classify(path), class, "{path}");
        }
    }

    #[test]
    fn server_domains_path() {
        assert!(is_server_domains("/emby/System/Ext/ServerDomains"));
        assert!(is_server_domains("/system/ext/serverdomains/"));
        assert!(!is_server_domains("/System/Info/Public"));
        assert!(!is_server_domains("/System/Ext/ServerDomains/x"));
    }

    #[test]
    fn block_list_ignores_case_and_emby_prefix() {
        let b = BlockList::new(&["/emby/api/danmu/", "/System/Ext/ServerDomains"]);
        assert!(b.blocks("/emby/api/danmu/1"));
        assert!(b.blocks("/EMBY/Api/Danmu/1"));
        assert!(b.blocks("/api/danmu/"));
        assert!(b.blocks("/emby/System/Ext/ServerDomains"));
        assert!(b.blocks("/system/ext/serverdomains"));
        assert!(!b.blocks("/api/danmu"));
        assert!(!b.blocks("/embyapi/danmu/1"));
        assert!(!b.blocks("/emby/System/Info"));
        assert!(!BlockList::default().blocks("/anything"));
    }
}
