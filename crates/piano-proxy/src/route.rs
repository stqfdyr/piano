//! Route classes: what a request path is, by Emby semantics.
//!
//! Matching ignores ASCII case and an optional leading `/emby` segment, and does not
//! allocate.

use http::Method;
use piano_telemetry::{Kind, Ttfb};
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
    pub const ALL: [Self; 8] = [
        Self::Media,
        Self::Subtitle,
        Self::Image,
        Self::PlaybackInfo,
        Self::Info,
        Self::Socket,
        Self::Api,
        Self::Local,
    ];

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

    /// What the request's bytes count as.
    pub fn kind(self) -> Kind {
        match self {
            Self::Media => Kind::Media,
            Self::Image => Kind::Image,
            Self::Socket => Kind::Socket,
            _ => Kind::Other,
        }
    }

    /// Which time-to-first-byte histogram a request counts in. Browsing is what a
    /// client waits on: API reads, server and playback information. Writes such as
    /// playback progress reports are quick and frequent and would hide it.
    pub fn ttfb(self, method: &Method) -> Option<Ttfb> {
        match self {
            Self::Media => Some(Ttfb::Media),
            Self::Image => Some(Ttfb::Image),
            Self::PlaybackInfo | Self::Info => Some(Ttfb::Browse),
            Self::Api if method == Method::GET => Some(Ttfb::Browse),
            _ => None,
        }
    }

    /// Longest wait for the client to accept more response bytes. Players stop reading
    /// once their buffer is full, for well over a minute; a shorter limit cuts them only
    /// to have them reconnect at once.
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

    /// Whether the request may share an upstream HTTP/2 connection with others. Media
    /// keeps a connection to itself: TCP's own flow control bounds what a slow client
    /// makes the relay hold, and a stalled stream is replaced by a new connection. The
    /// websocket needs an HTTP/1.1 upgrade.
    pub fn multiplexed(self) -> bool {
        !matches!(self, Self::Media | Self::Socket)
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
            ("/Users/Public", Api),
            ("//a/Images", Api),
            ("/emby/Items/5/Similar", Api),
            ("/Play/x", Api),
            ("/x/subtitle/y", Api),
            ("/Users/Info", Api),
            ("/System/Ext/Other", Api),
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
    fn all_lists_every_class_once() {
        // No wildcard: a new class does not compile until it has a place here and in ALL.
        let place = |c: RouteClass| match c {
            Media => 0,
            Subtitle => 1,
            Image => 2,
            PlaybackInfo => 3,
            Info => 4,
            Socket => 5,
            Api => 6,
            Local => 7,
        };
        for (i, c) in RouteClass::ALL.into_iter().enumerate() {
            assert_eq!(place(c), i, "{c:?}");
        }
        let names: std::collections::HashSet<_> =
            RouteClass::ALL.iter().map(|c| c.as_str()).collect();
        assert_eq!(names.len(), RouteClass::ALL.len());
    }

    #[test]
    fn traffic_kinds() {
        for (class, kind) in [
            (Media, Kind::Media),
            (Image, Kind::Image),
            (Socket, Kind::Socket),
            (Subtitle, Kind::Other),
            (PlaybackInfo, Kind::Other),
            (Info, Kind::Other),
            (Api, Kind::Other),
            (Local, Kind::Other),
        ] {
            assert_eq!(class.kind(), kind, "{class:?}");
        }
    }

    #[test]
    fn times_what_a_client_waits_on() {
        let (get, post) = (Method::GET, Method::POST);
        for (class, get_ttfb, post_ttfb) in [
            (Media, Some(Ttfb::Media), Some(Ttfb::Media)),
            (Image, Some(Ttfb::Image), Some(Ttfb::Image)),
            (PlaybackInfo, Some(Ttfb::Browse), Some(Ttfb::Browse)),
            (Info, Some(Ttfb::Browse), Some(Ttfb::Browse)),
            (Api, Some(Ttfb::Browse), None),
            (Subtitle, None, None),
            (Socket, None, None),
            (Local, None, None),
        ] {
            assert_eq!(class.ttfb(&get), get_ttfb, "{class:?} GET");
            assert_eq!(class.ttfb(&post), post_ttfb, "{class:?} POST");
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
        assert!(!b.blocks("/embz/api/danmu/1"));
        assert!(!b.blocks("/emby/System/Info"));
        assert!(!BlockList::default().blocks("/anything"));
    }
}
