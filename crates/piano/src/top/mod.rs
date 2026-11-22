//! `piano top`: a full-screen view of what the daemon is doing now. Asks the control
//! socket for `live` at each interval and reads new access log lines for problems.

mod model;
mod view;

use crate::logtail::Follower;
use model::{History, Problems, View};
use piano_ctl::proto::Live;
use ratatui::DefaultTerminal;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Bytes of the access log read at start for recent problems.
const BACKLOG: u64 = 256 * 1024;

pub struct Options {
    pub socket: PathBuf,
    pub interval: Duration,
}

/// Asks the daemon for `live` once.
pub fn ask(socket: &Path, timeout: Duration) -> Result<Live, String> {
    let v = piano_ctl::call(socket, "live", timeout).map_err(|e| e.to_string())?;
    serde_json::from_value(v).map_err(|e| format!("unexpected reply from the daemon: {e}"))
}

struct State {
    history: History,
    view: Option<View>,
    problems: Problems,
    /// The access log the daemon writes, and the reader, or why it cannot be read.
    log: Option<(String, Result<Follower, String>)>,
    /// Why the last read of an open log failed; cleared by the next good one.
    log_read: Option<String>,
    clock: String,
    error: Option<String>,
    paused: bool,
    full: bool,
}

impl State {
    fn new() -> Self {
        Self {
            history: History::default(),
            view: None,
            problems: Problems::default(),
            log: None,
            log_read: None,
            clock: String::new(),
            error: None,
            paused: false,
            full: false,
        }
    }

    fn log_error(&self) -> Option<String> {
        match (&self.log, &self.log_read) {
            (Some((path, Err(e))), _) | (Some((path, Ok(_))), Some(e)) => {
                Some(format!("cannot read {path}: {e}"))
            }
            _ => None,
        }
    }

    fn refresh(&mut self, opts: &Options) {
        match ask(&opts.socket, opts.interval.max(Duration::from_secs(2))) {
            Ok(live) => {
                self.error = None;
                self.follow(live.access_log.as_deref());
                self.history.push(live);
                self.view = View::of(&self.history);
                self.clock = chrono::Local::now().format("%H:%M:%S").to_string();
            }
            Err(e) => self.error = Some(e),
        }
        if let Some((_, Ok(log))) = &mut self.log {
            let problems = &mut self.problems;
            let read = log.poll(|l| {
                problems.add(l);
                Ok(())
            });
            self.log_read = read.err().map(|e| e.to_string());
        }
    }

    /// Opens the access log the daemon writes, again when that changes, and tries
    /// again at each refresh while it cannot be read.
    fn follow(&mut self, path: Option<&str>) {
        let Some(path) = path else {
            self.log = None;
            self.log_read = None;
            return;
        };
        match &self.log {
            Some((p, Ok(_))) if p == path => return,
            Some((p, _)) if p == path => {}
            // Problems of another file are not this one's.
            _ => self.problems = Problems::default(),
        }
        self.log_read = None;
        let log = Follower::open(Path::new(path), Some(BACKLOG)).map_err(|e| e.to_string());
        self.log = Some((path.to_owned(), log));
    }

    fn draw(&self, terminal: &mut DefaultTerminal, opts: &Options) -> io::Result<()> {
        let series = self.history.sent_series();
        let problems: Vec<_> = self.problems.list.iter().cloned().collect();
        let log_error = self.log_error();
        let screen = view::Screen {
            view: self.view.as_ref(),
            series: &series,
            problems: &problems,
            log_error: log_error.as_deref(),
            clock: self.clock.clone(),
            full_addresses: self.full,
            paused: self.paused,
            error: self.error.as_deref(),
            interval_secs: opts.interval.as_secs_f64(),
        };
        terminal.draw(|f| view::draw(f, &screen))?;
        Ok(())
    }
}

/// Runs the view until the user quits.
pub fn run(opts: &Options) -> io::Result<()> {
    let mut terminal = ratatui::init();
    let result = event_loop(&mut terminal, opts);
    ratatui::restore();
    result
}

fn event_loop(terminal: &mut DefaultTerminal, opts: &Options) -> io::Result<()> {
    let mut s = State::new();
    s.draw(terminal, opts)?;
    loop {
        let due = Instant::now() + opts.interval;
        if !s.paused {
            s.refresh(opts);
        }
        s.draw(terminal, opts)?;
        loop {
            let left = due.saturating_duration_since(Instant::now());
            if left.is_zero() || !event::poll(left)? {
                break;
            }
            match event::read()? {
                Event::Key(k) if k.kind == KeyEventKind::Press => match k.code {
                    KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                    KeyCode::Char('c') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                        return Ok(());
                    }
                    KeyCode::Char('p') => s.paused = !s.paused,
                    KeyCode::Char('f') => s.full = !s.full,
                    _ => continue,
                },
                Event::Resize(..) => {}
                _ => continue,
            }
            s.draw(terminal, opts)?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::State;
    use super::model::{History, Problems, View};
    use super::view::{Screen, draw};
    use piano_ctl::proto::Live;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn live() -> Live {
        serde_json::from_value(serde_json::json!({
            "schema": 1, "version": "0.1.0", "pid": 1, "uptime_ms": 45000,
            "connections": {"open": 4, "handshaking": 0, "limit": 1024, "closed_at_limit": 0,
                "handshake_timeouts": 0, "handshake_errors": 0, "denied": 0, "media_streams": 1},
            "access_log": "/var/log/piano/access.log",
            "ttfb_bounds_ms": [],
            "sites": [{"name": "media", "total": {"requests": 10, "status": {"2xx": 9, "5xx": 1},
                "ends": {}, "upstream_attempts": 10, "reused": 8, "bytes_sent": 5000, "bytes_fetched": 5000},
                "ttfb": {"browse": [0,0,0,0,0,0,0,0,0,0,0,0,0,3,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
                         "image": [], "media": []}}],
            "streams": [{"rid": "r1", "site": "media", "client": "203.0.113.9", "path": "/emby/videos/424242/stream",
                "range": null, "age_ms": 30000, "sent": 2000000000, "position": 2100000000,
                "size": 8300000000u64, "ttfb_ms": 180, "idle_ms": 50, "requests": 1, "hedges": 0,
                "resumes": 0, "in_flight": 1, "client_holds": false, "upstream": "vod1.example.com"}],
            "cache": {"schema": 2, "missing": 0, "redirects": 0, "fetched": 0, "coalesced": 0,
                "missing_hits": 0, "shed": 0, "redirect_hits": 0, "upstreams": [{"upstream": "v1.example.com:443",
                "burst": 200.0, "per_sec": 2.5, "tokens": 180.0, "paused_secs": null, "limited": 0, "waiting": 0}]}
        }))
        .unwrap()
    }

    fn render(width: u16, height: u16, full: bool) -> String {
        render_with(width, height, full, None)
    }

    fn render_with(width: u16, height: u16, full: bool, log_error: Option<&str>) -> String {
        let mut h = History::default();
        h.push(live());
        let v = View::of(&h).unwrap();
        let mut problems = Problems::default();
        problems.add(r#"{"ts":"2026-11-20T08:01:02.345Z","site":"media","status":502,"path":"/emby/Items","end":"upstream_timeout"}"#);
        let list: Vec<_> = problems.list.iter().cloned().collect();
        let screen = Screen {
            view: Some(&v),
            series: &[1, 5, 3],
            problems: &list,
            log_error,
            clock: "12:03:11".into(),
            full_addresses: full,
            paused: false,
            error: None,
            interval_secs: 1.0,
        };
        let mut t = Terminal::new(TestBackend::new(width, height)).unwrap();
        t.draw(|f| draw(f, &screen)).unwrap();
        let buf = t.backend().buffer().clone();
        let mut out = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                out.push_str(buf[(x, y)].symbol());
            }
            out.push('\n');
        }
        out
    }

    #[test]
    fn a_frame_shows_streams_sites_budgets_and_problems() {
        let out = render(160, 30, false);
        for want in [
            "piano",
            "4 connections",
            "Streams",
            "203.0.*.*",
            "424242",
            "25%",
            "playing",
            "vod1.example.com",
            "Sites",
            "last 45s",
            "media",
            "Upstream budget",
            "180/200",
            "Problems",
            "upstream_timeout",
            "q quit",
        ] {
            assert!(out.contains(want), "{want:?} missing from\n{out}");
        }
        assert!(!out.contains("203.0.113.9"), "{out}");
        assert!(render(160, 30, true).contains("203.0.113.9"));
    }

    #[test]
    fn an_access_log_that_cannot_be_read_is_said_so() {
        let mut s = State::new();
        let dir = std::env::temp_dir().join(format!("piano-top-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("access.log");
        let path = path.to_str().unwrap();
        s.follow(Some(path));
        let e = s.log_error().unwrap();
        assert!(e.starts_with(&format!("cannot read {path}: ")), "{e}");
        // Tried again at the next refresh, and gone once the file is there.
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(path, "").unwrap();
        s.follow(Some(path));
        assert_eq!(s.log_error(), None);
        s.log_read = Some("Input/output error".into());
        assert_eq!(
            s.log_error().as_deref(),
            Some(format!("cannot read {path}: Input/output error").as_str())
        );
        s.problems.add(
            r#"{"ts":"2026-11-20T08:01:02.345Z","site":"a","status":502,"path":"/x","end":"ok"}"#,
        );
        s.follow(Some(path));
        assert_eq!(s.problems.list.len(), 1);
        s.follow(Some("/elsewhere/access.log"));
        assert!(s.problems.list.is_empty());
        assert!(
            s.log_error()
                .unwrap()
                .starts_with("cannot read /elsewhere/")
        );
        s.follow(None);
        assert!(s.log.is_none());
        std::fs::remove_dir_all(&dir).unwrap();
        let out = render_with(160, 30, false, Some("cannot read /x: denied"));
        assert!(out.contains("cannot read /x: denied"), "{out}");
        assert!(!out.contains("upstream_timeout"), "{out}");
    }

    #[test]
    fn a_narrow_terminal_still_draws() {
        let out = render(80, 24, false);
        assert!(out.contains("Streams"), "{out}");
        // The header keeps its parts apart, dropping the least needed.
        let head = out.lines().next().unwrap();
        assert!(head.contains("req/s") && head.contains("out"), "{head}");
        assert!(!head.contains("12:03:11"), "{head}");
    }

    #[test]
    fn without_a_reply_it_says_why() {
        let screen = Screen {
            view: None,
            series: &[],
            problems: &[],
            log_error: None,
            clock: String::new(),
            full_addresses: false,
            paused: false,
            error: Some("cannot connect to /run/piano/ctl.sock"),
            interval_secs: 1.0,
        };
        let mut t = Terminal::new(TestBackend::new(100, 20)).unwrap();
        t.draw(|f| draw(f, &screen)).unwrap();
        let buf = t.backend().buffer();
        let text: String = (0..buf.area.height)
            .flat_map(|y| (0..buf.area.width).map(move |x| (x, y)))
            .map(|p| buf[p].symbol().to_owned())
            .collect();
        assert!(text.contains("piano is not reachable"), "{text}");
    }
}
