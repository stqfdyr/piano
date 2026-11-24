//! Drawing of `piano top`: one page at a time under a bar of numbered pages, never
//! boxes. Colour marks state (muted green, amber, red) besides one accent; labels are
//! dimmed and the numbers that matter are bold. Inverted chips are kept for the name,
//! the shown page, key caps and a state that needs attention. Motion means something:
//! a light band runs over bytes that are flowing, a band scans while a head is awaited,
//! and the dot by the name lights up at each reply.

use super::chart::{self, Scrub};
use super::model::{Edge, Memory, Percentiles, Problem, SiteRow, State, StreamRow, View, mask};
use crate::render::{duration, local_time, millis as ms, size};
use piano_telemetry::latency;
use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Flex, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Sparkline, Table, Wrap};

pub const DIM: Color = Color::Indexed(244);
const RULE: Color = Color::Indexed(240);
const FAINT: Color = Color::Indexed(238);
/// Key caps: light text on a dark grey cap, readable on dark and light themes alike.
const CAP: Color = Color::Indexed(238);
const CAP_TEXT: Color = Color::Indexed(253);
const SPARK: Color = Color::Indexed(242);
/// Text on a coloured chip: the palette's black, which themes leave alone.
const ON_CHIP: Color = Color::Indexed(16);
const ACCENT: Color = Color::Indexed(110);
const OK: Color = Color::Indexed(108);
const WARN: Color = Color::Indexed(179);
const BAD: Color = Color::Indexed(167);
/// The light band over flowing bytes.
const SHINE: Color = Color::Indexed(153);

/// Cells of the progress and budget bars.
const BAR: usize = 12;

/// Thresholds of the p95 time to first byte, in milliseconds, for browse, image and
/// media: about the 99th and 99.9th percentiles measured at two relays.
const SLOW_MS: [(f64, f64); 3] = [(1500.0, 5000.0), (1500.0, 5000.0), (5000.0, 10_000.0)];

/// The pages of the view, in the order of their keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Page {
    Streams,
    Sites,
    Upstream,
    Edge,
    Problems,
}

impl Page {
    pub const ALL: [Page; 5] = [
        Page::Streams,
        Page::Sites,
        Page::Upstream,
        Page::Edge,
        Page::Problems,
    ];

    fn name(self) -> &'static str {
        match self {
            Page::Streams => "streams",
            Page::Sites => "sites",
            Page::Upstream => "upstream",
            Page::Edge => "edge",
            Page::Problems => "problems",
        }
    }

    pub fn index(self) -> usize {
        Page::ALL.iter().position(|&p| p == self).unwrap_or(0)
    }

    /// The page of a number key, `1` to `5`.
    pub fn of_key(c: char) -> Option<Page> {
        let n = c.to_digit(10)? as usize;
        Page::ALL.get(n.checked_sub(1)?).copied()
    }

    pub fn next(self) -> Page {
        Page::ALL[(self.index() + 1) % Page::ALL.len()]
    }

    pub fn prev(self) -> Page {
        Page::ALL[(self.index() + Page::ALL.len() - 1) % Page::ALL.len()]
    }
}

/// Everything one frame shows.
pub struct Screen<'a> {
    pub page: Page,
    /// Problems that came in while another page was shown.
    pub unseen: usize,
    /// Seconds on the clock that moves the animations.
    pub phase: f64,
    /// 1 right after a reply, falling to 0.
    pub pulse: f64,
    /// Pages whose count just grew, by [`Page::ALL`].
    pub flash: [bool; 5],
    pub view: Option<&'a View>,
    pub series: &'a [u64],
    pub problems: &'a [Problem],
    /// Why the access log cannot be read.
    pub log_error: Option<&'a str>,
    /// Local time of the last reply.
    pub clock: String,
    pub full_addresses: bool,
    pub paused: bool,
    /// Why the last reply did not come.
    pub error: Option<&'a str>,
    pub interval_secs: f64,
}

fn dim(s: impl Into<String>) -> Span<'static> {
    Span::styled(s.into(), Style::new().fg(DIM))
}

fn faint(s: impl Into<String>) -> Span<'static> {
    Span::styled(s.into(), Style::new().fg(FAINT))
}

fn colored(s: impl Into<String>, c: Color) -> Span<'static> {
    Span::styled(s.into(), Style::new().fg(c))
}

fn bold(s: impl Into<String>) -> Span<'static> {
    Span::styled(s.into(), Style::new().add_modifier(Modifier::BOLD))
}

/// ` text ` inverted: the name, a key, or a state that needs attention.
fn chip(s: &str, bg: Color, fg: Color) -> Span<'static> {
    Span::styled(
        format!(" {s} "),
        Style::new().bg(bg).fg(fg).add_modifier(Modifier::BOLD),
    )
}

fn rule(n: usize) -> Span<'static> {
    Span::styled("─".repeat(n), Style::new().fg(RULE))
}

fn right(s: impl Into<Line<'static>>) -> Cell<'static> {
    Cell::from(s.into().alignment(Alignment::Right))
}

/// `4.1 MiB/s`; a dim `0` when nothing moves.
fn rate(bytes_per_sec: f64) -> Span<'static> {
    if bytes_per_sec < 1.0 {
        return dim("0");
    }
    Span::raw(format!("{}/s", size(bytes_per_sec as u64)))
}

/// `r` with at most two decimals and no trailing zeros: `2.5`, `0.33`, `1`.
fn short(r: f64) -> String {
    let s = format!("{r:.2}");
    s.trim_end_matches('0').trim_end_matches('.').to_owned()
}

/// Bold unless dimmed for being zero.
fn strong(s: Span<'static>) -> Span<'static> {
    if s.style.fg == Some(DIM) {
        s
    } else {
        let style = s.style.add_modifier(Modifier::BOLD);
        s.style(style)
    }
}

fn count(n: u64, c: Color) -> Span<'static> {
    if n == 0 {
        dim("0")
    } else {
        colored(n.to_string(), c)
    }
}

/// A bar of [`BAR`] cells filled to `share` with a thick dash, on a thin faint track.
fn bar(share: f64, color: Color) -> Vec<Span<'static>> {
    bar_of(share, color, BAR)
}

fn bar_of(share: f64, color: Color, cells: usize) -> Vec<Span<'static>> {
    let share = if share.is_nan() { 0.0 } else { share };
    let full = ((share.clamp(0.0, 1.0) * cells as f64).round() as usize).min(cells);
    vec![
        colored(chart::BAR.repeat(full), color),
        faint(chart::TRACK.repeat(cells - full)),
    ]
}

/// A table column: its header, width, whether numbers align right, and when it goes
/// on a narrow terminal (0 never; higher goes first).
struct Col {
    head: &'static str,
    width: u16,
    right: bool,
    drop: u8,
}

const SPACING: u16 = 2;

/// Indexes of the columns that fit in `width`, dropping the most expendable first.
fn fit(cols: &[Col], width: u16) -> Vec<usize> {
    let mut keep: Vec<usize> = (0..cols.len()).collect();
    let total = |keep: &[usize]| keep.iter().map(|&i| cols[i].width + SPACING).sum::<u16>();
    while total(&keep) > width {
        let Some(worst) = keep
            .iter()
            .copied()
            .filter(|&i| cols[i].drop > 0)
            .max_by_key(|&i| (cols[i].drop, i))
        else {
            break;
        };
        keep.retain(|&i| i != worst);
    }
    keep
}

/// A table of the kept columns; the last column takes what width is left.
fn table<'a>(cols: &[Col], keep: &[usize], rows: Vec<Vec<Cell<'a>>>) -> Table<'a> {
    let header = Row::new(keep.iter().map(|&i| {
        let c = &cols[i];
        if c.right {
            right(dim(c.head))
        } else {
            Cell::from(dim(c.head))
        }
    }));
    let rows = rows.into_iter().map(|cells| {
        let mut cells: Vec<Option<Cell<'a>>> = cells.into_iter().map(Some).collect();
        Row::new(
            keep.iter()
                .filter_map(|&i| cells.get_mut(i).and_then(Option::take))
                .collect::<Vec<_>>(),
        )
    });
    let widths: Vec<Constraint> = keep
        .iter()
        .map(|&i| Constraint::Length(cols[i].width))
        .collect();
    Table::new(rows, widths)
        .header(header)
        .column_spacing(SPACING)
        .flex(Flex::Start)
}

/// What needs attention on each page, by [`Page::ALL`]: a count and its colour, and
/// whether the count is of events, so that its growth is news.
pub fn badges(v: &View, unseen: usize) -> [Option<Badge>; 5] {
    let mut out = counts(v, unseen).map(|b| {
        b.map(|(n, color)| Badge {
            n,
            color,
            events: false,
        })
    });
    // Sites count 5xx, upstream red counts blocked upstreams, edge red counts closes and
    // problems count arrivals; the rest are levels.
    for (i, b) in out.iter_mut().enumerate() {
        if let Some(b) = b {
            b.events = match i {
                1 | 4 => true,
                2 | 3 => b.color == BAD,
                _ => false,
            };
        }
    }
    out
}

/// A page's count in the page bar.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Badge {
    pub n: usize,
    pub color: Color,
    pub events: bool,
}

/// What needs attention on each page: a count and its colour.
fn counts(v: &View, unseen: usize) -> [Option<(usize, Color)>; 5] {
    let streams = (!v.streams.is_empty()).then(|| {
        let c = v.streams.iter().fold(DIM, |c, r| match r.state {
            State::Stalled { ms, .. } if ms >= 15_000 => BAD,
            State::Stalled { .. } | State::Waiting { .. } if c != BAD => WARN,
            _ => c,
        });
        (v.streams.len(), c)
    });
    let errors: u64 = v.sites.iter().map(|r| r.status[3]).sum();
    let sites = (errors > 0).then_some((errors as usize, BAD));
    let blocked = v
        .budgets
        .iter()
        .filter(|b| b.paused_secs.is_some() || b.limited > 0)
        .count();
    let queued = v.budgets.iter().filter(|b| b.waiting > 0).count();
    let upstream = if blocked > 0 {
        Some((blocked, BAD))
    } else {
        (queued > 0).then_some((queued, WARN))
    };
    let e = &v.edge;
    let edge = if e.closed > 0 {
        Some((e.closed as usize, BAD))
    } else {
        // Four fifths of the limit, as the finding in `status`.
        (e.limit > 0 && e.open * 5 >= e.limit * 4).then_some((e.open as usize, WARN))
    };
    let problems = (unseen > 0).then_some((unseen, BAD));
    [streams, sites, upstream, edge, problems]
}

/// The page bar, which is also the rule above the page:
/// `─   01 streams  2   02 sites   03 upstream   04 edge   05 problems 3  ───  tag  ─`. The shown
/// page is an inverted chip. When the line is too short the tag goes, then the names of
/// the other pages, leaving their numbers.
fn tabs(f: &mut Frame<'_>, area: Rect, s: &Screen<'_>, v: &View, tag: Vec<Span<'static>>) {
    let width = |spans: &[Span<'_>]| spans.iter().map(Span::width).sum::<usize>();
    let badges = badges(v, s.unseen);
    let build = |short: bool| {
        let mut spans = vec![rule(1), Span::raw("  ")];
        for (i, page) in Page::ALL.into_iter().enumerate() {
            if i > 0 {
                spans.push(Span::raw("   "));
            }
            let label = if short && page != s.page {
                format!("{:02}", i + 1)
            } else {
                format!("{:02} {}", i + 1, page.name())
            };
            if page == s.page {
                spans.push(Span::styled(
                    format!(" {label} "),
                    Style::new().add_modifier(Modifier::REVERSED | Modifier::BOLD),
                ));
            } else {
                spans.push(dim(label));
            }
            if let Some(Badge { n, color: c, .. }) = badges[i] {
                spans.push(Span::raw(" "));
                if s.flash[i] {
                    spans.push(chip(&n.to_string(), c, ON_CHIP));
                } else {
                    spans.push(colored(n.to_string(), c));
                }
            }
        }
        spans
    };
    let mut tail = Vec::new();
    if !tag.is_empty() {
        tail.push(Span::raw("  "));
        tail.extend(tag);
        tail.extend([Span::raw("  "), rule(1)]);
    }
    let room = usize::from(area.width);
    let full = build(false);
    // At least a few cells of rule between the pages and the tag.
    let (head, tail) = if width(&full) + width(&tail) + 5 <= room {
        (full, tail)
    } else if width(&full) + 3 <= room {
        (full, Vec::new())
    } else {
        (build(true), Vec::new())
    };
    let used = width(&head) + width(&tail) + 2;
    let mut spans = head;
    spans.push(Span::raw("  "));
    spans.push(rule(room.saturating_sub(used)));
    spans.extend(tail);
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

pub fn draw(f: &mut Frame<'_>, s: &Screen<'_>) {
    let area = f.area();
    let Some(v) = s.view else {
        let [middle, foot] =
            Layout::vertical([Constraint::Min(0), Constraint::Length(1)]).areas(area);
        offline(f, middle, s);
        footer(f, foot, s);
        return;
    };
    // The chart gets a second row when the screen has rows to spare.
    let chart = if area.height >= 20 { 2 } else { 1 };
    let [head, spark, _, bar, _, body, foot] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(chart),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(0),
        Constraint::Length(1),
    ])
    .areas(area);
    header(f, head, v, s);
    throughput(f, spark, s);
    let tag = match s.page {
        Page::Streams => {
            let shown = usize::from(body.height.saturating_sub(1));
            let mut tag = Vec::new();
            if v.streams.len() > shown {
                tag.push(dim(format!("showing {shown} of {}", v.streams.len())));
                tag.push(faint(" · "));
            }
            tag.extend(tally(&v.streams));
            tag
        }
        Page::Sites => vec![dim(match v.window_secs {
            0 => "ttfb p50 / p95 · starting".to_owned(),
            w => format!("ttfb p50 / p95 · last {w}s"),
        })],
        Page::Upstream => vec![dim(match v.window_secs {
            0 => "429 and images · starting".to_owned(),
            w => format!("429 and images · last {w}s"),
        })],
        Page::Edge => vec![dim(match v.window_secs {
            0 => "starting".to_owned(),
            w => format!("last {w}s"),
        })],
        Page::Problems => vec![dim("from the access log")],
    };
    tabs(f, bar, s, v, tag);
    match s.page {
        Page::Streams => streams(f, body, v, s),
        Page::Sites => sites(f, body, v),
        Page::Upstream => upstreams(f, body, v),
        Page::Edge => edge(f, body, &v.edge),
        Page::Problems => problems(f, body, s, v.access_log.is_some()),
    }
    footer(f, foot, s);
}

/// Before the first reply: the name on a rule, and a leader to the socket's state.
fn offline(f: &mut Frame<'_>, area: Rect, s: &Screen<'_>) {
    let w = area.width.saturating_sub(4).min(72);
    let [_, block, _] = Layout::vertical([
        Constraint::Percentage(40),
        Constraint::Length(5),
        Constraint::Min(0),
    ])
    .areas(area);
    let [_, block, _] = Layout::horizontal([
        Constraint::Fill(1),
        Constraint::Length(w),
        Constraint::Fill(1),
    ])
    .areas(block);
    let [lockup, _, leader, detail] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(0),
    ])
    .areas(block);
    let name = "piano top";
    let side = usize::from(w).saturating_sub(name.len() + 4);
    let left = side / 2;
    f.render_widget(
        Paragraph::new(Line::from(vec![
            rule(left),
            Span::raw("  "),
            bold(name),
            Span::raw("  "),
            rule(side - left),
        ])),
        lockup,
    );
    let (value, color) = match s.error {
        Some(_) => ("not reachable", WARN),
        None => ("connecting", DIM),
    };
    let label = "control socket";
    let dots = usize::from(w).saturating_sub(label.len() + value.len() + 2);
    f.render_widget(
        Paragraph::new(Line::from(vec![
            dim(label),
            Span::raw(" "),
            faint(".".repeat(dots)),
            Span::raw(" "),
            Span::styled(value, Style::new().fg(color).add_modifier(Modifier::BOLD)),
        ])),
        leader,
    );
    if let Some(e) = s.error {
        f.render_widget(
            Paragraph::new(dim(e.to_owned())).wrap(Wrap { trim: false }),
            detail,
        );
    }
}

/// Bytes per second written to clients, each reply as wide as the screen allows, with
/// its peak and, given a second row, its span.
fn throughput(f: &mut Frame<'_>, area: Rect, s: &Screen<'_>) {
    // The legend is at most this wide, so the chart's width is known before it.
    let lw = 18u16.min(area.width / 3);
    let [chart, _, legend] = Layout::horizontal([
        Constraint::Min(0),
        Constraint::Length(2),
        Constraint::Length(lw),
    ])
    .areas(area);
    let tail = chart::stretch(s.series, usize::from(chart.width));
    let shown = tail.len() / (usize::from(chart.width) / s.series.len().max(1)).max(1);
    let span = (shown as f64 * s.interval_secs).round();
    // Over what is drawn: a narrow chart leaves the oldest replies out.
    let peak = tail.iter().copied().max().unwrap_or(0);
    let mut labels = vec![Line::from(vec![dim("peak "), rate(peak as f64)])];
    if area.height >= 2 {
        labels.push(Line::from(dim(format!("out · last {span}s"))));
    }
    f.render_widget(
        Sparkline::default()
            .data(&tail)
            .style(Style::new().fg(SPARK)),
        chart,
    );
    f.render_widget(Paragraph::new(labels).alignment(Alignment::Right), legend);
}

fn header(f: &mut Frame<'_>, area: Rect, v: &View, s: &Screen<'_>) {
    let sep = || faint("   ·   ");
    let mut right = vec![
        dim("out "),
        strong(rate(v.sent_rate)),
        dim("   in "),
        strong(rate(v.fetched_rate)),
    ];
    let clock = [Span::raw("   "), dim(s.clock.clone())];
    // Pieces of the left side, least needed last; they go when the line is too short.
    let mut name = vec![
        Span::styled(
            " piano ",
            Style::new().add_modifier(Modifier::REVERSED | Modifier::BOLD),
        ),
        Span::raw(" "),
        Span::styled("●", Style::new().fg(chart::fade(s.pulse))),
        dim(format!(" {}", v.version)),
    ];
    if s.error.is_some() {
        name.extend([Span::raw("  "), chip("reconnecting", WARN, ON_CHIP)]);
    } else if s.paused {
        name.extend([Span::raw("  "), chip("paused", ACCENT, ON_CHIP)]);
    }
    let mut parts: Vec<Vec<Span<'static>>> = vec![name];
    parts.push(vec![
        sep(),
        bold(format!("{:.1}", v.requests_rate)),
        dim(" req/s"),
    ]);
    parts.push(vec![
        sep(),
        bold(v.connections.to_string()),
        dim(" connections"),
    ]);
    parts.push(vec![sep(), dim("up "), Span::raw(duration(v.uptime_secs))]);
    let width = |spans: &[Span<'_>]| spans.iter().map(Span::width).sum::<usize>();
    let room = usize::from(area.width);
    if width(&right) + width(&clock) + width(&parts.concat()) + 2 <= room {
        right.extend(clock);
    }
    while parts.len() > 1 && width(&parts.concat()) + width(&right) + 2 > room {
        parts.pop();
    }
    let right = Line::from(right).alignment(Alignment::Right);
    let rw = right.width() as u16;
    let [l, r] = Layout::horizontal([Constraint::Min(0), Constraint::Length(rw)]).areas(area);
    f.render_widget(Paragraph::new(Line::from(parts.concat())), l);
    f.render_widget(Paragraph::new(right), r);
}

fn state(st: State) -> Line<'static> {
    let secs = |ms: u64| format!("{:.0}s", ms as f64 / 1000.0);
    match st {
        State::Playing => Line::from(vec![colored("● ", OK), Span::raw("playing")]),
        State::Waiting { ms, attempt } => {
            let mut l = vec![
                colored("● ", WARN),
                Span::raw(format!("waiting {}", secs(ms))),
            ];
            if attempt > 1 {
                l.push(dim(format!(" · try {attempt}")));
            }
            Line::from(l)
        }
        State::Held(ms) => Line::from(vec![dim("● "), dim(format!("held by client {}", secs(ms)))]),
        State::Stalled { ms, hedging } => {
            let c = if ms >= 15_000 { BAD } else { WARN };
            let mut l = vec![colored("● ", c), Span::raw(format!("stalled {}", secs(ms)))];
            if hedging {
                l.push(dim(" · hedging"));
            }
            Line::from(l)
        }
    }
}

fn progress(r: &StreamRow, phase: f64) -> Line<'static> {
    match (r.position, r.size) {
        (Some(p), Some(n)) if n > 0 => {
            let share = p as f64 / n as f64;
            let mut spans = bar(share, ACCENT);
            if r.state == State::Playing {
                spans = shine(spans, phase);
            }
            spans.push(Span::raw(format!(" {:>3.0}%", share * 100.0)));
            Line::from(spans)
        }
        _ => Line::from(dim("—")),
    }
}

/// The first span of `spans` with a light band running over it: bytes are flowing.
fn shine(mut spans: Vec<Span<'static>>, phase: f64) -> Vec<Span<'static>> {
    let Some(first) = spans.first().cloned() else {
        return spans;
    };
    let cells: Vec<char> = first.content.chars().collect();
    let band = chart::band_at(cells.len(), 2, 8.0, phase);
    let piece = |r: std::ops::Range<usize>| cells[r].iter().collect::<String>();
    let lit = Span::styled(piece(band.clone()), first.style.fg(SHINE));
    let head = Span::styled(piece(0..band.start), first.style);
    let tail = Span::styled(piece(band.end..cells.len()), first.style);
    spans.splice(0..1, [head, lit, tail]);
    spans
}

/// How many streams are in each state, in that state's colour: `2 playing · 1 stalled`.
fn tally(streams: &[StreamRow]) -> Vec<Span<'static>> {
    let mut n = [0usize; 4];
    let mut worst_stall = 0;
    for r in streams {
        match r.state {
            State::Playing => n[0] += 1,
            State::Stalled { ms, .. } => {
                n[1] += 1;
                worst_stall = worst_stall.max(ms);
            }
            State::Waiting { .. } => n[2] += 1,
            State::Held(_) => n[3] += 1,
        }
    }
    let stall = if worst_stall >= 15_000 { BAD } else { WARN };
    let mut out = Vec::new();
    for (k, (what, c)) in [
        ("playing", OK),
        ("stalled", stall),
        ("waiting", WARN),
        ("held", DIM),
    ]
    .into_iter()
    .enumerate()
    {
        if n[k] == 0 {
            continue;
        }
        if !out.is_empty() {
            out.push(faint(" · "));
        }
        out.push(colored(n[k].to_string(), c));
        out.push(dim(format!(" {what}")));
    }
    out
}

/// Rows a stream card takes, the gap after it included.
const CARD: u16 = 4;
/// Rows a site's block takes, the gap after it included.
const SITE_BLOCK: u16 = 13;
/// Width of a histogram panel: its axis and a column per bucket.
const PANEL: u16 = latency::BUCKETS as u16 + 1;

/// Streams as cards while they fit, else as a table.
fn streams(f: &mut Frame<'_>, body: Rect, v: &View, s: &Screen<'_>) {
    if v.streams.is_empty() {
        f.render_widget(Paragraph::new(dim("  nothing playing")), body);
        return;
    }
    let rows = (v.streams.len() as u16)
        .saturating_mul(CARD)
        .saturating_sub(1);
    if rows > body.height || body.width < 72 {
        stream_table(f, body, v, s.full_addresses, s.phase);
        return;
    }
    for (i, r) in v.streams.iter().enumerate() {
        let y = body.y + i as u16 * CARD;
        card(f, Rect::new(body.x, y, body.width, 3), r, s);
    }
}

fn pad(spans: &mut Vec<Span<'static>>, to: usize) {
    let w: usize = spans.iter().map(Span::width).sum();
    spans.push(Span::raw(" ".repeat(to.saturating_sub(w).max(1))));
}

/// One stream: who and what with its rate and trend; where it is in the file; where
/// the bytes come from.
fn card(f: &mut Frame<'_>, area: Rect, r: &StreamRow, s: &Screen<'_>) {
    let [top, mid, low] = Layout::vertical([Constraint::Length(1); 3]).areas(area);
    let client = r.client.as_deref().map_or_else(
        || "-".to_owned(),
        |c| {
            if s.full_addresses {
                c.to_owned()
            } else {
                mask(c)
            }
        },
    );
    let mut left = state(r.state).spans;
    pad(&mut left, 28);
    left.push(Span::raw(client));
    pad(&mut left, if s.full_addresses { 70 } else { 46 });
    left.push(dim(r.site.clone()));
    pad(&mut left, if s.full_addresses { 80 } else { 56 });
    left.push(bold(r.item.clone()));
    let flowing = r.state == State::Playing;
    let trend = if flowing { ACCENT } else { SPARK };
    // The rate always; then its trend, the first byte and the age as they fit.
    let lw: usize = left.iter().map(Span::width).sum();
    let room = usize::from(top.width).saturating_sub(lw + 2);
    let mut right = vec![strong(rate(r.rate))];
    let extras = [
        vec![Span::raw("  "), chart::spark(&r.series, 24, None, trend)],
        vec![
            dim("   ttfb "),
            r.ttfb_ms
                .map_or_else(|| dim("—"), |t| Span::raw(ms(t as f64))),
        ],
        vec![dim("   "), dim(duration(r.age_ms / 1000))],
    ];
    for extra in extras {
        let w: usize = right.iter().chain(&extra).map(Span::width).sum();
        if w <= room {
            right.extend(extra);
        }
    }
    let right = Line::from(right).alignment(Alignment::Right);
    let rw = (right.width() as u16).min(top.width);
    let [l, rr] = Layout::horizontal([Constraint::Min(0), Constraint::Length(rw)]).areas(top);
    f.render_widget(Paragraph::new(Line::from(left)), l);
    f.render_widget(Paragraph::new(right), rr);

    let [_, track, pct] = Layout::horizontal([
        Constraint::Length(3),
        Constraint::Min(0),
        Constraint::Length(7),
    ])
    .areas(mid);
    let width = usize::from(track.width);
    let head = match r.state {
        State::Playing => Color::Reset,
        State::Stalled { ms, .. } if ms >= 15_000 => BAD,
        State::Stalled { .. } | State::Waiting { .. } => WARN,
        State::Held(_) => DIM,
    };
    let colours = Scrub {
        before: SPARK,
        this: ACCENT,
        shine: SHINE,
        head,
        rest: FAINT,
    };
    let (line, share) = match (r.position, r.size) {
        (Some(p), Some(n)) if n > 0 => (
            chart::scrub(
                width,
                n,
                r.start.unwrap_or(p),
                p,
                flowing,
                s.phase,
                &colours,
            ),
            Some(p as f64 / n as f64),
        ),
        _ if matches!(r.state, State::Waiting { .. }) => {
            (chart::scanner(width, s.phase, WARN, FAINT), None)
        }
        _ => (vec![faint(chart::TRACK.repeat(width))], None),
    };
    f.render_widget(Paragraph::new(Line::from(line)), track);
    let pct_text = share.map_or_else(|| dim("—"), |x| Span::raw(format!("{:.0}%", x * 100.0)));
    f.render_widget(
        Paragraph::new(Line::from(pct_text).alignment(Alignment::Right)),
        pct,
    );

    let plural = |n: u32, one: &str| {
        if n == 1 {
            format!("{n} {one}")
        } else {
            format!("{n} {one}s")
        }
    };
    let mut info = vec![
        Span::raw("   "),
        dim(r.upstream.clone().unwrap_or_else(|| "-".into())),
        faint("   ·   "),
        dim(plural(r.requests, "upstream request")),
        dim(format!(", {} in flight", r.in_flight)),
    ];
    if r.hedges + r.resumes > 0 {
        info.push(faint("   ·   "));
        info.push(Span::raw(format!(
            "{} hedged, {} resumed",
            r.hedges, r.resumes
        )));
    }
    if r.attempt > 1 {
        info.push(faint("   ·   "));
        info.push(colored(format!("client try {}", r.attempt), WARN));
    }
    let amount = match (r.position, r.size) {
        (Some(p), Some(n)) => format!("{} / {}", size(p), size(n)),
        _ => String::new(),
    };
    let right = Line::from(vec![
        dim(amount),
        dim("   sent "),
        Span::raw(size(r.sent)),
        Span::raw(" "),
    ])
    .alignment(Alignment::Right);
    let rw = (right.width() as u16).min(low.width / 2);
    let [l, rr] = Layout::horizontal([Constraint::Min(0), Constraint::Length(rw)]).areas(low);
    f.render_widget(Paragraph::new(Line::from(info)), l);
    f.render_widget(Paragraph::new(right), rr);
}

/// Sites as blocks with their histograms while they fit, else as a table.
fn sites(f: &mut Frame<'_>, body: Rect, v: &View) {
    let panels = if body.width >= 3 * (PANEL + 6) {
        3
    } else if body.width >= 2 * (PANEL + 6) {
        2
    } else {
        0
    };
    let rows = (v.sites.len() as u16)
        .saturating_mul(SITE_BLOCK)
        .saturating_sub(1);
    if panels == 0 || v.sites.is_empty() || rows > body.height {
        site_table(f, body, v);
        return;
    }
    for (i, r) in v.sites.iter().enumerate() {
        let y = body.y + i as u16 * SITE_BLOCK;
        site_block(
            f,
            Rect::new(body.x, y, body.width, SITE_BLOCK - 1),
            r,
            panels,
        );
    }
}

fn site_block(f: &mut Frame<'_>, area: Rect, r: &SiteRow, panels: usize) {
    let [top, _, charts, _, foot, given] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(7),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .areas(area);
    let classes = [
        (r.status[0], OK, "2xx"),
        (r.status[1], ACCENT, "3xx"),
        (r.status[2], WARN, "4xx"),
        (r.status[3], BAD, "5xx"),
    ];
    let total: u64 = r.status.iter().sum();
    let mut left = vec![bold(r.name.clone())];
    pad(&mut left, 12);
    left.push(Span::raw(r.requests.to_string()));
    left.push(dim(" requests"));
    pad(&mut left, 30);
    left.extend(chart::stacked(&classes.map(|c| (c.0, c.1)), 32, FAINT));
    let right = Line::from(vec![
        dim("out "),
        strong(rate(r.sent_rate)),
        dim("   in "),
        strong(rate(r.fetched_rate)),
    ])
    .alignment(Alignment::Right);
    let rw = (right.width() as u16).min(top.width / 3);
    // The legend, as far as it fits beside the rates.
    let room = usize::from(top.width.saturating_sub(rw + 2));
    left.push(Span::raw("   "));
    for (n, c, name) in classes {
        if n == 0 {
            continue;
        }
        let item = [
            colored("■ ", c),
            dim(format!("{name} ")),
            Span::raw(format!("{:.1}%   ", n as f64 * 100.0 / total.max(1) as f64)),
        ];
        let used: usize = left.iter().chain(&item).map(Span::width).sum();
        if used > room {
            break;
        }
        left.extend(item);
    }
    let [l, rr] = Layout::horizontal([Constraint::Min(0), Constraint::Length(rw)]).areas(top);
    f.render_widget(Paragraph::new(Line::from(left)), l);
    f.render_widget(Paragraph::new(right), rr);

    let which: &[usize] = if panels == 3 { &[0, 1, 2] } else { &[0, 2] };
    let names = ["browse", "image", "media"];
    let mut constraints = Vec::new();
    for _ in which {
        constraints.push(Constraint::Length(PANEL));
        constraints.push(Constraint::Length(6));
    }
    let areas = Layout::horizontal(constraints).split(charts);
    for (k, &i) in which.iter().enumerate() {
        histogram(
            f,
            areas[2 * k],
            names[i],
            &r.histograms[i],
            r.ttfb[i],
            SLOW_MS[i],
        );
    }

    let mut line = Vec::new();
    if r.failures.is_empty() {
        line.push(dim("no failures"));
    } else {
        line.push(dim("failures  "));
        for (k, (end, n)) in r.failures.iter().take(4).enumerate() {
            if k > 0 {
                line.push(faint("  ·  "));
            }
            line.push(colored(end.clone(), WARN));
            line.push(Span::raw(format!(" {n}")));
        }
    }
    let mut right = vec![dim("connections reused  ")];
    match r.reuse {
        Some(x) => {
            right.extend(bar(x, ACCENT));
            right.push(Span::raw(format!(" {:>3.0}%", x * 100.0)));
        }
        None => right.push(dim("—")),
    }
    let right = Line::from(right).alignment(Alignment::Right);
    let rw = (right.width() as u16).min(foot.width / 2);
    let [l, rr] = Layout::horizontal([Constraint::Min(0), Constraint::Length(rw)]).areas(foot);
    f.render_widget(Paragraph::new(Line::from(line)), l);
    f.render_widget(Paragraph::new(right), rr);
    let asked = r.gave_up + r.answered;
    let text = if asked == 0 {
        Line::from(dim("no media requests"))
    } else {
        let share = r.gave_up as f64 / asked as f64;
        // As the finding in `status`: at least 5, and at least 30 %.
        let c = if r.gave_up >= 5 && share >= 0.3 {
            WARN
        } else {
            Color::Reset
        };
        let mut spans = vec![dim("media given up before the head  ")];
        spans.extend(bar(share, c));
        spans.push(colored(format!(" {:>3.0}%", share * 100.0), c));
        spans.push(dim(format!("   {} of {asked} requests", r.gave_up)));
        Line::from(spans)
    };
    f.render_widget(Paragraph::new(text), given);
}

/// A time to first byte histogram: a title with p50 / p95, four rows of bars over the
/// log-spaced buckets coloured past the slow thresholds, an axis and its labels.
fn histogram(
    f: &mut Frame<'_>,
    area: Rect,
    name: &str,
    counts: &[u64],
    p: Percentiles,
    slow: (f64, f64),
) {
    let [title, bars, axis, labels] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(4),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .areas(area);
    let mut head = vec![dim(format!("{name} ttfb  "))];
    head.extend(percentiles(p, slow).spans);
    f.render_widget(Paragraph::new(Line::from(head)), title);
    if counts.len() != latency::BUCKETS || counts.iter().all(|&n| n == 0) {
        f.render_widget(Paragraph::new(dim("│ none in the window")), bars);
    } else {
        let colour = |i: usize| {
            let lo_ms = i
                .checked_sub(1)
                .map_or(0.0, |j| latency::BOUNDS_US[j] as f64 / 1000.0);
            if lo_ms >= slow.1 {
                BAD
            } else if lo_ms >= slow.0 {
                WARN
            } else {
                SPARK
            }
        };
        let lines: Vec<Line<'_>> = chart::columns(counts, 4)
            .into_iter()
            .map(|row| {
                let mut spans = vec![faint("│")];
                spans.extend(
                    row.chars()
                        .enumerate()
                        .map(|(i, ch)| colored(ch.to_string(), colour(i))),
                );
                Line::from(spans)
            })
            .collect();
        f.render_widget(Paragraph::new(lines), bars);
    }
    f.render_widget(
        Paragraph::new(faint(format!("└{}", "─".repeat(latency::BUCKETS)))),
        axis,
    );
    let mut text = vec![' '; usize::from(PANEL) + 4];
    for (ms_mark, label) in [(10, "10ms"), (100, "100ms"), (1000, "1s"), (10_000, "10s")] {
        let i = latency::BOUNDS_US.partition_point(|&b| b < ms_mark * 1000);
        let at = 1 + i;
        if text[at.saturating_sub(1)..(at + label.len()).min(text.len())]
            .iter()
            .all(|&c| c == ' ')
        {
            for (k, ch) in label.chars().enumerate() {
                if let Some(slot) = text.get_mut(at + k) {
                    *slot = ch;
                }
            }
        }
    }
    f.render_widget(
        Paragraph::new(dim(text.into_iter().collect::<String>())),
        labels,
    );
}

fn stream_table(f: &mut Frame<'_>, body: Rect, v: &View, full: bool, phase: f64) {
    if v.streams.is_empty() {
        f.render_widget(Paragraph::new(dim("  nothing playing")), body);
        return;
    }
    let cols = [
        Col {
            head: "client",
            width: if full { 39 } else { 14 },
            right: false,
            drop: 0,
        },
        Col {
            head: "site",
            width: 6,
            right: false,
            drop: 4,
        },
        Col {
            head: "item",
            width: 12,
            right: false,
            drop: 0,
        },
        Col {
            head: "progress",
            width: BAR as u16 + 5,
            right: false,
            drop: 0,
        },
        Col {
            head: "",
            width: 23,
            right: true,
            drop: 6,
        },
        Col {
            head: "rate",
            width: 11,
            right: true,
            drop: 0,
        },
        Col {
            head: "ttfb",
            width: 6,
            right: true,
            drop: 3,
        },
        Col {
            head: "retries",
            width: 7,
            right: true,
            drop: 5,
        },
        Col {
            head: "state",
            width: 22,
            right: false,
            drop: 0,
        },
        Col {
            head: "upstream",
            width: 20,
            right: false,
            drop: 9,
        },
    ];
    let rows = v
        .streams
        .iter()
        .take(usize::from(body.height.saturating_sub(1)))
        .map(|r| {
            let client = r.client.as_deref().map_or_else(
                || "-".to_owned(),
                |c| if full { c.to_owned() } else { mask(c) },
            );
            let amount = match (r.position, r.size) {
                (Some(p), Some(n)) => format!("{} / {}", size(p), size(n)),
                _ => size(r.sent),
            };
            let retries = if r.hedges + r.resumes == 0 {
                dim("—")
            } else {
                Span::raw(format!("{} · {}", r.hedges, r.resumes))
            };
            vec![
                Cell::from(client),
                Cell::from(r.site.clone()),
                Cell::from(r.item.clone()),
                Cell::from(progress(r, phase)),
                right(dim(amount)),
                right(rate(r.rate)),
                right(
                    r.ttfb_ms
                        .map_or_else(|| dim("—"), |t| Span::raw(ms(t as f64))),
                ),
                right(retries),
                Cell::from(state(r.state)),
                Cell::from(dim(r.upstream.clone().unwrap_or_default())),
            ]
        })
        .collect();
    let keep = fit(&cols, body.width);
    f.render_widget(table(&cols, &keep, rows), body);
}

fn percentiles(p: Percentiles, slow: (f64, f64)) -> Line<'static> {
    match p {
        None => Line::from(dim("—")),
        Some((p50, p95)) => {
            let c = if p95 >= slow.1 {
                Some(BAD)
            } else if p95 >= slow.0 {
                Some(WARN)
            } else {
                None
            };
            let tail = match c {
                Some(c) => colored(ms(p95), c),
                None => Span::raw(ms(p95)),
            };
            Line::from(vec![Span::raw(ms(p50)), faint(" / "), tail])
        }
    }
}

fn site_table(f: &mut Frame<'_>, body: Rect, v: &View) {
    let cols = [
        Col {
            head: "site",
            width: 8,
            right: false,
            drop: 0,
        },
        Col {
            head: "requests",
            width: 8,
            right: true,
            drop: 0,
        },
        Col {
            head: "2xx",
            width: 5,
            right: true,
            drop: 5,
        },
        Col {
            head: "3xx",
            width: 5,
            right: true,
            drop: 7,
        },
        Col {
            head: "4xx",
            width: 5,
            right: true,
            drop: 4,
        },
        Col {
            head: "5xx",
            width: 5,
            right: true,
            drop: 0,
        },
        Col {
            head: "failed",
            width: 6,
            right: true,
            drop: 0,
        },
        Col {
            head: "out",
            width: 11,
            right: true,
            drop: 0,
        },
        Col {
            head: "in",
            width: 11,
            right: true,
            drop: 6,
        },
        Col {
            head: "browse",
            width: 13,
            right: true,
            drop: 0,
        },
        Col {
            head: "image",
            width: 13,
            right: true,
            drop: 3,
        },
        Col {
            head: "media",
            width: 13,
            right: true,
            drop: 0,
        },
    ];
    let rows = v
        .sites
        .iter()
        .map(|r: &SiteRow| {
            vec![
                Cell::from(r.name.clone()),
                right(Span::raw(r.requests.to_string())),
                right(count(r.status[0], Color::Reset)),
                right(count(r.status[1], Color::Reset)),
                right(count(r.status[2], WARN)),
                right(count(r.status[3], BAD)),
                right(count(r.failed, BAD)),
                right(rate(r.sent_rate)),
                right(rate(r.fetched_rate)),
                right(percentiles(r.ttfb[0], SLOW_MS[0])),
                right(percentiles(r.ttfb[1], SLOW_MS[1])),
                right(percentiles(r.ttfb[2], SLOW_MS[2])),
            ]
        })
        .collect();
    let keep = fit(&cols, body.width);
    f.render_widget(table(&cols, &keep, rows), body);
}

fn upstreams(f: &mut Frame<'_>, area: Rect, v: &View) {
    let budgets = &v.budgets;
    let [body, _, images, _, memory] = Layout::vertical([
        Constraint::Length(budgets.len().max(1) as u16 + 1),
        Constraint::Length(1),
        Constraint::Length(3),
        Constraint::Length(1),
        Constraint::Length(2),
    ])
    .areas(area);
    if budgets.is_empty() {
        f.render_widget(Paragraph::new(dim("  no upstream requests yet")), body);
    } else {
        let header = Row::new(vec![
            Cell::from(dim("upstream")),
            Cell::from(dim("budget")),
            right(dim("refill")),
            right(dim("waiting")),
            right(dim("429")),
            Cell::from(dim("budget, last minute")),
        ]);
        let name = budgets
            .iter()
            .map(|b| b.upstream.chars().count())
            .max()
            .unwrap_or(0)
            .max(8) as u16;
        // The trend takes the width the other columns leave.
        let fixed = name + BAR as u16 + 9 + 7 + 7 + 5 + 5 * 3;
        let trend_width = usize::from(body.width.saturating_sub(fixed)).max(10);
        let rows = budgets.iter().map(|b| {
            let budget = match (b.paused_secs, b.burst) {
                (Some(p), _) => Line::from(colored(format!("paused {p:.0}s"), BAD)),
                (None, Some(burst)) => {
                    let share = b.tokens / burst;
                    let c = if share < 0.3 { WARN } else { OK };
                    let mut spans = bar(share, c);
                    spans.push(dim(format!(" {:.0}/{burst:.0}", b.tokens.max(0.0))));
                    Line::from(spans)
                }
                (None, None) => Line::from(dim("no limit set")),
            };
            let refill = b
                .per_sec
                .map_or_else(|| dim("—"), |r| Span::raw(format!("{}/s", short(r))));
            let max = b.burst.map(|x| x.max(1.0).round() as u64);
            let trend = chart::stretch(&b.series, trend_width);
            Row::new(vec![
                Cell::from(b.upstream.clone()),
                Cell::from(budget),
                right(refill),
                right(count(b.waiting, WARN)),
                right(count(b.limited, BAD)),
                Cell::from(chart::spark(&trend, trend_width, max, SPARK)),
            ])
        });
        let widths = [
            Constraint::Length(name),
            Constraint::Length(BAR as u16 + 9),
            Constraint::Length(7),
            Constraint::Length(7),
            Constraint::Length(5),
            Constraint::Length(trend_width as u16),
        ];
        f.render_widget(
            Table::new(rows, widths)
                .header(header)
                .column_spacing(3)
                .flex(Flex::Start),
            body,
        );
    }
    let img = &v.images;
    let [head, strip, legend] = Layout::vertical([Constraint::Length(1); 3]).areas(images);
    f.render_widget(
        Paragraph::new(Line::from(vec![
            bold("images"),
            dim(format!("  {} answered", img.answered)),
        ])),
        head,
    );
    let parts = [
        (img.local, OK, "remembered 404"),
        (img.fetched, SPARK, "fetched"),
        (img.shared, ACCENT, "shared a fetch"),
        (img.refused, BAD, "refused, over budget"),
    ];
    let width = usize::from(strip.width).min(120);
    f.render_widget(
        Paragraph::new(Line::from(chart::stacked(
            &parts.map(|p| (p.0, p.1)),
            width,
            FAINT,
        ))),
        strip,
    );
    if img.answered == 0 {
        f.render_widget(Paragraph::new(dim("none recently")), legend);
    } else {
        let mut spans = Vec::new();
        for (n, c, what) in parts {
            if !spans.is_empty() {
                spans.push(Span::raw("    "));
            }
            spans.push(colored("■ ", c));
            spans.push(dim(format!("{what} ")));
            spans.push(Span::raw(format!(
                "{n}  {:.0}%",
                n as f64 * 100.0 / img.answered as f64
            )));
        }
        f.render_widget(Paragraph::new(Line::from(spans)), legend);
    }
    let m: &Memory = &v.memory;
    let [head, line] = Layout::vertical([Constraint::Length(1); 2]).areas(memory);
    f.render_widget(Paragraph::new(bold("remembered")), head);
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::raw(m.redirects.to_string()),
            dim(" redirects, "),
            Span::raw(m.redirect_hits.to_string()),
            dim(" requests went straight to one    "),
            Span::raw(m.missing.to_string()),
            dim(" images the upstream does not have"),
        ])),
        line,
    );
}

/// Client connections against the limit, and what the edge turned away.
fn edge(f: &mut Frame<'_>, area: Rect, e: &Edge) {
    let [gauge, _, rest] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(0),
    ])
    .areas(area);
    let share = if e.limit == 0 {
        0.0
    } else {
        e.open as f64 / e.limit as f64
    };
    let c = if share >= 0.95 {
        BAD
    } else if share >= 0.8 {
        WARN
    } else {
        OK
    };
    let mut spans = vec![bold("connections"), Span::raw("   ")];
    spans.extend(bar_of(share, c, 40));
    spans.extend([
        Span::raw("   "),
        bold(e.open.to_string()),
        dim(format!(" of {}  ", e.limit)),
        Span::raw(format!("{:.0}%", share * 100.0)),
        Span::raw("    "),
        Span::raw(e.handshaking.to_string()),
        dim(" in a handshake"),
    ]);
    f.render_widget(Paragraph::new(Line::from(spans)), gauge);
    let total = |n: u64, c: Color| {
        if n == 0 {
            dim("none")
        } else {
            colored(format!("{n} in the window"), c)
        }
    };
    let metrics = [
        (
            "open connections",
            &e.open_series,
            Span::raw(format!("{} now", e.open)),
            SPARK,
        ),
        (
            "handshakes failed or timed out",
            &e.failed_series,
            total(e.failed, WARN),
            WARN,
        ),
        (
            "refused by the allow list",
            &e.denied_series,
            total(e.denied, DIM),
            SPARK,
        ),
        (
            "closed at the connection limit",
            &e.closed_series,
            total(e.closed, BAD),
            BAD,
        ),
    ];
    let mut y = rest.y;
    for (label, series, value, color) in metrics {
        if y + 3 > rest.bottom() {
            break;
        }
        let row = |dy: u16, h: u16| Rect::new(rest.x, y + dy, rest.width, h);
        let [l, r] =
            Layout::horizontal([Constraint::Min(0), Constraint::Length(30)]).areas(row(0, 1));
        f.render_widget(Paragraph::new(dim(label)), l);
        f.render_widget(
            Paragraph::new(Line::from(value).alignment(Alignment::Right)),
            r,
        );
        let chart = row(1, 2);
        let tail = chart::stretch(series, usize::from(chart.width));
        if tail.iter().all(|&n| n == 0) {
            f.render_widget(
                Paragraph::new(faint("─".repeat(usize::from(chart.width)))),
                row(2, 1),
            );
        } else {
            f.render_widget(
                Sparkline::default()
                    .data(&tail)
                    .style(Style::new().fg(color)),
                chart,
            );
        }
        y += 4;
    }
}

/// Problems newest first, a run of the same failure folded into its newest line and
/// a count.
fn folded(list: &[Problem]) -> Vec<(&Problem, usize)> {
    let mut out: Vec<(&Problem, usize)> = Vec::new();
    for p in list.iter().rev() {
        match out.last_mut() {
            Some((q, n))
                if q.site == p.site
                    && q.status == p.status
                    && q.end == p.end
                    && q.path == p.path =>
            {
                *n += 1;
            }
            _ => out.push((p, 1)),
        }
    }
    out
}

fn problems(f: &mut Frame<'_>, body: Rect, s: &Screen<'_>, log_on: bool) {
    let list = s.problems;
    if !log_on {
        f.render_widget(Paragraph::new(dim("  the access log is off")), body);
        return;
    }
    if let Some(e) = s.log_error {
        // Wrapped: the reason comes last.
        f.render_widget(
            Paragraph::new(colored(format!("  {e}"), WARN)).wrap(Wrap { trim: false }),
            body,
        );
        return;
    }
    if list.is_empty() {
        f.render_widget(Paragraph::new(dim("  none recently")), body);
        return;
    }
    let lines: Vec<Line<'_>> = folded(list)
        .into_iter()
        .take(usize::from(body.height))
        .map(|(p, n)| {
            let status = p.status.map_or_else(|| "---".to_owned(), |s| s.to_string());
            let sc = if p.status.is_some_and(|s| s >= 500) {
                BAD
            } else {
                WARN
            };
            let mut spans = vec![
                dim(local_time(&p.ts, "%H:%M:%S")
                    .unwrap_or_else(|| p.ts.get(11..19).unwrap_or(&p.ts).to_owned())),
                Span::raw("  "),
                Span::raw(format!("{:<6}", p.site)),
                colored(status, sc),
                Span::raw("  "),
            ];
            if let Some(end) = &p.end {
                spans.push(colored(end.clone(), WARN));
                spans.push(Span::raw("  "));
            }
            if n > 1 {
                spans.push(dim(format!("×{n}  ")));
            }
            spans.push(dim(p.path.clone()));
            Line::from(spans)
        })
        .collect();
    f.render_widget(Paragraph::new(lines), body);
}

fn footer(f: &mut Frame<'_>, area: Rect, s: &Screen<'_>) {
    let key = |k: &str, what: &str| vec![chip(k, CAP, CAP_TEXT), dim(format!(" {what}   "))];
    let mut left = Vec::new();
    left.extend(key("q", "quit"));
    if s.view.is_some() {
        left.extend(key("1-5", "pages"));
        left.extend(key("tab", "next"));
    }
    left.extend(key("p", if s.paused { "resume" } else { "pause" }));
    if s.view.is_some() && s.page == Page::Streams {
        left.extend(key(
            "f",
            if s.full_addresses {
                "short addresses"
            } else {
                "full addresses"
            },
        ));
    }
    let note = match s.error {
        // Without a view the reason is in the middle of the screen already.
        Some(_) if s.view.is_none() => dim(format!("trying every {}s", s.interval_secs)),
        Some(e) => colored(e.to_owned(), WARN),
        None => dim(format!("every {}s", s.interval_secs)),
    };
    let right = Line::from(note).alignment(Alignment::Right);
    let width = (right.width() as u16).min(area.width / 2);
    let [l, r] = Layout::horizontal([Constraint::Min(0), Constraint::Length(width)]).areas(area);
    f.render_widget(Paragraph::new(Line::from(left)), l);
    f.render_widget(Paragraph::new(right), r);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rates_are_short() {
        assert_eq!(short(2.5), "2.5");
        assert_eq!(short(1.0), "1");
        assert_eq!(short(1.0 / 3.0), "0.33");
        assert_eq!(short(0.1 + 0.2), "0.3");
    }

    #[test]
    fn repeated_problems_fold_into_one_line() {
        let p = |path: &str, ts: &str| Problem {
            ts: ts.into(),
            site: "a".into(),
            status: Some(502),
            path: path.into(),
            end: None,
            err: None,
        };
        let list = [p("/x", "1"), p("/x", "2"), p("/y", "3"), p("/x", "4")];
        let f: Vec<(&str, &str, usize)> = folded(&list)
            .into_iter()
            .map(|(q, n)| (q.path.as_str(), q.ts.as_str(), n))
            .collect();
        assert_eq!(f, [("/x", "4", 1), ("/y", "3", 1), ("/x", "2", 2)]);
    }

    #[test]
    fn narrow_terminals_drop_the_most_expendable_columns_first() {
        let cols = [
            Col {
                head: "a",
                width: 10,
                right: false,
                drop: 0,
            },
            Col {
                head: "b",
                width: 10,
                right: false,
                drop: 2,
            },
            Col {
                head: "c",
                width: 10,
                right: false,
                drop: 1,
            },
        ];
        assert_eq!(fit(&cols, 36), [0, 1, 2]);
        assert_eq!(fit(&cols, 35), [0, 2]);
        assert_eq!(fit(&cols, 20), [0]);
        assert_eq!(fit(&cols, 5), [0]);
    }
}
