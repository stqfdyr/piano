//! Drawing of `piano top`. Sections are told apart by space and a faint rule rather than
//! boxes; colour marks state only (muted green, amber, red) besides one accent, and
//! labels are dimmed so the numbers stand out.

use super::model::{
    BudgetRow, Images, Percentiles, Problem, SiteRow, State, StreamRow, View, mask,
};
use crate::render::{duration, local_time, millis as ms, size};
use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Flex, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Sparkline, Table};

const DIM: Color = Color::Indexed(244);
const FAINT: Color = Color::Indexed(238);
const ACCENT: Color = Color::Indexed(110);
const OK: Color = Color::Indexed(108);
const WARN: Color = Color::Indexed(179);
const BAD: Color = Color::Indexed(167);

/// Stream rows shown at most; the busiest relay had nine streams at once.
const MAX_STREAMS: usize = 12;
/// Cells of the progress and budget bars.
const BAR: usize = 12;

/// Thresholds of the p95 time to first byte, in milliseconds, for browse, image and
/// media: about the 99th and 99.9th percentiles measured at two relays.
const SLOW_MS: [(f64, f64); 3] = [(1500.0, 5000.0), (1500.0, 5000.0), (5000.0, 10_000.0)];

/// Everything one frame shows.
pub struct Screen<'a> {
    pub view: Option<&'a View>,
    pub series: &'a [u64],
    pub problems: &'a [Problem],
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

fn count(n: u64, c: Color) -> Span<'static> {
    if n == 0 {
        dim("0")
    } else {
        colored(n.to_string(), c)
    }
}

/// A thin bar: `filled` of [`BAR`] cells in `color`, the rest faint.
fn bar(share: f64, color: Color) -> Vec<Span<'static>> {
    let filled = ((share.clamp(0.0, 1.0) * BAR as f64).round() as usize).min(BAR);
    vec![
        colored("━".repeat(filled), color),
        faint("─".repeat(BAR - filled)),
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

fn section(f: &mut Frame<'_>, area: Rect, title: &str, note: &str) {
    let used = title.chars().count() + note.chars().count() + 4;
    let rule = "─".repeat(usize::from(area.width).saturating_sub(used));
    let mut spans = vec![
        Span::styled(title.to_owned(), Style::new().add_modifier(Modifier::BOLD)),
        Span::raw("  "),
    ];
    if !note.is_empty() {
        spans.push(dim(note));
        spans.push(Span::raw("  "));
    }
    spans.push(faint(rule));
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

pub fn draw(f: &mut Frame<'_>, s: &Screen<'_>) {
    let area = f.area();
    let Some(v) = s.view else {
        let [_, middle, _, foot] = Layout::vertical([
            Constraint::Percentage(45),
            Constraint::Length(2),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .areas(area);
        let text = match s.error {
            Some(e) => vec![
                Line::from(colored("piano is not reachable", WARN)),
                Line::from(dim(e.to_owned())),
            ],
            None => vec![Line::from(dim("connecting…"))],
        };
        f.render_widget(Paragraph::new(text).alignment(Alignment::Center), middle);
        footer(f, foot, s);
        return;
    };
    let streams = v.streams.len().clamp(1, MAX_STREAMS) as u16;
    let sites = v.sites.len().max(1) as u16;
    let [head, spark, _, st, _, si, _, bottom, foot] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(streams + 2),
        Constraint::Length(1),
        Constraint::Length(sites + 2),
        Constraint::Length(1),
        Constraint::Min(3),
        Constraint::Length(1),
    ])
    .areas(area);
    header(f, head, v, s);
    let take = usize::from(spark.width);
    let tail = &s.series[s.series.len().saturating_sub(take)..];
    f.render_widget(
        Sparkline::default()
            .data(tail)
            .style(Style::new().fg(FAINT)),
        spark,
    );
    stream_table(f, st, v, s.full_addresses);
    site_table(f, si, v);
    if bottom.width >= 110 {
        let [l, _, r] = Layout::horizontal([
            Constraint::Percentage(48),
            Constraint::Length(3),
            Constraint::Min(0),
        ])
        .areas(bottom);
        upstreams(f, l, &v.budgets, &v.images);
        problems(f, r, s.problems, v.access_log.is_some());
    } else {
        let budgets = (v.budgets.len().max(1) + 3) as u16;
        let [l, _, r] = Layout::vertical([
            Constraint::Length(budgets),
            Constraint::Length(1),
            Constraint::Min(0),
        ])
        .areas(bottom);
        upstreams(f, l, &v.budgets, &v.images);
        problems(f, r, s.problems, v.access_log.is_some());
    }
    footer(f, foot, s);
}

fn header(f: &mut Frame<'_>, area: Rect, v: &View, s: &Screen<'_>) {
    let sep = || faint("   ·   ");
    let mut right = vec![
        dim("out "),
        rate(v.sent_rate),
        dim("   in "),
        rate(v.fetched_rate),
    ];
    let clock = [Span::raw("   "), dim(s.clock.clone())];
    // Pieces of the left side, least needed last; they go when the line is too short.
    let mut parts: Vec<Vec<Span<'static>>> = vec![vec![
        Span::styled("piano", Style::new().add_modifier(Modifier::BOLD)),
        dim(format!(" {}", v.version)),
    ]];
    if s.error.is_some() {
        parts.push(vec![sep(), colored("reconnecting", WARN)]);
    } else if s.paused {
        parts.push(vec![sep(), colored("paused", ACCENT)]);
    }
    parts.push(vec![
        sep(),
        Span::raw(format!("{:.1}", v.requests_rate)),
        dim(" req/s"),
    ]);
    parts.push(vec![
        sep(),
        Span::raw(v.connections.to_string()),
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
        State::Waiting(ms) => Line::from(vec![
            colored("● ", WARN),
            Span::raw(format!("waiting {}", secs(ms))),
        ]),
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

fn progress(r: &StreamRow) -> Line<'static> {
    match (r.position, r.size) {
        (Some(p), Some(n)) if n > 0 => {
            let share = p as f64 / n as f64;
            let mut spans = bar(share, ACCENT);
            spans.push(Span::raw(format!(" {:>3.0}%", share * 100.0)));
            Line::from(spans)
        }
        _ => Line::from(dim("—")),
    }
}

fn stream_table(f: &mut Frame<'_>, area: Rect, v: &View, full: bool) {
    let [title, body] = Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).areas(area);
    let note = match v.streams.len() {
        0 => String::new(),
        n if n > MAX_STREAMS => format!("{n} · showing {MAX_STREAMS}"),
        n => n.to_string(),
    };
    section(f, title, "Streams", &note);
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
        .take(MAX_STREAMS)
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
                Cell::from(progress(r)),
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

fn site_table(f: &mut Frame<'_>, area: Rect, v: &View) {
    let [title, body] = Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).areas(area);
    let note = match v.window_secs {
        0 => "starting · ttfb p50 / p95".to_owned(),
        s => format!("last {s}s · ttfb p50 / p95"),
    };
    section(f, title, "Sites", &note);
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

fn upstreams(f: &mut Frame<'_>, area: Rect, budgets: &[BudgetRow], img: &Images) {
    let [title, body, images] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(budgets.len().max(1) as u16 + 1),
        Constraint::Min(0),
    ])
    .areas(area);
    section(f, title, "Upstream budget", "");
    if budgets.is_empty() {
        f.render_widget(Paragraph::new(dim("  no upstream requests yet")), body);
    } else {
        let header = Row::new(vec![
            Cell::from(dim("upstream")),
            Cell::from(dim("budget")),
            right(dim("waiting")),
            right(dim("429")),
        ]);
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
            Row::new(vec![
                Cell::from(b.upstream.clone()),
                Cell::from(budget),
                right(count(b.waiting, WARN)),
                right(count(b.limited, BAD)),
            ])
        });
        let widths = [
            Constraint::Fill(1),
            Constraint::Length(BAR as u16 + 9),
            Constraint::Length(7),
            Constraint::Length(7),
        ];
        f.render_widget(
            Table::new(rows, widths).header(header).column_spacing(2),
            body,
        );
    }
    let line = if img.answered == 0 {
        Line::from(dim("images  none recently"))
    } else {
        let pct = img.local as f64 * 100.0 / img.answered as f64;
        Line::from(vec![
            dim("images  "),
            Span::raw(format!("{pct:.0}%")),
            dim(" without the upstream   "),
            Span::raw(img.fetched.to_string()),
            dim(" fetched   "),
            Span::raw(img.shared.to_string()),
            dim(" shared   "),
            count(img.refused, BAD),
            dim(" refused"),
        ])
    };
    f.render_widget(Paragraph::new(line), images);
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

fn problems(f: &mut Frame<'_>, area: Rect, list: &[Problem], log_on: bool) {
    let [title, body] = Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).areas(area);
    section(f, title, "Problems", "from the access log");
    if !log_on {
        f.render_widget(Paragraph::new(dim("  the access log is off")), body);
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
    let key =
        |k: &str, what: &str| vec![colored(k.to_owned(), ACCENT), dim(format!(" {what}    "))];
    let mut left = Vec::new();
    left.extend(key("q", "quit"));
    left.extend(key("p", if s.paused { "resume" } else { "pause" }));
    left.extend(key(
        "f",
        if s.full_addresses {
            "short addresses"
        } else {
            "full addresses"
        },
    ));
    let note = match s.error {
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
