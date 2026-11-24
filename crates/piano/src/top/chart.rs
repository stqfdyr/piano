//! Drawing primitives of `piano top`: sparklines, histograms, stacked bars and the
//! motion that marks bytes flowing. They return spans in the colours they are given.

use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Span;

const LEVELS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
/// One cell of a bar: a thick dash, centred like a line but heavier than box drawing,
/// and in the WGL4 set every common monospace font covers.
pub const BAR: &str = "▬";
/// The empty part of a bar: a thin line, so that on a light theme it stays lighter
/// than what is filled.
pub const TRACK: &str = "─";

fn styled(s: String, c: Color) -> Span<'static> {
    Span::styled(s, Style::new().fg(c))
}

/// The newest `width` values of `series` as one row of bars, right-aligned, scaled to
/// `max` or else the largest value shown. Zero draws nothing, anything else at least the lowest bar.
pub fn spark(series: &[u64], width: usize, max: Option<u64>, color: Color) -> Span<'static> {
    let tail = &series[series.len().saturating_sub(width)..];
    let top = max
        .unwrap_or_else(|| tail.iter().copied().max().unwrap_or(0))
        .max(1);
    let mut s = " ".repeat(width - tail.len());
    for &v in tail {
        s.push(level(v, top, LEVELS.len()).map_or(' ', |i| LEVELS[i]));
    }
    styled(s, color)
}

/// `series` widened to fill about `width` cells: each value repeated as often as the
/// newest values still fit, so a minute of replies spans a wide screen.
pub fn stretch(series: &[u64], width: usize) -> Vec<u64> {
    let times = (width / series.len().max(1)).max(1);
    let keep = width / times;
    series[series.len().saturating_sub(keep)..]
        .iter()
        .flat_map(|&v| std::iter::repeat_n(v, times))
        .collect()
}

/// Which of `steps` steps `v` reaches out of `top`, from 0; `None` for zero.
fn level(v: u64, top: u64, steps: usize) -> Option<usize> {
    if v == 0 {
        return None;
    }
    let share = (v as f64 / top as f64).min(1.0);
    Some(((share * steps as f64).ceil() as usize).clamp(1, steps) - 1)
}

/// Columns of `values` as bars `rows` high, scaled to the largest, top row first.
pub fn columns(values: &[u64], rows: usize) -> Vec<String> {
    let top = values.iter().copied().max().unwrap_or(0).max(1);
    let steps = rows * LEVELS.len();
    let heights: Vec<usize> = values
        .iter()
        .map(|&v| level(v, top, steps).map_or(0, |i| i + 1))
        .collect();
    (0..rows)
        .map(|r| {
            // Eighths below this row's floor are drawn by the rows beneath it.
            let floor = (rows - 1 - r) * LEVELS.len();
            heights
                .iter()
                .map(|&h| match h.saturating_sub(floor) {
                    0 => ' ',
                    n => LEVELS[n.min(LEVELS.len()) - 1],
                })
                .collect()
        })
        .collect()
}

/// Shares of `width` cells, by largest remainder so that every part present gets a cell
/// while there are cells to give; a faint line when there is nothing.
pub fn stacked(parts: &[(u64, Color)], width: usize, empty: Color) -> Vec<Span<'static>> {
    let total: u64 = parts.iter().map(|p| p.0).sum();
    if total == 0 || width == 0 {
        return vec![styled("─".repeat(width), empty)];
    }
    let exact: Vec<f64> = parts
        .iter()
        .map(|p| p.0 as f64 * width as f64 / total as f64)
        .collect();
    let mut cells: Vec<usize> = exact.iter().map(|x| x.floor() as usize).collect();
    for (i, p) in parts.iter().enumerate() {
        if p.0 > 0 && cells[i] == 0 {
            cells[i] = 1;
        }
    }
    let mut order: Vec<usize> = (0..parts.len()).collect();
    order.sort_by(|&a, &b| (exact[b] - exact[b].floor()).total_cmp(&(exact[a] - exact[a].floor())));
    let mut used: usize = cells.iter().sum();
    for &i in order.iter().cycle().take(parts.len() * width) {
        if used >= width {
            break;
        }
        if parts[i].0 > 0 {
            cells[i] += 1;
            used += 1;
        }
    }
    // Rounding up small parts can overshoot; take the excess from the largest.
    while used > width {
        let Some(big) = (0..cells.len()).max_by_key(|&i| cells[i]) else {
            break;
        };
        cells[big] -= 1;
        used -= 1;
    }
    parts
        .iter()
        .zip(cells)
        .filter(|(_, n)| *n > 0)
        .map(|(p, n)| styled("█".repeat(n), p.1))
        .collect()
}

/// Where a light band of `band` cells is at `phase` seconds on a run of `len` cells: it
/// sweeps across at `speed` cells a second and leaves before coming back.
pub fn band_at(len: usize, band: usize, speed: f64, phase: f64) -> std::ops::Range<usize> {
    let period = len + 2 * band;
    let lead = (phase * speed).max(0.0) as usize % period.max(1);
    lead.saturating_sub(band).min(len)..lead.min(len)
}

/// Colours of a file and a stream's place in it.
pub struct Scrub {
    pub before: Color,
    pub this: Color,
    pub shine: Color,
    pub head: Color,
    pub rest: Color,
}

/// A stream's place in its file over `width` cells: the part before this response began, the
/// part this response delivered, the playhead and the rest. When `flowing`, a light band
/// travels over the delivered part.
pub fn scrub(
    width: usize,
    size: u64,
    start: u64,
    position: u64,
    flowing: bool,
    phase: f64,
    c: &Scrub,
) -> Vec<Span<'static>> {
    if width == 0 {
        return Vec::new();
    }
    let cell = |x: u64| ((x.min(size) as f64 / size.max(1) as f64) * width as f64) as usize;
    let head = cell(position).min(width - 1);
    let from = cell(start).min(head);
    let shine = if flowing && head > from {
        let r = band_at(head - from, 3, 14.0, phase);
        r.start + from..r.end + from
    } else {
        0..0
    };
    let mut spans = Vec::new();
    let mut push = |s: String, st: Style| spans.push(Span::styled(s, st));
    push(BAR.repeat(from), Style::new().fg(c.before));
    for i in from..head {
        let fg = if shine.contains(&i) { c.shine } else { c.this };
        push(BAR.into(), Style::new().fg(fg));
    }
    push(
        "╋".into(),
        Style::new().fg(c.head).add_modifier(Modifier::BOLD),
    );
    push(TRACK.repeat(width - head - 1), Style::new().fg(c.rest));
    spans
}

/// A band moving back and forth over `width` cells: something is awaited.
pub fn scanner(width: usize, phase: f64, band: Color, rest: Color) -> Vec<Span<'static>> {
    if width == 0 {
        return Vec::new();
    }
    let len = 4.min(width);
    let travel = width - len;
    let steps = (phase * 18.0) as usize % (2 * travel).max(1);
    let at = if steps <= travel {
        steps
    } else {
        2 * travel - steps
    };
    vec![
        styled(TRACK.repeat(at), rest),
        styled(BAR.repeat(len), band),
        styled(TRACK.repeat(width - at - len), rest),
    ]
}

/// A grey that fades from bright to dark as `level` falls from 1 to 0.
pub fn fade(level: f64) -> Color {
    Color::Indexed(238 + (level.clamp(0.0, 1.0) * 17.0).round() as u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(spans: &[Span<'_>]) -> String {
        spans.iter().map(|s| s.content.as_ref()).collect()
    }

    #[test]
    fn sparklines_scale_and_pad() {
        assert_eq!(spark(&[0, 4, 8], 5, None, Color::Reset).content, "   ▄█");
        assert_eq!(
            spark(&[1, 2, 3, 4, 5, 6], 3, Some(12), Color::Reset).content,
            "▃▄▄"
        );
        assert_eq!(spark(&[], 2, None, Color::Reset).content, "  ");
    }

    #[test]
    fn a_band_stays_on_its_run_at_any_phase() {
        for len in [0, 1, 3, 12, 40] {
            for step in 0..2000 {
                let r = band_at(len, 3, 14.0, f64::from(step) * 0.013);
                assert!(r.start <= r.end && r.end <= len, "{len} {step} {r:?}");
            }
        }
    }

    #[test]
    fn stretched_series_fill_the_width_with_the_newest_values() {
        assert_eq!(stretch(&[1, 2, 3], 7), [1, 1, 2, 2, 3, 3]);
        assert_eq!(stretch(&[1, 2, 3], 2), [2, 3]);
        assert_eq!(stretch(&[], 5), Vec::<u64>::new());
        assert_eq!(stretch(&[4], 0), Vec::<u64>::new());
    }

    #[test]
    fn columns_stack_eighths_over_rows() {
        let rows = columns(&[0, 1, 8, 16], 2);
        assert_eq!(rows, ["   █", " ▁██"]);
        assert_eq!(columns(&[], 3), ["", "", ""]);
    }

    #[test]
    fn stacked_bars_keep_their_width_and_every_part() {
        for (parts, width) in [
            (vec![1000, 1, 0, 1], 10usize),
            (vec![1, 1, 1, 1], 3),
            (vec![3, 3, 3], 10),
            (vec![5], 1),
        ] {
            let p: Vec<(u64, Color)> = parts.iter().map(|&n| (n, Color::Reset)).collect();
            let out = stacked(&p, width, Color::Reset);
            assert_eq!(text(&out).chars().count(), width, "{parts:?}");
            if width >= parts.iter().filter(|&&n| n > 0).count() {
                assert_eq!(out.len(), parts.iter().filter(|&&n| n > 0).count());
            }
        }
        assert_eq!(
            text(&stacked(&[(0, Color::Reset)], 4, Color::Reset)),
            "────"
        );
    }

    #[test]
    fn a_scrub_bar_is_as_wide_as_asked_and_marks_the_playhead() {
        let c = Scrub {
            before: Color::Reset,
            this: Color::Reset,
            shine: Color::Reset,
            head: Color::Reset,
            rest: Color::Reset,
        };
        for (size, start, pos) in [
            (100, 20, 50),
            (100, 0, 0),
            (100, 100, 100),
            (0, 0, 0),
            (10, 50, 5),
        ] {
            for phase in [0.0, 0.7, 3.3] {
                let t = text(&scrub(20, size, start, pos, true, phase, &c));
                assert_eq!(t.chars().count(), 20, "{size} {start} {pos}");
                assert_eq!(t.matches('╋').count(), 1);
            }
        }
        assert!(scrub(0, 1, 0, 0, true, 0.0, &c).is_empty());
        for phase in [0.0, 0.4, 9.9] {
            for w in [0, 1, 3, 30] {
                assert_eq!(
                    text(&scanner(w, phase, Color::Reset, Color::Reset))
                        .chars()
                        .count(),
                    w
                );
            }
        }
    }
}
