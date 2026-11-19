//! Bounded chart geometry.
//!
//! A sparkline used to emit one line segment per retained value, every frame, for every
//! card. A chart keeps up to [`crate::ipc::Series::MAX_POINTS`] values, so the cost of a
//! frame grew with the length of the session: after a long run each frame tessellated
//! hundreds of thousands of segments, which is exactly how a window degrades into
//! "Not Responding" while it is being resized or scrolled.
//!
//! [`envelope`] reduces any number of values to at most two points per pixel column — the
//! minimum and the maximum of the values that fall into that column, in arrival order — so
//! the work of drawing a chart is bounded by its width, not by the session length. Peaks
//! are preserved: the global minimum and maximum of the finite values are always part of
//! the result. Non-finite values are skipped, never drawn as zero.

/// One vertex of a reduced chart: `x` in `0.0..=1.0` across the chart, `value` unscaled.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ChartPoint {
    pub x: f32,
    pub value: f64,
}

/// The reduced chart and the value range it spans.
#[derive(Debug, Clone, PartialEq)]
pub struct Envelope {
    pub points: Vec<ChartPoint>,
    pub min: f64,
    pub max: f64,
}

/// One pixel column being reduced: `(column, (index, min), (index, max))`.
type Bucket = (usize, (usize, f64), (usize, f64));

/// Reduce `values` to at most `2 * columns + 2` vertices: the minimum and maximum of each
/// column, plus the oldest and the newest finite value so both edges of the chart are exact.
///
/// `len` is the number of items `values` yields (finite or not); it positions each value
/// on the x axis exactly as the unreduced chart did, so the shape does not shift when a
/// series grows past the width of its card. Returns `None` when fewer than two finite
/// values exist or there is no column to draw into.
pub fn envelope<I>(values: I, len: usize, columns: usize) -> Option<Envelope>
where
    I: IntoIterator<Item = f64>,
{
    if columns == 0 || len < 2 {
        return None;
    }
    let span = (len - 1) as f64;
    let mut points: Vec<ChartPoint> = Vec::with_capacity(columns.saturating_mul(2).min(len));
    let mut min = f64::INFINITY;
    let mut max = f64::NEG_INFINITY;
    let mut finite = 0usize;
    let mut first_finite: Option<(usize, f64)> = None;
    let mut last_finite: Option<(usize, f64)> = None;
    // The bucket being filled: its column and its min/max entries (index, value).
    let mut bucket: Option<Bucket> = None;
    // A vertex for an index that is already the last vertex is not repeated.
    let push = |points: &mut Vec<ChartPoint>, entry: (usize, f64)| {
        let x = (entry.0 as f64 / span) as f32;
        if points.last().is_none_or(|last| last.x < x) {
            points.push(ChartPoint { x, value: entry.1 });
        }
    };
    let flush = |points: &mut Vec<ChartPoint>, lo: (usize, f64), hi: (usize, f64)| {
        let (first, second) = if lo.0 <= hi.0 { (lo, hi) } else { (hi, lo) };
        push(points, first);
        push(points, second);
    };
    for (index, value) in values.into_iter().enumerate().take(len) {
        if !value.is_finite() {
            continue;
        }
        finite += 1;
        if first_finite.is_none() {
            first_finite = Some((index, value));
        }
        last_finite = Some((index, value));
        min = min.min(value);
        max = max.max(value);
        // The column a value falls into; the last value lands in the last column.
        let column = ((index as f64 / span) * (columns as f64 - 1.0)).round() as usize;
        match bucket.as_mut() {
            Some((current, lo, hi)) if *current == column => {
                if value < lo.1 {
                    *lo = (index, value);
                }
                if value > hi.1 {
                    *hi = (index, value);
                }
            }
            _ => {
                if let Some((_, lo, hi)) = bucket.take() {
                    flush(&mut points, lo, hi);
                }
                bucket = Some((column, (index, value), (index, value)));
            }
        }
        // The oldest value is the left edge of the chart and is drawn first.
        if points.is_empty() && first_finite == Some((index, value)) {
            push(&mut points, (index, value));
        }
    }
    if let Some((_, lo, hi)) = bucket {
        flush(&mut points, lo, hi);
    }
    // The newest value is the right edge of the chart: it is always drawn, even when it
    // is neither the minimum nor the maximum of its column.
    if let Some(last) = last_finite {
        push(&mut points, last);
    }
    if finite < 2 || points.len() < 2 {
        return None;
    }
    Some(Envelope { points, min, max })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_long_series_is_bounded_by_the_width_not_the_length() {
        let values: Vec<f64> = (0..10_000)
            .map(|i| (i as f64 * 0.37).sin() * 50.0)
            .collect();
        let reduced = envelope(values.iter().copied(), values.len(), 240).expect("chart");
        assert!(
            reduced.points.len() <= 482,
            "at most two vertices per column plus both edges, got {}",
            reduced.points.len()
        );
        assert!(reduced.points.len() >= 240, "every column is represented");
    }

    #[test]
    fn peaks_survive_the_reduction() {
        let mut values = vec![10.0; 9_000];
        values[4_321] = 99.0;
        values[7_777] = -5.0;
        let reduced = envelope(values.iter().copied(), values.len(), 100).expect("chart");
        assert_eq!(reduced.max, 99.0);
        assert_eq!(reduced.min, -5.0);
        assert!(reduced.points.iter().any(|p| p.value == 99.0));
        assert!(reduced.points.iter().any(|p| p.value == -5.0));
    }

    #[test]
    fn x_is_monotonic_and_spans_the_chart() {
        let values: Vec<f64> = (0..5_000).map(|i| (i % 17) as f64).collect();
        let reduced = envelope(values.iter().copied(), values.len(), 300).expect("chart");
        assert!(reduced.points.windows(2).all(|w| w[0].x <= w[1].x));
        assert_eq!(reduced.points.first().unwrap().x, 0.0);
        assert_eq!(reduced.points.last().unwrap().x, 1.0);
    }

    #[test]
    fn a_short_series_is_drawn_unchanged() {
        let values = [1.0, 3.0, 2.0];
        let reduced = envelope(values.iter().copied(), values.len(), 200).expect("chart");
        let drawn: Vec<f64> = reduced.points.iter().map(|p| p.value).collect();
        assert_eq!(drawn, vec![1.0, 3.0, 2.0]);
    }

    #[test]
    fn non_finite_values_are_skipped_not_drawn_as_zero() {
        let values = [f64::NAN, 4.0, f64::INFINITY, 6.0];
        let reduced = envelope(values.iter().copied(), values.len(), 50).expect("chart");
        assert!(reduced.points.iter().all(|p| p.value.is_finite()));
        assert_eq!(reduced.min, 4.0);
        assert_eq!(reduced.max, 6.0);
        assert!(!reduced.points.iter().any(|p| p.value == 0.0));
    }

    #[test]
    fn nothing_to_draw_is_none() {
        assert!(envelope([1.0].iter().copied(), 1, 10).is_none());
        assert!(envelope([f64::NAN, 2.0].iter().copied(), 2, 10).is_none());
        assert!(envelope([1.0, 2.0].iter().copied(), 2, 0).is_none());
    }
}
