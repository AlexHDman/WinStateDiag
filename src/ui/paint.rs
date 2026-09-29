//! Reusable, deterministic drawing primitives (card system, text-on-baseline,
//! anti-aliased gradient ring arcs, continuous progress bars, icon glyphs and
//! the button/radio/checkbox family). Everything here is pure presentation.

use super::fonts::font;
use super::tokens::{color as c, layout as l, typography::TextStyle};
use egui::epaint::{Mesh, Shape};
use egui::{
    Align, Color32, CornerRadius, Painter, Pos2, Rect, Response, Sense, Stroke, StrokeKind, Ui,
    pos2, vec2,
};

// ---------------------------------------------------------------------------
// Card system
// ---------------------------------------------------------------------------

/// The one card primitive: graphite/navy fill, 1px cool-blue border drawn
/// inside the rect, radius 7 (all cards derive from this).
pub fn card(painter: &Painter, rect: Rect) {
    painter.rect(
        rect,
        CornerRadius::same(l::CARD_RADIUS),
        c::BG_CARD,
        Stroke::new(l::CARD_BORDER_WIDTH, c::BORDER_NORMAL),
        StrokeKind::Inside,
    );
}

/// Nested card (Modules panel inside Overall Progress).
pub fn inner_card(painter: &Painter, rect: Rect) {
    painter.rect(
        rect,
        CornerRadius::same(l::INNER_CARD_RADIUS),
        c::BG_CARD_INNER,
        Stroke::new(1.0, c::BORDER_INNER),
        StrokeKind::Inside,
    );
}

// ---------------------------------------------------------------------------
// Text placed on a baseline (the master is measured in baselines).
// ---------------------------------------------------------------------------

pub fn text(
    painter: &Painter,
    x: f32,
    baseline: f32,
    align: Align,
    text: &str,
    style: TextStyle,
    color: Color32,
) -> Rect {
    let galley = painter.layout_no_wrap(text.to_owned(), font(style), color);
    let ascent = galley
        .rows
        .first()
        .and_then(|r| r.row.glyphs.first().map(|g| r.pos.y + g.pos.y))
        .unwrap_or(style.size * 0.8);
    let w = galley.size().x;
    let left = match align {
        Align::Min => x,
        Align::Center => x - w / 2.0,
        Align::Max => x - w,
    };
    let top = baseline - ascent;
    let rect = Rect::from_min_size(pos2(left, top), galley.size());
    painter.galley(rect.min, galley, color);
    rect
}

/// Same as [`text`] but elides with "…" so the text never exceeds `max_w`.
pub fn text_clipped(
    painter: &Painter,
    x: f32,
    baseline: f32,
    max_w: f32,
    text_value: &str,
    style: TextStyle,
    color: Color32,
) -> Rect {
    let fits = |s: &str| {
        painter
            .layout_no_wrap(s.to_owned(), font(style), color)
            .size()
            .x
            <= max_w
    };
    if fits(text_value) {
        return text(painter, x, baseline, Align::Min, text_value, style, color);
    }
    let chars: Vec<char> = text_value.chars().collect();
    let mut n = chars.len();
    while n > 0 {
        let candidate: String = chars[..n].iter().collect::<String>() + "…";
        if fits(&candidate) {
            return text(painter, x, baseline, Align::Min, &candidate, style, color);
        }
        n -= 1;
    }
    text(painter, x, baseline, Align::Min, "…", style, color)
}

pub fn text_width(painter: &Painter, text_value: &str, style: TextStyle) -> f32 {
    painter
        .layout_no_wrap(text_value.to_owned(), font(style), Color32::WHITE)
        .size()
        .x
}

// ---------------------------------------------------------------------------
// Colour helpers
// ---------------------------------------------------------------------------

pub fn lerp(a: Color32, b: Color32, t: f32) -> Color32 {
    a.lerp_to_gamma(b, t.clamp(0.0, 1.0))
}

/// Visual intensity `k` (0..1): blends `col` from the card background
/// (k = 0) to its full value (k = 1). Used to keep progress decoration
/// quieter than the information it supports.
pub fn intensity(col: Color32, k: f32) -> Color32 {
    lerp(c::BG_CARD, col, k)
}

/// Conic gradient lookup (`deg` 0..360, 0 = 12 o'clock, clockwise).
pub fn conic(stops: &[(f32, Color32)], deg: f32) -> Color32 {
    let d = deg.rem_euclid(360.0);
    for w in stops.windows(2) {
        let (a0, c0) = w[0];
        let (a1, c1) = w[1];
        if d >= a0 && d <= a1 {
            let t = if a1 > a0 { (d - a0) / (a1 - a0) } else { 0.0 };
            return lerp(c0, c1, t);
        }
    }
    stops.last().map(|s| s.1).unwrap_or(Color32::WHITE)
}

fn with_alpha(col: Color32, a: f32) -> Color32 {
    col.gamma_multiply(a.clamp(0.0, 1.0))
}

// ---------------------------------------------------------------------------
// Rings: anti-aliased arc bands with per-angle colour.
// ---------------------------------------------------------------------------

/// Polar point: `deg` 0 = up, clockwise.
pub fn polar(center: Pos2, r: f32, deg: f32) -> Pos2 {
    let a = deg.to_radians();
    pos2(center.x + r * a.sin(), center.y - r * a.cos())
}

/// Arc band between `r_mid ± thickness/2` from `deg0` to `deg1` (clockwise),
/// coloured per angle. Edges are feathered by 1px for anti-aliasing (the
/// same approach epaint uses for its own shapes).
pub fn arc_band(
    painter: &Painter,
    center: Pos2,
    r_mid: f32,
    thickness: f32,
    deg0: f32,
    deg1: f32,
    color_at: impl Fn(f32) -> Color32,
) {
    if deg1 <= deg0 || thickness <= 0.0 {
        return;
    }
    let ppp = painter.pixels_per_point();
    let f = 0.5 / ppp;
    let r_in = r_mid - thickness / 2.0;
    let r_out = r_mid + thickness / 2.0;
    let radii = [r_in - f, r_in + f, r_out - f, r_out + f];
    let alphas = [0.0, 1.0, 1.0, 0.0];
    let arc_len = (deg1 - deg0).to_radians() * r_out;
    let steps = ((arc_len * ppp / 1.5).ceil() as usize).clamp(8, 1024);
    let mut mesh = Mesh::default();
    for i in 0..=steps {
        let deg = deg0 + (deg1 - deg0) * (i as f32 / steps as f32);
        let col = color_at(deg);
        for (r, a) in radii.iter().zip(alphas.iter()) {
            mesh.colored_vertex(polar(center, *r, deg), with_alpha(col, *a));
        }
    }
    for i in 0..steps as u32 {
        let base = i * 4;
        let next = base + 4;
        for band in 0..3u32 {
            let a = base + band;
            let b = base + band + 1;
            let cc = next + band;
            let d = next + band + 1;
            mesh.add_triangle(a, b, d);
            mesh.add_triangle(a, d, cc);
        }
    }
    painter.add(Shape::mesh(mesh));
}

/// Full-circle ring stroke (AA via epaint).
pub fn ring_track(painter: &Painter, center: Pos2, r_mid: f32, thickness: f32, color: Color32) {
    arc_band(painter, center, r_mid, thickness, 0.0, 360.0, |_| color);
}

// ---------------------------------------------------------------------------
// Continuous progress bars (never segmented).
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub struct BarStyle {
    pub radius: u8,
    pub track: Color32,
    pub track_border: Color32,
}

pub const BAR_STAGE: BarStyle = BarStyle {
    radius: l::PROGRESS_BAR_RADIUS,
    track: c::PROGRESS_TRACK,
    track_border: c::PROGRESS_TRACK_BORDER,
};
pub const BAR_STAGE_PENDING: BarStyle = BarStyle {
    radius: l::PROGRESS_BAR_RADIUS,
    track: c::PROGRESS_TRACK_PENDING,
    track_border: c::PROGRESS_TRACK_PENDING_BORDER,
};
/// `fraction = Some(f)`: determinate fill. `None` + `animate_time = Some(t)`:
/// indeterminate sliding highlight (no fabricated percentage).
pub fn progress_bar(
    painter: &Painter,
    rect: Rect,
    style: BarStyle,
    fraction: Option<f32>,
    fill: Color32,
    animate_time: Option<f64>,
) {
    let cr = CornerRadius::same(style.radius.min((rect.height() / 2.0) as u8));
    painter.rect(
        rect,
        cr,
        style.track,
        Stroke::new(1.0, style.track_border),
        StrokeKind::Inside,
    );
    match (fraction, animate_time) {
        (Some(f), _) => {
            let f = f.clamp(0.0, 1.0);
            if f > 0.0 {
                let w = (rect.width() * f).max(rect.height());
                let fill_rect = Rect::from_min_size(
                    rect.min + vec2(0.0, 1.0),
                    vec2(w.min(rect.width()), rect.height() - 2.0),
                );
                painter.rect_filled(fill_rect, cr, fill);
            }
        }
        (None, Some(t)) => {
            let cycle = 1.7;
            let phase = ((t % cycle) / cycle) as f32;
            let seg_w = rect.width() * 0.3;
            let x = rect.left() - seg_w + (rect.width() + seg_w) * phase;
            let seg = Rect::from_min_max(
                pos2(x.max(rect.left()), rect.top()),
                pos2((x + seg_w).min(rect.right()), rect.bottom()),
            );
            if seg.width() > 1.0 {
                painter.rect_filled(seg, cr, fill);
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Status icons
// ---------------------------------------------------------------------------

pub fn icon_check_circle(painter: &Painter, center: Pos2, diameter: f32, fill: Color32) {
    let r = diameter / 2.0;
    painter.circle_filled(center, r, fill);
    let s = r / 11.0;
    let pts = vec![
        center + vec2(-5.2 * s, 0.2 * s),
        center + vec2(-1.6 * s, 3.8 * s),
        center + vec2(5.4 * s, -3.6 * s),
    ];
    painter.add(Shape::line(pts, Stroke::new(2.6 * s, c::BG_CARD)));
}

pub fn icon_radio_active(painter: &Painter, center: Pos2, diameter: f32, col: Color32) {
    // Master: thin accent ring, dark gap, blue disc, bright white-blue core.
    let r = diameter / 2.0;
    circle_outline(painter, center, r, 2.2, col);
    painter.circle_filled(center, r * 0.64, c::BLUE_DARK);
    painter.circle_filled(center, r * 0.50, lerp(col, Color32::WHITE, 0.55));
    painter.circle_filled(center, r * 0.36, Color32::from_rgb(0xee, 0xf6, 0xff));
}

/// Circle outline whose OUTER edge is at `r_outer` (epaint strokes circles
/// outside the radius, so the radius is compensated here).
pub fn circle_outline(painter: &Painter, center: Pos2, r_outer: f32, width: f32, col: Color32) {
    painter.circle_stroke(center, (r_outer - width).max(0.0), Stroke::new(width, col));
}

pub fn icon_ring(painter: &Painter, center: Pos2, diameter: f32, col: Color32) {
    circle_outline(painter, center, diameter / 2.0, 2.5, col);
}

pub fn icon_error(painter: &Painter, center: Pos2, diameter: f32) {
    let r = diameter / 2.0;
    painter.circle_filled(center, r, c::RED_ERROR);
    let d = r * 0.38;
    let st = Stroke::new(2.2, Color32::WHITE);
    painter.line_segment([center + vec2(-d, -d), center + vec2(d, d)], st);
    painter.line_segment([center + vec2(-d, d), center + vec2(d, -d)], st);
}

pub fn icon_document(painter: &Painter, rect: Rect, col: Color32) {
    let fold = rect.width() * 0.34;
    let st = Stroke::new(2.4, col);
    let p = |x: f32, y: f32| pos2(rect.left() + x, rect.top() + y);
    let (w, h) = (rect.width(), rect.height());
    let outline = vec![
        p(1.5, 1.5),
        p(w - fold, 1.5),
        p(w - 1.5, fold),
        p(w - 1.5, h - 1.5),
        p(1.5, h - 1.5),
    ];
    painter.add(Shape::closed_line(outline, st));
    painter.add(Shape::line(
        vec![p(w - fold, 1.5), p(w - fold, fold), p(w - 1.5, fold)],
        st,
    ));
}

pub fn icon_clock(painter: &Painter, rect: Rect, col: Color32) {
    let center = rect.center();
    let r = rect.width().min(rect.height()) / 2.0 - 1.5;
    circle_outline(painter, center, r + 1.2, 2.4, col);
    let st = Stroke::new(2.2, col);
    painter.line_segment([center, center + vec2(0.0, -r * 0.55)], st);
    painter.line_segment([center, center + vec2(r * 0.45, r * 0.3)], st);
}

pub fn icon_hourglass(painter: &Painter, rect: Rect, col: Color32) {
    let st = Stroke::new(2.3, col);
    let (x0, x1, y0, y1) = (
        rect.left() + 2.0,
        rect.right() - 2.0,
        rect.top() + 1.5,
        rect.bottom() - 1.5,
    );
    let cx = rect.center().x;
    let cy = rect.center().y;
    painter.line_segment([pos2(x0 - 1.0, y0), pos2(x1 + 1.0, y0)], st);
    painter.line_segment([pos2(x0 - 1.0, y1), pos2(x1 + 1.0, y1)], st);
    painter.add(Shape::line(
        vec![
            pos2(x0 + 1.0, y0),
            pos2(x0 + 1.0, y0 + 4.0),
            pos2(cx - 1.5, cy),
            pos2(x0 + 1.0, y1 - 4.0),
            pos2(x0 + 1.0, y1),
        ],
        st,
    ));
    painter.add(Shape::line(
        vec![
            pos2(x1 - 1.0, y0),
            pos2(x1 - 1.0, y0 + 4.0),
            pos2(cx + 1.5, cy),
            pos2(x1 - 1.0, y1 - 4.0),
            pos2(x1 - 1.0, y1),
        ],
        st,
    ));
    painter.add(Shape::convex_polygon(
        vec![
            pos2(cx, y1 - 7.0),
            pos2(x1 - 3.0, y1 - 2.0),
            pos2(x0 + 3.0, y1 - 2.0),
        ],
        col,
        Stroke::NONE,
    ));
}

/// Heartbeat/pulse glyph used as the application mark in the header.
pub fn icon_pulse(painter: &Painter, rect: Rect, col: Color32) {
    let p = |fx: f32, fy: f32| {
        pos2(
            rect.left() + fx * rect.width(),
            rect.top() + fy * rect.height(),
        )
    };
    let pts = vec![
        p(0.0, 0.55),
        p(0.22, 0.55),
        p(0.30, 0.38),
        p(0.37, 0.72),
        p(0.46, 0.02),
        p(0.56, 0.98),
        p(0.64, 0.30),
        p(0.71, 0.62),
        p(0.78, 0.55),
        p(1.0, 0.55),
    ];
    painter.add(Shape::line(
        pts.clone(),
        Stroke::new(7.0, col.gamma_multiply(0.18)),
    ));
    painter.add(Shape::line(pts, Stroke::new(3.0, col)));
}

pub fn icon_trash(painter: &Painter, rect: Rect, col: Color32) {
    // Master glyph: lid bar with a small handle, tapered bin, two slots.
    let st = Stroke::new(1.8, col);
    let (l, r, t, b) = (rect.left(), rect.right(), rect.top(), rect.bottom());
    let cx = rect.center().x;
    let lid_y = t + 4.0;
    painter.line_segment([pos2(l, lid_y), pos2(r, lid_y)], st);
    painter.add(Shape::line(
        vec![
            pos2(cx - 3.0, lid_y),
            pos2(cx - 3.0, t + 1.0),
            pos2(cx + 3.0, t + 1.0),
            pos2(cx + 3.0, lid_y),
        ],
        st,
    ));
    painter.add(Shape::line(
        vec![
            pos2(l + 2.0, lid_y + 2.0),
            pos2(l + 3.0, b - 1.0),
            pos2(r - 3.0, b - 1.0),
            pos2(r - 2.0, lid_y + 2.0),
        ],
        st,
    ));
    for dx in [-2.2, 2.2] {
        painter.line_segment(
            [pos2(cx + dx, lid_y + 5.0), pos2(cx + dx, b - 4.5)],
            Stroke::new(1.6, col),
        );
    }
}

pub fn icon_play(painter: &Painter, rect: Rect, col: Color32) {
    painter.add(Shape::convex_polygon(
        vec![
            pos2(rect.left(), rect.top()),
            pos2(rect.right(), rect.center().y),
            pos2(rect.left(), rect.bottom()),
        ],
        col,
        Stroke::NONE,
    ));
}

pub fn icon_refresh(painter: &Painter, center: Pos2, diameter: f32, col: Color32) {
    let r = diameter / 2.0;
    let st = Stroke::new(2.0, col);
    let steps = 36;
    let pts: Vec<Pos2> = (0..=steps)
        .map(|i| polar(center, r, 60.0 + 270.0 * i as f32 / steps as f32))
        .collect();
    let tip = *pts.last().unwrap_or(&center);
    painter.add(Shape::line(pts, st));
    painter.add(Shape::convex_polygon(
        vec![
            tip + vec2(-4.0, -3.5),
            tip + vec2(4.0, -3.5),
            tip + vec2(0.5, 3.5),
        ],
        col,
        Stroke::NONE,
    ));
}

// ---------------------------------------------------------------------------
// Buttons (one family: primary / secondary / disabled, real hover/pressed).
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ButtonKind {
    Primary,
    Secondary,
    /// Secondary look with the softer label colour (journal "Очистить").
    Subtle,
    /// Non-interactive secondary look: the control is present and readable
    /// (e.g. CryptoPro ReHash while HASH is fine) but not clickable. Unlike
    /// the disabled grey it keeps the card composition calm and legible.
    Passive,
}

#[derive(Clone, Copy)]
pub enum ButtonIcon {
    None,
    Play,
    Refresh,
    /// Refresh glyph in the accent blue (CryptoPro ReHash).
    RefreshAccent,
    Trash,
}

pub fn button(
    ui: &mut Ui,
    rect: Rect,
    id_salt: &str,
    label: &str,
    kind: ButtonKind,
    enabled: bool,
    icon: ButtonIcon,
    style: TextStyle,
) -> Response {
    let sense = if enabled {
        Sense::click()
    } else {
        Sense::hover()
    };
    let response = ui.interact(rect, ui.id().with(id_salt), sense);
    let hovered = enabled && response.hovered();
    let pressed = enabled && response.is_pointer_button_down_on();
    let (fill, border, text_col) = match (kind, enabled) {
        (ButtonKind::Passive, _) => (
            c::BUTTON_SECONDARY_FILL,
            c::BUTTON_SECONDARY_BORDER,
            c::TEXT_BODY,
        ),
        (_, false) => (
            c::BUTTON_DISABLED_FILL,
            c::BORDER_INNER,
            c::BUTTON_DISABLED_TEXT,
        ),
        (ButtonKind::Primary, true) => {
            let f = if pressed {
                c::BLUE_DARK
            } else if hovered {
                c::BLUE_BRIGHT
            } else {
                c::BLUE_PRIMARY
            };
            (f, f, Color32::WHITE)
        }
        (ButtonKind::Secondary | ButtonKind::Subtle, true) => {
            let f = if pressed {
                c::BUTTON_SECONDARY_PRESSED
            } else if hovered {
                c::BUTTON_SECONDARY_HOVER
            } else {
                c::BUTTON_SECONDARY_FILL
            };
            let b = if hovered {
                c::BORDER_ACTIVE
            } else {
                c::BUTTON_SECONDARY_BORDER
            };
            let t = if kind == ButtonKind::Subtle {
                c::BUTTON_SUBTLE_TEXT
            } else {
                c::TEXT_PRIMARY
            };
            (f, b, t)
        }
    };
    let painter = ui.painter();
    painter.rect(
        rect,
        CornerRadius::same(l::BUTTON_RADIUS),
        fill,
        Stroke::new(1.0, border),
        StrokeKind::Inside,
    );
    // (icon box width, gap to the label) per icon, measured on the master.
    let (icon_box, icon_gap) = match icon {
        ButtonIcon::None => (0.0, 0.0),
        ButtonIcon::Trash => (17.0, 15.0),
        ButtonIcon::Play | ButtonIcon::Refresh | ButtonIcon::RefreshAccent => {
            (style.size, style.size * 0.05 + 10.0)
        }
    };
    let icon_w = icon_box + icon_gap;
    let tw = text_width(painter, label, style);
    let total = tw + icon_w;
    let x0 = rect.center().x - total / 2.0;
    let cy = rect.center().y;
    let icon_center = pos2(x0 + icon_box * 0.5, cy);
    let isz = style.size * 1.0;
    match icon {
        ButtonIcon::None => {}
        ButtonIcon::Play => icon_play(
            painter,
            Rect::from_center_size(icon_center, vec2(isz * 0.78, isz * 0.9)),
            text_col,
        ),
        ButtonIcon::Refresh => icon_refresh(painter, icon_center, isz * 0.9, text_col),
        ButtonIcon::RefreshAccent => icon_refresh(
            painter,
            icon_center,
            isz * 1.05,
            if enabled || kind == ButtonKind::Passive {
                c::BLUE_ACCENT
            } else {
                text_col
            },
        ),
        ButtonIcon::Trash => icon_trash(
            painter,
            Rect::from_center_size(icon_center, vec2(17.0, 19.0)),
            if enabled { c::ICON_TRASH } else { text_col },
        ),
    }
    let baseline = cy + style.size * 0.36;
    text(
        painter,
        x0 + icon_w,
        baseline,
        Align::Min,
        label,
        style,
        text_col,
    );
    if enabled {
        response.on_hover_cursor(egui::CursorIcon::PointingHand)
    } else {
        response
    }
}

/// Radio control (23px) with real hover state; returns true when clicked.
pub fn radio(
    ui: &mut Ui,
    center: Pos2,
    diameter: f32,
    selected: bool,
    enabled: bool,
    id_salt: &str,
    hit: Rect,
) -> bool {
    let sense = if enabled {
        Sense::click()
    } else {
        Sense::hover()
    };
    let resp = ui.interact(hit, ui.id().with(id_salt), sense);
    let hovered = enabled && resp.hovered();
    let painter = ui.painter();
    let r = diameter / 2.0;
    if selected {
        let ring = if hovered {
            c::BLUE_BRIGHT
        } else {
            c::BLUE_PRIMARY
        };
        icon_radio_active(painter, center, diameter, ring);
    } else {
        let ring = if hovered {
            c::BORDER_ACTIVE
        } else {
            c::RADIO_UNSELECTED
        };
        let ring = if hovered { ring } else { c::RADIO_RING_OFF };
        painter.circle_filled(center, r - 1.0, c::RADIO_FILL_OFF);
        circle_outline(painter, center, r - 0.5, 2.5, ring);
    }
    enabled && resp.clicked()
}

/// Checkbox (24px, filled blue with a white tick when checked).
pub fn checkbox(
    ui: &mut Ui,
    rect: Rect,
    checked: bool,
    enabled: bool,
    id_salt: &str,
    hit: Rect,
) -> bool {
    let sense = if enabled {
        Sense::click()
    } else {
        Sense::hover()
    };
    let resp = ui.interact(hit, ui.id().with(id_salt), sense);
    let hovered = enabled && resp.hovered();
    let painter = ui.painter();
    let cr = CornerRadius::same(4);
    if checked {
        let fill = if hovered {
            c::BLUE_BRIGHT
        } else {
            c::BLUE_PRIMARY
        };
        painter.rect_filled(rect, cr, fill);
        let s = rect.width() / 24.0;
        let o = rect.min;
        painter.add(Shape::line(
            vec![
                o + vec2(6.0 * s, 12.5 * s),
                o + vec2(10.5 * s, 17.0 * s),
                o + vec2(18.5 * s, 7.5 * s),
            ],
            Stroke::new(2.6 * s, Color32::WHITE),
        ));
    } else {
        let border = if hovered {
            c::BORDER_ACTIVE
        } else {
            c::BUTTON_SECONDARY_BORDER
        };
        painter.rect(
            rect,
            cr,
            c::BG_FIELD,
            Stroke::new(1.5, border),
            StrokeKind::Inside,
        );
    }
    enabled && resp.clicked()
}

// ---------------------------------------------------------------------------
// Driver Audit glyphs (generic shapes; no brand logos)
// ---------------------------------------------------------------------------

/// Filled circle with a white "!" (card state / PROBLEM), soft red glow.
pub fn icon_alert_circle(painter: &Painter, center: Pos2, diameter: f32, col: Color32) {
    let r = diameter / 2.0;
    for (k, a) in [(4.0, 18u8), (2.5, 36), (1.2, 60)] {
        painter.circle_filled(
            center,
            r + k,
            Color32::from_rgba_unmultiplied(col.r(), col.g(), col.b(), a),
        );
    }
    painter.circle_filled(center, r, col);
    let w = (diameter * 0.12).max(2.0);
    painter.line_segment(
        [center + vec2(0.0, -r * 0.52), center + vec2(0.0, r * 0.14)],
        Stroke::new(w, Color32::WHITE),
    );
    painter.circle_filled(center + vec2(0.0, r * 0.48), w * 0.62, Color32::WHITE);
}

/// Warning triangle with a dark "!" inside.
pub fn icon_warning_triangle(painter: &Painter, rect: Rect, col: Color32, mark: Color32) {
    let top = pos2(rect.center().x, rect.top());
    let bl = pos2(rect.left(), rect.bottom());
    let br = pos2(rect.right(), rect.bottom());
    painter.add(Shape::convex_polygon(
        vec![top, br, bl],
        col,
        Stroke::new(1.0, col),
    ));
    let h = rect.height();
    let cx = rect.center().x;
    let w = (rect.width() * 0.11).max(1.6);
    painter.line_segment(
        [
            pos2(cx, rect.top() + h * 0.36),
            pos2(cx, rect.top() + h * 0.68),
        ],
        Stroke::new(w, mark),
    );
    painter.circle_filled(pos2(cx, rect.top() + h * 0.82), w * 0.6, mark);
}

/// Outline ring with a tick (OK).
pub fn icon_check_ring(painter: &Painter, center: Pos2, diameter: f32, col: Color32) {
    let r = diameter / 2.0;
    circle_outline(painter, center, r, 1.8, col);
    let s = r / 8.0;
    painter.add(Shape::line(
        vec![
            center + vec2(-3.6 * s, 0.2 * s),
            center + vec2(-1.1 * s, 2.8 * s),
            center + vec2(3.8 * s, -2.6 * s),
        ],
        Stroke::new(1.9, col),
    ));
}

/// Device-category glyph inside a square box of side `size`.
pub fn icon_device(
    painter: &Painter,
    center: Pos2,
    size: f32,
    kind: super::vm::DeviceIcon,
    col: Color32,
) {
    use super::vm::DeviceIcon as D;
    let h = size / 2.0;
    let st = Stroke::new(1.6, col);
    match kind {
        D::Gpu => {
            // Card with a fan and bracket.
            let body = Rect::from_min_max(center + vec2(-h, -h * 0.62), center + vec2(h, h * 0.62));
            painter.rect_stroke(body, CornerRadius::same(2), st, StrokeKind::Inside);
            painter.circle_stroke(center + vec2(h * 0.18, 0.0), h * 0.36, st);
            painter.circle_filled(center + vec2(h * 0.18, 0.0), h * 0.12, col);
            painter.line_segment(
                [
                    center + vec2(-h * 0.62, -h * 0.25),
                    center + vec2(-h * 0.62, h * 0.25),
                ],
                st,
            );
        }
        D::Chip => {
            let body = Rect::from_center_size(center, vec2(size * 0.58, size * 0.58));
            painter.rect_filled(body, CornerRadius::same(2), col);
            for i in 0..3 {
                let t = -0.2 + 0.2 * i as f32;
                for (a, b) in [
                    (vec2(t * size, -h), vec2(t * size, -h * 0.58)),
                    (vec2(t * size, h * 0.58), vec2(t * size, h)),
                    (vec2(-h, t * size), vec2(-h * 0.58, t * size)),
                    (vec2(h * 0.58, t * size), vec2(h, t * size)),
                ] {
                    painter.line_segment([center + a, center + b], Stroke::new(1.3, col));
                }
            }
            painter.rect_filled(
                Rect::from_center_size(center, vec2(size * 0.22, size * 0.22)),
                CornerRadius::ZERO,
                c::BG_CARD,
            );
        }
        D::Audio => {
            let pts = vec![
                center + vec2(-h, -h * 0.3),
                center + vec2(-h * 0.45, -h * 0.3),
                center + vec2(h * 0.1, -h * 0.85),
                center + vec2(h * 0.1, h * 0.85),
                center + vec2(-h * 0.45, h * 0.3),
                center + vec2(-h, h * 0.3),
            ];
            painter.add(Shape::convex_polygon(pts, col, Stroke::NONE));
            for (k, rr) in [(0usize, h * 0.45), (1, h * 0.85)] {
                let _ = k;
                let arc: Vec<Pos2> = (0..=10)
                    .map(|i| {
                        let a = (-45.0 + 9.0 * i as f32).to_radians();
                        center + vec2(h * 0.2 + rr * a.cos(), rr * a.sin())
                    })
                    .collect();
                painter.add(Shape::line(arc, Stroke::new(1.5, col)));
            }
        }
        D::Wifi => {
            let base = center + vec2(0.0, h * 0.75);
            for rr in [h * 0.55, h * 1.05, h * 1.55] {
                let arc: Vec<Pos2> = (0..=12)
                    .map(|i| {
                        let a = (-135.0 + 7.5 * i as f32).to_radians();
                        base + vec2(rr * a.cos(), rr * a.sin())
                    })
                    .collect();
                painter.add(Shape::line(arc, Stroke::new(1.7, col)));
            }
            painter.circle_filled(base, 1.8, col);
        }
        D::Ethernet => {
            let body = Rect::from_min_max(
                center + vec2(-h * 0.8, -h * 0.55),
                center + vec2(h * 0.8, h * 0.75),
            );
            painter.rect_stroke(body, CornerRadius::same(1), st, StrokeKind::Inside);
            painter.rect_filled(
                Rect::from_min_max(
                    center + vec2(-h * 0.35, -h * 0.9),
                    center + vec2(h * 0.35, -h * 0.5),
                ),
                CornerRadius::ZERO,
                col,
            );
            for i in 0..4 {
                let x = -h * 0.45 + h * 0.3 * i as f32;
                painter.line_segment(
                    [center + vec2(x, h * 0.05), center + vec2(x, h * 0.45)],
                    Stroke::new(1.2, col),
                );
            }
        }
        D::Storage => {
            let body = Rect::from_min_max(center + vec2(-h, -h * 0.72), center + vec2(h, h * 0.72));
            painter.rect_filled(body, CornerRadius::same(2), col);
            painter.rect_filled(
                Rect::from_min_max(
                    center + vec2(-h * 0.7, -h * 0.4),
                    center + vec2(h * 0.7, h * 0.15),
                ),
                CornerRadius::same(1),
                c::BG_CARD,
            );
            painter.circle_filled(center + vec2(h * 0.55, h * 0.45), 1.3, c::BG_CARD);
        }
        D::Kernel | D::Generic => {
            circle_outline(painter, center, h * 0.95, 1.6, col);
            for i in 0..8 {
                let a = (i as f32 * 45.0).to_radians();
                let d = vec2(a.cos(), a.sin());
                painter.line_segment(
                    [center + d * h * 0.55, center + d * h * 0.95],
                    Stroke::new(1.6, col),
                );
            }
            painter.circle_filled(center, h * 0.28, col);
        }
    }
}

/// Small four-pane Windows-logo glyph (v0.3.6 multi-SSD selector): marks the
/// one physical disk backing `SystemDrive`. Deliberately generic/geometric
/// (four tilted panes with a thin gap), not a traced brand asset.
pub fn icon_windows_logo(painter: &Painter, center: Pos2, size: f32, col: Color32) {
    let h = size / 2.0;
    let gap = size * 0.08;
    for (dx, dy) in [(-1.0, -1.0), (1.0, -1.0), (-1.0, 1.0), (1.0, 1.0)] {
        let cx = center.x + dx * (h * 0.5 + gap * 0.5);
        let cy = center.y + dy * (h * 0.5 + gap * 0.5);
        let pane = Rect::from_center_size(pos2(cx, cy), vec2(h - gap, h - gap));
        painter.rect_filled(pane, CornerRadius::same(1), col);
    }
}

/// Small neutral disk/SSD glyph (v0.3.6 multi-SSD selector): every physical
/// disk other than the Windows system disk.
pub fn icon_disk_neutral(painter: &Painter, center: Pos2, size: f32, col: Color32) {
    icon_device(painter, center, size, super::vm::DeviceIcon::Storage, col);
}
