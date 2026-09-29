//! WinStateDiag presentation layer (visual reconstruction of
//! `docs/UI_VISUAL_MASTER.png`; spec in `docs/UI_VISUAL_MASTER.md`).
//! Pure UI: no diagnostic, PowerShell, ZIP or SSD-benchmark logic here.

pub mod capture;
pub mod dashboard;
pub mod fixture;
pub mod fonts;
pub mod paint;
pub mod sysinfo;
pub mod tokens;
pub mod vm;

use tokens::{CANVAS_H, CANVAS_W};

/// Pixels-per-point that fits the reference canvas into a physical client
/// area (keeps the approved proportions at any window size).
pub fn fit_pixels_per_point(physical_w: f32, physical_h: f32) -> f32 {
    (physical_w / CANVAS_W).min(physical_h / CANVAS_H)
}

/// Lowest scale before the canvas starts scrolling instead of shrinking.
pub const MIN_PIXELS_PER_POINT: f32 = 0.6;
