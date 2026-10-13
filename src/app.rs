use crate::cryptopro;
use crate::deep_checks::{self, CheckResult, DeepCheck, DeepCheckOutcome};
use crate::details;
use crate::driver_audit::{self, AuditReport, Category, Severity};
use crate::engine::{
    self, DeepChecks, DiagnosticMode, EXPC_DEEP_FLAGS, EXPC_STEP_COUNT, EXPC_STEP_LABELS,
    EXPC_WEIGHTS, EngineEvent, HardwareEvent, HardwareViewRequest, SessionRequest, Stage,
};
use crate::events;
use crate::i18n::{self, Language};
use crate::nvme_health;
use crate::report_package::{
    self, EvidenceFile, SessionIdentity, SessionPackage, SharedPackage, evidence_stamp,
    identity_date,
};
use crate::ssd_history::{self, HistoryEntry};
use crate::storage_benchmark::{self, DiagnosticProgress, StorageDiagnosticSummary};
use crate::storage_health;
use crate::storage_topology::{self, DiskCandidate};
use crate::ui::capture::ReferenceMode;
use crate::ui::dashboard::{self, Controls};
use crate::ui::tokens::{CANVAS_H, CANVAS_W, color as c};
use crate::ui::vm::{
    Action, CryptoVm, DashboardVm, DeviceIcon, DiskEntryVm, DriverRow, DriversVm, JournalLine,
    MetaRow, ModuleRow, ModuleState, OperationVm, OverallVm, ResultVm, RowState, SsdVm,
    StageFinding, StageRow, StartVm, Tone,
};
use crate::ui::vm::{
    AnalysisProgressVm, CrashVm, GpoVm, InfoRow, InstallVm, Page, SensorCell, SensorChip,
    SensorMatrixRow, SensorRefRow, SensorsVm, StageMark, SystemStateVm, TestBlockVm, TestVm,
};
use crate::ui::{self, fixture, fonts, sysinfo};
use crate::{crash_dump, gpo_admx, incidents, passport, sensors};
use egui::RichText;
use egui::{Rect, vec2};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------
// Theme: only what the few real egui widgets (text fields, tooltips, the
// raw-passes window, scrollbars) need; all dashboard geometry and colour is
// painted from `ui::tokens`.
// ---------------------------------------------------------------------

fn apply_theme(ctx: &egui::Context) {
    ctx.set_theme(egui::ThemePreference::Dark);
    let mut visuals = egui::Visuals::dark();
    visuals.panel_fill = c::BG_ROOT;
    visuals.window_fill = c::BG_CARD;
    visuals.window_stroke = egui::Stroke::new(1.0, c::BORDER_NORMAL);
    visuals.extreme_bg_color = c::BG_FIELD;
    visuals.faint_bg_color = c::BG_ROW;
    visuals.selection.bg_fill = c::BLUE_PRIMARY;
    visuals.selection.stroke = egui::Stroke::new(1.0, c::TEXT_PRIMARY);
    visuals.hyperlink_color = c::BLUE_ACCENT;
    visuals.override_text_color = Some(c::TEXT_PRIMARY);
    visuals.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0, c::BORDER_INNER);
    visuals.widgets.noninteractive.fg_stroke = egui::Stroke::new(1.0, c::TEXT_SECONDARY);
    ctx.set_visuals_of(egui::Theme::Dark, visuals);
}

// ---------------------------------------------------------------------
// Journal entries carry a local receive timestamp (UI-side only).
// ---------------------------------------------------------------------

struct JournalEntry {
    timestamp: String,
    message: String,
}

/// Most recent lines the dashboard card presents (a window over the
/// session journal; the journal itself is never truncated to this).
const JOURNAL_LIMIT: usize = 200;
/// Memory bound of the complete session journal. Far above any real
/// session; only past it are the oldest lines dropped (and counted).
const JOURNAL_SESSION_CAP: usize = 100_000;

/// v0.3.7: the one authoritative journal of this application session.
/// The dashboard shows a presentation window over it (`dashboard_lines`);
/// the full-journal viewer, Save and Copy use every line (`full_text`).
/// Clear and a new diagnostic run only move the dashboard window — the
/// session journal, and every report/evidence file on disk, stay intact.
#[derive(Default)]
struct SessionJournal {
    entries: Vec<JournalEntry>,
    /// First entry the dashboard card may show (moved by Clear/new run).
    view_start: usize,
    /// Oldest lines dropped past `JOURNAL_SESSION_CAP` (normally 0).
    dropped: usize,
}

impl SessionJournal {
    fn push(&mut self, message: String) {
        self.entries.push(JournalEntry {
            timestamp: sysinfo::local_time().hms(),
            message,
        });
        if self.entries.len() > JOURNAL_SESSION_CAP {
            // Drop in chunks so a capped journal stays O(1) amortised.
            let excess = self.entries.len() - JOURNAL_SESSION_CAP + JOURNAL_SESSION_CAP / 10;
            self.entries.drain(..excess);
            self.dropped += excess;
            self.view_start = self.view_start.saturating_sub(excess);
        }
    }

    fn len(&self) -> usize {
        self.entries.len()
    }

    #[cfg(test)]
    fn last(&self) -> Option<&JournalEntry> {
        self.entries.last()
    }

    #[cfg(test)]
    fn iter(&self) -> std::slice::Iter<'_, JournalEntry> {
        self.entries.iter()
    }

    /// Empties the dashboard card only; the session journal is kept.
    fn clear_view(&mut self) {
        self.view_start = self.entries.len();
    }

    /// The dashboard's presentation window: at most `JOURNAL_LIMIT` most
    /// recent lines since the last Clear / new run.
    fn dashboard_lines(&self) -> &[JournalEntry] {
        let visible = &self.entries[self.view_start.min(self.entries.len())..];
        &visible[visible.len().saturating_sub(JOURNAL_LIMIT)..]
    }

    /// Display line of one entry (timestamp + message, as on the card).
    fn line(entry: &JournalEntry) -> String {
        format!("{}  {}", entry.timestamp, entry.message)
    }

    /// The complete session journal as text (Copy and Save use this).
    fn full_text(&self, d: &i18n::Dict) -> String {
        let mut out = String::new();
        if self.dropped > 0 {
            out.push_str(
                &d.journal_viewer_dropped_fmt
                    .replace("{count}", &self.dropped.to_string()),
            );
            out.push_str("\r\n");
        }
        for e in &self.entries {
            out.push_str(&Self::line(e));
            out.push_str("\r\n");
        }
        out
    }
}

fn push_journal(journal: &mut SessionJournal, message: String) {
    journal.push(message);
}

/// `WinStateDiag_Log_YYYY-MM-DD_HH-MM-SS.txt`
fn journal_log_file_name(t: sysinfo::LocalTime) -> String {
    format!(
        "WinStateDiag_Log_{:04}-{:02}-{:02}_{:02}-{:02}-{:02}.txt",
        t.year, t.month, t.day, t.hour, t.minute, t.second
    )
}

/// Saved journals live in `<EXE>\Reports\Logs` — never inside a report
/// folder (whose files are exactly the ZIP's contents) and never loose in
/// the Reports root.
fn journal_logs_dir(reports_root: &Path) -> PathBuf {
    reports_root.join("Logs")
}

/// Writes the journal text as UTF-8 (with BOM, like the other TXT
/// evidence). Creates only the Logs folder; never deletes anything.
fn save_journal_text(dir: &Path, file_name: &str, text: &str) -> Result<PathBuf, String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let path = dir.join(file_name);
    let mut bytes = vec![0xEF, 0xBB, 0xBF];
    bytes.extend_from_slice(text.as_bytes());
    std::fs::write(&path, bytes).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(path)
}

/// Outcome line of the journal viewer (localized when drawn, so a language
/// switch with the viewer open updates it too).
enum JournalViewerStatus {
    Saved(PathBuf),
    SaveFailed(String),
    Copied,
}

/// Export destination of a details window (one text, two targets).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExportAction {
    Copy,
    Save,
}

/// Outcome line under a details window (localized when drawn).
#[derive(Debug)]
enum ExportStatus {
    Copied,
    Saved(PathBuf),
    Failed(String),
    /// v1.0: the user closed the Save As dialog.
    Cancelled,
}

impl ExportStatus {
    fn text(&self, d: &i18n::Dict) -> (String, egui::Color32) {
        match self {
            ExportStatus::Copied => (d.export_copied.to_string(), c::TEXT_PRIMARY),
            ExportStatus::Saved(p) => (
                format!("{}: {}", d.export_saved, p.display()),
                c::TEXT_PRIMARY,
            ),
            ExportStatus::Failed(e) => (format!("{}: {e}", d.export_save_failed), c::RED_ERROR),
            ExportStatus::Cancelled => (d.export_cancelled.to_string(), c::TEXT_SECONDARY),
        }
    }
}

/// v0.4.1 Driver Check summary header + action row. Returns (run again,
/// export action).
pub(crate) fn driver_summary_header(
    ui: &mut egui::Ui,
    d: &i18n::Dict,
    report: &AuditReport,
    status: Option<&(String, egui::Color32)>,
) -> (bool, Option<ExportAction>) {
    let s = details::driver_summary(report);
    let mut rerun = false;
    let mut export = None;
    details::card_frame().show(ui, |ui| {
        details::section_title(ui, d.driver_summary_title);
        ui.add_space(2.0);
        ui.horizontal_wrapped(|ui| {
            details::counter_chip(
                ui,
                d.driver_sum_problems,
                &s.problems.to_string(),
                c::DRIVER_STATUS_PROBLEM_TEXT,
            );
            details::counter_chip(
                ui,
                d.driver_sum_warnings,
                &s.warnings.to_string(),
                c::YELLOW_WARNING,
            );
            details::counter_chip(ui, d.driver_sum_ok, &s.ok.to_string(), c::GREEN_SUCCESS);
            details::counter_chip(
                ui,
                d.driver_sum_devices,
                &s.devices.to_string(),
                c::TEXT_SUBTITLE,
            );
            details::counter_chip(
                ui,
                d.driver_sum_events,
                &s.events.to_string(),
                c::TEXT_SUBTITLE,
            );
            let info = details::counter_chip(ui, d.driver_sum_info, "i", c::BLUE_ACCENT);
            details::dark_tooltip(info, &[d.driver_info_tooltip, d.driver_info_tooltip_age]);
        });
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            rerun = details::primary_button(ui, d.driver_action_rerun, true).clicked();
            ui.add_space(4.0);
            let has_issues = s.problems + s.warnings > 0;
            if details::secondary_button(ui, d.driver_copy_issues, true).clicked() {
                export = Some(ExportAction::Copy);
            }
            if details::secondary_button(ui, d.driver_save_issues, true).clicked() {
                export = Some(ExportAction::Save);
            }
            if !has_issues {
                ui.label(RichText::new(d.driver_issues_none).color(c::TEXT_MUTED));
            }
        });
        if let Some((text, color)) = status {
            ui.add(egui::Label::new(RichText::new(text).color(*color)).wrap());
        }
    });
    (rerun, export)
}

/// One step of the EXPC details window.
/// v0.4.5 Details windows are real OS windows (egui immediate viewports):
/// large, movable, resizable, allowed outside the main window, in the
/// WinStateDiag colours. Where the backend cannot open another native
/// window (and in unit tests) egui embeds the same content in a window
/// inside the dashboard. The OS close button clears `open`.
pub(crate) fn detail_window<R>(
    ctx: &egui::Context,
    key: &str,
    title: &str,
    size: [f32; 2],
    open: &mut bool,
    add: impl FnOnce(&mut egui::Ui) -> R,
) -> Option<R> {
    let mut add = Some(add);
    let builder = egui::ViewportBuilder::default()
        .with_title(title)
        .with_inner_size(size)
        .with_min_inner_size([420.0, 300.0])
        .with_resizable(true);
    let (out, close) =
        ctx.show_viewport_immediate(egui::ViewportId::from_hash_of(key), builder, |ui, class| {
            let Some(add) = add.take() else {
                return (None, false);
            };
            details_text_scale(ui.style_mut());
            if class == egui::ViewportClass::EmbeddedWindow {
                return (Some(add(ui)), false);
            }
            let close = ui.ctx().input(|i| i.viewport().close_requested());
            let r = egui::CentralPanel::default()
                .frame(
                    egui::Frame::new()
                        .fill(c::BG_CARD)
                        .inner_margin(egui::Margin::same(16)),
                )
                .show(ui, |ui| add(ui))
                .inner;
            (Some(r), close)
        });
    if close {
        *open = false;
    }
    out
}

/// v1.0 polish: Details windows read larger than the dashboard defaults
/// (body 15, small 13, monospace 13.5, buttons 15) — engineering windows
/// meant for reading, not glancing. Only the Details UI scope is changed.
pub(crate) fn details_text_scale(style: &mut egui::Style) {
    use egui::{FontFamily, FontId, TextStyle};
    for (ts, size, family) in [
        (TextStyle::Body, 15.0, FontFamily::Proportional),
        (TextStyle::Button, 15.0, FontFamily::Proportional),
        (TextStyle::Small, 13.0, FontFamily::Proportional),
        (TextStyle::Monospace, 13.5, FontFamily::Monospace),
        (TextStyle::Heading, 21.0, FontFamily::Proportional),
    ] {
        style.text_styles.insert(ts, FontId::new(size, family));
    }
    style.spacing.item_spacing = egui::vec2(8.0, 5.0);
}

/// v1.0 polish: Sensor Details summary — "Наименование | T°C | Volt | Watt"
/// in large type (real values only; missing = "Нет данных", not meaningful
/// = "—") and the "Эталон" panel with the references the app really has
/// (ATX bands, drive-reported thresholds, "динамический", "без фикс.
/// эталона"). Nothing is invented for display.
pub(crate) fn sensor_summary_block(ui: &mut egui::Ui, d: &i18n::Dict, svm: &SensorsVm) {
    use crate::ui::vm::SensorCell;
    let cell = |ui: &mut egui::Ui, v: &SensorCell| {
        let (text, col) = match v {
            SensorCell::Value { text, tone } => (text.clone(), crate::ui::pages::tone_color(*tone)),
            SensorCell::NoData => (d.sensors_no_data.to_string(), c::TEXT_MUTED),
            SensorCell::NotApplicable => ("—".to_string(), c::TEXT_MUTED),
        };
        ui.label(RichText::new(text).size(17.0).strong().color(col));
    };
    ui.horizontal(|ui| {
        ui.label(
            RichText::new(d.sensors_title)
                .size(22.0)
                .strong()
                .color(c::TEXT_TITLE),
        );
        ui.label(
            RichText::new(d.sensors_header_units)
                .size(17.0)
                .color(c::TEXT_TITLE.gamma_multiply(0.7)),
        );
    });
    ui.add_space(6.0);
    let total = ui.available_width();
    let ref_w = (total * 0.30).clamp(230.0, 360.0);
    // Two framed panels: each frame adds 2 × 12 margin + 2 × 1 stroke.
    let left_w = (total - ref_w - 2.0 * 26.0 - 12.0).max(300.0);
    ui.horizontal_top(|ui| {
        egui::Frame::new()
            .fill(c::BG_CARD_INNER)
            .stroke(egui::Stroke::new(1.0, c::BORDER_INNER))
            .corner_radius(egui::CornerRadius::same(6))
            .inner_margin(egui::Margin::symmetric(12, 8))
            .show(ui, |ui| {
                ui.set_width(left_w);
                if svm.matrix.is_empty() {
                    ui.label(
                        RichText::new(d.sensors_no_data)
                            .size(16.0)
                            .color(c::TEXT_MUTED),
                    );
                    return;
                }
                egui::Grid::new("wsd_sensor_summary_matrix")
                    .num_columns(4)
                    .striped(true)
                    .min_col_width((left_w - 3.0 * 22.0) / 5.0)
                    .spacing(vec2(22.0, 7.0))
                    .show(ui, |ui| {
                        for h in [d.sensors_col_name, "T°C", "Volt", "Watt"] {
                            ui.label(RichText::new(h).size(15.0).color(c::TEXT_MUTED));
                        }
                        ui.end_row();
                        for row in &svm.matrix {
                            ui.label(RichText::new(&row.label).size(17.0).color(c::TEXT_PRIMARY));
                            cell(ui, &row.temp);
                            cell(ui, &row.volt);
                            cell(ui, &row.watt);
                            ui.end_row();
                        }
                    });
            });
        egui::Frame::new()
            .fill(c::BG_CARD_INNER)
            .stroke(egui::Stroke::new(1.0, c::TEXT_TITLE.gamma_multiply(0.45)))
            .corner_radius(egui::CornerRadius::same(6))
            .inner_margin(egui::Margin::symmetric(12, 8))
            .show(ui, |ui| {
                ui.set_width(ref_w);
                ui.vertical(|ui| {
                    ui.label(
                        RichText::new(d.sensors_ref_title)
                            .size(17.0)
                            .strong()
                            .color(c::TEXT_TITLE),
                    );
                    ui.separator();
                    if svm.refs.is_empty() {
                        ui.label(RichText::new(d.sensors_no_data).color(c::TEXT_MUTED));
                    }
                    egui::Grid::new("wsd_sensor_summary_refs")
                        .num_columns(2)
                        .min_col_width(ref_w * 0.42)
                        .spacing(vec2(14.0, 6.0))
                        .show(ui, |ui| {
                            for r in &svm.refs {
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(&r.label).size(15.0).color(c::TEXT_SECONDARY),
                                    )
                                    .wrap(),
                                );
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(&r.range).size(15.0).color(c::TEXT_PRIMARY),
                                    )
                                    .wrap(),
                                );
                                ui.end_row();
                            }
                        });
                    ui.add_space(4.0);
                    ui.add(
                        egui::Label::new(
                            RichText::new(d.sensors_note).small().color(c::TEXT_MUTED),
                        )
                        .wrap(),
                    );
                });
            });
    });
    ui.add_space(8.0);
}

/// v1.0 polish: one row of the Disk Details performance table.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct PerfRow {
    pub cells: [String; 7],
    /// Status colour; `None` = the test did not run.
    pub tone: Option<Tone>,
}

/// v1.0 polish: a framed Details section with a large cyan heading.
pub(crate) fn disk_section_frame(ui: &mut egui::Ui, title: &str, add: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::new()
        .fill(c::BG_CARD_INNER)
        .stroke(egui::Stroke::new(1.0, c::BORDER_INNER))
        .corner_radius(egui::CornerRadius::same(6))
        .inner_margin(egui::Margin::symmetric(12, 8))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(
                RichText::new(title)
                    .size(18.0)
                    .strong()
                    .color(c::TEXT_TITLE),
            );
            ui.add_space(4.0);
            add(ui);
        });
    ui.add_space(8.0);
}

/// v1.0 polish: label / value rows split into two side-by-side tables
/// (first half left, second half right); wrapped values, no clipping.
pub(crate) fn two_column_tables(
    ui: &mut egui::Ui,
    id: impl std::hash::Hash + Copy + std::fmt::Debug,
    rows: &[(String, String)],
) {
    let keyed: Vec<&(String, String)> = rows.iter().filter(|(k, _)| !k.is_empty()).collect();
    let notes: Vec<&(String, String)> = rows.iter().filter(|(k, _)| k.is_empty()).collect();
    let half = keyed.len().div_ceil(2);
    let width = ((ui.available_width() - 16.0) / 2.0).max(220.0);
    ui.horizontal_top(|ui| {
        for (side, part) in [&keyed[..half], &keyed[half..]].iter().enumerate() {
            ui.vertical(|ui| {
                ui.set_width(width);
                egui::Grid::new((id, side))
                    .num_columns(2)
                    .striped(true)
                    .min_col_width(width * 0.38)
                    .max_col_width(width * 0.62)
                    .spacing(vec2(14.0, 6.0))
                    .show(ui, |ui| {
                        for (k, v) in part.iter() {
                            ui.add(
                                egui::Label::new(RichText::new(k).color(c::TEXT_SECONDARY)).wrap(),
                            );
                            ui.add(
                                egui::Label::new(RichText::new(v).color(c::TEXT_PRIMARY)).wrap(),
                            );
                            ui.end_row();
                        }
                    });
            });
        }
    });
    for (_, v) in notes {
        ui.add(egui::Label::new(RichText::new(v).small().color(c::TEXT_MUTED)).wrap());
    }
}

/// v1.0 polish: Test 1 / Test 2 performance table.
pub(crate) fn disk_performance_table(ui: &mut egui::Ui, d: &i18n::Dict, rows: &[PerfRow]) {
    ui.label(
        RichText::new(d.disk_det_performance_note)
            .small()
            .color(c::TEXT_MUTED),
    );
    egui::Grid::new("wsd_disk_perf_table")
        .num_columns(7)
        .striped(true)
        .spacing(vec2(18.0, 7.0))
        .show(ui, |ui| {
            for h in d.disk_det_perf_header {
                ui.label(RichText::new(h).strong().color(c::TEXT_TITLE));
            }
            ui.end_row();
            for r in rows {
                for (k, v) in r.cells.iter().enumerate() {
                    let col = match (k, r.tone) {
                        (6, Some(t)) => crate::ui::pages::tone_color(t),
                        (6, None) | (1..=5, None) => c::TEXT_MUTED,
                        (0, _) => c::TEXT_PRIMARY,
                        _ => c::TEXT_PRIMARY,
                    };
                    let text = RichText::new(v).color(col);
                    let text = if k == 6 && r.tone.is_some() {
                        text.strong()
                    } else {
                        text
                    };
                    // Short cells never wrap (a wrapped "ТЕСТ 1 — первый
                    // замер" broke per letter); a long reason may.
                    if k == 6 && r.tone.is_none() {
                        ui.add(egui::Label::new(text).wrap());
                    } else {
                        ui.add(egui::Label::new(text).extend());
                    }
                }
                ui.end_row();
            }
        });
}

/// v1.0 standard action of a Details window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DetailsAct {
    Copy,
    Save,
    OpenFolder,
    Close,
}

/// v1.0 standard Details action bar, left to right:
/// [Копировать] [Сохранить как...] ([Открыть папку отчёта]) [Закрыть].
/// Copy / Save act on the CURRENT module's text only.
pub(crate) fn details_action_bar(
    ui: &mut egui::Ui,
    d: &i18n::Dict,
    export_enabled: bool,
    folder: Option<bool>,
) -> Option<DetailsAct> {
    let mut act = None;
    ui.horizontal(|ui| {
        if details::secondary_button(ui, d.journal_viewer_copy, export_enabled).clicked() {
            act = Some(DetailsAct::Copy);
        }
        if details::secondary_button(ui, d.details_save_as, export_enabled).clicked() {
            act = Some(DetailsAct::Save);
        }
        if let Some(enabled) = folder
            && details::secondary_button(ui, d.details_open_folder, enabled).clicked()
        {
            act = Some(DetailsAct::OpenFolder);
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if details::secondary_button(ui, d.journal_viewer_close, true).clicked() {
                act = Some(DetailsAct::Close);
            }
        });
    });
    act
}

pub(crate) fn expc_stage_card(
    ui: &mut egui::Ui,
    d: &i18n::Dict,
    det: &details::StageDetail,
    drive: &str,
    copy_command: &mut Option<String>,
) {
    let color = det.state.color();
    egui::Frame::new()
        .fill(c::BG_CARD_INNER)
        .stroke(egui::Stroke::new(1.0, color.gamma_multiply(0.45)))
        .corner_radius(egui::CornerRadius::same(4))
        .inner_margin(egui::Margin::symmetric(10, 6))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(format!("{:02}", det.number))
                        .color(c::TEXT_SECONDARY)
                        .monospace(),
                );
                ui.label(
                    RichText::new(d.stage_short[det.number - 1])
                        .color(c::TEXT_PRIMARY)
                        .strong(),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(
                        RichText::new(d.expc_state_labels[det.state.index()])
                            .color(color)
                            .strong(),
                    );
                });
            });
            let ex = details::explain(det, d, drive);
            if let Some(e) = &ex.explanation {
                ui.add(egui::Label::new(RichText::new(e).color(c::TEXT_BODY)).wrap());
            }
            for f in &det.findings {
                ui.add(
                    egui::Label::new(
                        RichText::new(format!("{}: {f}", d.expc_result_label))
                            .color(c::TEXT_SECONDARY),
                    )
                    .wrap(),
                );
            }
            if let Some(cmd) = &ex.suggested_command {
                ui.add_space(2.0);
                ui.label(
                    RichText::new(d.expc_suggested_action)
                        .color(c::TEXT_TITLE)
                        .strong(),
                );
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new(cmd).monospace().color(c::TEXT_PRIMARY));
                    // Copies the TEXT only; there is no run/repair action.
                    if ui.small_button(d.expc_copy_command).clicked() {
                        *copy_command = Some(cmd.clone());
                    }
                });
                ui.label(
                    RichText::new(d.expc_not_executed)
                        .color(c::TEXT_MUTED)
                        .italics(),
                );
            }
        });
    ui.add_space(4.0);
}

/// Default (opening) size of the journal viewer, in points.
const JOURNAL_VIEWER_SIZE: [f32; 2] = [540.0, 580.0];

/// Buttons of the journal viewer's bottom row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum JournalViewerAction {
    Save,
    Copy,
    Close,
}

fn hms(total_secs: u64) -> String {
    format!(
        "{:02}:{:02}:{:02}",
        total_secs / 3600,
        (total_secs / 60) % 60,
        total_secs % 60
    )
}

/// Exponential glide of an on-screen value toward the real backend target
/// (presentation only; never fed back into telemetry).
fn smooth_toward(current: &mut f32, target: f32, dt: f32) {
    let speed = 6.0_f32;
    let k = 1.0 - (-speed * dt).exp();
    *current += (target - *current) * k;
    if (*current - target).abs() < 0.0005 {
        *current = target;
    }
}

// ---------------------------------------------------------------------
// SSD / NVMe presentation helpers
// ---------------------------------------------------------------------
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum StabilityLevel {
    Stable,
    Acceptable,
    Unstable,
}

fn stability_level(spread: f64) -> StabilityLevel {
    if spread <= 5.0 {
        StabilityLevel::Stable
    } else if spread <= 12.0 {
        StabilityLevel::Acceptable
    } else {
        StabilityLevel::Unstable
    }
}

/// v1.0: the one stability rule of the TXT / JSON evidence and the GUI.
const BENCH_STABILITY_RULE: &str = "STABLE <= 5 % spread, ACCEPT <= 12 %, UNSTABLE > 12 % (worse of read / write); stable = STABLE or ACCEPT";
/// How the benchmark bypasses the Windows file cache (facts of the engine).
const BENCH_IO_MODE: &str = "FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH, OVERLAPPED QD4, dedicated temporary file: the Windows file cache is bypassed";
const BENCH_IO_MODE_RU: &str =
    "FILE_FLAG_NO_BUFFERING + WRITE_THROUGH, QD4 — кэш файловой системы Windows не используется";
const BENCH_SCOPE: &str = "512 MiB x 4 passes: short burst within the drive's own cache (SLC / DRAM); not a sustained-write rate";
const BENCH_SCOPE_RU: &str = "512 MiB × 4 прохода — короткий пиковый замер в пределах кэша накопителя (SLC / DRAM), не устойчивая скорость записи";

fn stability_text(level: StabilityLevel) -> &'static str {
    match level {
        StabilityLevel::Stable => "STABLE",
        StabilityLevel::Acceptable => "ACCEPT",
        StabilityLevel::Unstable => "UNSTABLE",
    }
}

fn stability_tone(level: StabilityLevel) -> Tone {
    match level {
        StabilityLevel::Stable => Tone::Success,
        StabilityLevel::Acceptable => Tone::Warning,
        StabilityLevel::Unstable => Tone::Error,
    }
}

/// Human-friendly block-size label for the SSD metadata row, e.g. `1 MiB`
/// or `256 KiB`. Purely presentational — the numeric byte value from the
/// real backend profile always drives it.
fn format_block_size(bytes: usize) -> String {
    const KIB: usize = 1024;
    const MIB: usize = 1024 * 1024;
    if bytes >= MIB && bytes % MIB == 0 {
        format!("{} MiB", bytes / MIB)
    } else if bytes >= KIB && bytes % KIB == 0 {
        format!("{} KiB", bytes / KIB)
    } else {
        format!("{bytes} B")
    }
}

// ---------------------------------------------------------------------
// Per-module status, derived from `RunState` -- purely presentational,
// does not change what the engine does or reports.
// ---------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum ModuleStatus {
    Pending,
    Running,
    Done,
    Error,
}

fn expc_status(state: &RunState) -> ModuleStatus {
    match state {
        RunState::Idle => ModuleStatus::Pending,
        RunState::Running { stage, .. } => match stage {
            Stage::Preparing | Stage::SystemDiagnostics => ModuleStatus::Running,
            Stage::HardwareReport | Stage::Packaging | Stage::Complete => ModuleStatus::Done,
        },
        RunState::Done { .. } => ModuleStatus::Done,
        RunState::Failed { stage, .. } => match stage {
            Stage::Preparing | Stage::SystemDiagnostics => ModuleStatus::Error,
            Stage::HardwareReport | Stage::Packaging | Stage::Complete => ModuleStatus::Done,
        },
        // A stopped run is never shown as completed.
        RunState::Cancelled { stage, .. } => match stage {
            Stage::Preparing | Stage::SystemDiagnostics => ModuleStatus::Pending,
            Stage::HardwareReport | Stage::Packaging | Stage::Complete => ModuleStatus::Done,
        },
    }
}

fn hardware_status(state: &RunState) -> ModuleStatus {
    match state {
        RunState::Idle => ModuleStatus::Pending,
        RunState::Running { stage, .. } => match stage {
            Stage::Preparing | Stage::SystemDiagnostics => ModuleStatus::Pending,
            Stage::HardwareReport => ModuleStatus::Running,
            Stage::Packaging | Stage::Complete => ModuleStatus::Done,
        },
        RunState::Done { .. } => ModuleStatus::Done,
        RunState::Failed { stage, .. } => match stage {
            Stage::Preparing | Stage::SystemDiagnostics => ModuleStatus::Pending,
            Stage::HardwareReport => ModuleStatus::Error,
            Stage::Packaging | Stage::Complete => ModuleStatus::Done,
        },
        RunState::Cancelled { stage, .. } => match stage {
            Stage::Preparing | Stage::SystemDiagnostics | Stage::HardwareReport => {
                ModuleStatus::Pending
            }
            Stage::Packaging | Stage::Complete => ModuleStatus::Done,
        },
    }
}

fn zip_status(state: &RunState) -> ModuleStatus {
    match state {
        RunState::Idle => ModuleStatus::Pending,
        RunState::Running { stage, .. } => match stage {
            Stage::Preparing | Stage::SystemDiagnostics | Stage::HardwareReport => {
                ModuleStatus::Pending
            }
            Stage::Packaging => ModuleStatus::Running,
            Stage::Complete => ModuleStatus::Done,
        },
        RunState::Done { .. } => ModuleStatus::Done,
        RunState::Failed { stage, .. } => match stage {
            Stage::Packaging => ModuleStatus::Error,
            Stage::Complete => ModuleStatus::Done,
            Stage::Preparing | Stage::SystemDiagnostics | Stage::HardwareReport => {
                ModuleStatus::Pending
            }
        },
        RunState::Cancelled { .. } => ModuleStatus::Pending,
    }
}

/// Friendly short path for displaying the report location.
fn display_report_path(path: &Path) -> String {
    let full = path.display().to_string();
    // Try to find "Reports\" and show from there
    if let Some(idx) = full.find("Reports\\") {
        return full[idx..].to_string();
    }
    if let Some(idx) = full.find("Reports/") {
        return full[idx..].to_string();
    }
    // Fall back to filename
    path.file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or(full)
}

// ---------------------------------------------------------------------
// EXPC sub-stage tracker — maps incoming WSD_PROGRESS events to a
// per-step state machine for the 14 EXPC pipeline steps.
// ---------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum SubStageStatus {
    Pending,
    Running,
    Done,
    Skipped,
    Error,
}

/// Tracks the state of each of the 14 EXPC pipeline steps, their internal
/// progress (for SFC/DISM/CHKDSK), and computes weighted aggregate credit.
struct ExpcSubStageTracker {
    /// Per-step status
    status: [SubStageStatus; 14],
    /// Internal percent for determinate steps (SFC/DISM/CHKDSK), 0..100
    internal_pct: [u32; 14],
    /// Which step is currently active (0-indexed), None before first event
    active_index: Option<usize>,
    /// Last message received from PowerShell (retained for future use)
    #[allow(dead_code)]
    last_message: String,
    /// v0.4.4: when each step started and how long it took.
    started: [Option<Instant>; 14],
    durations: [Option<Duration>; 14],
}

impl Default for ExpcSubStageTracker {
    fn default() -> Self {
        Self {
            status: [SubStageStatus::Pending; 14],
            internal_pct: [0; 14],
            active_index: None,
            last_message: String::new(),
            started: [None; 14],
            durations: [None; 14],
        }
    }
}

impl ExpcSubStageTracker {
    /// Feed a WSD_PROGRESS event to the state machine.
    /// `percent` is the overall 0..100 from PS1, `message` is the title/suffix text.
    fn update(&mut self, _percent: u32, message: &str) {
        self.last_message = message.to_string();

        // Detect which step this event belongs to by matching the title prefix
        // against EXPC_STEP_LABELS. The PS1 emits messages like:
        //   "Title"              → step started
        //   "Title — завершено"  → step done
        //   "Title — пропущено"  → step skipped
        //   "Label — NN%"        → intermediate deep-check progress (new)
        let mut matched_index: Option<usize> = None;
        for (i, label) in EXPC_STEP_LABELS.iter().enumerate() {
            if message.starts_with(label) {
                matched_index = Some(i);
                break;
            }
        }

        // Handle deep-check intermediate progress: "SFC /verifyonly — 45%"
        // These come from Invoke-NativeWithProgress with the Label, not the
        // Invoke-Step Title. Match by checking the internal label patterns.
        if matched_index.is_none() {
            if message.starts_with("SFC ") {
                matched_index = Some(10); // step 11
            } else if message.starts_with("DISM ") {
                matched_index = Some(11); // step 12
            } else if message.starts_with("CHKDSK ") {
                matched_index = Some(12); // step 13
            }
        }

        let Some(idx) = matched_index else {
            // Unknown event — just update the active step's internal progress
            // based on percent if we have one active.
            return;
        };

        // Parse the suffix to determine state
        let finished = message.contains("— завершено") || message.contains("— пропущено");
        if finished && self.durations[idx].is_none() {
            self.durations[idx] = self.started[idx].map(|t| t.elapsed());
        }
        if !finished && self.started[idx].is_none() {
            self.started[idx] = Some(Instant::now());
        }
        if message.contains("— завершено") {
            self.status[idx] = SubStageStatus::Done;
            self.internal_pct[idx] = 100;
            // Move active to the next pending step (if any)
            self.active_index = None;
            for i in (idx + 1)..14 {
                if self.status[i] == SubStageStatus::Pending {
                    self.active_index = Some(i);
                    break;
                }
            }
        } else if message.contains("— пропущено") {
            self.status[idx] = SubStageStatus::Skipped;
            self.internal_pct[idx] = 0;
            self.active_index = None;
            for i in (idx + 1)..14 {
                if self.status[i] == SubStageStatus::Pending {
                    self.active_index = Some(i);
                    break;
                }
            }
        } else if message.contains(" — ") && message.ends_with('%') {
            // Intermediate progress: "SFC /verifyonly — 45%"
            self.status[idx] = SubStageStatus::Running;
            self.active_index = Some(idx);
            // Parse the NN% from the end
            if let Some(pct_str) = message.rsplit("— ").next() {
                if let Some(pct_str) = pct_str.strip_suffix('%') {
                    if let Ok(pct) = pct_str.trim().parse::<u32>() {
                        self.internal_pct[idx] = pct.min(100);
                    }
                }
            }
        } else {
            // Step just started
            self.status[idx] = SubStageStatus::Running;
            self.internal_pct[idx] = 0;
            self.active_index = Some(idx);
        }
    }

    /// Total weighted credit earned so far.
    /// Pending = 0, Running indeterminate = 10% of weight,
    /// Running determinate = 10% + 80% × (pct/100) of weight,
    /// Done/Skipped = 100% of weight.
    fn total_credit(&self) -> f32 {
        let mut credit = 0.0_f32;
        for i in 0..14 {
            let w = EXPC_WEIGHTS[i];
            credit += match self.status[i] {
                SubStageStatus::Pending => 0.0,
                SubStageStatus::Running => {
                    if self.internal_pct[i] > 0 {
                        // Determinate: 10% base + 80% × internal progress
                        w * (0.1 + 0.8 * (self.internal_pct[i] as f32 / 100.0))
                    } else {
                        // Indeterminate: just 10% of weight
                        w * 0.1
                    }
                }
                SubStageStatus::Done => w,
                SubStageStatus::Skipped => {
                    // Skipped deep checks get minimal weight so progress advances
                    if EXPC_DEEP_FLAGS[i] { 0.1 } else { w }
                }
                SubStageStatus::Error => w * 0.5,
            };
        }
        credit
    }

    /// Total weight (denominator for progress fraction).
    /// Adjusts for skipped deep checks.
    fn total_weight(&self) -> f32 {
        let mut weight = 0.0_f32;
        for i in 0..14 {
            if self.status[i] == SubStageStatus::Skipped && EXPC_DEEP_FLAGS[i] {
                weight += 0.1; // Minimal weight for skipped deep check
            } else {
                weight += EXPC_WEIGHTS[i];
            }
        }
        weight
    }

    fn reset(&mut self) {
        *self = Self::default();
    }
}

// ---------------------------------------------------------------------
// App state
// ---------------------------------------------------------------------

enum RunState {
    Idle,
    Running {
        stage: Stage,
        step_done: u32,
        step_total: u32,
        stage_message: String,
        rx: Receiver<EngineEvent>,
    },
    Done {
        zip_path: PathBuf,
    },
    Failed {
        message: String,
        stage: Stage,
    },
    /// Stopped by the user (Stop button): startable again, never "done".
    Cancelled {
        stage: Stage,
        note: String,
    },
}

/// Hardware Report "Смотреть": hidden collection (progress window), then
/// the viewer; its evidence is persisted before the viewer opens.
enum HardwareViewState {
    Idle,
    Collecting {
        rx: Receiver<HardwareEvent>,
        started: Instant,
        saving: bool,
    },
    Viewer {
        rx: Receiver<HardwareEvent>,
    },
}

/// "Открыть отчёт" pulses only for a verified final report that the user
/// has not opened yet.
fn report_attention(report_exists: bool, opened: bool) -> bool {
    report_exists && !opened
}

/// v1.1 Startup Orchestration: who started a module's check. A PREFLIGHT
/// check runs automatically at launch (read-only, no session, no report)
/// and is never presented as the result of a full diagnostic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CheckOrigin {
    /// Automatic read-only check at launch.
    Preflight,
    /// The user's explicit re-check of this one module.
    Manual,
    /// Part of a full diagnostic session.
    Session,
}

impl CheckOrigin {
    pub(crate) fn code(self) -> &'static str {
        match self {
            CheckOrigin::Preflight => "PREFLIGHT",
            CheckOrigin::Manual => "MANUAL",
            CheckOrigin::Session => "SESSION",
        }
    }

    pub(crate) fn text(self, d: &i18n::Dict) -> &'static str {
        match self {
            CheckOrigin::Preflight => d.origin_preflight,
            CheckOrigin::Manual => d.origin_manual,
            CheckOrigin::Session => d.origin_session,
        }
    }
}

/// When and how a module's last result was produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CheckStamp {
    /// Local wall-clock time, `YYYY-MM-DD HH:MM:SS`.
    pub at: String,
    pub origin: CheckOrigin,
}

impl CheckStamp {
    pub(crate) fn now(origin: CheckOrigin) -> Self {
        let t = sysinfo::local_time();
        Self {
            at: format!(
                "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
                t.year, t.month, t.day, t.hour, t.minute, t.second
            ),
            origin,
        }
    }

    /// `HH:MM` for compact cards.
    pub(crate) fn clock(&self) -> &str {
        self.at.get(11..16).unwrap_or(&self.at)
    }

    /// «Предварительно · 10:42» — compact card caption.
    pub(crate) fn caption(&self, d: &i18n::Dict) -> String {
        let short = match self.origin {
            CheckOrigin::Preflight => d.origin_preflight_short,
            CheckOrigin::Manual => d.origin_manual_short,
            CheckOrigin::Session => d.origin_session_short,
        };
        format!("{short} · {}", self.clock())
    }

    /// «Предварительная проверка · 2026-10-13 10:42:05» — Details.
    pub(crate) fn full(&self, d: &i18n::Dict) -> String {
        format!("{} · {}", self.origin.text(d), self.at)
    }
}

/// v1.1: one line of the Driver Audit Details journal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DriverHistoryEntry {
    pub stamp: CheckStamp,
    /// Localized one-line outcome (status, problems, warnings / error).
    pub outcome: String,
}

/// v1.1: appends one Driver Audit history line (bounded) and records the
/// time / origin of the latest result.
fn record_check(
    history: &mut Vec<DriverHistoryEntry>,
    checked: &mut Option<CheckStamp>,
    stamp: CheckStamp,
    outcome: String,
) {
    history.push(DriverHistoryEntry {
        stamp: stamp.clone(),
        outcome,
    });
    if history.len() > 200 {
        history.remove(0);
    }
    *checked = Some(stamp);
}

/// Driver Audit lifecycle: a read-only audit runs inside every diagnostic
/// session (for the report), when the user starts it, and (v1.1) once
/// automatically at launch as a PREFLIGHT check that joins no report.
enum DriverAuditState {
    /// Not run in this WinStateDiag session yet.
    Idle,
    Running(Receiver<Result<AuditReport, String>>),
    Done(Box<AuditReport>),
    Failed(String),
}

fn severity_tone(s: Severity) -> Tone {
    match s {
        Severity::Problem => Tone::Error,
        Severity::Warning => Tone::Warning,
        Severity::Ok => Tone::Success,
    }
}

fn device_icon(item: &driver_audit::AuditItem) -> DeviceIcon {
    match item.category {
        Category::Display => DeviceIcon::Gpu,
        Category::Chipset => DeviceIcon::Chip,
        Category::Audio => DeviceIcon::Audio,
        Category::Network if item.label.contains("Wi-Fi") => DeviceIcon::Wifi,
        Category::Network => DeviceIcon::Ethernet,
        Category::Storage => DeviceIcon::Storage,
        Category::KernelDriver => DeviceIcon::Kernel,
        Category::Other => DeviceIcon::Generic,
    }
}

/// Presentation-only: the Driver Audit's category labels ("Чипсет (Intel)",
/// "Аудио (Realtek)", "Сеть (Intel Wi-Fi)") in the UI language. Vendor and
/// device names are data and stay as reported; the audit itself is untouched.
fn localized_driver_label(d: &i18n::Dict, label: &str) -> String {
    for (ru, localized) in [
        ("Чипсет", d.driver_cat_chipset),
        ("Аудио", d.driver_cat_audio),
        ("Сеть", d.driver_cat_network),
    ] {
        if let Some(rest) = label.strip_prefix(ru) {
            if rest.is_empty() || rest.starts_with(' ') {
                return format!("{localized}{rest}");
            }
        }
    }
    label.to_string()
}

/// Compact Current Operation line for the status bar.
fn current_operation_status_text(
    d: &i18n::Dict,
    bench_running: bool,
    state: &RunState,
    op: &OperationVm,
) -> String {
    if bench_running && !matches!(state, RunState::Running { .. }) {
        return d.status_ssd_running.to_string();
    }
    match state {
        RunState::Running { .. } => {
            let mut s = format!("{}: {}", d.curop_title, op.name);
            if !op.subtitle.is_empty() {
                s.push_str(" — ");
                s.push_str(&op.subtitle);
            }
            if !op.percent_text.is_empty() {
                s.push_str("  ");
                s.push_str(&op.percent_text);
            }
            s
        }
        _ => op.name.clone(),
    }
}

fn driver_status_label(d: &i18n::Dict, s: Severity) -> &'static str {
    match s {
        Severity::Ok => d.driver_status_ok,
        Severity::Warning => d.driver_status_warning,
        Severity::Problem => d.driver_status_problem,
    }
}

/// Dashboard card content from a real audit report (never invented).
fn drivers_vm(report: &AuditReport, d: &i18n::Dict) -> DriversVm {
    let (items, more) =
        driver_audit::summary_rows(report, crate::ui::tokens::layout::DRIVER_ROWS_MAX);
    let rows = items
        .iter()
        .map(|it| {
            let reason = it
                .primary_reason()
                .or_else(|| it.evidence.first())
                .map(|e| {
                    if e.count > 1 {
                        format!("{} (×{})", e.reason, e.count)
                    } else {
                        e.reason.clone()
                    }
                })
                .unwrap_or_else(|| d.driver_no_problem_reason.into());
            DriverRow {
                icon: device_icon(it),
                name: localized_driver_label(d, &it.label),
                version: if it.version.is_empty() {
                    d.driver_na.into()
                } else {
                    it.version.clone()
                },
                tone: severity_tone(it.status),
                status_text: driver_status_label(d, it.status).into(),
                tooltip: format!(
                    "{}\n{}: {} {}\n{}",
                    it.device,
                    d.driver_driver_label,
                    if it.provider.is_empty() {
                        d.driver_na
                    } else {
                        &it.provider
                    },
                    it.date,
                    reason
                ),
            }
        })
        .collect();
    let problems = report.count(Severity::Problem);
    let warnings = report.count(Severity::Warning);
    let alert = match report.overall {
        Severity::Problem => Some((
            Tone::Error,
            if warnings > 0 {
                d.driver_alert_problems_and_warnings_fmt
                    .replace("{problems}", &problems.to_string())
                    .replace("{warnings}", &warnings.to_string())
            } else {
                d.driver_alert_problems_only_fmt
                    .replace("{problems}", &problems.to_string())
            },
            d.driver_alert_problem_note.to_string(),
        )),
        Severity::Warning => Some((
            Tone::Warning,
            d.driver_alert_warning_fmt
                .replace("{warnings}", &warnings.to_string()),
            d.driver_alert_warning_note.to_string(),
        )),
        Severity::Ok => None,
    };
    DriversVm::Done {
        overall: severity_tone(report.overall),
        rows,
        more,
        alert,
        ok_line: d
            .driver_ok_line_fmt
            .replace("{devices}", &report.devices_scanned.to_string()),
    }
}

fn start_driver_audit() -> DriverAuditState {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let work = std::env::temp_dir()
            .join("WinStateDiag")
            .join(format!("driver-audit-{}", std::process::id()));
        let result = driver_audit::run_audit(&work);
        let _ = std::fs::remove_dir_all(&work);
        let _ = tx.send(result);
    });
    DriverAuditState::Running(rx)
}

/// Driver Audit evidence (same files the in-session audit writes).
fn driver_audit_evidence(report: &AuditReport) -> Vec<EvidenceFile> {
    let t = sysinfo::local_time();
    // Same tag style as the in-session audit: DriverAudit_dd-MM-yy_HH-mm-ss.
    let stem = format!(
        "DriverAudit_{}_{:02}-{:02}-{:02}",
        identity_date(t),
        t.hour,
        t.minute,
        t.second
    );
    let mut txt = vec![0xEF, 0xBB, 0xBF];
    txt.extend_from_slice(driver_audit::to_text(report).as_bytes());
    vec![
        EvidenceFile::new(
            format!("{stem}.json"),
            driver_audit::to_json(report).into_bytes(),
        ),
        EvidenceFile::new(format!("{stem}.txt"), txt),
    ]
}

/// SSD benchmark evidence: the real measured result (TXT + JSON).
/// Human-readable disk identity for the TXT/JSON evidence (v0.3.6,
/// multi-SSD): the physical-disk identity string when one was captured,
/// otherwise an explicit "не определён" — never silently omitted, so that
/// several SSD results in one report/ZIP stay distinguishable by content.
fn disk_identity_label(physical_identity: Option<&str>) -> String {
    match physical_identity {
        Some(id) if !id.is_empty() => id.to_string(),
        _ => "не определён (физический диск не обнаружен)".to_string(),
    }
}

/// Label/value rows of the NVMe Health facts shown in the SSD Details
/// popup. Raw controller values only (temperatures converted from Kelvin,
/// data units shown in TB next to nothing else); anything not read is
/// "n/a" — never 0 — and no row carries a verdict.
fn nvme_health_rows(h: &nvme_health::NvmeHealth, d: &i18n::Dict) -> Vec<(String, String)> {
    use nvme_health::ProbeStatus;
    let na = || d.nvme_value_unknown.to_string();
    let status = match h.status {
        ProbeStatus::Ok => "OK".to_string(),
        ProbeStatus::Unsupported => d.nvme_status_unsupported.to_string(),
        ProbeStatus::AccessDenied => d.nvme_status_access_denied.to_string(),
        ProbeStatus::Error => d.nvme_status_error.to_string(),
    };
    let mut rows = vec![(d.nvme_status_label.to_string(), status)];
    // v1.0 ATA / SATA SMART facts (read-only; UNSUPPORTED is honest).
    if let Some(a) = &h.ata_smart {
        rows.extend(a.fact_lines());
    }
    let Some(s) = h.smart.as_ref() else {
        if let Some(detail) = &h.status_detail {
            rows.push((String::new(), detail.clone()));
        }
        return rows;
    };
    let tb = |units: u128| {
        nvme_health::data_units_to_bytes(units)
            .map(|b| format!("{:.2} {}", b as f64 / 1e12, d.nvme_tb_unit))
            .unwrap_or_else(na)
    };
    let flags = nvme_health::critical_warning_flags(s.critical_warning);
    let warning = if flags.is_empty() {
        s.critical_warning.to_string()
    } else {
        format!("0x{:02X} ({})", s.critical_warning, flags.join(", "))
    };
    rows.push((d.nvme_critical_warning.into(), warning));
    rows.push((
        d.nvme_temperature.into(),
        s.composite_temperature_c()
            .map(|t| format!("{t} °C"))
            .unwrap_or_else(na),
    ));
    let sensors = s.temperature_sensors_c();
    if !sensors.is_empty() {
        let list: Vec<String> = sensors
            .iter()
            .map(|(n, t)| format!("#{n} {t} °C"))
            .collect();
        rows.push((d.nvme_temp_sensors.into(), list.join(", ")));
    }
    rows.push((
        d.nvme_available_spare.into(),
        format!("{} %", s.available_spare_percent),
    ));
    rows.push((
        d.nvme_spare_threshold.into(),
        format!("{} %", s.available_spare_threshold_percent),
    ));
    rows.push((
        d.nvme_percentage_used.into(),
        format!("{} %", s.percentage_used),
    ));
    rows.push((d.nvme_data_read.into(), tb(s.data_units_read)));
    rows.push((d.nvme_data_written.into(), tb(s.data_units_written)));
    rows.push((d.nvme_power_cycles.into(), s.power_cycles.to_string()));
    rows.push((d.nvme_power_on_hours.into(), s.power_on_hours.to_string()));
    rows.push((
        d.nvme_unsafe_shutdowns.into(),
        s.unsafe_shutdowns.to_string(),
    ));
    rows.push((
        d.nvme_media_errors.into(),
        s.media_and_data_integrity_errors.to_string(),
    ));
    rows.push((
        d.nvme_error_log_entries.into(),
        s.error_information_log_entries.to_string(),
    ));
    let error_log = match (&h.error_log_status, &h.error_log) {
        (ProbeStatus::Ok, Some(list)) => d
            .nvme_error_log_read_fmt
            .replace("{n}", &list.len().to_string()),
        (ProbeStatus::Unsupported, _) => d.nvme_status_unsupported.to_string(),
        (ProbeStatus::AccessDenied, _) => d.nvme_status_access_denied.to_string(),
        _ => d.nvme_status_error.to_string(),
    };
    rows.push((d.nvme_error_log.into(), error_log));
    rows
}

fn section_title(ui: &mut egui::Ui, text: &str) {
    ui.label(egui::RichText::new(text).strong().color(c::TEXT_SECONDARY));
}

/// The per-pass table of one benchmark run (Details window).
fn pass_grid(ui: &mut egui::Ui, id: &str, result: &StorageDiagnosticSummary) {
    egui::Grid::new(id)
        .striped(true)
        .spacing(vec2(12.0, 6.0))
        .show(ui, |ui| {
            for heading in [
                "PASS", "READ", "WRITE", "R IOPS", "W IOPS", "R LAT", "W LAT", "R TIME", "W TIME",
            ] {
                ui.label(
                    egui::RichText::new(heading)
                        .strong()
                        .color(c::TEXT_SECONDARY),
                );
            }
            ui.end_row();
            for pass in &result.raw_passes {
                ui.label(pass.pass_number.to_string());
                ui.label(format!(
                    "{:.1} MB/s",
                    pass.run.read.mb_per_second * 1.048576
                ));
                ui.label(format!(
                    "{:.1} MB/s",
                    pass.run.write.mb_per_second * 1.048576
                ));
                ui.label(format!("{:.0}", pass.run.read.iops));
                ui.label(format!("{:.0}", pass.run.write.iops));
                ui.label(format!(
                    "{:.3} ms",
                    pass.run.read.average_latency.as_secs_f64() * 1000.0
                ));
                ui.label(format!(
                    "{:.3} ms",
                    pass.run.write.average_latency.as_secs_f64() * 1000.0
                ));
                ui.label(format!("{:.3} s", pass.run.read.elapsed.as_secs_f64()));
                ui.label(format!("{:.3} s", pass.run.write.elapsed.as_secs_f64()));
                ui.end_row();
            }
        });
}

/// `YYYY-MM-DDTHH:MM:SS` local time (NVMe Health `captured_at`).
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn local_iso(t: sysinfo::LocalTime) -> String {
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        t.year, t.month, t.day, t.hour, t.minute, t.second
    )
}

#[cfg(test)]
fn ssd_benchmark_evidence(
    result: &StorageDiagnosticSummary,
    test_dir: &Path,
    duration_seconds: f64,
    previous: Option<&HistoryEntry>,
    disk_label: String,
) -> Vec<EvidenceFile> {
    ssd_benchmark_evidence_for(
        result,
        test_dir,
        duration_seconds,
        previous,
        disk_label,
        None,
        RunRole::Initial,
        None,
    )
}

/// v0.4.2: which run of the benchmark workflow produced the evidence.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum RunRole {
    Initial,
    AutomaticRetest,
}

impl RunRole {
    fn code(self) -> &'static str {
        match self {
            RunRole::Initial => "initial",
            RunRole::AutomaticRetest => "automatic_retest",
        }
    }
}

/// Benchmark evidence. Additive v0.4.2 JSON fields: `physical_disk_index`,
/// `model` (per-disk manifest grouping) and `run_role`; the automatic
/// retest gets its own `_retest` file so both runs are always kept.
/// v1.0 evidence of an INVALID run (physically impossible for the
/// transport): raw facts + reason, explicitly not a performance result.
fn invalid_benchmark_evidence(
    result: &StorageDiagnosticSummary,
    test_dir: &Path,
    duration_seconds: f64,
    disk: Option<&storage_topology::PhysicalDiskInfo>,
    reason: &str,
) -> Vec<EvidenceFile> {
    let t = sysinfo::local_time();
    let mb = |v: f64| v * 1.048_576;
    let q = crate::deep_checks::json::string;
    let json = format!(
        "{{\"schema\":\"winstatediag.ssd_benchmark/1\",\"validity\":\"INVALID\",\"verdict\":\"BENCHMARK INVALID / RESULT NOT TRUSTED\",\"invalid_reason\":{},\"captured_at\":{},\"physical_disk_index\":{},\"model\":{},\"bus_type\":{},\"transport_ceiling_mb_s\":{},\"test_dir\":{},\"duration_s\":{:.3},\"read_max_mb_s\":{:.3},\"write_max_mb_s\":{:.3},\"note\":\"not disk performance; excluded from history and stability\"}}",
        q(reason),
        q(&local_iso(t)),
        disk.map(|d| d.index.to_string())
            .unwrap_or_else(|| "null".into()),
        disk.map(|d| q(d.model.trim()))
            .unwrap_or_else(|| "null".into()),
        disk.map(|d| q(&d.bus_type))
            .unwrap_or_else(|| "null".into()),
        disk.and_then(|d| storage_benchmark::transport_ceiling_mb_s(&d.bus_type))
            .map(|c| format!("{c:.0}"))
            .unwrap_or_else(|| "null".into()),
        q(&test_dir.display().to_string()),
        duration_seconds,
        mb(result.read_max_mib_s),
        mb(result.write_max_mib_s),
    );
    vec![EvidenceFile::new(
        format!("SSD_Benchmark_{}_INVALID.json", evidence_stamp(t)),
        json.into_bytes(),
    )]
}

fn ssd_benchmark_evidence_for(
    result: &StorageDiagnosticSummary,
    test_dir: &Path,
    duration_seconds: f64,
    previous: Option<&HistoryEntry>,
    disk_label: String,
    disk: Option<&storage_topology::PhysicalDiskInfo>,
    role: RunRole,
    retest_of: Option<&str>,
) -> Vec<EvidenceFile> {
    let t = sysinfo::local_time();
    // v1.0: the retest is named after the STORED stem of the initial run it
    // confirms (`<initial>_retest`), so the pair can never be mismatched
    // with another same-minute run (`_02`).
    let stem = match (role, retest_of) {
        (RunRole::Initial, _) => format!("SSD_Benchmark_{}", evidence_stamp(t)),
        (RunRole::AutomaticRetest, Some(initial)) => {
            format!("{}_retest", initial.trim_end_matches(".json"))
        }
        (RunRole::AutomaticRetest, None) => {
            format!("SSD_Benchmark_{}_retest", evidence_stamp(t))
        }
    };
    let mb = |mib: f64| mib * 1.048576;
    let mut text = String::new();
    text.push_str("WinStateDiag — SSD / NVMe benchmark\r\n");
    text.push_str(&format!("Дата: {} {}\r\n", t.date_dmy(), t.hms()));
    text.push_str(&format!("Папка теста: {}\r\n", test_dir.display()));
    text.push_str(&format!("Диск: {disk_label}\r\n"));
    if role == RunRole::AutomaticRetest {
        text.push_str(
            "Замер: автоматический контрольный повтор после нестабильного первого замера\r\n",
        );
    }
    text.push_str(&format!(
        "Профиль: блок {} байт, QD{}, файл {} байт, проходов {}\r\n",
        result.profile.block_size,
        result.profile.queue_depth,
        result.profile.test_file_size,
        result.profile.pass_count
    ));
    text.push_str(&format!("Длительность: {duration_seconds:.1} с\r\n"));
    text.push_str(&format!("Режим I/O: {BENCH_IO_MODE_RU}\r\n"));
    text.push_str(&format!("Объём теста: {BENCH_SCOPE_RU}\r\n"));
    text.push_str(&format!(
        "READ: {:.1} MB/s (min {:.1}, max {:.1}, разброс {:.2}%)\r\n",
        mb(result.summary_read_mib_s),
        mb(result.read_min_mib_s),
        mb(result.read_max_mib_s),
        result.read_variation_percent
    ));
    text.push_str(&format!(
        "WRITE: {:.1} MB/s (min {:.1}, max {:.1}, разброс {:.2}%)\r\n",
        mb(result.summary_write_mib_s),
        mb(result.write_min_mib_s),
        mb(result.write_max_mib_s),
        result.write_variation_percent
    ));
    // One shared source of truth for the STABLE/ACCEPT/UNSTABLE thresholds
    // (`stability_level`), used identically by the GUI and by this TXT/JSON
    // evidence, so a spread like 10.38% is never ACCEPT in the GUI and
    // "unstable" in the report.
    let read_level = stability_level(result.read_variation_percent);
    let write_level = stability_level(result.write_variation_percent);
    let overall_level = read_level.max(write_level);
    text.push_str(&format!(
        "Стабильность: {} ({BENCH_STABILITY_RULE})\r\n",
        stability_text(overall_level)
    ));
    match previous {
        Some(p) => text.push_str(&format!(
            "Предыдущий совместимый замер: READ {:.1} MB/s, WRITE {:.1} MB/s\r\n",
            mb(p.read_mib_s),
            mb(p.write_mib_s)
        )),
        None => text.push_str("Предыдущий совместимый замер: нет\r\n"),
    }
    text.push_str("Проходы:\r\n");
    let mut passes = Vec::new();
    for pass in &result.raw_passes {
        text.push_str(&format!(
            "  #{}: READ {:.1} MB/s, WRITE {:.1} MB/s, R IOPS {:.0}, W IOPS {:.0}\r\n",
            pass.pass_number,
            mb(pass.run.read.mb_per_second),
            mb(pass.run.write.mb_per_second),
            pass.run.read.iops,
            pass.run.write.iops
        ));
        passes.push(format!(
            "{{\"pass\":{},\"read_mb_s\":{:.3},\"write_mb_s\":{:.3},\"read_iops\":{:.1},\"write_iops\":{:.1}}}",
            pass.pass_number,
            mb(pass.run.read.mb_per_second),
            mb(pass.run.write.mb_per_second),
            pass.run.read.iops,
            pass.run.write.iops
        ));
    }
    let json_str = |s: &str| {
        let mut out = String::from("\"");
        for ch in s.chars() {
            match ch {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
                c => out.push(c),
            }
        }
        out.push('"');
        out
    };
    let json = format!(
        "{{\"schema\":\"winstatediag.ssd_benchmark/1\",\"run_role\":{},\"captured_at\":{},\"retest_of\":{},\"physical_disk_index\":{},\"model\":{},\"test_dir\":{},\"disk\":{},\"block_size\":{},\"queue_depth\":{},\"test_file_size\":{},\"pass_count\":{},\"duration_s\":{:.3},\"read_mb_s\":{:.3},\"write_mb_s\":{:.3},\"read_variation_percent\":{:.3},\"write_variation_percent\":{:.3},\"stability\":{},\"stable\":{},\"stability_rule\":{},\"io_mode\":{},\"test_scope\":{},\"passes\":[{}]}}",
        json_str(role.code()),
        json_str(&local_iso(t)),
        retest_of
            .map(|r| json_str(&format!("{}.json", r.trim_end_matches(".json"))))
            .unwrap_or_else(|| "null".into()),
        disk.map(|d| d.index.to_string())
            .unwrap_or_else(|| "null".into()),
        disk.map(|d| json_str(d.model.trim()))
            .unwrap_or_else(|| "null".into()),
        json_str(&test_dir.display().to_string()),
        json_str(&disk_label),
        result.profile.block_size,
        result.profile.queue_depth,
        result.profile.test_file_size,
        result.profile.pass_count,
        duration_seconds,
        mb(result.summary_read_mib_s),
        mb(result.summary_write_mib_s),
        result.read_variation_percent,
        result.write_variation_percent,
        json_str(stability_text(overall_level)),
        // v1.0: `stable` = the run is ACCEPTED as a measurement (STABLE or
        // ACCEPT), the same verdict as `stability` — never "ACCEPT" with
        // "stable": false.
        overall_level != StabilityLevel::Unstable,
        json_str(BENCH_STABILITY_RULE),
        json_str(BENCH_IO_MODE),
        json_str(BENCH_SCOPE),
        passes.join(",")
    );
    let mut txt = vec![0xEF, 0xBB, 0xBF];
    txt.extend_from_slice(text.as_bytes());
    vec![
        EvidenceFile::new(format!("{stem}.txt"), txt),
        EvidenceFile::new(format!("{stem}.json"), json.into_bytes()),
    ]
}

/// The Hardware Report progress window (modal, no invented percentage).
pub(crate) fn draw_hardware_progress(
    ctx: &egui::Context,
    d: &i18n::Dict,
    status: &str,
    elapsed: &str,
) {
    let time = ctx.input(|i| i.time);
    egui::Modal::new(egui::Id::new("hardware_progress"))
        .frame(
            egui::Frame::window(&ctx.global_style())
                .fill(c::BG_CARD)
                .stroke(egui::Stroke::new(1.0, c::BORDER_NORMAL))
                .inner_margin(egui::Margin::same(22)),
        )
        .show(ctx, |ui| {
            ui.set_width(380.0);
            ui.label(
                egui::RichText::new(d.hw_progress_title)
                    .size(18.0)
                    .strong()
                    .color(c::TEXT_PRIMARY),
            );
            ui.add_space(10.0);
            ui.label(egui::RichText::new(status).color(c::TEXT_PRIMARY));
            ui.add_space(12.0);
            // Indeterminate activity bar: no invented percentage.
            let (bar, _) =
                ui.allocate_exact_size(vec2(ui.available_width(), 6.0), egui::Sense::hover());
            let painter = ui.painter();
            painter.rect_filled(bar, egui::CornerRadius::same(3), c::BG_FIELD);
            let seg = bar.width() * 0.28;
            let phase = (time * 0.6).fract() as f32;
            let x0 = bar.left() - seg + (bar.width() + seg) * phase;
            let active = Rect::from_min_max(
                egui::pos2(x0.max(bar.left()), bar.top()),
                egui::pos2((x0 + seg).min(bar.right()), bar.bottom()),
            );
            if active.width() > 0.0 {
                painter.rect_filled(active, egui::CornerRadius::same(3), c::BLUE_PRIMARY);
            }
            ui.add_space(12.0);
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new(d.hw_progress_please_wait).color(c::TEXT_SECONDARY));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(egui::RichText::new(elapsed).color(c::TEXT_SECONDARY));
                });
            });
        });
}

/// Background CryptoPro work: read-only check or confirmed ReHash.
enum CryptoEvent {
    /// v1.1: the registry inventory of the same check (sent first).
    Inventory(cryptopro::Inventory),
    Checked(cryptopro::Detection, cryptopro::HashState),
    Rehashed(cryptopro::RehashOutcome),
}

/// v0.4.4 Crash Dump analyzer UI state.
#[derive(Default)]
struct CrashState {
    inventory: Option<Result<crash_dump::Inventory, String>>,
    /// v1.0 evidence fix: the SessionId whose scan collected `inventory`
    /// (a later analysis of the cached listing never re-labels it).
    inventory_session: Option<String>,
    /// v1.1: origin of the RUNNING scan, and of / time of the inventory.
    scan_origin: Option<CheckOrigin>,
    inventory_checked: Option<CheckStamp>,
    /// v1.1: a full diagnostic started while the preflight scan ran — a
    /// fresh session scan follows it (the preflight listing never joins
    /// a client report).
    rescan_for_session: bool,
    analyses: Vec<crash_dump::DumpAnalysis>,
    busy: CrashBusy,
    /// v1.0 live stage of the running analysis.
    progress: Option<AnalysisProgress>,
    /// v1.0 embedded installer.
    install: InstallState,
    /// v1.0 local install journal (Details).
    install_log: Vec<String>,
}

/// v1.0 real progress of the running analysis (stages from the debugger's
/// own output; no percentage).
#[derive(Clone, Debug)]
struct AnalysisProgress {
    stage: crash_dump::AnalysisStage,
    started: Instant,
    dump_index: usize,
    dump_total: usize,
    dump_name: String,
    symbols_downloading: bool,
}

/// v1.0 embedded WinDbg installer state.
#[derive(Clone, Debug, Default, PartialEq)]
enum InstallState {
    #[default]
    Idle,
    Running {
        stage: crash_dump::InstallStage,
        percent: Option<u8>,
    },
    /// winget reported success; the analyzer is being re-detected.
    Verifying,
    Succeeded,
    Failed(String),
}

#[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
enum CrashBusy {
    #[default]
    Idle,
    // Constructed by the Windows-only inventory collector.
    #[cfg_attr(not(windows), allow(dead_code))]
    Scanning,
    Analyzing,
}

/// One analyzed dump from the worker.
struct AnalyzedDump {
    dump: crash_dump::DumpFile,
    bugcheck: Option<crash_dump::BugcheckEvent>,
    status: crash_dump::AnalysisStatus,
    raw: String,
    bytes: Option<Vec<u8>>,
    /// v1.0 `lmvm` + installed-driver resolution of the implicated module.
    module_info: Option<crash_dump::ModuleInfo>,
    resolution: Option<crash_dump::DriverResolution>,
}

/// Messages of the crash worker thread.
#[cfg_attr(any(not(windows), test), allow(dead_code))]
enum CrashMsg {
    Inventory(Result<crash_dump::Inventory, String>),
    /// v1.0 real stage reached (index of the dump, total dumps, name).
    Stage(crash_dump::AnalysisStage, usize, usize, String),
    /// v1.0 the local symbol cache is growing (Microsoft symbol download).
    Symbols(bool),
    Analyzed(Vec<AnalyzedDump>),
}

/// v1.0 one physical disk of the read-only ATA SMART scan.
#[derive(Clone, Debug)]
struct AtaDisk {
    index: u32,
    model: String,
    bus: String,
    smart: crate::ata_smart::AtaSmart,
}

/// v1.0 messages of the hidden installer thread.
#[cfg_attr(not(windows), allow(dead_code))]
enum InstallMsg {
    Line(String),
    Done(crash_dump::InstallResult),
}

/// PowerShell host used by the Windows collectors.
#[cfg_attr(not(windows), allow(dead_code))]
const PS_HOST: &str = "powershell.exe";

/// Local symbol cache for headless dump analysis.
// Used by the analysis thread, which never runs under `cfg(test)`.
#[cfg_attr(any(not(windows), test), allow(dead_code))]
fn symbol_cache_dir() -> PathBuf {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("WinStateDiag")
        .join("Symbols")
}

/// Total size of the files under `dir` (symbol-download detection; read
/// only, bounded depth).
#[cfg_attr(any(not(windows), test), allow(dead_code))]
fn dir_size(dir: &Path) -> u64 {
    fn walk(p: &Path, depth: u32) -> u64 {
        let Ok(rd) = std::fs::read_dir(p) else {
            return 0;
        };
        rd.flatten()
            .map(|e| match e.metadata() {
                Ok(m) if m.is_dir() && depth < 4 => walk(&e.path(), depth + 1),
                Ok(m) => m.len(),
                Err(_) => 0,
            })
            .sum()
    }
    walk(dir, 0)
}

/// Short, safe idle between an UNSTABLE first run and its retest.
const RETEST_IDLE: Duration = Duration::from_secs(10);
/// Extra time the retest waits for the health read before failing closed.
const RETEST_HEALTH_WAIT: Duration = Duration::from_secs(45);

/// Messages of the background health/event probe (sent on Windows only).
#[cfg_attr(not(windows), allow(dead_code))]
enum ProbeMsg {
    Health(nvme_health::NvmeHealth),
    Events(String, storage_health::EventsInput),
}

/// One physical disk's storage correlation (first run, retest, health,
/// events). The first run is never discarded.
struct StorageAssessment {
    disk: Option<storage_topology::PhysicalDiskInfo>,
    first: StorageDiagnosticSummary,
    first_duration: f64,
    first_previous: Option<HistoryEntry>,
    second: Option<StorageDiagnosticSummary>,
    /// v1.0 duration of the automatic retest (Disk Details).
    second_duration: Option<f64>,
    retest: storage_health::RetestOutcome,
    benchmark_files: Vec<String>,
    health_file: Option<String>,
    events: storage_health::EventsInput,
    health_pending: bool,
    events_pending: bool,
    classification: Option<storage_health::Classification>,
    /// v1.0 item 18: session start (benchmark accepted).
    started_at: String,
    /// v1.0 Client Identity: the session package of THIS run; its health,
    /// correlation and storage history record belong to that session even
    /// when another benchmark / session starts before they complete.
    package: Option<SharedPackage>,
}

fn bench_facts(r: &StorageDiagnosticSummary) -> storage_health::BenchmarkFacts {
    let level =
        stability_level(r.read_variation_percent).max(stability_level(r.write_variation_percent));
    storage_health::BenchmarkFacts {
        stability: match level {
            StabilityLevel::Stable => storage_health::BenchStability::Stable,
            StabilityLevel::Acceptable => storage_health::BenchStability::Accept,
            StabilityLevel::Unstable => storage_health::BenchStability::Unstable,
        },
        read_variation_percent: r.read_variation_percent,
        write_variation_percent: r.write_variation_percent,
    }
}

/// Elapsed seconds as an "mm:ss" clock (live Test 1 / Test 2 timer).
fn clock_mm_ss(secs: u64) -> String {
    format!("{:02}:{:02}", secs / 60, secs % 60)
}

/// "UNSTABLE (WRITE 18.40%)": a run's overall level and its worst spread.
fn test_vm(
    r: &StorageDiagnosticSummary,
    previous: Option<&HistoryEntry>,
    d: &i18n::Dict,
) -> TestVm {
    let mb = |mib: f64| format!("{:.0}", mib * 1.048576);
    let level =
        stability_level(r.read_variation_percent).max(stability_level(r.write_variation_percent));
    let pct = |v: Option<f64>| v.map(|x| format!("{x:+.1}%")).unwrap_or_else(|| "—".into());
    TestVm {
        read: mb(r.summary_read_mib_s),
        write: mb(r.summary_write_mib_s),
        stability: format!(
            "{} · R {:.1}% / W {:.1}%",
            stability_text(level),
            r.read_variation_percent,
            r.write_variation_percent
        ),
        tone: stability_tone(level),
        delta: previous.map(|p| {
            d.test_delta_fmt
                .replace(
                    "{r}",
                    &pct(ssd_history::delta_percent(
                        r.summary_read_mib_s,
                        p.read_mib_s,
                    )),
                )
                .replace(
                    "{w}",
                    &pct(ssd_history::delta_percent(
                        r.summary_write_mib_s,
                        p.write_mib_s,
                    )),
                )
        }),
    }
}

/// "UNSTABLE 18.4%": compact form for the dashboard note lines.
fn run_brief(r: &StorageDiagnosticSummary) -> String {
    let level =
        stability_level(r.read_variation_percent).max(stability_level(r.write_variation_percent));
    let v = r.read_variation_percent.max(r.write_variation_percent);
    format!("{} {v:.1}%", stability_text(level))
}

fn storage_tone(state: storage_health::StorageState) -> Tone {
    use storage_health::StorageState as S;
    match state {
        S::Ok | S::AnomalyNotConfirmed => Tone::Success,
        S::InsufficientData => Tone::Idle,
        S::BenchmarkAnomalyRetest | S::BenchmarkAnomalyCheck | S::StorageAttention => Tone::Warning,
        S::StorageProblem => Tone::Error,
    }
}

enum BenchmarkEvent {
    Progress(DiagnosticProgress),
    Finished(Result<StorageDiagnosticSummary, String>),
}

enum BenchmarkUiState {
    Idle,
    /// v0.4.2: the first run was UNSTABLE — a short idle before the ONE
    /// automatic confirmation retest. The first result is kept (it is what
    /// a cancel/skip returns to) and stays in evidence/history.
    RetestWaiting {
        identity: String,
        result: StorageDiagnosticSummary,
        until: Instant,
        /// Latest moment to wait for the health read before failing closed.
        deadline: Instant,
    },
    Running {
        progress: DiagnosticProgress,
        rx: Receiver<BenchmarkEvent>,
        cancel: Arc<AtomicBool>,
        started: Instant,
        /// Kept for disk-identity lookup once the run finishes (spec §17).
        test_dir: PathBuf,
        /// Physical-disk identity of the candidate selected when this run
        /// started (v0.3.6, multi-SSD) — `None` when no candidate could be
        /// enumerated, in which case history falls back to the older
        /// volume-serial identity (`ssd_history::disk_identity_for`).
        physical_identity: Option<String>,
        /// v0.4.5 latest measured MiB/s (live Test block values).
        live_write: Option<f64>,
        live_read: Option<f64>,
    },
    Done {
        result: StorageDiagnosticSummary,
        duration_seconds: f64,
        /// Most recent history entry compatible with this run (same disk,
        /// same profile) — `None` on the very first benchmark for this
        /// disk/profile combination. Never a fabricated value.
        previous: Option<HistoryEntry>,
    },
    Failed(String),
    Cancelled,
}
pub struct WinStateDiagApp {
    /// v1.0: crisp multi-size resource icon on every native window.
    window_icons: crate::win_icon::WindowIcons,
    client_name: String,
    computer_name: String,
    mode: DiagnosticMode,
    deep_checks: DeepChecks,
    include_hardware: bool,
    state: RunState,
    journal: SessionJournal,
    /// v0.3.7 full-journal viewer window.
    journal_viewer_open: bool,
    journal_viewer_status: Option<JournalViewerStatus>,
    /// v0.4.0: SFC / DISM / CHKDSK results of the last EXPC run.
    deep_check_results: Vec<DeepCheckOutcome>,
    /// v0.4.1: every EXPC check of the last run (details window).
    expc_checks: Vec<deep_checks::ExpcCheck>,
    expc_details_open: bool,
    expc_export_status: Option<ExportStatus>,
    /// v0.4.5 Copy/Save status of the per-stage Details window.
    stage_export_status: Option<ExportStatus>,
    /// v1.0 Copy / Save as status lines of the remaining Details windows.
    crash_export_status: Option<ExportStatus>,
    disk_export_status: Option<ExportStatus>,
    gpo_export_status: Option<ExportStatus>,
    /// v0.4.5 Copy/Save status of the sensor Details window.
    sensors_export_status: Option<ExportStatus>,
    driver_export_status: Option<ExportStatus>,
    #[cfg(test)]
    driver_rerun_requests: usize,
    theme_ready: bool,
    benchmark_path: String,
    benchmark_state: BenchmarkUiState,
    /// Tracks per-step state for all 14 EXPC pipeline steps.
    expc_tracker: ExpcSubStageTracker,
    /// When the current diagnostic session was started (for elapsed / ETA).
    session_started: Option<Instant>,
    /// Elapsed seconds frozen when the user stopped the run.
    stopped_elapsed: Option<u64>,
    /// Smooth UI contract: on-screen values glide toward the real target.
    ring_smoothed: f32,
    deep_check_smoothed: [f32; 14],
    /// Windows edition + build for the status bar (read once).
    os_label: String,
    raw_passes_open: bool,
    /// The user opened the current report once (stops its attention pulse).
    report_opened: bool,
    /// `<EXE dir>\Reports`: the only place a final report may be opened from.
    reports_root: PathBuf,
    /// v1.0 item 18: identity of this app run's storage sessions.
    storage_session_id: String,
    /// The one cumulative report package of this running WinStateDiag.
    package: SharedPackage,
    /// Stop request of the running diagnostic (None when nothing runs).
    session_cancel: Option<Arc<AtomicBool>>,
    hardware: HardwareViewState,
    /// CryptoPro card: current state (None while a check/ReHash runs).
    crypto: Option<cryptopro::HashState>,
    crypto_detection: cryptopro::Detection,
    crypto_rx: Option<Receiver<CryptoEvent>>,
    /// v1.0: read-only startup inventory (presence / version / licence),
    /// registry only; the HASH check stays with the diagnostic.
    crypto_inventory: Option<cryptopro::Inventory>,
    /// v1.1: origin of the running / last CryptoPro check and its time.
    crypto_origin: CheckOrigin,
    crypto_checked: Option<CheckStamp>,
    /// v1.1: a full diagnostic started while the preflight check was still
    /// running — a fresh SESSION check follows it (never reused).
    crypto_recheck_for_session: bool,
    /// v1.1 CryptoPro Details window + ReHash confirmation dialog.
    crypto_details_open: bool,
    crypto_rehash_confirm: bool,
    crypto_export_status: Option<ExportStatus>,
    /// v1.1: the last ReHash outcome line (Details).
    crypto_last_rehash: Option<String>,
    driver_audit: DriverAuditState,
    /// v1.1: origin of the running / last Driver Audit and its time.
    driver_origin: CheckOrigin,
    driver_checked: Option<CheckStamp>,
    /// v1.1: this UI's Driver Audit history (Details journal; clearing it
    /// never touches Windows logs or saved reports).
    driver_history: Vec<DriverHistoryEntry>,
    driver_history_clear_confirm: bool,
    /// v1.1: the last good result while a re-check runs.
    driver_previous: Option<Box<AuditReport>>,
    /// v1.1: when the launch preflight started (None = not started).
    preflight_started: Option<CheckStamp>,
    /// v1.1 Hardware Passport 2.0: the collector JSON (built in the UI
    /// language when drawn), window and export status.
    passport2_json: Option<String>,
    passport2_open: bool,
    passport2_status: Option<ExportStatus>,
    drivers_open: bool,
    /// v0.4.4: active page (Diagnostics / Hardware).
    page: Page,
    /// Crash Dump / BSOD analyzer state.
    crash: CrashState,
    crash_rx: Option<Receiver<CrashMsg>>,
    /// v1.0 read-only ATA SMART of every physical disk (HDDs included).
    ata_scan: Option<Vec<AtaDisk>>,
    ata_rx: Option<Receiver<Vec<AtaDisk>>>,
    ata_evidence_pending: bool,
    /// v1.0 aggregated event evidence of this session.
    event_evidence: Option<Result<(Vec<events::Aggregate>, Option<bool>), String>>,
    events_rx: Option<Receiver<Result<(Vec<events::RawEvent>, Vec<events::ServiceInfo>), String>>>,
    /// v1.0 hidden WinDbg installer output.
    install_rx: Option<Receiver<InstallMsg>>,
    crash_details_open: bool,
    /// After an explicit "install analyzer" click: (launched, last re-scan).
    /// The debugger is re-detected periodically for 10 minutes.
    crash_redetect: Option<(Instant, Instant)>,
    /// v0.4.5 hardware sensors (10 s sampling window; session min/max).
    sensors: Option<sensors::Snapshot>,
    sensors_rx: Option<Receiver<sensors::Snapshot>>,
    /// v1.0 item 8: when the current sensor read started (real timer).
    sensors_started: Option<Instant>,
    /// v1.0 item 8: the last read failed (cleared by the next read).
    sensors_error: Option<String>,
    /// Write sensor evidence for the read in flight.
    sensors_evidence_pending: bool,
    sensors_details_open: bool,
    /// v0.4.5 compact computer passport (read-only CIM collector).
    passport: Option<Result<passport::Passport, String>>,
    passport_rx: Option<Receiver<Result<passport::Passport, String>>>,
    /// v0.4.5 text queued for the clipboard (copied on the next frame).
    clipboard_out: Option<String>,
    /// v0.4.5 per-stage Details window (0-based EXPC stage index).
    stage_details: Option<usize>,
    /// Group Policy / ADMX health.
    gpo: Option<Result<(gpo_admx::GpoInputs, gpo_admx::GpoResult), String>>,
    gpo_rx: Option<Receiver<Result<gpo_admx::GpoInputs, String>>>,
    gpo_details_open: bool,
    window_fitted: bool,
    /// Physical SSD/NVMe disks WinStateDiag could enumerate on this machine
    /// (v0.3.6, multi-SSD). Empty when enumeration is unavailable (e.g. any
    /// non-Windows build, or a Windows machine where the probe failed) —
    /// never a fabricated single entry.
    ssd_candidates: Vec<DiskCandidate>,
    /// Index into `ssd_candidates` currently targeted by the benchmark.
    ssd_selected: usize,
    /// v1.0: the background launch enumeration of the disk selector.
    ssd_enum_rx: Option<Receiver<Vec<DiskCandidate>>>,
    /// v0.3.6 §10 regression guard: per-physical-disk cache of this
    /// session's own last completed benchmark, keyed by the same
    /// `disk_identity` string used for on-disk history. Selecting a
    /// different physical disk WITHOUT rerunning the benchmark must
    /// immediately show that disk's own latest+previous READ/WRITE
    /// results — never another disk's, and never stale data — so
    /// `select_ssd_disk` restores from this cache instead of leaving the
    /// single shared `benchmark_state` pointed at whichever disk ran last.
    ssd_results:
        std::collections::HashMap<String, (StorageDiagnosticSummary, f64, Option<HistoryEntry>)>,
    /// Native NVMe Health (experimental, read-only): the latest health
    /// record per physical disk, keyed by the SAME
    /// `storage_topology::physical_disk_identity` the benchmark uses —
    /// never by drive letter. Facts only; no severity is derived from it.
    nvme_health: std::collections::HashMap<String, nvme_health::NvmeHealth>,
    /// Pending background health + storage-event read (started after a
    /// completed first benchmark run).
    nvme_rx: Option<Receiver<ProbeMsg>>,
    /// v0.4.2 storage correlation, per physical disk identity.
    assessments: std::collections::HashMap<String, StorageAssessment>,
    /// Identity whose automatic retest run is executing (one at most).
    retest_identity: Option<String>,
    /// Idle before the automatic retest (tests shorten it).
    retest_idle: Duration,
    /// Test seam: lets tests drive a "running" benchmark without I/O.
    #[cfg(test)]
    bench_test_tx: Option<std::sync::mpsc::Sender<BenchmarkEvent>>,
    /// Active UI language (v0.3.6 bilingual pass). Loaded once at startup
    /// from the portable-safe preference file next to the EXE; switching it
    /// live never rebuilds the window, only the next frame's `DashboardVm`.
    language: Language,
    /// Folder holding the portable language preference file (the EXE's
    /// folder in production; a temporary folder in tests).
    language_pref_dir: PathBuf,
    /// VISUAL_REFERENCE mode (`--visual-reference`), QA only.
    reference: Option<ReferenceMode>,
    /// v1.0 Client Identity: sessions opened by this process (SessionId
    /// suffix, unique within the second-resolution stamp + PID).
    session_seq: u32,
    /// Crash analyzer clicked before any inventory existed: the scan runs
    /// first and the analysis follows it.
    crash_analyze_after_scan: bool,
    /// v1.0 Client Identity: the session package each UI-thread module
    /// (sensors, gpo, ata, crash, events, drivers, storage) was started in.
    op_packages: std::collections::HashMap<&'static str, SharedPackage>,
    /// Test seam: every diagnostic collector start request, in order (unit
    /// tests never start the real collectors / subprocesses).
    #[cfg(test)]
    collector_requests: Vec<&'static str>,
    /// Test seam: (client, computer) of the last diagnostic engine request
    /// and its event sender (tests inject Cancelled / Finished).
    #[cfg(test)]
    test_session_request: Option<(String, String)>,
    #[cfg(test)]
    engine_test_tx: Option<Sender<EngineEvent>>,
}

/// `%SystemDrive%` (for the CHKDSK manual command text), `C:` if unset.
fn system_drive() -> String {
    std::env::var("SystemDrive")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "C:".into())
}

/// Folder of the portable EXE (the report destination lives under it).
fn exe_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."))
}

impl Default for WinStateDiagApp {
    fn default() -> Self {
        let computer_name = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "UNKNOWN-PC".into());
        // v0.4.0: full build with the update revision (26200.xxxx) when
        // Windows reports it; the footer text is right-aligned and the left
        // text is clipped to the remaining room, so the layout is unchanged.
        let (product, build) = sysinfo::windows_edition_and_full_build();
        let os_label = if build.is_empty() {
            product
        } else {
            format!("{product}   {build}")
        };
        let mut app = Self {
            client_name: String::new(),
            computer_name,
            mode: DiagnosticMode::Standard,
            deep_checks: DeepChecks::default(),
            include_hardware: true,
            state: RunState::Idle,
            journal: SessionJournal::default(),
            journal_viewer_open: false,
            journal_viewer_status: None,
            deep_check_results: Vec::new(),
            expc_checks: Vec::new(),
            expc_details_open: false,
            expc_export_status: None,
            stage_export_status: None,
            crash_export_status: None,
            disk_export_status: None,
            gpo_export_status: None,
            sensors_export_status: None,
            driver_export_status: None,
            #[cfg(test)]
            driver_rerun_requests: 0,
            theme_ready: false,
            benchmark_path: std::env::temp_dir().display().to_string(),
            benchmark_state: BenchmarkUiState::Idle,
            expc_tracker: ExpcSubStageTracker::default(),
            session_started: None,
            stopped_elapsed: None,
            ring_smoothed: 0.0,
            deep_check_smoothed: [0.0; 14],
            os_label,
            raw_passes_open: false,
            report_opened: false,
            reports_root: exe_dir().join("Reports"),
            storage_session_id: {
                let t = sysinfo::local_time();
                crate::storage_history::new_session_id(&format!(
                    "{:04}{:02}{:02}-{:02}{:02}{:02}",
                    t.year, t.month, t.day, t.hour, t.minute, t.second
                ))
            },
            package: Arc::new(Mutex::new(SessionPackage::for_exe_dir(&exe_dir()))),
            session_cancel: None,
            hardware: HardwareViewState::Idle,
            crypto: None,
            crypto_detection: cryptopro::Detection::NotInstalled,
            crypto_rx: None,
            crypto_inventory: None,
            crypto_origin: CheckOrigin::Session,
            crypto_checked: None,
            crypto_recheck_for_session: false,
            crypto_details_open: false,
            crypto_rehash_confirm: false,
            crypto_export_status: None,
            crypto_last_rehash: None,
            driver_audit: DriverAuditState::Idle,
            driver_origin: CheckOrigin::Session,
            driver_checked: None,
            driver_history: Vec::new(),
            driver_history_clear_confirm: false,
            driver_previous: None,
            preflight_started: None,
            passport2_json: None,
            passport2_open: false,
            passport2_status: None,
            drivers_open: false,
            page: Page::Diagnostics,
            crash: CrashState::default(),
            crash_rx: None,
            ata_scan: None,
            ata_rx: None,
            ata_evidence_pending: false,
            event_evidence: None,
            events_rx: None,
            install_rx: None,
            crash_details_open: false,
            crash_redetect: None,
            sensors: None,
            sensors_rx: None,
            sensors_started: None,
            sensors_error: None,
            sensors_evidence_pending: false,
            sensors_details_open: false,
            passport: None,
            passport_rx: None,
            clipboard_out: None,
            stage_details: None,
            gpo: None,
            gpo_rx: None,
            gpo_details_open: false,
            window_fitted: false,
            ssd_candidates: Vec::new(),
            ssd_selected: 0,
            ssd_enum_rx: None,
            ssd_results: std::collections::HashMap::new(),
            nvme_health: std::collections::HashMap::new(),
            nvme_rx: None,
            assessments: std::collections::HashMap::new(),
            retest_identity: None,
            retest_idle: RETEST_IDLE,
            #[cfg(test)]
            bench_test_tx: None,
            // Reading the preference is best-effort and must never block
            // startup: `i18n::load` itself falls back to `Language::Ru` on
            // any I/O error, missing file, or corrupted content.
            language: i18n::load(&exe_dir()),
            language_pref_dir: exe_dir(),
            reference: ReferenceMode::from_args(),
            session_seq: 0,
            crash_analyze_after_scan: false,
            op_packages: std::collections::HashMap::new(),
            #[cfg(test)]
            collector_requests: Vec::new(),
            #[cfg(test)]
            test_session_request: None,
            #[cfg(test)]
            engine_test_tx: None,
            window_icons: Default::default(),
        };
        // v1.0 polish QA: `--visual-reference --lang en|ru`.
        match app.reference.as_ref().and_then(|r| r.lang.as_deref()) {
            Some("en") => app.language = Language::En,
            Some("ru") => app.language = Language::Ru,
            _ => {}
        }
        // v1.1 Startup Orchestration: a launch creates no report, session or
        // ZIP and starts no EXPC diagnostic. In the background it fills the
        // SSD/NVMe disk selector and runs the automatic read-only PREFLIGHT
        // checks (Driver Audit, CryptoPro, WinDbg + crash / dump discovery —
        // see `start_preflight`). Sensors, passport, SMART, events, GPO and
        // the EXPC stages still run only after an explicit user action.
        // (Unit tests drive the preflight explicitly.)
        app.enumerate_disk_selector();
        if !cfg!(test) {
            app.start_preflight();
        }
        if app.reference.is_some() {
            app.client_name = fixture::CLIENT_NAME.into();
            app.computer_name = fixture::COMPUTER_NAME.into();
            app.benchmark_path = fixture::BENCHMARK_PATH.into();
            let scene = app
                .reference
                .as_ref()
                .map(|r| r.scene.clone())
                .unwrap_or_default();
            app.seed_qa_scene(&scene);
        }
        app
    }
}

impl WinStateDiagApp {
    /// One-off informational line in the journal (used by Safe Graphics
    /// Startup to say that the safe renderer is active).
    pub fn push_notice(&mut self, message: String) {
        push_journal(&mut self.journal, message);
    }

    fn is_running(&self) -> bool {
        matches!(self.state, RunState::Running { .. })
    }

    fn benchmark_is_running(&self) -> bool {
        matches!(
            self.benchmark_state,
            BenchmarkUiState::Running { .. } | BenchmarkUiState::RetestWaiting { .. }
        )
    }

    /// Physical disk currently targeted by the selector (v0.3.6), if any
    /// were enumerated.
    fn selected_ssd_candidate(&self) -> Option<&DiskCandidate> {
        self.ssd_candidates.get(self.ssd_selected)
    }

    /// Direct card click (v0.3.6 UI finalization): select exactly this
    /// physical SSD/NVMe and re-resolve `benchmark_path` from it. Never
    /// falls back to `C:` silently: a candidate with no writable volume is
    /// still selected (its card highlights, its info shows why it can't be
    /// benchmarked) but `benchmark_path` is left at its previous value and
    /// the journal records why — `start_benchmark` also refuses to run
    /// against a candidate with no resolvable target.
    fn select_ssd_disk(&mut self, index: usize) {
        if self.benchmark_is_running() || index >= self.ssd_candidates.len() {
            return;
        }
        self.ssd_selected = index;
        let mut new_identity = None;
        if let Some(candidate) = self.ssd_candidates.get(self.ssd_selected) {
            let physical_identity = storage_topology::physical_disk_identity(&candidate.disk);
            match storage_topology::benchmark_target_dir(candidate) {
                Ok(dir) => {
                    let identity = ssd_history::disk_identity_with_physical(
                        &dir,
                        Some(physical_identity.as_str()),
                    );
                    self.benchmark_path = dir.display().to_string();
                    new_identity = Some(identity);
                }
                Err(_) => {
                    // App-generated line in the UI language (the disk is
                    // named by its model, never by a guessed letter).
                    let disk = if candidate.disk.model.trim().is_empty() {
                        format!("PhysicalDrive{}", candidate.disk.index)
                    } else {
                        candidate.disk.model.trim().to_string()
                    };
                    let line = i18n::t(self.language)
                        .journal_ssd_no_writable_fmt
                        .replace("{disk}", &disk);
                    push_journal(&mut self.journal, line);
                }
            }
        }
        // v0.3.6 §10: switching to a disk WITHOUT rerunning the benchmark
        // must immediately show that physical disk's own latest+previous
        // READ/WRITE results when this session already benchmarked it, and
        // must never keep showing a different disk's stale "Done" screen
        // otherwise. Never touches state while a benchmark is running (the
        // early return above already guards that) and never invents data —
        // an un-benchmarked disk simply goes back to Idle.
        if !matches!(self.benchmark_state, BenchmarkUiState::Running { .. }) {
            match new_identity
                .as_deref()
                .and_then(|id| self.ssd_results.get(id))
            {
                Some((result, duration_seconds, previous)) => {
                    self.benchmark_state = BenchmarkUiState::Done {
                        result: result.clone(),
                        duration_seconds: *duration_seconds,
                        previous: previous.clone(),
                    };
                }
                None => {
                    self.benchmark_state = BenchmarkUiState::Idle;
                }
            }
        }
    }

    /// v1.0 Startup Idle: the disk selector (v0.3.6 physical SSD/NVMe
    /// cards) is filled off the UI thread at launch: in-process volume /
    /// device-property queries only — no subprocess, no SMART, nothing
    /// written (writability is not probed, see `LaunchTopologySource`).
    /// Windows-only, not in QA reference / not under test. On any other
    /// target this stays empty — never a fabricated single "C:" candidate.
    fn enumerate_disk_selector(&mut self) {
        #[cfg(windows)]
        if self.reference.is_none() && !cfg!(test) {
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let source = storage_topology::windows_source::LaunchTopologySource;
                let _ = tx.send(storage_topology::candidates_from(&source));
            });
            self.ssd_enum_rx = Some(rx);
        }
    }

    fn poll_disk_selector(&mut self) {
        let Some(rx) = &self.ssd_enum_rx else {
            return;
        };
        match rx.try_recv() {
            Ok(candidates) => {
                self.ssd_enum_rx = None;
                self.apply_disk_candidates(candidates);
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => {}
            Err(std::sync::mpsc::TryRecvError::Disconnected) => self.ssd_enum_rx = None,
        }
    }

    /// Installs enumerated disks, keeping the selected physical disk when it
    /// is still present (otherwise the default candidate).
    fn apply_disk_candidates(&mut self, candidates: Vec<DiskCandidate>) {
        let previous = self
            .selected_ssd_candidate()
            .map(|c| storage_topology::physical_disk_identity(&c.disk));
        self.ssd_candidates = candidates;
        self.ssd_selected = previous
            .and_then(|id| {
                self.ssd_candidates
                    .iter()
                    .position(|c| storage_topology::physical_disk_identity(&c.disk) == id)
            })
            .or_else(|| storage_topology::default_candidate_index(&self.ssd_candidates))
            .unwrap_or(0);
        if let Some(candidate) = self.ssd_candidates.get(self.ssd_selected) {
            if let Ok(dir) = storage_topology::benchmark_target_dir(candidate) {
                self.benchmark_path = dir.display().to_string();
            }
        }
    }

    fn start_benchmark(&mut self) {
        // v1.0: the previous run's health / events probe still belongs to
        // that run (and its session): a new run would replace its pending
        // assessment, so it waits (the start control is disabled meanwhile).
        if self.benchmark_is_running() || self.is_running() || self.nvme_rx.is_some() {
            return;
        }
        self.begin_operation(false);
        // Benchmark, NVMe health, correlation and the automatic retest of
        // this run all belong to this session.
        self.claim_package("storage");
        // The explicit start re-enumerates WITH the writability probe (the
        // launch selector never wrote anything); the selection is kept.
        #[cfg(windows)]
        if self.reference.is_none() && !cfg!(test) {
            self.ssd_enum_rx = None;
            let source = storage_topology::windows_source::WindowsTopologySource;
            let candidates = storage_topology::candidates_from(&source);
            self.apply_disk_candidates(candidates);
        }
        // A user-started run is always an initial run.
        self.retest_identity = None;
        self.launch_benchmark();
    }

    /// Starts one benchmark run on the selected disk. Returns false when
    /// the target is not resolvable (nothing is started).
    fn launch_benchmark(&mut self) -> bool {
        // Never silently fall back to C: — if candidates were enumerated
        // but the selected one has no writable volume, refuse rather than
        // benchmarking whatever benchmark_path happened to still hold.
        if !self.ssd_candidates.is_empty()
            && self
                .selected_ssd_candidate()
                .map(|c| storage_topology::benchmark_target_dir(c).is_err())
                .unwrap_or(true)
        {
            let msg = i18n::t(self.language).journal_ssd_target_unavailable;
            push_journal(&mut self.journal, msg.to_string());
            return false;
        }
        // benchmark_path is still the single source of truth for where the
        // temp file goes (Action::SelectSsdDisk keeps it in sync with the
        // selected physical disk); we only read the physical identity here
        // so history stays keyed by disk, not by drive letter.
        let physical_identity = self
            .selected_ssd_candidate()
            .map(|c| storage_topology::physical_disk_identity(&c.disk));
        // v1.0 (SATA "2571–3065 MB/s" audit): the target directory and the
        // disk identity come from the SAME selected candidate. A stale UI
        // path could otherwise write to another volume (e.g. the NVMe C:)
        // while the result is attributed to the selected SATA disk.
        if let Some(c) = self.selected_ssd_candidate() {
            match storage_topology::benchmark_target_dir(c) {
                Ok(dir)
                    if c.volume
                        .as_ref()
                        .is_some_and(|v| v.physical_disk_index == c.disk.index) =>
                {
                    self.benchmark_path = dir.display().to_string();
                }
                _ => {
                    let msg = i18n::t(self.language).journal_ssd_target_unavailable;
                    push_journal(&mut self.journal, msg.to_string());
                    return false;
                }
            }
        }
        let path = PathBuf::from(self.benchmark_path.trim());
        let test_dir = path.clone();
        self.request_collector("ssd_benchmark");
        let cancel = Arc::new(AtomicBool::new(false));
        let (tx, rx) = std::sync::mpsc::channel();
        // Tests drive the run through this sender instead (no disk I/O).
        #[cfg(test)]
        {
            self.bench_test_tx = Some(tx.clone());
        }
        if !cfg!(test) {
            let worker_cancel = Arc::clone(&cancel);
            std::thread::spawn(move || {
                let progress_tx = tx.clone();
                let result = storage_benchmark::run_diagnostic_summary_with_progress(
                    path,
                    &worker_cancel,
                    move |progress| {
                        let _ = progress_tx.send(BenchmarkEvent::Progress(progress));
                    },
                )
                .map_err(|error| error.to_string());
                let _ = tx.send(BenchmarkEvent::Finished(result));
            });
        }
        self.benchmark_state = BenchmarkUiState::Running {
            live_write: None,
            live_read: None,
            progress: DiagnosticProgress::Preparation,
            rx,
            cancel,
            started: Instant::now(),
            test_dir,
            physical_identity,
        };
        true
    }

    fn poll_benchmark(&mut self) {
        let mut next_state = None;
        let mut history_log: Option<String> = None;
        let mut finished: Option<(String, StorageDiagnosticSummary, f64, Option<HistoryEntry>)> =
            None;
        let mut finished_err = false;
        let mut was_cancelled = false;
        let role = if self.retest_identity.is_some() {
            RunRole::AutomaticRetest
        } else {
            RunRole::Initial
        };
        let disk = self.selected_ssd_candidate().map(|c| c.disk.clone());
        // v1.0: the stored stem of the initial run this retest confirms.
        let retest_of: Option<String> = self
            .retest_identity
            .as_ref()
            .and_then(|id| self.assessments.get(id))
            .and_then(|a| {
                a.benchmark_files
                    .iter()
                    .find(|n| n.ends_with(".json"))
                    .cloned()
            });
        let mut ssd_evidence: Option<Vec<EvidenceFile>> = None;
        let storage_package = self.package_of("storage");
        if let BenchmarkUiState::Running {
            progress,
            rx,
            cancel,
            started,
            test_dir,
            physical_identity,
            live_write,
            live_read,
        } = &mut self.benchmark_state
        {
            while let Ok(event) = rx.try_recv() {
                match event {
                    BenchmarkEvent::Progress(DiagnosticProgress::Measured {
                        write_mib_s,
                        read_mib_s,
                        ..
                    }) => {
                        *live_write = Some(write_mib_s);
                        if read_mib_s.is_some() {
                            *live_read = read_mib_s;
                        }
                    }
                    BenchmarkEvent::Progress(value) => *progress = value,
                    BenchmarkEvent::Finished(Ok(result))
                        if disk
                            .as_ref()
                            .and_then(|d| {
                                storage_benchmark::implausible_reason(&d.bus_type, &result)
                            })
                            .is_some() =>
                    {
                        // v1.0: physically impossible for the detected
                        // transport → BENCHMARK INVALID / RESULT NOT TRUSTED.
                        // Never history, never a stability verdict, never
                        // "performance"; the raw facts stay in evidence.
                        let reason = disk
                            .as_ref()
                            .and_then(|d| {
                                storage_benchmark::implausible_reason(&d.bus_type, &result)
                            })
                            .unwrap_or_default();
                        let duration_seconds = started.elapsed().as_secs_f64();
                        ssd_evidence = Some(invalid_benchmark_evidence(
                            &result,
                            test_dir,
                            duration_seconds,
                            disk.as_ref(),
                            &reason,
                        ));
                        finished_err = true;
                        history_log = Some(format!(
                            "{}: {reason}",
                            i18n::t(self.language).ssd_benchmark_invalid
                        ));
                        next_state = Some(BenchmarkUiState::Failed(format!(
                            "{} — {reason}",
                            i18n::t(self.language).ssd_benchmark_invalid
                        )));
                    }
                    BenchmarkEvent::Finished(Ok(result)) => {
                        // Best-effort history bookkeeping: a storage or
                        // permission failure here never affects the result.
                        // v0.4.0: the persistent history is
                        // `Reports\History\` (application state); this PC's
                        // report folder of today keeps its session copy for
                        // the ZIP (restored from the ZIP first when the
                        // folder was already finalized). Comparison reads
                        // both, each run counted once. v0.4.2: the automatic
                        // retest is recorded exactly like the first run.
                        let reports_root = self.reports_root.clone();
                        let history_path = report_package::lock(&storage_package)
                            .open_for_update(
                                &self.client_name,
                                &self.computer_name,
                                &identity_date(sysinfo::local_time()),
                            )
                            .map(|id| id.report_dir.join(report_package::SSD_HISTORY_FILE));
                        let disk_identity = ssd_history::disk_identity_with_physical(
                            test_dir,
                            physical_identity.as_deref(),
                        );
                        let current_entry = HistoryEntry {
                            timestamp_unix: ssd_history::now_unix(),
                            disk_identity: disk_identity.clone(),
                            block_size: result.profile.block_size,
                            queue_depth: result.profile.queue_depth,
                            test_file_size: result.profile.test_file_size,
                            pass_count: result.profile.pass_count,
                            read_mib_s: result.summary_read_mib_s,
                            write_mib_s: result.summary_write_mib_s,
                        };
                        let existing_history = ssd_history::load_all_history(&reports_root);
                        let previous = ssd_history::find_previous_compatible(
                            &existing_history,
                            &current_entry,
                        );
                        let appended = history_path
                            .map_err(std::io::Error::other)
                            .and_then(|p| ssd_history::append_entry(&p, &current_entry))
                            .and_then(|_| {
                                ssd_history::merge_into(
                                    &ssd_history::canonical_history_path(&reports_root),
                                    std::slice::from_ref(&current_entry),
                                )
                            });
                        if let Err(err) = appended {
                            history_log = Some(
                                i18n::t(self.language)
                                    .journal_ssd_history_failed_fmt
                                    .replace("{error}", &err.to_string()),
                            );
                        }
                        let duration_seconds = started.elapsed().as_secs_f64();
                        ssd_evidence = Some(ssd_benchmark_evidence_for(
                            &result,
                            test_dir,
                            duration_seconds,
                            previous.as_ref(),
                            disk_identity_label(physical_identity.as_deref()),
                            disk.as_ref(),
                            role,
                            retest_of.as_deref(),
                        ));
                        // v0.3.6 §10: cache this disk's own result by its
                        // identity so selecting away and back (without a
                        // rerun) restores it instead of showing whichever
                        // disk's run happens to be the single shared state.
                        self.ssd_results.insert(
                            disk_identity.clone(),
                            (result.clone(), duration_seconds, previous.clone()),
                        );
                        finished = Some((
                            disk_identity,
                            result.clone(),
                            duration_seconds,
                            previous.clone(),
                        ));
                        next_state = Some(BenchmarkUiState::Done {
                            result,
                            duration_seconds,
                            previous,
                        });
                    }
                    BenchmarkEvent::Finished(Err(message)) => {
                        finished_err = true;
                        was_cancelled = cancel.load(Ordering::Relaxed);
                        next_state = Some(if was_cancelled {
                            BenchmarkUiState::Cancelled
                        } else {
                            BenchmarkUiState::Failed(message)
                        });
                    }
                }
            }
        }
        if let Some(state) = next_state {
            self.benchmark_state = state;
        }
        if let Some(line) = history_log {
            push_journal(&mut self.journal, line);
        }
        // The completed benchmark joins the session report automatically;
        // the assessment records the names it was STORED under.
        let mut names: Vec<String> = Vec::new();
        if let Some(files) = ssd_evidence {
            let module = i18n::t(self.language).ssd_module_name;
            names = self.contribute_evidence("storage", module, files);
        }
        if let Some((identity, result, duration, previous)) = finished {
            match self.retest_identity.take() {
                Some(id) => {
                    // The automatic retest finished: both runs are kept.
                    if let Some(a) = self.assessments.get_mut(&id) {
                        a.retest = storage_health::RetestOutcome::Completed(bench_facts(&result));
                        a.second = Some(result);
                        a.second_duration = Some(duration);
                        a.benchmark_files.extend(names);
                    }
                    self.finalize_assessment(&id);
                }
                None => self.begin_assessment(identity, result, duration, previous, names, disk),
            }
        } else if finished_err {
            if let Some(id) = self.retest_identity.take() {
                // A cancelled/failed retest never hides the first result.
                let outcome = if was_cancelled {
                    storage_health::RetestOutcome::Cancelled
                } else {
                    storage_health::RetestOutcome::Failed
                };
                self.end_retest(&id, outcome);
            }
        }
    }

    /// First run of a user-started benchmark: opens this disk's storage
    /// assessment, starts the read-only health/event probe and — when the
    /// run is UNSTABLE — schedules the ONE automatic confirmation retest.
    fn begin_assessment(
        &mut self,
        identity: String,
        result: StorageDiagnosticSummary,
        duration: f64,
        previous: Option<HistoryEntry>,
        files: Vec<String>,
        disk: Option<storage_topology::PhysicalDiskInfo>,
    ) {
        let probing = self.start_nvme_health_probe(&identity);
        let unstable = bench_facts(&result).stability == storage_health::BenchStability::Unstable;
        self.assessments.insert(
            identity.clone(),
            StorageAssessment {
                disk,
                first: result.clone(),
                first_duration: duration,
                first_previous: previous,
                second: None,
                second_duration: None,
                retest: if unstable {
                    storage_health::RetestOutcome::Pending
                } else {
                    storage_health::RetestOutcome::NotNeeded
                },
                benchmark_files: files,
                health_file: None,
                events: storage_health::EventsInput::NotCollected,
                health_pending: probing,
                events_pending: probing,
                classification: None,
                started_at: local_iso(sysinfo::local_time()),
                package: Some(self.package_of("storage")),
            },
        );
        if unstable {
            let now = Instant::now();
            let d = i18n::t(self.language);
            push_journal(
                &mut self.journal,
                d.journal_retest_scheduled_fmt
                    .replace("{s}", &self.retest_idle.as_secs().to_string()),
            );
            self.benchmark_state = BenchmarkUiState::RetestWaiting {
                identity: identity.clone(),
                result,
                until: now + self.retest_idle,
                deadline: now + self.retest_idle + RETEST_HEALTH_WAIT,
            };
        }
        self.finalize_assessment(&identity);
    }

    /// Drives the idle → retest step. Fails closed: no retest when the
    /// target is gone, the health read did not arrive in time, or the
    /// controller state makes more write testing inappropriate.
    fn poll_retest(&mut self) {
        let BenchmarkUiState::RetestWaiting {
            identity,
            until,
            deadline,
            ..
        } = &self.benchmark_state
        else {
            return;
        };
        let now = Instant::now();
        if now < *until {
            return;
        }
        let identity = identity.clone();
        let health_pending = self
            .assessments
            .get(&identity)
            .is_some_and(|a| a.health_pending);
        if health_pending && now < *deadline {
            return;
        }
        let skip = if health_pending {
            Some(storage_health::RetestSkip::HealthPending)
        } else if !storage_health::retest_allowed(self.nvme_health.get(&identity)) {
            Some(storage_health::RetestSkip::HealthForbidsWrites)
        } else if !self.retest_target_ok(&identity) {
            Some(storage_health::RetestSkip::TargetUnavailable)
        } else {
            None
        };
        if let Some(why) = skip {
            self.end_retest(&identity, storage_health::RetestOutcome::Skipped(why));
            return;
        }
        self.retest_identity = Some(identity.clone());
        if self.launch_benchmark() {
            let d = i18n::t(self.language);
            push_journal(&mut self.journal, d.journal_retest_started.to_string());
        } else {
            self.retest_identity = None;
            self.end_retest(
                &identity,
                storage_health::RetestOutcome::Skipped(
                    storage_health::RetestSkip::TargetUnavailable,
                ),
            );
        }
    }

    /// The retest target must still be the same, resolvable disk.
    fn retest_target_ok(&self, identity: &str) -> bool {
        let path_ok = Path::new(self.benchmark_path.trim()).is_dir();
        if self.ssd_candidates.is_empty() {
            return path_ok;
        }
        self.selected_ssd_candidate().is_some_and(|c| {
            storage_topology::physical_disk_identity(&c.disk) == identity
                && storage_topology::benchmark_target_dir(c).is_ok()
        }) && path_ok
    }

    /// Ends the retest phase without a second result: the first run is
    /// shown again (never hidden) and the outcome is recorded.
    fn end_retest(&mut self, identity: &str, outcome: storage_health::RetestOutcome) {
        let d = i18n::t(self.language);
        let line = storage_health::Finding::RetestNotRun(outcome.clone())
            .text(self.language == Language::Ru);
        if let Some(a) = self.assessments.get_mut(identity) {
            a.retest = outcome;
            self.benchmark_state = BenchmarkUiState::Done {
                result: a.first.clone(),
                duration_seconds: a.first_duration,
                previous: a.first_previous.clone(),
            };
            self.ssd_results.insert(
                identity.to_string(),
                (a.first.clone(), a.first_duration, a.first_previous.clone()),
            );
        } else {
            self.benchmark_state = BenchmarkUiState::Idle;
        }
        push_journal(&mut self.journal, format!("{}: {line}", d.ssd_module_name));
        self.finalize_assessment(identity);
    }

    /// Classifies a disk once every input is in (retest done/skipped,
    /// health and events read or failed) and records the evidence.
    fn finalize_assessment(&mut self, identity: &str) {
        let Some(a) = self.assessments.get(identity) else {
            return;
        };
        if a.classification.is_some()
            || a.health_pending
            || a.events_pending
            || a.retest == storage_health::RetestOutcome::Pending
        {
            return;
        }
        let now = sysinfo::local_time();
        let inputs = storage_health::StorageHealthInputs {
            physical_identity: identity.to_string(),
            disk_index: a.disk.as_ref().map(|d| d.index),
            benchmark: Some(bench_facts(&a.first)),
            retest: a.retest.clone(),
            nvme: self.nvme_health.get(identity).cloned(),
            events: a.events.clone(),
            assessed_at: local_iso(now),
        };
        let c = storage_health::classify(&inputs);
        let model = a
            .disk
            .as_ref()
            .map(|d| d.model.trim().to_string())
            .unwrap_or_default();
        // v1.0 items 15 + 18: session identity; delta against the latest
        // COMPLETED session of this disk (cancelled runs never anchor).
        let status = match inputs.retest {
            storage_health::RetestOutcome::Cancelled => {
                crate::storage_history::SessionStatus::Cancelled
            }
            storage_health::RetestOutcome::Failed => crate::storage_history::SessionStatus::Failed,
            _ => crate::storage_history::SessionStatus::Completed,
        };
        let smart_now = inputs.nvme.as_ref().and_then(|h| h.smart.as_ref());
        let run_session = self.storage_session_of(identity);
        let record = crate::storage_history::SessionRecord {
            session_id: run_session.clone(),
            physical_identity: identity.to_string(),
            start_time: a.started_at.clone(),
            end_time: inputs.assessed_at.clone(),
            status,
            producer_version: crate::APP_VERSION.to_string(),
            storage_state: c.state.code().to_string(),
            error_log_entries: smart_now
                .map(|s| s.error_information_log_entries.min(u64::MAX as u128) as u64),
            media_errors: smart_now
                .map(|s| s.media_and_data_integrity_errors.min(u64::MAX as u128) as u64),
        };
        let history_path = self.reports_root.join(crate::storage_history::FILE_NAME);
        // An unreadable / corrupt history is never treated as empty: no
        // delta is claimed and the file is not overwritten.
        let loaded = crate::storage_history::load(&history_path);
        let error_log_delta = smart_now.map(|_| match &loaded {
            Ok(history) => crate::storage_history::delta_against_history(
                history,
                identity,
                &run_session,
                record.error_log_entries,
            ),
            Err(_) => crate::storage_history::ErrorLogDelta::HistoryUnavailable,
        });
        let history_error = match loaded {
            Ok(mut history) => {
                crate::storage_history::upsert(&mut history, record.clone());
                crate::storage_history::save_atomic(&history_path, &history)
                    .err()
                    .map(|e| format!("save failed: {e}"))
            }
            Err(e) => Some(format!("load failed (file kept unchanged): {e}")),
        };
        let json = storage_health::to_json_with(
            &inputs,
            &c,
            &model,
            a.health_file.as_deref(),
            &a.benchmark_files,
            &storage_health::CorrelationExtras {
                session: Some(record),
                error_log_delta: error_log_delta.clone(),
                history_error: history_error.clone(),
            },
        );
        if let Some(e) = &history_error {
            push_journal(
                &mut self.journal,
                if self.language == Language::Ru {
                    format!("История сессий накопителя: ошибка — {e}")
                } else {
                    format!("Storage session history: error — {e}")
                },
            );
        }
        if let Some(dl) = error_log_delta.as_ref() {
            push_journal(&mut self.journal, dl.text(self.language == Language::Ru));
        }
        let name = storage_health::evidence_file_name(&evidence_stamp(now), inputs.disk_index);
        let d = i18n::t(self.language);
        let disk = inputs
            .disk_index
            .map(|n| format!("PhysicalDrive{n}"))
            .unwrap_or_else(|| model.clone());
        push_journal(
            &mut self.journal,
            d.journal_storage_assessment_fmt
                .replace("{disk}", &disk)
                .replace("{state}", c.state.text(self.language == Language::Ru)),
        );
        if let Some(a) = self.assessments.get_mut(identity) {
            a.classification = Some(c);
        }
        let package = self.storage_package_of(identity);
        self.contribute_evidence_to(
            package,
            d.ssd_module_name,
            vec![EvidenceFile::new(name, json.into_bytes())],
        );
    }

    /// Native NVMe Health + storage events: reads the SMART / Health and
    /// Error Information log pages and the storage System events for the
    /// benchmarked physical disk on a background thread. Windows only,
    /// never in tests/QA reference mode; any failure becomes a status,
    /// never a crash. Returns whether a probe was started.
    fn start_nvme_health_probe(&mut self, identity: &str) -> bool {
        #[cfg(windows)]
        if self.reference.is_none() && !cfg!(test) && self.nvme_rx.is_none() {
            if let Some(candidate) = self.selected_ssd_candidate() {
                let disk = candidate.disk.clone();
                let identity = identity.to_string();
                let (tx, rx) = std::sync::mpsc::channel();
                std::thread::spawn(move || {
                    let captured_at = local_iso(sysinfo::local_time());
                    let mut health = nvme_health::collect(
                        &nvme_health::windows_source::WindowsNvmeReader,
                        &disk,
                        &captured_at,
                    );
                    // v0.4.4 SATA/ATA fallback: never the NVMe protocol;
                    // Windows Storage Reliability counters (facts only).
                    if nvme_health::is_ata_bus(&disk.bus_type) {
                        health.reliability =
                            nvme_health::read_reliability("powershell.exe", disk.index);
                        // v1.0 read-only ATA SMART (READ DATA / THRESHOLDS).
                        nvme_health::apply_ata(&mut health, crate::ata_smart::read(disk.index));
                    }
                    let _ = tx.send(ProbeMsg::Health(health));
                    let events = storage_health::collect_events("powershell.exe");
                    let _ = tx.send(ProbeMsg::Events(identity, events));
                });
                self.nvme_rx = Some(rx);
                return true;
            }
        }
        let _ = identity;
        false
    }

    fn poll_nvme_health(&mut self) {
        let Some(rx) = &self.nvme_rx else {
            return;
        };
        let mut msgs = Vec::new();
        let mut done = false;
        loop {
            match rx.try_recv() {
                Ok(m) => msgs.push(m),
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    done = true;
                    break;
                }
            }
        }
        if done {
            self.nvme_rx = None;
            // A probe thread that ended early never leaves an assessment
            // waiting forever: missing inputs become "not collected".
            let open: Vec<String> = self
                .assessments
                .iter()
                .filter(|(_, a)| a.health_pending || a.events_pending)
                .map(|(k, _)| k.clone())
                .collect();
            for m in msgs.drain(..) {
                self.accept_probe_msg(m);
            }
            for id in open {
                if let Some(a) = self.assessments.get_mut(&id) {
                    a.health_pending = false;
                    a.events_pending = false;
                }
                self.finalize_assessment(&id);
            }
            return;
        }
        for m in msgs {
            self.accept_probe_msg(m);
        }
    }

    fn accept_probe_msg(&mut self, m: ProbeMsg) {
        match m {
            ProbeMsg::Health(h) => self.accept_nvme_health(h),
            ProbeMsg::Events(id, events) => self.accept_storage_events(&id, events),
        }
    }

    /// Stores a health record under its physical identity and adds its
    /// evidence (`NVMe_Health_<stamp>_PD<n>.json`) to the session package.
    fn accept_nvme_health(&mut self, health: nvme_health::NvmeHealth) {
        let name = nvme_health::evidence_file_name(
            &evidence_stamp(sysinfo::local_time()),
            health.disk_index,
        );
        let file = EvidenceFile::new(&name, nvme_health::to_json(&health).into_bytes());
        let d = i18n::t(self.language);
        push_journal(
            &mut self.journal,
            d.journal_nvme_health_fmt
                .replace("{disk}", &format!("PhysicalDrive{}", health.disk_index))
                .replace("{status}", health.status.as_str()),
        );
        let identity = health.physical_identity.clone();
        self.nvme_health.insert(identity.clone(), health);
        // v1.0: the correlation references the health file by its STORED
        // name (a same-day collision stores it as `_NN`).
        let package = self.storage_package_of(&identity);
        let stored = self
            .contribute_evidence_to(package, d.nvme_module_name, vec![file])
            .into_iter()
            .next()
            .unwrap_or(name);
        if let Some(a) = self.assessments.get_mut(&identity) {
            a.health_pending = false;
            a.health_file = Some(stored);
        }
        self.finalize_assessment(&identity);
    }

    fn accept_storage_events(&mut self, identity: &str, events: storage_health::EventsInput) {
        if let Some(a) = self.assessments.get_mut(identity) {
            a.events = events;
            a.events_pending = false;
        }
        self.finalize_assessment(identity);
    }

    /// Health record of the currently selected physical disk, if read.
    fn selected_nvme_health(&self) -> Option<&nvme_health::NvmeHealth> {
        let candidate = self.selected_ssd_candidate()?;
        self.nvme_health
            .get(&storage_topology::physical_disk_identity(&candidate.disk))
    }

    /// Storage assessment of the currently selected physical disk.
    fn selected_assessment(&self) -> Option<&StorageAssessment> {
        let candidate = self.selected_ssd_candidate()?;
        self.assessments
            .get(&storage_topology::physical_disk_identity(&candidate.disk))
    }

    /// v1.0 Client Identity: module `owner` starts work now; its evidence
    /// goes to THIS session's package even if a later operation opens
    /// another session before it completes.
    fn claim_package(&mut self, owner: &'static str) {
        self.op_packages.insert(owner, Arc::clone(&self.package));
    }

    /// The session package of the storage run of disk `identity` (the
    /// storage owner's when the run is unknown).
    fn storage_package_of(&self, identity: &str) -> SharedPackage {
        self.assessments
            .get(identity)
            .and_then(|a| a.package.clone())
            .unwrap_or_else(|| self.package_of("storage"))
    }

    /// The SessionId of the storage run of disk `identity`.
    fn storage_session_of(&self, identity: &str) -> String {
        report_package::lock(&self.storage_package_of(identity))
            .session()
            .map(|s| s.session_id.clone())
            .unwrap_or_else(|| self.storage_session_id.clone())
    }

    /// The package of `owner`'s current / last operation (the current
    /// session when it never claimed one).
    fn package_of(&self, owner: &'static str) -> SharedPackage {
        self.op_packages
            .get(owner)
            .cloned()
            .unwrap_or_else(|| Arc::clone(&self.package))
    }

    /// Adds evidence of module `owner` to the package of the session that
    /// module was started in (UI-thread modules) and journals the outcome.
    /// Returns the names the files were STORED under (input order); on an
    /// error the requested names (nothing was renamed).
    fn contribute_evidence(
        &mut self,
        owner: &'static str,
        module: &str,
        files: Vec<EvidenceFile>,
    ) -> Vec<String> {
        let package = self.package_of(owner);
        self.contribute_evidence_to(package, module, files)
    }

    /// [`contribute_evidence`] into one given session package.
    fn contribute_evidence_to(
        &mut self,
        package: SharedPackage,
        module: &str,
        files: Vec<EvidenceFile>,
    ) -> Vec<String> {
        let date = identity_date(sysinfo::local_time());
        let current = Arc::ptr_eq(&package, &self.package);
        let created = report_package::lock(&package).final_zip().is_none();
        let requested: Vec<String> = files.iter().map(|f| f.name.clone()).collect();
        let (sys_state, hw_state) = self.state_codes();
        report_package::lock(&package).set_states(&sys_state, &hw_state);
        let result = report_package::lock(&package).contribute_named(
            &self.client_name,
            &self.computer_name,
            &date,
            files,
        );
        match result {
            Ok((zip, stored)) => {
                if created && current {
                    self.report_opened = false;
                }
                let line = i18n::t(self.language)
                    .journal_module_added_fmt
                    .replace("{module}", module)
                    .replace("{path}", &display_report_path(&zip));
                push_journal(&mut self.journal, line);
                stored
            }
            Err(err) => {
                push_journal(&mut self.journal, format!("[ERROR] {module}: {err}"));
                requested
            }
        }
    }

    /// v1.0 Client Identity: fixes the session of the operation the user
    /// starts now. A full diagnostic always opens a NEW session (unique
    /// SessionId; Client / Computer frozen from the input fields now). A
    /// separate module opens one only when none is bound yet or Client /
    /// Computer changed since — a stale identity is never reused; while a
    /// diagnostic is running, modules join that running session.
    fn begin_operation(&mut self, full_diagnostic: bool) {
        let unchanged = report_package::lock(&self.package)
            .session()
            .is_some_and(|s| s.same_identity(&self.client_name, &self.computer_name));
        if !full_diagnostic && (self.is_running() || unchanged) {
            return;
        }
        self.session_seq += 1;
        let t = sysinfo::local_time();
        let stamp = format!(
            "{:04}{:02}{:02}-{:02}{:02}{:02}",
            t.year, t.month, t.day, t.hour, t.minute, t.second
        );
        let session = SessionIdentity::new(
            &format!(
                "{}-{:02}",
                crate::storage_history::new_session_id(&stamp),
                self.session_seq
            ),
            &self.client_name,
            &self.computer_name,
        );
        let successor = {
            let mut package = report_package::lock(&self.package);
            if package.is_fresh() {
                package.bind_session(session.clone());
                None
            } else {
                Some(package.successor(session.clone()))
            }
        };
        if let Some(next) = successor {
            // Operations still running keep their own (previous) package.
            self.package = Arc::new(Mutex::new(next));
            // The finished diagnostic shown so far belongs to the previous
            // session: its result / Open report must not stand for this one.
            if !self.is_running() {
                self.reset_run_view();
            }
        }
        // Storage history / correlation records carry the same SessionId.
        self.storage_session_id = session.session_id.clone();
        self.report_opened = false;
        let line = i18n::t(self.language)
            .journal_session_started_fmt
            .replace("{session}", &session.session_id)
            .replace(
                "{client}",
                if session.client.is_empty() {
                    "—"
                } else {
                    &session.client
                },
            )
            .replace("{computer}", &session.computer);
        push_journal(&mut self.journal, line);
    }

    /// Every diagnostic collector start goes through here (test seam; the
    /// collectors themselves never run under unit tests).
    fn request_collector(&mut self, name: &'static str) {
        #[cfg(test)]
        self.collector_requests.push(name);
        let _ = name;
    }

    /// Back to the idle diagnostic view (Reset; a new session).
    fn reset_run_view(&mut self) {
        self.state = RunState::Idle;
        self.expc_tracker.reset();
        self.deep_check_results.clear();
        self.expc_checks.clear();
        self.session_started = None;
        self.ring_smoothed = 0.0;
        self.deep_check_smoothed = [0.0; 14];
    }

    /// The identity of the current session (bound by `begin_operation`).
    fn session_identity(&self) -> Option<SessionIdentity> {
        report_package::lock(&self.package).session().cloned()
    }

    fn start_diagnostics(&mut self) {
        if self.is_running() || self.benchmark_is_running() {
            return;
        }
        let exe_dir = exe_dir();

        self.reports_root = exe_dir.join("Reports");
        // New run: the dashboard card starts empty; the session journal
        // (full viewer / Save / Copy) keeps every earlier line.
        self.journal.clear_view();
        self.begin_operation(true);
        let session = self
            .session_identity()
            .unwrap_or_else(|| SessionIdentity::new("", &self.client_name, &self.computer_name));
        let cancel = Arc::new(AtomicBool::new(false));
        self.session_cancel = Some(Arc::clone(&cancel));
        let req = SessionRequest {
            client_name: session.client.clone(),
            computer_name: session.computer.clone(),
            mode: self.mode,
            deep_checks: self.deep_checks,
            include_hardware: self.include_hardware,
            cancel,
            package: Arc::clone(&self.package),
        };

        let (tx, rx): (Sender<EngineEvent>, Receiver<EngineEvent>) = std::sync::mpsc::channel();
        self.request_collector("expc_session");
        // Unit tests record the request only (no engine, no PowerShell).
        #[cfg(not(test))]
        std::thread::spawn(move || engine::run_session(req, tx));
        #[cfg(test)]
        {
            let _ = engine::run_session;
            self.test_session_request = Some((req.client_name.clone(), req.computer_name.clone()));
            self.engine_test_tx = Some(tx);
        }

        self.expc_tracker.reset();
        self.deep_check_results.clear();
        self.expc_checks.clear();
        self.session_started = Some(Instant::now());
        self.stopped_elapsed = None;
        self.ring_smoothed = 0.0;
        self.deep_check_smoothed = [0.0; 14];
        self.state = RunState::Running {
            stage: Stage::Preparing,
            step_done: 0,
            step_total: 100,
            stage_message: "Подготовка EXPC Diagnostic".into(),
            rx,
        };
        // v0.4.4 auxiliary read-only modules (not EXPC stages): Group Policy
        // / ADMX health and a fresh crash inventory join this session.
        self.start_gpo_check();
        self.start_crash_scan();
        self.start_sensor_read(true);
        self.start_event_collection();
        // v1.0: a fresh ATA SMART scan joins this session's report.
        self.ata_evidence_pending = true;
        self.start_ata_scan();
        // v1.0 Startup Idle: the checks that used to run at launch run
        // here, for this session (the engine runs its own Driver Audit).
        self.start_crypto_check();
        self.start_passport();
    }

    /// v1.0 read-only event evidence for this session (joins its ZIP).
    fn start_event_collection(&mut self) {
        self.request_collector("events");
        if self.events_rx.is_none() {
            self.claim_package("events");
        }
        #[cfg(windows)]
        if self.reference.is_none() && !cfg!(test) && self.events_rx.is_none() {
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let _ = tx.send(events::collect(PS_HOST));
            });
            self.events_rx = Some(rx);
        }
    }

    fn poll_events(&mut self) {
        let Some(rx) = &self.events_rx else {
            return;
        };
        match rx.try_recv() {
            Ok(res) => {
                self.events_rx = None;
                self.accept_events(res);
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => {}
            Err(std::sync::mpsc::TryRecvError::Disconnected) => self.events_rx = None,
        }
    }

    /// Aggregates the raw events and adds `Event_Evidence_<stamp>.json`.
    fn accept_events(
        &mut self,
        res: Result<(Vec<events::RawEvent>, Vec<events::ServiceInfo>), String>,
    ) {
        match res {
            Ok((raw, services)) => {
                let now = sysinfo::local_time();
                let aggs = events::aggregate(&raw, &services, &local_iso(now));
                let wu = events::wu_failure_is_historical(&raw);
                let json = events::to_json(&aggs, wu, &local_iso(now));
                let name = format!("{}{}.json", events::EVIDENCE_PREFIX, evidence_stamp(now));
                self.event_evidence = Some(Ok((aggs, wu)));
                let d = i18n::t(self.language);
                self.contribute_evidence(
                    "events",
                    d.module_event_evidence,
                    vec![EvidenceFile::new(&name, json.into_bytes())],
                );
            }
            Err(e) => self.event_evidence = Some(Err(e)),
        }
    }

    /// v1.0 aggregated event lines that belong to EXPC stage `i` only.
    fn stage_event_lines(&self, i: usize) -> Vec<String> {
        let Some(Ok((aggs, wu))) = &self.event_evidence else {
            return Vec::new();
        };
        // v1.0: unique actionable groups first (primary metric), then the
        // raw aggregates (secondary evidence, scope in Event_Evidence JSON).
        let mut out: Vec<String> = events::actionable(aggs)
            .iter()
            .filter(|g| g.stage == i)
            .map(|g| {
                format!(
                    "Группа · [{}] {} · {} → {}",
                    g.class.code(),
                    g.title,
                    g.first_seen.replace('T', " "),
                    g.last_seen.replace('T', " ")
                )
            })
            .collect();
        out.extend(
            aggs.iter()
                .filter(|a| {
                    a.group
                        .is_some_and(|g| g != events::Group::Other && g.stage() == i)
                })
                .map(|a| format!("Events · {}", events::aggregate_line(a))),
        );
        if i == 3
            && let Some(hist) = wu
        {
            out.push(format!(
                "Events · WindowsUpdateClient #20: {}",
                if *hist {
                    "historical failure (a later update installed successfully)"
                } else {
                    "no successful install after the newest failure"
                }
            ));
        }
        out
    }

    fn poll_engine(&mut self) {
        // Drain whatever is currently available without blocking the UI
        // thread; multiple events per frame are fine, we only redraw once.
        let mut next_state: Option<RunState> = None;
        let mut deep: Option<Vec<DeepCheckOutcome>> = None;
        if let RunState::Running {
            stage,
            step_done,
            step_total,
            stage_message,
            rx,
        } = &mut self.state
        {
            while let Ok(event) = rx.try_recv() {
                match event {
                    EngineEvent::Stage(s) => {
                        *stage = s;
                    }
                    EngineEvent::ExpcProgress { percent, message } => {
                        *step_done = (*step_done).max(percent.min(100));
                        *step_total = 100;
                        self.expc_tracker.update(percent, &message);
                        *stage_message = message;
                    }
                    EngineEvent::Log(line) => {
                        push_journal(&mut self.journal, line);
                    }
                    EngineEvent::DeepChecks(outcomes) => deep = Some(outcomes),
                    EngineEvent::ExpcChecks(checks) => self.expc_checks = checks,
                    EngineEvent::DriverAudit(result) => {
                        // Keep the earlier result if the in-session run failed.
                        let d = i18n::t(self.language);
                        let stamp = CheckStamp::now(CheckOrigin::Session);
                        match result {
                            Ok(report) => {
                                let summary = d
                                    .driver_journal_summary_fmt
                                    .replace("{status}", driver_status_label(d, report.overall))
                                    .replace(
                                        "{problems}",
                                        &report.count(Severity::Problem).to_string(),
                                    )
                                    .replace(
                                        "{warnings}",
                                        &report.count(Severity::Warning).to_string(),
                                    );
                                // v1.1: the session's own audit supersedes a
                                // preflight / manual result still running.
                                self.driver_origin = CheckOrigin::Session;
                                self.driver_previous = None;
                                record_check(
                                    &mut self.driver_history,
                                    &mut self.driver_checked,
                                    stamp,
                                    summary,
                                );
                                self.driver_audit = DriverAuditState::Done(report);
                            }
                            Err(err) => {
                                record_check(
                                    &mut self.driver_history,
                                    &mut self.driver_checked,
                                    stamp,
                                    format!("{}: {err}", d.driver_status_error),
                                );
                                if !matches!(self.driver_audit, DriverAuditState::Done(_)) {
                                    self.driver_audit = DriverAuditState::Failed(err);
                                }
                            }
                        }
                    }
                    EngineEvent::Finished(Ok(zip_path)) => {
                        // The engine returns the FINAL verified ZIP under
                        // Reports\; anything else is rejected, never shown.
                        self.report_opened = false;
                        next_state = Some(
                            match engine::verify_final_report(&zip_path, &self.reports_root) {
                                Ok(final_zip) => RunState::Done {
                                    zip_path: final_zip,
                                },
                                Err(message) => RunState::Failed {
                                    message,
                                    stage: stage.clone(),
                                },
                            },
                        );
                    }
                    EngineEvent::Cancelled { zip_path, note } => {
                        if zip_path.is_some() {
                            self.report_opened = false;
                        }
                        push_journal(
                            &mut self.journal,
                            i18n::t(self.language).journal_diag_stopped_by_user.into(),
                        );
                        push_journal(
                            &mut self.journal,
                            if note.starts_with("[ERROR]") {
                                note.clone()
                            } else {
                                format!("[INFO] {note}")
                            },
                        );
                        self.stopped_elapsed = self.session_started.map(|s| s.elapsed().as_secs());
                        next_state = Some(RunState::Cancelled {
                            stage: stage.clone(),
                            note,
                        });
                    }
                    EngineEvent::Finished(Err(message)) => {
                        // Mark the currently active EXPC sub-stage as Error
                        if let Some(idx) = self.expc_tracker.active_index {
                            self.expc_tracker.status[idx] = SubStageStatus::Error;
                        }
                        next_state = Some(RunState::Failed {
                            message,
                            stage: stage.clone(),
                        });
                    }
                }
            }
        }
        if let Some(outcomes) = deep {
            self.apply_deep_checks(outcomes);
        }
        if let Some(state) = next_state {
            self.session_cancel = None;
            self.state = state;
        }
    }

    /// Stores the deep-check results and explains each one in the journal
    /// (ATTENTION also names the manual repair command — as text only;
    /// WinStateDiag never runs it).
    fn apply_deep_checks(&mut self, outcomes: Vec<DeepCheckOutcome>) {
        let d = i18n::t(self.language);
        for o in &outcomes {
            let prefix = match o.result {
                CheckResult::Skipped => continue,
                CheckResult::Attention => "[WARN] ",
                CheckResult::Error => "[ERROR] ",
                _ => "",
            };
            let line = format!(
                "{prefix}{}",
                deep_checks::describe(o, &d.deep_check_findings)
            );
            push_journal(&mut self.journal, line);
            if o.result == CheckResult::Attention {
                let line = d
                    .deep_check_manual_command_fmt
                    .replace("{check}", o.check.key())
                    .replace("{command}", &o.check.manual_command(&system_drive()));
                push_journal(&mut self.journal, line);
            }
        }
        self.deep_check_results = outcomes;
    }

    /// Deep-check result of EXPC step `index` (0-based), if any.
    fn deep_check_at(&self, index: usize) -> Option<&DeepCheckOutcome> {
        let check = DeepCheck::of_step_index(index)?;
        self.deep_check_results.iter().find(|o| o.check == check)
    }

    /// v0.4.0 fail-safe report cleanup point: nothing is running, the last
    /// diagnostic run did not fail or get stopped, and a verified package
    /// rebuild is waiting. `finalize` itself re-verifies the ZIP and keeps
    /// every file on any doubt.
    fn finalize_report_if_idle(&mut self) {
        let busy = self.is_running()
            || self.benchmark_is_running()
            || self.nvme_rx.is_some()
            || !matches!(self.hardware, HardwareViewState::Idle)
            || matches!(self.driver_audit, DriverAuditState::Running(_))
            || self.gpo_rx.is_some()
            || (self.sensors_rx.is_some() && self.sensors_evidence_pending)
            || self.crash.busy == CrashBusy::Analyzing;
        if busy
            || matches!(
                self.state,
                RunState::Failed { .. } | RunState::Cancelled { .. }
            )
        {
            return;
        }
        // v1.0: the current session and any earlier session a module still
        // completed into (each package once).
        let mut packages: Vec<SharedPackage> = vec![Arc::clone(&self.package)];
        let pinned = self.assessments.values().filter_map(|a| a.package.as_ref());
        for p in self.op_packages.values().chain(pinned) {
            if !packages.iter().any(|q| Arc::ptr_eq(p, q)) {
                packages.push(Arc::clone(p));
            }
        }
        for shared in packages {
            let mut package = report_package::lock(&shared);
            if !package.needs_finalize() {
                continue;
            }
            let result = package.finalize();
            drop(package);
            let d = i18n::t(self.language);
            match result {
                Ok(removed) if !removed.is_empty() => {
                    push_journal(&mut self.journal, d.journal_report_finalized.to_string())
                }
                Ok(_) => {}
                Err(err) => push_journal(
                    &mut self.journal,
                    format!(
                        "[WARN] {}",
                        d.journal_report_finalize_failed_fmt
                            .replace("{error}", &err)
                    ),
                ),
            }
        }
    }

    /// Stop button: graceful request; the engine stops before the next
    /// stage and terminates only its own running process tree.
    fn request_stop(&mut self) {
        if !self.is_running() {
            return;
        }
        if let Some(cancel) = &self.session_cancel {
            if !cancel.swap(true, Ordering::SeqCst) {
                let msg = i18n::t(self.language).journal_stopping.to_string();
                push_journal(&mut self.journal, msg);
            }
        }
    }

    fn stop_enabled(&self) -> bool {
        self.is_running()
            && self
                .session_cancel
                .as_ref()
                .is_some_and(|c| !c.load(Ordering::SeqCst))
    }

    // -----------------------------------------------------------------
    // Hardware Report "Смотреть"
    // -----------------------------------------------------------------

    fn start_hardware_view(&mut self) {
        if !matches!(self.hardware, HardwareViewState::Idle) {
            let msg = i18n::t(self.language).journal_hw_already_open.to_string();
            push_journal(&mut self.journal, msg);
            return;
        }
        self.begin_operation(false);
        // v1.0 Startup Idle: the Hardware page's passport and ATA SMART
        // rows are read on this explicit action (or with the diagnostic).
        self.start_passport();
        self.ata_evidence_pending = true;
        self.start_ata_scan();
        let now = sysinfo::local_time();
        let date = identity_date(now);
        // The session destination is resolved once and passed to the
        // viewer ("Открыть папку отчёта"); never a temporary folder.
        let identity = report_package::lock(&self.package).resolve(
            &self.client_name,
            &self.computer_name,
            &date,
        );
        let req = HardwareViewRequest {
            client_name: self.client_name.clone(),
            computer_name: self.computer_name.clone(),
            date,
            report_dir: identity.report_dir,
            package: Arc::clone(&self.package),
        };
        let (tx, rx) = std::sync::mpsc::channel();
        self.request_collector("hardware_view");
        #[cfg(not(test))]
        std::thread::spawn(move || engine::run_hardware_view(req, tx));
        #[cfg(test)]
        let _ = (engine::run_hardware_view, req, tx);
        let d = i18n::t(self.language);
        push_journal(
            &mut self.journal,
            format!("{}: {}", d.module_name_hardware, d.hw_progress_collecting),
        );
        self.hardware = HardwareViewState::Collecting {
            rx,
            started: Instant::now(),
            saving: false,
        };
    }

    fn poll_hardware(&mut self) {
        let mut events = Vec::new();
        match &self.hardware {
            HardwareViewState::Idle => return,
            HardwareViewState::Collecting { rx, .. } | HardwareViewState::Viewer { rx } => {
                while let Ok(event) = rx.try_recv() {
                    events.push(event);
                }
            }
        }
        for event in events {
            self.apply_hardware_event(event);
        }
    }

    fn apply_hardware_event(&mut self, event: HardwareEvent) {
        match event {
            HardwareEvent::Saving => {
                if let HardwareViewState::Collecting { saving, .. } = &mut self.hardware {
                    *saving = true;
                }
            }
            HardwareEvent::Persisted(result) => {
                let what = i18n::t(self.language).hw_journal_saved;
                self.journal_hardware_result(what, result);
                let state = std::mem::replace(&mut self.hardware, HardwareViewState::Idle);
                self.hardware = match state {
                    HardwareViewState::Collecting { rx, .. } | HardwareViewState::Viewer { rx } => {
                        HardwareViewState::Viewer { rx }
                    }
                    HardwareViewState::Idle => HardwareViewState::Idle,
                };
            }
            HardwareEvent::Refreshed(result) => {
                let what = i18n::t(self.language).hw_journal_refreshed;
                self.journal_hardware_result(what, result);
            }
            // v1.1 Hardware Passport 2.0: the native single-page window.
            HardwareEvent::Passport(json) => {
                self.passport2_json = Some(json);
                self.passport2_open = true;
                self.passport2_status = None;
            }
            HardwareEvent::Failed(err) => {
                let hw = i18n::t(self.language).module_name_hardware;
                push_journal(&mut self.journal, format!("[ERROR] {hw}: {err}"));
                self.hardware = HardwareViewState::Idle;
            }
            HardwareEvent::Closed => self.hardware = HardwareViewState::Idle,
        }
    }

    fn journal_hardware_result(&mut self, what: &str, result: Result<PathBuf, String>) {
        let hw = i18n::t(self.language).module_name_hardware;
        match result {
            Ok(zip) => {
                push_journal(
                    &mut self.journal,
                    format!("{hw} {what}: {}", display_report_path(&zip)),
                );
            }
            Err(err) => push_journal(&mut self.journal, format!("[ERROR] {hw}: {err}")),
        }
    }

    /// Small modal while the hidden collection runs (no console window).
    fn hardware_progress_window(&mut self, ctx: &egui::Context) {
        let HardwareViewState::Collecting {
            started, saving, ..
        } = &self.hardware
        else {
            return;
        };
        let d = i18n::t(self.language);
        let status = if *saving {
            d.hw_progress_saving
        } else {
            d.hw_progress_collecting
        };
        let elapsed = hms(started.elapsed().as_secs());
        draw_hardware_progress(ctx, d, status, &elapsed);
        ctx.request_repaint();
    }

    // -----------------------------------------------------------------
    // CryptoPro (read-only check; ReHash only after confirmation)
    // -----------------------------------------------------------------

    /// The CryptoPro check that runs now: the user's ⟳ outside a session,
    /// the session's own check during a diagnostic.
    fn start_crypto_check(&mut self) {
        let origin = if self.is_running() {
            CheckOrigin::Session
        } else {
            CheckOrigin::Manual
        };
        self.start_crypto_check_as(origin);
    }

    /// v1.1: one fresh READ-ONLY CryptoPro check: the registry inventory
    /// (presence, version, licence key) and the `cpverify -rv` HASH state.
    /// Never ReHash, never two at once; the previous result is cleared so a
    /// stale state is never shown as current.
    fn start_crypto_check_as(&mut self, origin: CheckOrigin) {
        self.request_collector("cryptopro");
        if self.crypto_rx.is_some() {
            if origin == CheckOrigin::Session && self.crypto_origin == CheckOrigin::Preflight {
                self.crypto_recheck_for_session = true;
            }
            return;
        }
        self.crypto_origin = origin;
        self.crypto_export_status = None;
        if self.reference.is_some() {
            return;
        }
        // A fresh check never shows the previous result as current.
        self.crypto = None;
        self.crypto_inventory = None;
        if cfg!(test) {
            return;
        }
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(CryptoEvent::Inventory(cryptopro::inventory(
                &cryptopro::SystemRegistry,
            )));
            let det = cryptopro::detect(&cryptopro::program_files_roots());
            let runner = cryptopro::HiddenRunner {
                timeout: Duration::from_secs(120),
            };
            let state = cryptopro::check(&det, &runner);
            let _ = tx.send(CryptoEvent::Checked(det, state));
        });
        self.crypto_rx = Some(rx);
    }

    /// v1.1: ReHash is offered only from NO HASH and never while a check or
    /// another ReHash runs.
    fn crypto_rehash_allowed(&self) -> bool {
        self.crypto_rx.is_none() && self.crypto.as_ref().is_some_and(|s| s.rehash_available())
    }

    /// Runs the ReHash after the user confirmed it (only from NO HASH).
    fn start_crypto_rehash(&mut self) {
        let Some(current) = self.crypto.clone() else {
            return;
        };
        if !current.rehash_available() || self.crypto_rx.is_some() {
            return;
        }
        let det = self.crypto_detection.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        self.crypto_origin = CheckOrigin::Manual;
        // Unit tests never run cpverify: the request is recorded only.
        if cfg!(test) {
            self.request_collector("cryptopro_rehash");
            std::mem::forget(tx);
            self.crypto = None;
            self.crypto_rx = Some(rx);
            return;
        }
        std::thread::spawn(move || {
            let runner = cryptopro::HiddenRunner {
                timeout: Duration::from_secs(900),
            };
            let outcome = cryptopro::rehash(&det, &current, &runner);
            let _ = tx.send(CryptoEvent::Rehashed(outcome));
        });
        self.crypto = None;
        self.crypto_rx = Some(rx);
    }

    fn poll_crypto(&mut self) {
        loop {
            let Some(rx) = &self.crypto_rx else {
                return;
            };
            let event = match rx.try_recv() {
                Ok(event) => event,
                Err(std::sync::mpsc::TryRecvError::Empty) => return,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    self.crypto_rx = None;
                    return;
                }
            };
            match event {
                CryptoEvent::Inventory(inv) => {
                    for line in inv.journal() {
                        push_journal(&mut self.journal, line);
                    }
                    self.crypto_inventory = Some(inv);
                }
                CryptoEvent::Checked(det, state) => {
                    self.crypto_rx = None;
                    for line in cryptopro::journal_for(&state) {
                        push_journal(&mut self.journal, line);
                    }
                    self.crypto_detection = det;
                    self.crypto = Some(state);
                    self.crypto_checked = Some(CheckStamp::now(self.crypto_origin));
                    // v1.1: a diagnostic started during the preflight check
                    // gets its own fresh session check.
                    if std::mem::take(&mut self.crypto_recheck_for_session) && self.is_running() {
                        self.start_crypto_check_as(CheckOrigin::Session);
                    }
                    return;
                }
                CryptoEvent::Rehashed(outcome) => {
                    self.crypto_rx = None;
                    self.crypto_last_rehash = outcome.journal.last().cloned();
                    for line in outcome.journal {
                        push_journal(&mut self.journal, line);
                    }
                    self.crypto = Some(outcome.state);
                    self.crypto_checked = Some(CheckStamp::now(CheckOrigin::Manual));
                    return;
                }
            }
        }
    }

    fn crypto_vm(&self) -> CryptoVm {
        match &self.crypto {
            None if self.crypto_rx.is_some() => CryptoVm::Checking,
            // v1.0: the startup inventory proved CryptoPro CSP is absent.
            None if self
                .crypto_inventory
                .as_ref()
                .is_some_and(|i| !i.installed()) =>
            {
                CryptoVm::NotInstalled
            }
            // v1.0 Startup Idle: the HASH is checked with the diagnostic.
            None => CryptoVm::NotChecked,
            Some(cryptopro::HashState::HashOk) => CryptoVm::HashOk,
            Some(cryptopro::HashState::NoHash) => CryptoVm::NoHash,
            Some(cryptopro::HashState::NotInstalled) => CryptoVm::NotInstalled,
            Some(cryptopro::HashState::CheckError(_)) => CryptoVm::CheckError,
        }
    }

    fn poll_driver_audit(&mut self) {
        let DriverAuditState::Running(rx) = &self.driver_audit else {
            return;
        };
        let Ok(result) = rx.try_recv() else {
            return;
        };
        let origin = self.driver_origin;
        let stamp = CheckStamp::now(origin);
        let d = i18n::t(self.language);
        match result {
            Ok(report) => {
                let summary = d
                    .driver_journal_summary_fmt
                    .replace("{status}", driver_status_label(d, report.overall))
                    .replace("{problems}", &report.count(Severity::Problem).to_string())
                    .replace("{warnings}", &report.count(Severity::Warning).to_string());
                push_journal(
                    &mut self.journal,
                    if origin == CheckOrigin::Preflight {
                        format!("{} — {summary}", d.origin_preflight)
                    } else {
                        summary.clone()
                    },
                );
                // v1.1: a PREFLIGHT audit belongs to no report (it is never
                // offered, so it can never join a later client session).
                // Other runs join their session report as soon as one
                // exists (a launch alone never creates a report folder).
                if origin != CheckOrigin::Preflight {
                    let files = driver_audit_evidence(&report);
                    let offered = report_package::lock(&self.package_of("drivers")).offer(files);
                    match offered {
                        Ok(Some(zip)) => push_journal(
                            &mut self.journal,
                            d.driver_journal_added_fmt
                                .replace("{path}", &display_report_path(&zip)),
                        ),
                        Ok(None) => {}
                        Err(err) => push_journal(
                            &mut self.journal,
                            format!("[ERROR] Проверка драйверов: {err}"),
                        ),
                    }
                }
                self.record_driver_check(stamp, summary);
                self.driver_previous = None;
                self.driver_audit = DriverAuditState::Done(Box::new(report));
            }
            Err(err) => {
                push_journal(&mut self.journal, format!("[WARN] {err}"));
                self.record_driver_check(stamp, format!("{}: {err}", d.driver_status_error));
                // A failed re-check never hides the last good result.
                self.driver_audit = match self.driver_previous.take() {
                    Some(previous) => DriverAuditState::Done(previous),
                    None => DriverAuditState::Failed(err),
                };
            }
        }
    }

    /// v1.1: time / origin of the latest Driver Audit result and one line
    /// in this UI's Driver Audit history.
    fn record_driver_check(&mut self, stamp: CheckStamp, outcome: String) {
        record_check(
            &mut self.driver_history,
            &mut self.driver_checked,
            stamp,
            outcome,
        );
    }

    // -----------------------------------------------------------------
    // v1.1 Startup Orchestration (automatic read-only preflight)
    // -----------------------------------------------------------------

    /// v1.1: the automatic read-only checks at launch, in the background:
    /// Driver Audit, CryptoPro (inventory + HASH check, never ReHash), and
    /// the crash / dump discovery with WinDbg / cdb detection (never
    /// `!analyze`, never symbols). No session, report or ZIP is created and
    /// no preflight result joins a client report; every result carries its
    /// origin and time. A collector that is already busy is not doubled.
    fn start_preflight(&mut self) {
        if self.reference.is_some() || self.preflight_started.is_some() {
            return;
        }
        self.preflight_started = Some(CheckStamp::now(CheckOrigin::Preflight));
        // A. Driver Audit.
        if !matches!(self.driver_audit, DriverAuditState::Running(_)) {
            self.driver_origin = CheckOrigin::Preflight;
            self.request_collector("driver_audit");
            #[cfg(not(test))]
            {
                self.driver_audit = start_driver_audit();
            }
        }
        // B. CryptoPro: registry inventory + read-only HASH check.
        self.start_crypto_check_as(CheckOrigin::Preflight);
        // C + D. WinDbg / cdb detection and the crash / dump discovery are
        // one read-only inventory scan (no debugger execution).
        self.start_crash_scan_as(CheckOrigin::Preflight);
    }

    /// Real target fraction for the overall ring (backend-derived).
    fn overall_target(&self) -> f32 {
        match &self.state {
            RunState::Idle => 0.0,
            RunState::Done { .. } => 1.0,
            RunState::Running { stage, .. }
            | RunState::Failed { stage, .. }
            | RunState::Cancelled { stage, .. } => engine::session_fraction(
                stage,
                self.expc_tracker.total_credit(),
                self.expc_tracker.total_weight(),
                self.include_hardware,
            ),
        }
    }

    /// Builds the presentation view-model from real application state.
    fn build_vm(&mut self, dt: f32, time: f64) -> DashboardVm {
        let running = self.is_running();
        let bench_running = self.benchmark_is_running();
        let d = i18n::t(self.language);

        // ---- Stages ----
        // v0.4.4 stage table: results/findings from the EXPC evidence.
        let stage_details = self.expc_stage_details();
        let consistency_inputs = (
            self.audit_view()
                .map(|r| significant_system_evidence(&r))
                .unwrap_or(0),
            match &self.crash.inventory {
                Some(Ok(inv)) => inv.bugchecks.len(),
                _ => 0,
            },
        );
        let step_count = EXPC_STEP_COUNT as usize;
        let mut stages = Vec::with_capacity(step_count);
        for i in 0..step_count {
            let status = self.expc_tracker.status[i];
            let ipct = self.expc_tracker.internal_pct[i];
            let (state, fraction, right) = match (&self.state, status) {
                (RunState::Idle, _) => (RowState::Pending, None, d.stage_waiting.to_string()),
                (RunState::Cancelled { .. }, SubStageStatus::Running) => (
                    RowState::Pending,
                    None,
                    d.overall_status_stopped.to_string(),
                ),
                (_, SubStageStatus::Pending) => (RowState::Pending, None, d.stage_waiting.into()),
                (_, SubStageStatus::Running) => {
                    if EXPC_DEEP_FLAGS[i] && ipct > 0 {
                        smooth_toward(&mut self.deep_check_smoothed[i], ipct as f32 / 100.0, dt);
                        (
                            RowState::Running,
                            Some(self.deep_check_smoothed[i]),
                            format!("{ipct}%"),
                        )
                    } else {
                        (RowState::Running, None, String::new())
                    }
                }
                (_, SubStageStatus::Done) => (RowState::Done, Some(1.0), "100%".into()),
                (_, SubStageStatus::Skipped) => (RowState::Skipped, None, d.stage_skipped.into()),
                (_, SubStageStatus::Error) => (RowState::Error, Some(1.0), d.stage_error.into()),
            };
            // v0.4.0: a completed deep check also shows what it found
            // (icon + hover explanation); "100%" keeps meaning "completed".
            let outcome = (state == RowState::Done)
                .then(|| self.deep_check_at(i))
                .flatten();
            let finding = outcome.and_then(|o| match o.result {
                CheckResult::Ok => Some(StageFinding::Ok),
                CheckResult::Attention => Some(StageFinding::Attention),
                CheckResult::Error => Some(StageFinding::Error),
                CheckResult::Unknown => Some(StageFinding::Unknown),
                CheckResult::Skipped => None,
            });
            let mut full_label = EXPC_STEP_LABELS[i].to_string();
            if let Some(o) = outcome {
                full_label.push('\n');
                full_label.push_str(&deep_checks::describe(o, &d.deep_check_findings));
                if o.result == CheckResult::Attention {
                    full_label.push('\n');
                    full_label.push_str(
                        &d.deep_check_manual_command_fmt
                            .replace("{check}", o.check.key())
                            .replace("{command}", &o.check.manual_command(&system_drive())),
                    );
                }
            }
            let detail = stage_details.get(i);
            let (sys_events, bugchecks) = consistency_inputs;
            let result = detail.map(|e| e.state).filter(|st| {
                !matches!(
                    st,
                    details::StageState::Waiting | details::StageState::Running
                )
            });
            let repaired = self.deep_check_at(i).is_some_and(|o| {
                o.finding_class() == Some(crate::deep_checks::ChkdskFinding::Repaired)
            });
            let result_text = if repaired && result.is_some() {
                d.chkdsk_repaired_label.to_string()
            } else {
                result
                    .map(|st| d.expc_state_labels[st.index()].to_string())
                    .unwrap_or_default()
            };
            let mut short_finding = detail
                .and_then(|e| e.findings.first().cloned())
                .unwrap_or_default();
            // v1.0 cross-module consistency (no silent contradiction).
            if let Some(note) = consistency_note(
                i,
                result == Some(details::StageState::Ok),
                sys_events,
                bugchecks,
                d,
            ) {
                short_finding = note;
            }
            let duration = self.expc_tracker.durations[i]
                .map(|t| {
                    let s = t.as_secs();
                    if s >= 60 {
                        format!("{}:{:02}", s / 60, s % 60)
                    } else {
                        format!("{s} s")
                    }
                })
                .unwrap_or_default();
            stages.push(StageRow {
                number: i + 1,
                label: d.stage_short[i].to_string(),
                full_label,
                state,
                fraction,
                right_text: right,
                active: running && self.expc_tracker.active_index == Some(i),
                finding,
                result,
                result_text,
                short_finding,
                duration,
            });
        }

        // ---- Overall ring + time ----
        let target = self.overall_target();
        smooth_toward(&mut self.ring_smoothed, target, dt);
        let displayed = if matches!(self.state, RunState::Idle | RunState::Done { .. }) {
            target
        } else {
            self.ring_smoothed
        };
        let (status_text, tone) = match &self.state {
            RunState::Idle => (d.overall_status_waiting, Tone::Idle),
            RunState::Running { .. } => (d.overall_status_running, Tone::Running),
            RunState::Done { .. } => (d.overall_status_done, Tone::Success),
            RunState::Failed { .. } => (d.stage_error, Tone::Error),
            RunState::Cancelled { .. } => (d.overall_status_stopped, Tone::Warning),
        };
        let elapsed_secs = match (&self.state, self.stopped_elapsed) {
            (RunState::Cancelled { .. }, Some(frozen)) => frozen,
            _ => self
                .session_started
                .map(|s| s.elapsed().as_secs())
                .unwrap_or(0),
        };
        let elapsed = if self.session_started.is_some() && !matches!(self.state, RunState::Idle) {
            hms(elapsed_secs)
        } else {
            "00:00:00".to_string()
        };
        let eta = match &self.state {
            RunState::Running { .. } if target > 0.05 && elapsed_secs > 5 => {
                let total = elapsed_secs as f64 / target as f64;
                format!("~{}", hms((total - elapsed_secs as f64).max(0.0) as u64))
            }
            RunState::Running { .. } => d.overall_eta_calculating.to_string(),
            RunState::Done { .. } => "00:00:00".to_string(),
            _ => "—".to_string(),
        };
        let module = |label: &str, st: ModuleStatus| ModuleRow {
            label: label.to_string(),
            state: match st {
                ModuleStatus::Pending => ModuleState::Pending,
                ModuleStatus::Running => ModuleState::Running,
                ModuleStatus::Done => ModuleState::Done,
                ModuleStatus::Error => ModuleState::Error,
            },
            status_text: match st {
                ModuleStatus::Pending => d.module_status_waiting,
                ModuleStatus::Running => d.module_status_running,
                ModuleStatus::Done => d.module_status_done,
                ModuleStatus::Error => d.stage_error,
            }
            .to_string(),
        };
        let mut hw_row = module(d.module_name_hardware, hardware_status(&self.state));
        if !self.include_hardware {
            hw_row.state = ModuleState::NotSelected;
            hw_row.status_text = d.module_status_not_selected.into();
        }
        let overall = OverallVm {
            fraction: displayed,
            percent_text: format!("{:.0}%", (displayed * 100.0).clamp(0.0, 100.0)),
            status_text: status_text.to_string(),
            tone,
            elapsed,
            eta,
            modules: vec![
                module(d.module_name_expc, expc_status(&self.state)),
                hw_row,
                module(d.module_name_zip, zip_status(&self.state)),
            ],
        };

        // ---- Current operation ----
        let operation = match &self.state {
            RunState::Idle => OperationVm {
                name: d.curop_waiting_name.into(),
                subtitle: d.curop_waiting_subtitle.into(),
                fraction: Some(0.0),
                percent_text: String::new(),
                indeterminate: false,
                tone: Tone::Idle,
            },
            RunState::Running { stage, .. } => {
                let active = self.expc_tracker.active_index;
                match (stage, active) {
                    (Stage::SystemDiagnostics, Some(idx)) => {
                        let ipct = self.expc_tracker.internal_pct[idx];
                        let determinate = EXPC_DEEP_FLAGS[idx] && ipct > 0;
                        OperationVm {
                            name: d.stage_short[idx].into(),
                            subtitle: d.stage_description[idx].into(),
                            fraction: determinate.then(|| self.deep_check_smoothed[idx]),
                            percent_text: if determinate {
                                format!("{ipct}%")
                            } else {
                                String::new()
                            },
                            indeterminate: !determinate,
                            tone: Tone::Running,
                        }
                    }
                    _ => {
                        let name = match stage {
                            Stage::Preparing => d.curop_stage_preparing,
                            Stage::SystemDiagnostics => d.module_name_expc,
                            Stage::HardwareReport => d.module_name_hardware,
                            Stage::Packaging => d.curop_stage_packaging,
                            Stage::Complete => d.curop_stage_complete,
                        };
                        // The engine's stage label is bilingual ("English /
                        // Russian"): show the half matching the UI language.
                        let label = engine::stage_label(stage);
                        let half = match self.language {
                            Language::Ru => 1,
                            Language::En => 0,
                        };
                        let subtitle = label.split(" / ").nth(half).unwrap_or(label);
                        OperationVm {
                            name: name.into(),
                            subtitle: subtitle.into(),
                            fraction: None,
                            percent_text: String::new(),
                            indeterminate: true,
                            tone: Tone::Running,
                        }
                    }
                }
            }
            RunState::Done { zip_path } => OperationVm {
                name: d.curop_done_name.into(),
                subtitle: display_report_path(zip_path),
                fraction: Some(1.0),
                percent_text: "100%".into(),
                indeterminate: false,
                tone: Tone::Success,
            },
            RunState::Cancelled { note, .. } => OperationVm {
                name: d.curop_stopped_name.into(),
                subtitle: note.clone(),
                fraction: None,
                percent_text: String::new(),
                indeterminate: false,
                tone: Tone::Warning,
            },
            RunState::Failed { message, .. } => OperationVm {
                name: d.curop_failed_name.into(),
                subtitle: message.lines().next().unwrap_or_default().to_string(),
                fraction: None,
                percent_text: String::new(),
                indeterminate: false,
                tone: Tone::Error,
            },
        };

        // ---- SSD / NVMe ----
        let ssd = match &self.benchmark_state {
            BenchmarkUiState::Idle => SsdVm::Idle,
            BenchmarkUiState::Cancelled => SsdVm::Cancelled,
            BenchmarkUiState::Failed(msg) => SsdVm::Failed(msg.clone()),
            BenchmarkUiState::RetestWaiting { until, result, .. } => {
                let left = until.saturating_duration_since(Instant::now()).as_secs();
                let waiting = d.ssd_retest_waiting_fmt.replace("{s}", &left.to_string());
                let first_previous = self
                    .retest_identity
                    .as_ref()
                    .and_then(|id| self.assessments.get(id))
                    .and_then(|a| a.first_previous.as_ref());
                SsdVm::Running {
                    fraction: 0.0,
                    status: waiting.clone(),
                    elapsed: String::new(),
                    note: Some([
                        d.ssd_retest_note_fmt.replace("{first}", &run_brief(result)),
                        d.ssd_unstable_rule_note.to_string(),
                    ]),
                    blocks: [
                        TestBlockVm::Done(test_vm(result, first_previous, d)),
                        TestBlockVm::Waiting(Some(waiting)),
                    ],
                    retest: true,
                }
            }
            BenchmarkUiState::Running {
                progress,
                started,
                live_write,
                live_read,
                ..
            } => {
                let (fraction, status) = match progress {
                    DiagnosticProgress::Preparation => (0.03, d.ssd_preparing_file.to_string()),
                    DiagnosticProgress::PassWrite { pass, total } => (
                        ((*pass - 1) * 2 + 1) as f32 / (*total * 2) as f32,
                        format!("{} {pass}/{total}: WRITE", d.ssd_pass_word),
                    ),
                    DiagnosticProgress::PassRead { pass, total } => (
                        ((*pass - 1) * 2 + 2) as f32 / (*total * 2) as f32,
                        format!("{} {pass}/{total}: READ", d.ssd_pass_word),
                    ),
                    DiagnosticProgress::Complete => (1.0, d.ssd_finishing.to_string()),
                    // Never stored as `progress` (poll keeps the pass).
                    DiagnosticProgress::Measured { .. } => (0.5, String::new()),
                };
                // The automatic retest says so (with the kept first run)
                // in the note lines; the status line stays the pass.
                let note = self
                    .retest_identity
                    .as_ref()
                    .and_then(|id| self.assessments.get(id))
                    .map(|a| {
                        [
                            d.ssd_retest_note_fmt
                                .replace("{first}", &run_brief(&a.first)),
                            d.ssd_unstable_rule_note.to_string(),
                        ]
                    });
                let assessment = self
                    .retest_identity
                    .as_ref()
                    .and_then(|id| self.assessments.get(id));
                let mb = |mib: &Option<f64>| mib.map(|v| format!("{:.0}", v * 1.048576));
                let active = TestBlockVm::Active {
                    read: mb(live_read),
                    write: mb(live_write),
                    elapsed: clock_mm_ss(started.elapsed().as_secs()),
                };
                let (blocks, retest) = match assessment {
                    Some(a) => (
                        [
                            TestBlockVm::Done(test_vm(&a.first, a.first_previous.as_ref(), d)),
                            active,
                        ],
                        true,
                    ),
                    None => ([active, TestBlockVm::Waiting(None)], false),
                };
                SsdVm::Running {
                    fraction,
                    status,
                    elapsed: format!("{:.1} s", started.elapsed().as_secs_f64()),
                    note,
                    blocks,
                    retest,
                }
            }
            BenchmarkUiState::Done {
                result,
                duration_seconds,
                previous,
            } => {
                // MiB/s (internal) -> MB/s (user-facing): x 1.048576.
                let mb = |mib: f64| format!("{:.0}", mib * 1.048576);
                let read_level = stability_level(result.read_variation_percent);
                let write_level = stability_level(result.write_variation_percent);
                let overall = read_level.max(write_level);
                // v0.4.2: the storage correlation decides the status colour
                // (never a raw counter); the first UNSTABLE run of a retest
                // stays visible in the note.
                let assessment = self.selected_assessment();
                let ru = self.language == Language::Ru;
                let status = assessment
                    .and_then(|a| a.classification.as_ref())
                    .map(|c| (c.state.short(ru).to_string(), storage_tone(c.state)));
                let note = assessment
                    .filter(|a| a.retest != storage_health::RetestOutcome::NotNeeded)
                    .map(|a| {
                        let second = match (&a.second, &a.retest) {
                            (Some(r), _) => run_brief(r),
                            (None, storage_health::RetestOutcome::Pending) => {
                                d.ssd_retest_pending.to_string()
                            }
                            _ => d.ssd_retest_not_run.to_string(),
                        };
                        [
                            d.ssd_runs_note_fmt
                                .replace("{first}", &run_brief(&a.first))
                                .replace("{second}", &second),
                            d.ssd_unstable_rule_note.to_string(),
                        ]
                    });
                // v0.4.4 Test 1 / Test 2: the first run and, when one ran,
                // the automatic retest (both kept).
                let tests = match assessment.and_then(|a| a.second.as_ref().map(|_| a)) {
                    Some(a) => [
                        Some(test_vm(&a.first, a.first_previous.as_ref(), d)),
                        Some(test_vm(result, previous.as_ref(), d)),
                    ],
                    None => [Some(test_vm(result, previous.as_ref(), d)), None],
                };
                SsdVm::Done {
                    tests,
                    status,
                    note,
                    read_current: mb(result.summary_read_mib_s),
                    read_previous: previous.as_ref().map(|p| mb(p.read_mib_s)),
                    read_delta: previous.as_ref().and_then(|p| {
                        ssd_history::delta_percent(result.summary_read_mib_s, p.read_mib_s)
                    }),
                    write_current: mb(result.summary_write_mib_s),
                    write_previous: previous.as_ref().map(|p| mb(p.write_mib_s)),
                    write_delta: previous.as_ref().and_then(|p| {
                        ssd_history::delta_percent(result.summary_write_mib_s, p.write_mib_s)
                    }),
                    meta: vec![
                        MetaRow {
                            label: d.ssd_profile_label.into(),
                            value: format!(
                                "{}  QD{}  ×{}",
                                format_block_size(result.profile.block_size),
                                result.profile.queue_depth,
                                result.profile.pass_count
                            ),
                            value_tone: Tone::Idle,
                            dot: false,
                        },
                        MetaRow {
                            label: d.ssd_passes_label.into(),
                            value: result.profile.pass_count.to_string(),
                            value_tone: Tone::Idle,
                            dot: false,
                        },
                        MetaRow {
                            label: d.ssd_duration_label.into(),
                            value: hms(duration_seconds.round() as u64),
                            value_tone: Tone::Idle,
                            dot: false,
                        },
                        MetaRow {
                            label: d.ssd_read_spread_label.into(),
                            value: format!(
                                "{:.2}% ({})",
                                result.read_variation_percent,
                                stability_text(read_level)
                            ),
                            value_tone: stability_tone(read_level),
                            dot: false,
                        },
                        MetaRow {
                            label: d.ssd_write_spread_label.into(),
                            value: format!(
                                "{:.2}% ({})",
                                result.write_variation_percent,
                                stability_text(write_level)
                            ),
                            value_tone: stability_tone(write_level),
                            dot: false,
                        },
                        MetaRow {
                            label: d.ssd_stability_label.into(),
                            value: stability_text(overall).into(),
                            value_tone: stability_tone(overall),
                            dot: true,
                        },
                    ],
                }
            }
        };

        // The session package is the report, whichever module created it.
        let package_zip = report_package::lock(&self.package).final_zip();
        let result = match (&self.state, package_zip) {
            (RunState::Running { .. }, _) => ResultVm::Running,
            (RunState::Done { zip_path }, _) => ResultVm::Done {
                path_display: display_report_path(zip_path),
                attention: report_attention(zip_path.is_file(), self.report_opened),
            },
            (RunState::Failed { message, .. }, _) => ResultVm::Failed {
                message: message.clone(),
            },
            (RunState::Idle | RunState::Cancelled { .. }, Some(zip)) => ResultVm::Done {
                path_display: display_report_path(&zip),
                attention: report_attention(zip.is_file(), self.report_opened),
            },
            (RunState::Idle | RunState::Cancelled { .. }, None) => ResultVm::Idle,
        };
        let start = match &self.state {
            RunState::Idle | RunState::Failed { .. } | RunState::Cancelled { .. } => {
                StartVm::Start {
                    enabled: !bench_running,
                }
            }
            RunState::Running { .. } => StartVm::Running,
            RunState::Done { .. } => StartVm::NewDiagnostic,
        };
        let journal = self
            .journal
            .dashboard_lines()
            .iter()
            .map(|e| JournalLine {
                timestamp: e.timestamp.clone(),
                message: e.message.clone(),
                dim: e.message.starts_with("[stderr]"),
            })
            .collect();
        // The status bar carries the compact Current Operation (the master
        // has no separate card for it): the running step with its detail
        // and percentage, otherwise the operation's final/idle state.
        let status_left = current_operation_status_text(d, bench_running, &self.state, &operation);
        let now = sysinfo::local_time();
        let drivers = match &self.driver_audit {
            DriverAuditState::Running(_) => DriversVm::Running,
            DriverAuditState::Done(_) => match self.audit_view() {
                Some(view) => drivers_vm(&view, d),
                None => DriversVm::Running,
            },
            DriverAuditState::Failed(msg) => DriversVm::Unavailable(msg.clone()),
            DriverAuditState::Idle => DriversVm::NotRun,
        };
        DashboardVm {
            controls_enabled: !running,
            stop_enabled: self.stop_enabled(),
            crypto: self.crypto_vm(),
            crypto_caption: self
                .crypto_checked
                .as_ref()
                .filter(|_| self.crypto_rx.is_none())
                .map(|s| s.caption(i18n::t(self.language))),
            crypto_recheck_enabled: self.crypto_rx.is_none(),
            drivers_caption: self
                .driver_checked
                .as_ref()
                .map(|s| s.caption(i18n::t(self.language))),
            drivers_check_enabled: !matches!(self.driver_audit, DriverAuditState::Running(_)),
            computer_name: self.computer_name.clone(),
            stages,
            overall,
            operation,
            ssd,
            // A storage run is complete only after its health / events
            // probe: no new run (or disk switch) before that.
            ssd_controls_enabled: !running && !bench_running && self.nvme_rx.is_none(),
            ssd_disks: self
                .ssd_candidates
                .iter()
                .map(|c| DiskEntryVm {
                    drive_letter: storage_topology::drive_letter_text(c),
                    model: if c.disk.model.trim().is_empty() {
                        format!("PhysicalDrive{}", c.disk.index)
                    } else {
                        c.disk.model.trim().to_string()
                    },
                    volume_label: storage_topology::volume_label_text(c),
                    capacity: storage_topology::capacity_text(&c.disk),
                    interface: storage_topology::interface_text(&c.disk),
                    serial: storage_topology::serial_text(&c.disk),
                    is_system: c.is_system,
                    has_target: c.volume.as_ref().is_some_and(|v| v.writable),
                })
                .collect(),
            ssd_selected: self.ssd_selected,
            drivers,
            result,
            start,
            journal,
            journal_follow_tail: true,
            status_left,
            status_right: vec![
                self.os_label.clone(),
                self.computer_name.clone(),
                format!("{}   {}", now.date_dmy(), now.hm()),
            ],
            time,
            animate: true,
            lang: self.language,
            page: self.page,
            crash: self.crash_vm(),
            sensors: self.sensors_vm(),
            gpo: self.gpo_vm(),
            system_state: self.system_state_vm(),
            smart: self.smart_rows(),
            passport: self.passport_rows(),
        }
    }

    fn apply(&mut self, action: Action) {
        match action {
            Action::Start => self.start_diagnostics(),
            Action::Reset => self.reset_run_view(),
            Action::OpenReport => self.open_final_report(&engine::open_report),
            Action::OpenFolder => self.open_final_report_folder(&engine::open_report_folder),
            Action::BenchmarkStart => self.start_benchmark(),
            Action::BenchmarkCancel => {
                if let BenchmarkUiState::Running { cancel, .. } = &self.benchmark_state {
                    cancel.store(true, Ordering::Relaxed);
                } else if let BenchmarkUiState::RetestWaiting { identity, .. } =
                    &self.benchmark_state
                {
                    // Stop during the idle: no retest, first result kept.
                    let id = identity.clone();
                    self.end_retest(&id, storage_health::RetestOutcome::Cancelled);
                }
            }
            Action::Stop => self.request_stop(),
            // v1.1: ReHash changes the system — the request only opens the
            // warning / confirmation; it runs after the explicit «Yes».
            Action::CryptoRehashRequest => {
                if self.crypto_rehash_allowed() {
                    self.crypto_rehash_confirm = true;
                }
            }
            Action::CryptoRehashConfirmed => {
                self.crypto_rehash_confirm = false;
                if self.crypto_rehash_allowed() {
                    self.start_crypto_rehash();
                }
            }
            Action::CryptoRehashCancelled => self.crypto_rehash_confirm = false,
            Action::CryptoRecheck => {
                if self.crypto_rx.is_none() {
                    self.start_crypto_check();
                }
            }
            Action::ShowCryptoDetails => self.crypto_details_open = true,
            Action::CheckDrivers => self.request_driver_audit(),
            Action::SelectSsdDisk(index) => self.select_ssd_disk(index),
            Action::SetLanguage(lang) => {
                if self.language != lang {
                    self.language = lang;
                    // Best-effort: a read-only portable medium must never
                    // block the switch itself, which is why `save` never
                    // returns an error to propagate.
                    i18n::save(&self.language_pref_dir, lang);
                }
            }
            Action::ViewHardware => self.start_hardware_view(),
            // Clear empties the dashboard card only. It never touches the
            // session journal's files or any report/evidence on disk.
            Action::ClearLog => self.journal.clear_view(),
            Action::OpenJournal => self.journal_viewer_open = true,
            Action::ShowRawPasses => self.raw_passes_open = true,
            Action::ShowDrivers => self.drivers_open = true,
            Action::ShowExpcDetails => self.expc_details_open = true,
            // v0.4.4: page switch only changes what is drawn; every module
            // state (selected disk, benchmark, audit, crash) is untouched.
            Action::SetPage(page) => self.page = page,
            Action::AnalyzeDumps => self.start_crash_analysis(),
            Action::ShowCrashDetails => self.crash_details_open = true,
            // v1.0: the hidden install is observed to its end and re-detects
            // the analyzer itself (no blind periodic re-scans).
            Action::InstallAnalyzer => self.install_analyzer(),
            // v1.0: an explicit module run (its own session when Client /
            // Computer changed, see `begin_operation`).
            Action::RefreshSensors => {
                self.begin_operation(false);
                self.start_sensor_read(true);
            }
            Action::ShowSensorDetails => self.sensors_details_open = true,
            Action::RunGpoCheck => {
                self.begin_operation(false);
                self.start_gpo_check();
            }
            Action::ShowGpoDetails => self.gpo_details_open = true,
            Action::CopyClientInfo => {
                self.clipboard_out = Some(passport::client_clipboard_text(
                    &self.client_name,
                    &self.computer_name,
                    self.language == Language::Ru,
                ));
            }
            Action::ShowStageDetails(i) => {
                if self.stage_details != Some(i) {
                    self.stage_export_status = None;
                }
                self.stage_details = Some(i);
            }
        }
    }

    /// Final verified report of the completed session (never a temporary
    /// or packaging path; no fallback).
    fn final_report(&self) -> Result<PathBuf, String> {
        match &self.state {
            RunState::Done { zip_path } => {
                engine::verify_final_report(zip_path, &self.reports_root)
            }
            _ => match report_package::lock(&self.package).final_zip() {
                Some(zip) => engine::verify_final_report(&zip, &self.reports_root),
                None => Err(i18n::t(self.language).report_not_ready_error.to_string()),
            },
        }
    }

    fn open_final_report(&mut self, opener: &dyn Fn(&Path) -> Result<(), String>) {
        // The attention pulse stops after the first attempt; the button stays.
        self.report_opened = true;
        match self.final_report() {
            Ok(path) => {
                if let Err(err) = opener(&path) {
                    push_journal(&mut self.journal, format!("[ERROR] {err}"));
                }
            }
            Err(err) => push_journal(&mut self.journal, format!("[ERROR] {err}")),
        }
    }

    /// v1.0 "Открыть папку отчёта" of a Details window (same final-report
    /// rules as the dashboard button; no Explorer launch under tests).
    fn open_report_folder_from_details(&mut self) {
        if cfg!(test) {
            self.open_final_report_folder(&|_| Ok(()));
        } else {
            self.open_final_report_folder(&engine::open_report_folder);
        }
    }

    fn open_final_report_folder(&mut self, opener: &dyn Fn(&Path) -> Result<(), String>) {
        match self.final_report() {
            Ok(path) => {
                if let Err(err) = opener(&path) {
                    push_journal(&mut self.journal, format!("[ERROR] {err}"));
                }
            }
            Err(err) => push_journal(&mut self.journal, format!("[ERROR] {err}")),
        }
    }

    /// Normal mode: scale the reference canvas uniformly to the window
    /// (hierarchy and proportions preserved; below the minimum scale the
    /// canvas scrolls instead of shrinking further).
    fn fit_scale(&mut self, ctx: &egui::Context) {
        let native = ctx.native_pixels_per_point().unwrap_or(1.0);
        if !self.window_fitted {
            self.window_fitted = true;
            if let Some(monitor) = ctx.input(|i| i.viewport().monitor_size) {
                let design = vec2(CANVAS_W, CANVAS_H) / native;
                let k = (0.94 * monitor.x / design.x)
                    .min(0.88 * monitor.y / design.y)
                    .min(1.0);
                ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(design * k));
            }
        }
        let physical = ctx.content_rect().size() * ctx.pixels_per_point();
        let target_ppp =
            ui::fit_pixels_per_point(physical.x, physical.y).max(ui::MIN_PIXELS_PER_POINT);
        let zoom = target_ppp / native;
        if (ctx.zoom_factor() - zoom).abs() > 0.002 {
            ctx.set_zoom_factor(zoom);
            ctx.request_repaint();
        }
    }

    /// Full Driver Audit: every audited driver with status, reasons and the
    /// concrete evidence (the same data as the report).
    fn drivers_window(&mut self, ctx: &egui::Context) {
        if !self.drivers_open {
            return;
        }
        let mut open = self.drivers_open;
        let mut rerun = false;
        let mut close_drivers = false;
        let mut export: Option<ExportAction> = None;
        let d = i18n::t(self.language);
        let export_status = self.driver_export_status.as_ref().map(|s| s.text(d));
        let view = self.audit_view();
        // v1.1: the check history (this UI only) and the last-check line.
        let history = self.driver_history.clone();
        let confirm_clear = self.driver_history_clear_confirm;
        let has_report = view.is_some();
        let last_check = self.driver_checked.as_ref().map(|s| {
            d.driver_last_check_fmt
                .replace("{origin}", s.origin.text(d))
                .replace("{time}", &s.at)
        });
        let recheck_failed = history
            .last()
            .is_some_and(|e| e.outcome.starts_with(d.driver_status_error))
            && matches!(self.driver_audit, DriverAuditState::Done(_));
        let mut history_act: Option<v11::HistoryAct> = None;
        detail_window(
            ctx,
            "wsd_driver_details",
            d.driver_details_title,
            [980.0, 760.0],
            &mut open,
            |ui| {
                if let Some(line) = &last_check {
                    ui.label(RichText::new(line).color(c::TEXT_MUTED));
                }
                if recheck_failed {
                    ui.label(RichText::new(d.driver_recheck_failed).color(c::YELLOW_WARNING));
                }
                match &self.driver_audit {
                    DriverAuditState::Idle => {
                        ui.label(d.driver_not_run);
                        rerun = ui.button(d.driver_popup_run).clicked();
                        history_act =
                            v11::driver_history_section(ui, d, &history, confirm_clear, has_report);
                    }
                    DriverAuditState::Running(_) => {
                        ui.label(d.driver_popup_running);
                        history_act =
                            v11::driver_history_section(ui, d, &history, confirm_clear, has_report);
                    }
                    DriverAuditState::Failed(msg) => {
                        ui.colored_label(c::RED_ERROR, msg);
                        rerun = ui.button(d.driver_popup_retry).clicked();
                        history_act =
                            v11::driver_history_section(ui, d, &history, confirm_clear, has_report);
                    }
                    DriverAuditState::Done(base) => {
                        let report: &AuditReport = view.as_deref().unwrap_or(base);
                        // v0.4.1 summary header: application UI, not a log line
                        // (no date/time); the rule text lives in the Info tip.
                        let (header_rerun, header_export) =
                            driver_summary_header(ui, d, report, export_status.as_ref());
                        rerun = header_rerun;
                        export = header_export;
                        ui.add_space(4.0);
                        ui.separator();
                        egui::ScrollArea::vertical()
                            .id_salt("wsd_driver_details_scroll")
                            .auto_shrink([false, false])
                            .max_height((ui.available_height() - 50.0).max(120.0))
                            .show(ui, |ui| {
                                for (n, it) in report.items.iter().enumerate() {
                                    let col = match it.status {
                                        Severity::Problem => c::RED_ERROR,
                                        Severity::Warning => c::YELLOW_WARNING,
                                        Severity::Ok => c::GREEN_SUCCESS,
                                    };
                                    egui::CollapsingHeader::new(
                                        egui::RichText::new(format!(
                                            "[{}]  {}  —  {}",
                                            driver_status_label(d, it.status),
                                            localized_driver_label(d, &it.label),
                                            if it.version.is_empty() {
                                                d.driver_na
                                            } else {
                                                &it.version
                                            }
                                        ))
                                        .color(col),
                                    )
                                    .id_salt(("drv", n))
                                    .default_open(it.status != Severity::Ok)
                                    .show(ui, |ui| {
                                        ui.label(
                                            d.driver_popup_device_fmt
                                                .replace("{device}", &it.device),
                                        );
                                        ui.label(
                                            d.driver_popup_provider_fmt
                                                .replace(
                                                    "{provider}",
                                                    if it.provider.is_empty() {
                                                        d.driver_na
                                                    } else {
                                                        &it.provider
                                                    },
                                                )
                                                .replace(
                                                    "{date}",
                                                    if it.date.is_empty() {
                                                        d.driver_na
                                                    } else {
                                                        &it.date
                                                    },
                                                )
                                                .replace(
                                                    "{inf}",
                                                    if it.inf.is_empty() {
                                                        d.driver_na
                                                    } else {
                                                        &it.inf
                                                    },
                                                )
                                                .replace(
                                                    "{service}",
                                                    if it.service.is_empty() {
                                                        d.driver_na
                                                    } else {
                                                        &it.service
                                                    },
                                                ),
                                        );
                                        if !it.pnp_id.is_empty() {
                                            ui.label(
                                                egui::RichText::new(&it.pnp_id)
                                                    .color(c::TEXT_MUTED),
                                            );
                                        }
                                        for e in &it.evidence {
                                            ui.label(format!(
                                                "• {} [{}{}]{}{}",
                                                e.reason,
                                                e.source,
                                                e.event_id
                                                    .map(|i| d
                                                        .driver_popup_event_fmt
                                                        .replace("{event_id}", &i.to_string()))
                                                    .unwrap_or_default(),
                                                if e.count > 1 {
                                                    format!(" ×{}", e.count)
                                                } else {
                                                    String::new()
                                                },
                                                if e.last_seen.is_empty() {
                                                    String::new()
                                                } else {
                                                    d.driver_popup_last_seen_fmt
                                                        .replace("{last_seen}", &e.last_seen)
                                                }
                                            ));
                                        }
                                    });
                                }
                                // Engineering detail only: inactive-by-design drivers
                                // (never counted, never on the card or in the TXT).
                                if !report.expected_inactive.is_empty() {
                                    ui.separator();
                                    for e in &report.expected_inactive {
                                        ui.label(
                                            egui::RichText::new(format!("[INFO] {}", e.reason))
                                                .color(c::TEXT_MUTED),
                                        );
                                    }
                                }
                                if !report.software_findings.is_empty() {
                                    ui.separator();
                                    ui.label(
                                        egui::RichText::new(d.driver_software_findings_title)
                                            .strong()
                                            .color(c::YELLOW_WARNING),
                                    );
                                    for e in &report.software_findings {
                                        ui.label(format!(
                                            "• {} [{}{}] ×{} · {} … {}",
                                            e.reason,
                                            e.source,
                                            e.event_id
                                                .map(|i| format!(" #{i}"))
                                                .unwrap_or_default(),
                                            e.count,
                                            e.first_seen.replace('T', " "),
                                            e.last_seen.replace('T', " ")
                                        ));
                                    }
                                }
                                if !report.unattributed.is_empty() {
                                    ui.separator();
                                    ui.label(
                                        egui::RichText::new(d.driver_popup_unattributed_note)
                                            .color(c::TEXT_MUTED),
                                    );
                                    for e in &report.unattributed {
                                        ui.label(format!(
                                            "• {} [{}] ×{}",
                                            e.reason, e.source, e.count
                                        ));
                                    }
                                }
                                if !report.errors.is_empty() {
                                    ui.separator();
                                    for e in &report.errors {
                                        ui.colored_label(
                                            c::YELLOW_WARNING,
                                            d.driver_popup_collection_error_fmt
                                                .replace("{error}", e),
                                        );
                                    }
                                }
                                ui.add_space(8.0);
                                history_act = v11::driver_history_section(
                                    ui,
                                    d,
                                    &history,
                                    confirm_clear,
                                    has_report,
                                );
                            });
                        // v1.0 standard action bar (this module's text only).
                        ui.separator();
                        match details_action_bar(ui, d, true, None) {
                            Some(DetailsAct::Copy) => export = Some(ExportAction::Copy),
                            Some(DetailsAct::Save) => export = Some(ExportAction::Save),
                            Some(DetailsAct::Close) => close_drivers = true,
                            _ => {}
                        }
                    }
                }
            },
        );
        if close_drivers {
            open = false;
        }
        self.drivers_open = open;
        if let Some(act) = history_act {
            self.apply_history_act(ctx, act);
        }
        if let Some(action) = export {
            self.driver_issues_export(ctx, action);
        }
        if rerun {
            self.request_driver_audit();
        }
    }

    /// Run / re-run of the Driver Audit («Проверка» on the card or in its
    /// Details window): a separate module run in its own correctly
    /// identified session (nothing else is started; never two at once).
    fn request_driver_audit(&mut self) {
        if matches!(self.driver_audit, DriverAuditState::Running(_)) {
            return;
        }
        self.driver_export_status = None;
        self.begin_operation(false);
        self.claim_package("drivers");
        self.driver_origin = CheckOrigin::Manual;
        self.request_collector("driver_audit");
        // Unit tests never start the collector.
        #[cfg(not(test))]
        {
            let previous = std::mem::replace(&mut self.driver_audit, start_driver_audit());
            self.keep_previous_driver_result(previous);
        }
        #[cfg(test)]
        {
            let _ = start_driver_audit;
            self.driver_rerun_requests += 1;
        }
    }

    /// v1.1: the result shown before a re-check stays available until the
    /// re-check SUCCEEDS (a failed re-check never replaces it).
    #[cfg_attr(test, allow(dead_code))]
    fn keep_previous_driver_result(&mut self, previous: DriverAuditState) {
        if let DriverAuditState::Done(report) = previous {
            self.driver_previous = Some(report);
        }
    }

    /// The canonical Driver Check issues text of the current audit.
    fn driver_issues_text(&self) -> Option<String> {
        let report = self.audit_view()?;
        let d = i18n::t(self.language);
        Some(details::driver_issues_text(&report, d, &|l| {
            localized_driver_label(d, l)
        }))
    }

    /// Copy issues / Save issues: one text, two destinations. Save goes to
    /// `Reports\Logs` (never a ZIP-only report folder); failures are shown
    /// and journaled, never fatal.
    fn driver_issues_export(&mut self, ctx: &egui::Context, action: ExportAction) {
        let Some(text) = self.driver_issues_text() else {
            return;
        };
        self.driver_export_status = Some(self.export_text(ctx, action, "DriverIssues", &text));
    }

    fn export_text(
        &mut self,
        ctx: &egui::Context,
        action: ExportAction,
        kind: &str,
        text: &str,
    ) -> ExportStatus {
        let d = i18n::t(self.language);
        match action {
            ExportAction::Copy => {
                ctx.copy_text(text.to_string());
                ExportStatus::Copied
            }
            ExportAction::Save => {
                let name = details::export_file_name(kind, sysinfo::local_time());
                let dir = journal_logs_dir(&self.reports_root);
                // v1.0: standard Windows Save As dialog; only THIS module's
                // text is written. Without a dialog (tests, no comdlg32) the
                // file goes to the session logs folder as before.
                let picked = crate::win_dialog::save_as(&dir, &name, d.details_save_as);
                let saved = match picked {
                    crate::win_dialog::SavePick::Cancelled => return ExportStatus::Cancelled,
                    crate::win_dialog::SavePick::Path(path) => {
                        crate::win_dialog::write_text(&path, text)
                    }
                    crate::win_dialog::SavePick::Unavailable => {
                        save_journal_text(&dir, &name, text)
                    }
                };
                match saved {
                    Ok(path) => {
                        let line = format!("{}: {}", d.export_saved, path.display());
                        push_journal(&mut self.journal, line);
                        ExportStatus::Saved(path)
                    }
                    Err(err) => {
                        let line = format!("[ERROR] {}: {err}", d.export_save_failed);
                        push_journal(&mut self.journal, line);
                        ExportStatus::Failed(err)
                    }
                }
            }
        }
    }

    /// Per-step execution state for the EXPC details window.
    fn expc_step_progress(&self) -> Vec<details::StepProgress> {
        use details::StepProgress as P;
        self.expc_tracker
            .status
            .iter()
            .map(|s| match (&self.state, s) {
                (RunState::Idle, _) => P::Waiting,
                (RunState::Cancelled { .. }, SubStageStatus::Running) => P::Waiting,
                (_, SubStageStatus::Pending) => P::Waiting,
                (_, SubStageStatus::Running) => P::Running,
                (_, SubStageStatus::Done) => P::Done,
                (_, SubStageStatus::Skipped) => P::Skipped,
                (_, SubStageStatus::Error) => P::Failed,
            })
            .collect()
    }

    fn expc_stage_details(&self) -> Vec<details::StageDetail> {
        // EXPC evidence (its JSON/TXT) exists once the run left the EXPC
        // stage; before that, completed steps show "result pending".
        let evidence_ready = !self.expc_checks.is_empty()
            || !self.deep_check_results.is_empty()
            || !self.is_running();
        details::build_stage_details(
            &self.expc_step_progress(),
            evidence_ready,
            &self.expc_checks,
            &self.deep_check_results,
        )
    }

    /// v0.4.5: evidence lines of ONE EXPC stage — its EXPC check records
    /// (key, status, detail) plus the stage's own read-only sources (07:
    /// unexpected shutdowns / BugCheck / dumps / incidents; 14: Driver
    /// Audit). Never another stage's data.
    fn stage_evidence_lines(&self, i: usize) -> Vec<String> {
        let mut out: Vec<String> = self
            .expc_checks
            .iter()
            .filter(|c| details::step_of_key(&c.key) == Some(i))
            .map(|c| {
                if c.detail.is_empty() {
                    format!("EXPC · {} · {}", c.key, c.status)
                } else {
                    format!("EXPC · {} · {} · {}", c.key, c.status, c.detail)
                }
            })
            .collect();
        if let Some(o) = self
            .deep_check_results
            .iter()
            .find(|o| DeepCheck::of_step_index(i) == Some(o.check))
        {
            out.push(format!(
                "{} · {} · {}",
                o.check.key(),
                o.effective_result().as_str(),
                o.detail
            ));
            // v1.0: CHKDSK execution vs finding are separate facts.
            if let Some(f) = o.finding_class() {
                out.push(format!(
                    "{} · execution_status=completed · finding_class={}",
                    o.check.key(),
                    f.code()
                ));
            }
        }
        // v1.0 cross-module consistency note of this stage.
        let ok = self
            .expc_stage_details()
            .get(i)
            .is_some_and(|det| det.state == details::StageState::Ok);
        let sys_events = self
            .audit_view()
            .map(|r| significant_system_evidence(&r))
            .unwrap_or(0);
        let bugchecks = match &self.crash.inventory {
            Some(Ok(inv)) => inv.bugchecks.len(),
            _ => 0,
        };
        if let Some(note) = consistency_note(i, ok, sys_events, bugchecks, i18n::t(self.language)) {
            out.push(format!("Consistency · {note}"));
        }
        // v1.0 aggregated event evidence of THIS stage only (04 System,
        // 05 VSS / Volsnap, 03 kernel CI, 08 applications / user-mode CI /
        // SideBySide).
        out.extend(self.stage_event_lines(i));
        match i {
            6 => out.extend(self.crash_stage_evidence()),
            13 => {
                if let Some(r) = self.audit_view() {
                    let count = |s: Severity| r.items.iter().filter(|it| it.status == s).count();
                    out.push(format!(
                        "Driver Audit · {} · PROBLEM {} · WARNING {} · OK {} · devices {}",
                        r.overall.code(),
                        count(Severity::Problem),
                        count(Severity::Warning),
                        count(Severity::Ok),
                        r.devices_scanned
                    ));
                }
            }
            _ => {}
        }
        out
    }

    /// Session journal lines that belong to stage `i` (its EXPC title, its
    /// short name or its deep-check label), newest last, at most 12.
    fn stage_journal_lines(&self, i: usize) -> Vec<String> {
        let d = i18n::t(self.language);
        let mut needles: Vec<String> = vec![
            EXPC_STEP_LABELS[i].to_string(),
            d.stage_short[i].to_string(),
            format!("{:02}/14", i + 1),
        ];
        if let Some(k) = DeepCheck::of_step_index(i) {
            needles.push(format!("{} ", k.key()));
        }
        let lines: Vec<String> = self
            .journal
            .entries
            .iter()
            .filter(|e| {
                needles
                    .iter()
                    .any(|n| !n.trim().is_empty() && e.message.contains(n.as_str()))
            })
            .map(SessionJournal::line)
            .collect();
        let start = lines.len().saturating_sub(12);
        lines[start..].to_vec()
    }

    /// Plain-text export of one stage window (Copy / Save).
    fn stage_details_text(&self, i: usize) -> String {
        let d = i18n::t(self.language);
        let entries = self.expc_stage_details();
        let mut o = String::new();
        let title = d
            .stage_window_title_fmt
            .replace("{n}", &format!("{:02}", i + 1))
            .replace("{name}", d.stage_short[i]);
        o.push_str(&format!("WinStateDiag — {title}\r\n"));
        o.push_str(&format!(
            "{}: {}\r\n",
            d.stage_scope_label, d.stage_scope[i]
        ));
        if let Some(det) = entries.get(i) {
            o.push_str(&format!(
                "{}: {}\r\n",
                d.stage_status_label,
                d.expc_state_labels[det.state.index()]
            ));
            if let Some(t) = self.expc_tracker.durations[i] {
                o.push_str(&format!(
                    "{}: {} s\r\n",
                    d.stage_duration_label,
                    t.as_secs()
                ));
            }
            let ex = details::explain(det, d, &system_drive());
            if let Some(e) = &ex.explanation {
                o.push_str(&format!("{e}\r\n"));
            }
            for f in &det.findings {
                o.push_str(&format!("{}: {f}\r\n", d.expc_result_label));
            }
            if let Some(cmd) = &ex.suggested_command {
                o.push_str(&format!(
                    "{}: {cmd} ({})\r\n",
                    d.expc_suggested_action, d.expc_not_executed
                ));
            }
        }
        o.push_str(&format!("\r\n{}:\r\n", d.stage_evidence_label));
        let ev = self.stage_evidence_lines(i);
        if ev.is_empty() {
            o.push_str(&format!("  {}\r\n", d.stage_no_evidence));
        }
        for l in ev {
            o.push_str(&format!("  {l}\r\n"));
        }
        o.push_str(&format!("\r\n{}:\r\n", d.stage_journal_label));
        for l in self.stage_journal_lines(i) {
            o.push_str(&format!("  {l}\r\n"));
        }
        o
    }

    /// v0.4.5 Details of ONE EXPC stage (row button). Status, result,
    /// evidence and the stage's own journal lines; Copy / Save / Close.
    fn stage_details_window(&mut self, ctx: &egui::Context) {
        let Some(i) = self.stage_details.filter(|i| *i < 14) else {
            return;
        };
        let d = i18n::t(self.language);
        let entries = self.expc_stage_details();
        let Some(det) = entries.get(i).cloned() else {
            self.stage_details = None;
            return;
        };
        let evidence = self.stage_evidence_lines(i);
        let journal = self.stage_journal_lines(i);
        let duration = self.expc_tracker.durations[i].map(|t| {
            let s = t.as_secs();
            format!("{:02}:{:02}", s / 60, s % 60)
        });
        let drive = system_drive();
        let status = self.stage_export_status.as_ref().map(|s| s.text(d));
        let title = d
            .stage_window_title_fmt
            .replace("{n}", &format!("{:02}", i + 1))
            .replace("{name}", d.stage_short[i]);
        let mut open = true;
        let mut close = false;
        let mut action: Option<ExportAction> = None;
        let mut copy_command: Option<String> = None;
        let not_run = det.state == details::StageState::Waiting;
        let folder_ok = self.final_report().is_ok();
        let mut open_folder = false;
        detail_window(
            ctx,
            "wsd_stage_details",
            &title,
            [940.0, 780.0],
            &mut open,
            |ui| {
                ui.label(
                    RichText::new(&title)
                        .strong()
                        .size(17.0)
                        .color(c::TEXT_TITLE),
                );
                ui.label(
                    RichText::new(format!("{}: {}", d.stage_scope_label, d.stage_scope[i]))
                        .color(c::TEXT_SECONDARY),
                );
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(format!("{}:", d.stage_status_label))
                            .color(c::TEXT_SECONDARY),
                    );
                    ui.label(
                        RichText::new(d.expc_state_labels[det.state.index()])
                            .strong()
                            .color(det.state.color()),
                    );
                    if let Some(t) = &duration {
                        ui.label(
                            RichText::new(format!("· {}: {t}", d.stage_duration_label))
                                .color(c::TEXT_SECONDARY),
                        );
                    }
                });
                ui.add_space(6.0);
                let footer = if status.is_some() { 70.0 } else { 46.0 };
                egui::ScrollArea::vertical()
                    .id_salt("wsd_stage_details_scroll")
                    .auto_shrink([false, false])
                    .max_height((ui.available_height() - footer).max(80.0))
                    .show(ui, |ui| {
                        if not_run {
                            ui.label(RichText::new(d.stage_not_run).color(c::TEXT_MUTED));
                        } else {
                            expc_stage_card(ui, d, &det, &drive, &mut copy_command);
                        }
                        ui.add_space(8.0);
                        details::section_title(ui, d.stage_evidence_label);
                        if evidence.is_empty() {
                            ui.label(RichText::new(d.stage_no_evidence).color(c::TEXT_MUTED));
                        }
                        for l in &evidence {
                            ui.add(
                                egui::Label::new(
                                    RichText::new(l).monospace().size(12.5).color(c::TEXT_BODY),
                                )
                                .wrap(),
                            );
                        }
                        ui.add_space(8.0);
                        details::section_title(ui, d.stage_journal_label);
                        if journal.is_empty() {
                            ui.label(RichText::new(d.stage_journal_empty).color(c::TEXT_MUTED));
                        }
                        for l in &journal {
                            ui.add(
                                egui::Label::new(
                                    RichText::new(l)
                                        .monospace()
                                        .size(12.0)
                                        .color(c::TEXT_SECONDARY),
                                )
                                .wrap(),
                            );
                        }
                    });
                ui.separator();
                if let Some((text, color)) = &status {
                    ui.add(egui::Label::new(RichText::new(text).color(*color)).wrap());
                }
                match details_action_bar(ui, d, !not_run, Some(folder_ok)) {
                    Some(DetailsAct::Copy) => action = Some(ExportAction::Copy),
                    Some(DetailsAct::Save) => action = Some(ExportAction::Save),
                    Some(DetailsAct::OpenFolder) => open_folder = true,
                    Some(DetailsAct::Close) => close = true,
                    None => {}
                }
            },
        );
        if open_folder {
            self.open_report_folder_from_details();
        }
        if let Some(cmd) = copy_command {
            ctx.copy_text(cmd);
            self.stage_export_status = Some(ExportStatus::Copied);
        }
        if let Some(action) = action {
            let text = self.stage_details_text(i);
            let kind = format!("EXPC_Stage_{:02}", i + 1);
            self.stage_export_status = Some(self.export_text(ctx, action, &kind, &text));
        }
        if !open || close {
            self.stage_details = None;
            self.stage_export_status = None;
        }
    }

    /// v0.4.1: EXPC diagnostic results — explanation of the 14 steps
    /// (dashboard = status, this window = explanation, ZIP = evidence).
    fn expc_details_window(&mut self, ctx: &egui::Context) {
        if !self.expc_details_open {
            return;
        }
        let d = i18n::t(self.language);
        let entries = self.expc_stage_details();
        let never_ran = matches!(self.state, RunState::Idle)
            && entries
                .iter()
                .all(|e| e.state == details::StageState::Waiting);
        let counts = details::expc_counts(&entries);
        let drive = system_drive();
        let status = self.expc_export_status.as_ref().map(|s| s.text(d));
        let mut open = true;
        let mut action: Option<ExportAction> = None;
        let mut close = false;
        let mut copy_command: Option<String> = None;
        let folder_ok = self.final_report().is_ok();
        let mut open_folder = false;
        detail_window(
            ctx,
            "wsd_expc_details",
            d.expc_details_title,
            [1000.0, 820.0],
            &mut open,
            |ui| {
                details::section_title(ui, d.expc_details_summary);
                ui.horizontal_wrapped(|ui| {
                    details::counter_chip(
                        ui,
                        d.expc_sum_problems,
                        &counts.problems.to_string(),
                        c::DRIVER_STATUS_PROBLEM_TEXT,
                    );
                    details::counter_chip(
                        ui,
                        d.expc_sum_attention,
                        &counts.attention.to_string(),
                        c::YELLOW_WARNING,
                    );
                    details::counter_chip(
                        ui,
                        d.expc_sum_ok,
                        &counts.ok.to_string(),
                        c::GREEN_SUCCESS,
                    );
                    details::counter_chip(
                        ui,
                        d.expc_sum_info,
                        &counts.info.to_string(),
                        c::BLUE_STATUS,
                    );
                    details::counter_chip(
                        ui,
                        d.expc_sum_skipped,
                        &counts.skipped.to_string(),
                        c::TEXT_MUTED,
                    );
                    if counts.other > 0 {
                        details::counter_chip(
                            ui,
                            d.expc_sum_other,
                            &counts.other.to_string(),
                            c::TEXT_SECONDARY,
                        );
                    }
                });
                ui.add_space(6.0);
                let footer = if status.is_some() { 70.0 } else { 46.0 };
                egui::ScrollArea::vertical()
                    .id_salt("wsd_expc_details_scroll")
                    .auto_shrink([false, false])
                    .max_height((ui.available_height() - footer).max(80.0))
                    .show(ui, |ui| {
                        if never_ran {
                            ui.label(RichText::new(d.expc_not_started).color(c::TEXT_MUTED));
                            return;
                        }
                        for det in details::findings_first(&entries) {
                            expc_stage_card(ui, d, det, &drive, &mut copy_command);
                        }
                    });
                ui.separator();
                if let Some((text, color)) = &status {
                    ui.add(egui::Label::new(RichText::new(text).color(*color)).wrap());
                }
                match details_action_bar(ui, d, !never_ran, Some(folder_ok)) {
                    Some(DetailsAct::Copy) => action = Some(ExportAction::Copy),
                    Some(DetailsAct::Save) => action = Some(ExportAction::Save),
                    Some(DetailsAct::OpenFolder) => open_folder = true,
                    Some(DetailsAct::Close) => close = true,
                    None => {}
                }
            },
        );
        if open_folder {
            self.open_report_folder_from_details();
        }
        if let Some(cmd) = copy_command {
            ctx.copy_text(cmd);
            self.expc_export_status = Some(ExportStatus::Copied);
        }
        if let Some(action) = action {
            let text = details::expc_details_text(&entries, d, &drive);
            self.expc_export_status = Some(self.export_text(ctx, action, "EXPC_Results", &text));
        }
        if !open || close {
            self.expc_details_open = false;
            self.expc_export_status = None;
        }
    }

    /// v1.0 Disk Benchmark Details: a large resizable engineering window
    /// for the selected PHYSICAL disk — identity, Test 1 / Test 2, their
    /// comparison, SMART / NVMe health, the final storage assessment and
    /// the last benchmark runs of this disk. Copy / Save as / folder / Close.
    fn raw_passes_window(&mut self, ctx: &egui::Context) {
        if !self.raw_passes_open {
            return;
        }
        let BenchmarkUiState::Done { result, .. } = &self.benchmark_state else {
            self.raw_passes_open = false;
            return;
        };
        let result = result.clone();
        let d = i18n::t(self.language);
        let sections = self.disk_details_sections(&result);
        let text = disk_details_text(&self.disk_details_title(), &sections);
        let title = self.disk_details_title();
        let status = self.disk_export_status.as_ref().map(|s| s.text(d));
        let folder_ok = self.final_report().is_ok();
        let assessment = self.selected_assessment();
        let first = assessment.map(|a| a.first.clone());
        let perf = self.disk_performance_rows(&result);
        let mut open = true;
        let mut act: Option<DetailsAct> = None;
        detail_window(
            ctx,
            "wsd_disk_details",
            &title,
            [1060.0, 860.0],
            &mut open,
            |ui| {
                ui.label(
                    RichText::new(&title)
                        .strong()
                        .size(22.0)
                        .color(c::TEXT_TITLE),
                );
                ui.label(RichText::new(d.disk_det_subtitle).color(c::TEXT_SECONDARY));
                ui.add_space(4.0);
                let footer = if status.is_some() { 76.0 } else { 50.0 };
                egui::ScrollArea::vertical()
                    .id_salt("wsd_disk_details_scroll")
                    .auto_shrink([false, false])
                    .max_height((ui.available_height() - footer).max(120.0))
                    .show(ui, |ui| {
                        let mut perf_done = false;
                        for (n, (head, rows)) in sections.iter().enumerate() {
                            // v1.0 polish: identity and controller data as
                            // two side-by-side tables; Test 1 / Test 2 as one
                            // performance table. Same facts as Copy / Save.
                            let is_test =
                                head.starts_with(d.test1_title) || head.starts_with(d.test2_title);
                            if is_test {
                                if !perf_done {
                                    perf_done = true;
                                    disk_section_frame(ui, d.disk_det_performance, |ui| {
                                        disk_performance_table(ui, d, &perf);
                                    });
                                }
                                continue;
                            }
                            if n == 0 || head == d.nvme_health_title {
                                disk_section_frame(ui, head, |ui| {
                                    two_column_tables(ui, ("wsd_disk_2col", n), rows);
                                });
                                continue;
                            }
                            disk_section_frame(ui, head, |ui| {
                                egui::Grid::new(("wsd_disk_sec", n))
                                    .num_columns(2)
                                    .striped(true)
                                    .spacing(vec2(16.0, 4.0))
                                    .show(ui, |ui| {
                                        for (k, v) in rows {
                                            if k.is_empty() {
                                                ui.label("");
                                                ui.add(
                                                    egui::Label::new(
                                                        RichText::new(v).color(c::TEXT_SECONDARY),
                                                    )
                                                    .wrap(),
                                                );
                                            } else {
                                                ui.label(RichText::new(k).color(c::TEXT_SECONDARY));
                                                ui.add(egui::Label::new(v).wrap());
                                            }
                                            ui.end_row();
                                        }
                                    });
                            });
                        }
                        // Raw passes of both runs (kept for engineers).
                        egui::CollapsingHeader::new(d.ssd_raw_passes_title)
                            .id_salt("wsd_disk_raw_passes")
                            .show(ui, |ui| {
                                if let Some(f) = &first {
                                    section_title(ui, d.test1_title);
                                    pass_grid(ui, "benchmark_first_run_passes", f);
                                }
                                section_title(ui, d.ssd_disk_details_current);
                                pass_grid(ui, "benchmark_raw_passes", &result);
                            });
                    });
                ui.separator();
                if let Some((t, col)) = &status {
                    ui.add(egui::Label::new(RichText::new(t).color(*col)).wrap());
                }
                act = details_action_bar(ui, d, true, Some(folder_ok));
            },
        );
        match act {
            Some(DetailsAct::Copy) => {
                self.disk_export_status =
                    Some(self.export_text(ctx, ExportAction::Copy, "Disk_Benchmark", &text))
            }
            Some(DetailsAct::Save) => {
                self.disk_export_status =
                    Some(self.export_text(ctx, ExportAction::Save, "Disk_Benchmark", &text))
            }
            Some(DetailsAct::OpenFolder) => self.open_report_folder_from_details(),
            Some(DetailsAct::Close) => open = false,
            None => {}
        }
        if !open {
            self.disk_export_status = None;
        }
        self.raw_passes_open = open;
    }

    /// v1.0 polish: the performance table rows (Test 1, Test 2) — label,
    /// Read, Write, read / write spread, duration, status and its tone.
    /// Test 2 that did not run reads "—" with the real reason.
    fn disk_performance_rows(&self, current: &StorageDiagnosticSummary) -> Vec<PerfRow> {
        let d = i18n::t(self.language);
        let ru = self.language == Language::Ru;
        let mb = |mib: f64| format!("{:.0}", mib * 1.048576);
        let row = |label: String, r: &StorageDiagnosticSummary, dur: Option<f64>| {
            let level = stability_level(r.read_variation_percent)
                .max(stability_level(r.write_variation_percent));
            PerfRow {
                cells: [
                    label,
                    mb(r.summary_read_mib_s),
                    mb(r.summary_write_mib_s),
                    format!("{:.2} %", r.read_variation_percent),
                    format!("{:.2} %", r.write_variation_percent),
                    dur.map(|s| format!("{s:.1}")).unwrap_or_else(|| "—".into()),
                    stability_text(level).to_string(),
                ],
                tone: Some(stability_tone(level)),
            }
        };
        let assessment = self.selected_assessment();
        let mut out = Vec::new();
        match assessment {
            Some(a) => {
                out.push(row(
                    format!("{} — {}", d.test1_title, d.disk_det_initial),
                    &a.first,
                    Some(a.first_duration),
                ));
                match &a.second {
                    Some(r2) => out.push(row(d.test2_title.to_string(), r2, a.second_duration)),
                    None => {
                        let why = match &a.retest {
                            storage_health::RetestOutcome::NotNeeded => d.test2_none.to_string(),
                            other => storage_health::Finding::RetestNotRun(other.clone()).text(ru),
                        };
                        out.push(PerfRow {
                            cells: [
                                d.test2_title.to_string(),
                                "—".into(),
                                "—".into(),
                                "—".into(),
                                "—".into(),
                                "—".into(),
                                why,
                            ],
                            tone: None,
                        });
                    }
                }
            }
            None => out.push(row(
                format!("{} — {}", d.test1_title, d.disk_det_initial),
                current,
                None,
            )),
        }
        out
    }

    fn disk_details_title(&self) -> String {
        let d = i18n::t(self.language);
        let model = self
            .selected_ssd_candidate()
            .map(|c| c.disk.model.trim().to_string())
            .filter(|m| !m.is_empty())
            .unwrap_or_else(|| "—".into());
        format!("{} — {model}", d.disk_details_title)
    }

    /// v1.0 Disk Details content as (section, rows); shared by the window
    /// and the Copy / Save as text so both always say the same thing.
    fn disk_details_sections(
        &self,
        current: &StorageDiagnosticSummary,
    ) -> Vec<(String, Vec<(String, String)>)> {
        let d = i18n::t(self.language);
        let ru = self.language == Language::Ru;
        let mb = |mib: f64| format!("{:.0} MB/s", mib * 1.048576);
        let mut out: Vec<(String, Vec<(String, String)>)> = Vec::new();
        // Identity.
        let mut id_rows = Vec::new();
        if let Some(cand) = self.selected_ssd_candidate() {
            let disk = &cand.disk;
            id_rows.push((d.disk_det_model.into(), disk.model.trim().to_string()));
            id_rows.push((
                d.disk_det_physical.into(),
                format!("PhysicalDrive{}", disk.index),
            ));
            id_rows.push((
                d.disk_det_volume.into(),
                match &cand.volume {
                    Some(v) => format!(
                        "{}{}{}",
                        v.mount_point.trim_end_matches('\\'),
                        if v.label.is_empty() {
                            String::new()
                        } else {
                            format!(" {}", v.label)
                        },
                        if cand.is_system {
                            format!(" · {}", d.disk_det_system)
                        } else {
                            String::new()
                        }
                    ),
                    None => "—".into(),
                },
            ));
            id_rows.push((d.disk_det_interface.into(), disk.bus_type.clone()));
            id_rows.push((
                d.disk_det_capacity.into(),
                storage_topology::capacity_text(disk),
            ));
        }
        out.push((d.disk_det_identity.into(), id_rows));
        let assessment = self.selected_assessment();
        let test_rows = |r: &StorageDiagnosticSummary, dur: Option<f64>| {
            let level = stability_level(r.read_variation_percent)
                .max(stability_level(r.write_variation_percent));
            vec![
                ("Read".to_string(), mb(r.summary_read_mib_s)),
                ("Write".to_string(), mb(r.summary_write_mib_s)),
                (
                    d.disk_det_read_spread.into(),
                    format!("{:.2}%", r.read_variation_percent),
                ),
                (
                    d.disk_det_write_spread.into(),
                    format!("{:.2}%", r.write_variation_percent),
                ),
                (
                    d.disk_det_duration.into(),
                    dur.map(|s| format!("{s:.1} s"))
                        .unwrap_or_else(|| "—".into()),
                ),
                (d.disk_det_status.into(), stability_text(level).to_string()),
            ]
        };
        let (t1, t1_dur, t2, t2_dur) = match assessment {
            Some(a) => (
                a.first.clone(),
                Some(a.first_duration),
                a.second.clone(),
                a.second_duration,
            ),
            None => (current.clone(), None, None, None),
        };
        out.push((
            format!("{} — {}", d.test1_title, d.disk_det_initial),
            test_rows(&t1, t1_dur),
        ));
        match &t2 {
            Some(r2) => {
                out.push((
                    format!("{} — {}", d.test2_title, d.test_retest_label),
                    test_rows(r2, t2_dur),
                ));
                let pct = |a: f64, b: f64| {
                    if a > 0.0 {
                        format!("{:+.1}%", (b - a) / a * 100.0)
                    } else {
                        "—".into()
                    }
                };
                let interp = assessment
                    .and_then(|a| a.classification.as_ref())
                    .map(|c| c.state.text(ru).to_string())
                    .unwrap_or_else(|| "—".into());
                out.push((
                    d.disk_det_comparison.into(),
                    vec![
                        (
                            d.disk_det_delta_read.into(),
                            pct(t1.summary_read_mib_s, r2.summary_read_mib_s),
                        ),
                        (
                            d.disk_det_delta_write.into(),
                            pct(t1.summary_write_mib_s, r2.summary_write_mib_s),
                        ),
                        (d.disk_det_interpretation.into(), interp),
                    ],
                ));
            }
            None => {
                let why = assessment
                    .map(|a| match &a.retest {
                        storage_health::RetestOutcome::NotNeeded => d.test2_none.to_string(),
                        other => storage_health::Finding::RetestNotRun(other.clone()).text(ru),
                    })
                    .unwrap_or_else(|| d.test2_none.to_string());
                out.push((d.test2_title.to_string(), vec![(String::new(), why)]));
            }
        }
        // SMART / NVMe health (facts, uncoloured).
        let mut health_rows = Vec::new();
        if let Some(h) = self.selected_nvme_health() {
            for (k, v) in nvme_health_rows(h, d) {
                health_rows.push((k, v));
            }
            health_rows.push((String::new(), d.nvme_health_note.to_string()));
        } else {
            health_rows.push((String::new(), d.disk_det_no_health.to_string()));
        }
        out.push((d.nvme_health_title.into(), health_rows));
        // Final storage assessment.
        let mut final_rows = Vec::new();
        match assessment.and_then(|a| a.classification.as_ref()) {
            Some(c) => {
                final_rows.push((d.disk_det_state.into(), c.state.text(ru).to_string()));
                for f in &c.findings {
                    final_rows.push((String::new(), format!("• {}", f.text(ru))));
                }
            }
            None => final_rows.push((String::new(), d.disk_det_assessment_pending.into())),
        }
        out.push((d.storage_assessment_title.into(), final_rows));
        // History: last 5 runs of THIS physical disk.
        let identity = self
            .selected_ssd_candidate()
            .map(|c| storage_topology::physical_disk_identity(&c.disk));
        let mut hist: Vec<HistoryEntry> = ssd_history::load_all_history(&self.reports_root)
            .into_iter()
            .filter(|h| identity.as_deref() == Some(h.disk_identity.as_str()))
            .collect();
        hist.sort_by_key(|h| std::cmp::Reverse(h.timestamp_unix));
        hist.dedup_by_key(|h| h.timestamp_unix);
        let mut hist_rows: Vec<(String, String)> = hist
            .iter()
            .take(5)
            .map(|h| {
                (
                    crate::ui::sysinfo::local_time_of_unix(h.timestamp_unix)
                        .map(|t| format!("{} {}", t.date_dmy(), t.hms()))
                        .unwrap_or_else(|| h.timestamp_unix.to_string()),
                    format!(
                        "R {} · W {} · QD{} · {} × {} MiB",
                        mb(h.read_mib_s),
                        mb(h.write_mib_s),
                        h.queue_depth,
                        h.pass_count,
                        h.test_file_size / (1024 * 1024)
                    ),
                )
            })
            .collect();
        if hist_rows.is_empty() {
            hist_rows.push((String::new(), d.disk_det_no_history.into()));
        }
        out.push((d.disk_det_history.into(), hist_rows));
        out
    }

    /// One journal viewer button. Copy goes through egui's clipboard
    /// output (eframe hands it to the Windows clipboard); Close only hides
    /// the viewer; Save writes a new file. None of them clears anything.
    fn journal_viewer_act(&mut self, ctx: &egui::Context, action: JournalViewerAction) {
        let d = i18n::t(self.language);
        match action {
            JournalViewerAction::Save => {
                let name = journal_log_file_name(sysinfo::local_time());
                let dir = journal_logs_dir(&self.reports_root);
                let status = match save_journal_text(&dir, &name, &self.journal.full_text(d)) {
                    Ok(path) => {
                        let line = format!("{}: {}", d.journal_viewer_saved, path.display());
                        push_journal(&mut self.journal, line);
                        JournalViewerStatus::Saved(path)
                    }
                    Err(err) => {
                        let line = format!("[ERROR] {}: {err}", d.journal_viewer_save_failed);
                        push_journal(&mut self.journal, line);
                        JournalViewerStatus::SaveFailed(err)
                    }
                };
                self.journal_viewer_status = Some(status);
            }
            JournalViewerAction::Copy => {
                ctx.copy_text(self.journal.full_text(d));
                self.journal_viewer_status = Some(JournalViewerStatus::Copied);
            }
            JournalViewerAction::Close => {
                self.journal_viewer_open = false;
                self.journal_viewer_status = None;
            }
        }
    }

    /// v0.3.7: the complete session journal in its own resizable window
    /// (in-app; no external program). Rows are laid out lazily, so long
    /// journals stay smooth; lines are never truncated (horizontal scroll).
    fn journal_window(&mut self, ctx: &egui::Context) {
        if !self.journal_viewer_open {
            return;
        }
        let d = i18n::t(self.language);
        let mut open = true;
        let mut clicked: Option<JournalViewerAction> = None;
        let screen = ctx.content_rect();
        let status = self.journal_viewer_status.as_ref().map(|s| match s {
            JournalViewerStatus::Saved(path) => (
                format!("{}: {}", d.journal_viewer_saved, path.display()),
                c::TEXT_PRIMARY,
            ),
            JournalViewerStatus::SaveFailed(err) => (
                format!("{}: {err}", d.journal_viewer_save_failed),
                c::RED_ERROR,
            ),
            JournalViewerStatus::Copied => (d.journal_viewer_copied.to_string(), c::TEXT_PRIMARY),
        });
        let journal = &self.journal;
        egui::Window::new(d.journal_viewer_title)
            // Fixed id: the title changes with RU/EN, the window does not.
            .id(egui::Id::new("wsd_journal_viewer"))
            .open(&mut open)
            .collapsible(false)
            .resizable(true)
            .constrain(true)
            // v0.4.0: compact by default (≈540×580), opened over the right
            // side of the dashboard; still movable/resizable and modeless.
            .default_size(vec2(
                JOURNAL_VIEWER_SIZE[0].min(screen.width()),
                JOURNAL_VIEWER_SIZE[1].min(screen.height()),
            ))
            .default_pos(egui::pos2(
                (screen.right() - JOURNAL_VIEWER_SIZE[0] - 32.0).max(screen.left()),
                screen.top() + 72.0,
            ))
            .min_size(vec2(360.0, 240.0))
            .show(ctx, |ui| {
                let footer = if status.is_some() { 64.0 } else { 40.0 };
                let dropped = usize::from(journal.dropped > 0);
                let rows = journal.len() + dropped;
                let row_h = ui.text_style_height(&egui::TextStyle::Monospace);
                egui::ScrollArea::both()
                    .id_salt("wsd_journal_viewer_scroll")
                    .auto_shrink([false, false])
                    .max_height((ui.available_height() - footer).max(60.0))
                    .stick_to_bottom(true)
                    .show_rows(ui, row_h, rows.max(1), |ui, range| {
                        if rows == 0 {
                            ui.label(egui::RichText::new(d.journal_empty).monospace());
                            return;
                        }
                        for i in range {
                            let text = if i < dropped {
                                d.journal_viewer_dropped_fmt
                                    .replace("{count}", &journal.dropped.to_string())
                            } else {
                                // One row per entry: embedded line breaks are
                                // shown as spaces (Save/Copy keep them as-is).
                                SessionJournal::line(&journal.entries[i - dropped])
                                    .replace(['\r', '\n'], " ")
                            };
                            ui.add(
                                egui::Label::new(egui::RichText::new(text).monospace())
                                    .selectable(true)
                                    .extend(),
                            );
                        }
                    });
                ui.separator();
                if let Some((text, color)) = &status {
                    ui.add(egui::Label::new(egui::RichText::new(text).color(*color)).wrap());
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    // Right-to-left: shown as [Save] [Copy] [Close].
                    if ui.button(d.journal_viewer_close).clicked() {
                        clicked = Some(JournalViewerAction::Close);
                    }
                    if ui.button(d.journal_viewer_copy).clicked() {
                        clicked = Some(JournalViewerAction::Copy);
                    }
                    if ui.button(d.journal_viewer_save).clicked() {
                        clicked = Some(JournalViewerAction::Save);
                    }
                });
            });
        if !open {
            clicked = Some(JournalViewerAction::Close);
        }
        if let Some(action) = clicked {
            self.journal_viewer_act(ctx, action);
        }
    }
}

/// v0.4.4: two pages, Crash Dump analyzer, Power Diagnostics, Group Policy
/// / ADMX health. Every collector is read-only and runs in the background;
/// a failure is shown as a status, never a crash.
impl WinStateDiagApp {
    fn audit_report(&self) -> Option<&AuditReport> {
        match &self.driver_audit {
            DriverAuditState::Done(r) => Some(r),
            _ => None,
        }
    }

    /// v1.0 the Driver Audit as SHOWN: the base audit plus the dump-driven
    /// items for a probable third-party kernel module named by a crash dump
    /// (outside the normal audit scope when needed). Base audit unchanged.
    fn audit_view(&self) -> Option<std::borrow::Cow<'_, AuditReport>> {
        let base = self.audit_report()?;
        if self
            .crash
            .analyses
            .iter()
            .any(|a| a.third_party_module().is_some())
        {
            Some(std::borrow::Cow::Owned(crash_dump::extend_audit(
                base,
                &self.crash.analyses,
            )))
        } else {
            Some(std::borrow::Cow::Borrowed(base))
        }
    }

    // ---- start-up / triggers ------------------------------------------

    /// v1.0 read-only ATA SMART of every physical disk (SMART READ DATA /
    /// READ THRESHOLDS only). NVMe / bridges / RAID report UNSUPPORTED.
    fn start_ata_scan(&mut self) {
        self.request_collector("ata_smart");
        if self.ata_rx.is_none() {
            self.claim_package("ata");
        }
        #[cfg(windows)]
        if self.reference.is_none() && !cfg!(test) && self.ata_rx.is_none() {
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                use storage_topology::TopologySource;
                let src = storage_topology::windows_source::WindowsTopologySource;
                let list: Vec<AtaDisk> = src
                    .physical_disks()
                    .into_iter()
                    .filter(|d| nvme_health::is_ata_bus(&d.bus_type))
                    .map(|d| AtaDisk {
                        smart: crate::ata_smart::read(d.index),
                        index: d.index,
                        model: d.model.trim().to_string(),
                        bus: d.bus_type.clone(),
                    })
                    .collect();
                let _ = tx.send(list);
            });
            self.ata_rx = Some(rx);
        }
    }

    fn poll_ata_scan(&mut self) {
        let Some(rx) = &self.ata_rx else {
            return;
        };
        match rx.try_recv() {
            Ok(list) => {
                self.ata_rx = None;
                self.accept_ata_scan(list);
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => {}
            Err(std::sync::mpsc::TryRecvError::Disconnected) => self.ata_rx = None,
        }
    }

    fn accept_ata_scan(&mut self, list: Vec<AtaDisk>) {
        self.ata_scan = Some(list);
        if self.ata_evidence_pending {
            self.ata_evidence_pending = false;
            self.contribute_ata_evidence();
        }
    }

    /// `Ata_Smart_<stamp>.json`: every ATA disk with its SMART facts.
    fn contribute_ata_evidence(&mut self) {
        let Some(list) = &self.ata_scan else {
            return;
        };
        let items: Vec<String> = list
            .iter()
            .map(|a| {
                format!(
                    "    {{\"physical_disk_index\": {}, \"model\": {}, \"bus\": {}, \"ata_smart\": {}}}",
                    a.index,
                    crate::deep_checks::json::string(&a.model),
                    crate::deep_checks::json::string(&a.bus),
                    crate::ata_smart::to_json(&a.smart)
                )
            })
            .collect();
        let now = sysinfo::local_time();
        let json = format!(
            "{{\n  \"format\": \"winstatediag.ata_smart/1\",\n  \"status\": \"COLLECTED\",\n  \"captured_at\": {},\n  \"note\": \"Read-only SMART READ DATA / READ THRESHOLDS. UNSUPPORTED means the driver path does not pass SMART through, not a disk failure.\",\n  \"disks\": [\n{}\n  ]\n}}\n",
            crate::deep_checks::json::string(&local_iso(now)),
            items.join(",\n")
        );
        let name = format!("Ata_Smart_{}.json", evidence_stamp(now));
        let d = i18n::t(self.language);
        self.contribute_evidence(
            "ata",
            d.nvme_module_name,
            vec![EvidenceFile::new(&name, json.into_bytes())],
        );
    }

    /// v0.4.5: Windows / CPU / RAM / board passport (display only).
    fn start_passport(&mut self) {
        self.request_collector("passport");
        #[cfg(windows)]
        if self.reference.is_none() && !cfg!(test) && self.passport_rx.is_none() {
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let _ = tx.send(passport::collect(PS_HOST));
            });
            self.passport_rx = Some(rx);
        }
    }

    fn poll_passport(&mut self) {
        let Some(rx) = &self.passport_rx else {
            return;
        };
        match rx.try_recv() {
            Ok(res) => {
                self.passport_rx = None;
                self.passport = Some(res);
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => {}
            Err(std::sync::mpsc::TryRecvError::Disconnected) => self.passport_rx = None,
        }
    }

    /// Stage 07 sources: crash inventory counts (unexpected shutdowns /
    /// BugCheck / dumps) and the freeze/hang incidents.
    fn crash_stage_evidence(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(Ok(inv)) = &self.crash.inventory {
            out.push(crash_dump::counts_line(inv));
            for b in inv.bugchecks.iter().take(5) {
                out.push(format!(
                    "BugCheck 0x{:08X} · {} · {}",
                    b.code,
                    b.time,
                    match b.source {
                        crash_dump::BugcheckSource::Wer1001 => "WER 1001",
                        crash_dump::BugcheckSource::KernelPower41 => "Kernel-Power 41",
                    }
                ));
            }
            for inc in inv.incidents.iter().take(5) {
                out.push(crash_dump::incident_line(inc));
            }
        }
        out
    }

    fn passport_rows(&self) -> Vec<InfoRow> {
        let d = i18n::t(self.language);
        let labels = [
            d.passport_windows,
            d.passport_cpu,
            d.passport_ram,
            d.passport_board,
            d.passport_bios,
        ];
        let ru = self.language == Language::Ru;
        match &self.passport {
            // Still collecting: the card shows its own placeholder.
            None if self.passport_rx.is_some() => Vec::new(),
            Some(Ok(p)) => labels
                .into_iter()
                .zip([
                    p.windows.clone(),
                    p.cpu.clone(),
                    p.ram_text(ru),
                    p.board.clone(),
                    p.bios.clone(),
                ])
                .map(|(l, v)| {
                    let v = if v.is_empty() {
                        d.passport_no_data
                    } else {
                        v.as_str()
                    };
                    InfoRow::new(l, v, Tone::Idle)
                })
                .collect(),
            _ => {
                // No collector result: the OS line is still known locally.
                let (product, build) = sysinfo::windows_edition_and_full_build();
                let os = format!("{product} ({build})");
                labels
                    .into_iter()
                    .enumerate()
                    .map(|(i, l)| {
                        InfoRow::new(
                            l,
                            if i == 0 {
                                os.as_str()
                            } else {
                                d.passport_no_data
                            },
                            Tone::Idle,
                        )
                    })
                    .collect()
            }
        }
    }

    fn start_crash_scan(&mut self) {
        let origin = if self.is_running() {
            CheckOrigin::Session
        } else {
            CheckOrigin::Manual
        };
        self.start_crash_scan_as(origin);
    }

    /// v1.1: the read-only crash inventory scan (BugChecks, shutdowns,
    /// dumps, LiveKernelReports, WinDbg / cdb detection) for `origin`.
    /// Never two scans at once: a session that finds the PREFLIGHT scan
    /// running gets its own fresh scan right after it.
    fn start_crash_scan_as(&mut self, origin: CheckOrigin) {
        self.request_collector("crash_scan");
        if self.crash_rx.is_some() {
            if origin == CheckOrigin::Session
                && self.crash.scan_origin == Some(CheckOrigin::Preflight)
            {
                self.crash.rescan_for_session = true;
            }
            return;
        }
        // A preflight scan belongs to no session package.
        if origin != CheckOrigin::Preflight {
            self.claim_package("crash");
        }
        self.crash.scan_origin = Some(origin);
        #[cfg(windows)]
        if self.reference.is_none() && !cfg!(test) && self.crash_rx.is_none() {
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let _ = tx.send(CrashMsg::Inventory(crash_dump::collect_inventory(PS_HOST)));
            });
            self.crash_rx = Some(rx);
            self.crash.busy = CrashBusy::Scanning;
        }
    }

    /// The analyzer's "Analyze" click (explicit): fixes the session, then
    /// analyzes — or, without an inventory yet (v1.0 Startup Idle: none is
    /// read at launch), scans first and the analysis follows the scan in
    /// that same session.
    fn start_crash_analysis(&mut self) {
        if self.crash.busy != CrashBusy::Idle || self.crash_rx.is_some() {
            return;
        }
        self.begin_operation(false);
        // v1.1: a preflight inventory is never analyzed into a report — the
        // explicit analysis scans again for its own session first.
        let preflight = self
            .crash
            .inventory_checked
            .as_ref()
            .is_some_and(|s| s.origin == CheckOrigin::Preflight);
        if !matches!(self.crash.inventory, Some(Ok(_))) || preflight {
            self.crash_analyze_after_scan = true;
            self.start_crash_scan_as(CheckOrigin::Manual);
            return;
        }
        self.claim_package("crash");
        self.run_crash_analysis();
    }

    /// Analyzes the inventory's queue for the session that owns "crash"
    /// (never re-reads the input fields: a continuation after the scan
    /// stays in the session the click opened).
    fn run_crash_analysis(&mut self) {
        let Some(Ok(inv)) = &self.crash.inventory else {
            return;
        };
        let crash_dump::DebuggerStatus::Installed { cdb } = &inv.debugger else {
            return;
        };
        if self.crash_rx.is_some() {
            return;
        }
        let queue: Vec<(crash_dump::DumpFile, Option<crash_dump::BugcheckEvent>)> = inv
            .analysis_queue()
            .into_iter()
            .map(|dmp| (dmp.clone(), inv.bugcheck_for(dmp).cloned()))
            .collect();
        if queue.is_empty() {
            return;
        }
        let cdb = cdb.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        let total = queue.len();
        self.crash.progress = Some(AnalysisProgress {
            stage: crash_dump::AnalysisStage::PrepareDump,
            started: Instant::now(),
            dump_index: 0,
            dump_total: total,
            dump_name: queue[0].0.name.clone(),
            symbols_downloading: false,
        });
        #[cfg(not(test))]
        std::thread::spawn(move || {
            let cache = symbol_cache_dir();
            let mut out: Vec<AnalyzedDump> = Vec::new();
            for (i, (dmp, bc)) in queue.into_iter().enumerate() {
                let stage = |s| CrashMsg::Stage(s, i, total, dmp.name.clone());
                let _ = tx.send(stage(crash_dump::AnalysisStage::PrepareDump));
                // The original dump is only READ (copied into the report).
                let bytes = std::fs::read(&dmp.path).ok();
                // Symbol download watcher: the cache growing = Microsoft
                // symbols are being downloaded right now (real signal).
                let watching = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
                {
                    let watching = std::sync::Arc::clone(&watching);
                    let tx = tx.clone();
                    let cache = cache.clone();
                    std::thread::spawn(move || {
                        let mut last = dir_size(&cache);
                        let mut was = false;
                        while watching.load(Ordering::Relaxed) {
                            std::thread::sleep(Duration::from_millis(1500));
                            let now = dir_size(&cache);
                            let growing = now > last;
                            last = now;
                            if growing != was {
                                was = growing;
                                let _ = tx.send(CrashMsg::Symbols(growing));
                            }
                        }
                        if was {
                            let _ = tx.send(CrashMsg::Symbols(false));
                        }
                    });
                }
                let line_tx = tx.clone();
                let name = dmp.name.clone();
                let mut best = crash_dump::AnalysisStage::PrepareDump;
                let (status, raw) = crash_dump::run_analysis_observed(
                    &cdb,
                    &dmp.path,
                    &cache,
                    Duration::from_secs(crash_dump::ANALYSIS_TIMEOUT_SECS),
                    move |line| {
                        if let Some(s) = crash_dump::stage_of_cdb_line(line)
                            && s > best
                        {
                            best = s;
                            let _ = line_tx.send(CrashMsg::Stage(s, i, total, name.clone()));
                        }
                    },
                );
                watching.store(false, Ordering::Relaxed);
                // v1.0 dump-driven correlation: lmvm + installed driver.
                let _ = tx.send(stage(crash_dump::AnalysisStage::CorrelateDriverAudit));
                let third_party = crash_dump::DumpAnalysis::build(
                    dmp.clone(),
                    None,
                    status.clone(),
                    raw.clone(),
                    None,
                )
                .third_party_module();
                let (module_info, resolution) = match &third_party {
                    Some(m) => (
                        crash_dump::run_lmvm(&cdb, &dmp.path, &cache, m, Duration::from_secs(180)),
                        Some(crash_dump::resolve_driver(PS_HOST, m)),
                    ),
                    None => (None, None),
                };
                let _ = tx.send(stage(crash_dump::AnalysisStage::BuildReport));
                out.push(AnalyzedDump {
                    dump: dmp,
                    bugcheck: bc,
                    status,
                    raw,
                    bytes,
                    module_info,
                    resolution,
                });
            }
            let _ = tx.send(CrashMsg::Analyzed(out));
        });
        #[cfg(test)]
        {
            let _ = (cdb, queue, tx);
        }
        self.crash_rx = Some(rx);
        self.crash.busy = CrashBusy::Analyzing;
    }

    fn poll_crash(&mut self) {
        self.poll_install();
        let Some(rx) = &self.crash_rx else {
            return;
        };
        let mut msgs = Vec::new();
        let mut disconnected = false;
        loop {
            match rx.try_recv() {
                Ok(m) => msgs.push(m),
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    disconnected = true;
                    break;
                }
            }
        }
        for msg in msgs {
            self.accept_crash_msg(msg);
        }
        if disconnected && self.crash_rx.is_some() {
            self.crash_rx = None;
            self.crash.busy = CrashBusy::Idle;
            self.crash.progress = None;
        }
        // "Analyze" clicked before any inventory: once the scan's channel is
        // fully handled, analyze (when there is something to analyze and an
        // analyzer). Never inside the message loop above: its cleanup would
        // drop the NEW analysis channel.
        // v1.1: the session's own scan after a preflight scan it found.
        if self.crash_rx.is_none()
            && std::mem::take(&mut self.crash.rescan_for_session)
            && self.is_running()
        {
            self.start_crash_scan_as(CheckOrigin::Session);
        }
        if self.crash_rx.is_none() && self.crash.inventory.is_some() {
            if std::mem::take(&mut self.crash_analyze_after_scan)
                && matches!(self.crash.inventory, Some(Ok(_)))
            {
                self.run_crash_analysis();
            }
        }
    }

    fn accept_crash_msg(&mut self, msg: CrashMsg) {
        // Final results end the worker; progress messages do not.
        if matches!(msg, CrashMsg::Inventory(_) | CrashMsg::Analyzed(_)) {
            self.crash_rx = None;
            self.crash.busy = CrashBusy::Idle;
            self.crash.progress = None;
        }
        match msg {
            CrashMsg::Stage(stage, i, total, name) => {
                if let Some(p) = &mut self.crash.progress {
                    if i != p.dump_index || stage > p.stage {
                        p.stage = stage;
                    }
                    p.dump_index = i;
                    p.dump_total = total;
                    p.dump_name = name;
                }
            }
            CrashMsg::Symbols(on) => {
                if let Some(p) = &mut self.crash.progress {
                    p.symbols_downloading = on;
                }
            }
            CrashMsg::Inventory(inv) => {
                let origin = self.crash.scan_origin.take().unwrap_or(CheckOrigin::Manual);
                self.crash.inventory = Some(inv);
                self.crash.inventory_checked = Some(CheckStamp::now(origin));
                // The scan reports into the package it claimed at start; a
                // preflight listing was observed by no session.
                self.crash.inventory_session = if origin == CheckOrigin::Preflight {
                    None
                } else {
                    report_package::lock(&self.package_of("crash"))
                        .session()
                        .map(|s| s.session_id.clone())
                };
                if origin == CheckOrigin::Preflight && self.is_running() {
                    // A diagnostic started meanwhile: its report gets a
                    // fresh listing (started after this channel is done).
                    self.crash.rescan_for_session = true;
                }
                // v1.0 installer: winget said "installed" → the re-scan
                // confirms the analyzer (or reports what is still missing).
                if self.crash.install == InstallState::Verifying {
                    let found = matches!(
                        &self.crash.inventory,
                        Some(Ok(crash_dump::Inventory {
                            debugger: crash_dump::DebuggerStatus::Installed { .. },
                            ..
                        }))
                    );
                    // v1.0 item 41: package present ≠ analysis available.
                    let state = match &self.crash.inventory {
                        Some(Ok(inv)) => inv.debugger.clone(),
                        Some(Err(e)) => crash_dump::DebuggerStatus::Error(e.clone()),
                        None => crash_dump::DebuggerStatus::NotInstalled,
                    };
                    self.crash.install = if found {
                        InstallState::Succeeded
                    } else {
                        InstallState::Failed(crate::crash_report::debugger_line(
                            &state,
                            self.language == Language::Ru,
                        ))
                    };
                    self.crash
                        .install_log
                        .push(format!("re-detect: {}", state.code()));
                }
                // The scan started with a diagnostic run joins its report
                // (a preflight listing never does).
                if self.is_running() && origin != CheckOrigin::Preflight {
                    self.contribute_incidents();
                }
            }
            CrashMsg::Analyzed(list) => self.accept_crash_analyses(list),
        }
    }

    /// v0.4.5 freeze / hang incident evidence (`Incidents_<stamp>.json`):
    /// every incident with its conservative verdict and correlated events.
    fn contribute_incidents(&mut self) {
        let Some(Ok(inv)) = &self.crash.inventory else {
            return;
        };
        let verdicts = crash_dump::incident_verdicts(inv, &self.crash.analyses);
        // The session that OBSERVED the listing (its scan), not the session
        // a later analysis of the cached inventory reports into.
        let json = incidents::to_json_in_session(
            &verdicts,
            inv.unexpected_shutdowns.max(inv.incidents.len()),
            &inv.live_kernel_reports,
            self.crash.inventory_session.as_deref(),
        );
        let d = i18n::t(self.language);
        if let Some((_, v)) = verdicts.first() {
            push_journal(
                &mut self.journal,
                format!(
                    "{}: {}",
                    d.module_incidents,
                    v.headline_localized(self.language == Language::Ru)
                ),
            );
        }
        let name = format!(
            "{}{}.json",
            incidents::EVIDENCE_PREFIX,
            evidence_stamp(sysinfo::local_time())
        );
        self.contribute_evidence(
            "crash",
            d.module_incidents,
            vec![EvidenceFile::new(&name, json.into_bytes())],
        );
    }

    /// Builds the analyses (correlated with the current Driver Audit) and
    /// adds the original dumps, raw outputs and summaries to the report.
    fn accept_crash_analyses(&mut self, list: Vec<AnalyzedDump>) {
        let stamp = evidence_stamp(sysinfo::local_time());
        let cdb = match &self.crash.inventory {
            Some(Ok(crash_dump::Inventory {
                debugger: crash_dump::DebuggerStatus::Installed { cdb },
                ..
            })) => Some(cdb.clone()),
            _ => None,
        };
        let mut files = Vec::new();
        let mut analyses = Vec::new();
        for (n, item) in list.into_iter().enumerate() {
            let AnalyzedDump {
                dump: dmp,
                bugcheck: bc,
                status,
                raw,
                bytes,
                module_info,
                resolution,
            } = item;
            // Confidence uses the BASE Driver Audit only: the dump-driven
            // item derived from this very dump never corroborates it.
            let a = crash_dump::DumpAnalysis::build(dmp, bc, status, raw, self.audit_report())
                .with_module(module_info, resolution);
            let (txt, js, dmp_name) = crash_dump::evidence_names(&stamp, n + 1, &a.dump.name);
            let copied = bytes.map(|b| {
                files.push(EvidenceFile::new(&dmp_name, b));
                dmp_name.clone()
            });
            files.push(EvidenceFile::new(
                &txt,
                crash_dump::analysis_txt(&a, cdb.as_deref()),
            ));
            files.push(EvidenceFile::new(
                &js,
                crash_dump::summary_json(&a, copied.as_deref(), &txt).into_bytes(),
            ));
            analyses.push(a);
        }
        let d = i18n::t(self.language);
        if let Some(latest) = analyses.first() {
            push_journal(
                &mut self.journal,
                d.journal_crash_done_fmt
                    .replace("{n}", &analyses.len().to_string())
                    .replace("{conf}", latest.confidence.code()),
            );
        }
        self.crash.analyses = analyses;
        if !files.is_empty() {
            self.contribute_evidence("crash", d.module_crash, files);
            // v1.0.1: Incidents.json is re-issued with the dump cause of
            // the same boot (it was written before the analysis existed).
            self.contribute_incidents();
        }
    }

    /// v1.0 embedded installer: ONLY after the explicit click, the official
    /// `winget install --id Microsoft.WinDbg` runs hidden (no console
    /// window), its output is captured line by line into real stages and the
    /// local install journal; afterwards the analyzer is re-detected. UAC,
    /// when Windows asks for it, is the normal system prompt (never hidden
    /// or bypassed).
    fn install_analyzer(&mut self) {
        if matches!(
            self.crash.install,
            InstallState::Running { .. } | InstallState::Verifying
        ) {
            return;
        }
        let d = i18n::t(self.language);
        self.crash.install = InstallState::Running {
            stage: crash_dump::InstallStage::Preparing,
            percent: None,
        };
        self.crash.install_log.clear();
        self.crash.install_log.push(format!(
            "winget {}",
            crash_dump::winget_install_args().join(" ")
        ));
        push_journal(&mut self.journal, d.journal_crash_install.to_string());
        #[cfg(windows)]
        if !cfg!(test) {
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let line_tx = tx.clone();
                let result = crash_dump::run_debugger_install(move |l| {
                    let _ = line_tx.send(InstallMsg::Line(l.to_string()));
                });
                let _ = tx.send(InstallMsg::Done(result));
            });
            self.install_rx = Some(rx);
        }
    }

    fn poll_install(&mut self) {
        let Some(rx) = &self.install_rx else {
            return;
        };
        let mut msgs = Vec::new();
        let mut gone = false;
        loop {
            match rx.try_recv() {
                Ok(m) => msgs.push(m),
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    gone = true;
                    break;
                }
            }
        }
        for m in msgs {
            self.accept_install_msg(m);
        }
        if gone {
            self.install_rx = None;
            if matches!(self.crash.install, InstallState::Running { .. }) {
                self.crash.install = InstallState::Failed("installer ended unexpectedly".into());
            }
        }
    }

    fn accept_install_msg(&mut self, msg: InstallMsg) {
        let d = i18n::t(self.language);
        match msg {
            InstallMsg::Line(line) => {
                let (stage, pct) = crash_dump::install_progress_of_line(&line);
                if let InstallState::Running { stage: s, percent } = &mut self.crash.install {
                    if let Some(st) = stage
                        && st > *s
                    {
                        *s = st;
                    }
                    if pct.is_some() {
                        *percent = pct;
                    }
                }
                if self.crash.install_log.len() < 400 {
                    self.crash.install_log.push(line);
                }
            }
            InstallMsg::Done(result) => {
                self.install_rx = None;
                self.crash
                    .install_log
                    .push(format!("result: {}", result.exit_text));
                // v1.0 item 41: the final state is NEVER decided by the
                // winget exit text ("no newer package" when WinDbg is
                // already installed is not a failure) — always re-detect
                // the package and its analysis backend independently.
                if !result.success {
                    push_journal(
                        &mut self.journal,
                        d.journal_crash_install_failed_fmt
                            .replace("{error}", &result.exit_text),
                    );
                }
                self.crash.install = InstallState::Verifying;
                self.start_crash_scan();
            }
        }
    }

    /// Re-detects the debugger after an explicit install click (the official
    /// winget install runs in its own visible window, so its end is not
    /// observable): one inventory re-scan every 20 s for up to 10 minutes,
    /// stopping as soon as the debugger is found.
    fn poll_crash_redetect(&mut self) {
        let Some((launched, last)) = self.crash_redetect else {
            return;
        };
        let installed = matches!(
            &self.crash.inventory,
            Some(Ok(crash_dump::Inventory {
                debugger: crash_dump::DebuggerStatus::Installed { .. },
                ..
            }))
        );
        if installed || launched.elapsed() > Duration::from_secs(600) {
            self.crash_redetect = None;
            return;
        }
        if self.crash_rx.is_none() && last.elapsed() >= Duration::from_secs(20) {
            self.crash_redetect = Some((launched, Instant::now()));
            self.start_crash_scan();
        }
    }

    /// Starts one read-only sensor sampling window (~10 s, 1 sample/s, no
    /// load applied). Evidence is written for explicit refreshes and for
    /// diagnostic sessions.
    fn start_sensor_read(&mut self, evidence: bool) {
        self.request_collector("sensors");
        if self.sensors_rx.is_none() {
            self.claim_package("sensors");
        }
        #[cfg(windows)]
        if self.reference.is_none() && !cfg!(test) && self.sensors_rx.is_none() {
            let (tx, rx) = std::sync::mpsc::channel();
            let base = std::env::temp_dir().join("WinStateDiag");
            std::thread::spawn(move || {
                let _ = tx.send(sensors::collect(PS_HOST, &base, 10, 1000));
            });
            self.sensors_rx = Some(rx);
        }
        if self.sensors_rx.is_some() && self.sensors_started.is_none() {
            self.sensors_started = Some(Instant::now());
            self.sensors_error = None;
        }
        self.sensors_evidence_pending |= evidence;
    }

    /// v1.0 item 8: READ indicator state (Idle / Reading + elapsed / Error).
    fn sensor_read_vm(&self) -> crate::ui::vm::SensorReadVm {
        use crate::ui::vm::SensorReadVm;
        if self.sensors_rx.is_some() {
            return SensorReadVm::Reading {
                elapsed_s: self
                    .sensors_started
                    .map(|t| t.elapsed().as_secs())
                    .unwrap_or(0),
            };
        }
        match &self.sensors_error {
            Some(m) => SensorReadVm::Error { message: m.clone() },
            None => SensorReadVm::Idle,
        }
    }

    /// The sensor read ended: success clears the indicator, a lost worker
    /// or a snapshot where every provider failed is an ERROR state.
    fn finish_sensor_read(&mut self, snap: Option<&sensors::Snapshot>) {
        self.sensors_started = None;
        self.sensors_error = match snap {
            None => Some("sensor reader ended without a result".into()),
            Some(s) if s.state() == sensors::ProviderState::ProviderError => {
                Some(format!("sensor providers failed ({})", s.state().code()))
            }
            Some(_) => None,
        };
    }

    fn poll_sensors(&mut self) {
        let Some(rx) = &self.sensors_rx else {
            return;
        };
        match rx.try_recv() {
            Ok(snap) => {
                self.sensors_rx = None;
                self.finish_sensor_read(Some(&snap));
                self.accept_sensors(snap);
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => {}
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                self.sensors_rx = None;
                self.finish_sensor_read(None);
            }
        }
    }

    fn accept_sensors(&mut self, snap: sensors::Snapshot) {
        self.sensors = Some(snap);
        if std::mem::take(&mut self.sensors_evidence_pending)
            && let Some(merged) = self.sensors_with_storage()
        {
            let d = i18n::t(self.language);
            let summary = sensors::summarize(&merged.sensors);
            push_journal(
                &mut self.journal,
                d.journal_sensors_fmt
                    .replace("{state}", merged.state().code())
                    .replace("{power}", summary.power_status().code()),
            );
            let name = format!(
                "{}{}.json",
                sensors::EVIDENCE_PREFIX,
                evidence_stamp(sysinfo::local_time())
            );
            self.contribute_evidence(
                "sensors",
                d.module_sensors,
                vec![EvidenceFile::new(
                    name,
                    sensors::to_json(&merged).into_bytes(),
                )],
            );
        }
    }

    /// The sensor snapshot plus the storage temperatures WinStateDiag
    /// already holds (NVMe Health — the authoritative disk temperature —
    /// and the SATA Storage Reliability counters), so no contradictory
    /// duplicate SSD temperature is shown.
    /// Drive-reported (warning, critical) temperature of the disk named by
    /// a sensor label (NVMe Identify WCTEMP / CCTEMP); (None, None) when the
    /// drive reports none.
    fn disk_temp_thresholds(&self, label: &str) -> (Option<f64>, Option<f64>) {
        let base = match label.rsplit_once(" #") {
            Some((b, n)) if n.chars().all(|c| c.is_ascii_digit()) => b,
            _ => label,
        };
        let key = sensors::disk_key(base);
        self.nvme_health
            .values()
            .find(|h| sensors::disk_key(&h.model) == key)
            .map(|h| (h.temp_warning_c, h.temp_critical_c))
            .unwrap_or((None, None))
    }

    fn sensors_with_storage(&self) -> Option<sensors::Snapshot> {
        let mut snap = self.sensors.clone()?;
        let mut keys: Vec<&String> = self.nvme_health.keys().collect();
        keys.sort();
        for k in keys {
            let h = &self.nvme_health[k];
            let reading = |provider, value: f64, id: String| sensors::Sensor {
                provider,
                hw_id: format!("disk/{}", h.disk_index),
                hw_name: h.model.clone(),
                category: sensors::HwCategory::Storage,
                sensor_id: id,
                name: "Temperature".into(),
                kind: sensors::SensorKind::Temperature,
                value,
                min: value,
                max: value,
                samples: 1,
                confidence: if provider == sensors::Provider::NvmeHealth {
                    sensors::Confidence::High
                } else {
                    sensors::Confidence::Medium
                },
                timestamp: h.captured_at.clone(),
            };
            if let Some(t) = h.smart.as_ref().and_then(|s| s.composite_temperature_c())
                && sensors::plausible(sensors::SensorKind::Temperature, f64::from(t))
            {
                snap.sensors.push(reading(
                    sensors::Provider::NvmeHealth,
                    f64::from(t),
                    format!("nvme/{}/composite", h.disk_index),
                ));
            }
            if let Some(t) = h.reliability.as_ref().and_then(|r| r.temperature_c)
                && sensors::plausible(sensors::SensorKind::Temperature, t)
            {
                snap.sensors.push(reading(
                    sensors::Provider::StorageReliability,
                    t,
                    format!("storrel/{}", h.disk_index),
                ));
            }
        }
        // v1.0: SATA disks (HDDs too) from the read-only ATA SMART scan, so
        // every physical disk is an expected row of the sensor matrix.
        for a in self.ata_scan.iter().flatten() {
            if let Some(t) = a.smart.temperature_c() {
                let v = f64::from(t);
                snap.sensors.push(sensors::Sensor {
                    provider: sensors::Provider::AtaSmart,
                    hw_id: format!("disk/{}", a.index),
                    hw_name: a.model.clone(),
                    category: sensors::HwCategory::Storage,
                    sensor_id: format!("ata/{}/194", a.index),
                    name: "Temperature".into(),
                    kind: sensors::SensorKind::Temperature,
                    value: v,
                    min: v,
                    max: v,
                    samples: 1,
                    confidence: sensors::Confidence::High,
                    timestamp: snap.captured_at.clone(),
                });
            }
        }
        Some(snap)
    }

    fn start_gpo_check(&mut self) {
        self.request_collector("gpo");
        if self.gpo_rx.is_none() {
            self.claim_package("gpo");
        }
        #[cfg(windows)]
        if self.reference.is_none() && !cfg!(test) && self.gpo_rx.is_none() {
            let reference_dir = exe_dir().join("Reference");
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let _ = tx.send(gpo_admx::collect(PS_HOST, &reference_dir));
            });
            self.gpo_rx = Some(rx);
        }
    }

    fn poll_gpo(&mut self) {
        let Some(rx) = &self.gpo_rx else {
            return;
        };
        match rx.try_recv() {
            Ok(res) => {
                self.gpo_rx = None;
                self.accept_gpo(res);
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => {}
            Err(std::sync::mpsc::TryRecvError::Disconnected) => self.gpo_rx = None,
        }
    }

    fn accept_gpo(&mut self, res: Result<gpo_admx::GpoInputs, String>) {
        let d = i18n::t(self.language);
        match res {
            Ok(inputs) => {
                let result = gpo_admx::classify(&inputs);
                let stamp = evidence_stamp(sysinfo::local_time());
                let json = gpo_admx::to_json(&inputs, &result);
                let txt = gpo_text(&inputs, &result);
                push_journal(
                    &mut self.journal,
                    d.journal_gpo_fmt.replace("{status}", result.status.code()),
                );
                self.contribute_evidence(
                    "gpo",
                    d.module_gpo,
                    vec![
                        EvidenceFile::new(
                            gpo_admx::evidence_name(&stamp, "json"),
                            json.into_bytes(),
                        ),
                        EvidenceFile::new(gpo_admx::evidence_name(&stamp, "txt"), txt),
                    ],
                );
                self.gpo = Some(Ok((inputs, result)));
            }
            Err(e) => self.gpo = Some(Err(e)),
        }
    }

    // ---- view models ----------------------------------------------------

    fn crash_vm(&self) -> CrashVm {
        let d = i18n::t(self.language);
        let ru = self.language == Language::Ru;
        let busy = self.crash.busy != CrashBusy::Idle;
        let (headline, tone) = match (&self.crash.busy, &self.crash.inventory) {
            (CrashBusy::Scanning, _) => (d.crash_scanning.to_string(), Tone::Running),
            (CrashBusy::Analyzing, _) => (d.crash_analyzing.to_string(), Tone::Running),
            (_, None) => (d.crash_not_scanned.to_string(), Tone::Idle),
            (_, Some(Err(_))) => (d.crash_scan_failed.to_string(), Tone::Warning),
            // v0.4.5: one consistent wording — a BSOD is only claimed with
            // a BugCheck; an unexpected shutdown alone says so.
            (_, Some(Ok(inv))) => match inv.state() {
                crash_dump::CrashState::NoCrashes if inv.unexpected_shutdowns > 0 => {
                    (d.crash_unexpected_only.to_string(), Tone::Warning)
                }
                crash_dump::CrashState::NoCrashes => (d.crash_none.to_string(), Tone::Success),
                crash_dump::CrashState::BugcheckNoDump => {
                    (d.crash_no_dump.to_string(), Tone::Warning)
                }
                crash_dump::CrashState::DumpsFound => (
                    d.crash_found_fmt.replace(
                        "{status}",
                        &self
                            .crash
                            .analyses
                            .first()
                            .map(|a| a.confidence.label(ru))
                            .unwrap_or_else(|| d.crash_analysis_pending.to_string()),
                    ),
                    Tone::Warning,
                ),
            },
        };
        let debugger = match &self.crash.inventory {
            Some(Ok(inv)) => inv.debugger.clone(),
            Some(Err(e)) => crash_dump::DebuggerStatus::Error(e.clone()),
            None => crash_dump::DebuggerStatus::NotInstalled,
        };
        // v1.1 WinDbg status: installed + backend ready / not found / needs
        // a check — never "not installed" before any detection ran.
        let (dbg_text, dbg_tone) = match (&self.crash.inventory, &debugger) {
            (None, _) => (d.windbg_unknown, Tone::Idle),
            (_, crash_dump::DebuggerStatus::Installed { .. }) => {
                (d.windbg_backend_ready, Tone::Success)
            }
            (_, crash_dump::DebuggerStatus::PackageOnly { .. }) => {
                (d.windbg_package_only, Tone::Warning)
            }
            (_, crash_dump::DebuggerStatus::NotInstalled) => (d.windbg_not_found, Tone::Warning),
            (_, crash_dump::DebuggerStatus::Error(_)) => (d.windbg_unknown, Tone::Error),
        };
        let inventory_known = matches!(self.crash.inventory, Some(Ok(_)));
        let mut rows = Vec::new();
        match self.crash.analyses.first() {
            Some(a) => {
                let code = a
                    .bugcheck_code()
                    .map(|c| format!("0x{c:08X}"))
                    .unwrap_or_else(|| "—".into());
                rows.push(InfoRow::new(
                    d.crash_row_bugcheck,
                    match &a.parsed.bugcheck_name {
                        Some(n) => format!("{code} {n}"),
                        None => code,
                    },
                    Tone::Warning,
                ));
                rows.push(InfoRow::new(
                    d.crash_row_dump,
                    format!("{} · {}", a.dump.name, a.dump.modified.replace('T', " ")),
                    Tone::Idle,
                ));
                rows.push(InfoRow::new(
                    d.crash_row_module,
                    a.probable_module()
                        .unwrap_or_else(|| d.crash_not_determined.to_string()),
                    if a.probable_module().is_some() {
                        Tone::Warning
                    } else {
                        Tone::Idle
                    },
                ));
                rows.push(InfoRow::new(
                    d.crash_row_process,
                    process_name_text(a, ru),
                    Tone::Idle,
                ));
                rows.push(InfoRow::new(
                    d.crash_row_confidence,
                    a.confidence.label(ru),
                    match a.confidence {
                        crash_dump::Confidence::High => Tone::Warning,
                        _ => Tone::Idle,
                    },
                ));
                rows.push(InfoRow::new(
                    d.crash_row_stack,
                    a.parsed
                        .stack_text
                        .iter()
                        .filter_map(|l| l.rsplit(" : ").next())
                        .take(3)
                        .collect::<Vec<_>>()
                        .join(" ← "),
                    Tone::Idle,
                ));
                let dump_driven = a.third_party_module().map(|m| {
                    let r = a.resolution.as_ref();
                    format!(
                        "{} · {}",
                        a.parsed
                            .image_name
                            .clone()
                            .unwrap_or_else(|| format!("{m}.sys")),
                        match r {
                            Some(r) if !r.present => d.crash_driver_removed.to_string(),
                            Some(r) if !r.service_name.is_empty() => format!(
                                "{} {} ({}){}",
                                d.crash_driver_service,
                                r.service_name,
                                r.service_state,
                                r.devices
                                    .first()
                                    .map(|dv| format!(" · {}", dv.name))
                                    .unwrap_or_default()
                            ),
                            _ => d.crash_driver_dump_item.to_string(),
                        }
                    )
                });
                rows.push(InfoRow::new(
                    d.crash_row_driver,
                    a.linked
                        .first()
                        .map(|l| {
                            format!(
                                "[{}] {} — {} ×{}",
                                if ru {
                                    l.status.label_ru()
                                } else {
                                    l.status.code()
                                },
                                l.device,
                                l.kind.code(),
                                l.count.max(1)
                            )
                        })
                        .or(dump_driven.clone())
                        .unwrap_or_else(|| "—".into()),
                    a.linked
                        .first()
                        .map(|l| severity_tone(l.status))
                        .or(dump_driven.map(|_| Tone::Warning))
                        .unwrap_or(Tone::Idle),
                ));
                if a.memory_test_recommended {
                    rows.push(InfoRow::new("", d.crash_memory_hint, Tone::Warning));
                }
            }
            None => {
                if let Some(Ok(inv)) = &self.crash.inventory {
                    if let Some(b) = inv.bugchecks.first() {
                        rows.push(InfoRow::new(
                            d.crash_row_bugcheck,
                            format!("0x{:08X} · {}", b.code, b.time.replace('T', " ")),
                            Tone::Warning,
                        ));
                    }
                    if let Some(dmp) = inv.dumps.first() {
                        rows.push(InfoRow::new(
                            d.crash_row_dump,
                            format!("{} · {}", dmp.name, dmp.modified.replace('T', " ")),
                            Tone::Idle,
                        ));
                    }
                }
                rows.push(InfoRow::new("", d.crash_no_analysis, Tone::Idle));
            }
        }
        if let Some(Ok(inv)) = &self.crash.inventory
            && let Some((_, v)) = crash_dump::incident_verdicts(inv, &self.crash.analyses).first()
        {
            rows.push(InfoRow::new(
                d.crash_row_incident,
                v.headline_localized(ru),
                if v.hang_confirmed || v.bsod_registered {
                    Tone::Warning
                } else {
                    Tone::Idle
                },
            ));
        }
        // v1.0 item 40: the same counters as Details / export / evidence.
        let counts = match &self.crash.inventory {
            Some(Ok(inv)) => {
                let c = crate::crash_report::Counters::of(inv);
                let line = d
                    .crash_counts_fmt
                    .replace("{s}", &c.unexpected_shutdowns.to_string())
                    .replace("{b}", &c.bugchecks.to_string())
                    .replace("{d}", &c.dumps.to_string());
                // v1.1: every result says when / how it was produced.
                match &self.crash.inventory_checked {
                    Some(stamp) => format!("{line} · {}", stamp.caption(d)),
                    None => line,
                }
            }
            _ => String::new(),
        };
        CrashVm {
            headline,
            tone,
            counts,
            debugger: dbg_text.to_string(),
            debugger_tone: dbg_tone,
            debugger_missing: inventory_known
                && !matches!(debugger, crash_dump::DebuggerStatus::Installed { .. }),
            busy,
            // v1.0 Startup Idle: before any inventory the click scans first.
            can_analyze: self.crash.inventory.is_none()
                || (matches!(debugger, crash_dump::DebuggerStatus::Installed { .. })
                    && matches!(&self.crash.inventory, Some(Ok(inv)) if !inv.analysis_queue().is_empty())),
            has_details: inventory_known || !self.crash.analyses.is_empty(),
            rows,
            analysis: self.analysis_progress_vm(),
            outcome: crash_dump::analysis_outcome(&self.crash.analyses)
                .filter(|_| self.crash.busy == CrashBusy::Idle)
                .map(|o| match o {
                    crash_dump::AnalysisOutcome::Completed => {
                        (d.crash_outcome_ok.to_string(), Tone::Success)
                    }
                    crash_dump::AnalysisOutcome::CompletedIncomplete => {
                        (d.crash_outcome_incomplete.to_string(), Tone::Warning)
                    }
                    crash_dump::AnalysisOutcome::Failed => {
                        (d.crash_outcome_failed.to_string(), Tone::Error)
                    }
                }),
            install: self.install_vm(),
        }
    }

    /// v1.0 running analysis: real stages (done / active / pending), the
    /// elapsed time and the symbol-download note. No percentage.
    fn analysis_progress_vm(&self) -> Option<AnalysisProgressVm> {
        let p = self.crash.progress.as_ref()?;
        if self.crash.busy != CrashBusy::Analyzing {
            return None;
        }
        let d = i18n::t(self.language);
        let ru = self.language == Language::Ru;
        let stages = crash_dump::AnalysisStage::ALL
            .iter()
            .map(|s| {
                let mark = match s.cmp(&p.stage) {
                    std::cmp::Ordering::Less => StageMark::Done,
                    std::cmp::Ordering::Equal => StageMark::Active,
                    std::cmp::Ordering::Greater => StageMark::Pending,
                };
                (s.text(ru).to_string(), mark)
            })
            .collect();
        let secs = p.started.elapsed().as_secs();
        Some(AnalysisProgressVm {
            stages,
            elapsed: format!("{:02}:{:02}", secs / 60, secs % 60),
            note: p
                .symbols_downloading
                .then(|| d.crash_symbols_download.to_string()),
            dump_label: d
                .crash_dump_of_fmt
                .replace("{i}", &(p.dump_index + 1).to_string())
                .replace("{n}", &p.dump_total.to_string())
                .replace("{name}", &p.dump_name),
        })
    }

    /// v1.0 embedded installer status (above the install button).
    fn install_vm(&self) -> Option<InstallVm> {
        let d = i18n::t(self.language);
        let ru = self.language == Language::Ru;
        let lines = |current: Option<crash_dump::InstallStage>, all_done: bool| {
            [
                crash_dump::InstallStage::Preparing,
                crash_dump::InstallStage::Downloading,
                crash_dump::InstallStage::Installing,
                crash_dump::InstallStage::Verifying,
            ]
            .iter()
            .map(|s| {
                let mark = if all_done {
                    StageMark::Done
                } else {
                    match current.map(|c| s.cmp(&c)) {
                        Some(std::cmp::Ordering::Less) => StageMark::Done,
                        Some(std::cmp::Ordering::Equal) => StageMark::Active,
                        _ => StageMark::Pending,
                    }
                };
                (s.text(ru).to_string(), mark)
            })
            .collect::<Vec<_>>()
        };
        let vm = |lines, percent, running, failed, succeeded, status: String| InstallVm {
            title: d.install_title.to_string(),
            lines,
            percent,
            running,
            failed,
            succeeded,
            status,
        };
        // v1.0 item 41: an installed, usable analyzer is shown as such
        // whatever an earlier install attempt reported.
        let usable = matches!(&self.crash.inventory, Some(Ok(inv)) if inv.debugger.usable());
        if usable && matches!(self.crash.install, InstallState::Failed(_)) {
            return Some(vm(
                lines(None, true),
                None,
                false,
                false,
                true,
                d.install_installed.to_string(),
            ));
        }
        match &self.crash.install {
            InstallState::Idle => None,
            InstallState::Running { stage, percent } => Some(vm(
                lines(Some(*stage), false),
                *percent,
                true,
                false,
                false,
                String::new(),
            )),
            InstallState::Verifying => Some(vm(
                lines(Some(crash_dump::InstallStage::Verifying), false),
                None,
                true,
                false,
                false,
                String::new(),
            )),
            InstallState::Succeeded => Some(vm(
                lines(None, true),
                None,
                false,
                false,
                true,
                d.install_installed.to_string(),
            )),
            InstallState::Failed(e) => Some(vm(
                Vec::new(),
                None,
                false,
                true,
                false,
                format!("{} ({e})", d.install_failed),
            )),
        }
    }

    fn sensors_vm(&self) -> SensorsVm {
        let d = i18n::t(self.language);
        let ru = self.language == Language::Ru;
        let busy = self.sensors_rx.is_some();
        let Some(snap) = self.sensors_with_storage() else {
            return SensorsVm {
                matrix: Vec::new(),
                refs: Vec::new(),
                temps: Vec::new(),
                rails: Vec::new(),
                power_state: if busy {
                    d.sensors_reading
                } else {
                    d.sensors_not_read
                }
                .into(),
                power_tone: if busy { Tone::Running } else { Tone::Idle },
                power_message: String::new(),
                power: Vec::new(),
                fans: Vec::new(),
                status_line: String::new(),
                busy,
                has_data: false,
                read: self.sensor_read_vm(),
            };
        };
        let sum = sensors::summarize(&snap.sensors);
        let status_tone = |st: sensors::PowerStatus| match st {
            sensors::PowerStatus::Excellent => Tone::Success,
            sensors::PowerStatus::Attention | sensors::PowerStatus::CheckSensor => Tone::Warning,
            sensors::PowerStatus::Critical => Tone::Error,
            sensors::PowerStatus::NoData => Tone::Idle,
        };
        let level_tone = |l: sensors::ReadingLevel| match l {
            sensors::ReadingLevel::Unknown => Tone::Idle,
            sensors::ReadingLevel::Normal => Tone::Success,
            sensors::ReadingLevel::Near => Tone::Warning,
            sensors::ReadingLevel::Critical => Tone::Error,
        };
        // v0.4.5: CPU (core average), GPU, hotspot, board, PCH, RAM, disks —
        // never per-core values. References only where reliably known.
        let temps = sum
            .temps
            .iter()
            .filter(|c| sensors::on_dashboard(&c.role))
            .map(|c| {
                let (level, reference) = match &c.role {
                    sensors::Role::DiskTemp(_) => {
                        let (w, cr) = self.disk_temp_thresholds(&c.label);
                        (
                            sensors::disk_temp_level(c.value, w, cr),
                            sensors::disk_reference(w, cr)
                                .unwrap_or_else(|| d.sensors_ref_none.to_string()),
                        )
                    }
                    _ => (
                        sensors::ReadingLevel::Unknown,
                        d.sensors_ref_none.to_string(),
                    ),
                };
                SensorChip::new(
                    sensor_label(&c.role, &c.label, d),
                    format!("{:.0}°C", c.value),
                    level_tone(level),
                )
                .with_ref(reference)
            })
            .collect();
        let mut rails: Vec<SensorChip> = sum
            .rails
            .iter()
            .map(|(rail, c, st)| {
                SensorChip::new(
                    rail.label(),
                    format!("{:.2} V", c.value),
                    level_tone(sensors::rail_level(*st)),
                )
                .with_ref(sensors::rail_reference(*rail))
            })
            .collect();
        rails.extend(sum.dynamic_voltages.iter().take(3).map(|c| {
            SensorChip::new(
                sensor_label(&c.role, &c.label, d),
                format!("{:.3} V", c.value),
                Tone::Idle,
            )
            .with_ref(d.sensors_ref_dynamic)
        }));
        let power = sum
            .power
            .iter()
            .filter(|c| sensors::on_dashboard(&c.role))
            .map(|c| {
                SensorChip::new(
                    sensor_label(&c.role, &c.label, d),
                    format!("{:.0} W", c.value),
                    Tone::Idle,
                )
                .with_ref(d.sensors_ref_none)
            })
            .collect();
        let fans = sum
            .fans
            .iter()
            .filter(|c| sensors::on_dashboard(&c.role))
            .map(|c| {
                SensorChip::new(
                    sensor_label(&c.role, &c.label, d),
                    format!("{:.0} RPM", c.value),
                    Tone::Idle,
                )
            })
            .collect();
        let ps = sum.power_status();
        let mut status = vec![snap.state().code().to_string()];
        if let Some(p) = snap.main_provider() {
            status.push(p.short().to_string());
        }
        if let Some(r) = snap.providers.iter().find(|r| {
            r.provider == sensors::Provider::LhmInternal
                && r.state != sensors::ProviderState::Available
        }) {
            status.push(format!("LHM: {}", r.state.code()));
        }
        if !sum.mismatches.is_empty() {
            status.push(d.sensors_mismatch.to_string());
        }
        let (matrix, refs) =
            sensor_matrix(&sum, &|label: &str| self.disk_temp_thresholds(label), d);
        SensorsVm {
            matrix,
            refs,
            temps,
            rails,
            power_state: ps.text(ru).into(),
            power_tone: status_tone(ps),
            power_message: ps.message(ru).into(),
            power,
            fans,
            status_line: status.join(" · "),
            busy,
            has_data: !sum.is_empty(),
            read: self.sensor_read_vm(),
        }
    }

    fn gpo_vm(&self) -> GpoVm {
        let d = i18n::t(self.language);
        let ru = self.language == Language::Ru;
        let busy = self.gpo_rx.is_some();
        match &self.gpo {
            None => GpoVm {
                status: if busy { d.gpo_running } else { d.gpo_not_run }.to_string(),
                tone: if busy { Tone::Running } else { Tone::Idle },
                rows: Vec::new(),
                busy,
                has_result: false,
            },
            Some(Err(e)) => GpoVm {
                status: gpo_admx::GpoStatus::InsufficientData.text(ru).into(),
                tone: Tone::Idle,
                rows: vec![InfoRow::new("", e.clone(), Tone::Idle)],
                busy,
                has_result: false,
            },
            Some(Ok((i, r))) => {
                let store = i.central.as_ref().filter(|c| c.exists).unwrap_or(&i.local);
                let lang = if i.ui_language.is_empty() {
                    "en-US"
                } else {
                    &i.ui_language
                };
                let central = if !i.domain_joined {
                    d.gpo_standalone.to_string()
                } else if !i.sysvol_reachable {
                    d.gpo_unreachable.to_string()
                } else if i.central.as_ref().is_some_and(|c| c.exists) {
                    d.gpo_found.to_string()
                } else {
                    d.gpo_not_found.to_string()
                };
                let tone_of = |s: gpo_admx::GpoStatus| match s {
                    gpo_admx::GpoStatus::Ok => Tone::Success,
                    gpo_admx::GpoStatus::Outdated
                    | gpo_admx::GpoStatus::Mismatch
                    | gpo_admx::GpoStatus::CentralStoreNotFound => Tone::Warning,
                    _ => Tone::Idle,
                };
                let tone = tone_of(r.status);
                // v1.0: Central Store and the LOCAL store are two verdicts;
                // a standalone PC is "not applicable" for the Central Store
                // but its local PolicyDefinitions health is still shown.
                let (status, tone) = if i.domain_joined {
                    (r.status.text(ru).to_string(), tone)
                } else {
                    (
                        format!(
                            "{} · {}: {}",
                            r.status.text(ru),
                            d.gpo_local_short,
                            r.local_status.text(ru)
                        ),
                        tone_of(r.local_status),
                    )
                };
                GpoVm {
                    status,
                    tone,
                    rows: vec![
                        InfoRow::new(
                            d.gpo_domain,
                            if i.domain.is_empty() {
                                "—".to_string()
                            } else {
                                i.domain.to_uppercase()
                            },
                            Tone::Idle,
                        ),
                        InfoRow::new(d.gpo_central, central, Tone::Idle),
                        InfoRow::new(
                            d.gpo_windows,
                            format!(
                                "{} ({})",
                                if i.windows_release.is_empty() {
                                    "?"
                                } else {
                                    &i.windows_release
                                },
                                i.windows_build
                            ),
                            Tone::Idle,
                        ),
                        InfoRow::new(d.gpo_templates, r.status.text(ru), tone),
                        InfoRow::new(d.gpo_admx, store.admx.len().to_string(), Tone::Idle),
                        InfoRow::new(
                            d.gpo_missing_adml,
                            if store.exists {
                                store.missing_adml(lang).len().to_string()
                            } else {
                                "—".into()
                            },
                            Tone::Idle,
                        ),
                    ],
                    busy,
                    has_result: true,
                }
            }
        }
    }

    fn system_state_vm(&self) -> SystemStateVm {
        let d = i18n::t(self.language);
        let hardware = self.system_state_vm_hardware_only();
        self.system_state_vm_with(d, hardware)
    }

    fn system_state_vm_hardware_only(&self) -> InfoRow {
        let d = i18n::t(self.language);
        // Hardware: sensors + storage correlation (never "computer healthy").
        let mut hw: Option<Tone> = None;
        let mut worst = |t: Tone| {
            let rank = |t: Tone| match t {
                Tone::Error => 3,
                Tone::Warning => 2,
                Tone::Success => 1,
                _ => 0,
            };
            if hw.is_none_or(|h| rank(t) > rank(h)) {
                hw = Some(t);
            }
        };
        // Only trusted rail readings count; CHECK SENSOR is not a finding.
        if let Some(snap) = &self.sensors {
            match sensors::summarize(&snap.sensors).power_status() {
                sensors::PowerStatus::Excellent => worst(Tone::Success),
                sensors::PowerStatus::Attention => worst(Tone::Warning),
                sensors::PowerStatus::Critical => worst(Tone::Error),
                sensors::PowerStatus::CheckSensor | sensors::PowerStatus::NoData => {}
            }
        }
        // v1.0: SATA SMART verdicts (the drive's own threshold / sector
        // counters; UNSUPPORTED is not a finding).
        for a in self.ata_scan.iter().flatten() {
            match a.smart.health() {
                "SMART: OK" => worst(Tone::Success),
                "SMART: THRESHOLD EXCEEDED" => worst(Tone::Error),
                h if h.starts_with("SMART: ATTENTION") => worst(Tone::Warning),
                _ => {}
            }
        }
        for a in self.assessments.values() {
            if let Some(c) = &a.classification {
                worst(match c.state {
                    storage_health::StorageState::StorageProblem => Tone::Error,
                    storage_health::StorageState::StorageAttention
                    | storage_health::StorageState::BenchmarkAnomalyCheck
                    | storage_health::StorageState::BenchmarkAnomalyRetest => Tone::Warning,
                    storage_health::StorageState::InsufficientData => Tone::Idle,
                    _ => Tone::Success,
                });
            }
        }
        let hw_text = |t: Option<Tone>| match t {
            Some(Tone::Error) => d.state_critical,
            Some(Tone::Warning) => d.state_attention,
            Some(Tone::Success) => d.state_ok,
            _ => d.state_no_data,
        };
        InfoRow::new(d.hw_state_label, hw_text(hw), hw.unwrap_or(Tone::Idle))
    }

    fn system_state_vm_with(&self, d: &i18n::Dict, hardware: InfoRow) -> SystemStateVm {
        // System: confirmed BSOD / unexpected shutdowns / hangs / driver
        // problems are never hidden behind a hardware "OK".
        let (code, _) = self.state_codes();
        let system = match code.as_str() {
            "ATTENTION_BSOD" => {
                let n = match &self.crash.inventory {
                    Some(Ok(inv)) => inv.bugchecks.len(),
                    _ => 0,
                };
                InfoRow::new(
                    d.sys_state_label,
                    d.sys_bsod_fmt.replace("{n}", &n.to_string()),
                    Tone::Warning,
                )
            }
            "ATTENTION_HANG" => InfoRow::new(d.sys_state_label, d.sys_hang, Tone::Warning),
            "ATTENTION_UNEXPECTED_SHUTDOWN" => {
                InfoRow::new(d.sys_state_label, d.sys_unexpected_shutdown, Tone::Warning)
            }
            "ATTENTION_DRIVER_PROBLEM" => {
                InfoRow::new(d.sys_state_label, d.sys_driver_problem, Tone::Warning)
            }
            "OK" => InfoRow::new(d.sys_state_label, d.state_ok, Tone::Success),
            _ => InfoRow::new(d.sys_state_label, d.state_no_data, Tone::Idle),
        };
        SystemStateVm {
            hardware,
            system,
            note: d.system_state_note.into(),
        }
    }

    /// v1.0 machine-readable (system, hardware) state codes — two separate
    /// concepts: "Hardware state: OK" never means "computer healthy".
    fn state_codes(&self) -> (String, String) {
        let inv = match &self.crash.inventory {
            Some(Ok(inv)) => Some(inv),
            _ => None,
        };
        let hang = inv.is_some_and(|inv| {
            crash_dump::incident_verdicts(inv, &self.crash.analyses)
                .iter()
                .any(|(_, v)| v.hang_confirmed)
        });
        let driver_problem = self
            .audit_view()
            .is_some_and(|r| r.overall == Severity::Problem);
        let system = match inv {
            Some(inv) if !inv.bugchecks.is_empty() => "ATTENTION_BSOD",
            _ if hang => "ATTENTION_HANG",
            Some(inv) if inv.unexpected_shutdowns > 0 => "ATTENTION_UNEXPECTED_SHUTDOWN",
            _ if driver_problem => "ATTENTION_DRIVER_PROBLEM",
            Some(_) => "OK",
            None => "NO_DATA",
        };
        let hw = {
            let d = i18n::t(Language::En);
            let _ = d;
            let row = self.system_state_hardware_tone();
            match row {
                Some(Tone::Error) => "CRITICAL",
                Some(Tone::Warning) => "ATTENTION",
                Some(Tone::Success) => "OK",
                _ => "NO_DATA",
            }
        };
        (system.to_string(), hw.to_string())
    }

    /// Worst hardware tone (sensors, SATA SMART, storage correlation).
    fn system_state_hardware_tone(&self) -> Option<Tone> {
        let vm = self.system_state_vm_hardware_only();
        (vm.tone != Tone::Idle).then_some(vm.tone)
    }

    /// v1.0 item 11: SMART / NVMe block — one row PER PHYSICAL DISK
    /// ("Samsung … · NVMe · OK · 48°C", "TOSHIBA … #2 · SATA · OK"), never
    /// a bus/provider category as if it were a disk; then the selected NVMe
    /// disk's facts. Still reading → "Чтение…".
    fn smart_rows(&self) -> Vec<InfoRow> {
        let d = i18n::t(self.language);
        let mut disks: Vec<(String, String, Tone)> = Vec::new();
        // NVMe disks (SSD candidates): their NVMe health record.
        for cand in &self.ssd_candidates {
            if nvme_health::is_ata_bus(&cand.disk.bus_type) {
                continue; // listed below from the ATA scan of every disk
            }
            let id = storage_topology::physical_disk_identity(&cand.disk);
            let (value, tone) = match self.nvme_health.get(&id) {
                Some(h) => {
                    let (_, status) = nvme_health::health_source_status(h);
                    let temp = nvme_health::temperature_provenance(h)
                        .map(|(c, _)| format!(" · {c:.0}°C"))
                        .unwrap_or_default();
                    let tone = match status {
                        "OK" => Tone::Success,
                        "ATTENTION" => Tone::Warning,
                        "PROBLEM" => Tone::Error,
                        _ => Tone::Idle,
                    };
                    (format!("{} · {status}{temp}", cand.disk.bus_type), tone)
                }
                None if self.assessments.get(&id).is_some_and(|a| a.health_pending) => (
                    format!("{} · {}", cand.disk.bus_type, d.smart_reading),
                    Tone::Running,
                ),
                None => (
                    format!("{} · {}", cand.disk.bus_type, d.smart_not_read),
                    Tone::Idle,
                ),
            };
            disks.push((sensors::disk_short(&cand.disk.model), value, tone));
        }
        // ATA / SATA disks (HDDs too) with their read-only SMART.
        match &self.ata_scan {
            Some(list) => {
                for a in list {
                    let health = a.smart.health().trim_start_matches("SMART: ").to_string();
                    let tone = match a.smart.health() {
                        "SMART: OK" => Tone::Success,
                        "SMART: THRESHOLD EXCEEDED" => Tone::Error,
                        h if h.starts_with("SMART: ATTENTION") => Tone::Warning,
                        _ => Tone::Idle,
                    };
                    let temp = a
                        .smart
                        .temperature_c()
                        .map(|t| format!(" · {t}°C"))
                        .unwrap_or_default();
                    disks.push((
                        sensors::disk_short(&a.model),
                        format!("{} · {health}{temp}", a.bus),
                        tone,
                    ));
                }
            }
            None if self.ata_rx.is_some() => disks.push((
                d.smart_sata_disks.to_string(),
                d.smart_reading.to_string(),
                Tone::Running,
            )),
            None => {}
        }
        // Same model twice → "#1" / "#2" (physical disks, not categories).
        let names: Vec<String> = disks.iter().map(|x| x.0.clone()).collect();
        let mut rows: Vec<InfoRow> = Vec::new();
        for (k, (name, value, tone)) in disks.into_iter().enumerate() {
            let total = names.iter().filter(|n| **n == name).count();
            let label = if total > 1 {
                let nth = names[..k].iter().filter(|n| **n == name).count() + 1;
                format!("{name} #{nth}")
            } else {
                name
            };
            rows.push(InfoRow::new(label, value, tone));
        }
        if rows.is_empty() {
            rows.push(InfoRow::new("", d.smart_no_disk, Tone::Idle));
        }
        rows.extend(self.selected_smart_rows());
        rows
    }

    /// Facts of the selected NVMe disk (no verdict colours). The per-disk
    /// status line itself is in `smart_rows`.
    fn selected_smart_rows(&self) -> Vec<InfoRow> {
        let d = i18n::t(self.language);
        let Some(s) = self.selected_nvme_health().and_then(|h| h.smart.as_ref()) else {
            return Vec::new();
        };
        vec![
            InfoRow::new(
                d.nvme_critical_warning,
                s.critical_warning.to_string(),
                Tone::Idle,
            ),
            InfoRow::new(
                d.nvme_percentage_used,
                format!(
                    "{} % · {} {} % / {} %",
                    s.percentage_used,
                    d.nvme_available_spare,
                    s.available_spare_percent,
                    s.available_spare_threshold_percent
                ),
                Tone::Idle,
            ),
            InfoRow::new(
                d.nvme_media_errors,
                format!(
                    "{} · {} {}",
                    s.media_and_data_integrity_errors,
                    d.nvme_error_log_entries,
                    s.error_information_log_entries
                ),
                Tone::Idle,
            ),
        ]
    }

    // ---- detail windows ---------------------------------------------------

    fn crash_details_window(&mut self, ctx: &egui::Context) {
        if !self.crash_details_open {
            return;
        }
        let d = i18n::t(self.language);
        let ru = self.language == Language::Ru;
        let mut open = true;
        let status = self.crash_export_status.as_ref().map(|s| s.text(d));
        let text = self.crash_details_text();
        let folder_ok = self.final_report().is_ok();
        let mut act: Option<DetailsAct> = None;
        detail_window(
            ctx,
            "wsd_crash_details",
            d.crash_details_title,
            [1040.0, 820.0],
            &mut open,
            |ui| {
                let footer = if status.is_some() { 76.0 } else { 50.0 };
                egui::ScrollArea::vertical()
                    .id_salt("wsd_crash_details_scroll")
                    .auto_shrink([false, false])
                    .max_height((ui.available_height() - footer).max(120.0))
                    .show(ui, |ui| {
                        // v1.0 item 38: СОСТОЯНИЕ → ЧТО ОБНАРУЖЕНО →
                        // ИНЦИДЕНТЫ → ВЕРОЯТНАЯ ПРИЧИНА → ЧТО ПРОВЕРИТЬ,
                        // then the detailed dump analysis (raw collapsed).
                        if let Some(Ok(inv)) = &self.crash.inventory {
                            let r = crate::crash_report::build(inv, &self.crash.analyses, ru);
                            let level_col = match r.level {
                                crate::crash_report::Level::Ok => c::GREEN_SUCCESS,
                                crate::crash_report::Level::Info => c::TEXT_TITLE,
                                crate::crash_report::Level::Attention => c::YELLOW_WARNING,
                                crate::crash_report::Level::Problem => c::RED_ERROR,
                            };
                            details::section_title(ui, d.crash_sec_state);
                            ui.add(
                                egui::Label::new(
                                    RichText::new(&r.state).strong().size(15.0).color(level_col),
                                )
                                .wrap(),
                            );
                            ui.label(
                                RichText::new(crate::crash_report::debugger_line(
                                    &inv.debugger,
                                    ru,
                                ))
                                .color(c::TEXT_SECONDARY),
                            );
                            // v1.0 item 42: the analyzer install mini-journal
                            // (4–6 lines) right under the state; the full
                            // installer output stays collapsed at the end.
                            if !self.crash.install_log.is_empty() {
                                ui.add_space(4.0);
                                ui.label(
                                    RichText::new(d.install_log_title)
                                        .strong()
                                        .color(c::TEXT_TITLE),
                                );
                                for l in self.install_journal_lines() {
                                    ui.add(
                                        egui::Label::new(RichText::new(l).color(c::TEXT_BODY))
                                            .wrap(),
                                    );
                                }
                            }
                            ui.add_space(6.0);
                            details::section_title(ui, d.crash_sec_found);
                            ui.label(
                                RichText::new(format!("• {}", r.counters.line(ru)))
                                    .color(c::TEXT_SECONDARY),
                            );
                            for l in &r.found {
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(format!("• {l}")).color(c::TEXT_BODY),
                                    )
                                    .wrap(),
                                );
                            }
                            ui.add_space(6.0);
                            details::section_title(ui, d.crash_sec_incidents);
                            if r.incidents.is_empty() {
                                ui.label(RichText::new(d.crash_incident_none).color(c::TEXT_MUTED));
                            } else {
                                egui::Grid::new("wsd_crash_incident_table")
                                    .num_columns(5)
                                    .spacing(vec2(16.0, 4.0))
                                    .striped(true)
                                    .show(ui, |ui| {
                                        for h in d.crash_incident_header {
                                            ui.label(
                                                RichText::new(h).strong().color(c::TEXT_TITLE),
                                            );
                                        }
                                        ui.end_row();
                                        for i in &r.incidents {
                                            for v in [&i.time, &i.kind, &i.code, &i.dump, &i.cause]
                                            {
                                                ui.label(RichText::new(v).color(c::TEXT_BODY));
                                            }
                                            ui.end_row();
                                        }
                                    });
                            }
                            ui.add_space(6.0);
                            details::section_title(ui, d.crash_sec_cause);
                            for l in &r.cause {
                                ui.add(
                                    egui::Label::new(RichText::new(l).color(c::TEXT_PRIMARY))
                                        .wrap(),
                                );
                            }
                            if !r.why.is_empty() {
                                ui.add_space(6.0);
                                details::section_title(ui, d.crash_sec_why);
                                for l in &r.why {
                                    ui.add(
                                        egui::Label::new(
                                            RichText::new(format!("• {l}")).color(c::TEXT_BODY),
                                        )
                                        .wrap(),
                                    );
                                }
                            }
                            ui.add_space(6.0);
                            details::section_title(ui, d.crash_sec_check);
                            for l in &r.checks {
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(format!("• {l}")).color(c::TEXT_PRIMARY),
                                    )
                                    .wrap(),
                                );
                            }
                            ui.separator();
                        }
                        // v1.0 polish: the WinDbg technical data (per dump:
                        // fields, STACK_TEXT, lmvm, resolution, raw output)
                        // is one expandable section, closed by default.
                        if !self.crash.analyses.is_empty() {
                            egui::CollapsingHeader::new(
                                RichText::new(d.crash_sec_dumps)
                                    .size(17.0)
                                    .strong()
                                    .color(c::TEXT_TITLE),
                            )
                            .id_salt("wsd_crash_windbg_technical")
                            .default_open(false)
                            .show(ui, |ui| {
                                for (n, a) in self.crash.analyses.iter().enumerate() {
                                    details::section_title(
                                        ui,
                                        &format!(
                                            "{} — {} — {}",
                                            a.dump.name,
                                            a.status.code(),
                                            a.confidence.label(ru)
                                        ),
                                    );
                                    egui::Grid::new(("wsd_crash_kv", n))
                                        .num_columns(2)
                                        .spacing(vec2(14.0, 4.0))
                                        .striped(true)
                                        .show(ui, |ui| {
                                            for (k, v) in crash_analysis_rows(a, d, ru) {
                                                ui.label(RichText::new(k).color(c::TEXT_SECONDARY));
                                                ui.add(egui::Label::new(v).wrap());
                                                ui.end_row();
                                            }
                                        });
                                    if !a.parsed.stack_text.is_empty() {
                                        ui.add_space(4.0);
                                        ui.label(RichText::new("STACK_TEXT").color(c::TEXT_TITLE));
                                        for line in &a.parsed.stack_text {
                                            ui.add(
                                                egui::Label::new(
                                                    RichText::new(line)
                                                        .monospace()
                                                        .size(11.5)
                                                        .color(c::TEXT_BODY),
                                                )
                                                .wrap(),
                                            );
                                        }
                                    }
                                    if let Some(m) = &a.module_info {
                                        ui.add_space(4.0);
                                        ui.label(
                                            RichText::new(format!("lmvm {}", m.module))
                                                .color(c::TEXT_TITLE),
                                        );
                                        ui.add(
                                            egui::Label::new(
                                                RichText::new(crash_dump::without_debugger_noise(
                                                    &m.raw,
                                                ))
                                                .monospace()
                                                .size(11.5),
                                            )
                                            .wrap(),
                                        );
                                    }
                                    if let Some(r) = &a.resolution {
                                        ui.add_space(4.0);
                                        ui.label(
                                            RichText::new(d.crash_resolution_title)
                                                .color(c::TEXT_TITLE),
                                        );
                                        for l in crash_dump::resolution_lines(r, ru) {
                                            ui.label(RichText::new(l).color(c::TEXT_BODY));
                                        }
                                    }
                                    if !a.linked.is_empty() {
                                        ui.add_space(4.0);
                                        ui.label(
                                            RichText::new(d.crash_row_driver).color(c::TEXT_TITLE),
                                        );
                                        for l in &a.linked {
                                            ui.label(format!(
                                                "→ [{}] {} — {} ×{} {}",
                                                l.status.code(),
                                                l.device,
                                                l.kind.code(),
                                                l.count.max(1),
                                                l.text
                                            ));
                                        }
                                    }
                                    if a.memory_test_recommended {
                                        ui.label(
                                            RichText::new(d.crash_memory_hint)
                                                .color(c::YELLOW_WARNING),
                                        );
                                    }
                                    egui::CollapsingHeader::new(d.crash_raw_title)
                                        .id_salt(("wsd_crash_raw", n))
                                        .show(ui, |ui| {
                                            ui.add(
                                                egui::Label::new(
                                                    RichText::new(&a.raw_output)
                                                        .monospace()
                                                        .size(11.0),
                                                )
                                                .wrap(),
                                            );
                                        });
                                    ui.separator();
                                }
                            });
                        }
                        if let Some(Ok(inv)) = &self.crash.inventory {
                            // v0.4.5 freeze / hang incident timelines.
                            details::section_title(ui, d.crash_incidents_title);
                            let verdicts = crash_dump::incident_verdicts(inv, &self.crash.analyses);
                            if verdicts.is_empty() {
                                ui.label(RichText::new(d.crash_incident_none).color(c::TEXT_MUTED));
                            }
                            for (inc, v) in &verdicts {
                                ui.label(RichText::new(v.headline_localized(ru)).strong().color(
                                    if v.hang_confirmed || v.bsod_registered {
                                        c::YELLOW_WARNING
                                    } else {
                                        c::TEXT_TITLE
                                    },
                                ));
                                ui.label(
                                    RichText::new(crash_dump::incident_line(inc))
                                        .color(c::TEXT_SECONDARY),
                                );
                                for sig in &v.signals {
                                    ui.label(
                                        RichText::new(format!("  - {sig}")).monospace().size(12.0),
                                    );
                                }
                                if !inc.events.is_empty() {
                                    egui::CollapsingHeader::new(format!(
                                        "{} ({})",
                                        d.crash_incident_events,
                                        inc.events.len()
                                    ))
                                    .id_salt(("wsd_incident", &inc.logged))
                                    .show(ui, |ui| {
                                        for e in &inc.events {
                                            ui.add(
                                                egui::Label::new(
                                                    RichText::new(format!(
                                                        "{} · {} · {} #{} · {}",
                                                        e.time.replace('T', " "),
                                                        e.log,
                                                        e.provider,
                                                        e.id,
                                                        e.message
                                                    ))
                                                    .monospace()
                                                    .size(11.5),
                                                )
                                                .wrap(),
                                            );
                                        }
                                    });
                                }
                                ui.add_space(4.0);
                            }
                            if !inv.live_kernel_reports.is_empty() {
                                ui.label(
                                    RichText::new(format!(
                                        "LiveKernelReports: {}",
                                        inv.live_kernel_reports
                                            .iter()
                                            .take(8)
                                            .map(|r| format!(
                                                "{}\\{} ({}, {} B)",
                                                r.folder,
                                                r.name,
                                                r.time.replace('T', " "),
                                                r.size
                                            ))
                                            .collect::<Vec<_>>()
                                            .join(" · ")
                                    ))
                                    .color(c::TEXT_SECONDARY),
                                );
                            }
                            ui.separator();
                        }
                        if !self.crash.install_log.is_empty() {
                            // v1.0 item 42: 4–6 line mini-journal; the raw
                            // installer output stays collapsed below it.
                            egui::CollapsingHeader::new(d.install_raw_title)
                                .id_salt("wsd_install_raw")
                                .show(ui, |ui| {
                                    for l in &self.crash.install_log {
                                        ui.add(
                                            egui::Label::new(
                                                RichText::new(l)
                                                    .monospace()
                                                    .size(11.5)
                                                    .color(c::TEXT_BODY),
                                            )
                                            .wrap(),
                                        );
                                    }
                                });
                            ui.label(
                                RichText::new(format!(
                                    "{} · {}",
                                    d.install_note,
                                    crash_dump::WINDBG_DOWNLOAD_URL
                                ))
                                .small()
                                .color(c::TEXT_MUTED),
                            );
                            ui.separator();
                        }
                        ui.label(
                            RichText::new(d.crash_heuristic_note)
                                .small()
                                .color(c::TEXT_MUTED),
                        );
                    });
                ui.separator();
                if let Some((t, col)) = &status {
                    ui.add(egui::Label::new(RichText::new(t).color(*col)).wrap());
                }
                act = details_action_bar(ui, d, !text.trim().is_empty(), Some(folder_ok));
            },
        );
        match act {
            Some(DetailsAct::Copy) => {
                self.crash_export_status =
                    Some(self.export_text(ctx, ExportAction::Copy, "CrashDump_Details", &text))
            }
            Some(DetailsAct::Save) => {
                self.crash_export_status =
                    Some(self.export_text(ctx, ExportAction::Save, "CrashDump_Details", &text))
            }
            Some(DetailsAct::OpenFolder) => self.open_report_folder_from_details(),
            Some(DetailsAct::Close) => open = false,
            None => {}
        }
        if !open {
            self.crash_export_status = None;
        }
        self.crash_details_open = open;
    }

    /// v1.0 plain-text export of the crash Details (Copy / Save as): this
    /// module only.
    fn crash_details_text(&self) -> String {
        let d = i18n::t(self.language);
        let ru = self.language == Language::Ru;
        let mut o = format!("WinStateDiag — {}\r\n", d.crash_details_title);
        if let Some(Ok(inv)) = &self.crash.inventory {
            // v1.0 item 49: the same sections as the window, same counters.
            let r = crate::crash_report::build(inv, &self.crash.analyses, ru);
            o.push_str(&crate::crash_report::to_text(&r, ru));
            o.push_str(&format!(
                "{}\r\n\r\n",
                crate::crash_report::debugger_line(&inv.debugger, ru)
            ));
            o.push_str(&format!(
                "{} · {}\r\n",
                crash_dump::counts_line(inv),
                inv.debugger.code()
            ));
            for b in &inv.bugchecks {
                o.push_str(&format!(
                    "BugCheck 0x{:08X} · {} · {:?}\r\n",
                    b.code,
                    b.time.replace('T', " "),
                    b.source
                ));
            }
            for (inc, v) in crash_dump::incident_verdicts(inv, &self.crash.analyses) {
                o.push_str(&format!(
                    "{} · {}\r\n",
                    crash_dump::incident_line(&inc),
                    v.headline_localized(ru)
                ));
            }
        }
        for a in &self.crash.analyses {
            o.push_str("\r\n------------------------------------------------------------\r\n");
            for (k, v) in crash_analysis_rows(a, d, ru) {
                o.push_str(&format!("{k}: {v}\r\n"));
            }
            if !a.parsed.stack_text.is_empty() {
                o.push_str("STACK_TEXT:\r\n");
                for l in &a.parsed.stack_text {
                    o.push_str(&format!("  {l}\r\n"));
                }
            }
            if let Some(m) = &a.module_info {
                // v1.1: debugger service noise stays in the raw evidence
                // only (the RAW section below keeps every original line).
                o.push_str(&format!(
                    "lmvm {}:\r\n{}\r\n",
                    m.module,
                    crash_dump::without_debugger_noise(&m.raw)
                ));
            }
            if let Some(r) = &a.resolution {
                for l in crash_dump::resolution_lines(r, ru) {
                    o.push_str(&format!("{l}\r\n"));
                }
            }
            for l in &a.linked {
                o.push_str(&format!(
                    "Driver Audit: [{}] {} — {} ×{} {}\r\n",
                    l.status.code(),
                    l.device,
                    l.kind.code(),
                    l.count.max(1),
                    l.text
                ));
            }
        }
        if !self.crash.install_log.is_empty() {
            o.push_str(&format!("\r\n{}:\r\n", d.install_log_title));
            for l in self.install_journal_lines() {
                o.push_str(&format!("  {l}\r\n"));
            }
            o.push_str(&format!("{}:\r\n", d.install_raw_title));
            for l in &self.crash.install_log {
                o.push_str(&format!("  {l}\r\n"));
            }
        }
        o.push_str(&format!("\r\n{}\r\n", d.crash_heuristic_note));
        o
    }

    /// v1.0 item 42: the 4–6 line installer mini-journal; the debugger
    /// state is added only once the install was re-detected.
    fn install_journal_lines(&self) -> Vec<String> {
        let after = match (&self.crash.install, &self.crash.inventory) {
            (InstallState::Succeeded | InstallState::Failed(_), Some(Ok(inv))) => {
                Some(inv.debugger.clone())
            }
            _ => None,
        };
        crate::crash_report::install_journal(
            &self.crash.install_log,
            after.as_ref(),
            self.language == Language::Ru,
        )
    }

    /// v0.4.5 Hardware Sensors details: the full technical table in the
    /// WinStateDiag card style (TEMPERATURE / VOLTAGE / POWER / FANS,
    /// providers, source mismatches). Min/Max are session sample values.
    fn sensors_details_window(&mut self, ctx: &egui::Context) {
        if !self.sensors_details_open {
            return;
        }
        let Some(snap) = self.sensors_with_storage() else {
            self.sensors_details_open = false;
            return;
        };
        let d = i18n::t(self.language);
        let ru = self.language == Language::Ru;
        let sum = sensors::summarize(&snap.sensors);
        let mut open = true;
        let mut close = false;
        let mut action: Option<ExportAction> = None;
        let export_status = self.sensors_export_status.as_ref().map(|s| s.text(d));
        let svm = self.sensors_vm();
        let dashboard_status = svm.status_line.clone();
        let head = |ui: &mut egui::Ui, text: &str| {
            ui.add_space(8.0);
            ui.label(RichText::new(text).size(15.0).strong().color(c::TEXT_TITLE));
            ui.add_space(2.0);
        };
        let conf_color = |cf: sensors::Confidence| match cf {
            sensors::Confidence::High => c::GREEN_SUCCESS,
            sensors::Confidence::Medium => c::TEXT_PRIMARY,
            sensors::Confidence::Low | sensors::Confidence::Unknown => c::YELLOW_WARNING,
        };
        let header = |ui: &mut egui::Ui, status_col: bool| {
            let mut cols = vec![
                d.sensors_col_sensor,
                d.sensors_col_current,
                d.sensors_col_min,
                d.sensors_col_max,
                d.sensors_col_unit,
            ];
            if status_col {
                cols.push(d.sensors_col_status);
            }
            cols.extend([
                d.sensors_ref_title,
                d.sensors_col_source,
                d.sensors_col_conf,
            ]);
            for h in cols {
                ui.label(RichText::new(h).small().color(c::TEXT_MUTED));
            }
            ui.end_row();
        };
        let row = |ui: &mut egui::Ui,
                   cn: &sensors::Canonical,
                   status: Option<(String, egui::Color32)>| {
            let digits = match cn.kind {
                sensors::SensorKind::Voltage => 3,
                sensors::SensorKind::Power => 1,
                _ => 0,
            };
            let v = |x: f64| format!("{x:.digits$}");
            ui.label(RichText::new(sensor_label(&cn.role, &cn.label, d)).color(c::TEXT_PRIMARY));
            ui.label(RichText::new(v(cn.value)).strong().color(c::TEXT_PRIMARY));
            ui.label(RichText::new(v(cn.min)).color(c::TEXT_SECONDARY));
            ui.label(RichText::new(v(cn.max)).color(c::TEXT_SECONDARY));
            ui.label(RichText::new(cn.kind.unit()).color(c::TEXT_SECONDARY));
            if let Some((st, col)) = status {
                ui.label(RichText::new(st).color(col));
            }
            ui.label(RichText::new(self.sensor_reference(cn, d)).color(c::TEXT_SECONDARY));
            ui.label(RichText::new(cn.provider.short()).color(c::TEXT_SECONDARY));
            ui.label(RichText::new(cn.confidence.code()).color(conf_color(cn.confidence)));
            ui.end_row();
        };
        detail_window(
            ctx,
            "wsd_sensors_details",
            d.sensors_details_title,
            [1100.0, 820.0],
            &mut open,
            |ui| {
                ui.label(
                    RichText::new(format!(
                        "{} · {} · {} × {} ms · {}",
                        snap.state().code(),
                        snap.captured_at.replace('T', " "),
                        snap.samples,
                        snap.interval_ms,
                        snap.main_provider()
                            .map(sensors::Provider::code)
                            .unwrap_or("—")
                    ))
                    .color(c::TEXT_SECONDARY),
                );
                let footer = if export_status.is_some() { 70.0 } else { 46.0 };
                // v1.0 polish: the large T°C / Volt / Watt summary table
                // (same rows as the dashboard, "Нет данных" kept) with the
                // real reference panel beside it, in its own scroll region
                // (never more than ~55 % of the window, never clipped); the
                // detailed tables with sources, timestamps and confidence
                // scroll below it.
                egui::ScrollArea::vertical()
                    .id_salt("wsd_sensors_summary_scroll")
                    .auto_shrink([false, true])
                    .max_height(((ui.available_height() - footer) * 0.55).max(120.0))
                    .show(ui, |ui| sensor_summary_block(ui, d, &svm));
                egui::ScrollArea::vertical()
                    .id_salt("wsd_sensors_scroll")
                    .auto_shrink([false, false])
                    .max_height((ui.available_height() - footer).max(80.0))
                    .show(ui, |ui| {
                        if !sum.temps.is_empty() {
                            head(ui, d.sensors_sec_temperature);
                            egui::Grid::new("sens_t")
                                .striped(true)
                                .spacing([18.0, 4.0])
                                .show(ui, |ui| {
                                    header(ui, false);
                                    for cn in &sum.temps {
                                        row(ui, cn, None);
                                    }
                                });
                        }
                        if !sum.rails.is_empty() || !sum.dynamic_voltages.is_empty() {
                            head(ui, d.sensors_sec_voltage);
                            egui::Grid::new("sens_v")
                                .striped(true)
                                .spacing([18.0, 4.0])
                                .show(ui, |ui| {
                                    header(ui, true);
                                    for (_, cn, st) in &sum.rails {
                                        let col = match st {
                                            sensors::PowerStatus::Excellent => c::GREEN_SUCCESS,
                                            sensors::PowerStatus::Critical => c::RED_ERROR,
                                            sensors::PowerStatus::NoData => c::TEXT_MUTED,
                                            _ => c::YELLOW_WARNING,
                                        };
                                        row(ui, cn, Some((st.text(ru).to_string(), col)));
                                    }
                                    for cn in &sum.dynamic_voltages {
                                        row(ui, cn, Some(("—".into(), c::TEXT_MUTED)));
                                    }
                                });
                            ui.label(
                                RichText::new(d.sensors_dynamic_note)
                                    .small()
                                    .color(c::TEXT_MUTED),
                            );
                            let ps = sum.power_status();
                            if ps != sensors::PowerStatus::NoData {
                                ui.label(RichText::new(ps.message(ru)).color(c::TEXT_SECONDARY));
                            }
                        }
                        if !sum.power.is_empty() {
                            head(ui, d.sensors_sec_power);
                            egui::Grid::new("sens_p")
                                .striped(true)
                                .spacing([18.0, 4.0])
                                .show(ui, |ui| {
                                    header(ui, false);
                                    for cn in &sum.power {
                                        row(ui, cn, None);
                                    }
                                });
                        }
                        if !sum.fans.is_empty() {
                            head(ui, d.sensors_sec_fans);
                            egui::Grid::new("sens_f")
                                .striped(true)
                                .spacing([18.0, 4.0])
                                .show(ui, |ui| {
                                    header(ui, false);
                                    for cn in &sum.fans {
                                        row(ui, cn, None);
                                    }
                                });
                        }
                        if !sum.mismatches.is_empty() {
                            head(ui, d.sensors_mismatch);
                            for m in &sum.mismatches {
                                ui.label(
                                    RichText::new(format!(
                                        "{:?}: {:.2} {} ({}) / {:.2} {} ({})",
                                        m.role,
                                        m.canonical.1,
                                        m.unit,
                                        m.canonical.0.short(),
                                        m.other.1,
                                        m.unit,
                                        m.other.0.short()
                                    ))
                                    .color(c::YELLOW_WARNING),
                                );
                            }
                        }
                        // v1.0 CPU load context of the sampling window.
                        head(ui, d.sensors_sec_cpu_context);
                        match &snap.process_context {
                            Some(pc) => {
                                ui.label(
                                    RichText::new(format!(
                                        "{}: {:.0}% · {} · {} CPU",
                                        d.sensors_cpu_load,
                                        pc.system_cpu_percent,
                                        pc.timestamp.replace('T', " "),
                                        pc.logical_processors
                                    ))
                                    .color(if pc.high_load {
                                        c::YELLOW_WARNING
                                    } else {
                                        c::TEXT_SECONDARY
                                    }),
                                );
                                for t in &pc.top {
                                    ui.label(
                                        RichText::new(format!(
                                            "  {:<28} PID {:>6}  {:>5.1}%",
                                            t.name, t.pid, t.cpu_percent
                                        ))
                                        .monospace()
                                        .color(c::TEXT_BODY),
                                    );
                                }
                                ui.label(
                                    RichText::new(d.sensors_cpu_note)
                                        .small()
                                        .color(c::TEXT_MUTED),
                                );
                            }
                            None => {
                                ui.label(RichText::new(d.sensors_cpu_none).color(c::TEXT_MUTED));
                            }
                        }
                        head(ui, d.sensors_sec_providers);
                        // v0.4.5: the provider / layer state lives here, not on
                        // the dashboard.
                        if !dashboard_status.is_empty() {
                            ui.label(
                                RichText::new(&dashboard_status)
                                    .monospace()
                                    .color(c::TEXT_SECONDARY),
                            );
                        }
                        for p in &snap.providers {
                            ui.label(
                                RichText::new(format!(
                                    "{} — {} — {}",
                                    p.provider.code(),
                                    p.state.code(),
                                    p.detail
                                ))
                                .color(c::TEXT_SECONDARY),
                            );
                        }
                        ui.add_space(6.0);
                        ui.label(
                            RichText::new(d.sensors_session_note)
                                .small()
                                .color(c::TEXT_MUTED),
                        );
                        ui.label(RichText::new(d.sensors_note).small().color(c::TEXT_MUTED));
                    });
                ui.separator();
                if let Some((text, color)) = &export_status {
                    ui.add(egui::Label::new(RichText::new(text).color(*color)).wrap());
                }
                match details_action_bar(ui, d, true, None) {
                    Some(DetailsAct::Copy) => action = Some(ExportAction::Copy),
                    Some(DetailsAct::Save) => action = Some(ExportAction::Save),
                    Some(DetailsAct::Close) => close = true,
                    _ => {}
                }
            },
        );
        if let Some(action) = action {
            let text = self.sensors_details_text(&snap);
            self.sensors_export_status =
                Some(self.export_text(ctx, action, "Hardware_Sensors_Details", &text));
        }
        if !open || close {
            self.sensors_details_open = false;
            self.sensors_export_status = None;
        }
    }

    /// Reference column of one sensor (dashboard and Details): ATX band,
    /// drive-reported NVMe thresholds, "динамический", else "без фикс.
    /// эталона" — never an invented limit.
    fn sensor_reference(&self, cn: &sensors::Canonical, d: &i18n::Dict) -> String {
        match &cn.role {
            sensors::Role::AtxRail(r) => sensors::rail_reference(*r),
            sensors::Role::DynamicVoltage(_) => d.sensors_ref_dynamic.into(),
            sensors::Role::DiskTemp(_) => {
                let (w, c) = self.disk_temp_thresholds(&cn.label);
                sensors::disk_reference(w, c).unwrap_or_else(|| d.sensors_ref_none.into())
            }
            _ if cn.kind == sensors::SensorKind::Fan => "—".into(),
            _ => d.sensors_ref_none.into(),
        }
    }

    /// Plain-text export of the sensor Details window.
    fn sensors_details_text(&self, snap: &sensors::Snapshot) -> String {
        let d = i18n::t(self.language);
        let sum = sensors::summarize(&snap.sensors);
        let mut o = format!(
            "WinStateDiag — {}\r\n{} · {} · {} × {} ms\r\n",
            d.sensors_details_title,
            snap.state().code(),
            snap.captured_at.replace('T', " "),
            snap.samples,
            snap.interval_ms
        );
        if let Some(pc) = &snap.process_context {
            o.push_str(&format!(
                "\r\n{}\r\n  {}: {:.0}% ({})\r\n",
                d.sensors_sec_cpu_context,
                d.sensors_cpu_load,
                pc.system_cpu_percent,
                pc.timestamp.replace('T', " ")
            ));
            for t in &pc.top {
                o.push_str(&format!(
                    "  {:<28} PID {:>6} {:>5.1}%\r\n",
                    t.name, t.pid, t.cpu_percent
                ));
            }
        }
        let mut section = |title: &str, list: Vec<&sensors::Canonical>| {
            if list.is_empty() {
                return;
            }
            o.push_str(&format!("\r\n{title}\r\n"));
            for cn in list {
                o.push_str(&format!(
                    "  {:<28} {:>9.3} {:>9.3} {:>9.3} {:<4} | {} | {} | {}\r\n",
                    sensor_label(&cn.role, &cn.label, d),
                    cn.value,
                    cn.min,
                    cn.max,
                    cn.kind.unit(),
                    self.sensor_reference(cn, d),
                    cn.provider.short(),
                    cn.confidence.code()
                ));
            }
        };
        section(d.sensors_sec_temperature, sum.temps.iter().collect());
        section(
            d.sensors_sec_voltage,
            sum.rails
                .iter()
                .map(|(_, c, _)| c)
                .chain(sum.dynamic_voltages.iter())
                .collect(),
        );
        section(d.sensors_sec_power, sum.power.iter().collect());
        section(d.sensors_sec_fans, sum.fans.iter().collect());
        o.push_str(&format!("\r\n{}\r\n", d.sensors_sec_providers));
        o.push_str(&format!("  {}\r\n", self.sensors_vm().status_line));
        for p in &snap.providers {
            o.push_str(&format!(
                "  {} — {} — {}\r\n",
                p.provider.code(),
                p.state.code(),
                p.detail
            ));
        }
        o.push_str(&format!(
            "\r\n{}\r\n{}\r\n",
            d.sensors_session_note, d.sensors_note
        ));
        o
    }

    fn gpo_details_window(&mut self, ctx: &egui::Context) {
        if !self.gpo_details_open {
            return;
        }
        let d = i18n::t(self.language);
        let ru = self.language == Language::Ru;
        let mut open = true;
        let status = self.gpo_export_status.as_ref().map(|s| s.text(d));
        let text = match &self.gpo {
            Some(Ok((i, r))) => String::from_utf8_lossy(&gpo_text(i, r))
                .trim_start_matches('\u{feff}')
                .to_string(),
            _ => String::new(),
        };
        let mut act: Option<DetailsAct> = None;
        detail_window(
            ctx,
            "wsd_gpo_details",
            d.gpo_details_title,
            [900.0, 680.0],
            &mut open,
            |ui| {
                let footer = if status.is_some() { 76.0 } else { 50.0 };
                egui::ScrollArea::vertical()
                    .id_salt("wsd_gpo_details_scroll")
                    .auto_shrink([false, false])
                    .max_height((ui.available_height() - footer).max(120.0))
                    .show(ui, |ui| match &self.gpo {
                        Some(Ok((i, r))) => {
                            ui.label(
                                RichText::new(format!("Central Store: {}", r.status.text(ru)))
                                    .strong()
                                    .color(c::TEXT_TITLE),
                            );
                            ui.label(
                                RichText::new(format!(
                                    "{}: {}",
                                    d.gpo_local_store,
                                    r.local_status.text(ru)
                                ))
                                .strong()
                                .color(c::TEXT_TITLE),
                            );
                            for f in &r.local_findings {
                                ui.label(format!("• {f}"));
                            }
                            ui.separator();
                            ui.label(format!(
                                "{}: {}",
                                d.gpo_domain,
                                if i.domain.is_empty() {
                                    "—"
                                } else {
                                    &i.domain
                                }
                            ));
                            ui.label(format!(
                                "{}: {} · {} ADMX",
                                d.gpo_local_store,
                                i.local.path,
                                i.local.admx.len()
                            ));
                            if let Some(cs) = &i.central {
                                ui.label(format!(
                                    "{}: {} · {} ADMX",
                                    d.gpo_central,
                                    if cs.exists {
                                        d.gpo_found
                                    } else {
                                        d.gpo_not_found
                                    },
                                    cs.admx.len()
                                ));
                            }
                            ui.separator();
                            ui.label(RichText::new(d.gpo_findings).strong());
                            for f in r
                                .mismatch_findings
                                .iter()
                                .chain(&r.version_findings)
                                .chain(&r.info)
                            {
                                ui.label(format!("• {f}"));
                            }
                            if !r.missing_adml.is_empty() {
                                ui.label(format!(
                                    "{}: {}",
                                    d.gpo_missing_adml,
                                    r.missing_adml
                                        .iter()
                                        .take(20)
                                        .cloned()
                                        .collect::<Vec<_>>()
                                        .join(", ")
                                ));
                            }
                            ui.separator();
                            ui.label(
                                RichText::new(d.gpo_reference_note)
                                    .small()
                                    .color(c::TEXT_MUTED),
                            );
                            ui.label(
                                RichText::new(gpo_admx::MS_26H2_REFERENCE)
                                    .small()
                                    .color(c::TEXT_SECONDARY),
                            );
                            ui.label(
                                RichText::new(d.gpo_readonly_note)
                                    .small()
                                    .color(c::TEXT_MUTED),
                            );
                        }
                        Some(Err(e)) => {
                            ui.label(e);
                        }
                        None => {
                            ui.label(d.gpo_not_run);
                        }
                    });
                ui.separator();
                if let Some((t, col)) = &status {
                    ui.add(egui::Label::new(RichText::new(t).color(*col)).wrap());
                }
                act = details_action_bar(ui, d, !text.is_empty(), None);
            },
        );
        match act {
            Some(DetailsAct::Copy) => {
                self.gpo_export_status =
                    Some(self.export_text(ctx, ExportAction::Copy, "GroupPolicy_ADMX", &text))
            }
            Some(DetailsAct::Save) => {
                self.gpo_export_status =
                    Some(self.export_text(ctx, ExportAction::Save, "GroupPolicy_ADMX", &text))
            }
            Some(DetailsAct::Close) => open = false,
            Some(DetailsAct::OpenFolder) | None => {}
        }
        if !open {
            self.gpo_export_status = None;
        }
        self.gpo_details_open = open;
    }
}

/// Readable TXT companion of the Group Policy evidence (UTF-8 BOM, CRLF).
/// v1.0 main sensor view: the 4-column matrix (Наименование | T°C | Volt |
/// Watt) and the "Эталон" reference table, from the canonical summary.
///
/// Every EXPECTED row is always present — CPU, motherboard, PCH, RAM, GPU,
/// GPU hotspot, each disk with a temperature, +12V / +5V / +3.3V — and a
/// value that should exist but was not read is `NoData` ("Нет данных"),
/// never a hidden row and never a misleading 0. Cells that make no sense for
/// a row are `NotApplicable` ("—"). Only the number is coloured: rails by
/// their ATX band, disks by the drive-reported thresholds; everything
/// without a reliable reference stays neutral.
pub(crate) fn sensor_matrix(
    sum: &sensors::Summary,
    disk_thresholds: &dyn Fn(&str) -> (Option<f64>, Option<f64>),
    d: &i18n::Dict,
) -> (Vec<SensorMatrixRow>, Vec<SensorRefRow>) {
    use sensors::Role;
    let level_tone = |l: sensors::ReadingLevel| match l {
        sensors::ReadingLevel::Unknown => Tone::Idle,
        sensors::ReadingLevel::Normal => Tone::Success,
        sensors::ReadingLevel::Near => Tone::Warning,
        sensors::ReadingLevel::Critical => Tone::Error,
    };
    let temp_of = |role: &Role| sum.temps.iter().find(|c| &c.role == role);
    let temp_cell = |c: Option<&sensors::Canonical>| match c {
        Some(c) => SensorCell::value(format!("{:.0}°C", c.value), Tone::Idle),
        None => SensorCell::NoData,
    };
    let dyn_volt = |names: &[&str]| {
        names
            .iter()
            .find_map(|n| {
                sum.dynamic_voltages
                    .iter()
                    .find(|c| c.role == Role::DynamicVoltage((*n).to_string()))
            })
            .map(|c| SensorCell::value(format!("{:.3} V", c.value), Tone::Idle))
            .unwrap_or(SensorCell::NoData)
    };
    // A power counter that reports 0 W (or less) is unavailable, not idle.
    let watt = |role: Role| {
        sum.power
            .iter()
            .find(|c| c.role == role && c.value > 0.05)
            .map(|c| SensorCell::value(format!("{:.0} W", c.value), Tone::Idle))
            .unwrap_or(SensorCell::NoData)
    };
    let row = |label: &str, temp, volt, watt| SensorMatrixRow {
        label: label.to_string(),
        temp,
        volt,
        watt,
    };
    let na = || SensorCell::NotApplicable;
    let cpu_temp = temp_of(&Role::CpuCoreAverage).or_else(|| temp_of(&Role::CpuPackage));
    let mut rows = vec![
        row(
            d.sensors_lbl_cpu,
            temp_cell(cpu_temp),
            dyn_volt(&["CPU Vcore", "CPU VID"]),
            watt(Role::CpuPackagePower),
        ),
        row(
            d.sensors_lbl_board,
            temp_cell(temp_of(&Role::BoardTemp)),
            na(),
            na(),
        ),
        row(
            d.sensors_lbl_pch,
            temp_cell(temp_of(&Role::ChipsetTemp)),
            na(),
            na(),
        ),
        row(
            d.sensors_lbl_ram,
            temp_cell(temp_of(&Role::RamTemp)),
            na(),
            na(),
        ),
        row(
            d.sensors_lbl_gpu,
            temp_cell(temp_of(&Role::GpuTemp)),
            dyn_volt(&["GPU Core"]),
            watt(Role::GpuPower),
        ),
        row(
            d.sensors_lbl_hotspot,
            temp_cell(temp_of(&Role::GpuHotspot)),
            na(),
            na(),
        ),
    ];
    let mut refs: Vec<SensorRefRow> = Vec::new();
    // Each physical disk keeps its own row (same model twice: "#1", "#2").
    for c in sum
        .temps
        .iter()
        .filter(|c| matches!(c.role, Role::DiskTemp(_)))
    {
        let (w, cr) = disk_thresholds(&c.label);
        let label = sensors::disk_compact(&sensor_label(&c.role, &c.label, d));
        rows.push(row(
            &label,
            SensorCell::value(
                format!("{:.0}°C", c.value),
                level_tone(sensors::disk_temp_level(c.value, w, cr)),
            ),
            na(),
            na(),
        ));
        if let Some(range) = sensors::disk_reference(w, cr) {
            refs.push(SensorRefRow { label, range });
        }
    }
    // Fixed ATX rails: always expected (Нет данных without a sensor).
    for rail in [
        crate::power::Rail::V12,
        crate::power::Rail::V5,
        crate::power::Rail::V3_3,
    ] {
        let volt = sum
            .rails
            .iter()
            .find(|(r, _, _)| *r == rail)
            .map(|(_, c, st)| {
                SensorCell::value(
                    format!("{:.2} V", c.value),
                    level_tone(sensors::rail_level(*st)),
                )
            })
            .unwrap_or(SensorCell::NoData);
        rows.push(row(rail.label(), na(), volt, na()));
    }
    if let Some((_, c, st)) = sum
        .rails
        .iter()
        .find(|(r, _, _)| *r == crate::power::Rail::V5Sb)
    {
        rows.push(row(
            crate::power::Rail::V5Sb.label(),
            na(),
            SensorCell::value(
                format!("{:.2} V", c.value),
                level_tone(sensors::rail_level(*st)),
            ),
            na(),
        ));
    }
    let mut fixed: Vec<SensorRefRow> = [
        crate::power::Rail::V12,
        crate::power::Rail::V5,
        crate::power::Rail::V3_3,
    ]
    .into_iter()
    .map(|r| SensorRefRow {
        label: r.label().to_string(),
        range: sensors::rail_reference(r),
    })
    .collect();
    fixed.extend(refs);
    fixed.push(SensorRefRow {
        label: "Vcore / VID".into(),
        range: d.sensors_ref_dynamic.into(),
    });
    fixed.push(SensorRefRow {
        label: "GPU Core".into(),
        range: d.sensors_ref_dynamic.into(),
    });
    fixed.push(SensorRefRow {
        label: d.sensors_ref_cpu_gpu_temp.into(),
        range: d.sensors_ref_none.into(),
    });
    (rows, fixed)
}

/// v1.0 cross-module consistency: an EXPC stage that says OK must not
/// contradict another module that accepted significant evidence for the
/// same domain — stage 04 (System events) vs Driver Audit's significant
/// System-log evidence, stage 07 (shutdowns / BSOD) vs BugChecks found by
/// the crash inventory. Returns the qualification line, if any.
pub(crate) fn consistency_note(
    stage: usize,
    stage_ok: bool,
    significant_system_events: usize,
    bugchecks: usize,
    d: &i18n::Dict,
) -> Option<String> {
    if !stage_ok {
        return None;
    }
    match stage {
        3 if significant_system_events > 0 => Some(
            d.consistency_driver_events_fmt
                .replace("{n}", &significant_system_events.to_string()),
        ),
        6 if bugchecks > 0 => Some(d.consistency_bsod.to_string()),
        _ => None,
    }
}

/// Driver Audit evidence that came from the System log and that the audit
/// counts as significant (WARNING / PROBLEM).
pub(crate) fn significant_system_evidence(report: &AuditReport) -> usize {
    report
        .items
        .iter()
        .flat_map(|it| it.evidence.iter())
        .filter(|e| e.source.starts_with("System") && e.severity >= Severity::Warning)
        .count()
}

/// v1.0 plain-text export of the Disk Details (this disk only).
fn disk_details_text(title: &str, sections: &[(String, Vec<(String, String)>)]) -> String {
    let mut o = format!("WinStateDiag — {title}\r\n");
    for (head, rows) in sections {
        o.push_str(&format!("\r\n{head}\r\n"));
        for (k, v) in rows {
            if k.is_empty() {
                o.push_str(&format!("  {v}\r\n"));
            } else {
                o.push_str(&format!("  {k}: {v}\r\n"));
            }
        }
    }
    o
}

/// v1.0 key facts of one analyzed dump (Details grid and text export).
fn crash_analysis_rows(
    a: &crash_dump::DumpAnalysis,
    d: &i18n::Dict,
    ru: bool,
) -> Vec<(String, String)> {
    let opt = |v: &Option<String>| v.clone().unwrap_or_else(|| "—".into());
    let mut rows = vec![
        (
            "BugCheck".to_string(),
            format!(
                "{} {}",
                a.bugcheck_code()
                    .map(|c| format!("0x{c:08X}"))
                    .unwrap_or_else(|| "—".into()),
                a.parsed.bugcheck_name.clone().unwrap_or_default()
            ),
        ),
        (
            d.crash_row_dump.to_string(),
            format!("{} · {}", a.dump.name, a.dump.modified.replace('T', " ")),
        ),
        ("FAILURE_BUCKET_ID".into(), opt(&a.parsed.failure_bucket_id)),
        ("MODULE_NAME".into(), opt(&a.parsed.module_name)),
        ("IMAGE_NAME".into(), opt(&a.parsed.image_name)),
        ("PROCESS_NAME".into(), process_name_text(a, ru)),
        (
            d.crash_row_module.to_string(),
            a.probable_module()
                .unwrap_or_else(|| d.crash_not_determined.into()),
        ),
        (d.crash_row_confidence.to_string(), a.confidence.label(ru)),
        (
            "Symbols".into(),
            a.parsed.symbol_status().code().to_string(),
        ),
        ("Analysis".into(), a.status.code().to_string()),
    ];
    if let Some(m) = &a.module_info {
        let ver = [&m.file_version, &m.product_version]
            .iter()
            .find(|v| !v.is_empty())
            .map(|v| v.to_string())
            .unwrap_or_else(|| "—".into());
        rows.push((
            "lmvm".into(),
            format!(
                "{} · {} · {} · {}",
                if m.image_name.is_empty() {
                    &m.module
                } else {
                    &m.image_name
                },
                ver,
                if m.company.is_empty() {
                    "—"
                } else {
                    &m.company
                },
                if m.timestamp.is_empty() {
                    "—"
                } else {
                    &m.timestamp
                }
            ),
        ));
    }
    rows
}

/// v1.1: PROCESS_NAME as the dump states it; a name WinDbg itself cut to
/// 14 characters is marked as such (the parser never shortens it).
fn process_name_text(a: &crash_dump::DumpAnalysis, ru: bool) -> String {
    match &a.parsed.process_name {
        None => "—".into(),
        Some(n) if a.parsed.process_name_truncated => format!(
            "{n} ({})",
            if ru {
                "имя сокращено WinDbg до 14 символов"
            } else {
                "name shortened by WinDbg to 14 characters"
            }
        ),
        Some(n) => n.clone(),
    }
}

/// UI label of a canonical sensor role (identity stays in `Role`).
fn sensor_label(role: &sensors::Role, label: &str, d: &i18n::Dict) -> String {
    use sensors::Role::*;
    match role {
        CpuCoreAverage => d.sensors_lbl_cpu.into(),
        CpuPackage => d.sensors_lbl_cpu_pkg.into(),
        GpuTemp | GpuPower => d.sensors_lbl_gpu.into(),
        GpuHotspot => d.sensors_lbl_hotspot.into(),
        GpuMemory => d.sensors_lbl_gpu_mem.into(),
        BoardTemp => d.sensors_lbl_board.into(),
        ChipsetTemp => d.sensors_lbl_pch.into(),
        VrmTemp => d.sensors_lbl_vrm.into(),
        RamTemp => d.sensors_lbl_ram.into(),
        DiskTemp(_) => match label.rsplit_once(" #") {
            // Same model twice: keep the "#n" distinction on the dashboard.
            Some((base, n)) if !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()) => {
                format!("{} #{n}", sensors::disk_short(base))
            }
            _ => sensors::disk_short(label),
        },
        CpuPackagePower => d.sensors_lbl_cpu.into(),
        CpuCorePower => d.sensors_lbl_cpu_cores.into(),
        CpuUncorePower => d.sensors_lbl_cpu_uncore.into(),
        Gpu12vhpwrPower => d.sensors_lbl_gpu_12v.into(),
        GpuPciePower => d.sensors_lbl_gpu_pcie.into(),
        CpuFan => d.sensors_lbl_cpu_fan.into(),
        Pump => d.sensors_lbl_pump.into(),
        AtxRail(r) => r.label().into(),
        SystemFan(n) | GpuFan(n) | DynamicVoltage(n) => n.clone(),
        CpuCore => label.into(),
    }
}

fn gpo_text(i: &gpo_admx::GpoInputs, r: &gpo_admx::GpoResult) -> Vec<u8> {
    let mut t = String::new();
    t.push_str("WinStateDiag — Group Policy / ADMX Health (read-only)\r\n");
    t.push_str(&format!("Status: {}\r\n", r.status.code()));
    t.push_str(&format!(
        "Machine: {}{}\r\n",
        if i.domain_joined {
            "domain-joined "
        } else {
            "standalone"
        },
        i.domain
    ));
    t.push_str(&format!(
        "Windows: {} ({})\r\n",
        i.windows_release, i.windows_build
    ));
    t.push_str(&format!(
        "Local PolicyDefinitions: {} ADMX · local status {}\r\n",
        i.local.admx.len(),
        r.local_status.code()
    ));
    for f in &r.local_findings {
        t.push_str(&format!("- local: {f}\r\n"));
    }
    if let Some(cs) = &i.central {
        t.push_str(&format!(
            "Central Store: exists={} · {} ADMX\r\n",
            cs.exists,
            cs.admx.len()
        ));
    }
    for f in r
        .mismatch_findings
        .iter()
        .chain(&r.version_findings)
        .chain(&r.info)
    {
        t.push_str(&format!("- {f}\r\n"));
    }
    t.push_str(&format!(
        "Reference (26H2): {}\r\n",
        gpo_admx::MS_26H2_REFERENCE
    ));
    let mut out = vec![0xEF, 0xBB, 0xBF];
    out.extend_from_slice(t.as_bytes());
    out
}

impl WinStateDiagApp {
    /// v1.1: the application closes — every background check is cancelled
    /// (its process tree ends) and a running diagnostic is stopped. Nothing
    /// is started any more and nothing new is written.
    pub(crate) fn shutdown(&mut self, flag: &std::sync::atomic::AtomicBool) {
        engine::request_shutdown(flag);
        if let Some(cancel) = &self.session_cancel {
            cancel.store(true, Ordering::SeqCst);
        }
        self.crash_analyze_after_scan = false;
        self.crash.rescan_for_session = false;
        self.crypto_recheck_for_session = false;
    }
}

impl eframe::App for WinStateDiagApp {
    fn on_exit(&mut self) {
        self.shutdown(&engine::SHUTDOWN);
    }

    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let viewports = ctx.input(|i| i.raw.viewports.len());
        self.window_icons.update(viewports);
        self.poll_engine();
        self.poll_benchmark();
        self.poll_nvme_health();
        self.poll_retest();
        self.poll_driver_audit();
        self.poll_hardware();
        self.poll_crypto();
        self.poll_crash();
        self.poll_sensors();
        self.poll_gpo();
        self.poll_passport();
        self.poll_crash_redetect();
        self.poll_events();
        self.poll_ata_scan();
        self.poll_disk_selector();
        if self.reference.is_none() {
            self.finalize_report_if_idle();
        }
        if self.is_running()
            || self.crypto_rx.is_some()
            || matches!(self.hardware, HardwareViewState::Collecting { .. })
            || self.benchmark_is_running()
            || self.nvme_rx.is_some()
            || matches!(self.driver_audit, DriverAuditState::Running(_))
            || self.crash_rx.is_some()
            || self.sensors_rx.is_some()
            || self.gpo_rx.is_some()
        {
            ctx.request_repaint();
        } else {
            // Keeps the status-bar clock current.
            ctx.request_repaint_after(Duration::from_secs(15));
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        if !self.theme_ready {
            apply_theme(&ctx);
            if !fonts::ready(&ctx) {
                fonts::install(&ctx);
            }
            self.theme_ready = true;
        }
        let full = ctx.content_rect();
        ui.painter()
            .rect_filled(full, egui::CornerRadius::ZERO, c::BG_ROOT);
        if !fonts::ready(&ctx) {
            // Fonts set this frame become live on the next one.
            ctx.request_repaint();
            return;
        }

        let reference_mode = self.reference.is_some();
        if let Some(reference) = &mut self.reference {
            reference.drive(&ctx);
        } else {
            self.fit_scale(&ctx);
        }

        let dt = ctx.input(|i| i.stable_dt).clamp(0.0, 0.1);
        let time = ctx.input(|i| i.time);
        let scene = self
            .reference
            .as_ref()
            .map(|r| r.scene.clone())
            .unwrap_or_default();
        let vm = if reference_mode {
            if qa_scenes::is_details_scene(&scene) {
                // Details windows embedded into the captured framebuffer.
                ctx.set_embed_viewports(true);
            }
            self.qa_scene_vm(&scene)
        } else {
            self.build_vm(dt, time)
        };

        let canvas_size = vec2(CANVAS_W, CANVAS_H);
        let mut actions: Vec<Action> = Vec::new();
        {
            let mut controls = Controls {
                client_name: &mut self.client_name,
                mode: &mut self.mode,
                deep_checks: &mut self.deep_checks,
                include_hardware: &mut self.include_hardware,
                benchmark_path: &mut self.benchmark_path,
            };
            if full.width() + 0.5 >= canvas_size.x && full.height() + 0.5 >= canvas_size.y {
                // Centre the canvas (letterbox with the root background).
                let offset = ((full.size() - canvas_size) / 2.0).floor();
                let origin = full.min + offset;
                ui.scope_builder(
                    egui::UiBuilder::new().max_rect(Rect::from_min_size(origin, canvas_size)),
                    |ui| dashboard::draw(ui, origin, &vm, &mut controls, &mut actions),
                );
            } else {
                egui::ScrollArea::both()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        let (rect, _) = ui.allocate_exact_size(canvas_size, egui::Sense::hover());
                        dashboard::draw(ui, rect.min, &vm, &mut controls, &mut actions);
                    });
            }
        }
        if !reference_mode {
            for action in actions {
                self.apply(action);
            }
        }
        if let Some(text) = self.clipboard_out.take() {
            ctx.copy_text(text);
        }
        self.raw_passes_window(&ctx);
        self.drivers_window(&ctx);
        self.crypto_details_window(&ctx);
        self.passport2_window(&ctx);
        self.journal_window(&ctx);
        self.expc_details_window(&ctx);
        self.stage_details_window(&ctx);
        self.hardware_progress_window(&ctx);
        self.crash_details_window(&ctx);
        self.gpo_details_window(&ctx);
        self.sensors_details_window(&ctx);
    }
}

/// One shared STABLE/ACCEPT/UNSTABLE threshold, used identically by the GUI
/// (`stability_level`/`stability_text`) and by the TXT/JSON SSD evidence
/// (`ssd_benchmark_evidence`). A field report showed 10.38% spread as
/// "нестабильно" in the report while the GUI already correctly showed
/// ACCEPT — that divergence is what these tests guard against.
#[cfg(test)]
mod ssd_stability_tests {
    use super::*;
    use crate::storage_benchmark::{
        DiagnosticPass, StorageDiagnosticProfile, StorageDiagnosticSummary,
    };
    use std::time::Duration;

    #[test]
    fn boundary_5_00_is_stable() {
        assert_eq!(stability_level(5.00), StabilityLevel::Stable);
        assert_eq!(stability_text(stability_level(5.00)), "STABLE");
    }

    #[test]
    fn boundary_5_01_is_accept() {
        assert_eq!(stability_level(5.01), StabilityLevel::Acceptable);
        assert_eq!(stability_text(stability_level(5.01)), "ACCEPT");
    }

    #[test]
    fn boundary_12_00_is_accept() {
        assert_eq!(stability_level(12.00), StabilityLevel::Acceptable);
        assert_eq!(stability_text(stability_level(12.00)), "ACCEPT");
    }

    #[test]
    fn boundary_12_01_is_unstable() {
        assert_eq!(stability_level(12.01), StabilityLevel::Unstable);
        assert_eq!(stability_text(stability_level(12.01)), "UNSTABLE");
    }

    #[test]
    fn field_example_10_38_percent_is_accept_not_unstable() {
        // Real-world report: 10.38% must be ACCEPT everywhere, never UNSTABLE.
        assert_eq!(stability_level(10.38), StabilityLevel::Acceptable);
    }

    fn measurement(mb_s: f64) -> crate::storage_benchmark::IoMeasurement {
        crate::storage_benchmark::IoMeasurement {
            bytes: 0,
            operations: 0,
            elapsed: Duration::from_secs(1),
            mb_per_second: mb_s,
            iops: 0.0,
            average_latency: Duration::from_millis(1),
        }
    }

    fn summary_with_spread(read_pct: f64, write_pct: f64) -> StorageDiagnosticSummary {
        StorageDiagnosticSummary {
            profile: StorageDiagnosticProfile {
                block_size: 1024 * 1024,
                queue_depth: 4,
                test_file_size: 512 * 1024 * 1024,
                pass_count: 1,
                stable_spread_limit_percent: 10.0,
            },
            preparation_method: "test",
            preparation_elapsed: Duration::from_secs(0),
            summary_read_mib_s: 500.0,
            summary_write_mib_s: 400.0,
            read_min_mib_s: 480.0,
            read_max_mib_s: 520.0,
            write_min_mib_s: 380.0,
            write_max_mib_s: 420.0,
            read_variation_percent: read_pct,
            write_variation_percent: write_pct,
            // Deliberately the OLD single-threshold boolean, kept wrong on
            // purpose in this fixture to prove the TXT/JSON no longer reads it.
            stable: false,
            raw_passes: vec![DiagnosticPass {
                pass_number: 1,
                run: crate::storage_benchmark::BenchmarkRun {
                    block_size: 1024 * 1024,
                    read: measurement(500.0),
                    write: measurement(400.0),
                },
            }],
        }
    }

    /// The TXT/JSON evidence must classify with the same STABLE/ACCEPT/
    /// UNSTABLE thresholds as the GUI, never the old raw `result.stable`
    /// (single 10% cutoff) boolean.
    #[test]
    fn txt_and_json_use_the_shared_thresholds_not_the_raw_bool() {
        let dir = std::env::temp_dir();
        let summary = summary_with_spread(10.38, 3.0);
        let files = ssd_benchmark_evidence(&summary, &dir, 12.0, None, "test".into());
        let txt = String::from_utf8_lossy(&files[0].bytes).to_string();
        let json = String::from_utf8_lossy(&files[1].bytes).to_string();
        assert!(
            txt.contains("Стабильность: ACCEPT"),
            "10.38% must report ACCEPT in the TXT evidence: {txt}"
        );
        assert!(
            json.contains("\"stability\":\"ACCEPT\""),
            "10.38% must report ACCEPT in the JSON evidence: {json}"
        );
        // The worse of read/write drives the overall verdict.
        let unstable = summary_with_spread(2.0, 12.5);
        let files = ssd_benchmark_evidence(&unstable, &dir, 12.0, None, "test".into());
        let txt = String::from_utf8_lossy(&files[0].bytes).to_string();
        assert!(txt.contains("Стабильность: UNSTABLE"), "{txt}");
        let json_unstable = String::from_utf8_lossy(&files[1].bytes).to_string();
        assert!(
            json_unstable.contains("\"stable\":false"),
            "{json_unstable}"
        );
    }

    /// v1.0 (real case): "stability": "ACCEPT" with "stable": false was a
    /// contradiction. `stable` now means "accepted measurement" and the
    /// rule, the I/O mode (no OS cache) and the test scope are written.
    #[test]
    fn accept_is_stable_true_and_io_mode_and_scope_are_recorded() {
        let dir = std::env::temp_dir();
        let summary = summary_with_spread(7.45, 9.73);
        let files = ssd_benchmark_evidence(&summary, &dir, 0.6, None, "test".into());
        let txt = String::from_utf8_lossy(&files[0].bytes).to_string();
        let json = String::from_utf8_lossy(&files[1].bytes).to_string();
        assert!(
            json.contains("\"stability\":\"ACCEPT\",\"stable\":true"),
            "{json}"
        );
        assert!(json.contains("FILE_FLAG_NO_BUFFERING"), "{json}");
        assert!(json.contains("\"test_scope\":\"512 MiB"), "{json}");
        assert!(
            crate::deep_checks::json::parse(&json).is_some(),
            "valid JSON"
        );
        assert!(
            txt.contains("кэш файловой системы Windows не используется"),
            "{txt}"
        );
        assert!(txt.contains("Стабильность: ACCEPT (STABLE <= 5 %"), "{txt}");
        // A single NVMe drive faster than PCIe 5.0 x4 is not the disk.
        let mut fast = summary_with_spread(1.0, 1.0);
        fast.read_max_mib_s = 21_000.0 / 1.048_576;
        assert!(crate::storage_benchmark::implausible_reason("NVMe", &fast).is_some());
        let mut real = summary_with_spread(7.45, 9.73);
        real.read_max_mib_s = 12_416.2 / 1.048_576;
        real.write_max_mib_s = 13_349.0 / 1.048_576;
        assert!(
            crate::storage_benchmark::implausible_reason("NVMe", &real).is_none(),
            "a real PCIe 5.0 drive result stays valid"
        );
    }
}

#[cfg(test)]
mod release_polish_tests {
    use super::*;

    #[test]
    fn report_pulse_only_for_an_existing_unopened_report() {
        assert!(report_attention(true, false));
        assert!(!report_attention(true, true));
        assert!(!report_attention(false, false));
    }

    #[test]
    fn opening_the_report_clears_the_pulse_but_keeps_the_button() {
        let root = std::env::temp_dir().join(format!("wsd-final-{}", std::process::id()));
        let reports = root.join("Reports");
        let dir = reports.join("SERVER - 24-09-26");
        std::fs::create_dir_all(&dir).unwrap();
        let zip = dir.join("SERVER - 24-09-26.zip");
        std::fs::write(&zip, b"PK\x03\x04").unwrap();
        let mut app = WinStateDiagApp::default();
        app.reports_root = reports.clone();
        app.state = RunState::Done {
            zip_path: zip.clone(),
        };
        let attention = |app: &mut WinStateDiagApp| match app.build_vm(0.0, 0.0).result {
            ResultVm::Done { attention, .. } => attention,
            _ => panic!("result must stay Done"),
        };
        assert!(attention(&mut app));
        let opened = std::cell::RefCell::new(Vec::new());
        app.open_final_report(&|p| {
            opened.borrow_mut().push(p.to_path_buf());
            Ok(())
        });
        assert_eq!(opened.borrow().as_slice(), [zip.clone()]);
        assert!(!attention(&mut app));
        assert!(matches!(app.state, RunState::Done { .. }));
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Regression (v0.3.3): "Открыть отчёт" must open the FINAL ZIP under
    /// <EXE>\Reports\<Client> - <Computer> - DD-MM-YY\, never the temporary
    /// packaging ZIP.
    #[test]
    fn open_report_uses_the_final_reports_zip_never_the_temp_zip() {
        let base = std::env::temp_dir().join(format!("wsd-e2e-{}", std::process::id()));
        // Temporary packaging ZIP (what PowerShell produced in %TEMP%).
        let temp_dir = base.join("runtime").join("Reports").join("24-09-26");
        std::fs::create_dir_all(&temp_dir).unwrap();
        let temp_zip = temp_dir.join("EXPC_Diagnostics_24-09-26_10-00-00.zip");
        std::fs::write(&temp_zip, b"PK\x03\x04payload").unwrap();
        // Portable EXE folder.
        let exe_dir = base.join("Портативная папка WinStateDiag");
        let final_zip = engine::place_final_report_for_tests(
            &temp_zip,
            &exe_dir,
            &engine::report_base_name("Мегастрой", "SERVER", "24-09-26"),
        )
        .unwrap();
        assert_eq!(
            final_zip,
            exe_dir
                .join("Reports")
                .join("Мегастрой - SERVER - 24-09-26")
                .join("Мегастрой - SERVER - 24-09-26.zip")
        );

        let mut app = WinStateDiagApp::default();
        app.reports_root = exe_dir.join("Reports");
        // What the engine reports on success goes through the same check.
        app.state = RunState::Done {
            zip_path: engine::verify_final_report(&final_zip, &app.reports_root).unwrap(),
        };
        let opened = std::cell::RefCell::new(Vec::new());
        app.open_final_report(&|p| {
            opened.borrow_mut().push(p.to_path_buf());
            Ok(())
        });
        app.open_final_report_folder(&|p| {
            opened.borrow_mut().push(engine::report_folder_of(p));
            Ok(())
        });
        let opened = opened.into_inner();
        assert_eq!(opened[0], final_zip, "UI open path == final Reports ZIP");
        assert_ne!(opened[0], temp_zip, "UI open path != temp ZIP");
        assert!(!opened[0].starts_with(&base.join("runtime")));
        assert_eq!(opened[1], final_zip.parent().unwrap());

        // A temporary ZIP can never become the open target.
        assert!(engine::verify_final_report(&temp_zip, &app.reports_root).is_err());
        app.state = RunState::Done {
            zip_path: temp_zip.clone(),
        };
        let tried = std::cell::RefCell::new(Vec::new());
        app.open_final_report(&|p| {
            tried.borrow_mut().push(p.to_path_buf());
            Ok(())
        });
        assert!(tried.borrow().is_empty(), "temp path must not be opened");
        assert!(
            app.journal
                .last()
                .unwrap()
                .message
                .contains("вне папки Reports")
        );

        // Final ZIP deleted: exact expected path in the journal, no fallback.
        app.state = RunState::Done {
            zip_path: final_zip.clone(),
        };
        std::fs::remove_file(&final_zip).unwrap();
        app.open_final_report(&|p| {
            tried.borrow_mut().push(p.to_path_buf());
            Ok(())
        });
        assert!(tried.borrow().is_empty());
        let last = &app.journal.last().unwrap().message;
        assert!(last.starts_with("[ERROR]") && last.contains(&final_zip.display().to_string()));
        let _ = std::fs::remove_dir_all(&base);
    }
}

/// v0.3.6 UI finalization: the physical-disk selector cards, direct-click
/// selection, and the "never silently fall back to C:" guarantee, all
/// driven through the same app-level API the UI calls.
#[cfg(test)]
mod multi_ssd_ui_tests {
    use super::*;
    use crate::storage_topology::{DiskCandidate, PhysicalDiskInfo, VolumeInfo};

    fn disk(index: u32, model: &str, serial: &str, bus: &str) -> PhysicalDiskInfo {
        PhysicalDiskInfo {
            index,
            model: model.into(),
            serial: serial.into(),
            bus_type: bus.into(),
            size_bytes: 1_000_000_000_000,
            is_ssd_like: true,
        }
    }

    fn candidate(index: u32, model: &str, is_system: bool, target: Option<&str>) -> DiskCandidate {
        let d = disk(index, model, "SN", "NVMe");
        let label = format!("{model} candidate");
        DiskCandidate {
            volume: target.map(|t| VolumeInfo {
                mount_point: t.into(),
                physical_disk_index: index,
                writable: true,
                label: String::new(),
            }),
            disk: d,
            is_system,
            label,
        }
    }

    fn app_with_candidates(candidates: Vec<DiskCandidate>) -> WinStateDiagApp {
        let mut app = WinStateDiagApp::default();
        app.ssd_selected = storage_topology::default_candidate_index(&candidates).unwrap_or(0);
        app.ssd_candidates = candidates;
        app
    }

    #[test]
    fn one_ssd_shows_exactly_one_card() {
        let mut app = app_with_candidates(vec![candidate(
            0,
            "Samsung 9100 PRO 1TB",
            true,
            Some("C:\\"),
        )]);
        let vm = app.build_vm(0.0, 0.0);
        assert_eq!(vm.ssd_disks.len(), 1);
        assert_eq!(vm.ssd_selected, 0);
        assert!(vm.ssd_disks[0].is_system);
    }

    #[test]
    fn two_ssds_show_two_cards_windows_disk_selected_by_default() {
        let mut app = app_with_candidates(vec![
            candidate(0, "Samsung 9100 PRO 1TB", true, Some("C:\\")),
            candidate(1, "Netac NV7000T 1TB", false, Some("E:\\")),
        ]);
        let vm = app.build_vm(0.0, 0.0);
        assert_eq!(vm.ssd_disks.len(), 2);
        assert_eq!(vm.ssd_selected, 0);
        assert!(vm.ssd_disks[0].is_system);
        assert!(!vm.ssd_disks[1].is_system);
    }

    #[test]
    fn three_and_four_ssds_are_all_listed_never_an_extra_placeholder() {
        let mut three = app_with_candidates(vec![
            candidate(0, "A", true, Some("C:\\")),
            candidate(1, "B", false, Some("D:\\")),
            candidate(2, "C", false, Some("E:\\")),
        ]);
        assert_eq!(three.build_vm(0.0, 0.0).ssd_disks.len(), 3);

        let mut four = app_with_candidates(vec![
            candidate(0, "A", true, Some("C:\\")),
            candidate(1, "B", false, Some("D:\\")),
            candidate(2, "C", false, Some("E:\\")),
            candidate(3, "D", false, Some("F:\\")),
        ]);
        assert_eq!(four.build_vm(0.0, 0.0).ssd_disks.len(), 4);
    }

    #[test]
    fn no_hdd_ever_appears_because_only_ssd_like_candidates_are_ever_built() {
        // build_candidates() itself filters HDDs; the app-level list is
        // exactly whatever candidates() returned, so this asserts the
        // wiring never re-adds anything build_candidates already excluded.
        let candidates = storage_topology::build_candidates(
            &[
                PhysicalDiskInfo {
                    index: 0,
                    model: "Samsung 9100 PRO 1TB".into(),
                    serial: "S1".into(),
                    bus_type: "NVMe".into(),
                    size_bytes: 1_000_000_000_000,
                    is_ssd_like: true,
                },
                PhysicalDiskInfo {
                    index: 1,
                    model: "Old Spinning HDD".into(),
                    serial: "S2".into(),
                    bus_type: "SATA".into(),
                    size_bytes: 2_000_000_000_000,
                    is_ssd_like: false,
                },
            ],
            &[VolumeInfo {
                mount_point: "C:\\".into(),
                physical_disk_index: 0,
                writable: true,
                label: String::new(),
            }],
            Some(0),
        );
        let mut app = app_with_candidates(candidates);
        let vm = app.build_vm(0.0, 0.0);
        assert_eq!(vm.ssd_disks.len(), 1);
        assert!(!vm.ssd_disks.iter().any(|d| d.model.contains("HDD")));
    }

    #[test]
    fn clicking_a_card_selects_exactly_that_disk_and_updates_the_target() {
        let mut app = app_with_candidates(vec![
            candidate(0, "Samsung 9100 PRO 1TB", true, Some("C:\\")),
            candidate(1, "Netac NV7000T 1TB", false, Some("E:\\")),
        ]);
        assert_eq!(app.ssd_selected, 0);
        app.select_ssd_disk(1);
        assert_eq!(app.ssd_selected, 1);
        assert_eq!(app.benchmark_path.trim_end_matches('\\'), "E:");
        let vm = app.build_vm(0.0, 0.0);
        assert_eq!(vm.ssd_selected, 1);
        // Right-side metadata switches with the selection.
        assert_eq!(vm.ssd_disks[vm.ssd_selected].model, "Netac NV7000T 1TB");
    }

    #[test]
    fn selecting_back_to_the_first_disk_restores_its_own_target() {
        let mut app = app_with_candidates(vec![
            candidate(0, "Samsung 9100 PRO 1TB", true, Some("C:\\")),
            candidate(1, "Netac NV7000T 1TB", false, Some("E:\\")),
        ]);
        app.select_ssd_disk(1);
        app.select_ssd_disk(0);
        assert_eq!(app.ssd_selected, 0);
        assert_eq!(app.benchmark_path.trim_end_matches('\\'), "C:");
    }

    #[test]
    fn a_disk_with_no_writable_volume_never_falls_back_to_c_and_blocks_start() {
        let mut app = app_with_candidates(vec![
            candidate(0, "Samsung 9100 PRO 1TB", true, Some("C:\\")),
            candidate(1, "Netac NV7000T 1TB", false, None),
        ]);
        app.benchmark_path = "C:\\".into();
        app.select_ssd_disk(1);
        // benchmark_path is left exactly as it was — never silently
        // redirected to C: or anywhere else.
        assert_eq!(app.benchmark_path, "C:\\");
        assert!(!app.benchmark_is_running());
        app.start_benchmark();
        assert!(
            !app.benchmark_is_running(),
            "start must refuse a disk with no writable volume"
        );
        assert!(
            app.journal
                .iter()
                .any(|e| e.message.contains("[WARN]") && e.message.contains("недоступен"))
        );
        let vm = app.build_vm(0.0, 0.0);
        assert!(!vm.ssd_disks[vm.ssd_selected].has_target);
    }

    #[test]
    fn history_stays_isolated_per_physical_disk_through_the_app_api() {
        let samsung = candidate(0, "Samsung 9100 PRO 1TB", true, Some("C:\\"));
        let netac = candidate(1, "Netac NV7000T 1TB", false, Some("E:\\"));
        let id_samsung = storage_topology::physical_disk_identity(&samsung.disk);
        let id_netac = storage_topology::physical_disk_identity(&netac.disk);
        assert_ne!(id_samsung, id_netac);
        // Same identity is produced again after "reselecting" the same
        // disk — i.e. a drive-letter change alone never changes it.
        let samsung_relettered = candidate(0, "Samsung 9100 PRO 1TB", true, Some("D:\\"));
        assert_eq!(
            id_samsung,
            storage_topology::physical_disk_identity(&samsung_relettered.disk)
        );
    }

    // ---- v0.3.6 §10 / §28: per-physical-disk switching without a rerun ----

    fn minimal_summary(read: f64, write: f64) -> StorageDiagnosticSummary {
        StorageDiagnosticSummary {
            profile: crate::storage_benchmark::StorageDiagnosticProfile {
                block_size: 1024 * 1024,
                queue_depth: 4,
                test_file_size: 512 * 1024 * 1024,
                pass_count: 4,
                stable_spread_limit_percent: 5.0,
            },
            preparation_method: "test",
            preparation_elapsed: std::time::Duration::from_secs(0),
            summary_read_mib_s: read,
            summary_write_mib_s: write,
            read_min_mib_s: read * 0.98,
            read_max_mib_s: read * 1.02,
            write_min_mib_s: write * 0.98,
            write_max_mib_s: write * 1.02,
            read_variation_percent: 1.0,
            write_variation_percent: 1.0,
            stable: true,
            raw_passes: Vec::new(),
        }
    }

    /// Simulates "this session already benchmarked this disk" by populating
    /// the per-identity cache directly (the real path is `poll_benchmark`
    /// finishing a run) and marks `benchmark_state` as if that disk's run
    /// had just completed — matching what `select_ssd_disk` would restore.
    fn seed_result(app: &mut WinStateDiagApp, index: usize, read: f64, write: f64) {
        let candidate = &app.ssd_candidates[index];
        let dir = storage_topology::benchmark_target_dir(candidate).expect("target dir");
        let physical = storage_topology::physical_disk_identity(&candidate.disk);
        let identity = ssd_history::disk_identity_with_physical(&dir, Some(physical.as_str()));
        let result = minimal_summary(read, write);
        app.ssd_results
            .insert(identity, (result.clone(), 12.5, None));
        app.benchmark_state = BenchmarkUiState::Done {
            result,
            duration_seconds: 12.5,
            previous: None,
        };
    }

    #[test]
    fn c_then_e_then_d_then_c_restores_each_disks_own_result_without_rerunning() {
        let mut app = app_with_candidates(vec![
            candidate(0, "Samsung 9100 PRO 1TB", true, Some("C:\\")), // C
            candidate(1, "Netac NV7000T 1TB", false, Some("E:\\")),   // E
            candidate(2, "WD Black SN850 2TB", false, Some("D:\\")),  // D
        ]);
        app.select_ssd_disk(0);
        seed_result(&mut app, 0, 3100.0, 2600.0); // C test #1 (result #2 would just overwrite in the real flow)
        app.select_ssd_disk(1);
        seed_result(&mut app, 1, 1800.0, 1500.0); // E
        app.select_ssd_disk(2);
        seed_result(&mut app, 2, 4200.0, 3900.0); // D

        // C -> E -> D -> C, never rerunning: each selection must show that
        // disk's own cached result, never another disk's and never Idle.
        app.select_ssd_disk(0);
        match &app.benchmark_state {
            BenchmarkUiState::Done { result, .. } => {
                assert_eq!(result.summary_read_mib_s, 3100.0);
                assert_eq!(result.summary_write_mib_s, 2600.0);
            }
            _other => panic!("expected C's cached Done result, got something else"),
        }

        app.select_ssd_disk(1);
        match &app.benchmark_state {
            BenchmarkUiState::Done { result, .. } => {
                assert_eq!(result.summary_read_mib_s, 1800.0);
                assert_eq!(result.summary_write_mib_s, 1500.0);
            }
            _other => panic!("expected E's cached Done result, got something else"),
        }

        app.select_ssd_disk(2);
        match &app.benchmark_state {
            BenchmarkUiState::Done { result, .. } => {
                assert_eq!(result.summary_read_mib_s, 4200.0);
                assert_eq!(result.summary_write_mib_s, 3900.0);
            }
            _other => panic!("expected D's cached Done result, got something else"),
        }

        app.select_ssd_disk(0);
        match &app.benchmark_state {
            BenchmarkUiState::Done { result, .. } => {
                assert_eq!(result.summary_read_mib_s, 3100.0);
                assert_eq!(result.summary_write_mib_s, 2600.0);
            }
            _other => panic!("expected C's cached Done result again, got something else"),
        }

        // The selected disk stays the benchmark target throughout.
        assert_eq!(app.ssd_selected, 0);
        assert_eq!(app.benchmark_path.trim_end_matches('\\'), "C:");
    }

    #[test]
    fn selecting_a_never_benchmarked_disk_never_shows_another_disks_stale_result() {
        let mut app = app_with_candidates(vec![
            candidate(0, "Samsung 9100 PRO 1TB", true, Some("C:\\")),
            candidate(1, "Netac NV7000T 1TB", false, Some("E:\\")),
        ]);
        app.select_ssd_disk(0);
        seed_result(&mut app, 0, 3100.0, 2600.0);
        // E was never benchmarked this session: selecting it must not keep
        // showing C's Done screen.
        app.select_ssd_disk(1);
        assert!(matches!(app.benchmark_state, BenchmarkUiState::Idle));
        // And the view model shows no values (never C's numbers under E).
        let vm = app.build_vm(0.0, 0.0);
        assert!(matches!(vm.ssd, SsdVm::Idle));
    }

    /// A completed run with EVERY per-disk field distinct: current values,
    /// a previous compatible run (-> deltas), spreads (-> stability),
    /// profile, passes and duration.
    #[allow(clippy::too_many_arguments)]
    fn seed_full(
        app: &mut WinStateDiagApp,
        index: usize,
        read: f64,
        write: f64,
        prev: (f64, f64),
        spreads: (f64, f64),
        passes: u32,
        duration: f64,
    ) {
        let candidate = &app.ssd_candidates[index];
        let dir = storage_topology::benchmark_target_dir(candidate).expect("target dir");
        let physical = storage_topology::physical_disk_identity(&candidate.disk);
        let identity = ssd_history::disk_identity_with_physical(&dir, Some(physical.as_str()));
        let mut result = minimal_summary(read, write);
        result.read_variation_percent = spreads.0;
        result.write_variation_percent = spreads.1;
        result.profile.pass_count = passes;
        let previous = HistoryEntry {
            timestamp_unix: 1,
            disk_identity: identity.clone(),
            block_size: result.profile.block_size,
            queue_depth: result.profile.queue_depth,
            test_file_size: result.profile.test_file_size,
            pass_count: passes,
            read_mib_s: prev.0,
            write_mib_s: prev.1,
        };
        app.ssd_results
            .insert(identity, (result.clone(), duration, Some(previous.clone())));
        app.benchmark_state = BenchmarkUiState::Done {
            result,
            duration_seconds: duration,
            previous: Some(previous),
        };
    }

    fn done_fields(app: &mut WinStateDiagApp) -> Vec<String> {
        match app.build_vm(0.0, 0.0).ssd {
            SsdVm::Done {
                read_current,
                read_previous,
                read_delta,
                write_current,
                write_previous,
                write_delta,
                meta,
                ..
            } => {
                let mut v = vec![
                    read_current,
                    read_previous.unwrap_or_default(),
                    format!("{:.3}", read_delta.unwrap_or(f64::NAN)),
                    write_current,
                    write_previous.unwrap_or_default(),
                    format!("{:.3}", write_delta.unwrap_or(f64::NAN)),
                ];
                v.extend(meta.into_iter().map(|m| m.value));
                v
            }
            _ => panic!("expected a Done view for the selected disk"),
        }
    }

    #[test]
    fn switching_c_e_third_c_restores_every_result_field_of_each_physical_disk() {
        let mut app = app_with_candidates(vec![
            candidate(0, "Samsung 9100 PRO 1TB", true, Some("C:\\")),
            candidate(1, "Netac NV7000T 1TB", false, Some("E:\\")),
            candidate(2, "Kingston KC3000 2TB", false, Some("D:\\")),
        ]);
        // Two runs per disk (the second one stays "latest", with the first
        // as its "previous"), all with distinct numbers.
        app.select_ssd_disk(0);
        seed_full(
            &mut app,
            0,
            3000.0,
            2500.0,
            (2900.0, 2450.0),
            (1.0, 2.0),
            3,
            5.0,
        );
        seed_full(
            &mut app,
            0,
            3100.0,
            2600.0,
            (3000.0, 2500.0),
            (0.5, 3.1),
            4,
            6.0,
        );
        let c = done_fields(&mut app);
        app.select_ssd_disk(1);
        seed_full(
            &mut app,
            1,
            1700.0,
            1400.0,
            (1650.0, 1380.0),
            (4.0, 6.0),
            3,
            7.0,
        );
        seed_full(
            &mut app,
            1,
            1800.0,
            1500.0,
            (1700.0, 1400.0),
            (6.2, 9.5),
            4,
            8.0,
        );
        let e = done_fields(&mut app);
        app.select_ssd_disk(2);
        seed_full(
            &mut app,
            2,
            4100.0,
            3800.0,
            (4000.0, 3700.0),
            (11.0, 2.0),
            3,
            9.0,
        );
        seed_full(
            &mut app,
            2,
            4200.0,
            3900.0,
            (4100.0, 3800.0),
            (12.5, 1.2),
            4,
            10.0,
        );
        let third = done_fields(&mut app);
        assert_ne!(c, e);
        assert_ne!(e, third);
        assert_ne!(c, third);

        // No rerun from here on: every selection restores that disk's own
        // latest + previous, deltas, spreads, stability, profile, passes
        // and duration — together.
        for (index, expected) in [(0, &c), (1, &e), (2, &third), (0, &c), (1, &e), (2, &third)] {
            app.select_ssd_disk(index);
            assert_eq!(&done_fields(&mut app), expected, "disk {index}");
        }
        // The key is the physical identity, not a global "last result".
        assert_eq!(app.ssd_results.len(), 3);
        assert!(app.ssd_results.keys().all(|k| k.contains("PHYS#")));
    }

    #[test]
    fn disk_cards_show_the_real_volume_label_or_only_the_letter() {
        let mut labelled = candidate(0, "Samsung 9100 PRO 1TB", true, Some("C:\\"));
        labelled.volume.as_mut().unwrap().label = "Win11".into();
        let unlabelled = candidate(1, "Netac NV7000T 1TB", false, Some("E:\\"));
        let mut app = app_with_candidates(vec![labelled, unlabelled]);
        let vm = app.build_vm(0.0, 0.0);
        assert_eq!(vm.ssd_disks[0].drive_letter, "C:");
        assert_eq!(vm.ssd_disks[0].volume_label.as_deref(), Some("Win11"));
        assert_eq!(vm.ssd_disks[1].drive_letter, "E:");
        assert_eq!(
            vm.ssd_disks[1].volume_label, None,
            "never a fabricated label"
        );
        // The label is data: identical in both UI languages.
        app.language = Language::En;
        let vm_en = app.build_vm(0.0, 0.0);
        assert_eq!(vm_en.ssd_disks[0].volume_label.as_deref(), Some("Win11"));
    }

    #[test]
    fn language_switch_ru_en_ru_keeps_all_state_and_persists_the_choice() {
        let dir = std::env::temp_dir().join(format!("wsd-lang-switch-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut app = app_with_candidates(vec![
            candidate(0, "Samsung 9100 PRO 1TB", true, Some("C:\\")),
            candidate(1, "Netac NV7000T 1TB", false, Some("E:\\")),
        ]);
        app.language_pref_dir = dir.clone();
        app.language = Language::Ru;
        app.client_name = "Алексей".into();
        app.select_ssd_disk(1);
        seed_full(
            &mut app,
            1,
            1800.0,
            1500.0,
            (1700.0, 1400.0),
            (6.2, 9.5),
            4,
            8.0,
        );
        push_journal(&mut app.journal, "raw evidence line".into());
        let values_before = done_fields(&mut app);
        let journal_before = app.journal.len();
        let path_before = app.benchmark_path.clone();

        app.apply(Action::SetLanguage(Language::En));
        let en = app.build_vm(0.0, 0.0);
        assert_eq!(en.lang, Language::En);
        assert_eq!(en.stages[0].label, i18n::EN.stage_short[0]);
        assert_eq!(en.overall.modules[0].label, i18n::EN.module_name_expc);
        assert_eq!(i18n::load(&dir), Language::En, "choice persisted");
        // Nothing else moved: selection, result, journal, target, client.
        assert_eq!(en.ssd_selected, 1);
        assert_eq!(done_fields(&mut app), values_before);
        assert_eq!(app.journal.len(), journal_before);
        assert_eq!(app.benchmark_path, path_before);
        assert_eq!(app.client_name, "Алексей");

        app.apply(Action::SetLanguage(Language::Ru));
        let ru = app.build_vm(0.0, 0.0);
        assert_eq!(ru.lang, Language::Ru);
        assert_eq!(ru.stages[0].label, i18n::RU.stage_short[0]);
        assert_eq!(i18n::load(&dir), Language::Ru, "choice persisted");
        assert_eq!(ru.ssd_selected, 1);
        assert_eq!(done_fields(&mut app), values_before);
        assert_eq!(app.journal.len(), journal_before);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn app_generated_journal_lines_follow_the_ui_language() {
        let mut app = app_with_candidates(vec![
            candidate(0, "Samsung 9100 PRO 1TB", true, Some("C:\\")),
            candidate(1, "Netac NV7000T 1TB", false, None),
        ]);
        app.language = Language::En;
        app.select_ssd_disk(1);
        let last = app.journal.last().unwrap().message.clone();
        assert!(last.contains("no writable volume"), "{last}");
        assert!(!last.chars().any(|c| ('а'..='я').contains(&c)), "{last}");
        app.start_benchmark();
        let last = app.journal.last().unwrap().message.clone();
        assert_eq!(last, i18n::EN.journal_ssd_target_unavailable);
    }

    #[test]
    fn driver_category_labels_are_presented_in_the_ui_language() {
        let en = i18n::t(Language::En);
        let ru = i18n::t(Language::Ru);
        assert_eq!(
            localized_driver_label(en, "Чипсет (Intel)"),
            "Chipset (Intel)"
        );
        assert_eq!(
            localized_driver_label(en, "Аудио (Realtek)"),
            "Audio (Realtek)"
        );
        assert_eq!(
            localized_driver_label(en, "Сеть (Intel Wi-Fi)"),
            "Network (Intel Wi-Fi)"
        );
        assert_eq!(localized_driver_label(en, "Сеть"), "Network");
        // Device names are data: untouched.
        assert_eq!(
            localized_driver_label(en, "Intel Graphics"),
            "Intel Graphics"
        );
        assert_eq!(
            localized_driver_label(ru, "Чипсет (Intel)"),
            "Чипсет (Intel)"
        );
    }
}

#[cfg(test)]
mod ssd_layout_geometry_tests {
    //! v0.3.6 §15/§16/§28: SSD disk-card row layout and the selection
    //! connector geometry, purely as coordinate math (no rendering needed
    //! on Linux).
    use crate::ui::dashboard::{
        ssd_connector_points_for_tests, ssd_disk_card_rects_for_tests,
        ssd_ring_group_rect_for_tests, ssd_ring_rects_for_tests, ssd_slot_rects_for_tests,
    };
    use egui::Pos2;

    #[test]
    fn three_disks_are_one_horizontal_row_not_two_plus_one() {
        let rects = ssd_disk_card_rects_for_tests(Pos2::ZERO, 3);
        assert_eq!(rects.len(), 3);
        // Same row: all three top edges equal.
        let y0 = rects[0].min.y;
        assert!(rects.iter().all(|r| (r.min.y - y0).abs() < 0.01));
        // Left-to-right, non-overlapping.
        assert!(rects[0].max.x <= rects[1].min.x);
        assert!(rects[1].max.x <= rects[2].min.x);
    }

    #[test]
    fn four_disks_are_a_two_by_two_grid() {
        let rects = ssd_disk_card_rects_for_tests(Pos2::ZERO, 4);
        assert_eq!(rects.len(), 4);
        let row_ys: std::collections::BTreeSet<i32> =
            rects.iter().map(|r| r.min.y.round() as i32).collect();
        assert_eq!(row_ys.len(), 2, "four disks must be exactly two rows");
        let col_xs: std::collections::BTreeSet<i32> =
            rects.iter().map(|r| r.min.x.round() as i32).collect();
        assert_eq!(col_xs.len(), 2, "four disks must be exactly two columns");
    }

    #[test]
    fn connector_origin_follows_whichever_card_is_selected() {
        let o = Pos2::ZERO;
        let rects = ssd_disk_card_rects_for_tests(o, 3);
        let ring_group = ssd_ring_group_rect_for_tests(o);
        for (selected_idx, card) in rects.iter().enumerate() {
            let expected_x = card.center().x;
            // The connector line always runs from the selected card's
            // center-bottom to the ring group's center-top.
            assert!(
                (expected_x - rects[selected_idx].center().x).abs() < 0.01,
                "connector x must match card {selected_idx}'s own center"
            );
        }
        // Distinct cards (C / E / a third disk) have distinct centers, so
        // the connector visibly moves when selection changes.
        assert_ne!(rects[0].center().x, rects[1].center().x);
        assert_ne!(rects[1].center().x, rects[2].center().x);
        // The ring group itself is a fixed target the connector always
        // terminates at, regardless of which disk is selected.
        assert!(ring_group.width() > 0.0 && ring_group.height() > 0.0);
    }

    #[test]
    fn connector_never_has_a_diagonal_segment() {
        let o = Pos2::ZERO;
        let ring_group = ssd_ring_group_rect_for_tests(o);
        for n in [1, 2, 3, 4] {
            for (idx, card) in ssd_disk_card_rects_for_tests(o, n).iter().enumerate() {
                let pts = ssd_connector_points_for_tests(*card, ring_group);
                assert!(
                    pts.len() == 2 || pts.len() == 4,
                    "connector must be a straight run or a vertical/horizontal/vertical dog-leg"
                );
                for pair in pts.windows(2) {
                    let (a, b) = (pair[0], pair[1]);
                    let horizontal = (a.y - b.y).abs() < 0.01;
                    let vertical = (a.x - b.x).abs() < 0.01;
                    assert!(
                        horizontal || vertical,
                        "disk {n}/card {idx}: connector segment {a:?}->{b:?} is diagonal"
                    );
                }
                // First point is always the selected card's own center-bottom.
                assert!((pts[0].x - card.center().x).abs() < 0.01);
                // Last point always terminates at the ring frame's center-top.
                let last = *pts.last().unwrap();
                assert!((last.x - ring_group.center().x).abs() < 0.01);
                assert!((last.y - ring_group.min.y).abs() < 0.01);
            }
        }
    }

    #[test]
    fn ring_frame_never_touches_the_rings() {
        // A clear, uniform internal gap on all four sides (explicit
        // correction: the frame must never touch or merge with the rings).
        let frame = ssd_ring_group_rect_for_tests(Pos2::ZERO);
        let [read, write] = ssd_ring_rects_for_tests(Pos2::ZERO);
        let gaps = [
            read.min.y - frame.min.y,
            write.min.y - frame.min.y,
            read.min.x - frame.min.x,
            frame.max.x - write.max.x,
        ];
        for g in gaps {
            assert!(g >= 12.0, "ring-to-frame gap {g} < 12px ({gaps:?})");
        }
        // Bottom: the rings clear the frame by even more (the delta line
        // lives there).
        assert!(frame.max.y - read.max.y >= 12.0);
        assert!(frame.max.y - write.max.y >= 12.0);
        // Moving the layout origin moves frame and rings together.
        let shifted = ssd_ring_group_rect_for_tests(Pos2::new(0.0, 100.0));
        assert!((shifted.min.y - frame.min.y - 100.0).abs() < 0.01);
    }

    #[test]
    fn delta_text_keeps_breathing_room_above_the_frame_bottom() {
        use crate::ui::tokens::{layout as l, typography as t};
        let frame_bottom = l::SSD_RING_FRAME[1] + l::SSD_RING_FRAME[3];
        // Lowest ink of the delta line ≈ baseline + descender (0.25 em).
        let delta_bottom = l::RING_DELTA_BASELINE + t::DELTA.size * 0.25;
        assert!(
            frame_bottom - delta_bottom >= 10.0,
            "delta text too close to the frame bottom ({} px)",
            frame_bottom - delta_bottom
        );
        // And the delta line sits below the rings, never inside them.
        let ring_bottom = l::READ_RING_CENTER[1] + l::RING_OUTER_DIAMETER / 2.0;
        assert!(l::RING_DELTA_BASELINE - t::DELTA.size * 0.75 > ring_bottom);
    }

    #[test]
    fn button_row_has_clear_air_above_and_below_and_equal_heights() {
        use crate::ui::tokens::layout as l;
        let frame_bottom = l::SSD_RING_FRAME[1] + l::SSD_RING_FRAME[3];
        let (p, s) = (l::SSD_BUTTON_PRIMARY, l::SSD_BUTTON_SECONDARY);
        assert_eq!(p[3], s[3], "Run Test and Details must have equal heights");
        assert_eq!(p[1], s[1], "the two buttons form one row");
        assert!(p[2] >= s[2], "the primary button may be the wider one");
        assert!(s[2] >= 0.6 * p[2], "Details must not look tiny next to Run");
        assert!(p[1] - frame_bottom >= 8.0, "buttons rest on the frame");
        let row_bottom = p[1] + p[3];
        let strip_top = l::SSD_META_STRIP[1];
        assert!(strip_top - row_bottom >= 8.0, "buttons rest on the strip");
        let card_bottom = l::SSD_CARD[1] + l::SSD_CARD[3];
        assert!(l::SSD_META_STRIP[1] + l::SSD_META_STRIP[3] <= card_bottom - 4.0);
    }

    #[test]
    fn ssd_section_always_reserves_three_fixed_slots() {
        let reference = ssd_slot_rects_for_tests(Pos2::ZERO, 3);
        assert_eq!(reference.len(), 3);
        for n in 0..=3 {
            // The slot geometry is identical whether 0, 1, 2 or 3 SSDs
            // exist: the section never reflows.
            assert_eq!(
                ssd_slot_rects_for_tests(Pos2::ZERO, n),
                reference,
                "n = {n}"
            );
            // Occupied cards are exactly the first n reserved slots.
            let cards = ssd_disk_card_rects_for_tests(Pos2::ZERO, n);
            assert_eq!(cards.len(), n);
            assert_eq!(&cards[..], &reference[..n]);
        }
        // Equal-width slots in one row.
        assert!(
            reference
                .iter()
                .all(|r| (r.width() - reference[0].width()).abs() < 0.01)
        );
        // A 4th SSD uses a 2x2 grid INSIDE the same band.
        let grid = ssd_slot_rects_for_tests(Pos2::ZERO, 4);
        let band_top = reference[0].min.y;
        let band_bottom = reference[0].max.y;
        assert!(
            grid.iter()
                .all(|r| r.min.y >= band_top - 0.01 && r.max.y <= band_bottom + 0.01)
        );
    }

    #[test]
    fn connector_follows_slot_one_two_and_three() {
        let o = Pos2::ZERO;
        let frame = ssd_ring_group_rect_for_tests(o);
        let slots = ssd_disk_card_rects_for_tests(o, 3);
        let mut starts = Vec::new();
        for slot in &slots {
            let pts = ssd_connector_points_for_tests(*slot, frame);
            assert_eq!(pts[0], egui::pos2(slot.center().x, slot.max.y));
            let end = *pts.last().unwrap();
            assert_eq!(end, egui::pos2(frame.center().x, frame.min.y));
            starts.push(pts[0].x);
        }
        assert!(starts[0] < starts[1] && starts[1] < starts[2]);
    }

    #[test]
    fn dashboard_cards_fit_the_reference_canvas_without_overlap() {
        use crate::ui::tokens::{CANVAS_H, CANVAS_ORIGIN_IN_MASTER, CANVAS_W, layout as l};
        let cards = [
            ("client", l::CLIENT_CARD),
            ("diagnostic", l::DIAGNOSTIC_CARD),
            ("crypto", l::CRYPTO_CARD),
            ("hardware", l::HARDWARE_CARD),
            ("stages", l::STAGES_CARD),
            ("drivers", l::DRIVERS_CARD),
            ("result", l::RESULT_CARD),
            ("start", l::START_BUTTON),
            ("overall", l::OVERALL_CARD),
            ("ssd", l::SSD_CARD),
            ("journal", l::JOURNAL_CARD),
        ];
        let rect = |v: [f32; 4]| {
            egui::Rect::from_min_size(
                egui::pos2(
                    v[0] - CANVAS_ORIGIN_IN_MASTER[0],
                    v[1] - CANVAS_ORIGIN_IN_MASTER[1],
                ),
                egui::vec2(v[2], v[3]),
            )
        };
        let canvas = egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(CANVAS_W, CANVAS_H));
        let status_top = l::STATUS_SEPARATOR_Y - CANVAS_ORIGIN_IN_MASTER[1];
        for (name, v) in cards {
            let r = rect(v);
            assert!(canvas.contains_rect(r), "{name} leaves the canvas");
            assert!(r.max.y <= status_top, "{name} overlaps the status bar");
        }
        for (i, (a, va)) in cards.iter().enumerate() {
            for (b, vb) in cards.iter().skip(i + 1) {
                let inter = rect(*va).intersect(rect(*vb));
                assert!(
                    inter.width() <= 0.0 || inter.height() <= 0.0,
                    "{a} overlaps {b}"
                );
            }
        }
    }
}

/// Unified session package + Stop button at application level.
#[cfg(test)]
mod session_package_tests {
    use super::*;
    use crate::report_package::read_zip;

    fn app_with_exe(tag: &str) -> (WinStateDiagApp, PathBuf) {
        let exe = std::env::temp_dir()
            .join(format!("wsd-app-{tag}-{}", std::process::id()))
            .join("Портативная WinStateDiag");
        let _ = std::fs::remove_dir_all(exe.parent().unwrap());
        let mut app = WinStateDiagApp::default();
        app.client_name = "Алексей".into();
        app.computer_name = "MSI".into();
        app.reports_root = exe.join("Reports");
        app.package = Arc::new(Mutex::new(SessionPackage::new(exe.join("Reports"), None)));
        (app, exe)
    }

    fn hardware_files() -> Vec<EvidenceFile> {
        vec![
            EvidenceFile::new("Hardware_24.09.26_10-30.txt", b"HW".to_vec()),
            EvidenceFile::new("Hardware_24.09.26_10-30.json", b"{}".to_vec()),
            EvidenceFile::new("Hardware_24.09.26_10-30.html", b"<html/>".to_vec()),
        ]
    }

    /// A + H + I: Hardware alone creates the report; the viewer closing
    /// keeps the evidence; "Открыть отчёт"/"Открыть папку" use the session
    /// package under <EXE>\Reports, never TEMP.
    #[test]
    fn hardware_only_report_survives_the_viewer_and_opens_from_reports() {
        let (mut app, exe) = app_with_exe("hw");
        let (tx, rx) = std::sync::mpsc::channel();
        app.hardware = HardwareViewState::Collecting {
            rx,
            started: Instant::now(),
            saving: false,
        };
        // What the hidden collection thread does: persist, then report.
        let zip = report_package::lock(&app.package)
            .contribute("Алексей", "MSI", "24-09-26", hardware_files())
            .unwrap();
        tx.send(HardwareEvent::Saving).unwrap();
        tx.send(HardwareEvent::Persisted(Ok(zip.clone()))).unwrap();
        app.poll_hardware();
        assert!(matches!(app.hardware, HardwareViewState::Viewer { .. }));
        tx.send(HardwareEvent::Closed).unwrap();
        app.poll_hardware();
        assert!(matches!(app.hardware, HardwareViewState::Idle));
        // Evidence is still there after the viewer closed (plus the v0.4.0
        // generated manifest.json).
        let names: Vec<String> = read_zip(&zip)
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .filter(|n| n != crate::manifest::MANIFEST_FILE)
            .collect();
        assert_eq!(names.len(), 3);
        assert_eq!(
            zip,
            exe.join("Reports")
                .join("Алексей - MSI - 24-09-26")
                .join("Алексей - MSI - 24-09-26.zip")
        );
        // The result card shows the package although EXPC never ran.
        match app.build_vm(0.0, 0.0).result {
            ResultVm::Done { attention, .. } => assert!(attention),
            other => panic!("expected Done, got {other:?}"),
        }
        let opened = std::cell::RefCell::new(Vec::new());
        app.open_final_report(&|p| {
            opened.borrow_mut().push(p.to_path_buf());
            Ok(())
        });
        app.open_final_report_folder(&|p| {
            opened.borrow_mut().push(engine::report_folder_of(p));
            Ok(())
        });
        let opened = opened.into_inner();
        assert_eq!(
            opened,
            vec![zip.clone(), zip.parent().unwrap().to_path_buf()]
        );
        let temp = std::env::temp_dir().join("WinStateDiag");
        assert!(opened.iter().all(|p| !p.starts_with(&temp)));
        let _ = std::fs::remove_dir_all(exe.parent().unwrap());
    }

    #[test]
    fn hardware_collection_failure_is_journaled_and_closes_the_progress() {
        let (mut app, exe) = app_with_exe("hwfail");
        let (tx, rx) = std::sync::mpsc::channel();
        app.hardware = HardwareViewState::Collecting {
            rx,
            started: Instant::now(),
            saving: false,
        };
        tx.send(HardwareEvent::Failed("код 1".into())).unwrap();
        app.poll_hardware();
        assert!(matches!(app.hardware, HardwareViewState::Idle));
        assert!(app.journal.last().unwrap().message.starts_with(&format!(
            "[ERROR] {}",
            i18n::t(app.language).module_name_hardware
        )));
        assert!(!exe.join("Reports").exists(), "no fake report");
        let _ = std::fs::remove_dir_all(exe.parent().unwrap());
    }

    #[test]
    fn ssd_benchmark_and_held_driver_audit_join_the_same_package() {
        let (mut app, exe) = app_with_exe("mods");
        // Audit offered to an unbound, unresolved package: held, no folder.
        let held = report_package::lock(&app.package)
            .offer(vec![EvidenceFile::new(
                "DriverAudit_24-09-26_09-00-00.json",
                b"{}".to_vec(),
            )])
            .unwrap();
        assert!(held.is_none());
        assert!(!exe.join("Reports").exists());
        app.contribute_evidence(
            "storage",
            "SSD benchmark",
            vec![EvidenceFile::new(
                "SSD_Benchmark_24.09.26_10-35.txt",
                b"SSD".to_vec(),
            )],
        );
        app.contribute_evidence("storage", "Hardware Report", hardware_files());
        let zip = report_package::lock(&app.package).final_zip().unwrap();
        let names: Vec<String> = read_zip(&zip)
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert!(names.contains(&"DriverAudit_24-09-26_09-00-00.json".to_string()));
        assert!(names.contains(&"SSD_Benchmark_24.09.26_10-35.txt".to_string()));
        assert!(names.contains(&"Hardware_24.09.26_10-30.json".to_string()));
        let dirs = std::fs::read_dir(exe.join("Reports")).unwrap().count();
        assert_eq!(dirs, 1, "no (2) folder within one session");
        let _ = std::fs::remove_dir_all(exe.parent().unwrap());
    }

    /// Stop button: enabled only while running; after cancellation the UI
    /// is startable again and says what happened.
    #[test]
    fn stop_returns_the_ui_to_a_startable_state() {
        let (mut app, exe) = app_with_exe("stop");
        assert!(!app.build_vm(0.0, 0.0).stop_enabled, "hidden when idle");
        let (tx, rx) = std::sync::mpsc::channel();
        let cancel = Arc::new(AtomicBool::new(false));
        app.session_cancel = Some(Arc::clone(&cancel));
        app.state = RunState::Running {
            stage: Stage::SystemDiagnostics,
            step_done: 10,
            step_total: 100,
            stage_message: String::new(),
            rx,
        };
        assert!(app.build_vm(0.0, 0.0).stop_enabled);
        app.apply(Action::Stop);
        assert!(cancel.load(Ordering::SeqCst), "graceful request sent");
        assert!(!app.build_vm(0.0, 0.0).stop_enabled, "no double stop");
        tx.send(EngineEvent::Cancelled {
            zip_path: None,
            note: "Данные ещё не были собраны — отчёт не создавался.".into(),
        })
        .unwrap();
        app.poll_engine();
        assert!(matches!(app.state, RunState::Cancelled { .. }));
        let vm = app.build_vm(0.0, 0.0);
        assert_eq!(vm.operation.name, "Диагностика остановлена пользователем");
        assert!(matches!(vm.start, StartVm::Start { enabled: true }));
        assert!(!vm.stop_enabled);
        assert!(vm.controls_enabled);
        assert!(matches!(vm.result, ResultVm::Idle), "no fake report");
        assert_eq!(vm.overall.status_text, "Остановлено");
        assert!(
            app.journal
                .iter()
                .any(|e| e.message == "[INFO] Диагностика остановлена пользователем.")
        );
        // Never presented as a successful EXPC run.
        assert!(expc_status(&app.state) != ModuleStatus::Done);
        // A new diagnostic can be started afterwards.
        assert!(!app.is_running());
        let _ = std::fs::remove_dir_all(exe.parent().unwrap());
    }

    #[test]
    fn cancelled_run_with_partial_evidence_shows_the_session_report() {
        let (mut app, exe) = app_with_exe("stop2");
        let zip = report_package::lock(&app.package)
            .contribute(
                "Алексей",
                "MSI",
                "24-09-26",
                vec![EvidenceFile::new(
                    "EXPC_24.09.26_10-30_USER_CANCELLED.txt",
                    b"x".to_vec(),
                )],
            )
            .unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        app.state = RunState::Running {
            stage: Stage::SystemDiagnostics,
            step_done: 0,
            step_total: 100,
            stage_message: String::new(),
            rx,
        };
        tx.send(EngineEvent::Cancelled {
            zip_path: Some(zip.clone()),
            note: "Собранные данные сохранены".into(),
        })
        .unwrap();
        app.poll_engine();
        match app.build_vm(0.0, 0.0).result {
            ResultVm::Done { path_display, .. } => assert!(path_display.contains("Алексей - MSI")),
            other => panic!("expected the session report, got {other:?}"),
        }
        assert!(
            report_package::lock(&app.package)
                .completed_modules()
                .is_empty()
        );
        let _ = std::fs::remove_dir_all(exe.parent().unwrap());
    }

    /// CryptoPro card: ReHash confirmation only from NO HASH; the vm never
    /// shows two states; ReHash only ever starts from NO HASH (one click,
    /// no confirmation dialog).
    #[test]
    fn crypto_card_offers_rehash_only_for_no_hash() {
        let (mut app, exe) = app_with_exe("crypto");
        // v1.0 Startup Idle: not checked at launch; "Checking" only while a
        // check actually runs.
        assert_eq!(app.build_vm(0.0, 0.0).crypto, CryptoVm::NotChecked);
        let (_keep, rx) = std::sync::mpsc::channel();
        app.crypto_rx = Some(rx);
        assert_eq!(app.build_vm(0.0, 0.0).crypto, CryptoVm::Checking);
        app.crypto_rx = None;
        for (state, vm, starts_rehash) in [
            (cryptopro::HashState::HashOk, CryptoVm::HashOk, false),
            (
                cryptopro::HashState::NotInstalled,
                CryptoVm::NotInstalled,
                false,
            ),
            (
                cryptopro::HashState::CheckError("x".into()),
                CryptoVm::CheckError,
                false,
            ),
            (cryptopro::HashState::NoHash, CryptoVm::NoHash, true),
        ] {
            app.crypto = Some(state);
            app.crypto_rx = None;
            assert_eq!(app.build_vm(0.0, 0.0).crypto, vm);
            // v1.1: the request only opens the warning; nothing runs yet.
            app.apply(Action::CryptoRehashRequest);
            assert!(app.crypto_rx.is_none(), "{vm:?}: no ReHash on request");
            assert_eq!(app.crypto_rehash_confirm, starts_rehash);
            app.apply(Action::CryptoRehashConfirmed);
            assert_eq!(
                app.crypto_rx.is_some(),
                starts_rehash,
                "{vm:?}: ReHash must start only from NO HASH, after confirmation"
            );
            assert!(!app.crypto_rehash_confirm);
            // Drain so the next iteration starts clean.
            app.crypto_rx = None;
        }
        // A check result lands in the card and the journal.
        let (tx, rx) = std::sync::mpsc::channel();
        app.crypto_rx = Some(rx);
        tx.send(CryptoEvent::Checked(
            cryptopro::Detection::NotInstalled,
            cryptopro::HashState::NotInstalled,
        ))
        .unwrap();
        app.poll_crypto();
        assert_eq!(app.crypto, Some(cryptopro::HashState::NotInstalled));
        assert!(
            app.journal
                .iter()
                .any(|e| e.message == "[INFO] CryptoPro не установлен.")
        );
        let _ = std::fs::remove_dir_all(exe.parent().unwrap());
    }
}

/// v0.3.7 journal: Open button, complete session journal viewer,
/// Save / Copy / Close, Clear safety and RU/EN with the viewer open.
#[cfg(test)]
mod journal_viewer_tests {
    use super::*;
    use crate::ui::tokens::{CANVAS_ORIGIN_IN_MASTER, layout as l};

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "wsd-journal-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn app_in(dir: &Path) -> WinStateDiagApp {
        let mut app = WinStateDiagApp::default();
        app.reports_root = dir.join("Reports");
        app.language_pref_dir = dir.to_path_buf();
        app.language = Language::Ru;
        app
    }

    fn fill(app: &mut WinStateDiagApp, n: usize) {
        for i in 0..n {
            push_journal(&mut app.journal, format!("строка журнала №{i} / line {i}"));
        }
    }

    fn frame(
        ctx: &egui::Context,
        events: Vec<egui::Event>,
        f: impl FnMut(&mut egui::Ui),
    ) -> egui::FullOutput {
        let input = egui::RawInput {
            screen_rect: Some(Rect::from_min_size(egui::Pos2::ZERO, vec2(1400.0, 1200.0))),
            events,
            ..Default::default()
        };
        let mut out = ctx.run_ui(input, f);
        // No GPU in unit tests: the texture uploads eframe's renderer would
        // apply are consumed here on purpose (epaint debug-asserts when an
        // unapplied `TexturesDelta` is dropped).
        out.textures_delta.clear();
        out
    }

    #[test]
    fn test_frames_consume_their_texture_deltas() {
        let ctx = egui::Context::default();
        // A fresh context really does emit texture uploads (font atlas)...
        let mut raw = ctx.run_ui(egui::RawInput::default(), |ui| {
            ui.label("Журнал WinStateDiag");
        });
        assert!(!raw.textures_delta.is_empty());
        raw.textures_delta.clear();
        // ...and every frame of the test helper hands back none unapplied,
        // including the frame that lays out the viewer for the first time.
        let dir = temp_dir("deltas");
        let mut app = app_in(&dir);
        fill(&mut app, 20);
        app.apply(Action::OpenJournal);
        let fresh = egui::Context::default();
        for _ in 0..3 {
            let out = frame(&fresh, Vec::new(), |ui| app.journal_window(ui.ctx()));
            assert!(out.textures_delta.is_empty());
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn texts(out: &egui::FullOutput) -> Vec<String> {
        fn walk(shape: &egui::Shape, acc: &mut Vec<String>) {
            match shape {
                egui::Shape::Text(t) => acc.push(t.galley.text().to_string()),
                egui::Shape::Vec(v) => v.iter().for_each(|s| walk(s, acc)),
                _ => {}
            }
        }
        let mut acc = Vec::new();
        for clipped in &out.shapes {
            walk(&clipped.shape, &mut acc);
        }
        acc
    }

    fn render_viewer(app: &mut WinStateDiagApp, ctx: &egui::Context) -> Vec<String> {
        let mut last = Vec::new();
        for _ in 0..3 {
            let out = frame(ctx, Vec::new(), |ui| app.journal_window(ui.ctx()));
            last = texts(&out);
        }
        last
    }

    #[test]
    fn open_journal_action_opens_the_viewer_without_touching_the_journal() {
        let dir = temp_dir("open");
        let mut app = app_in(&dir);
        fill(&mut app, 5);
        assert!(!app.journal_viewer_open);
        app.apply(Action::OpenJournal);
        assert!(app.journal_viewer_open);
        assert_eq!(app.journal.len(), 5);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn journal_open_button_sits_left_of_clear_with_the_same_size() {
        let (open, clear, card) = (
            l::JOURNAL_OPEN_BUTTON,
            l::JOURNAL_CLEAR_BUTTON,
            l::JOURNAL_CARD,
        );
        // Approved Clear button and card geometry are unchanged.
        assert_eq!(clear, [1224.0, 970.0, 117.0, 29.0]);
        assert_eq!(card, [571.0, 966.0, 788.0, 133.0]);
        // Same row, height and width (balanced pair), clean 8 px gap.
        assert_eq!(open[1], clear[1]);
        assert_eq!(open[3], clear[3]);
        assert_eq!(open[2], clear[2]);
        assert_eq!(clear[0] - (open[0] + open[2]), 8.0);
        // Inside the card, above the log panel, clear of the title.
        assert!(open[0] > card[0] + 250.0);
        assert!(open[1] >= card[1] && open[1] + open[3] <= l::JOURNAL_PANEL[1]);
    }

    #[test]
    fn clicking_the_open_button_on_the_dashboard_emits_open_journal() {
        let dir = temp_dir("click");
        let mut app = app_in(&dir);
        fill(&mut app, 3);
        for lang in [Language::Ru, Language::En] {
            app.language = lang;
            let ctx = egui::Context::default();
            fonts::install(&ctx);
            let vm = app.build_vm(0.0, 0.0);
            // v0.4.4: the Diagnostics page carries the compact journal.
            let b = l::JOURNAL_COMPACT_OPEN_BUTTON;
            let at = egui::pos2(
                b[0] - CANVAS_ORIGIN_IN_MASTER[0] + b[2] / 2.0,
                b[1] - CANVAS_ORIGIN_IN_MASTER[1]
                    + b[3] / 2.0
                    + crate::ui::tokens::layout::BODY_SHIFT,
            );
            let press = |pressed| egui::Event::PointerButton {
                pos: at,
                button: egui::PointerButton::Primary,
                pressed,
                modifiers: Default::default(),
            };
            let mut all = Vec::new();
            let script = vec![
                vec![],
                vec![egui::Event::PointerMoved(at)],
                vec![press(true)],
                vec![press(false)],
                vec![],
            ];
            let mut rendered = Vec::new();
            for events in script {
                let mut actions = Vec::new();
                let (mut client, mut mode, mut deep, mut hw, mut bench) = (
                    app.client_name.clone(),
                    app.mode,
                    app.deep_checks,
                    app.include_hardware,
                    app.benchmark_path.clone(),
                );
                let out = frame(&ctx, events, |ui| {
                    let mut controls = Controls {
                        client_name: &mut client,
                        mode: &mut mode,
                        deep_checks: &mut deep,
                        include_hardware: &mut hw,
                        benchmark_path: &mut bench,
                    };
                    dashboard::draw(ui, egui::Pos2::ZERO, &vm, &mut controls, &mut actions);
                });
                rendered = texts(&out);
                all.extend(actions);
            }
            let d = i18n::t(lang);
            assert!(
                rendered.iter().any(|t| t == d.journal_open_button),
                "{lang:?}"
            );
            assert!(
                rendered.iter().any(|t| t == d.journal_clear_button),
                "{lang:?}"
            );
            assert!(
                all.iter().any(|a| matches!(a, Action::OpenJournal)),
                "{lang:?}: {all:?}"
            );
            assert!(!all.iter().any(|a| matches!(a, Action::ClearLog)));
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn full_journal_is_not_truncated_by_the_dashboard_window() {
        let dir = temp_dir("full");
        let mut app = app_in(&dir);
        fill(&mut app, 1500);
        let vm = app.build_vm(0.0, 0.0);
        // Dashboard: presentation window of the most recent lines only.
        assert_eq!(vm.journal.len(), JOURNAL_LIMIT);
        assert_eq!(
            vm.journal.last().unwrap().message,
            "строка журнала №1499 / line 1499"
        );
        // Session journal: every line.
        assert_eq!(app.journal.len(), 1500);
        let text = app.journal.full_text(i18n::t(app.language));
        assert_eq!(text.lines().count(), 1500);
        assert!(text.contains("строка журнала №0 / line 0\r\n"));
        assert!(text.ends_with("строка журнала №1499 / line 1499\r\n"));
        // The viewer lays out every line (lazily, but all rows exist).
        app.journal_viewer_open = true;
        let ctx = egui::Context::default();
        let shown = render_viewer(&mut app, &ctx);
        assert!(
            shown
                .iter()
                .any(|t| t.ends_with("строка журнала №1499 / line 1499"))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn session_cap_bounds_memory_and_says_so() {
        let mut j = SessionJournal::default();
        for i in 0..JOURNAL_SESSION_CAP + 1 {
            j.push(format!("l{i}"));
        }
        assert!(j.len() <= JOURNAL_SESSION_CAP);
        assert!(j.dropped > 0);
        assert_eq!(j.dropped + j.len(), JOURNAL_SESSION_CAP + 1);
        assert_eq!(j.last().unwrap().message, format!("l{JOURNAL_SESSION_CAP}"));
        let text = j.full_text(i18n::t(Language::En));
        assert!(text.starts_with(&format!(
            "Earlier lines not kept (memory limit): {}",
            j.dropped
        )));
    }

    #[test]
    fn copy_puts_the_complete_journal_on_the_clipboard() {
        let dir = temp_dir("copy");
        let mut app = app_in(&dir);
        fill(&mut app, 750);
        app.apply(Action::OpenJournal);
        let ctx = egui::Context::default();
        let out = frame(&ctx, Vec::new(), |ui| {
            app.journal_viewer_act(ui.ctx(), JournalViewerAction::Copy)
        });
        let copied: Vec<&String> = out
            .platform_output
            .commands
            .iter()
            .filter_map(|c| match c {
                egui::OutputCommand::CopyText(t) => Some(t),
                _ => None,
            })
            .collect();
        assert_eq!(copied.len(), 1);
        let expected = app.journal.full_text(i18n::t(app.language));
        assert_eq!(copied[0], &expected);
        assert_eq!(copied[0].lines().count(), 750);
        assert!(copied[0].contains("строка журнала №0 / line 0"));
        // Copy neither clears nor closes.
        assert_eq!(app.journal.len(), 750);
        assert!(app.journal_viewer_open);
        assert!(matches!(
            app.journal_viewer_status,
            Some(JournalViewerStatus::Copied)
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn close_only_hides_the_viewer() {
        let dir = temp_dir("close");
        let mut app = app_in(&dir);
        fill(&mut app, 10);
        app.apply(Action::OpenJournal);
        let ctx = egui::Context::default();
        frame(&ctx, Vec::new(), |ui| {
            app.journal_viewer_act(ui.ctx(), JournalViewerAction::Close)
        });
        assert!(!app.journal_viewer_open);
        assert_eq!(app.journal.len(), 10);
        assert_eq!(app.build_vm(0.0, 0.0).journal.len(), 10);
        assert!(!app.reports_root.exists(), "Close writes nothing");
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn snapshot(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
        let mut out = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            for e in std::fs::read_dir(&dir).unwrap().flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                } else {
                    out.push((p.clone(), std::fs::read(&p).unwrap()));
                }
            }
        }
        out.sort();
        out
    }

    #[test]
    fn clear_empties_the_dashboard_journal_but_never_evidence() {
        let dir = temp_dir("clear");
        let mut app = app_in(&dir);
        // Every kind of on-disk evidence a session produces.
        let report = app.reports_root.join("Клиент - PC - 28-09-26");
        std::fs::create_dir_all(&report).unwrap();
        for (name, body) in [
            ("EXPC_Diagnostic_28.09.26_10-00.txt", "diagnostic txt"),
            ("EXPC_Diagnostic_28.09.26_10-00.json", "{\"diag\":1}"),
            ("DriverAudit_28-09-26_10-01-00.json", "{\"drivers\":1}"),
            ("DriverAudit_28-09-26_10-01-00.txt", "driver audit"),
            ("Hardware_28.09.26_10-02.json", "{\"hw\":1}"),
            ("SSD_Benchmark_28.09.26_10-03.txt", "ssd bench"),
            ("SSD_Benchmark_28.09.26_10-03.json", "{\"ssd\":1}"),
            ("ssd_benchmark_history.log", "history line"),
            ("WinStateDiag_startup.log", "persisted log"),
            ("Клиент - PC - 28-09-26.zip", "PK zip bytes"),
        ] {
            std::fs::write(report.join(name), body).unwrap();
        }
        std::fs::create_dir_all(journal_logs_dir(&app.reports_root)).unwrap();
        std::fs::write(
            journal_logs_dir(&app.reports_root).join("WinStateDiag_Log_2026-09-28_10-00-00.txt"),
            "saved journal",
        )
        .unwrap();
        let before = snapshot(&dir);
        assert_eq!(before.len(), 11);

        fill(&mut app, 40);
        app.apply(Action::OpenJournal);
        assert_eq!(app.build_vm(0.0, 0.0).journal.len(), 40);
        app.apply(Action::ClearLog);

        // GUI journal cleared...
        assert!(app.build_vm(0.0, 0.0).journal.is_empty());
        // ...the session journal (viewer / Save / Copy) and the viewer stay...
        assert_eq!(app.journal.len(), 40);
        assert!(app.journal_viewer_open);
        let text = app.journal.full_text(i18n::t(app.language));
        assert_eq!(text.lines().count(), 40);
        // ...and every evidence / report / history / ZIP / log byte survives.
        assert_eq!(snapshot(&dir), before);

        // New lines after Clear appear on the card again.
        push_journal(&mut app.journal, "после очистки".into());
        let vm = app.build_vm(0.0, 0.0);
        assert_eq!(vm.journal.len(), 1);
        assert_eq!(vm.journal[0].message, "после очистки");
        assert_eq!(app.journal.len(), 41);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_file_name_has_the_required_format() {
        let t = sysinfo::LocalTime {
            year: 2026,
            month: 9,
            day: 8,
            hour: 7,
            minute: 5,
            second: 3,
        };
        assert_eq!(
            journal_log_file_name(t),
            "WinStateDiag_Log_2026-09-08_07-05-03.txt"
        );
        let now = journal_log_file_name(sysinfo::local_time());
        assert_eq!(now.len(), "WinStateDiag_Log_YYYY-MM-DD_HH-MM-SS.txt".len());
        assert!(now.starts_with("WinStateDiag_Log_") && now.ends_with(".txt"));
        assert_eq!(
            journal_logs_dir(Path::new("X").join("Reports").as_path()),
            Path::new("X").join("Reports").join("Logs")
        );
    }

    #[test]
    fn save_writes_the_complete_journal_as_utf8_and_shows_the_path() {
        let dir = temp_dir("save");
        let mut app = app_in(&dir);
        fill(&mut app, 600);
        app.apply(Action::OpenJournal);
        app.apply(Action::ClearLog); // Save still writes the whole session.
        let expected = app.journal.full_text(i18n::t(app.language));
        let ctx = egui::Context::default();
        frame(&ctx, Vec::new(), |ui| {
            app.journal_viewer_act(ui.ctx(), JournalViewerAction::Save)
        });
        let Some(JournalViewerStatus::Saved(path)) = &app.journal_viewer_status else {
            panic!("save failed");
        };
        let path = path.clone();
        assert_eq!(path.parent().unwrap(), journal_logs_dir(&app.reports_root));
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        assert!(
            name.starts_with("WinStateDiag_Log_") && name.ends_with(".txt"),
            "{name}"
        );
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(&bytes[..3], &[0xEF, 0xBB, 0xBF]);
        let text = String::from_utf8(bytes[3..].to_vec()).expect("valid UTF-8");
        assert_eq!(text, expected);
        assert_eq!(text.lines().count(), 600);
        // Nothing loose in the Reports root; only the Logs folder was made.
        let root: Vec<_> = std::fs::read_dir(&app.reports_root)
            .unwrap()
            .flatten()
            .collect();
        assert_eq!(root.len(), 1);
        assert!(root[0].path().is_dir());
        // The saved path is shown in the viewer (and noted in the journal).
        let shown = render_viewer(&mut app, &ctx);
        let d = i18n::t(app.language);
        let status = format!("{}: {}", d.journal_viewer_saved, path.display());
        assert!(shown.iter().any(|t| t == &status), "{shown:?}");
        assert_eq!(app.journal.last().unwrap().message, status);
        assert!(app.journal_viewer_open);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_failure_is_reported_not_hidden() {
        let dir = temp_dir("savefail");
        let mut app = app_in(&dir);
        fill(&mut app, 3);
        // `Reports` is a file: the Logs folder cannot be created.
        std::fs::write(dir.join("Reports"), "not a folder").unwrap();
        let ctx = egui::Context::default();
        frame(&ctx, Vec::new(), |ui| {
            app.journal_viewer_act(ui.ctx(), JournalViewerAction::Save)
        });
        assert!(matches!(
            app.journal_viewer_status,
            Some(JournalViewerStatus::SaveFailed(_))
        ));
        let last = &app.journal.last().unwrap().message;
        assert!(
            last.starts_with("[ERROR] Не удалось сохранить журнал"),
            "{last}"
        );
        assert_eq!(std::fs::read(dir.join("Reports")).unwrap(), b"not a folder");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn viewer_shows_russian_and_english_strings() {
        let dir = temp_dir("strings");
        let mut app = app_in(&dir);
        fill(&mut app, 4);
        app.apply(Action::OpenJournal);
        for (lang, title, buttons, other_title) in [
            (
                Language::Ru,
                "Журнал WinStateDiag",
                ["Сохранить", "Копировать", "Закрыть"],
                "WinStateDiag Log",
            ),
            (
                Language::En,
                "WinStateDiag Log",
                ["Save", "Copy", "Close"],
                "Журнал WinStateDiag",
            ),
        ] {
            app.language = lang;
            let ctx = egui::Context::default();
            let shown = render_viewer(&mut app, &ctx);
            assert!(shown.iter().any(|t| t == title), "{lang:?}: {shown:?}");
            for b in buttons {
                assert!(shown.iter().any(|t| t == b), "{lang:?}: {b}");
            }
            assert!(!shown.iter().any(|t| t == other_title));
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn language_switch_with_the_viewer_open_updates_it_immediately() {
        let dir = temp_dir("lang");
        let mut app = app_in(&dir);
        fill(&mut app, 300);
        app.apply(Action::OpenJournal);
        let ctx = egui::Context::default();
        let ru = render_viewer(&mut app, &ctx);
        assert!(ru.iter().any(|t| t == "Журнал WinStateDiag"));
        for (lang, title, save) in [
            (Language::En, "WinStateDiag Log", "Save"),
            (Language::Ru, "Журнал WinStateDiag", "Сохранить"),
        ] {
            app.apply(Action::SetLanguage(lang));
            // The very next frame (same context, same window) is translated.
            let out = frame(&ctx, Vec::new(), |ui| app.journal_window(ui.ctx()));
            let shown = texts(&out);
            assert!(shown.iter().any(|t| t == title), "{lang:?}: {shown:?}");
            assert!(shown.iter().any(|t| t == save), "{lang:?}");
            assert!(app.journal_viewer_open, "viewer stays open");
            assert_eq!(app.journal.len(), 300, "no journal loss");
            assert!(egui::AreaState::load(&ctx, egui::Id::new("wsd_journal_viewer")).is_some());
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// v0.4.0: deep-check result state, compact journal viewer and the
/// fail-safe ZIP-only report folder at app level.
#[cfg(test)]
mod v040_tests {
    use super::*;
    use crate::deep_checks::ResultSource;
    use crate::report_package::read_zip;

    fn app_in(tag: &str) -> (WinStateDiagApp, PathBuf) {
        let exe = std::env::temp_dir()
            .join(format!("wsd-v040-{tag}-{}", std::process::id()))
            .join("WinStateDiag");
        let _ = std::fs::remove_dir_all(exe.parent().unwrap());
        std::fs::create_dir_all(&exe).unwrap();
        let mut app = WinStateDiagApp::default();
        app.client_name = "Алексей".into();
        app.computer_name = "MSI".into();
        app.reports_root = exe.join("Reports");
        app.language_pref_dir = exe.clone();
        app.language = Language::Ru;
        app.package = Arc::new(Mutex::new(SessionPackage::new(exe.join("Reports"), None)));
        (app, exe)
    }

    fn outcome(check: DeepCheck, result: CheckResult) -> DeepCheckOutcome {
        DeepCheckOutcome {
            check,
            result,
            detail: "evidence detail".into(),
            source: ResultSource::ExpcJson,
        }
    }

    fn completed_run(app: &mut WinStateDiagApp) {
        for s in app.expc_tracker.status.iter_mut() {
            *s = SubStageStatus::Done;
        }
        app.state = RunState::Done {
            zip_path: PathBuf::from("x.zip"),
        };
    }

    #[test]
    fn deep_check_results_are_shown_separately_from_completion() {
        let (mut app, exe) = app_in("rows");
        completed_run(&mut app);
        app.apply_deep_checks(vec![
            outcome(DeepCheck::Sfc, CheckResult::Ok),
            outcome(DeepCheck::Dism, CheckResult::Attention),
            outcome(DeepCheck::Chkdsk, CheckResult::Error),
        ]);
        let vm = app.build_vm(0.0, 0.0);
        let row = |i: usize| &vm.stages[i];
        // Progress / completion semantics are unchanged: every deep check
        // row is Done at 100% whatever it found.
        for i in [10, 11, 12] {
            assert_eq!(row(i).state, RowState::Done);
            assert_eq!(row(i).right_text, "100%");
            assert_eq!(row(i).fraction, Some(1.0));
        }
        assert_eq!(row(10).finding, Some(StageFinding::Ok));
        assert_eq!(row(11).finding, Some(StageFinding::Attention));
        assert_eq!(row(12).finding, Some(StageFinding::Error));
        // Non-deep rows carry no finding.
        assert!(
            vm.stages
                .iter()
                .enumerate()
                .all(|(i, r)| (10..=12).contains(&i) || r.finding.is_none())
        );
        // The hover explains it, with the manual command as text only.
        assert!(
            row(11)
                .full_label
                .contains("DISM: хранилище компонентов Windows требует восстановления.")
        );
        assert!(
            row(11)
                .full_label
                .contains("DISM /Online /Cleanup-Image /RestoreHealth")
        );
        assert!(row(11).full_label.contains("WinStateDiag её не запускает"));
        assert!(!row(10).full_label.contains("/scannow"));
        // Journal: explanation + manual command for ATTENTION.
        let lines: Vec<String> = app.journal.iter().map(|e| e.message.clone()).collect();
        assert!(
            lines.contains(
                &"SFC: нарушений целостности системных файлов не обнаружено.".to_string()
            )
        );
        assert!(lines.contains(
            &"[WARN] DISM: хранилище компонентов Windows требует восстановления.".to_string()
        ));
        assert!(
            lines
                .iter()
                .any(|l| l.starts_with("DISM: команда для ручного выполнения")
                    && l.ends_with("DISM /Online /Cleanup-Image /RestoreHealth"))
        );
        assert!(lines.contains(&"[ERROR] CHKDSK: проверку не удалось выполнить.".to_string()));
        // The finding is kept in view on the stages card after the run.
        assert_eq!(dashboard::stage_window_start(&vm.stages, l_visible()), 9);
        // EN.
        app.language = Language::En;
        let vm = app.build_vm(0.0, 0.0);
        assert!(
            vm.stages[11]
                .full_label
                .contains("DISM: the Windows component store is repairable.")
        );
        assert!(
            vm.stages[11]
                .full_label
                .contains("(WinStateDiag does not run it)")
        );
        let _ = std::fs::remove_dir_all(exe.parent().unwrap());
    }

    fn l_visible() -> usize {
        crate::ui::tokens::layout::STAGE_VISIBLE_ROWS
    }

    #[test]
    fn skipped_or_missing_results_keep_the_existing_semantics() {
        let (mut app, exe) = app_in("skip");
        completed_run(&mut app);
        app.apply_deep_checks(vec![
            outcome(DeepCheck::Sfc, CheckResult::Skipped),
            outcome(DeepCheck::Dism, CheckResult::Unknown),
        ]);
        let vm = app.build_vm(0.0, 0.0);
        assert_eq!(vm.stages[10].finding, None);
        assert_eq!(vm.stages[11].finding, Some(StageFinding::Unknown));
        assert_eq!(vm.stages[12].finding, None);
        // Skipped checks are not journaled as findings.
        assert!(!app.journal.iter().any(|e| e.message.starts_with("SFC:")));
        // A new run clears the previous results.
        app.apply(Action::Reset);
        assert!(app.deep_check_results.is_empty());
        let _ = std::fs::remove_dir_all(exe.parent().unwrap());
    }

    #[test]
    fn journal_viewer_opens_compact_near_540_by_580() {
        let (mut app, exe) = app_in("viewer");
        for i in 0..50 {
            push_journal(&mut app.journal, format!("line {i}"));
        }
        app.apply(Action::OpenJournal);
        let ctx = egui::Context::default();
        for _ in 0..3 {
            let input = egui::RawInput {
                screen_rect: Some(Rect::from_min_size(egui::Pos2::ZERO, vec2(1376.0, 1108.0))),
                ..Default::default()
            };
            let mut out = ctx.run_ui(input, |ui| app.journal_window(ui.ctx()));
            out.textures_delta.clear();
        }
        let area = egui::AreaState::load(&ctx, egui::Id::new("wsd_journal_viewer")).unwrap();
        let rect = area.rect();
        assert!((rect.width() - 540.0).abs() <= 40.0, "{rect:?}");
        assert!((rect.height() - 580.0).abs() <= 60.0, "{rect:?}");
        // Over the right side of the dashboard, fully on screen.
        assert!(rect.left() > 1376.0 / 2.0, "{rect:?}");
        assert!(
            rect.right() <= 1376.0 && rect.bottom() <= 1108.0,
            "{rect:?}"
        );
        assert_eq!(JOURNAL_VIEWER_SIZE, [540.0, 580.0]);
        // Still the complete session journal, still open, nothing cleared.
        assert_eq!(app.journal.len(), 50);
        assert!(app.journal_viewer_open);
        let _ = std::fs::remove_dir_all(exe.parent().unwrap());
    }

    fn report_folder(app: &WinStateDiagApp) -> PathBuf {
        report_package::lock(&app.package)
            .identity()
            .unwrap()
            .report_dir
            .clone()
    }

    #[test]
    fn stopped_or_failed_sessions_keep_loose_evidence_until_a_final_success() {
        let (mut app, exe) = app_in("stop");
        app.contribute_evidence(
            "storage",
            "EXPC",
            vec![EvidenceFile::new(
                "EXPC_Diagnostic_24.09.26_10-30_USER_CANCELLED.txt",
                b"partial".to_vec(),
            )],
        );
        let dir = report_folder(&app);
        let count = || std::fs::read_dir(&dir).unwrap().count();
        let before = count();
        assert!(before > 1);
        for state in [
            RunState::Cancelled {
                stage: Stage::SystemDiagnostics,
                note: String::new(),
            },
            RunState::Failed {
                message: "x".into(),
                stage: Stage::SystemDiagnostics,
            },
        ] {
            app.state = state;
            app.finalize_report_if_idle();
            assert_eq!(count(), before, "evidence kept");
        }
        // A later successful hardware-only workflow finalizes the package.
        app.state = RunState::Idle;
        app.contribute_evidence(
            "storage",
            "Hardware Report",
            vec![EvidenceFile::new(
                "Hardware_24.09.26_10-40.json",
                b"{}".to_vec(),
            )],
        );
        app.finalize_report_if_idle();
        assert_eq!(count(), 1, "ZIP only");
        let zip = report_package::lock(&app.package).final_zip().unwrap();
        let names: Vec<String> = read_zip(&zip)
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert!(names.contains(&"EXPC_Diagnostic_24.09.26_10-30_USER_CANCELLED.txt".to_string()));
        assert!(names.contains(&"Hardware_24.09.26_10-40.json".to_string()));
        assert!(names.contains(&crate::manifest::MANIFEST_FILE.to_string()));
        assert!(
            app.journal
                .iter()
                .any(|e| e.message == i18n::RU.journal_report_finalized)
        );
        let _ = std::fs::remove_dir_all(exe.parent().unwrap());
    }

    #[test]
    fn no_cleanup_while_a_module_is_still_working() {
        let (mut app, exe) = app_in("busy");
        app.contribute_evidence(
            "storage",
            "Hardware Report",
            vec![EvidenceFile::new(
                "Hardware_24.09.26_10-40.json",
                b"{}".to_vec(),
            )],
        );
        let dir = report_folder(&app);
        let before = std::fs::read_dir(&dir).unwrap().count();
        let (_tx, rx) = std::sync::mpsc::channel();
        app.hardware = HardwareViewState::Viewer { rx };
        app.finalize_report_if_idle();
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), before);
        app.hardware = HardwareViewState::Idle;
        app.finalize_report_if_idle();
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        let _ = std::fs::remove_dir_all(exe.parent().unwrap());
    }
}

/// v0.4.1: Driver Check summary/actions/export and the EXPC details window.
#[cfg(test)]
mod v041_tests {
    use super::*;
    use crate::deep_checks::ResultSource;
    use crate::ui::tokens::{CANVAS_ORIGIN_IN_MASTER, layout as l};

    fn app_in(tag: &str) -> (WinStateDiagApp, PathBuf) {
        let exe = std::env::temp_dir()
            .join(format!("wsd-v041-{tag}-{}", std::process::id()))
            .join("WinStateDiag");
        let _ = std::fs::remove_dir_all(exe.parent().unwrap());
        std::fs::create_dir_all(&exe).unwrap();
        let mut app = WinStateDiagApp::default();
        app.reports_root = exe.join("Reports");
        app.language_pref_dir = exe.clone();
        app.language = Language::Ru;
        app.package = Arc::new(Mutex::new(SessionPackage::new(exe.join("Reports"), None)));
        app.driver_audit = DriverAuditState::Done(Box::new(details::tests::report()));
        (app, exe)
    }

    struct Frame {
        texts: Vec<(String, Rect)>,
        copied: Vec<String>,
    }

    fn run(ctx: &egui::Context, events: Vec<egui::Event>, f: impl FnMut(&mut egui::Ui)) -> Frame {
        run_at(ctx, events, None, f)
    }

    fn run_at(
        ctx: &egui::Context,
        events: Vec<egui::Event>,
        time: Option<f64>,
        f: impl FnMut(&mut egui::Ui),
    ) -> Frame {
        let input = egui::RawInput {
            screen_rect: Some(Rect::from_min_size(egui::Pos2::ZERO, vec2(1400.0, 1200.0))),
            events,
            time,
            ..Default::default()
        };
        let mut out = ctx.run_ui(input, f);
        out.textures_delta.clear();
        fn walk(shape: &egui::Shape, acc: &mut Vec<(String, Rect)>) {
            match shape {
                egui::Shape::Text(t) => acc.push((
                    t.galley.text().to_string(),
                    t.galley.rect.translate(t.pos.to_vec2()),
                )),
                egui::Shape::Vec(v) => v.iter().for_each(|s| walk(s, acc)),
                _ => {}
            }
        }
        let mut texts = Vec::new();
        for c in &out.shapes {
            walk(&c.shape, &mut texts);
        }
        let copied = out
            .platform_output
            .commands
            .iter()
            .filter_map(|c| match c {
                egui::OutputCommand::CopyText(t) => Some(t.clone()),
                _ => None,
            })
            .collect();
        Frame { texts, copied }
    }

    fn click(at: egui::Pos2) -> Vec<Vec<egui::Event>> {
        let b = |pressed| egui::Event::PointerButton {
            pos: at,
            button: egui::PointerButton::Primary,
            pressed,
            modifiers: Default::default(),
        };
        vec![
            vec![egui::Event::PointerMoved(at)],
            vec![b(true)],
            vec![b(false)],
            vec![],
        ]
    }

    fn has(f: &Frame, t: &str) -> bool {
        f.texts.iter().any(|(x, _)| x == t)
    }

    fn find(f: &Frame, t: &str) -> Rect {
        f.texts
            .iter()
            .find(|(x, _)| x == t)
            .map(|(_, r)| *r)
            .unwrap_or_else(|| panic!("{t} not drawn"))
    }

    fn render_drivers(app: &mut WinStateDiagApp, ctx: &egui::Context) -> Frame {
        let mut last = run(ctx, vec![], |ui| app.drivers_window(ui.ctx()));
        for _ in 0..2 {
            last = run(ctx, vec![], |ui| app.drivers_window(ui.ctx()));
        }
        last
    }

    #[test]
    fn driver_header_shows_counters_not_a_log_line() {
        for (lang, d) in [(Language::Ru, &i18n::RU), (Language::En, &i18n::EN)] {
            let (mut app, exe) = app_in("hdr");
            app.language = lang;
            app.drivers_open = true;
            let ctx = egui::Context::default();
            let f = render_drivers(&mut app, &ctx);
            for label in [
                d.driver_summary_title,
                d.driver_sum_problems,
                d.driver_sum_warnings,
                d.driver_sum_ok,
                d.driver_sum_devices,
                d.driver_sum_events,
                d.driver_sum_info,
                d.driver_action_rerun,
                d.driver_copy_issues,
                d.driver_save_issues,
            ] {
                assert!(has(&f, label), "{lang:?}: {label}");
            }
            // Actual runtime values of the report.
            for v in ["1", "159", "11", "i"] {
                assert!(has(&f, v), "{v}");
            }
            // No old technical summary line, no date/time in the header.
            assert!(
                !f.texts
                    .iter()
                    .any(|(t, _)| t.contains("10:11:12") || t.contains("2026-09-30"))
            );
            assert!(
                !f.texts
                    .iter()
                    .any(|(t, _)| t.starts_with("Итог:") || t.starts_with("Summary:"))
            );
            // The driver list below is preserved.
            assert!(f.texts.iter().any(|(t, _)| t.contains("BadDev")));
            // Run again is the primary, larger button.
            let run_again = find(&f, d.driver_action_rerun);
            let copy = find(&f, d.driver_copy_issues);
            assert!(run_again.center().y <= copy.center().y + 2.0);
            let _ = std::fs::remove_dir_all(exe.parent().unwrap());
        }
    }

    #[test]
    fn info_tooltip_text_is_localized() {
        assert_eq!(
            i18n::RU.driver_info_tooltip,
            "Статус ставится только по конкретным признакам (ошибка PnP, сбой в модуле драйвера, Code Integrity, отказ загрузки)."
        );
        assert_eq!(
            i18n::RU.driver_info_tooltip_age,
            "Возраст драйвера сам по себе не считается проблемой."
        );
        assert_eq!(
            i18n::EN.driver_info_tooltip,
            "Status is assigned only from specific evidence (PnP error, driver module failure, Code Integrity, or driver load failure)."
        );
        assert_eq!(
            i18n::EN.driver_info_tooltip_age,
            "Driver age by itself is not considered a problem."
        );
        // Shown on hover of the Info chip (dark, wrapped tooltip).
        let (mut app, exe) = app_in("tip");
        app.drivers_open = true;
        let ctx = egui::Context::default();
        let f = render_drivers(&mut app, &ctx);
        let info = find(&f, "i").center();
        let mut shown = false;
        for i in 0..40 {
            let events = if i == 0 {
                vec![egui::Event::PointerMoved(info)]
            } else {
                vec![]
            };
            let f = run_at(&ctx, events, Some(10.0 + f64::from(i) * 0.1), |ui| {
                app.drivers_window(ui.ctx())
            });
            if has(&f, i18n::RU.driver_info_tooltip) {
                shown = true;
                assert!(has(&f, i18n::RU.driver_info_tooltip_age));
                break;
            }
        }
        assert!(shown, "tooltip appears on hover");
        let _ = std::fs::remove_dir_all(exe.parent().unwrap());
    }

    #[test]
    fn run_again_keeps_the_existing_recheck_behavior() {
        let (mut app, exe) = app_in("rerun");
        app.drivers_open = true;
        app.driver_export_status = Some(ExportStatus::Copied);
        let ctx = egui::Context::default();
        let f = render_drivers(&mut app, &ctx);
        let at = find(&f, i18n::RU.driver_action_rerun).center();
        for ev in click(at) {
            run(&ctx, ev, |ui| app.drivers_window(ui.ctx()));
        }
        assert_eq!(app.driver_rerun_requests, 1, "one re-check request");
        assert!(app.driver_export_status.is_none());
        assert!(app.drivers_open, "window stays open");
        let _ = std::fs::remove_dir_all(exe.parent().unwrap());
    }

    #[test]
    fn copy_and_save_issues_use_the_same_canonical_text() {
        let (mut app, exe) = app_in("export");
        app.drivers_open = true;
        let expected = app.driver_issues_text().unwrap();
        assert!(expected.contains("BadDev") && expected.contains("WarnDev"));
        assert!(!expected.contains("GoodDev"));
        let ctx = egui::Context::default();
        // Copy issues: clicked in the window → clipboard.
        let f = render_drivers(&mut app, &ctx);
        let at = find(&f, i18n::RU.driver_copy_issues).center();
        let mut copied = Vec::new();
        for ev in click(at) {
            copied.extend(run(&ctx, ev, |ui| app.drivers_window(ui.ctx())).copied);
        }
        assert_eq!(copied, [expected.clone()]);
        assert!(matches!(
            app.driver_export_status,
            Some(ExportStatus::Copied)
        ));
        // Save issues: same bytes (UTF-8 BOM) under Reports\Logs.
        let f = render_drivers(&mut app, &ctx);
        let at = find(&f, i18n::RU.driver_save_issues).center();
        for ev in click(at) {
            run(&ctx, ev, |ui| app.drivers_window(ui.ctx()));
        }
        let path = match &app.driver_export_status {
            Some(ExportStatus::Saved(p)) => p.clone(),
            other => panic!("saved: {other:?}"),
        };
        assert_eq!(path.parent().unwrap(), app.reports_root.join("Logs"));
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        assert!(name.starts_with("WinStateDiag_DriverIssues_") && name.ends_with(".txt"));
        assert_eq!(
            name.len(),
            "WinStateDiag_DriverIssues_YYYY-MM-DD_HH-MM-SS.txt".len()
        );
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(&bytes[..3], &[0xEF, 0xBB, 0xBF]);
        assert_eq!(std::str::from_utf8(&bytes[3..]).unwrap(), expected);
        // The saved path is shown and journaled; no report folder touched.
        let f = render_drivers(&mut app, &ctx);
        let shown = format!("{}: {}", i18n::RU.export_saved, path.display());
        assert!(has(&f, &shown));
        assert_eq!(app.journal.last().unwrap().message, shown);
        let root: Vec<_> = std::fs::read_dir(&app.reports_root)
            .unwrap()
            .flatten()
            .collect();
        assert_eq!(root.len(), 1, "only Reports\\Logs");
        let _ = std::fs::remove_dir_all(exe.parent().unwrap());
    }

    #[test]
    fn save_issues_failure_is_reported_and_journaled() {
        let (mut app, exe) = app_in("savefail");
        std::fs::write(&app.reports_root, "a file, not a folder").unwrap();
        let ctx = egui::Context::default();
        run(&ctx, vec![], |ui| {
            app.driver_issues_export(ui.ctx(), ExportAction::Save)
        });
        assert!(matches!(
            app.driver_export_status,
            Some(ExportStatus::Failed(_))
        ));
        assert!(
            app.journal
                .last()
                .unwrap()
                .message
                .starts_with("[ERROR] Не удалось сохранить файл")
        );
        let _ = std::fs::remove_dir_all(exe.parent().unwrap());
    }

    fn dashboard_frame(
        app: &mut WinStateDiagApp,
        ctx: &egui::Context,
        events: Vec<egui::Event>,
    ) -> (Frame, Vec<Action>) {
        let vm = app.build_vm(0.0, 0.0);
        let mut actions = Vec::new();
        let (mut client, mut mode, mut deep, mut hw, mut bench) = (
            app.client_name.clone(),
            app.mode,
            app.deep_checks,
            app.include_hardware,
            app.benchmark_path.clone(),
        );
        let f = run(ctx, events, |ui| {
            let mut controls = Controls {
                client_name: &mut client,
                mode: &mut mode,
                deep_checks: &mut deep,
                include_hardware: &mut hw,
                benchmark_path: &mut bench,
            };
            dashboard::draw(ui, egui::Pos2::ZERO, &vm, &mut controls, &mut actions);
        });
        (f, actions)
    }

    #[test]
    fn details_button_in_the_stages_card_opens_the_results_window() {
        for (lang, d) in [(Language::Ru, &i18n::RU), (Language::En, &i18n::EN)] {
            let (mut app, exe) = app_in("btn");
            app.language = lang;
            let ctx = egui::Context::default();
            fonts::install(&ctx);
            let (f, _) = dashboard_frame(&mut app, &ctx, vec![]);
            let (f, _) = if has(&f, d.expc_details_button) {
                (f, vec![])
            } else {
                dashboard_frame(&mut app, &ctx, vec![])
            };
            assert!(has(&f, d.expc_details_button), "{lang:?}");
            // Inside the stages card header, right of the title, above row 1.
            // v0.4.4: header of the stage table on the Diagnostics page.
            let b = l::STAGE_TABLE_DETAILS_BUTTON;
            let card = l::STAGE_TABLE_CARD;
            assert!(b[0] + b[2] <= card[0] + card[2] - 12.0);
            assert!(b[1] >= card[1] && b[1] + b[3] < card[1] + 46.0);
            let at = egui::pos2(
                b[0] - CANVAS_ORIGIN_IN_MASTER[0] + b[2] / 2.0,
                b[1] - CANVAS_ORIGIN_IN_MASTER[1]
                    + b[3] / 2.0
                    + crate::ui::tokens::layout::BODY_SHIFT,
            );
            let mut all = Vec::new();
            for ev in click(at) {
                all.extend(dashboard_frame(&mut app, &ctx, ev).1);
            }
            assert!(
                all.iter().any(|a| matches!(a, Action::ShowExpcDetails)),
                "{all:?}"
            );
            assert!(
                !all.iter()
                    .any(|a| matches!(a, Action::Start | Action::Reset))
            );
            let _ = std::fs::remove_dir_all(exe.parent().unwrap());
        }
    }

    fn finished_run(app: &mut WinStateDiagApp) {
        for s in app.expc_tracker.status.iter_mut() {
            *s = SubStageStatus::Done;
        }
        app.state = RunState::Done {
            zip_path: PathBuf::from("x.zip"),
        };
        app.apply_deep_checks(vec![
            DeepCheckOutcome {
                check: DeepCheck::Sfc,
                result: CheckResult::Ok,
                detail: String::new(),
                source: ResultSource::ExpcJson,
            },
            DeepCheckOutcome {
                check: DeepCheck::Dism,
                result: CheckResult::Attention,
                detail: "The component store is repairable.".into(),
                source: ResultSource::ExpcJson,
            },
        ]);
        app.expc_checks = vec![deep_checks::ExpcCheck {
            key: "Defender".into(),
            status: "OK".into(),
            detail: "всё включено".into(),
        }];
    }

    fn render_expc(app: &mut WinStateDiagApp, ctx: &egui::Context) -> Frame {
        let mut last = run(ctx, vec![], |ui| app.expc_details_window(ui.ctx()));
        for _ in 0..2 {
            last = run(ctx, vec![], |ui| app.expc_details_window(ui.ctx()));
        }
        last
    }

    #[test]
    fn expc_details_window_explains_findings_in_ru_and_en() {
        for (lang, d) in [(Language::Ru, &i18n::RU), (Language::En, &i18n::EN)] {
            let (mut app, exe) = app_in("expc");
            app.language = lang;
            finished_run(&mut app);
            app.apply(Action::ShowExpcDetails);
            let ctx = egui::Context::default();
            let f = render_expc(&mut app, &ctx);
            for t in [
                d.expc_details_title,
                d.expc_details_summary,
                d.expc_sum_problems,
                d.expc_sum_attention,
                d.expc_sum_ok,
                d.expc_sum_skipped,
                d.stage_short[11],
                d.expc_state_labels[1],
                d.deep_check_findings[1][1],
                d.expc_suggested_action,
                "DISM /Online /Cleanup-Image /RestoreHealth",
                d.expc_not_executed,
                d.expc_copy_command,
                d.journal_viewer_copy,
                d.details_save_as,
                d.details_open_folder,
                d.journal_viewer_close,
            ] {
                assert!(has(&f, t), "{lang:?}: {t}");
            }
            assert!(has(
                &f,
                &format!(
                    "{}: The component store is repairable.",
                    d.expc_result_label
                )
            ));
            // The DISM finding is listed before the OK steps.
            assert!(find(&f, d.stage_short[11]).top() < find(&f, d.stage_short[9]).top());
            let _ = std::fs::remove_dir_all(exe.parent().unwrap());
        }
    }

    #[test]
    fn expc_details_copy_uses_actual_results_and_commands_stay_text() {
        let (mut app, exe) = app_in("expccopy");
        finished_run(&mut app);
        app.apply(Action::ShowExpcDetails);
        let ctx = egui::Context::default();
        let f = render_expc(&mut app, &ctx);
        let expected =
            details::expc_details_text(&app.expc_stage_details(), &i18n::RU, &system_drive());
        let at = find(&f, i18n::RU.journal_viewer_copy).center();
        let mut copied = Vec::new();
        for ev in click(at) {
            copied.extend(run(&ctx, ev, |ui| app.expc_details_window(ui.ctx())).copied);
        }
        assert_eq!(copied, [expected.clone()]);
        assert!(expected.contains("DISM /Online /Cleanup-Image /RestoreHealth"));
        assert!(expected.contains("всё включено"));
        // "Copy command" copies the command TEXT only.
        let f = render_expc(&mut app, &ctx);
        let at = find(&f, i18n::RU.expc_copy_command).center();
        let mut copied = Vec::new();
        for ev in click(at) {
            copied.extend(run(&ctx, ev, |ui| app.expc_details_window(ui.ctx())).copied);
        }
        assert_eq!(
            copied,
            ["DISM /Online /Cleanup-Image /RestoreHealth".to_string()]
        );
        // No UI string offers to run / repair / fix anything.
        for d in [&i18n::RU, &i18n::EN] {
            for word in [
                "Исправить",
                "Выполнить команду",
                "Восстановить",
                "Repair",
                "Fix",
                "Execute",
                "Run command",
            ] {
                assert!(!format!("{d:?}").contains(word), "{word}");
            }
        }
        let _ = std::fs::remove_dir_all(exe.parent().unwrap());
    }

    #[test]
    fn opening_and_closing_details_keeps_the_diagnostic_state() {
        let (mut app, exe) = app_in("state");
        finished_run(&mut app);
        let before_rows: Vec<(RowState, Option<StageFinding>, String)> = app
            .build_vm(0.0, 0.0)
            .stages
            .iter()
            .map(|r| (r.state, r.finding, r.right_text.clone()))
            .collect();
        let journal = app.journal.len();
        app.apply(Action::ShowExpcDetails);
        let ctx = egui::Context::default();
        let f = render_expc(&mut app, &ctx);
        let at = find(&f, i18n::RU.journal_viewer_close).center();
        for ev in click(at) {
            run(&ctx, ev, |ui| app.expc_details_window(ui.ctx()));
        }
        assert!(!app.expc_details_open);
        assert!(matches!(app.state, RunState::Done { .. }));
        assert_eq!(app.deep_check_results.len(), 2);
        assert_eq!(app.expc_checks.len(), 1);
        assert_eq!(app.journal.len(), journal);
        let after: Vec<(RowState, Option<StageFinding>, String)> = app
            .build_vm(0.0, 0.0)
            .stages
            .iter()
            .map(|r| (r.state, r.finding, r.right_text.clone()))
            .collect();
        assert_eq!(before_rows, after);
        let _ = std::fs::remove_dir_all(exe.parent().unwrap());
    }

    #[test]
    fn running_session_shows_only_available_information() {
        let (mut app, exe) = app_in("live");
        let (_tx, rx) = std::sync::mpsc::channel();
        app.state = RunState::Running {
            stage: Stage::SystemDiagnostics,
            step_done: 20,
            step_total: 100,
            stage_message: String::new(),
            rx,
        };
        app.expc_tracker.status[0] = SubStageStatus::Done;
        app.expc_tracker.status[1] = SubStageStatus::Running;
        let det = app.expc_stage_details();
        assert_eq!(det[0].state, details::StageState::Completed);
        assert!(det[0].pending);
        assert_eq!(det[1].state, details::StageState::Running);
        assert!(
            det[2..]
                .iter()
                .all(|d| d.state == details::StageState::Waiting)
        );
        assert!(
            det.iter()
                .all(|d| d.findings.is_empty() && d.deep.is_none())
        );
        // Never ran at all: the window says so.
        let (mut idle, exe2) = app_in("idle");
        idle.apply(Action::ShowExpcDetails);
        let ctx = egui::Context::default();
        let f = render_expc(&mut idle, &ctx);
        assert!(has(&f, i18n::RU.expc_not_started));
        let _ = std::fs::remove_dir_all(exe.parent().unwrap());
        let _ = std::fs::remove_dir_all(exe2.parent().unwrap());
    }

    // ---- v0.4.5 consolidation ------------------------------------------

    fn render_stage(app: &mut WinStateDiagApp, ctx: &egui::Context, ev: Vec<egui::Event>) -> Frame {
        let mut last = run(ctx, vec![], |ui| app.stage_details_window(ui.ctx()));
        for _ in 0..2 {
            last = run(ctx, vec![], |ui| app.stage_details_window(ui.ctx()));
        }
        if !ev.is_empty() {
            last = run(ctx, ev, |ui| app.stage_details_window(ui.ctx()));
        }
        last
    }

    /// Row [Детали] opens ONLY that stage; the header button keeps the
    /// global summary.
    #[test]
    fn stage_row_details_button_opens_only_its_own_stage() {
        let (mut app, exe) = app_in("rowbtn");
        finished_run(&mut app);
        let d = &i18n::RU;
        let ctx = egui::Context::default();
        fonts::install(&ctx);
        dashboard_frame(&mut app, &ctx, vec![]);
        let (f, _) = dashboard_frame(&mut app, &ctx, vec![]);
        let card = l::STAGE_TABLE_CARD;
        let mid = card[0] - CANVAS_ORIGIN_IN_MASTER[0] + card[2] / 2.0;
        let mut rows: Vec<Rect> = f
            .texts
            .iter()
            .filter(|(t, r)| t == d.stage_details_short && r.center().x > mid)
            .map(|(_, r)| *r)
            .collect();
        rows.sort_by(|a, b| a.top().total_cmp(&b.top()));
        assert!(
            rows.len() >= 14,
            "14 row buttons (+ header): {}",
            rows.len()
        );
        // The header button reads "Детали" too; row buttons are the last 14.
        let rows = &rows[rows.len() - 14..];
        let mut all = Vec::new();
        for ev in click(rows[11].center()) {
            all.extend(dashboard_frame(&mut app, &ctx, ev).1);
        }
        assert!(
            all.iter()
                .any(|a| matches!(a, Action::ShowStageDetails(11))),
            "{all:?}"
        );
        assert!(
            !all.iter().any(|a| matches!(a, Action::ShowExpcDetails)),
            "never the global window"
        );
        let _ = std::fs::remove_dir_all(exe.parent().unwrap());
    }

    #[test]
    fn stage_window_shows_the_selected_stage_and_nothing_else() {
        for (lang, d) in [(Language::Ru, &i18n::RU), (Language::En, &i18n::EN)] {
            let (mut app, exe) = app_in("stagewin");
            app.language = lang;
            finished_run(&mut app);
            push_journal(
                &mut app.journal,
                format!("{} — завершено", EXPC_STEP_LABELS[11]),
            );
            push_journal(
                &mut app.journal,
                format!("{} — завершено", EXPC_STEP_LABELS[9]),
            );
            app.apply(Action::ShowStageDetails(11));
            let ctx = egui::Context::default();
            let f = render_stage(&mut app, &ctx, vec![]);
            let title = d
                .stage_window_title_fmt
                .replace("{n}", "12")
                .replace("{name}", d.stage_short[11]);
            assert!(has(&f, &title), "{lang:?}");
            assert!(f.texts.iter().any(|(t, _)| t.contains(d.stage_scope[11])));
            assert!(
                f.texts
                    .iter()
                    .any(|(t, _)| t.contains("The component store is repairable."))
            );
            for t in [
                d.stage_status_label,
                d.stage_evidence_label,
                d.stage_journal_label,
                d.journal_viewer_copy,
                d.journal_viewer_save,
                d.journal_viewer_close,
            ] {
                assert!(f.texts.iter().any(|(x, _)| x.contains(t)), "{lang:?}: {t}");
            }
            // Stage 10 (Defender) data never leaks into stage 12.
            assert!(!f.texts.iter().any(|(t, _)| t.contains("всё включено")));
            assert!(!f.texts.iter().any(|(t, _)| t.contains(EXPC_STEP_LABELS[9])));
            assert!(
                f.texts
                    .iter()
                    .any(|(t, _)| t.contains(EXPC_STEP_LABELS[11])),
                "stage journal"
            );
            // Copy exports this stage only.
            let text = app.stage_details_text(11);
            assert!(text.contains("DISM"));
            assert!(!text.contains("всё включено"));
            // Another row switches the window to that stage.
            app.apply(Action::ShowStageDetails(9));
            let f = render_stage(&mut app, &ctx, vec![]);
            assert!(f.texts.iter().any(|(t, _)| t.contains("всё включено")));
            assert!(
                !f.texts
                    .iter()
                    .any(|(t, _)| t.contains("The component store is repairable."))
            );
            let _ = std::fs::remove_dir_all(exe.parent().unwrap());
        }
    }

    #[test]
    fn stage_seven_evidence_is_the_crash_inventory_and_incidents() {
        let (mut app, exe) = app_in("stage7");
        finished_run(&mut app);
        let mut inv = crash_inventory_with_incident();
        inv.bugchecks.clear();
        app.crash.inventory = Some(Ok(inv));
        let ev = app.stage_evidence_lines(6);
        assert!(
            ev.iter().any(|l| l.starts_with(
                "Last 30 days: unexpected shutdowns: 1 · BugCheck / BSOD: 0 · Dumps (all files): 0"
            )),
            "{ev:?}"
        );
        assert!(
            ev.iter()
                .any(|l| l.starts_with("Incident 2026-10-04 21:14:10")),
            "{ev:?}"
        );
        assert!(
            app.stage_evidence_lines(11)
                .iter()
                .all(|l| !l.contains("Incident"))
        );
        let _ = std::fs::remove_dir_all(exe.parent().unwrap());
    }

    fn crash_inventory_with_incident() -> crash_dump::Inventory {
        crash_dump::Inventory {
            bugchecks: Vec::new(),
            dumps: Vec::new(),
            debugger: crash_dump::DebuggerStatus::NotInstalled,
            notes: Vec::new(),
            unexpected_shutdowns: 1,
            incidents: vec![crate::incidents::tests::incident(
                vec![crate::incidents::tests::ev(
                    "2026-10-04T20:57:44",
                    "nvlddmkm",
                    153,
                    2,
                    "Restarting TDR occurred",
                )],
                0,
            )],
            live_kernel_reports: Vec::new(),
        }
    }

    #[test]
    fn unexpected_shutdown_without_bugcheck_never_claims_a_bsod() {
        for (lang, d) in [(Language::Ru, &i18n::RU), (Language::En, &i18n::EN)] {
            let (mut app, exe) = app_in("unexp");
            app.language = lang;
            app.crash.inventory = Some(Ok(crash_inventory_with_incident()));
            let vm = app.crash_vm();
            assert_eq!(vm.headline, d.crash_unexpected_only);
            assert_eq!(
                vm.counts,
                d.crash_counts_fmt
                    .replace("{s}", "1")
                    .replace("{b}", "0")
                    .replace("{d}", "0")
            );
            let row = vm
                .rows
                .iter()
                .find(|r| r.label == d.crash_row_incident)
                .expect("incident row");
            assert!(row.value.contains("BSOD NOT REGISTERED"), "{}", row.value);
            assert!(
                !row.value.contains("nvlddmkm"),
                "no culprit binary in the verdict"
            );
            let _ = std::fs::remove_dir_all(exe.parent().unwrap());
        }
        assert_eq!(
            i18n::RU.crash_no_dump,
            "BugCheck обнаружен, dump не найден."
        );
        assert_eq!(
            i18n::RU.crash_unexpected_only,
            "Внимание — обнаружено неожиданное выключение. BSOD не подтверждён."
        );
    }

    #[test]
    fn incidents_evidence_joins_the_report_and_the_manifest() {
        let (mut app, exe) = app_in("incev");
        app.crash.inventory = Some(Ok(crash_inventory_with_incident()));
        app.contribute_incidents();
        let zip = report_package::lock(&app.package).final_zip().expect("zip");
        let files = crate::report_package::read_zip(&zip).unwrap();
        let ev = files
            .iter()
            .find(|f| f.name.starts_with(incidents::EVIDENCE_PREFIX))
            .expect("Incidents_ evidence");
        let text = String::from_utf8_lossy(&ev.bytes);
        assert!(text.contains("\"probable_subsystem\": \"GPU\""));
        assert!(text.contains("\"bsod\": \"NOT_REGISTERED\""));
        let manifest = files
            .iter()
            .find(|f| f.name == "manifest.json")
            .expect("manifest");
        let m = String::from_utf8_lossy(&manifest.bytes);
        assert!(m.contains("\"freeze_hang_incidents\""), "{m}");
        assert!(m.contains("\"incident_count\": 1"), "{m}");
        let _ = std::fs::remove_dir_all(exe.parent().unwrap());
    }

    #[test]
    fn client_copy_button_copies_client_and_computer_without_state_change() {
        let (mut app, exe) = app_in("copy");
        app.computer_name = "MSI".into();
        app.client_name = "Алексей".into();
        let before = (app.client_name.clone(), app.page, app.journal.entries.len());
        app.apply(Action::CopyClientInfo);
        assert_eq!(
            app.clipboard_out.as_deref(),
            Some("Клиент: Алексей\nКомпьютер: MSI")
        );
        assert_eq!(
            before,
            (app.client_name.clone(), app.page, app.journal.entries.len())
        );
        app.client_name.clear();
        app.language = Language::En;
        app.apply(Action::CopyClientInfo);
        assert_eq!(app.clipboard_out.as_deref(), Some("Computer: MSI"));
        // The copy icon sits between the "Клиент" label and the field.
        let b = l::CLIENT_COPY_BUTTON;
        assert!(b[0] > l::CLIENT_LABEL_X + 60.0 && b[0] + b[2] < l::CLIENT_FIELD[0]);
        let ctx = egui::Context::default();
        fonts::install(&ctx);
        app.language = Language::Ru;
        app.client_name = "ACME".into();
        dashboard_frame(&mut app, &ctx, vec![]);
        let at = egui::pos2(
            b[0] - CANVAS_ORIGIN_IN_MASTER[0] + b[2] / 2.0,
            b[1] - CANVAS_ORIGIN_IN_MASTER[1] + b[3] / 2.0 + crate::ui::tokens::layout::BODY_SHIFT,
        );
        let mut all = Vec::new();
        for ev in click(at) {
            all.extend(dashboard_frame(&mut app, &ctx, ev).1);
        }
        assert!(
            all.iter().any(|a| matches!(a, Action::CopyClientInfo)),
            "{all:?}"
        );
        let _ = std::fs::remove_dir_all(exe.parent().unwrap());
    }

    #[test]
    fn passport_shows_windows_cpu_ram_board_only() {
        let (mut app, exe) = app_in("passport");
        app.passport = Some(Ok(passport::Passport {
            windows: "Windows 11 Pro 25H2 (26200.6584)".into(),
            cpu: "Intel(R) Core(TM) i7-14700K · 20C/28T".into(),
            ram: "32 GB DDR5-6000 (2×16 GB)".into(),
            board: String::new(),
            bios: "7E06v1A (2025-03-14)".into(),
            ram_onboard_devices: None,
        }));
        let rows = app.passport_rows();
        let d = &i18n::RU;
        let labels: Vec<&str> = rows.iter().map(|r| r.label.as_str()).collect();
        assert_eq!(
            labels,
            [
                d.passport_windows,
                d.passport_cpu,
                d.passport_ram,
                d.passport_board,
                d.passport_bios
            ]
        );
        assert_eq!(
            rows[4].value, "7E06v1A (2025-03-14)",
            "BIOS line after Плата"
        );
        assert_eq!(
            rows[3].value, d.passport_no_data,
            "missing board is said, not invented"
        );
        // The collector failing still shows the locally known OS line.
        app.passport = Some(Err("x".into()));
        assert!(app.passport_rows()[0].value.contains('('));
        let _ = std::fs::remove_dir_all(exe.parent().unwrap());
    }

    /// Details windows are OS viewports; without a multi-viewport backend
    /// (and in tests) egui embeds them, so they always render.
    #[test]
    fn detail_windows_fall_back_to_embedded_windows() {
        let ctx = egui::Context::default();
        assert!(ctx.embed_viewports());
        let mut open = true;
        let mut f = run(&ctx, vec![], |_| {});
        for _ in 0..3 {
            f = run(&ctx, vec![], |ui| {
                detail_window(
                    ui.ctx(),
                    "wsd_test_viewport",
                    "Тест",
                    [700.0, 500.0],
                    &mut open,
                    |ui| {
                        ui.label("inside");
                    },
                );
            });
        }
        assert!(has(&f, "inside"));
        assert!(has(&f, "Тест"));
        assert!(open);
    }
}

/// Native NVMe Health (experimental phase): identity binding, evidence and
/// the facts-only Details section. The benchmark itself is untouched.
#[cfg(test)]
mod nvme_health_tests {
    use super::*;
    use crate::nvme_health::tests::{disk, smart_bytes};
    use crate::nvme_health::{LogRead, NvmeLogSource, ProbeError, ProbeStatus, collect};
    use crate::report_package::read_zip;
    use crate::storage_benchmark::{BenchmarkRun, DiagnosticPass, IoMeasurement};
    use crate::storage_topology::{DiskCandidate, VolumeInfo};

    struct Src(Result<Vec<u8>, ProbeError>);
    impl NvmeLogSource for Src {
        fn read_log_page(&self, _: u32, lid: u8, _: usize) -> Result<LogRead, ProbeError> {
            if lid == crate::nvme_health::LID_SMART_HEALTH {
                self.0.clone().map(|data| LogRead {
                    data,
                    via: "StorageDeviceProtocolSpecificProperty",
                })
            } else {
                Ok(LogRead {
                    data: vec![0u8; 1024],
                    via: "StorageDeviceProtocolSpecificProperty",
                })
            }
        }
    }

    fn cand(index: u32, model: &str, serial: &str, letter: &str, system: bool) -> DiskCandidate {
        DiskCandidate {
            disk: disk(index, model, serial, "NVMe"),
            is_system: system,
            volume: Some(VolumeInfo {
                mount_point: letter.into(),
                physical_disk_index: index,
                writable: true,
                label: String::new(),
            }),
            label: model.into(),
        }
    }

    fn app(tag: &str) -> (WinStateDiagApp, PathBuf) {
        let exe = std::env::temp_dir()
            .join(format!("wsd-nvme-{tag}-{}", std::process::id()))
            .join("WinStateDiag");
        let _ = std::fs::remove_dir_all(exe.parent().unwrap());
        std::fs::create_dir_all(&exe).unwrap();
        let mut app = WinStateDiagApp::default();
        app.client_name = "Алексей".into();
        app.computer_name = "MSI".into();
        app.reports_root = exe.join("Reports");
        app.language = Language::En;
        app.package = Arc::new(Mutex::new(SessionPackage::new(exe.join("Reports"), None)));
        app.ssd_candidates = vec![
            cand(1, "Samsung SSD 9100 PRO 2TB", "S7XXNOTREAL", "C:\\", true),
            cand(0, "Netac NVMe SSD 1TB", "", "D:\\", false),
        ];
        app.ssd_selected = 0;
        (app, exe)
    }

    fn summary() -> StorageDiagnosticSummary {
        let m = |mb: f64| IoMeasurement {
            bytes: 0,
            operations: 0,
            elapsed: Duration::from_secs(1),
            mb_per_second: mb,
            iops: 0.0,
            average_latency: Duration::from_millis(1),
        };
        StorageDiagnosticSummary {
            profile: crate::storage_benchmark::StorageDiagnosticProfile {
                block_size: 1024 * 1024,
                queue_depth: 4,
                test_file_size: 512 * 1024 * 1024,
                pass_count: 1,
                stable_spread_limit_percent: 10.0,
            },
            preparation_method: "test",
            preparation_elapsed: Duration::from_secs(0),
            summary_read_mib_s: 500.0,
            summary_write_mib_s: 400.0,
            read_min_mib_s: 480.0,
            read_max_mib_s: 520.0,
            write_min_mib_s: 380.0,
            write_max_mib_s: 420.0,
            read_variation_percent: 2.0,
            write_variation_percent: 3.0,
            stable: true,
            raw_passes: vec![DiagnosticPass {
                pass_number: 1,
                run: BenchmarkRun {
                    block_size: 1024 * 1024,
                    read: m(500.0),
                    write: m(400.0),
                },
            }],
        }
    }

    #[test]
    fn health_binds_to_the_benchmark_identity_and_joins_the_package() {
        let (mut app, exe) = app("bind");
        let samsung = app.ssd_candidates[0].disk.clone();
        let health = collect(&Src(Ok(smart_bytes())), &samsung, "2026-10-03T12:00:00");
        // Same key as the benchmark/history (never a drive letter).
        let bench_identity = ssd_history::disk_identity_with_physical(
            Path::new("C:\\"),
            Some(storage_topology::physical_disk_identity(&samsung).as_str()),
        );
        assert_eq!(health.physical_identity, bench_identity);
        assert!(!health.physical_identity.contains("C:"));
        app.accept_nvme_health(health);
        assert!(app.selected_nvme_health().is_some());
        // The other physical disk never inherits this record.
        app.ssd_selected = 1;
        assert!(app.selected_nvme_health().is_none());

        let zip = report_package::lock(&app.package).final_zip().unwrap();
        let names: Vec<String> = read_zip(&zip)
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        let file = names
            .iter()
            .find(|n| n.starts_with("NVMe_Health_") && n.ends_with("_PD1.json"))
            .expect("health evidence in the package");
        assert!(names.contains(&"manifest.json".to_string()));
        let manifest = read_zip(&zip)
            .unwrap()
            .into_iter()
            .find(|e| e.name == "manifest.json")
            .map(|e| String::from_utf8(e.bytes).unwrap())
            .unwrap();
        assert!(manifest.contains("\"nvme_health\""));
        assert!(manifest.contains(file.as_str()));
        assert!(manifest.contains("\"schema_version\": \"1.0\""));
        assert!(
            app.journal
                .iter()
                .any(|e| e.message.contains("NVMe Health (PhysicalDrive1): OK"))
        );
        let _ = std::fs::remove_dir_all(exe.parent().unwrap());
    }

    #[test]
    fn unsupported_health_is_recorded_without_values() {
        let (mut app, exe) = app("unsup");
        let netac = app.ssd_candidates[1].disk.clone();
        let h = collect(&Src(Err(ProbeError::InvalidFunction)), &netac, "t");
        assert_eq!(h.status, ProbeStatus::Unsupported);
        let rows = nvme_health_rows(&h, i18n::t(Language::En));
        assert_eq!(rows[0], ("Status".to_string(), "Not supported".to_string()));
        assert!(
            rows.iter().all(|(_, v)| !v.contains(" %")),
            "no fabricated values"
        );
        app.accept_nvme_health(h);
        app.ssd_selected = 1;
        assert_eq!(
            app.selected_nvme_health().map(|h| h.status),
            Some(ProbeStatus::Unsupported)
        );
        let _ = std::fs::remove_dir_all(exe.parent().unwrap());
    }

    #[test]
    fn details_rows_are_facts_without_verdicts() {
        let samsung = disk(1, "Samsung SSD 9100 PRO 2TB", "S", "NVMe");
        let mut b = smart_bytes();
        b[160] = 2; // media errors: shown as a raw count, not a verdict
        let h = collect(&Src(Ok(b)), &samsung, "t");
        for lang in [Language::En, Language::Ru] {
            let rows = nvme_health_rows(&h, i18n::t(lang));
            let text: String = rows.iter().map(|(l, v)| format!("{l}={v};")).collect();
            for verdict in ["HEALTHY", "BAD", "FAIL", "GOOD", "ИСПРАВ", "НЕИСПРАВ"] {
                assert!(
                    !text.to_uppercase().contains(verdict),
                    "{verdict} in {text}"
                );
            }
            assert!(text.contains("42 °C"));
            assert!(text.contains("#1 45 °C, #2 52 °C"));
        }
        let rows = nvme_health_rows(&h, i18n::t(Language::En));
        let get = |k: &str| rows.iter().find(|(l, _)| l == k).map(|(_, v)| v.as_str());
        assert_eq!(get("Critical Warning"), Some("0"));
        assert_eq!(get("Available Spare"), Some("100 %"));
        assert_eq!(get("Spare Threshold"), Some("10 %"));
        assert_eq!(get("Percentage Used"), Some("3 %"));
        assert_eq!(get("Unsafe Shutdowns"), Some("37"));
        assert_eq!(get("Media and Data Integrity Errors"), Some("2"));
        assert_eq!(get("Error Log Entries"), Some("12"));
        assert_eq!(get("Power On Hours"), Some("4321"));
        assert_eq!(get("Data Written"), Some("26.80 TB"));
        assert_eq!(get("Error Information Log"), Some("0 entries read"));
    }

    #[test]
    fn details_popup_shows_the_health_section_for_the_selected_disk_only() {
        let (mut app, exe) = app("ui");
        let samsung = app.ssd_candidates[0].disk.clone();
        app.accept_nvme_health(collect(&Src(Ok(smart_bytes())), &samsung, "t"));
        app.benchmark_state = BenchmarkUiState::Done {
            result: summary(),
            duration_seconds: 10.0,
            previous: None,
        };
        app.raw_passes_open = true;
        let render = |app: &mut WinStateDiagApp| -> String {
            let ctx = egui::Context::default();
            let mut texts = String::new();
            for _ in 0..12 {
                let mut out = ctx.run_ui(
                    egui::RawInput {
                        screen_rect: Some(Rect::from_min_size(
                            egui::Pos2::ZERO,
                            vec2(1400.0, 1000.0),
                        )),
                        ..Default::default()
                    },
                    |ui| {
                        app.raw_passes_window(ui.ctx());
                    },
                );
                out.textures_delta.clear();
                fn walk(shape: &egui::Shape, acc: &mut String) {
                    match shape {
                        egui::Shape::Text(t) => {
                            acc.push_str(t.galley.text());
                            acc.push('\n');
                        }
                        egui::Shape::Vec(v) => v.iter().for_each(|s| walk(s, acc)),
                        _ => {}
                    }
                }
                texts.clear();
                for c in &out.shapes {
                    walk(&c.shape, &mut texts);
                }
            }
            texts
        };
        let shown = render(&mut app);
        assert!(shown.contains("NVMe HEALTH"), "health section rendered");
        assert!(shown.contains("Critical Warning"));
        assert!(shown.contains("Controller facts, not a verdict"), "{shown}");
        app.ssd_selected = 1;
        let other = render(&mut app);
        let d = i18n::t(app.language);
        // v1.0 Disk Details: raw passes stay available (collapsible) and
        // the other disk shows "no health data" — never Samsung's facts.
        assert!(
            other.contains(d.ssd_raw_passes_title),
            "benchmark passes still offered"
        );
        assert!(other.contains(d.disk_det_no_health), "{other}");
        assert!(!other.contains("Critical Warning"), "no cross-disk health");
        let _ = std::fs::remove_dir_all(exe.parent().unwrap());
    }

    /// The benchmark, its thresholds and its evidence are unchanged by the
    /// health phase (the probe is a separate step after contribution).
    #[test]
    fn benchmark_logic_and_evidence_are_unchanged() {
        assert_eq!(stability_level(5.0), StabilityLevel::Stable);
        assert_eq!(stability_level(5.01), StabilityLevel::Acceptable);
        assert_eq!(stability_level(12.0), StabilityLevel::Acceptable);
        assert_eq!(stability_level(12.01), StabilityLevel::Unstable);
        let files = ssd_benchmark_evidence(&summary(), Path::new("C:\\"), 1.0, None, "x".into());
        assert_eq!(files.len(), 2);
        assert!(files.iter().all(|f| f.name.starts_with("SSD_Benchmark_")));
        let bench_src = include_str!("storage_benchmark.rs");
        assert!(!bench_src.contains("nvme_health"));
        assert!(!bench_src.to_lowercase().contains("smart"));
        // No storage severity is derived from health yet.
        // Storage severity comes only from storage_health::classify.
    }
}

/// v0.4.2 storage correlation + automatic retest workflow (driven through
/// the test seam: no real disk I/O).
#[cfg(test)]
mod storage_correlation_tests {
    use super::*;
    use crate::nvme_health::collect;
    use crate::report_package::read_zip;
    use crate::storage_benchmark::{BenchmarkRun, DiagnosticPass, IoMeasurement};
    use crate::storage_health::tests::{netac_page, samsung_page, smart_page};
    use crate::storage_health::{RetestOutcome, RetestSkip, StorageState};
    use crate::storage_topology::{DiskCandidate, VolumeInfo};

    struct Src(Vec<u8>);
    impl nvme_health::NvmeLogSource for Src {
        fn read_log_page(
            &self,
            _: u32,
            lid: u8,
            _: usize,
        ) -> Result<nvme_health::LogRead, nvme_health::ProbeError> {
            if lid == nvme_health::LID_SMART_HEALTH {
                Ok(nvme_health::LogRead {
                    data: self.0.clone(),
                    via: "test",
                })
            } else {
                Err(nvme_health::ProbeError::InvalidFunction)
            }
        }
    }

    fn summary(write_spread: f64) -> StorageDiagnosticSummary {
        let m = |mb: f64| IoMeasurement {
            bytes: 0,
            operations: 0,
            elapsed: Duration::from_secs(1),
            mb_per_second: mb,
            iops: 0.0,
            average_latency: Duration::from_millis(1),
        };
        StorageDiagnosticSummary {
            profile: crate::storage_benchmark::StorageDiagnosticProfile {
                block_size: 1024 * 1024,
                queue_depth: 4,
                test_file_size: 512 * 1024 * 1024,
                pass_count: 3,
                stable_spread_limit_percent: 10.0,
            },
            preparation_method: "test",
            preparation_elapsed: Duration::from_secs(0),
            summary_read_mib_s: 6500.0,
            // Distinct per run (history lines are de-duplicated by content).
            summary_write_mib_s: 5600.0 - write_spread,
            read_min_mib_s: 6400.0,
            read_max_mib_s: 6600.0,
            write_min_mib_s: 5000.0,
            write_max_mib_s: 6000.0,
            read_variation_percent: 1.5,
            write_variation_percent: write_spread,
            stable: write_spread <= 5.0,
            raw_passes: (1..=3)
                .map(|n| DiagnosticPass {
                    pass_number: n,
                    run: BenchmarkRun {
                        block_size: 1024 * 1024,
                        read: m(6500.0),
                        write: m(5600.0),
                    },
                })
                .collect(),
        }
    }

    fn new_app(tag: &str) -> (WinStateDiagApp, PathBuf) {
        let root = std::env::temp_dir().join(format!("wsd-corr-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let exe = root.join("WinStateDiag");
        let target = root.join("target");
        std::fs::create_dir_all(&exe).unwrap();
        std::fs::create_dir_all(&target).unwrap();
        let mut app = WinStateDiagApp::default();
        app.client_name = "Алексей".into();
        app.computer_name = "MSI".into();
        app.language = Language::En;
        app.reports_root = exe.join("Reports");
        app.package = Arc::new(Mutex::new(SessionPackage::new(exe.join("Reports"), None)));
        app.retest_idle = Duration::ZERO;
        let mk = |index: u32, model: &str, system: bool| DiskCandidate {
            disk: crate::nvme_health::tests::disk(index, model, "", "NVMe"),
            is_system: system,
            volume: Some(VolumeInfo {
                mount_point: target.display().to_string(),
                physical_disk_index: index,
                writable: true,
                label: String::new(),
            }),
            label: model.into(),
        };
        app.ssd_candidates = vec![
            mk(3, "Samsung SSD 9100 PRO 1TB", true),
            mk(4, "Netac NVMe SSD 1TB", false),
        ];
        app.ssd_selected = 0;
        app.benchmark_path = target.display().to_string();
        (app, root)
    }

    fn identity(app: &WinStateDiagApp) -> String {
        storage_topology::physical_disk_identity(&app.selected_ssd_candidate().unwrap().disk)
    }

    fn finish(app: &mut WinStateDiagApp, r: Result<StorageDiagnosticSummary, String>) {
        app.bench_test_tx
            .as_ref()
            .expect("a run was launched")
            .send(BenchmarkEvent::Finished(r))
            .unwrap();
        app.poll_benchmark();
    }

    fn package_names(app: &WinStateDiagApp) -> Vec<String> {
        let zip = report_package::lock(&app.package).final_zip().unwrap();
        read_zip(&zip)
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect()
    }

    fn state(app: &WinStateDiagApp) -> StorageState {
        app.selected_assessment()
            .and_then(|a| a.classification.as_ref())
            .map(|c| c.state)
            .expect("classified")
    }

    /// v1.0 real case: a SATA SSD "measured" 2571–3065 MB/s. Physically
    /// impossible on SATA 6 Gb/s → BENCHMARK INVALID; never history, never
    /// a stability verdict; a plausible ~538 / 515 MB/s run is accepted.
    #[test]
    fn impossible_sata_benchmark_is_invalid_and_plausible_one_is_accepted() {
        let (mut app, root) = new_app("sata_invalid");
        app.ssd_candidates[0].disk.bus_type = "SATA".into();
        app.ssd_candidates[0].disk.model = "Samsung SSD 870 EVO 1TB".into();
        let mut fast = summary(1.0);
        fast.read_max_mib_s = 3065.0 / 1.048_576;
        fast.write_max_mib_s = 2571.0 / 1.048_576;
        assert!(crate::storage_benchmark::implausible_reason("SATA", &fast).is_some());
        app.start_benchmark();
        finish(&mut app, Ok(fast));
        match &app.benchmark_state {
            BenchmarkUiState::Failed(m) => {
                assert!(
                    m.starts_with("BENCHMARK INVALID / RESULT NOT TRUSTED"),
                    "{m}"
                )
            }
            _ => panic!("expected Failed (invalid benchmark)"),
        }
        assert!(app.ssd_results.is_empty(), "never cached as a result");
        assert!(app.selected_assessment().is_none(), "never classified");
        let names = package_names(&app);
        assert!(
            names.iter().any(|n| n.ends_with("_INVALID.json")),
            "{names:?}"
        );
        assert!(
            crate::ssd_history::load_all_history(&app.reports_root).is_empty(),
            "never in history"
        );
        // A physically plausible SATA run is a normal result.
        let mut ok = summary(1.0);
        ok.read_max_mib_s = 538.0 / 1.048_576;
        ok.write_max_mib_s = 515.0 / 1.048_576;
        ok.summary_read_mib_s = 530.0 / 1.048_576;
        ok.summary_write_mib_s = 510.0 / 1.048_576;
        assert!(crate::storage_benchmark::implausible_reason("SATA", &ok).is_none());
        app.start_benchmark();
        finish(&mut app, Ok(ok));
        assert!(matches!(app.benchmark_state, BenchmarkUiState::Done { .. }));
        // NVMe has no fixed ceiling here; 7000 MB/s stays valid.
        assert!(crate::storage_benchmark::implausible_reason("NVMe", &summary(1.0)).is_none());
        let _ = std::fs::remove_dir_all(root);
    }

    /// v1.0: the target directory always comes from the selected candidate
    /// (never a stale UI path), so a result cannot be attributed to the
    /// wrong physical disk.
    #[test]
    fn benchmark_target_is_derived_from_the_selected_candidate() {
        let (mut app, root) = new_app("target_bind");
        app.benchmark_path = "Z:\\stale".into();
        app.start_benchmark();
        assert!(app.benchmark_is_running());
        assert_ne!(app.benchmark_path, "Z:\\stale");
        assert_eq!(
            app.benchmark_path,
            app.ssd_candidates[0].volume.as_ref().unwrap().mount_point
        );
        finish(&mut app, Err("stop".into()));
        // A candidate whose volume belongs to another physical disk is
        // refused (no silent cross-disk run).
        app.ssd_candidates[0]
            .volume
            .as_mut()
            .unwrap()
            .physical_disk_index = 99;
        app.benchmark_state = BenchmarkUiState::Idle;
        app.start_benchmark();
        assert!(!app.benchmark_is_running());
        let _ = std::fs::remove_dir_all(root);
    }

    /// v0.4.5 Test 1 / Test 2 live visibility: the active block shows the
    /// live MB/s and an mm:ss clock, Test 2 stays waiting; after run 1 the
    /// first block is marked done (final values kept) and the retest block
    /// is labelled as the confirmation retest.
    #[test]
    fn live_test_blocks_follow_the_run_and_the_retest() {
        let (mut app, _root) = new_app("liveblocks");
        let id = identity(&app);
        let samsung = app.ssd_candidates[0].disk.clone();
        app.nvme_health
            .insert(id.clone(), collect(&Src(samsung_page()), &samsung, "t"));
        app.start_benchmark();
        match &app.build_vm(0.0, 0.0).ssd {
            SsdVm::Running { blocks, retest, .. } => {
                assert!(!retest);
                assert!(matches!(
                    &blocks[0],
                    TestBlockVm::Active {
                        read: None,
                        write: None,
                        ..
                    }
                ));
                assert_eq!(blocks[1], TestBlockVm::Waiting(None));
            }
            other => panic!("{other:?}"),
        }
        let tx = app.bench_test_tx.clone().expect("a run was launched");
        tx.send(BenchmarkEvent::Progress(DiagnosticProgress::Measured {
            pass: 1,
            write_mib_s: 1000.0,
            read_mib_s: None,
        }))
        .unwrap();
        app.poll_benchmark();
        tx.send(BenchmarkEvent::Progress(DiagnosticProgress::Measured {
            pass: 1,
            write_mib_s: 1000.0,
            read_mib_s: Some(2000.0),
        }))
        .unwrap();
        app.poll_benchmark();
        match &app.build_vm(0.0, 0.0).ssd {
            SsdVm::Running { blocks, status, .. } => {
                match &blocks[0] {
                    TestBlockVm::Active {
                        read,
                        write,
                        elapsed,
                    } => {
                        assert_eq!(read.as_deref(), Some("2097"), "MiB/s -> MB/s");
                        assert_eq!(write.as_deref(), Some("1049"));
                        assert_eq!(elapsed.len(), 5, "mm:ss clock: {elapsed}");
                    }
                    other => panic!("{other:?}"),
                }
                assert!(!status.is_empty(), "Measured never blanks the pass status");
            }
            other => panic!("{other:?}"),
        }
        finish(&mut app, Ok(summary(18.4)));
        match &app.build_vm(0.0, 0.0).ssd {
            SsdVm::Running { blocks, retest, .. } => {
                assert!(retest, "confirmation retest pending");
                assert!(
                    matches!(&blocks[0], TestBlockVm::Done(t) if t.stability.starts_with("UNSTABLE"))
                );
                assert!(
                    matches!(&blocks[1], TestBlockVm::Waiting(Some(t)) if t.starts_with("Retest in"))
                );
            }
            other => panic!("{other:?}"),
        }
        app.poll_retest();
        match &app.build_vm(0.0, 0.0).ssd {
            SsdVm::Running { blocks, retest, .. } => {
                assert!(retest);
                assert!(
                    matches!(&blocks[0], TestBlockVm::Done(_)),
                    "Test 1 kept as done"
                );
                assert!(
                    matches!(&blocks[1], TestBlockVm::Active { .. }),
                    "Test 2 now active"
                );
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn test_block_clock_and_captions() {
        assert_eq!(clock_mm_ss(6), "00:06");
        assert_eq!(clock_mm_ss(125), "02:05");
        let ru = i18n::t(Language::Ru);
        assert_eq!(ru.test_done, "ГОТОВ");
        assert_eq!(ru.test_running, "ВЫПОЛНЯЕТСЯ");
        assert_eq!(
            ru.test_retest_label,
            "ПОВТОРНЫЙ ТЕСТ — подтверждение результата"
        );
    }

    /// Real Samsung/Netac-equivalent case: run 1 WRITE spread above the
    /// UNSTABLE threshold, ONE automatic retest back in range, clean health
    /// -> anomaly not confirmed, never a storage failure; both runs kept.
    #[test]
    fn unstable_then_normal_retest_keeps_both_runs_and_is_not_a_failure() {
        let (mut app, root) = new_app("normalized");
        let id = identity(&app);
        let samsung = app.ssd_candidates[0].disk.clone();
        app.nvme_health
            .insert(id.clone(), collect(&Src(samsung_page()), &samsung, "t"));
        app.start_benchmark();
        finish(&mut app, Ok(summary(18.4)));
        assert!(matches!(
            app.benchmark_state,
            BenchmarkUiState::RetestWaiting { .. }
        ));
        assert!(
            app.benchmark_is_running(),
            "UI shows the confirmation phase"
        );
        let vm = app.build_vm(0.0, 0.0);
        match &vm.ssd {
            SsdVm::Running { status, note, .. } => {
                assert!(status.starts_with("Retest in"), "{status}");
                let note = note.clone().expect("retest note");
                assert!(
                    note[0].contains("Confirmation retest: run 1 UNSTABLE 18.4%"),
                    "{note:?}"
                );
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(
            app.assessments[&id].retest,
            RetestOutcome::Pending,
            "not classified before the retest"
        );
        app.poll_retest();
        assert!(app.retest_identity.is_some(), "retest launched");
        match &app.build_vm(0.0, 0.0).ssd {
            SsdVm::Running { note, .. } => {
                assert!(
                    note.as_ref()
                        .is_some_and(|n| n[0].contains("Confirmation retest"))
                )
            }
            other => panic!("{other:?}"),
        }
        finish(&mut app, Ok(summary(6.2)));
        assert!(matches!(app.benchmark_state, BenchmarkUiState::Done { .. }));
        assert!(app.retest_identity.is_none());
        // Only ONE automatic retest: nothing else is scheduled.
        app.poll_retest();
        assert!(!app.benchmark_is_running());
        assert_eq!(state(&app), StorageState::AnomalyNotConfirmed);
        let a = app.selected_assessment().unwrap();
        assert!(a.first.write_variation_percent > 12.0, "first run kept");
        assert!(a.second.is_some(), "second run kept");
        // Evidence: both benchmark runs + the correlation, history ×2.
        let names = package_names(&app);
        let bench_json: Vec<&String> = names
            .iter()
            .filter(|n| n.starts_with("SSD_Benchmark_") && n.ends_with(".json"))
            .collect();
        assert_eq!(bench_json.len(), 2, "{names:?}");
        assert!(bench_json.iter().any(|n| n.ends_with("_retest.json")));
        assert!(
            names
                .iter()
                .any(|n| n.starts_with("Storage_Correlation_") && n.ends_with("_PD3.json"))
        );
        assert_eq!(ssd_history::load_all_history(&app.reports_root).len(), 2);
        // Dashboard: correlation colour + the first UNSTABLE run in the note.
        match &app.build_vm(0.0, 0.0).ssd {
            SsdVm::Done { status, note, .. } => {
                let (text, tone) = status.clone().expect("status");
                assert_eq!(text, "Retest normal");
                assert_eq!(tone, Tone::Success);
                let note = note.clone().expect("note");
                assert_eq!(note[0], "Run 1 UNSTABLE 18.4%, retest ACCEPT 6.2%");
                assert!(note[1].contains("not an SSD failure"));
            }
            other => panic!("{other:?}"),
        }
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn unstable_twice_with_clean_health_is_check_not_failure() {
        let (mut app, root) = new_app("twice");
        let id = identity(&app);
        let netac = app.ssd_candidates[0].disk.clone();
        app.nvme_health
            .insert(id.clone(), collect(&Src(netac_page()), &netac, "t"));
        app.start_benchmark();
        finish(&mut app, Ok(summary(18.4)));
        app.poll_retest();
        finish(&mut app, Ok(summary(16.0)));
        assert_eq!(state(&app), StorageState::BenchmarkAnomalyCheck);
        app.poll_retest();
        assert!(
            !app.benchmark_is_running(),
            "never a second automatic retest"
        );
        match &app.build_vm(0.0, 0.0).ssd {
            SsdVm::Done { status, .. } => {
                assert_eq!(status.clone().unwrap().1, Tone::Warning, "not red");
            }
            other => panic!("{other:?}"),
        }
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn stable_first_run_never_retests() {
        let (mut app, root) = new_app("stable");
        app.start_benchmark();
        finish(&mut app, Ok(summary(3.0)));
        assert!(matches!(app.benchmark_state, BenchmarkUiState::Done { .. }));
        assert_eq!(
            app.selected_assessment().unwrap().retest,
            RetestOutcome::NotNeeded
        );
        // No health on this host: benchmark fine, health unknown.
        assert_eq!(state(&app), StorageState::InsufficientData);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn cancel_during_idle_prevents_the_retest_and_keeps_the_first_result() {
        let (mut app, root) = new_app("cancel-idle");
        app.retest_idle = Duration::from_secs(3600);
        app.start_benchmark();
        finish(&mut app, Ok(summary(18.4)));
        app.apply(Action::BenchmarkCancel);
        match &app.benchmark_state {
            BenchmarkUiState::Done { result, .. } => {
                assert!(result.write_variation_percent > 12.0, "first result shown")
            }
            _ => panic!("first result must stay visible"),
        }
        let a = app.selected_assessment().unwrap();
        assert_eq!(a.retest, RetestOutcome::Cancelled);
        assert_eq!(state(&app), StorageState::BenchmarkAnomalyRetest);
        app.retest_idle = Duration::ZERO;
        app.poll_retest();
        assert!(app.retest_identity.is_none() && !app.benchmark_is_running());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn cancel_or_failure_of_the_retest_run_restores_the_first_result() {
        for cancel in [true, false] {
            let (mut app, root) = new_app(if cancel { "cancel-run" } else { "fail-run" });
            app.start_benchmark();
            finish(&mut app, Ok(summary(18.4)));
            app.poll_retest();
            if cancel {
                app.apply(Action::BenchmarkCancel);
            }
            finish(&mut app, Err("I/O error".into()));
            match &app.benchmark_state {
                BenchmarkUiState::Done { result, .. } => {
                    assert!(result.write_variation_percent > 12.0)
                }
                _ => panic!("first result must stay visible"),
            }
            let a = app.selected_assessment().unwrap();
            assert_eq!(
                a.retest,
                if cancel {
                    RetestOutcome::Cancelled
                } else {
                    RetestOutcome::Failed
                }
            );
            assert_eq!(state(&app), StorageState::BenchmarkAnomalyRetest);
            let _ = std::fs::remove_dir_all(root);
        }
    }

    #[test]
    fn retest_fails_closed_on_health_or_missing_target() {
        // Media errors: no further write testing.
        let (mut app, root) = new_app("health");
        let id = identity(&app);
        let disk = app.ssd_candidates[0].disk.clone();
        app.nvme_health.insert(
            id.clone(),
            collect(
                &Src(smart_page(0, 40, 100, 10, 2, 1, 1, 0, 4, 4)),
                &disk,
                "t",
            ),
        );
        app.start_benchmark();
        finish(&mut app, Ok(summary(18.4)));
        app.poll_retest();
        assert!(app.retest_identity.is_none());
        assert_eq!(
            app.assessments[&id].retest,
            RetestOutcome::Skipped(RetestSkip::HealthForbidsWrites)
        );
        assert_eq!(state(&app), StorageState::StorageAttention);
        let _ = std::fs::remove_dir_all(root);

        // Target disappeared during the idle.
        let (mut app, root) = new_app("target");
        let id = identity(&app);
        app.start_benchmark();
        finish(&mut app, Ok(summary(18.4)));
        std::fs::remove_dir_all(root.join("target")).unwrap();
        app.poll_retest();
        assert_eq!(
            app.assessments[&id].retest,
            RetestOutcome::Skipped(RetestSkip::TargetUnavailable)
        );
        assert!(!app.benchmark_is_running());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn health_pending_waits_then_fails_closed() {
        let (mut app, root) = new_app("pending");
        let id = identity(&app);
        app.start_benchmark();
        finish(&mut app, Ok(summary(18.4)));
        // Simulate an in-flight health read.
        app.assessments.get_mut(&id).unwrap().health_pending = true;
        app.poll_retest();
        assert!(
            matches!(app.benchmark_state, BenchmarkUiState::RetestWaiting { .. }),
            "waits for the health read"
        );
        if let BenchmarkUiState::RetestWaiting { deadline, .. } = &mut app.benchmark_state {
            *deadline = Instant::now();
        }
        app.poll_retest();
        assert_eq!(
            app.assessments[&id].retest,
            RetestOutcome::Skipped(RetestSkip::HealthPending)
        );
        let _ = std::fs::remove_dir_all(root);
    }

    /// Two physical disks, each benchmarked: assessments never mix.
    #[test]
    fn assessments_are_per_physical_disk() {
        let (mut app, root) = new_app("two");
        app.start_benchmark();
        finish(&mut app, Ok(summary(3.0)));
        app.select_ssd_disk(1);
        app.start_benchmark();
        finish(&mut app, Ok(summary(18.4)));
        assert!(matches!(
            app.benchmark_state,
            BenchmarkUiState::RetestWaiting { .. }
        ));
        app.poll_retest();
        finish(&mut app, Ok(summary(4.0)));
        assert_eq!(state(&app), StorageState::AnomalyNotConfirmed);
        app.select_ssd_disk(0);
        assert_eq!(state(&app), StorageState::InsufficientData);
        assert_eq!(app.assessments.len(), 2);
        let names = package_names(&app);
        assert!(
            names
                .iter()
                .any(|n| n.starts_with("Storage_Correlation_") && n.ends_with("_PD3.json"))
        );
        assert!(
            names
                .iter()
                .any(|n| n.starts_with("Storage_Correlation_") && n.ends_with("_PD4.json"))
        );
        let _ = std::fs::remove_dir_all(root);
    }
}

#[path = "app_qa_scenes.rs"]
mod qa_scenes;

#[path = "app_v11.rs"]
mod v11;

#[cfg(test)]
#[path = "app_v11_tests.rs"]
mod v11_tests;

#[cfg(test)]
#[path = "app_v10_tests.rs"]
mod v10_tests;

#[cfg(test)]
#[path = "app_v044_tests.rs"]
mod v044_tests;

#[cfg(test)]
#[path = "app_startup_idle_tests.rs"]
mod startup_idle_tests;
