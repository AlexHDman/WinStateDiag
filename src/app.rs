use crate::cryptopro;
use crate::deep_checks::{self, CheckResult, DeepCheck, DeepCheckOutcome};
use crate::driver_audit::{self, AuditReport, Category, Severity};
use crate::engine::{
    self, DeepChecks, DiagnosticMode, EXPC_DEEP_FLAGS, EXPC_STEP_COUNT, EXPC_STEP_LABELS,
    EXPC_WEIGHTS, EngineEvent, HardwareEvent, HardwareViewRequest, SessionRequest, Stage,
};
use crate::i18n::{self, Language};
use crate::report_package::{
    self, EvidenceFile, SessionPackage, SharedPackage, evidence_stamp, identity_date,
};
use crate::ssd_history::{self, HistoryEntry};
use crate::storage_benchmark::{self, DiagnosticProgress, StorageDiagnosticSummary};
use crate::storage_topology::{self, DiskCandidate};
use crate::ui::capture::ReferenceMode;
use crate::ui::dashboard::{self, Controls};
use crate::ui::tokens::{CANVAS_H, CANVAS_W, color as c};
use crate::ui::vm::{
    Action, CryptoVm, DashboardVm, DeviceIcon, DiskEntryVm, DriverRow, DriversVm, JournalLine,
    MetaRow, ModuleRow, ModuleState, OperationVm, OverallVm, ResultVm, RowState, SsdVm,
    StageFinding, StageRow, StartVm, Tone,
};
use crate::ui::{self, fixture, fonts, sysinfo};
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
}

impl Default for ExpcSubStageTracker {
    fn default() -> Self {
        Self {
            status: [SubStageStatus::Pending; 14],
            internal_pct: [0; 14],
            active_index: None,
            last_message: String::new(),
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

/// Driver Audit lifecycle: a read-only audit runs in the background at
/// start-up and again inside every diagnostic session (for the report).
enum DriverAuditState {
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

fn ssd_benchmark_evidence(
    result: &StorageDiagnosticSummary,
    test_dir: &Path,
    duration_seconds: f64,
    previous: Option<&HistoryEntry>,
    disk_label: String,
) -> Vec<EvidenceFile> {
    let t = sysinfo::local_time();
    let stem = format!("SSD_Benchmark_{}", evidence_stamp(t));
    let mb = |mib: f64| mib * 1.048576;
    let mut text = String::new();
    text.push_str("WinStateDiag — SSD / NVMe benchmark\r\n");
    text.push_str(&format!("Дата: {} {}\r\n", t.date_dmy(), t.hms()));
    text.push_str(&format!("Папка теста: {}\r\n", test_dir.display()));
    text.push_str(&format!("Диск: {disk_label}\r\n"));
    text.push_str(&format!(
        "Профиль: блок {} байт, QD{}, файл {} байт, проходов {}\r\n",
        result.profile.block_size,
        result.profile.queue_depth,
        result.profile.test_file_size,
        result.profile.pass_count
    ));
    text.push_str(&format!("Длительность: {duration_seconds:.1} с\r\n"));
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
        "Стабильность: {}\r\n",
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
        "{{\"schema\":\"winstatediag.ssd_benchmark/1\",\"test_dir\":{},\"disk\":{},\"block_size\":{},\"queue_depth\":{},\"test_file_size\":{},\"pass_count\":{},\"duration_s\":{:.3},\"read_mb_s\":{:.3},\"write_mb_s\":{:.3},\"read_variation_percent\":{:.3},\"write_variation_percent\":{:.3},\"stability\":{},\"stable\":{},\"passes\":[{}]}}",
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
        overall_level == StabilityLevel::Stable,
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
    Checked(cryptopro::Detection, cryptopro::HashState),
    Rehashed(cryptopro::RehashOutcome),
}

enum BenchmarkEvent {
    Progress(DiagnosticProgress),
    Finished(Result<StorageDiagnosticSummary, String>),
}

enum BenchmarkUiState {
    Idle,
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
    /// The one cumulative report package of this running WinStateDiag.
    package: SharedPackage,
    /// Stop request of the running diagnostic (None when nothing runs).
    session_cancel: Option<Arc<AtomicBool>>,
    hardware: HardwareViewState,
    /// CryptoPro card: current state (None while a check/ReHash runs).
    crypto: Option<cryptopro::HashState>,
    crypto_detection: cryptopro::Detection,
    crypto_rx: Option<Receiver<CryptoEvent>>,
    driver_audit: DriverAuditState,
    drivers_open: bool,
    window_fitted: bool,
    /// Physical SSD/NVMe disks WinStateDiag could enumerate on this machine
    /// (v0.3.6, multi-SSD). Empty when enumeration is unavailable (e.g. any
    /// non-Windows build, or a Windows machine where the probe failed) —
    /// never a fabricated single entry.
    ssd_candidates: Vec<DiskCandidate>,
    /// Index into `ssd_candidates` currently targeted by the benchmark.
    ssd_selected: usize,
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
    /// Active UI language (v0.3.6 bilingual pass). Loaded once at startup
    /// from the portable-safe preference file next to the EXE; switching it
    /// live never rebuilds the window, only the next frame's `DashboardVm`.
    language: Language,
    /// Folder holding the portable language preference file (the EXE's
    /// folder in production; a temporary folder in tests).
    language_pref_dir: PathBuf,
    /// VISUAL_REFERENCE mode (`--visual-reference`), QA only.
    reference: Option<ReferenceMode>,
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
            package: Arc::new(Mutex::new(SessionPackage::for_exe_dir(&exe_dir()))),
            session_cancel: None,
            hardware: HardwareViewState::Idle,
            crypto: None,
            crypto_detection: cryptopro::Detection::NotInstalled,
            crypto_rx: None,
            driver_audit: DriverAuditState::Failed(String::new()),
            drivers_open: false,
            window_fitted: false,
            ssd_candidates: Vec::new(),
            ssd_selected: 0,
            ssd_results: std::collections::HashMap::new(),
            // Reading the preference is best-effort and must never block
            // startup: `i18n::load` itself falls back to `Language::Ru` on
            // any I/O error, missing file, or corrupted content.
            language: i18n::load(&exe_dir()),
            language_pref_dir: exe_dir(),
            reference: ReferenceMode::from_args(),
        };
        // Unit tests never start the (read-only) PowerShell collector.
        if app.reference.is_none() && !cfg!(test) {
            app.driver_audit = start_driver_audit();
            app.start_crypto_check();
        }
        // Physical SSD/NVMe enumeration (v0.3.6): Windows-only real probe,
        // behind the same "not in QA reference / not under test" guard as
        // the other startup collectors above. On any other target this
        // stays empty — never a fabricated single "C:" candidate.
        #[cfg(windows)]
        if app.reference.is_none() && !cfg!(test) {
            let source = storage_topology::windows_source::WindowsTopologySource;
            app.ssd_candidates = storage_topology::candidates_from(&source);
            app.ssd_selected =
                storage_topology::default_candidate_index(&app.ssd_candidates).unwrap_or(0);
            if let Some(candidate) = app.ssd_candidates.get(app.ssd_selected) {
                if let Ok(dir) = storage_topology::benchmark_target_dir(candidate) {
                    app.benchmark_path = dir.display().to_string();
                }
            }
        }
        if app.reference.is_some() {
            app.client_name = fixture::CLIENT_NAME.into();
            app.computer_name = fixture::COMPUTER_NAME.into();
            app.benchmark_path = fixture::BENCHMARK_PATH.into();
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
        matches!(self.benchmark_state, BenchmarkUiState::Running { .. })
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

    fn start_benchmark(&mut self) {
        if self.benchmark_is_running() || self.is_running() {
            return;
        }
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
            return;
        }
        // benchmark_path is still the single source of truth for where the
        // temp file goes (Action::SelectSsdDisk keeps it in sync with the
        // selected physical disk); we only read the physical identity here
        // so history stays keyed by disk, not by drive letter.
        let physical_identity = self
            .selected_ssd_candidate()
            .map(|c| storage_topology::physical_disk_identity(&c.disk));
        let path = PathBuf::from(self.benchmark_path.trim());
        let test_dir = path.clone();
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = Arc::clone(&cancel);
        let (tx, rx) = std::sync::mpsc::channel();
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
        self.benchmark_state = BenchmarkUiState::Running {
            progress: DiagnosticProgress::Preparation,
            rx,
            cancel,
            started: Instant::now(),
            test_dir,
            physical_identity,
        };
    }

    fn poll_benchmark(&mut self) {
        let mut next_state = None;
        let mut history_log: Option<String> = None;
        let mut ssd_evidence: Option<Vec<EvidenceFile>> = None;
        if let BenchmarkUiState::Running {
            progress,
            rx,
            cancel,
            started,
            test_dir,
            physical_identity,
        } = &mut self.benchmark_state
        {
            while let Ok(event) = rx.try_recv() {
                match event {
                    BenchmarkEvent::Progress(value) => *progress = value,
                    BenchmarkEvent::Finished(Ok(result)) => {
                        // Best-effort history bookkeeping: a storage or
                        // permission failure here never affects the result.
                        // v0.4.0: the persistent history is
                        // `Reports\History\` (application state); this PC's
                        // report folder of today keeps its session copy for
                        // the ZIP (restored from the ZIP first when the
                        // folder was already finalized). Comparison reads
                        // both, each run counted once.
                        let reports_root = self.reports_root.clone();
                        let history_path = report_package::lock(&self.package)
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
                        ssd_evidence = Some(ssd_benchmark_evidence(
                            &result,
                            test_dir,
                            duration_seconds,
                            previous.as_ref(),
                            disk_identity_label(physical_identity.as_deref()),
                        ));
                        // v0.3.6 §10: cache this disk's own result by its
                        // identity so selecting away and back (without a
                        // rerun) restores it instead of showing whichever
                        // disk's run happens to be the single shared state.
                        self.ssd_results.insert(
                            disk_identity.clone(),
                            (result.clone(), duration_seconds, previous.clone()),
                        );
                        next_state = Some(BenchmarkUiState::Done {
                            result,
                            duration_seconds,
                            previous,
                        });
                    }
                    BenchmarkEvent::Finished(Err(message)) => {
                        next_state = Some(if cancel.load(Ordering::Relaxed) {
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
        // The completed benchmark joins the session report automatically.
        if let Some(files) = ssd_evidence {
            let module = i18n::t(self.language).ssd_module_name;
            self.contribute_evidence(module, files);
        }
    }

    /// Adds evidence to the session package (UI-thread modules) and
    /// journals the outcome.
    fn contribute_evidence(&mut self, module: &str, files: Vec<EvidenceFile>) {
        let date = identity_date(sysinfo::local_time());
        let created = report_package::lock(&self.package).final_zip().is_none();
        let result = report_package::lock(&self.package).contribute(
            &self.client_name,
            &self.computer_name,
            &date,
            files,
        );
        match result {
            Ok(zip) => {
                if created {
                    self.report_opened = false;
                }
                let line = i18n::t(self.language)
                    .journal_module_added_fmt
                    .replace("{module}", module)
                    .replace("{path}", &display_report_path(&zip));
                push_journal(&mut self.journal, line);
            }
            Err(err) => push_journal(&mut self.journal, format!("[ERROR] {module}: {err}")),
        }
    }

    fn start_diagnostics(&mut self) {
        if self.is_running() || self.benchmark_is_running() {
            return;
        }
        let exe_dir = exe_dir();

        self.reports_root = exe_dir.join("Reports");
        let cancel = Arc::new(AtomicBool::new(false));
        self.session_cancel = Some(Arc::clone(&cancel));
        let req = SessionRequest {
            client_name: self.client_name.clone(),
            computer_name: self.computer_name.clone(),
            mode: self.mode,
            deep_checks: self.deep_checks,
            include_hardware: self.include_hardware,
            cancel,
            package: Arc::clone(&self.package),
        };

        let (tx, rx): (Sender<EngineEvent>, Receiver<EngineEvent>) = std::sync::mpsc::channel();
        std::thread::spawn(move || engine::run_session(req, tx));

        // New run: the dashboard card starts empty; the session journal
        // (full viewer / Save / Copy) keeps every earlier line.
        self.journal.clear_view();
        self.expc_tracker.reset();
        self.deep_check_results.clear();
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
                    EngineEvent::DriverAudit(result) => {
                        // Keep the earlier result if the in-session run failed.
                        match result {
                            Ok(report) => self.driver_audit = DriverAuditState::Done(report),
                            Err(err) => {
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
            || !matches!(self.hardware, HardwareViewState::Idle)
            || matches!(self.driver_audit, DriverAuditState::Running(_));
        if busy
            || matches!(
                self.state,
                RunState::Failed { .. } | RunState::Cancelled { .. }
            )
        {
            return;
        }
        let mut package = report_package::lock(&self.package);
        if !package.needs_finalize() {
            return;
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
        std::thread::spawn(move || engine::run_hardware_view(req, tx));
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

    fn start_crypto_check(&mut self) {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let det = cryptopro::detect(&cryptopro::program_files_roots());
            let runner = cryptopro::HiddenRunner {
                timeout: Duration::from_secs(120),
            };
            let state = cryptopro::check(&det, &runner);
            let _ = tx.send(CryptoEvent::Checked(det, state));
        });
        self.crypto = None;
        self.crypto_rx = Some(rx);
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
        let Some(rx) = &self.crypto_rx else {
            return;
        };
        let Ok(event) = rx.try_recv() else {
            return;
        };
        self.crypto_rx = None;
        match event {
            CryptoEvent::Checked(det, state) => {
                for line in cryptopro::journal_for(&state) {
                    push_journal(&mut self.journal, line);
                }
                self.crypto_detection = det;
                self.crypto = Some(state);
            }
            CryptoEvent::Rehashed(outcome) => {
                for line in outcome.journal {
                    push_journal(&mut self.journal, line);
                }
                self.crypto = Some(outcome.state);
            }
        }
    }

    fn crypto_vm(&self) -> CryptoVm {
        match &self.crypto {
            None => CryptoVm::Checking,
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
        match result {
            Ok(report) => {
                let d = i18n::t(self.language);
                push_journal(
                    &mut self.journal,
                    d.driver_journal_summary_fmt
                        .replace("{status}", driver_status_label(d, report.overall))
                        .replace("{problems}", &report.count(Severity::Problem).to_string())
                        .replace("{warnings}", &report.count(Severity::Warning).to_string()),
                );
                // Automatic evidence: joins the session report as soon as
                // one exists (a launch alone never creates a report folder).
                let files = driver_audit_evidence(&report);
                let offered = report_package::lock(&self.package).offer(files);
                match offered {
                    Ok(Some(zip)) => push_journal(
                        &mut self.journal,
                        i18n::t(self.language)
                            .driver_journal_added_fmt
                            .replace("{path}", &display_report_path(&zip)),
                    ),
                    Ok(None) => {}
                    Err(err) => push_journal(
                        &mut self.journal,
                        format!("[ERROR] Проверка драйверов: {err}"),
                    ),
                }
                self.driver_audit = DriverAuditState::Done(Box::new(report));
            }
            Err(err) => {
                push_journal(&mut self.journal, format!("[WARN] {err}"));
                self.driver_audit = DriverAuditState::Failed(err);
            }
        }
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
            stages.push(StageRow {
                number: i + 1,
                label: d.stage_short[i].to_string(),
                full_label,
                state,
                fraction,
                right_text: right,
                active: running && self.expc_tracker.active_index == Some(i),
                finding,
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
            BenchmarkUiState::Running {
                progress, started, ..
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
                };
                SsdVm::Running {
                    fraction,
                    status,
                    elapsed: format!("{:.1} s", started.elapsed().as_secs_f64()),
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
                SsdVm::Done {
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
            DriverAuditState::Done(report) => drivers_vm(report, d),
            DriverAuditState::Failed(msg) => DriversVm::Unavailable(msg.clone()),
        };
        DashboardVm {
            controls_enabled: !running,
            stop_enabled: self.stop_enabled(),
            crypto: self.crypto_vm(),
            computer_name: self.computer_name.clone(),
            stages,
            overall,
            operation,
            ssd,
            ssd_controls_enabled: !running && !bench_running,
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
        }
    }

    fn apply(&mut self, action: Action) {
        match action {
            Action::Start => self.start_diagnostics(),
            Action::Reset => {
                self.state = RunState::Idle;
                self.expc_tracker.reset();
                self.deep_check_results.clear();
                self.session_started = None;
                self.ring_smoothed = 0.0;
                self.deep_check_smoothed = [0.0; 14];
            }
            Action::OpenReport => self.open_final_report(&engine::open_report),
            Action::OpenFolder => self.open_final_report_folder(&engine::open_report_folder),
            Action::BenchmarkStart => self.start_benchmark(),
            Action::BenchmarkCancel => {
                if let BenchmarkUiState::Running { cancel, .. } = &self.benchmark_state {
                    cancel.store(true, Ordering::Relaxed);
                }
            }
            Action::Stop => self.request_stop(),
            Action::CryptoRehashRequest => {
                if self.crypto.as_ref().is_some_and(|s| s.rehash_available()) {
                    self.start_crypto_rehash();
                }
            }
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
        let d = i18n::t(self.language);
        egui::Window::new(d.driver_details_title)
            .open(&mut open)
            .default_size(vec2(760.0, 560.0))
            .collapsible(false)
            .show(ctx, |ui| match &self.driver_audit {
                DriverAuditState::Running(_) => {
                    ui.label(d.driver_popup_running);
                }
                DriverAuditState::Failed(msg) => {
                    ui.colored_label(c::RED_ERROR, msg);
                    rerun = ui.button(d.driver_popup_retry).clicked();
                }
                DriverAuditState::Done(report) => {
                    ui.horizontal(|ui| {
                        ui.label(
                            d.driver_popup_summary_fmt
                                .replace("{status}", driver_status_label(d, report.overall))
                                .replace("{problems}", &report.count(Severity::Problem).to_string())
                                .replace("{warnings}", &report.count(Severity::Warning).to_string())
                                .replace("{ok}", &report.count(Severity::Ok).to_string())
                                .replace("{devices}", &report.devices_scanned.to_string())
                                .replace("{days}", &report.window_days.to_string())
                                .replace("{generated}", &report.generated),
                        );
                    });
                    ui.label(egui::RichText::new(d.driver_popup_note).color(c::TEXT_MUTED));
                    rerun = ui.button(d.driver_popup_rerun).clicked();
                    ui.separator();
                    egui::ScrollArea::vertical().show(ui, |ui| {
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
                                ui.label(d.driver_popup_device_fmt.replace("{device}", &it.device));
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
                                    ui.label(egui::RichText::new(&it.pnp_id).color(c::TEXT_MUTED));
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
                        if !report.unattributed.is_empty() {
                            ui.separator();
                            ui.label(
                                egui::RichText::new(d.driver_popup_unattributed_note)
                                    .color(c::TEXT_MUTED),
                            );
                            for e in &report.unattributed {
                                ui.label(format!("• {} [{}] ×{}", e.reason, e.source, e.count));
                            }
                        }
                        if !report.errors.is_empty() {
                            ui.separator();
                            for e in &report.errors {
                                ui.colored_label(
                                    c::YELLOW_WARNING,
                                    d.driver_popup_collection_error_fmt.replace("{error}", e),
                                );
                            }
                        }
                    });
                }
            });
        self.drivers_open = open;
        if rerun && !matches!(self.driver_audit, DriverAuditState::Running(_)) {
            self.driver_audit = start_driver_audit();
        }
    }

    fn raw_passes_window(&mut self, ctx: &egui::Context) {
        if !self.raw_passes_open {
            return;
        }
        let BenchmarkUiState::Done { result, .. } = &self.benchmark_state else {
            self.raw_passes_open = false;
            return;
        };
        let mut open = self.raw_passes_open;
        let raw_passes_title = i18n::t(self.language).ssd_raw_passes_title;
        egui::Window::new(raw_passes_title)
            .open(&mut open)
            .resizable(false)
            .collapsible(false)
            .show(ctx, |ui| {
                egui::Grid::new("benchmark_raw_passes")
                    .striped(true)
                    .spacing(vec2(12.0, 6.0))
                    .show(ui, |ui| {
                        for heading in [
                            "PASS", "READ", "WRITE", "R IOPS", "W IOPS", "R LAT", "W LAT",
                            "R TIME", "W TIME",
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
            });
        self.raw_passes_open = open;
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

impl eframe::App for WinStateDiagApp {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_engine();
        self.poll_benchmark();
        self.poll_driver_audit();
        self.poll_hardware();
        self.poll_crypto();
        if self.reference.is_none() {
            self.finalize_report_if_idle();
        }
        if self.is_running()
            || self.crypto_rx.is_some()
            || matches!(self.hardware, HardwareViewState::Collecting { .. })
            || self.benchmark_is_running()
            || matches!(self.driver_audit, DriverAuditState::Running(_))
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
        let vm = if reference_mode {
            fixture::master_vm()
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
        self.raw_passes_window(&ctx);
        self.drivers_window(&ctx);
        self.journal_window(&ctx);
        self.hardware_progress_window(&ctx);
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
    fn ssd_benchmark_and_start_up_driver_audit_join_the_same_package() {
        let (mut app, exe) = app_with_exe("mods");
        // Start-up audit before any package: held, no folder created.
        let held = report_package::lock(&app.package)
            .offer(vec![EvidenceFile::new(
                "DriverAudit_24-09-26_09-00-00.json",
                b"{}".to_vec(),
            )])
            .unwrap();
        assert!(held.is_none());
        assert!(!exe.join("Reports").exists());
        app.contribute_evidence(
            "SSD benchmark",
            vec![EvidenceFile::new(
                "SSD_Benchmark_24.09.26_10-35.txt",
                b"SSD".to_vec(),
            )],
        );
        app.contribute_evidence("Hardware Report", hardware_files());
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
        assert_eq!(app.build_vm(0.0, 0.0).crypto, CryptoVm::Checking);
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
            app.apply(Action::CryptoRehashRequest);
            assert_eq!(
                app.crypto_rx.is_some(),
                starts_rehash,
                "{vm:?}: ReHash must start only from NO HASH"
            );
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
            let b = l::JOURNAL_OPEN_BUTTON;
            let at = egui::pos2(
                b[0] - CANVAS_ORIGIN_IN_MASTER[0] + b[2] / 2.0,
                b[1] - CANVAS_ORIGIN_IN_MASTER[1] + b[3] / 2.0,
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
