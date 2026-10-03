//! v0.4.1 details windows: the Driver Check summary / issue export and the
//! EXPC diagnostic results window.
//!
//! Presentation and export only. Nothing here classifies anything anew:
//! Driver Check uses the computed Driver Audit model, EXPC results use
//! EXPC's own `Checks[]` classification and the v0.4.0 deep-check results
//! (`deep_checks.rs`). Repair commands are text; nothing is executed.

use crate::deep_checks::{self, CheckResult, DeepCheck, DeepCheckOutcome, ExpcCheck};
use crate::driver_audit::{AuditReport, Evidence, Severity};
use crate::i18n::Dict;
use crate::ui::sysinfo::LocalTime;
use crate::ui::tokens::color as c;
use egui::{Color32, CornerRadius, RichText, Stroke, vec2};

// ---------------------------------------------------------------------
// Shared export helpers
// ---------------------------------------------------------------------

/// `WinStateDiag_<kind>_YYYY-MM-DD_HH-MM-SS.txt`
pub fn export_file_name(kind: &str, t: LocalTime) -> String {
    format!(
        "WinStateDiag_{kind}_{:04}-{:02}-{:02}_{:02}-{:02}-{:02}.txt",
        t.year, t.month, t.day, t.hour, t.minute, t.second
    )
}

fn push_line(out: &mut String, line: &str) {
    out.push_str(line);
    out.push_str("\r\n");
}

// ---------------------------------------------------------------------
// Driver Check
// ---------------------------------------------------------------------

/// The counters of the Driver Check summary header (actual runtime values).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DriverSummary {
    pub problems: usize,
    pub warnings: usize,
    pub ok: usize,
    pub devices: usize,
    /// Event-log occurrences behind the evidence (attributed and not).
    pub events: u64,
}

fn event_occurrences(e: &Evidence) -> u64 {
    if e.event_id.is_some() {
        u64::from(e.count.max(1))
    } else {
        0
    }
}

pub fn driver_summary(r: &AuditReport) -> DriverSummary {
    let events = r
        .items
        .iter()
        .flat_map(|i| i.evidence.iter())
        .chain(r.unattributed.iter())
        .map(event_occurrences)
        .sum();
    DriverSummary {
        problems: r.count(Severity::Problem),
        warnings: r.count(Severity::Warning),
        ok: r.count(Severity::Ok),
        devices: r.devices_scanned,
        events,
    }
}

fn or_na<'a>(v: &'a str, na: &'a str) -> &'a str {
    if v.trim().is_empty() { na } else { v }
}

/// The ONE canonical Driver Check issues text (Copy issues and Save issues
/// both use it). Problems and warnings only — OK devices are never listed.
/// CRLF line ends. `label` localizes the short dashboard label of an item.
pub fn driver_issues_text(r: &AuditReport, d: &Dict, label: &dyn Fn(&str) -> String) -> String {
    let s = driver_summary(r);
    let mut o = String::new();
    push_line(&mut o, d.driver_export_title);
    push_line(
        &mut o,
        &format!(
            "{}: {}; {}: {}; {}: {}; {}: {}; {}: {}",
            d.driver_sum_problems,
            s.problems,
            d.driver_sum_warnings,
            s.warnings,
            d.driver_sum_ok,
            s.ok,
            d.driver_sum_devices,
            s.devices,
            d.driver_sum_events,
            s.events
        ),
    );
    push_line(
        &mut o,
        &format!("{} {}", d.driver_info_tooltip, d.driver_info_tooltip_age),
    );
    let issues: Vec<_> = [Severity::Problem, Severity::Warning]
        .into_iter()
        .flat_map(|sev| r.items.iter().filter(move |i| i.status == sev))
        .collect();
    if issues.is_empty() {
        push_line(&mut o, "");
        push_line(&mut o, d.driver_issues_none);
    }
    for it in issues {
        let status = match it.status {
            Severity::Problem => d.driver_status_problem,
            Severity::Warning => d.driver_status_warning,
            Severity::Ok => d.driver_status_ok,
        };
        push_line(&mut o, "");
        push_line(
            &mut o,
            &format!(
                "[{status}] {} — {}",
                label(&it.label),
                or_na(&it.device, d.driver_na)
            ),
        );
        push_line(
            &mut o,
            &format!(
                "    {}: {}; {}: {}; {}: {}",
                d.driver_export_version,
                or_na(&it.version, d.driver_na),
                d.driver_export_date,
                or_na(&it.date, d.driver_na),
                d.driver_export_provider,
                or_na(&it.provider, d.driver_na),
            ),
        );
        push_line(
            &mut o,
            &format!(
                "    INF: {}; {}: {}",
                or_na(&it.inf, d.driver_na),
                d.driver_export_service,
                or_na(&it.service, d.driver_na),
            ),
        );
        push_line(
            &mut o,
            &format!(
                "    {}: {}",
                d.driver_export_hwid,
                or_na(&it.pnp_id, d.driver_na)
            ),
        );
        if !it.evidence.is_empty() {
            push_line(&mut o, &format!("    {}:", d.driver_export_evidence));
            for e in &it.evidence {
                push_line(&mut o, &format!("      • {}", evidence_line(e, d)));
            }
        }
    }
    if !r.unattributed.is_empty() {
        push_line(&mut o, "");
        push_line(&mut o, &format!("{}:", d.driver_export_unattributed));
        for e in &r.unattributed {
            push_line(&mut o, &format!("      • {}", evidence_line(e, d)));
        }
    }
    o
}

fn evidence_line(e: &Evidence, d: &Dict) -> String {
    let mut s = format!("{} [{}", e.reason, e.source);
    if let Some(id) = e.event_id {
        s.push_str(
            &d.driver_popup_event_fmt
                .replace("{event_id}", &id.to_string()),
        );
    }
    s.push(']');
    let mut extra = Vec::new();
    if e.event_id.is_some() || e.count > 1 {
        extra.push(format!("{}: {}", d.driver_export_count, e.count.max(1)));
    }
    if !e.last_seen.is_empty() {
        extra.push(format!("{}: {}", d.driver_export_last_seen, e.last_seen));
    }
    if !extra.is_empty() {
        s.push_str(&format!(" ({})", extra.join("; ")));
    }
    s
}

// ---------------------------------------------------------------------
// EXPC diagnostic results
// ---------------------------------------------------------------------

/// Execution state of one EXPC step (from the progress tracker).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StepProgress {
    Waiting,
    Running,
    Done,
    Skipped,
    Failed,
}

/// What the details window says about one step. Order = index into
/// `Dict::expc_state_labels`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StageState {
    Problem,
    Attention,
    Ok,
    Info,
    Skipped,
    Unknown,
    Running,
    Waiting,
    Completed,
}

impl StageState {
    pub fn index(self) -> usize {
        self as usize
    }

    /// Findings first: problems, attention, OK, then the neutral states.
    fn rank(self) -> u8 {
        match self {
            StageState::Problem => 0,
            StageState::Attention => 1,
            StageState::Ok => 2,
            StageState::Info => 3,
            StageState::Completed => 4,
            StageState::Running => 5,
            StageState::Unknown => 6,
            StageState::Skipped => 7,
            StageState::Waiting => 8,
        }
    }

    pub fn color(self) -> Color32 {
        match self {
            StageState::Problem => c::DRIVER_STATUS_PROBLEM_TEXT,
            StageState::Attention => c::YELLOW_WARNING,
            StageState::Ok => c::GREEN_SUCCESS,
            StageState::Info => c::BLUE_STATUS,
            StageState::Running => c::BLUE_STAGE,
            StageState::Completed => c::TEXT_SECONDARY,
            StageState::Skipped | StageState::Unknown | StageState::Waiting => c::TEXT_MUTED,
        }
    }
}

/// EXPC status text (as EXPC writes it) → state. Unknown text stays
/// neutral; nothing is guessed.
pub fn state_of_status(status: &str) -> StageState {
    match status.trim().to_ascii_uppercase().as_str() {
        "OK" => StageState::Ok,
        "ATTENTION" | "WARNING" | "REVIEW" => StageState::Attention,
        "ERROR" => StageState::Problem,
        "INFO" => StageState::Info,
        "SKIPPED" | "NOT TESTED" => StageState::Skipped,
        _ => StageState::Unknown,
    }
}

fn state_of_result(r: CheckResult) -> StageState {
    match r {
        CheckResult::Ok => StageState::Ok,
        CheckResult::Attention => StageState::Attention,
        CheckResult::Error => StageState::Problem,
        CheckResult::Unknown => StageState::Unknown,
        CheckResult::Skipped => StageState::Skipped,
    }
}

/// 0-based EXPC step of a `Checks[]` key (EXPC-Diagnostic.ps1
/// `Set-CheckStatus -Key` values, grouped by `Invoke-Step -Number`).
pub fn step_of_key(key: &str) -> Option<usize> {
    let k = key.trim().to_ascii_lowercase();
    let step = match k.as_str() {
        "system / pending reboot" => 1,
        "storage" => 2,
        "pnp devices" => 3,
        "system event log" | "smart card / ccid" => 4,
        "vss shadow storage" => 5,
        "whea" => 6,
        "stability / bsod" => 7,
        "applications" => 8,
        "memory diagnostic" => 9,
        "defender" => 10,
        "sfc" => 11,
        "dism" => 12,
        "chkdsk" => 13,
        "bios / drivers" => 14,
        _ => return None,
    };
    Some(step - 1)
}

#[derive(Clone, Debug, PartialEq)]
pub struct StageDetail {
    /// 1-based step number as on the dashboard (01–14).
    pub number: usize,
    pub state: StageState,
    /// Raw findings as the evidence states them (EXPC detail texts).
    pub findings: Vec<String>,
    /// SFC / DISM / CHKDSK result (v0.4.0 classification), when present.
    pub deep: Option<DeepCheckOutcome>,
    /// Completed, but EXPC has not produced its evidence yet.
    pub pending: bool,
    /// The step itself failed to run.
    pub failed: bool,
}

/// One entry per EXPC step. Only completed steps get a result, and only
/// from existing evidence: running / waiting steps never claim a finding.
pub fn build_stage_details(
    progress: &[StepProgress],
    evidence_ready: bool,
    checks: &[ExpcCheck],
    deep: &[DeepCheckOutcome],
) -> Vec<StageDetail> {
    let mut out = Vec::with_capacity(progress.len());
    for (i, p) in progress.iter().enumerate() {
        let mut d = StageDetail {
            number: i + 1,
            state: StageState::Waiting,
            findings: Vec::new(),
            deep: None,
            pending: false,
            failed: false,
        };
        match p {
            StepProgress::Waiting => {}
            StepProgress::Running => d.state = StageState::Running,
            StepProgress::Skipped => d.state = StageState::Skipped,
            StepProgress::Failed => {
                d.state = StageState::Problem;
                d.failed = true;
            }
            StepProgress::Done => {
                let deep_check = DeepCheck::of_step_index(i);
                if let Some(o) = deep_check.and_then(|k| deep.iter().find(|o| o.check == k)) {
                    d.state = state_of_result(o.result);
                    if !o.detail.is_empty() {
                        d.findings.push(o.detail.clone());
                    }
                    d.deep = Some(o.clone());
                } else {
                    let mine: Vec<&ExpcCheck> = checks
                        .iter()
                        .filter(|c| step_of_key(&c.key) == Some(i))
                        .collect();
                    if mine.is_empty() {
                        d.state = StageState::Completed;
                        d.pending = !evidence_ready;
                    } else {
                        d.state = mine
                            .iter()
                            .map(|c| state_of_status(&c.status))
                            .min_by_key(|s| s.rank())
                            .unwrap_or(StageState::Unknown);
                        for c in &mine {
                            if c.detail.is_empty() {
                                continue;
                            }
                            d.findings.push(if mine.len() > 1 {
                                format!("{}: {}", c.key, c.detail)
                            } else {
                                c.detail.clone()
                            });
                        }
                    }
                }
            }
        }
        out.push(d);
    }
    out
}

/// Findings first (problems, attention, OK, neutral), stage order within.
pub fn findings_first(details: &[StageDetail]) -> Vec<&StageDetail> {
    let mut v: Vec<&StageDetail> = details.iter().collect();
    v.sort_by_key(|d| (d.state.rank(), d.number));
    v
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExpcCounts {
    pub problems: usize,
    pub attention: usize,
    pub ok: usize,
    /// v0.4.2: EXPC "INFO" steps (e.g. 14 BIOS / drivers / firmware) are a
    /// category of their own — never folded into OK.
    pub info: usize,
    pub skipped: usize,
    /// Steps without a final result yet (waiting, running, completed
    /// without a structured result, undetermined). Shown only when > 0.
    pub other: usize,
}

impl ExpcCounts {
    /// Every represented step is in exactly one category.
    #[cfg(test)]
    pub fn total(&self) -> usize {
        self.problems + self.attention + self.ok + self.info + self.skipped + self.other
    }
}

pub fn expc_counts(details: &[StageDetail]) -> ExpcCounts {
    let n = |s: StageState| details.iter().filter(|d| d.state == s).count();
    let problems = n(StageState::Problem);
    let attention = n(StageState::Attention);
    let ok = n(StageState::Ok);
    let info = n(StageState::Info);
    let skipped = n(StageState::Skipped);
    ExpcCounts {
        problems,
        attention,
        ok,
        info,
        skipped,
        other: details.len() - problems - attention - ok - info - skipped,
    }
}

/// The summary line ("Проблем: 0; Внимание: 2; Без ошибок: 7; Инфо: 1;
/// Пропущено: 4"), shared by the window text and Copy/Save.
pub fn expc_summary_line(n: &ExpcCounts, d: &Dict) -> String {
    let mut s = format!(
        "{}: {}; {}: {}; {}: {}; {}: {}; {}: {}",
        d.expc_sum_problems,
        n.problems,
        d.expc_sum_attention,
        n.attention,
        d.expc_sum_ok,
        n.ok,
        d.expc_sum_info,
        n.info,
        d.expc_sum_skipped,
        n.skipped
    );
    if n.other > 0 {
        s.push_str(&format!("; {}: {}", d.expc_sum_other, n.other));
    }
    s
}

/// Explanation lines of one step (localized), shared by the window and the
/// Copy/Save text. The repair command is TEXT, never an action.
pub struct StageExplanation {
    pub explanation: Option<String>,
    pub suggested_command: Option<String>,
}

pub fn explain(detail: &StageDetail, d: &Dict, system_drive: &str) -> StageExplanation {
    let mut ex = StageExplanation {
        explanation: None,
        suggested_command: None,
    };
    if let Some(o) = &detail.deep {
        ex.explanation = Some(deep_checks::describe(o, &d.deep_check_findings));
        if o.result == CheckResult::Attention {
            ex.suggested_command = Some(o.check.manual_command(system_drive));
        }
    } else if detail.failed {
        ex.explanation = Some(d.expc_stage_failed.to_string());
    } else if detail.state == StageState::Completed {
        ex.explanation = Some(
            if detail.pending {
                d.expc_result_pending
            } else {
                d.expc_no_structured
            }
            .to_string(),
        );
    }
    ex
}

/// The ONE canonical EXPC results text (Copy and Save). Findings first,
/// stage numbers kept; CRLF line ends.
pub fn expc_details_text(details: &[StageDetail], d: &Dict, system_drive: &str) -> String {
    let n = expc_counts(details);
    let mut o = String::new();
    push_line(&mut o, &format!("WinStateDiag — {}", d.expc_details_title));
    push_line(
        &mut o,
        &format!("{}: {}", d.expc_details_summary, expc_summary_line(&n, d)),
    );
    for det in findings_first(details) {
        push_line(&mut o, "");
        push_line(
            &mut o,
            &format!(
                "[{}] {:02} — {}",
                d.expc_state_labels[det.state.index()],
                det.number,
                d.stage_short[det.number - 1]
            ),
        );
        let ex = explain(det, d, system_drive);
        if let Some(e) = &ex.explanation {
            push_line(&mut o, &format!("    {e}"));
        }
        for f in &det.findings {
            push_line(&mut o, &format!("    {}: {f}", d.expc_result_label));
        }
        if let Some(cmd) = &ex.suggested_command {
            push_line(&mut o, &format!("    {}: {cmd}", d.expc_suggested_action));
            push_line(&mut o, &format!("    {}", d.expc_not_executed));
        }
    }
    o
}

// ---------------------------------------------------------------------
// Widgets (WinStateDiag popup style)
// ---------------------------------------------------------------------

/// Compact counter: label + value box with a status accent.
pub fn counter_chip(
    ui: &mut egui::Ui,
    label: &str,
    value: &str,
    accent: Color32,
) -> egui::Response {
    let frame = egui::Frame::new()
        .fill(c::BG_CARD_INNER)
        .stroke(Stroke::new(1.0, accent.gamma_multiply(0.55)))
        .corner_radius(CornerRadius::same(4))
        .inner_margin(egui::Margin::symmetric(8, 4))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new(label).color(c::TEXT_SECONDARY).size(13.0));
                egui::Frame::new()
                    .fill(accent.gamma_multiply(0.14))
                    .stroke(Stroke::new(1.0, accent.gamma_multiply(0.8)))
                    .corner_radius(CornerRadius::same(3))
                    .inner_margin(egui::Margin::symmetric(7, 1))
                    .show(ui, |ui| {
                        ui.label(RichText::new(value).color(accent).strong().size(14.0));
                    });
            });
        })
        .response;
    // One hover target for the whole chip (on top of its labels), so a
    // tooltip attached to it shows wherever the chip is hovered.
    ui.interact(
        frame.rect,
        ui.id().with(("wsd_chip", label)),
        egui::Sense::hover(),
    )
}

pub fn section_title(ui: &mut egui::Ui, text: &str) {
    ui.label(RichText::new(text).color(c::TEXT_TITLE).strong().size(15.0));
}

/// Primary action (blue, larger, still compact).
pub fn primary_button(ui: &mut egui::Ui, text: &str, enabled: bool) -> egui::Response {
    ui.add_enabled(
        enabled,
        egui::Button::new(
            RichText::new(text)
                .color(Color32::WHITE)
                .strong()
                .size(15.0),
        )
        .fill(c::BLUE_PRIMARY)
        .stroke(Stroke::new(1.0, c::BLUE_BRIGHT))
        .corner_radius(CornerRadius::same(4))
        .min_size(vec2(170.0, 34.0)),
    )
}

pub fn secondary_button(ui: &mut egui::Ui, text: &str, enabled: bool) -> egui::Response {
    ui.add_enabled(
        enabled,
        egui::Button::new(RichText::new(text).color(c::TEXT_PRIMARY).size(14.0))
            .fill(c::BG_FIELD)
            .stroke(Stroke::new(1.0, c::BORDER_ACTIVE))
            .corner_radius(CornerRadius::same(4))
            .min_size(vec2(0.0, 30.0)),
    )
}

/// Dark, wrapped hover text (never a white system tooltip); one label per
/// paragraph.
pub fn dark_tooltip(resp: egui::Response, paragraphs: &[&str]) -> egui::Response {
    resp.on_hover_ui(|ui| {
        ui.set_max_width(380.0);
        for (i, p) in paragraphs.iter().enumerate() {
            if i > 0 {
                ui.add_space(6.0);
            }
            ui.add(egui::Label::new(RichText::new(*p).color(c::TEXT_BODY)).wrap());
        }
    })
}

/// Frame of a details section (card look inside a popup).
pub fn card_frame() -> egui::Frame {
    egui::Frame::new()
        .fill(c::BG_CARD)
        .stroke(Stroke::new(1.0, c::BORDER_NORMAL))
        .corner_radius(CornerRadius::same(5))
        .inner_margin(egui::Margin::same(10))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::driver_audit::{AuditItem, Category, EvidenceKind};
    use crate::i18n::{EN, RU};

    fn ev(reason: &str, sev: Severity, event_id: Option<u32>, count: u32, last: &str) -> Evidence {
        Evidence {
            kind: EvidenceKind::PnpError,
            severity: sev,
            source: "System / Kernel-PnP".into(),
            event_id,
            first_seen: String::new(),
            last_seen: last.into(),
            count,
            module: String::new(),
            module_version: String::new(),
            exception: String::new(),
            process: String::new(),
            reason: reason.into(),
        }
    }

    fn item(label: &str, device: &str, status: Severity, evidence: Vec<Evidence>) -> AuditItem {
        AuditItem {
            category: Category::Other,
            label: label.into(),
            device: device.into(),
            vendor: "Vendor".into(),
            provider: format!("{device} Provider"),
            version: "1.2.3.4".into(),
            date: "2025-01-02".into(),
            inf: "oem42.inf".into(),
            service: "svc42".into(),
            pnp_id: format!("PCI\\VEN_1234&DEV_{device}"),
            pnp_error_code: None,
            signed: Some(true),
            status,
            evidence,
        }
    }

    pub(crate) fn report() -> AuditReport {
        AuditReport {
            generated: "2026-09-30 10:11:12".into(),
            window_days: 30,
            complete: true,
            devices_scanned: 159,
            overall: Severity::Problem,
            items: vec![
                item("GoodDev", "GOOD", Severity::Ok, vec![]),
                item(
                    "BadDev",
                    "BAD",
                    Severity::Problem,
                    vec![ev(
                        "PnP error code 43",
                        Severity::Problem,
                        Some(411),
                        7,
                        "2026-09-29 08:00",
                    )],
                ),
                item(
                    "WarnDev",
                    "WARN",
                    Severity::Warning,
                    vec![ev(
                        "Driver load failure",
                        Severity::Warning,
                        Some(7026),
                        1,
                        "2026-09-28 07:00",
                    )],
                ),
            ],
            unattributed: vec![ev("Old WUDFRd event", Severity::Warning, Some(219), 3, "")],
            expected_inactive: vec![],
            errors: vec![],
        }
    }

    #[test]
    fn driver_summary_uses_the_actual_report_values() {
        let s = driver_summary(&report());
        assert_eq!(
            s,
            DriverSummary {
                problems: 1,
                warnings: 1,
                ok: 1,
                devices: 159,
                events: 7 + 1 + 3,
            }
        );
    }

    #[test]
    fn driver_issues_text_lists_problems_and_warnings_with_all_fields_only() {
        let r = report();
        for d in [&RU, &EN] {
            let t = driver_issues_text(&r, d, &|l| format!("L:{l}"));
            assert!(t.starts_with(d.driver_export_title));
            assert!(
                t.contains("\r\n") && !t.replace("\r\n", "").contains('\n'),
                "CRLF only"
            );
            assert!(t.contains(&format!("[{}] L:BadDev — BAD", d.driver_status_problem)));
            assert!(t.contains(&format!("[{}] L:WarnDev — WARN", d.driver_status_warning)));
            // Problems before warnings.
            assert!(t.find("L:BadDev").unwrap() < t.find("L:WarnDev").unwrap());
            // Never OK devices.
            assert!(!t.contains("GoodDev") && !t.contains("GOOD Provider"));
            for field in [
                "BAD Provider",
                "2025-01-02",
                "oem42.inf",
                "svc42",
                "PCI\\VEN_1234&DEV_BAD",
                "1.2.3.4",
                "PnP error code 43",
                "System / Kernel-PnP",
                "2026-09-29 08:00",
                "Old WUDFRd event",
            ] {
                assert!(t.contains(field), "{field} in {t}");
            }
            assert!(t.contains(&format!("{}: 7", d.driver_export_count)));
            assert!(t.contains(&format!("{}: 2026-09-29 08:00", d.driver_export_last_seen)));
            assert!(t.contains(d.driver_export_hwid));
            assert!(t.contains(&format!("{}: 159", d.driver_sum_devices)));
            assert!(t.contains(&format!("{}: 11", d.driver_sum_events)));
            // Summary header data only; the generation timestamp is not part
            // of the UI header (it stays in the Driver Audit evidence).
            assert!(!t.contains("10:11:12"));
        }
        let mut clean = report();
        clean.items.retain(|i| i.status == Severity::Ok);
        clean.unattributed.clear();
        let t = driver_issues_text(&clean, &RU, &|l| l.to_string());
        assert!(t.contains(RU.driver_issues_none));
        assert!(!t.contains("GoodDev"));
    }

    #[test]
    fn export_file_names_follow_the_pattern() {
        let t = LocalTime {
            year: 2026,
            month: 9,
            day: 30,
            hour: 7,
            minute: 5,
            second: 9,
        };
        assert_eq!(
            export_file_name("DriverIssues", t),
            "WinStateDiag_DriverIssues_2026-09-30_07-05-09.txt"
        );
        assert_eq!(
            export_file_name("EXPC_Results", t),
            "WinStateDiag_EXPC_Results_2026-09-30_07-05-09.txt"
        );
    }

    fn outcome_from(json: &str) -> Vec<DeepCheckOutcome> {
        deep_checks::from_expc_json(json.as_bytes())
    }

    fn chk(key: &str, status: &str, detail: &str) -> ExpcCheck {
        ExpcCheck {
            key: key.into(),
            status: status.into(),
            detail: detail.into(),
        }
    }

    fn all_done() -> Vec<StepProgress> {
        vec![StepProgress::Done; 14]
    }

    #[test]
    fn deep_check_details_follow_the_v040_classification() {
        // DISM repairable → ATTENTION, SFC clean → OK, CHKDSK findings →
        // ATTENTION, exactly as deep_checks classified the evidence.
        let deep = outcome_from(
            r#"{"Checks": [
                {"Check": "SFC", "Status": "OK", "Detail": "Windows Resource Protection did not find any integrity violations."},
                {"Check": "DISM", "Status": "ATTENTION", "Detail": "The component store is repairable."},
                {"Check": "CHKDSK", "Status": "ATTENTION", "Detail": "Windows found problems"}
            ]}"#,
        );
        let det = build_stage_details(&all_done(), true, &[], &deep);
        assert_eq!(det[10].state, StageState::Ok);
        assert_eq!(det[11].state, StageState::Attention);
        assert_eq!(det[12].state, StageState::Attention);
        assert_eq!(det[11].findings, ["The component store is repairable."]);
        let ex = explain(&det[11], &RU, "C:");
        assert_eq!(
            ex.explanation.as_deref(),
            Some("DISM: хранилище компонентов Windows требует восстановления.")
        );
        assert_eq!(
            ex.suggested_command.as_deref(),
            Some("DISM /Online /Cleanup-Image /RestoreHealth")
        );
        assert!(explain(&det[10], &RU, "C:").suggested_command.is_none());
        assert_eq!(
            explain(&det[12], &EN, "D:").suggested_command.as_deref(),
            Some("chkdsk D: /f")
        );
        // DISM "cannot be repaired" keeps its ERROR classification; SFC
        // findings are ATTENTION; CHKDSK clean is OK.
        let deep = outcome_from(
            r#"{"Checks": [
                {"Check": "SFC", "Status": "ATTENTION", "Detail": "found integrity violations"},
                {"Check": "DISM", "Status": "ERROR", "Detail": "The component store cannot be repaired."},
                {"Check": "CHKDSK", "Status": "OK", "Detail": "found no problems"}
            ]}"#,
        );
        let det = build_stage_details(&all_done(), true, &[], &deep);
        assert_eq!(det[10].state, StageState::Attention);
        assert_eq!(det[11].state, StageState::Problem);
        assert_eq!(det[12].state, StageState::Ok);
        assert!(explain(&det[11], &EN, "C:").suggested_command.is_none());
        // UNKNOWN / SKIPPED stay neutral.
        let deep = outcome_from(
            r#"{"Checks": [
                {"Check": "SFC", "Status": "UNKNOWN", "Detail": ""},
                {"Check": "DISM", "Status": "SKIPPED", "Detail": "no admin"}
            ]}"#,
        );
        let det = build_stage_details(&all_done(), true, &[], &deep);
        assert_eq!(det[10].state, StageState::Unknown);
        assert_eq!(det[11].state, StageState::Skipped);
    }

    #[test]
    fn other_stages_use_existing_expc_checks_only() {
        let checks = vec![
            chk(
                "Defender",
                "ATTENTION",
                "Microsoft Defender: отключено — RealTimeProtection",
            ),
            chk("System event log", "OK", ""),
            chk("Smart Card / CCID", "INFO", "CCID events"),
            chk("WHEA", "ERROR", "Fatal WHEA"),
            chk("Memory Diagnostic", "NOT TESTED", ""),
            chk("Something new", "ERROR", "unmapped keys are ignored"),
        ];
        let det = build_stage_details(&all_done(), true, &checks, &[]);
        assert_eq!(det[9].state, StageState::Attention);
        assert_eq!(
            det[9].findings,
            ["Microsoft Defender: отключено — RealTimeProtection"]
        );
        // Two keys of step 4: the more severe wins, both details kept.
        assert_eq!(det[3].state, StageState::Ok);
        assert_eq!(det[3].findings, ["Smart Card / CCID: CCID events"]);
        assert_eq!(det[5].state, StageState::Problem);
        assert_eq!(det[8].state, StageState::Skipped);
        // No structured result → neutral "completed", never a guess.
        assert_eq!(det[0].state, StageState::Completed);
        assert!(
            det.iter()
                .all(|d| !d.findings.iter().any(|f| f.contains("unmapped")))
        );
        let counts = expc_counts(&det);
        assert_eq!(
            counts,
            ExpcCounts {
                problems: 1,
                attention: 1,
                ok: 1,
                info: 0,
                skipped: 1,
                other: 10,
            }
        );
        // Findings first, stage numbers kept.
        let order: Vec<usize> = findings_first(&det).iter().map(|d| d.number).collect();
        assert_eq!(&order[..3], &[6, 10, 4]);
    }

    #[test]
    fn running_or_incomplete_stages_never_claim_a_final_result() {
        let mut p = vec![StepProgress::Waiting; 14];
        p[0] = StepProgress::Done;
        p[1] = StepProgress::Running;
        p[10] = StepProgress::Skipped;
        // Evidence of a previous state must not leak into running steps.
        let deep =
            outcome_from(r#"{"Checks": [{"Check": "SFC", "Status": "ERROR", "Detail": "x"}]}"#);
        let det = build_stage_details(&p, false, &[chk("Storage", "ERROR", "old")], &deep);
        assert_eq!(det[0].state, StageState::Completed);
        assert!(det[0].pending);
        assert_eq!(
            explain(&det[0], &RU, "C:").explanation.as_deref(),
            Some(RU.expc_result_pending)
        );
        assert_eq!(det[1].state, StageState::Running);
        assert!(det[1].findings.is_empty());
        assert_eq!(det[2].state, StageState::Waiting);
        assert_eq!(det[10].state, StageState::Skipped);
        assert!(det[10].deep.is_none());
        // A step that itself failed is a problem of execution.
        p[3] = StepProgress::Failed;
        let det = build_stage_details(&p, false, &[], &[]);
        assert_eq!(det[3].state, StageState::Problem);
        assert_eq!(
            explain(&det[3], &EN, "C:").explanation.as_deref(),
            Some(EN.expc_stage_failed)
        );
    }

    #[test]
    fn expc_text_uses_actual_results_and_marks_commands_as_not_executed() {
        let deep = outcome_from(
            r#"{"Checks": [{"Check": "DISM", "Status": "ATTENTION", "Detail": "The component store is repairable."}]}"#,
        );
        let checks = vec![chk("Defender", "OK", "all on")];
        let det = build_stage_details(&all_done(), true, &checks, &deep);
        for d in [&RU, &EN] {
            let t = expc_details_text(&det, d, "C:");
            assert!(t.starts_with(&format!("WinStateDiag — {}", d.expc_details_title)));
            assert!(t.contains(&format!("{}: 1", d.expc_sum_attention)));
            assert!(t.contains(&format!(
                "[{}] 12 — {}",
                d.expc_state_labels[1], d.stage_short[11]
            )));
            assert!(t.contains("The component store is repairable."));
            assert!(t.contains(&format!(
                "{}: DISM /Online /Cleanup-Image /RestoreHealth",
                d.expc_suggested_action
            )));
            assert!(t.contains(d.expc_not_executed));
            assert!(t.contains("all on"));
            // The finding comes first.
            assert!(t.find("] 12 —").unwrap() < t.find("] 10 —").unwrap());
            assert!(!t.replace("\r\n", "").contains('\n'));
        }
    }

    #[test]
    fn status_mapping_is_conservative() {
        for (s, want) in [
            ("OK", StageState::Ok),
            ("ATTENTION", StageState::Attention),
            ("REVIEW", StageState::Attention),
            ("ERROR", StageState::Problem),
            ("INFO", StageState::Info),
            ("NOT TESTED", StageState::Skipped),
            ("SKIPPED", StageState::Skipped),
            ("", StageState::Unknown),
            ("weird", StageState::Unknown),
        ] {
            assert_eq!(state_of_status(s), want, "{s}");
        }
        for (i, key) in [
            "System / Pending reboot",
            "Storage",
            "PnP devices",
            "System event log",
            "VSS Shadow Storage",
            "WHEA",
            "Stability / BSOD",
            "Applications",
            "Memory Diagnostic",
            "Defender",
            "SFC",
            "DISM",
            "CHKDSK",
            "BIOS / Drivers",
        ]
        .iter()
        .enumerate()
        {
            assert_eq!(step_of_key(key), Some(i), "{key}");
        }
    }
}

/// v0.4.2: counter semantics and the INFO category.
#[cfg(test)]
mod v042_tests {
    use super::tests::report;
    use super::*;
    use crate::i18n::{EN, RU};

    fn chk(key: &str, status: &str) -> ExpcCheck {
        ExpcCheck {
            key: key.into(),
            status: status.into(),
            detail: String::new(),
        }
    }

    /// The real v0.4.1 report: 0 problems, 2 attention, 7 OK, step 14
    /// INFO, 4 skipped — 14 steps, all accounted for.
    fn real_v041() -> Vec<StageDetail> {
        let mut p = vec![StepProgress::Done; 14];
        for i in [10, 11, 12] {
            p[i] = StepProgress::Skipped;
        }
        let checks = vec![
            chk("System / Pending reboot", "OK"),
            chk("Storage", "OK"),
            chk("PnP devices", "ATTENTION"),
            chk("System event log", "OK"),
            chk("VSS Shadow Storage", "OK"),
            chk("WHEA", "OK"),
            chk("Stability / BSOD", "ATTENTION"),
            chk("Applications", "OK"),
            chk("Memory Diagnostic", "NOT TESTED"),
            chk("Defender", "OK"),
            chk("BIOS / Drivers", "INFO"),
        ];
        build_stage_details(&p, true, &checks, &[])
    }

    #[test]
    fn info_is_counted_separately_and_every_step_is_accounted_for() {
        let det = real_v041();
        assert_eq!(det[13].state, StageState::Info, "INFO is not OK");
        let n = expc_counts(&det);
        assert_eq!(
            n,
            ExpcCounts {
                problems: 0,
                attention: 2,
                ok: 7,
                info: 1,
                skipped: 4,
                other: 0
            }
        );
        assert_eq!(n.total(), 14);
        assert_eq!(n.total(), det.len());
        assert_eq!(
            expc_summary_line(&n, &RU),
            "Проблем: 0; Внимание: 2; Без ошибок: 7; Инфо: 1; Пропущено: 4"
        );
        assert_eq!(
            expc_summary_line(&n, &EN),
            "Problems: 0; Attention: 2; No errors: 7; Info: 1; Skipped: 4"
        );
        let t = expc_details_text(&det, &RU, "C:");
        assert!(t.contains("Результат диагностики: Проблем: 0; Внимание: 2; Без ошибок: 7; Инфо: 1; Пропущено: 4\r\n"));
        assert!(t.contains("[ИНФО] 14 — "));
    }

    #[test]
    fn steps_without_a_final_result_are_still_accounted_for() {
        let mut p = vec![StepProgress::Waiting; 14];
        p[0] = StepProgress::Done;
        p[1] = StepProgress::Running;
        let det = build_stage_details(&p, false, &[], &[]);
        let n = expc_counts(&det);
        assert_eq!(n.other, 14);
        assert_eq!(n.total(), 14);
        assert!(expc_summary_line(&n, &EN).ends_with("; No result yet: 14"));
        // Any mix sums to the number of represented steps.
        for k in 0..14 {
            let mut p = vec![StepProgress::Done; 14];
            p[k] = StepProgress::Failed;
            let det = build_stage_details(&p, true, &[chk("Storage", "INFO")], &[]);
            assert_eq!(expc_counts(&det).total(), 14);
        }
    }

    #[test]
    fn checked_ok_counter_counts_audited_items_without_findings_only() {
        let r = report();
        let s = driver_summary(&r);
        // It is NOT "devices minus problems minus warnings": it counts the
        // audited driver items (relevant categories plus anything with
        // evidence) whose status is OK.
        let audited_ok = r.items.iter().filter(|i| i.status == Severity::Ok).count();
        assert_eq!(s.ok, audited_ok);
        assert_eq!(s.ok, 1);
        assert_ne!(s.devices, s.problems + s.warnings + s.ok);
        assert_eq!(s.problems + s.warnings + s.ok, r.items.len());
        // Unchanged counters and event math.
        assert_eq!(
            (s.problems, s.warnings, s.devices, s.events),
            (1, 1, 159, 11)
        );
        assert_eq!(RU.driver_sum_ok, "Проверено без замечаний");
        assert_eq!(EN.driver_sum_ok, "Checked OK");
        let t = driver_issues_text(&r, &EN, &|l| l.to_string());
        assert!(t.contains("Checked OK: 1; Devices: 159; Total events: 11"));
    }
}
