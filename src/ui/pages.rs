//! v0.4.4 two-page UI: page tabs and the new cards (EXPC stage table,
//! Group Policy / ADMX, compact journal, system state, sensors, SMART/NVMe,
//! crash-dump analyzer). Provisional visual master: function first.

use super::paint::{self, ButtonIcon, ButtonKind};
use super::tokens::{color as c, layout as l, mrect, typography as t};
use super::vm::{Action, DashboardVm, InfoRow, Page, RowState, Tone};
use crate::details::StageState;
use crate::i18n;
use egui::{Align, Color32, CornerRadius, Painter, Pos2, Rect, Stroke, StrokeKind, Ui, vec2};

fn r(o: Pos2, v: l::R) -> Rect {
    mrect(o, v[0], v[1], v[2], v[3])
}

/// Card shell + title; returns the card rect.
fn card(p: &Painter, o: Pos2, v: l::R, title: &str) -> Rect {
    let rect = r(o, v);
    paint::card(p, rect);
    paint::text_clipped(
        p,
        rect.left() + 21.0,
        rect.top() + 26.0,
        rect.width() - 42.0,
        title,
        t::CARD_TITLE,
        c::TEXT_TITLE,
    );
    rect
}

pub fn tone_color(tone: Tone) -> Color32 {
    match tone {
        Tone::Idle => c::TEXT_PRIMARY,
        Tone::Running => c::BLUE_STATUS,
        Tone::Success => c::GREEN_SUCCESS,
        Tone::Warning => c::YELLOW_WARNING,
        Tone::Error => c::RED_ERROR,
    }
}

fn info_rows(
    p: &Painter,
    rows: &[InfoRow],
    x: f32,
    first_baseline: f32,
    pitch: f32,
    label_w: f32,
    right: f32,
) {
    for (i, row) in rows.iter().enumerate() {
        let b = first_baseline + i as f32 * pitch;
        paint::text_clipped(
            p,
            x,
            b,
            label_w - 8.0,
            &row.label,
            t::CAPTION,
            c::TEXT_SECONDARY,
        );
        let col = if row.tone == Tone::Idle {
            c::TEXT_BODY
        } else {
            tone_color(row.tone)
        };
        paint::text_clipped(
            p,
            x + label_w,
            b,
            right - x - label_w,
            &row.value,
            t::CAPTION,
            col,
        );
    }
}

// ---------------------------------------------------------------------
// Header: page tabs (purple = page navigation identity only)
// ---------------------------------------------------------------------

/// v1.0 compact page tabs: each tab is as wide as its label (+ padding,
/// never below `PAGE_TAB_MIN_W`), the pair centred under the Start button.
/// Width comes from the label length (caps at the tab font average ~9.6 px
/// per glyph) so the geometry is deterministic and testable.
pub fn page_tab_rects(o: Pos2, d: &i18n::Dict) -> [Rect; 2] {
    let w = |label: &str| {
        (label.chars().count() as f32 * 9.6 + 2.0 * l::PAGE_TAB_PAD_X).max(l::PAGE_TAB_MIN_W)
    };
    let (wd, wh) = (w(d.page_diagnostics), w(d.page_hardware));
    let start = r(o, l::START_BUTTON);
    let x0 = start.center().x - (wd + l::PAGE_TAB_GAP + wh) / 2.0;
    let y = mrect(o, 0.0, l::PAGE_TAB_Y, 1.0, 1.0).top();
    [
        Rect::from_min_size(egui::pos2(x0, y), vec2(wd, l::PAGE_TAB_H)),
        Rect::from_min_size(
            egui::pos2(x0 + wd + l::PAGE_TAB_GAP, y),
            vec2(wh, l::PAGE_TAB_H),
        ),
    ]
}

pub fn draw_tabs(ui: &mut Ui, o: Pos2, vm: &DashboardVm, actions: &mut Vec<Action>) {
    let d = i18n::t(vm.lang);
    let rects = page_tab_rects(o, d);
    for (page, rect, label, id) in [
        (Page::Diagnostics, rects[0], d.page_diagnostics, "page_diag"),
        (Page::Hardware, rects[1], d.page_hardware, "page_hw"),
    ] {
        let active = vm.page == page;
        let resp = ui.interact(rect, ui.id().with(id), egui::Sense::click());
        let p = ui.painter();
        if active {
            // Bright violet: soft two-step outer glow + clear border.
            for (grow, alpha) in [(5.0, 0.12), (2.5, 0.28)] {
                p.rect_filled(
                    rect.expand(grow),
                    CornerRadius::same(8),
                    c::PAGE_TAB_ACTIVE_GLOW.gamma_multiply(alpha),
                );
            }
            p.rect(
                rect,
                CornerRadius::same(6),
                c::PAGE_TAB_ACTIVE_FILL,
                Stroke::new(1.5, c::PAGE_TAB_ACTIVE_BORDER),
                StrokeKind::Inside,
            );
        } else {
            // Very dark muted violet, almost background; subtle border.
            let border = if resp.hovered() {
                c::PAGE_TAB_ACTIVE_GLOW
            } else {
                c::PAGE_TAB_INACTIVE_BORDER
            };
            p.rect(
                rect,
                CornerRadius::same(6),
                c::PAGE_TAB_INACTIVE_FILL,
                Stroke::new(1.0, border),
                StrokeKind::Inside,
            );
        }
        paint::text(
            p,
            rect.center().x,
            rect.center().y + 5.0,
            Align::Center,
            label,
            t::BUTTON_TEXT_SMALL,
            if active {
                c::PAGE_TAB_ACTIVE_TEXT
            } else {
                c::PAGE_TAB_INACTIVE_TEXT
            },
        );
        if resp.clicked() && !active {
            actions.push(Action::SetPage(page));
        }
    }
}

// ---------------------------------------------------------------------
// Diagnostics page
// ---------------------------------------------------------------------

fn stage_state_tone(s: StageState) -> Color32 {
    s.color()
}

/// v1.0: EXPC diagnostics are ACTUALLY running — the session can be
/// stopped and one stage row is running right now. Waiting, completed,
/// stopped or failed sessions never show the active focus.
pub fn expc_active(vm: &DashboardVm) -> bool {
    vm.stop_enabled && vm.stages.iter().any(|r| r.state == RowState::Running)
}

/// Breathing factor 0..1 of the EXPC focus glow (static 0.5 when frozen).
pub fn expc_glow_phase(vm: &DashboardVm) -> f32 {
    if !vm.animate {
        return 0.5;
    }
    let x = (vm.time / c::EXPC_GLOW_PERIOD * std::f64::consts::TAU).sin();
    (0.5 + 0.5 * x) as f32
}

/// The 14 EXPC stages as a table: №, stage, execution, result, finding,
/// duration, Details.
pub fn draw_stages_table(ui: &mut Ui, o: Pos2, vm: &DashboardVm, actions: &mut Vec<Action>) {
    let d = i18n::t(vm.lang);
    let p = ui.painter().clone();
    let active_focus = expc_active(vm);
    let card_rect = r(o, l::STAGE_TABLE_CARD);
    if active_focus {
        // Soft violet outer glow, calmly breathing (drawn under the card).
        let k = expc_glow_phase(vm);
        for (grow, alpha) in [(9.0_f32, 0.05_f32), (6.0, 0.08), (3.0, 0.14)] {
            p.rect_filled(
                card_rect.expand(grow),
                CornerRadius::same(l::CARD_RADIUS + grow as u8),
                c::EXPC_ACTIVE_GLOW.gamma_multiply(alpha * (0.55 + 0.45 * k)),
            );
        }
    }
    let rect = card(&p, o, l::STAGE_TABLE_CARD, d.stages_table_title);
    if active_focus {
        p.rect_stroke(
            rect,
            CornerRadius::same(l::CARD_RADIUS),
            Stroke::new(1.0, c::EXPC_ACTIVE_BORDER),
            StrokeKind::Inside,
        );
    }
    if paint::button(
        ui,
        mrect(
            o,
            l::STAGE_TABLE_DETAILS_BUTTON[0],
            l::STAGE_TABLE_DETAILS_BUTTON[1],
            l::STAGE_TABLE_DETAILS_BUTTON[2],
            l::STAGE_TABLE_DETAILS_BUTTON[3],
        ),
        "expc_details",
        d.expc_details_button,
        ButtonKind::Secondary,
        true,
        ButtonIcon::None,
        t::BUTTON_TEXT_SMALL,
    )
    .clicked()
    {
        actions.push(Action::ShowExpcDetails);
    }
    let x0 = rect.left() + 16.0;
    let cols = [
        x0,
        x0 + 34.0,
        x0 + 246.0,
        x0 + 356.0,
        x0 + 456.0,
        x0 + 606.0,
    ];
    let head_b = rect.top() + 58.0;
    for (x, h) in cols.iter().zip([
        "№",
        d.stages_col_stage,
        d.stages_col_exec,
        d.stages_col_result,
        d.stages_col_finding,
        d.stages_col_time,
    ]) {
        paint::text(&p, *x, head_b, Align::Min, h, t::CAPTION, c::TEXT_MUTED);
    }
    p.line_segment(
        [
            egui::pos2(x0, head_b + 8.0),
            egui::pos2(rect.right() - 16.0, head_b + 8.0),
        ],
        Stroke::new(1.0, c::BORDER_INNER),
    );
    let pitch = 44.0;
    let top = head_b + 12.0;
    for (i, row) in vm.stages.iter().enumerate().take(14) {
        let row_rect = Rect::from_min_size(
            egui::pos2(x0 - 6.0, top + i as f32 * pitch),
            vec2(rect.width() - 20.0, pitch - 4.0),
        );
        let fill = if row.active && active_focus {
            c::EXPC_ACTIVE_ROW
        } else if row.active {
            c::BG_ROW_ACTIVE
        } else if i % 2 == 0 {
            c::BG_ROW
        } else {
            c::BG_CARD_INNER
        };
        p.rect_filled(row_rect, CornerRadius::same(4), fill);
        if row.active && active_focus {
            // Thin violet accent on the current row's left edge.
            p.rect_filled(
                Rect::from_min_size(row_rect.min, vec2(3.0, row_rect.height())),
                CornerRadius::same(2),
                c::EXPC_ACTIVE_ROW_ACCENT,
            );
        }
        let b = row_rect.center().y + 5.0;
        paint::text(
            &p,
            cols[0],
            b,
            Align::Min,
            &format!("{:02}", row.number),
            t::STAGE_LABEL,
            c::TEXT_SECONDARY,
        );
        paint::text_clipped(
            &p,
            cols[1],
            b,
            cols[2] - cols[1] - 10.0,
            &row.label,
            t::STAGE_LABEL,
            c::TEXT_BODY,
        );
        // Execution: state + progress for running steps.
        let (exec, exec_col) = match row.state {
            RowState::Running => (
                if row.right_text.is_empty() {
                    "…".to_string()
                } else {
                    row.right_text.clone()
                },
                c::BLUE_STAGE,
            ),
            RowState::Done => (row.right_text.clone(), c::GREEN_PROGRESS),
            RowState::Error => (row.right_text.clone(), c::RED_ERROR),
            _ => (row.right_text.clone(), c::TEXT_MUTED),
        };
        if row.state == RowState::Running {
            let bar = Rect::from_min_size(
                egui::pos2(cols[2], row_rect.center().y + 9.0),
                vec2(110.0, 4.0),
            );
            paint::progress_bar(&p, bar, paint::BAR_STAGE, row.fraction, c::BLUE_STAGE, None);
        }
        paint::text_clipped(
            &p,
            cols[2],
            b - 2.0,
            cols[3] - cols[2] - 10.0,
            &exec,
            t::CAPTION,
            exec_col,
        );
        if let Some(res) = row.result {
            paint::text_clipped(
                &p,
                cols[3],
                b,
                cols[4] - cols[3] - 8.0,
                &row.result_text,
                t::CAPTION,
                stage_state_tone(res),
            );
        } else {
            paint::text(&p, cols[3], b, Align::Min, "—", t::CAPTION, c::TEXT_MUTED);
        }
        paint::text_clipped(
            &p,
            cols[4],
            b,
            cols[5] - cols[4] - 10.0,
            if row.short_finding.is_empty() {
                "—"
            } else {
                &row.short_finding
            },
            t::CAPTION,
            if row.short_finding.is_empty() {
                c::TEXT_MUTED
            } else {
                c::TEXT_BODY
            },
        );
        paint::text(
            &p,
            cols[5],
            b,
            Align::Min,
            if row.duration.is_empty() {
                "—"
            } else {
                &row.duration
            },
            t::CAPTION,
            c::TEXT_SECONDARY,
        );
        let btn = Rect::from_min_size(
            egui::pos2(rect.right() - 92.0, row_rect.top() + 6.0),
            vec2(72.0, pitch - 16.0),
        );
        let enabled = row.result.is_some();
        if paint::button(
            ui,
            btn,
            &format!("stage_details_{i}"),
            d.stage_details_short,
            ButtonKind::Secondary,
            enabled,
            ButtonIcon::None,
            t::BUTTON_TEXT_SMALL,
        )
        .on_hover_text(&row.full_label)
        .clicked()
        {
            // v0.4.5: the row opens ONLY its own stage; the header button
            // keeps the global summary.
            actions.push(Action::ShowStageDetails(row.number.saturating_sub(1)));
        }
    }
}

/// v1.0 compact "КОМПЬЮТЕР" passport: Windows, CPU, RAM and motherboard
/// only (disks live on the Hardware page; no technical metadata).
pub fn draw_passport(ui: &mut Ui, o: Pos2, vm: &DashboardVm) {
    let d = i18n::t(vm.lang);
    let p = ui.painter().clone();
    let rect = card(&p, o, l::PASSPORT_CARD, d.passport_title);
    let x = rect.left() + 21.0;
    let rows: Vec<InfoRow> = if vm.passport.is_empty() {
        [
            d.passport_windows,
            d.passport_cpu,
            d.passport_ram,
            d.passport_board,
            d.passport_bios,
        ]
        .into_iter()
        .map(|label| InfoRow::new(label, d.passport_collecting, Tone::Idle))
        .collect()
    } else {
        vm.passport.clone()
    };
    for (i, row) in rows.iter().take(5).enumerate() {
        let b = rect.top() + 56.0 + i as f32 * 21.0;
        paint::text_clipped(&p, x, b, 100.0, &row.label, t::CAPTION, c::TEXT_SECONDARY);
        paint::text_clipped(
            &p,
            x + 104.0,
            b,
            rect.right() - x - 104.0 - 16.0,
            &row.value,
            t::CAPTION,
            if row.value.is_empty() {
                c::TEXT_MUTED
            } else {
                c::TEXT_BODY
            },
        );
    }
}

/// v1.0 Group Policy / ADMX: a very small secondary card — title with
/// [Проверить] [Детали], one status line (central + local store result).
pub fn draw_gpo_compact(ui: &mut Ui, o: Pos2, vm: &DashboardVm, actions: &mut Vec<Action>) {
    let d = i18n::t(vm.lang);
    let p = ui.painter().clone();
    let rect = r(o, l::GPO_COMPACT_CARD);
    paint::card(&p, rect);
    let x = rect.left() + 21.0;
    paint::text(
        &p,
        x,
        rect.top() + 22.0,
        Align::Min,
        d.gpo_row_label,
        t::CAPTION,
        c::TEXT_TITLE,
    );
    let btn_details = Rect::from_min_size(
        egui::pos2(rect.right() - 92.0, rect.top() + 7.0),
        vec2(76.0, 24.0),
    );
    let btn_check = Rect::from_min_size(
        egui::pos2(btn_details.left() - 90.0, rect.top() + 7.0),
        vec2(84.0, 24.0),
    );
    paint::text_clipped(
        &p,
        x,
        rect.top() + 45.0,
        rect.width() - 42.0,
        &vm.gpo.status,
        t::CAPTION,
        tone_color(vm.gpo.tone),
    );
    if paint::button(
        ui,
        btn_check,
        "gpo_check",
        d.gpo_check_button,
        ButtonKind::Secondary,
        !vm.gpo.busy,
        ButtonIcon::None,
        t::BUTTON_TEXT_SMALL,
    )
    .clicked()
    {
        actions.push(Action::RunGpoCheck);
    }
    if paint::button(
        ui,
        btn_details,
        "gpo_details",
        d.stage_details_short,
        ButtonKind::Secondary,
        vm.gpo.has_result,
        ButtonIcon::None,
        t::BUTTON_TEXT_SMALL,
    )
    .clicked()
    {
        actions.push(Action::ShowGpoDetails);
    }
}

#[allow(dead_code)]
/// v0.4.5 compact report action row (replaces the large Result card):
/// status + path on the left, [Открыть отчёт] [Папка] on the right.
pub fn draw_report_row(ui: &mut Ui, o: Pos2, vm: &DashboardVm, actions: &mut Vec<Action>) {
    use super::vm::ResultVm;
    let d = i18n::t(vm.lang);
    let p = ui.painter().clone();
    let rect = r(o, l::REPORT_ROW_CARD);
    paint::card(&p, rect);
    let icon = Rect::from_center_size(
        egui::pos2(rect.left() + 30.0, rect.center().y),
        vec2(18.0, 24.0),
    );
    let folder = Rect::from_min_size(
        egui::pos2(rect.right() - 98.0, rect.top() + 10.0),
        vec2(84.0, 30.0),
    );
    let open = Rect::from_min_size(
        egui::pos2(folder.left() - 142.0, rect.top() + 10.0),
        vec2(134.0, 30.0),
    );
    let x = rect.left() + 52.0;
    let w = open.left() - x - 10.0;
    let (icon_col, headline, head_col, sub, done) = match &vm.result {
        ResultVm::Idle => (
            c::TEXT_MUTED,
            d.result_idle.to_string(),
            c::TEXT_PRIMARY,
            String::new(),
            false,
        ),
        ResultVm::Running => (
            c::BLUE_ACCENT,
            d.result_running.to_string(),
            c::TEXT_PRIMARY,
            String::new(),
            false,
        ),
        ResultVm::Done { path_display, .. } => (
            c::GREEN_SUCCESS,
            d.result_ready.to_string(),
            c::GREEN_SUCCESS,
            path_display.clone(),
            true,
        ),
        ResultVm::Failed { message } => (
            c::RED_ERROR,
            d.result_failed.to_string(),
            c::RED_ERROR,
            message.lines().next().unwrap_or_default().to_string(),
            false,
        ),
    };
    paint::icon_document(&p, icon, icon_col);
    if sub.is_empty() {
        paint::text_clipped(
            &p,
            x,
            rect.center().y + 5.0,
            w,
            &headline,
            t::BODY,
            head_col,
        );
    } else {
        paint::text_clipped(&p, x, rect.top() + 21.0, w, &headline, t::CAPTION, head_col);
        paint::text_clipped(
            &p,
            x,
            rect.top() + 39.0,
            w,
            &sub,
            t::SSD_NOTE,
            c::TEXT_SECONDARY,
        );
    }
    let attention = matches!(
        &vm.result,
        ResultVm::Done {
            attention: true,
            ..
        }
    );
    let open_resp = paint::button(
        ui,
        open,
        "open_report",
        d.report_row_open,
        ButtonKind::Secondary,
        done,
        ButtonIcon::None,
        t::BUTTON_TEXT_SMALL,
    );
    if attention && vm.animate && !open_resp.hovered() {
        p.rect_stroke(
            open,
            CornerRadius::same(l::BUTTON_RADIUS),
            Stroke::new(
                1.0,
                paint::intensity(
                    c::ATTENTION_REPORT,
                    super::dashboard::running_stage_intensity(vm.time, vm.animate),
                ),
            ),
            StrokeKind::Inside,
        );
    }
    if open_resp.clicked() {
        actions.push(Action::OpenReport);
    }
    if paint::button(
        ui,
        folder,
        "open_folder",
        d.report_row_folder,
        ButtonKind::Secondary,
        done,
        ButtonIcon::None,
        t::BUTTON_TEXT_SMALL,
    )
    .clicked()
    {
        actions.push(Action::OpenFolder);
    }
}

pub fn draw_journal_compact(ui: &mut Ui, o: Pos2, vm: &DashboardVm, actions: &mut Vec<Action>) {
    let d = i18n::t(vm.lang);
    let p = ui.painter().clone();
    let rect = card(&p, o, l::JOURNAL_COMPACT_CARD, d.journal_title);
    if paint::button(
        ui,
        mrect(
            o,
            l::JOURNAL_COMPACT_OPEN_BUTTON[0],
            l::JOURNAL_COMPACT_OPEN_BUTTON[1],
            l::JOURNAL_COMPACT_OPEN_BUTTON[2],
            l::JOURNAL_COMPACT_OPEN_BUTTON[3],
        ),
        "journal_compact_open",
        d.journal_open_button,
        ButtonKind::Secondary,
        true,
        ButtonIcon::None,
        t::BUTTON_TEXT_SMALL,
    )
    .clicked()
    {
        actions.push(Action::OpenJournal);
    }
    // v1.0: report actions in the journal header (the idle report block is
    // gone). Enabled once the report exists; the attention glow stays.
    let done = matches!(&vm.result, super::vm::ResultVm::Done { .. });
    let attention = matches!(
        &vm.result,
        super::vm::ResultVm::Done {
            attention: true,
            ..
        }
    );
    let br = l::JOURNAL_COMPACT_REPORT_BUTTON;
    let report_rect = mrect(o, br[0], br[1], br[2], br[3]);
    let report = paint::button(
        ui,
        report_rect,
        "open_report",
        d.journal_report_button,
        ButtonKind::Secondary,
        done,
        ButtonIcon::None,
        t::BUTTON_TEXT_SMALL,
    );
    if attention && vm.animate && !report.hovered() {
        p.rect_stroke(
            report_rect,
            CornerRadius::same(l::BUTTON_RADIUS),
            Stroke::new(
                1.0,
                paint::intensity(
                    c::ATTENTION_REPORT,
                    super::dashboard::running_stage_intensity(vm.time, vm.animate),
                ),
            ),
            StrokeKind::Inside,
        );
    }
    if report.clicked() {
        actions.push(Action::OpenReport);
    }
    let bf = l::JOURNAL_COMPACT_FOLDER_BUTTON;
    if paint::button(
        ui,
        mrect(o, bf[0], bf[1], bf[2], bf[3]),
        "open_folder",
        d.report_row_folder,
        ButtonKind::Secondary,
        done,
        ButtonIcon::None,
        t::BUTTON_TEXT_SMALL,
    )
    .clicked()
    {
        actions.push(Action::OpenFolder);
    }
    // Clear empties the dashboard view only (never the session journal).
    if paint::button(
        ui,
        mrect(
            o,
            l::JOURNAL_COMPACT_CLEAR_BUTTON[0],
            l::JOURNAL_COMPACT_CLEAR_BUTTON[1],
            l::JOURNAL_COMPACT_CLEAR_BUTTON[2],
            l::JOURNAL_COMPACT_CLEAR_BUTTON[3],
        ),
        "journal_compact_clear",
        d.journal_clear_button,
        ButtonKind::Secondary,
        !vm.journal.is_empty(),
        ButtonIcon::None,
        t::BUTTON_TEXT_SMALL,
    )
    .clicked()
    {
        actions.push(Action::ClearLog);
    }
    let panel = Rect::from_min_max(
        egui::pos2(rect.left() + 12.0, rect.top() + 42.0),
        egui::pos2(rect.right() - 12.0, rect.bottom() - 10.0),
    );
    p.rect(
        panel,
        CornerRadius::same(4),
        c::BG_JOURNAL,
        Stroke::new(1.0, c::BORDER_JOURNAL),
        StrokeKind::Inside,
    );
    let pitch = 18.0;
    let fit = ((panel.height() - 8.0) / pitch).floor() as usize;
    let start = vm.journal.len().saturating_sub(fit);
    for (i, line) in vm.journal[start..].iter().enumerate() {
        let b = panel.top() + 17.0 + i as f32 * pitch;
        paint::text(
            &p,
            panel.left() + 8.0,
            b,
            Align::Min,
            &line.timestamp,
            t::CAPTION,
            c::TEXT_MUTED,
        );
        paint::text_clipped(
            &p,
            panel.left() + 76.0,
            b,
            panel.width() - 86.0,
            &line.message,
            t::CAPTION,
            if line.dim {
                c::TEXT_MUTED
            } else {
                c::TEXT_BODY
            },
        );
    }
}

// ---------------------------------------------------------------------
// Hardware page
// ---------------------------------------------------------------------

pub fn draw_system_state(ui: &mut Ui, o: Pos2, vm: &DashboardVm) {
    let d = i18n::t(vm.lang);
    let p = ui.painter().clone();
    let rect = card(&p, o, l::SYSTEM_STATE_CARD, d.system_state_title);
    let x = rect.left() + 21.0;
    info_rows(
        &p,
        &[
            vm.system_state.hardware.clone(),
            vm.system_state.system.clone(),
        ],
        x,
        rect.top() + 54.0,
        21.0,
        130.0,
        rect.right() - 16.0,
    );
    paint::text_clipped(
        &p,
        x,
        rect.bottom() - 8.0,
        rect.width() - 42.0,
        &vm.system_state.note,
        t::SSD_NOTE,
        c::TEXT_MUTED,
    );
}

/// v1.0 SENSOR card: "ДАТЧИКИ  T°C / Volt / Watt" on one line, the main
/// 4-column matrix (Наименование | T°C | Volt | Watt) on the left with every
/// expected row visible, and the thin-framed "Эталон" reference table on the
/// right. No dots / checkmarks: only the number is coloured. Provider and
/// debug states live in Details.
pub fn draw_sensors(ui: &mut Ui, o: Pos2, vm: &DashboardVm, actions: &mut Vec<Action>) {
    use super::vm::SensorCell;
    let d = i18n::t(vm.lang);
    let p = ui.painter().clone();
    let rect = r(o, l::POWER_CARD);
    paint::card(&p, rect);
    // "ДАТЧИКИ" + "T°C / Volt / Watt" on one baseline (same cyan family,
    // ~24 % smaller, dimmer).
    let title_b = rect.top() + 26.0;
    let tr = paint::text(
        &p,
        rect.left() + 21.0,
        title_b,
        Align::Min,
        d.sensors_title,
        t::CARD_TITLE,
        c::TEXT_TITLE,
    );
    let units_style = t::TextStyle {
        size: t::CARD_TITLE.size * 0.76,
        ..t::CARD_TITLE
    };
    paint::text(
        &p,
        tr.right() + 10.0,
        title_b,
        Align::Min,
        d.sensors_header_units,
        units_style,
        c::TEXT_TITLE.gamma_multiply(0.62),
    );
    let sv = &vm.sensors;
    let btn_refresh = Rect::from_min_size(
        egui::pos2(rect.right() - 196.0, rect.top() + 8.0),
        vec2(96.0, 26.0),
    );
    let btn_details = Rect::from_min_size(
        egui::pos2(rect.right() - 92.0, rect.top() + 8.0),
        vec2(76.0, 26.0),
    );
    if paint::button(
        ui,
        btn_refresh,
        "sensors_refresh",
        d.sensors_refresh,
        ButtonKind::Secondary,
        !sv.busy,
        ButtonIcon::None,
        t::BUTTON_TEXT_SMALL,
    )
    .clicked()
    {
        actions.push(Action::RefreshSensors);
    }
    if paint::button(
        ui,
        btn_details,
        "sensors_details",
        d.sensors_details,
        ButtonKind::Secondary,
        sv.has_data,
        ButtonIcon::None,
        t::BUTTON_TEXT_SMALL,
    )
    .clicked()
    {
        actions.push(Action::ShowSensorDetails);
    }
    let geo = SensorMatrixGeometry::new(rect);
    let x0 = geo.name_x;
    if sv.matrix.is_empty() {
        let (text, tone) = if sv.busy {
            (d.sensors_reading, Tone::Running)
        } else {
            (sv.power_state.as_str(), Tone::Idle)
        };
        paint::text_clipped(
            &p,
            x0,
            rect.top() + 66.0,
            rect.width() - 42.0,
            text,
            t::BODY_STRONG,
            tone_color(tone),
        );
    } else {
        // Column headers.
        let head_b = rect.top() + 62.0;
        paint::text(
            &p,
            x0,
            head_b,
            Align::Min,
            d.sensors_col_name,
            t::SSD_NOTE,
            c::TEXT_MUTED,
        );
        for (x, h) in [
            (geo.temp_r, "T°C"),
            (geo.volt_r, "Volt"),
            (geo.watt_r, "Watt"),
        ] {
            paint::text(&p, x, head_b, Align::Max, h, t::SSD_NOTE, c::TEXT_MUTED);
        }
        p.line_segment(
            [
                egui::pos2(x0, head_b + 7.0),
                egui::pos2(geo.watt_r, head_b + 7.0),
            ],
            Stroke::new(1.0, c::BORDER_INNER),
        );
        let mut y = head_b + 7.0 + geo.pitch;
        for row in &sv.matrix {
            paint::text_clipped(
                &p,
                x0,
                y,
                geo.temp_r - geo.col_w - x0 + 6.0,
                &row.label,
                t::CAPTION,
                c::TEXT_BODY,
            );
            for (cell, xr) in [
                (&row.temp, geo.temp_r),
                (&row.volt, geo.volt_r),
                (&row.watt, geo.watt_r),
            ] {
                match cell {
                    SensorCell::Value { text, tone } => {
                        let col = if *tone == Tone::Idle {
                            c::TEXT_PRIMARY
                        } else {
                            tone_color(*tone)
                        };
                        paint::text(&p, xr, y, Align::Max, text, t::BODY_STRONG, col);
                    }
                    SensorCell::NoData => {
                        paint::text(
                            &p,
                            xr,
                            y,
                            Align::Max,
                            d.sensors_no_data,
                            t::SSD_NOTE,
                            c::TEXT_MUTED,
                        );
                    }
                    SensorCell::NotApplicable => {
                        paint::text(&p, xr, y, Align::Max, "—", t::CAPTION, c::TEXT_MUTED);
                    }
                }
            }
            y += geo.pitch;
        }
        // "Состояние ПИТАНИЯ: Отлично / Внимание! / Критично! / Нет данных".
        y += 8.0;
        let lr = paint::text(
            &p,
            x0,
            y,
            Align::Min,
            d.sensors_power_state_label,
            t::CAPTION,
            c::TEXT_SECONDARY,
        );
        paint::text(
            &p,
            lr.right() + 8.0,
            y,
            Align::Min,
            &sv.power_state,
            t::BODY_STRONG,
            if sv.power_tone == Tone::Idle {
                c::TEXT_SECONDARY
            } else {
                tone_color(sv.power_tone)
            },
        );
        if !sv.power_message.is_empty() && matches!(sv.power_tone, Tone::Warning | Tone::Error) {
            for (k, line) in wrap_two(&sv.power_message).iter().enumerate() {
                paint::text_clipped(
                    &p,
                    x0,
                    y + 20.0 + k as f32 * 16.0,
                    rect.width() - 42.0,
                    line,
                    t::SSD_NOTE,
                    tone_color(sv.power_tone),
                );
            }
        }
        // "Эталон" reference table: thin cyan frame, right-hand side.
        let frame = Rect::from_min_max(
            egui::pos2(geo.ref_l, rect.top() + 46.0),
            egui::pos2(
                geo.ref_r,
                rect.top() + 46.0 + 30.0 + sv.refs.len() as f32 * geo.ref_pitch + 8.0,
            ),
        );
        p.rect_stroke(
            frame,
            CornerRadius::same(4),
            Stroke::new(1.0, c::TEST_BLOCK_BORDER.gamma_multiply(0.6)),
            StrokeKind::Inside,
        );
        paint::text(
            &p,
            frame.left() + 8.0,
            frame.top() + 18.0,
            Align::Min,
            d.sensors_ref_title,
            t::SSD_NOTE,
            c::TEXT_TITLE.gamma_multiply(0.85),
        );
        let mut ry = frame.top() + 18.0 + geo.ref_pitch + 4.0;
        for rr in &sv.refs {
            let range_r = paint::text(
                &p,
                frame.right() - 8.0,
                ry,
                Align::Max,
                &rr.range,
                t::SSD_NOTE,
                c::TEXT_SECONDARY,
            );
            paint::text_clipped(
                &p,
                frame.left() + 8.0,
                ry,
                (range_r.left() - frame.left() - 14.0).max(30.0),
                &rr.label,
                t::SSD_NOTE,
                c::TEXT_MUTED,
            );
            ry += geo.ref_pitch;
        }
    }
    paint::text_clipped(
        &p,
        x0,
        rect.bottom() - 12.0,
        rect.width() - 42.0,
        d.sensors_note,
        t::SSD_NOTE,
        c::TEXT_MUTED,
    );
    draw_sensor_read_indicator(&p, rect, vm);
}

/// v1.0 item 8: lower-right READ indicator of the sensor card — a cyan
/// spinner ring with "READ" in the centre and the REAL elapsed time
/// (00:01, 00:02 …) under it; no percentage. ERROR: a static red ring.
/// Nothing is drawn when idle (the spinner disappears on success).
pub fn sensor_read_indicator_rect(card: Rect) -> Rect {
    Rect::from_center_size(
        egui::pos2(card.right() - 46.0, card.bottom() - 62.0),
        vec2(56.0, 56.0),
    )
}

fn draw_sensor_read_indicator(p: &Painter, card: Rect, vm: &DashboardVm) {
    use super::vm::SensorReadVm;
    let area = sensor_read_indicator_rect(card);
    let center = area.center();
    let r_mid = 22.0;
    match &vm.sensors.read {
        SensorReadVm::Idle => {}
        SensorReadVm::Reading { .. } => {
            paint::ring_track(p, center, r_mid, 3.0, c::BORDER_INNER);
            // Rotating 100° arc with a fading tail (time-driven; static
            // when animation is off, still clearly "in progress").
            let spin = if vm.animate {
                ((vm.time * 300.0) % 360.0) as f32
            } else {
                0.0
            };
            paint::arc_band(p, center, r_mid, 3.4, spin, spin + 110.0, |deg| {
                let k = ((deg - spin) / 110.0).clamp(0.0, 1.0);
                paint::with_alpha(c::TEXT_TITLE, 0.15 + 0.85 * k)
            });
            paint::text(
                p,
                center.x,
                center.y + 4.5,
                Align::Center,
                "READ",
                t::SSD_NOTE,
                c::TEXT_TITLE,
            );
            if let Some(e) = vm.sensors.read.elapsed_text() {
                paint::text(
                    p,
                    center.x,
                    area.bottom() + 14.0,
                    Align::Center,
                    &e,
                    t::SSD_NOTE,
                    c::TEXT_SECONDARY,
                );
            }
        }
        SensorReadVm::Error { .. } => {
            paint::ring_track(p, center, r_mid, 3.0, c::RED_ERROR);
            paint::text(
                p,
                center.x,
                center.y + 4.5,
                Align::Center,
                "ERROR",
                t::SSD_NOTE,
                c::RED_ERROR,
            );
        }
    }
}

/// Column geometry of the v1.0 sensor matrix (right edges of the value
/// columns, reference table bounds) inside the sensor card.
pub struct SensorMatrixGeometry {
    pub name_x: f32,
    pub temp_r: f32,
    pub volt_r: f32,
    pub watt_r: f32,
    pub col_w: f32,
    pub ref_l: f32,
    pub ref_r: f32,
    pub pitch: f32,
    pub ref_pitch: f32,
}

impl SensorMatrixGeometry {
    pub fn new(card: Rect) -> Self {
        let name_x = card.left() + 21.0;
        let col_w = 64.0;
        let temp_r = name_x + 120.0 + col_w;
        let volt_r = temp_r + 72.0;
        let watt_r = volt_r + 64.0;
        Self {
            name_x,
            temp_r,
            volt_r,
            watt_r,
            col_w,
            ref_l: watt_r + 14.0,
            ref_r: card.right() - 12.0,
            pitch: 23.0,
            ref_pitch: 19.0,
        }
    }
}

/// Splits a long status sentence into at most two lines at a sentence end.
fn wrap_two(s: &str) -> Vec<String> {
    match s.split_once(". ") {
        Some((a, b)) => vec![format!("{a}."), b.to_string()],
        None => vec![s.to_string()],
    }
}

/// v1.0 SMART / Health: one compact column — the selected NVMe disk's key
/// facts, then every ATA / SATA disk (HDDs included) with its read-only
/// SMART health and temperature.
pub fn draw_smart(ui: &mut Ui, o: Pos2, vm: &DashboardVm) {
    let d = i18n::t(vm.lang);
    let p = ui.painter().clone();
    let rect = card(&p, o, l::SMART_CARD, d.smart_title);
    let x = rect.left() + 21.0;
    let pitch = 21.0;
    let fit = ((rect.height() - 62.0) / pitch).floor().max(1.0) as usize;
    let rows: Vec<InfoRow> = vm.smart.iter().take(fit).cloned().collect();
    info_rows(
        &p,
        &rows,
        x,
        rect.top() + 54.0,
        pitch,
        190.0,
        rect.right() - 16.0,
    );
}

pub fn draw_crash(ui: &mut Ui, o: Pos2, vm: &DashboardVm, actions: &mut Vec<Action>) {
    use super::vm::StageMark;
    let d = i18n::t(vm.lang);
    let p = ui.painter().clone();
    let rect = card(&p, o, l::CRASH_CARD, d.crash_title);
    let x = rect.left() + 21.0;
    paint::text_clipped(
        &p,
        x,
        rect.top() + 58.0,
        rect.width() - 42.0,
        &vm.crash.headline,
        t::BODY_STRONG,
        tone_color(vm.crash.tone),
    );
    // v0.4.5 counts: unexpected shutdowns / BugCheck / dumps.
    paint::text_clipped(
        &p,
        x,
        rect.top() + 82.0,
        rect.width() - 42.0,
        &vm.crash.counts,
        t::CAPTION,
        c::TEXT_BODY,
    );
    // Debugger status line (+ v1.0 outcome colour of the last analysis).
    paint::text(
        &p,
        x,
        rect.top() + 104.0,
        Align::Min,
        d.crash_debugger,
        t::CAPTION,
        c::TEXT_SECONDARY,
    );
    paint::text(
        &p,
        x + 210.0,
        rect.top() + 104.0,
        Align::Min,
        &vm.crash.debugger,
        t::CAPTION,
        tone_color(vm.crash.debugger_tone),
    );
    if let Some((text, tone)) = &vm.crash.outcome {
        paint::text(
            &p,
            rect.right() - 18.0,
            rect.top() + 104.0,
            Align::Max,
            text,
            t::CAPTION,
            tone_color(*tone),
        );
    }
    let inner = Rect::from_min_max(
        egui::pos2(x - 6.0, rect.top() + 116.0),
        egui::pos2(rect.right() - 15.0, rect.bottom() - 58.0),
    );
    p.rect(
        inner,
        CornerRadius::same(5),
        c::BG_CARD_INNER,
        Stroke::new(1.0, c::BORDER_INNER),
        StrokeKind::Inside,
    );
    if let Some(a) = &vm.crash.analysis {
        // v1.0: LARGE indeterminate ring (no fake percentage), comparable in
        // visual weight to the main progress ring, with the real stages.
        let dia = (inner.height() - 30.0).min(160.0);
        let center = egui::pos2(inner.left() + 24.0 + dia / 2.0, inner.center().y);
        let r_mid = dia / 2.0 - 6.0;
        paint::ring_track(&p, center, r_mid, 8.0, c::RING_TRACK);
        let phase = if vm.animate {
            ((vm.time * 140.0) % 360.0) as f32
        } else {
            0.0
        };
        let pulse = super::dashboard::running_stage_intensity(vm.time, vm.animate);
        let sweep = 110.0;
        paint::arc_band(&p, center, r_mid, 8.0, phase, phase + sweep, |deg| {
            let k = ((deg - phase) / sweep).clamp(0.0, 1.0);
            paint::intensity(c::BLUE_STATUS, (0.35 + 0.65 * k) * (0.75 + 0.25 * pulse))
        });
        if phase + sweep > 360.0 {
            let rest = phase + sweep - 360.0;
            paint::arc_band(&p, center, r_mid, 8.0, 0.0, rest, |deg| {
                let k = ((deg + 360.0 - phase) / sweep).clamp(0.0, 1.0);
                paint::intensity(c::BLUE_STATUS, (0.35 + 0.65 * k) * (0.75 + 0.25 * pulse))
            });
        }
        paint::text(
            &p,
            center.x,
            center.y - 2.0,
            Align::Center,
            d.crash_progress_title,
            t::METRIC_SMALL,
            c::TEXT_HEADLINE,
        );
        paint::text(
            &p,
            center.x,
            center.y + 22.0,
            Align::Center,
            &a.elapsed,
            t::RING_STATUS,
            c::TEXT_SECONDARY,
        );
        let sx = center.x + dia / 2.0 + 28.0;
        let mut sy = inner.top() + 26.0;
        paint::text_clipped(
            &p,
            sx,
            sy,
            inner.right() - sx - 12.0,
            &a.dump_label,
            t::CAPTION,
            c::TEXT_SECONDARY,
        );
        sy += 26.0;
        for (label, mark) in &a.stages {
            let (marker, col) = match mark {
                // Glyphs present in Segoe UI (no tofu boxes).
                StageMark::Done => ("●", c::GREEN_SUCCESS),
                StageMark::Active => ("→", c::BLUE_STATUS),
                StageMark::Pending => ("·", c::TEXT_MUTED),
            };
            paint::text(&p, sx, sy, Align::Min, marker, t::CAPTION, col);
            paint::text(
                &p,
                sx + 20.0,
                sy,
                Align::Min,
                label,
                t::CAPTION,
                match mark {
                    StageMark::Active => c::TEXT_HEADLINE,
                    StageMark::Done => c::TEXT_BODY,
                    StageMark::Pending => c::TEXT_MUTED,
                },
            );
            sy += 22.0;
        }
        if let Some(note) = &a.note {
            paint::text_clipped(
                &p,
                sx,
                sy + 6.0,
                inner.right() - sx - 12.0,
                note,
                t::CAPTION,
                c::YELLOW_WARNING,
            );
        }
    } else {
        info_rows(
            &p,
            &vm.crash.rows,
            x + 6.0,
            inner.top() + 22.0,
            23.0,
            180.0,
            inner.right() - 10.0,
        );
    }
    // v1.0 embedded installer status, directly above the buttons.
    if let Some(inst) = &vm.crash.install {
        let band = Rect::from_min_max(
            egui::pos2(inner.left() + 8.0, inner.bottom() - 74.0),
            egui::pos2(inner.right() - 8.0, inner.bottom() - 6.0),
        );
        p.rect(
            band,
            CornerRadius::same(4),
            c::BG_CARD,
            Stroke::new(1.0, c::BORDER_NORMAL),
            StrokeKind::Inside,
        );
        let tx = band.left() + 12.0;
        paint::text(
            &p,
            tx,
            band.top() + 20.0,
            Align::Min,
            &inst.title,
            t::CAPTION,
            c::TEXT_TITLE,
        );
        if inst.failed || inst.succeeded {
            paint::text_clipped(
                &p,
                tx,
                band.top() + 44.0,
                band.width() - 24.0,
                &inst.status,
                t::BODY_STRONG,
                if inst.failed {
                    c::RED_ERROR
                } else {
                    c::GREEN_SUCCESS
                },
            );
        } else {
            let mut lx = tx;
            for (label, mark) in &inst.lines {
                let col = match mark {
                    StageMark::Done => c::GREEN_SUCCESS,
                    StageMark::Active => c::TEXT_HEADLINE,
                    StageMark::Pending => c::TEXT_MUTED,
                };
                let w = paint::text(
                    &p,
                    lx,
                    band.top() + 44.0,
                    Align::Min,
                    label,
                    t::SSD_NOTE,
                    col,
                );
                lx = w.right() + 14.0;
            }
            // Real percent only when winget printed one; otherwise an
            // indeterminate sliding segment.
            let bar = Rect::from_min_size(
                egui::pos2(tx, band.top() + 54.0),
                vec2(band.width() - 24.0, 5.0),
            );
            p.rect_filled(bar, CornerRadius::same(2), c::BG_FIELD);
            match inst.percent {
                Some(pc) => {
                    let w = bar.width() * f32::from(pc) / 100.0;
                    p.rect_filled(
                        Rect::from_min_size(bar.min, vec2(w, bar.height())),
                        CornerRadius::same(2),
                        c::BLUE_PRIMARY,
                    );
                }
                None => {
                    let seg = bar.width() * 0.25;
                    let ph = if vm.animate {
                        (vm.time * 0.5).fract() as f32
                    } else {
                        0.3
                    };
                    let x0 = bar.left() - seg + (bar.width() + seg) * ph;
                    let a = Rect::from_min_max(
                        egui::pos2(x0.max(bar.left()), bar.top()),
                        egui::pos2((x0 + seg).min(bar.right()), bar.bottom()),
                    );
                    if a.width() > 0.0 {
                        p.rect_filled(a, CornerRadius::same(2), c::BLUE_PRIMARY);
                    }
                }
            }
        }
    }
    // Actions.
    let y = rect.bottom() - 48.0;
    let mut bx = x - 4.0;
    let mut btn = |ui: &mut Ui, w: f32, id: &str, label: &str, kind: ButtonKind, enabled: bool| {
        let b = Rect::from_min_size(egui::pos2(bx, y), vec2(w, 36.0));
        bx += w + 10.0;
        paint::button(
            ui,
            b,
            id,
            label,
            kind,
            enabled,
            ButtonIcon::None,
            t::BUTTON_TEXT,
        )
        .clicked()
    };
    let installing = vm.crash.install.as_ref().is_some_and(|i| i.running);
    let install_failed = vm.crash.install.as_ref().is_some_and(|i| i.failed);
    if vm.crash.debugger_missing
        && btn(
            ui,
            230.0,
            "crash_install",
            if install_failed {
                d.install_retry
            } else {
                d.crash_install
            },
            ButtonKind::Primary,
            !vm.crash.busy && !installing,
        )
    {
        actions.push(Action::InstallAnalyzer);
    }
    if btn(
        ui,
        220.0,
        "crash_analyze",
        d.crash_analyze,
        if vm.crash.debugger_missing {
            ButtonKind::Secondary
        } else {
            ButtonKind::Primary
        },
        vm.crash.can_analyze && !vm.crash.busy,
    ) {
        actions.push(Action::AnalyzeDumps);
    }
    if btn(
        ui,
        110.0,
        "crash_details",
        d.crash_details,
        ButtonKind::Secondary,
        vm.crash.has_details || install_failed,
    ) {
        actions.push(Action::ShowCrashDetails);
    }
    if btn(
        ui,
        170.0,
        "crash_folder",
        d.crash_open_folder,
        ButtonKind::Secondary,
        true,
    ) {
        actions.push(Action::OpenFolder);
    }
}

/// Benchmark Test 1 / Test 2 blocks inside the SSD result frame.
pub fn draw_test_blocks(
    p: &Painter,
    frame: Rect,
    vm: &DashboardVm,
    tests: &[Option<super::vm::TestVm>; 2],
) {
    use super::vm::TestBlockVm;
    let blocks = [
        tests[0]
            .clone()
            .map(TestBlockVm::Done)
            .unwrap_or(TestBlockVm::Waiting(None)),
        match &tests[1] {
            Some(tv) => TestBlockVm::Done(tv.clone()),
            // No retest was needed: the explicit "not needed" caption.
            None => TestBlockVm::Waiting(Some(String::new())),
        },
    ];
    draw_test_block_pair(p, frame, vm, &blocks, tests[1].is_some());
}

/// v0.4.5 live Test 1 / Test 2 blocks: the active one pulses (cyan) with
/// its elapsed clock and live MB/s, a finished one is marked ГОТОВ with its
/// final values and stability, a pending one stays subdued. `retest` labels
/// Test 2 as the confirmation retest.
pub fn draw_test_block_pair(
    p: &Painter,
    frame: Rect,
    vm: &DashboardVm,
    blocks: &[super::vm::TestBlockVm; 2],
    retest: bool,
) {
    use super::vm::TestBlockVm;
    let d = i18n::t(vm.lang);
    let half = frame.width() / 2.0;
    let pulse = super::dashboard::running_stage_intensity(vm.time, vm.animate);
    for (i, block_vm) in blocks.iter().enumerate() {
        let block = Rect::from_min_size(
            egui::pos2(frame.left() + 10.0 + i as f32 * half, frame.top() + 12.0),
            vec2(half - 20.0, frame.height() - 24.0),
        );
        let active = matches!(block_vm, TestBlockVm::Active { .. });
        let waiting = matches!(block_vm, TestBlockVm::Waiting(_));
        let border = if active {
            paint::intensity(c::TEST_BLOCK_BORDER, pulse)
        } else if waiting {
            c::BORDER_INNER
        } else {
            c::TEST_BLOCK_BORDER
        };
        if active {
            // Soft outer glow of the running block.
            p.rect_stroke(
                block.expand(2.0),
                CornerRadius::same(8),
                Stroke::new(2.0, border.gamma_multiply(0.35)),
                StrokeKind::Outside,
            );
        }
        p.rect_stroke(
            block,
            CornerRadius::same(6),
            Stroke::new(if active { 1.5 } else { 1.0 }, border),
            StrokeKind::Inside,
        );
        let cx = block.center().x;
        let name = if i == 0 { d.test1_title } else { d.test2_title };
        let (title, title_col) = match block_vm {
            TestBlockVm::Active { elapsed, .. } => (format!("{name} · {elapsed}"), border),
            TestBlockVm::Done(_) => (format!("{name} · {}", d.test_done), c::TEST_BLOCK_BORDER),
            TestBlockVm::Waiting(_) => (name.to_string(), c::TEXT_MUTED),
        };
        paint::text(
            p,
            cx,
            block.top() + 24.0,
            Align::Center,
            &title,
            t::SSD_RING_LABEL,
            title_col,
        );
        // Caption: state, or (Test 2 of a retest) the two-line retest label.
        let caption = match block_vm {
            _ if i == 1 && retest => d.test_retest_label.to_string(),
            TestBlockVm::Active { .. } => d.test_running.to_string(),
            TestBlockVm::Waiting(Some(text)) if !text.is_empty() => text.clone(),
            TestBlockVm::Waiting(Some(_)) => d.test2_none.to_string(),
            TestBlockVm::Waiting(None) => d.test_waiting.to_string(),
            TestBlockVm::Done(_) => String::new(),
        };
        let (line1, line2) = match caption.split_once(" — ") {
            Some((a, b)) => (a.to_string(), Some(b.to_string())),
            None => (caption.clone(), None),
        };
        for (k, line) in std::iter::once(Some(line1)).chain([line2]).enumerate() {
            let Some(line) = line.filter(|l| !l.is_empty()) else {
                continue;
            };
            paint::text_clipped(
                p,
                block.left() + 8.0,
                block.top() + 42.0 + k as f32 * 13.0,
                block.width() - 16.0,
                &line,
                t::SSD_NOTE,
                if active {
                    c::TEXT_SECONDARY
                } else {
                    c::TEXT_MUTED
                },
            );
        }
        // A pending retest keeps its countdown visible below the values.
        if let TestBlockVm::Waiting(Some(text)) = block_vm
            && !text.is_empty()
            && i == 1
            && retest
        {
            paint::text(
                p,
                cx,
                block.top() + 168.0,
                Align::Center,
                text,
                t::CAPTION,
                c::TEXT_SECONDARY,
            );
        }
        let (read, write, value_col) = match block_vm {
            TestBlockVm::Active { read, write, .. } => (
                read.clone().unwrap_or_else(|| "—".into()),
                write.clone().unwrap_or_else(|| "—".into()),
                None,
            ),
            TestBlockVm::Done(tv) => (tv.read.clone(), tv.write.clone(), None),
            TestBlockVm::Waiting(_) => ("—".into(), "—".into(), Some(c::TEXT_MUTED)),
        };
        let rows = [
            ("READ", c::READ_LABEL, c::READ_CURRENT, &read, 90.0),
            ("WRITE", c::WRITE_LABEL, c::WRITE_CURRENT, &write, 136.0),
        ];
        for (label, label_col, value, text, y) in rows {
            paint::text(
                p,
                block.left() + 12.0,
                block.top() + y - 14.0,
                Align::Min,
                label,
                t::SSD_UNIT,
                if waiting { c::TEXT_MUTED } else { label_col },
            );
            paint::text(
                p,
                block.left() + 12.0,
                block.top() + y + 2.0,
                Align::Min,
                "MB/s",
                t::SSD_NOTE,
                c::TEXT_MUTED,
            );
            paint::text(
                p,
                block.right() - 12.0,
                block.top() + y + 8.0,
                Align::Max,
                text,
                t::TEST_METRIC,
                value_col.unwrap_or(value),
            );
        }
        if let TestBlockVm::Done(tv) = block_vm {
            // "STABLE · R 0.4% / W 2.1%": level, then the spreads.
            let (level, spread) = tv
                .stability
                .split_once(" · ")
                .unwrap_or((tv.stability.as_str(), ""));
            paint::text(
                p,
                cx,
                block.top() + 164.0,
                Align::Center,
                level,
                t::BODY_STRONG,
                tone_color(tv.tone),
            );
            paint::text_clipped(
                p,
                block.left() + 10.0,
                block.top() + 180.0,
                block.width() - 20.0,
                spread,
                t::SSD_NOTE,
                tone_color(tv.tone),
            );
            if let Some(delta) = &tv.delta {
                paint::text_clipped(
                    p,
                    block.left() + 10.0,
                    block.bottom() - 9.0,
                    block.width() - 20.0,
                    delta,
                    t::SSD_NOTE,
                    c::TEXT_MUTED,
                );
            }
        }
    }
}
