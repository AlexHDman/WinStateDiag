//! Fixed-geometry dashboard renderer. Macro layout (every card, ring, bar,
//! button) is placed at the measured master rectangles from `tokens`;
//! normal egui layout is used only for the few real input widgets inside
//! their own well-defined rects. The renderer reads a [`DashboardVm`] and
//! mutable control values, and reports user intents as [`Action`]s.

use super::fonts::font;
use super::paint::{self, BAR_STAGE, BAR_STAGE_PENDING, ButtonIcon, ButtonKind};
use super::tokens::{color as c, layout as l, mpos, mrect, typography as t};
use super::vm::*;
use crate::engine::{DeepChecks, DiagnosticMode};
use crate::i18n;
use egui::{
    Align, Color32, CornerRadius, Margin, Painter, Pos2, Rect, Sense, Stroke, StrokeKind, Ui,
    UiBuilder, vec2,
};

/// Mutable values edited directly by widgets (all UI-side state).
pub struct Controls<'a> {
    pub client_name: &'a mut String,
    pub mode: &'a mut DiagnosticMode,
    pub deep_checks: &'a mut DeepChecks,
    pub include_hardware: &'a mut bool,
    /// Implementation detail only (v0.3.6 UI finalization): the resolved
    /// writable-volume path for the selected physical disk. Never shown or
    /// edited in the UI — see `draw_disk_info_panel` and
    /// `App::select_ssd_disk` — kept here only so the field's owner
    /// (`app.rs`) stays the single source of truth.
    #[allow(dead_code)]
    pub benchmark_path: &'a mut String,
}

fn r(o: Pos2, v: l::R) -> Rect {
    mrect(o, v[0], v[1], v[2], v[3])
}

/// Canvas x / baseline from master coordinates.
fn mx(o: Pos2, x: f32) -> f32 {
    mpos(o, x, 0.0).x
}
fn my(o: Pos2, y: f32) -> f32 {
    mpos(o, 0.0, y).y
}

fn title(p: &Painter, o: Pos2, x: f32, baseline: f32, s: &str, style: t::TextStyle) {
    paint::text(
        p,
        mx(o, x),
        my(o, baseline),
        Align::Min,
        s,
        style,
        c::TEXT_TITLE,
    );
}

pub fn draw(
    ui: &mut Ui,
    origin: Pos2,
    vm: &DashboardVm,
    ctl: &mut Controls<'_>,
    actions: &mut Vec<Action>,
) {
    let o = origin;
    let canvas = Rect::from_min_size(o, vec2(super::tokens::CANVAS_W, super::tokens::CANVAS_H));
    ui.painter()
        .rect_filled(canvas, CornerRadius::ZERO, c::BG_ROOT);

    draw_header(ui, o, vm);
    draw_language_switch(ui, o, vm, actions);
    draw_client(ui, o, vm, ctl);
    draw_diagnostic(ui, o, vm, ctl);
    draw_crypto(ui, o, vm, actions);
    draw_hardware(ui, o, vm, ctl, actions);
    draw_stages(ui, o, vm);
    draw_drivers(ui, o, vm, actions);
    draw_result(ui, o, vm, actions);
    draw_start(ui, o, vm, actions);
    draw_overall(ui, o, vm);
    draw_ssd(ui, o, vm, ctl, actions);
    draw_journal(ui, o, vm, actions);
    draw_status_bar(ui, o, vm);
}

/// Compact RU/EN switch in the top header (v0.3.6 Visual Master alignment,
/// §2): both buttons keep the same dark internal fill and geometry — only
/// the border/text accent distinguishes the active language from the
/// inactive one. The active accent is now the same restrained gold/yellow
/// family as the EXPC logo, the selected SSD card and its connector (§8),
/// replacing the earlier green; inactive stays subdued blue/cyan. Clicking
/// pushes `Action::SetLanguage`; the whole GUI re-reads `vm.lang` on the
/// very next frame, no restart or window recreation involved.
fn draw_language_switch(ui: &mut Ui, o: Pos2, vm: &DashboardVm, actions: &mut Vec<Action>) {
    let p = ui.painter().clone();
    let pairs = [
        (i18n::Language::Ru, "RU", l::LANG_BUTTON_RU),
        (i18n::Language::En, "EN", l::LANG_BUTTON_EN),
    ];
    for (lang, label, rect_tok) in pairs {
        let rect = r(o, rect_tok);
        let active = vm.lang == lang;
        let (border, text_col) = lang_button_colors(active);
        p.rect(
            rect,
            CornerRadius::same(5),
            c::BG_FIELD,
            Stroke::new(1.0, border),
            StrokeKind::Inside,
        );
        paint::text(
            &p,
            rect.center().x,
            rect.center().y + t::LANG_BUTTON.size * 0.36,
            Align::Center,
            label,
            t::LANG_BUTTON,
            text_col,
        );
        let resp = ui.interact(rect, egui::Id::new(("lang_switch", label)), Sense::click());
        if resp.clicked() && !active {
            actions.push(Action::SetLanguage(lang));
        }
    }
}

/// Active language = the shared gold accent (same family as EXPC, the
/// selected SSD and its connector); inactive = subdued blue. Never green.
/// Returns (outline, text) colours.
pub(crate) fn lang_button_colors(active: bool) -> (Color32, Color32) {
    if active {
        (c::GOLD_ACCENT, c::GOLD_ACCENT)
    } else {
        (c::LANG_INACTIVE, c::LANG_INACTIVE_TEXT)
    }
}

/// Embedded EXPC header wordmark + emblem (v0.3.6 Visual Master alignment,
/// §3): derived from the existing `assets/logo.png` brand asset — the
/// "EXPC" wordmark and circular AI-profile emblem only (no "Design" text,
/// no QR code), with the black background cleanly removed and the gold
/// pushed toward the brighter/richer tone the new master shows. 534x88 RGBA.
const EXPC_HEADER_LOGO_RGBA: &[u8] = include_bytes!("../../assets/expc-header-logo.rgba");
const EXPC_HEADER_LOGO_DIM: [usize; 2] = [534, 88];

fn expc_header_logo(ctx: &egui::Context) -> egui::TextureHandle {
    let id = egui::Id::new("expc_header_logo");
    if let Some(t) = ctx.data(|d| d.get_temp::<egui::TextureHandle>(id)) {
        return t;
    }
    let image =
        egui::ColorImage::from_rgba_unmultiplied(EXPC_HEADER_LOGO_DIM, EXPC_HEADER_LOGO_RGBA);
    let t = ctx.load_texture("expc_header_logo", image, egui::TextureOptions::LINEAR);
    ctx.data_mut(|d| d.insert_temp(id, t.clone()));
    t
}

// ---------------------------------------------------------------------------
// Header
// ---------------------------------------------------------------------------

fn draw_header(ui: &mut Ui, o: Pos2, vm: &DashboardVm) {
    let d = i18n::t(vm.lang);
    let p = ui.painter();
    paint::icon_pulse(p, r(o, l::HEADER_ICON), c::BLUE_ACCENT);
    paint::text(
        p,
        mx(o, l::APP_TITLE_X),
        my(o, l::APP_TITLE_BASELINE),
        Align::Min,
        d.app_title,
        t::APP_TITLE,
        c::TEXT_HEADLINE,
    );
    paint::text(
        p,
        mx(o, l::APP_TITLE_X),
        my(o, l::APP_SUBTITLE_BASELINE),
        Align::Min,
        d.header_subtitle,
        t::APP_SUBTITLE,
        c::TEXT_SUBTITLE,
    );
    // v0.3.6 Visual Master alignment (§3): the old bilingual slogan is
    // removed entirely (in both languages) and replaced by the EXPC
    // wordmark + emblem, placed top-right after the compact RU/EN switch.
    let logo = expc_header_logo(ui.ctx());
    p.image(
        logo.id(),
        r(o, l::EXPC_HEADER_LOGO),
        Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0)),
        Color32::WHITE,
    );
}

// ---------------------------------------------------------------------------
// Left column
// ---------------------------------------------------------------------------

fn field(p: &Painter, rect: Rect) {
    p.rect(
        rect,
        CornerRadius::same(l::FIELD_RADIUS),
        c::BG_FIELD,
        Stroke::new(1.0, c::BORDER_FIELD),
        StrokeKind::Inside,
    );
}

fn single_line_edit(
    ui: &mut Ui,
    rect: Rect,
    value: &mut String,
    enabled: bool,
    hint: &str,
    id: &str,
) {
    field(ui.painter(), rect);
    let row_h = ui.fonts_mut(|f| f.row_height(&font(t::BODY)));
    let inner = Rect::from_min_size(
        rect.min + vec2(l::FIELD_TEXT_INSET_X, (rect.height() - row_h) / 2.0),
        vec2(rect.width() - 2.0 * l::FIELD_TEXT_INSET_X, row_h),
    );
    ui.scope_builder(UiBuilder::new().max_rect(inner).id_salt(id), |ui| {
        ui.add_enabled(
            enabled,
            egui::TextEdit::singleline(value)
                .frame(egui::Frame::NONE)
                .margin(Margin::ZERO)
                .font(font(t::BODY))
                .text_color(c::TEXT_PRIMARY)
                .desired_width(inner.width())
                .hint_text(egui::RichText::new(hint).color(c::TEXT_MUTED)),
        );
    });
}

fn draw_client(ui: &mut Ui, o: Pos2, vm: &DashboardVm, ctl: &mut Controls<'_>) {
    let d = i18n::t(vm.lang);
    let p = ui.painter().clone();
    paint::card(&p, r(o, l::CLIENT_CARD));
    for (label, baseline) in [d.client_label, d.computer_label]
        .iter()
        .zip(l::CLIENT_LABEL_BASELINES)
    {
        paint::text(
            &p,
            mx(o, l::CLIENT_LABEL_X),
            my(o, baseline),
            Align::Min,
            label,
            t::LABEL_LARGE,
            c::TEXT_HEADLINE,
        );
    }
    let client_rect = r(o, l::CLIENT_FIELD);
    let hint = d.client_field_hint;
    single_line_edit(
        ui,
        client_rect,
        ctl.client_name,
        vm.controls_enabled,
        hint,
        "client_name",
    );
    // Attention: while the client name is empty, the field's own 1px border
    // softly pulses toward violet (drawn on top; size never changes).
    if vm.animate && vm.controls_enabled && client_attention(ctl.client_name) {
        attention_border(
            ui,
            client_rect,
            l::FIELD_RADIUS,
            c::BORDER_FIELD,
            c::ATTENTION_CLIENT,
            vm.time,
        );
    }
    let comp = r(o, l::COMPUTER_FIELD);
    field(&p, comp);
    let baseline = comp.center().y + t::BODY.size * 0.36;
    paint::text_clipped(
        &p,
        comp.left() + l::FIELD_TEXT_INSET_X,
        baseline,
        comp.width() - 2.0 * l::FIELD_TEXT_INSET_X,
        &vm.computer_name,
        t::BODY,
        c::TEXT_PRIMARY,
    );
}

fn draw_diagnostic(ui: &mut Ui, o: Pos2, vm: &DashboardVm, ctl: &mut Controls<'_>) {
    let d = i18n::t(vm.lang);
    let p = ui.painter().clone();
    let card = r(o, l::DIAGNOSTIC_CARD);
    paint::card(&p, card);
    title(
        &p,
        o,
        l::LEFT_TITLE_X,
        l::DIAGNOSTIC_TITLE_BASELINE,
        d.expc_title,
        t::TITLE_EXPC,
    );
    let options = [
        (
            DiagnosticMode::Standard,
            d.expc_mode_standard,
            d.expc_mode_standard_desc,
        ),
        (
            DiagnosticMode::CustomDeepChecks,
            d.expc_mode_deep,
            d.expc_mode_deep_desc,
        ),
        (
            DiagnosticMode::Full,
            d.expc_mode_full,
            d.expc_mode_full_desc,
        ),
    ];
    for (i, (mode, label, hint)) in options.iter().enumerate() {
        let center = mpos(o, l::RADIO_CENTER_X, l::RADIO_CENTERS_Y[i]);
        let label_w = paint::text_width(&p, label, t::BODY);
        let hit = Rect::from_min_max(
            center - vec2(13.0, 13.0),
            egui::pos2(mx(o, l::RADIO_LABEL_X) + label_w + 6.0, center.y + 13.0),
        );
        let clicked = paint::radio(
            ui,
            center,
            l::RADIO_DIAMETER,
            *ctl.mode == *mode,
            vm.controls_enabled,
            &format!("mode_{i}"),
            hit,
        );
        if clicked {
            *ctl.mode = *mode;
        }
        ui.interact(hit, ui.id().with(("mode_hint", i)), Sense::hover())
            .on_hover_text(*hint);
        let col = if vm.controls_enabled {
            c::TEXT_PRIMARY
        } else {
            c::TEXT_SECONDARY
        };
        paint::text(
            &p,
            mx(o, l::RADIO_LABEL_X),
            my(o, l::RADIO_LABEL_BASELINES[i]),
            Align::Min,
            label,
            t::BODY,
            col,
        );
    }
    // Custom deep checks: a compact column (one per row) at the right of
    // the narrowed card, so the card never grows and never overflows into
    // the CryptoPro card (they only exist in that mode).
    if matches!(*ctl.mode, DiagnosticMode::CustomDeepChecks) {
        let x = l::DEEP_TOGGLES_X;
        let items: [(&str, &mut bool); 3] = [
            ("SFC", &mut ctl.deep_checks.sfc),
            ("DISM", &mut ctl.deep_checks.dism),
            ("CHKDSK", &mut ctl.deep_checks.chkdsk),
        ];
        for (row, (name, value)) in items.into_iter().enumerate() {
            let row_y = l::RADIO_CENTERS_Y[row];
            let bx = mrect(o, x, row_y - 7.0, 14.0, 14.0);
            let tw = paint::text_width(&p, name, t::DEEP_TOGGLE);
            let hit = Rect::from_min_max(bx.min, egui::pos2(bx.right() + 5.0 + tw, bx.bottom()));
            if paint::checkbox(
                ui,
                bx,
                *value,
                vm.controls_enabled,
                &format!("deep_{name}"),
                hit,
            ) {
                *value = !*value;
            }
            paint::text(
                &p,
                bx.right() + 5.0,
                bx.center().y + 4.6,
                Align::Min,
                name,
                t::DEEP_TOGGLE,
                c::TEXT_BODY,
            );
        }
    }
}

/// Embedded CryptoPro mark (v0.3.6 Visual Master alignment, §4): just the
/// red "C" arc + triangle, cropped from the official mark with the outer
/// diamond/shield container removed — 96x96 RGBA, colour and muted variants.
const CRYPTO_LOGO_RGBA: &[u8] = include_bytes!("../../assets/cryptopro-mark-96.rgba");
const CRYPTO_LOGO_GRAY_RGBA: &[u8] = include_bytes!("../../assets/cryptopro-mark-96-gray.rgba");

fn crypto_logo(ctx: &egui::Context, muted: bool) -> egui::TextureHandle {
    let id = egui::Id::new(("crypto_logo", muted));
    if let Some(t) = ctx.data(|d| d.get_temp::<egui::TextureHandle>(id)) {
        return t;
    }
    let bytes = if muted {
        CRYPTO_LOGO_GRAY_RGBA
    } else {
        CRYPTO_LOGO_RGBA
    };
    let image = egui::ColorImage::from_rgba_unmultiplied([96, 96], bytes);
    let t = ctx.load_texture(
        if muted {
            "crypto_logo_gray"
        } else {
            "crypto_logo"
        },
        image,
        egui::TextureOptions::LINEAR,
    );
    ctx.data_mut(|d| d.insert_temp(id, t.clone()));
    t
}

/// ONE CryptoPro card, composed as in the canonical master: simplified red
/// mark + name (top), status disc (middle), status word directly under it
/// (check + word read as one object), ReHash/Проверка button (bottom).
/// Only NO HASH makes the button clickable (unchanged behaviour: one click
/// runs the existing ReHash workflow, no confirmation dialog).
fn draw_crypto(ui: &mut Ui, o: Pos2, vm: &DashboardVm, actions: &mut Vec<Action>) {
    let d = i18n::t(vm.lang);
    let p = ui.painter().clone();
    let card = r(o, l::CRYPTO_CARD);
    paint::card(&p, card);
    let muted = vm.crypto == CryptoVm::NotInstalled;
    let logo = crypto_logo(ui.ctx(), muted);
    p.image(
        logo.id(),
        r(o, l::CRYPTO_LOGO),
        Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0)),
        Color32::WHITE,
    );
    let name_x = mx(o, l::CRYPTO_NAME_X);
    let name_max = card.right() - 8.0 - name_x;
    paint::text(
        &p,
        name_x,
        my(o, l::CRYPTO_NAME_BASELINE),
        Align::Min,
        "CryptoPro",
        fit_style(&p, "CryptoPro", t::CRYPTO_NAME, name_max),
        if muted {
            c::TEXT_MUTED
        } else {
            c::TEXT_HEADLINE
        },
    );
    let icon = r(o, l::CRYPTO_ICON);
    let base = my(o, l::CRYPTO_STATUS_BASELINE);
    let (label, col) = match vm.crypto {
        CryptoVm::Checking => (d.crypto_checking, c::TEXT_SECONDARY),
        // Just "HASH": the green check already says it's OK.
        CryptoVm::HashOk => (d.crypto_hash, c::GREEN_SUCCESS),
        CryptoVm::NoHash => (d.crypto_no_hash, c::YELLOW_WARNING),
        CryptoVm::NotInstalled => (d.crypto_not_installed, c::TEXT_MUTED),
        CryptoVm::CheckError => (d.crypto_check_error, c::TEXT_SECONDARY),
    };
    match vm.crypto {
        CryptoVm::HashOk => {
            paint::icon_check_circle(&p, icon.center(), icon.width(), c::GREEN_SUCCESS)
        }
        CryptoVm::NoHash => paint::icon_warning_triangle(
            &p,
            Rect::from_center_size(icon.center(), icon.size() * 0.92),
            c::YELLOW_WARNING,
            c::BG_CARD,
        ),
        CryptoVm::NotInstalled => {
            paint::circle_outline(
                &p,
                icon.center(),
                icon.width() / 2.0,
                2.5,
                c::RADIO_RING_OFF,
            );
            paint::text(
                &p,
                icon.center().x,
                icon.center().y + t::CRYPTO_STATUS_ICON.size * 0.33,
                Align::Center,
                "—",
                t::CRYPTO_STATUS_ICON,
                c::TEXT_MUTED,
            );
        }
        CryptoVm::CheckError => {
            paint::icon_alert_circle(&p, icon.center(), icon.width(), c::TEXT_SECONDARY)
        }
        CryptoVm::Checking => {
            paint::circle_outline(&p, icon.center(), icon.width() / 2.0, 3.0, c::RING_TRACK);
            let t0 = if vm.animate { vm.time as f32 } else { 0.0 };
            let a0 = (t0 * 240.0) % 360.0;
            paint::arc_band(
                &p,
                icon.center(),
                icon.width() / 2.0 - 1.5,
                3.0,
                a0,
                a0 + 90.0,
                |_| c::BLUE_STATUS,
            );
        }
    }
    let status_max = card.width() - 20.0;
    paint::text(
        &p,
        card.center().x,
        base,
        Align::Center,
        label,
        fit_style(&p, label, t::CRYPTO_STATUS, status_max),
        col,
    );

    // ReHash button: same place and size in every state. Clickable (blue)
    // only for NO HASH; otherwise a calm, readable non-interactive control.
    let button_rect = r(o, l::CRYPTO_BUTTON);
    let active = vm.crypto == CryptoVm::NoHash;
    let (kind, icon_kind) = if active {
        (ButtonKind::Primary, ButtonIcon::Refresh)
    } else {
        (ButtonKind::Passive, ButtonIcon::RefreshAccent)
    };
    let resp = paint::button(
        ui,
        button_rect,
        "crypto_rehash",
        d.crypto_rehash_button,
        kind,
        active && vm.controls_enabled,
        icon_kind,
        t::CRYPTO_ACTION,
    );
    if resp.clicked() && active && vm.controls_enabled {
        actions.push(Action::CryptoRehashRequest);
    }
}

/// The largest size <= `style.size` (never below 70%) at which `s` fits in
/// `max_w` — long English/Russian status words shrink instead of clipping.
fn fit_style(p: &Painter, s: &str, style: t::TextStyle, max_w: f32) -> t::TextStyle {
    let w = paint::text_width(p, s, style);
    if w <= max_w || w <= 0.0 {
        return style;
    }
    t::TextStyle {
        size: (style.size * max_w / w).max(style.size * 0.7),
        weight: style.weight,
    }
}

fn draw_hardware(
    ui: &mut Ui,
    o: Pos2,
    vm: &DashboardVm,
    ctl: &mut Controls<'_>,
    actions: &mut Vec<Action>,
) {
    let d = i18n::t(vm.lang);
    let p = ui.painter().clone();
    paint::card(&p, r(o, l::HARDWARE_CARD));
    title(
        &p,
        o,
        l::LEFT_TITLE_X,
        l::HARDWARE_TITLE_BASELINE,
        d.hardware_title,
        t::TITLE_HARDWARE,
    );
    let bx = r(o, l::HW_CHECKBOX);
    let label_w = paint::text_width(&p, d.hardware_include_label, t::CHECK_LABEL);
    let hit = Rect::from_min_max(
        bx.min,
        egui::pos2(mx(o, l::HW_CHECK_LABEL_X) + label_w + 6.0, bx.bottom()),
    );
    if paint::checkbox(
        ui,
        bx,
        *ctl.include_hardware,
        vm.controls_enabled,
        "include_hw",
        hit,
    ) {
        *ctl.include_hardware = !*ctl.include_hardware;
    }
    paint::text(
        &p,
        mx(o, l::HW_CHECK_LABEL_X),
        my(o, l::HW_CHECK_LABEL_BASELINE),
        Align::Min,
        d.hardware_include_label,
        t::CHECK_LABEL,
        c::TEXT_PRIMARY,
    );
    paint::text(
        &p,
        mx(o, l::HW_CAPTION_X),
        my(o, l::HW_CAPTION_BASELINE),
        Align::Min,
        d.hardware_subtitle,
        t::CAPTION,
        c::TEXT_SECONDARY,
    );
    if paint::button(
        ui,
        r(o, l::HW_BUTTON),
        "hw_view",
        d.hardware_view_button,
        ButtonKind::Secondary,
        vm.controls_enabled,
        ButtonIcon::None,
        t::BUTTON_TEXT,
    )
    .clicked()
    {
        actions.push(Action::ViewHardware);
    }
}

fn draw_stages(ui: &mut Ui, o: Pos2, vm: &DashboardVm) {
    let d = i18n::t(vm.lang);
    let p = ui.painter().clone();
    paint::card(&p, r(o, l::STAGES_CARD));
    title(
        &p,
        o,
        l::LEFT_TITLE_X,
        l::STAGES_TITLE_BASELINE,
        &format!("{} ({})", d.stages_title_prefix, vm.stages.len()),
        t::TITLE_STAGES,
    );
    let start = stage_window_start(&vm.stages, l::STAGE_VISIBLE_ROWS);
    for (slot, (i, row)) in vm
        .stages
        .iter()
        .enumerate()
        .skip(start)
        .take(l::STAGE_VISIBLE_ROWS)
        .enumerate()
    {
        let top = l::STAGE_ROW_FIRST_Y + slot as f32 * l::STAGE_ROW_PITCH;
        let row_rect = mrect(o, l::STAGE_ROW_X, top, l::STAGE_ROW_W, l::STAGE_ROW_H);
        if row.active {
            p.rect_filled(row_rect, CornerRadius::same(4), c::BG_ROW_ACTIVE);
        }
        let icon_c = egui::pos2(
            row_rect.left() + l::STAGE_ICON_CENTER_DX,
            row_rect.center().y,
        );
        let d = l::STAGE_ICON_DIAMETER;
        match row.state {
            // v0.4.0 deep-check result on a completed row: the check ran
            // (100%) but found something — yellow warning / red error; an
            // undeterminable result is a muted (not green) check.
            RowState::Done if row.finding == Some(StageFinding::Attention) => {
                let s = d - 1.0;
                let tri = Rect::from_center_size(icon_c + vec2(0.5, 0.0), vec2(s, s * 0.9));
                paint::icon_warning_triangle(&p, tri, c::YELLOW_WARNING, c::BG_ROOT)
            }
            RowState::Done if row.finding == Some(StageFinding::Error) => {
                paint::icon_error(&p, icon_c + vec2(0.5, 0.5), d - 1.0)
            }
            RowState::Done if row.finding == Some(StageFinding::Unknown) => {
                let cc = icon_c + vec2(0.5, 0.5);
                paint::icon_check_circle(&p, cc, d - 1.0, c::TEXT_MUTED)
            }
            RowState::Done => {
                // Master: 21px disc centred on a pixel centre.
                let cc = icon_c + vec2(0.5, 0.5);
                paint::icon_check_circle(&p, cc, d - 1.0, c::GREEN_SUCCESS)
            }
            RowState::Running => {
                // The highlighted (active) row's indicator is 2px larger.
                let da = if row.active { d + 2.0 } else { d };
                paint::icon_radio_active(&p, icon_c, da, c::BLUE_STAGE)
            }
            RowState::Pending => paint::icon_ring(&p, icon_c, d, c::PENDING),
            RowState::Skipped => paint::icon_ring(&p, icon_c, d, c::RADIO_UNSELECTED),
            RowState::Error => paint::icon_error(&p, icon_c, d),
        }
        let baseline = row_rect.top() + l::STAGE_TEXT_BASELINE_DY;
        let text_col = match row.state {
            RowState::Done => c::TEXT_PRIMARY,
            RowState::Running => c::TEXT_STAGE_RUNNING,
            RowState::Pending => c::TEXT_STAGE_PENDING,
            RowState::Skipped => c::TEXT_MUTED,
            RowState::Error => c::RED_ERROR,
        };
        paint::text(
            &p,
            mx(o, l::STAGE_NUMBER_X),
            baseline,
            Align::Min,
            &format!("{:02}", row.number),
            t::BODY_SMALL,
            text_col,
        );
        paint::text_clipped(
            &p,
            mx(o, l::STAGE_LABEL_X),
            baseline,
            l::STAGE_BAR_X - l::STAGE_LABEL_X - 10.0,
            &row.label,
            if row.label.is_ascii() {
                t::STAGE_LABEL_LATIN
            } else {
                t::STAGE_LABEL
            },
            text_col,
        );
        let bar_top = row_rect.top() + l::STAGE_BAR_DY;
        let pending_like = matches!(row.state, RowState::Pending | RowState::Skipped);
        let bar_w = if pending_like {
            l::STAGE_BAR_W_PENDING
        } else {
            l::STAGE_BAR_W
        };
        let bar = Rect::from_min_size(
            egui::pos2(mx(o, l::STAGE_BAR_X), bar_top),
            vec2(bar_w, l::STAGE_BAR_H),
        );
        let fill = stage_bar_color(row.state, vm.time, vm.animate);
        let (style, fraction, anim) = match row.state {
            RowState::Done => (BAR_STAGE, Some(1.0), None),
            RowState::Running => (
                BAR_STAGE,
                row.fraction,
                if vm.animate { Some(vm.time) } else { None },
            ),
            RowState::Error => (BAR_STAGE, Some(1.0), None),
            RowState::Pending | RowState::Skipped => (BAR_STAGE_PENDING, None, None),
        };
        paint::progress_bar(&p, bar, style, fraction, fill, anim);
        if !row.right_text.is_empty() {
            let (x, col, style) = if pending_like {
                (l::STAGE_PENDING_TEXT_X, c::TEXT_PENDING, t::STAGE_PENDING)
            } else if row.state == RowState::Error {
                (l::STAGE_PERCENT_X, c::RED_ERROR, t::BODY_SMALL)
            } else if row.state == RowState::Running {
                (
                    l::STAGE_PERCENT_X,
                    c::TEXT_STAGE_RUNNING_PERCENT,
                    t::BODY_SMALL,
                )
            } else {
                (l::STAGE_PERCENT_X, c::TEXT_PRIMARY, t::BODY_SMALL)
            };
            paint::text(
                &p,
                mx(o, x),
                baseline,
                Align::Min,
                &row.right_text,
                style,
                col,
            );
        }
        ui.interact(row_rect, ui.id().with(("stage_row", i)), Sense::hover())
            .on_hover_text(&row.full_label);
    }
    // "…" row: the stages outside the window, listed on hover.
    let top = l::STAGE_ROW_FIRST_Y + l::STAGE_VISIBLE_ROWS as f32 * l::STAGE_ROW_PITCH;
    let row_rect = mrect(o, l::STAGE_ROW_X, top, l::STAGE_ROW_W, l::STAGE_ROW_H);
    let hidden: Vec<&StageRow> = vm
        .stages
        .iter()
        .enumerate()
        .filter(|(i, _)| *i < start || *i >= start + l::STAGE_VISIBLE_ROWS)
        .map(|(_, r)| r)
        .collect();
    if !hidden.is_empty() {
        let icon_c = egui::pos2(
            row_rect.left() + l::STAGE_ICON_CENTER_DX,
            row_rect.center().y,
        );
        paint::icon_ring(&p, icon_c, l::STAGE_ICON_DIAMETER, c::PENDING);
        paint::text(
            &p,
            mx(o, l::STAGE_NUMBER_X),
            row_rect.top() + l::STAGE_TEXT_BASELINE_DY,
            Align::Min,
            "…",
            t::STAGE_LABEL,
            c::TEXT_STAGE_PENDING,
        );
        let list = hidden
            .iter()
            .map(|r| {
                let st = if r.right_text.is_empty() {
                    d.stage_running
                } else {
                    r.right_text.as_str()
                };
                format!("{:02}  {} — {st}", r.number, r.label)
            })
            .collect::<Vec<_>>()
            .join("\n");
        ui.interact(row_rect, ui.id().with("stage_more"), Sense::hover())
            .on_hover_text(list);
    }
}

/// Running stage bar intensity: a slow, smooth breath between
/// `STAGE_RUNNING_INTENSITY_MIN` and `_MAX` (cosine ease — never a blink).
/// Frozen at the minimum when animation is off (reference mode).
pub(crate) fn running_stage_intensity(time: f64, animate: bool) -> f32 {
    let lo = c::STAGE_RUNNING_INTENSITY_MIN;
    let hi = c::STAGE_RUNNING_INTENSITY_MAX;
    if !animate {
        return lo;
    }
    lo + (hi - lo) * pulse_level(time, c::STAGE_RUNNING_PULSE_PERIOD)
}

/// Stage progress-bar fill: running = restrained blue breathing, done =
/// static quiet green, error = red; information (check icon, text, %) keeps
/// full strength elsewhere.
pub(crate) fn stage_bar_color(state: RowState, time: f64, animate: bool) -> Color32 {
    match state {
        RowState::Running => {
            paint::intensity(c::BLUE_STAGE, running_stage_intensity(time, animate))
        }
        RowState::Done => paint::intensity(c::GREEN_PROGRESS, c::STAGE_DONE_INTENSITY),
        RowState::Error => c::RED_ERROR,
        RowState::Pending | RowState::Skipped => c::BLUE_STAGE,
    }
}

/// First visible stage row: keeps the active (or failed) stage in view with
/// up to two rows of context above it, as in the master (rows 1–5, active 3).
pub fn stage_window_start(rows: &[StageRow], visible: usize) -> usize {
    let focus = rows
        .iter()
        .position(|r| r.active)
        .or_else(|| rows.iter().position(|r| r.state == RowState::Error))
        .or_else(|| rows.iter().position(|r| r.state == RowState::Running))
        // v0.4.0: after the run, a deep-check finding stays in view.
        .or_else(|| {
            rows.iter().position(|r| {
                matches!(
                    r.finding,
                    Some(StageFinding::Error) | Some(StageFinding::Attention)
                )
            })
        });
    let max_start = rows.len().saturating_sub(visible);
    focus
        .map(|f| f.saturating_sub(2))
        .unwrap_or(0)
        .min(max_start)
}

/// 1px perimeter drawn inside `rect` (same place as the widget's own
/// border, so layout never moves) that eases between `base` and `accent`.
fn attention_border(ui: &Ui, rect: Rect, radius: u8, base: Color32, accent: Color32, time: f64) {
    let level = pulse_level(time, l::ATTENTION_PULSE_PERIOD);
    let col = paint::lerp(base, accent, 0.25 + 0.75 * level);
    ui.painter().rect_stroke(
        rect,
        CornerRadius::same(radius),
        Stroke::new(1.0, col),
        StrokeKind::Inside,
    );
    // ~30 fps is plenty for a slow fade and keeps CPU use negligible.
    ui.ctx()
        .request_repaint_after(std::time::Duration::from_millis(33));
}

// ---------------------------------------------------------------------------
// ПРОВЕРКА ДРАЙВЕРОВ (Driver Audit)
// ---------------------------------------------------------------------------

fn driver_status_colors(tone: Tone) -> (Color32, Color32) {
    match tone {
        Tone::Error => (c::DRIVER_STATUS_PROBLEM, c::DRIVER_STATUS_PROBLEM_TEXT),
        Tone::Warning => (c::DRIVER_STATUS_WARN, c::DRIVER_STATUS_WARN_TEXT),
        _ => (c::DRIVER_STATUS_OK, c::DRIVER_STATUS_OK_TEXT),
    }
}

fn device_icon_color(icon: DeviceIcon, tone: Tone) -> Color32 {
    if tone == Tone::Error {
        return c::DRIVER_ICON_PROBLEM;
    }
    match icon {
        DeviceIcon::Gpu => c::DRIVER_ICON_GPU,
        DeviceIcon::Chip => c::DRIVER_ICON_CHIP,
        DeviceIcon::Audio => c::DRIVER_ICON_AUDIO,
        DeviceIcon::Wifi | DeviceIcon::Ethernet => c::DRIVER_ICON_NET,
        DeviceIcon::Storage => c::DRIVER_ICON_STORAGE,
        DeviceIcon::Kernel | DeviceIcon::Generic => c::DRIVER_ICON_OTHER,
    }
}

fn draw_drivers(ui: &mut Ui, o: Pos2, vm: &DashboardVm, actions: &mut Vec<Action>) {
    let d = i18n::t(vm.lang);
    let p = ui.painter().clone();
    paint::card(&p, r(o, l::DRIVERS_CARD));
    let state_c = mpos(
        o,
        l::DRIVERS_STATE_ICON_CENTER[0],
        l::DRIVERS_STATE_ICON_CENTER[1],
    );
    let sd = l::DRIVERS_STATE_ICON_DIAMETER;
    let overall = match &vm.drivers {
        DriversVm::Done { overall, .. } => Some(*overall),
        _ => None,
    };
    match overall {
        Some(Tone::Error) => paint::icon_alert_circle(&p, state_c, sd, c::RED_ERROR),
        Some(Tone::Warning) => paint::icon_warning_triangle(
            &p,
            Rect::from_center_size(state_c, vec2(sd, sd * 0.9)),
            c::YELLOW_WARNING,
            c::BG_CARD,
        ),
        Some(_) => paint::icon_check_circle(&p, state_c, sd - 2.0, c::GREEN_SUCCESS),
        None => paint::icon_ring(&p, state_c, sd - 2.0, c::PENDING),
    }
    title(
        &p,
        o,
        l::DRIVERS_TITLE_X,
        l::DRIVERS_TITLE_BASELINE,
        d.driver_title,
        t::TITLE_DRIVERS,
    );
    let details_enabled = !matches!(vm.drivers, DriversVm::Running);
    if paint::button(
        ui,
        r(o, l::DRIVERS_BUTTON),
        "drivers_details",
        d.driver_details_button,
        ButtonKind::Secondary,
        details_enabled,
        ButtonIcon::None,
        t::BUTTON_TEXT,
    )
    .clicked()
    {
        actions.push(Action::ShowDrivers);
    }
    let row_b = |k: usize| {
        my(
            o,
            l::DRIVER_ROW_FIRST_BASELINE + k as f32 * l::DRIVER_ROW_PITCH,
        )
    };
    let name_w = l::DRIVER_VERSION_X - l::DRIVER_NAME_X - 8.0;
    let ver_w = l::DRIVER_STATUS_ICON_CENTER_X
        - l::DRIVER_STATUS_ICON_DIAMETER / 2.0
        - l::DRIVER_VERSION_X
        - 6.0;
    match &vm.drivers {
        DriversVm::Running => {
            paint::text(
                &p,
                mx(o, l::DRIVER_NAME_X),
                row_b(0),
                Align::Min,
                d.driver_running,
                t::DRIVER_NAME,
                c::TEXT_SECONDARY,
            );
            paint::text(
                &p,
                mx(o, l::DRIVER_NAME_X),
                row_b(1),
                Align::Min,
                d.driver_readonly_note,
                t::CAPTION,
                c::TEXT_MUTED,
            );
            let bar = Rect::from_min_size(
                egui::pos2(mx(o, l::DRIVER_NAME_X), row_b(2) - 8.0),
                vec2(mx(o, l::DRIVER_ROW_RIGHT_X) - mx(o, l::DRIVER_NAME_X), 10.0),
            );
            paint::progress_bar(
                &p,
                bar,
                BAR_STAGE,
                None,
                c::BLUE_STAGE,
                if vm.animate { Some(vm.time) } else { None },
            );
        }
        DriversVm::Unavailable(msg) => {
            paint::text(
                &p,
                mx(o, l::DRIVER_NAME_X),
                row_b(0),
                Align::Min,
                d.driver_unavailable,
                t::DRIVER_NAME,
                c::TEXT_SECONDARY,
            );
            paint::text_clipped(
                &p,
                mx(o, l::DRIVER_NAME_X),
                row_b(1),
                mx(o, l::DRIVER_ROW_RIGHT_X) - mx(o, l::DRIVER_NAME_X),
                msg,
                t::CAPTION,
                c::TEXT_MUTED,
            );
        }
        DriversVm::Done {
            rows,
            more,
            alert,
            ok_line,
            ..
        } => {
            let max_rows = if *more > 0 {
                l::DRIVER_ROWS_MAX - 1
            } else {
                l::DRIVER_ROWS_MAX
            };
            for (k, row) in rows.iter().take(max_rows).enumerate() {
                let b = row_b(k);
                let cy = b - 5.5;
                paint::icon_device(
                    &p,
                    egui::pos2(mx(o, l::DRIVER_ICON_CENTER_X), cy),
                    l::DRIVER_ICON_SIZE,
                    row.icon,
                    device_icon_color(row.icon, row.tone),
                );
                let name_col = if row.tone == Tone::Error {
                    c::DRIVER_NAME_PROBLEM
                } else {
                    c::DRIVER_NAME
                };
                paint::text_clipped(
                    &p,
                    mx(o, l::DRIVER_NAME_X),
                    b,
                    name_w,
                    &row.name,
                    t::DRIVER_NAME,
                    name_col,
                );
                paint::text_clipped(
                    &p,
                    mx(o, l::DRIVER_VERSION_X),
                    b,
                    ver_w,
                    &row.version,
                    t::DRIVER_VERSION,
                    c::DRIVER_VERSION,
                );
                let (icol, tcol) = driver_status_colors(row.tone);
                let sc = egui::pos2(mx(o, l::DRIVER_STATUS_ICON_CENTER_X), cy);
                let sdia = l::DRIVER_STATUS_ICON_DIAMETER;
                match row.tone {
                    Tone::Error => {
                        p.circle_filled(sc, sdia / 2.0, icol);
                    }
                    Tone::Warning => paint::icon_warning_triangle(
                        &p,
                        Rect::from_center_size(sc, vec2(sdia + 1.0, sdia)),
                        icol,
                        c::BG_CARD,
                    ),
                    _ => paint::icon_check_circle(&p, sc, sdia, icol),
                }
                paint::text(
                    &p,
                    mx(o, l::DRIVER_STATUS_TEXT_X),
                    b,
                    Align::Min,
                    &row.status_text,
                    t::DRIVER_STATUS,
                    tcol,
                );
                let hit = Rect::from_min_max(
                    egui::pos2(mx(o, l::DRIVER_ROW_LEFT_X), b - 17.0),
                    egui::pos2(mx(o, l::DRIVER_ROW_RIGHT_X), b + 7.0),
                );
                ui.interact(hit, ui.id().with(("driver_row", k)), Sense::hover())
                    .on_hover_text(&row.tooltip);
            }
            if *more > 0 {
                let b = row_b(max_rows);
                paint::text(
                    &p,
                    mx(o, l::DRIVER_NAME_X),
                    b,
                    Align::Min,
                    &format!(
                        "… {more} {} — {}",
                        d.driver_more_suffix, d.driver_details_button
                    ),
                    t::DRIVER_NAME,
                    c::TEXT_SECONDARY,
                );
            }
            let box_r = r(o, l::DRIVERS_ALERT);
            match alert {
                Some((tone, l1, l2)) => {
                    let (fill, border, icon, t1, t2) = if *tone == Tone::Error {
                        (
                            c::ALERT_PROBLEM_FILL,
                            c::ALERT_PROBLEM_BORDER,
                            c::ALERT_PROBLEM_ICON,
                            c::ALERT_PROBLEM_TEXT_1,
                            c::ALERT_PROBLEM_TEXT_2,
                        )
                    } else {
                        (
                            c::ALERT_WARN_FILL,
                            c::ALERT_WARN_BORDER,
                            c::ALERT_WARN_ICON,
                            c::ALERT_WARN_TEXT_1,
                            c::ALERT_WARN_TEXT_2,
                        )
                    };
                    p.rect(
                        box_r,
                        CornerRadius::same(l::DRIVERS_ALERT_RADIUS),
                        fill,
                        Stroke::new(1.0, border),
                        StrokeKind::Inside,
                    );
                    paint::icon_warning_triangle(&p, r(o, l::DRIVERS_ALERT_ICON), icon, fill);
                    let tw = box_r.right() - mx(o, l::DRIVERS_ALERT_TEXT_X) - 10.0;
                    for (line, (b, col)) in [l1, l2]
                        .iter()
                        .zip(l::DRIVERS_ALERT_BASELINES.iter().zip([t1, t2]))
                    {
                        paint::text_clipped(
                            &p,
                            mx(o, l::DRIVERS_ALERT_TEXT_X),
                            my(o, *b),
                            tw,
                            line,
                            t::ALERT_TEXT,
                            col,
                        );
                    }
                }
                None => {
                    // Calm green state: no alarm strip.
                    let cy = box_r.center().y;
                    paint::icon_check_ring(
                        &p,
                        egui::pos2(mx(o, l::DRIVERS_STATE_ICON_CENTER[0]), cy),
                        18.0,
                        c::DRIVER_STATUS_OK,
                    );
                    paint::text_clipped(
                        &p,
                        mx(o, l::DRIVERS_ALERT_TEXT_X),
                        cy + 5.0,
                        box_r.right() - mx(o, l::DRIVERS_ALERT_TEXT_X) - 10.0,
                        ok_line,
                        t::ALERT_TEXT,
                        c::DRIVER_STATUS_OK_TEXT,
                    );
                }
            }
        }
    }
}

fn draw_result(ui: &mut Ui, o: Pos2, vm: &DashboardVm, actions: &mut Vec<Action>) {
    let d = i18n::t(vm.lang);
    let p = ui.painter().clone();
    paint::card(&p, r(o, l::RESULT_CARD));
    title(
        &p,
        o,
        l::LEFT_TITLE_X,
        l::RESULT_TITLE_BASELINE,
        d.result_title,
        t::TITLE_RESULT,
    );
    let icon = r(o, l::RESULT_ICON);
    let x = mx(o, l::RESULT_TEXT_X);
    let b1 = my(o, l::RESULT_LINE_BASELINES[0]);
    let b2 = my(o, l::RESULT_LINE_BASELINES[1]);
    let card_right = mx(o, l::RESULT_CARD[0] + l::RESULT_CARD[2]) - l::CARD_PADDING_X_LEFT_COL;
    match &vm.result {
        ResultVm::Idle => {
            paint::icon_document(&p, icon, c::TEXT_PRIMARY);
            paint::text(
                &p,
                x,
                b1,
                Align::Min,
                d.result_idle,
                t::BODY,
                c::TEXT_PRIMARY,
            );
            paint::text(
                &p,
                x,
                b2,
                Align::Min,
                d.result_idle_hint,
                t::BODY_SECONDARY,
                c::TEXT_SECONDARY,
            );
        }
        ResultVm::Running => {
            paint::icon_document(&p, icon, c::BLUE_ACCENT);
            paint::text(
                &p,
                x,
                b1,
                Align::Min,
                d.result_running,
                t::BODY,
                c::TEXT_PRIMARY,
            );
            paint::text(
                &p,
                x,
                b2,
                Align::Min,
                d.result_running_hint,
                t::BODY_SECONDARY,
                c::TEXT_SECONDARY,
            );
        }
        ResultVm::Done {
            path_display,
            attention,
        } => {
            paint::icon_document(&p, icon, c::GREEN_SUCCESS);
            let b_open_folder = r(o, l::RESULT_BUTTON_FOLDER);
            let b_open = r(o, l::RESULT_BUTTON_REPORT);
            paint::text(
                &p,
                x,
                b1,
                Align::Min,
                d.result_ready,
                t::BODY_STRONG,
                c::GREEN_SUCCESS,
            );
            paint::text_clipped(
                &p,
                x,
                b2,
                b_open.left() - x - 10.0,
                path_display,
                t::BODY_SECONDARY,
                c::TEXT_SECONDARY,
            );
            let open_resp = paint::button(
                ui,
                b_open,
                "open_report",
                d.result_open_report_button,
                ButtonKind::Secondary,
                true,
                ButtonIcon::None,
                t::BUTTON_TEXT,
            );
            if *attention && vm.animate && !open_resp.hovered() {
                attention_border(
                    ui,
                    b_open,
                    l::BUTTON_RADIUS,
                    c::BUTTON_SECONDARY_BORDER,
                    c::ATTENTION_REPORT,
                    vm.time,
                );
            }
            if open_resp.clicked() {
                actions.push(Action::OpenReport);
            }
            let folder_resp = paint::button(
                ui,
                b_open_folder,
                "open_folder",
                d.result_open_folder_button,
                ButtonKind::Secondary,
                true,
                ButtonIcon::None,
                t::BUTTON_TEXT,
            );
            if !folder_resp.hovered() {
                ui.painter().rect_stroke(
                    b_open_folder,
                    CornerRadius::same(l::BUTTON_RADIUS),
                    Stroke::new(1.0, c::ACCENT_FOLDER),
                    StrokeKind::Inside,
                );
            }
            if folder_resp.clicked() {
                actions.push(Action::OpenFolder);
            }
        }
        ResultVm::Failed { message } => {
            paint::icon_error(&p, icon.center(), 30.0);
            paint::text(
                &p,
                x,
                b1,
                Align::Min,
                d.result_failed,
                t::BODY_STRONG,
                c::RED_ERROR,
            );
            let resp = ui.interact(
                Rect::from_min_max(egui::pos2(x, b2 - 16.0), egui::pos2(card_right, b2 + 4.0)),
                ui.id().with("result_err"),
                Sense::hover(),
            );
            paint::text_clipped(
                &p,
                x,
                b2,
                card_right - x,
                message,
                t::BODY_SECONDARY,
                c::RED_ERROR,
            );
            resp.on_hover_text(message);
        }
    }
}

fn draw_start(ui: &mut Ui, o: Pos2, vm: &DashboardVm, actions: &mut Vec<Action>) {
    let d = i18n::t(vm.lang);
    let full = r(o, l::START_BUTTON);
    // While EXPC runs, a compact square Stop button takes the right end of
    // the start button's own slot (no other element moves).
    let rect = if vm.stop_enabled {
        let side = full.height();
        let stop = Rect::from_min_size(
            egui::pos2(full.right() - side, full.top()),
            vec2(side, side),
        );
        let resp = paint::button(
            ui,
            stop,
            "stop",
            "",
            ButtonKind::Secondary,
            true,
            ButtonIcon::None,
            t::BUTTON_TEXT_LARGE,
        );
        let square = Rect::from_center_size(stop.center(), vec2(13.0, 13.0));
        ui.painter()
            .rect_filled(square, CornerRadius::same(2), c::RED_ERROR);
        if resp.on_hover_text(d.stop_hover).clicked() {
            actions.push(Action::Stop);
        }
        Rect::from_min_max(full.min, egui::pos2(stop.left() - 8.0, full.bottom()))
    } else {
        full
    };
    match vm.start {
        StartVm::Start { enabled } => {
            if paint::button(
                ui,
                rect,
                "start",
                d.start_button,
                ButtonKind::Primary,
                enabled,
                ButtonIcon::Play,
                t::BUTTON_TEXT_LARGE,
            )
            .clicked()
            {
                actions.push(Action::Start);
            }
        }
        StartVm::Running => {
            paint::button(
                ui,
                rect,
                "start",
                d.start_running_button,
                ButtonKind::Primary,
                false,
                ButtonIcon::None,
                t::BUTTON_TEXT_LARGE,
            );
        }
        StartVm::NewDiagnostic => {
            if paint::button(
                ui,
                rect,
                "start",
                d.new_diagnostics_button,
                ButtonKind::Primary,
                true,
                ButtonIcon::Play,
                t::BUTTON_TEXT_LARGE,
            )
            .clicked()
            {
                actions.push(Action::Reset);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Right column
// ---------------------------------------------------------------------------

fn tone_color(tone: Tone) -> Color32 {
    match tone {
        Tone::Idle => c::TEXT_PRIMARY,
        Tone::Running => c::BLUE_STATUS,
        Tone::Success => c::GREEN_SUCCESS,
        Tone::Warning => c::YELLOW_WARNING,
        Tone::Error => c::RED_ERROR,
    }
}

fn draw_overall(ui: &mut Ui, o: Pos2, vm: &DashboardVm) {
    let d = i18n::t(vm.lang);
    let p = ui.painter().clone();
    let ov = &vm.overall;
    paint::card(&p, r(o, l::OVERALL_CARD));
    title(
        &p,
        o,
        l::RIGHT_TITLE_X,
        l::OVERALL_TITLE_BASELINE,
        d.overall_title,
        t::TITLE_OVERALL,
    );

    // Ring (geometry per master: centre, outer diameter, stroke).
    let center = mpos(o, l::OVERALL_RING_CENTER[0], l::OVERALL_RING_CENTER[1]);
    let th = l::OVERALL_RING_ACTIVE_THICKNESS;
    let r_mid = l::OVERALL_RING_OUTER_DIAMETER / 2.0 - th / 2.0;
    paint::ring_track(
        &p,
        center,
        r_mid,
        l::OVERALL_RING_TRACK_THICKNESS,
        c::RING_TRACK,
    );
    let frac = ov.fraction.clamp(0.0, 1.0);
    if frac > 0.0005 {
        let a0 = l::OVERALL_RING_START_DEG;
        let a1 = a0 + 360.0 * frac;
        let tone = ov.tone;
        let color_at = move |deg: f32| -> Color32 {
            // Restrained ring: the 100% / status text carries the message.
            let k = c::OVERALL_RING_INTENSITY;
            match tone {
                Tone::Success => paint::intensity(c::GREEN_SUCCESS, k),
                Tone::Error => paint::intensity(c::RED_ERROR, k.max(0.8)),
                _ => {
                    let base = paint::conic(
                        &[
                            (0.0, c::RING_BLUE_START),
                            (45.0, Color32::from_rgb(0x00, 0x7a, 0xff)),
                            (90.0, Color32::from_rgb(0x00, 0xbe, 0xfd)),
                            (180.0, c::RING_BLUE_PEAK),
                            (360.0, c::RING_BLUE_PEAK),
                        ],
                        deg,
                    );
                    // The master darkens slightly towards the leading end.
                    let tail = ((deg - (a1 - 18.0)) / 18.0).clamp(0.0, 1.0);
                    paint::intensity(
                        paint::lerp(base, Color32::from_rgb(0x00, 0x9c, 0xfc), tail),
                        k,
                    )
                }
            }
        };
        paint::arc_band(&p, center, r_mid, th, a0, a1, color_at);
        // Round leading cap, flat start (as in the master).
        p.circle_filled(paint::polar(center, r_mid, a1), th / 2.0, color_at(a1));
    }
    paint::text(
        &p,
        center.x,
        my(o, l::OVERALL_PERCENT_BASELINE),
        Align::Center,
        &ov.percent_text,
        t::METRIC_LARGE,
        c::TEXT_HEADLINE,
    );
    paint::text(
        &p,
        center.x,
        my(o, l::OVERALL_STATUS_BASELINE),
        Align::Center,
        &ov.status_text,
        t::RING_STATUS,
        c::TEXT_PRIMARY,
    );

    // Time block.
    paint::icon_clock(&p, r(o, l::TIME_ICON_CLOCK), c::ICON_TIME);
    paint::icon_hourglass(&p, r(o, l::TIME_ICON_HOURGLASS), c::ICON_TIME);
    let tx = mx(o, l::TIME_TEXT_X);
    paint::text(
        &p,
        tx,
        my(o, l::TIME_LABEL_BASELINES[0]),
        Align::Min,
        d.overall_elapsed,
        t::TIME_LABEL,
        c::TEXT_MUTED,
    );
    paint::text(
        &p,
        tx,
        my(o, l::TIME_VALUE_BASELINES[0]),
        Align::Min,
        &ov.elapsed,
        t::METRIC_SMALL,
        c::TEXT_PRIMARY,
    );
    paint::text(
        &p,
        tx,
        my(o, l::TIME_LABEL_BASELINES[1]),
        Align::Min,
        d.overall_eta,
        t::TIME_LABEL,
        c::TEXT_SECONDARY,
    );
    paint::text(
        &p,
        tx,
        my(o, l::TIME_VALUE_BASELINES[1]),
        Align::Min,
        &ov.eta,
        t::METRIC_SMALL,
        c::TEXT_PRIMARY,
    );

    // Modules (inner card inside the same overall card).
    paint::inner_card(&p, r(o, l::MODULES_CARD));
    paint::text(
        &p,
        mx(o, l::MODULES_TITLE_X),
        my(o, l::MODULES_TITLE_BASELINE),
        Align::Min,
        d.overall_modules_title,
        t::SECTION_TITLE,
        c::TEXT_TITLE,
    );
    for (i, m) in ov.modules.iter().take(3).enumerate() {
        let row = mrect(
            o,
            l::MODULE_ROW_X,
            l::MODULE_ROWS_Y[i],
            l::MODULE_ROW_W,
            l::MODULE_ROW_H,
        );
        let fill = if m.state == ModuleState::Running {
            c::BG_ROW_ACTIVE_SOFT
        } else {
            c::BG_ROW
        };
        p.rect_filled(row, CornerRadius::same(l::ROW_RADIUS), fill);
        let ic = egui::pos2(mx(o, l::MODULE_ICON_CENTER_X), row.center().y);
        let md = l::MODULE_ICON_DIAMETER;
        match m.state {
            ModuleState::Done => paint::icon_check_circle(&p, ic, md, c::GREEN_SUCCESS),
            ModuleState::Running => paint::icon_radio_active(&p, ic, md, c::BLUE_ACCENT),
            ModuleState::Pending => paint::icon_ring(&p, ic, md, c::PENDING_MODULE),
            ModuleState::NotSelected => paint::icon_ring(&p, ic, md, c::RADIO_UNSELECTED),
            ModuleState::Error => paint::icon_error(&p, ic, md),
        }
        let baseline = row.top() + l::MODULE_TEXT_BASELINE_DY;
        let label_col = if m.state == ModuleState::NotSelected {
            c::TEXT_MUTED
        } else {
            c::TEXT_PRIMARY
        };
        paint::text(
            &p,
            mx(o, l::MODULE_LABEL_X),
            baseline,
            Align::Min,
            &m.label,
            t::BODY,
            label_col,
        );
        let status_col = match m.state {
            ModuleState::Done => c::GREEN_SUCCESS,
            ModuleState::Running => c::BLUE_STATUS,
            ModuleState::Error => c::RED_ERROR,
            ModuleState::Pending | ModuleState::NotSelected => c::TEXT_MUTED,
        };
        paint::text(
            &p,
            mx(o, l::MODULE_STATUS_RIGHT_X),
            baseline,
            Align::Max,
            &m.status_text,
            t::MUTED,
            status_col,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn dual_ring(
    p: &Painter,
    center: Pos2,
    label: &str,
    label_col: Color32,
    current: &str,
    current_col: Color32,
    previous: Option<&str>,
    previous_col: Color32,
    outer_stops: &[(f32, Color32)],
    inner_stops: &[(f32, Color32)],
    inner_track: Color32,
    o: Pos2,
) {
    // Rings are context, the numbers are the information: thinner, quieter
    // outer (current) ring, and an even quieter inner (previous) arc.
    let outer_r = l::RING_OUTER_DIAMETER / 2.0 - l::RING_OUTER_STROKE / 2.0;
    paint::arc_band(p, center, outer_r, l::RING_OUTER_STROKE, 0.0, 360.0, |d| {
        paint::intensity(paint::conic(outer_stops, d), c::RW_RING_INTENSITY)
    });
    let inner_r = l::RING_INNER_DIAMETER / 2.0 - l::RING_INNER_STROKE / 2.0;
    paint::ring_track(p, center, inner_r, l::RING_INNER_TRACK_STROKE, inner_track);
    if previous.is_some() {
        let [a0, a1] = l::RING_INNER_ARC_DEG;
        let inner_col =
            |d: f32| paint::intensity(paint::conic(inner_stops, d), c::RW_PREVIOUS_RING_INTENSITY);
        paint::arc_band(p, center, inner_r, l::RING_INNER_STROKE, a0, a1, inner_col);
        for a in [a0, a1] {
            p.circle_filled(
                paint::polar(center, inner_r, a),
                l::RING_INNER_STROKE / 2.0,
                inner_col(a),
            );
        }
    }
    paint::text(
        p,
        center.x,
        my(o, l::RING_LABEL_BASELINE),
        Align::Center,
        label,
        t::SSD_RING_LABEL,
        label_col,
    );
    let vx = center.x + l::RING_VALUE_DX;
    paint::text(
        p,
        vx,
        my(o, l::RING_CURRENT_BASELINE),
        Align::Center,
        current,
        t::SSD_CURRENT,
        current_col,
    );
    if let Some(prev) = previous {
        paint::text(
            p,
            vx,
            my(o, l::RING_PREVIOUS_BASELINE),
            Align::Center,
            prev,
            t::SSD_PREVIOUS,
            previous_col,
        );
    }
    if current != "—" {
        paint::text(
            p,
            center.x,
            my(o, l::RING_UNIT_BASELINE),
            Align::Center,
            "MB/s",
            t::SSD_UNIT,
            c::TEXT_BODY,
        );
    }
}

fn delta_text(p: &Painter, o: Pos2, center_x: f32, delta: Option<f64>) {
    if let Some(d) = delta {
        let col = if d >= 0.0 {
            c::GREEN_DELTA
        } else {
            c::TEXT_PRIMARY
        };
        paint::text(
            p,
            center_x,
            my(o, l::RING_DELTA_BASELINE),
            Align::Center,
            &format!("{d:+.1}%"),
            t::DELTA,
            col,
        );
    }
}

/// The FIXED SSD slot geometry (explicit correction): three card positions
/// are always reserved so the section never reflows when a third SSD
/// appears or disappears; four or more SSDs use a compact 2x2 grid inside
/// the SAME band (the first four; a "+N" caption reports the rest).
fn ssd_slot_rects(o: Pos2, n: usize) -> Vec<Rect> {
    if n >= 4 {
        let mut v = Vec::with_capacity(4);
        for y in l::SSD_SLOT_GRID_Y {
            for x in l::SSD_SLOT_GRID_X {
                v.push(mrect(o, x, y, l::SSD_SLOT_GRID_W, l::SSD_SLOT_GRID_H));
            }
        }
        v
    } else {
        l::SSD_SLOT_X
            .iter()
            .map(|x| mrect(o, *x, l::SSD_SLOT_Y, l::SSD_SLOT_W, l::SSD_SLOT_H))
            .collect()
    }
}

/// Rects of the slots actually occupied by the `n` eligible SSD/NVMe
/// disks (in candidate order: system disk first). Never more than 4.
fn ssd_disk_card_rects(o: Pos2, n: usize) -> Vec<Rect> {
    ssd_slot_rects(o, n).into_iter().take(n.min(4)).collect()
}

fn slot_pos(rect: Rect, rel: [f32; 2]) -> Pos2 {
    rect.min + vec2(rel[0], rel[1])
}

/// One clickable physical-disk card: selection mark, icon (Windows logo for
/// the system disk, neutral disk glyph otherwise), "letter + real volume
/// label", model and bus type. Selected = VERY THIN gold border and a gold
/// check disc; unselected = normal subdued border and an empty ring.
#[allow(clippy::too_many_arguments)]
fn draw_disk_card(
    ui: &mut Ui,
    p: &Painter,
    rect: Rect,
    entry: &DiskEntryVm,
    idx: usize,
    selected: bool,
    compact: bool,
    controls_enabled: bool,
    actions: &mut Vec<Action>,
) {
    let border = if selected {
        c::GOLD_ACCENT
    } else {
        c::BORDER_NORMAL
    };
    p.rect(
        rect,
        CornerRadius::same(6),
        c::BG_CARD_INNER,
        Stroke::new(1.0, border),
        StrokeKind::Inside,
    );
    let (dim, soft) = if entry.has_target {
        (c::TEXT_PRIMARY, c::TEXT_BODY)
    } else {
        (c::TEXT_MUTED, c::TEXT_MUTED)
    };
    let letter_line = |p: &Painter, x: f32, b: f32, max_w: f32| {
        let lr = paint::text(
            p,
            x,
            b,
            Align::Min,
            &entry.drive_letter,
            t::SSD_DISK_LETTER,
            dim,
        );
        if let Some(label) = entry.volume_label.as_deref() {
            let lx = lr.right() + 8.0;
            paint::text_clipped(
                p,
                lx,
                b,
                (x + max_w - lx).max(0.0),
                label,
                t::SSD_DISK_VOLUME_LABEL,
                soft,
            );
        }
    };
    if compact {
        let mark = rect.min + vec2(14.0, rect.height() / 2.0);
        if selected {
            paint::icon_check_circle(p, mark, 17.0, c::GOLD_ACCENT);
        } else {
            paint::icon_ring(p, mark, 17.0, c::PENDING);
        }
        let ic = rect.min + vec2(44.0, rect.height() / 2.0);
        if entry.is_system {
            paint::icon_windows_logo(p, ic, 24.0, c::BLUE_ACCENT);
        } else {
            paint::icon_disk_neutral(p, ic, 26.0, c::TEXT_BODY);
        }
        let x = rect.min.x + 68.0;
        let w = rect.right() - 8.0 - x;
        let cy = rect.center().y;
        letter_line(p, x, cy - 3.0, w);
        paint::text_clipped(p, x, cy + 16.0, w, &entry.model, t::SSD_DISK_BUS, soft);
    } else {
        let mark = slot_pos(rect, l::SSD_SLOT_MARK_CENTER);
        if selected {
            paint::icon_check_circle(p, mark, l::SSD_SLOT_MARK_DIAMETER, c::GOLD_ACCENT);
        } else {
            paint::icon_ring(p, mark, l::SSD_SLOT_MARK_DIAMETER, c::PENDING);
        }
        let ic = slot_pos(rect, l::SSD_SLOT_ICON_CENTER);
        if entry.is_system {
            paint::icon_windows_logo(p, ic, l::SSD_SLOT_ICON_SIZE, c::BLUE_ACCENT);
        } else {
            paint::icon_disk_neutral(p, ic, l::SSD_SLOT_ICON_SIZE, c::TEXT_BODY);
        }
        let x = rect.min.x + l::SSD_SLOT_TEXT_DX;
        let w = rect.right() - 8.0 - x;
        let [b0, b1, b2] = l::SSD_SLOT_BASELINES_DY;
        letter_line(p, x, rect.min.y + b0, w);
        paint::text_clipped(
            p,
            x,
            rect.min.y + b1,
            w,
            &entry.model,
            t::SSD_DISK_MODEL,
            soft,
        );
        paint::text_clipped(
            p,
            x,
            rect.min.y + b2,
            w,
            &format!("SSD · {}", entry.interface),
            t::SSD_DISK_BUS,
            c::TEXT_SECONDARY,
        );
    }
    if controls_enabled {
        let resp = ui.interact(rect, egui::Id::new(("ssd_disk_card", idx)), Sense::click());
        if resp.clicked() {
            actions.push(Action::SelectSsdDisk(idx));
        }
    }
}

/// A reserved slot with no eligible SSD/NVMe in it: neutral, never a
/// fabricated drive letter, never an HDD.
fn draw_empty_slot(p: &Painter, rect: Rect, text: &str) {
    p.rect(
        rect,
        CornerRadius::same(6),
        c::BG_CARD,
        Stroke::new(1.0, c::SSD_SLOT_EMPTY_BORDER),
        StrokeKind::Inside,
    );
    paint::icon_ring(
        p,
        slot_pos(rect, l::SSD_SLOT_MARK_CENTER),
        l::SSD_SLOT_MARK_DIAMETER,
        c::SSD_SLOT_EMPTY_BORDER,
    );
    paint::icon_disk_neutral(
        p,
        slot_pos(rect, l::SSD_SLOT_ICON_CENTER),
        l::SSD_SLOT_ICON_SIZE,
        c::SSD_SLOT_EMPTY_BORDER,
    );
    let x = rect.min.x + l::SSD_SLOT_TEXT_DX;
    paint::text_clipped(
        p,
        x,
        rect.min.y + l::SSD_SLOT_BASELINES_DY[1],
        rect.right() - 10.0 - x,
        text,
        t::SSD_DISK_MODEL,
        c::SSD_SLOT_EMPTY_TEXT,
    );
}

/// Selected Drive Information panel (always visible, as in the master):
/// the selected disk's read-only facts, its state, and the neutral note
/// about the temporary benchmark file (the path itself is never shown).
fn draw_disk_info_panel(
    d: &crate::i18n::Dict,
    p: &Painter,
    o: Pos2,
    entry: Option<&DiskEntryVm>,
    state_text: &str,
    state_col: Color32,
    note: [&str; 2],
    note_col: Color32,
) {
    let panel = r(o, l::SSD_INFO_PANEL);
    p.rect(
        panel,
        CornerRadius::same(l::INNER_CARD_RADIUS),
        c::BG_CARD_INNER,
        Stroke::new(1.0, c::BORDER_NORMAL),
        StrokeKind::Inside,
    );
    paint::text_clipped(
        p,
        mx(o, l::SSD_INFO_TITLE_X),
        my(o, l::SSD_INFO_TITLE_BASELINE),
        panel.right() - 10.0 - mx(o, l::SSD_INFO_TITLE_X),
        d.ssd_info_title,
        t::SECTION_TITLE,
        c::TEXT_TITLE,
    );
    let info_b = |i: usize| my(o, l::SSD_INFO_FIRST_BASELINE + i as f32 * l::SSD_INFO_PITCH);
    let label_x = mx(o, l::SSD_INFO_LABEL_X);
    let value_x = mx(o, l::SSD_INFO_VALUE_X);
    let value_w = panel.right() - 10.0 - value_x;
    let dash = "—".to_string();
    let rows: [(&str, String, Color32); 4] = match entry {
        Some(e) => [
            (d.ssd_model_label, e.model.clone(), c::TEXT_PRIMARY),
            (d.ssd_capacity_label, e.capacity.clone(), c::TEXT_PRIMARY),
            (d.ssd_interface_label, e.interface.clone(), c::TEXT_PRIMARY),
            (
                d.ssd_serial_label,
                e.serial
                    .clone()
                    .unwrap_or_else(|| d.ssd_serial_unreported.into()),
                c::TEXT_BODY,
            ),
        ],
        None => [
            (d.ssd_model_label, dash.clone(), c::TEXT_MUTED),
            (d.ssd_capacity_label, dash.clone(), c::TEXT_MUTED),
            (d.ssd_interface_label, dash.clone(), c::TEXT_MUTED),
            (d.ssd_serial_label, dash, c::TEXT_MUTED),
        ],
    };
    let label_w = value_x - label_x - 6.0;
    for (i, (label, value, col)) in rows.iter().enumerate() {
        let b = info_b(i);
        paint::text_clipped(
            p,
            label_x,
            b,
            label_w,
            label,
            t::SSD_META_LABEL,
            c::TEXT_SECONDARY,
        );
        paint::text_clipped(p, value_x, b, value_w, value, t::SSD_META_VALUE, *col);
    }
    let b = info_b(4);
    paint::text_clipped(
        p,
        label_x,
        b,
        label_w,
        d.ssd_status_label,
        t::SSD_META_LABEL,
        c::TEXT_SECONDARY,
    );
    let dot = l::SSD_INFO_DOT_DIAMETER;
    p.circle_filled(
        egui::pos2(value_x + dot / 2.0, b - 5.5),
        dot / 2.0,
        state_col,
    );
    paint::text_clipped(
        p,
        value_x + dot + 13.0,
        b,
        value_w - dot - 13.0,
        state_text,
        t::SSD_META_VALUE,
        c::TEXT_PRIMARY,
    );
    let note_r = r(o, l::SSD_INFO_NOTE);
    p.rect(
        note_r,
        CornerRadius::same(5),
        c::BG_CARD,
        Stroke::new(1.0, c::BORDER_INNER),
        StrokeKind::Inside,
    );
    let ic = mpos(
        o,
        l::SSD_INFO_NOTE_ICON_CENTER[0],
        l::SSD_INFO_NOTE_ICON_CENTER[1],
    );
    paint::circle_outline(p, ic, 12.0, 1.4, c::TEXT_SECONDARY);
    p.circle_filled(ic + vec2(0.0, -5.0), 1.5, c::TEXT_SECONDARY);
    p.line_segment(
        [ic + vec2(0.0, -1.5), ic + vec2(0.0, 6.0)],
        Stroke::new(1.8, c::TEXT_SECONDARY),
    );
    let nx = mx(o, l::SSD_INFO_NOTE_TEXT_X);
    let nw = note_r.right() - 8.0 - nx;
    for (line, b) in note.iter().zip(l::SSD_INFO_NOTE_BASELINES) {
        paint::text_clipped(p, nx, my(o, b), nw, line, t::SSD_NOTE, note_col);
    }
}

/// Lower metadata strip: Profile | Passes | Duration (row 1) and
/// Read spread | Write spread | Stability (row 2). Labels always shown in
/// the current language; values are "—" until the selected disk has a
/// result (never another disk's values).
fn draw_ssd_meta_strip(p: &Painter, o: Pos2, d: &crate::i18n::Dict, meta: Option<&[MetaRow]>) {
    let strip = r(o, l::SSD_META_STRIP);
    p.rect(
        strip,
        CornerRadius::same(5),
        c::BG_CARD_INNER,
        Stroke::new(1.0, c::BORDER_NORMAL),
        StrokeKind::Inside,
    );
    let mid_y = strip.center().y.round() + 0.5;
    p.line_segment(
        [
            egui::pos2(strip.left() + 1.0, mid_y),
            egui::pos2(strip.right() - 1.0, mid_y),
        ],
        Stroke::new(1.0, c::BORDER_INNER),
    );
    for x in &l::SSD_META_COL_X[1..] {
        let xx = mx(o, *x).round() + 0.5;
        p.line_segment(
            [
                egui::pos2(xx, strip.top() + 6.0),
                egui::pos2(xx, strip.bottom() - 6.0),
            ],
            Stroke::new(1.0, c::BORDER_INNER),
        );
    }
    let labels = [
        d.ssd_profile_label,
        d.ssd_passes_label,
        d.ssd_duration_label,
        d.ssd_read_spread_label,
        d.ssd_write_spread_label,
        d.ssd_stability_label,
    ];
    for (i, dict_label) in labels.iter().enumerate() {
        // The result rows carry their own (already localized) labels; the
        // dictionary supplies them while there is no result yet.
        let label = meta
            .and_then(|m| m.get(i))
            .map(|m| m.label.as_str())
            .unwrap_or(dict_label);
        let (row, col) = (i / 3, i % 3);
        let x0 = mx(o, l::SSD_META_COL_X[col]);
        let b = my(o, l::SSD_META_BASELINES[row]);
        let lx = x0 + l::SSD_META_LABEL_DX;
        let vx = x0 + l::SSD_META_VALUE_DX;
        let cell_right = x0 + l::SSD_META_COL_W - 8.0;
        paint::text_clipped(
            p,
            lx,
            b,
            vx - lx - 6.0,
            &format!("{label}:"),
            t::SSD_STRIP_LABEL,
            c::TEXT_SECONDARY,
        );
        match meta.and_then(|m| m.get(i)) {
            Some(row) => {
                let colr = tone_color(row.value_tone);
                let mut x = vx;
                if row.dot {
                    p.circle_filled(egui::pos2(x + 7.0, b - 5.0), 7.0, colr);
                    x += 20.0;
                }
                paint::text_clipped(
                    p,
                    x,
                    b,
                    cell_right - x,
                    &row.value,
                    t::SSD_STRIP_VALUE,
                    if row.value_tone == Tone::Idle {
                        c::TEXT_PRIMARY
                    } else {
                        colr
                    },
                );
            }
            None => {
                paint::text(p, vx, b, Align::Min, "—", t::SSD_STRIP_VALUE, c::TEXT_MUTED);
            }
        }
    }
}

fn draw_ssd(
    ui: &mut Ui,
    o: Pos2,
    vm: &DashboardVm,
    ctl: &mut Controls<'_>,
    actions: &mut Vec<Action>,
) {
    let _ = &ctl; // benchmark_path stays an internal implementation detail.
    let d = i18n::t(vm.lang);
    let p = ui.painter().clone();
    paint::card(&p, r(o, l::SSD_CARD));
    title(
        &p,
        o,
        l::SSD_TITLE_X,
        l::SSD_TITLE_BASELINE,
        d.ssd_title,
        t::TITLE_SSD,
    );

    // Physical-disk selector: always three reserved slots (or a 2x2 grid
    // for four), visible in every state, so the section never reflows. No
    // dropdown, no click-to-cycle — a direct click selects exactly that disk.
    let disk_count = vm.ssd_disks.len();
    paint::text_clipped(
        &p,
        mx(o, l::SSD_SUBTITLE_X),
        my(o, l::SSD_SUBTITLE_BASELINE),
        mx(o, l::SSD_CARD[0] + l::SSD_CARD[2]) - 16.0 - mx(o, l::SSD_SUBTITLE_X),
        if disk_count == 0 {
            d.ssd_none_detected
        } else {
            d.ssd_subtitle
        },
        t::BODY,
        c::TEXT_BODY,
    );
    let slots = ssd_slot_rects(o, disk_count);
    let compact = disk_count >= 4;
    for (idx, rect) in slots.iter().enumerate() {
        match vm.ssd_disks.get(idx) {
            Some(entry) => draw_disk_card(
                ui,
                &p,
                *rect,
                entry,
                idx,
                idx == vm.ssd_selected,
                compact,
                vm.ssd_controls_enabled,
                actions,
            ),
            None => draw_empty_slot(&p, *rect, d.ssd_empty_slot),
        }
    }
    if disk_count > 4 {
        paint::text(
            &p,
            mx(o, l::SSD_CARD[0] + l::SSD_CARD[2]) - 16.0,
            my(o, l::SSD_SUBTITLE_BASELINE),
            Align::Max,
            &format!("+{} {}", disk_count - 4, d.ssd_overflow_suffix),
            t::CAPTION,
            c::TEXT_MUTED,
        );
    }

    // READ/WRITE group frame + the orthogonal selection connector.
    let frame = r(o, l::SSD_RING_FRAME);
    let selected_rect = ssd_disk_card_rects(o, disk_count)
        .get(vm.ssd_selected)
        .copied();
    let frame_col = if selected_rect.is_some() {
        c::GOLD_ACCENT
    } else {
        c::BORDER_NORMAL
    };
    p.rect_stroke(
        frame,
        CornerRadius::same(8),
        Stroke::new(1.0, frame_col),
        StrokeKind::Inside,
    );
    let div_x = frame.center().x.round() + 0.5;
    p.line_segment(
        [
            egui::pos2(div_x, frame.top() + 16.0),
            egui::pos2(div_x, frame.bottom() - 16.0),
        ],
        Stroke::new(1.0, c::BORDER_INNER),
    );
    if let Some(sel) = selected_rect {
        draw_ssd_connector(&p, sel, frame);
    }

    let selected_disk = vm.ssd_disks.get(vm.ssd_selected);
    let rc = mpos(o, l::READ_RING_CENTER[0], l::READ_RING_CENTER[1]);
    let wc = mpos(o, l::WRITE_RING_CENTER[0], l::WRITE_RING_CENTER[1]);
    let temp_note = [d.ssd_temp_note_line1, d.ssd_temp_note_line2];
    let placeholder_rings = |p: &Painter| {
        dual_ring(
            p,
            rc,
            "READ",
            c::READ_LABEL,
            "—",
            c::TEXT_MUTED,
            None,
            c::TEXT_MUTED,
            &c::READ_RING_STOPS,
            &c::READ_PREVIOUS_ARC_STOPS,
            c::VIOLET_TRACK,
            o,
        );
        dual_ring(
            p,
            wc,
            "WRITE",
            c::WRITE_LABEL,
            "—",
            c::TEXT_MUTED,
            None,
            c::TEXT_MUTED,
            &c::WRITE_RING_STOPS,
            &c::WRITE_PREVIOUS_ARC_STOPS,
            c::TEAL_TRACK,
            o,
        );
    };
    // The disk is ready for (another) test unless it has no writable volume.
    let ready_state = || -> (String, Color32) {
        match selected_disk {
            Some(sd) if !sd.has_target => (d.ssd_state_no_target.into(), c::YELLOW_WARNING),
            Some(_) => (d.ssd_state_ready.into(), c::GREEN_SUCCESS),
            None => (d.ssd_state_unavailable.into(), c::TEXT_MUTED),
        }
    };
    let can_start = vm.ssd_controls_enabled && selected_disk.is_some_and(|d| d.has_target);
    let primary = r(o, l::SSD_BUTTON_PRIMARY);
    let secondary = r(o, l::SSD_BUTTON_SECONDARY);

    match &vm.ssd {
        SsdVm::Done {
            read_current,
            read_previous,
            read_delta,
            write_current,
            write_previous,
            write_delta,
            meta,
        } => {
            dual_ring(
                &p,
                rc,
                "READ",
                c::READ_LABEL,
                read_current,
                c::READ_CURRENT,
                read_previous.as_deref(),
                c::READ_PREVIOUS_TEXT,
                &c::READ_RING_STOPS,
                &c::READ_PREVIOUS_ARC_STOPS,
                c::VIOLET_TRACK,
                o,
            );
            dual_ring(
                &p,
                wc,
                "WRITE",
                c::WRITE_LABEL,
                write_current,
                c::WRITE_CURRENT,
                write_previous.as_deref(),
                c::WRITE_PREVIOUS_TEXT,
                &c::WRITE_RING_STOPS,
                &c::WRITE_PREVIOUS_ARC_STOPS,
                c::TEAL_TRACK,
                o,
            );
            delta_text(&p, o, rc.x, *read_delta);
            delta_text(&p, o, wc.x, *write_delta);
            let (st, sc) = ready_state();
            draw_disk_info_panel(d, &p, o, selected_disk, &st, sc, temp_note, c::TEXT_MUTED);
            draw_ssd_meta_strip(&p, o, d, Some(meta));
            if paint::button(
                ui,
                primary,
                "bench_rerun",
                d.ssd_rerun_button,
                ButtonKind::Primary,
                can_start,
                ButtonIcon::Play,
                t::BUTTON_TEXT,
            )
            .clicked()
            {
                actions.push(Action::BenchmarkStart);
            }
            if paint::button(
                ui,
                secondary,
                "bench_raw",
                d.ssd_details_button,
                ButtonKind::Secondary,
                true,
                ButtonIcon::None,
                t::BUTTON_TEXT,
            )
            .clicked()
            {
                actions.push(Action::ShowRawPasses);
            }
        }
        SsdVm::Idle | SsdVm::Cancelled | SsdVm::Failed(_) => {
            placeholder_rings(&p);
            let (state_text, state_col): (String, Color32) = match &vm.ssd {
                SsdVm::Failed(_) => (d.ssd_state_error.into(), c::RED_ERROR),
                SsdVm::Cancelled => (d.ssd_state_cancelled.into(), c::TEXT_SECONDARY),
                _ => ready_state(),
            };
            let (note, note_col) = match &vm.ssd {
                SsdVm::Failed(msg) => ([msg.as_str(), ""], c::RED_ERROR),
                _ => (temp_note, c::TEXT_MUTED),
            };
            draw_disk_info_panel(
                d,
                &p,
                o,
                selected_disk,
                &state_text,
                state_col,
                note,
                note_col,
            );
            draw_ssd_meta_strip(&p, o, d, None);
            let label = if matches!(vm.ssd, SsdVm::Idle) {
                d.ssd_start_button
            } else {
                d.ssd_rerun_button
            };
            if paint::button(
                ui,
                primary,
                "bench_start",
                label,
                ButtonKind::Primary,
                can_start,
                ButtonIcon::Play,
                t::BUTTON_TEXT,
            )
            .clicked()
            {
                actions.push(Action::BenchmarkStart);
            }
            // Same row geometry in every state: Details is present but only
            // meaningful once this disk has a result.
            paint::button(
                ui,
                secondary,
                "bench_raw",
                d.ssd_details_button,
                ButtonKind::Secondary,
                false,
                ButtonIcon::None,
                t::BUTTON_TEXT,
            );
        }
        SsdVm::Running {
            fraction,
            status,
            elapsed,
        } => {
            placeholder_rings(&p);
            draw_disk_info_panel(
                d,
                &p,
                o,
                selected_disk,
                status,
                c::BLUE_STATUS,
                temp_note,
                c::TEXT_MUTED,
            );
            draw_ssd_meta_strip(&p, o, d, None);
            // Progress lives in the delta line of the frame (no delta yet).
            let bar = Rect::from_min_size(
                egui::pos2(frame.left() + 24.0, my(o, l::RING_DELTA_BASELINE) - 10.0),
                vec2(frame.width() - 48.0 - 110.0, 8.0),
            );
            paint::progress_bar(
                &p,
                bar,
                BAR_STAGE,
                Some(*fraction),
                paint::intensity(c::BLUE_STAGE, running_stage_intensity(vm.time, vm.animate)),
                None,
            );
            paint::text(
                &p,
                frame.right() - 24.0,
                my(o, l::RING_DELTA_BASELINE) - 1.0,
                Align::Max,
                &format!("{} {elapsed}", d.ssd_elapsed_prefix),
                t::CAPTION,
                c::TEXT_SECONDARY,
            );
            paint::button(
                ui,
                primary,
                "bench_start",
                d.ssd_state_running,
                ButtonKind::Primary,
                false,
                ButtonIcon::None,
                t::BUTTON_TEXT,
            );
            if paint::button(
                ui,
                secondary,
                "bench_cancel",
                d.ssd_cancel_button,
                ButtonKind::Secondary,
                true,
                ButtonIcon::None,
                t::BUTTON_TEXT,
            )
            .clicked()
            {
                actions.push(Action::BenchmarkCancel);
            }
        }
    }
}

fn draw_journal(ui: &mut Ui, o: Pos2, vm: &DashboardVm, actions: &mut Vec<Action>) {
    let d = i18n::t(vm.lang);
    let p = ui.painter().clone();
    paint::card(&p, r(o, l::JOURNAL_CARD));
    title(
        &p,
        o,
        l::RIGHT_TITLE_X,
        l::JOURNAL_TITLE_BASELINE,
        d.journal_title,
        t::TITLE_JOURNAL,
    );
    // v0.3.7: the complete session journal opens in its own window. Always
    // available (the session journal outlives Clear and new runs).
    if paint::button(
        ui,
        r(o, l::JOURNAL_OPEN_BUTTON),
        "journal_open",
        d.journal_open_button,
        ButtonKind::Subtle,
        true,
        ButtonIcon::None,
        t::BUTTON_TEXT_SMALL,
    )
    .clicked()
    {
        actions.push(Action::OpenJournal);
    }
    if paint::button(
        ui,
        r(o, l::JOURNAL_CLEAR_BUTTON),
        "journal_clear",
        d.journal_clear_button,
        ButtonKind::Subtle,
        !vm.journal.is_empty(),
        ButtonIcon::Trash,
        t::BUTTON_TEXT_SMALL,
    )
    .clicked()
    {
        actions.push(Action::ClearLog);
    }
    let panel = r(o, l::JOURNAL_PANEL);
    p.rect(
        panel,
        CornerRadius::same(4),
        c::BG_JOURNAL,
        Stroke::new(1.0, c::BORDER_JOURNAL),
        StrokeKind::Inside,
    );
    let first_row_top = my(o, l::JOURNAL_FIRST_BASELINE) - l::JOURNAL_LINE_BASELINE_DY;
    // Custom always-visible scrollbar at the master position.
    let bar = Rect::from_min_max(
        egui::pos2(mx(o, l::JOURNAL_SCROLLBAR_X[0]), panel.top() + 2.0),
        egui::pos2(mx(o, l::JOURNAL_SCROLLBAR_X[1]), panel.bottom() - 2.0),
    );
    let inner = Rect::from_min_max(
        egui::pos2(panel.left() + 1.0, first_row_top),
        egui::pos2(bar.left() - 2.0, panel.bottom() - 3.0),
    );
    let ts_dx = mx(o, l::JOURNAL_TIMESTAMP_X) - inner.left();
    let msg_dx = mx(o, l::JOURNAL_MESSAGE_X) - inner.left();

    let scroll_id = ui.id().with("journal_scroll_request");
    let request: Option<f32> = ui.data_mut(|d| d.remove_temp(scroll_id));
    let mut state = (0.0_f32, 1.0_f32, 1.0_f32); // offset, content, viewport
    if vm.journal.is_empty() {
        paint::text(
            &p,
            inner.left() + ts_dx,
            first_row_top + l::JOURNAL_LINE_BASELINE_DY,
            Align::Min,
            d.journal_empty,
            t::MONO,
            c::JOURNAL_MESSAGE_DIM,
        );
    } else {
        ui.scope_builder(UiBuilder::new().max_rect(inner).id_salt("journal"), |ui| {
            ui.style_mut().spacing.item_spacing = vec2(0.0, 0.0);
            let mut area = egui::ScrollArea::vertical()
                .id_salt("journal_area")
                .auto_shrink([false, false])
                .stick_to_bottom(vm.journal_follow_tail)
                .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysHidden);
            if let Some(offset) = request {
                area = area.vertical_scroll_offset(offset);
            }
            let out = area.show_rows(ui, l::JOURNAL_LINE_PITCH, vm.journal.len(), |ui, range| {
                for line in &vm.journal[range] {
                    let (row, _) = ui.allocate_exact_size(
                        vec2(ui.available_width(), l::JOURNAL_LINE_PITCH),
                        Sense::hover(),
                    );
                    let pp = ui.painter();
                    let b = row.top() + l::JOURNAL_LINE_BASELINE_DY;
                    paint::text(
                        pp,
                        row.left() + ts_dx,
                        b,
                        Align::Min,
                        &line.timestamp,
                        t::MONO,
                        c::JOURNAL_TIMESTAMP,
                    );
                    let col = if line.dim {
                        c::JOURNAL_MESSAGE_DIM
                    } else {
                        c::JOURNAL_MESSAGE
                    };
                    paint::text_clipped(
                        pp,
                        row.left() + msg_dx,
                        b,
                        row.width() - msg_dx - 6.0,
                        &line.message,
                        t::MONO,
                        col,
                    );
                }
            });
            state = (
                out.state.offset.y,
                out.content_size.y.max(1.0),
                out.inner_rect.height().max(1.0),
            );
        });
    }
    if let Some(offset) = journal_scrollbar(ui, bar, state) {
        ui.data_mut(|d| d.insert_temp(scroll_id, offset));
        ui.ctx().request_repaint();
    }
}

/// Master-style scrollbar: outlined track, arrow glyphs, rounded thumb
/// proportional to the visible fraction. Returns a new scroll offset when
/// the user drags the thumb or clicks an arrow.
fn journal_scrollbar(
    ui: &mut Ui,
    bar: Rect,
    (offset, content, viewport): (f32, f32, f32),
) -> Option<f32> {
    let p = ui.painter().clone();
    p.rect(
        bar,
        CornerRadius::same(4),
        c::SCROLL_TRACK,
        Stroke::new(1.0, c::SCROLL_TRACK_BORDER),
        StrokeKind::Inside,
    );
    let arrow_h = 14.0;
    let cx = bar.center().x;
    let up = Rect::from_min_size(bar.min, vec2(bar.width(), arrow_h));
    let down = Rect::from_min_size(
        egui::pos2(bar.left(), bar.bottom() - arrow_h),
        vec2(bar.width(), arrow_h),
    );
    p.add(egui::Shape::convex_polygon(
        vec![
            egui::pos2(cx, up.top() + 5.0),
            egui::pos2(cx + 4.5, up.top() + 10.0),
            egui::pos2(cx - 4.5, up.top() + 10.0),
        ],
        c::SCROLL_ARROW,
        Stroke::NONE,
    ));
    p.add(egui::Shape::convex_polygon(
        vec![
            egui::pos2(cx - 4.5, down.bottom() - 10.0),
            egui::pos2(cx + 4.5, down.bottom() - 10.0),
            egui::pos2(cx, down.bottom() - 5.0),
        ],
        c::SCROLL_ARROW,
        Stroke::NONE,
    ));
    let track = Rect::from_min_max(
        egui::pos2(bar.left() + 1.0, up.bottom() + 1.0),
        egui::pos2(bar.right() - 1.0, down.top() - 1.0),
    );
    let max_offset = (content - viewport).max(0.0);
    let visible = (viewport / content).clamp(0.0, 1.0);
    let thumb_h = (track.height() * visible).max(20.0).min(track.height());
    let travel = track.height() - thumb_h;
    let t = if max_offset > 0.0 {
        offset / max_offset
    } else {
        0.0
    };
    let thumb = Rect::from_min_size(
        egui::pos2(track.left(), track.top() + travel * t),
        vec2(track.width(), thumb_h),
    );
    let thumb_resp = ui.interact(thumb, ui.id().with("journal_thumb"), Sense::drag());
    let fill = if thumb_resp.hovered() || thumb_resp.dragged() {
        c::SCROLL_THUMB_HOVER
    } else {
        c::SCROLL_THUMB
    };
    p.rect_filled(thumb, CornerRadius::same(6), fill);
    let mut new_offset = None;
    if thumb_resp.dragged() && travel > 0.0 {
        let dy = thumb_resp.drag_delta().y;
        new_offset = Some((offset + dy / travel * max_offset).clamp(0.0, max_offset));
    }
    let line = l::JOURNAL_LINE_PITCH;
    if ui
        .interact(up, ui.id().with("journal_up"), Sense::click())
        .clicked()
    {
        new_offset = Some((offset - line).clamp(0.0, max_offset));
    }
    if ui
        .interact(down, ui.id().with("journal_down"), Sense::click())
        .clicked()
    {
        new_offset = Some((offset + line).clamp(0.0, max_offset));
    }
    new_offset
}

// ---------------------------------------------------------------------------
// Status bar
// ---------------------------------------------------------------------------

fn draw_status_bar(ui: &mut Ui, o: Pos2, vm: &DashboardVm) {
    let p = ui.painter();
    let sep_y = my(o, l::STATUS_SEPARATOR_Y) + 0.5;
    let x0 = mx(o, l::STATUS_BAR[0]);
    let x1 = mx(o, l::STATUS_BAR_RIGHT_EDGE_X);
    p.rect_filled(r(o, l::STATUS_BAR), CornerRadius::ZERO, c::STATUS_BAR_FILL);
    p.line_segment(
        [egui::pos2(x0, sep_y), egui::pos2(x1, sep_y)],
        Stroke::new(1.0, c::STATUS_BAR_SEPARATOR),
    );
    let b = my(o, l::STATUS_BASELINE);
    // Right-hand segments first, so the left (Current Operation) text can
    // be clipped to whatever room remains.
    let mut x = mx(o, l::STATUS_TEXT_RIGHT_X);
    let gap = 11.0;
    for (i, seg) in vm.status_right.iter().enumerate().rev() {
        let rect = paint::text(p, x, b, Align::Max, seg, t::STATUS_BAR, c::STATUS_BAR_TEXT);
        x = rect.left() - gap;
        if i > 0 {
            p.line_segment(
                [egui::pos2(x + 0.5, b - 12.0), egui::pos2(x + 0.5, b + 3.0)],
                Stroke::new(1.0, c::STATUS_BAR_DIVIDER),
            );
            x -= gap;
        }
    }
    // Current Operation (compact, as in the master's footer): the running
    // step with its own progress, or the final state ("Диагностика
    // завершена" / "Diagnostics completed").
    let left_x = mx(o, l::STATUS_TEXT_LEFT_X);
    let running = vm.operation.tone == Tone::Running;
    let bar_room = if running {
        l::STATUS_OP_BAR_W + 16.0
    } else {
        0.0
    };
    let max_w = (x - 24.0 - left_x - bar_room).max(40.0);
    let text_col = match vm.operation.tone {
        Tone::Error => c::RED_ERROR,
        Tone::Warning => c::YELLOW_WARNING,
        _ => c::STATUS_BAR_TEXT,
    };
    let tr = paint::text_clipped(
        p,
        left_x,
        b,
        max_w,
        &vm.status_left,
        t::STATUS_LEFT,
        text_col,
    );
    if running {
        let bar = Rect::from_min_size(
            egui::pos2(tr.right() + 14.0, b - 4.0 - l::STATUS_OP_BAR_H / 2.0),
            vec2(l::STATUS_OP_BAR_W, l::STATUS_OP_BAR_H),
        );
        let anim = if vm.operation.indeterminate && vm.animate {
            Some(vm.time)
        } else {
            None
        };
        paint::progress_bar(
            p,
            bar,
            BAR_STAGE,
            vm.operation.fraction,
            paint::intensity(
                c::BLUE_PROGRESS,
                running_stage_intensity(vm.time, vm.animate),
            ),
            anim,
        );
    }
}

/// v0.3.6 Visual Master alignment (§7, supersedes the earlier diagonal
/// connector): a strictly orthogonal "schematic" connection from the
/// selected disk card's center-bottom down into the yellow READ/WRITE
/// frame's center-top — a single vertical segment when the card is already
/// aligned with the frame, otherwise a vertical/horizontal/vertical dog-leg.
/// Never a diagonal, never a curve, never an arrowhead.
fn draw_ssd_connector(p: &Painter, card: Rect, ring_frame: Rect) {
    let pts = ssd_connector_points(card, ring_frame);
    let stroke = Stroke::new(1.0, c::GOLD_ACCENT);
    for pair in pts.windows(2) {
        p.line_segment([pair[0], pair[1]], stroke);
    }
}

/// The connector's vertices, orthogonal-only: 2 points (a straight vertical
/// run) when the card is already aligned with the ring frame, otherwise 4
/// points (vertical / horizontal / vertical).
fn ssd_connector_points(card: Rect, ring_frame: Rect) -> Vec<Pos2> {
    let from = egui::pos2(card.center().x, card.max.y);
    let to = egui::pos2(ring_frame.center().x, ring_frame.min.y);
    if (from.x - to.x).abs() < 0.5 {
        return vec![from, to];
    }
    let mid_y = (from.y + to.y) / 2.0;
    vec![from, egui::pos2(from.x, mid_y), egui::pos2(to.x, mid_y), to]
}

/// Test-only exposure of the connector's vertex list (v0.3.6 §7/§28): used
/// to assert every segment is axis-aligned (no diagonal) and the origin
/// tracks the selected card.
#[cfg(test)]
pub(crate) fn ssd_connector_points_for_tests(card: Rect, ring_frame: Rect) -> Vec<Pos2> {
    ssd_connector_points(card, ring_frame)
}

/// Test-only exposure of the private SSD disk-card layout so app-level
/// tests (v0.3.6 §15/§16/§28) can assert on the coordinate math without
/// rendering — `ssd_disk_card_rects` itself stays private since it is only
/// ever otherwise called from `draw_ssd` in this module.
#[cfg(test)]
pub(crate) fn ssd_disk_card_rects_for_tests(o: Pos2, n: usize) -> Vec<Rect> {
    ssd_disk_card_rects(o, n)
}

/// Test-only exposure of the READ/WRITE frame (connector target).
#[cfg(test)]
pub(crate) fn ssd_ring_group_rect_for_tests(o: Pos2) -> Rect {
    r(o, l::SSD_RING_FRAME)
}

/// Test-only: the fixed reserved SSD slots for `n` eligible disks.
#[cfg(test)]
pub(crate) fn ssd_slot_rects_for_tests(o: Pos2, n: usize) -> Vec<Rect> {
    ssd_slot_rects(o, n)
}

/// Test-only: the READ and WRITE outer ring bounding boxes.
#[cfg(test)]
pub(crate) fn ssd_ring_rects_for_tests(o: Pos2) -> [Rect; 2] {
    let d = l::RING_OUTER_DIAMETER;
    [l::READ_RING_CENTER, l::WRITE_RING_CENTER]
        .map(|c| Rect::from_center_size(mpos(o, c[0], c[1]), vec2(d, d)))
}

/// Compact-language-control geometry: both RU/EN buttons keep an equal,
/// compact footprint with a visible horizontal gap between them.
#[cfg(test)]
pub(crate) fn lang_button_rects_for_tests() -> (Rect, Rect) {
    (
        r(Pos2::ZERO, l::LANG_BUTTON_RU),
        r(Pos2::ZERO, l::LANG_BUTTON_EN),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rows(active: Option<usize>) -> Vec<StageRow> {
        (0..14)
            .map(|i| StageRow {
                number: i + 1,
                label: String::new(),
                full_label: String::new(),
                state: match active {
                    Some(a) if i < a => RowState::Done,
                    Some(a) if i == a => RowState::Running,
                    _ => RowState::Pending,
                },
                fraction: None,
                right_text: String::new(),
                active: active == Some(i),
                finding: None,
            })
            .collect()
    }

    #[test]
    fn lang_buttons_are_compact_equal_and_do_not_overlap() {
        let (ru, en) = lang_button_rects_for_tests();
        assert_eq!(ru.width(), en.width());
        assert_eq!(ru.height(), en.height());
        // Explicit correction: ~30–40% larger than the 30x18 (540 px²)
        // compact pass, yet still well under the original 42x22 (924 px²).
        let area = ru.width() * ru.height();
        assert!((540.0 * 1.3..=540.0 * 1.4).contains(&area), "area {area}");
        assert!(area < 924.0);
        // The whole [RU][EN][EXPC] group shares one vertical centre line.
        let logo = r(Pos2::ZERO, l::EXPC_HEADER_LOGO);
        assert!((ru.center().y - logo.center().y).abs() <= 1.0);
        assert!((en.center().y - logo.center().y).abs() <= 1.0);
        assert!(en.max.x < logo.min.x, "EN must sit left of the EXPC logo");
        assert!(ru.max.x <= en.min.x, "RU and EN must not overlap");
    }

    #[test]
    fn active_language_is_gold_and_inactive_is_subdued_blue_never_green() {
        let (active_border, active_text) = lang_button_colors(true);
        let (idle_border, idle_text) = lang_button_colors(false);
        assert_eq!(active_border, c::GOLD_ACCENT);
        assert_eq!(active_text, c::GOLD_ACCENT);
        assert_ne!(active_border, c::GREEN_SUCCESS);
        // Gold: red and green high, blue low.
        let [r0, g0, b0, _] = active_border.to_array();
        assert!(r0 > 180 && g0 > 150 && b0 < 90);
        // Inactive: blue-dominant.
        let [r1, g1, b1, _] = idle_border.to_array();
        assert!(b1 > r1 && b1 > g1);
        assert_ne!(idle_text, c::GOLD_ACCENT);
    }

    #[test]
    fn running_stage_breathes_blue_within_bounds_and_done_stays_static_green() {
        let lo = c::STAGE_RUNNING_INTENSITY_MIN;
        let hi = c::STAGE_RUNNING_INTENSITY_MAX;
        assert!((lo - 0.65).abs() < 1e-6 && (hi - 0.75).abs() < 1e-6);
        let mut seen_lo = f32::MAX;
        let mut seen_hi = f32::MIN;
        let mut prev = running_stage_intensity(0.0, true);
        for i in 0..400 {
            let k = running_stage_intensity(i as f64 * 0.02, true);
            assert!((lo - 1e-4..=hi + 1e-4).contains(&k), "intensity {k}");
            // Smooth breathing: no jump bigger than a small step per 20 ms.
            assert!((k - prev).abs() < 0.01, "pulse jumped {prev} -> {k}");
            prev = k;
            seen_lo = seen_lo.min(k);
            seen_hi = seen_hi.max(k);
        }
        assert!(
            seen_lo < lo + 0.01 && seen_hi > hi - 0.01,
            "pulse spans the range"
        );
        // Running = blue family, animated.
        let a = stage_bar_color(RowState::Running, 0.0, true);
        let b = stage_bar_color(RowState::Running, c::STAGE_RUNNING_PULSE_PERIOD / 2.0, true);
        assert_ne!(a, b);
        for col in [a, b] {
            let [r0, g0, b0, _] = col.to_array();
            assert!(b0 > r0 && b0 >= g0, "running bar must stay blue: {col:?}");
        }
        // Done = static quiet green (60%), identical at any time.
        let done0 = stage_bar_color(RowState::Done, 0.0, true);
        for i in 0..50 {
            assert_eq!(
                stage_bar_color(RowState::Done, i as f64 * 0.37, true),
                done0
            );
        }
        assert_eq!(done0, paint::intensity(c::GREEN_PROGRESS, 0.60));
        let [r0, g0, b0, _] = done0.to_array();
        assert!(g0 > r0 && g0 > b0);
        assert!(
            g0 < c::GREEN_PROGRESS.to_array()[1],
            "quieter than full green"
        );
    }

    #[test]
    fn stage_window_follows_active_stage() {
        assert_eq!(stage_window_start(&rows(None), 5), 0);
        assert_eq!(stage_window_start(&rows(Some(2)), 5), 0);
        assert_eq!(stage_window_start(&rows(Some(7)), 5), 5);
        assert_eq!(stage_window_start(&rows(Some(13)), 5), 9);
    }
}
