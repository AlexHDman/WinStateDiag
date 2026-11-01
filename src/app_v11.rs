//! v1.1 final integration: CryptoPro Details (presence, version, licence,
//! HASH, time, source, errors; ReHash behind a warning + explicit
//! confirmation) and the Driver Audit check history.

use super::*;

/// What the Driver Audit history header asked for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HistoryAct {
    Copy,
    SaveReport,
    ClearRequest,
    ClearConfirmed,
    ClearCancelled,
}

/// One label / value row of the CryptoPro Details window.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CryptoDetailRow {
    pub label: String,
    pub value: String,
    pub tone: Tone,
    /// v1.1: exact text of the row's own [Копировать] button (the full
    /// licence number); `None` = no button.
    pub copy: Option<String>,
    /// v1.1: what the window-wide Copy text uses instead of `value`
    /// (the masked licence key); `None` = `value`.
    pub export_value: Option<String>,
}

impl WinStateDiagApp {
    /// The CryptoPro Details rows — the same model feeds the window and
    /// its Copy text (licence and HASH are separate rows, never merged).
    pub(crate) fn crypto_detail_rows(&self) -> Vec<CryptoDetailRow> {
        let d = i18n::t(self.language);
        let row = |label: &str, value: String, tone: Tone| CryptoDetailRow {
            label: label.to_string(),
            value,
            tone,
            copy: None,
            export_value: None,
        };
        let busy = self.crypto_rx.is_some();
        let mut rows = Vec::new();
        let product = self.crypto_inventory.as_ref().map(|i| i.product.as_ref());
        rows.push(row(
            d.crypto_det_presence,
            match product {
                _ if busy && self.crypto_inventory.is_none() => d.crypto_det_pending.to_string(),
                None => d.crypto_det_not_checked.to_string(),
                Some(Some(_)) => d.crypto_det_installed.to_string(),
                Some(None) => d.crypto_det_absent.to_string(),
            },
            match product {
                Some(Some(_)) => Tone::Success,
                _ => Tone::Idle,
            },
        ));
        if let Some(Some(p)) = product {
            rows.push(row(
                d.crypto_det_version,
                if p.version.is_empty() {
                    d.crypto_det_version_unknown.to_string()
                } else {
                    format!("{} ({})", p.version, p.name)
                },
                Tone::Idle,
            ));
            // v1.1 UI contract: the full number as read from the registry
            // (never guessed) with its own exact Copy; the masked form is
            // what the window-wide Copy text and any journal carry.
            rows.push(match &p.license {
                cryptopro::LicenseKey::Installed { masked, full } => CryptoDetailRow {
                    copy: Some(full.reveal().to_string()),
                    export_value: Some(masked.clone()),
                    ..row(
                        d.crypto_det_license,
                        d.crypto_det_license_key_fmt.replace("{key}", full.reveal()),
                        Tone::Idle,
                    )
                },
                cryptopro::LicenseKey::NotFound => row(
                    d.crypto_det_license,
                    d.crypto_det_license_none.to_string(),
                    Tone::Warning,
                ),
                cryptopro::LicenseKey::Unreadable(e) => row(
                    d.crypto_det_license,
                    d.crypto_det_license_unreadable_fmt.replace("{error}", e),
                    Tone::Warning,
                ),
            });
            rows.push(row(
                d.crypto_det_term,
                match p.term {
                    cryptopro::LicenseTerm::NotDetermined => d.crypto_det_term_unknown.to_string(),
                },
                Tone::Idle,
            ));
        }
        let (hash, tone) = match (&self.crypto, busy) {
            (None, true) => (d.crypto_checking.to_string(), Tone::Running),
            (None, false) => (d.crypto_not_checked.to_string(), Tone::Idle),
            (Some(cryptopro::HashState::HashOk), _) => ("HASH OK".to_string(), Tone::Success),
            (Some(cryptopro::HashState::NoHash), _) => ("NO HASH".to_string(), Tone::Warning),
            (Some(cryptopro::HashState::NotInstalled), _) => {
                (d.crypto_not_installed.to_string(), Tone::Idle)
            }
            (Some(cryptopro::HashState::CheckError(_)), _) => {
                (d.crypto_check_error.to_string(), Tone::Warning)
            }
        };
        rows.push(row(d.crypto_det_hash, hash, tone));
        rows.push(row(
            d.crypto_det_verifier,
            match &self.crypto_detection {
                cryptopro::Detection::Installed(exe) => exe.display().to_string(),
                cryptopro::Detection::NoVerifier(_) => d.crypto_det_verifier_missing.to_string(),
                cryptopro::Detection::NotInstalled => "—".to_string(),
            },
            Tone::Idle,
        ));
        rows.push(row(
            d.crypto_det_checked,
            self.crypto_checked
                .as_ref()
                .map(|s| s.full(d))
                .unwrap_or_else(|| "—".to_string()),
            Tone::Idle,
        ));
        rows.push(row(
            d.crypto_det_source,
            d.crypto_det_source_value.to_string(),
            Tone::Idle,
        ));
        let mut errors: Vec<String> = Vec::new();
        if let Some(cryptopro::HashState::CheckError(e)) = &self.crypto {
            errors.push(e.clone());
        }
        if let cryptopro::Detection::NoVerifier(dir) = &self.crypto_detection {
            errors.push(format!(
                "{} ({})",
                d.crypto_det_verifier_missing,
                dir.display()
            ));
        }
        rows.push(row(
            d.crypto_det_errors,
            if errors.is_empty() {
                d.crypto_det_no_errors.to_string()
            } else {
                errors.join("; ")
            },
            if errors.is_empty() {
                Tone::Idle
            } else {
                Tone::Warning
            },
        ));
        if let Some(last) = &self.crypto_last_rehash {
            rows.push(row(d.crypto_det_last_rehash, last.clone(), Tone::Idle));
        }
        rows
    }

    /// Copy text of the CryptoPro Details window.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn crypto_details_text(&self) -> String {
        let d = i18n::t(self.language);
        let mut out = format!("{}\r\n", d.crypto_details_title);
        for r in self.crypto_detail_rows() {
            let value = r.export_value.as_ref().unwrap_or(&r.value);
            out.push_str(&format!("{}: {}\r\n", r.label, value));
        }
        out
    }

    /// v1.1 CryptoPro Details window: facts + Copy / Close, and — apart
    /// from them — «Выполнить ReHash», which only opens a warning that the
    /// user must confirm explicitly.
    pub(crate) fn crypto_details_window(&mut self, ctx: &egui::Context) {
        if !self.crypto_details_open {
            return;
        }
        let d = i18n::t(self.language);
        let rows = self.crypto_detail_rows();
        let status = self.crypto_export_status.as_ref().map(|s| s.text(d));
        let mut open = true;
        let mut copy_licence: Option<String> = None;
        let mut escape = false;
        detail_window(
            ctx,
            "wsd_crypto_details",
            d.crypto_details_title,
            [580.0, 390.0],
            &mut open,
            |ui| {
                escape |= ui.input(|i| i.key_pressed(egui::Key::Escape));
                ui.spacing_mut().item_spacing.y = 2.0;
                egui::ScrollArea::vertical()
                    .id_salt("wsd_crypto_rows")
                    .auto_shrink([false, true])
                    .max_height(ui.available_height().max(1.0))
                    .show(ui, |ui| {
                        let label_width = (ui.available_width() * 0.34).clamp(90.0, 180.0);
                        let value_width = (ui.available_width() - label_width - 40.0).max(1.0);
                        for r in rows.iter().filter(|r| {
                            r.label != d.crypto_det_term
                                && r.label != d.crypto_det_last_rehash
                                && !(r.label == d.crypto_det_errors
                                    && r.value == d.crypto_det_no_errors)
                        }) {
                            ui.horizontal_top(|ui| {
                                ui.set_min_height(24.0);
                                ui.allocate_ui_with_layout(
                                    egui::vec2(label_width, 24.0),
                                    egui::Layout::top_down(egui::Align::Min),
                                    |ui| {
                                        ui.set_min_width(label_width);
                                        ui.add(
                                            egui::Label::new(
                                                RichText::new(&r.label).color(c::TEXT_SECONDARY),
                                            )
                                            .wrap(),
                                        );
                                    },
                                );
                                // Fixed label/value/icon columns, including rows without Copy.
                                ui.allocate_ui_with_layout(
                                    egui::vec2(value_width, 24.0),
                                    egui::Layout::top_down(egui::Align::Min),
                                    |ui| {
                                        ui.set_min_width(value_width);
                                        ui.add(
                                            egui::Label::new(
                                                RichText::new(&r.value)
                                                    .color(crate::ui::pages::tone_color(r.tone)),
                                            )
                                            .wrap(),
                                        );
                                    },
                                );
                                if let Some(exact) = &r.copy {
                                    let response = ui
                                        .add(
                                            egui::Button::new("")
                                                .frame(false)
                                                .min_size(egui::vec2(24.0, 24.0)),
                                        )
                                        .on_hover_text(d.crypto_license_copy);
                                    crate::ui::paint::icon_copy(
                                        ui.painter(),
                                        response.rect.shrink(3.0),
                                        c::TEXT_PRIMARY,
                                    );
                                    if response.clicked() {
                                        copy_licence = Some(exact.clone());
                                    }
                                }
                            });
                            ui.separator();
                        }
                        if let Some((text, color)) = &status {
                            ui.add(egui::Label::new(RichText::new(text).color(*color)).wrap());
                        }
                    });
            },
        );
        if let Some(exact) = copy_licence {
            self.copy_licence_number(ctx, &exact);
        }
        if !open || escape {
            self.crypto_details_open = false;
        }
    }

    /// v1.1: copies exactly the licence number (no label, no spaces) to
    /// the clipboard. Nothing is journalled or written to disk.
    pub(crate) fn copy_licence_number(&mut self, ctx: &egui::Context, exact: &str) {
        ctx.copy_text(exact.to_string());
        self.clipboard_out = Some(exact.to_string());
        self.crypto_export_status = Some(ExportStatus::Copied);
    }

    /// v1.1 UI contract: the ReHash confirmation opened by the card's round
    /// button — its own small window with the warning and an explicit
    /// [Да, выполнить ReHash] / [Отмена]. Nothing runs before the click.
    pub(crate) fn crypto_rehash_confirm_window(&mut self, ctx: &egui::Context) {
        if !self.crypto_rehash_confirm {
            return;
        }
        let d = i18n::t(self.language);
        let allowed = self.crypto_rehash_allowed();
        let mut open = true;
        let mut choice: Option<Action> = None;
        detail_window(
            ctx,
            "wsd_crypto_rehash_confirm",
            d.crypto_rehash_confirm_title,
            [520.0, 230.0],
            &mut open,
            |ui| {
                ui.label(
                    RichText::new(d.crypto_rehash_confirm_title)
                        .strong()
                        .color(c::YELLOW_WARNING),
                );
                ui.add(
                    egui::Label::new(RichText::new(d.crypto_rehash_warning).color(c::TEXT_BODY))
                        .wrap(),
                );
                if !allowed {
                    ui.label(RichText::new(d.crypto_rehash_only_no_hash).color(c::TEXT_MUTED));
                }
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if details::primary_button(ui, d.crypto_rehash_confirm_yes, allowed).clicked() {
                        choice = Some(Action::CryptoRehashConfirmed);
                    }
                    if details::secondary_button(ui, d.confirm_cancel, true).clicked() {
                        choice = Some(Action::CryptoRehashCancelled);
                    }
                });
            },
        );
        if !open && choice.is_none() {
            choice = Some(Action::CryptoRehashCancelled);
        }
        if let Some(a) = choice {
            self.apply(a);
        }
    }

    /// Text of this UI's Driver Audit history (Copy).
    pub(crate) fn driver_history_text(&self) -> String {
        let d = i18n::t(self.language);
        let mut out = format!("{}\r\n", d.driver_history_title);
        for e in &self.driver_history {
            out.push_str(&format!(
                "{} · [{}] {} · {}\r\n",
                e.stamp.at,
                e.stamp.origin.code(),
                e.stamp.origin.text(d),
                e.outcome
            ));
        }
        out
    }

    /// Applies a Driver Audit history header action.
    pub(crate) fn apply_history_act(&mut self, ctx: &egui::Context, act: HistoryAct) {
        match act {
            HistoryAct::Copy => {
                let text = self.driver_history_text();
                self.driver_export_status =
                    Some(self.export_text(ctx, ExportAction::Copy, "DriverAuditHistory", &text));
            }
            // Only the CURRENT Driver Audit report, via the Save As dialog.
            HistoryAct::SaveReport => {
                let Some(report) = self.audit_view() else {
                    return;
                };
                let text = driver_audit::to_text(&report);
                self.driver_export_status =
                    Some(self.export_text(ctx, ExportAction::Save, "DriverAudit", &text));
            }
            HistoryAct::ClearRequest => self.driver_history_clear_confirm = true,
            HistoryAct::ClearCancelled => self.driver_history_clear_confirm = false,
            // This UI's displayed history only: no Windows log, saved report
            // or diagnostic session evidence is touched.
            HistoryAct::ClearConfirmed => {
                self.driver_history_clear_confirm = false;
                self.driver_history.clear();
            }
        }
    }
}

/// v1.1 Driver Audit history section with its header
/// [Копировать] [Сохранить отчёт] [Очистить журнал].
pub(crate) fn driver_history_section(
    ui: &mut egui::Ui,
    d: &i18n::Dict,
    entries: &[DriverHistoryEntry],
    confirm_clear: bool,
    has_report: bool,
) -> Option<HistoryAct> {
    let mut act = None;
    details::card_frame().show(ui, |ui| {
        ui.horizontal(|ui| {
            details::section_title(ui, d.driver_history_title);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if details::secondary_button(ui, d.driver_history_clear, !entries.is_empty())
                    .clicked()
                {
                    act = Some(HistoryAct::ClearRequest);
                }
                if details::secondary_button(ui, d.driver_history_save, has_report).clicked() {
                    act = Some(HistoryAct::SaveReport);
                }
                if details::secondary_button(ui, d.driver_history_copy, !entries.is_empty())
                    .clicked()
                {
                    act = Some(HistoryAct::Copy);
                }
            });
        });
        if confirm_clear {
            ui.add(
                egui::Label::new(
                    RichText::new(d.driver_history_clear_confirm).color(c::YELLOW_WARNING),
                )
                .wrap(),
            );
            ui.horizontal(|ui| {
                if details::primary_button(ui, d.driver_history_clear_yes, true).clicked() {
                    act = Some(HistoryAct::ClearConfirmed);
                }
                if details::secondary_button(ui, d.confirm_cancel, true).clicked() {
                    act = Some(HistoryAct::ClearCancelled);
                }
            });
        }
        if entries.is_empty() {
            ui.label(RichText::new(d.driver_history_empty).color(c::TEXT_MUTED));
        }
        for e in entries.iter().rev() {
            ui.add(
                egui::Label::new(
                    RichText::new(format!(
                        "{} · {} · {}",
                        e.stamp.at,
                        e.stamp.origin.text(d),
                        e.outcome
                    ))
                    .color(c::TEXT_BODY),
                )
                .wrap(),
            );
        }
    });
    act
}

// ---------------------------------------------------------------------
// v1.1 Hardware Passport 2.0 window
// ---------------------------------------------------------------------

/// What the Passport 2.0 footer asked for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PassportAct {
    Refresh,
    Copy,
    Save,
    Close,
}

/// Colour of a passport value by its kind (configuration / current
/// measurement / not confirmed).
pub(crate) fn passport_value_color(kind: crate::passport2::Kind) -> egui::Color32 {
    match kind {
        crate::passport2::Kind::Config => c::TEXT_PRIMARY,
        // v1.1 UI contract: a measurement is not a health verdict.
        crate::passport2::Kind::Measured => c::PASSPORT_MEASURED,
        crate::passport2::Kind::Unconfirmed => c::TEXT_MUTED,
    }
}

/// v1.1 UI contract — hardware IDENTITY colour of a passport value: CPU by
/// vendor (Intel blue / AMD red), RAM violet, board orange, BIOS teal,
/// Windows green. Identity, never health. `None` = no identity colour.
pub(crate) fn identity_color(
    part: crate::passport2::CardKind,
    value: &str,
) -> Option<egui::Color32> {
    use crate::passport2::CardKind;
    match part {
        CardKind::Cpu => cpu_vendor_color(value),
        CardKind::Ram => Some(c::IDENT_RAM),
        CardKind::Board => Some(c::IDENT_BOARD),
        CardKind::Bios => Some(c::IDENT_BIOS),
        _ => None,
    }
}

/// Intel blue / AMD red from the CPU name (anything else: no accent).
pub(crate) fn cpu_vendor_color(value: &str) -> Option<egui::Color32> {
    let v = value.to_ascii_lowercase();
    if v.contains("intel") || v.contains("xeon") || v.contains("core(tm)") {
        Some(c::IDENT_INTEL)
    } else if v.contains("amd")
        || v.contains("ryzen")
        || v.contains("epyc")
        || v.contains("threadripper")
    {
        Some(c::IDENT_AMD)
    } else {
        None
    }
}

/// Colour of one passport value: unconfirmed stays muted, a measurement
/// stays neutral, configuration takes its identity colour; an incomplete
/// inventory is amber (a warning is never shown in an identity colour).
pub(crate) fn passport_row_color(
    kind: crate::passport2::Kind,
    part: crate::passport2::CardKind,
    value: &str,
) -> egui::Color32 {
    use crate::passport2::Kind;
    if value.contains("incomplete") || value.contains("неполн") {
        return c::YELLOW_WARNING;
    }
    match kind {
        Kind::Config => identity_color(part, value).unwrap_or(c::TEXT_PRIMARY),
        _ => passport_value_color(kind),
    }
}

fn passport_card(ui: &mut egui::Ui, card: &crate::passport2::Card) {
    use crate::passport2::Kind;
    egui::Frame::new()
        .fill(c::BG_CARD_INNER)
        .stroke(egui::Stroke::new(1.0, c::BORDER_INNER))
        .corner_radius(egui::CornerRadius::same(6))
        .inner_margin(egui::Margin::symmetric(12, 9))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(
                RichText::new(&card.title)
                    .size(17.0)
                    .strong()
                    .color(c::TEXT_TITLE),
            );
            ui.add_space(3.0);
            let width = ui.available_width();
            egui::Grid::new(("wsd_pp_card", card.title.as_str()))
                .num_columns(2)
                .min_col_width(width * 0.30)
                .max_col_width(width * 0.46)
                .spacing(vec2(12.0, 4.0))
                .show(ui, |ui| {
                    for r in &card.rows {
                        let value = |text: &str| {
                            let t = RichText::new(text)
                                .color(passport_row_color(r.kind, card.kind, text));
                            if r.kind == Kind::Unconfirmed {
                                t.italics()
                            } else {
                                t
                            }
                        };
                        match (r.label.is_empty(), r.value.is_empty()) {
                            // A sub-heading (disk / GPU / battery name).
                            (false, true) => {
                                if r.kind == Kind::Config
                                    && !crate::passport2::is_unconfirmed(&r.label)
                                {
                                    crate::ui::paint::copy_value(
                                        ui,
                                        &r.label,
                                        c::TEXT_PRIMARY,
                                        width * 0.46,
                                    );
                                } else {
                                    ui.add(
                                        egui::Label::new(
                                            RichText::new(&r.label).strong().color(c::TEXT_PRIMARY),
                                        )
                                        .wrap(),
                                    );
                                }
                                ui.label("");
                            }
                            // A note line under the previous row.
                            (true, _) => {
                                ui.label("");
                                ui.add(egui::Label::new(value(&r.value)).wrap());
                            }
                            (false, false) => {
                                if matches!(
                                    card.kind,
                                    crate::passport2::CardKind::Storage
                                        | crate::passport2::CardKind::Network
                                ) && !crate::passport2::is_unconfirmed(&r.label)
                                {
                                    crate::ui::paint::copy_value(
                                        ui,
                                        &r.label,
                                        c::PASSPORT_LABEL,
                                        width * 0.46,
                                    );
                                } else {
                                    ui.add(
                                        egui::Label::new(
                                            RichText::new(&r.label).color(c::PASSPORT_LABEL),
                                        )
                                        .wrap(),
                                    );
                                }
                                if r.kind == Kind::Config {
                                    crate::ui::paint::copy_value(
                                        ui,
                                        &r.value,
                                        passport_row_color(r.kind, card.kind, &r.value),
                                        width * 0.46,
                                    );
                                } else {
                                    ui.add(egui::Label::new(value(&r.value)).wrap());
                                }
                            }
                        }
                        ui.end_row();
                    }
                });
        });
}

/// v1.1 Passport 2.0 page body (header, legend, cards, not-confirmed list)
/// — without the fixed footer. Two columns when the window is wide.
pub(crate) fn passport_body(ui: &mut egui::Ui, d: &i18n::Dict, p: &crate::passport2::Passport) {
    ui.label(
        RichText::new(d.pp_title)
            .size(24.0)
            .strong()
            .color(c::TEXT_TITLE),
    );
    ui.label(RichText::new(d.pp_subtitle).color(c::TEXT_SECONDARY));
    if !p.system.is_empty() {
        // v1.1 UI contract: the Windows identity line in Windows green.
        ui.add(egui::Label::new(RichText::new(&p.system).color(c::IDENT_WINDOWS)).wrap());
    }
    ui.horizontal_wrapped(|ui| {
        for (text, kind) in [
            (d.pp_legend_config, crate::passport2::Kind::Config),
            (d.pp_legend_measured, crate::passport2::Kind::Measured),
            (d.pp_legend_unconfirmed, crate::passport2::Kind::Unconfirmed),
        ] {
            ui.label(RichText::new("●").color(passport_value_color(kind)));
            ui.label(RichText::new(text).small().color(c::TEXT_MUTED));
            ui.add_space(8.0);
        }
    });
    ui.add_space(6.0);
    let two = ui.available_width() >= 820.0;
    if two {
        ui.columns(2, |cols| {
            for (i, card) in p.cards.iter().enumerate() {
                passport_card(&mut cols[i % 2], card);
                cols[i % 2].add_space(8.0);
            }
        });
    } else {
        for card in &p.cards {
            passport_card(ui, card);
            ui.add_space(8.0);
        }
    }
    egui::Frame::new()
        .fill(c::BG_CARD_INNER)
        .stroke(egui::Stroke::new(1.0, c::BORDER_INNER))
        .corner_radius(egui::CornerRadius::same(6))
        .inner_margin(egui::Margin::symmetric(12, 9))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(
                RichText::new(d.pp_unconfirmed_title)
                    .size(17.0)
                    .strong()
                    .color(c::TEXT_TITLE),
            );
            if p.unconfirmed.is_empty() {
                ui.label(RichText::new(d.pp_unconfirmed_none).color(c::TEXT_MUTED));
            }
            for u in &p.unconfirmed {
                ui.add(egui::Label::new(RichText::new(u).italics().color(c::TEXT_MUTED)).wrap());
            }
        });
}

/// The fixed bottom panel: [Обновить] [Скопировать сводку]
/// [Сохранить отчёт] … [Закрыть] and the collection / export line.
/// Smallest footer height reserved under the scrolling page (points).
pub(crate) const PASSPORT_FOOTER_MIN_H: f32 = 78.0;

pub(crate) fn passport_footer(
    ui: &mut egui::Ui,
    d: &i18n::Dict,
    collected: Option<&str>,
    busy: bool,
    has_data: bool,
    status: Option<&(String, egui::Color32)>,
) -> Option<PassportAct> {
    let mut act = None;
    ui.separator();
    if let Some(at) = collected {
        ui.label(
            RichText::new(d.pp_collected_fmt.replace("{time}", at))
                .small()
                .color(c::TEXT_MUTED),
        );
    }
    // Wraps onto further rows in a narrow window — every button stays
    // reachable at any allowed width.
    ui.horizontal_wrapped(|ui| {
        if details::primary_button(ui, d.pp_refresh, !busy).clicked() {
            act = Some(PassportAct::Refresh);
        }
        if details::secondary_button(ui, d.pp_copy, has_data).clicked() {
            act = Some(PassportAct::Copy);
        }
        if details::secondary_button(ui, d.pp_save, has_data).clicked() {
            act = Some(PassportAct::Save);
        }
        if details::secondary_button(ui, d.pp_close, true).clicked() {
            act = Some(PassportAct::Close);
        }
        if busy {
            ui.label(RichText::new(d.pp_collecting).color(c::TEXT_SECONDARY));
        }
    });
    if let Some((text, color)) = status {
        ui.add(egui::Label::new(RichText::new(text).color(*color)).wrap());
    }
    act
}

impl WinStateDiagApp {
    /// The passport page model in the current UI language.
    pub(crate) fn passport2_view(&self) -> Option<crate::passport2::Passport> {
        let json = self.passport2_json.as_deref()?;
        crate::passport2::build(
            json,
            &crate::passport2::Texts {
                ru: self.language == Language::Ru,
                d: i18n::t(self.language),
            },
        )
    }

    /// v1.1 Hardware Passport 2.0: one large resizable, scrollable window
    /// in the WinStateDiag palette with a fixed bottom panel.
    pub(crate) fn passport2_window(&mut self, ctx: &egui::Context) {
        if !self.passport2_open {
            return;
        }
        let d = i18n::t(self.language);
        let view = self.passport2_view();
        let busy = !matches!(self.hardware, HardwareViewState::Idle);
        let status = self.passport2_status.as_ref().map(|s| s.text(d));
        let mut open = true;
        let mut act: Option<PassportAct> = None;
        detail_window(
            ctx,
            "wsd_hardware_passport2",
            d.pp_title,
            [1060.0, 860.0],
            &mut open,
            |ui| {
                // The footer's real (possibly wrapped) height of the last
                // frame is reserved under the scrolling page.
                let footer_id = egui::Id::new("wsd_passport2_footer_h");
                let footer_h = ui
                    .ctx()
                    .data(|m| m.get_temp::<f32>(footer_id))
                    .unwrap_or(PASSPORT_FOOTER_MIN_H)
                    .max(PASSPORT_FOOTER_MIN_H);
                // The footer has priority: the page may shrink to a sliver
                // (it scrolls) so the bottom controls are never clipped.
                let body_h = (ui.available_height() - footer_h).max(24.0);
                egui::ScrollArea::vertical()
                    .id_salt("wsd_passport2_scroll")
                    .auto_shrink([false, false])
                    .max_height(body_h)
                    .show(ui, |ui| match &view {
                        Some(p) => passport_body(ui, d, p),
                        None => {
                            ui.label(
                                RichText::new(d.pp_title)
                                    .size(24.0)
                                    .strong()
                                    .color(c::TEXT_TITLE),
                            );
                            ui.label(
                                RichText::new(if busy {
                                    d.pp_collecting
                                } else {
                                    d.pp_not_collected
                                })
                                .color(c::TEXT_SECONDARY),
                            );
                        }
                    });
                // A later layout pass must not erase a click from the
                // first pass; apply the selected action once, below.
                // Measure only the footer, never the enclosing panel's
                // minimum rectangle (which includes the scroll body).
                let footer = ui.scope(|ui| {
                    passport_footer(
                        ui,
                        d,
                        view.as_ref().map(|p| p.collected_at.as_str()),
                        busy,
                        view.is_some(),
                        status.as_ref(),
                    )
                });
                act = footer.inner.or(act);
                let used = footer.response.rect.height() + 8.0;
                ui.ctx().data_mut(|m| m.insert_temp(footer_id, used));
            },
        );
        match act {
            Some(PassportAct::Refresh) => {
                self.passport2_status = None;
                self.start_hardware_view();
            }
            Some(PassportAct::Copy) | Some(PassportAct::Save) => {
                if let Some(p) = &view {
                    let text = crate::passport2::summary_text(p, d);
                    let action = if act == Some(PassportAct::Copy) {
                        ExportAction::Copy
                    } else {
                        ExportAction::Save
                    };
                    self.passport2_status =
                        Some(self.export_text(ctx, action, "HardwarePassport", &text));
                }
            }
            Some(PassportAct::Close) => open = false,
            None => {}
        }
        if !open {
            self.passport2_open = false;
        }
    }
}
