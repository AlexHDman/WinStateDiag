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
            rows.push(row(
                d.crypto_det_license,
                match &p.license {
                    cryptopro::LicenseKey::Installed { masked } => {
                        d.crypto_det_license_key_fmt.replace("{key}", masked)
                    }
                    cryptopro::LicenseKey::NotFound => d.crypto_det_license_none.to_string(),
                },
                match p.license {
                    cryptopro::LicenseKey::Installed { .. } => Tone::Idle,
                    cryptopro::LicenseKey::NotFound => Tone::Warning,
                },
            ));
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
    pub(crate) fn crypto_details_text(&self) -> String {
        let d = i18n::t(self.language);
        let mut out = format!("{}\r\n", d.crypto_details_title);
        for r in self.crypto_detail_rows() {
            out.push_str(&format!("{}: {}\r\n", r.label, r.value));
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
        let rehash_allowed = self.crypto_rehash_allowed();
        let confirm = self.crypto_rehash_confirm;
        let status = self.crypto_export_status.as_ref().map(|s| s.text(d));
        let mut open = true;
        let mut act: Option<DetailsAct> = None;
        let mut rehash: Option<Action> = None;
        detail_window(
            ctx,
            "wsd_crypto_details",
            d.crypto_details_title,
            [640.0, 520.0],
            &mut open,
            |ui| {
                details::section_title(ui, d.crypto_details_title);
                egui::Grid::new("wsd_crypto_rows")
                    .num_columns(2)
                    .striped(true)
                    .spacing(vec2(16.0, 7.0))
                    .show(ui, |ui| {
                        for r in &rows {
                            ui.label(RichText::new(&r.label).color(c::TEXT_SECONDARY));
                            ui.add(
                                egui::Label::new(
                                    RichText::new(&r.value)
                                        .color(crate::ui::pages::tone_color(r.tone)),
                                )
                                .wrap(),
                            );
                            ui.end_row();
                        }
                    });
                ui.add_space(10.0);
                ui.separator();
                // ReHash: separate from Copy / Close, behind a warning.
                if confirm {
                    egui::Frame::new()
                        .fill(c::BG_CARD_INNER)
                        .stroke(egui::Stroke::new(1.0, c::YELLOW_WARNING))
                        .corner_radius(egui::CornerRadius::same(6))
                        .inner_margin(egui::Margin::symmetric(12, 10))
                        .show(ui, |ui| {
                            ui.label(
                                RichText::new(d.crypto_rehash_confirm_title)
                                    .strong()
                                    .color(c::YELLOW_WARNING),
                            );
                            ui.add(
                                egui::Label::new(
                                    RichText::new(d.crypto_rehash_warning).color(c::TEXT_BODY),
                                )
                                .wrap(),
                            );
                            ui.add_space(6.0);
                            ui.horizontal(|ui| {
                                if details::primary_button(
                                    ui,
                                    d.crypto_rehash_confirm_yes,
                                    rehash_allowed,
                                )
                                .clicked()
                                {
                                    rehash = Some(Action::CryptoRehashConfirmed);
                                }
                                if details::secondary_button(ui, d.confirm_cancel, true).clicked() {
                                    rehash = Some(Action::CryptoRehashCancelled);
                                }
                            });
                        });
                } else {
                    ui.horizontal(|ui| {
                        if details::secondary_button(ui, d.crypto_rehash_action, rehash_allowed)
                            .clicked()
                        {
                            rehash = Some(Action::CryptoRehashRequest);
                        }
                        if !rehash_allowed {
                            ui.label(
                                RichText::new(d.crypto_rehash_only_no_hash).color(c::TEXT_MUTED),
                            );
                        }
                    });
                }
                ui.add_space(10.0);
                ui.separator();
                ui.horizontal(|ui| {
                    if details::secondary_button(ui, d.journal_viewer_copy, true).clicked() {
                        act = Some(DetailsAct::Copy);
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if details::secondary_button(ui, d.journal_viewer_close, true).clicked() {
                            act = Some(DetailsAct::Close);
                        }
                    });
                });
                if let Some((text, color)) = &status {
                    ui.add(egui::Label::new(RichText::new(text).color(*color)).wrap());
                }
            },
        );
        match act {
            Some(DetailsAct::Copy) => {
                let text = self.crypto_details_text();
                self.crypto_export_status =
                    Some(self.export_text(ctx, ExportAction::Copy, "CryptoPro", &text));
            }
            Some(DetailsAct::Close) => open = false,
            _ => {}
        }
        if let Some(a) = rehash {
            self.apply(a);
        }
        if !open {
            self.crypto_details_open = false;
            self.crypto_rehash_confirm = false;
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
        crate::passport2::Kind::Measured => c::GREEN_SUCCESS,
        crate::passport2::Kind::Unconfirmed => c::TEXT_MUTED,
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
                .max_col_width(width * 0.66)
                .spacing(vec2(12.0, 4.0))
                .show(ui, |ui| {
                    for r in &card.rows {
                        let value = |text: &str| {
                            let t = RichText::new(text).color(passport_value_color(r.kind));
                            if r.kind == Kind::Unconfirmed {
                                t.italics()
                            } else {
                                t
                            }
                        };
                        match (r.label.is_empty(), r.value.is_empty()) {
                            // A sub-heading (disk / GPU / battery name).
                            (false, true) => {
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(&r.label).strong().color(c::TEXT_PRIMARY),
                                    )
                                    .wrap(),
                                );
                                ui.label("");
                            }
                            // A note line under the previous row.
                            (true, _) => {
                                ui.label("");
                                ui.add(egui::Label::new(value(&r.value)).wrap());
                            }
                            (false, false) => {
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(&r.label).color(c::TEXT_SECONDARY),
                                    )
                                    .wrap(),
                                );
                                ui.add(egui::Label::new(value(&r.value)).wrap());
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
        ui.add(egui::Label::new(RichText::new(&p.system).color(c::TEXT_PRIMARY)).wrap());
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
                let body_h = (ui.available_height() - footer_h).max(160.0);
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
                let top = ui.cursor().top();
                act = passport_footer(
                    ui,
                    d,
                    view.as_ref().map(|p| p.collected_at.as_str()),
                    busy,
                    view.is_some(),
                    status.as_ref(),
                );
                let used = ui.min_rect().bottom() - top + 8.0;
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
