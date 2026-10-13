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
