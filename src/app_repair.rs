//! Contextual A9 repair UI. Original EXPC evidence remains immutable.
use super::*;
use crate::repair::{self, Plan, Report, SharedProgress};
use std::sync::mpsc;
#[derive(Default)]
pub(super) struct RepairUi {
    #[cfg(test)]
    pub elevation_requests: usize,
    #[cfg(test)]
    pub runner: Option<Box<dyn repair::Runner + Send>>,
    #[cfg(test)]
    pub admin: Option<bool>,
    #[cfg(test)]
    pub log_root: Option<PathBuf>,
    #[cfg(test)]
    pub elevation_error: Option<String>,
    pub pending: Option<Plan>,
    pub active: Option<(String, Plan)>,
    pub evidence_error: Option<String>,
    pub rx: Option<Receiver<Vec<Report>>>,
    pub combined: bool,
    pub maintenance: bool,
    pub source_path: String,
    pub source_index: u32,
    pub progress: SharedProgress,
    pub cancel: Arc<AtomicBool>,
    pub reports: Vec<Report>,
    pub verified: Vec<DeepCheckOutcome>,
    pub directory: Option<PathBuf>,
    pub open: bool,
    pub message: String,
    pub logged_popup_message: String,
    pub logged_popup_progress: String,
}
impl WinStateDiagApp {
    pub(super) fn repair_busy(&self) -> bool {
        self.repair_ui.rx.is_some()
    }
    fn repair_admin(&self) -> bool {
        #[cfg(test)]
        if let Some(value) = self.repair_ui.admin {
            return value;
        }
        repair::elevated()
    }
    fn repair_rejected(&mut self, message: &str) {
        self.repair_ui.pending = None;
        self.repair_ui.open = true;
        self.repair_ui.message = format!("BLOCKED: {message}");
        push_journal(&mut self.journal, self.repair_ui.message.clone());
    }
    pub(super) fn request_repair(&mut self, index: usize) {
        self.request_repair_mode(index, false);
    }
    pub(super) fn request_windows_repair(&mut self) {
        self.request_repair_mode(DeepCheck::Dism.step_index(), true);
    }
    fn request_repair_mode(&mut self, index: usize, combined: bool) {
        if self.report_busy() || self.crypto_rx.is_some() || self.reference.is_some() {
            self.repair_rejected(
                "Ремонт недоступен во время другой операции или просмотра импортированного отчёта",
            );
            return;
        }
        let Some(o) = self.deep_check_at(index) else {
            self.repair_rejected("Нет актуального результата диагностики");
            return;
        };
        if self
            .repair_ui
            .reports
            .iter()
            .rev()
            .find(|r| r.plan.check == o.check)
            .is_some_and(|r| r.reboot)
        {
            self.repair_rejected("Требуется ручная перезагрузка и новая диагностика");
            return;
        }
        let Some(plan) = repair::plan(o, &system_drive()) else {
            self.repair_rejected("Исправляемая проблема не подтверждена");
            return;
        };
        self.repair_ui.combined = combined;
        self.repair_ui.maintenance = false;
        self.repair_ui.source_path.clear();
        self.repair_ui.source_index = 1;
        self.repair_ui.pending = Some(plan);
        self.repair_ui.open = true;
        self.repair_ui.message.clear();
        if matches!(index, 10 | 11) {
            self.confirm_repair(false);
            self.repair_ui.pending = None; // This click is the complete SFC/DISM authorization.
        }
    }
    pub(super) fn confirm_repair(&mut self, reboot: bool) {
        let Some(plan) = self.repair_ui.pending.clone() else {
            return;
        };
        // Revalidate the current finding: a stale dialog cannot authorize new evidence.
        if self.deep_check_at(plan.check.step_index()) != Some(&plan.before) {
            self.repair_ui.message = "Результат изменился; открой подтверждение заново".into();
            return;
        }
        let authorization = repair::authorize(
            plan.clone(),
            true,
            reboot,
            self.repair_admin() || matches!(plan.check, DeepCheck::Sfc | DeepCheck::Dism),
            self.report_busy() || self.crypto_rx.is_some(),
        );
        let auth = match authorization {
            Ok(a) => a,
            Err(e) => {
                self.repair_ui.message = e;
                return;
            }
        };
        let next = if self.repair_ui.combined {
            let outcome = self.deep_check_at(DeepCheck::Sfc.step_index());
            let next = outcome.and_then(|o| repair::plan(o, &system_drive()));
            match next.and_then(|p| repair::authorize(p, true, false, true, false).ok()) {
                Some(a) => Some(a),
                None => {
                    self.repair_ui.message =
                        "Состояние SFC изменилось; открой подтверждение заново".into();
                    return;
                }
            }
        } else {
            None
        };
        // No native runner or child process from GUI unit tests.
        if cfg!(test) && {
            #[cfg(test)]
            {
                self.repair_ui.runner.is_none()
            }
            #[cfg(not(test))]
            {
                false
            }
        } {
            self.repair_ui.message = "Native Repair отключён в тестах".into();
            return;
        }
        let id = repair::operation_id();
        let directory = crate::app_paths::data_root(&exe_dir())
            .join("Logs")
            .join("Repair")
            .join(&id);
        #[cfg(test)]
        let directory = self
            .repair_ui
            .log_root
            .as_ref()
            .map(|root| root.join(&id))
            .unwrap_or(directory);
        #[cfg(not(test))]
        let fallback = crate::repair_history::roots()[1].join(&id);
        #[cfg(test)]
        let fallback = directory.parent().unwrap().join("fallback").join(&id);
        let directory = match crate::repair_history::directory(&directory, &fallback) {
            Ok((path, warning)) => {
                if let Some(w) = warning {
                    push_journal(&mut self.journal, w);
                }
                path
            }
            Err(e) => {
                self.repair_rejected(&e);
                return;
            }
        };
        if let Err(e) = crate::repair_history::start(
            &directory,
            &self.computer_name,
            &plan,
            self.repair_admin(),
        ) {
            self.repair_rejected(&format!(
                "Не удалось сохранить начало операции: {e}; ремонт не запущен"
            ));
            return;
        }
        let context = format!(
            "{{\"original_session_id\":{},\"client\":{},\"computer\":{}}}",
            deep_checks::json::string(&self.current_session_id().unwrap_or_default()),
            deep_checks::json::string(&self.client_name),
            deep_checks::json::string(&self.computer_name)
        );
        if let Err(e) = std::fs::write(directory.join("before-context.json"), context) {
            self.repair_ui.message = format!(
                "Не удалось сохранить контекст исходной диагностики: {e}; ремонт не запущен"
            );
            return;
        }
        self.begin_operation(false);
        self.claim_package("repair");
        self.repair_ui.pending = None;
        self.repair_ui.active = Some((id.clone(), plan.clone()));
        self.repair_ui.cancel = Arc::new(AtomicBool::new(false));
        self.repair_ui.progress = Arc::new(Mutex::new(repair::Progress {
            check: Some(plan.check),
            phase: "RUNNING · Проверка прав и условий запуска".into(),
            ..Default::default()
        }));
        self.repair_ui.directory = Some(directory.clone());
        let cancel = Arc::clone(&self.repair_ui.cancel);
        let progress = Arc::clone(&self.repair_ui.progress);
        let (tx, rx) = mpsc::channel();
        self.repair_ui.rx = Some(rx);
        push_journal(
            &mut self.journal,
            format!(
                "Repair {}: пользователь подтвердил команду {}; исходные доказательства сохранены",
                plan.check.key(),
                plan.command()
            ),
        );
        let admin = self.repair_admin();
        #[cfg(test)]
        {
            self.repair_ui.elevation_requests += usize::from(!admin);
        }
        #[cfg(test)]
        let mock = self.repair_ui.runner.take();
        #[cfg(test)]
        let elevation_error = self.repair_ui.elevation_error.take();
        std::thread::spawn(move || {
            #[cfg(test)]
            {
                if let Some(mut runner) = mock {
                    runner.set_directory(&directory);
                    if !admin && let Some(error) = elevation_error {
                        let mut reports = vec![repair::not_started_report(auth, id, error)];
                        crate::repair_history::finish(&directory, &mut reports);
                        let _ = tx.send(reports);
                        return;
                    }
                    let mut reports =
                        repair::execute_sequence(auth, next, id, &mut *runner, &cancel, &progress);
                    crate::repair_history::finish(&directory, &mut reports);
                    let _ = tx.send(reports);
                    return;
                }
                // Native path below is compiled out in unit tests.
            }
            #[cfg(not(test))]
            {
                let mut reports = if admin {
                    let mut runner = repair::NativeRunner::new(directory.clone());
                    repair::execute_sequence(auth, next, id, &mut runner, &cancel, &progress)
                } else {
                    repair::elevate_sequence(auth, next, id, directory.clone(), &cancel, &progress)
                };
                crate::repair_history::finish(&directory, &mut reports);
                let _ = tx.send(reports);
            }
        });
    }
    pub(super) fn accept_repair_report(&mut self, report: Report) {
        if report.status == "SUCCESS_VERIFIED" && report.verified == Some(CheckResult::Ok) {
            self.repair_ui
                .verified
                .retain(|o| o.check != report.plan.check);
            self.repair_ui.verified.push(DeepCheckOutcome{check:report.plan.check,result:CheckResult::Ok,detail:format!("После Repair {}: повторная проверка подтвердила отсутствие нарушений; исходная диагностика сохранена",report.id),source:deep_checks::ResultSource::RepairVerification});
        }
        let mut files = vec![
            EvidenceFile::new(
                format!("Repair_{}.json", report.id),
                report.json().into_bytes(),
            ),
            EvidenceFile::new(
                format!("Repair_{}.txt", report.id),
                report.text().into_bytes(),
            ),
        ];
        if let Some(dir) = &self.repair_ui.directory {
            // A separate append-only operation directory; never overwrite an EXPC file.
            for (name, data) in [
                (&format!("result-{}.json", report.id), report.json()),
                (&format!("result-{}.txt", report.id), report.text()),
            ] {
                if let Err(e) = std::fs::write(dir.join(name), data) {
                    self.repair_ui.evidence_error =
                        Some(format!("Не удалось записать Repair {name}: {e}"));
                    push_journal(
                        &mut self.journal,
                        format!("[ERROR] Repair: не удалось записать {name}: {e}"),
                    );
                }
            }
            let mut pending = vec![dir.join(report.plan.check.key())];
            while let Some(folder) = pending.pop() {
                match std::fs::read_dir(&folder) {
                    Ok(entries) => {
                        for entry in entries {
                            let Ok(entry) = entry else {
                                self.repair_ui.evidence_error =
                                    Some("Ошибка перечисления Repair".into());
                                continue;
                            };
                            let path = entry.path();
                            if path.is_dir() {
                                pending.push(path);
                                continue;
                            }
                            let Ok(relative) = path.strip_prefix(dir) else {
                                continue;
                            };
                            if matches!(relative.to_str(), Some("result.json" | "result.txt")) {
                                continue;
                            }
                            match std::fs::read(&path) {
                                Ok(bytes) => files.push(EvidenceFile::new(
                                    format!(
                                        "Repair/{}/{}",
                                        report.id,
                                        relative.to_string_lossy().replace('\\', "/")
                                    ),
                                    bytes,
                                )),
                                Err(e) => {
                                    self.repair_ui.evidence_error =
                                        Some(format!("Не удалось прочитать Repair: {e}"))
                                }
                            }
                        }
                    }
                    Err(e) => {
                        self.repair_ui.evidence_error =
                            Some(format!("Не удалось открыть Repair: {e}"))
                    }
                }
            }
        }

        push_journal(
            &mut self.journal,
            format!(
                "Repair {}: {} · {}",
                report.plan.check.key(),
                report.status,
                report.message
            ),
        );
        self.repair_ui.message = report.message.clone();
        self.repair_ui.reports.push(report);
        self.contribute_evidence("repair", "Repair", files);
        self.manifest_states_checked = None;
    }
    pub(super) fn poll_repair(&mut self) {
        let result = self.repair_ui.rx.as_ref().map(|rx| rx.try_recv());
        match result {
            Some(Ok(report)) => {
                self.repair_ui.rx = None;
                self.repair_ui.active = None;
                for r in report {
                    self.accept_repair_report(r);
                }
            }
            Some(Err(mpsc::TryRecvError::Disconnected)) => {
                self.repair_ui.rx = None;
                if let Some((id, plan)) = self.repair_ui.active.take() {
                    self.accept_repair_report(Report{id,plan,status:"FAILED".into(),message:"Процесс Repair завершился без результата; успех не подтверждён. Повтори диагностику; журналы сохранены.".into(),repair:None,verification:None,verified:None,reboot:false,completed_at:repair::timestamp()});
                }
            }
            _ => {}
        }
    }
    pub(super) fn repair_window(&mut self, ctx: &egui::Context) {
        if !self.repair_ui.open {
            return;
        }
        let mut open = true;
        let mut confirm = false;
        let mut cancel = false;
        let busy = self.repair_busy();
        if !busy
            && self
                .repair_ui
                .pending
                .as_ref()
                .is_some_and(|p| matches!(p.check, DeepCheck::Sfc | DeepCheck::Dism))
        {
            self.repair_ui.pending = None;
        }

        // Keep raw rejection/result text in the journal, never in the compact popup.
        if !self.repair_ui.message.is_empty()
            && self.repair_ui.logged_popup_message != self.repair_ui.message
        {
            self.repair_ui.logged_popup_message = self.repair_ui.message.clone();
            if !self
                .journal
                .entries
                .iter()
                .any(|e| e.message.contains(&self.repair_ui.message))
            {
                push_journal(
                    &mut self.journal,
                    format!("Repair: {}", self.repair_ui.message),
                );
            }
        }
        let tone = if busy {
            c::BLUE_PROGRESS
        } else if self.repair_ui.pending.is_some() {
            c::YELLOW_WARNING
        } else {
            match self.repair_ui.reports.last().map(|r| r.status.as_str()) {
                Some("SUCCESS_VERIFIED") => c::GREEN_SUCCESS,
                Some("FAILED" | "VERIFICATION_FAILED") => c::RED_ERROR,
                _ => c::YELLOW_WARNING,
            }
        };
        let window = egui::Window::new(if self.repair_ui.pending.is_some() {
            "Исправление — подтверждение"
        } else {
            "Исправление — выполнение и результат"
        })
        .id(egui::Id::new("contextual_repair"))
        .open(&mut open)
        .resizable(true)
        .default_width(620.0)
        .min_width(260.0)
        .max_width((ctx.content_rect().width() - 32.0).max(260.0))
        .max_height((ctx.content_rect().height() - 64.0).max(180.0))
        .frame(egui::Frame::window(&ctx.global_style()).stroke(egui::Stroke::new(1.0, tone)));
        let window = if self.repair_ui.pending.is_none() {
            let (area, position, width) = repair_popup_layout(ctx);
            window
                .id(egui::Id::new("repair_presentation_v13"))
                .fixed_pos(position)
                .constrain_to(area)
                .resizable(false)
                .collapsible(false)
                .min_width(width)
                .max_width(width)
                .default_width(width)
                .max_height((area.height() - 50.0).max(80.0))
                .frame(
                    egui::Frame::window(&ctx.global_style())
                        .fill(c::BG_FIELD)
                        .inner_margin(16.0)
                        .stroke(egui::Stroke::new(2.0, tone)),
                )
        } else {
            window
        };
        if self.repair_ui.pending.is_none() {
            let (area, _, _) = repair_popup_layout(ctx);
            ctx.layer_painter(egui::LayerId::new(
                egui::Order::Middle,
                egui::Id::new("repair_dim"),
            ))
            .rect_filled(area, 0.0, egui::Color32::from_black_alpha(55));
        }
        let _response = window.show(ctx, |ui| {
                ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Wrap);
                egui::ScrollArea::vertical()
                    .id_salt(("repair_body", self.repair_ui.pending.is_some(), busy))
                    .max_height((ctx.content_rect().height() - 110.0).max(100.0))
                    .auto_shrink([false, true])
                    .show(ui, |ui| {
                let both = self.deep_check_at(DeepCheck::Sfc.step_index()).is_some_and(repair::eligible)
                    && self.deep_check_at(DeepCheck::Dism.step_index()).is_some_and(repair::eligible);
                if self.repair_ui.pending.as_ref().is_some_and(|p|p.check==DeepCheck::Dism) {
                    if both {ui.checkbox(&mut self.repair_ui.combined,"Восстановить Windows: DISM → ScanHealth → SFC → VerifyOnly");}
                    ui.label("Источник: Windows Update по умолчанию. При недоступности выбери путь к совместимому install.wim и индекс; preflight проверит версию, редакцию и языки.");
                    ui.text_edit_singleline(&mut self.repair_ui.source_path);
                    ui.add(egui::DragValue::new(&mut self.repair_ui.source_index).range(1..=1000).prefix("Индекс WIM: "));
                    if let Some(p)=&mut self.repair_ui.pending {p.source=(!self.repair_ui.source_path.trim().is_empty()).then(||(self.repair_ui.source_path.trim().into(),self.repair_ui.source_index));}
                }
                if let Some(plan) = &mut self.repair_ui.pending && plan.check == DeepCheck::Chkdsk { ui.checkbox(&mut plan.online_scan, "Онлайн /scan: может исправлять NTFS; offline /spotfix не запускать");
                }
                if let Some(plan) = &self.repair_ui.pending {
                    ui.strong(format!("{} · системный том {}", plan.check.key(), plan.drive));
                    ui.label(format!("Исходная находка: {}", plan.before.detail));
                    ui.separator();
                    ui.label(egui::RichText::new(plan.command()).monospace());
                    ui.label(plan.warning());
                    ui.colored_label(c::YELLOW_WARNING,"На сервере: согласуй окно обслуживания и резервную копию. Незавершённое обслуживание блокирует запуск.");
                    if self.repair_ui.combined {ui.monospace("DISM /Online /Cleanup-Image /ScanHealth → sfc /scannow → sfc /verifyonly");}
                    if plan.check == DeepCheck::Chkdsk && !plan.online_scan {
                        ui.colored_label(c::YELLOW_WARNING, "Системный NTFS-том / рабочий сервер: /spotfix может требовать offline-обслуживания. Автоматической перезагрузки и принудительного отключения тома нет. Планирование не означает завершённый ремонт.");
                        ui.checkbox(&mut self.repair_ui.maintenance,"Окно обслуживания согласовано; разрешаю /spotfix и возможное планирование при следующей ручной перезагрузке");
                    }
                    ui.label(format!("Повторная проверка: {}", plan.verification()));
                    if plan.check == DeepCheck::Sfc && self.deep_check_at(DeepCheck::Dism.step_index()).is_some_and(repair::eligible) {
                        ui.colored_label(c::YELLOW_WARNING, "Также повреждено хранилище компонентов. Рекомендуемый порядок: сначала DISM → затем SFC.");
                    }
                    let admin = repair::elevated();
                    if !admin { ui.colored_label(c::YELLOW_WARNING, "Нужны права администратора. Перезапусти EXE с подтверждением UAC; при отмене UAC операция не запускается."); }
                    ui.separator();
                    confirm = ui.add_enabled(admin && repair::valid_source(plan) && (plan.check != DeepCheck::Chkdsk || plan.online_scan || self.repair_ui.maintenance), egui::Button::new(if plan.check == DeepCheck::Chkdsk {
                        "Подтверждаю исправление и возможное планирование при загрузке"
                    } else { "Подтверждаю — выполнить исправление" }).wrap()).clicked();
                    cancel = ui.button("Отмена").clicked();
                } else if busy {
                    let progress = self.repair_ui.progress.lock().unwrap_or_else(|e| e.into_inner()).clone();
                    let technical = format!("Repair: {} · {}", progress.phase, progress.latest);
                    if technical != self.repair_ui.logged_popup_progress {
                        self.repair_ui.logged_popup_progress = technical.clone();
                        push_journal(&mut self.journal, technical);
                    }
                    ui.heading("Исправление выполняется");
                    ui.label(match self.repair_ui.progress.lock().ok().and_then(|p| p.check) {
                        Some(DeepCheck::Sfc) => "Восстановление системных файлов Windows",
                        Some(DeepCheck::Dism) => "Восстановление хранилища компонентов Windows",
                        _ => "Проверка и восстановление Windows",
                    });
                    ui.add_space(12.0);
                    repair_progress_bar(ui, progress.percent, tone);
                    ui.add_space(12.0);
                    ui.label("После завершения будет выполнена повторная проверка");
                    // Verification is mandatory; no user-facing skip action.
                    ctx.request_repaint_after(Duration::from_millis(100));
                }
                if !busy && self.repair_ui.pending.is_none() {
                    let current = self.repair_ui.reports.last().filter(|r|
                        self.repair_ui.message.is_empty() || r.message == self.repair_ui.message);
                    ui.heading(current.map_or("Исправление не запущено", |r| r.label()));
                    ui.label("Подробности сохранены в журнале");
                    if ui.button("Открыть журнал").clicked() { self.journal_viewer_open = true; }
                }
                });
            });
        if let Some(response) = &_response {
            ctx.move_to_top(response.response.layer_id);
        }
        #[cfg(test)]
        if let Some(response) = _response {
            ctx.data_mut(|d| {
                d.insert_temp(
                    egui::Id::new("repair_popup_test_rect"),
                    response.response.rect,
                )
            });
        }
        if confirm {
            // One explicit button authorizes the displayed command and its CHKDSK scheduling risk.
            let schedule = self
                .repair_ui
                .pending
                .as_ref()
                .is_some_and(|p| p.check == DeepCheck::Chkdsk);
            self.confirm_repair(schedule);
        }
        if cancel || (!open && !busy) {
            self.repair_ui.pending = None;
            self.repair_ui.open = false;
        }
    }
}

/// Anchor to the visible A9 card in actual canvas coordinates (including scroll/zoom).
fn repair_popup_layout(ctx: &egui::Context) -> (Rect, egui::Pos2, f32) {
    let screen = ctx.content_rect().shrink(8.0);
    let fallback = Rect::from_min_max(
        egui::pos2(screen.left() + screen.width() * 0.42, screen.top()),
        screen.max,
    );
    let area = ctx
        .data(|d| d.get_temp::<Rect>(egui::Id::new("repair_a9_anchor")))
        .map(|r| r.intersect(screen).shrink(8.0))
        .filter(|r| r.width() >= 180.0 && r.height() >= 160.0)
        .unwrap_or(fallback);
    let width = (area.width() - 40.0).clamp(80.0, 480.0);
    let position = egui::pos2(
        area.center().x - (width + 36.0) / 2.0,
        (area.center().y - 110.0).max(area.top()),
    );
    (area, position, width)
}
fn repair_progress_segment(track: Rect, percent: Option<f32>, time: f64) -> Rect {
    if let Some(value) = percent.filter(|v| v.is_finite() && (0.0..=100.0).contains(v)) {
        Rect::from_min_size(
            track.min,
            vec2(track.width() * value / 100.0, track.height()),
        )
    } else {
        let width = track.width() * 0.25;
        let offset = ((time * 2.5).sin() as f32 + 1.0) * 0.5 * (track.width() - width);
        Rect::from_min_size(track.min + vec2(offset, 0.0), vec2(width, track.height()))
    }
}
fn repair_progress_bar(ui: &mut egui::Ui, percent: Option<f32>, tone: egui::Color32) {
    let (track, response) =
        ui.allocate_exact_size(vec2(ui.available_width(), 10.0), egui::Sense::hover());
    response.widget_info(|| {
        egui::WidgetInfo::labeled(
            egui::WidgetType::ProgressIndicator,
            true,
            "Исправление выполняется",
        )
    });
    ui.painter().rect_filled(track, 5.0, c::BG_JOURNAL);
    let segment = repair_progress_segment(track, percent, ui.input(|i| i.time));
    if segment.width() > 0.0 {
        ui.painter().rect_filled(segment, 5.0, tone);
    }
    ui.ctx().request_repaint_after(Duration::from_millis(50));
}
#[cfg(test)]
#[path = "app_repair_ux_tests.rs"]
mod ux_tests;
