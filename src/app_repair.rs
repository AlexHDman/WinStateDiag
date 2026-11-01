//! Contextual A9 repair UI. Original EXPC evidence remains immutable.
use super::*;
use crate::repair::{self, Plan, Report, SharedProgress};
use std::sync::mpsc;
#[derive(Default)]
pub(super) struct RepairUi {
    pub pending: Option<Plan>,
    pub active: Option<(String, Plan)>,
    pub evidence_error: Option<String>,
    pub reboot_confirmation: bool,
    pub rx: Option<Receiver<Report>>,
    pub progress: SharedProgress,
    pub cancel: Arc<AtomicBool>,
    pub reports: Vec<Report>,
    pub verified: Vec<DeepCheckOutcome>,
    pub directory: Option<PathBuf>,
    pub open: bool,
    pub message: String,
}
impl WinStateDiagApp {
    pub(super) fn repair_busy(&self) -> bool {
        self.repair_ui.rx.is_some()
    }
    pub(super) fn request_repair(&mut self, index: usize) {
        if self.report_busy() || self.crypto_rx.is_some() || self.reference.is_some() {
            return;
        }
        let Some(o) = self.deep_check_at(index) else {
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
            return;
        }
        let Some(plan) = repair::plan(o, &system_drive()) else {
            return;
        };
        self.repair_ui.pending = Some(plan);
        self.repair_ui.open = true;
        self.repair_ui.reboot_confirmation = false;
        self.repair_ui.message.clear();
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
            repair::elevated(),
            self.report_busy() || self.crypto_rx.is_some(),
        );
        let auth = match authorization {
            Ok(a) => a,
            Err(e) => {
                self.repair_ui.message = e;
                return;
            }
        };
        // No native runner or child process from GUI unit tests.
        if cfg!(test) {
            self.repair_ui.message = "Native Repair отключён в тестах".into();
            return;
        }
        let id = crate::storage_history::new_session_id("repair");
        let directory = crate::app_paths::data_root(&exe_dir())
            .join("Logs")
            .join("Repair")
            .join(&id);
        if let Err(e) = std::fs::create_dir_all(directory.parent().unwrap())
            .and_then(|_| std::fs::create_dir(&directory))
            .and_then(|_| {
                std::fs::write(
                    directory.join("before.txt"),
                    format!(
                        "{}\n{}\n{}\n{}",
                        plan.check.key(),
                        plan.before.result.as_str(),
                        plan.before.detail,
                        plan.command()
                    ),
                )
            })
        {
            self.repair_ui.message =
                format!("Не удалось сохранить исходные доказательства: {e}; ремонт не запущен");
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
        self.repair_ui.progress = Arc::new(Mutex::new(repair::Progress::default()));
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
        std::thread::spawn(move || {
            let mut runner = repair::NativeRunner::new(directory);
            let report = repair::execute(auth, id, &mut runner, &cancel, &progress);
            let _ = tx.send(report);
        });
    }
    pub(super) fn accept_repair_report(&mut self, report: Report) {
        if report.status == "SUCCESS" && report.verified == Some(CheckResult::Ok) {
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
                ("result.json", report.json()),
                ("result.txt", report.text()),
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
            match std::fs::read_dir(dir) {
                Ok(entries) => {
                    for entry in entries {
                        let e = match entry {
                            Ok(e) => e,
                            Err(e) => {
                                self.repair_ui.evidence_error = Some(format!(
                                    "Не удалось перечислить доказательства Repair: {e}"
                                ));
                                continue;
                            }
                        };
                        if matches!(e.file_name().to_str(), Some("result.json" | "result.txt")) {
                            continue;
                        }
                        if e.path().is_file() {
                            match std::fs::read(e.path()) {
                                Ok(data) => files.push(EvidenceFile::new(
                                    format!(
                                        "Repair/{}/{}",
                                        report.id,
                                        e.file_name().to_string_lossy()
                                    ),
                                    data,
                                )),
                                Err(e) => {
                                    self.repair_ui.evidence_error = Some(format!(
                                        "Не удалось прочитать доказательства Repair: {e}"
                                    ));
                                    push_journal(
                                        &mut self.journal,
                                        format!("[ERROR] Repair: чтение доказательств: {e}"),
                                    );
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    self.repair_ui.evidence_error = Some(format!(
                        "Не удалось открыть каталог доказательств Repair: {e}"
                    ));
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
                self.accept_repair_report(report);
            }
            Some(Err(mpsc::TryRecvError::Disconnected)) => {
                self.repair_ui.rx = None;
                if let Some((id, plan)) = self.repair_ui.active.take() {
                    self.accept_repair_report(Report{id,plan,status:"ERROR".into(),message:"Процесс Repair завершился без результата; успех не подтверждён. Повтори диагностику; журналы сохранены.".into(),repair:None,verification:None,verified:None,reboot:false});
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
        let mut next = false;
        let mut cancel = false;
        egui::Window::new("Repair — подтверждение и результат").id(egui::Id::new("contextual_repair")).open(&mut open).resizable(true).default_width(620.0).show(ctx,|ui|{
            if let Some(plan)=&self.repair_ui.pending {
                ui.label(format!("Цель: {} · системный том {}",plan.check.key(),plan.drive));
                ui.label(format!("Исходная находка: {}",plan.before.detail));ui.separator();
                ui.monospace(plan.command());ui.label(plan.warning());
                if plan.check==DeepCheck::Chkdsk {ui.label("Поддерживается доступный системный NTFS-том. Команда /f без /x и /r. Ответ «да» разрешён только на распознанный запрос планирования при загрузке; любые другие запросы останавливают операцию.");}
                ui.label(format!("Повторная проверка: {}",plan.verification()));
                if plan.check==DeepCheck::Sfc && self.deep_check_at(DeepCheck::Dism.step_index()).is_some_and(repair::eligible){ui.colored_label(c::YELLOW_WARNING,"Также повреждено хранилище компонентов. Рекомендуемый порядок: сначала DISM → затем SFC.");}
                if !repair::elevated(){ui.colored_label(c::YELLOW_WARNING,"Нужны права администратора. Перезапусти EXE с подтверждением UAC; при отмене UAC операция не запускается.");}
                ui.separator();
                if plan.check==DeepCheck::Chkdsk && !self.repair_ui.reboot_confirmation {
                    next=ui.button("Продолжить к подтверждению перезагрузки…").clicked();
                }else{
                    if self.repair_ui.reboot_confirmation {ui.colored_label(c::YELLOW_WARNING,"Отдельное согласие: разрешить CHKDSK запланировать исправление при следующей загрузке. Это не означает, что ремонт уже выполнен. После загрузки запусти проверку явно.");}
                    confirm=ui.add_enabled(repair::elevated(),egui::Button::new(if self.repair_ui.reboot_confirmation{"Подтверждаю исправление и возможное планирование при загрузке"}else{"Подтверждаю — выполнить Repair"})).clicked();
                }
                cancel=ui.button("Отмена").clicked();
            }else if self.repair_busy(){
                let progress=self.repair_ui.progress.lock().unwrap_or_else(|e|e.into_inner()).clone();
                ui.label(progress.phase);
                if let Some(p)=progress.percent{ui.add(egui::ProgressBar::new(p/100.0).text(format!("{p:.1}%")));}else{ui.spinner();ui.label("Процент не сообщён инструментом; ожидание результата");}
                ui.label(crate::user_log::display(&progress.latest));
                ui.label("Прерывание не откатывает уже выполненные изменения. После него требуется повторная диагностика.");
                if ui.button("Прервать операцию").clicked(){self.repair_ui.cancel.store(true,Ordering::SeqCst);}
            }
            if !self.repair_ui.message.is_empty(){ui.separator();ui.label(&self.repair_ui.message);}
            if !self.repair_busy() && self.repair_ui.pending.is_none(){if let Some(r)=self.repair_ui.reports.last(){ui.monospace(format!("{} · код команды {:?} · код проверки {:?}",r.label(),r.repair.as_ref().and_then(|o|o.code),r.verification.as_ref().and_then(|o|o.code)));}ui.label("Результаты Repair добавляются отдельными файлами; первоначальные доказательства сохраняются.");}
        });
        if next {
            self.repair_ui.reboot_confirmation = true;
        }
        if confirm {
            self.confirm_repair(self.repair_ui.reboot_confirmation);
        }
        if cancel || (!open && !self.repair_busy()) {
            self.repair_ui.pending = None;
            self.repair_ui.open = false;
        }
    }
}
