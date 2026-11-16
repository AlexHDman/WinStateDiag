//! Additional controls inside existing stage details; workers never occupy the UI thread.
use super::*;
use crate::{repair, vss_repair, winsxs};
type ReliabilityResult = Result<(String, Vec<EvidenceFile>), String>;
#[derive(Default)]
pub(super) struct ReliabilityUi {
    pub open: bool,
    pub allow_quota: bool,
    pub rows: Vec<vss_repair::Row>,
    pub selection: usize,
    pub proposed_gb: u64,
    pub consent: bool,
    pub text: String,
    pub previous: String,
    pub current: String,
    pub rx: Option<Receiver<ReliabilityResult>>,
    pub progress: Arc<Mutex<String>>,
    pub mutating: bool,
    pub directory: Option<PathBuf>,
}
impl WinStateDiagApp {
    pub(super) fn vss_quota_allowed(&self) -> bool {
        self.reference.is_none()
            && self.expc_checks.iter().any(|c| {
                c.key.starts_with("VSS") && matches!(c.status.as_str(), "ATTENTION" | "WARNING")
            })
    }

    pub(super) fn reliability_window(&mut self, ctx: &egui::Context) {
        if let Some(rx) = &self.reliability_ui.rx {
            match rx.try_recv() {
                Ok(result) => {
                    self.reliability_ui.rx = None;
                    self.reliability_ui.mutating = false;
                    match result {
                        Ok((text, files)) => {
                            if let Ok(rows) = vss_repair::rows(&text) {
                                self.reliability_ui.rows = rows;
                                self.reliability_ui.selection = 0;
                                self.reliability_ui.proposed_gb = self
                                    .reliability_ui
                                    .rows
                                    .first()
                                    .and_then(vss_repair::recommend)
                                    .unwrap_or(0)
                                    / (1 << 30);
                            }
                            self.reliability_ui.text = vss_repair::summary(&text);
                            if !files.is_empty() {
                                self.contribute_evidence("reliability", "WinSxS / VSS", files);
                            }
                        }
                        Err(e) => self.reliability_ui.text = format!("UNKNOWN / FAILED: {e}"),
                    }
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    self.reliability_ui.rx = None;
                    self.reliability_ui.mutating = false;
                    self.reliability_ui.text =
                        "UNKNOWN: worker завершился без результата; проверь локальные журналы"
                            .into();
                }
                _ => {}
            }
        }
        if !self.reliability_ui.open {
            return;
        }
        let busy = self.reliability_ui.rx.is_some();
        let mut inspect = false;
        let mut apply = false;
        let mut compare = false;
        let mut open = true;
        egui::Window::new("VSS / WinSxS — анализ и управляемые действия").id(egui::Id::new("reliability")).open(&mut open).default_width(720.0).resizable(true).show(ctx,|ui|{
            ui.style_mut().wrap_mode=Some(egui::TextWrapMode::Wrap);
            egui::ScrollArea::vertical().max_height(650.0).show(ui,|ui|{
                ui.label("READ-ONLY по умолчанию. Анализ не создаёт снимки и не подтверждает успешный backup.");
                inspect=ui.add_enabled(!busy && !self.report_busy(),egui::Button::new("Прочитать актуальные ассоциации VSS")).clicked();
                let state=&mut self.reliability_ui;
                if !state.rows.is_empty(){
                    egui::ComboBox::from_label("Ассоциация").selected_text(format!("{}",state.selection+1)).show_ui(ui,|ui|{for(i,r)in state.rows.iter().enumerate(){if ui.selectable_value(&mut state.selection,i,format!("{} → {}",r.source,r.storage)).changed(){state.proposed_gb=vss_repair::recommend(r).unwrap_or(0)/(1<<30);state.consent=false;}}});
                    if let Some(row)=state.rows.get(state.selection){
                        let gb=|n:u64|n as f64/(1u64<<30) as f64;
                        ui.label(format!("Квота {:.2} ГБ · использовано {:.2} ГБ · свободно {:.2} ГБ · снимков {}",gb(row.maximum),gb(row.used),gb(row.free),row.copies));
                        if ui.add(egui::DragValue::new(&mut state.proposed_gb).range(1..=u32::MAX as u64).suffix(" ГБ — новая квота")).changed(){state.consent=false;}
                        let proposed=state.proposed_gb.saturating_mul(1<<30);
                        ui.label(format!("Изменение: {:+.2} ГБ. Расчёт предлагает +25% (не менее 1 ГБ), оставляя 2 ГБ свободными. Это не прогноз retention и не гарантия backup.",gb(proposed)-gb(row.maximum)));
                        ui.monospace(format!("vssadmin resize shadowstorage /For={} /On={} /MaxSize={}",row.source,row.storage,proposed));
                        ui.colored_label(c::YELLOW_WARNING,"Microsoft предупреждает: изменение storage association может привести к исчезновению снимков. Программа не удаляет снимки и не уменьшает квоту. На сервере согласуй окно обслуживания и наличие независимой резервной копии.");
                        ui.checkbox(&mut state.consent,"Подтверждаю увеличение указанной квоты и риск; окно обслуживания согласовано");
                        apply=ui.add_enabled(!busy && state.allow_quota && state.consent && vss_repair::valid(row,proposed) && repair::elevated(),egui::Button::new("Применить увеличение и проверить результат")).clicked();
                        if !state.allow_quota{ui.label("Изменение BLOCKED: в текущей диагностике нет подтверждённого предупреждения VSS.");}
                    }
                }
                ui.separator();ui.strong("WinSxS — сравнение двух ZIP одного компьютера");
                ui.label("Предыдущий ZIP");ui.text_edit_singleline(&mut state.previous);
                ui.label("Текущий ZIP");ui.text_edit_singleline(&mut state.current);
                compare=ui.add_enabled(!busy,egui::Button::new("Сравнить WinSxS (только чтение)")).clicked();
                ui.label("Отсутствие старой ошибки в новом ZIP не доказывает устранение. RECURRED требует проверенного промежуточного ремонта; недостаточная идентичность или покрытие → UNKNOWN.");
                if busy{ui.spinner();ui.label(state.progress.lock().unwrap_or_else(|e|e.into_inner()).clone());ctx.request_repaint_after(Duration::from_millis(100));}
                ui.label(&state.text);
            });
        });
        self.reliability_ui.open = open;
        if inspect || compare || apply {
            if apply && !self.vss_quota_allowed() {
                self.reliability_ui.text="BLOCKED: актуальная локальная проблема VSS не подтверждена; повтори диагностику".into();
                return;
            }
            if self.report_busy() || self.crypto_rx.is_some() {
                return;
            }
            self.reliability_ui.consent = false;
            let previous = self.reliability_ui.previous.clone();
            let current = self.reliability_ui.current.clone();
            let chosen = self
                .reliability_ui
                .rows
                .get(self.reliability_ui.selection)
                .cloned();
            let proposed = self.reliability_ui.proposed_gb.saturating_mul(1 << 30);
            let (tx, rx) = std::sync::mpsc::channel();
            self.reliability_ui.rx = Some(rx);
            self.reliability_ui.mutating = apply;
            let progress = Arc::clone(&self.reliability_ui.progress);
            *progress.lock().unwrap_or_else(|e| e.into_inner()) = "Чтение доказательств".into();
            let id = crate::storage_history::new_session_id("reliability");
            let dir = crate::app_paths::data_root(&exe_dir())
                .join("Logs")
                .join("Reliability")
                .join(&id);
            self.reliability_ui.directory = Some(dir.clone());
            if apply {
                self.begin_operation(false);
                self.claim_package("reliability");
            }
            std::thread::spawn(move || {
                let result = (|| -> Result<(String, Vec<EvidenceFile>), String> {
                    if inspect {
                        return vss_repair::inspect().map(|s| {
                            let file = EvidenceFile::new(
                                format!("VSS/Analysis-{id}.json"),
                                s.as_bytes().to_vec(),
                            );
                            (s, vec![file])
                        });
                    }
                    if apply {
                        let result = vss_repair::increase(
                            chosen.ok_or("VSS association missing")?,
                            proposed,
                            true,
                            &dir,
                            progress,
                        );
                        let text = match result {
                            Ok(text) => text,
                            Err(error) => format!(
                                "{{\"Status\":\"FAILED\",\"Error\":{}}}",
                                deep_checks::json::string(&error)
                            ),
                        };
                        let mut files = vec![EvidenceFile::new(
                            format!("VSS/{id}/result.json"),
                            text.as_bytes().to_vec(),
                        )];
                        for entry in std::fs::read_dir(&dir).into_iter().flatten() {
                            let p = entry.map_err(|e| e.to_string())?.path();
                            if p.is_file() {
                                files.push(EvidenceFile::new(
                                    format!(
                                        "VSS/{}/{}",
                                        id,
                                        p.file_name().unwrap().to_string_lossy()
                                    ),
                                    std::fs::read(&p).map_err(|e| e.to_string())?,
                                ));
                            }
                        }
                        return Ok((text, files));
                    }
                    let load = |path: &str| -> Result<_, String> {
                        let p = Path::new(path.trim());
                        if !p.is_absolute()
                            || p.extension().is_none_or(|x| !x.eq_ignore_ascii_case("zip"))
                        {
                            return Err("Укажи полный путь к ZIP".into());
                        }
                        if std::fs::metadata(p).map_err(|e| e.to_string())?.len()
                            > 512 * 1024 * 1024
                        {
                            return Err("ZIP больше 512 МБ; требуется отдельный анализ".into());
                        }
                        report_package::read_zip(p)
                    };
                    let before = winsxs::analyze(&load(&previous)?);
                    let after = winsxs::analyze(&load(&current)?);
                    let rows = winsxs::compare(&before, &after);
                    let mut counts = std::collections::BTreeMap::new();
                    for (_, s) in &rows {
                        *counts.entry(*s).or_insert(0) += 1;
                    }
                    let summary = format!(
                        "{}\nСравнение: {:?}\nСовпадение машины: {}. Отсутствие строк не доказывает исправность.",
                        after.text(),
                        counts,
                        !before.identity.is_empty() && before.identity == after.identity
                    );
                    let json = format!(
                        "{{\"before\":{},\"after\":{},\"comparison\":[{}]}}",
                        before.json(),
                        after.json(),
                        rows.iter()
                            .map(|(key, s)| format!(
                                "{{\"key\":{},\"state\":{}}}",
                                deep_checks::json::string(key),
                                deep_checks::json::string(s)
                            ))
                            .collect::<Vec<_>>()
                            .join(",")
                    );
                    Ok((
                        summary.clone(),
                        vec![
                            EvidenceFile::new(
                                format!("WinSxS_Comparison_{id}.json"),
                                json.into_bytes(),
                            ),
                            EvidenceFile::new(
                                format!("WinSxS_Comparison_{id}.txt"),
                                summary.into_bytes(),
                            ),
                        ],
                    ))
                })();
                let _ = tx.send(result);
            });
        }
    }
}
