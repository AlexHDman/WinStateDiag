type PreparedAndSaved = (
    crate::ai_analysis::Prepared,
    Option<(crate::ai_analysis::Analysis, PathBuf)>,
);
#[derive(Default)]
enum AiAnalysisJob {
    #[default]
    Idle,
    Preparing(Receiver<Result<PreparedAndSaved, crate::ai_analysis::Error>>),
    Sending(
        Receiver<Result<crate::ai_analysis::Analysis, crate::ai_analysis::Error>>,
        PathBuf,
    ),
}
#[cfg(test)]
type AiTestTransport = Box<
    dyn FnOnce(
            crate::ai_analysis::transport::SendRequest,
        ) -> Result<crate::ai_analysis::Analysis, crate::ai_analysis::Error>
        + Send,
>;
struct AiAnalysisState {
    #[cfg(test)]
    test_transport: Option<AiTestTransport>,
    open: bool,
    loaded: bool,
    model: String,
    key: String,
    key_present: bool,
    session_key_chosen: bool,
    progress: Arc<crate::ai_analysis::transport::Progress>,
    send_error: Option<crate::ai_analysis::Error>,
    prepared: Option<crate::ai_analysis::Prepared>,
    selected_zip: Option<PathBuf>,
    saved_path: Option<PathBuf>,
    auto_save: Option<Receiver<Result<PathBuf, crate::ai_analysis::Error>>>,
    result: Option<(crate::ai_analysis::Analysis, PathBuf)>,
    job: AiAnalysisJob,
    cancel: Arc<AtomicBool>,
    started: Option<Instant>,
    message: String,
    result_tab: bool,
    reviewed: Option<(String, String)>,
}
impl Default for AiAnalysisState {
    fn default() -> Self {
        Self {
            #[cfg(test)]
            test_transport: None,
            open: false,
            loaded: false,
            model: "gpt-4.1-mini".into(),
            key: String::new(),
            key_present: false,
            session_key_chosen: false,
            progress: Default::default(),
            send_error: None,
            prepared: None,
            selected_zip: None,
            saved_path: None,
            auto_save: None,
            result: None,
            job: AiAnalysisJob::Idle,
            cancel: Arc::new(AtomicBool::new(false)),
            started: None,
            message: String::new(),
            result_tab: false,
            reviewed: None,
        }
    }
}
impl Drop for AiAnalysisState {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Release);
        crate::ai_analysis::credentials::wipe(&mut self.key);
    }
}
impl AiAnalysisState {
    fn busy(&self) -> bool {
        !matches!(self.job, AiAnalysisJob::Idle) || self.auto_save.is_some()
    }
    fn has_key_choice(&self) -> bool {
        if self.session_key_chosen {
            !self.key.trim().is_empty()
        } else {
            self.key_present
        }
    }
    fn select_key(
        &self,
    ) -> Result<crate::ai_analysis::transport::KeyChoice, crate::ai_analysis::Error> {
        use crate::ai_analysis::{Error, credentials::Secret, transport::KeyChoice};
        if self.session_key_chosen {
            Secret::from_input(&self.key).map(KeyChoice::Session)
        } else if self.key_present {
            Ok(KeyChoice::Stored)
        } else {
            Err(Error::NoKey)
        }
    }
    fn prepare(&mut self, source: crate::ai_analysis::Source, seeds: Vec<String>) {
        if self.busy() {
            return;
        }
        self.cancel = Arc::new(AtomicBool::new(false));
        self.started = Some(Instant::now());
        self.prepared = None;
        self.selected_zip = match &source {
            crate::ai_analysis::Source::Zip(path) => Some(path.clone()),
            #[cfg(test)]
            _ => None,
        };
        self.result = None;
        self.saved_path = None;
        self.auto_save = None;
        self.send_error = None;
        self.reviewed = None;
        self.result_tab = false;
        self.message = "Подготовка и маскирование текста…".into();
        let cancel = self.cancel.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        self.job = AiAnalysisJob::Preparing(rx);
        std::thread::spawn(move || {
            let result = crate::ai_analysis::prepare(source, seeds, &cancel).map(|prepared| {
                let saved = prepared
                    .archive_sha256
                    .as_deref()
                    .and_then(|hash| crate::ai_analysis::saved_for_archive(&prepared.source, hash));
                (prepared, saved)
            });
            let _ = tx.send(result);
        });
    }
    fn send_with(
        &mut self,
        run: impl FnOnce(
            crate::ai_analysis::transport::SendRequest,
        ) -> Result<crate::ai_analysis::Analysis, crate::ai_analysis::Error>
        + Send
        + 'static,
    ) -> Result<(), crate::ai_analysis::Error> {
        use crate::ai_analysis::{Error, request, transport::SendRequest};
        if self.busy() {
            return Err(Error::Busy);
        }
        let key = self.select_key()?;
        let prepared = self.prepared.as_ref().ok_or(Error::NotReviewed)?;
        if self.reviewed.as_ref() != Some(&(prepared.digest.clone(), self.model.clone())) {
            return Err(Error::NotReviewed);
        }
        let body = request(prepared, &self.model, &prepared.digest)?;
        let source = prepared.source.clone();
        self.cancel = Arc::new(AtomicBool::new(false));
        self.progress = Default::default();
        self.started = Some(Instant::now());
        self.send_error = None;
        self.result = None;
        self.saved_path = None;
        self.auto_save = None;
        self.result_tab = false;
        let (tx, rx) = std::sync::mpsc::channel();
        self.job = AiAnalysisJob::Sending(rx, source);
        let request = SendRequest {
            body,
            model: self.model.clone(),
            key,
            cancel: self.cancel.clone(),
            progress: self.progress.clone(),
        };
        std::thread::spawn(move || {
            let _ = tx.send(run(request));
        });
        Ok(())
    }
    fn poll(&mut self) -> Option<String> {
        use std::sync::mpsc::TryRecvError;
        let sending = matches!(self.job, AiAnalysisJob::Sending(..));
        let result = match &self.job {
            AiAnalysisJob::Idle => return None,
            AiAnalysisJob::Preparing(rx) => match rx.try_recv() {
                Ok(r) => Some(
                    r.and_then(|p| {
                        if self.cancel.load(Ordering::Acquire) {
                            Err(crate::ai_analysis::Error::Cancelled)
                        } else {
                            Ok(p)
                        }
                    })
                    .map(|(prepared, saved)| {
                        let message = if let Some((analysis, path)) = saved {
                            self.result = Some((analysis, prepared.source.clone()));
                            self.result_tab = true;
                            self.saved_path = Some(path);
                            "Открыто сохранённое заключение."
                        } else {
                            "Текст подготовлен. Проверь отправляемую копию и модель."
                        };
                        self.prepared = Some(prepared);
                        message.to_owned()
                    }),
                ),
                Err(TryRecvError::Empty) => return None,
                Err(_) => Some(Err(crate::ai_analysis::Error::Worker)),
            },
            AiAnalysisJob::Sending(rx, source) => match rx.try_recv() {
                Ok(r) => {
                    let source = source.clone();
                    Some(
                        r.and_then(|a| {
                            if self.cancel.load(Ordering::Acquire) {
                                Err(crate::ai_analysis::Error::Cancelled)
                            } else {
                                Ok(a)
                            }
                        })
                        .map(|mut a| {
                            if let Some(p) = &self.prepared {
                                a.facts = p.facts.clone();
                                a.archive_sha256 = p.archive_sha256.clone();
                            }
                            if a.archive_sha256.is_some() {
                                let analysis = a.clone();
                                let zip = source.clone();
                                let (tx, rx) = std::sync::mpsc::channel();
                                self.auto_save = Some(rx);
                                std::thread::spawn(move || {
                                    let _ = tx.send(crate::ai_analysis::save(&analysis, &zip));
                                });
                            }
                            let msg = if a.incomplete {
                                "Готово. Ответ неполный, проверь ограничения."
                            } else {
                                "Готово. Заключение получено."
                            };
                            self.result = Some((a, source));
                            self.result_tab = true;
                            msg.to_owned()
                        }),
                    )
                }
                Err(TryRecvError::Empty) => return None,
                Err(_) => Some(Err(crate::ai_analysis::Error::Worker)),
            },
        };
        self.job = AiAnalysisJob::Idle;
        let outcome = if self.cancel.load(Ordering::Acquire) {
            self.result_tab = false;
            Err(crate::ai_analysis::Error::Cancelled)
        } else {
            result.unwrap()
        };
        self.message = match outcome {
            Ok(message) => message,
            Err(error) => {
                let message = error.message();
                if sending {
                    self.send_error = Some(error);
                }
                message
            }
        };
        Some(self.message.clone())
    }
}
impl WinStateDiagApp {
    fn current_analysis_zip(&self) -> Option<PathBuf> {
        if let RunState::Done { zip_path } = &self.state {
            let package = report_package::lock(&self.package);
            if package.needs_finalize() || package.packaging_error().is_some() {
                return None;
            }
            let path = package.final_zip().unwrap_or_else(|| zip_path.clone());
            return engine::verify_final_report(&path, &self.reports_root).ok();
        }
        None
    }
    fn open_ai_analysis(&mut self) {
        self.ai_analysis.open = true;
        if !self.ai_analysis.loaded {
            self.ai_analysis.loaded = true;
            #[cfg(not(test))]
            {
                match crate::ai_analysis::credentials::present() {
                    Ok(found) => self.ai_analysis.key_present = found,
                    Err(e) => self.ai_analysis.message = e.message(),
                };
            }
            let path = self.language_pref_dir.join("OpenAI.model");
            if let Ok(meta) = std::fs::metadata(&path)
                && meta.len() <= 128
                && let Ok(model) = std::fs::read_to_string(path)
                && crate::ai_analysis::valid_model(model.trim())
            {
                self.ai_analysis.model = model.trim().into();
            }
        }
        if self.ai_analysis.prepared.is_none()
            && self.ai_analysis.result.is_none()
            && !self.ai_analysis.busy()
            && let Some(zip) = self.current_analysis_zip()
        {
            self.prepare_ai_analysis(crate::ai_analysis::Source::Zip(zip));
        }
    }
    fn prepare_ai_analysis(&mut self, source: crate::ai_analysis::Source) {
        let seeds = vec![
            self.client_name.clone(),
            self.computer_name.clone(),
            std::env::var("USERNAME").unwrap_or_default(),
        ];
        self.ai_analysis.prepare(source, seeds);
    }
    fn poll_ai_analysis(&mut self) {
        if let Some(rx) = &self.ai_analysis.auto_save {
            use std::sync::mpsc::TryRecvError;
            match rx.try_recv() {
                Ok(Ok(path)) => {
                    self.ai_analysis.saved_path = Some(path);
                    self.ai_analysis.auto_save = None;
                }
                Ok(Err(error)) => {
                    self.ai_analysis.message = error.message();
                    self.ai_analysis.auto_save = None;
                }
                Err(TryRecvError::Disconnected) => {
                    self.ai_analysis.message = "Не удалось сохранить заключение. Повтори сохранение из вкладки «Результат».".into();
                    self.ai_analysis.auto_save = None;
                }
                Err(TryRecvError::Empty) => {}
            }
        }
        if let Some(msg) = self.ai_analysis.poll() {
            push_journal(&mut self.journal, format!("AI-разбор: {msg}"));
        }
    }
    fn ai_analysis_window(&mut self, ctx: &egui::Context) {
        if !self.ai_analysis.open {
            return;
        }
        let mut open = true;
        let mut choose = false;
        let mut open_zip_folder = false;
        let mut current = false;
        let mut save_key = false;
        let mut delete_key = false;
        let mut use_stored_key = false;
        let mut send = false;
        let mut save = false;
        let mut previous = false;
        let mut poster = false;
        let ru = self.language == Language::Ru;
        let current_zip = self.current_analysis_zip();
        detail_window(
            ctx,
            "ai_analysis",
            rpt(ru, "Отчёт ИИ — EXPC WinDiag", "AI report — EXPC WinDiag"),
            [1448.0, 1086.0],
            &mut open,
            |ui| {
                let l = |s| crate::locale::literal(ru, s);
                ui.spacing_mut().interact_size.y = 32.0;
                ui.spacing_mut().button_padding = egui::vec2(10.0, 6.0);
                let viewport_height = ui.available_height();
                egui::ScrollArea::vertical().id_salt("ai_window_body").auto_shrink([false,false]).show(ui, |ui| {
            let s = &mut self.ai_analysis;
                let busy = s.busy();
                if s.result_tab && let Some((a,_))=&s.result {
                    ui.label(crate::locale::text(ru,&s.message).as_ref());
                    ui.label(crate::locale::text(ru,&self.client_report.message).as_ref());
                    if s.auto_save.is_some() {
                        ui.small(rpt(ru, "Заключение сохраняется рядом с ZIP…", "Saving beside the ZIP…"));
                        ctx.request_repaint_after(Duration::from_millis(100));
                    } else if s.saved_path.is_some() {
                        ui.small(rpt(ru, "Заключение сохранено рядом с ZIP", "Conclusion saved beside the ZIP"));
                    }
                    if self.client_report.previous_rx.is_some(){ui.spinner();ctx.request_repaint_after(Duration::from_millis(100));}
                    let acts=draw_client_report(ui,a,ru);
                    if acts.preview {s.result_tab=false;}
                    save=acts.save;previous=acts.previous;poster=acts.poster;
                    return;
                }
                ui.heading(RichText::new(l("AI-разбор отчёта")).color(c::TEXT_TITLE));
                ui.label(
                    l("Источник — только сохранённые материалы. Новая диагностика не запускается."),
                );
                ui.horizontal_wrapped(|ui| {
                    current = ui
                        .add_enabled(
                            current_zip.is_some() && !busy,
                            egui::Button::new(rpt(ru,"Текущая сессия","Current session")),
                        )
                        .clicked();
                    choose = ui
                        .add_enabled(!busy, egui::Button::new(rpt(ru,"Выбрать ZIP…","Choose ZIP…")))
                        .clicked();
                    let source = s.selected_zip.as_ref().or_else(||s.prepared.as_ref().map(|p|&p.source));
                    if let Some(path) = source { ui.label(path.file_name().unwrap_or_default().to_string_lossy()); }
                });
                egui::Frame::new().fill(egui::Color32::from_rgb(15,38,59)).stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(38,72,100))).inner_margin(10).corner_radius(6).show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.label(l("Модель:"));
                    let edit = ui.add_enabled(!busy, egui::TextEdit::singleline(&mut s.model).desired_width(190.0).char_limit(128));
                    if edit.changed() { s.reviewed = None; }
                    ui.label(l("Ключ:"));
                    let key_status = if s.session_key_chosen && !s.key.trim().is_empty() {
                        rpt(ru, "Только на этот сеанс", "This session only")
                    } else if !s.session_key_chosen && s.key_present {
                        rpt(ru, "Сохранён для этого пользователя", "Saved for this user")
                    } else {
                        rpt(ru, "Ключ не задан", "No key set")
                    };
                    let edit_key = ui.add_enabled(!busy, egui::TextEdit::singleline(&mut s.key)
                        .password(true).desired_width(210.0).char_limit(4200)
                        .hint_text(rpt(ru, "Вставь ключ", "Paste key")));
                    if edit_key.changed() {
                        s.session_key_chosen = true;
                        if let Some(mut state) = egui::TextEdit::load_state(ui.ctx(), edit_key.id) {
                            state.clear_undoer();
                            egui::TextEdit::store_state(ui.ctx(), edit_key.id, state);
                        }
                    }
                    ui.small(key_status);
                });
                ui.horizontal_wrapped(|ui| {
                    save_key = ui.add_enabled(!busy && s.session_key_chosen && !s.key.trim().is_empty(),
                        egui::Button::new(rpt(ru, "Сохранить для этого пользователя", "Save for this user"))).clicked();
                    use_stored_key = ui.add_enabled(!busy && s.session_key_chosen && s.key_present,
                        egui::Button::new(rpt(ru, "Использовать сохранённый", "Use saved key"))).clicked();
                    delete_key = ui.add_enabled(!busy && s.key_present,
                        egui::Button::new(rpt(ru, "Удалить сохранённый ключ", "Delete saved key"))).clicked();
                });
                ui.small(l("OpenAI API оплачивается отдельно. Доступность указанной модели зависит от проекта OpenAI."));
            });
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    ui.selectable_value(&mut s.result_tab, false, l("Отправляемый текст"));
                    ui.add_enabled_ui(s.result.is_some(), |ui| {
                        ui.selectable_value(&mut s.result_tab, true, l("Результат"));
                    });
                });
                ui.separator();
                if s.auto_save.is_some() {
                    ui.spinner();
                    ui.label(rpt(ru, "Заключение сохраняется рядом с ZIP…", "Saving beside the ZIP…"));
                    ctx.request_repaint_after(Duration::from_millis(100));
                } else if busy {
                    let elapsed = s.started.map(|t| t.elapsed().as_secs()).unwrap_or(0);
                    ui.horizontal(|ui| {
                        ui.spinner();
                        use crate::ai_analysis::transport::Phase;
                        let phase = if matches!(s.job, AiAnalysisJob::Preparing(..)) {
                            rpt(ru, "Подготовка архива", "Preparing archive")
                        } else {
                            match s.progress.phase() {
                                Phase::Preparing => rpt(ru, "Подготовка", "Preparing"),
                                Phase::Sending => rpt(ru, "Отправка", "Sending"),
                                Phase::Waiting => rpt(ru, "Ожидание ответа", "Waiting for response"),
                            }
                        };
                        ui.label(format!("{phase} · {elapsed} {}", if ru { "с" } else { "s" }));
                        if ui.button(l("Отменить ожидание")).clicked() {
                            s.cancel.store(true, Ordering::Release);
                        }
                    });
                    ui.small(l("Отмена останавливает ожидание. Уже отправленный запрос может быть оплачен; автоматического повтора нет."));
                    ctx.request_repaint_after(Duration::from_millis(100));
                } else if !s.message.is_empty() {
                    ui.label(crate::locale::text(ru,&s.message).as_ref());
                    if let Some(error) = &s.send_error {
                        ui.small(rpt(ru,"Заключение не создано. Расход токенов неизвестен.", "No conclusion was created. Token usage is unknown."));
                        if let crate::ai_analysis::Error::Http(http) = error {
                            if http.problem == crate::ai_analysis::HttpProblem::Region
                                && s.selected_zip.is_some()
                            {
                                open_zip_folder = ui.button(rpt(ru, "Открыть папку с ZIP", "Open ZIP folder")).clicked();
                            }
                            egui::CollapsingHeader::new(rpt(ru,"Подробности", "Details")).show(ui, |ui| {
                                for line in http.details() { ui.label(line); }
                            });
                        }
                    }
                }
                if let Some(p) = &s.prepared {
                    ui.label(format!(
                        "OpenAI · api.openai.com · {}: {} · {} {} UTF-8",
                        rpt(ru,"Модель","Model"),s.model,p.text.len(),rpt(ru,"байт","bytes")
                    ));
                    ui.small(format!(
                        "{}: {} {} · {} · {}: {} · {}: {}",
                        rpt(ru,"Источник","Source"),p.source_bytes,rpt(ru,"байт","bytes"),p.encoding,rpt(ru,"Сокращено блоков","Omitted blocks"),p.omitted_blocks,rpt(ru,"Пропущено материалов","Omitted materials"),p.omissions.len()
                    ));
                    if !p.omissions.is_empty() {
                        egui::CollapsingHeader::new(l("Пропущенные материалы")).show(ui, |ui| {
                            egui::ScrollArea::vertical()
                                .max_height(80.0)
                                .show(ui, |ui| {
                                    for name in &p.omissions {
                                        ui.label(name);
                                    }
                                });
                        });
                    }
                    ui.small(l("Ниже — точная копия input запроса. Проверь свободный текст: автоматическое маскирование не гарантирует анонимность."));
                    ui.small(l("Нажатие «Отправить в OpenAI» разрешает платный запрос с показанными текстом и моделью."));
                    if !busy {
                        s.reviewed = Some((p.digest.clone(), s.model.clone()));
                    }
                    let checked = s.reviewed.as_ref() == Some(&(p.digest.clone(), s.model.clone()));
                    send = ui
                        .add_enabled(
                            !busy
                                && checked
                                && s.has_key_choice()
                                && crate::ai_analysis::valid_model(&s.model),
                            egui::Button::new(RichText::new(l("Отправить в OpenAI")).strong())
                                .fill(egui::Color32::from_rgb(74, 31, 148)),
                        )
                        .clicked();
                    if !s.has_key_choice() {
                        ui.small(l("Ключ не настроен. Подготовка и просмотр доступны без ключа."));
                    }
                    egui::Frame::new()
                        .fill(egui::Color32::from_rgb(0, 12, 24))
                        .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(38, 72, 100)))
                        .inner_margin(10)
                        .show(ui, |ui| {
                            egui::ScrollArea::both()
                                .id_salt("ai_preview")
                                .max_height((viewport_height - 500.0).clamp(120.0,550.0))
                                .show(ui, |ui| {
                                    let mut exact = p.text.as_str();
                                    ui.add(
                                        egui::TextEdit::multiline(&mut exact)
                                            .font(egui::TextStyle::Monospace)
                                            .desired_width(ui.available_width())
                                            .desired_rows(16),
                                    );
                                });
                        });
                } else {
                    ui.label(rpt(ru, "Выбери сохранённый ZIP. Текущая сессия доступна после создания ZIP.", "Select a saved ZIP. The current session is available once its ZIP is ready."));
                }
                });
            },
        );
        self.ai_analysis.open = open;
        if !open {
            self.ai_analysis.cancel.store(true, Ordering::Release);
            self.ai_analysis.reviewed = None;
        }
        if previous
            && self.client_report.previous_rx.is_none()
            && let crate::win_dialog::SavePick::Path(path) =
                crate::win_dialog::open_zip(&self.reports_root)
            && let Some((_, source)) = &self.ai_analysis.result
        {
            let source = source.clone();
            let (tx, rx) = std::sync::mpsc::channel();
            self.client_report.previous_rx = Some((rx, source));
            std::thread::spawn(move || {
                let _ = tx.send(crate::ai_analysis::prepare(
                    crate::ai_analysis::Source::Zip(path),
                    vec![],
                    &AtomicBool::new(false),
                ));
            });
        }
        if poster {
            self.request_poster_source(true);
        }
        if open_zip_folder && let Some(path) = &self.ai_analysis.selected_zip {
            #[cfg(not(test))]
            if let Err(error) = engine::open_containing_folder(path) {
                self.ai_analysis.message = error;
            }
            #[cfg(test)]
            let _ = path;
        }
        if choose {
            match crate::win_dialog::open_zip(&self.reports_root) {
                crate::win_dialog::SavePick::Path(path) => {
                    self.prepare_ai_analysis(crate::ai_analysis::Source::Zip(path));
                }
                crate::win_dialog::SavePick::Unavailable => {
                    self.ai_analysis.message =
                        "Диалог выбора ZIP недоступен. Открой готовый ZIP текущей сессии.".into();
                }
                crate::win_dialog::SavePick::Cancelled => {}
            }
        }
        if current && let Some(zip) = current_zip {
            self.prepare_ai_analysis(crate::ai_analysis::Source::Zip(zip));
        }
        if save_key {
            let r = crate::ai_analysis::credentials::save(&self.ai_analysis.key);
            self.ai_analysis.message = match r {
                Ok(()) => {
                    self.ai_analysis.key_present = true;
                    self.ai_analysis.session_key_chosen = false;
                    crate::ai_analysis::credentials::wipe(&mut self.ai_analysis.key);
                    rpt(ru, "Сохранён для этого пользователя", "Saved for this user").into()
                }
                Err(error) => error.message(),
            };
        }
        if use_stored_key {
            self.ai_analysis.session_key_chosen = false;
            crate::ai_analysis::credentials::wipe(&mut self.ai_analysis.key);
        }
        if delete_key {
            let deleted = crate::ai_analysis::credentials::delete()
                .and_then(|()| crate::ai_analysis::credentials::present());
            self.ai_analysis.message = match deleted {
                Ok(false) => {
                    self.ai_analysis.key_present = false;
                    rpt(ru, "Сохранённый ключ удалён", "Saved key deleted").into()
                }
                Ok(true) => rpt(
                    ru,
                    "Windows всё ещё показывает сохранённый ключ",
                    "Windows still reports a saved key",
                )
                .into(),
                Err(error) => error.message(),
            };
        }
        if send {
            #[cfg(test)]
            let runner = self
                .ai_analysis
                .test_transport
                .take()
                .unwrap_or_else(|| Box::new(|_| Err(crate::ai_analysis::Error::Worker)));
            #[cfg(not(test))]
            let runner = crate::ai_analysis::transport::execute;
            if let Err(error) = self.ai_analysis.send_with(runner) {
                self.ai_analysis.message = error.message();
                self.ai_analysis.send_error = Some(error);
            }
            // Only non-secret, validated model selection is persisted.
            #[cfg(not(test))]
            if crate::ai_analysis::valid_model(&self.ai_analysis.model)
                && (std::fs::create_dir_all(&self.language_pref_dir).is_err()
                    || std::fs::write(
                        self.language_pref_dir.join("OpenAI.model"),
                        &self.ai_analysis.model,
                    )
                    .is_err())
            {
                push_journal(
                    &mut self.journal,
                    "AI-разбор: модель не сохранена; ключ не затронут.".into(),
                );
            }
        }
        if save
            && self.ai_analysis.auto_save.is_none()
            && let Some((a, path)) = &self.ai_analysis.result
        {
            if let Some(saved) = &self.ai_analysis.saved_path {
                let _ = engine::reveal_in_explorer(saved);
                return;
            }
            self.ai_analysis.message = match crate::ai_analysis::save(a, path) {
                Ok(path) => {
                    let _ = engine::reveal_in_explorer(&path);
                    self.ai_analysis.saved_path = Some(path);
                    "Заключение сохранено рядом с исходным отчётом".into()
                }
                Err(e) => e.message(),
            };
        }
    }
}
#[cfg(test)]
mod ai_analysis_flow_tests {
    use super::*;
    fn prepared() -> crate::ai_analysis::Prepared {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target/ai-flow-tests")
            .join(format!(
                "{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("Тестовый отчёт.zip");
        let entries = [
            report_package::EvidenceFile::new(
                "manifest.json",
                br#"{"producer":"WinDiag","producer_version":"1.12","computer_name":"FIXTURE-PC","created_at":"2026-11-19"}"#.to_vec(),
            ),
            report_package::EvidenceFile::new(
                "State_Summary.json",
                br#"{"state":"ATTENTION_INTEGRITY"}"#.to_vec(),
            ),
            report_package::EvidenceFile::new(
                "SFC.txt",
                b"SFC INTEGRITY_VIOLATIONS\nDISM CLEAN".to_vec(),
            ),
        ];
        let bytes = report_package::build_zip(&entries, crate::ui::sysinfo::local_time()).unwrap();
        std::fs::write(&path, bytes).unwrap();
        crate::ai_analysis::prepare(
            crate::ai_analysis::Source::Zip(path),
            vec![],
            &AtomicBool::new(false),
        )
        .unwrap()
    }
    fn mock_response() -> crate::ai_analysis::Analysis {
        crate::ai_analysis::Analysis {
            archive_sha256: None,
            facts: Default::default(),
            sections: [
                "ТЕСТОВЫЙ ОТВЕТ, не OpenAI".into(),
                "SFC INTEGRITY_VIOLATIONS — источник SFC.txt".into(),
                "Факт: нарушения SFC. Гипотеза: причина не установлена".into(),
                "Проверить CBS".into(),
                "Проверка требует внимания".into(),
            ],
            raw_partial: None,
            model: "synthetic-model".into(),
            requested_model: "gpt-4.1-mini".into(),
            usage: Some(crate::ai_analysis::Usage {
                input: 123,
                output: 45,
                total: 168,
            }),
            incomplete: false,
            created_at: "2026-11-19 00:00:00".into(),
        }
    }
    fn ready() -> AiAnalysisState {
        let p = prepared();
        let mut s = AiAnalysisState::default();
        s.open = true;
        s.key_present = true;
        s.reviewed = Some((p.digest.clone(), "gpt-4.1-mini".into()));
        s.prepared = Some(p);
        s
    }
    #[test]
    fn running_session_cannot_expose_a_previous_zip() {
        let old_zip = prepared().source;
        let (_, rx) = std::sync::mpsc::channel();
        let mut app = WinStateDiagApp {
            state: RunState::Running {
                stage: Stage::Preparing,
                step_done: 0,
                step_total: 1,
                stage_message: String::new(),
                rx,
            },
            reports_root: old_zip.parent().unwrap().to_path_buf(),
            ..Default::default()
        };
        assert_eq!(app.current_analysis_zip(), None);
        app.state = RunState::Done {
            zip_path: old_zip.clone(),
        };
        assert_eq!(app.current_analysis_zip(), Some(old_zip));
    }

    #[test]
    fn controller_double_send_model_binding_and_no_key() {
        let mut s = ready();
        s.key_present = false;
        assert_eq!(
            s.send_with(|_| panic!("no key must not launch")),
            Err(crate::ai_analysis::Error::NoKey)
        );
        s.key_present = true;
        s.model = "another-model".into();
        assert_eq!(
            s.send_with(|_| panic!("changed model must not launch")),
            Err(crate::ai_analysis::Error::NotReviewed)
        );
        s.model = "gpt-4.1-mini".into();
        let (release, wait) = std::sync::mpsc::channel();
        s.send_with(move |_| {
            wait.recv().unwrap();
            Ok(mock_response())
        })
        .unwrap();
        assert!(s.busy());
        assert_eq!(
            s.send_with(|_| panic!("duplicate")),
            Err(crate::ai_analysis::Error::Busy)
        );
        release.send(()).unwrap();
        for _ in 0..100 {
            if s.poll().is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(s.result.is_some());
        assert!(
            s.busy(),
            "keep the source bound until its conclusion is saved"
        );
        let path = s
            .auto_save
            .take()
            .expect("automatic save")
            .recv_timeout(Duration::from_secs(3))
            .unwrap()
            .unwrap();
        assert!(path.is_file());
        assert!(!s.busy());
    }
    #[test]
    fn unsaved_or_replacement_key_wins_and_invalid_input_does_not_fall_back() {
        use crate::ai_analysis::{Error, transport::KeyChoice};
        let mut state = ready();
        let fixture = "mock-local-key-not-production";
        for has_saved in [false, true] {
            state.key_present = has_saved;
            state.key = format!("  {fixture} \n");
            state.session_key_chosen = true;
            let KeyChoice::Session(key) = state
                .select_key()
                .unwrap_or_else(|_| panic!("key must remain available for the session"))
            else {
                panic!("saved key selected");
            };
            assert!(key.bytes() == fixture.as_bytes());
        }
        state.key = "  invalid space inside key  ".into();
        assert!(matches!(state.select_key(), Err(Error::InvalidKey)));
        state.key.clear();
        assert!(matches!(state.select_key(), Err(Error::NoKey)));
        state.session_key_chosen = false;
        assert!(matches!(state.select_key(), Ok(KeyChoice::Stored)));
    }
    #[test]
    fn cancelled_late_response_is_discarded_and_error_is_visible() {
        let mut s = ready();
        let (release, wait) = std::sync::mpsc::channel();
        s.send_with(move |_| {
            wait.recv().unwrap();
            Ok(mock_response())
        })
        .unwrap();
        s.cancel.store(true, Ordering::Release);
        assert!(s.busy());
        release.send(()).unwrap();
        for _ in 0..100 {
            if s.poll().is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(s.result.is_none());
        assert!(s.message.contains("отменено"));
        s.send_with(|_| {
            Err(crate::ai_analysis::classify_http(
                429,
                r#"{"error":{"code":"insufficient_quota"}}"#,
                "req_TestQuota",
            ))
        })
        .unwrap();
        for _ in 0..100 {
            if s.poll().is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(s.message.contains("квоту"));
        assert!(s.prepared.is_some());
        assert!(s.result.is_none());
    }
    fn render(
        app: &mut WinStateDiagApp,
        ctx: &egui::Context,
        events: Vec<egui::Event>,
    ) -> egui::FullOutput {
        let input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(1100., 860.),
            )),
            events,
            ..Default::default()
        };
        let mut output = ctx.run_ui(input, |_ui| app.ai_analysis_window(ctx));
        output.textures_delta.clear();
        output
    }
    fn find_text(shapes: &[egui::epaint::ClippedShape], needle: &str) -> Option<egui::Pos2> {
        fn search(shape: &egui::Shape, needle: &str) -> Option<egui::Pos2> {
            match shape {
                egui::Shape::Text(t)
                    if (t.galley.job.text == needle
                        || (needle != "Отправить в OpenAI"
                            && t.galley.job.text.contains(needle))) =>
                {
                    Some(t.pos + t.galley.rect.size() / 2.)
                }
                egui::Shape::Vec(v) => v.iter().find_map(|s| search(s, needle)),
                _ => None,
            }
        }
        shapes.iter().find_map(|s| search(&s.shape, needle))
    }
    #[test]
    fn regional_rejection_keeps_preview_and_shows_zip_folder_action() {
        let mut app = WinStateDiagApp {
            ai_analysis: ready(),
            ..Default::default()
        };
        let original = app.ai_analysis.prepared.as_ref().unwrap().clone();
        app.ai_analysis.selected_zip = Some(original.source.clone());
        let error = crate::ai_analysis::classify_http(
            403,
            r#"{"error":{"code":"unsupported_country_region_territory"}}"#,
            "req_RegionalFixture",
        );
        app.ai_analysis.message = error.message();
        app.ai_analysis.send_error = Some(error);
        let ctx = egui::Context::default();
        apply_theme(&ctx);
        fonts::install(&ctx);
        ctx.set_embed_viewports(true);
        let _ = render(&mut app, &ctx, vec![]);
        let frame = render(&mut app, &ctx, vec![]);
        assert!(find_text(&frame.shapes, "региона текущего подключения").is_some());
        assert!(find_text(&frame.shapes, "Открыть папку с ZIP").is_some());
        let after = app.ai_analysis.prepared.as_ref().unwrap();
        assert_eq!(after.text, original.text);
        assert_eq!(after.source, original.source);
    }
    #[test]
    fn genuine_egui_send_click_exact_request_result_and_reopen_without_resend() {
        let mut app = WinStateDiagApp {
            ai_analysis: ready(),
            ..Default::default()
        };
        let expected = app.ai_analysis.prepared.as_ref().unwrap().text.clone();
        let source = app.ai_analysis.prepared.as_ref().unwrap().source.clone();
        let before = std::fs::read(&source).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        app.ai_analysis.session_key_chosen = true;
        app.ai_analysis.key = " \r\nmock-session-key-value-123\t ".into();
        app.ai_analysis.test_transport = Some(Box::new(move |request| {
            let crate::ai_analysis::transport::KeyChoice::Session(key) = request.key else {
                panic!("A pasted key must override the saved credential");
            };
            assert!(key.bytes() == b"mock-session-key-value-123");
            tx.send(request.body).unwrap();
            Ok(mock_response())
        }));
        let ctx = egui::Context::default();
        apply_theme(&ctx);
        fonts::install(&ctx);
        ctx.set_embed_viewports(true);
        let mut at = None;
        for _ in 0..3 {
            let out = render(&mut app, &ctx, vec![]);
            at = find_text(&out.shapes, "Отправить в OpenAI").or(at);
        }
        let at = at.expect("real Send button rendered");
        assert!(rx.try_recv().is_err());
        for pressed in [true, false] {
            let _ = render(
                &mut app,
                &ctx,
                vec![
                    egui::Event::PointerMoved(at),
                    egui::Event::PointerButton {
                        pos: at,
                        button: egui::PointerButton::Primary,
                        pressed,
                        modifiers: Default::default(),
                    },
                ],
            );
        }
        let body = rx
            .recv_timeout(Duration::from_secs(3))
            .expect("GUI click reached injected transport");
        let json = powerlab_core::json::Json::parse(&body).unwrap();
        assert_eq!(
            json.get("input")
                .and_then(powerlab_core::json::Json::as_str),
            Some(expected.as_str())
        );
        for _ in 0..100 {
            app.poll_ai_analysis();
            if !app.ai_analysis.busy() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(app.ai_analysis.result_tab);
        let out = render(&mut app, &ctx, vec![]);
        assert!(find_text(&out.shapes, "ТЕСТОВЫЙ ОТВЕТ").is_some());
        let mut visible = find_text(&out.shapes, "input_tokens: 123").is_some();
        if !visible {
            let _ = render(
                &mut app,
                &ctx,
                vec![
                    egui::Event::PointerMoved(egui::pos2(12.0, 700.0)),
                    egui::Event::MouseWheel {
                        unit: egui::MouseWheelUnit::Point,
                        phase: egui::TouchPhase::Move,
                        delta: egui::vec2(0.0, -2400.0),
                        modifiers: Default::default(),
                    },
                ],
            );
            let out = render(&mut app, &ctx, vec![]);
            visible = find_text(&out.shapes, "input_tokens: 123").is_some();
        }
        assert!(
            visible,
            "actual usage remains available below the scrollable result"
        );
        let saved_path = app
            .ai_analysis
            .saved_path
            .clone()
            .expect("automatic sidecar");
        assert!(
            std::fs::read_to_string(&saved_path)
                .unwrap()
                .contains("SFC.txt")
        );
        assert_eq!(std::fs::read(&source).unwrap(), before);

        // A fresh controller reopens the same archive and never needs a transport.
        let mut reopened = WinStateDiagApp::default();
        reopened.prepare_ai_analysis(crate::ai_analysis::Source::Zip(source.clone()));
        for _ in 0..200 {
            reopened.poll_ai_analysis();
            if !reopened.ai_analysis.busy() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(reopened.ai_analysis.result_tab);
        assert_eq!(
            reopened.ai_analysis.saved_path.as_deref(),
            Some(saved_path.as_path())
        );
        let (a, input) = reopened.ai_analysis.result.as_ref().unwrap();
        assert_eq!(input, &source);
        assert_eq!(
            a.archive_sha256.as_deref(),
            crate::content_hash::sha256(before.as_slice())
                .ok()
                .as_deref()
        );
        assert!(matches!(
            rx.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Disconnected)
        ));
        assert_eq!(std::fs::read(&source).unwrap(), before);
        assert!(
            crate::ai_analysis::saved_for_archive(&source, &"0".repeat(64)).is_none(),
            "a different ZIP at the same path cannot reuse this conclusion"
        );
    }
}
