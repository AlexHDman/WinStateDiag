#[derive(Default)]
struct AiExportState {
    rx: Option<Receiver<Result<crate::ai_export::Outcome, String>>>,
}
impl WinStateDiagApp {
    fn current_ai_input(&self) -> Option<crate::ai_export::Input> {
        let p = report_package::lock(&self.package);
        if let Some(id) = p.identity() {
            return Some(crate::ai_export::Input {
                zip: (!p.needs_finalize()).then(|| id.zip_path.clone()),
                directory: Some(id.evidence_dir()),
                base: id.base.clone(),
            });
        }
        if let RunState::Done { zip_path } = &self.state {
            return Some(crate::ai_export::Input::zip(zip_path.clone()));
        }
        None
    }
    fn request_ai_export(&mut self, choose_zip: bool) {
        if self.report_busy() || self.ai_export.rx.is_some() {
            return;
        }
        let input = if choose_zip {
            None
        } else {
            self.current_ai_input()
        };
        let input = if let Some(input) = input {
            input
        } else {
            match crate::win_dialog::open_zip(&self.reports_root) {
                crate::win_dialog::SavePick::Path(path) => crate::ai_export::Input::zip(path),
                crate::win_dialog::SavePick::Cancelled => return,
                crate::win_dialog::SavePick::Unavailable => {
                    push_journal(
                        &mut self.journal,
                        "[ERROR] Для ИИ: не удалось открыть выбор ZIP.".into(),
                    );
                    return;
                }
            }
        };
        self.launch_ai_export(input);
    }
    fn launch_ai_export(&mut self, input: crate::ai_export::Input) {
        if self.report_busy() || self.ai_export.rx.is_some() {
            return;
        }
        let destination = self.reports_root.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        self.ai_export.rx = Some(rx);
        push_journal(
            &mut self.journal,
            "Готовлю отчёт для ИИ из сохранённых материалов…".into(),
        );
        std::thread::spawn(move || {
            let _ = tx.send(crate::ai_export::export(&input, &destination));
        });
    }
    fn poll_ai_export(&mut self) {
        let Some(rx) = &self.ai_export.rx else {
            return;
        };
        let result = match rx.try_recv() {
            Ok(r) => r,
            Err(std::sync::mpsc::TryRecvError::Empty) => return,
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                Err("Экспорт для ИИ прерван: рабочий поток завершился без результата.".into())
            }
        };
        self.ai_export.rx = None;
        match result {
            Ok(out) => {
                self.report_opened = true;
                push_journal(
                    &mut self.journal,
                    format!(
                        "ZIP для ИИ сохранён: {} (TXT {} байт → ZIP {} байт). Материалов: {}; пропущено: {}; сокращено: {}; маскирований: {}.{}",
                        out.path.display(),
                        out.text_bytes,
                        out.zip_bytes,
                        out.included,
                        out.omitted,
                        out.limited,
                        out.masked,
                        if out.incomplete {
                            " Пакет неполный — причины указаны в файле."
                        } else {
                            ""
                        }
                    ),
                );
                if let Err(e) = engine::reveal_in_explorer(&out.path) {
                    push_journal(
                        &mut self.journal,
                        format!("[ERROR] Файл сохранён, но папка не открылась: {e}"),
                    );
                }
            }
            Err(e) => push_journal(&mut self.journal, format!("[ERROR] {e}")),
        }
    }
}
#[cfg(test)]
mod ai_export_flow_tests {
    use super::*;
    fn fixture() -> (WinStateDiagApp, PathBuf) {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target/ai-export-ui-tests")
            .join(format!(
                "{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
        std::fs::create_dir_all(&root).unwrap();
        let zip = root.join("Client-PC-10.11.26.zip");
        std::fs::write(
            &zip,
            report_package::build_zip(
                &[EvidenceFile::new(
                    "State_Summary.txt",
                    b"SFC CLEAN".to_vec(),
                )],
                crate::ui::sysinfo::local_time(),
            )
            .unwrap(),
        )
        .unwrap();
        let app = WinStateDiagApp {
            reports_root: root.clone(),
            state: RunState::Done {
                zip_path: zip.clone(),
            },
            ..Default::default()
        };
        (app, zip)
    }
    fn finish(app: &mut WinStateDiagApp) {
        let until = Instant::now() + Duration::from_secs(8);
        while app.ai_export.rx.is_some() && Instant::now() < until {
            app.poll_ai_export();
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(app.ai_export.rx.is_none());
    }
    fn click_a6() -> Vec<Action> {
        let ctx = egui::Context::default();
        crate::ui::fonts::install(&ctx);
        let vm = crate::ui::fixture::master_vm();
        let mut actions = Vec::new();
        let b = crate::ui::tokens::layout::JOURNAL_COMPACT_REPORT_BUTTON;
        let at = crate::ui::tokens::mrect(egui::Pos2::ZERO, b[0], b[1], b[2], b[3]).center();
        for pressed in [None, Some(true), Some(false)] {
            let mut input = egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(1600.0, 1200.0),
                )),
                ..Default::default()
            };
            input.events.push(egui::Event::PointerMoved(at));
            if let Some(pressed) = pressed {
                input.events.push(egui::Event::PointerButton {
                    pos: at,
                    button: egui::PointerButton::Primary,
                    pressed,
                    modifiers: Default::default(),
                });
            }
            let mut out = ctx.run_ui(input, |ui| {
                crate::ui::pages::draw_journal_compact(ui, egui::Pos2::ZERO, &vm, &mut actions)
            });
            out.textures_delta.clear();
        }
        actions
    }
    #[test]
    fn selected_zip_exports_its_materials_not_current_session() {
        let (mut app, current) = fixture();
        let selected = app.reports_root.join("Other-PC-10.11.26.zip");
        std::fs::write(
            &selected,
            report_package::build_zip(
                &[EvidenceFile::new(
                    "State_Summary.txt",
                    b"SELECTED MATERIAL".to_vec(),
                )],
                crate::ui::sysinfo::local_time(),
            )
            .unwrap(),
        )
        .unwrap();
        app.launch_ai_export(crate::ai_export::Input::zip(selected));
        finish(&mut app);
        let output =
            crate::ai_export::exported_text(app.reports_root.join("Other-PC-10.11.26.AI.zip"));
        assert!(output.contains("SELECTED MATERIAL"));
        assert!(!output.contains("SFC CLEAN"));
        assert!(current.exists());
    }
    #[test]
    fn action_worker_result_repeat_never_starts_diagnostics() {
        let (mut app, zip) = fixture();
        let before = std::fs::read(&zip).unwrap();
        let actions = click_a6();
        assert!(matches!(actions.as_slice(), [Action::ExportAi]));
        app.apply(actions.into_iter().next().unwrap());
        assert!(app.ai_export.rx.is_some());
        // A second click during the active worker cannot queue another export.
        app.apply(Action::ExportAi);
        assert!(!app.is_running());
        finish(&mut app);
        app.apply(Action::ExportAi);
        finish(&mut app);
        assert!(matches!(app.state, RunState::Done { .. }));
        assert_eq!(std::fs::read(zip).unwrap(), before);
        assert_eq!(
            std::fs::read_dir(&app.reports_root)
                .unwrap()
                .filter_map(Result::ok)
                .filter(|p| p.file_name().to_string_lossy().ends_with(".AI.zip"))
                .count(),
            2
        );
    }
    #[test]
    fn corrupt_zip_reports_error_and_clears_busy() {
        let (mut app, zip) = fixture();
        std::fs::write(zip, b"bad").unwrap();
        app.request_ai_export(false);
        finish(&mut app);
        assert!(app.journal.iter().any(|s| s.message.contains("[ERROR]")));
    }
}
