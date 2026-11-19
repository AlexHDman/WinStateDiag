#[derive(Default)]
struct BiosUiState {
    rx: Option<Receiver<Result<crate::bios::Check, String>>>,
    cancel: Arc<std::sync::atomic::AtomicBool>,
    identity: Option<crate::bios::Identity>,
    result: Option<Result<crate::bios::Check, String>>,
    package: Option<SharedPackage>,
    client: String,
    computer: String,
    session: String,
    cache: std::collections::BTreeMap<String, crate::bios::Check>,
}
impl Drop for BiosUiState {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::SeqCst);
    }
}
impl BiosUiState {
    fn reset_request(&mut self) {
        let cache = std::mem::take(&mut self.cache);
        *self = Self::default();
        self.cache = cache;
    }
}
impl WinStateDiagApp {
    fn bios_cached(&self) -> Option<&crate::bios::Check> {
        if self.bios_ui.result.is_some() || self.bios_ui.rx.is_some() {
            return None;
        }
        let id = &self.passport.as_ref()?.as_ref().ok()?.bios_identity;
        self.bios_ui.cache.get(&id.json())
    }
    fn bios_request_matches(&self) -> bool {
        self.bios_ui.client == self.client_name
            && self.bios_ui.computer == self.computer_name
            && self
                .bios_ui
                .package
                .as_ref()
                .is_some_and(|p| Arc::ptr_eq(p, &self.package))
            && self.bios_ui.session
                == report_package::lock(&self.package)
                    .session()
                    .map_or(String::new(), |s| s.session_id.clone())
            && self
                .passport
                .as_ref()
                .and_then(|p| p.as_ref().ok())
                .map(|p| &p.bios_identity)
                == self.bios_ui.identity.as_ref()
    }
    fn bios_display(&self, p: &passport::Passport) -> String {
        if p.bios_identity.version.is_empty() && p.bios_identity.date.is_empty() {
            return p.bios_display();
        }
        if self.bios_ui.identity.as_ref() == Some(&p.bios_identity)
            && let Some(Ok(c)) = &self.bios_ui.result
        {
            return p.bios_identity.display(
                c.installed_public
                    .as_deref()
                    .or(crate::bios::confirmed_public(&p.bios_identity).as_deref()),
            );
        }
        if let Some(c) = self.bios_cached() {
            return p.bios_identity.display(c.installed_public.as_deref());
        }
        p.bios_display()
    }

    fn start_bios_check(&mut self) {
        if self.bios_ui.rx.is_some() {
            return;
        }
        let Some(Ok(p)) = &self.passport else {
            push_journal(
                &mut self.journal,
                "[WARN] BIOS: паспорт компьютера ещё не получен".into(),
            );
            return;
        };
        let id = p.bios_identity.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        self.bios_ui.cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
        self.bios_ui.identity = Some(id.clone());
        self.bios_ui.result = None;
        self.bios_ui.rx = Some(rx);
        self.bios_ui.package = Some(Arc::clone(&self.package));
        self.bios_ui.client = self.client_name.clone();
        self.bios_ui.computer = self.computer_name.clone();
        self.bios_ui.session = report_package::lock(&self.package)
            .session()
            .map_or(String::new(), |s| s.session_id.clone());
        #[cfg(not(test))]
        let cancel = Arc::clone(&self.bios_ui.cancel);
        #[cfg(test)]
        let body = self
            .bios_test_body
            .clone()
            .unwrap_or_else(|| Err("Сеть в GUI unit-тесте отключена".into()));
        push_journal(
            &mut self.journal,
            "BIOS: проверяю официальный каталог обновлений…".into(),
        );
        std::thread::spawn(move || {
            #[cfg(not(test))]
            let started = Instant::now();
            #[cfg(not(test))]
            let result = crate::bios_sources::check_pages(&id, |url| {
                let budget = Duration::from_secs(60)
                    .checked_sub(started.elapsed())
                    .ok_or("Истекло время проверки BIOS")?;
                crate::bios_net::fetch_page(url, &cancel, budget)
            });
            #[cfg(test)]
            let result = crate::bios_sources::check_with(&id, |_| body.clone());
            let _ = tx.send(result);
        });
    }
    fn poll_bios_check(&mut self) {
        let Some(rx) = &self.bios_ui.rx else { return };
        let result = match rx.try_recv() {
            Ok(r) => r,
            Err(std::sync::mpsc::TryRecvError::Empty) => return,
            Err(_) => Err("Проверка BIOS прервана без результата".into()),
        };
        self.bios_ui.rx = None;
        if !self.bios_request_matches() {
            self.bios_ui.result = None;
            self.bios_ui.identity = None;
            push_journal(
                &mut self.journal,
                "BIOS: поздний ответ предыдущей сессии отброшен; текущая карточка не изменена"
                    .into(),
            );
            return;
        }
        if let (Some(id), Ok(c)) = (&self.bios_ui.identity, &result) {
            if self.bios_ui.cache.len() >= 16 {
                self.bios_ui.cache.pop_first();
            }
            self.bios_ui.cache.insert(id.json(), c.clone());
        }
        let message = match &result {
            Ok(c) => format!("BIOS: {}. {}", c.label(), c.reason),
            Err(e) => format!("[WARN] BIOS: Не удалось проверить. {e}"),
        };
        push_journal(&mut self.journal, message);
        self.bios_ui.result = Some(result);
        if self
            .passport
            .as_ref()
            .and_then(|p| p.as_ref().ok())
            .map(|p| &p.bios_identity)
            == self.bios_ui.identity.as_ref()
            && let Some(package) = self.bios_ui.package.clone()
        {
            self.persist_bios_to(package);
        }
    }
    fn bios_view(&self) -> crate::ui::vm::BiosVm {
        let id = self
            .passport
            .as_ref()
            .and_then(|p| p.as_ref().ok())
            .map(|p| &p.bios_identity);
        let details=id.map(|i|format!("Компьютер: {} {}\nПлата: {} {} · ревизия {}\nBIOS vendor: {}\nSMBIOS: {}\nПолный ID: {}\nИсходная дата: {}",i.system_maker,i.system_model,i.board_maker,i.board_model,i.board_revision,i.vendor,i.version,i.full_id,i.date)).unwrap_or_else(||"Данные BIOS ещё не получены".into());
        let (label, tip, available, preview) = match &self.bios_ui.result {
            Some(Ok(c)) => (
                c.label(),
                format!("{details}\n{}", c.details()),
                !c.support.is_empty(),
                c.preview
                    .as_ref()
                    .map(|r| {
                        format!(
                            "{}: {}",
                            if r.channel == crate::bios::Channel::Beta {
                                "Бета"
                            } else {
                                "Предв.?"
                            },
                            r.version
                        )
                    })
                    .unwrap_or_default(),
            ),
            Some(Err(e)) => (
                match crate::bios::failure_code(e) {
                    "MODEL_AMBIGUOUS" => "Модель требует уточнения".into(),
                    "UNSUPPORTED" => "Не поддерживается".into(),
                    _ => format!(
                        "Не удалось проверить{}",
                        if e.contains("HTTP 403") {
                            ": HTTP 403"
                        } else if e.contains("HTTP 429") {
                            ": HTTP 429"
                        } else {
                            ""
                        }
                    ),
                },
                format!("{details}\n{e}"),
                false,
                String::new(),
            ),
            None if self.bios_ui.rx.is_some() => {
                ("Проверяется".into(), details, false, String::new())
            }
            None => {
                if let Some(c) = self.bios_cached() {
                    (
                        format!("Кэш: {}", c.label()),
                        format!(
                            "{details}\nСохранённый результат; кнопка выполняет новый запрос.\n{}",
                            c.details()
                        ),
                        !c.support.is_empty(),
                        String::new(),
                    )
                } else {
                    ("Не проверено".into(), details, false, String::new())
                }
            }
        };
        crate::ui::vm::BiosVm {
            label,
            tooltip: tip,
            available,
            preview,
            enabled: id.is_some() && self.passport_rx.is_none() && self.bios_ui.rx.is_none(),
        }
    }
    fn open_bios_support(&mut self) {
        let check = match &self.bios_ui.result {
            Some(Ok(c)) => Some(c),
            _ => self.bios_cached(),
        };
        let Some(check) = check else { return };
        if crate::bios_net::official_host(&check.support).is_none() {
            return;
        }
        // Only the verified exact-model support page; never a firmware package.
        if let Err(e) = engine::open_web_page(&check.support) {
            push_journal(
                &mut self.journal,
                format!("[ERROR] Не удалось открыть страницу BIOS: {e}"),
            );
        }
    }
    fn persist_bios_to(&mut self, package: SharedPackage) {
        if report_package::lock(&package).session().is_none() {
            return;
        }
        let Some(Ok(p)) = &self.passport else { return };
        if p.bios_identity.version.is_empty() && p.bios_identity.date.is_empty() {
            return;
        }
        let id = p.bios_identity.json();
        let result = match &self.bios_ui.result {
            Some(Ok(c)) => c.details(),
            Some(Err(e)) => format!("Не удалось проверить: {e}"),
            None => self.bios_cached().map_or("Не проверено".into(), |c| {
                format!("Кэш предыдущей проверки\n{}", c.details())
            }),
        };
        let check_json = match &self.bios_ui.result {
            Some(Ok(c)) => c.json(),
            Some(Err(e)) => format!(
                "{{\"status\":{},\"reason\":{}}}",
                deep_checks::json::string(crate::bios::failure_code(e)),
                deep_checks::json::string(e)
            ),
            None => self
                .bios_cached()
                .map_or("{\"status\":\"NOT_CHECKED\"}".into(), |c| c.json()),
        };
        let display = self.bios_display(p);
        let json = format!(
            "{{\"version\":{},\"identity\":{},\"installed_display\":{},\"check\":{},\"check_result\":{},\"cached\":{}}}",
            deep_checks::json::string(crate::APP_VERSION),
            id,
            deep_checks::json::string(&display),
            deep_checks::json::string(&result),
            check_json,
            self.bios_cached().is_some()
        );
        self.contribute_evidence_to(
            package,
            "BIOS",
            vec![
                EvidenceFile::new("BIOS_Identity.json", json.into_bytes()),
                EvidenceFile::new(
                    "BIOS_Update.txt",
                    format!("Установлено: {display}\n{result}\nИсходные данные: {id}\n")
                        .into_bytes(),
                ),
            ],
        );
    }
}

#[cfg(test)]
mod bios_flow_tests {
    use super::*;
    fn app() -> WinStateDiagApp {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target/bios-tests")
            .join(format!(
                "{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
        std::fs::create_dir_all(&root).unwrap();
        WinStateDiagApp {
            reports_root: root.join("Reports"),
            language_pref_dir: root.clone(),
            package: Arc::new(Mutex::new(SessionPackage::new(root.join("Reports"), None))),
            computer_name: "Synthetic-PC".into(),
            client_name: "Synthetic".into(),
            passport: Some(Ok(passport::Passport {
                bios_identity: crate::bios::Identity {
                    system_maker: "MSI".into(),
                    system_model: "MS-7D46".into(),
                    board_maker: "MSI".into(),
                    board_model: "PRO H610M-G DDR4".into(),
                    version: "1.Q0".into(),
                    date: "20260102000000.000000-720".into(),
                    ..Default::default()
                },
                ..Default::default()
            })),
            bios_test_body: Some(Ok(
                include_str!("../scripts/fixtures/bios/msi-panel.json").into()
            )),
            ..Default::default()
        }
    }
    fn click(vm: &crate::ui::vm::BiosVm) -> Vec<Action> {
        let ctx = egui::Context::default();
        crate::ui::fonts::install(&ctx);
        let mut full = crate::ui::fixture::master_vm();
        full.bios = vm.clone();
        let b = crate::ui::tokens::layout::PASSPORT_CARD;
        let rect = crate::ui::tokens::mrect(egui::Pos2::ZERO, b[0], b[1], b[2], b[3]);
        let at = egui::pos2(rect.right() - 23.0, rect.bottom() - 16.0);
        let mut actions = Vec::new();
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
                crate::ui::pages::draw_passport_actions(ui, egui::Pos2::ZERO, &full, &mut actions)
            });
            out.textures_delta.clear();
        }
        actions
    }
    fn finish(app: &mut WinStateDiagApp) {
        let until = Instant::now() + Duration::from_secs(3);
        while app.bios_ui.rx.is_some() && Instant::now() < until {
            app.poll_bios_check();
            std::thread::sleep(Duration::from_millis(5))
        }
        assert!(app.bios_ui.rx.is_none());
    }
    #[test]
    fn gui_click_worker_result_repeat_and_zip_never_rescan() {
        let mut a = app();
        assert_eq!(a.bios_view().label, "Не проверено");
        a.begin_operation(false);
        let actions = click(&a.bios_view());
        assert!(matches!(actions.as_slice(), [Action::CheckBios]));
        a.apply(actions.into_iter().next().unwrap());
        let token = a.bios_ui.cancel.clone();
        assert!(!a.bios_view().enabled);
        a.apply(Action::CheckBios);
        assert!(Arc::ptr_eq(&token, &a.bios_ui.cancel));
        assert!(click(&a.bios_view()).is_empty());
        finish(&mut a);
        assert_eq!(a.bios_view().label, "Доступен: 7D46v1R");
        assert_eq!(a.passport_rows()[4].value, "7D46v1Q (02.01.2026)");
        let zip = report_package::lock(&a.package).final_zip().unwrap();
        let files = report_package::read_zip(&zip).unwrap();
        let json = files
            .iter()
            .find(|f| {
                f.name.starts_with("BIOS_Identity")
                    && String::from_utf8_lossy(&f.bytes).contains("7D46v1Q")
            })
            .unwrap();
        let text = String::from_utf8_lossy(&json.bytes);
        assert!(
            text.contains("1.Q0")
                && text.contains("20260102000000.000000-720")
                && text.contains("7D46v1Q")
        );
        assert!(deep_checks::json::parse(&text).is_some());
        assert!(files.iter().any(|f| f.name.ends_with("BIOS_Update.txt")));
        a.apply(Action::CheckBios);
        finish(&mut a);
        assert_eq!(report_package::lock(&a.package).final_zip().unwrap(), zip);
        assert!(a.collector_requests.is_empty());
        assert!(!a.is_running());
    }
    #[test]
    fn network_failure_is_visible_and_does_not_show_current() {
        let mut a = app();
        a.bios_test_body = Some(Err("HTTP 403".into()));
        a.apply(Action::CheckBios);
        finish(&mut a);
        assert_eq!(a.bios_view().label, "Не удалось проверить: HTTP 403");
        assert!(a.bios_view().tooltip.contains("HTTP 403"));
        assert!(a.journal.iter().any(|j| j.message.contains("HTTP 403")));
        assert!(!a.bios_view().available);
        assert!(report_package::lock(&a.package).final_zip().is_none());
    }
    #[test]
    fn stale_identity_is_not_attached_to_another_passport() {
        let mut a = app();
        a.apply(Action::CheckBios);
        a.passport
            .as_mut()
            .unwrap()
            .as_mut()
            .unwrap()
            .bios_identity
            .board_model = "Different".into();
        finish(&mut a);
        assert!(!a.bios_view().available);
        assert_eq!(a.bios_view().label, "Не проверено");
        assert!(
            a.journal
                .iter()
                .any(|j| j.message.contains("поздний ответ"))
        );
    }
    #[test]
    fn closing_bios_state_cancels_owned_work() {
        let state = BiosUiState::default();
        let flag = state.cancel.clone();
        drop(state);
        assert!(flag.load(Ordering::SeqCst));
    }
    #[test]
    fn bios_cache_is_explicit_and_refresh_failure_never_reuses_success() {
        let mut a = app();
        a.apply(Action::CheckBios);
        finish(&mut a);
        assert_eq!(a.bios_ui.cache.len(), 1);
        a.bios_ui.reset_request();
        assert!(a.bios_view().label.starts_with("Кэш:"));
        assert!(a.bios_view().tooltip.contains("Проверено:"));
        a.bios_test_body = Some(Err("HTTP 429".into()));
        a.apply(Action::CheckBios);
        assert_eq!(a.bios_view().label, "Проверяется");
        finish(&mut a);
        assert_eq!(a.bios_view().label, "Не удалось проверить: HTTP 429");
        assert!(a.bios_cached().is_none());
        assert!(!a.bios_view().available);
    }
    #[test]
    fn bios_late_same_hardware_response_cannot_change_new_client_or_session() {
        for new_client in [false, true] {
            let mut a = app();
            a.begin_operation(false);
            a.apply(Action::CheckBios);
            if new_client {
                a.client_name = "Another synthetic client".into();
            } else {
                let next = report_package::lock(&a.package).successor(
                    report_package::SessionIdentity::new(
                        "new-session",
                        "Synthetic",
                        "Synthetic-PC",
                    ),
                );
                a.package = Arc::new(Mutex::new(next));
            }
            finish(&mut a);
            assert!(a.bios_ui.result.is_none());
            assert_eq!(a.bios_view().label, "Не проверено");
        }
    }
    #[test]
    fn bios_offline_check_preserves_report_and_ai_export() {
        let mut a = app();
        a.begin_operation(false);
        a.bios_test_body = Some(Err("HTTP 403".into()));
        a.apply(Action::CheckBios);
        finish(&mut a);
        let zip = report_package::lock(&a.package).final_zip().unwrap();
        assert!(report_package::lock(&a.package).packaging_error().is_none());
        let before = std::fs::read(&zip).unwrap();
        let out =
            crate::ai_export::export(&crate::ai_export::Input::zip(zip.clone()), &a.reports_root)
                .unwrap();
        let text = crate::ai_export::exported_text(out.path);
        assert!(text.contains("CHECK_FAILED") && text.contains("HTTP 403"));
        assert_eq!(before, std::fs::read(zip).unwrap());
        assert!(a.collector_requests.is_empty());
    }
}
