#[derive(Default)]
struct RepairCenterState {
    rx: Option<Receiver<crate::repair_center::ResultRecord>>,
    cancel: Arc<AtomicBool>,
    analyzed: Option<deep_checks::json::Value>,
    snapshot: String,
    saved_history: Option<deep_checks::json::Value>,
    plan: Option<crate::repair_center::Plan>,
    confirmed: bool,
    caches: std::collections::BTreeSet<String>,
    started: Option<Instant>,
    mutating: bool,
    current: String,
    message: String,
    volume: String,
    filter: String,
    installer_path: String,
    installer: Option<deep_checks::json::Value>,
    product: Option<deep_checks::json::Value>,
    history: Vec<crate::repair_center::ResultRecord>,
}
impl WinStateDiagApp {
    fn stage_center_plan(&mut self, operation: crate::repair_center::Operation) {
        self.repair_center.plan = Some(crate::repair_center::Plan {
            operation,
            identity: self.computer_name.clone(),
            snapshot: self.repair_center.snapshot.clone(),
            created: Instant::now(),
        });
        self.repair_center.confirmed = false;
    }
    fn start_repair_center(&mut self, op: crate::repair_center::Operation) {
        if self.report_busy() || self.crypto_rx.is_some() || self.reference.is_some() {
            self.repair_center.message = "Дождись завершения другой операции".into();
            return;
        }
        if op.mutating() {
            let Some(p) = &self.repair_center.plan else {
                return;
            };
            if p.operation != op {
                return;
            }
            if let Err(e) = p.authorize(
                self.repair_center.confirmed,
                &self.computer_name,
                &self.repair_center.snapshot,
                false,
            ) {
                self.repair_center.message = e;
                return;
            }
        }
        if cfg!(test) {
            self.repair_center.message = "Native operations disabled in unit tests".into();
            return;
        }
        let root = crate::app_paths::data_root(&exe_dir()).join("Logs/Repair");
        let id = self.computer_name.clone();
        let snapshot = self.repair_center.snapshot.clone();
        let cancel = Arc::new(AtomicBool::new(false));
        let token = cancel.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        self.repair_center.rx = Some(rx);
        self.repair_center.cancel = cancel;
        self.repair_center.started = Some(Instant::now());
        self.repair_center.mutating = op.mutating();
        self.repair_center.current = op.label().into();
        self.repair_center.message.clear();
        self.repair_center.message="Выполняется. Прерывание текущего обслуживания не поддерживается; дождись его завершения.".into();
        self.repair_center.plan = None;
        self.repair_center.confirmed = false;
        std::thread::spawn(move || {
            let _ = tx.send(crate::repair_center::run(op, id, root, snapshot, token));
        });
    }
    fn poll_repair_center(&mut self) {
        let Some(rx) = &self.repair_center.rx else {
            return;
        };
        let r = match rx.try_recv() {
            Ok(r) => r,
            Err(std::sync::mpsc::TryRecvError::Empty) => return,
            Err(_) => {
                self.repair_center.rx = None;
                self.repair_center.message = "Результат не получен; см. локальный журнал".into();
                return;
            }
        };
        self.repair_center.rx = None;
        if let Some(v) = crate::repair_center::parse(&r.raw) {
            self.repair_center.message = format!(
                "{}\n{}{}",
                crate::repair_center::status_label(crate::repair_center::field(&v, "Status")),
                crate::repair_center::field(&v, "Error"),
                crate::repair_center::field(&v, "Detail")
            );
            if crate::repair_center::field(&v, "Status") == "HISTORY_LOADED" {
                self.repair_center.saved_history = Some(v.clone());
            }
            if let Some(installer) = v.get("Installer")
                && crate::repair_center::field(installer, "Path")
                    == self.repair_center.installer_path
            {
                self.repair_center.installer = Some(installer.clone());
            }
            if v.get("Programs").is_some() {
                self.repair_center.snapshot = r.raw.clone();
                self.repair_center.analyzed = Some(v);
                self.repair_center.plan = None;
                self.repair_center.product = None;
                self.repair_center.caches.clear();
            }
        } else {
            self.repair_center.message = r
                .error
                .clone()
                .unwrap_or_else(|| "Результат не подтверждён".into());
        }
        push_journal(
            &mut self.journal,
            format!("Repair: {}", self.repair_center.message),
        );
        let files = crate::repair_center::history_files(&r.directory);
        if !files.is_empty() && r.directory.file_name().is_some_and(|n| n != "Repair") {
            self.contribute_evidence_to(Arc::clone(&self.package), "Repair", files);
        }
        self.repair_center.history.push(r);
    }
    fn repair_center_page(&mut self, ctx: &egui::Context) {
        if self.page != Page::Repair {
            return;
        }
        use crate::repair_center::{Operation as Op, field, rows};
        let busy = self.report_busy();
        let mut stage = None;
        let mut run = None;
        let mut windows = None;
        let mut compare = false;
        let old_selection = (
            self.repair_center.volume.clone(),
            self.repair_center.product.clone(),
        );
        let screen = ctx.content_rect();
        egui::Window::new("Repair · восстановление и обслуживание").id(egui::Id::new("repair_page"))
   .fixed_pos(egui::pos2((screen.center().x-625.0).max(8.0),screen.top()+145.0)).fixed_size(egui::vec2(1250.0,(screen.height()-215.0).max(350.0)))
   .movable(false).resizable(false).collapsible(false).title_bar(false).show(ctx,|ui|{
    egui::ScrollArea::vertical().show(ui,|ui|{ui.columns(2,|cols|{
     cols[0].group(|ui|{ui.heading("C1 · Восстановление Windows");for check in [DeepCheck::Dism,DeepCheck::Sfc]{if let Some(o)=self.deep_check_at(check.step_index()){ui.label(format!("{}: {}",check.key(),match o.result{deep_checks::CheckResult::Ok=>"Нарушений не найдено",deep_checks::CheckResult::Attention=>"Требует внимания",deep_checks::CheckResult::Error=>"Ошибка проверки",deep_checks::CheckResult::Unknown=>"Недостаточно данных",deep_checks::CheckResult::Skipped=>"Не выполнялось"}));}else{ui.label(format!("{}: нет результатов",check.key()));}}
      for (label,check,combined) in [("План DISM → SFC",DeepCheck::Dism,true),("План DISM",DeepCheck::Dism,false),("План SFC",DeepCheck::Sfc,false)] {
       let eligible=self.deep_check_at(check.step_index()).is_some_and(crate::repair::eligible) && (!combined || self.deep_check_at(DeepCheck::Sfc.step_index()).is_some_and(crate::repair::eligible));
       if ui.add_enabled(!busy && eligible,egui::Button::new(label)).clicked(){windows=Some((check,combined));}
      }ui.small("Источник, подтверждение, проверка каждого этапа. Перезагрузка вручную.");});
     cols[0].group(|ui|{ui.heading("C2 · Windows Update");if ui.add_enabled(!busy,egui::Button::new("Анализировать систему и программы")).clicked(){run=Some(Op::Analyze)}
      if let Some(v)=&self.repair_center.analyzed{ui.label(format!("Ошибок обновлений: {}",rows(v,"UpdateErrors").len()));for s in rows(v,"Services"){ui.label(format!("{}: {}",field(s,"Name"),field(s,"State")));}
      if ui.add_enabled(!busy && !rows(v,"UpdateErrors").is_empty(),egui::Button::new("План обслуживания кэша загрузок")).clicked(){stage=Some(Op::UpdateCache)}}ui.small("Политики и ACL не сбрасываются. Старый кэш сохраняется.");});
     cols[0].group(|ui|{ui.heading("C3 · Файловая система и накопители");
      if let Some(v)=&self.repair_center.analyzed{egui::ComboBox::from_id_salt("repair_volume").selected_text(if self.repair_center.volume.is_empty(){"Выбери том"}else{&self.repair_center.volume}).show_ui(ui,|ui|{for r in rows(v,"Volumes"){let d=field(r,"Drive");ui.selectable_value(&mut self.repair_center.volume,d.into(),format!("{} · {} · {}",d,field(r,"Label"),field(r,"FileSystem")));}});}
      let volume=self.repair_center.volume.clone();if ui.add_enabled(!busy && !volume.is_empty(),egui::Button::new("Проверить без исправлений")).clicked(){run=Some(Op::CheckVolume(volume.clone()))}
      if ui.add_enabled(!busy && !volume.is_empty(),egui::Button::new("План исправления тома")).clicked(){stage=Some(Op::RepairVolume(volume))}ui.small("При аппаратных ошибках сначала сохрани данные. /r и принудительное отключение запрещены.");});
     cols[0].group(|ui|{ui.heading("C4 · Очистка и обслуживание");if let Some(v)=&self.repair_center.analyzed{for r in rows(v,"Cleanup"){ui.label(format!("{} · {} · {} · {} байт",field(r,"Category"),field(r,"Risk"),field(r,"Status"),if field(r,"Bytes").is_empty(){"нет данных"}else{field(r,"Bytes")}));}}
      if let Some(v)=&self.repair_center.analyzed {
       ui.strong("SAFE · Проверенные эскизы Windows");ui.label(format!("Доступно: {}; используемые/защищённые объекты пропущены: {}",rows(v,"CacheFiles").len(),match v.get("CacheSkipped"){Some(deep_checks::json::Value::Num(n))=>format!("{n:.0}"),_=>"нет данных".into()}));
       for file in rows(v,"CacheFiles") {
        let path=field(file,"Path");let mut selected=self.repair_center.caches.contains(path);
        if ui.checkbox(&mut selected,path).changed(){if selected{self.repair_center.caches.insert(path.into());}else{self.repair_center.caches.remove(path);}self.repair_center.plan=None;self.repair_center.confirmed=false;}
       }
       let chosen=rows(v,"CacheFiles").iter().filter(|v|self.repair_center.caches.contains(field(v,"Path"))).map(|v|crate::repair_center::CacheFile{path:field(v,"Path").into(),hash:field(v,"Hash").into(),identity:field(v,"Identity").into()}).collect::<Vec<_>>();
       if ui.add_enabled(!busy && !chosen.is_empty(),egui::Button::new("План очистки выбранных эскизов")).clicked(){stage=Some(Op::ThumbnailCleanup(chosen));}
      }
      ui.small("Используемые файлы, ссылки и изменённые объекты пропускаются. Другие категории пока доступны только для анализа: документы, браузерные сессии, проекты, данные восстановления и корзина не удаляются.");
      if ui.add_enabled(!busy,egui::Button::new("Анализ WinSxS")).clicked(){run=Some(Op::ComponentAnalysis)}
      if ui.add_enabled(!busy && self.repair_center.analyzed.is_some(),egui::Button::new("План обслуживания компонентов")).clicked(){stage=Some(Op::ComponentCleanup)}});
     cols[1].group(|ui|{ui.heading("C5 · Установка и удаление программ");
      ui.label("Путь к подписанному MSI-пакету:");
      if ui.text_edit_singleline(&mut self.repair_center.installer_path).changed(){self.repair_center.installer=None;self.repair_center.plan=None;self.repair_center.confirmed=false;}
      let inspect=Op::AnalyzeInstaller(self.repair_center.installer_path.clone());
      if ui.add_enabled(!busy && inspect.valid(),egui::Button::new("Проверить пакет без установки")).clicked(){run=Some(inspect);}
      if let Some(p)=&self.repair_center.installer {
       ui.label(format!("{} · {}\nИздатель: {}\nПодпись: {}",field(p,"Name"),field(p,"Version"),field(p,"Publisher"),field(p,"SignaturePublisher")));
       let install=Op::MsiInstall(crate::repair_center::Installer{path:field(p,"Path").into(),hash:field(p,"Hash").into(),product:field(p,"ProductCode").into(),name:field(p,"Name").into(),publisher:field(p,"Publisher").into(),version:field(p,"Version").into()});
       if ui.add_enabled(!busy && install.valid(),egui::Button::new("План установки этого пакета")).clicked(){stage=Some(install);}
      }
      ui.separator();
      if ui.button("Intel Chipset · выбрать точную установку").clicked(){self.repair_center.filter="Chipset Device Software".into();self.repair_center.product=None;self.repair_center.plan=None;}
      ui.label("Поиск установленной программы:");ui.text_edit_singleline(&mut self.repair_center.filter);
      if let Some(v)=&self.repair_center.analyzed{egui::ScrollArea::vertical().id_salt("repair_programs").max_height(170.0).show(ui,|ui|{for r in rows(v,"Programs").iter().filter(|r|field(r,"Name").to_lowercase().contains(&self.repair_center.filter.to_lowercase())){if ui.selectable_label(self.repair_center.product.as_ref()==Some(r),format!("{} · {} · {}",field(r,"Name"),field(r,"Version"),field(r,"Context"))).clicked(){self.repair_center.product=Some(r.clone())}}});}
      if let Some(p)=&self.repair_center.product{ui.label(format!("Издатель: {}\nProductCode: {}",field(p,"Publisher"),field(p,"ProductCode")));let id=field(p,"ProductCode").to_owned();for(op,label)in[(Op::MsiRepair(id.clone()),"План восстановления"),(Op::MsiRemove(id),"План удаления")]{if ui.add_enabled(!busy && op.valid(),egui::Button::new(label)).clicked(){stage=Some(op)}}}
      ui.small("Для повреждённой регистрации выбери исходный подписанный MSI того же продукта; результат требует проверки. EXE/Store не поддерживаются. Intel — только выбранный продукт; DriverStore не затрагивается. Diagcab не включён: совместимость/распространение не подтверждены.");});
     cols[1].group(|ui|{ui.heading("C6 · Ход выполнения");ui.label(&self.repair_center.current);if self.repair_center.rx.is_some(){ui.spinner();
      if !self.repair_center.mutating && ui.button("Отменить анализ").clicked(){self.repair_center.cancel.store(true,Ordering::SeqCst);}
      if let Some(t)=self.repair_center.started{ui.label(format!("Прошло: {} с",t.elapsed().as_secs()));}ctx.request_repaint_after(Duration::from_millis(200));}ui.label(&self.repair_center.message);
      if let Some(p)=&self.repair_center.plan{ui.separator();ui.strong(p.operation.label());ui.label(p.operation.consequences());ui.checkbox(&mut self.repair_center.confirmed,"Объект проверен; последствия понятны; разрешаю этот план");if ui.add_enabled(!busy && self.repair_center.confirmed,egui::Button::new("Выполнить выбранный план")).clicked(){run=Some(p.operation.clone())}}});
     cols[1].group(|ui|{ui.heading("C7 · История и результаты");
      if ui.add_enabled(!busy,egui::Button::new("Прочитать сохранённую историю этого компьютера")).clicked(){run=Some(Op::History);}
      if ui.add_enabled(!busy && report_package::lock(&self.package).final_zip().is_some(),egui::Button::new("Сравнить текущий отчёт с предыдущим ZIP")).clicked(){compare=true;}
      if let Some(v)=&self.repair_center.saved_history{egui::ScrollArea::vertical().id_salt("persistent_repair_history").max_height(150.0).show(ui,|ui|{
       for record in rows(v,"Entries") {if let Some(meta)=record.get("metadata"){ui.collapsing(format!("{} · {}",field(meta,"started_at"),field(meta,"operation")),|ui|{ui.label(field(record,"detail"));});}}
      });}
      ui.label("Сравнение требует совпадения компьютера, схемы и аппаратного fingerprint. Отсутствующие данные не считаются улучшением.");egui::ScrollArea::vertical().id_salt("repair_history").max_height(180.0).show(ui,|ui|{for r in &self.repair_center.history{ui.collapsing(r.directory.file_name().unwrap_or_default().to_string_lossy(),|ui|{ui.label(r.error.as_deref().unwrap_or("Журнал сохранён"));ui.label(&r.raw);});}});ui.small("История включается в последующий диагностический и AI.zip отчёт.");});
    });});
   });
        if old_selection
            != (
                self.repair_center.volume.clone(),
                self.repair_center.product.clone(),
            )
        {
            self.repair_center.plan = None;
            self.repair_center.confirmed = false;
        }
        if compare && let Some(current) = report_package::lock(&self.package).final_zip() {
            match crate::win_dialog::open_zip(&self.reports_root) {
                crate::win_dialog::SavePick::Path(old) => run = Some(Op::Compare(current, old)),
                crate::win_dialog::SavePick::Cancelled => {}
                crate::win_dialog::SavePick::Unavailable => {
                    self.repair_center.message = "Диалог выбора отчёта недоступен".into()
                }
            }
        }
        if let Some(op) = stage {
            self.stage_center_plan(op)
        }
        if let Some(op) = run {
            self.start_repair_center(op)
        }
        if let Some((check, combined)) = windows {
            self.repair_ui.combined = combined;
            self.repair_ui.source_path.clear();
            self.repair_ui.source_index = 1;
            self.repair_ui.maintenance = false;
            self.repair_ui.pending = self
                .deep_check_at(check.step_index())
                .and_then(|o| crate::repair::plan(o, &system_drive()));
            self.repair_ui.open = true;
            self.repair_ui.message = "Проверь план и источник восстановления".into();
        }
    }
}

#[cfg(test)]
mod repair_center_flow_tests {
    use super::*;
    #[test]
    fn opening_repair_does_not_collect_or_execute() {
        let mut app = WinStateDiagApp {
            page: Page::Repair,
            ..Default::default()
        };
        let ctx = egui::Context::default();
        crate::ui::fonts::install(&ctx);
        let mut out = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(1400.0, 1200.0),
                )),
                ..Default::default()
            },
            |_| app.repair_center_page(&ctx),
        );
        out.textures_delta.clear();
        assert!(app.repair_center.rx.is_none());
        assert!(app.repair_center.history.is_empty());
        assert!(app.collector_requests.is_empty());
    }
    #[test]
    fn executor_requires_exact_explicit_plan_and_blocks_conflicts() {
        let mut app = WinStateDiagApp {
            computer_name: "SYNTHETIC-PC".into(),
            ..Default::default()
        };
        let op = crate::repair_center::Operation::MsiRemove(
            "{12345678-1234-1234-1234-123456789ABC}".into(),
        );
        app.start_repair_center(op.clone());
        assert!(app.repair_center.rx.is_none());
        app.stage_center_plan(op.clone());
        app.start_repair_center(op.clone());
        assert!(app.repair_center.message.contains("подтверждён"));
        app.repair_center.confirmed = true;
        app.start_repair_center(op);
        assert!(app.repair_center.message.contains("disabled in unit tests"));
        assert!(app.repair_center.rx.is_none());
        let (_tx, rx) = std::sync::mpsc::channel();
        app.repair_center.rx = Some(rx);
        assert!(app.report_busy());
        let before = app.collector_requests.len();
        app.apply(Action::Start);
        assert_eq!(before, app.collector_requests.len());
    }
    #[test]
    fn three_header_tabs_are_bounded_and_nonoverlapping() {
        for lang in [&i18n::RU, &i18n::EN] {
            let tabs = crate::ui::pages::page_tab_rects(egui::Pos2::ZERO, lang);
            assert_eq!(tabs.len(), 3);
            assert!(tabs[0].left() > 530.0);
            assert!(tabs[2].right() < 1033.0);
            assert!(tabs.windows(2).all(|p| p[0].right() < p[1].left()));
        }
    }
}
