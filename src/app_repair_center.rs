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
    target: String,
    focus_history: bool,
    history_titles: Vec<String>,
    message: String,
    volume: String,
    filter: String,
    cleanup_category: usize,
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
        self.repair_center.target = if matches!(
            op,
            crate::repair_center::Operation::MsiRepair(_)
                | crate::repair_center::Operation::MsiRemove(_)
                | crate::repair_center::Operation::AnalyzeProduct(_)
        ) {
            self.repair_center
                .product
                .as_ref()
                .map(|p| {
                    format!(
                        "{} · {}",
                        crate::repair_center::field(p, "Name"),
                        crate::repair_center::field(p, "Version")
                    )
                })
                .unwrap_or("Выбранная программа".into())
        } else {
            crate::repair_center::plan_target(&op)
        };
        self.repair_center.message.clear();
        self.repair_center.message = if op.mutating() {
            "Выполняется обслуживание; безопасная отмена текущего этапа не поддерживается."
        } else {
            "Выполняется анализ; доступна безопасная отмена."
        }
        .into();
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
                "{}\n{}{}{}",
                crate::repair_center::status_label(crate::repair_center::field(&v, "Status")),
                crate::repair_center::field(&v, "Error"),
                crate::repair_center::field(&v, "Detail"),
                crate::repair_center::field(&v, "EventReadError")
            );
            if crate::repair_center::field(&v, "Status") == "COMPARISON" {
                self.repair_center.focus_history = true;
            }
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
            format!("Ремонт: {}", self.repair_center.message),
        );
        let files = crate::repair_center::history_files(&r.directory);
        if !files.is_empty() && r.directory.file_name().is_some_and(|n| n != "Repair") {
            self.contribute_evidence_to(Arc::clone(&self.package), "Repair", files);
        }
        let status = crate::repair_center::parse(&r.raw)
            .map(|v| {
                crate::repair_center::status_label(crate::repair_center::field(&v, "Status"))
                    .to_owned()
            })
            .unwrap_or_else(|| "Результат не подтверждён".into());
        self.repair_center.history_titles.push(format!(
            "{} · {} · {} · {}",
            local_iso(crate::ui::sysinfo::local_time()),
            self.repair_center.current,
            self.repair_center.target,
            status
        ));
        self.repair_center.history.push(r);
    }
    fn repair_center_page(&mut self, ctx: &egui::Context) {
        let is_ru = self.language == Language::Ru;
        let l = |s| crate::locale::literal(is_ru, s);

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
            self.repair_center.cleanup_category,
        );
        let readable_scale = (1.0 / ctx.zoom_factor()).clamp(0.75, 2.0);
        let screen = ctx.content_rect();
        let width = (screen.width() - 48.).clamp(300., 1250.);
        egui::Window::new(l("Ремонт")).id(egui::Id::new("repair_page"))
         .fixed_pos(egui::pos2((screen.center().x-width/2.).max(8.),screen.top()+145.))
         .fixed_size(egui::vec2(width,(screen.height()-205.).max(250.)))
         .movable(false).resizable(false).collapsible(false).title_bar(false).show(ctx,|ui|{
          ui.style_mut().text_styles.insert(egui::TextStyle::Body,egui::FontId::proportional(16.*readable_scale));
          ui.style_mut().text_styles.insert(egui::TextStyle::Button,egui::FontId::proportional(16.*readable_scale));
          ui.style_mut().text_styles.insert(egui::TextStyle::Small,egui::FontId::proportional(14.*readable_scale));
          ui.style_mut().spacing.button_padding=egui::vec2(12.*readable_scale,7.*readable_scale);
          ui.style_mut().spacing.interact_size.y=32.*readable_scale;
          ui.style_mut().spacing.item_spacing=egui::vec2(8.,8.);
          ui.style_mut().visuals.override_text_color=Some(c::TEXT_PRIMARY);
          let widgets=&mut ui.style_mut().visuals.widgets;widgets.inactive.bg_fill=c::BG_FIELD;widgets.inactive.weak_bg_fill=c::BG_FIELD;widgets.inactive.bg_stroke=egui::Stroke::new(1.,c::BORDER_NORMAL);
          egui::ScrollArea::vertical().id_salt("repair-page-scroll").auto_shrink([false,false]).show(ui,|ui|{
           ui.horizontal_wrapped(|ui|{ui.heading(egui::RichText::new(l("Ремонт")).color(c::TEXT_TITLE));if ui.add_enabled(!busy,egui::Button::new(l("Анализировать систему и программы"))).clicked(){run=Some(Op::Analyze);}});
           ui.label(l("Сначала анализ и план. Изменения — только после твоего подтверждения."));
           ui.add_space(4.);
           // One card renderer for both column and narrow layouts. No backend work on layout/navigation.
           let mut draw=|ui:&mut egui::Ui,n:usize|{
            let titles=[l("Восстановление Windows"),l("Восстановление Windows Update"),l("Файловая система и накопители"),l("Очистка и обслуживание"),l("Установка и удаление программ")];
            repair_card(ui,&format!("C{}",n+1),titles[n],|ui|{
             match n {
              0=>{
               let clean=[DeepCheck::Dism,DeepCheck::Sfc].iter().all(|k|self.deep_check_at(k.step_index()).is_some_and(|o|o.result==deep_checks::CheckResult::Ok));
               if clean{ui.label(egui::RichText::new(l("Исправление не требуется")).color(c::GREEN_SUCCESS));}
               for check in [DeepCheck::Dism,DeepCheck::Sfc]{ui.label(format!("{}: {}",check.key(),self.deep_check_at(check.step_index()).map(|o|match o.result{deep_checks::CheckResult::Ok=>l("Нарушений не найдено"),deep_checks::CheckResult::Attention=>l("Требует внимания"),deep_checks::CheckResult::Error=>l("Ошибка проверки"),deep_checks::CheckResult::Unknown=>l("Недостаточно данных"),deep_checks::CheckResult::Skipped=>l("Не выполнялось")}).unwrap_or(l("Проверка ещё не выполнена"))));}
               ui.horizontal_wrapped(|ui|{for(label,check,combined)in[(l("План DISM → SFC"),DeepCheck::Dism,true),(l("План DISM"),DeepCheck::Dism,false),(l("План SFC"),DeepCheck::Sfc,false)]{
                let eligible=self.deep_check_at(check.step_index()).is_some_and(crate::repair::eligible)&&(!combined||self.deep_check_at(DeepCheck::Sfc.step_index()).is_some_and(crate::repair::eligible));
                if eligible&&ui.add_enabled(!busy,egui::Button::new(label)).clicked(){windows=Some((check,combined));}
               }});
               if !clean&&[DeepCheck::Dism,DeepCheck::Sfc].iter().all(|k|self.deep_check_at(k.step_index()).is_none()){ui.label(l("Выполни диагностическую проверку SFC/DISM, чтобы получить обоснованный план."));}
              }
              1=>{
               if let Some(v)=&self.repair_center.analyzed {
                let update_unavailable=rows(v,"Errors").iter().any(|v|v.as_str().is_some_and(|s|s.starts_with("Windows Update:")||s.starts_with(l("Службы:"))));
                if update_unavailable{ui.label(egui::RichText::new(l("Проверка Windows Update неполная — часть данных недоступна")).color(c::YELLOW_WARNING));}else{ui.label(crate::locale::text(is_ru,&format!("Событий ошибок обновления: {}",rows(v,"UpdateErrors").len())).into_owned());}
                if !rows(v,"UpdateErrors").is_empty(){if ui.add_enabled(!busy,egui::Button::new(l("План обслуживания кэша загрузок"))).clicked(){stage=Some(Op::UpdateCache);}}else if !update_unavailable{ui.label(l("Оснований для обслуживания кэша в анализе не найдено. Это не проверка установки обновлений."));}
                ui.collapsing(l("Службы и подробности анализа"),|ui|{for service in rows(v,"Services"){ui.label(format!("{}: {}",field(service,"Name"),field(service,"State")));}ui.label(l("Политики и ACL не сбрасываются. Старый кэш сохраняется."));for error in rows(v,"Errors"){ui.label(format!("{error:?}"));}for event in rows(v,"UpdateErrors"){ui.label(format!("{event:?}"));}});
               }else{ui.label(l("Анализ Windows Update ещё не выполнен."));if ui.add_enabled(!busy,egui::Button::new(l("Проверить Windows Update"))).clicked(){run=Some(Op::Analyze);}}
              }
              2=>{
               if let Some(v)=&self.repair_center.analyzed{egui::ComboBox::from_id_salt("repair_volume").selected_text(if self.repair_center.volume.is_empty(){l("Выбери том")}else{&self.repair_center.volume}).show_ui(ui,|ui|{for r in rows(v,"Volumes"){let d=field(r,"Drive");ui.selectable_value(&mut self.repair_center.volume,d.into(),format!("{} · {} · {}",d,field(r,"Label"),field(r,"FileSystem")));}});}else{ui.label(l("Список томов появится после анализа."));}
               let volume=self.repair_center.volume.clone();ui.label(crate::locale::text(is_ru,&format!("Выбранный том: {}",if volume.is_empty(){l("не выбран")}else{&volume})).into_owned());
               ui.horizontal_wrapped(|ui|{if ui.add_enabled(!busy&&!volume.is_empty(),egui::Button::new(l("Проверить без исправлений"))).clicked(){run=Some(Op::CheckVolume(volume.clone()));}
                if ui.add_enabled(!busy&&!volume.is_empty(),egui::Button::new(l("План исправления тома"))).clicked(){stage=Some(Op::RepairVolume(volume.clone()));}});
               for r in self.repair_center.history.iter().rev(){if let Some(v)=crate::repair_center::parse(&r.raw)&&v.get("Before").is_some_and(|v|field(v,"DeviceID")==volume){ui.label(crate::locale::text(is_ru,crate::repair_center::status_label(field(&v,"Status"))));ui.collapsing(l("Последний CHKDSK: подробности"),|ui|{ui.label(&r.raw);});break;}}
               ui.collapsing(l("Условия и риски"),|ui|{ui.label(l("При аппаратных ошибках сначала сохрани данные. /r, принудительное отключение и автоматическая перезагрузка не выполняются."));});
              }
              3=>{
               let categories=[l("Эскизы Windows"),l("Компоненты Windows / WinSxS"),l("Другие категории · только анализ")];
               egui::ComboBox::from_id_salt("maintenance-category").selected_text(categories[self.repair_center.cleanup_category.min(2)]).show_ui(ui,|ui|{for(i,name)in categories.iter().enumerate(){ui.selectable_value(&mut self.repair_center.cleanup_category,i,*name);}});
               if self.repair_center.cleanup_category==0 {
               if let Some(v)=&self.repair_center.analyzed {
                ui.label(crate::locale::text(is_ru,&format!("Доступно проверенных файлов эскизов: {}",rows(v,"CacheFiles").len())).into_owned());
                egui::CollapsingHeader::new(l("Выбрать эскизы Windows")).show(ui,|ui|{for f in rows(v,"CacheFiles"){let path=field(f,"Path");let mut selected=self.repair_center.caches.contains(path);if ui.checkbox(&mut selected,path).changed(){if selected{self.repair_center.caches.insert(path.into());}else{self.repair_center.caches.remove(path);}self.repair_center.plan=None;self.repair_center.confirmed=false;}}});
                let chosen=rows(v,"CacheFiles").iter().filter(|f|self.repair_center.caches.contains(field(f,"Path"))).map(|f|crate::repair_center::CacheFile{path:field(f,"Path").into(),hash:field(f,"Hash").into(),identity:field(f,"Identity").into()}).collect::<Vec<_>>();
                if !chosen.is_empty()&&ui.add_enabled(!busy,egui::Button::new(l("План очистки выбранных эскизов"))).clicked(){stage=Some(Op::ThumbnailCleanup(chosen));}
                ui.collapsing(l("Категории, объёмы и ограничения"),|ui|{for r in rows(v,"Cleanup"){ui.label(format!("{} · {} · {:?}",field(r,"Category"),field(r,"Risk"),r.get("Bytes")));}ui.label(l("Используемые файлы, ссылки и изменённые объекты пропускаются. Браузеры, проекты, документы, корзина, Windows.old и восстановление автоматически не очищаются."));});
               }else{ui.label(l("Оценка объёма появится после анализа. Анализ ничего не удаляет."));}
               }
               if self.repair_center.cleanup_category==2 {if let Some(v)=&self.repair_center.analyzed{for category in rows(v,"Cleanup"){ui.label(crate::locale::text(is_ru,&format!("{} · {} байт",field(category,"Category"),if field(category,"Bytes").is_empty(){l("нет данных")}else{field(category,"Bytes")})).into_owned());}}else{ui.label(l("Сначала выполни анализ системы. Удаление для этих категорий недоступно."));}}
               if self.repair_center.cleanup_category==1 {ui.label(l("Штатное обслуживание Windows, без ResetBase."));
               ui.horizontal_wrapped(|ui|{if ui.add_enabled(!busy,egui::Button::new(l("Анализ WinSxS"))).clicked(){run=Some(Op::ComponentAnalysis);}
                if ui.add_enabled(!busy&&self.repair_center.analyzed.is_some(),egui::Button::new(l("План обслуживания компонентов"))).clicked(){stage=Some(Op::ComponentCleanup);}});
               }
              }
              _=>{
               ui.label(l("Установленная программа:"));ui.text_edit_singleline(&mut self.repair_center.filter);
               if let Some(v)=&self.repair_center.analyzed{egui::ScrollArea::vertical().id_salt("repair-programs").max_height(110.).show(ui,|ui|{for p in rows(v,"Programs").iter().filter(|p|field(p,"Name").to_lowercase().contains(&self.repair_center.filter.to_lowercase())){if ui.selectable_label(self.repair_center.product.as_ref()==Some(p),format!("{} · {}",field(p,"Name"),field(p,"Version"))).clicked(){self.repair_center.product=Some(p.clone());}}});}
               if let Some(p)=&self.repair_center.product{ui.label(format!("{} · {}",field(p,"Name"),field(p,"Publisher")));let id=field(p,"ProductCode").to_owned();ui.horizontal_wrapped(|ui|{for(op,label)in[(Op::AnalyzeProduct(id.clone()),l("Анализ ошибок")),(Op::MsiRepair(id.clone()),l("План восстановления")),(Op::MsiRemove(id),l("План удаления"))]{if ui.add_enabled(!busy&&op.valid(),egui::Button::new(label)).clicked(){if op.mutating(){stage=Some(op);}else{run=Some(op);}}}});}
               ui.collapsing(l("Установка из подписанного MSI"),|ui|{
                ui.label(l("Путь к пакету:"));if ui.text_edit_singleline(&mut self.repair_center.installer_path).changed(){self.repair_center.installer=None;self.repair_center.plan=None;self.repair_center.confirmed=false;}
                let op=Op::AnalyzeInstaller(self.repair_center.installer_path.clone());if ui.add_enabled(!busy&&op.valid(),egui::Button::new(l("Проверить пакет без установки"))).clicked(){run=Some(op);}
                if let Some(p)=&self.repair_center.installer{ui.label(format!("{} · {} · {}",field(p,"Name"),field(p,"Version"),field(p,"Publisher")));let op=Op::MsiInstall(crate::repair_center::Installer{path:field(p,"Path").into(),hash:field(p,"Hash").into(),product:field(p,"ProductCode").into(),name:field(p,"Name").into(),publisher:field(p,"Publisher").into(),version:field(p,"Version").into()});if ui.add_enabled(!busy&&op.valid(),egui::Button::new(l("План установки этого пакета"))).clicked(){stage=Some(op);}}
               });
               ui.collapsing(l("Intel Chipset и технические ограничения"),|ui|{if ui.button(l("Выбрать Chipset Device Software")).clicked(){self.repair_center.filter="Chipset Device Software".into();self.repair_center.product=None;self.repair_center.plan=None;}ui.label(l("Только выбранный ProductCode и подписанный локальный MSI. EXE/Store, регистрационная хирургия и DriverStore не поддерживаются. Diagcab не включён: совместимость не доказана. События анализа относятся только к точному ProductCode."));});
              }
             }
            });
           };
           if width*ctx.zoom_factor()>=980. {ui.columns(2,|cols|{for n in 0..3{draw(&mut cols[0],n);}for n in 3..5{draw(&mut cols[1],n);}});}else{for n in 0..5{draw(ui,n);}}
           repair_card(ui,"C6",l("Ход выполнения"),|ui|{
            if self.repair_ui.rx.is_some(){let progress=self.repair_ui.progress.lock().unwrap_or_else(|e|e.into_inner()).clone();ui.label(crate::locale::text(is_ru,&progress.phase));ui.label(crate::locale::text(is_ru,&self.repair_ui.message));ui.add(egui::ProgressBar::new(progress.percent.unwrap_or(0.)/100.).animate(progress.percent.is_none()));ctx.request_repaint_after(Duration::from_millis(200));}
            else if self.repair_center.rx.is_some(){ui.label(crate::locale::text(is_ru,&self.repair_center.current));ui.label(crate::locale::text(is_ru,&format!("Объект: {}",self.repair_center.target)).into_owned());ui.label(if self.repair_center.mutating{l("Выполнение выбранного плана")}else{l("Сбор и анализ данных")});ui.add(egui::ProgressBar::new(0.).animate(true));if !self.repair_center.mutating&&ui.button(l("Отменить анализ")).clicked(){self.repair_center.cancel.store(true,Ordering::SeqCst);}
                if let Some(t)=self.repair_center.started{ui.label(crate::locale::text(is_ru,&format!("Прошло: {} с",t.elapsed().as_secs())).into_owned());}ctx.request_repaint_after(Duration::from_millis(200));}
            else if self.repair_center.history.is_empty(){ui.label(l("Операция не запущена"));}
            else {ui.label(crate::locale::text(is_ru,&format!("{} · завершено",self.repair_center.current)).into_owned());if let Some(r)=self.repair_center.history.last(){ui.label(crate::locale::text(is_ru,&record_outcome(r)));}}
            if let Some(p)=&self.repair_center.plan{ui.separator();ui.strong(crate::locale::text(is_ru,p.operation.label()));ui.label(crate::locale::text(is_ru,&format!("Объект: {}",crate::repair_center::plan_target(&p.operation))).into_owned());ui.label(crate::locale::text(is_ru,p.operation.consequences()));ui.checkbox(&mut self.repair_center.confirmed,l("Объект проверен; последствия понятны; разрешаю этот план"));if ui.add_enabled(!busy&&self.repair_center.confirmed,egui::Button::new(l("Выполнить выбранный план"))).clicked(){run=Some(p.operation.clone());}}
            if !self.repair_center.message.is_empty(){ui.collapsing(l("Подробности выполнения"),|ui|{ui.label(crate::locale::text(is_ru,&self.repair_center.message).as_ref());});}
           });
           let history_response=repair_card(ui,"C7",l("История и результаты"),|ui|{
            ui.horizontal_wrapped(|ui|{if ui.add_enabled(!busy,egui::Button::new(l("Прочитать историю"))).clicked(){run=Some(Op::History);}
                if ui.add_enabled(!busy&&report_package::lock(&self.package).final_zip().is_some(),egui::Button::new(l("Сравнить с предыдущим ZIP"))).clicked(){compare=true;}});
            for r in self.repair_center.history.iter().rev().filter(|r|crate::repair_center::parse(&r.raw).is_some_and(|v|field(&v,"Status")=="COMPARISON")).take(1){if let Some(v)=crate::repair_center::parse(&r.raw){ui.label(crate::locale::structured(is_ru,&comparison_view(field(&v,"Detail"))));}}
            if self.repair_center.history.is_empty()&&self.repair_center.saved_history.is_none(){ui.label(l("Сохранённых операций ещё нет"));}
            egui::ScrollArea::vertical().id_salt("repair-history-readable").max_height(220.).show(ui,|ui|{
             for(i,r)in self.repair_center.history.iter().enumerate().rev(){let title=self.repair_center.history_titles.get(i).cloned().unwrap_or_else(||crate::locale::text(is_ru,&format!("Сохранённая операция · {}",record_outcome(r))).into_owned());ui.collapsing(crate::locale::structured(is_ru,&title),|ui|{ui.label(crate::locale::text(is_ru,&record_outcome(r)));ui.collapsing(l("Технические подробности"),|ui|{ui.label(&r.raw);ui.label(r.directory.to_string_lossy());});});}
             if let Some(v)=&self.repair_center.saved_history{for r in rows(v,"Entries"){if let Some(m)=r.get("metadata"){ui.collapsing(crate::locale::structured(is_ru,&history_entry_title(m,field(r,"detail"))),|ui|{ui.label(field(r,"detail"));});}}}
            });
           });
           if self.repair_center.focus_history{history_response.scroll_to_me(Some(egui::Align::BOTTOM));self.repair_center.focus_history=false;}
          });
         });
        if old_selection
            != (
                self.repair_center.volume.clone(),
                self.repair_center.product.clone(),
                self.repair_center.cleanup_category,
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
                    self.repair_center.message = l("Диалог выбора отчёта недоступен").into()
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
            self.repair_ui.message = l("Проверь план и источник восстановления").into();
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

fn repair_card(
    ui: &mut egui::Ui,
    code: &str,
    title: &str,
    body: impl FnOnce(&mut egui::Ui),
) -> egui::Response {
    let response = egui::Frame::new()
        .fill(c::BG_CARD)
        .stroke(egui::Stroke::new(1., c::BORDER_NORMAL))
        .corner_radius(7)
        .inner_margin(14)
        .show(ui, |ui| {
            ui.set_width((ui.available_width() - 2.).max(100.));
            ui.horizontal_wrapped(|ui| {
                ui.label(
                    egui::RichText::new(code)
                        .size(14. / ui.ctx().zoom_factor())
                        .color(c::TEXT_MUTED),
                );
                ui.label(
                    egui::RichText::new(title)
                        .size(19. / ui.ctx().zoom_factor())
                        .color(c::TEXT_TITLE)
                        .strong(),
                );
            });
            ui.add_space(4.);
            body(ui);
        });
    ui.add_space(8.);
    response.response
}
fn record_outcome(r: &crate::repair_center::ResultRecord) -> String {
    if let Some(e) = &r.error {
        return format!("Ошибка: {e}");
    }
    crate::repair_center::parse(&r.raw)
        .map(|v| {
            crate::repair_center::status_label(crate::repair_center::field(&v, "Status")).into()
        })
        .unwrap_or("Результат не подтверждён".into())
}
fn operation_display(s: &str) -> &str {
    match s {
        "Analyze" => "Анализ системы",
        "UpdateCache" => "Обслуживание Windows Update",
        "CheckVolume" => "Проверка тома",
        "RepairVolume" => "Исправление тома",
        "MsiInstall" => "Установка программы",
        "MsiRemove" => "Удаление программы",
        "MsiRepair" => "Восстановление программы",
        "ThumbnailCleanup" => "Очистка эскизов",
        "ComponentCleanup" => "Обслуживание компонентов",
        "History" => "Просмотр истории",
        _ => s,
    }
}
fn comparison_view(detail: &str) -> String {
    let mut changed = vec![];
    let mut missing = false;
    let mut matched = 0;
    for line in detail.lines() {
        for (key, label) in [
            ("system:", "Система"),
            ("hardware:", "Оборудование"),
            ("execution_status:", "Выполнение"),
            ("coverage_status:", "Полнота"),
            ("repair_status:", "Восстановление"),
        ] {
            if let Some(values) = line.strip_prefix(key) {
                if let Some((a, b)) = values.split_once('→') {
                    matched += 1;
                    if a.trim() != b.trim() {
                        changed.push(format!(
                            "{label}: {} → {}",
                            state_display(a.trim()),
                            state_display(b.trim())
                        ));
                    }
                } else {
                    missing = true;
                }
            }
        }
    }
    if matched == 0 {
        return "Недостаточно данных для сравнения. Подробности сохранены в журнале.".into();
    }
    let mut result = if changed.is_empty() {
        "Изменений по сопоставимым показателям нет".into()
    } else {
        format!("Что изменилось:\n{}", changed.join("\n"))
    };
    if missing {
        result.push_str("\nЧасть данных отсутствует — сравнение неполное.");
    }
    result
}
fn state_display(s: &str) -> &str {
    match s {
        "OK" | "CLEAN" => "без замечаний",
        "PARTIAL" | "INCOMPLETE" => "неполные данные",
        "UNKNOWN" | "NO_DATA" => "нет достоверных данных",
        "CRITICAL" => "критическое замечание",
        "COMPLETED" => "завершено",
        "FAILED" | "ERROR" => "ошибка",
        _ if s.starts_with("ATTENTION") => "требует внимания",
        _ => s,
    }
}

#[cfg(test)]
mod ux19_tests {
    use super::*;
    #[test]
    fn comparison_stays_readable_and_missing_is_not_improvement() {
        assert_eq!(
            comparison_view("system: OK → OK\nhardware: OK → OK"),
            "Изменений по сопоставимым показателям нет"
        );
        assert!(
            comparison_view("system: OK → ATTENTION\nexecution_status: недостаточно данных")
                .contains("Что изменилось")
        );
        assert!(
            comparison_view("system: OK → ATTENTION\nexecution_status: недостаточно данных")
                .contains("неполное")
        );
        assert!(comparison_view("Report belongs to other machine").contains("Недостаточно данных"));
    }
}

fn history_entry_title(meta: &deep_checks::json::Value, detail: &str) -> String {
    use crate::repair_center::field;
    let parsed = crate::repair_center::parse(detail);
    let object = if field(meta, "object_label").is_empty() {
        "Объект не указан в старой записи"
    } else {
        field(meta, "object_label")
    };
    let outcome = parsed
        .as_ref()
        .map(|v| crate::repair_center::status_label(field(v, "Status")))
        .unwrap_or("Результат не подтверждён");
    format!(
        "{} · {} · {} · {}",
        field(meta, "started_at"),
        operation_display(field(meta, "operation")),
        object,
        outcome
    )
}

#[cfg(test)]
mod ux19_state_tests {
    use super::*;
    #[test]
    fn history_title_has_date_object_outcome_and_never_uses_internal_record_id() {
        let meta=deep_checks::json::parse(r#"{"started_at":"2026-11-17T12:00:00","operation":"Проверка тома","object_label":"C:"}"#).unwrap();
        let text = history_entry_title(&meta, r#"WSD_REPAIR_CENTER {"Status":"FAILED"}"#);
        assert!(
            text.contains("2026-11-17")
                && text.contains("Проверка тома")
                && text.contains("C:")
                && text.contains("Ошибка")
        );
        let old = deep_checks::json::parse(r#"{"operation":"Проверка тома"}"#).unwrap();
        assert!(history_entry_title(&old, "").contains("Объект не указан"));
        assert!(history_entry_title(&old, "").contains("Результат не подтверждён"));
    }
    fn texts(shape: &egui::Shape, out: &mut Vec<String>) {
        match shape {
            egui::Shape::Text(t) => out.push(t.galley.text().into()),
            egui::Shape::Vec(v) => {
                for s in v {
                    texts(s, out)
                }
            }
            _ => {}
        }
    }
    #[test]
    fn clean_and_partial_update_states_are_rendered_without_executing_anything() {
        let mut app = WinStateDiagApp {
            page: Page::Repair,
            ..Default::default()
        };
        for check in [DeepCheck::Dism, DeepCheck::Sfc] {
            app.deep_check_results.push(DeepCheckOutcome {
                check,
                result: deep_checks::CheckResult::Ok,
                detail: "CLEAN".into(),
                source: deep_checks::ResultSource::ExpcJson,
            });
        }
        app.repair_center.analyzed = deep_checks::json::parse(
            r#"{"Programs":[],"Errors":["Windows Update: synthetic denied"],"UpdateErrors":[],"Volumes":[],"Services":[]}"#,
        );
        let ctx = egui::Context::default();
        crate::ui::fonts::install(&ctx);
        let mut labels = vec![];
        for _ in 0..3 {
            let mut output = ctx.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(1378., 1172.),
                    )),
                    ..Default::default()
                },
                |_| app.repair_center_page(&ctx),
            );
            labels.clear();
            for s in &output.shapes {
                texts(&s.shape, &mut labels);
            }
            output.textures_delta.clear();
        }
        assert!(labels.iter().any(|s| s == "Исправление не требуется"));
        assert!(
            labels
                .iter()
                .any(|s| s.contains("Проверка Windows Update неполная"))
        );
        assert!(
            !labels
                .iter()
                .any(|s| s.contains("Оснований для обслуживания"))
        );
        assert!(app.repair_center.rx.is_none() && app.repair_ui.rx.is_none());
    }
}
