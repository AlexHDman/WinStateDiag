#[derive(Default)]
struct ClientReportUi {
    poster_open: bool,
    poster_rx: Option<Receiver<Result<crate::poster::PosterDocument, String>>>,
    poster: Option<crate::poster::PosterDocument>,
    light: bool,
    poster_page: usize,
    print_open: bool,
    print_page: usize,
    poster_texture: Option<egui::TextureHandle>,
    print_texture: Option<egui::TextureHandle>,
    previous_rx: Option<(
        Receiver<Result<crate::ai_analysis::Prepared, crate::ai_analysis::Error>>,
        PathBuf,
    )>,
    message: String,
    benchmark_open: bool,
    benchmark_mode: usize,
}
#[derive(Default)]
struct ClientReportActions {
    preview: bool,
    save: bool,
    previous: bool,
    poster: bool,
}
fn rpt(ru: bool, a: &'static str, b: &'static str) -> &'static str {
    if ru { a } else { b }
}
fn poster_page_selector(ui: &mut egui::Ui, page: &mut usize, total: usize) {
    if total > 1 {
        if ui.add_enabled(*page > 0, egui::Button::new("‹")).clicked() {
            *page -= 1;
        }
        ui.label(format!("{} / {total}", *page + 1));
        if ui
            .add_enabled(*page + 1 < total, egui::Button::new("›"))
            .clicked()
        {
            *page += 1;
        }
    }
}
fn poster_preview(
    ui: &mut egui::Ui,
    p: &crate::poster::Poster,
    texture: &mut Option<egui::TextureHandle>,
    name: &str,
) {
    let tex = texture.get_or_insert_with(|| {
        let limit = ui.ctx().input(|input| input.max_texture_side);
        ui.ctx()
            .load_texture(name, p.preview_image(limit), egui::TextureOptions::LINEAR)
    });
    let width = ui.available_width();
    egui::ScrollArea::vertical().id_salt(name).show(ui, |ui| {
        ui.image((
            tex.id(),
            egui::vec2(width, width * p.height as f32 / p.width as f32),
        ));
    });
}
fn report_card(ui: &mut egui::Ui, title: &str, body: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::new()
        .fill(egui::Color32::from_rgb(18, 32, 49))
        .stroke(egui::Stroke::new(1.0, c::BORDER_NORMAL))
        .corner_radius(8)
        .inner_margin(14)
        .show(ui, |ui| {
            ui.set_min_width((ui.available_width() - 1.0).max(50.0));
            ui.label(
                RichText::new(title)
                    .size(23.0)
                    .strong()
                    .color(c::TEXT_TITLE),
            );
            ui.add_space(6.0);
            body(ui);
        });
}
fn draw_client_report(
    ui: &mut egui::Ui,
    a: &crate::ai_analysis::Analysis,
    ru: bool,
) -> ClientReportActions {
    let f = &a.facts;
    let mut acts = ClientReportActions::default();
    let no = rpt(ru, "Нет данных", "No data");
    let v = |s: &String| {
        if s.trim().is_empty() {
            no.to_owned()
        } else {
            s.clone()
        }
    };
    ui.horizontal_wrapped(|ui| {
        ui.vertical(|ui| {
            ui.label(
                RichText::new(format!(
                    "{} {}",
                    rpt(
                        ru,
                        "Отчёт диагностики компьютера",
                        "Computer diagnostic report"
                    ),
                    v(&f.computer)
                ))
                .size(28.0)
                .strong()
                .color(c::TEXT_TITLE),
            );
            ui.label(format!(
                "{} · WinDiag {}",
                crate::report_facts::display_date(&f.date),
                v(&f.version)
            ));
        });
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(
                RichText::new("EXPC")
                    .size(38.0)
                    .strong()
                    .italics()
                    .color(egui::Color32::from_rgb(242, 211, 106)),
            );
        });
    });
    ui.horizontal_wrapped(|ui| {
        acts.preview = ui.button(rpt(ru, "Предпросмотр", "Preview")).clicked();
        let _ = ui.selectable_label(true, rpt(ru, "Результат", "Result"));
        acts.save = ui
            .button(rpt(ru, "Сохранить заключение", "Save conclusion"))
            .clicked();
        acts.poster = ui.button(rpt(ru, "Постер", "Poster")).clicked();
    });
    ui.add_space(10.0);
    report_card(
        ui,
        rpt(ru, "Паспорт компьютера", "Computer passport"),
        |ui| {
            ui.horizontal_wrapped(|ui| {
                for text in [v(&f.cpu), v(&f.board), v(&f.ram), v(&f.gpu)] {
                    ui.label(RichText::new(text).size(18.0).strong());
                    ui.separator();
                }
            });
            ui.label(format!(
                "{} · BIOS {} · {}",
                v(&f.windows),
                v(&f.bios),
                v(&f.disks)
            ));
        },
    );
    ui.label(&a.sections[0]);
    ui.add_space(12.0);
    let draw_left = |left: &mut egui::Ui| {
        report_card(
            left,
            rpt(ru, "Требует внимания", "Needs attention"),
            |ui| {
                if f.findings.is_empty() {
                    ui.label(rpt(ru,"Подтверждённые находки не извлечены. Проверь вывод модели и ограничения.","No confirmed findings extracted. Review the AI response and coverage limitations."));
                }
                for item in &f.findings {
                    let severity = match item.severity {
                        0 => rpt(ru, "КРИТИЧНО", "CRITICAL"),
                        1 => rpt(ru, "ВАЖНО", "IMPORTANT"),
                        2 => rpt(ru, "ВНИМАНИЕ", "ATTENTION"),
                        _ => rpt(ru, "ИНФОРМАЦИЯ", "INFORMATION"),
                    };
                    let color = if item.severity == 0 {
                        c::RED_ERROR
                    } else if item.severity <= 2 {
                        c::YELLOW_WARNING
                    } else {
                        c::TEXT_SECONDARY
                    };
                    egui::CollapsingHeader::new(
                        RichText::new(format!("{severity} · {}", item.title))
                            .color(color)
                            .strong(),
                    )
                    .default_open(false)
                    .show(ui, |ui| {
                        ui.label(format!(
                            "{}: {}",
                            rpt(ru, "Когда", "When"),
                            crate::report_facts::display_date(&item.when)
                        ));
                        ui.label(crate::locale::text(ru, &item.why).as_ref());
                        ui.label(crate::locale::text(ru, &item.check).as_ref());
                        ui.label(format!(
                            "{}: {}",
                            rpt(ru, "Доказательства", "Evidence"),
                            item.evidence
                        ));
                    });
                    ui.add_space(8.0);
                }
                if !a.sections[1].is_empty() {
                    ui.separator();
                    ui.collapsing(
                        rpt(
                            ru,
                            "Вывод модели — сверить с первичными данными",
                            "AI findings — verify against primary evidence",
                        ),
                        |ui| {
                            ui.label(&a.sections[1]);
                        },
                    );
                }
            },
        );
        left.add_space(12.0);
        report_card(
            left,
            rpt(ru, "Следующие проверки", "Next checks"),
            |ui| {
                ui.label(&a.sections[3]);
                ui.collapsing(
                    rpt(ru, "Факты и гипотезы модели", "AI facts and hypotheses"),
                    |ui| {
                        ui.label(&a.sections[2]);
                    },
                );
            },
        );
    };
    let draw_right = |right: &mut egui::Ui, acts: &mut ClientReportActions| {
        report_card(
            right,
            rpt(ru, "Что изменилось", "What changed"),
            |ui| {
                if f.changes.is_empty() {
                    ui.label(rpt(
                        ru,
                        "Сопоставимая история отсутствует.",
                        "Comparable history is unavailable.",
                    ));
                }
                for change in &f.changes {
                    ui.strong(&change.device);
                    ui.label(&change.metric);
                    ui.label(format!(
                        "{}: {} → {}: {} {}",
                        crate::report_facts::display_date(&change.before_date),
                        change.before,
                        crate::report_facts::display_date(&change.after_date),
                        change.after,
                        change.unit
                    ));
                    ui.small(rpt(ru,"То же устройство, метрика и единицы; изменение не означает причину неисправности.","Same device, metric and units; a change does not establish a fault cause."));
                    ui.separator();
                }
                acts.previous = ui
                    .button(rpt(
                        ru,
                        "Выбрать предыдущий отчёт…",
                        "Choose previous report…",
                    ))
                    .clicked();
            },
        );
        right.add_space(12.0);
        report_card(
            right,
            rpt(ru, "Показания датчиков", "Sensor readings"),
            |ui| {
                if f.readings.is_empty() {
                    ui.label(no);
                }
                egui::ScrollArea::vertical()
                    .id_salt("report_sensors")
                    .max_height(290.0)
                    .show(ui, |ui| {
                        let mut readings: Vec<_> = f.readings.iter().collect();
                        readings.sort_by_key(|r| {
                            if r.unit == "V"
                                && ["12", "5V", "3.3"].iter().any(|s| r.metric.contains(s))
                            {
                                0
                            } else if r.unit == "W"
                                && (r.device.contains("Graphics")
                                    || r.device.contains("GeForce")
                                    || r.device.contains("Radeon"))
                            {
                                1
                            } else if r.unit == "V" {
                                2
                            } else if r.unit == "W" {
                                3
                            } else {
                                4
                            }
                        });
                        for r in readings {
                            let value = if r.unit == "W" {
                                sensors::power_text(r.value)
                            } else {
                                format!("{} {}", r.value, r.unit)
                            };
                            ui.horizontal_wrapped(|ui| {
                                ui.label(format!("{} · {}", r.device, r.metric));
                                ui.strong(value).on_hover_text(format!(
                                    "{}\n{}",
                                    crate::report_facts::display_date(&r.when),
                                    r.source
                                ));
                            });
                        }
                    });
            },
        );
    };
    if ui.available_width() >= 850.0 {
        ui.columns(2, |uis| {
            let (left, right) = uis.split_at_mut(1);
            draw_left(&mut left[0]);
            draw_right(&mut right[0], &mut acts);
        });
    } else {
        draw_left(ui);
        ui.add_space(12.0);
        draw_right(ui, &mut acts);
    }
    ui.add_space(12.0);
    report_card(
        ui,
        rpt(ru, "Заключение для клиента", "Client conclusion"),
        |ui| {
            ui.label(&a.sections[4]);
            if a.incomplete {
                ui.colored_label(
                    c::YELLOW_WARNING,
                    rpt(
                        ru,
                        "НЕПОЛНЫЙ ОТВЕТ — не окончательное заключение",
                        "INCOMPLETE RESPONSE — not a final conclusion",
                    ),
                );
            }
            ui.small(rpt(
                ru,
                "Рекомендуемые действия автоматически не выполняются.",
                "Recommended actions are never executed automatically.",
            ));
        },
    );
    egui::CollapsingHeader::new(rpt(ru, "Ограничения проверки", "Coverage limitations")).show(
        ui,
        |ui| {
            for l in &f.limitations {
                ui.label(crate::locale::text(ru, l).as_ref());
            }
            if let Some(raw) = &a.raw_partial {
                ui.label(raw);
            }
        },
    );
    ui.label(format!(
        "{} · {} · {}",
        a.model,
        a.created_at,
        crate::locale::text(ru, &crate::ai_analysis::usage_text(&a.usage))
    ));
    acts
}
impl WinStateDiagApp {
    fn request_poster(&mut self) {
        self.request_poster_source(false);
    }
    fn request_poster_source(&mut self, from_result: bool) {
        self.client_report.poster_open = true;
        if self.client_report.poster_rx.is_some() {
            return;
        }
        let result = self.ai_analysis.result.as_ref();
        let source = if from_result {
            result.map(|(_, p)| p.clone())
        } else {
            self.current_analysis_zip()
                .or_else(|| self.ai_analysis.selected_zip.clone())
        };
        let path = if let Some(path) = source {
            path
        } else {
            match crate::win_dialog::open_zip(&self.reports_root) {
                crate::win_dialog::SavePick::Path(path) => path,
                crate::win_dialog::SavePick::Unavailable => {
                    self.client_report.message = "Не удалось открыть выбор ZIP".into();
                    return;
                }
                crate::win_dialog::SavePick::Cancelled => {
                    self.client_report.poster_open = self.client_report.poster.is_some();
                    return;
                }
            }
        };
        let cached = result.filter(|(_, p)| *p == path).map(|(a, _)| a.clone());
        self.launch_poster(path, cached);
    }
    fn launch_poster(&mut self, source: PathBuf, cached: Option<crate::ai_analysis::Analysis>) {
        let (tx, rx) = std::sync::mpsc::channel();
        let poster = &mut self.client_report;
        poster.poster = None;
        poster.poster_texture = None;
        poster.print_texture = None;
        poster.print_open = false;
        poster.poster_rx = Some(rx);
        poster.poster_open = true;
        poster.message = "Готовлю постер из выбранного ZIP…".into();
        let ru = self.language == Language::Ru;
        std::thread::spawn(move || {
            let _ = tx.send(crate::poster::from_zip(&source, cached, ru));
        });
    }
    fn poll_client_report(&mut self) {
        if let Some(rx) = &self.client_report.poster_rx {
            match rx.try_recv() {
                Ok(result) => {
                    self.client_report.poster_rx = None;
                    match result {
                        Ok(p) => {
                            self.client_report.poster = Some(p);
                            self.client_report.poster_texture = None;
                            self.client_report.print_texture = None;
                            self.client_report.light = false;
                            self.client_report.poster_page = 0;
                            self.client_report.print_page = 0;
                            self.client_report.message = String::new();
                        }
                        Err(e) => self.client_report.message = e,
                    }
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    self.client_report.poster_rx = None;
                    self.client_report.message = "Создание PNG прервано".into();
                }
                _ => {}
            }
        }
        if let Some((rx, source)) = &self.client_report.previous_rx {
            let response = rx.try_recv();
            if let Err(std::sync::mpsc::TryRecvError::Disconnected) = response {
                self.client_report.previous_rx = None;
                self.client_report.message = rpt(
                    self.language == Language::Ru,
                    "Сравнение прервано",
                    "Comparison interrupted",
                )
                .into();
            } else if let Ok(result) = response {
                let source = source.clone();
                self.client_report.previous_rx = None;
                self.client_report.message = match result {
                    Ok(old) => {
                        if let Some((a, current)) = &mut self.ai_analysis.result {
                            if current == &source {
                                match a.facts.compare(&old.facts) {
                                    Ok(()) => {
                                        "Предыдущий отчёт проверен. Модель повторно не вызывалась."
                                            .into()
                                    }
                                    Err(e) => e,
                                }
                            } else {
                                "Ответ предыдущего выбора отброшен: источник изменился".into()
                            }
                        } else {
                            "Нет текущего заключения для сравнения".into()
                        }
                    }
                    Err(e) => e.message(),
                };
            }
        }
    }
    fn client_report_windows(&mut self, ctx: &egui::Context) {
        let ru = self.language == Language::Ru;
        if self.client_report.poster_open {
            let mut open = true;
            detail_window(
                ctx,
                "client-poster",
                rpt(ru, "Постер — EXPC WinDiag", "Poster — EXPC WinDiag"),
                [686.0, 902.0],
                &mut open,
                |ui| {
                    let state = &mut self.client_report;
                    if !state.message.is_empty() {
                        ui.label(crate::locale::text(ru, &state.message).as_ref());
                    }
                    if state.poster_rx.is_some() {
                        ui.spinner();
                        ctx.request_repaint_after(Duration::from_millis(100));
                    }
                    if let Some(document) = &state.poster {
                        let previous = (state.light, state.poster_page);
                        ui.horizontal_wrapped(|ui| {
                            ui.selectable_value(&mut state.light, false, rpt(ru, "Тёмный", "Dark"));
                            ui.selectable_value(
                                &mut state.light,
                                true,
                                rpt(ru, "Светлый", "Light"),
                            );
                            if state.light {
                                poster_page_selector(
                                    ui,
                                    &mut state.poster_page,
                                    document.light.len(),
                                );
                            }
                        });
                        if previous != (state.light, state.poster_page) {
                            state.poster_texture = None;
                        }
                        let p = if state.light {
                            &document.light[state.poster_page]
                        } else {
                            &document.dark
                        };
                        ui.horizontal_wrapped(|ui| {
                            if ui
                                .button(rpt(ru, "Скопировать изображение", "Copy image"))
                                .clicked()
                            {
                                ui.ctx().copy_image(p.image());
                                state.message = rpt(
                                    ru,
                                    "Изображение передано в буфер обмена",
                                    "Image sent to the clipboard",
                                )
                                .into();
                            }
                            if ui
                                .button(rpt(ru, "Сохранить на рабочий стол", "Save to Desktop"))
                                .clicked()
                            {
                                state.message = crate::poster::save_desktop(p)
                                    .map(|_| {
                                        rpt(
                                            ru,
                                            "PNG сохранён на рабочем столе",
                                            "PNG saved to Desktop",
                                        )
                                        .into()
                                    })
                                    .unwrap_or_else(|e| e);
                            }
                            if ui.button(rpt(ru, "Печать…", "Print…")).clicked() {
                                state.print_open = true;
                                state.print_page = 0;
                                state.print_texture = None;
                            }
                        });
                        poster_preview(ui, p, &mut state.poster_texture, "poster");
                    }
                },
            );
            self.client_report.poster_open = open;
        }
        if self.client_report.print_open
            && let Some(document) = &self.client_report.poster
        {
            let mut open = true;
            let mut send = false;
            let mut cancel = false;
            detail_window(
                ctx,
                "client-print-preview",
                rpt(ru, "Предпросмотр печати — A4", "Print preview — A4"),
                [720.0, 915.0],
                &mut open,
                |ui| {
                    let previous = self.client_report.print_page;
                    ui.horizontal_wrapped(|ui| {
                        send |= ui
                            .button(rpt(ru, "Выбрать принтер…", "Choose printer…"))
                            .clicked();
                        cancel |= ui.button(rpt(ru, "Отмена", "Cancel")).clicked();
                        poster_page_selector(
                            ui,
                            &mut self.client_report.print_page,
                            document.light.len(),
                        );
                    });
                    if previous != self.client_report.print_page {
                        self.client_report.print_texture = None;
                    }
                    poster_preview(
                        ui,
                        &document.light[self.client_report.print_page],
                        &mut self.client_report.print_texture,
                        "print-preview",
                    );
                },
            );
            if send && !cancel {
                use crate::print_report::Outcome;
                self.client_report.message = match crate::print_report::print(&document.light) {
                    Ok(Outcome::Printed) => {
                        rpt(ru, "Документ передан на печать", "Document sent to printer").into()
                    }
                    Ok(Outcome::Cancelled) => {
                        rpt(ru, "Печать отменена", "Printing cancelled").into()
                    }
                    Err(error) => error,
                };
                open = false;
            }
            self.client_report.print_open = open && !cancel;
        }
        if self.client_report.benchmark_open {
            let vm = self.build_vm(0., 0.);
            let value = |i: usize| {
                vm.passport
                    .get(i)
                    .map(|r| r.value.clone())
                    .unwrap_or_else(|| rpt(ru, "Нет данных", "No data").into())
            };
            let (cpu, board, bios) = (value(1), value(3), value(4));
            let support_available = self
                .bios_ui
                .result
                .as_ref()
                .and_then(|r| r.as_ref().ok())
                .or_else(|| self.bios_cached())
                .is_some_and(|c| crate::bios_net::official_host(&c.support).is_some());
            let mut open = true;
            let mut support = false;
            detail_window(
                ctx,
                "cpu-reference",
                rpt(
                    ru,
                    "WinDiag — Бенчмарк процессоров",
                    "WinDiag — CPU reference",
                ),
                [1340.0, 940.0],
                &mut open,
                |ui| {
                    ui.heading(
                        RichText::new(rpt(ru, "Сравнение процессоров", "CPU comparison"))
                            .size(28.0)
                            .color(c::TEXT_TITLE),
                    );
                    report_card(ui, rpt(ru, "Ваш процессор", "Your CPU"), |ui| {
                        ui.horizontal_wrapped(|ui| {
                            ui.label(
                                RichText::new(&cpu)
                                    .size(23.0)
                                    .strong()
                                    .color(c::YELLOW_WARNING),
                            );
                            ui.label(&board);
                            if ui
                                .add_enabled(support_available, egui::Button::new(rpt(ru, "Поддержка платы ↗", "Board support ↗")))
                                .on_hover_text(rpt(ru, "Нужна подтверждённая страница точной модели платы из проверки BIOS", "Requires an exact-model support page verified by the BIOS check"))
                                .clicked()
                            {
                                support = true;
                            }
                        });
                        ui.label(format!("BIOS: {bios}"));
                    });
                    ui.horizontal_wrapped(|ui| {
                        for (i, label) in [
                            (0, rpt(ru, "Все модели", "All models")),
                            (1, rpt(ru, "Для моей платы", "For my motherboard")),
                        ] {
                            ui.selectable_value(&mut self.client_report.benchmark_mode, i, label);
                        }
                        if ui.button(rpt(ru, "К моему CPU", "My CPU")).clicked() {
                            self.client_report.benchmark_mode = 0;
                        }
                    });
                    report_card(
                        ui,
                        rpt(ru, "Справочные оценки", "Reference scores"),
                        |ui| {
                            ui.label(rpt(ru,"Нет данных: права на поставку баллов PassMark не подтверждены. Демонстрационные баллы и относительные индексы не включены.","No data: rights to distribute PassMark scores have not been confirmed. No demonstration scores or derived indices are included."));
                            ui.label(rpt(
                                ru,
                                "CPU Mark: Нет данных · Одно ядро: Нет данных",
                                "CPU Mark: No data · Single thread: No data",
                            ));
                            if ui
                                .button(rpt(ru, "Посмотреть на PassMark ↗", "View on PassMark ↗"))
                                .clicked()
                            {
                                let _ = engine::open_web_page("https://www.cpubenchmark.net/");
                            }
                            if self.client_report.benchmark_mode == 1 {
                                ui.label(rpt(ru,"Поддержка кандидатов не подтверждена. Совпадение сокета недостаточно; необходим официальный список CPU точной модели и ревизии платы.","Candidate support is not confirmed. A matching socket is insufficient; the exact motherboard model/revision CPU support list is required."));
                            }
                        },
                    );
                    egui::ScrollArea::vertical().show(ui,|ui|{ui.label(rpt(ru,"Каталог оценок не поставляется до подтверждения прав. Прирост и максимум для платы не рассчитываются.","A score catalogue is not distributed pending permission. Upgrade gains and motherboard maxima are not calculated."));});
                },
            );
            self.client_report.benchmark_open = open;
            if support {
                self.open_bios_support();
            }
        }
    }
}
