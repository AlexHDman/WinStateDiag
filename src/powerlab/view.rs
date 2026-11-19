//! Presentation only: the existing shared sampler, raw metrics and exports are unchanged.
use super::*;
#[derive(Default)]
pub(super) struct ViewState {
    group: Option<Group>,
    metric: String,
    seconds: u64,
    end: Option<usize>,
    split_height: f32,
}
const GROUPS: [(Option<Group>, &str); 7] = [
    (None, "Обзор"),
    (Some(Group::Cpu), "Процессор"),
    (Some(Group::Gpu), "Видеокарта"),
    (Some(Group::Motherboard), "Плата"),
    (Some(Group::Memory), "Память"),
    (Some(Group::Storage), "Накопители"),
    (Some(Group::Cooling), "Охлаждение"),
];
#[derive(Debug, PartialEq)]
pub(super) enum Kind {
    Live,
    Fact,
    Timing,
    Unknown,
}
pub(super) fn kind(m: &Metric) -> Kind {
    if m.unit == "Timing" {
        Kind::Timing
    } else if present::role(&m.id) == present::Role::Fact
        || m.unit == "GiB"
            && (m.label.to_lowercase().contains("capacity") || m.id.ends_with(".capacity"))
    {
        Kind::Fact
    } else if matches!(
        m.unit.as_str(),
        "°C" | "degC"
            | "W"
            | "V"
            | "MHz"
            | "GHz"
            | "%"
            | "RPM"
            | "MiB"
            | "GiB"
            | "MB/s"
            | "GB/s"
            | "A"
    ) {
        Kind::Live
    } else {
        Kind::Unknown
    }
}
pub(super) fn device_id(m: &Metric) -> String {
    m.hardware.clone().unwrap_or_else(|| {
        if m.id.starts_with("storage.") {
            m.id.split('.').take(2).collect::<Vec<_>>().join(".")
        } else {
            m.id.clone()
        }
    })
}
pub(super) fn device_name(m: &Metric) -> String {
    if m.id.starts_with("storage.") {
        // This provider's documented notes are [bus type, model, provenance]. No matching by chipset/model similarity.
        if let Some(model) = m.notes.get(1).filter(|s| !s.trim().is_empty()) {
            return format!("{} #{}", model, m.id.split('.').nth(1).unwrap_or("?"));
        }
    }
    m.label.split(" · ").next().unwrap_or(&m.label).into()
}
fn title(m: &Metric) -> String {
    if m.label.contains("Unknown")
        || m.label
            .split(" · ")
            .last()
            .unwrap_or(&m.label)
            .starts_with("VIN")
    {
        return format!(
            "{} · назначение не подтверждено",
            m.label.split(" · ").last().unwrap_or(&m.label)
        );
    }
    if m.id.starts_with("storage.") {
        return device_name(m);
    }
    let base = present::title(m);
    if base == "CPU Core" || base == "GPU Core" {
        return format!(
            "{} · {}",
            base,
            match m.unit.as_str() {
                "V" => "напряжение",
                "°C" | "degC" => "температура",
                "MHz" => "частота",
                _ => "показание",
            }
        );
    }
    base
}
fn value(m: &Metric) -> String {
    if m.usable_value().is_none() {
        return if m.state == MetricState::Error {
            "Ошибка источника"
        } else {
            "Нет данных"
        }
        .into();
    }
    if kind(m) == Kind::Timing {
        return m
            .usable_value()
            .map(|v| format!("{v}"))
            .unwrap_or("Нет данных".into());
    }
    display_value(m)
}
fn tooltip(m: &Metric) -> String {
    format!(
        "ID: {}\nИсточник: {}\nУстройство: {}\nИсходный датчик: {}\nИсходная единица: {}\nПричина: {}\n{}",
        m.id,
        m.source,
        m.hardware.as_deref().unwrap_or("не указан"),
        m.sensor.as_deref().unwrap_or("не указан"),
        m.raw_unit.as_deref().unwrap_or(&m.unit),
        reason_ru(m),
        m.notes.join("\n")
    )
}
fn frame(ui: &mut egui::Ui, body: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::new()
        .fill(c::BG_CARD)
        .stroke(egui::Stroke::new(1., c::BORDER_NORMAL))
        .corner_radius(7)
        .inner_margin(12)
        .show(ui, |ui| {
            ui.vertical(|ui| body(ui));
        });
}
fn in_group(m: &Metric, group: Option<Group>) -> bool {
    match group {
        None => true,
        Some(Group::Cooling) => {
            m.group == Group::Cooling
                || m.unit == "RPM"
                || m.unit == "%"
                    && (m.id.contains(".fan")
                        || m.label.to_lowercase().contains("fan")
                        || m.label.to_lowercase().contains("pump")
                        || m.label.contains("Вентилятор"))
        }
        Some(g) => m.group == g,
    }
}
impl Monitor {
    #[cfg(test)]
    pub(crate) fn presentation_receipt(&self) -> String {
        use powerlab_core::json::Json;
        Json::Array(
            self.latest
                .values()
                .map(|m| {
                    Json::Object(vec![
                        ("id".into(), Json::str(&m.id)),
                        ("label".into(), Json::str(&title(m))),
                        ("display".into(), Json::str(&value(m))),
                        ("kind".into(), Json::str(&format!("{:?}", kind(m)))),
                        ("unit".into(), Json::str(&m.unit)),
                        (
                            "raw_value".into(),
                            m.usable_value().map_or(Json::Null, Json::Float),
                        ),
                        ("timestamp_ms".into(), Json::Int(m.timestamp_ms as i64)),
                        (
                            "has_session_stats".into(),
                            Json::Bool(kind(m) == Kind::Live),
                        ),
                        ("source".into(), Json::str(&m.source)),
                    ])
                })
                .collect(),
        )
        .render()
    }
    pub(super) fn dashboard(
        &mut self,
        ui: &mut egui::Ui,
        dependency: &str,
        busy: bool,
        client: &str,
    ) -> Action {
        let ru = !self.english;
        let l = move |s| crate::locale::literal(ru, s);

        crate::app::details_text_scale(ui.style_mut());
        ui.style_mut().spacing.button_padding = egui::vec2(12., 7.);
        ui.style_mut().spacing.interact_size.y = 30.;
        {
            let w = &mut ui.style_mut().visuals.widgets.inactive;
            w.bg_fill = c::BG_FIELD;
            w.weak_bg_fill = c::BG_FIELD;
            w.bg_stroke = egui::Stroke::new(1., c::BORDER_NORMAL);
        }
        let mut action = Action::None;
        ui.horizontal_wrapped(|ui| {
            ui.heading(egui::RichText::new("PowerLab").color(c::TEXT_TITLE));
            ui.label(if self.owns_reader() {
                l("● Мониторинг выполняется")
            } else if self.history.is_empty() {
                l("Ожидание запуска")
            } else {
                l("Мониторинг остановлен")
            });
            ui.label(crate::locale::text(
                ru,
                &format!("{} измерений", self.history.len()),
            ));
        });
        ui.horizontal_wrapped(|ui| {
            if ui
                .add_enabled(
                    !self.owns_reader() && !busy,
                    egui::Button::new(l("▶ Старт")),
                )
                .clicked()
            {
                self.pending = true;
            }
            if ui
                .add_enabled(self.owns_reader(), egui::Button::new(l("■ Стоп")))
                .clicked()
            {
                self.stop();
            }
            if ui
                .add_enabled(
                    !self.owns_reader() && !self.history.is_empty() && !self.saving(),
                    egui::Button::new(l("Новый сеанс")),
                )
                .clicked()
            {
                self.reset();
                self.view = Default::default();
            }
            ui.separator();
            ui.menu_button(l("Экспорт"), |ui| {
                for f in ["TXT", "JSON", "CSV"] {
                    if ui
                        .add_enabled(
                            !self.history.is_empty() && !self.saving(),
                            egui::Button::new(f),
                        )
                        .clicked()
                    {
                        self.export(&f.to_lowercase(), client);
                        ui.close();
                    }
                }
            });
        });
        if !self.message.is_empty()
            && !self.message.starts_with("Мониторинг")
            && !self.message.starts_with("Ожидание")
        {
            ui.label(
                egui::RichText::new(crate::locale::text(ru, &self.message))
                    .color(c::TEXT_SECONDARY),
            );
        }
        ui.horizontal_wrapped(|ui| {
            ui.label(crate::locale::text(
                ru,
                crate::hardware_support::label(dependency),
            ));
            if !self.owns_reader() && !busy {
                if crate::hardware_support::can_install(dependency)
                    && ui.button(l("Установить PawnIO")).clicked()
                {
                    action = Action::Install;
                }
                if dependency == "ACCESS_DENIED" && ui.button(l("Получить права (UAC)")).clicked()
                {
                    action = Action::Rights;
                }
                if ui.button(l("Проверить доступ")).clicked() {
                    action = Action::Detect;
                }
            }
        });
        let discovery_complete = self
            .latest
            .get("lhm.ready")
            .is_some_and(|m| matches!(m.state, MetricState::Ok | MetricState::Zero));
        if self.owns_reader() && !discovery_complete {
            ui.horizontal_wrapped(|ui| {
                ui.spinner();
                ui.label(l("Обнаружение доступных датчиков…"));
            });
        }
        ui.separator();
        let wide = ui.available_width() >= 850.;
        if wide {
            ui.horizontal_top(|ui| {
                ui.allocate_ui(egui::vec2(154., ui.available_height()), |ui| {
                    ui.set_width(154.);
                    self.navigation(ui);
                });
                ui.separator();
                egui::ScrollArea::vertical()
                    .id_salt("powerlab-main")
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.vertical(|ui| self.content(ui));
                    });
            });
        } else {
            self.navigation(ui);
            egui::ScrollArea::vertical()
                .id_salt("powerlab-main-narrow")
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    ui.vertical(|ui| self.content(ui));
                });
        }
        action
    }
    fn navigation(&mut self, ui: &mut egui::Ui) {
        let ru = !self.english;
        let draw = |ui: &mut egui::Ui, this: &mut Self, g: Option<Group>, label: &str| {
            let selected = this.view.group == g;
            let width = if ui.available_width() < 200.0 {
                ui.available_width().max(110.0)
            } else {
                (label.chars().count() as f32 * 8.0 + 46.0).clamp(110.0, 180.0)
            };
            let response = ui.add(
                egui::Button::new("")
                    .min_size(egui::vec2(width, 34.0))
                    .corner_radius(7)
                    .fill(if selected {
                        c::EXPC_ACTIVE_ROW
                    } else {
                        c::BG_FIELD
                    }),
            );
            let caption = crate::locale::text(ru, label);
            response.widget_info(|| {
                egui::WidgetInfo::labeled(egui::WidgetType::Button, true, caption.as_ref())
            });
            ui.painter().with_clip_rect(response.rect.shrink(4.0)).text(
                egui::pos2(response.rect.left() + 32.0, response.rect.center().y),
                egui::Align2::LEFT_CENTER,
                caption.as_ref(),
                egui::FontId::proportional(15.0),
                c::TEXT_PRIMARY,
            );
            let center = egui::pos2(response.rect.left() + 16.0, response.rect.center().y);
            use crate::ui::vm::DeviceIcon as D;
            if g.is_none() {
                crate::ui::paint::icon_pulse(
                    ui.painter(),
                    egui::Rect::from_center_size(center, egui::vec2(17.0, 17.0)),
                    c::TEXT_TITLE,
                );
            } else {
                let icon = match g {
                    Some(Group::Gpu) => D::Gpu,
                    Some(Group::Cpu | Group::Memory) => D::Chip,
                    Some(Group::Storage) => D::Storage,
                    _ => D::Generic,
                };
                crate::ui::paint::icon_device(ui.painter(), center, 17.0, icon, c::TEXT_TITLE);
            }
            if response.clicked() {
                this.view.group = g;
                this.view.metric.clear();
            }
        };
        if ui.available_width() < 200.0 {
            ui.vertical(|ui| {
                for (g, label) in GROUPS {
                    draw(ui, self, g, label);
                }
            });
        } else {
            ui.horizontal_wrapped(|ui| {
                for (g, label) in GROUPS {
                    draw(ui, self, g, label);
                }
            });
        }
    }
    fn content(&mut self, ui: &mut egui::Ui) {
        let ru = !self.english;
        let l = move |s| crate::locale::literal(ru, s);

        let metrics: Vec<Metric> = self
            .latest
            .values()
            .filter(|m| {
                in_group(m, self.view.group) && present::role(&m.id) != present::Role::Service
            })
            .cloned()
            .collect();
        let available: Vec<_> = metrics.iter().filter(|m| kind(m) == Kind::Live).collect();
        let key_card_width = ((ui.available_width() - 24.) / 4. - 24.).clamp(145., 250.);
        ui.horizontal_wrapped(|ui| {
            let cards: Vec<&Metric> = available
                .iter()
                .copied()
                .filter(|m| in_group(m, self.view.group))
                .take(4)
                .collect();
            if cards.is_empty() {
                ui.label(l("Нет доступных показаний выбранного раздела"));
            }
            for m in cards {
                frame(ui, |ui| {
                    ui.set_width(key_card_width);
                    ui.set_min_height(62.0);
                    ui.label(crate::locale::structured(ru, &title(m)));
                    let r = ui.add(
                        egui::Button::new(
                            egui::RichText::new(crate::locale::text(ru, &value(m)))
                                .size(23.0)
                                .color(c::PASSPORT_MEASURED),
                        )
                        .fill(c::BG_FIELD),
                    );
                    if r.clicked() {
                        self.view.metric = m.id.clone();
                    }
                    r.on_hover_text(crate::locale::structured(ru, &tooltip(m)));
                });
            }
        });
        ui.add_space(10.);
        frame(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(
                    egui::RichText::new(l("График сеанса"))
                        .color(c::TEXT_TITLE)
                        .strong(),
                );
                if !available.iter().any(|m| m.id == self.view.metric) {
                    self.view.metric = available.first().map(|m| m.id.clone()).unwrap_or_default();
                }
                egui::ComboBox::from_id_salt("plot-metric")
                    .width(260.)
                    .selected_text(
                        available
                            .iter()
                            .find(|m| m.id == self.view.metric)
                            .map(|m| {
                                format!("{} [{}]", crate::locale::structured(ru, &title(m)), m.unit)
                            })
                            .unwrap_or(l("Нет данных").into()),
                    )
                    .show_ui(ui, |ui| {
                        for m in &available {
                            ui.selectable_value(
                                &mut self.view.metric,
                                m.id.clone(),
                                format!(
                                    "{} [{}]",
                                    crate::locale::structured(ru, &title(m)),
                                    m.unit
                                ),
                            );
                        }
                    });
                if self.view.seconds == 0 {
                    self.view.seconds = 300;
                }
                egui::ComboBox::from_id_salt("plot-span")
                    .selected_text(format!(
                        "{} {}",
                        self.view.seconds,
                        if ru { "с" } else { "s" }
                    ))
                    .show_ui(ui, |ui| {
                        for sec in [60, 300, 900, 3600] {
                            ui.selectable_value(
                                &mut self.view.seconds,
                                sec,
                                format!("{sec} {}", if ru { "с" } else { "s" }),
                            );
                        }
                    });
            });
            if let Some(m) = available.iter().find(|m| m.id == self.view.metric) {
                self.plot(ui, m);
            } else {
                ui.label(l("Нет сопоставимых измерений для графика"));
            }
            if self.history.len() > 1 {
                ui.horizontal_wrapped(|ui| {
                    let mut index = self
                        .view
                        .end
                        .unwrap_or(self.history.len() - 1)
                        .min(self.history.len() - 1);
                    if ui
                        .add(
                            egui::Slider::new(&mut index, 0..=self.history.len() - 1)
                                .text(l("История графика")),
                        )
                        .changed()
                    {
                        self.view.end = Some(index);
                    }
                    if ui.button(l("Последние")).clicked() {
                        self.view.end = None;
                    }
                });
            }
        });
        ui.add_space(10.);
        frame(ui, |ui| {
            ui.label(
                egui::RichText::new(l("Телеметрия · последние показания"))
                    .color(c::TEXT_TITLE)
                    .strong(),
            );
            table_row(
                ui,
                &[
                    l("Датчик").into(),
                    if self.owns_reader() {
                        l("Сейчас").into()
                    } else {
                        l("Последнее").into()
                    },
                    l("Мин.").into(),
                    l("Макс.").into(),
                ],
                None,
                true,
            );
            for (index, m) in available.iter().enumerate() {
                let series = self.series.get(&m.id);
                let stat = |v: Option<f64>| {
                    v.map(|v| powerlab_core::ipc::format_value(v, &m.unit))
                        .unwrap_or("—".into())
                };
                table_row(
                    ui,
                    &[
                        crate::locale::structured(ru, &title(m)),
                        crate::locale::text(ru, &value(m)).into_owned(),
                        stat(series.and_then(|s| s.min)),
                        stat(series.and_then(|s| s.max)),
                    ],
                    Some(tooltip(m)),
                    index % 2 == 0,
                );
            }
        });
        ui.add_space(8.);
        let facts: Vec<_> = metrics
            .iter()
            .filter(|m| matches!(kind(m), Kind::Fact | Kind::Timing))
            .collect();
        if !facts.is_empty() {
            frame(ui, |ui| {
                ui.label(
                    egui::RichText::new(l(
                        "Паспорт, SPD и параметры источника · без статистики сеанса",
                    ))
                    .color(c::TEXT_TITLE)
                    .strong(),
                );
                for (index, m) in facts.iter().enumerate() {
                    let text = if kind(m) == Kind::Timing {
                        format!("{} · единица не подтверждена источником", value(m))
                    } else {
                        present::fact_text(m)
                    };
                    table_row(ui, &[title(m), text], Some(tooltip(m)), index % 2 == 0);
                }
            });
        }
        ui.add_space(8.);
        egui::CollapsingHeader::new(l("Каналы без данных, неопознанные и источники")).show(
            ui,
            |ui| {
                for m in self
                    .latest
                    .values()
                    .filter(|m| in_group(m, self.view.group))
                {
                    ui.collapsing(format!("{} · {}", title(m), value(m)), |ui| {
                        ui.label(tooltip(m));
                    });
                }
                for n in &self.notices {
                    ui.label(n);
                }
            },
        );
    }
    fn plot(&mut self, ui: &mut egui::Ui, m: &Metric) {
        let ru = !self.english;
        let l = move |s| crate::locale::literal(ru, s);

        let end = self
            .view
            .end
            .unwrap_or(self.history.len().saturating_sub(1));
        let ts = self.history.get(end).map(|s| s.timestamp_ms).unwrap_or(0);
        let start = ts
            .saturating_sub(self.view.seconds * 1000)
            .max(self.history.first().map(|s| s.timestamp_ms).unwrap_or(ts));
        ui.label(format!(
            "● {} · {} · {} {:.1} {} · {}",
            crate::locale::structured(ru, &title(m)),
            m.unit,
            if ru { "показано" } else { "shown" },
            ts.saturating_sub(start) as f64 / 1000.,
            if ru { "с" } else { "s" },
            if ru {
                "пропуски — разрывы"
            } else {
                "missing samples are gaps"
            }
        ));
        let (rect, _) = ui.allocate_exact_size(
            egui::vec2(
                ui.available_width().max(180.),
                if self.view.split_height <= 0.0 {
                    205.0
                } else {
                    self.view.split_height
                },
            ),
            egui::Sense::hover(),
        );
        let handle = egui::Rect::from_min_size(
            egui::pos2(rect.left(), rect.bottom() - 4.0),
            egui::vec2(rect.width(), 8.0),
        );
        let drag = ui.interact(
            handle,
            ui.id().with("graph_table_splitter"),
            egui::Sense::drag(),
        );
        if drag.dragged() {
            self.view.split_height = (rect.height() + drag.drag_delta().y).clamp(140.0, 560.0);
        }
        if drag.hovered() {
            ui.ctx().set_cursor_icon(egui::CursorIcon::ResizeVertical);
        }
        let plot = rect.shrink2(egui::vec2(46., 22.));
        let p = ui.painter();
        p.rect_filled(rect, 4, c::BG_ROOT);
        let segments = plot_segments(&self.history, &m.id, start, ts, end);
        let mut lo = segments
            .iter()
            .flatten()
            .map(|p| p.1)
            .fold(f64::INFINITY, f64::min);
        let mut hi = segments
            .iter()
            .flatten()
            .map(|p| p.1)
            .fold(f64::NEG_INFINITY, f64::max);
        if !lo.is_finite() {
            p.text(
                plot.center(),
                egui::Align2::CENTER_CENTER,
                l("Нет данных в выбранном интервале"),
                egui::FontId::proportional(14.),
                c::TEXT_SECONDARY,
            );
            return;
        }
        (lo, hi) = axis_bounds(&m.unit, lo, hi);
        for i in 0..=4 {
            let y = plot.bottom() - plot.height() * i as f32 / 4.;
            p.line_segment(
                [egui::pos2(plot.left(), y), egui::pos2(plot.right(), y)],
                egui::Stroke::new(1., c::BORDER_INNER),
            );
            p.text(
                egui::pos2(plot.left() - 5., y),
                egui::Align2::RIGHT_CENTER,
                format!("{:.2}", lo + (hi - lo) * i as f64 / 4.),
                egui::FontId::proportional(12.),
                c::TEXT_SECONDARY,
            );
        }
        for segment in segments {
            let reduced = powerlab_core::chart::envelope(
                segment.iter().map(|p| p.1),
                segment.len(),
                plot.width().max(1.) as usize,
            );
            let points: Vec<_> = if let Some(envelope) = reduced {
                let first = segment[0].0;
                let span = segment.last().unwrap().0 - first;
                envelope
                    .points
                    .iter()
                    .map(|point| {
                        egui::pos2(
                            plot.left()
                                + (((first - start) as f64 + f64::from(point.x) * span as f64)
                                    / (ts - start).max(1) as f64)
                                    as f32
                                    * plot.width(),
                            plot.bottom()
                                - ((point.value - lo) / (hi - lo).max(0.01)) as f32 * plot.height(),
                        )
                    })
                    .collect()
            } else {
                segment
                    .iter()
                    .map(|(t, v)| {
                        egui::pos2(
                            plot.left()
                                + ((*t - start) as f64 / (ts - start).max(1) as f64) as f32
                                    * plot.width(),
                            plot.bottom()
                                - ((*v - lo) / (hi - lo).max(0.01)) as f32 * plot.height(),
                        )
                    })
                    .collect()
            };
            if points.len() == 1 {
                p.circle_filled(points[0], 2., c::PASSPORT_MEASURED);
            } else {
                p.add(egui::Shape::line(
                    points,
                    egui::Stroke::new(1.7, c::PASSPORT_MEASURED),
                ));
            }
        }
        p.text(
            egui::pos2(plot.left(), rect.bottom() - 4.),
            egui::Align2::LEFT_BOTTOM,
            format!(
                "−{:.1} {}",
                ts.saturating_sub(start) as f64 / 1000.,
                if ru { "с" } else { "s" }
            ),
            egui::FontId::proportional(12.),
            c::TEXT_SECONDARY,
        );
        p.text(
            egui::pos2(plot.right(), rect.bottom() - 4.),
            egui::Align2::RIGHT_BOTTOM,
            if ru {
                "выбранный момент"
            } else {
                "selected time"
            },
            egui::FontId::proportional(12.),
            c::TEXT_SECONDARY,
        );
    }
}
/// Timestamped history, rather than Series::points which deliberately excludes missing readings.
pub(super) fn plot_segments(
    history: &[Arc<Sample>],
    id: &str,
    start: u64,
    end: u64,
    index: usize,
) -> Vec<Vec<(u64, f64)>> {
    let mut out = vec![];
    let mut line = vec![];
    let mut last = None;
    for s in history
        .iter()
        .take(index.saturating_add(1))
        .filter(|s| !s.warmup && s.timestamp_ms >= start && s.timestamp_ms <= end)
    {
        let m = s.metrics.iter().find(|m| m.id == id);
        let usable = m
            .filter(|m| {
                matches!(m.state, MetricState::Ok | MetricState::Zero)
                    && s.timestamp_ms.saturating_sub(m.timestamp_ms) <= 2500
            })
            .and_then(|m| m.usable_value());
        if (usable.is_none() || last.is_some_and(|t| s.timestamp_ms > t + 2500)) && !line.is_empty()
        {
            out.push(std::mem::take(&mut line));
        }
        if let Some(v) = usable {
            line.push((s.timestamp_ms, v));
        }
        last = Some(s.timestamp_ms);
    }
    if !line.is_empty() {
        out.push(line);
    }
    out
}

fn table_row(ui: &mut egui::Ui, cells: &[String], tip: Option<String>, stripe: bool) {
    let width = ui.available_width();
    let (rect, response) = ui.allocate_exact_size(egui::vec2(width, 31.), egui::Sense::hover());
    if let Some(tip) = tip {
        response.on_hover_text(tip);
    }
    let p = ui.painter();
    if stripe {
        p.rect_filled(rect, 2, c::BG_FIELD);
    }
    let name_width = if cells.len() == 4 {
        width * 0.49
    } else {
        width * 0.45
    };
    let value_width = (width - name_width) / (cells.len() - 1) as f32;
    for (i, text) in cells.iter().enumerate() {
        let (cell, align) = if i == 0 {
            (
                egui::Rect::from_min_max(
                    rect.min,
                    egui::pos2(rect.left() + name_width, rect.bottom()),
                ),
                egui::Align2::LEFT_CENTER,
            )
        } else {
            (
                egui::Rect::from_min_max(
                    egui::pos2(
                        rect.left() + name_width + (i - 1) as f32 * value_width,
                        rect.top(),
                    ),
                    egui::pos2(
                        rect.left() + name_width + i as f32 * value_width,
                        rect.bottom(),
                    ),
                ),
                egui::Align2::RIGHT_CENTER,
            )
        };
        let painter = p.with_clip_rect(cell.shrink(5.).intersect(ui.clip_rect()));
        let pos = if i == 0 {
            egui::pos2(cell.left() + 5., cell.center().y)
        } else {
            egui::pos2(cell.right() - 6., cell.center().y)
        };
        painter.text(
            pos,
            align,
            text,
            egui::FontId::proportional(15.),
            if i == 1 {
                c::PASSPORT_MEASURED
            } else {
                c::TEXT_BODY
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn metric(id: &str, label: &str, unit: &str, value: f64) -> Metric {
        Metric::measured(id, label, Group::Memory, unit, value, "synthetic")
    }
    #[test]
    fn timings_and_capacity_have_no_live_statistics_or_invented_units() {
        let timing = metric("lhm/dimm/timing/0", "CAS Latency", "Timing", 16.);
        assert_eq!(kind(&timing), Kind::Timing);
        assert_eq!(value(&timing), "16");
        let cap = metric("lhm/dimm/data/0", "Capacity", "GiB", 24.);
        assert_eq!(kind(&cap), Kind::Fact);
        assert_eq!(
            kind(&metric("lhm/ram/data/0", "Memory Used", "GiB", 24.)),
            Kind::Live
        );
        let raw = powerlab_core::ipc::metric_to_json(&timing).render();
        assert!(raw.contains("Timing"));
    }
    #[test]
    fn unknowns_and_ambiguous_cpu_core_keep_raw_identifiers() {
        let a = metric("cpu-a", "CPU Core", "°C", 42.);
        let b = metric("cpu-b", "CPU Core", "V", 1.2);
        assert!(title(&a).contains("температура"));
        assert!(title(&b).contains("напряжение"));
        assert!(title(&metric("/vin5", "Nuvoton · VIN5", "V", 1.)).contains("не подтверждено"));
    }
    #[test]
    fn storage_label_uses_explicit_provider_model_and_device_id() {
        let mut m = metric("storage.3.temperature", "storage.3.temperature", "degC", 0.);
        m.notes = vec![
            "NVMe".into(),
            "Synthetic Disk".into(),
            "documented provider".into(),
        ];
        assert_eq!(device_name(&m), "Synthetic Disk #3");
        assert_eq!(device_id(&m), "storage.3");
        assert_eq!(m.label, "storage.3.temperature");
    }
    #[test]
    fn absent_error_and_stale_readings_break_plot_never_become_zero() {
        let mut samples = vec![];
        for i in 1..=6 {
            let mut s = super::super::fixture_sample();
            s.index = i;
            s.timestamp_ms = i as u64 * 1000;
            s.warmup = false;
            s.metrics[0].timestamp_ms = s.timestamp_ms;
            if i == 3 {
                s.metrics.clear();
            }
            if i == 5 {
                s.metrics[0].state = MetricState::Error;
                s.metrics[0].value = None;
            }
            samples.push(Arc::new(s));
        }
        let lines = plot_segments(&samples, "cpu.package_power", 0, 6000, 5);
        assert_eq!(
            lines.iter().map(Vec::len).collect::<Vec<_>>(),
            vec![2, 1, 1]
        );
        assert!(lines.iter().flatten().all(|p| p.1 == 20.));
    }
    #[test]
    fn navigation_and_render_never_clear_history_or_start_another_reader() {
        let mut m = Monitor::default();
        m.apply(SamplerEvent::Sample(Box::new(
            super::super::fixture_sample(),
        )));
        m.view.group = Some(Group::Memory);
        m.view.end = Some(0);
        m.open_window();
        let context = egui::Context::default();
        let mut output = context.run_ui(Default::default(), |ui| {
            m.draw(ui, "NOT_INSTALLED", false, "synthetic");
        });
        output.textures_delta.clear();
        assert_eq!(m.samples(), 1);
        assert!(!m.owns_reader());
        assert!(!m.pending);
    }
}

#[cfg(test)]
mod identity_snapshot_tests {
    use super::*;
    #[test]
    fn proven_disk_alias_unifies_primary_summary_but_retains_raw_channel_in_metadata() {
        let mut monitor = Monitor::default();
        let mut sample = super::super::fixture_sample();
        let mut m = Metric::measured(
            "storage.7.temperature",
            "storage.7.temperature",
            Group::Storage,
            "degC",
            42.,
            "Windows/StorageReliabilityCounter.Temperature",
        );
        m.timestamp_ms = 1;
        m.notes = vec!["NVMe".into(), "Synthetic Disk".into()];
        sample.metrics = vec![m];
        monitor.apply(SamplerEvent::Sample(Box::new(sample)));
        monitor.storage_map.insert(
            "storage.7".into(),
            super::super::storage_identity::Identity {
                hardware: "disk/2".into(),
                model: "Synthetic Disk".into(),
            },
        );
        let mut snap = monitor.b3_snapshot();
        assert_eq!(snap.sensors[0].hw_id, "disk/2");
        assert!(
            snap.hardware_metadata
                .as_ref()
                .unwrap()
                .contains("storage.7.temperature")
        );
        assert!(
            snap.hardware_metadata
                .as_ref()
                .unwrap()
                .contains("Exact unique SerialNumber")
        );
        let mut other = snap.sensors[0].clone();
        other.provider = crate::sensors::Provider::NvmeHealth;
        other.sensor_id = "nvme/2/composite".into();
        snap.sensors.push(other);
        let summary = crate::sensors::summarize(&snap.sensors);
        assert_eq!(
            summary
                .temps
                .iter()
                .filter(|c| matches!(c.role, crate::sensors::Role::DiskTemp(_)))
                .count(),
            1
        );
    }
}

fn axis_bounds(unit: &str, mut lo: f64, mut hi: f64) -> (f64, f64) {
    if unit == "%" {
        return (0.0, 100.0);
    }
    if (hi - lo).abs() < 1e-9 {
        let pad = lo.abs().mul_add(0.1, 1.0);
        hi += pad;
        lo = (lo - pad).max(0.0);
    }
    (lo, hi)
}
#[cfg(test)]
mod v111_chart_tests {
    use super::*;
    #[test]
    fn constant_zero_ticks_are_distinct_and_duty_is_full_scale() {
        let (lo, hi) = axis_bounds("RPM", 0., 0.);
        let ticks: Vec<_> = (0..=4)
            .map(|i| format!("{:.2}", lo + (hi - lo) * i as f64 / 4.))
            .collect();
        assert_eq!(
            ticks
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            5
        );
        assert_eq!(axis_bounds("%", 41., 42.), (0., 100.));
    }
    #[test]
    fn cooling_includes_gpu_fan_rpm_and_duty_without_cpu_power() {
        let fan = Metric::measured("gpu.0.fan", "GPU fan", Group::Gpu, "RPM", 1200., "mock");
        let duty = Metric::measured(
            "gpu.0.fan.duty",
            "GPU fan duty",
            Group::Gpu,
            "%",
            40.,
            "mock",
        );
        let cpu = Metric::measured("cpu.power", "CPU power", Group::Cpu, "W", 40., "mock");
        assert!(in_group(&fan, Some(Group::Cooling)));
        assert!(in_group(&duty, Some(Group::Cooling)));
        assert!(!in_group(&cpu, Some(Group::Cooling)));
    }
}
