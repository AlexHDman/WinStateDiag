//! WinDiag-owned PowerLab viewport. Only the background supervisor owns a sampler.
#![allow(dead_code)]
mod elevation;
mod job;
pub fn elevated_worker(args: &[String]) -> i32 {
    elevation::broker(args)
}
mod placement;
mod report;
mod storage_identity;
mod supervisor;
mod view;
use crate::ui::tokens::color as c;
use powerlab_core::{
    ipc::{Group, Metric, MetricState, ProviderStatus, Sample, Series},
    present,
};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver},
    },
    time::{Duration, Instant},
};
use supervisor::{SamplerEvent, Supervisor, SupervisorConfig};

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Action {
    None,
    Install,
    Rights,
    Detect,
}
pub struct Monitor {
    pub open: bool,
    pub english: bool,
    pub pending: bool,
    rx: Option<Receiver<Result<SamplerEvent, String>>>,
    stop: Arc<AtomicBool>,
    latest: BTreeMap<String, Metric>,
    series: BTreeMap<String, Series>,
    last_ts: BTreeMap<String, u64>,
    history: Vec<Arc<Sample>>,
    bytes: usize,
    providers: Vec<ProviderStatus>,
    notices: Vec<String>,
    pub message: String,
    started: Option<Instant>,
    duration: Duration,
    version: String,
    clean: bool,
    export: Option<Receiver<Result<String, String>>>,
    pub report_dir: PathBuf,
    pub dirty_b3: bool,
    focus: bool,
    geometry: Option<placement::Geometry>,
    geometry_loaded: bool,
    viewport_created: bool,
    view: view::ViewState,
    storage_map: BTreeMap<String, storage_identity::Identity>,
    storage_rx: Option<Receiver<Result<BTreeMap<String, storage_identity::Identity>, String>>>,
    details: bool,
    pub runtime: Option<PathBuf>,
    pub fault: Option<String>,
    pub elevated: bool,
}
impl Default for Monitor {
    fn default() -> Self {
        Self {
            open: false,
            english: false,
            pending: false,
            rx: None,
            stop: Arc::new(AtomicBool::new(false)),
            latest: BTreeMap::new(),
            series: BTreeMap::new(),
            last_ts: BTreeMap::new(),
            history: vec![],
            bytes: 0,
            providers: vec![],
            notices: vec![],
            message: "Нажми «Старт», чтобы прочитать доступные датчики".into(),
            started: None,
            duration: Duration::ZERO,
            version: String::new(),
            clean: false,
            export: None,
            report_dir: std::env::current_exe()
                .unwrap_or_default()
                .with_file_name("Reports"),
            dirty_b3: false,
            focus: false,
            geometry: None,
            geometry_loaded: false,
            viewport_created: false,
            view: Default::default(),
            storage_map: BTreeMap::new(),
            storage_rx: None,
            details: false,
            runtime: None,
            fault: None,
            elevated: false,
        }
    }
}
impl Drop for Monitor {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(g) = self.geometry {
            placement::save(g);
        }
    }
}
impl Monitor {
    pub fn owns_reader(&self) -> bool {
        self.pending || self.rx.is_some()
    }
    pub fn running(&self) -> bool {
        self.rx.is_some()
    }
    pub fn saving(&self) -> bool {
        self.export.is_some()
    }
    pub fn last_sample_caption(&self, ru: bool) -> Option<String> {
        let ms = self.history.last()?.timestamp_ms;
        let t = crate::ui::sysinfo::local_time_of_unix(ms / 1000)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_millis() as u64;
        Some(format!(
            "{} {:02}:{:02}:{:02}{}",
            if ru { "Выборка" } else { "Sample" },
            t.hour,
            t.minute,
            t.second,
            if now.saturating_sub(ms) > 10000 {
                if ru {
                    " · устарело"
                } else {
                    " · stale"
                }
            } else {
                ""
            }
        ))
    }
    pub fn samples(&self) -> usize {
        self.history.len()
    }
    pub fn open_window(&mut self) {
        self.open = true;
        self.focus = true;
    }
    pub fn stop(&mut self) {
        self.pending = false;
        self.stop.store(true, Ordering::Release);
        if self.running() {
            self.message = "Завершение чтения…".into();
        }
    }
    fn notice(&mut self, text: String) {
        if self.notices.contains(&text) {
            return;
        }
        if self.notices.len() >= 240 {
            if let Some(i) = self.notices.iter().position(|s| !s.starts_with("error:")) {
                self.notices.remove(i);
            } else if !text.starts_with("error:") {
                return;
            } else {
                self.notices.remove(0);
            }
        }
        self.notices.push(text);
    }
    pub fn reader_state(&self) -> Option<String> {
        self.latest
            .get("lhm.access")
            .and_then(|m| m.notes.iter().find_map(|note| note.strip_prefix("pawnio=")))
            .and_then(|text| powerlab_core::json::Json::parse(text).ok())
            .and_then(|j| j.get("state").and_then(|v| v.as_str()).map(str::to_owned))
    }
    pub fn start(&mut self) {
        if self.running() {
            return;
        }
        if !elevation::available() {
            self.pending = false;
            self.message =
                "Расширенный reader ещё завершает работу; повторный запуск заблокирован".into();
            return;
        }
        self.pending = false;
        if self.storage_rx.is_none() {
            self.storage_map.clear();
            self.storage_rx = Some(storage_identity::start());
        }
        self.stop = Arc::new(AtomicBool::new(false));
        // Close/Open/Start preserve the full WinDiag-owned monitoring session.

        self.latest.clear();
        self.last_ts.clear();
        self.providers.clear();
        self.clean = false;
        let runtime_override = self.runtime.clone();
        let fault = self.fault.clone();
        let (tx, rx) = mpsc::sync_channel(32);
        self.rx = Some(rx);
        if self.started.is_none() {
            self.started = Some(Instant::now());
            self.duration = Duration::ZERO;
        }
        self.message = "Обнаружение оборудования…".into();
        let stop = self.stop.clone();
        let elevated = self.elevated;
        std::thread::spawn(move || {
            let result = (|| -> Result<(), String> {
                if elevated {
                    return elevation::run(tx.clone(), stop.clone());
                }
                let prepared = if runtime_override.is_none() {
                    Some(crate::portable::prepare()?)
                } else {
                    None
                };
                let program = runtime_override.unwrap_or_else(|| {
                    prepared
                        .as_ref()
                        .unwrap()
                        .root
                        .join("PowerLab/powerlab-sampler.exe")
                });
                let mut config = SupervisorConfig::new(program);
                config.fault = fault;
                let _runtime = verify_runtime(&config.program)?;
                let mut s = Supervisor::start_cancellable(config, &stop)?;
                if let Some(v) = s.sampler_version() {
                    tx.send(Ok(SamplerEvent::Hello {
                        sampler_version: v,
                        kind: "native".into(),
                    }))
                    .map_err(|_| "Окно закрыто")?;
                }
                loop {
                    if stop.load(Ordering::Acquire) {
                        let verdict = s.stop();
                        let _ = tx.send(Ok(SamplerEvent::Stopped(verdict)));
                        break;
                    }
                    if let Some(event) = s.poll(Duration::from_millis(20)) {
                        let ended = matches!(event, SamplerEvent::Stopped(_));
                        if tx.send(Ok(event)).is_err() {
                            let _ = s.stop();
                            break;
                        }
                        if ended {
                            break;
                        }
                    }
                }
                Ok(())
            })();
            if let Err(e) = result {
                let _ = tx.send(Err(e));
            }
        });
    }
    pub fn request_rights(&mut self) {
        if self.owns_reader() {
            return;
        }
        self.elevated = true;
        self.pending = true;
        self.message = "Ожидание штатного UAC reader; сессия WinDiag сохранена".into();
    }
    pub fn reset(&mut self) {
        if !self.owns_reader() && self.export.is_none() {
            self.latest.clear();
            self.history.clear();
            self.series.clear();
            self.last_ts.clear();
            self.bytes = 0;
            self.started = None;
            self.duration = Duration::ZERO;
            self.message = "Новый сеанс готов к запуску".into();
        }
    }
    pub fn pump(&mut self) {
        if let Some(rx) = &self.storage_rx {
            match rx.try_recv() {
                Ok(result) => {
                    self.storage_rx = None;
                    match result {
                        Ok(map) => {
                            self.storage_map = map;
                            self.dirty_b3 = true;
                        }
                        Err(reason) => self.notice(format!(
                            "Идентификация накопителей: {reason}; недоказанные дубли не объединены"
                        )),
                    }
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.storage_rx = None;
                }
                _ => {}
            }
        }

        for _ in 0..64 {
            let next = self.rx.as_ref().map(|rx| rx.try_recv());
            match next {
                Some(Ok(Ok(event))) => self.apply(event),
                Some(Ok(Err(e))) => {
                    self.message = e.clone();
                    self.notice(e);
                    self.rx = None;
                    break;
                }
                Some(Err(mpsc::TryRecvError::Disconnected)) => {
                    self.rx = None;
                    break;
                }
                _ => break,
            }
        }
        if let Some(rx) = &self.export {
            match rx.try_recv() {
                Ok(result) => {
                    self.message = result.unwrap_or_else(|e| format!("Не удалось сохранить: {e}"));
                    self.export = None
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.message = "Потерян ответ сохранения".into();
                    self.export = None
                }
                _ => {}
            }
        }
    }
    #[cfg(test)]
    pub(crate) fn replay_sample(&mut self, sample: powerlab_core::ipc::Sample) {
        self.apply(SamplerEvent::Sample(Box::new(sample)));
    }
    pub(crate) fn apply(&mut self, event: SamplerEvent) {
        match event {
            SamplerEvent::Hello {
                sampler_version, ..
            } => self.version = sampler_version,
            SamplerEvent::Providers(p) => self.providers = p,
            SamplerEvent::Notice { level, text } => self.notice(format!("{level}: {text}")),
            SamplerEvent::Stopped(reason) => {
                self.clean = reason.is_clean();
                self.message = reason.describe();
                self.duration = self.started.map(|t| t.elapsed()).unwrap_or_default();
            }
            SamplerEvent::Sample(sample) => {
                let mut sample = *sample;
                sample.index = self.history.len() as u32 + 1;
                let cost = sample_memory(&sample);
                if self.history.len() >= 20_000
                    || self.bytes.saturating_add(cost) > 64 * 1024 * 1024
                {
                    self.stop();
                    self.notice("Достигнут лимит сеанса: чтение остановлено, уже полученные измерения сохранены".into());
                    return;
                }
                for m in &sample.metrics {
                    if !sample.warmup && self.last_ts.get(&m.id) != Some(&m.timestamp_ms) {
                        self.series.entry(m.id.clone()).or_default().push(m);
                        self.last_ts.insert(m.id.clone(), m.timestamp_ms);
                    }
                    if self.latest.len() < 512 || self.latest.contains_key(&m.id) {
                        self.latest.insert(m.id.clone(), m.clone());
                    }
                }
                self.bytes += cost;
                self.history.push(Arc::new(sample));
                self.dirty_b3 = true;
                self.message = format!("Мониторинг · измерений: {}", self.history.len());
            }
        }
    }
    pub fn export(&mut self, format: &str, client: &str) {
        if self.export.is_some() || self.history.is_empty() {
            return;
        }
        let samples = self.history.clone();

        let providers = self.providers.clone();
        let notices = self.notices.clone();
        let version = self.version.clone();
        let duration = if self.running() {
            self.started.map(|t| t.elapsed()).unwrap_or_default()
        } else {
            self.duration
        };
        let clean = self.clean && !self.running();
        let dir = self.report_dir.clone();
        let format = format.to_owned();
        let machine = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "UNKNOWN".into());
        let client = client.to_owned();
        let (tx, rx) = mpsc::channel();
        self.export = Some(rx);
        std::thread::spawn(move || {
            let result = (|| {
                let samples: Vec<Sample> = samples.into_iter().map(|s| (*s).clone()).collect();
                let mut series: BTreeMap<String, Series> = BTreeMap::new();
                let mut stamps: BTreeMap<String, u64> = BTreeMap::new();
                for sample in &samples {
                    if sample.warmup {
                        continue;
                    }
                    for m in &sample.metrics {
                        if stamps.get(&m.id) != Some(&m.timestamp_ms) {
                            series.entry(m.id.clone()).or_default().push(m);
                            stamps.insert(m.id.clone(), m.timestamp_ms);
                        }
                    }
                }
                std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
                let ts = samples.first().map(|s| s.timestamp_ms).unwrap_or(0);
                let sources = vec![format!("WinDiag {}; client={}", crate::APP_VERSION, client)];
                let report = report::RunReport {
                    started_local: format!("unix_ms:{ts}"),
                    started_utc: format!("unix_ms:{ts}"),
                    duration,
                    interval: Duration::from_secs(1),
                    providers: &providers,
                    source_lines: &sources,
                    notices: &notices,
                    samples: &samples,
                    series: &series,
                    stop: if clean {
                        "Остановлен штатно"
                    } else {
                        "Промежуточный снимок / неполное завершение"
                    }
                    .into(),
                    clean,
                    sampler_version: &version,
                    machine,
                };
                let path = match format.as_str() {
                    "json" => report::write_json(&report, &dir),
                    "csv" => report::write_csv(&report, &dir),
                    _ => report::write_txt(&report, &dir),
                }?;
                Ok(format!("Сохранено: {}", path.display()))
            })();
            let _ = tx.send(result);
        });
    }
    pub fn b3_snapshot(&self) -> crate::sensors::Snapshot {
        use crate::sensors::*;
        let mut snap = Snapshot {
            captured_at: crate::app::local_iso(crate::ui::sysinfo::local_time()),
            samples: self.history.len() as u32,
            interval_ms: 1000,
            ..Default::default()
        };
        snap.providers.push(ProviderReport {
            provider: Provider::CollectorRuntime,
            state: ProviderState::Partial,
            detail: "Единый активный сеанс PowerLab; повторный опрос B3 не выполняется".into(),
        });
        snap.hardware_metadata = Some(
            powerlab_core::json::Json::Object(vec![
                (
                    "owner".into(),
                    powerlab_core::json::Json::str("WinDiag PowerLab shared stream"),
                ),
                ("storage_identity".into(),powerlab_core::json::Json::Array(self.storage_map.iter().map(|(id,v)|powerlab_core::json::Json::Object(vec![("provider_id".into(),powerlab_core::json::Json::str(id)),("hardware".into(),powerlab_core::json::Json::str(&v.hardware)),("model".into(),powerlab_core::json::Json::str(&v.model)),("proof".into(),powerlab_core::json::Json::str("Exact unique SerialNumber join: MSFT_PhysicalDisk to Win32_DiskDrive; serial omitted"))])).collect())),
                (
                    "metrics".into(),
                    powerlab_core::json::Json::Array(
                        self.latest
                            .values()
                            .map(powerlab_core::ipc::metric_to_json)
                            .collect(),
                    ),
                ),
            ])
            .render(),
        );
        for m in self.latest.values() {
            if !matches!(m.state, MetricState::Ok | MetricState::Zero) {
                continue;
            }
            let Some(value) = m.usable_value() else {
                continue;
            };
            let kind = match m.unit.as_str() {
                "°C" | "degC" => SensorKind::Temperature,
                "V" => SensorKind::Voltage,
                "W" => SensorKind::Power,
                "RPM" => SensorKind::Fan,
                _ => continue,
            };
            let category = match m.group {
                Group::Cpu => HwCategory::Cpu,
                Group::Gpu => HwCategory::Gpu,
                Group::Memory => HwCategory::Memory,
                Group::Motherboard | Group::Cooling => HwCategory::Motherboard,
                Group::Storage => HwCategory::Storage,
                _ => HwCategory::Other,
            };
            let stats = self.series.get(&m.id);
            snap.sensors.push(Sensor {
                provider: Provider::CollectorRuntime,
                hw_id: self
                    .storage_map
                    .get(&view::device_id(m))
                    .map(|v| v.hardware.clone())
                    .unwrap_or_else(|| view::device_id(m)),
                hw_name: self
                    .storage_map
                    .get(&view::device_id(m))
                    .map(|v| v.model.clone())
                    .unwrap_or_else(|| view::device_name(m)),
                category,
                sensor_id: m.sensor.clone().unwrap_or_else(|| m.id.clone()),
                name: b3_sensor_name(m),
                kind,
                value,
                min: stats.and_then(|s| s.min).unwrap_or(value),
                max: stats.and_then(|s| s.max).unwrap_or(value),
                samples: stats.map(|s| s.count as u32).unwrap_or(1),
                critical_consecutive: 0,
                confidence: if kind == SensorKind::Voltage && category == HwCategory::Motherboard {
                    Confidence::Low
                } else {
                    Confidence::Medium
                },
                timestamp: format!("unix_ms:{}", m.timestamp_ms),
            });
        }
        snap
    }
    pub fn draw(
        &mut self,
        ui: &mut egui::Ui,
        dependency: &str,
        busy: bool,
        client: &str,
    ) -> Action {
        self.dashboard(ui, dependency, busy, client)
    }
    pub fn window(
        &mut self,
        ctx: &egui::Context,
        dependency: &str,
        busy: bool,
        client: &str,
    ) -> Action {
        if !self.open {
            return Action::None;
        }
        let id = egui::ViewportId::from_hash_of("windiag-powerlab");
        if self.focus {
            ctx.send_viewport_cmd_to(id, egui::ViewportCommand::Minimized(false));
            ctx.send_viewport_cmd_to(id, egui::ViewportCommand::Focus);
            self.focus = false;
        }
        if !self.geometry_loaded {
            self.geometry_loaded = true;
            #[cfg(not(test))]
            {
                self.geometry = placement::load().filter(|g| placement::visible(*g));
            }
        }
        let mut builder = egui::ViewportBuilder::default()
            .with_title("WinDiag — PowerLab")
            .with_min_inner_size([640.0, 480.0])
            .with_clamp_size_to_monitor_size(true)
            .with_resizable(true);
        if !self.viewport_created {
            self.viewport_created = true;
            if let Some(g) = self.geometry {
                builder = builder
                    .with_position(egui::pos2(g.x, g.y))
                    .with_inner_size([g.w, g.h])
                    .with_maximized(g.maximized);
            } else {
                let pos = ctx
                    .input(|i| i.viewport().outer_rect.map(|r| r.min))
                    .unwrap_or(egui::pos2(40., 40.));
                builder = builder
                    .with_position(pos)
                    .with_inner_size([1180.0, 880.0])
                    .with_maximized(true);
            }
        }
        let (result, close) = ctx.show_viewport_immediate(id, builder, |ui, class| {
            crate::app::details_text_scale(ui.style_mut());
            let info = ui.ctx().input(|i| i.viewport().clone());
            if class != egui::ViewportClass::EmbeddedWindow {
                let zoomed = info.maximized.unwrap_or(false);
                if !zoomed
                    && info.minimized != Some(true)
                    && let (Some(outer), Some(inner)) = (info.outer_rect, info.inner_rect)
                {
                    let g = placement::Geometry {
                        x: outer.min.x,
                        y: outer.min.y,
                        w: inner.width(),
                        h: inner.height(),
                        scale: ui.ctx().pixels_per_point(),
                        maximized: false,
                    };
                    if placement::Geometry::parse(&format!(
                        "{} {} {} {} {} 0",
                        g.x, g.y, g.w, g.h, g.scale
                    ))
                    .is_some()
                    {
                        self.geometry = Some(g);
                    }
                } else if let Some(g) = &mut self.geometry {
                    g.maximized = zoomed;
                }
            }
            if class == egui::ViewportClass::EmbeddedWindow {
                return (self.draw(ui, dependency, busy, client), false);
            }
            let close = info.close_requested();
            let action = egui::CentralPanel::default()
                .frame(egui::Frame::new().fill(c::BG_CARD).inner_margin(16))
                .show(ui, |ui| self.draw(ui, dependency, busy, client))
                .inner;
            (action, close)
        });
        if close {
            self.open = false;
            self.viewport_created = false;
            if let Some(g) = self.geometry {
                placement::save(g);
            }
            self.stop();
        }
        ctx.request_repaint_after(Duration::from_millis(100));
        result
    }
}
fn b3_sensor_name(m: &Metric) -> String {
    match m.id.as_str() {
        "cpu.package_power" => "CPU Package".into(),
        "cpu.cores_power" => "CPU Cores".into(),
        id if id.starts_with("gpu.") && id.ends_with(".temperature") => "GPU Temperature".into(),
        id if id.starts_with("gpu.") && id.ends_with(".power") => "GPU Power".into(),
        id if id.starts_with("gpu.") && id.ends_with(".hotspot") => "GPU Hot Spot".into(),
        id if id.starts_with("gpu.") && id.ends_with(".voltage") => "GPU Core Voltage".into(),
        id if id.starts_with("storage.") && id.ends_with(".temperature") => "Temperature".into(),
        _ => m.label.split(" · ").last().unwrap_or(&m.label).into(),
    }
}

fn display_value(m: &Metric) -> String {
    let value = present::value_with_unit(m);
    if m.state == MetricState::Suspect {
        format!("Проверить: {value}")
    } else {
        value
    }
}
fn hidden_core(m: &Metric) -> bool {
    m.id.starts_with("lhm")
        && [" · Core #", " · P-Core #", " · E-Core #"]
            .iter()
            .any(|part| m.label.contains(part))
}
fn reason_ru(m: &Metric) -> String {
    let reason = m
        .reason
        .as_deref()
        .unwrap_or("Источник не предоставил значение");
    if reason.contains("ACCESS_DENIED") || reason.contains("Win32 5") {
        "Нет доступа к защищённому датчику. Требуются разрешённые права чтения.".into()
    } else if reason.contains("SMART") {
        "Источник LHM отключён: его чтение может менять настройки SMART. Используется Windows Storage.".into()
    } else if m.state == MetricState::Unsupported {
        "Датчик не поддерживается этим источником; это не признак неисправности.".into()
    } else {
        reason.into()
    }
}
fn sample_memory(sample: &Sample) -> usize {
    std::mem::size_of::<Sample>()
        + sample.metrics.capacity() * std::mem::size_of::<Metric>()
        + sample
            .metrics
            .iter()
            .map(|m| {
                m.id.capacity()
                    + m.label.capacity()
                    + m.unit.capacity()
                    + m.source.capacity()
                    + m.reason.as_ref().map_or(0, String::capacity)
                    + m.sensor.as_ref().map_or(0, String::capacity)
                    + m.hardware.as_ref().map_or(0, String::capacity)
                    + m.raw_unit.as_ref().map_or(0, String::capacity)
                    + m.notes.capacity() * std::mem::size_of::<String>()
                    + m.notes.iter().map(String::capacity).sum::<usize>()
            })
            .sum::<usize>()
}

const PINNED_RUNTIME: &str = include_str!("../../third_party/powerlab-runtime/SHA256SUMS.json");
fn verify_runtime(program: &std::path::Path) -> Result<Vec<std::fs::File>, String> {
    use std::os::windows::fs::OpenOptionsExt;
    if !program.is_file() {
        return Err(
            "В комплекте отсутствует внутренний sampler PowerLab. Повтори автоматическую подготовку зависимостей."
                .into(),
        );
    }
    let root = program.parent().ok_or("Каталог sampler недоступен")?;
    let manifest = powerlab_core::json::Json::parse(PINNED_RUNTIME).map_err(|e| e.to_string())?;
    let items = manifest.as_object().ok_or("Invalid pinned manifest")?;
    let mut locks = Vec::with_capacity(items.len());
    for (name, _) in items {
        locks.push(
            std::fs::OpenOptions::new()
                .read(true)
                .share_mode(1)
                .open(root.join(name))
                .map_err(|e| format!("Компонент PowerLab {name}: {e}"))?,
        );
    }
    let script = format!(
        "$ErrorActionPreference='Stop';$root='{}';$m=ConvertFrom-Json -InputObject @'\n{}\n'@;foreach($p in $m.PSObject.Properties){{if((Get-FileHash -LiteralPath (Join-Path $root $p.Name) -Algorithm SHA256).Hash -ne $p.Value){{throw ('Component hash mismatch: '+$p.Name)}}}};'WSD_POWERLAB_VERIFIED'",
        root.to_string_lossy().replace('\'', "''"),
        PINNED_RUNTIME
    );
    let output =
        crate::ps_exec::run_powershell_compact("powershell.exe", &script, Duration::from_secs(30))
            .map_err(|e| e.to_string())?;
    if !output.contains("WSD_POWERLAB_VERIFIED") {
        return Err("Не подтверждена целостность PowerLab".into());
    }
    Ok(locks)
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    #[test]
    #[ignore = "Read-only actual Windows sampler; explicit opt-in"]
    fn actual_embedded_reader_spike() {
        let mut m = Monitor::default();
        m.runtime = Some(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("third_party/powerlab-runtime/powerlab-sampler.exe"),
        );
        m.start();
        let deadline = Instant::now() + Duration::from_secs(20);
        while m.samples() < 4 && m.running() && Instant::now() < deadline {
            m.pump();
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(m.samples() >= 4, "{}", m.message);
        assert!(m.latest.values().any(|x| x.usable_value().is_some()));
        let t = Instant::now();
        m.stop();
        assert!(t.elapsed() < Duration::from_millis(20));
        while m.running() && Instant::now() < deadline {
            m.pump();
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(!m.running(), "reader did not finish");
        assert!(m.clean, "{}", m.message);
    }
}

#[cfg(test)]
mod acceptance_tests;

fn hidden_duplicate(m: &Metric, all: &BTreeMap<String, Metric>) -> bool {
    if (m.id.starts_with("lhm/ram/") || m.id.starts_with("lhm/vram/"))
        && all
            .keys()
            .any(|id| id.starts_with("ram.") && !id.starts_with("ram.module."))
    {
        return true;
    }
    if m.id.starts_with("lhm/") && (m.label.contains("D3D ") || m.label.contains("D3D·")) {
        return true;
    }
    false
}
#[cfg(test)]
mod offscreen;

#[cfg(test)]
pub(crate) fn fixture_sample() -> Sample {
    let mut m = Metric::measured(
        "cpu.package_power",
        "CPU Package",
        Group::Cpu,
        "W",
        20.,
        "fixture",
    );
    m.timestamp_ms = 1;
    m.sensor = Some("PKG".into());
    m.hardware = Some("cpu/0".into());
    Sample {
        index: 1,
        timestamp_ms: 1,
        window_ms: 1000.,
        elapsed_ms: 0.,
        warmup: false,
        metrics: vec![m],
    }
}

#[cfg(test)]
pub(crate) fn test_event() -> supervisor::SamplerEvent {
    supervisor::SamplerEvent::Sample(Box::new(fixture_sample()))
}

pub fn portable_probe(evidence: &std::path::Path) -> Result<(), String> {
    std::fs::create_dir_all(evidence).map_err(|e| e.to_string())?;
    let mut m = Monitor::default();
    m.report_dir = evidence.join("Reports");
    let run = |m: &mut Monitor, wanted: usize| -> Result<(), String> {
        m.start();
        let end = Instant::now() + Duration::from_secs(55);
        while m.samples() < wanted && m.running() && Instant::now() < end {
            m.pump();
            std::thread::sleep(Duration::from_millis(10));
        }
        m.stop();
        let end = Instant::now() + Duration::from_secs(15);
        while m.running() && Instant::now() < end {
            m.pump();
            std::thread::sleep(Duration::from_millis(10));
        }
        if m.running() || !m.clean || m.samples() < wanted {
            return Err(format!("Monitor: {} samples; {}", m.samples(), m.message));
        }
        Ok(())
    };
    run(&mut m, 4)?;
    let original = m.samples();
    m.open_window();
    m.open = false;
    m.open_window();
    if m.samples() != original {
        return Err("Session lost on reopening".into());
    }
    for _ in 0..2 {
        for format in ["txt", "json", "csv"] {
            m.export(format, "Проверка одиночного EXE");
            let until = Instant::now() + Duration::from_secs(15);
            while m.saving() && Instant::now() < until {
                m.pump();
                std::thread::sleep(Duration::from_millis(10));
            }
            if m.saving() || !m.message.starts_with("Сохранено:") {
                return Err(m.message.clone());
            }
        }
    }
    run(&mut m, original + 3)?;
    let mut capture =
        std::fs::File::create(evidence.join("samples.jsonl")).map_err(|e| e.to_string())?;
    use std::io::Write;
    for sample in &m.history {
        writeln!(capture, "{}", ipc_sample_json(sample)).map_err(|e| e.to_string())?;
    }
    std::fs::write(
        evidence.join("portable-live.txt"),
        format!(
            "version={}\nsamples={}\nclean={}\nexports=6\nsession_preserved=true\n",
            crate::APP_VERSION,
            m.samples(),
            m.clean
        ),
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}
fn ipc_sample_json(sample: &Sample) -> String {
    powerlab_core::ipc::sample_to_json(sample).render()
}
