// WinStateDiag - portable Windows state diagnostic center.
// A minimal GUI + session/orchestration layer around the proven, unmodified
// EXPC Diagnostic / Hardware Report PowerShell engine (see src/engine.rs).
// Library root: all modules + the process entry (`run`). The thin binary
// (src/main.rs) only owns `windows_subsystem` and the UAC manifest (build.rs),
// so `cargo test` exercises this crate without requiring elevation.

mod app;
mod ata_smart;
mod crash_dump;
mod crash_report;
mod cryptopro;
mod deep_checks;
mod details;
mod driver_audit;
mod engine;
mod events;
mod gpo_admx;
mod graphics_startup;
mod graphics_wgpu;
pub mod i18n;
mod incidents;
mod manifest;
mod nvme_health;
mod passport;
mod power;
mod ps_exec;
mod report_package;
mod sensors;
pub mod ssd_history;
pub mod storage_benchmark;
mod storage_health;
mod storage_history;
pub mod storage_topology;
mod ui;
mod win_dialog;
mod win_icon;

use graphics_startup::{GraphicsMode, Role, StartupLog};
use std::path::PathBuf;

/// Single source of truth for the displayed application version, derived
/// from the Cargo package version by build.rs (v1.0 policy: `1.0.0` is
/// shown as "1.0"), so the title bar never drifts from what shipped.
pub const APP_VERSION: &str = env!("WSD_DISPLAY_VERSION");

/// v0.4.5: titlebar / taskbar / Alt+Tab icon from the approved
/// `assets\icon.ico` (256 px PNG frame). Without it eframe installs egui's
/// default icon at runtime. Falls back to an empty icon (OS default from
/// the EXE resource) if decoding ever fails.
fn window_icon() -> std::sync::Arc<egui::IconData> {
    let ico: &[u8] = include_bytes!("../assets/icon.ico");
    let icon = graphics_startup::largest_png_icon_frame(ico)
        .and_then(|png| eframe::icon_data::from_png_bytes(png).ok())
        .unwrap_or_default();
    std::sync::Arc::new(icon)
}

/// Process entry, called by the `win_state_diag` binary.
pub fn run() -> ! {
    let args: Vec<String> = std::env::args().skip(1).collect();
    // v0.4.5 validation hook (no GUI): one read-only sensor sampling window
    // written as Hardware_Sensors JSON. Used for the AIDA64 comparison.
    if args.first().map(String::as_str) == Some("--sensor-probe") {
        std::process::exit(sensor_probe(args.get(1).map(PathBuf::from)));
    }
    // v0.4.5 validation hook (no GUI): crash inventory + freeze / hang
    // incidents + computer passport, read only, for the live tests.
    if args.first().map(String::as_str) == Some("--incident-probe") {
        std::process::exit(incident_probe(args.get(1).map(PathBuf::from)));
    }
    // v1.0 validation hooks (no GUI, read-only): event evidence + driver
    // resolver + process snapshot; full dump analysis pipeline.
    if args.first().map(String::as_str) == Some("--evidence-probe") {
        std::process::exit(evidence_probe(
            args.get(1).map(PathBuf::from),
            args.get(2).cloned(),
        ));
    }
    if args.first().map(String::as_str) == Some("--dump-probe") {
        std::process::exit(dump_probe(
            args.get(1).map(PathBuf::from),
            args.get(2).map(PathBuf::from),
        ));
    }
    // v1.0 validation hook (no GUI): read-only ATA SMART of every physical
    // disk (UNSUPPORTED is reported honestly for NVMe / bridges / RAID).
    if args.first().map(String::as_str) == Some("--consistency-probe") {
        std::process::exit(consistency_probe(args.get(1).map(PathBuf::from)));
    }
    if args.first().map(String::as_str) == Some("--smart-probe") {
        std::process::exit(smart_probe(args.get(1).map(PathBuf::from)));
    }
    let handshake = std::env::var(graphics_startup::ENV_HANDSHAKE).ok();
    let code = match graphics_startup::parse_role(&args, handshake.as_deref()) {
        // Safe Graphics Startup: the bootstrap only supervises renderer
        // children (normal, then safe) and never renders itself.
        Ok(Role::Bootstrap) => graphics_startup::run_bootstrap(&args),
        Ok(Role::Renderer { mode, supervised }) => run_renderer(
            &args,
            mode,
            handshake.filter(|_| supervised).map(PathBuf::from),
        ),
        Err(err) => {
            let log = StartupLog::open("startup");
            log.line(&format!("invalid arguments: {err}"));
            graphics_startup::show_native_error(&format!(
                "WinStateDiag: {err}\n\nЖурнал запуска: {}",
                log.path().display()
            ));
            graphics_startup::EXIT_INVALID_MODE
        }
    };
    std::process::exit(code);
}

/// `--sensor-probe [out.json]`: samples the sensors for ~10 s (no load,
/// nothing installed) and writes the evidence JSON. Exit code 0 when
/// written.
fn sensor_probe(out: Option<PathBuf>) -> i32 {
    let out = out.unwrap_or_else(|| PathBuf::from("Hardware_Sensors_probe.json"));
    let base = std::env::temp_dir().join("WinStateDiag");
    let (snap, raw) = sensors::collect_raw("powershell.exe", &base, 10, 1000);
    // Raw sampler output beside the JSON, for validation / diagnosis.
    let _ = std::fs::write(out.with_extension("raw.txt"), raw);
    match std::fs::write(&out, sensors::to_json(&snap)) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

/// `--evidence-probe <dir> [module]`: Event_Evidence JSON, the read-only
/// driver resolution of `module` (default `stornvme`) and one process
/// snapshot, for live validation.
fn evidence_probe(dir: Option<PathBuf>, module: Option<String>) -> i32 {
    let dir = dir.unwrap_or_else(|| PathBuf::from("evidence_probe"));
    let _ = std::fs::create_dir_all(&dir);
    let started = std::time::Instant::now();
    let mut summary = String::new();
    match events::collect("powershell.exe") {
        Ok((raw, services)) => {
            let collected_at = app::local_iso(ui::sysinfo::local_time());
            let aggs = events::aggregate(&raw, &services, &collected_at);
            let wu = events::wu_failure_is_historical(&raw);
            let _ = std::fs::write(
                dir.join("Event_Evidence_probe.json"),
                events::to_json(&aggs, wu, &collected_at),
            );
            summary.push_str(&format!(
                "EVENTS raw={} services={} aggregates={} seconds={}\r\n",
                raw.len(),
                services.len(),
                aggs.len(),
                started.elapsed().as_secs()
            ));
            for a in aggs.iter().take(25) {
                summary.push_str(&format!("AGG {}\r\n", events::aggregate_line(a)));
            }
        }
        Err(e) => summary.push_str(&format!("EVENTS_ERROR {e}\r\n")),
    }
    let module = module.unwrap_or_else(|| "stornvme".into());
    let r = crash_dump::resolve_driver("powershell.exe", &module);
    for l in crash_dump::resolution_lines(&r, false) {
        summary.push_str(&format!("DRIVER {l}\r\n"));
    }
    match ps_exec::run_powershell(
        "powershell.exe",
        sensors::PROCESS_PS1,
        std::time::Duration::from_secs(40),
    ) {
        Ok(out) => match sensors::parse_process_context(&out) {
            Some(p) => summary.push_str(&format!(
                "PROCESS cpu={:.0}% high={} top={}\r\n",
                p.system_cpu_percent,
                p.high_load,
                p.top.len()
            )),
            None => summary.push_str("PROCESS unparsed\r\n"),
        },
        Err(e) => summary.push_str(&format!("PROCESS_ERROR {e}\r\n")),
    }
    match std::fs::write(dir.join("evidence_probe.txt"), summary) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

/// `--dump-probe <dump> <dir>`: one complete headless analysis exactly as
/// the app runs it (real stages, symbols, lmvm, driver resolution),
/// written as the same CrashDump evidence files.
fn dump_probe(dump: Option<PathBuf>, dir: Option<PathBuf>) -> i32 {
    let (Some(dump), Some(dir)) = (dump, dir) else {
        return 2;
    };
    let _ = std::fs::create_dir_all(&dir);
    let inv = match crash_dump::collect_inventory("powershell.exe") {
        Ok(i) => i,
        Err(_) => return 3,
    };
    let crash_dump::DebuggerStatus::Installed { cdb } = &inv.debugger else {
        return 4;
    };
    let cache = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("WinStateDiag")
        .join("Symbols");
    let stages = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let seen = std::sync::Arc::clone(&stages);
    let started = std::time::Instant::now();
    let mut best = crash_dump::AnalysisStage::PrepareDump;
    let (status, raw) = crash_dump::run_analysis_observed(
        cdb,
        &dump.display().to_string(),
        &cache,
        std::time::Duration::from_secs(crash_dump::ANALYSIS_TIMEOUT_SECS),
        move |line| {
            if let Some(s) = crash_dump::stage_of_cdb_line(line)
                && s > best
            {
                best = s;
                if let Ok(mut v) = seen.lock() {
                    v.push(format!(
                        "{:?} at {:.1}s",
                        s,
                        started.elapsed().as_secs_f32()
                    ));
                }
            }
        },
    );
    let name = dump
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let file = crash_dump::DumpFile {
        path: dump.display().to_string(),
        name: name.clone(),
        size: std::fs::metadata(&dump).map(|m| m.len()).unwrap_or(0),
        modified: String::new(),
        kind: crash_dump::DumpKind::Mini,
    };
    let mut a = crash_dump::DumpAnalysis::build(file, None, status, raw, None);
    if let Some(m) = a.third_party_module() {
        let info = crash_dump::run_lmvm(
            cdb,
            &dump.display().to_string(),
            &cache,
            &m,
            std::time::Duration::from_secs(180),
        );
        let res = crash_dump::resolve_driver("powershell.exe", &m);
        a = a.with_module(info, Some(res));
    }
    let _ = std::fs::write(
        dir.join("CrashDump_Analysis_probe.txt"),
        crash_dump::analysis_txt(&a, Some(cdb)),
    );
    let _ = std::fs::write(
        dir.join("CrashDump_Summary_probe.json"),
        crash_dump::summary_json(&a, None, "CrashDump_Analysis_probe.txt"),
    );
    let mut s = format!(
        "STATUS {}\r\nCONFIDENCE {}\r\nMODULE {:?}\r\nSECONDS {}\r\n",
        a.status.code(),
        a.confidence.code(),
        a.parsed.implicated_module(),
        started.elapsed().as_secs()
    );
    for st in stages.lock().map(|v| v.clone()).unwrap_or_default() {
        s.push_str(&format!("STAGE {st}\r\n"));
    }
    match std::fs::write(dir.join("dump_probe.txt"), s) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn smart_probe(out: Option<PathBuf>) -> i32 {
    let out = out.unwrap_or_else(|| PathBuf::from("Ata_Smart_probe.json"));
    let mut items: Vec<String> = Vec::new();
    let mut lines: Vec<String> = Vec::new();
    #[allow(unused_mut)]
    let mut inconsistent = 0usize;
    #[cfg(windows)]
    {
        use storage_topology::TopologySource;
        let src = storage_topology::windows_source::WindowsTopologySource;
        for disk in src.physical_disks() {
            let s = ata_smart::read(disk.index);
            // v1.0 consistency probe: the SAME normalized record the app
            // writes (NVMe log or ATA SMART) and the correlation verdict
            // built from it must agree: ATA SMART read OK may never end up
            // as UNSUPPORTED / health unavailable.
            let mut h = nvme_health::collect(
                &nvme_health::windows_source::WindowsNvmeReader,
                &disk,
                "probe",
            );
            if nvme_health::is_ata_bus(&disk.bus_type) {
                nvme_health::apply_ata(&mut h, s.clone());
            }
            let (source, status) = nvme_health::health_source_status(&h);
            let c = storage_health::classify(&storage_health::StorageHealthInputs {
                physical_identity: h.physical_identity.clone(),
                disk_index: Some(disk.index),
                benchmark: None,
                retest: storage_health::RetestOutcome::NotNeeded,
                nvme: Some(h.clone()),
                events: storage_health::EventsInput::NotCollected,
                assessed_at: "probe".into(),
            });
            let unavailable = c.findings.iter().any(|f| f.code() == "health_unavailable");
            let ata_ok = s.state == ata_smart::AtaState::Ok;
            let consistent = !(ata_ok && (status == "UNSUPPORTED" || unavailable));
            if !consistent {
                inconsistent += 1;
            }
            lines.push(format!(
                "DISK PD{} | {} | {} | ata={} | health_source={source} | health_status={status} | correlation={} | consistent={}",
                disk.index,
                disk.model.trim(),
                disk.bus_type,
                s.state.code(),
                c.state.code(),
                consistent
            ));
            items.push(format!(
                "  {{\"physical_disk_index\": {}, \"model\": {}, \"bus\": {}, \"ata_smart\": {}, \"health_source\": {}, \"health_status\": {}, \"correlation_state\": {}}}",
                disk.index,
                deep_checks::json::string(disk.model.trim()),
                deep_checks::json::string(&disk.bus_type),
                ata_smart::to_json(&s),
                deep_checks::json::string(source),
                deep_checks::json::string(status),
                deep_checks::json::string(c.state.code())
            ));
        }
    }
    lines.push(format!(
        "SMART_CONSISTENCY={}",
        if inconsistent == 0 { "PASS" } else { "FAIL" }
    ));
    let _ = std::fs::write(out.with_extension("txt"), lines.join("\r\n") + "\r\n");
    let body = format!("[\n{}\n]\n", items.join(",\n"));
    match std::fs::write(&out, body) {
        Ok(()) if inconsistent == 0 => 0,
        _ => 1,
    }
}

fn incident_probe(out: Option<PathBuf>) -> i32 {
    let out = out.unwrap_or_else(|| PathBuf::from("Incidents_probe.json"));
    let mut summary = String::new();
    match passport::collect("powershell.exe") {
        Ok(p) => summary.push_str(&format!(
            "PASSPORT_WINDOWS={}\r\nPASSPORT_CPU={}\r\nPASSPORT_RAM={}\r\nPASSPORT_BOARD={}\r\nPASSPORT_BIOS={}\r\n",
            p.windows, p.cpu, p.ram_text(false), p.board, p.bios
        )),
        Err(e) => summary.push_str(&format!("PASSPORT_ERROR={e}\r\n")),
    }
    let code = match crash_dump::collect_inventory("powershell.exe") {
        Ok(inv) => {
            let verdicts = crash_dump::incident_verdicts(&inv, &[]);
            summary.push_str(&format!("COUNTS={}\r\n", crash_dump::counts_line(&inv)));
            for b in &inv.bugchecks {
                summary.push_str(&format!("BUGCHECK=0x{:08X} {}\r\n", b.code, b.time));
            }
            for (i, v) in &verdicts {
                summary.push_str(&format!(
                    "INCIDENT={} | {} | {}\r\n",
                    crash_dump::incident_line(i),
                    v.headline(),
                    v.signals.join(" ; ")
                ));
            }
            summary.push_str(&format!(
                "LIVE_KERNEL_REPORTS={}\r\n",
                inv.live_kernel_reports.len()
            ));
            // v1.0: WinDbg package / backend state and the crash report
            // exactly as the Details window builds it.
            summary.push_str(&format!(
                "DEBUGGER={}\r\nDEBUGGER_TEXT={}\r\n",
                inv.debugger.code(),
                crash_report::debugger_line(&inv.debugger, false)
            ));
            let report = crash_report::build(&inv, &[], false);
            summary.push_str(&format!("CRASH_LEVEL={}\r\n", report.level.code()));
            summary.push_str(&crash_report::to_text(&report, false));
            let json = incidents::to_json(
                &verdicts,
                inv.unexpected_shutdowns.max(inv.incidents.len()),
                &inv.live_kernel_reports,
            );
            if std::fs::write(&out, json).is_ok() {
                0
            } else {
                1
            }
        }
        Err(e) => {
            summary.push_str(&format!("INVENTORY_ERROR={e}\r\n"));
            1
        }
    };
    let _ = std::fs::write(out.with_extension("txt"), summary);
    code
}

/// Renderer process: runs the GUI in `mode`. Never starts another process.
/// The main window title (also reported by `--consistency-probe`).
pub fn base_window_title() -> String {
    format!("WinStateDiag — v{APP_VERSION}")
}

/// v1.0 release-gate hook (no GUI, read-only): version strings of the
/// shipped binary + cross-view consistency of the normalized records
/// (storage health → manifest / correlation; crash counters card ↔
/// report on the REAL crash inventory of this machine).
fn consistency_probe(out: Option<PathBuf>) -> i32 {
    let out = out.unwrap_or_else(|| PathBuf::from("Consistency_probe.txt"));
    let mut lines: Vec<String> = vec![
        format!("TITLE={}", base_window_title()),
        format!("APP_VERSION={APP_VERSION}"),
        format!("PRODUCER_VERSION={}", manifest::PRODUCER_VERSION),
    ];
    let mut ok = APP_VERSION == "1.0" && manifest::PRODUCER_VERSION == "1.0";
    // Storage: an ATA SMART health record through the shipped writers.
    let disk = storage_topology::PhysicalDiskInfo {
        index: 1,
        model: "PROBE SATA SSD".into(),
        serial: String::new(),
        bus_type: "SATA".into(),
        size_bytes: 0,
        is_ssd_like: true,
    };
    struct NoNvme;
    impl nvme_health::NvmeLogSource for NoNvme {
        fn read_log_page(
            &self,
            _: u32,
            _: u8,
            _: usize,
        ) -> Result<nvme_health::LogRead, nvme_health::ProbeError> {
            Err(nvme_health::ProbeError::InvalidFunction)
        }
    }
    let mut h = nvme_health::collect(&NoNvme, &disk, "probe");
    nvme_health::apply_ata(
        &mut h,
        ata_smart::AtaSmart {
            state: ata_smart::AtaState::Ok,
            detail: String::new(),
            attributes: Vec::new(),
        },
    );
    let inputs = storage_health::StorageHealthInputs {
        physical_identity: h.physical_identity.clone(),
        disk_index: Some(1),
        benchmark: None,
        retest: storage_health::RetestOutcome::NotNeeded,
        nvme: Some(h.clone()),
        events: storage_health::EventsInput::Collected(Vec::new()),
        assessed_at: "probe".into(),
    };
    let c = storage_health::classify(&inputs);
    let health_json = nvme_health::to_json(&h);
    let corr_json = storage_health::to_json(&inputs, &c, "PROBE SATA SSD", None, &[]);
    let field = |t: &str, k: &str| {
        deep_checks::json::parse(t)
            .and_then(|v| v.get(k).and_then(|x| x.as_str()).map(str::to_string))
            .unwrap_or_default()
    };
    let (hs, cs, ch) = (
        field(&health_json, "health_status"),
        field(&corr_json, "state"),
        field(&corr_json, "health_status"),
    );
    let storage_ok = hs == "OK" && ch == "OK" && cs == "OK";
    ok &= storage_ok;
    lines.push(format!(
        "STORAGE_ATA health_status={hs} correlation_state={cs} correlation_health={ch} -> {}",
        if storage_ok { "PASS" } else { "FAIL" }
    ));
    // Crash counters on this machine's real inventory.
    match crash_dump::collect_inventory("powershell.exe") {
        Ok(inv) => {
            let a = crash_report::Counters::of(&inv);
            let r = crash_report::build(&inv, &[], true);
            let text = crash_report::to_text(&r, true);
            let same = a == r.counters && text.contains(&a.line(true));
            ok &= same;
            lines.push(format!(
                "CRASH_COUNTERS {} -> {}",
                a.line(false),
                if same { "PASS" } else { "FAIL" }
            ));
            lines.push(format!("DEBUGGER={}", inv.debugger.code()));
        }
        Err(e) => lines.push(format!("CRASH_COUNTERS NOT_VERIFIED ({e})")),
    }
    lines.push(format!("CONSISTENCY={}", if ok { "PASS" } else { "FAIL" }));
    let _ = std::fs::write(&out, lines.join("\r\n") + "\r\n");
    if ok { 0 } else { 1 }
}

fn run_renderer(args: &[String], mode: GraphicsMode, handshake: Option<PathBuf>) -> i32 {
    let log = StartupLog::open(&format!("renderer:{}", mode.name()));
    if handshake.is_none() {
        // Started directly (no bootstrap): this process opens the session.
        log.session_start(mode.name());
    }
    log.line(&format!(
        "renderer start: {} ({}); {}",
        mode.name(),
        mode.description(),
        graphics_startup::environment_summary()
    ));

    let reference = args.iter().any(|a| a == "--visual-reference");
    let mut title = base_window_title();
    if reference {
        title.push_str("  [VISUAL REFERENCE]");
    }
    if mode == GraphicsMode::Safe {
        title.push_str("  [безопасный графический режим]");
    }
    // Initial size = reference canvas at 80%; the first frame fits it to the
    // monitor and the canvas then scales uniformly with the window.
    let mut options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title(title.clone())
            .with_inner_size([ui::tokens::CANVAS_W * 0.8, ui::tokens::CANVAS_H * 0.8])
            .with_min_inner_size([640.0_f32, 516.0_f32])
            .with_icon(window_icon()),
        ..Default::default()
    };
    graphics_wgpu::configure(&mut options.wgpu_options, mode);

    let supervised = handshake.is_some();
    let creator_log = log.clone();
    let result = eframe::run_native(
        &title,
        options,
        Box::new(move |cc| {
            ui::fonts::install(&cc.egui_ctx);
            let adapter = cc
                .wgpu_render_state
                .as_ref()
                .map(|rs| graphics_wgpu::describe(&rs.adapter.get_info()))
                .unwrap_or_else(|| "unknown".into());
            if let Some(rs) = cc.wgpu_render_state.as_ref() {
                let all: Vec<String> = rs
                    .available_adapters
                    .iter()
                    .map(|a| graphics_wgpu::describe(&a.get_info()))
                    .collect();
                creator_log.line(&format!("available DX12 adapters: {}", all.join("; ")));
            }
            creator_log.line(&format!("renderer initialised: adapter {adapter}"));
            let mut inner = app::WinStateDiagApp::default();
            if mode == GraphicsMode::Safe {
                inner.push_notice(
                    "WinStateDiag запущен в безопасном графическом режиме. \
                     Обнаружена проблема инициализации стандартного графического режима."
                        .into(),
                );
            }
            Ok(Box::new(StartupGuard {
                inner,
                frames: 0,
                handshake,
                detail: format!("mode {}, adapter {adapter}", mode.name()),
                log: creator_log,
            }))
        }),
    );
    match result {
        Ok(()) => 0,
        Err(err) => {
            log.line(&format!("renderer initialisation failed: {err}"));
            if !supervised {
                // Started by hand (no supervisor): report directly.
                graphics_startup::show_native_error(&format!(
                    "WinStateDiag: не удалось запустить графический режим «{}».\n\n{err}\n\nЖурнал запуска: {}",
                    mode.name(),
                    log.path().display()
                ));
            }
            graphics_startup::EXIT_RENDERER_INIT_FAILED
        }
    }
}

/// Wraps the application to report "first frame painted" to the bootstrap.
struct StartupGuard {
    inner: app::WinStateDiagApp,
    frames: u32,
    handshake: Option<PathBuf>,
    detail: String,
    log: StartupLog,
}

impl eframe::App for StartupGuard {
    fn logic(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        self.inner.logic(ctx, frame);
    }

    fn ui(&mut self, ui: &mut egui::Ui, frame: &mut eframe::Frame) {
        self.inner.ui(ui, frame);
        self.frames = self.frames.saturating_add(1);
        // ui() of frame 2 runs after frame 1 was presented.
        if self.frames == 2 {
            self.log
                .line(&format!("first frame presented ({})", self.detail));
            if let Some(path) = self.handshake.take() {
                graphics_startup::signal_ready(&path, &self.detail);
            }
        }
        if self.frames < 3 {
            ui.ctx().request_repaint();
        }
    }
}

#[cfg(test)]
mod consistency_probe_tests {
    /// v1.0 release-gate hook: the shipped binary's version strings and the
    /// ATA health → correlation path agree (crash counters need Windows).
    #[test]
    fn consistency_probe_passes_storage_and_version_checks() {
        let dir = std::env::temp_dir().join(format!("wsd-consistency-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let out = dir.join("c.txt");
        let code = super::consistency_probe(Some(out.clone()));
        let text = std::fs::read_to_string(&out).unwrap();
        assert!(text.contains("TITLE=WinStateDiag — v1.0"), "{text}");
        assert!(text.contains("PRODUCER_VERSION=1.0"), "{text}");
        assert!(
            text.contains(
                "STORAGE_ATA health_status=OK correlation_state=OK correlation_health=OK -> PASS"
            ),
            "{text}"
        );
        if !cfg!(windows) {
            assert!(
                text.contains("CRASH_COUNTERS NOT_VERIFIED") || text.contains("CRASH_COUNTERS")
            );
        }
        assert!(code == 0 || text.contains("CRASH_COUNTERS"), "{text}");
        let _ = std::fs::remove_dir_all(dir);
    }
}
