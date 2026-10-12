//! v1.0 Startup Idle / Client Identity regression tests (app level).
//!
//! A launch runs no diagnostic collector, starts no subprocess and creates
//! no report / session / ZIP; active collection only follows an explicit
//! user action. Every operation reports under the Client / Computer frozen
//! when the user started it (unique SessionId), never a stale identity.

use super::*;
use crate::deep_checks::json;

fn app_in(tag: &str) -> (WinStateDiagApp, PathBuf) {
    let exe = std::env::temp_dir()
        .join(format!("wsd-idle-{tag}-{}", std::process::id()))
        .join("WinStateDiag");
    let _ = std::fs::remove_dir_all(exe.parent().unwrap());
    std::fs::create_dir_all(&exe).unwrap();
    let mut app = WinStateDiagApp::default();
    app.reports_root = exe.join("Reports");
    app.language_pref_dir = exe.clone();
    app.language = Language::Ru;
    app.computer_name = "MSI".into();
    app.package = Arc::new(Mutex::new(SessionPackage::new(exe.join("Reports"), None)));
    (app, exe)
}

/// One frame without a window: the per-frame polls of `logic()` and the
/// dashboard drawn headlessly; any action it emits is applied, as `ui()`.
fn frame(app: &mut WinStateDiagApp, ctx: &egui::Context) {
    app.poll_engine();
    app.poll_benchmark();
    app.poll_nvme_health();
    app.poll_retest();
    app.poll_driver_audit();
    app.poll_hardware();
    app.poll_crypto();
    app.poll_crash();
    app.poll_sensors();
    app.poll_gpo();
    app.poll_passport();
    app.poll_crash_redetect();
    app.poll_events();
    app.poll_ata_scan();
    app.finalize_report_if_idle();
    let vm = app.build_vm(0.016, 1.0);
    let mut actions = Vec::new();
    ctx.run_ui(egui::RawInput::default(), |ui| {
        let mut controls = Controls {
            client_name: &mut app.client_name,
            mode: &mut app.mode,
            deep_checks: &mut app.deep_checks,
            include_hardware: &mut app.include_hardware,
            benchmark_path: &mut app.benchmark_path,
        };
        dashboard::draw(ui, egui::pos2(0.0, 0.0), &vm, &mut controls, &mut actions);
    })
    .textures_delta
    .clear();
    for a in actions {
        app.apply(a);
    }
}

/// A window-less egui context with the app fonts live (they apply from
/// the frame after `install`).
fn headless_ctx() -> egui::Context {
    let ctx = egui::Context::default();
    fonts::install(&ctx);
    ctx.run_ui(egui::RawInput::default(), |_| {})
        .textures_delta
        .clear();
    ctx
}

/// The report ZIP of `base` under the package's own Reports folder.
fn zip_in(exe: &Path, base: &str) -> PathBuf {
    exe.join("Reports").join(base).join(format!("{base}.zip"))
}

fn session(app: &WinStateDiagApp) -> Option<SessionIdentity> {
    app.session_identity()
}

fn manifest(zip: &Path) -> json::Value {
    let m = report_package::read_zip(zip)
        .unwrap()
        .into_iter()
        .find(|e| e.name == crate::manifest::MANIFEST_FILE)
        .expect("manifest.json");
    json::parse(std::str::from_utf8(&m.bytes).unwrap()).unwrap()
}

fn str_of<'a>(v: &'a json::Value, k: &str) -> &'a str {
    v.get(k).and_then(|x| x.as_str()).unwrap_or_default()
}

/// Delivers one finished sensor read (the evidence of an explicit read).
fn deliver_sensors(app: &mut WinStateDiagApp) {
    let (tx, rx) = std::sync::mpsc::channel();
    tx.send(sensors::Snapshot::default()).unwrap();
    app.sensors_rx = Some(rx);
    app.poll_sensors();
}

fn zip_of(app: &WinStateDiagApp) -> PathBuf {
    report_package::lock(&app.package)
        .final_zip()
        .expect("the session ZIP")
}

fn today() -> String {
    identity_date(sysinfo::local_time())
}

// ---------------- STARTUP IDLE ----------------

#[test]
fn startup_runs_no_diagnostic_and_starts_no_collector_in_both_languages() {
    for lang in [Language::Ru, Language::En] {
        let mut app = WinStateDiagApp::default();
        app.language = lang;
        let ctx = headless_ctx();
        for _ in 0..5 {
            frame(&mut app, &ctx);
        }
        assert!(
            app.collector_requests.is_empty(),
            "{lang:?}: startup requested {:?}",
            app.collector_requests
        );
        assert!(matches!(app.state, RunState::Idle));
        assert!(matches!(app.driver_audit, DriverAuditState::Idle));
        assert!(matches!(app.hardware, HardwareViewState::Idle));
        assert!(matches!(app.benchmark_state, BenchmarkUiState::Idle));
        assert!(app.crypto.is_none() && app.crypto_rx.is_none());
        assert!(app.sensors.is_none() && app.sensors_rx.is_none());
        assert!(app.passport.is_none() && app.passport_rx.is_none());
        assert!(app.ata_scan.is_none() && app.ata_rx.is_none());
        assert!(app.crash.inventory.is_none() && app.crash_rx.is_none());
        assert!(app.gpo.is_none() && app.gpo_rx.is_none());
        assert!(app.event_evidence.is_none() && app.events_rx.is_none());
        assert!(app.nvme_rx.is_none() && app.session_cancel.is_none());

        // IDLE / "Ожидание запуска", and honest idle cards.
        let d = i18n::t(lang);
        let vm = app.build_vm(0.0, 0.0);
        assert_eq!(vm.operation.name, d.curop_waiting_name);
        assert_eq!(vm.overall.status_text, d.overall_status_waiting);
        assert!(matches!(vm.drivers, DriversVm::NotRun));
        assert_eq!(vm.crypto, CryptoVm::NotChecked);
        assert!(!vm.sensors.busy);
        assert!(!vm.crash.busy);
        assert_eq!(vm.crash.headline, d.crash_not_scanned);
        assert!(
            vm.crash.can_analyze,
            "Analyze stays available (scans first)"
        );
    }
    assert_eq!(i18n::RU.curop_waiting_name, "Ожидание запуска");
    assert_eq!(i18n::EN.curop_waiting_name, "Waiting to start");
}

/// Source contract: the constructor (the launch) never starts a collector,
/// a thread or a process — not even behind a "not under test" guard that
/// the runtime checks above could not see.
#[test]
fn the_launch_code_path_contains_no_collector_start() {
    let src = include_str!("app.rs");
    let start = src
        .find("impl Default for WinStateDiagApp {")
        .expect("constructor");
    let end = start + src[start..].find("\nimpl WinStateDiagApp {").unwrap();
    let ctor = &src[start..end];
    for forbidden in [
        "start_",
        "thread::spawn",
        "Command::new",
        "run_session",
        "run_hardware_view",
        "begin_operation",
        "contribute",
        "StartupLog",
    ] {
        assert!(!ctor.contains(forbidden), "launch code calls `{forbidden}`");
    }
    // The renderer entry opens only the start-up log (Reports\Logs).
    let lib = include_str!("lib.rs");
    assert!(lib.contains("let mut inner = app::WinStateDiagApp::default();"));
}

#[test]
fn startup_creates_no_report_folder_session_or_zip() {
    let fresh = WinStateDiagApp::default();
    assert!(report_package::lock(&fresh.package).is_fresh());
    assert!(fresh.session_identity().is_none());

    let (mut app, exe) = app_in("nofiles");
    let ctx = headless_ctx();
    for _ in 0..5 {
        frame(&mut app, &ctx);
    }
    assert!(!app.reports_root.exists(), "no Reports, no session folder");
    assert!(report_package::lock(&app.package).is_fresh());
    assert!(report_package::lock(&app.package).final_zip().is_none());
    assert!(app.final_report().is_err());
    // Nothing at all was written next to the EXE.
    let entries: Vec<_> = std::fs::read_dir(&exe).unwrap().flatten().collect();
    assert!(entries.is_empty(), "{entries:?}");
    let _ = std::fs::remove_dir_all(exe.parent().unwrap());
}

#[test]
fn switching_pages_never_starts_a_scan() {
    let (mut app, exe) = app_in("pages");
    let ctx = headless_ctx();
    for page in [
        Page::Hardware,
        Page::Diagnostics,
        Page::Hardware,
        Page::Diagnostics,
    ] {
        app.apply(Action::SetPage(page));
        for _ in 0..3 {
            frame(&mut app, &ctx);
        }
        assert_eq!(app.page, page);
    }
    assert!(
        app.collector_requests.is_empty(),
        "{:?}",
        app.collector_requests
    );
    assert!(app.session_identity().is_none());
    assert!(!app.reports_root.exists());
    let _ = std::fs::remove_dir_all(exe.parent().unwrap());
}

// ---------------- CLIENT IDENTITY ----------------

#[test]
fn start_freezes_client_and_computer_into_session_manifest_and_evidence() {
    let (mut app, exe) = app_in("identity");
    app.client_name = "  Иванов Иван ".into();
    app.apply(Action::Start);

    // The full pipeline and its modules start only now.
    for m in [
        "expc_session",
        "gpo",
        "crash_scan",
        "sensors",
        "events",
        "ata_smart",
        "cryptopro",
        "passport",
    ] {
        assert!(app.collector_requests.contains(&m), "{m} not started");
    }
    let s = session(&app).expect("a session");
    assert_eq!(s.client, "Иванов Иван");
    assert_eq!(s.computer, "MSI");
    assert!(s.session_id.starts_with("WSD-") && s.session_id.ends_with("-01"));
    assert_eq!(
        app.test_session_request,
        Some(("Иванов Иван".to_string(), "MSI".to_string()))
    );
    let line = app
        .journal
        .iter()
        .map(|e| e.message.clone())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        line.contains(&s.session_id) && line.contains("Иванов Иван"),
        "{line}"
    );

    // Editing the field while the session runs never changes its identity.
    app.client_name = "Петров".into();
    deliver_sensors(&mut app);
    let zip = zip_of(&app);
    let base = format!("Иванов Иван - MSI - {}", today());
    assert_eq!(zip, zip_in(&exe, &base));
    let m = manifest(&zip);
    let ms = m.get("session").expect("session in manifest");
    assert_eq!(str_of(ms, "session_id"), s.session_id);
    assert_eq!(str_of(ms, "client_name"), "Иванов Иван");
    assert_eq!(str_of(&m, "computer_name"), "MSI");
    assert_eq!(str_of(&m, "package"), format!("{base}.zip"));
    let names: Vec<String> = report_package::read_zip(&zip)
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    assert!(
        names
            .iter()
            .any(|n| n.starts_with(sensors::EVIDENCE_PREFIX)),
        "{names:?}"
    );
    let _ = std::fs::remove_dir_all(exe.parent().unwrap());
}

#[test]
fn a_new_run_with_another_client_never_reuses_the_old_identity() {
    let (mut app, exe) = app_in("rerun");
    app.client_name = "Иванов".into();
    app.apply(Action::Start);
    let first = session(&app).unwrap();
    deliver_sensors(&mut app);
    let zip1 = zip_of(&app);
    let zip1_bytes = std::fs::read(&zip1).unwrap();
    // The first run ends (any final state), then another client starts.
    app.state = RunState::Idle;
    app.client_name = "Петров".into();
    app.apply(Action::Start);
    let second = session(&app).unwrap();
    assert_ne!(second.session_id, first.session_id);
    assert_eq!(second.client, "Петров");
    assert_eq!(
        app.test_session_request,
        Some(("Петров".to_string(), "MSI".to_string()))
    );
    deliver_sensors(&mut app);
    let zip2 = zip_of(&app);
    let base2 = format!("Петров - MSI - {}", today());
    assert_eq!(zip2, zip_in(&exe, &base2));
    let ms = manifest(&zip2);
    assert_eq!(str_of(ms.get("session").unwrap(), "client_name"), "Петров");
    assert_eq!(
        str_of(ms.get("session").unwrap(), "session_id"),
        second.session_id
    );
    // The first client's report is untouched.
    assert_eq!(std::fs::read(&zip1).unwrap(), zip1_bytes);
    assert_eq!(
        str_of(manifest(&zip1).get("session").unwrap(), "client_name"),
        "Иванов"
    );
    // Same client again: a new session id, its own folder reused.
    app.state = RunState::Idle;
    app.client_name = "Иванов".into();
    app.apply(Action::Start);
    let third = session(&app).unwrap();
    assert_ne!(third.session_id, first.session_id);
    deliver_sensors(&mut app);
    assert_eq!(zip_of(&app), zip1);
    assert_eq!(
        str_of(manifest(&zip1).get("session").unwrap(), "session_id"),
        third.session_id
    );
    let _ = std::fs::remove_dir_all(exe.parent().unwrap());
}

#[test]
fn empty_client_reports_under_the_computer_only() {
    let (mut app, exe) = app_in("empty");
    app.client_name = "   ".into();
    app.apply(Action::Start);
    let s = session(&app).unwrap();
    assert_eq!(s.client, "");
    assert_eq!(
        app.test_session_request,
        Some((String::new(), "MSI".to_string()))
    );
    deliver_sensors(&mut app);
    let base = format!("MSI - {}", today());
    assert_eq!(zip_of(&app), zip_in(&exe, &base));
    let m = manifest(&zip_of(&app));
    assert_eq!(str_of(m.get("session").unwrap(), "client_name"), "");
    assert_eq!(str_of(&m, "computer_name"), "MSI");
    let _ = std::fs::remove_dir_all(exe.parent().unwrap());
}

#[test]
fn cancelling_a_diagnostic_stops_it_and_the_next_run_is_a_new_session() {
    let (mut app, exe) = app_in("cancel");
    app.client_name = "Иванов".into();
    app.apply(Action::Start);
    let first = session(&app).unwrap();
    assert!(app.stop_enabled());
    app.apply(Action::Stop);
    assert!(
        app.session_cancel
            .as_ref()
            .is_some_and(|c| c.load(Ordering::SeqCst)),
        "the cancel request reaches the engine"
    );
    assert!(!app.stop_enabled());
    let tx = app.engine_test_tx.take().expect("engine request");
    tx.send(EngineEvent::Cancelled {
        zip_path: None,
        note: "stopped".into(),
    })
    .unwrap();
    app.poll_engine();
    assert!(matches!(app.state, RunState::Cancelled { .. }));
    assert!(app.session_cancel.is_none());
    // A stopped run is never finalized or re-started by itself.
    let requests = app.collector_requests.len();
    let ctx = headless_ctx();
    for _ in 0..3 {
        frame(&mut app, &ctx);
    }
    assert_eq!(app.collector_requests.len(), requests);
    // The next Start opens a fresh session with the identity of NOW.
    app.client_name = "Петров".into();
    app.apply(Action::Start);
    let next = session(&app).unwrap();
    assert_ne!(next.session_id, first.session_id);
    assert_eq!(next.client, "Петров");
    let _ = std::fs::remove_dir_all(exe.parent().unwrap());
}

// ---------------- EXPLICIT SEPARATE MODULES ----------------

#[test]
fn separate_modules_start_only_themselves_with_their_own_identity() {
    // Sensors.
    let (mut app, exe) = app_in("mod-sensors");
    app.client_name = "Клиент А".into();
    app.apply(Action::RefreshSensors);
    assert_eq!(app.collector_requests, ["sensors"]);
    assert_eq!(session(&app).unwrap().client, "Клиент А");
    deliver_sensors(&mut app);
    assert_eq!(
        str_of(
            manifest(&zip_of(&app)).get("session").unwrap(),
            "client_name"
        ),
        "Клиент А"
    );
    let _ = std::fs::remove_dir_all(exe.parent().unwrap());

    // Hardware view (+ the Hardware page's passport and ATA SMART rows).
    let (mut app, exe) = app_in("mod-hw");
    app.apply(Action::ViewHardware);
    assert_eq!(
        app.collector_requests,
        ["passport", "ata_smart", "hardware_view"]
    );
    assert!(session(&app).is_some());
    let _ = std::fs::remove_dir_all(exe.parent().unwrap());

    // SMART alone is part of that explicit Hardware action; never at launch.
    // Crash analyzer before any inventory: the scan runs first.
    let (mut app, exe) = app_in("mod-crash");
    app.apply(Action::AnalyzeDumps);
    assert_eq!(app.collector_requests, ["crash_scan"]);
    assert!(app.crash_analyze_after_scan);
    let _ = std::fs::remove_dir_all(exe.parent().unwrap());

    // SSD benchmark.
    let (mut app, exe) = app_in("mod-bench");
    app.benchmark_path = exe.display().to_string();
    app.apply(Action::BenchmarkStart);
    assert_eq!(app.collector_requests, ["ssd_benchmark"]);
    assert!(app.benchmark_is_running());
    let _ = std::fs::remove_dir_all(exe.parent().unwrap());

    // Group Policy / ADMX.
    let (mut app, exe) = app_in("mod-gpo");
    app.apply(Action::RunGpoCheck);
    assert_eq!(app.collector_requests, ["gpo"]);
    let _ = std::fs::remove_dir_all(exe.parent().unwrap());

    // Driver Audit (Details window "Run check").
    let (mut app, exe) = app_in("mod-drivers");
    app.client_name = "Клиент Б".into();
    app.request_driver_audit();
    assert_eq!(app.collector_requests, ["driver_audit"]);
    assert_eq!(app.driver_rerun_requests, 1);
    // Its evidence joins its own session package right away.
    let (tx, rx) = std::sync::mpsc::channel();
    app.driver_audit = DriverAuditState::Running(rx);
    tx.send(Ok(crate::details::tests::report())).unwrap();
    app.poll_driver_audit();
    let m = manifest(&zip_of(&app));
    assert_eq!(str_of(m.get("session").unwrap(), "client_name"), "Клиент Б");
    let base = format!("Клиент Б - MSI - {}", today());
    assert_eq!(zip_of(&app), zip_in(&exe, &base));
    let _ = std::fs::remove_dir_all(exe.parent().unwrap());
}

#[test]
fn a_separate_module_after_a_client_change_opens_a_new_session() {
    let (mut app, exe) = app_in("mod-ident");
    app.client_name = "Клиент А".into();
    app.apply(Action::RefreshSensors);
    let a = session(&app).unwrap();
    app.sensors_rx = None;
    // Same identity: the module joins the current session.
    app.apply(Action::RunGpoCheck);
    assert_eq!(session(&app).unwrap(), a);
    // Changed client: a new session, never the stale one.
    app.client_name = "Клиент Б".into();
    app.gpo_rx = None;
    app.apply(Action::RunGpoCheck);
    let b = session(&app).unwrap();
    assert_ne!(b.session_id, a.session_id);
    assert_eq!(b.client, "Клиент Б");
    // While a full diagnostic runs, a module joins that running session.
    app.client_name = "Клиент В".into();
    app.apply(Action::Start);
    let full = session(&app).unwrap();
    assert_eq!(full.client, "Клиент В");
    app.client_name = "Клиент Г".into();
    app.sensors_rx = None;
    app.apply(Action::RefreshSensors);
    assert_eq!(session(&app).unwrap(), full);
    let _ = std::fs::remove_dir_all(exe.parent().unwrap());
}

#[test]
fn session_journal_line_is_localized() {
    for (lang, word) in [(Language::Ru, "клиент"), (Language::En, "client")] {
        let (mut app, exe) = app_in(&format!("journal-{lang:?}"));
        app.language = lang;
        app.client_name = String::new();
        app.apply(Action::RefreshSensors);
        let last = app.journal.last().unwrap().message.clone();
        assert!(last.starts_with("[INFO]") && last.contains(word), "{last}");
        assert!(last.contains("—") && last.contains("MSI"), "{last}");
        let _ = std::fs::remove_dir_all(exe.parent().unwrap());
    }
}
