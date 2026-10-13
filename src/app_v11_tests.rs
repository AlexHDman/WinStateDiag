//! v1.1 final integration regression tests (app level): startup
//! orchestration, CryptoPro / Driver Audit / WinDbg / crash preflight,
//! client identity isolation, re-checks, confirmations, cancellation,
//! concurrency, Hardware Passport 2.0 and RU / EN / DPI.

use super::*;
use crate::deep_checks::json;

fn app_in(tag: &str) -> (WinStateDiagApp, PathBuf) {
    let exe = std::env::temp_dir()
        .join(format!("wsd-v11-{tag}-{}", std::process::id()))
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

fn cleanup(exe: &Path) {
    let _ = std::fs::remove_dir_all(exe.parent().unwrap());
}

fn audit() -> AuditReport {
    crate::details::tests::report()
}

fn inventory(debugger: crash_dump::DebuggerStatus) -> crash_dump::Inventory {
    crash_dump::Inventory {
        bugchecks: Vec::new(),
        dumps: vec![crash_dump::DumpFile {
            path: "C:\\Windows\\Minidump\\100326-9500-01.dmp".into(),
            name: "100326-9500-01.dmp".into(),
            size: 1024,
            modified: "2026-10-03T00:34:41".into(),
            kind: crash_dump::DumpKind::Mini,
        }],
        debugger,
        notes: Vec::new(),
        unexpected_shutdowns: 1,
        incidents: Vec::new(),
        live_kernel_reports: Vec::new(),
    }
}

/// Delivers a finished Driver Audit through the real poll path.
fn deliver_audit(app: &mut WinStateDiagApp, result: Result<AuditReport, String>) {
    let (tx, rx) = std::sync::mpsc::channel();
    app.driver_audit = DriverAuditState::Running(rx);
    tx.send(result).unwrap();
    app.poll_driver_audit();
}

/// Delivers a finished crash inventory scan through the real poll path.
fn deliver_scan(app: &mut WinStateDiagApp, inv: crash_dump::Inventory) {
    let (tx, rx) = std::sync::mpsc::channel();
    tx.send(CrashMsg::Inventory(Ok(inv))).unwrap();
    drop(tx);
    app.crash_rx = Some(rx);
    app.crash.busy = CrashBusy::Scanning;
    app.poll_crash();
}

// ---------------- 1. asynchronous startup ----------------

#[test]
fn startup_preflight_starts_the_three_read_only_checks_without_blocking() {
    let (mut app, exe) = app_in("async");
    let t0 = Instant::now();
    app.start_preflight();
    assert!(
        t0.elapsed() < Duration::from_millis(500),
        "never blocks the GUI"
    );
    assert_eq!(
        app.collector_requests,
        ["driver_audit", "cryptopro", "crash_scan"]
    );
    assert_eq!(app.driver_origin, CheckOrigin::Preflight);
    assert_eq!(app.crypto_origin, CheckOrigin::Preflight);
    assert_eq!(app.crash.scan_origin, Some(CheckOrigin::Preflight));
    assert!(
        app.preflight_started
            .as_ref()
            .is_some_and(|s| s.origin == CheckOrigin::Preflight)
    );
    // Once per launch: a second call starts nothing.
    app.start_preflight();
    assert_eq!(app.collector_requests.len(), 3);
    // No EXPC session, no other module.
    assert!(matches!(app.state, RunState::Idle));
    assert!(app.sensors_rx.is_none() && app.passport_rx.is_none());
    assert!(app.gpo_rx.is_none() && app.events_rx.is_none() && app.ata_rx.is_none());
    cleanup(&exe);
}

// ---------------- 2. startup without session / report ----------------

#[test]
fn preflight_results_create_no_session_report_or_held_evidence() {
    let (mut app, exe) = app_in("noreport");
    app.start_preflight();
    deliver_audit(&mut app, Ok(audit()));
    deliver_scan(
        &mut app,
        inventory(crash_dump::DebuggerStatus::NotInstalled),
    );
    let (tx, rx) = std::sync::mpsc::channel();
    tx.send(CryptoEvent::Checked(
        cryptopro::Detection::NotInstalled,
        cryptopro::HashState::NotInstalled,
    ))
    .unwrap();
    app.crypto_rx = Some(rx);
    app.poll_crypto();
    let package = report_package::lock(&app.package);
    assert!(package.is_fresh(), "no report / session / ZIP");
    assert!(package.session().is_none());
    assert!(package.final_zip().is_none());
    assert_eq!(
        package.pending_len(),
        0,
        "nothing held back for a later client report"
    );
    drop(package);
    assert!(!exe.join("Reports").exists(), "no report folder");
    cleanup(&exe);
}

// ---------------- 3. auto Driver Audit ----------------

#[test]
fn auto_driver_audit_shows_result_with_origin_and_time() {
    let (mut app, exe) = app_in("autodrv");
    app.start_preflight();
    deliver_audit(&mut app, Ok(audit()));
    assert!(matches!(app.driver_audit, DriverAuditState::Done(_)));
    let stamp = app.driver_checked.clone().expect("checked");
    assert_eq!(stamp.origin, CheckOrigin::Preflight);
    assert_eq!(stamp.at.len(), 19, "{}", stamp.at);
    assert_eq!(app.driver_history.len(), 1);
    let vm = app.build_vm(0.0, 0.0);
    assert!(matches!(vm.drivers, DriversVm::Done { .. }));
    assert!(
        vm.drivers_caption
            .as_deref()
            .is_some_and(|c| c.starts_with(i18n::RU.origin_preflight_short)),
        "{:?}",
        vm.drivers_caption
    );
    assert!(vm.drivers_check_enabled);
    assert!(
        app.journal
            .iter()
            .any(|e| e.message.starts_with(i18n::RU.origin_preflight)),
        "the journal line says it was a preflight check"
    );
    cleanup(&exe);
}

// ---------------- 4. auto CryptoPro: see startup_idle_tests ----------------

#[test]
fn auto_cryptopro_never_rehashes_and_its_check_is_read_only() {
    let (mut app, exe) = app_in("autocrypto");
    app.start_preflight();
    assert!(!app.collector_requests.contains(&"cryptopro_rehash"));
    // The preflight check found NO HASH: ReHash is only offered.
    app.crypto = Some(cryptopro::HashState::NoHash);
    assert!(app.crypto_rx.is_none());
    assert!(!app.crypto_rehash_confirm);
    assert!(!app.collector_requests.contains(&"cryptopro_rehash"));
    // The check itself is cpverify -rv only (source contract).
    let src = include_str!("cryptopro.rs").replace("\r\n", "\n");
    let check = &src[src.find("pub fn check(").unwrap()..];
    let check = &check[..check.find("\n}\n").unwrap()];
    assert!(check.contains("\"-rv\""));
    assert!(!check.contains("\"-rm\""));
    cleanup(&exe);
}

// ---------------- 5. auto WinDbg detection ----------------

#[test]
fn auto_windbg_detection_states() {
    let (mut app, exe) = app_in("windbg");
    let d = &i18n::RU;
    assert_eq!(
        app.crash_vm().debugger,
        d.windbg_unknown,
        "before detection"
    );
    for (status, expected) in [
        (
            crash_dump::DebuggerStatus::Installed {
                cdb: "C:\\cdb.exe".into(),
            },
            d.windbg_backend_ready,
        ),
        (
            crash_dump::DebuggerStatus::PackageOnly {
                package: "Microsoft.WinDbg 1.2506".into(),
            },
            d.windbg_package_only,
        ),
        (crash_dump::DebuggerStatus::NotInstalled, d.windbg_not_found),
        (
            crash_dump::DebuggerStatus::Error("x".into()),
            d.windbg_unknown,
        ),
    ] {
        app.start_crash_scan_as(CheckOrigin::Preflight);
        deliver_scan(&mut app, inventory(status));
        assert_eq!(app.crash_vm().debugger, expected);
    }
    // No install is ever started by the detection.
    assert!(!app.collector_requests.contains(&"windbg_install"));
    assert!(matches!(app.crash.install, InstallState::Idle));
    cleanup(&exe);
}

// ---------------- 6. crash discovery without debugger execution ----------------

#[test]
fn preflight_crash_discovery_never_runs_the_debugger() {
    let (mut app, exe) = app_in("nodebug");
    app.start_preflight();
    deliver_scan(
        &mut app,
        inventory(crash_dump::DebuggerStatus::Installed {
            cdb: "C:\\cdb.exe".into(),
        }),
    );
    assert!(app.crash.analyses.is_empty(), "no !analyze");
    assert!(app.crash.progress.is_none());
    assert_eq!(app.crash.busy, CrashBusy::Idle);
    assert!(app.crash_rx.is_none());
    let checked = app.crash.inventory_checked.clone().unwrap();
    assert_eq!(checked.origin, CheckOrigin::Preflight);
    assert!(
        app.crash_vm()
            .counts
            .contains(i18n::RU.origin_preflight_short)
    );
    // The explicit «Analyze» on a preflight listing scans again for its own
    // session first (never analyzes the preflight listing into a report).
    app.client_name = "Клиент".into();
    app.start_crash_analysis();
    assert!(app.crash_analyze_after_scan);
    assert_eq!(app.crash.scan_origin, Some(CheckOrigin::Manual));
    cleanup(&exe);
}

// ---------------- 7. client identity isolation ----------------

#[test]
fn preflight_results_never_join_the_client_session() {
    let (mut app, exe) = app_in("isolation");
    app.start_preflight();
    // Preflight Driver Audit and crash scan are still running when the
    // user starts the full diagnostic for a client.
    let (dtx, drx) = std::sync::mpsc::channel();
    app.driver_audit = DriverAuditState::Running(drx);
    let (ctx_, crx) = std::sync::mpsc::channel();
    app.crash_rx = Some(crx);
    app.crash.busy = CrashBusy::Scanning;
    app.client_name = "Клиент А".into();
    app.start_diagnostics();
    assert!(app.is_running());
    let session = app.session_identity().expect("full session");
    assert_eq!(session.client, "Клиент А");
    assert!(
        app.crash.rescan_for_session,
        "the session gets its own scan"
    );
    // The preflight Driver Audit was cancelled (the engine audits for the
    // session) — its late result has nowhere to go …
    assert!(matches!(app.driver_audit, DriverAuditState::Idle));
    assert!(dtx.send(Ok(audit())).is_err());
    app.poll_driver_audit();
    // … and the preflight crash listing arrives during the session …
    ctx_.send(CrashMsg::Inventory(Ok(inventory(
        crash_dump::DebuggerStatus::NotInstalled,
    ))))
    .unwrap();
    drop(ctx_);
    let requests = app.collector_requests.len();
    app.poll_crash();
    // … and none of them is evidence of the client session.
    assert_eq!(
        report_package::lock(&app.package).pending_len(),
        0,
        "preflight audit not offered"
    );
    assert!(
        app.crash.inventory_session.is_none(),
        "preflight listing observed by no session"
    );
    assert_eq!(
        app.collector_requests[requests..],
        ["crash_scan"],
        "a fresh SESSION scan follows"
    );
    assert_eq!(app.crash.scan_origin, Some(CheckOrigin::Session));
    let zip = report_package::lock(&app.package).final_zip();
    if let Some(zip) = zip {
        let names: Vec<String> = report_package::read_zip(&zip)
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert!(
            !names.iter().any(|n| n.starts_with("DriverAudit_")),
            "{names:?}"
        );
        assert!(
            !names
                .iter()
                .any(|n| n.starts_with(incidents::EVIDENCE_PREFIX)),
            "{names:?}"
        );
    }
    cleanup(&exe);
}

// ---------------- 8. repeated CryptoPro re-check ----------------

#[test]
fn crypto_recheck_is_fresh_read_only_and_never_parallel() {
    let (mut app, exe) = app_in("recheck");
    app.crypto = Some(cryptopro::HashState::HashOk);
    app.crypto_checked = Some(CheckStamp::now(CheckOrigin::Preflight));
    app.apply(Action::CryptoRecheck);
    assert_eq!(app.collector_requests, ["cryptopro"]);
    assert_eq!(app.crypto_origin, CheckOrigin::Manual);
    assert!(
        app.crypto.is_none(),
        "the previous state is not shown as current"
    );
    assert!(app.crypto_inventory.is_none());
    // While a check runs, ⟳ is disabled and a click starts nothing.
    let (tx, rx) = std::sync::mpsc::channel();
    app.crypto_rx = Some(rx);
    assert!(!app.build_vm(0.0, 0.0).crypto_recheck_enabled);
    app.apply(Action::CryptoRecheck);
    assert_eq!(app.collector_requests.len(), 1, "no parallel check");
    tx.send(CryptoEvent::Checked(
        cryptopro::Detection::NotInstalled,
        cryptopro::HashState::HashOk,
    ))
    .unwrap();
    app.poll_crypto();
    assert_eq!(
        app.crypto_checked.as_ref().map(|s| s.origin),
        Some(CheckOrigin::Manual)
    );
    // Every ⟳ is a new check.
    app.apply(Action::CryptoRecheck);
    assert_eq!(app.collector_requests.len(), 2);
    cleanup(&exe);
}

// ---------------- 9. ReHash explicit confirmation ----------------

#[test]
fn rehash_needs_warning_and_confirmation_and_never_runs_during_a_check() {
    let (mut app, exe) = app_in("rehash");
    app.crypto = Some(cryptopro::HashState::NoHash);
    // A check is running: no ReHash, not even the confirmation.
    let (_tx, rx) = std::sync::mpsc::channel();
    app.crypto_rx = Some(rx);
    app.apply(Action::CryptoRehashRequest);
    assert!(!app.crypto_rehash_confirm);
    app.crypto_rx = None;
    // Request → warning only.
    app.apply(Action::CryptoRehashRequest);
    assert!(app.crypto_rehash_confirm);
    assert!(!app.collector_requests.contains(&"cryptopro_rehash"));
    // Cancel → nothing ran.
    app.apply(Action::CryptoRehashCancelled);
    assert!(!app.crypto_rehash_confirm);
    assert!(app.crypto_rx.is_none());
    // Confirm → ReHash starts (and its result is re-verified by rehash()).
    app.apply(Action::CryptoRehashRequest);
    app.apply(Action::CryptoRehashConfirmed);
    assert!(app.collector_requests.contains(&"cryptopro_rehash"));
    assert!(app.crypto_rx.is_some());
    let src = include_str!("cryptopro.rs").replace("\r\n", "\n");
    let rehash = &src[src.find("pub fn rehash(").unwrap()..];
    let rehash = &rehash[..rehash.find("\n}\n").unwrap()];
    assert!(
        rehash.find("\"-rm\"").unwrap() < rehash.rfind("check(det, runner)").unwrap(),
        "verified again (cpverify -rv) after ReHash"
    );
    // The Details window shows the warning text.
    let ctx = egui::Context::default();
    crate::ui::fonts::install(&ctx);
    app.crypto_rx = None;
    app.crypto = Some(cryptopro::HashState::NoHash);
    app.crypto_rehash_confirm = true;
    app.crypto_details_open = true;
    let mut texts = Vec::new();
    for _ in 0..3 {
        texts = shown_texts(&ctx, |ui| app.crypto_details_window(ui.ctx()));
    }
    assert!(
        texts.iter().any(|t| t.contains("ИЗМЕНЯЕТ СИСТЕМУ")),
        "{texts:?}"
    );
    assert!(
        texts
            .iter()
            .any(|t| t == i18n::RU.crypto_rehash_confirm_yes)
    );
    cleanup(&exe);
}

// ---------------- 10. Driver Audit manual re-check ----------------

#[test]
fn driver_manual_recheck_replaces_on_success_and_keeps_on_failure() {
    let (mut app, exe) = app_in("drvrecheck");
    deliver_audit(&mut app, Ok(audit()));
    app.client_name = "Клиент".into();
    app.apply(Action::CheckDrivers);
    assert_eq!(app.collector_requests, ["driver_audit"]);
    assert_eq!(app.driver_origin, CheckOrigin::Manual);
    // Only this module: no EXPC session, no other collector.
    assert!(matches!(app.state, RunState::Idle));
    // A failed re-check keeps the last good result.
    let Some(prev) = (match std::mem::replace(&mut app.driver_audit, DriverAuditState::Idle) {
        DriverAuditState::Done(r) => Some(r),
        _ => None,
    }) else {
        panic!("done")
    };
    app.driver_previous = Some(prev);
    deliver_audit(&mut app, Err("timeout".into()));
    assert!(matches!(app.driver_audit, DriverAuditState::Done(_)));
    assert!(
        app.driver_history
            .last()
            .is_some_and(|e| e.outcome.contains("timeout"))
    );
    // A successful re-check replaces it.
    deliver_audit(&mut app, Ok(audit()));
    assert!(app.driver_previous.is_none());
    assert_eq!(app.driver_history.len(), 3);
    // Running: «Проверка» disabled, a click starts nothing.
    let (_tx, rx) = std::sync::mpsc::channel();
    app.driver_audit = DriverAuditState::Running(rx);
    assert!(!app.build_vm(0.0, 0.0).drivers_check_enabled);
    let before = app.collector_requests.len();
    app.apply(Action::CheckDrivers);
    assert_eq!(app.collector_requests.len(), before, "no parallel scan");
    cleanup(&exe);
}

#[test]
fn driver_history_clear_needs_confirmation_and_touches_nothing_else() {
    let (mut app, exe) = app_in("drvclear");
    deliver_audit(&mut app, Ok(audit()));
    deliver_audit(&mut app, Ok(audit()));
    let ctx = egui::Context::default();
    app.apply_history_act(&ctx, v11::HistoryAct::ClearRequest);
    assert!(app.driver_history_clear_confirm);
    assert_eq!(app.driver_history.len(), 2, "not before confirmation");
    app.apply_history_act(&ctx, v11::HistoryAct::ClearCancelled);
    assert_eq!(app.driver_history.len(), 2);
    app.apply_history_act(&ctx, v11::HistoryAct::ClearRequest);
    app.apply_history_act(&ctx, v11::HistoryAct::ClearConfirmed);
    assert!(app.driver_history.is_empty());
    // The audit result and the session journal stay.
    assert!(matches!(app.driver_audit, DriverAuditState::Done(_)));
    assert!(app.journal.len() >= 2);
    // Save = the CURRENT Driver Audit report only (Save As / logs dir).
    app.apply_history_act(&ctx, v11::HistoryAct::SaveReport);
    match &app.driver_export_status {
        Some(ExportStatus::Saved(p)) => {
            let text = std::fs::read_to_string(p).unwrap();
            assert!(text.contains(&driver_audit::to_text(&audit())[..40]));
        }
        other => panic!("{other:?}"),
    }
    cleanup(&exe);
}

// ---------------- 11. cancel / close during background checks ----------------

#[test]
fn closing_the_app_cancels_background_processes() {
    let (mut app, exe) = app_in("close");
    let cancel = Arc::new(AtomicBool::new(false));
    app.session_cancel = Some(Arc::clone(&cancel));
    app.crash.rescan_for_session = true;
    app.crypto_recheck_for_session = true;
    app.crash_analyze_after_scan = true;
    let flag = AtomicBool::new(false);
    app.shutdown(&flag);
    assert!(flag.load(Ordering::SeqCst));
    assert!(
        cancel.load(Ordering::SeqCst),
        "the running diagnostic stops"
    );
    assert!(!app.crash.rescan_for_session && !app.crypto_recheck_for_session);
    assert!(!app.crash_analyze_after_scan, "nothing new starts");
    // A waiting collector ends its process tree on the shutdown flag.
    #[cfg(windows)]
    {
        let mut cmd = std::process::Command::new("ping");
        cmd.args(["-n", "30", "127.0.0.1"])
            .stdout(std::process::Stdio::null());
        let mut guard = engine::ProcessGuard::spawn(cmd).unwrap();
        let never = AtomicBool::new(false);
        let t0 = Instant::now();
        let r = guard.wait_or_cancel_with(&never, &flag, Some(Duration::from_secs(60)));
        assert!(matches!(r, Err(engine::WaitEnd::Cancelled)));
        assert!(t0.elapsed() < Duration::from_secs(10));
    }
    // The real app close calls it with the global flag.
    let src = include_str!("app.rs").replace("\r\n", "\n");
    assert!(src.contains("    fn on_exit(&mut self) {\n        self.shutdown(&engine::SHUTDOWN);"));
    let lib = include_str!("lib.rs").replace("\r\n", "\n");
    assert!(lib.contains("    fn on_exit(&mut self) {\n        self.inner.on_exit();"));
    cleanup(&exe);
}

// ---------------- 12. concurrent action rejection ----------------

#[test]
fn concurrent_actions_are_rejected() {
    let (mut app, exe) = app_in("concurrent");
    // Crash scan already running: a second scan claims / starts nothing.
    let (_tx, rx) = std::sync::mpsc::channel();
    app.crash_rx = Some(rx);
    app.crash.scan_origin = Some(CheckOrigin::Manual);
    app.start_crash_scan_as(CheckOrigin::Manual);
    assert!(app.op_packages.get("crash").is_none());
    assert_eq!(app.crash.scan_origin, Some(CheckOrigin::Manual));
    // Analysis while scanning: rejected.
    app.crash.busy = CrashBusy::Scanning;
    app.start_crash_analysis();
    assert!(!app.crash_analyze_after_scan);
    // Passport refresh while a collection runs: journaled, not started.
    let (_htx, hrx) = std::sync::mpsc::channel();
    app.hardware = HardwareViewState::Collecting {
        rx: hrx,
        started: Instant::now(),
        saving: false,
    };
    let before = app.collector_requests.len();
    app.start_hardware_view();
    assert_eq!(app.collector_requests.len(), before);
    cleanup(&exe);
}

// ---------------- 13. Hardware Passport single-page layout ----------------

fn shown_texts(ctx: &egui::Context, mut f: impl FnMut(&mut egui::Ui)) -> Vec<String> {
    fn walk(shape: &egui::Shape, acc: &mut Vec<String>) {
        match shape {
            egui::Shape::Text(t) => acc.push(t.galley.text().to_string()),
            egui::Shape::Vec(v) => v.iter().for_each(|s| walk(s, acc)),
            _ => {}
        }
    }
    let input = egui::RawInput {
        screen_rect: Some(Rect::from_min_size(egui::Pos2::ZERO, vec2(1400.0, 1200.0))),
        ..Default::default()
    };
    let mut out = ctx.run_ui(input, |ui| f(ui));
    out.textures_delta.clear();
    let mut acc = Vec::new();
    for c in &out.shapes {
        walk(&c.shape, &mut acc);
    }
    acc
}

#[test]
fn hardware_passport_is_one_page_with_all_cards_and_a_fixed_footer() {
    for (lang, d) in [(Language::Ru, &i18n::RU), (Language::En, &i18n::EN)] {
        let (mut app, exe) = app_in("passport");
        app.language = lang;
        app.apply_hardware_event(engine::HardwareEvent::Passport(
            crate::passport2::QA_PASSPORT_JSON.to_string(),
        ));
        assert!(app.passport2_open);
        let ctx = egui::Context::default();
        crate::ui::fonts::install(&ctx);
        let mut texts = Vec::new();
        for _ in 0..3 {
            texts = shown_texts(&ctx, |ui| app.passport2_window(ui.ctx()));
        }
        for title in [
            d.pp_cpu,
            d.pp_ram,
            d.pp_board,
            d.pp_bios,
            d.pp_storage,
            d.pp_gpu,
        ] {
            assert!(texts.iter().any(|t| t == title), "{lang:?}: {title}");
        }
        for button in [d.pp_refresh, d.pp_copy, d.pp_save, d.pp_close] {
            assert!(texts.iter().any(|t| t == button), "{lang:?}: {button}");
        }
        // No tab navigation and no universal verdict.
        for gone in ["Обзор", "Raw JSON", "ОБЩИЙ СТАТУС", "Overview"] {
            assert!(!texts.iter().any(|t| t == gone), "{gone}");
        }
        assert!(texts.iter().any(|t| t == d.pp_legend_measured));
        cleanup(&exe);
    }
}

#[test]
fn hardware_passport_copy_save_and_close() {
    let (mut app, exe) = app_in("ppexport");
    app.passport2_json = Some(crate::passport2::QA_PASSPORT_JSON.to_string());
    app.passport2_open = true;
    let view = app.passport2_view().unwrap();
    let text = crate::passport2::summary_text(&view, &i18n::RU);
    assert!(text.contains("Intel(R) Core(TM) Ultra 7 270K Plus"));
    let ctx = egui::Context::default();
    app.passport2_status =
        Some(app.export_text(&ctx, ExportAction::Save, "HardwarePassport", &text));
    match &app.passport2_status {
        Some(ExportStatus::Saved(p)) => {
            assert!(std::fs::read_to_string(p).unwrap().contains("[Процессор]"))
        }
        other => panic!("{other:?}"),
    }
    cleanup(&exe);
}

// ---------------- 14. crash parser field consistency ----------------

#[test]
fn crash_fields_are_filled_from_raw_and_process_name_is_never_cut() {
    let raw = "BUGCHECK_CODE:  139\n0: kd> MODULE_NAME: RvNetMP60\n3: kd> IMAGE_NAME:  RvNetMP60.sys\nPROCESS_NAME:  RvControlSvc.e\nImage path: C:\\Program Files\\Famatech\\Radmin VPN\\RvControlSvc.exe\n";
    let p = crash_dump::parse_analyze_output(raw);
    assert_eq!(p.module_name.as_deref(), Some("RvNetMP60"));
    assert_eq!(p.image_name.as_deref(), Some("RvNetMP60.sys"));
    assert_eq!(p.process_name.as_deref(), Some("RvControlSvc.exe"));
    assert!(!p.process_name_truncated);
    // Only the debugger's short form: kept as printed, flagged.
    let p = crash_dump::parse_analyze_output("PROCESS_NAME:  RvControlSvc.e\n");
    assert_eq!(p.process_name.as_deref(), Some("RvControlSvc.e"));
    assert!(p.process_name_truncated);
    // A full name stays untouched (the parser never shortens).
    let p = crash_dump::parse_analyze_output("PROCESS_NAME:  VeryLongProcessName.exe\n");
    assert_eq!(p.process_name.as_deref(), Some("VeryLongProcessName.exe"));
    assert!(!p.process_name_truncated);
    // Not a key inside another identifier.
    let p = crash_dump::parse_analyze_output("XMODULE_NAME: nope\n");
    assert_eq!(p.module_name, None);
}

#[test]
fn natvis_noise_is_hidden_from_the_main_view_but_kept_raw() {
    let raw = "start\nNatVis script unloaded from 'C:\\x\\atlmfc.natvis'\nImage path: x\n----> Repository : UserExtensions, Enabled: true\nend";
    let clean = crash_dump::without_debugger_noise(raw);
    assert!(!clean.contains("NatVis"));
    assert!(!clean.contains("Repository"));
    assert!(clean.contains("Image path: x"));
    assert!(raw.contains("NatVis"), "raw untouched");
}

#[test]
fn statuses_are_localized_with_canonical_ids() {
    assert_eq!(
        crash_dump::Confidence::Medium.label(true),
        "средняя (MEDIUM)"
    );
    assert_eq!(
        crash_dump::Confidence::Medium.label(false),
        "medium (MEDIUM)"
    );
    assert_eq!(crash_dump::Confidence::Medium.code(), "MEDIUM");
    let v = incidents::Verdict {
        hang_confirmed: false,
        bsod_registered: true,
        subsystem: None,
        confidence: incidents::Confidence::Low,
        signals: Vec::new(),
        dump_cause: None,
    };
    let ru = v.headline_localized(true);
    assert!(
        ru.contains("зависание не подтверждено (HANG NOT CONFIRMED)"),
        "{ru}"
    );
    assert!(ru.contains("(BSOD REGISTERED)"));
    assert!(
        v.headline().starts_with("HANG NOT CONFIRMED"),
        "canonical kept"
    );
    // The crash card / details show the localized forms.
    let (mut app, exe) = app_in("crashloc");
    app.crash.inventory = Some(Ok(qa_scenes::qa_inventory()));
    app.crash.analyses = vec![qa_scenes::qa_analysis()];
    let vm = app.crash_vm();
    assert!(
        vm.rows.iter().any(|r| r.value == "средняя (MEDIUM)"),
        "{:?}",
        vm.rows
    );
    assert!(vm.headline.contains("средняя (MEDIUM)"));
    // 0x139 → RvNetMP60.sys → Radmin VPN → MEDIUM stays.
    let a = &app.crash.analyses[0];
    assert_eq!(a.confidence, crash_dump::Confidence::Medium);
    assert_eq!(a.probable_module().as_deref(), Some("RvNetMP60.sys"));
    // Evidence keeps the canonical identifier.
    let ev = crash_dump::summary_json(a, None, "analysis.txt");
    let v = json::parse(&ev).unwrap();
    assert_eq!(v.get("confidence").and_then(|x| x.as_str()), Some("MEDIUM"));
    cleanup(&exe);
}

// ---------------- 15. RU / EN / DPI ----------------

#[test]
fn v11_texts_exist_in_both_languages() {
    let pairs = [
        (i18n::RU.origin_preflight, i18n::EN.origin_preflight),
        (i18n::RU.crypto_details_title, i18n::EN.crypto_details_title),
        (
            i18n::RU.crypto_rehash_warning,
            i18n::EN.crypto_rehash_warning,
        ),
        (i18n::RU.driver_check_button, i18n::EN.driver_check_button),
        (i18n::RU.driver_history_clear, i18n::EN.driver_history_clear),
        (i18n::RU.pp_title, i18n::EN.pp_title),
        (i18n::RU.pp_unconfirmed_title, i18n::EN.pp_unconfirmed_title),
        (i18n::RU.windbg_backend_ready, i18n::EN.windbg_backend_ready),
    ];
    for (ru, en) in pairs {
        assert!(!ru.is_empty() && !en.is_empty());
        assert_ne!(ru, en);
        assert!(
            !en.chars().any(|c| ('\u{0400}'..='\u{04FF}').contains(&c)),
            "{en}"
        );
    }
}

#[test]
fn passport_layout_follows_the_window_width_and_dpi() {
    let view = crate::passport2::build(
        crate::passport2::QA_PASSPORT_JSON,
        &crate::passport2::Texts {
            ru: true,
            d: &i18n::RU,
        },
    )
    .unwrap();
    // Card titles' left edges: one column narrow (or at 150 % DPI on the
    // same physical width), two columns wide.
    let xs = |width: f32, ppp: f32| {
        let ctx = egui::Context::default();
        crate::ui::fonts::install(&ctx);
        ctx.set_pixels_per_point(ppp);
        let mut xs: Vec<f32> = Vec::new();
        for _ in 0..3 {
            let input = egui::RawInput {
                screen_rect: Some(Rect::from_min_size(egui::Pos2::ZERO, vec2(width, 2400.0))),
                ..Default::default()
            };
            let mut out = ctx.run_ui(input, |ui| v11::passport_body(ui, &i18n::RU, &view));
            out.textures_delta.clear();
            xs.clear();
            for c in &out.shapes {
                if let egui::Shape::Text(t) = &c.shape
                    && (t.galley.text() == i18n::RU.pp_cpu || t.galley.text() == i18n::RU.pp_ram)
                {
                    xs.push(c.shape.visual_bounding_rect().min.x);
                }
            }
        }
        xs
    };
    let wide = xs(1100.0, 1.0);
    assert_eq!(wide.len(), 2);
    assert!((wide[0] - wide[1]).abs() > 100.0, "two columns: {wide:?}");
    let narrow = xs(700.0, 1.0);
    assert_eq!(narrow.len(), 2);
    assert!(
        (narrow[0] - narrow[1]).abs() < 20.0,
        "one column: {narrow:?}"
    );
    // 1100 physical px at 150 % = 733 points: one column, nothing lost.
    let dpi = xs(1100.0 / 1.5, 1.5);
    assert!((dpi[0] - dpi[1]).abs() < 20.0, "{dpi:?}");
}

#[test]
fn dashboard_crypto_and_driver_headers_fit_at_100_125_150() {
    for scale in [1.0_f32, 1.25, 1.5] {
        for lang in [Language::Ru, Language::En] {
            let ctx = egui::Context::default();
            crate::ui::fonts::install(&ctx);
            ctx.set_pixels_per_point(scale);
            let vm = crate::ui::fixture::master_vm_in(lang);
            let d = i18n::t(lang);
            let mut boxes: Vec<(String, Rect)> = Vec::new();
            for _ in 0..3 {
                let input = egui::RawInput {
                    screen_rect: Some(Rect::from_min_size(
                        egui::Pos2::ZERO,
                        vec2(
                            crate::ui::tokens::CANVAS_W / scale,
                            crate::ui::tokens::CANVAS_H / scale,
                        ),
                    )),
                    ..Default::default()
                };
                let mut client = String::new();
                let mut mode = engine::DiagnosticMode::Standard;
                let mut deep = engine::DeepChecks::default();
                let mut hw = true;
                let mut path = String::new();
                let mut out = ctx.run_ui(input, |ui| {
                    let mut controls = Controls {
                        client_name: &mut client,
                        mode: &mut mode,
                        deep_checks: &mut deep,
                        include_hardware: &mut hw,
                        benchmark_path: &mut path,
                    };
                    let mut actions = Vec::new();
                    dashboard::draw(ui, egui::pos2(0.0, 0.0), &vm, &mut controls, &mut actions);
                });
                out.textures_delta.clear();
                boxes.clear();
                for c in &out.shapes {
                    if let egui::Shape::Text(t) = &c.shape {
                        boxes.push((t.galley.text().to_string(), c.shape.visual_bounding_rect()));
                    }
                }
            }
            let find = |s: &str| boxes.iter().find(|(t, _)| t == s).map(|(_, r)| *r);
            let title = find(d.driver_title).expect("driver title");
            let check = find(d.driver_check_button).expect("check button");
            assert!(
                title.max.x < check.min.x,
                "{lang:?} {scale}: title {title:?} overlaps «{}» {check:?}",
                d.driver_check_button
            );
            let name = find("CryptoPro").expect("name");
            assert!(
                name.max.x
                    <= crate::ui::tokens::layout::CRYPTO_RECHECK_CENTER[0]
                        - crate::ui::tokens::layout::CRYPTO_RECHECK_D / 2.0
                        + 1.0,
                "{lang:?} {scale}: CryptoPro name runs into ⟳"
            );
        }
    }
}

// ---------------- PR #4 review round 1 regressions ----------------

/// P1: preflight results are display-only — the manifest states and the
/// crash-dump correlation of a client report never use them.
#[test]
fn preflight_results_never_feed_report_states_or_correlation() {
    let (mut app, exe) = app_in("derived");
    app.start_preflight();
    let mut bad = audit();
    bad.overall = Severity::Problem;
    deliver_audit(&mut app, Ok(bad));
    let mut inv = inventory(crash_dump::DebuggerStatus::NotInstalled);
    inv.bugchecks = vec![crash_dump::BugcheckEvent {
        time: "2026-10-03T00:35:00".into(),
        code: 0x139,
        params: Vec::new(),
        dump_path: None,
        source: crash_dump::BugcheckSource::Wer1001,
    }];
    app.start_crash_scan_as(CheckOrigin::Preflight);
    deliver_scan(&mut app, inv.clone());
    // Shown on the cards …
    assert!(app.audit_report().is_some());
    assert!(matches!(app.crash.inventory, Some(Ok(_))));
    // … but never a report's state or correlation input.
    assert!(app.report_audit().is_none());
    assert!(app.report_inventory().is_none());
    assert_eq!(app.state_codes().0, "NO_DATA");
    // The same data from a SESSION / manual run is used.
    app.start_crash_scan_as(CheckOrigin::Manual);
    deliver_scan(&mut app, inv);
    app.driver_origin = CheckOrigin::Manual;
    let mut bad = audit();
    bad.overall = Severity::Problem;
    deliver_audit(&mut app, Ok(bad));
    assert!(app.report_audit().is_some());
    assert_eq!(app.state_codes().0, "ATTENTION_BSOD");
    cleanup(&exe);
}

/// P1: a full diagnostic cancels a running app-side audit (its process
/// tree ends) — the engine's audit is the only one; no manual audit can
/// start during the session.
#[test]
fn start_diagnostics_cancels_the_running_preflight_audit() {
    let (mut app, exe) = app_in("drvcancel");
    app.start_preflight();
    let (tx, rx) = std::sync::mpsc::channel::<Result<AuditReport, String>>();
    app.driver_audit = DriverAuditState::Running(rx);
    let cancel = app.new_driver_cancel();
    app.client_name = "Клиент".into();
    app.start_diagnostics();
    assert!(cancel.load(Ordering::SeqCst), "process tree ends");
    assert!(matches!(app.driver_audit, DriverAuditState::Idle));
    assert!(
        app.journal
            .iter()
            .any(|e| e.message == i18n::RU.driver_cancelled_for_session)
    );
    drop(tx);
    // During the session «Проверка» is disabled and starts nothing.
    assert!(!app.build_vm(0.0, 0.0).drivers_check_enabled);
    let before = app.collector_requests.len();
    app.apply(Action::CheckDrivers);
    assert_eq!(app.collector_requests.len(), before);
    cleanup(&exe);
}

/// P2: whatever CryptoPro operation runs when a diagnostic starts (⟳ or a
/// ReHash), the session gets its own fresh check right after it.
#[test]
fn session_gets_its_own_crypto_check_after_a_manual_check_or_rehash() {
    for rehash in [false, true] {
        let (mut app, exe) = app_in("cryptosession");
        let (tx, rx) = std::sync::mpsc::channel();
        app.crypto_rx = Some(rx);
        app.crypto_origin = CheckOrigin::Manual;
        app.client_name = "Клиент".into();
        app.start_diagnostics();
        assert!(app.crypto_recheck_for_session, "rehash={rehash}");
        let before = app.collector_requests.len();
        if rehash {
            tx.send(CryptoEvent::Rehashed(cryptopro::RehashOutcome {
                state: cryptopro::HashState::HashOk,
                journal: vec!["[PASS] ReHash".into()],
            }))
            .unwrap();
        } else {
            tx.send(CryptoEvent::Checked(
                cryptopro::Detection::NotInstalled,
                cryptopro::HashState::HashOk,
            ))
            .unwrap();
        }
        app.poll_crypto();
        assert_eq!(app.collector_requests[before..], ["cryptopro"]);
        assert_eq!(app.crypto_origin, CheckOrigin::Session);
        assert!(!app.crypto_recheck_for_session);
        cleanup(&exe);
    }
}

/// P2: a failed attempt never re-stamps the result that stays shown.
#[test]
fn failed_audit_keeps_the_time_and_origin_of_the_shown_result() {
    let (mut app, exe) = app_in("drvstamp");
    app.start_preflight();
    deliver_audit(&mut app, Ok(audit()));
    let shown = app.driver_checked.clone().unwrap();
    assert_eq!(shown.origin, CheckOrigin::Preflight);
    // Engine audit of a session fails: the preflight result stays, with
    // its own stamp; the failure is in the history.
    app.client_name = "Клиент".into();
    app.start_diagnostics();
    let (tx, rx) = std::sync::mpsc::channel();
    tx.send(engine::EngineEvent::DriverAudit(Err(
        "collector failed".into()
    )))
    .unwrap();
    if let RunState::Running { rx: run_rx, .. } = &mut app.state {
        *run_rx = rx;
    }
    app.poll_engine();
    assert!(matches!(app.driver_audit, DriverAuditState::Done(_)));
    assert_eq!(app.driver_checked.as_ref(), Some(&shown));
    assert!(app.driver_history.last().is_some_and(
        |e| e.outcome.contains("collector failed") && e.stamp.origin == CheckOrigin::Session
    ));
    cleanup(&exe);
}
