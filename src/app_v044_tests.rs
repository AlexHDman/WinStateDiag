//! v0.4.4: two-page navigation, page-state preservation and the app-level
//! Crash Dump flow (analysis → evidence → manifest, original dump intact).
//! Child module of `app` (private items are visible through `super::*`).

use super::*;
use crate::ui::tokens::{CANVAS_ORIGIN_IN_MASTER, layout as l};

fn app_in(tag: &str) -> (WinStateDiagApp, PathBuf) {
    let exe = std::env::temp_dir()
        .join(format!("wsd-v044-{tag}-{}", std::process::id()))
        .join("WinStateDiag");
    let _ = std::fs::remove_dir_all(exe.parent().unwrap());
    std::fs::create_dir_all(&exe).unwrap();
    let mut app = WinStateDiagApp::default();
    app.reports_root = exe.join("Reports");
    app.language_pref_dir = exe.clone();
    app.language = Language::Ru;
    app.package = Arc::new(Mutex::new(SessionPackage::new(exe.join("Reports"), None)));
    app.driver_audit = DriverAuditState::Done(Box::new(details::tests::report()));
    (app, exe)
}

/// Renders one dashboard frame; returns (visible texts, actions).
fn frame(
    app: &mut WinStateDiagApp,
    ctx: &egui::Context,
    events: Vec<egui::Event>,
) -> (Vec<String>, Vec<Action>) {
    let vm = app.build_vm(0.0, 0.0);
    let mut actions = Vec::new();
    let (mut client, mut mode, mut deep, mut hw, mut bench) = (
        app.client_name.clone(),
        app.mode,
        app.deep_checks,
        app.include_hardware,
        app.benchmark_path.clone(),
    );
    let input = egui::RawInput {
        screen_rect: Some(Rect::from_min_size(egui::Pos2::ZERO, vec2(1400.0, 1200.0))),
        events,
        ..Default::default()
    };
    let mut out = ctx.run_ui(input, |ui| {
        let mut controls = Controls {
            client_name: &mut client,
            mode: &mut mode,
            deep_checks: &mut deep,
            include_hardware: &mut hw,
            benchmark_path: &mut bench,
        };
        dashboard::draw(ui, egui::Pos2::ZERO, &vm, &mut controls, &mut actions);
    });
    out.textures_delta.clear();
    let mut texts = Vec::new();
    for shape in &out.shapes {
        collect_texts(&shape.shape, &mut texts);
    }
    (texts, actions)
}

fn collect_texts(shape: &egui::Shape, out: &mut Vec<String>) {
    match shape {
        egui::Shape::Text(t) => out.push(t.galley.text().to_string()),
        egui::Shape::Vec(v) => v.iter().for_each(|s| collect_texts(s, out)),
        _ => {}
    }
}

/// Click on a BODY token (cards are drawn `BODY_SHIFT` lower since v1.0).
#[allow(dead_code)]
fn click_events(b: [f32; 4]) -> Vec<Vec<egui::Event>> {
    click_at(egui::pos2(
        b[0] - CANVAS_ORIGIN_IN_MASTER[0] + b[2] / 2.0,
        b[1] - CANVAS_ORIGIN_IN_MASTER[1] + b[3] / 2.0 + l::BODY_SHIFT,
    ))
}

/// Click on one of the compact page tabs (header, text-width geometry).
fn tab_events(page: Page, d: &i18n::Dict) -> Vec<Vec<egui::Event>> {
    let rects = crate::ui::pages::page_tab_rects(egui::Pos2::ZERO, d);
    click_at(match page {
        Page::Diagnostics => rects[0].center(),
        Page::Hardware => rects[1].center(),
    })
}

fn click_at(at: egui::Pos2) -> Vec<Vec<egui::Event>> {
    let press = |pressed| egui::Event::PointerButton {
        pos: at,
        button: egui::PointerButton::Primary,
        pressed,
        modifiers: Default::default(),
    };
    vec![
        vec![egui::Event::PointerMoved(at)],
        vec![press(true)],
        vec![press(false)],
    ]
}

fn no_debugger_inventory() -> crash_dump::Inventory {
    crash_dump::Inventory {
        bugchecks: Vec::new(),
        dumps: Vec::new(),
        debugger: crash_dump::DebuggerStatus::NotInstalled,
        notes: Vec::new(),
        unexpected_shutdowns: 0,
        incidents: Vec::new(),
        live_kernel_reports: Vec::new(),
    }
}

#[test]
fn page_tabs_switch_between_diagnostics_and_hardware() {
    for (lang, d) in [(Language::Ru, &i18n::RU), (Language::En, &i18n::EN)] {
        let (mut app, exe) = app_in(&format!("nav{lang:?}"));
        app.language = lang;
        let ctx = egui::Context::default();
        fonts::install(&ctx);
        frame(&mut app, &ctx, vec![]);
        assert_eq!(app.page, Page::Diagnostics, "default page");
        let (texts, _) = frame(&mut app, &ctx, vec![]);
        // Both tabs always visible (common header).
        assert!(texts.iter().any(|t| t == d.page_diagnostics), "{lang:?}");
        assert!(texts.iter().any(|t| t == d.page_hardware), "{lang:?}");
        // Diagnostics page: stage table + passport with the thin GPO row,
        // the compact report row; no crash / power cards.
        assert!(texts.iter().any(|t| t == d.stages_table_title));
        assert!(texts.iter().any(|t| t == d.passport_title));
        assert!(texts.iter().any(|t| t == d.gpo_row_label));
        // v1.0: report actions live in the journal header; the idle
        // "Диагностика не выполнялась" block is gone.
        assert!(texts.iter().any(|t| t == d.journal_report_button));
        assert!(!texts.iter().any(|t| t == d.result_idle));
        // GPO / ADMX is a very small secondary card (title + one line).
        assert!(l::GPO_COMPACT_CARD[3] <= 60.0);
        // v1.0: no large RESULT card on either page.
        assert!(!texts.iter().any(|t| t == d.result_title));
        assert!(!texts.iter().any(|t| t == d.crash_title));
        assert!(!texts.iter().any(|t| t == d.sensors_title));

        let mut all = Vec::new();
        for ev in tab_events(Page::Hardware, d) {
            all.extend(frame(&mut app, &ctx, ev).1);
        }
        assert!(
            all.iter()
                .any(|a| matches!(a, Action::SetPage(Page::Hardware))),
            "{all:?}"
        );
        for a in all {
            app.apply(a);
        }
        assert_eq!(app.page, Page::Hardware);
        let (texts, _) = frame(&mut app, &ctx, vec![]);
        // Hardware page: crash + power, no EXPC stage table.
        assert!(texts.iter().any(|t| t == d.crash_title));
        assert!(texts.iter().any(|t| t == d.sensors_title));
        assert!(!texts.iter().any(|t| t == d.stages_table_title));

        let mut all = Vec::new();
        for ev in tab_events(Page::Diagnostics, d) {
            all.extend(frame(&mut app, &ctx, ev).1);
        }
        for a in all {
            app.apply(a);
        }
        assert_eq!(app.page, Page::Diagnostics);
        let _ = std::fs::remove_dir_all(exe.parent().unwrap());
    }
}

#[test]
fn switching_pages_preserves_every_module_state() {
    let (mut app, exe) = app_in("keep");
    app.client_name = "Client-1".into();
    app.ssd_selected = 1;
    app.crash.inventory = Some(Ok(no_debugger_inventory()));
    push_journal(&mut app.journal, "line".into());
    let snapshot = |app: &WinStateDiagApp| {
        (
            app.client_name.clone(),
            app.ssd_selected,
            app.crash.inventory.clone(),
            app.journal.len(),
            matches!(app.driver_audit, DriverAuditState::Done(_)),
        )
    };
    let before = snapshot(&app);
    for p in [Page::Hardware, Page::Diagnostics, Page::Hardware] {
        app.apply(Action::SetPage(p));
        assert_eq!(before, snapshot(&app));
        assert_eq!(app.build_vm(0.0, 0.0).page, p);
    }
    let _ = std::fs::remove_dir_all(exe.parent().unwrap());
}

#[test]
fn crash_analysis_preserves_the_original_dump_and_lands_in_the_report() {
    let (mut app, exe) = app_in("crash");
    let dump_dir = exe.join("Minidump");
    std::fs::create_dir_all(&dump_dir).unwrap();
    let dump_path = dump_dir.join("100426-12345-01.dmp");
    let original = b"PAGEDU64 fake minidump bytes".to_vec();
    std::fs::write(&dump_path, &original).unwrap();
    let dmp = crash_dump::DumpFile {
        path: dump_path.display().to_string(),
        name: "100426-12345-01.dmp".into(),
        size: original.len() as u64,
        modified: "2026-10-04T10:00:00".into(),
        kind: crash_dump::DumpKind::Mini,
    };
    app.crash.inventory = Some(Ok(crash_dump::Inventory {
        bugchecks: Vec::new(),
        dumps: vec![dmp.clone()],
        debugger: crash_dump::DebuggerStatus::Installed {
            cdb: "C:\\dbg\\cdb.exe".into(),
        },
        notes: Vec::new(),
        unexpected_shutdowns: 0,
        incidents: Vec::new(),
        live_kernel_reports: Vec::new(),
    }));
    app.accept_crash_msg(CrashMsg::Analyzed(vec![AnalyzedDump {
        dump: dmp,
        bugcheck: None,
        status: crash_dump::AnalysisStatus::Completed,
        raw: crash_dump::tests::NVIDIA_ANALYZE.to_string(),
        bytes: Some(std::fs::read(&dump_path).unwrap()),
        module_info: None,
        resolution: None,
    }]));
    // Original dump untouched (read only).
    assert_eq!(std::fs::read(&dump_path).unwrap(), original);
    assert_eq!(app.crash.analyses.len(), 1);
    let zip = report_package::lock(&app.package).final_zip().expect("zip");
    let files = report_package::read_zip(&zip).unwrap();
    let names: Vec<&str> = files.iter().map(|f| f.name.as_str()).collect();
    assert!(
        names
            .iter()
            .any(|n| n.starts_with("CrashDump_Analysis_") && n.ends_with(".txt")),
        "{names:?}"
    );
    assert!(
        names
            .iter()
            .any(|n| n.starts_with("CrashDump_Summary_") && n.ends_with(".json")),
        "{names:?}"
    );
    let copy = files
        .iter()
        .find(|f| f.name.ends_with(".dmp"))
        .expect("original dump copied into the report");
    assert_eq!(copy.bytes, original);
    let manifest = files
        .iter()
        .find(|f| f.name == crate::manifest::MANIFEST_FILE)
        .expect("manifest");
    let text = String::from_utf8_lossy(&manifest.bytes);
    assert!(text.contains("crash_dump_analysis"), "{text}");
    // Card shows the probable module; never ntoskrnl alone.
    let vm = app.crash_vm();
    assert!(vm.has_details);
    assert!(!vm.rows.iter().any(|r| r.value.trim() == "ntoskrnl.exe"));
    let _ = std::fs::remove_dir_all(exe.parent().unwrap());
}

#[test]
fn analyze_without_debugger_does_nothing_and_install_is_explicit() {
    let (mut app, exe) = app_in("nodbg");
    app.crash.inventory = Some(Ok(no_debugger_inventory()));
    app.apply(Action::AnalyzeDumps);
    assert!(app.crash_rx.is_none());
    assert_eq!(app.crash.busy, CrashBusy::Idle);
    let vm = app.crash_vm();
    assert!(vm.debugger_missing && !vm.can_analyze);
    // v1.0: nothing is installed until the explicit click; the click starts
    // the embedded (hidden, observed) install — no blind re-scan loop.
    assert_eq!(app.crash.install, InstallState::Idle);
    assert!(app.crash_vm().install.is_none());
    app.apply(Action::InstallAnalyzer);
    assert!(matches!(app.crash.install, InstallState::Running { .. }));
    let inst = app.crash_vm().install.expect("install status shown");
    assert!(
        inst.running && !inst.failed && inst.percent.is_none(),
        "no fake percent"
    );
    assert!(app.crash.install_log[0].contains("winget install --id Microsoft.WinDbg"));
    assert!(app.crash_redetect.is_none());
    let _ = std::fs::remove_dir_all(exe.parent().unwrap());
}

// ---- v0.4.5 hardware sensors ------------------------------------------

fn msi_snapshot() -> sensors::Snapshot {
    sensors::Snapshot {
        captured_at: "2026-10-05T11:00:00".into(),
        samples: 10,
        interval_ms: 1000,
        sensors: sensors::tests::sample(&sensors::tests::msi_reference()),
        providers: vec![sensors::ProviderReport {
            provider: sensors::Provider::LhmInternal,
            state: sensors::ProviderState::Partial,
            detail: "PawnIO low-level driver not installed".into(),
        }],
        process_context: None,
    }
}

/// v0.4.5: an NVMe temperature is judged only against the drive's own
/// WCTEMP / CCTEMP; without them the number stays neutral.
#[test]
fn nvme_temperature_uses_drive_reported_thresholds_only() {
    let (mut app, exe) = app_in("nvmeref");
    app.sensors = Some(msi_snapshot());
    let vm = app.sensors_vm();
    let samsung = vm.temps.iter().find(|c| c.label == "Samsung 9100").unwrap();
    assert_eq!(samsung.tone, Tone::Idle);
    assert_eq!(samsung.reference, i18n::RU.sensors_ref_none);
    let health = |model: &str, w: Option<f64>, c: Option<f64>| crate::nvme_health::NvmeHealth {
        physical_identity: "x".into(),
        disk_index: 0,
        model: model.into(),
        bus_type: "NVMe".into(),
        captured_at: String::new(),
        source: String::new(),
        status: crate::nvme_health::ProbeStatus::Ok,
        status_detail: None,
        smart: None,
        error_log_status: crate::nvme_health::ProbeStatus::Ok,
        error_log_detail: None,
        error_log: None,
        reliability: None,
        ata_smart: None,
        temp_warning_c: w,
        temp_critical_c: c,
    };
    app.nvme_health.insert(
        "s".into(),
        health("Samsung SSD 9100 PRO 1TB", Some(83.0), Some(85.0)),
    );
    let vm = app.sensors_vm();
    let samsung = vm.temps.iter().find(|c| c.label == "Samsung 9100").unwrap();
    assert_eq!(samsung.reference, "W 83° / C 85°");
    assert_eq!(
        samsung.tone,
        Tone::Success,
        "well below the warning threshold"
    );
    assert_eq!(
        sensors::disk_temp_level(79.0, Some(83.0), Some(85.0)),
        sensors::ReadingLevel::Near
    );
    assert_eq!(
        sensors::disk_temp_level(86.0, Some(83.0), Some(85.0)),
        sensors::ReadingLevel::Critical
    );
    let _ = std::fs::remove_dir_all(exe.parent().unwrap());
}

#[test]
fn sensor_card_is_compact_and_never_lists_cpu_cores() {
    let (mut app, exe) = app_in("sens");
    let vm = app.sensors_vm();
    assert!(!vm.has_data, "nothing invented before a read");
    assert_eq!(vm.power_state, i18n::RU.sensors_not_read);
    app.sensors = Some(msi_snapshot());
    let vm = app.sensors_vm();
    assert!(vm.has_data);
    let labels: Vec<&str> = vm.temps.iter().map(|c| c.label.as_str()).collect();
    assert_eq!(labels[0], "CPU", "{labels:?}");
    assert_eq!(vm.temps[0].value, "49°C", "average of all cores");
    // v0.4.5: no invented CPU limit — neutral number, "без фикс. эталона".
    assert_eq!(vm.temps[0].tone, Tone::Idle);
    assert_eq!(vm.temps[0].reference, i18n::RU.sensors_ref_none);
    assert!(
        labels.iter().all(|l| !l.to_lowercase().contains("core")),
        "{labels:?}"
    );
    assert!(labels.contains(&"Samsung 9100") && labels.contains(&"Netac NVMe"));
    let atx: Vec<&SensorChip> = vm
        .rails
        .iter()
        .filter(|r| r.label.starts_with('+'))
        .collect();
    assert_eq!(atx.len(), 3);
    assert_eq!(atx[0].reference, "11.40–12.60 V");
    assert!(
        vm.rails
            .iter()
            .filter(|r| !r.label.starts_with('+'))
            .all(|r| r.reference == i18n::RU.sensors_ref_dynamic && r.tone == Tone::Idle)
    );
    assert_eq!(vm.power_state, "Отлично");
    assert_eq!(vm.power.len(), 2, "CPU + GPU only on the dashboard");
    assert!(vm.fans.iter().any(|f| f.value == "1180 RPM"));
    assert!(vm.status_line.contains("LHM: PARTIAL"));
    // Hardware state counts trusted rails; the page switch keeps the data.
    app.apply(Action::SetPage(Page::Diagnostics));
    assert!(app.sensors.is_some());
    let _ = std::fs::remove_dir_all(exe.parent().unwrap());
}

#[test]
fn sensor_evidence_lands_in_the_report_with_manifest_module() {
    let (mut app, exe) = app_in("sensev");
    app.sensors_evidence_pending = true;
    app.accept_sensors(msi_snapshot());
    let zip = report_package::lock(&app.package).final_zip().expect("zip");
    let files = report_package::read_zip(&zip).unwrap();
    let ev = files
        .iter()
        .find(|f| f.name.starts_with(sensors::EVIDENCE_PREFIX))
        .expect("Hardware_Sensors_*.json");
    let text = String::from_utf8_lossy(&ev.bytes);
    assert!(crate::deep_checks::json::parse(&text).is_some());
    let manifest = files
        .iter()
        .find(|f| f.name == crate::manifest::MANIFEST_FILE)
        .unwrap();
    let m = String::from_utf8_lossy(&manifest.bytes);
    assert!(m.contains("\"hardware_sensors\""), "{m}");
    assert!(m.contains("\"sensor_count\""));
    assert!(app.journal.iter().any(|e| e.message.contains("EXCELLENT")));
    let _ = std::fs::remove_dir_all(exe.parent().unwrap());
}

/// v0.4.5 sensor Details: TEMPERATURE / VOLTAGE / POWER / FANS with a
/// Reference column, session Min/Max, the provider state (moved off the
/// dashboard) and Copy / Save / Close; the dashboard shows no provider
/// debug string any more.
#[test]
fn sensor_details_window_has_reference_providers_and_export() {
    let (mut app, exe) = app_in("sensdet");
    app.sensors = Some(msi_snapshot());
    app.page = Page::Hardware;
    let ctx = egui::Context::default();
    fonts::install(&ctx);
    let (texts, _) = frame(&mut app, &ctx, vec![]);
    let (texts, _) = if texts.is_empty() {
        frame(&mut app, &ctx, vec![])
    } else {
        (texts, vec![])
    };
    assert!(
        !texts.iter().any(|t| t.contains("LHM: PARTIAL")),
        "no provider strings on the dashboard"
    );
    assert!(texts.iter().any(|t| t == i18n::RU.sensors_header_units));
    assert!(texts.iter().any(|t| t == "11.40–12.60 V"));
    app.apply(Action::ShowSensorDetails);
    let mut all = Vec::new();
    for _ in 0..3 {
        let input = egui::RawInput {
            screen_rect: Some(Rect::from_min_size(egui::Pos2::ZERO, vec2(1400.0, 1200.0))),
            ..Default::default()
        };
        let mut out = ctx.run_ui(input, |ui| app.sensors_details_window(ui.ctx()));
        out.textures_delta.clear();
        all.clear();
        for shape in &out.shapes {
            collect_texts(&shape.shape, &mut all);
        }
    }
    let d = &i18n::RU;
    for t in [
        d.sensors_sec_temperature,
        d.sensors_sec_voltage,
        d.sensors_sec_power,
        d.sensors_ref_title,
        d.sensors_col_min,
        d.sensors_col_max,
        d.journal_viewer_copy,
        d.details_save_as,
        d.journal_viewer_close,
    ] {
        assert!(all.iter().any(|x| x == t), "{t}");
    }
    let text = app.sensors_details_text(&app.sensors_with_storage().unwrap());
    assert!(text.contains("11.40–12.60 V") && text.contains(d.sensors_session_note));
    assert!(text.contains(d.sensors_sec_fans) && text.contains(d.sensors_sec_providers));
    assert!(
        text.contains("LHM: PARTIAL"),
        "provider state moved to Details"
    );
    let _ = std::fs::remove_dir_all(exe.parent().unwrap());
}
