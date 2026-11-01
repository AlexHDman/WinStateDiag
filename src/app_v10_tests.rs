//! v1.0 regression tests (app level): sensor matrix, EXPC focus, Details
//! windows, stage-local evidence, cross-module consistency, system vs
//! hardware state, crash progress / installer states, Disk Details, RAM and
//! release-script contracts.

use super::*;

#[test]
fn rc3_automatic_nvme_keeps_two_disks_and_denial_evidence() {
    struct Denied;
    impl nvme_health::NvmeLogSource for Denied {
        fn read_log_page(
            &self,
            _: u32,
            _: u8,
            _: usize,
        ) -> Result<nvme_health::LogRead, nvme_health::ProbeError> {
            Err(nvme_health::ProbeError::AccessDenied)
        }
    }
    let disks = vec![
        nvme_health::tests::disk(0, "NVMe A", "TEST-A", "NVMe"),
        nvme_health::tests::disk(1, "NVMe B", "TEST-B", "NVMe"),
        nvme_health::tests::disk(2, "SATA", "TEST-C", "SATA"),
    ];
    let health = collect_automatic_nvme(&disks, &Denied, "2026-10-20T02:00:00");
    assert_eq!(health.len(), 2);
    assert_ne!(health[0].physical_identity, health[1].physical_identity);
    for h in &health {
        assert_eq!(h.status, nvme_health::ProbeStatus::AccessDenied);
        assert!(h.smart.is_none());
        assert!(h.status_detail.is_some());
        assert!(nvme_health::to_json(h).contains("ACCESS_DENIED"));
    }
    let (mut app, exe) = app_in("rc3-auto-nvme-export");
    app.automatic_nvme = health;
    app.ata_scan = Some(Vec::new());
    app.contribute_ata_evidence();
    let zip = report_package::lock(&app.package_of("ata"))
        .identity()
        .unwrap()
        .zip_path
        .clone();
    let entries = report_package::read_zip(&zip).unwrap();
    assert_eq!(
        entries
            .iter()
            .filter(|e| e.name.starts_with("NVMe_Health_"))
            .count(),
        2
    );
    let manifest = entries.iter().find(|e| e.name == "manifest.json").unwrap();
    let text = std::str::from_utf8(&manifest.bytes).unwrap();
    assert!(text.contains("ACCESS_DENIED"));
    let _ = std::fs::remove_dir_all(exe);
}

#[test]
fn rc3_driver_stage_is_not_hardware_or_zip() {
    let state = RunState::Running {
        stage: Stage::DriverAudit,
        step_done: 0,
        step_total: 0,
        stage_message: String::new(),
        rx: std::sync::mpsc::channel().1,
    };
    assert!(matches!(hardware_status(&state), ModuleStatus::Done));
    assert!(matches!(zip_status(&state), ModuleStatus::Pending));
    assert!(engine::stage_label(&Stage::DriverAudit).contains("Driver Audit"));
}

#[test]
#[ignore = "explicit read-only Windows hardware probe"]
fn rc3_live_nvme_probe() {
    use storage_topology::TopologySource;
    let start = std::time::Instant::now();
    let disks = storage_topology::windows_source::WindowsTopologySource.physical_disks();
    let health = collect_automatic_nvme(
        &disks,
        &nvme_health::windows_source::WindowsNvmeReader,
        &local_iso(sysinfo::local_time()),
    );
    println!(
        "NVME_DISCOVERED={} ELAPSED_MS={}",
        health.len(),
        start.elapsed().as_millis()
    );
    for h in &health {
        println!(
            "PD={} STATUS={} SMART={} REASON={:?}",
            h.disk_index,
            h.status.as_str(),
            h.smart.is_some(),
            h.status_detail
        );
        assert!(crate::deep_checks::json::parse(&nvme_health::to_json(h)).is_some());
    }
    let root = std::env::temp_dir().join(format!(
        "WsdRc3Live-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    ));
    let audit_started = std::time::Instant::now();
    let report = driver_audit::run_audit_with_cancel(&root.join("audit"), &AtomicBool::new(false));
    println!(
        "DRIVER_AUDIT_MS={} SUCCESS={}",
        audit_started.elapsed().as_millis(),
        report.is_ok()
    );
    let mut files: Vec<_> = health
        .iter()
        .map(|h| {
            EvidenceFile::new(
                nvme_health::evidence_file_name("fixture", h.disk_index),
                nvme_health::to_json(h).into_bytes(),
            )
        })
        .collect();
    if let Ok(report) = report {
        files.push(EvidenceFile::new(
            "DriverAudit_fixture.json",
            driver_audit::to_json(&report).into_bytes(),
        ));
    }
    let mut package = SessionPackage::for_exe_dir(&root);
    package.bind_session(report_package::SessionIdentity::new(
        "rc3-live", "TEST", "LOCAL",
    ));
    let timer = std::time::Instant::now();
    let zip = package.contribute("", "", "20-10-26", files).unwrap();
    println!("ZIP_STAGE_MS={}", timer.elapsed().as_millis());
    let timer = std::time::Instant::now();
    package.finalize().unwrap();
    println!("ZIP_FINALIZE_MS={}", timer.elapsed().as_millis());
    let entries = report_package::read_zip(&zip).unwrap();
    assert_eq!(
        entries
            .iter()
            .filter(|e| e.name.starts_with("NVMe_Health_"))
            .count(),
        health.len()
    );
    assert!(!root.join(".WinStateDiag-work").exists());
    println!("PRIVATE_EVIDENCE={}", zip.display());
}
use crate::ui::vm::{SensorCell, StageMark};

fn app_in(tag: &str) -> (WinStateDiagApp, PathBuf) {
    let exe = std::env::temp_dir()
        .join(format!("wsd-v10-{tag}-{}", std::process::id()))
        .join("WinStateDiag");
    let _ = std::fs::remove_dir_all(exe.parent().unwrap());
    std::fs::create_dir_all(&exe).unwrap();
    let mut app = WinStateDiagApp::default();
    app.reports_root = exe.join("Reports");
    app.language_pref_dir = exe.clone();
    app.language = Language::Ru;
    app.package = Arc::new(Mutex::new(SessionPackage::new(exe.join("Reports"), None)));
    (app, exe)
}

fn no_thresholds(_: &str) -> (Option<f64>, Option<f64>) {
    (None, None)
}

// ---------------- SENSORS ----------------

#[test]
fn sensor_matrix_has_four_columns_and_every_expected_row_without_data() {
    let d = &i18n::RU;
    let (rows, refs) = sensor_matrix(&sensors::Summary::default(), &no_thresholds, d);
    let labels: Vec<&str> = rows.iter().map(|r| r.label.as_str()).collect();
    assert_eq!(
        labels,
        [
            d.sensors_lbl_cpu,
            d.sensors_lbl_board,
            d.sensors_lbl_pch,
            d.sensors_lbl_ram,
            d.sensors_lbl_gpu,
            d.sensors_lbl_hotspot,
            "+12V",
            "+5V",
            "+3.3V",
        ],
        "every expected row stays visible"
    );
    // Expected measurements → "Нет данных"; meaningless cells → "—".
    assert_eq!(rows[0].temp, SensorCell::NoData);
    assert_eq!(rows[0].volt, SensorCell::NoData);
    assert_eq!(rows[0].watt, SensorCell::NoData);
    assert_eq!(rows[1].volt, SensorCell::NotApplicable);
    assert_eq!(rows[6].volt, SensorCell::NoData);
    assert_eq!(rows[6].temp, SensorCell::NotApplicable);
    // Reference table: fixed ATX bands, dynamic rails, no invented limits.
    let r: Vec<(&str, &str)> = refs
        .iter()
        .map(|x| (x.label.as_str(), x.range.as_str()))
        .collect();
    assert!(r.contains(&("+12V", "11.40–12.60 V")));
    assert!(r.contains(&("+5V", "4.75–5.25 V")));
    assert!(r.contains(&("+3.3V", "3.14–3.47 V")));
    assert!(r.contains(&("Vcore / VID", d.sensors_ref_dynamic)));
    assert!(r.contains(&("GPU Core", d.sensors_ref_dynamic)));
    assert!(r.contains(&(d.sensors_ref_cpu_gpu_temp, d.sensors_ref_none)));
}

#[test]
fn sensor_matrix_values_zero_watt_colours_and_duplicate_disks() {
    let d = &i18n::RU;
    let mut readings = sensors::fixture::msi_reference();
    // A power counter that reports 0 W is unavailable, never "0 W".
    for r in readings.iter_mut() {
        if r.name == "CPU Package Power" {
            r.value = Some(0.0);
        }
    }
    let sum = sensors::summarize(&sensors::fixture::sample(&readings));
    let (rows, _) = sensor_matrix(&sum, &no_thresholds, d);
    let cpu = &rows[0];
    assert!(
        matches!(&cpu.temp, SensorCell::Value { text, tone } if text == "49°C" && *tone == Tone::Idle)
    );
    assert_eq!(cpu.watt, SensorCell::NoData, "0 W → Нет данных");
    let gpu = rows.iter().find(|r| r.label == d.sensors_lbl_gpu).unwrap();
    assert!(matches!(&gpu.watt, SensorCell::Value { text, .. } if text.ends_with(" W")));
    // Only rails (ATX band) and disks (drive thresholds) carry a colour.
    for row in &rows {
        for cell in [&row.temp, &row.volt, &row.watt] {
            if let SensorCell::Value { tone, .. } = cell
                && !row.label.starts_with('+')
            {
                assert_eq!(*tone, Tone::Idle, "{} has no reliable reference", row.label);
            }
        }
    }
    let v12 = rows.iter().find(|r| r.label == "+12V").unwrap();
    assert!(matches!(&v12.volt, SensorCell::Value { tone, .. } if *tone == Tone::Success));
    // NVMe disk with drive thresholds: coloured number + reference line.
    let (rows, refs) = sensor_matrix(
        &sum,
        &|l: &str| {
            if l.contains("9100") {
                (Some(83.0), Some(85.0))
            } else {
                (None, None)
            }
        },
        d,
    );
    let samsung = rows.iter().find(|r| r.label.contains("9100")).unwrap();
    assert!(matches!(&samsung.temp, SensorCell::Value { tone, .. } if *tone == Tone::Success));
    assert!(
        refs.iter()
            .any(|r| r.label.contains("9100") && r.range == "W 83° / C 85°")
    );
}

#[test]
fn sata_disks_from_ata_smart_join_the_matrix_as_separate_rows() {
    let (mut app, exe) = app_in("atarows");
    app.sensors = Some(sensors::Snapshot {
        captured_at: "t".into(),
        ..Default::default()
    });
    let smart = |t: u64| crate::ata_smart::AtaSmart {
        state: crate::ata_smart::AtaState::Ok,
        detail: String::new(),
        attributes: vec![crate::ata_smart::Attribute {
            id: 194,
            current: 100,
            worst: 100,
            threshold: Some(0),
            raw: t,
        }],
    };
    app.ata_scan = Some(vec![
        AtaDisk {
            index: 0,
            model: "TOSHIBA DT02ABA400".into(),
            bus: "SATA".into(),
            smart: smart(28),
        },
        AtaDisk {
            index: 1,
            model: "TOSHIBA DT02ABA400".into(),
            bus: "SATA".into(),
            smart: smart(25),
        },
    ]);
    let vm = app.sensors_vm();
    let labels: Vec<&str> = vm.matrix.iter().map(|r| r.label.as_str()).collect();
    assert!(
        labels.contains(&"TOSHIBA #1") && labels.contains(&"TOSHIBA #2"),
        "{labels:?}"
    );
    // The SMART card lists every SATA disk with its read-only health.
    let smart_rows = app.smart_rows();
    assert!(
        smart_rows
            .iter()
            .any(|r| r.value.contains("SATA · OK · 28°C"))
    );
    let _ = std::fs::remove_dir_all(exe.parent().unwrap());
}

#[test]
fn sensor_card_draws_numbers_only_no_status_dots_or_checkmarks() {
    let src = include_str!("ui/pages.rs");
    let a = src.find("pub fn draw_sensors(").unwrap();
    let b = src.find("pub struct SensorMatrixGeometry").unwrap();
    let body = &src[a..b];
    for forbidden in ["circle_filled", "icon_check", "icon_alert", "icon_warning"] {
        assert!(!body.contains(forbidden), "{forbidden} in the sensor card");
    }
    assert!(body.contains("d.sensors_col_name") && body.contains("\"Watt\""));
}

// ---------------- EXPC focus ----------------

#[test]
fn expc_violet_focus_only_while_a_stage_really_runs() {
    let mut vm = crate::ui::fixture::master_vm_in(Language::Ru);
    vm.stop_enabled = false;
    assert!(!crate::ui::pages::expc_active(&vm), "completed: no glow");
    vm.stop_enabled = true;
    assert!(
        !crate::ui::pages::expc_active(&vm),
        "nothing running: no glow"
    );
    vm.stages[6].state = RowState::Running;
    vm.stages[6].active = true;
    assert!(crate::ui::pages::expc_active(&vm));
    vm.animate = false;
    assert_eq!(
        crate::ui::pages::expc_glow_phase(&vm),
        0.5,
        "no fake animation"
    );
    let src = include_str!("ui/pages.rs");
    assert!(
        src.contains("Stroke::new(1.0, c::EXPC_ACTIVE_BORDER)"),
        "1 px violet border"
    );
    assert!(src.contains("c::EXPC_ACTIVE_ROW"), "active row violet");
}

// ---------------- Details windows ----------------

#[test]
fn every_details_window_is_a_large_resizable_viewport_with_the_action_bar() {
    // Sources may be checked out with CRLF (core.autocrlf): slice on LF.
    let src = &include_str!("app.rs").replace("\r\n", "\n");
    // The shared helper: real OS viewport, resizable, min size.
    let helper = &src[src.find("pub(crate) fn detail_window<R>(").unwrap()..];
    let helper = &helper[..helper.find("\n}\n").unwrap()];
    assert!(helper.contains(".with_resizable(true)"));
    assert!(helper.contains("show_viewport_immediate"));
    // Every Details window uses it with a noticeably larger default.
    for key in [
        "wsd_driver_details",
        "wsd_stage_details",
        "wsd_expc_details",
        "wsd_crash_details",
        "wsd_sensors_details",
        "wsd_gpo_details",
        "wsd_disk_details",
    ] {
        let at = src.find(&format!("\"{key}\",")).expect(key);
        let tail = &src[at..at + 220];
        let open = tail.find('[').unwrap();
        let close = tail.find(']').unwrap();
        let w: f32 = tail[open + 1..close]
            .split(',')
            .next()
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert!(w >= 900.0, "{key} default width {w}");
    }
    // The disk window is no longer a tiny embedded egui::Window.
    assert!(!src.contains("egui::Window::new(raw_passes_title)"));
    // Standard action bar: Copy / Save as / (Open report folder) / Close.
    assert!(src.matches("details_action_bar(ui, d,").count() >= 7);
    let d = &i18n::RU;
    assert_eq!(d.details_save_as, "Сохранить как...");
    assert_eq!(d.details_open_folder, "Открыть папку отчёта");
}

#[test]
fn save_as_writes_only_the_current_module_text() {
    let (mut app, exe) = app_in("saveas");
    let ctx = egui::Context::default();
    // Tests have no modal dialog: the session logs folder is used.
    let st = app.export_text(
        &ctx,
        ExportAction::Save,
        "Disk_Benchmark",
        "ONLY THIS MODULE",
    );
    let ExportStatus::Saved(path) = st else {
        panic!("{st:?}")
    };
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.contains("ONLY THIS MODULE"));
    assert!(
        path.file_name()
            .unwrap()
            .to_string_lossy()
            .contains("Disk_Benchmark")
    );
    assert_eq!(
        ExportStatus::Cancelled.text(&i18n::RU).0,
        i18n::RU.export_cancelled
    );
    let _ = std::fs::remove_dir_all(exe.parent().unwrap());
}

#[test]
fn disk_details_show_identity_both_tests_comparison_health_and_history() {
    let (mut app, exe) = app_in("diskdet");
    app.seed_qa_scene("disk-details");
    let BenchmarkUiState::Done { result, .. } = &app.benchmark_state else {
        panic!("seeded")
    };
    let result = result.clone();
    let d = &i18n::RU;
    let sections = app.disk_details_sections(&result);
    let heads: Vec<&str> = sections.iter().map(|(h, _)| h.as_str()).collect();
    assert_eq!(heads[0], d.disk_det_identity);
    assert!(heads[1].starts_with(d.test1_title));
    assert!(heads[2].starts_with(d.test2_title));
    assert!(heads.contains(&d.disk_det_comparison));
    assert!(heads.contains(&d.nvme_health_title));
    assert!(heads.contains(&d.storage_assessment_title));
    assert!(heads.contains(&d.disk_det_history));
    let text = disk_details_text(&app.disk_details_title(), &sections);
    assert!(
        text.contains("PhysicalDrive3") && text.contains("UNSTABLE") && text.contains("ACCEPT")
    );
    assert!(
        app.disk_details_title()
            .contains("Samsung SSD 9100 PRO 1TB")
    );
    let _ = std::fs::remove_dir_all(exe.parent().unwrap());
}

// ---------------- EXPC stage-local evidence ----------------

#[test]
fn row_details_show_only_that_stages_evidence() {
    let (mut app, exe) = app_in("stagelocal");
    let ev = |p: &str, id: u32, m: &str| events::RawEvent {
        log: "x".into(),
        provider: p.into(),
        id,
        time: "2026-10-01T03:00:00".into(),
        message: m.into(),
        data: vec![("param1".into(), "app.exe".into())],
        ..Default::default()
    };
    let aggs = events::aggregate(
        &[
            ev("volsnap", 33, "quota eviction"),
            ev("Application Error", 1000, "Faulting application app.exe"),
            ev("Service Control Manager", 7031, "terminated"),
        ],
        &[],
        "2026-10-02T00:00:00",
    );
    app.event_evidence = Some(Ok((aggs, None)));
    let vss = app.stage_evidence_lines(4).join("\n");
    let apps = app.stage_evidence_lines(7).join("\n");
    let system = app.stage_evidence_lines(3).join("\n");
    assert!(vss.contains("volsnap") && !vss.contains("Application Error") && !vss.contains("7031"));
    assert!(apps.contains("Application Error") && !apps.contains("volsnap"));
    assert!(system.contains("Service Control Manager") && !system.contains("volsnap"));
    let _ = std::fs::remove_dir_all(exe.parent().unwrap());
}

// ---------------- consistency / states ----------------

#[test]
fn ok_stages_are_qualified_when_another_module_has_significant_evidence() {
    let d = &i18n::RU;
    assert!(consistency_note(3, true, 2, 0, d).unwrap().contains('2'));
    assert_eq!(consistency_note(3, true, 0, 0, d), None);
    assert_eq!(
        consistency_note(3, false, 5, 0, d),
        None,
        "non-OK needs no note"
    );
    assert_eq!(
        consistency_note(6, true, 0, 1, d).as_deref(),
        Some(d.consistency_bsod)
    );
    assert_eq!(consistency_note(10, true, 9, 9, d), None);
}

#[test]
fn hardware_ok_and_system_attention_are_separate_states() {
    let (mut app, exe) = app_in("states");
    app.seed_qa_scene("hardware");
    if let Some(Ok(inv)) = &mut app.crash.inventory {
        for b in &mut inv.bugchecks {
            b.time = local_iso(sysinfo::local_time());
        }
    }
    // v1.1 RC: the scene has 3 NVMe disks, health read for 2 → not an OK.
    assert_eq!(app.state_codes().1, "PARTIAL");
    assert_eq!(app.system_state_vm().hardware.tone, Tone::Idle);
    let third = storage_topology::physical_disk_identity(&app.ssd_candidates[2].disk);
    let mut h = app.nvme_health.values().next().unwrap().clone();
    h.physical_identity = third.clone();
    app.nvme_health.insert(third, h);
    let (system, hardware) = app.state_codes();
    assert_eq!(system, "ATTENTION_BSOD");
    assert_eq!(hardware, "OK");
    let vm = app.system_state_vm();
    assert_eq!(vm.hardware.tone, Tone::Success);
    assert_eq!(vm.system.tone, Tone::Warning);
    // Unexpected shutdown without a BugCheck: never "BSOD".
    if let Some(Ok(inv)) = &mut app.crash.inventory {
        inv.bugchecks.clear();
        inv.dumps.clear();
    }
    assert_eq!(app.state_codes().0, "ATTENTION_UNEXPECTED_SHUTDOWN");
    let _ = std::fs::remove_dir_all(exe.parent().unwrap());
}

// ---------------- crash progress / installer ----------------

#[test]
fn bsod_analysis_shows_real_stages_elapsed_and_no_percentage() {
    let (mut app, exe) = app_in("bsodprog");
    app.seed_qa_scene("bsod-running");
    let vm = app.crash_vm();
    let a = vm.analysis.expect("progress shown while analyzing");
    assert_eq!(a.stages.len(), 6);
    assert_eq!(a.stages[0].1, StageMark::Done);
    assert_eq!(a.stages[1].1, StageMark::Active);
    assert_eq!(a.stages[5].1, StageMark::Pending);
    assert!(a.elapsed.starts_with("00:4"), "{}", a.elapsed);
    assert_eq!(a.note.as_deref(), Some(i18n::RU.crash_symbols_download));
    assert!(vm.busy && vm.outcome.is_none());
    // Finished: outcome colour, no progress.
    let (mut done, exe2) = app_in("bsoddone");
    done.seed_qa_scene("hardware");
    let vm = done.crash_vm();
    assert!(vm.analysis.is_none());
    assert_eq!(vm.outcome.as_ref().map(|o| o.1), Some(Tone::Success));
    // The dump-driven Driver Audit item appears on the card and in the view.
    let link = vm
        .rows
        .iter()
        .find(|r| r.label == i18n::RU.crash_row_driver)
        .unwrap();
    assert!(link.value.contains("RvNetMP60.sys"), "{}", link.value);
    let view = done.audit_view().unwrap();
    assert_eq!(view.count(Severity::Warning), 1);
    let _ = std::fs::remove_dir_all(exe.parent().unwrap());
    let _ = std::fs::remove_dir_all(exe2.parent().unwrap());
}

#[test]
fn installer_states_success_failure_and_redetection() {
    let (mut app, exe) = app_in("install");
    app.crash.inventory = Some(Ok(crash_dump::Inventory {
        bugchecks: Vec::new(),
        dumps: Vec::new(),
        debugger: crash_dump::DebuggerStatus::NotInstalled,
        notes: Vec::new(),
        unexpected_shutdowns: 0,
        incidents: Vec::new(),
        live_kernel_reports: Vec::new(),
    }));
    // Nothing happens without the explicit click.
    assert_eq!(app.crash.install, InstallState::Idle);
    app.apply(Action::InstallAnalyzer);
    app.accept_install_msg(InstallMsg::Line("Found WinDbg [Microsoft.WinDbg]".into()));
    app.accept_install_msg(InstallMsg::Line("  1.0 MB / 4.0 MB".into()));
    let inst = app.crash_vm().install.unwrap();
    assert_eq!(inst.percent, Some(25), "real percentage only when printed");
    assert!(inst.lines.iter().any(|(_, m)| *m == StageMark::Active));
    // Failure → retry + details journal.
    app.accept_install_msg(InstallMsg::Done(crash_dump::InstallResult {
        success: false,
        exit_text: "0x8a150014".into(),
        log: String::new(),
    }));
    // v1.0 item 41: never decided by the exit text — re-detection first.
    assert_eq!(app.crash.install, InstallState::Verifying);
    app.accept_crash_msg(CrashMsg::Inventory(Ok(crash_dump::Inventory {
        bugchecks: Vec::new(),
        dumps: Vec::new(),
        debugger: crash_dump::DebuggerStatus::NotInstalled,
        notes: Vec::new(),
        unexpected_shutdowns: 0,
        incidents: Vec::new(),
        live_kernel_reports: Vec::new(),
    })));
    let inst = app.crash_vm().install.unwrap();
    assert!(inst.failed && inst.status.contains(i18n::RU.install_failed));
    assert!(inst.status.contains("не установлен"), "{}", inst.status);
    assert!(
        app.crash
            .install_log
            .iter()
            .any(|l| l.contains("0x8a150014"))
    );
    // Success → re-detection → "АНАЛИЗАТОР УСТАНОВЛЕН".
    app.apply(Action::InstallAnalyzer);
    app.accept_install_msg(InstallMsg::Done(crash_dump::InstallResult {
        success: true,
        exit_text: "OK".into(),
        log: String::new(),
    }));
    assert_eq!(app.crash.install, InstallState::Verifying);
    app.accept_crash_msg(CrashMsg::Inventory(Ok(crash_dump::Inventory {
        bugchecks: Vec::new(),
        dumps: Vec::new(),
        debugger: crash_dump::DebuggerStatus::Installed {
            cdb: "cdbX64.exe".into(),
        },
        notes: Vec::new(),
        unexpected_shutdowns: 0,
        incidents: Vec::new(),
        live_kernel_reports: Vec::new(),
    })));
    assert_eq!(app.crash.install, InstallState::Succeeded);
    let inst = app.crash_vm().install.unwrap();
    assert!(inst.succeeded && inst.status == i18n::RU.install_installed);
    assert!(!app.crash_vm().debugger_missing, "button becomes Analyze");
    let _ = std::fs::remove_dir_all(exe.parent().unwrap());
}

// ---------------- GPO / RAM / release ----------------

#[test]
fn standalone_gpo_still_evaluates_the_local_policy_store() {
    let mut local = gpo_admx::Store {
        path: "C:\\Windows\\PolicyDefinitions".into(),
        exists: true,
        admx: vec![("windows.admx".into(), "1.0".into())],
        adml: vec![("ru-RU".into(), vec!["windows.adml".into()])],
        supported_defined: vec!["SUPPORTED_Windows_11_0_26H2".into()],
        supported_referenced: vec!["SUPPORTED_Windows_11_0_26H2".into()],
        newest_release: Some("26H2".into()),
    };
    let mut i = gpo_admx::GpoInputs {
        domain_joined: false,
        windows_release: "26H2".into(),
        ui_language: "ru-RU".into(),
        local: local.clone(),
        ..Default::default()
    };
    let r = gpo_admx::classify(&i);
    assert_eq!(
        r.status,
        gpo_admx::GpoStatus::NotApplicable,
        "Central Store"
    );
    assert_eq!(
        r.local_status,
        gpo_admx::GpoStatus::Ok,
        "local store evaluated"
    );
    local.adml = vec![("ru-RU".into(), Vec::new())];
    i.local = local;
    let r = gpo_admx::classify(&i);
    // v1.0: harmless local differences on a standalone PC are INFO.
    assert_eq!(r.local_status, gpo_admx::GpoStatus::Info);
    assert!(!r.local_findings.is_empty(), "facts are kept");
    let js = gpo_admx::to_json(&i, &r);
    assert!(js.contains("\"central_store_status\": \"NOT APPLICABLE\""));
    assert!(js.contains("\"local_store_status\": \"INFO\""));
    // A domain member keeps MISMATCH semantics for its stores.
    i.domain_joined = true;
    assert_eq!(
        gpo_admx::classify_local(&i).0,
        gpo_admx::GpoStatus::Mismatch
    );
}

#[test]
fn mixed_ram_capacity_is_info_context_never_a_hardware_warning() {
    let ps = include_str!("../embedded/Hardware-Report/HardwarePassport.psm1");
    assert!(ps.contains("$ramContext += 'Mixed module capacities (context"));
    assert!(!ps.contains("$ramReasons += 'Mixed module capacities"));
    assert!(ps.contains("elseif ($ramContext.Count -or $declaredSlots -le 0"));
    // Configured-below-rated (XMP / JEDEC profile) is context too.
    assert!(ps.contains(
        "Configured data rate below the declared rate (JEDEC / XMP-EXPO profile context"
    ));
    assert!(ps.contains(
        "State = $(if($speed -and $configured -and [int]$configured -lt [int]$speed){'INFO'}"
    ));
}

#[test]
fn release_script_names_v1_0_and_never_touches_older_releases() {
    let s = include_str!("../scripts/make_release.ps1");
    assert!(s.contains("$version = if ($Matches[4]) { $semver }"));
    assert!(s.contains("elseif ($Matches[3] -eq '0')"));
    assert!(s.contains("Get-OtherReleaseHashes"));
    assert!(s.contains("an older dist release changed during this run"));
    assert!(
        !s.contains("Remove-Item"),
        "the release script never deletes"
    );
}

/// v1.0 item 41: WinDbg already installed, winget answers "No newer package
/// versions are available" (non-success exit text) → independent re-detect
/// decides: the analyzer is shown as INSTALLED, not "install failed".
#[test]
fn windbg_installed_but_winget_has_nothing_to_upgrade_is_installed() {
    let (mut app, dir) = app_in("windbg_noupgrade");
    let inv = |dbg: crash_dump::DebuggerStatus| crash_dump::Inventory {
        bugchecks: Vec::new(),
        dumps: Vec::new(),
        debugger: dbg,
        notes: Vec::new(),
        unexpected_shutdowns: 0,
        incidents: Vec::new(),
        live_kernel_reports: Vec::new(),
    };
    app.crash.install = InstallState::Running {
        stage: crash_dump::InstallStage::Preparing,
        percent: None,
    };
    app.accept_install_msg(InstallMsg::Done(crash_dump::InstallResult {
        success: false,
        exit_text: "No newer package versions are available from the configured sources.".into(),
        log: String::new(),
    }));
    assert_eq!(
        app.crash.install,
        InstallState::Verifying,
        "re-detect, not FAILED"
    );
    app.accept_crash_msg(CrashMsg::Inventory(Ok(inv(
        crash_dump::DebuggerStatus::Installed {
            cdb: "C:\\Program Files\\WindowsApps\\Microsoft.WinDbg_1.2506.12002.0_x64__8wekyb3d8bbwe\\amd64\\cdb.exe".into(),
        },
    ))));
    assert_eq!(app.crash.install, InstallState::Succeeded);
    let vm = app.install_vm().expect("vm");
    assert!(vm.succeeded && !vm.failed);

    // Package installed, backend missing → truthful, not "installed".
    app.crash.install = InstallState::Verifying;
    app.accept_crash_msg(CrashMsg::Inventory(Ok(inv(
        crash_dump::DebuggerStatus::PackageOnly {
            package: "Microsoft.WinDbg 1.2506.12002.0".into(),
        },
    ))));
    match &app.crash.install {
        InstallState::Failed(t) => assert!(t.contains("cdb не найден"), "{t}"),
        other => panic!("{other:?}"),
    }
    // A stale failure never hides a usable analyzer.
    app.crash.inventory = Some(Ok(inv(crash_dump::DebuggerStatus::Installed {
        cdb: "cdbX64.exe".into(),
    })));
    assert!(app.install_vm().unwrap().succeeded);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn windbg_package_only_parses_from_inventory() {
    let out = "WSD_CRASH {\"bugchecks\":[],\"dumps\":[],\"cdb\":\"\",\"pkg\":\"Microsoft.WinDbg 1.2506.12002.0\",\"notes\":[],\"shutdowns\":0,\"incidents\":[],\"lkr\":[]}";
    let inv = crash_dump::parse_inventory(out).expect("parsed");
    assert_eq!(inv.debugger.code(), "PACKAGE ONLY (NO CDB BACKEND)");
    assert!(!inv.debugger.usable());
    let out = out.replace("\"cdb\":\"\"", "\"cdb\":\"C:\\\\x\\\\cdb.exe\"");
    assert!(crash_dump::parse_inventory(&out).unwrap().debugger.usable());
}

/// v1.0 item 8: sensor READ indicator — Idle → Reading (real elapsed
/// timer, Refresh disabled) → Idle on success / ERROR on failure → a new
/// read clears the error.
#[test]
fn sensor_read_indicator_state_transitions() {
    use crate::ui::vm::SensorReadVm;
    let (mut app, dir) = app_in("sensor_read");
    assert_eq!(app.sensors_vm().read, SensorReadVm::Idle);
    // Reading: a live receiver + start instant (the worker is not spawned
    // in tests; the channel stands in for it).
    let (tx, rx) = std::sync::mpsc::channel::<sensors::Snapshot>();
    app.sensors_rx = Some(rx);
    app.sensors_started = Some(Instant::now() - Duration::from_secs(7));
    let vm = app.sensors_vm();
    assert!(vm.busy, "Refresh is disabled while reading");
    assert_eq!(vm.read, SensorReadVm::Reading { elapsed_s: 7 });
    assert_eq!(vm.read.elapsed_text().as_deref(), Some("00:07"));
    // Worker lost → ERROR.
    drop(tx);
    app.poll_sensors();
    assert!(matches!(app.sensors_vm().read, SensorReadVm::Error { .. }));
    // Next read clears the error; a successful snapshot hides the spinner.
    let (tx, rx) = std::sync::mpsc::channel::<sensors::Snapshot>();
    app.sensors_rx = Some(rx);
    app.sensors_started = None;
    app.sensors_error = None;
    app.sensors_started = Some(Instant::now());
    assert!(matches!(
        app.sensors_vm().read,
        SensorReadVm::Reading { .. }
    ));
    tx.send(sensors::Snapshot::default()).unwrap();
    app.poll_sensors();
    assert_eq!(app.sensors_vm().read, SensorReadVm::Idle);
    assert!(app.sensors_started.is_none());
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn sensor_read_elapsed_text_has_no_percent() {
    use crate::ui::vm::SensorReadVm;
    assert_eq!(
        SensorReadVm::Reading { elapsed_s: 65 }
            .elapsed_text()
            .as_deref(),
        Some("01:05")
    );
    assert_eq!(SensorReadVm::Idle.elapsed_text(), None);
}

/// v1.0 item 11: the SMART / NVMe block lists PHYSICAL DISKS, never a bus
/// category ("NVMe") as if it were a device; duplicates get #1 / #2.
#[test]
fn smart_block_lists_physical_disks_never_a_category_row() {
    let (mut app, dir) = app_in("smart_disks");
    let cand = |i: u32, model: &str, bus: &str| storage_topology::DiskCandidate {
        disk: crate::nvme_health::tests::disk(i, model, "", bus),
        is_system: i == 0,
        volume: None,
        label: model.into(),
    };
    app.ssd_candidates = vec![
        cand(0, "Samsung SSD 990 PRO 2TB", "NVMe"),
        cand(1, "Netac NVMe SSD 1TB", "NVMe"),
    ];
    let page = crate::storage_health::tests::netac_page();
    let h = crate::storage_health::tests::health(Some(page), 1);
    let mut h = h;
    h.physical_identity = storage_topology::physical_disk_identity(&app.ssd_candidates[1].disk);
    app.nvme_health.insert(h.physical_identity.clone(), h);
    let ok = crate::ata_smart::AtaSmart {
        state: crate::ata_smart::AtaState::Ok,
        detail: String::new(),
        attributes: vec![crate::ata_smart::Attribute {
            id: 5,
            current: 100,
            worst: 100,
            threshold: Some(36),
            raw: 0,
        }],
    };
    app.ata_scan = Some(vec![
        AtaDisk {
            index: 2,
            model: "TOSHIBA DT01ACA100".into(),
            bus: "SATA".into(),
            smart: ok.clone(),
        },
        AtaDisk {
            index: 3,
            model: "TOSHIBA DT01ACA100".into(),
            bus: "SATA".into(),
            smart: ok.clone(),
        },
        AtaDisk {
            index: 4,
            model: "ST2000DM008-2FR102".into(),
            bus: "SATA".into(),
            smart: ok,
        },
    ]);
    let rows = app.smart_rows();
    let labels: Vec<&str> = rows.iter().map(|r| r.label.as_str()).collect();
    for bad in ["NVMe", "SATA", "ATA"] {
        assert!(!labels.contains(&bad), "category row {bad}: {labels:?}");
    }
    assert!(rows[0].value.starts_with("NVMe · "), "{:?}", rows[0]);
    assert!(rows[0].value.contains(i18n::RU.smart_not_read));
    assert!(rows[1].value.starts_with("NVMe · OK"), "{:?}", rows[1]);
    assert!(labels.iter().any(|l| l.ends_with("#1")) && labels.iter().any(|l| l.ends_with("#2")));
    assert!(rows.iter().any(|r| r.value.starts_with("SATA · OK")));
    let _ = std::fs::remove_dir_all(dir);
}

// ---------------- v1.1 RC: no OK without a complete basis ----------------

fn clean_inventory(notes: Vec<String>) -> crash_dump::Inventory {
    crash_dump::Inventory {
        bugchecks: Vec::new(),
        dumps: Vec::new(),
        debugger: crash_dump::DebuggerStatus::NotInstalled,
        notes,
        unexpected_shutdowns: 0,
        incidents: Vec::new(),
        live_kernel_reports: Vec::new(),
    }
}

fn clean_audit() -> AuditReport {
    let mut r = crate::details::tests::report();
    r.items.retain(|i| i.status == Severity::Ok);
    r.overall = Severity::Ok;
    r
}

#[test]
fn system_ok_needs_a_finished_driver_audit() {
    let (mut app, exe) = app_in("rc_sys");
    app.crash.inventory = Some(Ok(clean_inventory(Vec::new())));
    // Crash inventory alone: not OK.
    assert_eq!(app.state_codes().0, "PARTIAL");
    assert_eq!(app.system_state_vm().system.tone, Tone::Idle);
    app.driver_audit = DriverAuditState::Done(Box::new(clean_audit()));
    app.expc_checks = ["SFC", "DISM", "WHEA", "VSS"]
        .into_iter()
        .map(|k| crate::deep_checks::ExpcCheck {
            key: k.into(),
            status: "OK".into(),
            detail: "fixture completed".into(),
        })
        .collect();
    assert_eq!(app.state_codes().0, "OK");
    // A Driver Audit with collection gaps is not an OK basis.
    let mut gaps = clean_audit();
    gaps.errors.push("Win32_SystemDriver: Access denied".into());
    app.driver_audit = DriverAuditState::Done(Box::new(gaps));
    assert_eq!(app.state_codes().0, "PARTIAL");
    // A failed event-evidence read is not an OK basis either.
    app.driver_audit = DriverAuditState::Done(Box::new(clean_audit()));
    app.event_evidence = Some(Err("access denied".into()));
    assert_eq!(app.state_codes().0, "PARTIAL");
    let _ = std::fs::remove_dir_all(exe.parent().unwrap());
}

#[test]
fn phase04_empty_failed_partial_pnp_and_warning_gaps_never_back_system_ok() {
    let (mut app, exe) = app_in("phase04_pnp");
    app.crash.inventory = Some(Ok(clean_inventory(Vec::new())));
    for (index, (complete, errors, severity, scanned)) in [
        (true, vec![], Severity::Ok, 0),
        (false, vec!["PnP access denied".into()], Severity::Ok, 0),
        (false, vec![], Severity::Ok, 1),
        (
            true,
            vec!["event source denied".into()],
            Severity::Warning,
            1,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let mut r = clean_audit();
        r.complete = complete;
        r.errors = errors;
        r.overall = severity;
        r.devices_scanned = scanned;
        if scanned == 0 {
            r.items.clear();
        }
        assert!(!r.coverage_gaps().is_empty());
        assert_eq!(
            r.verdict_code(),
            if severity == Severity::Warning {
                "WARNING"
            } else {
                "INCOMPLETE"
            }
        );
        for d in [&i18n::RU, &i18n::EN] {
            let text = crate::details::driver_issues_text(&r, d, &str::to_string);
            assert!(!text.contains(d.driver_issues_none));
            assert!(text.contains(d.driver_alert_incomplete_note));
        }
        let verdict = r.verdict_code();
        let files = vec![
            EvidenceFile::new(
                "DriverAudit_fixture.json",
                driver_audit::to_json(&r).into_bytes(),
            ),
            EvidenceFile::new(
                "DriverAudit_fixture.txt",
                driver_audit::to_text(&r).into_bytes(),
            ),
        ];
        app.driver_audit = DriverAuditState::Done(Box::new(r));
        assert_eq!(
            app.state_codes().0,
            if severity >= Severity::Warning {
                "ATTENTION_DIAG"
            } else {
                "PARTIAL"
            }
        );
        let mut pkg = SessionPackage::new(exe.join(format!("fixture-{index}")), None);
        let (system, hardware) = app.state_codes();
        pkg.set_states(&system, &hardware);
        let zip = pkg.contribute("", "fixture", "19-10-26", files).unwrap();
        let entries = report_package::read_zip(&zip).unwrap();
        let contents = |name: &str| {
            String::from_utf8(
                entries
                    .iter()
                    .find(|f| f.name == name)
                    .unwrap()
                    .bytes
                    .clone(),
            )
            .unwrap()
        };
        assert!(contents("State_Summary.txt").contains(&format!("System: {system}")));
        let summary = crate::deep_checks::json::parse(&contents("State_Summary.json")).unwrap();
        assert_eq!(
            summary.get("system").and_then(|v| v.as_str()),
            Some(system.as_str())
        );
        let manifest = contents("manifest.json");
        assert!(manifest.contains(&format!("\"system\": \"{system}\"")));
        assert!(manifest.contains(&format!("\"result_status\": \"{verdict}\"")));
        pkg.finalize().unwrap();
    }
    let mut problem = clean_audit();
    problem.overall = Severity::Problem;
    problem.errors.push("source unavailable".into());
    app.driver_audit = DriverAuditState::Done(Box::new(problem));
    assert_eq!(app.state_codes().0, "ATTENTION_DRIVER_PROBLEM");
    let _ = std::fs::remove_dir_all(exe.parent().unwrap());
}

#[test]
fn phase04_sensor_worker_failure_is_exported_not_just_displayed() {
    use crate::ui::vm::SensorReadVm;
    let (mut app, exe) = app_in("phase04_sensor");
    app.sensors = Some(sensors::Snapshot {
        sensors: sensors::tests::sample(&sensors::tests::msi_reference()),
        ..Default::default()
    });
    app.ata_scan = Some(vec![AtaDisk {
        index: 0,
        model: "Fixture SATA".into(),
        bus: "SATA".into(),
        smart: crate::ata_smart::AtaSmart {
            state: crate::ata_smart::AtaState::Ok,
            detail: String::new(),
            attributes: vec![crate::ata_smart::Attribute {
                id: 194,
                current: 100,
                worst: 100,
                threshold: Some(0),
                raw: 30,
            }],
        },
    }]);
    assert_eq!(app.state_codes().1, "OK");
    app.claim_package("sensors");
    app.sensors_evidence_pending = true;
    let (tx, rx) = std::sync::mpsc::channel::<sensors::Snapshot>();
    app.sensors_rx = Some(rx);
    drop(tx);
    app.poll_sensors();
    let reason = "sensor reader ended without a result";
    assert!(matches!(app.sensors_vm().read, SensorReadVm::Error { .. }));
    let snap = app.sensors.as_ref().unwrap();
    assert_eq!(snap.state(), sensors::ProviderState::ProviderError);
    assert!(app.sensors_details_text(snap).contains(reason));
    assert!(sensors::to_json(snap).contains(reason));
    assert_eq!(app.state_codes().1, "PARTIAL");
    app.sync_manifest_states();
    let pkg = app.op_packages.get("sensors").unwrap();
    let files = report_package::read_zip(&pkg.lock().unwrap().final_zip().unwrap()).unwrap();
    for ext in [".json", ".txt"] {
        assert!(
            files
                .iter()
                .any(|f| f.name.starts_with(sensors::EVIDENCE_PREFIX)
                    && f.name.ends_with(ext)
                    && String::from_utf8_lossy(&f.bytes).contains(reason))
        );
    }
    let manifest = files.iter().find(|f| f.name == "manifest.json").unwrap();
    let manifest = String::from_utf8_lossy(&manifest.bytes);
    assert!(manifest.contains(reason));
    assert!(manifest.contains("PROVIDER_ERROR"));
    assert!(manifest.contains("\"hardware\": \"PARTIAL\""));
    assert!(files.iter().any(|f| f.name == "State_Summary.txt"
        && String::from_utf8_lossy(&f.bytes).contains("Hardware: PARTIAL")));
    assert!(!app.sensors_evidence_pending);
    let _ = std::fs::remove_dir_all(exe.parent().unwrap());
}

#[test]
fn unreadable_crash_source_is_not_no_crashes() {
    let (mut app, exe) = app_in("rc_crash");
    app.crash.inventory = Some(Ok(clean_inventory(vec![
        "Dump folder not readable: C:\\Windows\\Minidump".into(),
    ])));
    let vm = app.crash_vm();
    assert_eq!(vm.headline, i18n::RU.crash_incomplete);
    assert_eq!(vm.tone, Tone::Warning);
    app.driver_audit = DriverAuditState::Done(Box::new(clean_audit()));
    assert_eq!(app.state_codes().0, "PARTIAL");
    let r = crate::crash_report::build(
        match &app.crash.inventory {
            Some(Ok(i)) => i,
            _ => unreachable!(),
        },
        &[],
        true,
    );
    let txt = crate::crash_report::to_text(&r, true);
    assert!(txt.contains("сбор неполный"), "{txt}");
    assert!(txt.contains("Minidump"));
    // A failed scan keeps its reason in the exported details.
    app.crash.inventory = Some(Err("PowerShell: access denied".into()));
    assert!(
        app.crash_details_text()
            .contains("PowerShell: access denied")
    );
    let _ = std::fs::remove_dir_all(exe.parent().unwrap());
}

#[test]
fn incomplete_driver_audit_card_is_never_green() {
    let mut r = clean_audit();
    r.complete = false;
    let vm = drivers_vm(&r, &i18n::EN);
    match vm {
        DriversVm::Done { overall, alert, .. } => {
            assert_eq!(overall, Tone::Warning);
            let (tone, text, _) = alert.expect("incomplete alert");
            assert_eq!(tone, Tone::Warning);
            assert!(text.contains("incomplete"), "{text}");
        }
        _ => panic!("done expected"),
    }
    assert_eq!(
        driver_verdict_label(&i18n::EN, &r),
        i18n::EN.driver_status_incomplete
    );
}

#[test]
fn rc9_diag_findings_gui_json_txt_zip_share_all_reasons() {
    let (mut app, exe) = app_in("rc9-diag");
    app.include_hardware = false;
    app.crash.inventory = Some(Ok(clean_inventory(Vec::new())));
    app.driver_audit = DriverAuditState::Done(Box::new(clean_audit()));
    app.expc_checks = [
        ("SFC", "ATTENTION"),
        ("DISM", "ATTENTION"),
        ("WHEA", "ERROR"),
        ("VSS Shadow Storage", "ATTENTION"),
    ]
    .into_iter()
    .map(|(key, status)| crate::deep_checks::ExpcCheck {
        key: key.into(),
        status: status.into(),
        detail: format!("{key} confirmed fixture finding"),
    })
    .collect();
    assert_ne!(app.state_codes().0, "OK");
    assert_eq!(app.done_verdict(&i18n::RU).1, Tone::Warning);
    assert_eq!(app.system_state_vm().system.tone, Tone::Warning);
    let reasons = app.state_reasons();
    let (system, hardware) = app.state_codes();
    let mut pkg = SessionPackage::new(exe.join("rc9-evidence"), None);
    pkg.set_states(&system, &hardware);
    pkg.set_state_reasons(reasons.clone());
    let zip = pkg
        .contribute(
            "",
            "TEST",
            "27-10-26",
            vec![EvidenceFile::new("evidence.txt", b"fixture".to_vec())],
        )
        .unwrap();
    for name in ["State_Summary.json", "State_Summary.txt"] {
        let entries = report_package::read_zip(&zip).unwrap();
        let content = String::from_utf8(
            entries
                .iter()
                .find(|e| e.name == name)
                .unwrap()
                .bytes
                .clone(),
        )
        .unwrap();
        for key in ["SFC", "DISM", "WHEA", "VSS"] {
            assert!(content.contains(key), "{name}: {key}");
        }
        assert!(content.contains(&system));
    }
    for key in ["SFC", "DISM", "WHEA", "VSS"] {
        assert!(app.system_state_vm().note.contains(key));
    }
    pkg.set_state_reasons(vec!["new evidence while status unchanged".into()]);
    pkg.refresh_states(&system, &hardware).unwrap();
    let entries = report_package::read_zip(&zip).unwrap();
    assert!(
        String::from_utf8_lossy(
            &entries
                .iter()
                .find(|e| e.name == "State_Summary.json")
                .unwrap()
                .bytes
        )
        .contains("new evidence while status unchanged")
    );
    pkg.finalize().unwrap();
}

#[test]
fn rc9_old_bsod_is_history_and_missing_temperature_is_not_ok() {
    let (mut app, _) = app_in("rc9-history");
    app.driver_audit = DriverAuditState::Done(Box::new(clean_audit()));
    app.expc_checks = ["SFC", "DISM", "WHEA", "VSS"]
        .into_iter()
        .map(|key| crate::deep_checks::ExpcCheck {
            key: key.into(),
            status: "OK".into(),
            detail: "fixture".into(),
        })
        .collect();
    let mut inv = clean_inventory(Vec::new());
    inv.bugchecks.push(crash_dump::BugcheckEvent {
        time: "2020-01-01T00:00:00".into(),
        code: 0x139,
        params: Vec::new(),
        dump_path: None,
        source: crash_dump::BugcheckSource::Wer1001,
    });
    app.crash.inventory = Some(Ok(inv));
    assert_eq!(app.state_codes().0, "HISTORICAL");
    if let Some(Ok(inv)) = &mut app.crash.inventory {
        inv.bugchecks[0].time = local_iso(sysinfo::local_time());
    }
    assert_eq!(app.state_codes().0, "ATTENTION_BSOD");
    app.sensors = Some(sensors::Snapshot::default());
    assert_ne!(app.state_codes().1, "OK");
    assert!(
        app.state_reasons()
            .iter()
            .any(|r| r.contains("CPU TEMPERATURE"))
    );
}
