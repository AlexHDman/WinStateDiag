//! v1.0 regression tests (app level): sensor matrix, EXPC focus, Details
//! windows, stage-local evidence, cross-module consistency, system vs
//! hardware state, crash progress / installer states, Disk Details, RAM and
//! release-script contracts.

use super::*;
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
    let src = include_str!("app.rs");
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
    assert!(s.contains("$version = if ($Matches[3] -eq '0')"));
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
        attributes: Vec::new(),
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
