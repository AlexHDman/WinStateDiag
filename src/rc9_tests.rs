use crate::{deep_checks, driver_audit::*, sensors::*};
#[test]
fn a5_all_codes_retained_and_date_provenance() {
    let mut raw = RawAudit {
        complete: true,
        generated: "2026-10-27T10:00:00".into(),
        ..Default::default()
    };
    for code in [0, 24, 45, 43] {
        raw.devices.push(RawDevice {
            name: format!("device-{code}"),
            pnp_id: format!("TEST\\{code}"),
            error_code: Some(code),
            ..Default::default()
        });
    }
    let report = classify(&raw);
    assert_eq!(report.devices_scanned, 4);
    assert_eq!(report.items.len(), 4);
    assert_eq!(
        report
            .items
            .iter()
            .find(|i| i.pnp_error_code == Some(45))
            .unwrap()
            .status_code(),
        "NOT_PRESENT"
    );
    assert_ne!(
        report
            .items
            .iter()
            .find(|i| i.pnp_error_code == Some(24))
            .unwrap()
            .status_code(),
        "OK"
    );
    assert_eq!(report.overall, Severity::Problem);
    let r = parse_collector_output(
        "META\tdone\t1\nDEV\tMEDIA\tCamera\tUGREEN\tUGREEN\t1\t2026-09-12\toem1.inf\t0\tTrue\tTEST\\1\tsvc\tCIM\t\tDEVPKEY_Device_DriverDate\t2026-12-09\n",
    );
    let report = classify(&r);
    let j = crate::driver_audit::to_json(&report);
    assert!(
        j.contains("2026-09-12")
            && j.contains("2026-12-09")
            && j.contains("DEVPKEY_Device_DriverDate")
    );
}
#[test]
fn rail_single_spike_recovery_and_two_consecutive_failures() {
    let mut r = fixture::rr(
        Provider::LhmInternal,
        HwCategory::Motherboard,
        "NCT",
        "+12V",
        SensorKind::Voltage,
        Some(12.0),
    );
    r.board_mapped = true;
    let mut s = Sampler::default();
    s.add_sample(&[r.clone()], "1");
    r.value = Some(10.5);
    s.add_sample(&[r.clone()], "2");
    assert_eq!(
        summarize(s.sensors()).power_status(),
        PowerStatus::CheckSensor
    );
    r.value = Some(12.0);
    s.add_sample(&[r.clone()], "3");
    assert_eq!(
        summarize(s.sensors()).power_status(),
        PowerStatus::CheckSensor
    );
    r.value = Some(10.5);
    s.add_sample(&[r.clone()], "4");
    s.add_sample(&[r.clone()], "5");
    assert_eq!(summarize(s.sensors()).power_status(), PowerStatus::Critical);
    r.value = None;
    s.add_sample(&[r.clone()], "6");
    r.value = Some(10.5);
    s.add_sample(&[r], "7");
    assert_eq!(
        summarize(s.sensors()).power_status(),
        PowerStatus::CheckSensor
    );
}
#[test]
fn sfc_ru_en_semantics_match_collector_contract() {
    for (text, want) in [
        (
            "There is a system repair pending which requires reboot to complete.",
            "REBOOT_PENDING",
        ),
        (
            "Требуется перезагрузка для завершения восстановления",
            "REBOOT_PENDING",
        ),
        (
            "Windows Resource Protection could not start the repair service.",
            "SERVICE_ERROR",
        ),
        (
            "Не удалось запустить службу восстановления",
            "SERVICE_ERROR",
        ),
        (
            "Windows Resource Protection could not perform the requested operation.",
            "ERROR",
        ),
        (
            "Защита ресурсов Windows не может выполнить запрошенную операцию.",
            "ERROR",
        ),
        ("Verification 100% complete.", "UNKNOWN"),
        (
            "Защита ресурсов Windows не обнаружила нарушений целостности.",
            "CLEAN",
        ),
    ] {
        assert_eq!(deep_checks::sfc_semantic_result(text, false, Some(0)), want);
    }
}
#[test]
fn scm_binary_exact_identity_and_partial_query_evidence() {
    use crate::events::*;
    for name in ["TermService", "ScDeviceEnum"] {
        let hex = name
            .encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .map(|b| format!("{b:02X}"))
            .collect::<String>();
        let e = RawEvent {
            id: 7031,
            data: vec![
                ("param1".into(), "Localized name".into()),
                ("Binary".into(), hex),
            ],
            ..Default::default()
        };
        assert_eq!(scm_service(&e).0, name);
    }
    let (events, _) = parse_collector(
        "WSD_EV_ERROR VSS: access denied\nWSD_EV {\"p\":\"volsnap\",\"id\":36,\"m\":\"user imposed limit\"}\n",
    );
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].provider, "WinStateDiag.CollectionError");
    assert_eq!(
        vss_category(&events[1]),
        "shadow_copies_aborted_storage_limit"
    );
}

#[test]
fn volsnap95_deletion_dependency_is_not_quota_or_power_failure() {
    let e = crate::events::RawEvent {
        provider: "volsnap".into(),
        id: 95,
        message: "oldest shadow copy deleted; later copies marked for delete".into(),
        ..Default::default()
    };
    assert_eq!(
        crate::events::vss_category(&e),
        "shadow_copy_delete_dependency"
    );
}

#[test]
fn rc10_execution_completion_and_true_progress() {
    use crate::diag_state::execution_status as status;
    assert_eq!(status("OK", "OK", &[]), "COMPLETED");
    assert_eq!(status("ATTENTION_DIAG", "OK", &[]), "COMPLETED");
    assert_eq!(
        status("ATTENTION_DIAG", "OK", &["Step 07 [COVERAGE/ERROR]".into()]),
        "COMPLETED_WITH_ERRORS"
    );
    assert_eq!(status("CANCELLED", "OK", &[]), "CANCELLED");
    assert_eq!(status("ERROR", "OK", &[]), "ERROR");
    assert_eq!(
        crate::details::state_of_status("HISTORICAL"),
        crate::details::StageState::Info
    );
    assert!(
        progress_text("PROGRESS\tDevice metadata\t25\t297\t3.1")
            .unwrap()
            .contains("25/297")
    );
    assert!(progress_text("PROGRESS\tDevice metadata\t298\t297\t3.1").is_none());
    assert!(progress_text("PROGRESS\tDevice metadata\t0\t0\tNaN").is_none());
}

#[test]
fn v1210_package_error_does_not_create_or_hide_a_pnp_problem() {
    let mut raw = RawAudit {
        complete: true,
        ..Default::default()
    };
    raw.devices.push(RawDevice {
        name: "Network".into(),
        class: "Net".into(),
        pnp_id: "TEST\\NET".into(),
        error_code: Some(0),
        pnp_source: "Win32_PnPEntity".into(),
        ..Default::default()
    });
    raw.errors.push("Get-WindowsDriver: code=0xC0040009; category=DISMAPI_E_LOGGING_DISABLED; scope=DRIVER_PACKAGE_COLLECTION".into());
    let healthy = classify(&raw);
    assert_eq!(healthy.overall, Severity::Ok);
    assert_eq!(healthy.package_inventory_status(), "LIMITED");
    assert_eq!(healthy.verdict_code(), "INCOMPLETE");
    let json = deep_checks::json::parse(&crate::driver_audit::to_json(&healthy)).unwrap();
    assert_eq!(
        json.get("package_inventory_status").unwrap().as_str(),
        Some("LIMITED")
    );
    assert!(to_text(&healthy).contains("0xC0040009"));
    raw.devices[0].error_code = Some(43);
    let failed = classify(&raw);
    assert_eq!(failed.overall, Severity::Problem);
    assert_eq!(failed.package_inventory_status(), "LIMITED");
}
#[test]
fn v1210_execution_and_coverage_are_orthogonal() {
    use crate::diag_state::*;
    let gap = vec!["A5 [COVERAGE]: Get-WindowsDriver: code=0xC0040009".into()];
    assert_eq!(execution_status("PARTIAL", "OK", &gap), "COMPLETED");
    assert_eq!(coverage_status("PARTIAL", "OK", &gap), "LIMITED");
    assert_eq!(execution_status("ATTENTION_DIAG", "OK", &gap), "COMPLETED");
    assert_eq!(findings_status("ATTENTION_DIAG", "OK"), "ATTENTION");
    let failure = vec!["Step 07 [COVERAGE/ERROR]: exception".into()];
    assert_eq!(
        execution_status("PARTIAL", "OK", &failure),
        "COMPLETED_WITH_ERRORS"
    );
    assert_eq!(execution_status("CANCELLED", "OK", &failure), "CANCELLED");
}
