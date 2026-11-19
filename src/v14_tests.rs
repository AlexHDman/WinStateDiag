//! Synthetic regression evidence only; no Windows repair is executed.
use crate::{
    deep_checks::{self, ExpcCheck},
    diag_state,
};
#[test]
fn sfc_final_conflicts_unknown_and_nonfinal_incomplete() {
    let clean = "Windows Resource Protection did not find any integrity violations.";
    assert_eq!(
        deep_checks::sfc_classification(clean, false, Some(0), true),
        "PASS"
    );
    assert_eq!(
        deep_checks::sfc_classification(clean, true, Some(0), true),
        "UNKNOWN"
    );
    assert_eq!(
        deep_checks::sfc_classification("Verification 100% complete.", false, Some(0), true),
        "UNKNOWN"
    );
    assert_eq!(
        deep_checks::sfc_classification(clean, false, Some(0), false),
        "INCOMPLETE"
    );
    assert_eq!(
        deep_checks::sfc_classification(clean, false, Some(5), true),
        "EXECUTION_FAILED"
    );
    assert_eq!(
        deep_checks::sfc_classification(
            "Windows Resource Protection found integrity violations.",
            false,
            Some(0),
            true
        ),
        "ATTENTION"
    );
    assert_eq!(
        deep_checks::sfc_classification(
            "2026-11-01 10:00:00 CBS repair pending reboot",
            false,
            Some(0),
            true
        ),
        "UNKNOWN"
    );
}
#[test]
fn repair_success_does_not_poison_completed_diagnostics() {
    let mut checks: Vec<_> = ["SFC", "DISM", "WHEA", "VSS"]
        .into_iter()
        .map(|k| ExpcCheck {
            key: k.into(),
            status: "OK".into(),
            detail: "synthetic".into(),
        })
        .collect();
    checks.push(ExpcCheck {
        key: "Repair SFC".into(),
        status: "REPAIR_SUCCESS".into(),
        detail: "SUCCESS_VERIFIED".into(),
    });
    let summary = diag_state::aggregate("OK", &checks);
    assert_eq!(summary.code, "OK");
    assert_eq!(
        diag_state::execution_status(&summary.code, "OK", &summary.reasons),
        "COMPLETED"
    );
    assert_eq!(
        diag_state::repair_status(&summary.reasons),
        "REPAIR_SUCCESS"
    );
    assert!(!diag_state::user_summary(&summary.code, "OK", &summary.reasons).contains("Ошибка"));
    checks.last_mut().unwrap().status = "VERIFICATION_FAILED".into();
    let summary = diag_state::aggregate("OK", &checks);
    assert_eq!(
        diag_state::execution_status(&summary.code, "OK", &summary.reasons),
        "COMPLETED"
    );
    assert!(
        diag_state::user_summary(&summary.code, "OK", &summary.reasons)
            .contains("Ошибка восстановления")
    );
    checks[0].status = "ERROR".into();
    let summary = diag_state::aggregate("OK", &checks);
    assert_eq!(
        diag_state::execution_status(&summary.code, "OK", &summary.reasons),
        "COMPLETED_WITH_ERRORS"
    );
}
#[test]
fn durable_history_restart_incomplete_and_other_computer_excluded() {
    use crate::{repair, repair_history};
    use std::fs;
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target/v14-history")
        .join(format!("{}-{}", std::process::id(), repair::operation_id()));
    let primary = root.join("records/op");
    let fallback = root.join("fallback/op");
    let (dir, warning) = repair_history::directory(&primary, &fallback).unwrap();
    assert!(warning.is_none());
    let before = deep_checks::classify_output(
        deep_checks::DeepCheck::Sfc,
        "Windows Resource Protection found integrity violations.",
        Some(0),
    );
    let plan = repair::Plan {
        check: deep_checks::DeepCheck::Sfc,
        drive: "C:".into(),
        before: deep_checks::DeepCheckOutcome {
            check: deep_checks::DeepCheck::Sfc,
            result: before,
            detail: "INTEGRITY_VIOLATIONS".into(),
            source: deep_checks::ResultSource::ExpcJson,
        },
        source: None,
        online_scan: false,
    };
    repair_history::start(&dir, "SYNTHETIC-PC", &plan, true).unwrap();
    fs::write(dir.join("stdout.bin"), [0xff, 0xfe, 0x41, 0]).unwrap();
    let roots = [primary.parent().unwrap().to_owned()];
    let files = repair_history::collect(&roots, "SYNTHETIC-PC");
    assert!(
        files
            .iter()
            .any(|f| f.name.ends_with("stdout.bin") && f.bytes == [0xff, 0xfe, 0x41, 0])
    );
    assert!(files.iter().any(|f| f.name.ends_with("_recovered.json")
        && String::from_utf8_lossy(&f.bytes).contains("RESULT_UNKNOWN")));
    assert!(repair_history::collect(&roots, "OTHER-PC").is_empty());
    fs::write(dir.join("result-op.json"),r#"{"repair_id":"op","check":"SFC","status":"SUCCESS_VERIFIED","repair_status":"REPAIR_SUCCESS"}"#).unwrap();
    let files = repair_history::collect(&roots, "SYNTHETIC-PC");
    assert!(files.iter().any(|f| f.name == "Repair_op.json"));
    assert!(!files.iter().any(|f| f.name.ends_with("_recovered.json")));
    let zip = crate::report_package::build_zip(&files, crate::ui::sysinfo::local_time()).unwrap();
    let restored = crate::report_package::parse_zip(&zip).unwrap();
    assert_eq!(restored.len(), files.len());
    for f in &files {
        assert!(
            restored
                .iter()
                .any(|r| r.name == f.name && r.bytes == f.bytes)
        );
    }

    let blocked = root.join("file");
    fs::write(&blocked, "blocked").unwrap();
    let (_, warning) = repair_history::directory(&blocked.join("op"), &fallback).unwrap();
    assert!(warning.is_some());
    assert!(repair_history::directory(&blocked.join("op2"), &blocked.join("op3")).is_err());
}

#[test]
fn wu_driver_update_requires_same_identity_and_later_success() {
    use crate::events::{RawEvent, wu_failure_resolved};
    let event = |id, time: &str, guid: &str| RawEvent {
        provider: "Microsoft-Windows-WindowsUpdateClient".into(),
        id,
        time: time.into(),
        data: vec![
            ("updateGuid".into(), guid.into()),
            (
                "updateTitle".into(),
                "Microsoft - AudioProcessingObject - Synthetic".into(),
            ),
            ("errorCode".into(), "0x80240017".into()),
        ],
        ..Default::default()
    };
    let failure = event(20, "2026-11-07T10:00:00", "synthetic-a");
    assert_eq!(
        wu_failure_resolved(&failure, &[event(19, "2026-11-07T10:01:00", "synthetic-b")]),
        Some(false)
    );
    assert_eq!(
        wu_failure_resolved(&failure, &[event(19, "2026-11-07T10:01:00", "synthetic-a")]),
        Some(true)
    );
    assert_eq!(
        wu_failure_resolved(&failure, &[event(19, "2026-11-07T09:00:00", "synthetic-a")]),
        Some(false)
    );
}
#[test]
fn report_v3_pass_action_and_mode_are_concrete() {
    use crate::{deep_checks::json, manifest::ManifestContext, report_package::EvidenceFile};
    let ctx = ManifestContext {
        producer_version: crate::APP_VERSION.into(),
        package: "test".into(),
        computer_name: "SYNTHETIC".into(),
        created_at: crate::ui::sysinfo::local_time(),
        windows_product: "Test".into(),
        windows_build: "0".into(),
        system_state: Some("OK".into()),
        hardware_state: Some("OK".into()),
        session: None,
    };
    let files=vec![EvidenceFile::new("EXPC_test.json",br#"{"GeneratedAt":"2026-11-07T12:00:00","Checks":[{"Check":"SFC","Status":"OK","Detail":"clean"},{"Check":"DISM","Status":"UNKNOWN","Detail":"Final result missing"}]}"#.to_vec())];
    let reports = crate::report_v3::build(&ctx, &files).unwrap();
    let text = String::from_utf8_lossy(&reports[0].bytes);
    assert!(text.contains("Не требуется"));
    assert!(text.contains("READ-ONLY"));
    assert!(!text.contains("Наблюдать; учитывать охват"));
    assert!(json::parse(&String::from_utf8_lossy(&reports[1].bytes)).is_some());
}
