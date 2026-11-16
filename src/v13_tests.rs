//! Synthetic regressions and separately invoked private archive replay. No native repairs.
use crate::{
    deep_checks::json::{self, Value},
    events,
    manifest::ManifestContext,
    report_package::EvidenceFile,
    report_v3, winsxs,
};
fn context() -> ManifestContext {
    ManifestContext {
        producer_version: crate::APP_VERSION.into(),
        package: "test".into(),
        computer_name: "SYNTHETIC".into(),
        created_at: crate::ui::sysinfo::local_time(),
        windows_product: "Test Windows".into(),
        windows_build: "00000".into(),
        system_state: Some("PARTIAL".into()),
        hardware_state: Some("NO_DATA".into()),
        session: None,
    }
}
#[test]
fn v3_additive_report_preserves_unknown_repair_and_version() {
    let files=vec![EvidenceFile::new("EXPC_test.json",br#"{"GeneratedAt":"2026-11-04T12:00:00","Checks":[{"Check":"Defender","Status":"UNKNOWN","Detail":"coverage unavailable"}]}"#.to_vec()),EvidenceFile::new("Repair_test.json",br#"{"repair_id":"synthetic","status":"FAILED","check":"DISM","message":"source missing"}"#.to_vec())];
    let mut files = files;
    files.push(EvidenceFile::new("Hardware_synthetic.json",br#"{"Cpu":{"Models":["TEST CPU"]},"Ram":{"Total":"32 GB"},"Storage":{"Disks":[{"Model":"TEST SSD"}]}}"#.to_vec()));
    let reports = report_v3::build(&context(), &files).unwrap();
    let text = String::from_utf8_lossy(&reports[0].bytes);
    assert!(text.contains("WinDiag: 1.6\n"));
    assert!(text.contains("UNKNOWN"));
    assert!(text.contains("FAILED"));
    assert!(!text.contains("1.6.0"));
    let v = json::parse(&String::from_utf8_lossy(&reports[1].bytes)).unwrap();
    assert_eq!(v.get("service_closed"), Some(&Value::Bool(false)));
    assert!(text.contains("TEST CPU"));
    assert!(text.contains("32 GB"));
    assert!(text.contains("TEST SSD"));
    assert_eq!(files.len(), 3);
}
#[test]
fn incomplete_history_is_partial_not_an_incident_or_resolution() {
    let a = events::Aggregate {
        provider: "WinStateDiag.HistoryCoverage".into(),
        latest: vec![r#"{"Complete":false,"Returned":0}"#.into()],
        ..Default::default()
    };
    let text = events::to_json(&[a], None, "2026-11-04T12:00:00");
    let v = json::parse(&text).unwrap();
    assert_eq!(v.get("status").and_then(Value::as_str), Some("PARTIAL"));
    assert_eq!(v.get("aggregate_count"), Some(&Value::Num(0.0)));
    assert_eq!(
        v.get("absence_proves_resolution"),
        Some(&Value::Bool(false))
    );
}
#[test]
fn public_version_contract() {
    assert_eq!(crate::APP_VERSION, "1.6");
    assert_eq!(crate::manifest::PRODUCER_VERSION, "1.6");
    assert_eq!(crate::APP_VERSION.split('.').count(), 2);
}
#[test]
#[ignore = "Private ZIP replay requires WSD_FIELD_ROOT; no private fixtures are tracked"]
fn field_archive_replay() {
    let root = std::path::PathBuf::from(
        std::env::var("WSD_FIELD_ROOT").expect("explicit private field directory"),
    );
    let mut count = 0;
    let mut servicing = false;
    for e in std::fs::read_dir(root).unwrap() {
        let path = e.unwrap().path();
        if path
            .extension()
            .is_none_or(|s| !s.eq_ignore_ascii_case("zip"))
        {
            continue;
        }
        let files = crate::report_package::read_zip(&path).unwrap();
        count += 1;
        let a = winsxs::analyze(&files);
        assert!(json::parse(&a.json()).is_some());
        let reports = report_v3::build(&context(), &files).expect("EXPC report");
        assert!(json::parse(&String::from_utf8_lossy(&reports[1].bytes)).is_some());
        if a.detected == Some(3153) {
            servicing = true;
            assert_eq!(a.repaired, Some(0));
            assert!(!a.findings.is_empty());
            assert!(a.repair_proof.is_empty());
            println!(
                "Current component evidence: detected=3153 repaired=0 components={}",
                a.findings.len()
            );
        }
    }
    assert_eq!(count, 6);
    assert!(servicing);
    println!(
        "PRIVATE_REPLAY: 6 CRC/EXPC/WinSxS/V3 archives PASS; older independent ZIP not available"
    );
}

#[test]
fn vss_summary_does_not_claim_backup_or_dump_copy_identifiers() {
    let text = crate::vss_repair::summary(
        r#"{"Status":"SUCCESS_VERIFIED","After":{"Rows":[{"For":"C:","On":"D:","Maximum":"123","Used":"12","Free":"200","CopyIds":["PRIVATE-COPY-ID"]}]}}"#,
    );
    assert!(text.contains("SUCCESS_VERIFIED"));
    assert!(text.contains("UNKNOWN"));
    assert!(!text.contains("PRIVATE-COPY-ID"));
}

#[test]
fn generic_absent_is_compact_but_pnp_faults_survive() {
    use crate::driver_audit::*;
    let raw = RawAudit {
        complete: true,
        devices: (0..20)
            .map(|n| RawDevice {
                name: "Generic software device".into(),
                pnp_id: format!("SWD\\SYNTHETIC{n}"),
                pnp_source: "CfgMgr32.NOT_PRESENT".into(),
                error_code: Some(45),
                ..Default::default()
            })
            .collect(),
        ..Default::default()
    };
    let report = classify(&raw);
    assert_eq!(report.devices_scanned, 20);
    assert_eq!(
        report.items.iter().filter(|i| generic_absent(i)).count(),
        20
    );
    let json = to_json(&report);
    assert!(json.contains("SYNTHETIC19"));
    assert!(!to_text(&report).contains("SYNTHETIC19"));
    let mut fault = raw;
    fault.devices[0].error_code = Some(10);
    fault.devices[0].pnp_source = "CfgMgr32.PRESENT".into();
    let report = classify(&fault);
    assert_eq!(report.overall, Severity::Problem);
    assert_eq!(
        report.items.iter().filter(|i| generic_absent(i)).count(),
        19
    );
}
