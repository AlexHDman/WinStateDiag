#[cfg(all(test, windows))]
mod native_tests {
    use crate::deep_checks::json;
    use crate::hardware_support::*;
    use std::path::PathBuf;
    #[test]
    #[ignore = "Explicit read-only Windows hardware smoke, no UAC or install"]
    fn ordinary_reader_chain() {
        let (tx, _) = std::sync::mpsc::channel();
        let d = run(Operation::Detect, &std::env::temp_dir(), &tx).expect("actual detector");
        let evidence = std::env::var_os("WSD_HW_EVIDENCE")
            .map(PathBuf::from)
            .expect("evidence directory");
        std::fs::write(evidence.join("ordinary-dependency.json"), &d.raw).unwrap();
        assert!(!d.state.is_empty());
        let admin = json::parse(&d.raw).and_then(|v| v.get("reader_admin").cloned())
            == Some(json::Value::Bool(true));
        assert!(
            !admin,
            "This test is intentionally restricted to an ordinary token"
        );
        let (snap, raw) = crate::sensors::collect_raw(
            "powershell.exe",
            &std::env::temp_dir().join("WinStateDiag"),
            3,
            1000,
        );
        std::fs::write(evidence.join("ordinary-sensors.raw.txt"), raw.as_bytes()).unwrap();
        std::fs::write(
            evidence.join("ordinary-sensors.json"),
            crate::sensors::to_json(&snap),
        )
        .unwrap();
        assert!(
            snap.hardware_metadata.is_some(),
            "reader did not complete provenance/cleanup: {raw}"
        );
        assert!(
            !raw.contains("driver not installed"),
            "do not infer missing driver from access denied"
        );
        assert!(
            snap.sensors.iter().any(|s| s.value.is_finite()),
            "no accessible sensor reached consumer"
        );
    }
}
