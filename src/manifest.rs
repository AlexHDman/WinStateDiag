//! v0.4.0: `manifest.json` — a small, versioned, machine-readable index of
//! the final report ZIP (future stable hand-off to tools such as WinRepair
//! Pro; this is NOT that integration).
//!
//! Contract (schema 1.0, backwards-extensible: readers must ignore unknown
//! fields; new fields are only ever added):
//!
//! ```text
//! {
//!   "schema_version": "1.0",
//!   "producer": "WinStateDiag",
//!   "producer_version": "0.4.0",
//!   "package": "<report>.zip",
//!   "computer_name": "...",
//!   "created_at": "YYYY-MM-DDTHH:MM:SS",          (local time)
//!   "windows": { "product": "...", "build": "..." },
//!   "modules": [
//!     { "name": "expc_diagnostic" | "hardware_report" | "driver_audit"
//!               | "ssd_benchmark",
//!       "status": "completed" | "cancelled",
//!       "evidence": ["<file name in this ZIP>", ...],
//!       "checks": [                                (expc_diagnostic only)
//!         { "check": "SFC" | "DISM" | "CHKDSK",
//!           "execution_status": "completed" | "skipped",
//!           "result_status": "OK" | "ATTENTION" | "ERROR" | "UNKNOWN" | "SKIPPED",
//!           "finding": "<short finding as the evidence states it>",
//!           "source_file": "<EXPC evidence file name>",
//!           "source": "expc_json.checks" | "expc_txt.result_line" | "expc_txt.key_output",
//!           "timestamp": "<EXPC GeneratedAt>" | null } ] } ],
//!   "shared_files": ["ssd_benchmark_history.log", ...]
//! }
//! ```
//!
//! Only file NAMES inside the ZIP are listed — never local/temporary paths,
//! never hardware serials. Output is deterministic for the same input
//! (fixed field order, sorted file lists, `\n` line ends, UTF-8 without BOM).

use crate::deep_checks::{self, CheckResult, json};
use crate::report_package::{EvidenceFile, EvidenceModule, USER_CANCELLED};
use crate::ui::sysinfo::LocalTime;

pub const MANIFEST_FILE: &str = "manifest.json";
pub const SCHEMA_VERSION: &str = "1.0";
pub const PRODUCER: &str = "WinStateDiag";
/// The canonical application version (Cargo.toml `[package] version`).
pub const PRODUCER_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Clone, Debug)]
pub struct ManifestContext {
    pub producer_version: String,
    pub package: String,
    pub computer_name: String,
    pub created_at: LocalTime,
    pub windows_product: String,
    pub windows_build: String,
}

fn module_name(m: EvidenceModule) -> &'static str {
    match m {
        EvidenceModule::Expc => "expc_diagnostic",
        EvidenceModule::Hardware => "hardware_report",
        EvidenceModule::DriverAudit => "driver_audit",
        EvidenceModule::SsdBenchmark => "ssd_benchmark",
    }
}

/// Module of an evidence file name (cancelled files included).
fn module_of(name: &str) -> Option<EvidenceModule> {
    EvidenceModule::of_file_name(&name.replace(USER_CANCELLED, ""))
}

fn iso(t: LocalTime) -> String {
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        t.year, t.month, t.day, t.hour, t.minute, t.second
    )
}

fn str_list(items: &[&str], indent: &str) -> String {
    if items.is_empty() {
        return "[]".into();
    }
    let inner: Vec<String> = items
        .iter()
        .map(|s| format!("{indent}  {}", json::string(s)))
        .collect();
    format!("[\n{}\n{indent}]", inner.join(",\n"))
}

/// Builds `manifest.json` for the ZIP holding `entries` (the manifest
/// itself is never listed).
pub fn build(ctx: &ManifestContext, entries: &[EvidenceFile]) -> Vec<u8> {
    let mut names: Vec<&str> = entries
        .iter()
        .map(|e| e.name.as_str())
        .filter(|n| *n != MANIFEST_FILE)
        .collect();
    names.sort_unstable();
    names.dedup();

    let order = [
        EvidenceModule::Expc,
        EvidenceModule::Hardware,
        EvidenceModule::DriverAudit,
        EvidenceModule::SsdBenchmark,
    ];
    let mut modules: Vec<String> = Vec::new();
    for m in order {
        let files: Vec<&str> = names
            .iter()
            .copied()
            .filter(|n| module_of(n) == Some(m))
            .collect();
        if files.is_empty() {
            continue;
        }
        let completed = files.iter().any(|n| !n.contains(USER_CANCELLED));
        let mut fields = vec![
            format!("      \"name\": {}", json::string(module_name(m))),
            format!(
                "      \"status\": {}",
                json::string(if completed { "completed" } else { "cancelled" })
            ),
            format!("      \"evidence\": {}", str_list(&files, "      ")),
        ];
        if m == EvidenceModule::Expc {
            let run = deep_checks::from_evidence_files(
                entries
                    .iter()
                    .filter(|e| files.contains(&e.name.as_str()))
                    .map(|e| (e.name.as_str(), e.bytes.as_slice())),
            );
            let mut checks: Vec<String> = Vec::new();
            if let Some(run) = run {
                for o in &run.outcomes {
                    let exec = if o.result == CheckResult::Skipped {
                        "skipped"
                    } else {
                        "completed"
                    };
                    let ts = run
                        .generated_at
                        .as_deref()
                        .map(json::string)
                        .unwrap_or_else(|| "null".into());
                    checks.push(format!(
                        "        {{\n          \"check\": {},\n          \"execution_status\": {},\n          \"result_status\": {},\n          \"finding\": {},\n          \"source_file\": {},\n          \"source\": {},\n          \"timestamp\": {}\n        }}",
                        json::string(o.check.key()),
                        json::string(exec),
                        json::string(o.result.as_str()),
                        json::string(&o.detail),
                        json::string(&run.source_file),
                        json::string(o.source.as_str()),
                        ts
                    ));
                }
            }
            fields.push(if checks.is_empty() {
                "      \"checks\": []".into()
            } else {
                format!("      \"checks\": [\n{}\n      ]", checks.join(",\n"))
            });
        }
        modules.push(format!("    {{\n{}\n    }}", fields.join(",\n")));
    }
    let shared: Vec<&str> = names
        .iter()
        .copied()
        .filter(|n| module_of(n).is_none())
        .collect();

    let mut out = String::new();
    out.push_str("{\n");
    out.push_str(&format!(
        "  \"schema_version\": {},\n",
        json::string(SCHEMA_VERSION)
    ));
    out.push_str(&format!("  \"producer\": {},\n", json::string(PRODUCER)));
    out.push_str(&format!(
        "  \"producer_version\": {},\n",
        json::string(&ctx.producer_version)
    ));
    out.push_str(&format!("  \"package\": {},\n", json::string(&ctx.package)));
    out.push_str(&format!(
        "  \"computer_name\": {},\n",
        json::string(&ctx.computer_name)
    ));
    out.push_str(&format!(
        "  \"created_at\": {},\n",
        json::string(&iso(ctx.created_at))
    ));
    out.push_str(&format!(
        "  \"windows\": {{\n    \"product\": {},\n    \"build\": {}\n  }},\n",
        json::string(&ctx.windows_product),
        json::string(&ctx.windows_build)
    ));
    if modules.is_empty() {
        out.push_str("  \"modules\": [],\n");
    } else {
        out.push_str(&format!(
            "  \"modules\": [\n{}\n  ],\n",
            modules.join(",\n")
        ));
    }
    out.push_str(&format!(
        "  \"shared_files\": {}\n",
        str_list(&shared, "  ")
    ));
    out.push_str("}\n");
    out.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deep_checks::json::{self as j, Value};

    fn ctx() -> ManifestContext {
        ManifestContext {
            producer_version: PRODUCER_VERSION.to_string(),
            package: "Алексей - MSI - 28-09-26.zip".into(),
            computer_name: "MSI".into(),
            created_at: LocalTime {
                year: 2026,
                month: 9,
                day: 28,
                hour: 10,
                minute: 35,
                second: 7,
            },
            windows_product: "Windows 11 Pro".into(),
            windows_build: "26200.7462".into(),
        }
    }

    fn expc_json() -> Vec<u8> {
        let mut b = vec![0xEF, 0xBB, 0xBF];
        b.extend_from_slice(
            "{\"GeneratedAt\": \"2026-09-28T10:30:00+03:00\", \"TxtPath\": \"C:\\\\Users\\\\u\\\\AppData\\\\Local\\\\Temp\\\\WinStateDiag\\\\x.txt\", \"Checks\": [{\"Check\": \"DISM\", \"Status\": \"ATTENTION\", \"Detail\": \"DISM сообщает: хранилище компонентов повреждено, но подлежит восстановлению.\"}, {\"Check\": \"SFC\", \"Status\": \"OK\", \"Detail\": \"ok\"}]}"
                .as_bytes(),
        );
        b
    }

    fn entries() -> Vec<EvidenceFile> {
        vec![
            EvidenceFile::new("SSD_Benchmark_28.09.26_10-40.txt", b"ssd".to_vec()),
            EvidenceFile::new("EXPC_Diagnostic_28.09.26_10-30.json", expc_json()),
            EvidenceFile::new("EXPC_Diagnostic_28.09.26_10-30.txt", b"txt".to_vec()),
            EvidenceFile::new(
                "Hardware_28.09.26_10-31.json",
                b"{\"SerialNumber\": \"S6XNNS0W123456\", \"BaseBoardSerial\": \"MB-SERIAL-999\"}"
                    .to_vec(),
            ),
            EvidenceFile::new("DriverAudit_28-09-26_10-32-00.json", b"{}".to_vec()),
            EvidenceFile::new("DriverAudit_28-09-26_10-32-00.txt", b"da".to_vec()),
            EvidenceFile::new("ssd_benchmark_history.log", b"1|x|1|1|1|1|1|1\n".to_vec()),
            EvidenceFile::new("GRAPHIC_REPORT.md", b"# g".to_vec()),
            EvidenceFile::new(MANIFEST_FILE, b"stale".to_vec()),
        ]
    }

    fn parsed(bytes: &[u8]) -> Value {
        j::parse(std::str::from_utf8(bytes).expect("UTF-8")).expect("valid JSON")
    }

    fn s<'a>(v: &'a Value, k: &str) -> &'a str {
        v.get(k)
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("{k}"))
    }

    #[test]
    fn version_0_4_0_source_contract() {
        // One canonical version: Cargo.toml → Cargo.lock → EXE metadata
        // (winresource, build.rs) → title (env!) → manifest → release
        // script/folder (read from Cargo.toml).
        let toml = include_str!("../Cargo.toml").replace("\r\n", "\n");
        let lock = include_str!("../Cargo.lock").replace("\r\n", "\n");
        let package = toml.split("[dependencies]").next().unwrap();
        assert!(package.contains("name = \"win_state_diag\""));
        assert!(package.contains("\nversion = \"0.4.0\"\n"), "{package}");
        assert!(lock.contains("name = \"win_state_diag\"\nversion = \"0.4.0\"\n"));
        assert_eq!(PRODUCER_VERSION, "0.4.0");
        let main = include_str!("main.rs").replace("\r\n", "\n");
        assert!(main.contains("pub const APP_VERSION: &str = env!(\"CARGO_PKG_VERSION\");"));
        assert!(main.contains("format!(\"WinStateDiag — v{APP_VERSION}\")"));
        let release = include_str!("../scripts/make_release.ps1");
        assert!(release.contains("Join-Path $root 'Cargo.toml'"));
        assert!(release.contains("\"WinStateDiag-v$version\""));
    }

    #[test]
    fn manifest_is_valid_versioned_utf8_json() {
        let bytes = build(&ctx(), &entries());
        assert!(!bytes.starts_with(&[0xEF, 0xBB, 0xBF]), "no BOM");
        let v = parsed(&bytes);
        assert_eq!(s(&v, "schema_version"), "1.0");
        assert_eq!(s(&v, "producer"), "WinStateDiag");
        assert_eq!(s(&v, "producer_version"), "0.4.0");
        assert_eq!(s(&v, "package"), "Алексей - MSI - 28-09-26.zip");
        assert_eq!(s(&v, "computer_name"), "MSI");
        assert_eq!(s(&v, "created_at"), "2026-09-28T10:35:07");
        let w = v.get("windows").unwrap();
        assert_eq!(s(w, "product"), "Windows 11 Pro");
        assert_eq!(s(w, "build"), "26200.7462");
    }

    #[test]
    fn manifest_maps_modules_to_their_evidence_and_deep_check_results() {
        let v = parsed(&build(&ctx(), &entries()));
        let modules = v.get("modules").unwrap().as_arr().unwrap();
        let names: Vec<&str> = modules.iter().map(|m| s(m, "name")).collect();
        assert_eq!(
            names,
            [
                "expc_diagnostic",
                "hardware_report",
                "driver_audit",
                "ssd_benchmark"
            ]
        );
        let ev = |i: usize| -> Vec<&str> {
            modules[i]
                .get("evidence")
                .unwrap()
                .as_arr()
                .unwrap()
                .iter()
                .map(|x| x.as_str().unwrap())
                .collect()
        };
        assert_eq!(
            ev(0),
            [
                "EXPC_Diagnostic_28.09.26_10-30.json",
                "EXPC_Diagnostic_28.09.26_10-30.txt"
            ]
        );
        assert_eq!(ev(1), ["Hardware_28.09.26_10-31.json"]);
        assert_eq!(ev(2).len(), 2);
        assert_eq!(ev(3), ["SSD_Benchmark_28.09.26_10-40.txt"]);
        assert!(modules.iter().all(|m| s(m, "status") == "completed"));
        let checks = modules[0].get("checks").unwrap().as_arr().unwrap();
        assert_eq!(checks.len(), 2);
        let dism = checks.iter().find(|c| s(c, "check") == "DISM").unwrap();
        assert_eq!(s(dism, "execution_status"), "completed");
        assert_eq!(s(dism, "result_status"), "ATTENTION");
        assert!(s(dism, "finding").contains("подлежит восстановлению"));
        assert_eq!(
            s(dism, "source_file"),
            "EXPC_Diagnostic_28.09.26_10-30.json"
        );
        assert_eq!(s(dism, "source"), "expc_json.checks");
        assert_eq!(s(dism, "timestamp"), "2026-09-28T10:30:00+03:00");
        // Shared files, and never the manifest itself.
        let shared: Vec<&str> = v
            .get("shared_files")
            .unwrap()
            .as_arr()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap())
            .collect();
        assert_eq!(shared, ["GRAPHIC_REPORT.md", "ssd_benchmark_history.log"]);
    }

    #[test]
    fn manifest_has_no_local_paths_secrets_or_serials_and_is_deterministic() {
        let a = build(&ctx(), &entries());
        let mut shuffled = entries();
        shuffled.reverse();
        assert_eq!(a, build(&ctx(), &shuffled), "input order does not matter");
        let text = String::from_utf8(a).unwrap();
        for bad in [
            ":\\",
            "AppData",
            "Temp",
            "/tmp",
            "S6XNNS0W123456",
            "MB-SERIAL-999",
            "stale",
            "TxtPath",
        ] {
            assert!(!text.contains(bad), "{bad} in manifest");
        }
        assert!(!text.contains("\"manifest.json\""));
    }

    #[test]
    fn cancelled_only_module_is_marked_cancelled() {
        let files = vec![
            EvidenceFile::new(
                "EXPC_Diagnostic_28.09.26_10-30_USER_CANCELLED.txt",
                b"x".to_vec(),
            ),
            EvidenceFile::new(
                "EXPC_Diagnostic_USER_CANCELLED_28.09.26_10-31-00.txt",
                b"STATUS=USER_CANCELLED".to_vec(),
            ),
        ];
        let v = parsed(&build(&ctx(), &files));
        let modules = v.get("modules").unwrap().as_arr().unwrap();
        assert_eq!(modules.len(), 1);
        assert_eq!(s(&modules[0], "status"), "cancelled");
        assert_eq!(modules[0].get("checks").unwrap().as_arr().unwrap().len(), 0);
        let empty = parsed(&build(&ctx(), &[]));
        assert_eq!(empty.get("modules").unwrap().as_arr().unwrap().len(), 0);
    }
}
