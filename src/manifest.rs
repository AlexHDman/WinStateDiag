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
//!   "producer_version": "<Cargo package version>",
//!   "package": "<report>.zip",
//!   "computer_name": "...",
//!   "created_at": "YYYY-MM-DDTHH:MM:SS",          (local time)
//!   "windows": { "product": "...", "build": "..." },
//!   "modules": [
//!     { "name": "expc_diagnostic" | "hardware_report" | "driver_audit"
//!               | "ssd_benchmark" | "nvme_health" | "storage_correlation",
//!       "status": "completed" | "cancelled",
//!       "evidence": ["<file name in this ZIP>", ...],
//!       "latest_evidence": ["<files of the newest completed run>", ...],
//!                       (v0.4.2, additive: one package per PC and date
//!                        keeps every same-day run; this names the run a
//!                        reader should interpret as the current result)
//!       "checks": [                                (expc_diagnostic only)
//!         { "check": "SFC" | "DISM" | "CHKDSK",
//!           "execution_status": "completed" | "skipped",
//!           "result_status": "OK" | "ATTENTION" | "ERROR" | "UNKNOWN" | "SKIPPED",
//!           "finding": "<short finding as the evidence states it>",
//!           "source_file": "<EXPC evidence file name>",
//!           "source": "expc_json.checks" | "expc_txt.result_line" | "expc_txt.key_output",
//!           "timestamp": "<EXPC GeneratedAt>" | null } ],
//!       "disks": [   (ssd_benchmark, nvme_health, storage_correlation; additive)
//!         { "disk_key": "<FNV-1a of the physical identity>",
//!           "physical_disk_index": n | null, "model": "...",
//!           "status": "<latest run: stability / health status / state>",
//!           "evidence": [...this disk's files...],
//!           "latest_evidence": [...this disk's newest run...] } ] } ],
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
        EvidenceModule::NvmeHealth => "nvme_health",
        EvidenceModule::StorageCorrelation => "storage_correlation",
    }
}

/// Module of an evidence file name (cancelled files included).
fn module_of(name: &str) -> Option<EvidenceModule> {
    EvidenceModule::of_file_name(&name.replace(USER_CANCELLED, ""))
}

fn stem(name: &str) -> &str {
    match name.rfind('.') {
        Some(i) if i > 0 => &name[..i],
        _ => name,
    }
}

/// Chronological key of an evidence file name: the digit groups after the
/// module prefix (`dd.MM.yy_HH-mm[_NN]`, `dd-MM-yy_HH-mm-ss[_NN]`),
/// reordered as year, month, day, then the rest (time, collision suffix).
fn run_key(name: &str) -> Option<Vec<u32>> {
    let groups: Vec<u32> = stem(name)
        .split(|c: char| !c.is_ascii_digit())
        .filter(|g| !g.is_empty())
        .map(|g| g.parse().ok())
        .collect::<Option<Vec<u32>>>()?;
    if groups.len() < 3 {
        return None;
    }
    let mut key = vec![groups[2], groups[1], groups[0]];
    key.extend_from_slice(&groups[3..]);
    Some(key)
}

/// Files of the newest completed (not cancelled) run among `files`;
/// `preferred_stem` (the EXPC run the checks were read from) wins.
fn latest_run<'a>(files: &[&'a str], preferred_stem: Option<&str>) -> Vec<&'a str> {
    let completed: Vec<&str> = files
        .iter()
        .copied()
        .filter(|n| !n.contains(USER_CANCELLED))
        .collect();
    let chosen = preferred_stem
        .filter(|p| completed.iter().any(|n| stem(n) == *p))
        .map(str::to_string)
        .or_else(|| {
            completed
                .iter()
                .max_by(|a, b| run_key(a).cmp(&run_key(b)).then(a.cmp(b)))
                .map(|n| stem(n).to_string())
        });
    match chosen {
        Some(s) => completed.into_iter().filter(|n| stem(n) == s).collect(),
        None => Vec::new(),
    }
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

/// One physical disk's evidence inside a per-disk module.
struct DiskGroup<'a> {
    key: String,
    index: Option<u64>,
    model: String,
    files: Vec<&'a str>,
}

/// FNV-1a 64: a stable, non-reversible key for a physical identity (the
/// identity may embed a serial, which the manifest never carries).
fn disk_key(identity: &str) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in identity.as_bytes() {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    format!("{h:016x}")
}

fn json_field(bytes: &[u8], keys: &[&str]) -> Option<String> {
    let text = std::str::from_utf8(bytes).ok()?;
    let v = json::parse(text.trim_start_matches('\u{feff}'))?;
    keys.iter()
        .find_map(|k| v.get(k).and_then(|x| x.as_str()).map(str::to_string))
}

/// (identity, index, model) of one benchmark / health / correlation JSON.
fn disk_of(bytes: &[u8]) -> Option<(String, Option<u64>, String)> {
    let text = std::str::from_utf8(bytes).ok()?;
    let v = json::parse(text.trim_start_matches('\u{feff}'))?;
    let identity = v
        .get("physical_identity")
        .or_else(|| v.get("disk"))
        .and_then(|x| x.as_str())?
        .to_string();
    // Only physical-disk identities group runs; a drive-letter/volume
    // fallback identity is never treated as a physical disk.
    if !identity.starts_with("PHYS#") {
        return None;
    }
    // "PHYS#model#serial" / "PHYS#model#IDXn": fallbacks for evidence that
    // predates the explicit fields.
    let mut parts = identity.split('#');
    let _ = parts.next();
    let id_model = parts.next().unwrap_or("").to_string();
    let id_index = parts
        .next()
        .and_then(|t| t.strip_prefix("IDX"))
        .and_then(|n| n.parse::<u64>().ok());
    let index = match v.get("physical_disk_index") {
        Some(json::Value::Num(n)) if *n >= 0.0 => Some(*n as u64),
        _ => id_index,
    };
    let model = v
        .get("model")
        .and_then(|x| x.as_str())
        .map(str::to_string)
        .filter(|m| !m.is_empty())
        .unwrap_or(id_model);
    Some((identity, index, model))
}

/// Groups a per-disk module's files by physical disk: each JSON names its
/// disk; a TXT with the same stem belongs to the same run.
fn disk_groups<'a>(files: &[&'a str], entries: &[EvidenceFile]) -> Vec<DiskGroup<'a>> {
    let mut groups: Vec<DiskGroup<'a>> = Vec::new();
    let mut by_stem: Vec<(&'a str, usize)> = Vec::new();
    for name in files.iter().copied().filter(|n| n.ends_with(".json")) {
        let Some(entry) = entries.iter().find(|e| e.name == name) else {
            continue;
        };
        let Some((identity, index, model)) = disk_of(&entry.bytes) else {
            continue;
        };
        let key = disk_key(&identity);
        let at = match groups.iter().position(|g| g.key == key) {
            Some(i) => i,
            None => {
                groups.push(DiskGroup {
                    key,
                    index,
                    model,
                    files: Vec::new(),
                });
                groups.len() - 1
            }
        };
        groups[at].files.push(name);
        by_stem.push((stem(name), at));
    }
    for name in files.iter().copied().filter(|n| !n.ends_with(".json")) {
        if let Some((_, at)) = by_stem.iter().find(|(s, _)| *s == stem(name)) {
            groups[*at].files.push(name);
        }
    }
    for g in &mut groups {
        g.files.sort_unstable();
    }
    groups.sort_by(|a, b| a.index.cmp(&b.index).then(a.key.cmp(&b.key)));
    groups
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
        EvidenceModule::NvmeHealth,
        EvidenceModule::StorageCorrelation,
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
        let expc_run = (m == EvidenceModule::Expc).then(|| {
            deep_checks::from_evidence_files(
                entries
                    .iter()
                    .filter(|e| files.contains(&e.name.as_str()))
                    .map(|e| (e.name.as_str(), e.bytes.as_slice())),
            )
        });
        let preferred = expc_run
            .as_ref()
            .and_then(|r| r.as_ref())
            .map(|r| stem(&r.source_file).to_string());
        fields.push(format!(
            "      \"latest_evidence\": {}",
            str_list(&latest_run(&files, preferred.as_deref()), "      ")
        ));
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
        if matches!(
            m,
            EvidenceModule::SsdBenchmark
                | EvidenceModule::NvmeHealth
                | EvidenceModule::StorageCorrelation
        ) {
            // v0.4.2 (additive, schema 1.0 unchanged): per-disk modules name
            // the latest evidence of EACH physical disk. Grouping is by the
            // physical identity read back from the evidence (never a drive
            // letter); only a non-reversible `disk_key`, the disk index and
            // the model are written here — no serial.
            let groups = disk_groups(&files, entries);
            let disks: Vec<String> = groups
                .iter()
                .map(|g| {
                    let latest = latest_run(&g.files, None);
                    let status = latest
                        .iter()
                        .filter(|n| n.ends_with(".json"))
                        .find_map(|n| entries.iter().find(|e| e.name == *n))
                        .and_then(|e| json_field(&e.bytes, &["status", "state", "stability"]));
                    format!(
                        "        {{\n          \"disk_key\": {},\n          \"physical_disk_index\": {},\n          \"model\": {},\n          \"status\": {},\n          \"evidence\": {},\n          \"latest_evidence\": {}\n        }}",
                        json::string(&g.key),
                        g.index
                            .map(|i| i.to_string())
                            .unwrap_or_else(|| "null".into()),
                        json::string(&g.model),
                        status
                            .map(|s| json::string(&s))
                            .unwrap_or_else(|| "null".into()),
                        str_list(&g.files, "          "),
                        str_list(&latest, "          ")
                    )
                })
                .collect();
            fields.push(if disks.is_empty() {
                "      \"disks\": []".into()
            } else {
                format!("      \"disks\": [\n{}\n      ]", disks.join(",\n"))
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
    fn version_source_contract_0_4_3() {
        // One canonical version: Cargo.toml → Cargo.lock → EXE metadata
        // (winresource, build.rs) → title (env!) → manifest → release
        // script/folder (read from Cargo.toml).
        let toml = include_str!("../Cargo.toml").replace("\r\n", "\n");
        let lock = include_str!("../Cargo.lock").replace("\r\n", "\n");
        let package = toml.split("[dependencies]").next().unwrap();
        assert!(package.contains("name = \"win_state_diag\""));
        assert!(package.contains("\nversion = \"0.4.3\"\n"), "{package}");
        assert!(lock.contains("name = \"win_state_diag\"\nversion = \"0.4.3\"\n"));
        assert_eq!(PRODUCER_VERSION, "0.4.3");
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
        assert_eq!(s(&v, "producer_version"), PRODUCER_VERSION);
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

    /// v0.4.2: one package per PC and date keeps every same-day run (by
    /// design); `latest_evidence` names the current one unambiguously.
    #[test]
    fn repeated_same_day_runs_name_the_latest_result() {
        let json = |t: &str, dism: &str| {
            format!(
                "{{\"GeneratedAt\": \"{t}\", \"Checks\": [{{\"Check\": \"DISM\", \"Status\": \"{dism}\", \"Detail\": \"\"}}]}}"
            )
            .into_bytes()
        };
        let files = vec![
            EvidenceFile::new(
                "EXPC_28.09.26_09-00.json",
                json("2026-09-28T09:05:00", "ATTENTION"),
            ),
            EvidenceFile::new("EXPC_28.09.26_09-00.txt", b"a".to_vec()),
            EvidenceFile::new(
                "EXPC_28.09.26_11-30.json",
                json("2026-09-28T11:35:00", "OK"),
            ),
            EvidenceFile::new("EXPC_28.09.26_11-30.txt", b"b".to_vec()),
            EvidenceFile::new("EXPC_28.09.26_12-00_USER_CANCELLED.txt", b"c".to_vec()),
            EvidenceFile::new("Hardware_28.09.26_10-31.json", b"{}".to_vec()),
            EvidenceFile::new("Hardware_28.09.26_10-31.txt", b"x".to_vec()),
            EvidenceFile::new("Hardware_28.09.26_14-02.json", b"{}".to_vec()),
            EvidenceFile::new("DriverAudit_28-09-26_09-59-58.json", b"{}".to_vec()),
            EvidenceFile::new("DriverAudit_28-09-26_10-00-01.json", b"{}".to_vec()),
            EvidenceFile::new("SSD_Benchmark_28.09.26_17-05.txt", b"1".to_vec()),
            EvidenceFile::new("SSD_Benchmark_28.09.26_17-05_02.txt", b"2".to_vec()),
            EvidenceFile::new("SSD_Benchmark_27.09.26_23-59.txt", b"0".to_vec()),
        ];
        let v = parsed(&build(&ctx(), &files));
        let modules = v.get("modules").unwrap().as_arr().unwrap();
        let latest = |i: usize| -> Vec<&str> {
            modules[i]
                .get("latest_evidence")
                .unwrap()
                .as_arr()
                .unwrap()
                .iter()
                .map(|x| x.as_str().unwrap())
                .collect()
        };
        // All evidence is kept…
        assert_eq!(
            modules[0].get("evidence").unwrap().as_arr().unwrap().len(),
            5
        );
        // …and the current result is unambiguous (cancelled runs never win).
        assert_eq!(
            latest(0),
            ["EXPC_28.09.26_11-30.json", "EXPC_28.09.26_11-30.txt"]
        );
        assert_eq!(latest(1), ["Hardware_28.09.26_14-02.json"]);
        assert_eq!(latest(2), ["DriverAudit_28-09-26_10-00-01.json"]);
        assert_eq!(latest(3), ["SSD_Benchmark_28.09.26_17-05_02.txt"]);
        // The deep-check results come from that same latest EXPC run.
        let checks = modules[0].get("checks").unwrap().as_arr().unwrap();
        assert_eq!(s(&checks[0], "result_status"), "OK");
        assert_eq!(s(&checks[0], "source_file"), "EXPC_28.09.26_11-30.json");
        // Schema unchanged (additive field only).
        assert_eq!(s(&v, "schema_version"), SCHEMA_VERSION);
        assert_eq!(SCHEMA_VERSION, "1.0");
    }

    /// NVMe Health phase: the health evidence is its own additive module
    /// (schema 1.0 unchanged), referenced per disk, without the serial.
    #[test]
    fn nvme_health_evidence_is_referenced_without_schema_change() {
        let d =
            crate::nvme_health::tests::disk(1, "Samsung SSD 9100 PRO 2TB", "S7XXNOTREAL", "NVMe");
        struct Src;
        impl crate::nvme_health::NvmeLogSource for Src {
            fn read_log_page(
                &self,
                _: u32,
                lid: u8,
                _: usize,
            ) -> Result<crate::nvme_health::LogRead, crate::nvme_health::ProbeError> {
                if lid == 2 {
                    Ok(crate::nvme_health::LogRead {
                        data: crate::nvme_health::tests::smart_bytes(),
                        via: "test",
                    })
                } else {
                    Err(crate::nvme_health::ProbeError::InvalidFunction)
                }
            }
        }
        let health = crate::nvme_health::collect(&Src, &d, "2026-09-28T10:41:00");
        let mut files = entries();
        files.push(EvidenceFile::new(
            "NVMe_Health_28.09.26_10-41_PD1.json",
            crate::nvme_health::to_json(&health).into_bytes(),
        ));
        let bytes = build(&ctx(), &files);
        let text = String::from_utf8(bytes.clone()).unwrap();
        let v = parsed(&bytes);
        assert_eq!(s(&v, "schema_version"), "1.0");
        let modules = v.get("modules").unwrap().as_arr().unwrap();
        let nvme = modules.last().unwrap();
        assert_eq!(s(nvme, "name"), "nvme_health");
        assert_eq!(s(nvme, "status"), "completed");
        let ev = nvme.get("latest_evidence").unwrap().as_arr().unwrap();
        assert_eq!(ev[0].as_str(), Some("NVMe_Health_28.09.26_10-41_PD1.json"));
        let disks = nvme.get("disks").unwrap().as_arr().unwrap();
        assert_eq!(disks.len(), 1);
        assert_eq!(s(&disks[0], "status"), "OK");
        assert_eq!(s(&disks[0], "model"), "Samsung SSD 9100 PRO 2TB");
        assert_eq!(disks[0].get("physical_disk_index"), Some(&Value::Num(1.0)));
        assert!(!text.contains("S7XXNOTREAL"), "no serial in the manifest");
        // The other modules are unchanged by the new one.
        assert_eq!(s(&modules[3], "name"), "ssd_benchmark");
        assert!(
            !v.get("shared_files")
                .and_then(|x| x.as_arr())
                .unwrap_or(&[])
                .iter()
                .any(|x| x.as_str() == Some("NVMe_Health_28.09.26_10-41_PD1.json"))
        );
    }

    fn bench_json(identity: &str, index: u32, model: &str, stability: &str) -> Vec<u8> {
        format!(
            "{{\"schema\":\"winstatediag.ssd_benchmark/1\",\"run_role\":\"initial\",\"physical_disk_index\":{index},\"model\":\"{model}\",\"disk\":\"{identity}\",\"stability\":\"{stability}\"}}"
        )
        .into_bytes()
    }

    /// v0.4.2 real-report ambiguity: two physical disks with several runs
    /// each — the manifest names the latest evidence PER DISK.
    #[test]
    fn per_disk_latest_evidence_with_two_disks_and_several_runs() {
        let samsung = "PHYS#Samsung SSD 9100 PRO 1TB#S7XXSERIALA";
        let netac = "PHYS#Netac NVMe SSD 1TB#IDX4";
        let f = |n: &str, b: Vec<u8>| EvidenceFile::new(n, b);
        let files = vec![
            f("SSD_Benchmark_03.10.26_10-00.json", bench_json(samsung, 3, "Samsung SSD 9100 PRO 1TB", "UNSTABLE")),
            f("SSD_Benchmark_03.10.26_10-00.txt", b"s1".to_vec()),
            f("SSD_Benchmark_03.10.26_10-01_retest.json", bench_json(samsung, 3, "Samsung SSD 9100 PRO 1TB", "ACCEPT")),
            f("SSD_Benchmark_03.10.26_10-01_retest.txt", b"s2".to_vec()),
            f("SSD_Benchmark_03.10.26_10-20.json", bench_json(netac, 4, "Netac NVMe SSD 1TB", "STABLE")),
            f("SSD_Benchmark_03.10.26_10-20.txt", b"n1".to_vec()),
            f("SSD_Benchmark_03.10.26_09-30.json", bench_json(netac, 4, "Netac NVMe SSD 1TB", "ACCEPT")),
            // Legacy evidence without the new fields: model/index recovered
            // from the identity itself.
            f(
                "SSD_Benchmark_02.10.26_18-00.json",
                format!("{{\"disk\":\"{netac}\",\"stability\":\"STABLE\"}}").into_bytes(),
            ),
            f(
                "NVMe_Health_03.10.26_10-02_PD3.json",
                format!("{{\"physical_identity\":\"{samsung}\",\"physical_disk_index\":3,\"model\":\"Samsung SSD 9100 PRO 1TB\",\"status\":\"OK\"}}").into_bytes(),
            ),
            f(
                "NVMe_Health_03.10.26_10-21_PD4.json",
                format!("{{\"physical_identity\":\"{netac}\",\"physical_disk_index\":4,\"model\":\"Netac NVMe SSD 1TB\",\"status\":\"OK\"}}").into_bytes(),
            ),
            f(
                "Storage_Correlation_03.10.26_10-03_PD3.json",
                format!("{{\"physical_identity\":\"{samsung}\",\"physical_disk_index\":3,\"model\":\"Samsung SSD 9100 PRO 1TB\",\"state\":\"BENCHMARK_ANOMALY_NOT_CONFIRMED\"}}").into_bytes(),
            ),
        ];
        let bytes = build(&ctx(), &files);
        let text = String::from_utf8(bytes.clone()).unwrap();
        let v = parsed(&bytes);
        assert_eq!(s(&v, "schema_version"), "1.0");
        assert!(!text.contains("S7XXSERIALA"), "no serial in the manifest");
        let modules = v.get("modules").unwrap().as_arr().unwrap();
        let module = |name: &str| {
            modules
                .iter()
                .find(|m| s(m, "name") == name)
                .unwrap_or_else(|| panic!("{name}"))
        };
        let names = |x: &Value, k: &str| -> Vec<String> {
            x.get(k)
                .unwrap()
                .as_arr()
                .unwrap()
                .iter()
                .map(|n| n.as_str().unwrap().to_string())
                .collect()
        };
        let ssd = module("ssd_benchmark");
        // Every run is still listed.
        assert_eq!(names(ssd, "evidence").len(), 8);
        let disks = ssd.get("disks").unwrap().as_arr().unwrap();
        assert_eq!(disks.len(), 2);
        assert_eq!(disks[0].get("physical_disk_index"), Some(&Value::Num(3.0)));
        assert_eq!(s(&disks[0], "model"), "Samsung SSD 9100 PRO 1TB");
        assert_eq!(
            names(&disks[0], "latest_evidence"),
            [
                "SSD_Benchmark_03.10.26_10-01_retest.json",
                "SSD_Benchmark_03.10.26_10-01_retest.txt"
            ]
        );
        assert_eq!(s(&disks[0], "status"), "ACCEPT");
        assert_eq!(names(&disks[0], "evidence").len(), 4);
        assert_eq!(disks[1].get("physical_disk_index"), Some(&Value::Num(4.0)));
        assert_eq!(
            names(&disks[1], "latest_evidence"),
            [
                "SSD_Benchmark_03.10.26_10-20.json",
                "SSD_Benchmark_03.10.26_10-20.txt"
            ]
        );
        assert_eq!(
            names(&disks[1], "evidence").len(),
            4,
            "legacy run grouped too"
        );
        assert_ne!(s(&disks[0], "disk_key"), s(&disks[1], "disk_key"));
        let nvme = module("nvme_health");
        let nd = nvme.get("disks").unwrap().as_arr().unwrap();
        assert_eq!(nd.len(), 2);
        assert_eq!(
            names(&nd[1], "latest_evidence"),
            ["NVMe_Health_03.10.26_10-21_PD4.json"]
        );
        assert_eq!(
            s(&nd[0], "disk_key"),
            s(&disks[0], "disk_key"),
            "same disk, same key"
        );
        let corr = module("storage_correlation");
        let cd = corr.get("disks").unwrap().as_arr().unwrap();
        assert_eq!(s(&cd[0], "status"), "BENCHMARK_ANOMALY_NOT_CONFIRMED");
        // A drive-letter identity is never grouped as a physical disk.
        let legacy = vec![f(
            "SSD_Benchmark_01.10.26_10-00.json",
            b"{\"disk\":\"C:\\\\#1A2B3C4D\"}".to_vec(),
        )];
        let v = parsed(&build(&ctx(), &legacy));
        let m = &v.get("modules").unwrap().as_arr().unwrap()[0];
        assert_eq!(m.get("disks").unwrap().as_arr().unwrap().len(), 0);
        assert_eq!(names(m, "evidence").len(), 1, "evidence still listed");
    }
}
