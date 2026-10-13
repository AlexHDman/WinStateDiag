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
//!   "session": { "session_id": "...", "client_name": "..." | "" },
//!                       (v1.0 additive: the diagnostic session the report
//!                        belongs to, fixed when the user started it)
//!   "created_at": "YYYY-MM-DDTHH:MM:SS",          (local time)
//!   "windows": { "product": "...", "build": "..." },
//!   "modules": [
//!     { "name": "expc_diagnostic" | "hardware_report" | "driver_audit"
//!               | "ssd_benchmark" | "nvme_health" | "storage_correlation"
//!               | "crash_dump_analysis" | "group_policy_admx_health"
//!               | "hardware_sensors" | "freeze_hang_incidents",
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
//!       "dump_count", "analyzed_count", "analysis_status", "confidence"
//!                                         (crash_dump_analysis, additive)
//!       "result_status"   (group_policy_admx_health, hardware_sensors, additive)
//!       "provider", "sensor_count"           (hardware_sensors, v0.4.5 additive)
//!       "result_status", "incident_count"    (freeze_hang_incidents, v0.4.5 additive)
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
/// The canonical application version (Cargo.toml `[package] version`,
/// release form "1.0" — see build.rs `display_version`).
pub const PRODUCER_VERSION: &str = env!("WSD_DISPLAY_VERSION");

#[derive(Clone, Debug)]
pub struct ManifestContext {
    pub producer_version: String,
    pub package: String,
    pub computer_name: String,
    pub created_at: LocalTime,
    pub windows_product: String,
    pub windows_build: String,
    /// v1.0 (additive): separate system / hardware state codes.
    pub system_state: Option<String>,
    pub hardware_state: Option<String>,
    /// v1.0 (additive): `(session_id, client_name)` of the session.
    pub session: Option<(String, String)>,
}

fn module_name(m: EvidenceModule) -> &'static str {
    match m {
        EvidenceModule::Expc => "expc_diagnostic",
        EvidenceModule::Hardware => "hardware_report",
        EvidenceModule::DriverAudit => "driver_audit",
        EvidenceModule::SsdBenchmark => "ssd_benchmark",
        EvidenceModule::NvmeHealth => "nvme_health",
        EvidenceModule::StorageCorrelation => "storage_correlation",
        EvidenceModule::CrashDump => "crash_dump_analysis",
        EvidenceModule::GroupPolicyAdmx => "group_policy_admx_health",
        EvidenceModule::HardwareSensors => "hardware_sensors",
        EvidenceModule::FreezeIncidents => "freeze_hang_incidents",
        EvidenceModule::EventEvidence => "event_evidence",
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

/// Integer field of a JSON evidence file.
fn json_number(bytes: &[u8], key: &str) -> Option<u64> {
    let text = std::str::from_utf8(bytes).ok()?;
    match json::parse(text.trim_start_matches('\u{feff}'))?.get(key)? {
        json::Value::Num(n) if *n >= 0.0 => Some(*n as u64),
        _ => None,
    }
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

/// v1.0 the evidence set of the newest analyzed crash. Crash files are
/// `CrashDump_{Analysis|Summary|Dump}_<stamp>_<NN>[_<original>]`; one
/// analysis run numbers its dumps newest first, so the set is the newest
/// `<stamp>` with the smallest `<NN>`.
fn crash_evidence_set<'a>(files: &[&'a str]) -> Vec<&'a str> {
    let set_key = |name: &str| -> Option<(Vec<u32>, u32, String)> {
        let rest = ["Analysis_", "Summary_", "Dump_"]
            .iter()
            .find_map(|p| name.strip_prefix(&format!("CrashDump_{p}")))?;
        let parts: Vec<&str> = rest.splitn(4, '_').collect();
        if parts.len() < 3 {
            return None;
        }
        let nn_str = parts[2].split('.').next().unwrap_or("");
        let nn: u32 = nn_str.parse().ok()?;
        let stamp = format!("{}_{}", parts[0], parts[1]);
        Some((
            // `run_key` strips an extension itself (never the date dots).
            run_key(&format!("{stamp}.json")).unwrap_or_default(),
            nn,
            format!("{stamp}_{nn_str}"),
        ))
    };
    let newest = files
        .iter()
        .filter(|n| !n.contains(USER_CANCELLED))
        .filter_map(|n| set_key(n))
        .max_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));
    let Some((_, _, key)) = newest else {
        return Vec::new();
    };
    files
        .iter()
        .copied()
        .filter(|n| set_key(n).is_some_and(|(_, _, k)| k == key))
        .collect()
}

/// v1.0 chronological key of one per-disk JSON: its own timestamp
/// (`captured_at` / `assessed_at` / `generated_at`, seconds) when present,
/// else the file-name key (legacy evidence). A legacy `<stem>_retest`
/// sorts directly AFTER its base run, never before a later run.
fn evidence_order_key(name: &str, bytes: &[u8]) -> Vec<u32> {
    if let Some(ts) = json_field(bytes, &["captured_at", "assessed_at", "generated_at"]) {
        let nums: Vec<u32> = ts
            .split(|c: char| !c.is_ascii_digit())
            .filter(|g| !g.is_empty())
            .filter_map(|g| g.parse().ok())
            .take(6)
            .collect();
        if nums.len() >= 5 {
            return nums;
        }
    }
    let base = stem(name).trim_end_matches("_retest");
    // `run_key` strips an extension itself: the date dots of a bare stem
    // ("…_05.10.26_10-58") must never be taken for one.
    let mut key = run_key(&format!("{base}.json")).unwrap_or_default();
    if let Some(y) = key.first_mut()
        && *y < 100
    {
        *y += 2000;
    }
    if stem(name).ends_with("_retest") {
        key.push(u32::MAX);
    }
    key
}

/// v1.0 the CURRENT run of one disk: the newest JSON by its own timestamp
/// (an automatic retest is newer than the run it confirms, so a confirmed
/// sequence ends on its retest). Returns (final JSON name, sequence files:
/// the initial run + its retest, all extensions).
fn current_run<'a>(files: &[&'a str], entries: &[EvidenceFile]) -> Option<(&'a str, Vec<&'a str>)> {
    let jsons: Vec<(&'a str, Vec<u32>)> = files
        .iter()
        .copied()
        .filter(|n| n.ends_with(".json") && !n.contains(USER_CANCELLED))
        .filter_map(|n| {
            let e = entries.iter().find(|e| e.name == n)?;
            Some((n, evidence_order_key(n, &e.bytes)))
        })
        .collect();
    let (last, _) = jsons
        .iter()
        .max_by(|a, b| a.1.cmp(&b.1).then(a.0.cmp(b.0)))?;
    let last = *last;
    let last_stem = stem(last);
    // The initial run of a retest: explicit `retest_of`, else the legacy
    // `<initial>_retest` naming.
    let initial_stem: Option<String> = entries
        .iter()
        .find(|e| e.name == last)
        .and_then(|e| json_field(&e.bytes, &["retest_of"]))
        .map(|r| stem(&r).to_string())
        .or_else(|| last_stem.strip_suffix("_retest").map(str::to_string));
    let mut seq: Vec<&'a str> = files
        .iter()
        .copied()
        .filter(|n| {
            let s = stem(n);
            s == last_stem || initial_stem.as_deref() == Some(s)
        })
        .collect();
    seq.sort_unstable();
    Some((last, seq))
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
        EvidenceModule::CrashDump,
        EvidenceModule::GroupPolicyAdmx,
        EvidenceModule::HardwareSensors,
        EvidenceModule::FreezeIncidents,
        EvidenceModule::EventEvidence,
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
        // v1.0: for crash analysis the latest evidence is the complete
        // logical set of the newest analyzed crash (original .dmp copy +
        // CrashDump_Analysis .txt + CrashDump_Summary .json).
        let latest = if m == EvidenceModule::CrashDump {
            crash_evidence_set(&files)
        } else {
            latest_run(&files, preferred.as_deref())
        };
        fields.push(format!(
            "      \"latest_evidence\": {}",
            str_list(&latest, "      ")
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
                        "        {{\n          \"check\": {},\n          \"execution_status\": {},\n          \"result_status\": {},\n          \"finding_class\": {},\n          \"finding\": {},\n          \"source_file\": {},\n          \"source\": {},\n          \"timestamp\": {}\n        }}",
                        json::string(o.check.key()),
                        json::string(exec),
                        json::string(o.effective_result().as_str()),
                        o.finding_class()
                            .map(|f| json::string(f.code()))
                            .unwrap_or_else(|| "null".into()),
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
                    // v1.0: the CURRENT (final) run of this disk by its own
                    // timestamp — after UNSTABLE → retest → STABLE the
                    // retest is current; earlier runs stay in `evidence`.
                    let (latest, sequence) = match current_run(&g.files, entries) {
                        Some((last, seq)) => (
                            g.files
                                .iter()
                                .copied()
                                .filter(|n| stem(n) == stem(last))
                                .collect::<Vec<_>>(),
                            seq,
                        ),
                        None => (latest_run(&g.files, None), Vec::new()),
                    };
                    let current_json = latest
                        .iter()
                        .filter(|n| n.ends_with(".json"))
                        .find_map(|n| entries.iter().find(|e| e.name == *n));
                    // v1.0 item 13: NVMe_Health status = the normalized
                    // health record (`health_status`, e.g. ATA SMART OK),
                    // never the NVMe-log probe status alone; correlation =
                    // its storage state.
                    let keys: &[&str] = match m {
                        EvidenceModule::StorageCorrelation => &["state", "status"],
                        _ => &["health_status", "status", "state", "stability"],
                    };
                    let status = current_json.and_then(|e| json_field(&e.bytes, keys));
                    // Correlation: the exact benchmark / health evidence the
                    // current assessment was made from.
                    let refs = if m == EvidenceModule::StorageCorrelation {
                        let text = current_json
                            .and_then(|e| std::str::from_utf8(&e.bytes).ok())
                            .and_then(|t| json::parse(t.trim_start_matches('\u{feff}')));
                        let bench: Vec<String> = text
                            .as_ref()
                            .and_then(|v| match v.get("benchmark_evidence") {
                                Some(json::Value::Arr(a)) => Some(
                                    a.iter()
                                        .filter_map(|x| x.as_str().map(str::to_string))
                                        .collect(),
                                ),
                                _ => None,
                            })
                            .unwrap_or_default();
                        let health = text
                            .as_ref()
                            .and_then(|v| v.get("health_evidence").and_then(|x| x.as_str()).map(str::to_string));
                        let bench_refs: Vec<&str> = bench.iter().map(String::as_str).collect();
                        format!(
                            ",\n          \"current_benchmark_evidence\": {},\n          \"current_health_evidence\": {}",
                            str_list(&bench_refs, "          "),
                            health.map(|h| json::string(&h)).unwrap_or_else(|| "null".into())
                        )
                    } else {
                        String::new()
                    };
                    let seq_field = if m == EvidenceModule::SsdBenchmark {
                        format!(
                            ",\n          \"current_sequence\": {}",
                            str_list(&sequence, "          ")
                        )
                    } else {
                        String::new()
                    };
                    format!(
                        "        {{\n          \"disk_key\": {},\n          \"physical_disk_index\": {},\n          \"model\": {},\n          \"status\": {},\n          \"evidence\": {},\n          \"latest_evidence\": {}{}{}\n        }}",
                        json::string(&g.key),
                        g.index
                            .map(|i| i.to_string())
                            .unwrap_or_else(|| "null".into()),
                        json::string(&g.model),
                        status
                            .map(|s| json::string(&s))
                            .unwrap_or_else(|| "null".into()),
                        str_list(&g.files, "          "),
                        str_list(&latest, "          "),
                        seq_field,
                        refs
                    )
                })
                .collect();
            fields.push(if disks.is_empty() {
                "      \"disks\": []".into()
            } else {
                format!("      \"disks\": [\n{}\n      ]", disks.join(",\n"))
            });
        }
        if m == EvidenceModule::CrashDump {
            // v0.4.4 (additive): dump / analysis counts and the result of
            // the newest analysis, read from the summaries themselves.
            let summaries: Vec<&EvidenceFile> = entries
                .iter()
                .filter(|e| files.contains(&e.name.as_str()) && e.name.contains("_Summary_"))
                .collect();
            let dumps = files
                .iter()
                .filter(|n| n.to_ascii_lowercase().ends_with(".dmp"))
                .count();
            let analyzed = summaries
                .iter()
                .filter(|e| {
                    json_field(&e.bytes, &["analysis_status"]).as_deref() == Some("COMPLETED")
                })
                .count();
            let newest = summaries.iter().max_by(|a, b| {
                run_key(&a.name)
                    .cmp(&run_key(&b.name))
                    .then(a.name.cmp(&b.name))
            });
            let field = |k: &str| {
                newest
                    .and_then(|e| json_field(&e.bytes, &[k]))
                    .map(|v| json::string(&v))
                    .unwrap_or_else(|| "null".into())
            };
            fields.push(format!("      \"dump_count\": {dumps}"));
            fields.push(format!("      \"analyzed_count\": {analyzed}"));
            fields.push(format!(
                "      \"analysis_status\": {}",
                field("analysis_status")
            ));
            fields.push(format!("      \"confidence\": {}", field("confidence")));
        }
        if matches!(
            m,
            EvidenceModule::GroupPolicyAdmx
                | EvidenceModule::HardwareSensors
                | EvidenceModule::FreezeIncidents
                | EvidenceModule::EventEvidence
        ) {
            let latest = latest_run(&files, None);
            let newest = latest
                .iter()
                .filter(|n| n.ends_with(".json"))
                .find_map(|n| entries.iter().find(|e| e.name == *n));
            let status = newest
                .and_then(|e| json_field(&e.bytes, &["status"]))
                .map(|v| json::string(&v))
                .unwrap_or_else(|| "null".into());
            fields.push(format!("      \"result_status\": {status}"));
            if m == EvidenceModule::HardwareSensors {
                let provider = newest
                    .and_then(|e| json_field(&e.bytes, &["provider"]))
                    .map(|v| json::string(&v))
                    .unwrap_or_else(|| "null".into());
                let count = newest
                    .and_then(|e| json_number(&e.bytes, "sensor_count"))
                    .map(|n| format!("{n}"))
                    .unwrap_or_else(|| "null".into());
                fields.push(format!("      \"provider\": {provider}"));
                fields.push(format!("      \"sensor_count\": {count}"));
            }
            if m == EvidenceModule::EventEvidence {
                let count = newest
                    .and_then(|e| json_number(&e.bytes, "aggregate_count"))
                    .map(|n| format!("{n}"))
                    .unwrap_or_else(|| "null".into());
                fields.push(format!("      \"aggregate_count\": {count}"));
            }
            if m == EvidenceModule::FreezeIncidents {
                let count = newest
                    .and_then(|e| json_number(&e.bytes, "incident_count"))
                    .map(|n| format!("{n}"))
                    .unwrap_or_else(|| "null".into());
                fields.push(format!("      \"incident_count\": {count}"));
            }
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
    if let Some((session_id, client)) = &ctx.session {
        out.push_str(&format!(
            "  \"session\": {{\n    \"session_id\": {},\n    \"client_name\": {}\n  }},\n",
            json::string(session_id),
            json::string(client)
        ));
    }
    out.push_str(&format!(
        "  \"created_at\": {},\n",
        json::string(&iso(ctx.created_at))
    ));
    out.push_str(&format!(
        "  \"windows\": {{\n    \"product\": {},\n    \"build\": {}\n  }},\n",
        json::string(&ctx.windows_product),
        json::string(&ctx.windows_build)
    ));
    if let (Some(sys), Some(hw)) = (&ctx.system_state, &ctx.hardware_state) {
        out.push_str(&format!(
            "  \"state\": {{\n    \"system\": {},\n    \"hardware\": {},\n    \"note\": \"Two separate concepts: hardware state OK does not mean the computer is healthy.\"\n  }},\n",
            json::string(sys),
            json::string(hw)
        ));
    }
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
            system_state: None,
            hardware_state: None,
            session: None,
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
    fn version_source_contract_1_0() {
        // One canonical version: Cargo.toml → Cargo.lock → EXE metadata
        // (winresource, build.rs) → title (env!) → manifest → release
        // script/folder (read from Cargo.toml).
        let toml = include_str!("../Cargo.toml").replace("\r\n", "\n");
        let lock = include_str!("../Cargo.lock").replace("\r\n", "\n");
        let package = toml.split("[dependencies]").next().unwrap();
        assert!(package.contains("name = \"win_state_diag\""));
        assert!(package.contains("\nversion = \"1.1.0\"\n"), "{package}");
        assert!(lock.contains("name = \"win_state_diag\"\nversion = \"1.1.0\"\n"));
        // v1.1: displayed / manifest / folder version is "1.1".
        assert_eq!(PRODUCER_VERSION, "1.1");
        assert_eq!(crate::APP_VERSION, "1.1");
        let main = include_str!("lib.rs").replace("\r\n", "\n");
        assert!(main.contains("pub const APP_VERSION: &str = env!(\"WSD_DISPLAY_VERSION\");"));
        assert!(main.contains("format!(\"WinStateDiag — v{APP_VERSION}\")"));
        let build = include_str!("../build.rs");
        assert!(build.contains("res.set(\"FileVersion\", &display);"));
        assert!(build.contains("res.set(\"ProductVersion\", &display);"));
        // The admin manifest is linked into the shipped bin only; the bin
        // has no test harness, so `cargo test` never needs elevation.
        assert!(build.contains("cargo:rustc-link-arg-bin=win_state_diag={arg}"));
        assert!(build.contains("requireAdministrator"));
        let toml_bin = toml.split("[[bin]]").nth(1).unwrap_or("");
        assert!(toml_bin.contains("test = false"), "{toml_bin}");
        assert!(
            !build.contains("cargo:rustc-link-arg={"),
            "no package-wide link args"
        );
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

    /// v0.4.4: crash dump, Group Policy and power evidence are their own
    /// additive modules (schema 1.0 unchanged); original dumps are listed.
    #[test]
    fn v044_modules_are_referenced_with_counts() {
        let f = |n: &str, b: &str| EvidenceFile::new(n, b.as_bytes().to_vec());
        let files = vec![
            f(
                "CrashDump_Dump_04.10.26_10-00_01_100326-10421-01.dmp",
                "MDMP",
            ),
            f("CrashDump_Analysis_04.10.26_10-00_01.txt", "raw"),
            f(
                "CrashDump_Summary_04.10.26_10-00_01.json",
                "{\"analysis_status\": \"COMPLETED\", \"confidence\": \"HIGH\"}",
            ),
            f(
                "CrashDump_Summary_04.10.26_10-00_02.json",
                "{\"analysis_status\": \"TIMED_OUT\", \"confidence\": \"CAUSE NOT DETERMINED\"}",
            ),
            f(
                "GroupPolicy_ADMX_Health_04.10.26_10-01.json",
                "{\"status\": \"NOT APPLICABLE\"}",
            ),
            f("GroupPolicy_ADMX_Health_04.10.26_10-01.txt", "x"),
            f(
                "Hardware_Sensors_04.10.26_10-02.json",
                "{\"status\": \"PARTIAL\", \"provider\": \"nvidia-smi\", \"sensor_count\": 7}",
            ),
        ];
        let v = parsed(&build(&ctx(), &files));
        assert_eq!(s(&v, "schema_version"), "1.0");
        let modules = v.get("modules").unwrap().as_arr().unwrap();
        let m = |n: &str| {
            modules
                .iter()
                .find(|x| s(x, "name") == n)
                .unwrap_or_else(|| panic!("{n}"))
        };
        let crash = m("crash_dump_analysis");
        assert_eq!(crash.get("dump_count"), Some(&Value::Num(1.0)));
        assert_eq!(crash.get("analyzed_count"), Some(&Value::Num(1.0)));
        assert_eq!(s(crash, "analysis_status"), "TIMED_OUT", "newest summary");
        assert_eq!(crash.get("evidence").unwrap().as_arr().unwrap().len(), 4);
        assert_eq!(
            s(m("group_policy_admx_health"), "result_status"),
            "NOT APPLICABLE"
        );
        let names = |x: &Value, k: &str| -> Vec<String> {
            x.get(k)
                .and_then(|a| a.as_arr())
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default()
        };
        let hs = m("hardware_sensors");
        assert_eq!(s(hs, "result_status"), "PARTIAL");
        assert_eq!(s(hs, "provider"), "nvidia-smi");
        assert_eq!(hs.get("sensor_count"), Some(&Value::Num(7.0)));
        assert_eq!(names(hs, "latest_evidence").len(), 1);
        // Hardware_Sensors_* is not mistaken for the Hardware Report.
        assert!(names(hs, "evidence")[0].starts_with("Hardware_Sensors_"));
    }

    // ---- v1.0 final-state / per-run references ----

    fn bench(role: &str, at: &str, stability: &str, retest_of: Option<&str>) -> Vec<u8> {
        format!(
            "{{\"schema\":\"winstatediag.ssd_benchmark/1\",\"run_role\":\"{role}\",\"captured_at\":\"{at}\",\"retest_of\":{},\"physical_disk_index\":3,\"model\":\"Samsung SSD 9100 PRO 1TB\",\"disk\":\"PHYS#Samsung SSD 9100 PRO 1TB#S1\",\"stability\":\"{stability}\"}}",
            retest_of.map(|r| format!("\"{r}\"")).unwrap_or_else(|| "null".into())
        )
        .into_bytes()
    }

    fn corr(at: &str, state: &str, bench: &[&str], health: &str) -> Vec<u8> {
        format!(
            "{{\"format\":\"winstatediag.storage_correlation/1\",\"physical_identity\":\"PHYS#Samsung SSD 9100 PRO 1TB#S1\",\"physical_disk_index\":3,\"model\":\"Samsung SSD 9100 PRO 1TB\",\"assessed_at\":\"{at}\",\"state\":\"{state}\",\"health_evidence\":\"{health}\",\"benchmark_evidence\":[{}]}}",
            bench.iter().map(|b| format!("\"{b}\"")).collect::<Vec<_>>().join(",")
        )
        .into_bytes()
    }

    fn disk_entry<'a>(v: &'a Value, module: &str) -> &'a Value {
        let modules = v.get("modules").unwrap().as_arr().unwrap();
        let m = modules
            .iter()
            .find(|m| m.get("name").and_then(Value::as_str) == Some(module))
            .unwrap();
        &m.get("disks").unwrap().as_arr().unwrap()[0]
    }

    fn strs(v: &Value, k: &str) -> Vec<String> {
        v.get(k)
            .unwrap()
            .as_arr()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap().to_string())
            .collect()
    }

    /// The real MSI case: ACCEPT run, then an UNSTABLE run that collided
    /// on the same minute (`_02`), then its automatic retest ACCEPT. The
    /// current state is the retest — never the stale UNSTABLE `_02`.
    #[test]
    fn unstable_then_retest_stable_is_the_current_state_per_disk() {
        let entries = vec![
            EvidenceFile::new(
                "SSD_Benchmark_05.10.26_10-57.json",
                bench("initial", "2026-10-05T10:57:30", "ACCEPT", None),
            ),
            EvidenceFile::new(
                "SSD_Benchmark_05.10.26_10-57_02.json",
                bench("initial", "2026-10-05T10:57:36", "UNSTABLE", None),
            ),
            EvidenceFile::new(
                "SSD_Benchmark_05.10.26_10-57_02_retest.json",
                bench(
                    "automatic_retest",
                    "2026-10-05T10:57:47",
                    "ACCEPT",
                    Some("SSD_Benchmark_05.10.26_10-57_02.json"),
                ),
            ),
            EvidenceFile::new("SSD_Benchmark_05.10.26_10-57_02_retest.txt", b"t".to_vec()),
            EvidenceFile::new("SSD_Benchmark_05.10.26_10-57_02.txt", b"t".to_vec()),
            EvidenceFile::new(
                "Storage_Correlation_05.10.26_10-57_PD3.json",
                corr(
                    "2026-10-05T10:57:37",
                    "OK",
                    &["SSD_Benchmark_05.10.26_10-57.json"],
                    "NVMe_Health_05.10.26_10-57_PD3.json",
                ),
            ),
            EvidenceFile::new(
                "Storage_Correlation_05.10.26_10-57_PD3_02.json",
                corr(
                    "2026-10-05T10:57:48",
                    "BENCHMARK_ANOMALY_NOT_CONFIRMED",
                    &[
                        "SSD_Benchmark_05.10.26_10-57_02.json",
                        "SSD_Benchmark_05.10.26_10-57_02_retest.json",
                    ],
                    "NVMe_Health_05.10.26_10-57_PD3_02.json",
                ),
            ),
        ];
        let v = parsed(&build(&ctx(), &entries));
        let b = disk_entry(&v, "ssd_benchmark");
        assert_eq!(s(b, "status"), "ACCEPT", "final confirmed state");
        assert_eq!(
            strs(b, "latest_evidence"),
            vec![
                "SSD_Benchmark_05.10.26_10-57_02_retest.json".to_string(),
                "SSD_Benchmark_05.10.26_10-57_02_retest.txt".to_string()
            ]
        );
        let seq = strs(b, "current_sequence");
        assert!(seq.contains(&"SSD_Benchmark_05.10.26_10-57_02.json".to_string()));
        assert!(seq.contains(&"SSD_Benchmark_05.10.26_10-57_02_retest.json".to_string()));
        assert!(!seq.contains(&"SSD_Benchmark_05.10.26_10-57.json".to_string()));
        // History is preserved, not presented as current.
        assert_eq!(strs(b, "evidence").len(), 5);
        // Correlation: newest assessment + the exact runs it was made from.
        let c = disk_entry(&v, "storage_correlation");
        assert_eq!(s(c, "status"), "BENCHMARK_ANOMALY_NOT_CONFIRMED");
        assert_eq!(
            strs(c, "latest_evidence"),
            vec!["Storage_Correlation_05.10.26_10-57_PD3_02.json".to_string()]
        );
        assert_eq!(
            strs(c, "current_benchmark_evidence"),
            vec![
                "SSD_Benchmark_05.10.26_10-57_02.json".to_string(),
                "SSD_Benchmark_05.10.26_10-57_02_retest.json".to_string()
            ]
        );
        assert_eq!(
            s(c, "current_health_evidence"),
            "NVMe_Health_05.10.26_10-57_PD3_02.json"
        );
    }

    /// Legacy evidence (no timestamps, retest named after the first run):
    /// the retest still sorts directly after its base, so the confirmed
    /// sequence wins over the colliding `_02`.
    #[test]
    fn legacy_retest_without_timestamps_still_ends_the_sequence() {
        let legacy = |stab: &str, role: &str| {
            format!(
                "{{\"run_role\":\"{role}\",\"physical_disk_index\":3,\"model\":\"M\",\"disk\":\"PHYS#M#S\",\"stability\":\"{stab}\"}}"
            )
            .into_bytes()
        };
        let entries = vec![
            EvidenceFile::new(
                "SSD_Benchmark_05.10.26_10-57.json",
                legacy("ACCEPT", "initial"),
            ),
            EvidenceFile::new(
                "SSD_Benchmark_05.10.26_10-57_02.json",
                legacy("UNSTABLE", "initial"),
            ),
            EvidenceFile::new(
                "SSD_Benchmark_05.10.26_10-57_retest.json",
                legacy("ACCEPT", "automatic_retest"),
            ),
            EvidenceFile::new(
                "SSD_Benchmark_05.10.26_10-58.json",
                legacy("STABLE", "initial"),
            ),
        ];
        let v = parsed(&build(&ctx(), &entries));
        // A later initial run (10-58) is newer than everything at 10-57.
        assert_eq!(s(disk_entry(&v, "ssd_benchmark"), "status"), "STABLE");
        let v = parsed(&build(&ctx(), &entries[..3]));
        assert_eq!(s(disk_entry(&v, "ssd_benchmark"), "status"), "ACCEPT");
    }

    #[test]
    fn crash_latest_evidence_is_the_complete_set_of_the_newest_crash() {
        let summary = |status: &str| {
            format!("{{\"analysis_status\":\"{status}\",\"confidence\":\"MEDIUM\"}}").into_bytes()
        };
        let entries = vec![
            EvidenceFile::new("CrashDump_Analysis_06.10.26_11-00_01.txt", b"a".to_vec()),
            EvidenceFile::new(
                "CrashDump_Summary_06.10.26_11-00_01.json",
                summary("COMPLETED"),
            ),
            EvidenceFile::new(
                "CrashDump_Dump_06.10.26_11-00_01_100326-9500-01.dmp",
                b"d".to_vec(),
            ),
            EvidenceFile::new("CrashDump_Analysis_06.10.26_11-00_02.txt", b"a".to_vec()),
            EvidenceFile::new(
                "CrashDump_Summary_06.10.26_11-00_02.json",
                summary("COMPLETED"),
            ),
            EvidenceFile::new(
                "CrashDump_Dump_06.10.26_11-00_02_092926-1234-01.dmp",
                b"d".to_vec(),
            ),
            EvidenceFile::new("CrashDump_Analysis_05.10.26_09-00_01.txt", b"a".to_vec()),
        ];
        let v = parsed(&build(&ctx(), &entries));
        let modules = v.get("modules").unwrap().as_arr().unwrap();
        let m = modules
            .iter()
            .find(|m| m.get("name").and_then(Value::as_str) == Some("crash_dump_analysis"))
            .unwrap();
        let latest = strs(m, "latest_evidence");
        assert_eq!(latest.len(), 3, "{latest:?}");
        assert!(latest.iter().any(|n| n.ends_with("100326-9500-01.dmp")));
        assert!(
            latest
                .iter()
                .any(|n| n == "CrashDump_Analysis_06.10.26_11-00_01.txt")
        );
        assert!(
            latest
                .iter()
                .any(|n| n == "CrashDump_Summary_06.10.26_11-00_01.json")
        );
    }

    #[test]
    fn hardware_and_system_states_are_separate_in_the_manifest() {
        let mut c = ctx();
        c.system_state = Some("ATTENTION_BSOD".into());
        c.hardware_state = Some("OK".into());
        let v = parsed(&build(&c, &entries()));
        let st = v.get("state").unwrap();
        assert_eq!(s(st, "system"), "ATTENTION_BSOD");
        assert_eq!(s(st, "hardware"), "OK");
        assert!(s(st, "note").contains("does not mean the computer is healthy"));
        // Without states the field is simply absent (backward compatible).
        assert!(parsed(&build(&ctx(), &entries())).get("state").is_none());
    }

    /// v1.0 Client Identity: the session id and client of the report.
    #[test]
    fn session_identity_is_in_the_manifest_and_additive() {
        let mut c = ctx();
        c.session = Some(("S-20260928-103500-1".into(), "Алексей".into()));
        let v = parsed(&build(&c, &entries()));
        let session = v.get("session").unwrap();
        assert_eq!(s(session, "session_id"), "S-20260928-103500-1");
        assert_eq!(s(session, "client_name"), "Алексей");
        assert_eq!(s(&v, "computer_name"), "MSI");
        // Empty client stays an empty string (only the computer names it).
        c.session = Some(("S-2".into(), String::new()));
        let v = parsed(&build(&c, &entries()));
        assert_eq!(s(v.get("session").unwrap(), "client_name"), "");
        // Unbound package: field absent (backward compatible).
        assert!(parsed(&build(&ctx(), &entries())).get("session").is_none());
    }

    #[test]
    fn event_evidence_is_a_manifest_module_with_its_count() {
        let mut e = entries();
        e.push(EvidenceFile::new(
            "Event_Evidence_06.10.26_11-00.json",
            b"{\"status\":\"COLLECTED\",\"aggregate_count\":12}".to_vec(),
        ));
        let v = parsed(&build(&ctx(), &e));
        let modules = v.get("modules").unwrap().as_arr().unwrap();
        let m = modules
            .iter()
            .find(|m| m.get("name").and_then(Value::as_str) == Some("event_evidence"))
            .expect("event_evidence module");
        assert_eq!(s(m, "result_status"), "COLLECTED");
        assert!(matches!(m.get("aggregate_count"), Some(Value::Num(n)) if *n == 12.0));
    }

    /// v1.0 item 13 / 49: ATA SMART collected → the manifest NEVER says
    /// UNSUPPORTED for that disk; the correlation keeps its storage state.
    #[test]
    fn ata_smart_present_is_never_manifest_unsupported() {
        use crate::storage_health::tests::{ata, sata_health};
        let h = sata_health(ata(&[(5, 100, 10, 0), (194, 70, 0, 33)]));
        assert_eq!(h.status.as_str(), "UNSUPPORTED", "NVMe log status alone");
        let inputs = crate::storage_health::StorageHealthInputs {
            physical_identity: h.physical_identity.clone(),
            disk_index: Some(1),
            benchmark: None,
            retest: crate::storage_health::RetestOutcome::NotNeeded,
            nvme: Some(h.clone()),
            events: crate::storage_health::EventsInput::Collected(Vec::new()),
            assessed_at: "2026-10-09T10:00:00".into(),
        };
        let c = crate::storage_health::classify(&inputs);
        let files = vec![
            EvidenceFile::new(
                "NVMe_Health_09.10.26_10-00_PD1.json",
                crate::nvme_health::to_json(&h).into_bytes(),
            ),
            EvidenceFile::new(
                "Storage_Correlation_09.10.26_10-00_PD1.json",
                crate::storage_health::to_json(
                    &inputs,
                    &c,
                    "Patriot P210 512GB",
                    Some("NVMe_Health_09.10.26_10-00_PD1.json"),
                    &[],
                )
                .into_bytes(),
            ),
        ];
        let v = parsed(&build(&ctx(), &files));
        let modules = v.get("modules").unwrap().as_arr().unwrap();
        let disk_status = |name: &str| {
            let m = modules.iter().find(|m| s(m, "name") == name).unwrap();
            s(&m.get("disks").unwrap().as_arr().unwrap()[0], "status").to_string()
        };
        assert_eq!(disk_status("nvme_health"), "OK");
        assert_eq!(disk_status("storage_correlation"), "OK");
    }
}
