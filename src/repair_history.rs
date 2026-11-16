//! Durable local Repair evidence. No repair runs here; old records are read-only.
use crate::{
    deep_checks::json::{self, Value},
    repair::{self, Plan, Report},
    report_package::EvidenceFile,
};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};
fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or("")
}
pub fn roots() -> Vec<PathBuf> {
    vec![
        crate::app_paths::data_root(Path::new("")).join("Logs/Repair"),
        std::env::temp_dir().join("EXPC/WinStateDiag/Repair"),
    ]
}
fn write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    let mut f = fs::File::create(path).map_err(|e| e.to_string())?;
    f.write_all(bytes)
        .and_then(|_| f.sync_all())
        .map_err(|e| e.to_string())
}
pub fn directory(primary: &Path, fallback: &Path) -> Result<(PathBuf, Option<String>), String> {
    fn create(p: &Path) -> Result<(), String> {
        fs::create_dir_all(p.parent().ok_or("missing parent")?)
            .and_then(|_| fs::create_dir(p))
            .map_err(|e| e.to_string())?;
        write(&p.join("journal-ready.txt"), b"Repair journal initialized")
    }
    match create(primary) {
        Ok(()) => Ok((primary.into(), None)),
        Err(e) => {
            create(fallback)
                .map_err(|f| format!("Основной журнал: {e}; резервный: {f}; ремонт не запущен"))?;
            Ok((
                fallback.into(),
                Some(format!(
                    "Ошибка основного журнала: {e}. Используется резервный журнал: {}",
                    fallback.display()
                )),
            ))
        }
    }
}
fn exe_hash() -> String {
    #[cfg(test)]
    {
        "SYNTHETIC_TEST_EXE".into()
    }
    #[cfg(not(test))]
    {
        static HASH: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        HASH.get_or_init(|| {
            let Ok(p) = std::env::current_exe() else {
                return "UNKNOWN".into();
            };
            let cmd = format!(
                "(Get-FileHash -LiteralPath '{}' -Algorithm SHA256 -ErrorAction Stop).Hash",
                p.to_string_lossy().replace('\'', "''")
            );
            crate::ps_exec::run_powershell(
                "powershell.exe",
                &cmd,
                std::time::Duration::from_secs(30),
            )
            .ok()
            .map(|s| s.trim().trim_start_matches('\u{feff}').to_owned())
            .filter(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
            .unwrap_or("UNKNOWN".into())
        })
        .clone()
    }
}
pub fn start(dir: &Path, computer: &str, plan: &Plan, admin: bool) -> Result<(), String> {
    let q = json::string;
    let id = dir.file_name().unwrap_or_default().to_string_lossy();
    let text = format!(
        "{{\"repair_id\":{},\"computer\":{},\"started_at\":{},\"producer_version\":{},\"exe_sha256\":{},\"check\":{},\"command\":{},\"verification_command\":{},\"initial_admin\":{},\"original_finding\":{},\"status\":\"STARTED\"}}",
        q(&id),
        q(computer),
        q(&repair::timestamp()),
        q(crate::APP_VERSION),
        q(&exe_hash()),
        q(plan.check.key()),
        q(&plan.command()),
        q(&plan.verification()),
        admin,
        q(&plan.before.detail)
    );
    write(&dir.join("operation.json"), text.as_bytes())
}
pub fn finish(dir: &Path, reports: &mut [Report]) {
    for report in reports {
        let path = dir.join(format!("result-{}.json", report.id));
        if let Err(error) = write(&path, report.json().as_bytes()) {
            report
                .message
                .push_str(&format!(" Ошибка сохранения журнала: {error}."));
            #[cfg(not(test))]
            {
                let fallback = roots()[1].join(dir.file_name().unwrap_or_default());
                if let Err(e) = fs::create_dir_all(&fallback) {
                    report
                        .message
                        .push_str(&format!(" Резервный журнал недоступен: {e}."));
                } else {
                    for name in ["operation.json", "before-context.json"] {
                        if let Ok(b) = fs::read(dir.join(name)) {
                            let _ = write(&fallback.join(name), &b);
                        }
                    }
                    if let Err(e) = write(
                        &fallback.join(format!("result-{}.json", report.id)),
                        report.json().as_bytes(),
                    ) {
                        report
                            .message
                            .push_str(&format!(" Резервный журнал недоступен: {e}."));
                    }
                }
            }
        }
    }
}
/// Per-computer history is included in subsequent diagnostic ZIPs, without applying
/// historical verified results to the current checks. Read/permission errors remain explicit.
pub fn collect(roots: &[PathBuf], computer: &str) -> Vec<EvidenceFile> {
    let mut files = BTreeMap::<String, Vec<u8>>::new();
    let mut errors = Vec::new();
    let mut operations = 0;
    let mut terminal_ids = std::collections::BTreeSet::new();
    for root in roots {
        let entries = match fs::read_dir(root) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                errors.push(format!("{}: {e}", root.display()));
                continue;
            }
        };
        for entry in entries {
            let Ok(entry) = entry else {
                errors.push("Ошибка чтения каталога Repair".into());
                continue;
            };
            if !entry
                .file_type()
                .is_ok_and(|t| t.is_dir() && !t.is_symlink())
            {
                continue;
            }
            let dir = entry.path();
            let id = entry.file_name().to_string_lossy().into_owned();
            let context = fs::read_to_string(dir.join("operation.json"))
                .or_else(|_| fs::read_to_string(dir.join("before-context.json")));
            let Some(context) = context
                .ok()
                .and_then(|t| json::parse(t.trim_start_matches('\u{feff}')))
            else {
                errors.push(format!("{id}: метаданные Repair недоступны"));
                continue;
            };
            if !s(&context, "computer").eq_ignore_ascii_case(computer) {
                continue;
            }
            operations += 1;
            let mut pending = vec![dir.clone()];
            let mut terminal = false;
            while let Some(folder) = pending.pop() {
                let entries = match fs::read_dir(&folder) {
                    Ok(v) => v,
                    Err(e) => {
                        errors.push(format!("{id}: {e}"));
                        continue;
                    }
                };
                for e in entries {
                    let Ok(e) = e else {
                        errors.push(format!("{id}: ошибка записи каталога"));
                        continue;
                    };
                    let Ok(kind) = e.file_type() else { continue };
                    if kind.is_symlink() {
                        continue;
                    }
                    if kind.is_dir() {
                        pending.push(e.path());
                        continue;
                    }
                    if !kind.is_file() {
                        continue;
                    }
                    let path = e.path();
                    let relative = path
                        .strip_prefix(&dir)
                        .unwrap()
                        .to_string_lossy()
                        .replace('\\', "/");
                    match fs::read(&path) {
                        Ok(bytes) => {
                            if relative.starts_with("result-") && relative.ends_with(".json") {
                                if let Some(v) = json::parse(&String::from_utf8_lossy(&bytes)) {
                                    if !s(&v, "repair_id").is_empty() {
                                        terminal = true;
                                        terminal_ids.insert(id.clone());
                                        files.insert(
                                            format!("Repair_{}.json", s(&v, "repair_id")),
                                            bytes.clone(),
                                        );
                                    }
                                }
                            }
                            files.insert(format!("RepairHistory/{id}/{relative}"), bytes);
                        }
                        Err(e) => errors.push(format!("{id}/{relative}: {e}")),
                    }
                }
            }
            if !terminal {
                let q = json::string;
                let unknown = format!(
                    "{{\"repair_id\":{},\"check\":{},\"status\":\"COMPLETED_UNVERIFIED\",\"repair_status\":\"RESULT_UNKNOWN\",\"message\":\"Итог операции не сохранён; неизвестно, завершилась ли команда. Повторить диагностику\"}}",
                    q(&id),
                    q(s(&context, "check"))
                );
                files.insert(format!("Repair_{id}_recovered.json"), unknown.into_bytes());
            }
        }
    }
    for id in terminal_ids {
        files.remove(&format!("Repair_{id}_recovered.json"));
    }
    if operations > 0 || !errors.is_empty() {
        files.insert(
            "RepairHistoryIndex.json".into(),
            format!(
                "{{\"operations\":{operations},\"errors\":[{}]}}",
                errors
                    .iter()
                    .map(|s| json::string(s))
                    .collect::<Vec<_>>()
                    .join(",")
            )
            .into_bytes(),
        );
    }
    files
        .into_iter()
        .map(|(n, b)| EvidenceFile::new(n, b))
        .collect()
}
