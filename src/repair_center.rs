//! Repair workspace: immutable analysed plan, explicit authorization and one executor.
//! No operation is started by page navigation or diagnostic orchestration.
use crate::deep_checks::json::{self, Value};
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CacheFile {
    pub path: String,
    pub hash: String,
    pub identity: String,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Installer {
    pub path: String,
    pub hash: String,
    pub product: String,
    pub name: String,
    pub publisher: String,
    pub version: String,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Operation {
    Analyze,
    AnalyzeInstaller(String),
    AnalyzeProduct(String),
    MsiInstall(Installer),
    History,
    Compare(PathBuf, PathBuf),
    ThumbnailCleanup(Vec<CacheFile>),
    UpdateCache,
    CheckVolume(String),
    RepairVolume(String),
    MsiRepair(String),
    MsiRemove(String),
    ComponentAnalysis,
    ComponentCleanup,
}
impl Operation {
    pub fn mutating(&self) -> bool {
        matches!(
            self,
            Self::UpdateCache
                | Self::MsiInstall(_)
                | Self::ThumbnailCleanup(_)
                | Self::RepairVolume(_)
                | Self::MsiRepair(_)
                | Self::MsiRemove(_)
                | Self::ComponentCleanup
        )
    }
    pub fn label(&self) -> &str {
        match self {
            Self::Analyze => "Анализ",
            Self::AnalyzeInstaller(_) => "Проверка MSI-пакета",
            Self::AnalyzeProduct(_) => "Анализ ошибок выбранной программы",
            Self::MsiInstall(_) => "Установка выбранного MSI-пакета",
            Self::History => "История ремонта",
            Self::Compare(_, _) => "Сравнение диагностических отчётов",
            Self::ThumbnailCleanup(_) => "Очистка выбранных эскизов Windows",
            Self::UpdateCache => "Обслуживание кэша Windows Update",
            Self::CheckVolume(_) => "Проверка тома",
            Self::RepairVolume(_) => "Исправление тома",
            Self::MsiRepair(_) => "Восстановление программы",
            Self::MsiRemove(_) => "Удаление программы",
            Self::ComponentAnalysis => "Анализ хранилища компонентов",
            Self::ComponentCleanup => "Обслуживание компонентов",
        }
    }
    fn parameters(&self) -> (&str, &str) {
        match self {
            Self::Analyze => ("Analyze", ""),
            Self::AnalyzeInstaller(p) => ("AnalyzeInstaller", p),
            Self::AnalyzeProduct(p) => ("AnalyzeProduct", p),
            Self::MsiInstall(p) => ("MsiInstall", &p.path),
            Self::History => ("History", ""),
            Self::Compare(_, _) => ("Compare", ""),
            Self::ThumbnailCleanup(_) => ("ThumbnailCleanup", ""),
            Self::UpdateCache => ("UpdateCache", ""),
            Self::CheckVolume(v) => ("CheckVolume", v),
            Self::RepairVolume(v) => ("RepairVolume", v),
            Self::MsiRepair(v) => ("MsiRepair", v),
            Self::MsiRemove(v) => ("MsiRemove", v),
            Self::ComponentAnalysis => ("ComponentAnalysis", ""),
            Self::ComponentCleanup => ("ComponentCleanup", ""),
        }
    }
    pub fn valid(&self) -> bool {
        match self {
            Self::AnalyzeInstaller(p)=>Path::new(p).is_absolute() && p.to_ascii_lowercase().ends_with(".msi") && !p.chars().any(|c|c.is_control() || c=='"'),
            Self::MsiInstall(p)=>Operation::AnalyzeInstaller(p.path.clone()).valid() && Operation::MsiRemove(p.product.clone()).valid() && p.hash.len()==64 && p.hash.bytes().all(|b|b.is_ascii_hexdigit()) && !p.publisher.is_empty(),Self::ThumbnailCleanup(files)=>!files.is_empty() && files.len()<=128 && files.iter().all(|f|Path::new(&f.path).is_absolute() && f.hash.len()==64 && f.hash.bytes().all(|b|b.is_ascii_hexdigit()) && !f.identity.is_empty()),Self::CheckVolume(v)|Self::RepairVolume(v)=>v.len()==2 && v.as_bytes()[0].is_ascii_uppercase() && v.ends_with(':'),Self::MsiRepair(g)|Self::MsiRemove(g)|Self::AnalyzeProduct(g)=>regex::Regex::new(r"^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$").unwrap().is_match(g),_=>true}
    }
    pub fn consequences(&self) -> &str {
        match self {
            Self::MsiInstall(_) => {
                "Будет установлен выбранный подписанный MSI-пакет. Установщик может выполнять собственные изменения системы. Подпись не гарантирует безопасность. Автоматическая перезагрузка запрещена."
            }
            Self::ThumbnailCleanup(_) => {
                "Будут удалены только выбранные базы эскизов. Windows создаст их повторно. Изменённые или используемые файлы и ссылки пропускаются; удаление необратимо."
            }
            Self::UpdateCache => {
                "Будет сохранён журнал ошибок и переименован только кэш загрузок Windows Update. Службы будут возвращены к исходному состоянию. Старые данные сохранятся. Политики и разрешения не меняются."
            }
            Self::RepairVolume(_) => {
                "CHKDSK /spotfix изменяет файловую систему. Занятый том не отключается принудительно. Автоматического согласия на перезагрузку нет. Сохрани резервную копию; аппаратный отказ накопителя эта операция не устраняет."
            }
            Self::MsiRepair(_) => {
                "Штатное восстановление выбранного MSI-продукта может запросить исходный установщик. Автоматическая перезагрузка запрещена."
            }
            Self::MsiRemove(_) => {
                "Будет штатно удалён только выбранный MSI-продукт. Его настройки и данные могут быть утрачены. Удаление драйверов и DriverStore не выполняется."
            }
            Self::ComponentCleanup => {
                "DISM StartComponentCleanup удаляет заменённые компоненты. ResetBase не используется. Возможность отката отдельных обновлений может сократиться."
            }
            _ => "Анализ и проверка не запрашивают исправление.",
        }
    }
}
#[derive(Clone, Debug)]
pub struct Plan {
    pub operation: Operation,
    pub identity: String,
    pub snapshot: String,
    pub created: Instant,
}
impl Plan {
    pub fn authorize(
        &self,
        confirmed: bool,
        current: &str,
        snapshot: &str,
        busy: bool,
    ) -> Result<(), String> {
        if !confirmed || !self.operation.valid() {
            return Err("План не подтверждён или недопустим".into());
        }
        if busy {
            return Err("Другая операция ещё выполняется".into());
        }
        if self.identity != current
            || self.snapshot != snapshot
            || self.created.elapsed() > Duration::from_secs(300)
        {
            return Err("План устарел: повтори анализ выбранного объекта".into());
        }
        Ok(())
    }
}
#[derive(Clone, Debug)]
pub struct ResultRecord {
    pub directory: PathBuf,
    pub raw: String,
    pub error: Option<String>,
}
pub fn field<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or("")
}
pub fn rows<'a>(v: &'a Value, k: &str) -> &'a [Value] {
    match v.get(k) {
        Some(Value::Arr(a)) => a,
        _ => &[],
    }
}
pub fn run(
    op: Operation,
    identity: String,
    root: PathBuf,
    snapshot: String,
    cancel: Arc<AtomicBool>,
) -> ResultRecord {
    if let Operation::Compare(current, old) = &op {
        let detail = compare_archives(current, old, &identity)
            .unwrap_or_else(|e| format!("Недостаточно данных для сравнения: {e}"));
        return ResultRecord {
            directory: root,
            raw: format!(
                "WSD_REPAIR_CENTER {{\"Status\":\"COMPARISON\",\"Detail\":{}}}",
                json::string(&detail)
            ),
            error: None,
        };
    }
    if op == Operation::History {
        let mut entries = Vec::new();
        let mut total = 0usize;
        if let Ok(dirs) = std::fs::read_dir(&root) {
            for entry in dirs.filter_map(Result::ok).take(1000) {
                if !entry
                    .file_type()
                    .is_ok_and(|t| t.is_dir() && !t.is_symlink())
                {
                    continue;
                }
                let p = entry.path().join("operation.json");
                if !std::fs::metadata(&p).is_ok_and(|m| m.len() <= 1024 * 1024) {
                    continue;
                }
                let Ok(raw) = std::fs::read_to_string(p) else {
                    continue;
                };
                let Some(v) = json::parse(raw.trim_start_matches('\u{feff}')) else {
                    continue;
                };
                if !field(&v, "computer").eq_ignore_ascii_case(&identity) {
                    continue;
                }
                let result = entry.path().join("result.txt");
                let detail = if std::fs::metadata(&result).is_ok_and(|m| m.len() <= 2 * 1024 * 1024)
                {
                    std::fs::read_to_string(result)
                        .unwrap_or_else(|_| "Результат недоступен".into())
                } else {
                    "Результат недоступен или превышает предел отображения; исходник сохранён"
                        .into()
                };
                let row = format!(
                    "{{\"metadata\":{},\"detail\":{}}}",
                    raw.trim_start_matches('\u{feff}'),
                    json::string(&detail)
                );
                total = total.saturating_add(row.len());
                if total > 16 * 1024 * 1024 || entries.len() >= 100 {
                    break;
                }
                entries.push(row);
            }
        }
        return ResultRecord {
            directory: root,
            raw: format!(
                "WSD_REPAIR_CENTER {{\"Status\":\"HISTORY_LOADED\",\"Entries\":[{}]}}",
                entries.join(",")
            ),
            error: None,
        };
    }
    let dir = root.join(crate::repair::operation_id());
    let execute = || -> Result<String, String> {
        if !op.valid() {
            return Err("Недопустимый объект".into());
        }
        if cancel.load(Ordering::SeqCst) {
            return Err("Отменено до запуска".into());
        }
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let q = json::string;
        let record = format!(
            "{{\"computer\":{},\"operation\":{},\"confirmed\":{},\"producer_version\":{},\"started_at\":{}}}",
            q(&identity),
            q(op.label()),
            op.mutating(),
            q(crate::APP_VERSION),
            q(&crate::repair::timestamp())
        );
        let object_label = match &op {
            Operation::MsiRepair(id) | Operation::MsiRemove(id) | Operation::AnalyzeProduct(id) => {
                parse(&snapshot)
                    .and_then(|v| {
                        rows(&v, "Programs")
                            .iter()
                            .find(|p| field(p, "ProductCode") == id)
                            .map(|p| format!("{} · {}", field(p, "Name"), field(p, "Version")))
                    })
                    .unwrap_or_else(|| "Выбранная программа".into())
            }
            Operation::MsiInstall(p) => format!("{} · {}", p.name, p.version),
            _ => plan_target(&op),
        };
        let record = format!(
            "{},\"target\":{},\"object_label\":{}}}",
            record.trim_end_matches('}'),
            q(&plan_target(&op)),
            q(&object_label)
        );
        std::fs::write(dir.join("operation.json"), record)
            .map_err(|e| format!("Журнал недоступен; запуск запрещён: {e}"))?;
        let (kind, target) = op.parameters();
        let expected=crate::repair_center::parse(&snapshot).map_or("{}".into(),|v|{let target=op.parameters().1;let key=if matches!(op,Operation::MsiRemove(_)|Operation::MsiRepair(_)){"Programs"}else{"Volumes"};let found=rows(&v,key).iter().find(|v|field(v,if key=="Programs"{"ProductCode"}else{"Drive"})==target);found.map_or("{}".into(),|v|format!("{{\"Name\":{},\"Version\":{},\"Publisher\":{},\"Context\":{},\"VolumeSerialNumber\":{}}}",json::string(field(v,"Name")),json::string(field(v,"Version")),json::string(field(v,"Publisher")),json::string(field(v,"Context")),json::string(field(v,"VolumeSerialNumber"))))});
        let expected = if let Operation::ThumbnailCleanup(files) = &op {
            format!(
                "[{}]",
                files
                    .iter()
                    .map(|f| format!(
                        "{{\"Path\":{},\"Hash\":{},\"Identity\":{}}}",
                        json::string(&f.path),
                        json::string(&f.hash),
                        json::string(&f.identity)
                    ))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        } else {
            expected
        };
        let expected = if let Operation::MsiInstall(p) = &op {
            format!(
                "{{\"Hash\":{},\"ProductCode\":{},\"Name\":{},\"Publisher\":{},\"Version\":{}}}",
                json::string(&p.hash),
                json::string(&p.product),
                json::string(&p.name),
                json::string(&p.publisher),
                json::string(&p.version)
            )
        } else {
            expected
        };
        let script = format!(
            "{}\n$ExpectedJSON='{}'\n$Operation='{}'\n$Target='{}'\n$Evidence='{}'\n{}",
            crate::ps_exec::PS_PRELUDE,
            expected.replace('\'', "''"),
            kind,
            target.replace('\'', "''"),
            dir.to_string_lossy().replace('\'', "''"),
            include_str!("../embedded/WinStateDiag/RepairCenter.ps1").replace(
                "__THUMBNAIL_B64__",
                &crate::ps_exec::encoded_command(include_str!(
                    "../embedded/WinStateDiag/ThumbnailCleanup.cs"
                ))
            )
        );
        // The native runner owns the process tree. Mutations have a long safety
        // ceiling; a timeout is a failed/unknown result, never a verified repair.
        let raw = run_process(&script, &cancel, op.mutating())?;
        std::fs::write(dir.join("result.txt"), &raw)
            .map_err(|e| format!("Ошибка сохранения результата: {e}"))?;
        if let Some(value) = parse(&raw) {
            let id = dir.file_name().unwrap_or_default().to_string_lossy();
            let terminal = format!(
                "{{\"repair_id\":{},\"computer\":{},\"source\":\"REPAIR_CENTER\",\"check\":{},\"status\":{},\"repair_status\":\"RESULT_UNKNOWN\",\"completed_at\":{},\"raw_result\":{}}}",
                json::string(&id),
                json::string(&identity),
                json::string(op.parameters().0),
                json::string(field(&value, "Status")),
                json::string(&crate::repair::timestamp()),
                json::string(&raw)
            );
            std::fs::write(dir.join(format!("result-{id}.json")), terminal)
                .map_err(|e| format!("Ошибка сохранения итоговой записи: {e}"))?;
        }
        Ok(raw)
    };
    match execute() {
        Ok(raw) => ResultRecord {
            directory: dir,
            raw,
            error: None,
        },
        Err(e) => {
            let _ = std::fs::write(dir.join("failure.txt"), &e);
            ResultRecord {
                directory: dir,
                raw: String::new(),
                error: Some(e),
            }
        }
    }
}
pub fn parse(raw: &str) -> Option<Value> {
    crate::ps_exec::marked_line(raw, "WSD_REPAIR_CENTER ").and_then(json::parse)
}
pub fn history_files(dir: &Path) -> Vec<crate::report_package::EvidenceFile> {
    let Some(id) = dir.file_name().and_then(|s| s.to_str()) else {
        return Vec::new();
    };
    std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .filter_map(|e| {
            let meta = e.file_type().ok()?;
            if !meta.is_file() || meta.is_symlink() {
                return None;
            }
            let data = std::fs::read(e.path()).ok()?;
            Some(crate::report_package::EvidenceFile::new(
                format!("RepairHistory/{id}/{}", e.file_name().to_string_lossy()),
                data,
            ))
        })
        .collect()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stale_identity_confirmation_and_busy_are_rejected() {
        let mut p = Plan {
            operation: Operation::MsiRemove("{12345678-1234-1234-1234-123456789ABC}".into()),
            identity: "A".into(),
            snapshot: "S".into(),
            created: Instant::now(),
        };
        assert!(p.authorize(true, "A", "S", false).is_ok());
        for (c, i, s, b) in [
            (false, "A", "S", false),
            (true, "B", "S", false),
            (true, "A", "changed", false),
            (true, "A", "S", true),
        ] {
            assert!(p.authorize(c, i, s, b).is_err())
        }
        p.created = Instant::now() - Duration::from_secs(301);
        assert!(p.authorize(true, "A", "S", false).is_err());
    }
    #[test]
    fn object_validation_never_accepts_commands() {
        for s in ["C: /r", "C:&whoami", "../x", "C:\\", ";", "{not-guid}"] {
            assert!(!Operation::RepairVolume(s.into()).valid());
            assert!(!Operation::MsiRemove(s.into()).valid());
        }
    }
}

pub fn compare_materials(
    current: &[(String, Vec<u8>)],
    old: &[(String, Vec<u8>)],
    computer: &str,
) -> Result<String, String> {
    fn document(files: &[(String, Vec<u8>)], name: &str) -> Option<Value> {
        files
            .iter()
            .find(|(n, _)| n == name)
            .and_then(|(_, b)| std::str::from_utf8(b).ok())
            .and_then(|s| json::parse(s.trim_start_matches('\u{feff}')))
    }
    let a = document(current, "manifest.json").ok_or("Нет текущего manifest")?;
    let b = document(old, "manifest.json").ok_or("Нет предыдущего manifest")?;
    if !field(&a, "computer_name").eq_ignore_ascii_case(computer)
        || !field(&b, "computer_name").eq_ignore_ascii_case(computer)
    {
        return Err("Отчёт относится к другому компьютеру".into());
    }
    let schema = field(&a, "schema_version");
    if schema.is_empty() || schema != field(&b, "schema_version") {
        return Err("Схемы manifest отсутствуют или различаются".into());
    }
    let identity = |files: &[(String, Vec<u8>)]| {
        files
            .iter()
            .filter(|(n, _)| n.starts_with("Hardware_") && n.ends_with(".json"))
            .rev()
            .find_map(|(_, b)| {
                let v = json::parse(std::str::from_utf8(b).ok()?.trim_start_matches('\u{feff}'))?;
                v.get("Ram")
                    .and_then(|r| r.get("Identity"))
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
            })
    };
    let aid = identity(current).ok_or("Нет аппаратного идентификатора текущего отчёта")?;
    let bid = identity(old).ok_or("Нет аппаратного идентификатора предыдущего отчёта")?;
    if aid != bid {
        return Err("Аппаратный идентификатор изменился: возможна замена оборудования; улучшение не выводится".into());
    }
    let a = document(current, "State_Summary.json").ok_or("Нет текущего State_Summary")?;
    let b = document(old, "State_Summary.json").ok_or("Нет предыдущего State_Summary")?;
    let mut lines = Vec::new();
    for key in [
        "system",
        "hardware",
        "execution_status",
        "coverage_status",
        "repair_status",
    ] {
        let (a, b) = (field(&a, key), field(&b, key));
        lines.push(if a.is_empty() || b.is_empty() {
            format!("{key}: недостаточно данных")
        } else {
            format!("{key}: {b} → {a}")
        });
    }
    Ok(format!(
        "Принадлежность: имя компьютера, схема и аппаратный fingerprint совпали.\n{}\nЭто сравнение сохранённых статусов, без вывода причин и без подмены отсутствующих измерений нулём.",
        lines.join("\n")
    ))
}
fn compare_archives(current: &Path, old: &Path, computer: &str) -> Result<String, String> {
    let a = crate::ai_export::repair_comparison_materials(current)?;
    let b = crate::ai_export::repair_comparison_materials(old)?;
    compare_materials(&a, &b, computer)
}

#[cfg(test)]
mod comparison_tests {
    use super::*;
    fn materials(pc: &str, identity: &str) -> Vec<(String, Vec<u8>)> {
        vec![
            (
                "manifest.json".into(),
                format!(
                    "{{\"schema_version\":\"1.0\",\"computer_name\":{}}}",
                    json::string(pc)
                )
                .into_bytes(),
            ),
            (
                "Hardware_fixture.json".into(),
                format!("{{\"Ram\":{{\"Identity\":{}}}}}", json::string(identity)).into_bytes(),
            ),
            (
                "State_Summary.json".into(),
                br#"{"system":"ATTENTION","hardware":"PARTIAL"}"#.to_vec(),
            ),
        ]
    }
    #[test]
    fn comparison_never_accepts_other_machine_hardware_or_missing_measurements() {
        let a = materials("SYNTHETIC", "HW-A");
        let result = compare_materials(&a, &a, "SYNTHETIC").unwrap();
        assert!(result.contains("execution_status: недостаточно данных"));
        assert!(compare_materials(&a, &materials("OTHER", "HW-A"), "SYNTHETIC").is_err());
        assert!(compare_materials(&a, &materials("SYNTHETIC", "HW-B"), "SYNTHETIC").is_err());
        let mut missing = a.clone();
        missing.retain(|(n, _)| !n.starts_with("Hardware_"));
        assert!(compare_materials(&a, &missing, "SYNTHETIC").is_err());
        let mut schema = a.clone();
        schema[0].1 = br#"{"schema_version":"2.0","computer_name":"SYNTHETIC"}"#.to_vec();
        assert!(compare_materials(&a, &schema, "SYNTHETIC").is_err());
    }
}

pub fn status_label(code: &str) -> &str {
    match code {
        "ANALYZED" => "Анализ завершён",
        "PARTIAL" => "Выполнено частично; проверь пропуски",
        "COMPLETED_UNVERIFIED" => "Операция завершена; исправность не подтверждена",
        "HISTORY_LOADED" => "История загружена",
        "COMPARISON" => "Сравнение отчётов",
        "REMOVAL_VERIFIED" => "Удаление продукта подтверждено",
        "REBOOT_REQUIRED" => "Требуется ручная перезагрузка",
        "FAILED" => "Ошибка выполнения",
        "PRODUCT_ANALYZED" => {
            "Анализ выбранной программы завершён; отсутствие событий не доказывает исправность"
        }
        "INSTALLER_ANALYZED" => "Пакет проверен; установка не запускалась",
        "CLEANUP_COMPLETED" => "Очистка выбранных объектов завершена",
        "CHECK_COMPLETED" => "Проверка завершена; см. результат",
        _ => "Результат не подтверждён",
    }
}

fn run_process(script: &str, cancel: &AtomicBool, mutating: bool) -> Result<String, String> {
    use std::{
        io::Read,
        process::{Command, Stdio},
    };
    let mut command = Command::new("powershell.exe");
    command
        .env_remove("PSModulePath")
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-EncodedCommand",
        ])
        .arg(crate::ps_exec::encoded_command(script));
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut guard = crate::engine::ProcessGuard::spawn(command).map_err(|e| e.to_string())?;
    let stdout = guard
        .child_mut()
        .stdout
        .take()
        .ok_or("Нет канала результата")?;
    let reader = std::thread::spawn(move || {
        let mut stdout = stdout;
        let mut bytes = Vec::new();
        let mut chunk = [0u8; 16384];
        loop {
            let n = stdout.read(&mut chunk)?;
            if n == 0 {
                break;
            }
            let keep = n.min((16 * 1024 * 1024 + 1usize).saturating_sub(bytes.len()));
            bytes.extend_from_slice(&chunk[..keep]);
        }
        Ok::<_, std::io::Error>(bytes)
    });
    let never = AtomicBool::new(false);
    // Read-only workers are cancellable and bounded. Never force-kill servicing:
    // the GUI keeps the operation alive and makes the elapsed time visible.
    let end = guard.wait_or_cancel(
        if mutating { &never } else { cancel },
        if mutating {
            None
        } else {
            Some(Duration::from_secs(180))
        },
    );
    drop(guard);
    let bytes = reader
        .join()
        .map_err(|_| "Чтение результата прервано")?
        .map_err(|e| e.to_string())?;
    end.map_err(|e| match e {
        crate::engine::WaitEnd::Cancelled => "Анализ отменён".into(),
        crate::engine::WaitEnd::TimedOut => "Истекло время анализа; результат неполный".into(),
        crate::engine::WaitEnd::Io(e) => e.to_string(),
    })?;
    if bytes.len() > 16 * 1024 * 1024 {
        return Err("Ответ превышает предел; исходные журналы сохранены".into());
    }
    String::from_utf8(bytes).map_err(|_| "Некорректная кодировка результата".into())
}

#[cfg(test)]
mod process_tests {
    use super::*;
    #[test]
    fn read_worker_cancels_and_drains_oversized_output_without_deadlock() {
        if crate::ps_exec::test_host().is_none() {
            return;
        }
        let flag = Arc::new(AtomicBool::new(false));
        let signal = flag.clone();
        let t = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            signal.store(true, Ordering::SeqCst)
        });
        let started = Instant::now();
        assert!(
            run_process("Start-Sleep -Seconds 20", &flag, false)
                .unwrap_err()
                .contains("отменён")
        );
        t.join().unwrap();
        assert!(started.elapsed() < Duration::from_secs(5));
        let script = format!(
            "{}\\n[Console]::Write(('x' * (17*1024*1024)))",
            crate::ps_exec::PS_PRELUDE
        )
        .replace("\\n", "\n");
        assert!(
            run_process(&script, &AtomicBool::new(false), false)
                .unwrap_err()
                .contains("превышает")
        );
    }
}

pub fn plan_target(op: &Operation) -> String {
    match op {
        Operation::CheckVolume(v) | Operation::RepairVolume(v) => v.clone(),
        Operation::MsiInstall(p) => format!("{} · {} · {}", p.name, p.product, p.path),
        Operation::MsiRepair(id) | Operation::MsiRemove(id) | Operation::AnalyzeProduct(id) => {
            id.clone()
        }
        Operation::ThumbnailCleanup(files) => format!("{} выбранных баз эскизов", files.len()),
        Operation::UpdateCache => {
            r"Windows\SoftwareDistribution\Download (старый кэш сохраняется)".into()
        }
        Operation::ComponentCleanup => {
            "Хранилище компонентов текущей Windows, без ResetBase".into()
        }
        _ => op.label().into(),
    }
}

#[cfg(test)]
mod completion_tests {
    use super::*;
    #[test]
    fn selected_product_analysis_is_readonly_and_guid_bound() {
        assert!(
            !Operation::AnalyzeProduct("{12345678-1234-1234-1234-123456789ABC}".into()).mutating()
        );
        for id in ["", "name", "*", "{123};Remove-Item"] {
            assert!(!Operation::AnalyzeProduct(id.into()).valid());
        }
    }
    #[test]
    fn explicit_plan_names_the_real_target() {
        assert_eq!(plan_target(&Operation::RepairVolume("D:".into())), "D:");
        assert!(plan_target(&Operation::UpdateCache).contains("Download"));
    }
}
