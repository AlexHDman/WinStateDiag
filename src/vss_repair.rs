//! Explicit quota increase; no snapshot creation, deletion, or automatic decrease.
use crate::deep_checks::json::{self, Value};
use std::{
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};
#[derive(Clone, Debug)]
pub struct Row {
    pub source: String,
    pub storage: String,
    pub maximum: u64,
    pub used: u64,
    pub free: u64,
    pub copies: u64,
}
pub fn rows(text: &str) -> Result<Vec<Row>, String> {
    let v = json::parse(text.trim().trim_start_matches('﻿')).ok_or("VSS JSON недоступен")?;
    let Some(Value::Arr(rows)) = v.get("Rows") else {
        return Err("VSS coverage UNKNOWN".into());
    };
    let string = |v: &Value, k: &str| v.get(k).and_then(Value::as_str).unwrap_or("").to_owned();
    rows.iter()
        .map(|v| {
            Ok(Row {
                source: string(v, "For"),
                storage: string(v, "On"),
                maximum: string(v, "Maximum").parse().map_err(|_| "Квота UNKNOWN")?,
                used: string(v, "Used").parse().map_err(|_| "Used UNKNOWN")?,
                free: string(v, "Free").parse().map_err(|_| "Free UNKNOWN")?,
                copies: match v.get("Copies") {
                    Some(Value::Num(n)) => *n as u64,
                    _ => return Err("Copies UNKNOWN".into()),
                },
            })
        })
        .collect()
}
/// Compact presentation; the original JSON is kept as evidence.
pub fn summary(text: &str) -> String {
    let Some(v) = json::parse(text.trim().trim_start_matches('\u{feff}')) else {
        return text.into();
    };
    let get = |k| v.get(k).and_then(Value::as_str).unwrap_or("");
    let mut out = format!(
        "VSS: {}\n{} {}\nСоздание снимка: NOT TESTED. Успешность резервной копии: UNKNOWN.\n",
        get("Status"),
        get("Command"),
        get("Error")
    );
    let facts = v.get("After").unwrap_or(&v);
    if let Some(Value::Arr(items)) = facts.get("Rows") {
        if items.is_empty() {
            out.push_str("Ассоциации не получены. Это не подтверждает исправность VSS.\n");
        }
        for row in items {
            let s = |k| row.get(k).and_then(Value::as_str).unwrap_or("UNKNOWN");
            out.push_str(&format!(
                "{} → {}: квота {} байт, использовано {}, свободно {}\nСтарейший снимок: {:?}\n",
                s("For"),
                s("On"),
                s("Maximum"),
                s("Used"),
                s("Free"),
                row.get("Oldest")
            ));
        }
    }
    out.push_str(
        "Полные значения, идентификаторы снимков и временные отметки сохранены в JSON отчёта.",
    );
    out
}
pub fn valid(row: &Row, proposed: u64) -> bool {
    let drive = |s: &str| s.len() == 2 && s.as_bytes()[0].is_ascii_uppercase() && s.ends_with(':');
    drive(&row.source)
        && drive(&row.storage)
        && proposed > row.maximum
        && proposed - row.maximum <= row.free.saturating_sub(2 * 1024 * 1024 * 1024)
        && proposed >= row.used
        && row.maximum < u64::MAX / 2
}
pub fn recommend(row: &Row) -> Option<u64> {
    let gb = 1024 * 1024 * 1024;
    let target = row
        .maximum
        .checked_add((row.maximum / 4).max(gb))?
        .div_ceil(gb)
        .checked_mul(gb)?;
    valid(row, target).then_some(target)
}
pub fn script() -> &'static str {
    include_str!("../embedded/WinStateDiag/VssControl.ps1")
}
pub fn inspect() -> Result<String, String> {
    if cfg!(test) {
        return Err("Native VSS отключён в тестах".into());
    }
    crate::ps_exec::run_powershell("powershell.exe",&format!("{}\ntry {{ Get-VssControlFacts | ConvertTo-Json -Depth 8 -Compress }} catch {{ [pscustomobject]@{{Status='UNKNOWN';Error=$_.Exception.Message}}|ConvertTo-Json -Compress }}",script()),Duration::from_secs(45)).map_err(|e|e.to_string())
}
pub fn increase(
    row: Row,
    proposed: u64,
    confirmed: bool,
    dir: &Path,
    progress: Arc<Mutex<String>>,
) -> Result<String, String> {
    if cfg!(test) {
        return Err("Native VSS отключён в тестах".into());
    }
    if !confirmed || !crate::repair::elevated() || !valid(&row, proposed) {
        return Err("VSS BLOCKED: нет прав, подтверждения или безопасной квоты".into());
    }
    let _lease = crate::repair::NativeLease::acquire().map_err(|e| format!("{e:?}"))?;
    crate::repair::ensure_no_conflicting_process().map_err(|e| format!("{e:?}"))?;
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let call = format!(
        "{}\ntry {{ Invoke-VssQuotaIncrease -For '{}' -On '{}' -ExpectedMaximum {} -ProposedBytes {} -Confirmed $true | ConvertTo-Json -Depth 12 -Compress }} catch {{ [pscustomobject]@{{Status='FAILED';Error=$_.Exception.Message}}|ConvertTo-Json -Compress }}",
        script(),
        row.source,
        row.storage,
        row.maximum,
        proposed
    );
    std::fs::write(
        dir.join("command.txt"),
        format!(
            "{}\nvssadmin resize shadowstorage /For={} /On={} /MaxSize={}\nConfirmed=true",
            crate::repair::timestamp(),
            row.source,
            row.storage,
            proposed
        ),
    )
    .map_err(|e| e.to_string())?;
    let stdout = std::fs::File::create(dir.join("stdout.json")).map_err(|e| e.to_string())?;
    let stderr = std::fs::File::create(dir.join("stderr.txt")).map_err(|e| e.to_string())?;
    let mut cmd = std::process::Command::new("powershell.exe");
    cmd.args([
        "-NoProfile",
        "-NonInteractive",
        "-EncodedCommand",
        &crate::ps_exec::encoded_command(&format!("{}\n{}", crate::ps_exec::PS_PRELUDE, call)),
    ])
    .env_remove("PSModulePath")
    .stdin(std::process::Stdio::null())
    .stdout(stdout)
    .stderr(stderr);
    let mut guard = crate::engine::ProcessGuard::spawn_servicing(cmd).map_err(|e| e.to_string())?;
    let start = std::time::Instant::now();
    loop {
        if guard
            .child_mut()
            .try_wait()
            .map_err(|e| e.to_string())?
            .is_some()
        {
            break;
        }
        *progress.lock().unwrap_or_else(|e| e.into_inner()) = format!(
            "Настройка VSS и повторная проверка · {} с. Принудительная остановка запрещена",
            start.elapsed().as_secs()
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    let text = std::fs::read_to_string(dir.join("stdout.json")).map_err(|e| e.to_string())?;
    json::parse(text.trim().trim_start_matches('﻿'))
        .ok_or("Результат VSS UNKNOWN; см. сохранённые stdout/stderr")?;
    Ok(text)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn quota_increase_is_bounded_and_never_deletes() {
        let r = Row {
            source: "C:".into(),
            storage: "D:".into(),
            maximum: 10 << 30,
            used: 9 << 30,
            free: 20 << 30,
            copies: 4,
        };
        assert_eq!(recommend(&r), Some(13 << 30));
        assert!(!valid(&r, 9 << 30));
        assert!(!valid(&r, 30 << 30));
        assert!(valid(&r, 13 << 30));
        let mut bad = r;
        bad.source = "C: & command".into();
        assert!(!valid(&bad, 13 << 30));
    }
    #[test]
    fn missing_facts_are_not_success() {
        assert!(rows("{}").is_err());
        assert!(rows(r#"{"Rows":[{"For":"C:","Maximum":null}]}"#).is_err());
    }
}
