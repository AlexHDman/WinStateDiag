//! Additive human report; original TXT/JSON contracts and forensic evidence stay intact.
use crate::{
    deep_checks::json::{self, Value},
    manifest::ManifestContext,
    report_package::EvidenceFile,
};
fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or("")
}
fn clean(s: &str) -> String {
    s.replace(['\r', '\n', '|'], " ")
}
/// Same additive RAM configuration finding is used by GUI aggregation and V3.
pub fn ram_check(files: &[EvidenceFile]) -> Option<crate::deep_checks::ExpcCheck> {
    files.iter().filter(|f| f.name.starts_with("Hardware_") && f.name.ends_with(".json")).rev().find_map(|f| {
        let text = std::str::from_utf8(&f.bytes).ok()?;
        let h = json::parse(text.trim_start_matches('\u{feff}'))?;
        let i = h.get("Ram")?.get("Intelligence")?;
        Some(crate::deep_checks::ExpcCheck {
            key: "RAM configuration".into(),
            status: match s(i,"Status") { "ATTENTION" => "ATTENTION", "CONFIGURATION_MATCH" => "INFO", _ => "UNKNOWN" }.into(),
            detail: format!("{}; {}; текущая скорость {} MT/s; профиль {} MT/s; лимит CPU {} MT/s; предыдущая {} MT/s; XMP не определён; стабильность не проверялась", s(i,"Recommendation"), i.get("Notes").map(compact).unwrap_or_default(),i.get("CurrentMTs").map(compact).unwrap_or_default(),i.get("ProfileMTs").map(compact).unwrap_or_default(),i.get("CpuOfficialMTs").map(compact).unwrap_or_default(),i.get("PreviousMTs").map(compact).unwrap_or_default()),
        })
    })
}
pub fn build(ctx: &ManifestContext, files: &[EvidenceFile]) -> Option<Vec<EvidenceFile>> {
    let mut source: Option<Value> = None;
    let mut name = String::new();
    let mut generated = String::new();
    let mut hardware = None;
    for f in files.iter().filter(|f| f.name.ends_with(".json")) {
        let text = String::from_utf8_lossy(&f.bytes);
        let Some(v) = json::parse(text.trim_start_matches('\u{feff}')) else {
            continue;
        };
        if f.name.starts_with("EXPC_")
            && v.get("Checks").is_some()
            && s(&v, "GeneratedAt") >= generated.as_str()
        {
            generated = s(&v, "GeneratedAt").into();
            source = Some(v.clone());
            name = f.name.clone();
        }
        if f.name.starts_with("Hardware_") && v.get("Cpu").is_some() {
            hardware = Some(v);
        }
    }
    let v = source?;
    let Some(Value::Arr(checks)) = v.get("Checks") else {
        return None;
    };
    let system = ctx.system_state.as_deref().unwrap_or("UNKNOWN");
    let hardware_state = ctx.hardware_state.as_deref().unwrap_or("UNKNOWN");
    let mut passport = format!(
        "1. КРАТКИЙ ПАСПОРТ\nКомпьютер: {}\nРоль: не задана; не выводится из имени ПК\nWindows: {} {}\nWinDiag: {}\nДата: {}\nРежим: {} / READ-ONLY (история подтверждённых действий отдельно)\nОбщий статус: система {}; оборудование {}\n",
        ctx.computer_name,
        ctx.windows_product,
        ctx.windows_build,
        crate::APP_VERSION,
        generated,
        if s(&v, "Mode").is_empty() {
            "READ-ONLY · профиль в источнике не указан"
        } else {
            s(&v, "Mode")
        },
        system,
        hardware_state
    );
    if let Some(h) = hardware {
        if let Some(cpu) = h.get("Cpu") {
            let model = cpu
                .get("Models")
                .map(compact)
                .filter(|x| x != "Нет данных")
                .unwrap_or_else(|| {
                    let v = if !s(cpu, "Name").is_empty() {
                        s(cpu, "Name")
                    } else {
                        s(cpu, "Model")
                    };
                    if v.is_empty() {
                        "Нет данных".into()
                    } else {
                        v.into()
                    }
                });
            passport.push_str(&format!("CPU: {model}\n"));
        }
        if let Some(ram) = h.get("Ram") {
            passport.push_str(&format!(
                "RAM (SMBIOS/комплектация, не тест памяти): {}\n",
                compact(ram)
            ));
        }
        if let Some(storage) = h.get("Storage") {
            passport.push_str(&format!(
                "Накопители (инвентарь; здоровье — отдельные доказательства): {}\n",
                compact(storage)
            ));
        }
    }
    let mut rows: Vec<(String, String, String, String, String, String)> = Vec::new();
    let mut issues = Vec::new();
    if let Some(c) = ram_check(files) {
        rows.push((
            c.key.clone(),
            "CONFIGURATION".into(),
            c.status.clone(),
            c.detail.clone(),
            "Проверить настройки и источник профиля; стресс-тест не выполнялся".into(),
            "Hardware JSON / Ram.Intelligence".into(),
        ));
        if c.status == "ATTENTION" {
            issues.push(format!("{}: {}", c.key, c.detail));
        }
    }
    for c in checks {
        let key = s(c, "Check");
        let state = s(c, "Status");
        let detail = s(c, "Detail");
        let action = recommendation(key, state, detail);
        rows.push((
            key.to_string(),
            "READ-ONLY".into(),
            state.to_string(),
            detail.to_string(),
            action.to_string(),
            name.clone(),
        ));
        if matches!(state, "ATTENTION" | "WARNING" | "ERROR" | "UNKNOWN") {
            issues.push(format!(
                "{key} [{state}] → {}: {detail} → риск требует оценки по фактам → {action}",
                name
            ));
        }
    }
    for f in files {
        if !f.name.ends_with(".json") {
            continue;
        }
        let t = String::from_utf8_lossy(&f.bytes);
        let Some(j) = json::parse(t.trim_start_matches('\u{feff}')) else {
            continue;
        };
        if f.name.starts_with("DriverAudit_") {
            rows.push((
                "PnP/A5/Code Integrity".into(),
                "READ-ONLY".into(),
                s(&j, "overall").into(),
                s(&j, "scope_summary").into(),
                "Текущие PnP отдельно от исторических/защитных событий; подробности в JSON".into(),
                f.name.clone(),
            ));
        }
        if f.name.starts_with("Repair_") && j.get("repair_id").is_some() {
            rows.push((
                format!("Repair {}", s(&j, "check")),
                "USER-CONFIRMED".into(),
                s(&j, "status").into(),
                s(&j, "message").into(),
                "Сверить повторную проверку и необходимость ручной перезагрузки".into(),
                f.name.clone(),
            ));
        }
        if f.name.starts_with("VSS/") && !s(&j, "Status").is_empty() {
            rows.push((
                "VSS: подтверждённое действие".into(),
                "USER-CONFIRMED".into(),
                s(&j, "Status").into(),
                format!("{} {}", s(&j, "Command"), s(&j, "Error")),
                "Квота проверяется отдельно от backup; исходная диагностика сохранена".into(),
                f.name.clone(),
            ));
        }
        if f.name.starts_with("NVMe_Health")
            || f.name.starts_with("Storage_Correlation")
            || f.name.starts_with("Hardware_Sensors")
        {
            rows.push((
                f.name.split('_').next().unwrap_or("Hardware").into(),
                "READ-ONLY".into(),
                if s(&j, "status").is_empty() {
                    "См. источник".into()
                } else {
                    s(&j, "status").into()
                },
                "Область оценки и доступность источников приведены в JSON; NO DATA не является OK"
                    .into(),
                "Сверить датчики и накопители по их собственным критериям".into(),
                f.name.clone(),
            ));
        }
    }
    let mut text = passport.clone();
    text.push_str(
        "\n2. ОСНОВНАЯ ТАБЛИЦА\nПроверка | Режим | Результат | Что обнаружено | Что делать\n",
    );
    for (k, mode, status, detail, action, _) in &rows {
        text.push_str(&format!(
            "{} | {} | {} | {} | {}\n",
            clean(k),
            mode,
            clean(status),
            clean(detail),
            action
        ));
    }
    text.push_str(
        "\n3. КРИТИЧЕСКИЕ И ПОДОЗРИТЕЛЬНЫЕ МОМЕНТЫ\nТекущие предупреждения/неопределённость:\n",
    );
    for issue in issues {
        text.push_str(&issue);
        text.push('\n');
    }
    text.push_str("Исторические события помечены HISTORICAL в таблице. Отсутствие старого DWM/crash в новом ZIP не доказывает устранение. Kernel-Power 41/6008 не устанавливает причину выключения.\n\n4. WINDIAG — LIVE-ПРИЁМКА\nАвтоматическая обработка не является личной LIVE-приёмкой.\nПроверь завершение всех этапов, реальную текущую операцию, A5, GUI и соответствие статусов TXT/JSON. Ограничения охвата сохраняются в State_Summary и manifest.\nZIP: этот документ сформирован до закрытия архива. Итог CRC/комплектности записывается ПОСЛЕ проверки во внешний локальный ZIP verification log; наличие этого документа не является сертификатом CRC.\n\n5. ИТОГ ОБСЛУЖИВАНИЯ\n");
    text.push_str(&format!("Состояние: система {system}; оборудование {hardware_state}.\nПриоритет: по подтверждённым текущим находкам; UNKNOWN требует уточнения.\nЗакрытие обслуживания: решение пользователя после LIVE-приёмки и проверки ограничений; автоматически не подтверждено.\n"));
    let q = json::string;
    let rows_json=rows.iter().map(|(k,m,s,d,a,e)|format!("{{\"check\":{},\"mode\":{},\"status\":{},\"finding\":{},\"action\":{},\"evidence\":{}}}",q(k),q(m),q(s),q(d),q(a),q(e))).collect::<Vec<_>>().join(",");
    let summary = files
        .iter()
        .find(|f| f.name == "State_Summary.json")
        .and_then(|f| json::parse(&String::from_utf8_lossy(&f.bytes)));
    let dimensions = [
        "execution_status",
        "coverage_status",
        "findings_status",
        "packaging_status",
        "repair_status",
    ];
    let states_json = dimensions
        .iter()
        .map(|k| {
            format!(
                "{}:{}",
                q(k),
                q(summary
                    .as_ref()
                    .map(|v| s(v, k))
                    .filter(|v| !v.is_empty())
                    .unwrap_or("UNKNOWN"))
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    for key in dimensions {
        text.push_str(&format!(
            "{key}: {}\n",
            summary.as_ref().map(|v| s(v, key)).unwrap_or("UNKNOWN")
        ));
    }
    let json = format!(
        "{{\"schema\":\"expc.diag-prompt/3\",\"producer_version\":{},\"computer\":{},\"generated_at\":{},\"passport_text\":{},\"system\":{},\"hardware\":{},\"checks\":[{}],{states_json},\"live_acceptance\":\"PENDING\",\"service_closed\":false,\"zip_verification\":\"See external post-publication receipt\"}}",
        q(crate::APP_VERSION),
        q(&ctx.computer_name),
        q(&generated),
        q(&passport),
        q(system),
        q(hardware_state),
        rows_json
    );
    Some(vec![
        EvidenceFile::new("EXPC_User_Report_V3.txt", text.into_bytes()),
        EvidenceFile::new("EXPC_User_Report_V3.json", json.into_bytes()),
    ])
}
fn compact(v: &Value) -> String {
    let text = match v {
        Value::Str(s) => s.clone(),
        Value::Num(n) => n.to_string(),
        Value::Arr(a) => a
            .iter()
            .take(16)
            .map(compact)
            .collect::<Vec<_>>()
            .join("; "),
        Value::Obj(o) => o
            .iter()
            .filter(|(k, _)| {
                [
                    "Name",
                    "Model",
                    "TotalGB",
                    "Total",
                    "Disks",
                    "Capacity",
                    "Size",
                    "CapacityGB",
                    "TotalCapacityGB",
                    "SizeGB",
                    "Manufacturer",
                ]
                .contains(&k.as_str())
            })
            .map(|(k, v)| format!("{k}: {}", compact(v)))
            .collect::<Vec<_>>()
            .join(", "),
        _ => "Нет данных".into(),
    };
    if text.is_empty() {
        "Нет данных".into()
    } else {
        text
    }
}

fn recommendation<'a>(key: &str, state: &str, detail: &'a str) -> &'a str {
    match state {
        "PASS" | "OK" | "CLEAN" => "Не требуется",
        "NOT TESTED" | "SKIPPED" => {
            "Проверка не выполнялась; выполнить её при необходимости. Неисправность не установлена"
        }
        "UNKNOWN" | "INCOMPLETE" => {
            if detail.is_empty() {
                "Не получен итоговый результат; повторить сбор исходного вывода и журналов текущего запуска"
            } else {
                detail
            }
        }
        "HISTORICAL" => {
            "Текущее исправление не требуется; сопоставить последующие события с историей"
        }
        "ATTENTION" | "WARNING" | "ERROR" => match key {
            "SFC" => {
                "Сверить итог SFC и текущие CBS; при подтверждённом повреждении выполнить SFC Repair и контрольную проверку"
            }
            "DISM" => {
                "При подтверждённом повреждении хранилища выполнить DISM Repair и ScanHealth; при недоступном источнике проверить источник восстановления"
            }
            "VSS" => {
                "Проверить состояния writers и providers, доступность служб и место теневого хранилища; сверить актуальные ошибки"
            }
            "CHKDSK" => {
                "Сохранить резервную копию и согласовать проверку тома; offline-исправление только в окно обслуживания"
            }
            "WHEA" => {
                "Сверить тип аппаратной ошибки, время и повторяемость; проверить оборудование по указанному источнику"
            }
            _ => {
                if detail.is_empty() {
                    "Открыть первичные доказательства соответствующей проверки; причина и действие пока не установлены"
                } else {
                    detail
                }
            }
        },
        _ => "Проверить первичный результат модуля; автоматический ремонт не требуется",
    }
}
