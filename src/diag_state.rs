//! DIAG aggregation: retain every source reason; coverage is not a fault.
use crate::deep_checks::ExpcCheck;
#[derive(Debug, PartialEq)]
pub struct Summary {
    pub code: String,
    pub reasons: Vec<String>,
}
pub fn aggregate(base: &str, checks: &[ExpcCheck]) -> Summary {
    let mut reasons = Vec::new();
    let mut warning = base.starts_with("ATTENTION");
    let mut missing = matches!(base, "PARTIAL" | "NO_DATA");
    let mut history = base.starts_with("HISTORICAL");
    for c in checks {
        let status = c.status.to_ascii_uppercase();
        let kind = match status.as_str() {
            "ATTENTION"
            | "WARNING"
            | "PROBLEM"
            | "CRITICAL"
            | "INTEGRITY_VIOLATIONS"
            | "REPAIRABLE" => {
                warning = true;
                "FINDING"
            }
            "REBOOT_PENDING" => {
                warning = true;
                "WARNING"
            }
            "ERROR"
                if c.key == "WHEA"
                    || (c.key == "DISM"
                        && (c.detail.contains("повреждено")
                            || c.detail.contains("NOT_REPAIRABLE"))) =>
            {
                warning = true;
                "FINDING"
            }
            "ERROR" | "FAILED" | "SERVICE_ERROR" | "UNKNOWN" | "INCOMPLETE" | "SKIPPED"
            | "NOT TESTED" => {
                missing = true;
                "COVERAGE"
            }
            "INFO" => "CONTEXT",
            "HISTORICAL" => {
                history = true;
                "CONTEXT"
            }
            "OK" | "CLEAN" => "PASS",
            _ => {
                missing = true;
                "COVERAGE"
            }
        };
        reasons.push(format!("{} [{kind}/{}]: {}", c.key, c.status, c.detail));
    }
    for key in ["SFC", "DISM", "WHEA", "VSS"] {
        if !checks.iter().any(|c| c.key.to_uppercase().contains(key)) {
            missing = true;
            reasons.push(format!("{key} [COVERAGE]: результат не получен"));
        }
    }
    if checks.is_empty() {
        missing = true;
        reasons.push("DIAG [COVERAGE]: результаты SFC/DISM/WHEA/VSS не получены".into());
    }
    let code = if warning {
        if base.starts_with("ATTENTION") {
            base
        } else {
            "ATTENTION_DIAG"
        }
    } else if missing {
        if base == "NO_DATA" && checks.is_empty() {
            "NO_DATA"
        } else {
            "PARTIAL"
        }
    } else if history {
        "HISTORICAL"
    } else {
        "OK"
    };
    Summary {
        code: code.into(),
        reasons,
    }
}
/// Execution, coverage and findings are independent dimensions.
pub fn execution_status(system: &str, _hardware: &str, reasons: &[String]) -> &'static str {
    if system == "CANCELLED" {
        return "CANCELLED";
    }
    if system == "ERROR" {
        return "ERROR";
    }
    if reasons.iter().any(|r| {
        [
            "[COVERAGE/ERROR]",
            "[COVERAGE/FAILED]",
            "[COVERAGE/SERVICE_ERROR]",
        ]
        .iter()
        .any(|m| r.contains(m))
    }) {
        return "COMPLETED_WITH_ERRORS";
    }
    "COMPLETED"
}
pub fn coverage_status(system: &str, hardware: &str, reasons: &[String]) -> &'static str {
    if system == "NO_DATA" && hardware == "NO_DATA" {
        return "NO_DATA";
    }
    if matches!(system, "PARTIAL" | "NO_DATA" | "ERROR" | "CANCELLED")
        || matches!(hardware, "PARTIAL" | "NO_DATA")
        || reasons.iter().any(|r| r.contains("[COVERAGE"))
    {
        "LIMITED"
    } else {
        "COMPLETE"
    }
}
pub fn findings_status(system: &str, hardware: &str) -> &'static str {
    if system.starts_with("ATTENTION")
        || matches!(
            hardware,
            "CRITICAL" | "ATTENTION" | "WARNING" | "CHECK_SENSOR"
        )
    {
        "ATTENTION"
    } else if matches!(system, "OK" | "HISTORICAL") && hardware == "OK" {
        "NO_FINDINGS"
    } else {
        "UNKNOWN"
    }
}
pub fn execution_label(code: &str) -> &'static str {
    match code {
        "COMPLETED" => "Выполнение завершено",
        "COMPLETED_WITH_ERRORS" => "Завершено с ошибками выполнения",
        "ERROR" => "Ошибка выполнения",
        "CANCELLED" => "Остановлено пользователем",
        _ => "Выполнение не подтверждено",
    }
}
pub fn coverage_label(code: &str) -> &'static str {
    match code {
        "COMPLETE" => "Данные полные",
        "LIMITED" => "Покрытие ограничено",
        _ => "Нет данных",
    }
}

/// Unknown/future dates never establish freshness. Seven-day finding window.
pub fn recent(time: &str, collected: &str) -> bool {
    match (
        crate::events::day_number(time),
        crate::events::day_number(collected),
    ) {
        (Some(t), Some(c)) => (0..7).contains(&(c - t)),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rc9_all_reasons_survive_and_diagnostics_cannot_be_ok() {
        let checks: Vec<_> = [
            ("SFC", "ATTENTION"),
            ("DISM", "REPAIRABLE"),
            ("WHEA", "ATTENTION"),
            ("VSS", "ATTENTION"),
        ]
        .into_iter()
        .map(|(k, s)| ExpcCheck {
            key: k.into(),
            status: s.into(),
            detail: "evidence".into(),
        })
        .collect();
        let a = aggregate("OK", &checks);
        assert_eq!(a.code, "ATTENTION_DIAG");
        assert_eq!(a.reasons.len(), 4);
        for c in checks {
            assert_ne!(aggregate("OK", &[c]).code, "OK");
        }
    }
    #[test]
    fn rc9_coverage_and_history_are_not_hardware_failure() {
        let check = |s: &str| ExpcCheck {
            key: "SFC".into(),
            status: s.into(),
            detail: String::new(),
        };
        assert_eq!(aggregate("OK", &[check("UNKNOWN")]).code, "PARTIAL");
        assert_eq!(aggregate("OK", &[check("INFO")]).code, "PARTIAL");
        assert_eq!(aggregate("OK", &[check("CLEAN")]).code, "PARTIAL");
    }
}
