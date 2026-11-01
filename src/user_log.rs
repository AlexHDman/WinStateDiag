//! Russian presentation only. Diagnostic logs retain the original entry verbatim.
pub fn progress(raw: &str) -> String {
    let raw = raw.strip_prefix("A5_PROGRESS|").unwrap_or(raw);
    let (stage, timing) = raw.split_once(';').unwrap_or((raw, ""));
    let (phase, counts) = stage.split_once(": ").unwrap_or((stage, ""));
    let label = match phase.trim() {
        "PnP inventory" => "Получение списка устройств",
        "Signed driver inventory" => "Получение сведений о драйверах",
        "Native driver dates (batch)" | "Native date fallback" => "Проверка дат драйверов",
        "Device metadata" => "Проверка сведений об устройствах",
        "Remaining PnP nodes" => "Проверка остальных устройств",
        "System drivers / signatures" => "Проверка системных драйверов и подписей",
        "Driver packages" => "Получение пакетов драйверов",
        "Event evidence" => "Чтение событий драйверов",
        "Completed" => "Проверка драйверов завершена",
        _ => "Проверка драйверов",
    };
    let count = counts
        .split_once('/')
        .and_then(|(a, b)| Some((a.parse::<usize>().ok()?, b.parse::<usize>().ok()?)));
    let elapsed = timing
        .trim()
        .trim_end_matches(" s")
        .parse::<f64>()
        .ok()
        .filter(|v| v.is_finite() && *v >= 0.0);
    let mut text = label.to_string();
    if let Some((done, total)) = count {
        text.push_str(&format!(": {done} из {total}"));
    }
    if let Some(seconds) = elapsed {
        text.push_str(&format!(" · {seconds:.0} с"));
    }
    text
}
pub fn display(raw: &str) -> String {
    if raw.starts_with("A5_PROGRESS|") {
        return progress(raw);
    }
    if raw.starts_with("Repair ") {
        let mut text = raw.to_string();
        for (code, label) in [
            ("SUCCESS", "Исправление подтверждено"),
            ("ERROR", "Ошибка выполнения"),
            ("CANCELLED", "Операция прервана"),
            ("TIMEOUT", "Превышено время ожидания"),
            ("NOT_VERIFIED", "Исправность не подтверждена"),
            ("REBOOT_REQUIRED", "Требуется перезагрузка"),
        ] {
            text = text.replace(&format!(": {code} ·"), &format!(": {label} ·"));
        }
        return text;
    }
    if raw.starts_with("[timing]") {
        return "Записано время этапа; подробности в диагностическом журнале".into();
    }
    if raw.starts_with("Windows servicing logs:") {
        return "Сохранены сведения журналов обслуживания Windows".into();
    }
    let text = raw
        .replace("[WARN]", "Предупреждение:")
        .replace("[ERROR]", "Ошибка:")
        .replace("[INFO]", "Информация:")
        .replace("[stderr]", "Сообщение процесса:")
        .replace("A5 evidence:", "Сохранение результатов A5:")
        .replace("manifest:", "Описание архива:")
        .replace("runtime", "рабочих файлов");
    // Native/vendor prose belongs in the technical log, not an untranslated user message.
    let has_ru = raw
        .chars()
        .any(|c| ('А'..='я').contains(&c) || c == 'Ё' || c == 'ё');
    if !has_ru && raw.chars().filter(|c| c.is_ascii_alphabetic()).count() > 3 && raw.contains(' ') {
        let severity = if raw.starts_with("[ERROR]") {
            "Ошибка выполнения"
        } else if raw.starts_with("[WARN]") {
            "Предупреждение сбора данных"
        } else {
            "Техническая запись"
        };
        return format!("{severity}; подробности в диагностическом журнале");
    }
    text
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn date_progress_is_localized_without_machine_prefix() {
        assert_eq!(
            display("A5_PROGRESS|Native date fallback: 48/53; 31.0 s"),
            "Проверка дат драйверов: 48 из 53 · 31 с"
        );
        assert_eq!(
            progress("Driver packages; 32.0 s"),
            "Получение пакетов драйверов · 32 с"
        );
        assert!(!display("[timing] EXPC process wait finished; draining output").contains("EXPC"));
        assert!(display("[ERROR] Collector failed").starts_with("Ошибка выполнения"));
    }
}
