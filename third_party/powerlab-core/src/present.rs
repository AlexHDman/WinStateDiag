//! How a metric is presented to the operator.
//!
//! The sampler reports everything through one channel: live measurements, constant
//! hardware characteristics, presence/identity markers (a unit-less `1`) and its own
//! per-source status rows. Drawing all of them as measurement cards produced "1.000" cards
//! with charts for a CPU name, a chart of a DIMM's capacity, permanent "PROBING" cards and
//! English/technical captions. This module is the single place that decides, from the
//! metric alone, **what kind of thing it is** and **what to call it** — it changes nothing
//! in the data, the statistics or the export, which keep every id, state and reason.

use crate::ipc::{format_value, Metric, MetricState};

/// What a metric is, for the window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// A value that changes over time: a card with statistics and a chart.
    Live,
    /// Identity, presence or a constant characteristic of the hardware: a line in the
    /// device information of its group, without a chart.
    Fact,
    /// The sampler's own per-source bookkeeping: listed under the service details.
    Service,
}

/// Classify a metric id.
pub fn role(id: &str) -> Role {
    if id.starts_with("provider.")
        || id.starts_with("query.")
        || id.starts_with("lhm.")
        || id.ends_with(".enumeration")
        || id.ends_with(".query")
        || id == "storage.discovery"
    {
        return Role::Service;
    }
    if id.contains(".identity")
        || id.ends_with(".present")
        || id == "system.profile"
        || id == "system.name"
        || id == "battery.details"
        || id.starts_with("ram.module.")
        || id.ends_with(".power_limit")
    {
        return Role::Fact;
    }
    Role::Live
}

/// The instance number inside an id such as `gpu.0.fan` or `storage.3.temperature`.
fn index_of(id: &str, prefix: &str) -> Option<String> {
    let rest = id.strip_prefix(prefix)?;
    let index = rest.split('.').next()?;
    (!index.is_empty() && index.chars().all(|c| c.is_ascii_digit())).then(|| index.to_string())
}

/// The first note that is real text (the facts provider pads notes with empty strings).
fn first_note(metric: &Metric) -> Option<&str> {
    metric
        .notes
        .iter()
        .map(|note| note.trim())
        .find(|note| !note.is_empty())
}

/// The operator-facing name of a metric, in Russian.
///
/// A known id gets a fixed name; otherwise the sampler's own label is used unless it is
/// just the id repeated (the CIM facts provider labels rows with their id), in which case
/// the id is shown — an unknown metric is never hidden or renamed misleadingly.
pub fn title(metric: &Metric) -> String {
    if metric.id.starts_with("lhm/") {
        let label = metric.label.split(" · ").last().unwrap_or(&metric.label);
        if label == "GPU Core" && metric.unit == "MHz" {
            return if metric.id.contains("/gpu-intel-integrated/") {
                "Частота встроенной графики"
            } else {
                "Частота GPU"
            }
            .into();
        }
        return label
            .replace("GPU Core Voltage", "Напряжение GPU")
            .replace("GPU Memory Junction", "Температура памяти GPU")
            .replace("GPU Hot Spot", "Горячая точка GPU")
            .replace("GPU Fan", "Обороты вентилятора GPU")
            .replace("CPU Package", "Температура CPU Package")
            .replace("Core Average", "Средняя температура ядер")
            .replace("Core Max", "Максимальная температура ядер")
            .replace("Memory Used", "Занято памяти")
            .replace("Memory Available", "Доступно памяти")
            .replace("D3D Shared Memory Total", "Общая память графики")
            .replace("D3D Shared Memory Used", "Занято общей памяти графики")
            .replace("CPU Fan", "Вентилятор CPU")
            .replace("System Fan", "Системный вентилятор")
            .replace("Temperature #", "Температура #")
            .replace("Voltage #", "Напряжение #")
            .replace("Fan #", "Вентилятор #");
    }

    let id = metric.id.as_str();
    let fixed = match id {
        "lhm.board" => Some("Датчики платы и вентиляторов"),
        "lhm.dimm" => Some("Температура модулей памяти"),
        "lhm.storage" => Some("Дополнительный опрос накопителей LHM"),
        "cpu.load" => Some("Загрузка CPU (занятость)"),
        "cpu.utility" => Some("CPU Utility (работа относительно номинала)"),
        "cpu.clock.current" => Some("Частота CPU (средняя, расчётная)"),
        "cpu.package_power" => Some("Мощность CPU (пакет)"),
        "cpu.cores_power" => Some("Мощность ядер CPU"),
        "cpu.igpu_power" => Some("Мощность встроенной графики"),
        "cpu.temperature" => Some("Температура CPU"),
        "cpu.throttle.thermal" => Some("Термотроттлинг CPU"),
        "cpu.throttle.power" => Some("Лимиты мощности CPU"),
        "ram.used" => Some("Занятая память"),
        "ram.available" => Some("Доступная память"),
        "ram.load" => Some("Загрузка памяти"),
        "system.profile" => Some("Тип устройства"),
        "system.name" => Some("Компьютер"),
        "motherboard.identity" | "motherboard.board" => Some("Системная плата"),
        "battery.present" => Some("Батарея"),
        "battery.details" => Some("Сведения о батарее"),
        _ => None,
    };
    if let Some(name) = fixed {
        return name.to_string();
    }
    if id.starts_with("cpu.identity") {
        return "Процессор".to_string();
    }
    if id.starts_with("gpu.identity") {
        return "Видеоадаптер".to_string();
    }
    if let Some(n) = index_of(id, "gpu.") {
        let name = match id.rsplit('.').next().unwrap_or("") {
            "present" => Some("Видеокарта"),
            "temperature" => Some("Температура GPU"),
            "power" => Some("Мощность GPU"),
            "power_limit" => Some("Лимит мощности GPU"),
            "load" => Some("Загрузка GPU"),
            "memory_load" => Some("Занятость видеопамяти"),
            "memory_used" => Some("Занятая видеопамять"),
            "sm" => Some("Частота GPU"),
            "mem" => Some("Частота видеопамяти"),
            "fan" => Some("Вентилятор GPU (скважность)"),
            "hotspot" => Some("Температура hotspot GPU"),
            "voltage" => Some("Напряжение ядра GPU"),
            _ => None,
        };
        if let Some(name) = name {
            // The index is shown only when it distinguishes something.
            return if n == "0" {
                name.to_string()
            } else {
                format!("{name} №{n}")
            };
        }
    }
    if let Some(n) = index_of(id, "storage.") {
        if id.ends_with(".temperature") {
            return format!("Температура накопителя {n}");
        }
    }
    if let Some(n) = index_of(id, "ram.module.") {
        let what = match id.rsplit('.').next().unwrap_or("") {
            "capacity" => Some("объём"),
            "configured_speed" => Some("настроенная скорость"),
            "rated_speed" => Some("паспортная скорость"),
            "smbios_type" => Some("тип"),
            _ => None,
        };
        if let Some(what) = what {
            return format!("Модуль памяти {n}: {what}");
        }
    }
    let label = metric.label.trim();
    if label.is_empty() || label == id {
        id.to_string()
    } else {
        label.to_string()
    }
}

/// The value of a fact as text: a name from the notes for identity rows, a formatted
/// number for constant characteristics, or a plain-language absence.
pub fn fact_text(metric: &Metric) -> String {
    let id = metric.id.as_str();
    if metric.state.has_value() {
        if let Some(value) = metric.value {
            // Identity and presence markers carry a unit-less 1: the fact is the name.
            if metric.unit.is_empty() {
                let names: Vec<&str> = metric
                    .notes
                    .iter()
                    .map(|note| note.trim())
                    .filter(|note| !note.is_empty() && !note.contains("not guessed"))
                    .collect();
                if !names.is_empty() {
                    return names.join(" · ");
                }
                if id.ends_with(".present") {
                    let label = metric.label.trim();
                    return if label.is_empty() || label == id {
                        "обнаружено".to_string()
                    } else {
                        label.to_string()
                    };
                }
                return "обнаружено".to_string();
            }
            if id.ends_with(".capacity") && metric.unit == "bytes" {
                return format!("{:.0} ГиБ", value / (1024.0 * 1024.0 * 1024.0));
            }
            if id.ends_with(".smbios_type") {
                return match value as i64 {
                    26 => "DDR4".to_string(),
                    34 => "DDR5".to_string(),
                    other => format!("код SMBIOS {other}"),
                };
            }
            return format_value(value, &metric.unit);
        }
    }
    if id == "battery.present" && metric.state == MetricState::Unsupported {
        return "не обнаружена (для настольного ПК это норма)".to_string();
    }
    let (_, text) = status(metric.state, metric.reason.as_deref());
    match first_note(metric) {
        Some(note) if metric.state.has_value() => note.to_string(),
        _ => text,
    }
}

/// Why a metric shows no number, as the operator needs to tell the cases apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Absence {
    /// A value is present (including a measured zero).
    None,
    /// The first result of this source has not arrived yet.
    Waiting,
    /// Windows reserves this query for an administrator; expected in the normal mode.
    NeedsElevation,
    /// The source is switched off or does not exist on this machine.
    Unavailable,
    /// The source exists and answered, but had nothing to report.
    NoData,
    /// A read failed, timed out or went stale.
    Error,
}

/// Classify a state and its reason, and say it in plain Russian.
///
/// The raw reason is kept for the details panel and the export; this is only the short
/// line on a card or in a list. A measured zero is `Absence::None`: it is a value.
pub fn status(state: MetricState, reason: Option<&str>) -> (Absence, String) {
    let reason = reason.unwrap_or("").trim();
    if reason.starts_with("ACCESS_DENIED_EXPECTED") {
        return (
            Absence::NeedsElevation,
            "нужны права администратора (в обычном режиме недоступно)".to_string(),
        );
    }
    match state {
        MetricState::Ok | MetricState::Zero | MetricState::Suspect | MetricState::Conflict => {
            (Absence::None, String::new())
        }
        MetricState::NoData => {
            if reason.starts_with("PROBING")
                || reason.starts_with("WARMUP")
                || reason == "ожидание первого замера"
            {
                (Absence::Waiting, "ожидание первого результата".to_string())
            } else {
                (Absence::NoData, "источник не сообщил значение".to_string())
            }
        }
        MetricState::Unsupported => (
            Absence::Unavailable,
            "недоступно: источник отключён или не поддерживается".to_string(),
        ),
        MetricState::Error => {
            let text = if reason.starts_with("STALE") {
                "ошибка: данные устарели"
            } else if reason.starts_with("ACCESS_DENIED") {
                "ошибка: отказ в доступе даже с правами администратора"
            } else {
                "ошибка чтения"
            };
            (Absence::Error, text.to_string())
        }
    }
}

/// The big word on a card that has no number.
pub fn absence_word(absence: Absence) -> &'static str {
    match absence {
        Absence::None => "",
        Absence::Waiting => "ОЖИДАНИЕ",
        Absence::NeedsElevation => "НУЖНЫ ПРАВА",
        Absence::Unavailable => "НЕДОСТУПНО",
        Absence::NoData => "НЕТ ДАННЫХ",
        Absence::Error => "ОШИБКА",
    }
}

/// A value with its unit exactly once.
///
/// `Metric::display_value` already appends the unit, so callers that then appended the
/// unit again showed "45.20 W W". This is the one formatter the summary rows use.
pub fn value_with_unit(metric: &Metric) -> String {
    match (metric.state.has_value(), metric.value) {
        (true, Some(value)) => format_value(value, &metric.unit),
        _ => status(metric.state, metric.reason.as_deref()).1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::Group;

    fn fact(id: &str, unit: &str, value: f64, notes: &[&str]) -> Metric {
        let mut m = Metric::measured(id, id, Group::System, unit, value, "fixture");
        m.notes = notes.iter().map(|n| n.to_string()).collect();
        m
    }

    #[test]
    fn identity_and_presence_are_facts_not_measurements() {
        for id in [
            "cpu.identity.CPU0",
            "gpu.identity.VideoController1",
            "motherboard.identity",
            "gpu.0.present",
            "battery.present",
            "system.profile",
            "ram.module.0.capacity",
            "ram.module.1.configured_speed",
            "gpu.0.power_limit",
        ] {
            assert_eq!(role(id), Role::Fact, "{id}");
        }
        for id in [
            "provider.pdh",
            "query.BatteryStatus",
            "gpu.2.enumeration",
            "lhm.discovery",
        ] {
            assert_eq!(role(id), Role::Service, "{id}");
        }
        for id in [
            "cpu.load",
            "cpu.package_power",
            "gpu.0.temperature",
            "gpu.0.memory_load",
            "ram.used",
            "storage.0.temperature",
        ] {
            assert_eq!(role(id), Role::Live, "{id}");
        }
    }

    #[test]
    fn an_identity_row_shows_the_name_never_one() {
        let cpu = fact(
            "cpu.identity.CPU0",
            "",
            1.0,
            &["GenuineIntel", "Intel(R) Core(TM) Ultra 7"],
        );
        assert_eq!(title(&cpu), "Процессор");
        let text = fact_text(&cpu);
        assert_eq!(text, "GenuineIntel · Intel(R) Core(TM) Ultra 7");
        assert!(!text.contains("1.000") && text != "1");
        let gpu = fact(
            "gpu.identity.VideoController1",
            "",
            1.0,
            &[
                "NVIDIA",
                "NVIDIA GeForce RTX 5060",
                "Integrated/discrete classification not guessed from name",
            ],
        );
        assert_eq!(fact_text(&gpu), "NVIDIA · NVIDIA GeForce RTX 5060");
    }

    #[test]
    fn constant_characteristics_are_readable() {
        let capacity = fact(
            "ram.module.0.capacity",
            "bytes",
            24.0 * 1024.0 * 1024.0 * 1024.0,
            &[],
        );
        assert_eq!(title(&capacity), "Модуль памяти 0: объём");
        assert_eq!(fact_text(&capacity), "24 ГиБ");
        let kind = fact("ram.module.0.smbios_type", "SMBIOS enum", 34.0, &[]);
        assert_eq!(fact_text(&kind), "DDR5");
    }

    #[test]
    fn vram_occupancy_is_not_called_controller_load() {
        let m = fact("gpu.0.memory_load", "%", 31.0, &[]);
        assert_eq!(title(&m), "Занятость видеопамяти");
        assert_eq!(
            title(&fact("gpu.1.memory_used", "MiB", 1.0, &[])),
            "Занятая видеопамять №1"
        );
    }

    #[test]
    fn an_unknown_metric_keeps_its_own_label_or_id() {
        let mut m = fact("vendor.x.y", "W", 1.0, &[]);
        assert_eq!(title(&m), "vendor.x.y");
        m.label = "Особый датчик".into();
        assert_eq!(title(&m), "Особый датчик");
    }

    #[test]
    fn waiting_denied_unavailable_zero_and_error_are_all_different() {
        let cases = [
            (
                MetricState::NoData,
                Some("PROBING: first query has not completed"),
                Absence::Waiting,
            ),
            (
                MetricState::NoData,
                Some("WARMUP: source has not completed its first full measurement window"),
                Absence::Waiting,
            ),
            (
                MetricState::NoData,
                Some("ACCESS_DENIED_EXPECTED: requires an elevated (administrator) token"),
                Absence::NeedsElevation,
            ),
            (
                MetricState::NoData,
                Some("Temperature not reported"),
                Absence::NoData,
            ),
            (
                MetricState::Unsupported,
                Some("disabled by gate"),
                Absence::Unavailable,
            ),
            (
                MetricState::Error,
                Some("STALE: source timestamp"),
                Absence::Error,
            ),
            (
                MetricState::Error,
                Some("ACCESS_DENIED: refused even with an elevated token"),
                Absence::Error,
            ),
            (MetricState::Zero, None, Absence::None),
            (MetricState::Ok, None, Absence::None),
        ];
        let mut words = std::collections::BTreeSet::new();
        for (state, reason, expected) in cases {
            let (absence, text) = status(state, reason);
            assert_eq!(absence, expected, "{state:?} {reason:?}");
            assert_eq!(text.is_empty(), expected == Absence::None);
            words.insert(absence_word(absence));
        }
        // Six distinct presentations, and a zero is not one of the absences.
        assert_eq!(words.len(), 6);
    }

    #[test]
    fn a_unit_is_printed_exactly_once() {
        let m = Metric::measured("cpu.package_power", "x", Group::Cpu, "W", 45.2, "fixture");
        let text = value_with_unit(&m);
        assert_eq!(text.matches('W').count(), 1, "{text}");
        let mhz = Metric::measured(
            "cpu.clock.current",
            "x",
            Group::Cpu,
            "MHz",
            4800.0,
            "fixture",
        );
        assert_eq!(value_with_unit(&mhz).matches("MHz").count(), 1);
    }

    #[test]
    fn a_missing_battery_reads_as_normal_not_as_a_fault() {
        let m = Metric::unavailable(
            "battery.present",
            "Батарея",
            Group::Battery,
            "",
            MetricState::Unsupported,
            "батарея не обнаружена",
            "fixture",
        );
        assert!(fact_text(&m).contains("норма"));
    }
}
