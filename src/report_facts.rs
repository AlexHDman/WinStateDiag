//! Facts from saved evidence only. No collectors, inferred repairs or causal attribution.
use powerlab_core::json::Json;
use std::collections::BTreeMap;
#[derive(Clone, Default, Debug)]
pub struct Finding {
    pub severity: u8,
    pub title: String,
    pub when: String,
    pub why: String,
    pub check: String,
    pub evidence: String,
}
#[derive(Clone, Default, Debug)]
pub struct Reading {
    pub identity: String,
    pub device: String,
    pub metric: String,
    pub value: f64,
    pub unit: String,
    pub when: String,
    pub source: String,
}
#[derive(Clone, Default, Debug)]
pub struct Counter {
    pub identity: String,
    pub device: String,
    pub metric: String,
    pub value: f64,
    pub unit: String,
    pub date: String,
}
#[derive(Clone, Default, Debug)]
pub struct Change {
    pub device: String,
    pub metric: String,
    pub before: f64,
    pub after: f64,
    pub unit: String,
    pub before_date: String,
    pub after_date: String,
}
#[derive(Clone, Default, Debug)]
pub struct Facts {
    pub computer: String,
    pub date: String,
    pub version: String,
    pub cpu: String,
    pub board: String,
    pub bios: String,
    pub ram: String,
    pub gpu: String,
    pub disks: String,
    pub windows: String,
    pub findings: Vec<Finding>,
    pub readings: Vec<Reading>,
    pub counters: Vec<Counter>,
    pub changes: Vec<Change>,
    pub limitations: Vec<String>,
    pub repairs: Vec<String>,
    pub machine_key: String,
}
fn s<'a>(j: &'a Json, k: &str) -> &'a str {
    j.get(k).and_then(Json::as_str).unwrap_or("")
}
fn a<'a>(j: &'a Json, k: &str) -> &'a [Json] {
    j.get(k)
        .and_then(Json::as_array)
        .map_or(&[], |v| v.as_slice())
}
fn n(j: &Json, k: &str) -> Option<f64> {
    match j.get(k)? {
        Json::Int(n) => Some(*n as f64),
        Json::Float(n) if n.is_finite() => Some(*n),
        Json::String(s) => s.parse().ok(),
        _ => None,
    }
}
fn strings(j: &Json, k: &str) -> String {
    a(j, k)
        .iter()
        .filter_map(Json::as_str)
        .collect::<Vec<_>>()
        .join(", ")
}
fn obj(pairs: Vec<(&str, Json)>) -> Json {
    Json::Object(pairs.into_iter().map(|(k, v)| (k.into(), v)).collect())
}
fn identity_present(raw: &str) -> bool {
    let value = raw.trim();
    !value.is_empty()
        && !["unknown", "none", "n/a", "not available", "default string"]
            .iter()
            .any(|placeholder| value.eq_ignore_ascii_case(placeholder))
}
fn device_key(raw: &str) -> String {
    if identity_present(raw) {
        hash(raw.trim())
    } else {
        String::new()
    }
}

/// The wall time recorded in the report, independent of the current PC's zone.
pub(crate) fn display_date(value: &str) -> String {
    use std::sync::OnceLock;
    static DATE: OnceLock<regex::Regex> = OnceLock::new();
    let regex = DATE.get_or_init(|| {
        regex::Regex::new(
            r"^([0-9]{4})-([0-9]{2})-([0-9]{2})(?:[T ]([0-9]{2}):([0-9]{2})(?::[0-9]{2}(?:[.,][0-9]+)?)?(?:Z|[+-][0-9]{2}:[0-9]{2})?)?$"
        ).expect("static ISO date expression")
    });
    let Some(parts) = regex.captures(value.trim()) else {
        return "Дата неизвестна".into();
    };
    let year: u32 = parts[1].parse().unwrap_or(0);
    let month: u32 = parts[2].parse().unwrap_or(0);
    let day: u32 = parts[3].parse().unwrap_or(0);
    let days = match month {
        2 if year.is_multiple_of(400) || (year.is_multiple_of(4) && !year.is_multiple_of(100)) => {
            29
        }
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        _ => 0,
    };
    if day == 0 || day > days || year == 0 {
        return "Дата неизвестна".into();
    }
    let date = format!("{}.{}.{}", &parts[3], &parts[2], &parts[1]);
    if parts.get(4).is_none() {
        date
    } else if &parts[4] <= "23" && &parts[5] <= "59" {
        format!("{date}, {}:{}", &parts[4], &parts[5])
    } else {
        "Дата неизвестна".into()
    }
}

fn hash(s: &str) -> String {
    crate::content_hash::sha256(s.as_bytes()).unwrap_or_default()
}
/// Split original JSON records without assuming any customer filename or flattening record context.
pub fn documents(text: &str) -> Vec<(String, Json)> {
    let mut docs = vec![];
    let mut offset = 0;
    let mut skip = 0;
    let mut source = "TXT".to_owned();
    for line in text.split_inclusive('\n') {
        let start = offset;
        offset += line.len();
        if start < skip {
            continue;
        }
        if let Some(v) = line.strip_prefix("FILE: ") {
            source = v.split(" | ").next().unwrap_or("TXT").trim().into();
        } else if line.starts_with("========== ") && line.trim_end().ends_with(" ==========") {
            source = line.trim().trim_matches('=').trim().into();
        }
        let trim = line.trim_start();
        if !trim.starts_with('{') {
            continue;
        }
        let begin = start + line.len() - trim.len();
        let mut depth = 0usize;
        let mut quote = false;
        let mut escape = false;
        for (i, b) in text.as_bytes()[begin..]
            .iter()
            .take(32 * 1024 * 1024)
            .enumerate()
        {
            if quote {
                if escape {
                    escape = false;
                } else if *b == b'\\' {
                    escape = true;
                } else if *b == b'"' {
                    quote = false;
                }
                continue;
            }
            match b {
                b'"' => quote = true,
                b'{' => depth += 1,
                b'}' => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        let end = begin + i + 1;
                        skip = end;
                        if let Ok(j) = Json::parse(&text[begin..end]) {
                            docs.push((source.clone(), j));
                        }
                        break;
                    }
                }
                _ => {}
            }
            if depth > 128 {
                break;
            }
        }
        if docs.len() >= 512 {
            break;
        }
    }
    docs
}
impl Facts {
    pub fn parse(text: &str) -> Self {
        let docs = documents(text);
        let mut out = Self::default();
        let mut history = vec![];
        let mut disk_by_identity = BTreeMap::<String, usize>::new();
        let mut sensor_by_identity = BTreeMap::<(&str, &str, &str, &str), usize>::new();
        let mut checks = std::collections::BTreeSet::new();
        for (source, j) in &docs {
            if j.get("System").is_some() && j.get("Cpu").is_some() {
                let get = |k| j.get(k).unwrap_or(&Json::Null);
                out.cpu = strings(get("Cpu"), "Models");
                out.computer = s(get("System"), "Hostname").into();
                out.board = format!(
                    "{} {}",
                    s(get("Motherboard"), "Manufacturer"),
                    s(get("Motherboard"), "Product")
                )
                .trim()
                .into();
                out.bios = s(get("Bios"), "Version").into();
                out.ram = s(get("Ram"), "Total").into();
                out.gpu = a(get("Gpu"), "Controllers")
                    .iter()
                    .map(|g| s(g, "Name"))
                    .filter(|v| !v.is_empty())
                    .collect::<Vec<_>>()
                    .join(", ");
                out.disks = a(get("Storage"), "Disks")
                    .iter()
                    .map(|g| s(g, "Model"))
                    .filter(|v| !v.is_empty())
                    .collect::<Vec<_>>()
                    .join(", ");
                out.windows = format!(
                    "{} · {}",
                    s(get("System"), "WindowsEdition"),
                    s(get("System"), "WindowsBuild")
                );
                let identity = s(get("Motherboard"), "Serial");
                if !identity.is_empty()
                    && !["default string", "to be filled by o.e.m.", "none"]
                        .contains(&identity.to_lowercase().as_str())
                {
                    out.machine_key = hash(&format!("{}|{}", out.computer, identity));
                }
            }
            if j.get("producer_version").is_some() && j.get("computer_name").is_some() {
                out.version = s(j, "producer_version").into();
                out.computer = s(j, "computer_name").into();
                out.date = s(j, "created_at").into();
            }
            if j.get("incidents").is_some() {
                for incident in a(j, "incidents") {
                    out.findings.push(Finding{severity:2,title:"Неожиданное завершение работы".into(),when:s(incident,"last_activity").into(),why:"Зафиксирован инцидент выключения. Причина не установлена; события 41/6008 не доказывают неисправность питания.".into(),check:"Проверить повторяемость, связанные BugCheck/WHEA и журналы за тот же интервал.".into(),evidence:format!("{} · sources={} · BSOD={}",source,strings(incident,"sources"),s(incident,"bsod"))});
                }
            }
            for event in a(j, "aggregates") {
                let id = n(event, "event_id").unwrap_or(0.0) as u32;
                let count = n(event, "count").unwrap_or(0.0);
                if id == 154 && count > 0.0 {
                    out.findings.push(Finding{severity:1,title:format!("Сбой обращения к диску · событие 154 · {count:.0} записей"),when:s(event,"last_seen").into(),why:"Исторический номер диска не идентифицирует нынешний накопитель. Причина не установлена.".into(),check:"Уточнить подключённое в тот момент устройство и сохранить важные данные перед операциями записи.".into(),evidence:format!("{} · {} · first={} · last={}",source,s(event,"provider"),s(event,"first_seen"),s(event,"last_seen"))});
                }
            }
            if j.get("Checks").is_some() {
                for check in crate::deep_checks::from_expc_json(j.render().as_bytes()) {
                    let name = format!("{:?}", check.check);
                    checks.insert(name.clone());
                    let detail = check.detail.clone();
                    if check.result == crate::deep_checks::CheckResult::Skipped
                        || detail.contains("NOT_RUN")
                    {
                        out.limitations
                            .push(format!("{name}: проверка пропущена; {}", source));
                    } else if check.effective_result() != crate::deep_checks::CheckResult::Ok {
                        use crate::deep_checks::ChkdskFinding;
                        let title = match check.finding_class() {
                            Some(ChkdskFinding::Repaired) => {
                                "CHKDSK сообщил об исправлении. Нужна повторная проверка тома."
                                    .into()
                            }
                            Some(ChkdskFinding::ProblemsFound) => {
                                "CHKDSK обнаружил проблемы. Исправление не подтверждено.".into()
                            }
                            _ => format!("{name}: {detail}"),
                        };
                        out.findings.push(Finding {
                            severity: 1,
                            title,
                            when: s(j, "GeneratedAt").into(),
                            why: detail,
                            check: "Проверить первичный результат и условия выполнения.".into(),
                            evidence: source.clone(),
                        });
                    }
                }
            }
            if j.get("sensors").is_some() {
                for sensor in a(j, "sensors") {
                    let Some(value) = n(sensor, "value") else {
                        continue;
                    };
                    let kind = if s(sensor, "sensor_type").is_empty() {
                        s(sensor, "type")
                    } else {
                        s(sensor, "sensor_type")
                    };
                    let metric = if s(sensor, "name").is_empty() {
                        s(sensor, "sensor_name")
                    } else {
                        s(sensor, "name")
                    };
                    if ["Temperature", "Voltage", "Power", "Fan"].contains(&kind) {
                        let provider = s(sensor, "provider").trim();
                        let hardware = s(sensor, "hardware_id").trim();
                        let metric_id = s(sensor, "sensor_id").trim();
                        let identified = identity_present(provider) && identity_present(hardware);
                        let reading = Reading {
                            identity: if identified {
                                hash(&format!("{provider}|{hardware}"))
                            } else {
                                String::new()
                            },
                            device: s(sensor, "hardware").into(),
                            metric: metric.into(),
                            value,
                            unit: match kind {
                                "Temperature" => "°C",
                                "Voltage" => "V",
                                "Power" => "W",
                                _ => "RPM",
                            }
                            .into(),
                            when: s(sensor, "timestamp").into(),
                            source: format!("{source} · {provider}"),
                        };
                        if identified && identity_present(metric_id) {
                            let key = (provider, hardware, metric_id, kind);
                            if let Some(&index) = sensor_by_identity.get(&key) {
                                if reading.when > out.readings[index].when {
                                    out.readings[index] = reading;
                                }
                                continue;
                            }
                            sensor_by_identity.insert(key, out.readings.len());
                        }
                        out.readings.push(reading);
                    }
                }
            }
            if j.get("physical_identity").is_some()
                && j.get("error_information_log").is_some()
                && let Some(value) = j
                    .get("error_information_log")
                    .and_then(|v| n(v, "lifetime_entries_counter"))
            {
                let counter = Counter {
                    identity: device_key(s(j, "physical_identity")),
                    device: s(j, "model").to_owned(),
                    metric: "Журнал ошибок NVMe (накопительный счётчик)".into(),
                    value,
                    unit: "entries".into(),
                    date: s(j, "captured_at").to_owned(),
                };
                // This parser reads a single NVMe metric in a fixed unit.
                if !counter.identity.is_empty() {
                    if let Some(&index) = disk_by_identity.get(&counter.identity) {
                        if counter.date > out.counters[index].date {
                            out.counters[index] = counter;
                        }
                        continue;
                    }
                    disk_by_identity.insert(counter.identity.clone(), out.counters.len());
                }
                out.counters.push(counter);
            }
            for h in a(j, "sessions") {
                if let Some(value) = n(h, "error_log_entries") {
                    history.push((
                        device_key(s(h, "physical_identity")),
                        value,
                        s(h, "end_time").to_owned(),
                    ));
                }
            }
        }
        for counter in &out.counters {
            if let Some((_, before, date)) = history
                .iter()
                .filter(|(k, _, d)| {
                    !counter.identity.is_empty()
                        && k == &counter.identity
                        && !d.is_empty()
                        && d < &counter.date
                })
                .min_by(|a, b| a.2.cmp(&b.2))
            {
                out.changes.push(Change {
                    device: counter.device.clone(),
                    metric: counter.metric.clone(),
                    before: *before,
                    after: counter.value,
                    unit: counter.unit.clone(),
                    before_date: date.clone(),
                    after_date: counter.date.clone(),
                });
            }
        }
        for check in ["Sfc", "Dism", "Chkdsk"] {
            if !checks.contains(check) {
                out.limitations.push(format!(
                    "{check}: подтверждённый результат проверки отсутствует в выбранных материалах"
                ));
            }
        }
        if out.machine_key.is_empty() {
            out.limitations.push("Надёжный аппаратный fingerprint ПК отсутствует; межархивное сравнение не подтверждено".into());
        }
        if out.date.is_empty() {
            out.limitations
                .push("Дата диагностической сессии недоступна".into());
        }
        let mut repair_ids = std::collections::BTreeSet::new();
        for (source, result) in &docs {
            let id = s(result, "repair_id");
            let completed = s(result, "completed_at");
            if id.is_empty()
                || s(result, "status") != "SUCCESS_VERIFIED"
                || s(result, "verified_result") != "OK"
                || !result
                    .get("verification")
                    .is_some_and(|v| n(v, "exit_code") == Some(0.0))
            {
                continue;
            }
            let context = docs.iter().find(|(_, v)| {
                s(v, "repair_id") == id
                    && !out.computer.is_empty()
                    && s(v, "computer").eq_ignore_ascii_case(&out.computer)
                    && !s(v, "started_at").is_empty()
            });
            if let Some((_, context)) = context
                && completed >= s(context, "started_at")
                && completed
                    .get(..10)
                    .zip(out.date.get(..10))
                    .is_some_and(|(done, session)| done <= session)
                && repair_ids.insert(id.to_owned())
            {
                out.repairs.push(format!(
                    "{} · {} · {}",
                    s(result, "check"),
                    display_date(completed),
                    source
                ));
            }
        }
        out.findings.sort_by_key(|f| f.severity);
        out
    }
    pub fn context(&self) -> String {
        let mut text = format!(
            "FACTS FROM PARSED PRIMARY EVIDENCE\nCPU: {}\nBoard: {}\nBIOS version: {}\nRAM: {}\nGPU: {}\nWindows: {}\nSession date: {}\n",
            self.cpu, self.board, self.bios, self.ram, self.gpu, self.windows, self.date
        );
        for f in &self.findings {
            text.push_str(&format!(
                "FINDING severity={} · {} · time={} · evidence={} · {}\n",
                f.severity, f.title, f.when, f.evidence, f.why
            ));
        }
        for c in &self.changes {
            text.push_str(&format!("COMPARABLE {} · {} · {} {} → {} {} · unit={} · identical physical identity verified\n",c.device,c.metric,c.before_date,c.before,c.after_date,c.after,c.unit));
        }
        for r in &self.readings {
            text.push_str(&format!(
                "READING device_id={} [provider-local] · {} · {} · {} {} · time={} · source={}\n",
                r.identity, r.device, r.metric, r.value, r.unit, r.when, r.source
            ));
        }
        for l in &self.limitations {
            text.push_str(&format!("LIMITATION {l}\n"));
        }
        text
    }
    pub fn compare(&mut self, old: &Facts) -> Result<(), String> {
        if self.machine_key.is_empty()
            || self.machine_key != old.machine_key
            || !self.computer.eq_ignore_ascii_case(&old.computer)
        {
            return Err("Принадлежность обоих отчётов одному компьютеру не подтверждена".into());
        }
        let mut changes = vec![];
        for current in &self.counters {
            if let Some(previous) = old.counters.iter().find(|p| {
                p.identity == current.identity
                    && !p.identity.is_empty()
                    && p.metric == current.metric
                    && p.unit == current.unit
                    && !p.date.is_empty()
                    && !current.date.is_empty()
                    && p.date < current.date
            }) {
                changes.push(Change {
                    device: current.device.clone(),
                    metric: current.metric.clone(),
                    before: previous.value,
                    after: current.value,
                    unit: current.unit.clone(),
                    before_date: previous.date.clone(),
                    after_date: current.date.clone(),
                });
            }
        }
        if changes.is_empty() {
            return Err("Сопоставимые счётчики того же устройства, метрики и единиц отсутствуют; пропуск не считается улучшением".into());
        }
        self.changes = changes;
        self.limitations.push("Сравнение выполнено локально; модель повторно не вызывалась. Мгновенные датчики не используются как доказательство деградации.".into());
        Ok(())
    }
    pub fn to_json(&self) -> Json {
        let list = |v: &Vec<String>| Json::Array(v.iter().map(|s| Json::str(s)).collect());
        let findings = self
            .findings
            .iter()
            .map(|v| {
                obj(vec![
                    ("severity", Json::Int(i64::from(v.severity))),
                    ("title", Json::str(&v.title)),
                    ("when", Json::str(&v.when)),
                    ("why", Json::str(&v.why)),
                    ("check", Json::str(&v.check)),
                    ("evidence", Json::str(&v.evidence)),
                ])
            })
            .collect();
        let readings = self
            .readings
            .iter()
            .map(|v| {
                obj(vec![
                    ("identity", Json::str(&v.identity)),
                    ("device", Json::str(&v.device)),
                    ("metric", Json::str(&v.metric)),
                    ("value", Json::Float(v.value)),
                    ("unit", Json::str(&v.unit)),
                    ("when", Json::str(&v.when)),
                    ("source", Json::str(&v.source)),
                ])
            })
            .collect();
        let counters = self
            .counters
            .iter()
            .map(|v| {
                obj(vec![
                    ("identity", Json::str(&v.identity)),
                    ("device", Json::str(&v.device)),
                    ("metric", Json::str(&v.metric)),
                    ("value", Json::Float(v.value)),
                    ("unit", Json::str(&v.unit)),
                    ("date", Json::str(&v.date)),
                ])
            })
            .collect();
        let changes = self
            .changes
            .iter()
            .map(|v| {
                obj(vec![
                    ("device", Json::str(&v.device)),
                    ("metric", Json::str(&v.metric)),
                    ("before", Json::Float(v.before)),
                    ("after", Json::Float(v.after)),
                    ("unit", Json::str(&v.unit)),
                    ("before_date", Json::str(&v.before_date)),
                    ("after_date", Json::str(&v.after_date)),
                ])
            })
            .collect();
        obj(vec![
            ("computer", Json::str(&self.computer)),
            ("date", Json::str(&self.date)),
            ("version", Json::str(&self.version)),
            ("cpu", Json::str(&self.cpu)),
            ("board", Json::str(&self.board)),
            ("bios", Json::str(&self.bios)),
            ("ram", Json::str(&self.ram)),
            ("gpu", Json::str(&self.gpu)),
            ("disks", Json::str(&self.disks)),
            ("windows", Json::str(&self.windows)),
            ("machine_key", Json::str(&self.machine_key)),
            ("limitations", list(&self.limitations)),
            ("repairs", list(&self.repairs)),
            ("findings", Json::Array(findings)),
            ("readings", Json::Array(readings)),
            ("counters", Json::Array(counters)),
            ("changes", Json::Array(changes)),
        ])
    }
    pub fn from_json(j: &Json) -> Self {
        let mut f = Self {
            computer: s(j, "computer").into(),
            date: s(j, "date").into(),
            version: s(j, "version").into(),
            cpu: s(j, "cpu").into(),
            board: s(j, "board").into(),
            bios: s(j, "bios").into(),
            ram: s(j, "ram").into(),
            gpu: s(j, "gpu").into(),
            disks: s(j, "disks").into(),
            windows: s(j, "windows").into(),
            machine_key: s(j, "machine_key").into(),
            ..Default::default()
        };
        f.limitations = a(j, "limitations")
            .iter()
            .take(256)
            .filter_map(Json::as_str)
            .map(str::to_string)
            .collect();
        f.repairs = a(j, "repairs")
            .iter()
            .take(256)
            .filter_map(Json::as_str)
            .map(str::to_string)
            .collect();
        f.findings = a(j, "findings")
            .iter()
            .take(256)
            .map(|j| Finding {
                severity: n(j, "severity").unwrap_or(2.0).clamp(0.0, 3.0) as u8,
                title: s(j, "title").into(),
                when: s(j, "when").into(),
                why: s(j, "why").into(),
                check: s(j, "check").into(),
                evidence: s(j, "evidence").into(),
            })
            .collect();
        f.readings = a(j, "readings")
            .iter()
            .take(2048)
            .filter_map(|j| {
                Some(Reading {
                    identity: s(j, "identity").into(),
                    device: s(j, "device").into(),
                    metric: s(j, "metric").into(),
                    value: n(j, "value")?,
                    unit: s(j, "unit").into(),
                    when: s(j, "when").into(),
                    source: s(j, "source").into(),
                })
            })
            .collect();
        f.counters = a(j, "counters")
            .iter()
            .take(256)
            .filter_map(|j| {
                Some(Counter {
                    identity: s(j, "identity").into(),
                    device: s(j, "device").into(),
                    metric: s(j, "metric").into(),
                    value: n(j, "value")?,
                    unit: s(j, "unit").into(),
                    date: s(j, "date").into(),
                })
            })
            .collect();
        f.changes = a(j, "changes")
            .iter()
            .take(256)
            .filter_map(|j| {
                Some(Change {
                    device: s(j, "device").into(),
                    metric: s(j, "metric").into(),
                    before: n(j, "before")?,
                    after: n(j, "after")?,
                    unit: s(j, "unit").into(),
                    before_date: s(j, "before_date").into(),
                    after_date: s(j, "after_date").into(),
                })
            })
            .collect();
        f
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn extracts_complete_json_records_with_nested_braces_and_preserves_sources() {
        let raw = "FILE: test.json | BYTES: 10\n{\"computer_name\":\"TEST-PC\",\"producer_version\":\"1.11\",\"created_at\":\"2026-11-19\",\"nested\":{\"x\":\"} {\"}}\n========== END FILE ==========\n";
        let d = documents(raw);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].0, "test.json");
        let f = Facts::parse(raw);
        assert_eq!(f.computer, "TEST-PC");
        assert_eq!(f.version, "1.11");
        assert!(f.limitations.iter().any(|s| s.contains("Sfc")));
    }
    #[test]
    fn unknown_machine_never_compares_as_improvement() {
        assert!(Facts::default().compare(&Facts::default()).is_err());
    }
}
#[test]
#[ignore = "Read only owner-provided field ZIP from WSD_V111_FIELD_ZIP; no API"]
fn v111_real_field_facts_replay() {
    let path = std::path::PathBuf::from(std::env::var("WSD_V111_FIELD_ZIP").unwrap());
    let before = crate::content_hash::sha256(std::fs::File::open(&path).unwrap()).unwrap();
    let (text, _) = crate::ai_export::analysis_session(
        &crate::ai_export::Input::zip(path.clone()),
        &std::sync::atomic::AtomicBool::new(false),
    )
    .unwrap();
    let docs = documents(&text);
    println!(
        "FIELD_JSON_RECORDS={} INCIDENT_SECTION_PRESENT={}",
        docs.len(),
        text.contains("Incidents_")
    );
    for (source, j) in &docs {
        if source.contains("Incidents") {
            println!(
                "INCIDENT_ROOT fields={} count={}",
                j.render().len(),
                a(j, "incidents").len()
            );
        }
    }
    let facts = Facts::parse(&text);
    assert!(!facts.cpu.is_empty());
    assert!(!facts.board.is_empty());
    assert!(!facts.bios.is_empty());
    // No valid Disk154 record is present in this archive's structured evidence.
    // Never manufacture one from a timestamp/identifier substring or the UI mock.
    assert!(
        !facts
            .findings
            .iter()
            .any(|f| f.title.contains("154") && f.title.contains("Netac"))
    );
    assert_eq!(
        facts
            .findings
            .iter()
            .filter(|f| f.title == "Неожиданное завершение работы")
            .count(),
        1
    );
    assert!(
        facts
            .changes
            .iter()
            .any(|c| c.device.contains("Netac") && c.before == 9.0 && c.after == 9.0)
    );
    assert!(
        facts
            .readings
            .iter()
            .any(|r| r.device.contains("Intel") && r.unit == "W" && r.value == 0.025)
    );
    assert!(
        facts
            .readings
            .iter()
            .any(|r| r.device.contains("RTX 5060") && r.unit == "W" && r.value == 30.4)
    );
    for value in [12.024, 5.020, 3.328] {
        assert!(
            facts
                .readings
                .iter()
                .any(|r| r.unit == "V" && (r.value - value).abs() < 0.000001)
        );
    }
    assert_eq!(
        crate::content_hash::sha256(std::fs::File::open(&path).unwrap()).unwrap(),
        before
    );
    let encoded = facts.to_json().render();
    let reloaded = Facts::from_json(&Json::parse(&encoded).unwrap());
    assert_eq!(reloaded.cpu, facts.cpu);
    assert_eq!(reloaded.changes.len(), facts.changes.len());
    println!(
        "FIELD_FACTS PASS: source_sha256={before}; findings={}; changes={}; readings={}; source_unchanged=true; API=NOT_RUN",
        facts.findings.len(),
        facts.changes.len(),
        facts.readings.len()
    );
}

#[cfg(test)]
mod v111_evidence_tests {
    use super::*;
    #[test]
    fn historical_disk154_never_identifies_current_nvme_or_invents_repair() {
        let f = Facts::parse(
            r#"FILE: Event_Evidence.json | BYTES: 1
{"aggregates":[{"event_id":154,"count":2,"provider":"disk","last_seen":"2026-11-06"}]}
========== Hardware.json ==========
{"Storage":{"Disks":[{"Model":"Current NVMe"}]}}
"#,
        );
        let finding = f.findings.iter().find(|f| f.title.contains("154")).unwrap();
        assert!(!finding.title.contains("Current NVMe"));
        assert!(finding.why.contains("не идентифицирует"));
        assert!(f.repairs.is_empty());
    }
    #[test]
    fn comparable_identity_date_and_units_are_required_for_history() {
        let mut old = Facts {
            computer: "TEST-PC".into(),
            machine_key: "same".into(),
            ..Default::default()
        };
        old.counters.push(Counter {
            identity: "disk-A".into(),
            device: "NVMe".into(),
            metric: "errors".into(),
            value: 9.,
            unit: "count".into(),
            date: "2026-11-01".into(),
        });
        let mut current = old.clone();
        current.counters[0].date = "2026-11-19".into();
        assert!(current.compare(&old).is_ok());
        assert_eq!(current.changes[0].before, 9.);
        assert_eq!(current.changes[0].after, 9.);
        current.counters[0].identity = "disk-B".into();
        assert!(current.compare(&old).is_err());
        current.counters[0].identity = "disk-A".into();
        current.counters[0].unit = "different".into();
        assert!(current.compare(&old).is_err());
        current.machine_key = "another-machine".into();
        assert!(current.compare(&old).is_err());
    }
    #[test]
    fn large_root_record_does_not_consume_nested_records_as_documents() {
        let text = format!(
            "FILE: large.json | BYTES: 5000000\n{{\"padding\":\"{}\",\"nested\":{{\"computer_name\":\"not-root\"}}}}\nFILE: next.json | BYTES: 1\n{{\"producer_version\":\"1.11\",\"computer_name\":\"TEST-PC\",\"created_at\":\"2026-11-19\"}}",
            "x".repeat(4 * 1024 * 1024 + 1)
        );
        assert_eq!(documents(&text).len(), 2);
        assert_eq!(Facts::parse(&text).computer, "TEST-PC");
    }
}

#[test]
fn v111_repairs_require_verified_result_identity_and_time_not_command_launch() {
    let base = r#"FILE: manifest.json | BYTES: 1
{"computer_name":"TEST-PC","producer_version":"1.11","created_at":"2026-11-19"}
FILE: operation.json | BYTES: 1
{"repair_id":"test-operation","computer":"TEST-PC","started_at":"2026-11-18T10:00:00"}
FILE: result.json | BYTES: 1
{"repair_id":"test-operation","check":"SFC","status":"SUCCESS_VERIFIED","verified_result":"OK","completed_at":"2026-11-18T11:00:00","verification":{"exit_code":0}}
"#;
    assert_eq!(Facts::parse(base).repairs.len(), 1);
    for invalid in [
        base.replace("SUCCESS_VERIFIED", "STARTED"),
        base.replace("verified_result\":\"OK", "verified_result\":\"ATTENTION"),
        base.replace("computer\":\"TEST-PC", "computer\":\"OTHER-PC"),
        base.replace("2026-11-18T11", "2026-11-20T11"),
    ] {
        assert!(Facts::parse(&invalid).repairs.is_empty());
    }
}

#[test]
fn v111_empty_or_unknown_storage_identity_never_matches_history() {
    for id in ["", "UNKNOWN", "N/A"] {
        let text = format!(
            r#"FILE: NVMe.json | BYTES: 1
{{"physical_identity":"{id}","model":"Unknown disk","captured_at":"2026-11-19","error_information_log":{{"lifetime_entries_counter":9}}}}
FILE: history.json | BYTES: 1
{{"sessions":[{{"physical_identity":"{id}","error_log_entries":0,"end_time":"2026-11-01"}}]}}
"#
        );
        let f = Facts::parse(&text);
        assert_eq!(f.counters.len(), 1);
        assert!(f.counters[0].identity.is_empty());
        assert!(f.changes.is_empty());
    }
}

#[cfg(test)]
mod client_display_regressions {
    use super::*;

    #[test]
    fn source_wall_time_without_iso_noise_or_timezone_conversion() {
        assert_eq!(
            display_date("2026-11-19T16:14:44.9204577+03:00"),
            "19.11.2026, 16:14"
        );
        assert_eq!(
            display_date("2026-11-19T00:01:00+14:00"),
            "19.11.2026, 00:01"
        );
        assert_eq!(display_date("2026-11-19"), "19.11.2026");
        assert_eq!(display_date("2026-02-29"), "Дата неизвестна");
        assert_eq!(display_date(""), "Дата неизвестна");
    }

    #[test]
    fn repeated_readings_keep_each_physical_device_and_distinct_metric() {
        let facts = Facts::parse(
            r#"
{"sensors":[{"provider":"LHM","hardware_id":"/nvme/0","hardware":"SSD Model","sensor_id":"/nvme/0/temperature/0","sensor_type":"Temperature","sensor_name":"Drive","timestamp":"2026-11-19T12:00:00","value":30},{"provider":"LHM","hardware_id":"/nvme/1","hardware":"SSD Model","sensor_id":"/nvme/1/temperature/0","sensor_type":"Temperature","sensor_name":"Drive","timestamp":"2026-11-19T12:00:00","value":45}]}
{"sensors":[{"provider":"LHM","hardware_id":"/nvme/0","hardware":"SSD Model","sensor_id":"/nvme/0/temperature/0","sensor_type":"Temperature","sensor_name":"Drive","timestamp":"2026-11-19T12:30:00","value":44},{"provider":"LHM","hardware_id":"/nvme/0","hardware":"SSD Model","sensor_id":"/nvme/0/temperature/1","sensor_type":"Temperature","sensor_name":"Drive","timestamp":"2026-11-19T12:30:00","value":53}]}
{"physical_identity":"disk-A","model":"SSD Model","captured_at":"2026-11-19T12:00:00","error_information_log":{"lifetime_entries_counter":1100}}
{"physical_identity":"disk-A","model":"SSD Model","captured_at":"2026-11-19T12:30:00","error_information_log":{"lifetime_entries_counter":1184}}
{"physical_identity":"disk-B","model":"SSD Model","captured_at":"2026-11-19T12:30:00","error_information_log":{"lifetime_entries_counter":4}}
{"sessions":[{"physical_identity":"disk-A","error_log_entries":1032,"end_time":"2026-11-04T10:30:00"}]}
"#,
        );
        assert_eq!(
            facts.readings.iter().map(|r| r.value).collect::<Vec<_>>(),
            [44., 45., 53.]
        );
        assert_eq!(
            facts.counters.iter().map(|c| c.value).collect::<Vec<_>>(),
            [1184., 4.]
        );
        assert_eq!(facts.changes.len(), 1);
        let change = &facts.changes[0];
        assert!(change.metric.contains("NVMe"));
        assert_eq!((change.before, change.after), (1032., 1184.));
        assert_eq!(display_date(&change.before_date), "04.11.2026, 10:30");
        assert_eq!(display_date(&change.after_date), "19.11.2026, 12:30");
    }

    #[test]
    fn chkdsk_findings_do_not_claim_verified_work() {
        let problems = Facts::parse(
            r#"{"Checks":[{"Check":"CHKDSK","Status":"ATTENTION","Detail":"CHKDSK detected errors"}]}"#,
        );
        assert_eq!(problems.findings.len(), 1);
        assert!(
            problems.findings[0]
                .title
                .contains("Исправление не подтверждено")
        );
        assert!(problems.repairs.is_empty());
        let repaired = Facts::parse(
            r#"{"Checks":[{"Check":"CHKDSK","Status":"OK","Detail":"Windows has made corrections to the file system."}]}"#,
        );
        assert_eq!(repaired.findings.len(), 1);
        assert!(
            repaired.findings[0]
                .title
                .contains("Нужна повторная проверка")
        );
        assert!(repaired.repairs.is_empty());
    }
}
