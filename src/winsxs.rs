//! Offline, evidence-only component-store analysis. Missing records never prove repair.
use crate::{
    deep_checks::json::{self, Value},
    report_package::EvidenceFile,
};
use std::collections::{BTreeMap, BTreeSet};
fn strv<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or("")
}
fn arr<'a>(v: &'a Value, k: &str) -> &'a [Value] {
    match v.get(k) {
        Some(Value::Arr(a)) => a,
        _ => &[],
    }
}
fn time(s: &str) -> String {
    s.get(..19)
        .filter(|s| s.as_bytes().get(4) == Some(&b'-') && s.as_bytes().get(7) == Some(&b'-'))
        .unwrap_or("")
        .replace('T', " ")
}
#[derive(Clone, Debug, Default)]
pub struct Finding {
    pub component: String,
    pub version: String,
    pub file: String,
    pub count: usize,
    pub evidence: Vec<String>,
}
#[derive(Clone, Debug, Default)]
pub struct ServicingSummary {
    pub at: String,
    pub source: String,
    pub operation: String,
    pub result: String,
    pub detected: Option<u64>,
    pub repaired: Option<u64>,
    pub fixed: BTreeSet<String>,
    pub fixed_at: BTreeMap<String, String>,
}
impl ServicingSummary {
    pub fn confirmed_repair(&self) -> bool {
        self.operation.eq_ignore_ascii_case("Detect and Repair")
            && matches!(self.result.as_str(), "0x0" | "0x00000000")
            && self
                .detected
                .is_some_and(|n| n > 0 && self.repaired == Some(n))
    }
}
fn component_path(line: &str) -> Option<(&str, &str)> {
    let pos = ["amd64_", "wow64_", "x86_", "arm64_", "msil_"]
        .iter()
        .filter_map(|p| line.find(p))
        .min()?;
    Some(
        line[pos..]
            .trim()
            .split_once('\\')
            .unwrap_or((line[pos..].trim(), "")),
    )
}
// Summaries and explicit Fixed rows are historical evidence, never current health.
// A successful aggregate repair alone cannot identify which file was repaired.
fn cbs_history(text: &str, source: &str, start: &str) -> Vec<ServicingSummary> {
    let mut summaries = BTreeMap::<String, ServicingSummary>::new();
    let mut fixed = Vec::new();
    for line in text.lines() {
        let stamp = time(line);
        if stamp.is_empty() || stamp.as_str() >= start {
            continue;
        }
        if line.contains("(Fixed)")
            && let Some((component, file)) = component_path(line)
        {
            fixed.push((
                stamp.clone(),
                format!("{component}\\{file}").to_ascii_lowercase(),
            ));
        }
        let fields = [
            "Summary:",
            "Operation:",
            "Operation result:",
            "Total Detected Corruption:",
            "Total Repaired Corruption:",
        ];
        for field in fields {
            if let Some((_, tail)) = line.split_once(field) {
                let row = summaries
                    .entry(stamp.clone())
                    .or_insert_with(|| ServicingSummary {
                        at: stamp.clone(),
                        source: source.into(),
                        ..Default::default()
                    });
                let value = tail.trim();
                match field {
                    "Operation:" => row.operation = value.into(),
                    "Operation result:" => row.result = value.to_ascii_lowercase(),
                    "Total Detected Corruption:" => row.detected = value.parse().ok(),
                    "Total Repaired Corruption:" => row.repaired = value.parse().ok(),
                    _ => {}
                }
            }
        }
    }
    let mut previous = String::new();
    for row in summaries.values_mut() {
        // Do not carry Fixed rows across an intervening CBS summary.
        row.fixed = fixed
            .iter()
            .filter(|(t, _)| t > &previous && t <= &row.at)
            .map(|(_, key)| key.clone())
            .collect();
        for (stamp, key) in fixed.iter().filter(|(t, _)| t > &previous && t <= &row.at) {
            row.fixed_at
                .entry(key.clone())
                .and_modify(|t| {
                    if stamp > t {
                        t.clone_from(stamp);
                    }
                })
                .or_insert_with(|| stamp.clone());
        }
        previous.clone_from(&row.at);
    }
    summaries.into_values().collect()
}
#[derive(Clone, Debug, Default)]
pub struct Analysis {
    pub computer: String,
    pub identity: String,
    pub start: String,
    pub end: String,
    pub dism: String,
    pub sfc: String,
    pub detected: Option<u64>,
    pub repaired: Option<u64>,
    pub findings: BTreeMap<String, Finding>,
    pub hresults: BTreeSet<String>,
    pub source_failures: usize,
    pub summary: BTreeMap<String, u64>,
    pub repair_proof: Vec<String>,
    pub history: Vec<String>,
    pub cbs_history: Vec<ServicingSummary>,
    pub coverage: Vec<String>,
}
fn identity_text(s: &str) -> bool {
    !s.trim().is_empty()
        && ![
            "unknown",
            "none",
            "not available",
            "default string",
            "to be filled by o.e.m.",
            "system serial number",
            "0",
        ]
        .contains(&s.trim().to_ascii_lowercase().as_str())
}
pub fn analyze(files: &[EvidenceFile]) -> Analysis {
    let mut a = Analysis::default();
    let mut latest = String::new();
    for f in files {
        if !f.name.ends_with(".json") {
            continue;
        }
        let text = String::from_utf8_lossy(&f.bytes);
        let Some(v) = json::parse(text.trim_start_matches('﻿')) else {
            continue;
        };
        if f.name.starts_with("EXPC_")
            && v.get("Checks").is_some()
            && strv(&v, "GeneratedAt") >= latest.as_str()
        {
            latest = strv(&v, "GeneratedAt").into();
            a.start = time(strv(&v, "StartedAt"));
            a.end = time(&latest);
            a.computer = strv(&v, "Computer").into();
            for c in arr(&v, "Checks") {
                match strv(c, "Check") {
                    "SFC" => a.sfc = strv(c, "Status").into(),
                    "DISM" => a.dism = strv(c, "Status").into(),
                    _ => {}
                }
            }
            if let Some(h) = v.get("ServicingHistory") {
                a.history.push(format!("{}: {:?}", f.name, h));
            }
        }
        if let Some(b) = v.get("Motherboard") {
            let serial = strv(b, "Serial");
            if identity_text(serial) {
                a.identity = format!("{}|{}", strv(b, "Product"), serial);
            }
        }
        if strv(&v, "status") == "SUCCESS_VERIFIED"
            && strv(&v, "check") == "DISM"
            && strv(&v, "verified_result") == "OK"
        {
            let stamp = time(strv(&v, "completed_at"));
            if !stamp.is_empty() {
                a.repair_proof.push(stamp);
            }
        }
    }
    if a.start.is_empty() || a.end.is_empty() {
        a.coverage
            .push("UNKNOWN: границы текущей диагностики отсутствуют".into());
        return a;
    }
    let mut seen = BTreeSet::new();
    let mut logs = 0;
    for f in files {
        let lower = f.name.to_ascii_lowercase();
        if !lower.ends_with(".log") || !(lower.contains("cbs") || lower.contains("dism")) {
            continue;
        }
        logs += 1;
        let text = String::from_utf8_lossy(&f.bytes);
        if lower.contains("cbs") {
            for row in cbs_history(&text, &f.name, &a.start) {
                if !a.cbs_history.iter().any(|old| {
                    old.at == row.at
                        && old.operation == row.operation
                        && old.result == row.result
                        && old.detected == row.detected
                        && old.repaired == row.repaired
                        && old.fixed == row.fixed
                        && old.fixed_at == row.fixed_at
                }) {
                    a.cbs_history.push(row);
                }
            }
        }
        for (i, line) in text.lines().enumerate() {
            let stamp = time(line);
            if stamp.is_empty()
                || stamp < a.start
                || stamp > a.end
                || !seen.insert(line.to_string())
            {
                continue;
            }
            for (key, label) in [
                ("Total Detected Corruption:", "detected"),
                ("Total Repaired Corruption:", "repaired"),
                ("CSI Payload Corruption:", "payload"),
                ("CBS Manifest Corruption:", "cbs_manifest"),
                ("CSI Manifest Corruption:", "csi_manifest"),
            ] {
                if let Some((_, tail)) = line.split_once(key)
                    && let Ok(n) = tail.trim().parse::<u64>()
                {
                    a.summary.insert(label.into(), n);
                    match label {
                        "detected" => a.detected = Some(n),
                        "repaired" => a.repaired = Some(n),
                        _ => {}
                    }
                }
            }
            let low = line.to_ascii_lowercase();
            if low.contains("unable to repair payload")
                || low.contains("falling back to wu")
                || low.contains("source files could not be found")
            {
                a.source_failures += 1;
            }
            for (pos, _) in low.match_indices("0x") {
                if let Some(code) = low.get(pos..pos + 10)
                    && code[2..].chars().all(|c| c.is_ascii_hexdigit())
                {
                    a.hresults.insert(code.into());
                }
            }
            if !(line.contains("Payload Corrupt") || line.contains("Manifest Corrupt")) {
                continue;
            }
            let Some((component, file)) = component_path(line) else {
                continue;
            };
            let version = component
                .split('_')
                .find(|p| {
                    p.chars().all(|c| c.is_ascii_digit() || c == '.') && p.matches('.').count() >= 2
                })
                .unwrap_or("");
            let key = format!("{component}\\{file}").to_ascii_lowercase();
            let fnd = a.findings.entry(key).or_insert_with(|| Finding {
                component: component.into(),
                version: version.into(),
                file: file.into(),
                ..Default::default()
            });
            fnd.count += 1;
            if fnd.evidence.len() < 3 {
                fnd.evidence.push(format!("{}:{}", f.name, i + 1));
            }
        }
    }
    a.cbs_history.sort_by(|a, b| a.at.cmp(&b.at));
    if logs == 0 {
        a.coverage
            .push("CBS/DISM журналы отсутствуют; имена компонентов UNKNOWN".into());
    }
    if a.identity.is_empty() {
        a.coverage
            .push("Аппаратная идентичность не подтверждена; сравнение двух ПК запрещено".into());
    }
    if a.detected.is_none() {
        a.coverage.push(
            "Текущий CBS corruption summary не найден; отсутствие строк не означает CLEAN".into(),
        );
    }
    a
}
impl Analysis {
    pub fn text(&self) -> String {
        let mut out = format!(
            "WinSxS Reliability — WinDiag {}\nКомпьютер: {}\nИнтервал: {} — {} (локальное время источника)\nSFC: {}; DISM: {}\nCBS detected: {:?}; repaired: {:?}; уникальных component/file: {}\nОшибки repair source/fallback: {}\nHRESULT: {}\nПричина повреждения: UNKNOWN. Повторное обнаружение без доказанного ремонта не является новым повреждением.\n",
            crate::APP_VERSION,
            self.computer,
            self.start,
            self.end,
            self.sfc,
            self.dism,
            self.detected,
            self.repaired,
            self.findings.len(),
            self.source_failures,
            self.hresults.iter().cloned().collect::<Vec<_>>().join(", ")
        );
        let mut groups = BTreeMap::<&str, usize>::new();
        for f in self.findings.values() {
            *groups.entry(&f.component).or_default() += 1;
        }
        for (name, count) in groups.iter().take(50) {
            out.push_str(&format!("{name}: {count} файлов\n"));
        }
        if groups.len() > 50 {
            out.push_str("Остальные компоненты — в JSON, первичные строки — в CBS/DISM.\n");
        }
        for row in &self.cbs_history {
            out.push_str(&format!("История CBS {}: найдено {:?}, восстановлено {:?}; {}; поимённых Fixed: {}. Источник: {}\n",
                row.at, row.detected, row.repaired,
                if row.confirmed_repair() { "операция восстановления подтверждена" } else { "полный результат операции не подтверждён" }, row.fixed.len(), row.source));
        }
        if !self.cbs_history.is_empty() {
            out.push_str("История CBS не заменяет текущую проверку. Общие счётчики не доказывают повторное повреждение тех же файлов.\n");
        }
        for c in &self.coverage {
            out.push_str(c);
            out.push('\n');
        }
        out
    }
    pub fn json(&self) -> String {
        let q = json::string;
        let list = |a: Vec<String>| format!("[{}]", a.join(","));
        let cbs_history = list(self.cbs_history.iter().map(|r| format!(
            "{{\"at\":{},\"source\":{},\"operation\":{},\"result\":{},\"detected\":{},\"repaired\":{},\"confirmed_repair\":{},\"fixed_keys\":{},\"fixed_at\":{},\"temporal_state\":\"HISTORICAL\"}}",
            q(&r.at), q(&r.source), q(&r.operation), q(&r.result),
            r.detected.map(|n|n.to_string()).unwrap_or("null".into()),
            r.repaired.map(|n|n.to_string()).unwrap_or("null".into()), r.confirmed_repair(),
            list(r.fixed.iter().map(|key|q(key)).collect()),
            format_args!("{{{}}}", r.fixed_at.iter().map(|(k,v)|format!("{}:{}",q(k),q(v))).collect::<Vec<_>>().join(",")))).collect());
        let findings=list(self.findings.iter().map(|(key,f)|format!("{{\"key\":{},\"component\":{},\"version\":{},\"file\":{},\"occurrences\":{},\"temporal_state\":\"CURRENT\",\"evidence\":{}}}",q(key),q(&f.component),q(&f.version),q(&f.file),f.count,list(f.evidence.iter().map(|x|q(x)).collect()))).collect());
        format!(
            "{{\"producer_version\":{},\"computer\":{},\"identity\":{},\"started_at\":{},\"ended_at\":{},\"sfc\":{},\"dism\":{},\"detected\":{},\"repaired\":{},\"findings\":{},\"hresults\":{},\"source_failures\":{},\"coverage\":{},\"servicing_history\":{},\"cbs_history\":{},\"cause\":\"UNKNOWN\"}}",
            q(crate::APP_VERSION),
            q(&self.computer),
            q(&self.identity),
            q(&self.start),
            q(&self.end),
            q(&self.sfc),
            q(&self.dism),
            self.detected
                .map(|n| n.to_string())
                .unwrap_or("null".into()),
            self.repaired
                .map(|n| n.to_string())
                .unwrap_or("null".into()),
            findings,
            list(self.hresults.iter().map(|x| q(x)).collect()),
            self.source_failures,
            list(self.coverage.iter().map(|x| q(x)).collect()),
            list(self.history.iter().map(|x| q(x)).collect()),
            cbs_history
        )
    }
}
pub fn compare(before: &Analysis, after: &Analysis) -> Vec<(String, &'static str)> {
    let keys: BTreeSet<_> = before
        .findings
        .keys()
        .chain(after.findings.keys())
        .cloned()
        .collect();
    let same = !before.identity.is_empty()
        && before.identity == after.identity
        && before.computer.eq_ignore_ascii_case(&after.computer)
        && !before.end.is_empty()
        && before.end < after.start;
    let verified = after
        .repair_proof
        .iter()
        .chain(before.repair_proof.iter())
        .any(|t| t > &before.end && t < &after.start);
    let complete = before
        .detected
        .is_some_and(|n| n as usize == before.findings.len());
    keys.into_iter()
        .map(|key| {
            let file_repaired = after
                .cbs_history
                .iter()
                .chain(before.cbs_history.iter())
                .any(|r| {
                    r.confirmed_repair()
                        && r.at > before.end
                        && r.at < after.start
                        && r.fixed_at.get(&key).is_some_and(|t| t > &before.end)
                });
            let state = if !same {
                "UNKNOWN"
            } else {
                match (
                    before.findings.contains_key(&key),
                    after.findings.contains_key(&key),
                ) {
                    (true, true) => {
                        if verified || file_repaired {
                            "RECURRED"
                        } else {
                            "PERSISTENT"
                        }
                    }
                    (false, true) => {
                        if before.dism == "OK" || complete {
                            "CURRENT"
                        } else {
                            "UNKNOWN"
                        }
                    }
                    (true, false) => {
                        if after.dism == "OK" && after.detected == Some(0) {
                            "RESOLVED"
                        } else {
                            "UNKNOWN"
                        }
                    }
                    _ => "UNKNOWN",
                }
            };
            (key, state)
        })
        .collect()
}
pub fn evidence(files: &[EvidenceFile]) -> Vec<EvidenceFile> {
    let a = analyze(files);
    vec![
        EvidenceFile::new("WinSxS_Reliability.json", a.json().into_bytes()),
        EvidenceFile::new("WinSxS_Reliability.txt", a.text().into_bytes()),
    ]
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(start: &str, end: &str, rows: &str) -> Vec<EvidenceFile> {
        vec![EvidenceFile::new("EXPC_fixture.json",format!(r#"{{"StartedAt":"{start}","GeneratedAt":"{end}","Computer":"SYNTHETIC","Checks":[{{"Check":"DISM","Status":"ATTENTION"}}]}}"#).into_bytes()),EvidenceFile::new("Hardware_fixture.json",br#"{"Motherboard":{"Product":"Test","Serial":"SYNTHETIC-SERIAL"}}"#.to_vec()),EvidenceFile::new("CBS/CBS.log",rows.as_bytes().to_vec())]
    }
    #[test]
    fn persistent_requires_no_invented_repair() {
        let f = fixture(
            "2026-10-30T10:00:00",
            "2026-10-30T11:00:00",
            "2026-10-30 10:20:00 CBS (p) CSI Payload Corrupt (n) amd64_test_abcd_10.0.1.1_none_x\\file.dll\n2026-10-30 10:21:00 CBS Total Detected Corruption: 1",
        );
        let a = analyze(&f);
        let f2 = fixture(
            "2026-11-04T10:00:00",
            "2026-11-04T11:00:00",
            "2026-11-04 10:20:00 CBS (p) CSI Payload Corrupt (n) amd64_test_abcd_10.0.1.1_none_x\\file.dll",
        );
        let mut b = analyze(&f2);
        assert_eq!(compare(&a, &b)[0].1, "PERSISTENT");
        b.repair_proof.push("2026-11-01 12:00:00".into());
        assert_eq!(compare(&a, &b)[0].1, "RECURRED");
        b.findings.clear();
        assert_eq!(compare(&a, &b)[0].1, "UNKNOWN");
        b.dism = "OK".into();
        b.detected = Some(0);
        assert_eq!(compare(&a, &b)[0].1, "RESOLVED");
        assert!(json::parse(&a.json()).is_some());
    }
    #[test]
    fn old_cbs_and_idle_scavenge_not_current_or_repair() {
        let f = fixture(
            "2026-11-04T10:00:00",
            "2026-11-04T11:00:00",
            "2026-10-30 10:20:00 CBS (p) CSI Payload Corrupt (n) amd64_test_abcd_10.0.1.1_none_x\\file.dll\n2026-11-04 10:30:00 CBS Signaling IdleScavenge and/or repair complete",
        );
        let a = analyze(&f);
        assert!(a.findings.is_empty());
        assert!(a.repair_proof.is_empty());
        assert!(a.detected.is_none());
    }
    fn historical_rows(operation: &str, result: &str, detected: u64, repaired: u64) -> String {
        format!(
            "2026-11-02 09:59:59 CBS (p) CSI Payload Corrupt (w) (Fixed) msil_test_abcd_10.0.1.1_none_x\\one.dll\n--- source lines 1-1; key evidence ---\n2026-11-02 10:00:00 CBS Summary:\n2026-11-02 10:00:00 CBS Operation: {operation}\n2026-11-02 10:00:00 CBS Operation result: {result}\n2026-11-02 10:00:00 CBS Total Detected Corruption: {detected}\n2026-11-02 10:00:00 CBS Total Repaired Corruption: {repaired}\n"
        )
    }
    #[test]
    fn historical_summary_does_not_override_current_or_imply_same_file_recurrence() {
        let rows = historical_rows("Detect and Repair", "0x0", 4100, 4100)
            + "2026-11-04 10:20:00 CBS (p) CSI Payload Corrupt (n) amd64_other_abcd_10.0.2.1_none_x\\two.dll\n2026-11-04 10:21:00 CBS Total Detected Corruption: 15\n2026-11-04 10:21:00 CBS Total Repaired Corruption: 0";
        let a = analyze(&fixture(
            "2026-11-04T10:00:00",
            "2026-11-04T11:00:00",
            &rows,
        ));
        assert_eq!(a.detected, Some(15));
        assert_eq!(a.repaired, Some(0));
        assert_eq!(a.findings.len(), 1);
        assert_eq!(a.cbs_history.len(), 1);
        assert!(a.cbs_history[0].confirmed_repair());
        assert_eq!(a.cbs_history[0].fixed.len(), 1);
        assert!(
            !a.cbs_history[0]
                .fixed
                .contains(a.findings.keys().next().unwrap())
        );
        let v = json::parse(&a.json()).unwrap();
        assert_eq!(arr(&v, "cbs_history").len(), 1);
        assert!(a.text().contains("операция восстановления подтверждена"));
        assert!(a.repair_proof.is_empty()); // Aggregate historical result is not a clean verification.
    }
    #[test]
    fn cbs_requires_operation_success_counts_and_file_identity() {
        let before = analyze(&fixture(
            "2026-11-01T10:00:00",
            "2026-11-01T11:00:00",
            "2026-11-01 10:30:00 CBS (p) CSI Payload Corrupt (n) msil_test_abcd_10.0.1.1_none_x\\one.dll",
        ));
        let current = "2026-11-04 10:30:00 CBS (p) CSI Payload Corrupt (n) msil_test_abcd_10.0.1.1_none_x\\one.dll";
        for (operation, result, detected, repaired, expected) in [
            ("Detect and Repair", "0x0", 4, 4, "RECURRED"),
            ("Detect only", "0x0", 4, 4, "PERSISTENT"),
            ("Detect and Repair", "0x800f081f", 4, 4, "PERSISTENT"),
            ("Detect and Repair", "0x0", 4, 3, "PERSISTENT"),
            ("", "", 4, 4, "PERSISTENT"),
            ("Detect and Repair", "0x0", 0, 0, "PERSISTENT"),
        ] {
            let rows = historical_rows(operation, result, detected, repaired) + current;
            let after = analyze(&fixture(
                "2026-11-04T10:00:00",
                "2026-11-04T11:00:00",
                &rows,
            ));
            assert_eq!(
                compare(&before, &after)[0].1,
                expected,
                "{operation} {result}"
            );
        }
        let rows = historical_rows("Detect and Repair", "0x0", 4, 4)
            .replace("one.dll", "different.dll")
            + current;
        let after = analyze(&fixture(
            "2026-11-04T10:00:00",
            "2026-11-04T11:00:00",
            &rows,
        ));
        assert_eq!(compare(&before, &after)[0].1, "PERSISTENT");
    }
    #[test]
    fn fixed_rows_cannot_cross_intervening_summary_or_use_future_history() {
        let rows = historical_rows("Detect only", "0x0", 4, 0)
            + &historical_rows("Detect and Repair", "0x0", 4, 4)
                .replace("2026-11-02", "2026-11-03")
                .replace("(Fixed)", "(n)")
            + &historical_rows("Detect and Repair", "0x0", 4, 4)
                .replace("2026-11-02", "2026-11-06");
        let a = analyze(&fixture(
            "2026-11-04T10:00:00",
            "2026-11-04T11:00:00",
            &rows,
        ));
        assert_eq!(a.cbs_history.len(), 2);
        assert!(!a.cbs_history[0].confirmed_repair());
        assert!(a.cbs_history[1].confirmed_repair());
        assert!(a.cbs_history[1].fixed.is_empty());
    }
    #[test]
    fn fixed_before_previous_diagnosis_is_not_intermediate_repair() {
        let before = analyze(&fixture(
            "2026-11-02T09:00:00",
            "2026-11-02T09:59:59",
            "2026-11-02 09:30:00 CBS (p) CSI Payload Corrupt (n) msil_test_abcd_10.0.1.1_none_x\\one.dll",
        ));
        let rows = historical_rows("Detect and Repair", "0x0", 4, 4)
            + "2026-11-04 10:30:00 CBS (p) CSI Payload Corrupt (n) msil_test_abcd_10.0.1.1_none_x\\one.dll";
        let after = analyze(&fixture(
            "2026-11-04T10:00:00",
            "2026-11-04T11:00:00",
            &rows,
        ));
        assert!(after.cbs_history[0].confirmed_repair());
        assert_eq!(compare(&before, &after)[0].1, "PERSISTENT");
    }
    #[test]
    #[ignore = "Private archive requires WSD_HISTORY_ZIP; no private fixtures tracked"]
    fn private_servicing_history_replay() {
        let path = std::env::var("WSD_HISTORY_ZIP").expect("explicit archive path");
        let files = crate::report_package::read_zip(std::path::Path::new(&path)).unwrap();
        let a = analyze(&files);
        assert_eq!(a.detected, Some(15));
        assert_eq!(a.repaired, Some(0));
        assert_eq!(a.findings.len(), 15);
        let old: Vec<_> = a
            .cbs_history
            .iter()
            .filter(|r| r.detected == Some(4100))
            .collect();
        assert_eq!(old.len(), 1);
        assert_eq!(old[0].repaired, Some(4100));
        assert_eq!(old[0].fixed.len(), 3153);
        assert_eq!(
            old[0].confirmed_repair(),
            std::env::var("WSD_EXPECT_COMPLETE_HISTORY").as_deref() == Ok("1")
        );
        assert!(a.findings.keys().all(|k| !old[0].fixed.contains(k)));
        assert!(a.repair_proof.is_empty());
        assert!(json::parse(&a.json()).is_some());
        println!(
            "PRIVATE HISTORY: current 15/0; historical 4100/4100; 3153 fixed keys; intersection 0; complete repair proof={}",
            old[0].confirmed_repair()
        );
    }
}
