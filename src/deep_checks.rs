//! v0.4.0: result state of the EXPC deep checks (SFC / DISM / CHKDSK).
//!
//! Execution state (progress, "100%") and diagnostic RESULT are separate:
//! a check can complete (100%) and still report a Windows problem, e.g.
//! `DISM /ScanHealth` → "The component store is repairable.".
//!
//! Sources, most structured first (raw evidence is never modified):
//! 1. the EXPC JSON evidence (`Checks[] = {Check, Status, Detail}`, written
//!    by EXPC-Diagnostic.ps1 from the tool output it classified itself);
//! 2. the EXPC TXT evidence (`Result: <STATUS> — <detail>` line of the step);
//! 3. the key output lines of the step in the TXT, classified by
//!    [`classify_output`] (conservative: ambiguous text is `Unknown`).
//!
//! WinStateDiag stays read-only: nothing here runs a repair command. The
//! manual repair command is only ever shown as text.

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DeepCheck {
    Sfc,
    Dism,
    Chkdsk,
}

impl DeepCheck {
    pub const ALL: [DeepCheck; 3] = [DeepCheck::Sfc, DeepCheck::Dism, DeepCheck::Chkdsk];

    /// `Checks[].Check` key in the EXPC JSON (and the display name).
    pub fn key(self) -> &'static str {
        match self {
            DeepCheck::Sfc => "SFC",
            DeepCheck::Dism => "DISM",
            DeepCheck::Chkdsk => "CHKDSK",
        }
    }

    /// 0-based EXPC step index (SFC = step 11).
    pub fn step_index(self) -> usize {
        match self {
            DeepCheck::Sfc => 10,
            DeepCheck::Dism => 11,
            DeepCheck::Chkdsk => 12,
        }
    }

    pub fn of_step_index(i: usize) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.step_index() == i)
    }

    fn of_key(key: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|c| c.key().eq_ignore_ascii_case(key.trim()))
    }

    /// Manual repair command, shown as TEXT ONLY for an ATTENTION result.
    /// WinStateDiag never executes it.
    pub fn manual_command(self, system_drive: &str) -> String {
        match self {
            DeepCheck::Sfc => "sfc /scannow".into(),
            DeepCheck::Dism => "DISM /Online /Cleanup-Image /RestoreHealth".into(),
            DeepCheck::Chkdsk => format!("chkdsk {} /f", system_drive.trim()),
        }
    }
}

/// Diagnostic result of a completed (or skipped) deep check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckResult {
    Ok,
    Attention,
    Error,
    Unknown,
    Skipped,
}

impl CheckResult {
    /// Index into the localized finding table (`[ok, attention, error,
    /// unknown, skipped]`).
    pub fn index(self) -> usize {
        match self {
            CheckResult::Ok => 0,
            CheckResult::Attention => 1,
            CheckResult::Error => 2,
            CheckResult::Unknown => 3,
            CheckResult::Skipped => 4,
        }
    }

    /// Stable machine-readable value (manifest).
    pub fn as_str(self) -> &'static str {
        match self {
            CheckResult::Ok => "OK",
            CheckResult::Attention => "ATTENTION",
            CheckResult::Error => "ERROR",
            CheckResult::Unknown => "UNKNOWN",
            CheckResult::Skipped => "SKIPPED",
        }
    }

    /// EXPC status text → result. Anything unexpected is `Unknown`.
    pub fn from_status(status: &str) -> Self {
        match status.trim().to_ascii_uppercase().as_str() {
            "OK" => CheckResult::Ok,
            "ATTENTION" | "WARNING" => CheckResult::Attention,
            "ERROR" => CheckResult::Error,
            "SKIPPED" | "NOT TESTED" => CheckResult::Skipped,
            _ => CheckResult::Unknown,
        }
    }
}

/// Where a result was read from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResultSource {
    ExpcJson,
    ExpcTxtResult,
    ExpcTxtOutput,
}

impl ResultSource {
    pub fn as_str(self) -> &'static str {
        match self {
            ResultSource::ExpcJson => "expc_json.checks",
            ResultSource::ExpcTxtResult => "expc_txt.result_line",
            ResultSource::ExpcTxtOutput => "expc_txt.key_output",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct DeepCheckOutcome {
    pub check: DeepCheck,
    pub result: CheckResult,
    /// Short finding exactly as the evidence states it (not translated).
    pub detail: String,
    pub source: ResultSource,
}

// ---------------------------------------------------------------------
// Raw output classification (conservative)
// ---------------------------------------------------------------------

fn has(text: &str, needles: &[&str]) -> bool {
    let low = text.to_lowercase();
    needles.iter().any(|n| low.contains(&n.to_lowercase()))
}

/// Classifies the console output of a deep check. Only explicit, known
/// result sentences decide OK / ATTENTION; a failed execution is ERROR;
/// anything ambiguous is UNKNOWN (never an inferred fault).
pub fn classify_output(check: DeepCheck, text: &str, exit_code: Option<i32>) -> CheckResult {
    match check {
        DeepCheck::Sfc => {
            if has(
                text,
                &[
                    "could not perform the requested operation",
                    "не может выполнить запрошенную операцию",
                    "there is a system repair pending",
                    "ожидается восстановление системы",
                    "you must be an administrator",
                ],
            ) {
                CheckResult::Error
            } else if has(
                text,
                &[
                    "found integrity violations",
                    "found corrupt files",
                    "обнаружила нарушения целостности",
                    "обнаружила поврежденные файлы",
                    "обнаружила повреждённые файлы",
                ],
            ) {
                CheckResult::Attention
            } else if has(
                text,
                &[
                    "did not find any integrity violations",
                    "не обнаружила нарушений целостности",
                ],
            ) {
                CheckResult::Ok
            } else if exit_code.is_some_and(|c| c != 0) {
                CheckResult::Error
            } else {
                CheckResult::Unknown
            }
        }
        DeepCheck::Dism => {
            if has(text, &["component store cannot be repaired"]) {
                CheckResult::Error
            } else if has(text, &["component store is repairable"]) {
                CheckResult::Attention
            } else if has(text, &["no component store corruption detected"]) {
                CheckResult::Ok
            } else if exit_code.is_some_and(|c| c != 0) || has(text, &["\nerror:", "error: 0x"]) {
                CheckResult::Error
            } else {
                CheckResult::Unknown
            }
        }
        DeepCheck::Chkdsk => {
            if has(
                text,
                &[
                    "cannot open volume",
                    "access denied",
                    "cannot lock",
                    "не удается открыть том",
                    "не удаётся открыть том",
                    "отказано в доступе",
                ],
            ) {
                CheckResult::Error
            } else if has(
                text,
                &[
                    "found problems",
                    "found errors",
                    "windows has made corrections",
                    "обнаружила неполадки",
                    "обнаружены ошибки",
                    "внесла исправления",
                ],
            ) {
                CheckResult::Attention
            } else if has(
                text,
                &[
                    "windows has scanned the file system and found no problems",
                    "не обнаружила проблем",
                    "не обнаружено проблем",
                ],
            ) {
                CheckResult::Ok
            } else {
                // chkdsk exit codes other than 0 are not failures by
                // themselves (1 = errors fixed, 2 = cleanup, 3 = could not
                // check); without the sentence the result stays UNKNOWN.
                CheckResult::Unknown
            }
        }
    }
}

// ---------------------------------------------------------------------
// Structured evidence
// ---------------------------------------------------------------------

fn strip_bom(bytes: &[u8]) -> &[u8] {
    bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes)
}

/// `Checks[]` of an EXPC JSON evidence file (Windows PowerShell 5.1
/// `ConvertTo-Json`, UTF-8 with BOM). Only SFC / DISM / CHKDSK entries.
pub fn from_expc_json(bytes: &[u8]) -> Vec<DeepCheckOutcome> {
    let Ok(text) = std::str::from_utf8(strip_bom(bytes)) else {
        return Vec::new();
    };
    let Some(root) = json::parse(text) else {
        return Vec::new();
    };
    let checks = match root.get("Checks") {
        Some(json::Value::Arr(items)) => items.clone(),
        Some(obj @ json::Value::Obj(_)) => vec![obj.clone()],
        _ => return Vec::new(),
    };
    let mut out: Vec<DeepCheckOutcome> = Vec::new();
    for item in &checks {
        let Some(check) = item
            .get("Check")
            .and_then(|v| v.as_str())
            .and_then(DeepCheck::of_key)
        else {
            continue;
        };
        let status = item.get("Status").and_then(|v| v.as_str()).unwrap_or("");
        let detail = item.get("Detail").and_then(|v| v.as_str()).unwrap_or("");
        out.retain(|o| o.check != check);
        out.push(DeepCheckOutcome {
            check,
            result: CheckResult::from_status(status),
            detail: detail.trim().to_string(),
            source: ResultSource::ExpcJson,
        });
    }
    out.sort_by_key(|o| o.check);
    out
}

/// `GeneratedAt` of an EXPC JSON evidence file, when present.
pub fn expc_json_generated_at(bytes: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(strip_bom(bytes)).ok()?;
    json::parse(text)?
        .get("GeneratedAt")?
        .as_str()
        .map(str::to_string)
}

/// The step of `check` in an EXPC TXT evidence file: from its section
/// title line up to the next `=====` section frame after the body.
fn txt_section(text: &str, check: DeepCheck) -> Option<String> {
    let lines: Vec<&str> = text.lines().collect();
    // Section title written by Invoke-Step: "[11] SFC — ...".
    let prefix = format!("] {} —", check.key());
    let start = lines
        .iter()
        .position(|l| l.trim_start().starts_with('[') && l.contains(&prefix))?;
    let mut body = Vec::new();
    let mut frames = 0;
    for l in &lines[start + 1..] {
        if l.trim_start().starts_with("=====") {
            frames += 1;
            // Title frame (the line right after the title) is 1; the next
            // frame opens the following section.
            if frames > 1 {
                break;
            }
            continue;
        }
        body.push(*l);
    }
    Some(body.join("\n"))
}

/// Deep-check results from an EXPC TXT evidence file: the step's
/// `Result: <STATUS> — <detail>` line (EXPC classification), else the
/// skip marker, else the step's key output classified conservatively.
pub fn from_expc_txt(bytes: &[u8]) -> Vec<DeepCheckOutcome> {
    let text = String::from_utf8_lossy(strip_bom(bytes)).replace('\r', "");
    let mut out = Vec::new();
    for check in DeepCheck::ALL {
        let Some(section) = txt_section(&text, check) else {
            continue;
        };
        let result_line = section
            .lines()
            .map(str::trim)
            .find(|l| l.starts_with("Result:"));
        if let Some(line) = result_line {
            let rest = line.trim_start_matches("Result:").trim();
            let (status, detail) = match rest.split_once('—') {
                Some((s, d)) => (s.trim(), d.trim()),
                None => (rest, ""),
            };
            // "ERROR/UNKNOWN" (SFC with a non-zero exit code) is an error.
            let status = status.split('/').next().unwrap_or(status);
            out.push(DeepCheckOutcome {
                check,
                result: CheckResult::from_status(status),
                detail: detail.to_string(),
                source: ResultSource::ExpcTxtResult,
            });
            continue;
        }
        // Not selected ("ПРОПУЩЕНО:") or no admin rights ("ПРОПУСК:").
        if let Some(skip) = section
            .lines()
            .map(str::trim)
            .find(|l| l.starts_with("ПРОПУЩЕНО:") || l.starts_with("ПРОПУСК:"))
        {
            let detail = skip.split_once(':').map(|x| x.1).unwrap_or("").trim();
            out.push(DeepCheckOutcome {
                check,
                result: CheckResult::Skipped,
                detail: detail.to_string(),
                source: ResultSource::ExpcTxtResult,
            });
            continue;
        }
        // The step itself threw (EXPC "ОШИБКА ШАГА:"): execution failure.
        if let Some(err) = section
            .lines()
            .map(str::trim)
            .find(|l| l.starts_with("ОШИБКА ШАГА:"))
        {
            out.push(DeepCheckOutcome {
                check,
                result: CheckResult::Error,
                detail: err.trim_start_matches("ОШИБКА ШАГА:").trim().to_string(),
                source: ResultSource::ExpcTxtResult,
            });
            continue;
        }
        let exit_code = section.lines().find_map(|l| {
            l.trim()
                .strip_prefix("ExitCode:")
                .and_then(|v| v.trim().parse::<i32>().ok())
        });
        let result = classify_output(check, &section, exit_code);
        if result != CheckResult::Unknown || exit_code.is_some() {
            out.push(DeepCheckOutcome {
                check,
                result,
                detail: String::new(),
                source: ResultSource::ExpcTxtOutput,
            });
        }
    }
    out
}

/// Best available result per check from one run's EXPC evidence: the JSON
/// wins, the TXT fills in checks the JSON does not have.
pub fn from_expc_evidence(json: Option<&[u8]>, txt: Option<&[u8]>) -> Vec<DeepCheckOutcome> {
    let mut out = json.map(from_expc_json).unwrap_or_default();
    for o in txt.map(from_expc_txt).unwrap_or_default() {
        if !out.iter().any(|x| x.check == o.check) {
            out.push(o);
        }
    }
    out.sort_by_key(|o| o.check);
    out
}

/// Deep-check results of one EXPC run and the evidence they came from.
#[derive(Clone, Debug, PartialEq)]
pub struct ExpcRunChecks {
    /// Evidence file name (never a path).
    pub source_file: String,
    /// `GeneratedAt` of the EXPC JSON, when available.
    pub generated_at: Option<String>,
    pub outcomes: Vec<DeepCheckOutcome>,
}

/// Deep-check results of the newest EXPC run among `files` (name, bytes):
/// the newest completed `EXPC_*.json` and its `.txt` of the same stem.
pub fn from_evidence_files<'a>(
    files: impl IntoIterator<Item = (&'a str, &'a [u8])>,
) -> Option<ExpcRunChecks> {
    let files: Vec<(&str, &[u8])> = files.into_iter().collect();
    let is_run = |n: &str| n.starts_with("EXPC_") && !n.contains("USER_CANCELLED");
    let mut jsons: Vec<&(&str, &[u8])> = files
        .iter()
        .filter(|(n, _)| is_run(n) && n.to_ascii_lowercase().ends_with(".json"))
        .collect();
    jsons.sort_by(|a, b| {
        expc_json_generated_at(a.1)
            .cmp(&expc_json_generated_at(b.1))
            .then(a.0.cmp(b.0))
    });
    if let Some((name, bytes)) = jsons.last() {
        let stem = &name[..name.len() - 5];
        let txt = files
            .iter()
            .find(|(n, _)| n.len() == stem.len() + 4 && n.starts_with(stem) && n.ends_with(".txt"))
            .map(|(_, b)| *b);
        return Some(ExpcRunChecks {
            source_file: name.to_string(),
            generated_at: expc_json_generated_at(bytes),
            outcomes: from_expc_evidence(Some(bytes), txt),
        });
    }
    // No JSON (unusual): the newest TXT by name.
    let mut txts: Vec<&(&str, &[u8])> = files
        .iter()
        .filter(|(n, _)| is_run(n) && n.to_ascii_lowercase().ends_with(".txt"))
        .collect();
    txts.sort_by(|a, b| a.0.cmp(b.0));
    txts.last().map(|(name, b)| ExpcRunChecks {
        source_file: name.to_string(),
        generated_at: None,
        outcomes: from_expc_evidence(None, Some(b)),
    })
}

// ---------------------------------------------------------------------
// Minimal JSON (parse for evidence; string escaping for the manifest)
// ---------------------------------------------------------------------

pub mod json {
    /// JSON string literal (with quotes), escaping per RFC 8259.
    pub fn string(s: &str) -> String {
        let mut out = String::with_capacity(s.len() + 2);
        out.push('"');
        for c in s.chars() {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                c if (c as u32) < 0x20 => {
                    let _ =
                        std::fmt::Write::write_fmt(&mut out, format_args!("\\u{:04x}", c as u32));
                }
                c => out.push(c),
            }
        }
        out.push('"');
        out
    }

    #[derive(Clone, Debug, PartialEq)]
    pub enum Value {
        Null,
        Bool(bool),
        Num(f64),
        Str(String),
        Arr(Vec<Value>),
        Obj(Vec<(String, Value)>),
    }

    impl Value {
        pub fn get(&self, key: &str) -> Option<&Value> {
            match self {
                Value::Obj(fields) => fields.iter().find(|(k, _)| k == key).map(|(_, v)| v),
                _ => None,
            }
        }
        pub fn as_str(&self) -> Option<&str> {
            match self {
                Value::Str(s) => Some(s),
                _ => None,
            }
        }
        #[cfg(test)]
        pub fn as_arr(&self) -> Option<&[Value]> {
            match self {
                Value::Arr(a) => Some(a),
                _ => None,
            }
        }
    }

    /// Parses one complete JSON document (trailing whitespace allowed).
    pub fn parse(text: &str) -> Option<Value> {
        let mut p = Parser {
            s: text.as_bytes(),
            i: 0,
            depth: 0,
        };
        let v = p.value()?;
        p.ws();
        (p.i == p.s.len()).then_some(v)
    }

    struct Parser<'a> {
        s: &'a [u8],
        i: usize,
        depth: usize,
    }

    impl Parser<'_> {
        fn ws(&mut self) {
            while self.i < self.s.len() && matches!(self.s[self.i], b' ' | b'\t' | b'\r' | b'\n') {
                self.i += 1;
            }
        }
        fn eat(&mut self, b: u8) -> Option<()> {
            self.ws();
            (self.s.get(self.i) == Some(&b)).then(|| self.i += 1)
        }
        fn lit(&mut self, word: &str, v: Value) -> Option<Value> {
            self.s[self.i..].starts_with(word.as_bytes()).then(|| {
                self.i += word.len();
                v
            })
        }
        fn value(&mut self) -> Option<Value> {
            self.depth += 1;
            if self.depth > 64 {
                return None;
            }
            self.ws();
            let v = match *self.s.get(self.i)? {
                b'{' => {
                    self.i += 1;
                    let mut fields = Vec::new();
                    if self.eat(b'}').is_none() {
                        loop {
                            self.ws();
                            let k = self.string()?;
                            self.eat(b':')?;
                            let v = self.value()?;
                            fields.push((k, v));
                            if self.eat(b',').is_some() {
                                continue;
                            }
                            self.eat(b'}')?;
                            break;
                        }
                    }
                    Value::Obj(fields)
                }
                b'[' => {
                    self.i += 1;
                    let mut items = Vec::new();
                    if self.eat(b']').is_none() {
                        loop {
                            items.push(self.value()?);
                            if self.eat(b',').is_some() {
                                continue;
                            }
                            self.eat(b']')?;
                            break;
                        }
                    }
                    Value::Arr(items)
                }
                b'"' => Value::Str(self.string()?),
                b't' => self.lit("true", Value::Bool(true))?,
                b'f' => self.lit("false", Value::Bool(false))?,
                b'n' => self.lit("null", Value::Null)?,
                _ => {
                    let start = self.i;
                    while self.i < self.s.len()
                        && matches!(
                            self.s[self.i],
                            b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9'
                        )
                    {
                        self.i += 1;
                    }
                    let t = std::str::from_utf8(&self.s[start..self.i]).ok()?;
                    Value::Num(t.parse().ok()?)
                }
            };
            self.depth -= 1;
            Some(v)
        }
        fn hex4(&mut self) -> Option<u32> {
            let h = std::str::from_utf8(self.s.get(self.i..self.i + 4)?).ok()?;
            self.i += 4;
            u32::from_str_radix(h, 16).ok()
        }
        fn string(&mut self) -> Option<String> {
            if self.s.get(self.i) != Some(&b'"') {
                return None;
            }
            self.i += 1;
            let mut out: Vec<u8> = Vec::new();
            loop {
                let b = *self.s.get(self.i)?;
                self.i += 1;
                match b {
                    b'"' => break,
                    b'\\' => {
                        let e = *self.s.get(self.i)?;
                        self.i += 1;
                        let c = match e {
                            b'"' => '"',
                            b'\\' => '\\',
                            b'/' => '/',
                            b'b' => '\u{8}',
                            b'f' => '\u{c}',
                            b'n' => '\n',
                            b'r' => '\r',
                            b't' => '\t',
                            b'u' => {
                                let hi = self.hex4()?;
                                let cp = if (0xD800..0xDC00).contains(&hi) {
                                    if self.s.get(self.i..self.i + 2) != Some(b"\\u") {
                                        return None;
                                    }
                                    self.i += 2;
                                    let lo = self.hex4()?;
                                    if !(0xDC00..0xE000).contains(&lo) {
                                        return None;
                                    }
                                    0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                                } else {
                                    hi
                                };
                                char::from_u32(cp)?
                            }
                            _ => return None,
                        };
                        let mut buf = [0u8; 4];
                        out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
                    }
                    b if b < 0x20 => return None,
                    b => out.push(b),
                }
            }
            String::from_utf8(out).ok()
        }
    }
}

/// Localized one-line explanation of an outcome (`findings` is the
/// `[sfc, dism, chkdsk] × [ok, attention, error, unknown, skipped]` table
/// of the UI language). The raw evidence detail is not appended, so the
/// line stays in one language.
pub fn describe(outcome: &DeepCheckOutcome, findings: &[[&str; 5]; 3]) -> String {
    findings[outcome.check as usize][outcome.result.index()].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Representative tool output (Windows, EN / RU) ----

    const SFC_OK_EN: &str = "Beginning system scan.  This process will take some time.\r\n\r\nBeginning verification phase of system scan.\r\nVerification 100% complete.\r\n\r\nWindows Resource Protection did not find any integrity violations.\r\n";
    const SFC_OK_RU: &str = "Начато сканирование системы. Этот процесс может занять некоторое время.\r\nПроверка 100% завершена.\r\nЗащита ресурсов Windows не обнаружила нарушений целостности.\r\n";
    const SFC_BAD_EN: &str = "Verification 100% complete.\r\n\r\nWindows Resource Protection found integrity violations. For online repairs, details are included in the CBS log file located at windir\\Logs\\CBS\\CBS.log.\r\n";
    const SFC_BAD_RU: &str =
        "Проверка 100% завершена.\r\nЗащита ресурсов Windows обнаружила нарушения целостности.\r\n";
    const SFC_FAIL_EN: &str =
        "Windows Resource Protection could not perform the requested operation.\r\n";
    const DISM_OK: &str = "Deployment Image Servicing and Management tool\r\nVersion: 10.0.26100.1\r\n\r\nImage Version: 10.0.26200.7462\r\n\r\n[==========================100.0%==========================] No component store corruption detected.\r\nThe operation completed successfully.\r\n";
    const DISM_REPAIRABLE: &str = "Deployment Image Servicing and Management tool\r\nVersion: 10.0.26100.1\r\n\r\nImage Version: 10.0.26200.7462\r\n\r\n[==========================100.0%==========================] The component store is repairable.\r\nThe operation completed successfully.\r\n";
    const DISM_ERROR: &str = "Deployment Image Servicing and Management tool\r\nVersion: 10.0.26100.1\r\n\r\nError: 87\r\n\r\nThe scanhealth option is unknown.\r\n";
    const DISM_NOT_REPAIRABLE: &str = "[==========================100.0%==========================]\r\nThe component store cannot be repaired.\r\n";
    const CHKDSK_OK_EN: &str = "The type of the file system is NTFS.\r\nStage 1: Examining basic file system structure ...\r\n\r\nWindows has scanned the file system and found no problems.\r\nNo further action is required.\r\n";
    const CHKDSK_OK_RU: &str = "Тип файловой системы: NTFS.\r\nWindows проверила файловую систему и не обнаружила проблем.\r\nДальнейшие действия не требуются.\r\n";
    const CHKDSK_BAD_EN: &str = "Stage 3: Examining security descriptors ...\r\nWindows has found problems that must be fixed offline.\r\nPlease run \"chkdsk /spotfix\" to fix the issues.\r\nWindows found errors on the disk, but will not fix them\r\n";
    const CHKDSK_BAD_RU: &str = "Этап 3: проверка дескрипторов безопасности...\r\nВ файловой системе обнаружены ошибки.\r\n";
    const CHKDSK_FAIL_EN: &str = "Cannot open volume for direct access.\r\n";

    #[test]
    fn sfc_ok_is_ok() {
        assert_eq!(
            classify_output(DeepCheck::Sfc, SFC_OK_EN, Some(0)),
            CheckResult::Ok
        );
        assert_eq!(
            classify_output(DeepCheck::Sfc, SFC_OK_RU, None),
            CheckResult::Ok
        );
    }

    #[test]
    fn sfc_integrity_violations_are_attention() {
        assert_eq!(
            classify_output(DeepCheck::Sfc, SFC_BAD_EN, Some(0)),
            CheckResult::Attention
        );
        assert_eq!(
            classify_output(DeepCheck::Sfc, SFC_BAD_RU, None),
            CheckResult::Attention
        );
    }

    #[test]
    fn sfc_that_could_not_run_is_error() {
        assert_eq!(
            classify_output(DeepCheck::Sfc, SFC_FAIL_EN, Some(1)),
            CheckResult::Error
        );
        // A failed process without any result sentence.
        assert_eq!(
            classify_output(DeepCheck::Sfc, "", Some(2)),
            CheckResult::Error
        );
    }

    #[test]
    fn dism_healthy_is_ok() {
        assert_eq!(
            classify_output(DeepCheck::Dism, DISM_OK, Some(0)),
            CheckResult::Ok
        );
    }

    #[test]
    fn dism_repairable_component_store_is_attention_not_just_completed() {
        // The observed field case: the scan COMPLETED successfully (exit 0,
        // "The operation completed successfully.") and still found a problem.
        assert_eq!(
            classify_output(DeepCheck::Dism, DISM_REPAIRABLE, Some(0)),
            CheckResult::Attention
        );
    }

    #[test]
    fn dism_failures_are_error() {
        assert_eq!(
            classify_output(DeepCheck::Dism, DISM_ERROR, Some(87)),
            CheckResult::Error
        );
        assert_eq!(
            classify_output(DeepCheck::Dism, DISM_NOT_REPAIRABLE, Some(0)),
            CheckResult::Error
        );
    }

    #[test]
    fn chkdsk_clean_scan_is_ok() {
        assert_eq!(
            classify_output(DeepCheck::Chkdsk, CHKDSK_OK_EN, Some(0)),
            CheckResult::Ok
        );
        assert_eq!(
            classify_output(DeepCheck::Chkdsk, CHKDSK_OK_RU, None),
            CheckResult::Ok
        );
    }

    #[test]
    fn chkdsk_file_system_findings_are_attention() {
        assert_eq!(
            classify_output(DeepCheck::Chkdsk, CHKDSK_BAD_EN, Some(3)),
            CheckResult::Attention
        );
        assert_eq!(
            classify_output(DeepCheck::Chkdsk, CHKDSK_BAD_RU, None),
            CheckResult::Attention
        );
    }

    #[test]
    fn chkdsk_that_could_not_run_is_error() {
        assert_eq!(
            classify_output(DeepCheck::Chkdsk, CHKDSK_FAIL_EN, Some(3)),
            CheckResult::Error
        );
    }

    #[test]
    fn ambiguous_output_is_unknown_never_an_inferred_fault() {
        for check in DeepCheck::ALL {
            assert_eq!(
                classify_output(check, "Verification 100% complete.", Some(0)),
                CheckResult::Unknown,
                "{check:?}"
            );
        }
        // CHKDSK: a non-zero exit code alone is not a failure.
        assert_eq!(
            classify_output(DeepCheck::Chkdsk, "Stage 1 ...", Some(2)),
            CheckResult::Unknown
        );
    }

    /// EXPC JSON as Windows PowerShell 5.1 `ConvertTo-Json -Depth 8` writes
    /// it (BOM, PS 5.1 indentation, `\u0027`-style escapes, Cyrillic).
    fn ps51_json() -> Vec<u8> {
        let text = "{\r\n    \"Tool\":  \"EXPC Diagnostic\",\r\n    \"GeneratedAt\":  \"2026-09-28T10:35:12.1234567+03:00\",\r\n    \"ReadOnly\":  true,\r\n    \"Checks\":  [\r\n                   {\r\n                       \"Check\":  \"Defender\",\r\n                       \"Status\":  \"OK\",\r\n                       \"Detail\":  \"Microsoft Defender: включено — Antivirus\"\r\n                   },\r\n                   {\r\n                       \"Check\":  \"SFC\",\r\n                       \"Status\":  \"OK\",\r\n                       \"Detail\":  \"Признаков нарушений целостности по текущему запуску не обнаружено.\"\r\n                   },\r\n                   {\r\n                       \"Check\":  \"DISM\",\r\n                       \"Status\":  \"ATTENTION\",\r\n                       \"Detail\":  \"DISM сообщает: хранилище компонентов повреждено, но подлежит восстановлению.\"\r\n                   },\r\n                   {\r\n                       \"Check\":  \"CHKDSK\",\r\n                       \"Status\":  \"ERROR\",\r\n                       \"Detail\":  \"Don\\u0027t \\u003cknow\\u003e \\ud83d\\ude00\"\r\n                   }\r\n               ],\r\n    \"TxtPath\":  \"C:\\\\Users\\\\u\\\\AppData\\\\Local\\\\Temp\\\\x.txt\"\r\n}";
        let mut b = vec![0xEF, 0xBB, 0xBF];
        b.extend_from_slice(text.as_bytes());
        b
    }

    #[test]
    fn expc_json_from_powershell_51_is_read_structurally() {
        let out = from_expc_json(&ps51_json());
        assert_eq!(out.len(), 3, "{out:?}");
        assert_eq!(out[0].check, DeepCheck::Sfc);
        assert_eq!(out[0].result, CheckResult::Ok);
        assert_eq!(out[1].check, DeepCheck::Dism);
        assert_eq!(out[1].result, CheckResult::Attention);
        assert!(out[1].detail.contains("подлежит восстановлению"));
        assert_eq!(out[2].result, CheckResult::Error);
        assert_eq!(out[2].detail, "Don't <know> 😀");
        assert!(out.iter().all(|o| o.source == ResultSource::ExpcJson));
        assert_eq!(
            expc_json_generated_at(&ps51_json()).as_deref(),
            Some("2026-09-28T10:35:12.1234567+03:00")
        );
        // Unusable evidence yields nothing (never a guessed result).
        assert!(from_expc_json(b"{\"Checks\": [").is_empty());
        assert!(from_expc_json(b"not json").is_empty());
        // A single check serialized as an object (PS unrolled array).
        let one = from_expc_json(
            "{\"Checks\": {\"Check\": \"DISM\", \"Status\": \"OK\", \"Detail\": \"\"}}".as_bytes(),
        );
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].result, CheckResult::Ok);
    }

    fn txt() -> Vec<u8> {
        let text = "\u{feff}\r\n=====\r\n[10] Антивирус и состояние Microsoft Defender\r\n=====\r\nResult: OK — ignore me\r\n\r\n=====\r\n[11] SFC — проверка целостности системных файлов (/verifyonly)\r\n=====\r\nКоманда: sfc.exe /verifyonly\r\nExitCode: 5\r\nResult: ERROR/UNKNOWN — SFC завершился с ExitCode 5; итоговая строка не распознана.\r\n\r\n=====\r\n[12] DISM — диагностика хранилища компонентов (/ScanHealth)\r\n=====\r\nExitCode: 0\r\n\r\nКлючевые строки DISM:\r\nThe component store is repairable.\r\nThe operation completed successfully.\r\n\r\n=====\r\n[13] CHKDSK — онлайн-проверка C: (/scan)\r\n=====\r\nПРОПУЩЕНО: глубокая проверка не выбрана / выбран основной режим.\r\n\r\n=====\r\n[14] BIOS\r\n=====\r\nResult: ATTENTION — not a deep check\r\n";
        text.as_bytes().to_vec()
    }

    #[test]
    fn expc_txt_result_lines_skip_markers_and_key_output() {
        let out = from_expc_txt(&txt());
        assert_eq!(out.len(), 3, "{out:?}");
        let sfc = out.iter().find(|o| o.check == DeepCheck::Sfc).unwrap();
        assert_eq!(sfc.result, CheckResult::Error);
        assert_eq!(sfc.source, ResultSource::ExpcTxtResult);
        let dism = out.iter().find(|o| o.check == DeepCheck::Dism).unwrap();
        assert_eq!(dism.result, CheckResult::Attention);
        assert_eq!(dism.source, ResultSource::ExpcTxtOutput);
        let chk = out.iter().find(|o| o.check == DeepCheck::Chkdsk).unwrap();
        assert_eq!(chk.result, CheckResult::Skipped);
    }

    #[test]
    fn json_wins_and_txt_fills_the_gaps_for_the_newest_run() {
        let json_only_sfc = "{\"GeneratedAt\": \"2026-09-28T11:00:00\", \"Checks\": [{\"Check\": \"SFC\", \"Status\": \"OK\", \"Detail\": \"ok\"}]}";
        let old_json = "{\"GeneratedAt\": \"2026-09-28T09:00:00\", \"Checks\": [{\"Check\": \"SFC\", \"Status\": \"ERROR\", \"Detail\": \"old\"}]}";
        let t = txt();
        let files: Vec<(&str, &[u8])> = vec![
            ("EXPC_Diagnostic_28.09.26_09-00.json", old_json.as_bytes()),
            (
                "EXPC_Diagnostic_28.09.26_11-00.json",
                json_only_sfc.as_bytes(),
            ),
            ("EXPC_Diagnostic_28.09.26_11-00.txt", &t),
            ("EXPC_Diagnostic_USER_CANCELLED_28.09.26_12-00-00.txt", b"x"),
            ("Hardware_28.09.26_10-00.json", b"{}"),
        ];
        let run = from_evidence_files(files).unwrap();
        assert_eq!(run.source_file, "EXPC_Diagnostic_28.09.26_11-00.json");
        assert_eq!(run.generated_at.as_deref(), Some("2026-09-28T11:00:00"));
        let r: Vec<(DeepCheck, CheckResult)> =
            run.outcomes.iter().map(|o| (o.check, o.result)).collect();
        assert_eq!(
            r,
            vec![
                (DeepCheck::Sfc, CheckResult::Ok),
                (DeepCheck::Dism, CheckResult::Attention),
                (DeepCheck::Chkdsk, CheckResult::Skipped),
            ]
        );
        assert!(from_evidence_files(Vec::<(&str, &[u8])>::new()).is_none());
    }

    #[test]
    fn json_parser_handles_the_rfc_basics() {
        let v =
            json::parse(" {\"a\": [1, -2.5e1, true, false, null, \"x\\ny\"], \"b\": {}} ").unwrap();
        assert_eq!(v.get("a").unwrap().as_arr().unwrap().len(), 6);
        assert_eq!(v.get("b"), Some(&json::Value::Obj(vec![])));
        assert!(json::parse("{} x").is_none());
        assert!(json::parse("{\"a\" 1}").is_none());
        assert!(json::parse("\"\\ud83d\"").is_none());
        let s = "q\"b\\s\n\t\u{1}ж";
        assert_eq!(
            json::parse(&json::string(s)),
            Some(json::Value::Str(s.to_string()))
        );
    }

    #[test]
    fn localized_explanations_and_manual_commands() {
        let o = DeepCheckOutcome {
            check: DeepCheck::Dism,
            result: CheckResult::Attention,
            detail: "raw".into(),
            source: ResultSource::ExpcJson,
        };
        assert_eq!(
            describe(&o, &crate::i18n::RU.deep_check_findings),
            "DISM: хранилище компонентов Windows требует восстановления."
        );
        assert_eq!(
            describe(&o, &crate::i18n::EN.deep_check_findings),
            "DISM: the Windows component store is repairable."
        );
        assert_eq!(
            DeepCheck::Dism.manual_command("C:"),
            "DISM /Online /Cleanup-Image /RestoreHealth"
        );
        assert_eq!(DeepCheck::Sfc.manual_command("C:"), "sfc /scannow");
        assert_eq!(DeepCheck::Chkdsk.manual_command("D:"), "chkdsk D: /f");
        for d in [&crate::i18n::RU, &crate::i18n::EN] {
            for (i, check) in DeepCheck::ALL.iter().enumerate() {
                for text in d.deep_check_findings[i] {
                    assert!(text.starts_with(&format!("{}:", check.key())), "{text}");
                }
            }
        }
    }

    /// The JSON Windows PowerShell itself writes (ConvertTo-Json through a
    /// UTF-8-BOM StreamWriter, as EXPC-Diagnostic.ps1 does) is parsed.
    /// Runs `powershell.exe` (5.1) on Windows; elsewhere `WSD_PWSH`/`pwsh`.
    #[test]
    fn json_written_by_powershell_is_parsed() {
        let host = if cfg!(windows) {
            Some("powershell.exe".to_string())
        } else {
            std::env::var("WSD_PWSH").ok().or_else(|| {
                std::process::Command::new("pwsh")
                    .args(["-NoProfile", "-Command", "exit 0"])
                    .output()
                    .ok()
                    .filter(|o| o.status.success())
                    .map(|_| "pwsh".into())
            })
        };
        let Some(host) = host else {
            eprintln!("no PowerShell host: execution skipped");
            return;
        };
        let dir = std::env::temp_dir().join(format!("wsd-deepjson-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let out = dir.join("expc.json");
        let script = format!(
            "$checks = [ordered]@{{}}\r\n\
             $checks['SFC'] = [PSCustomObject]@{{ Check = 'SFC'; Status = 'OK'; Detail = 'Признаков нет.' }}\r\n\
             $checks['DISM'] = [PSCustomObject]@{{ Check = 'DISM'; Status = 'ATTENTION'; Detail = \"DISM сообщает: 'repairable' <x> & y\" }}\r\n\
             $checks['CHKDSK'] = [PSCustomObject]@{{ Check = 'CHKDSK'; Status = 'SKIPPED'; Detail = 'Нет административных прав.' }}\r\n\
             $r = [PSCustomObject][ordered]@{{ Tool = 'EXPC Diagnostic'; GeneratedAt = (Get-Date '2026-09-28T10:00:00').ToString('o'); Checks = @($checks.GetEnumerator() | ForEach-Object {{ $_.Value }}) }}\r\n\
             $s = [IO.File]::Open('{}', [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::Read)\r\n\
             $w = New-Object IO.StreamWriter($s, (New-Object System.Text.UTF8Encoding($true)))\r\n\
             try {{ $w.Write(($r | ConvertTo-Json -Depth 8)) }} finally {{ $w.Dispose() }}\r\n",
            out.display().to_string().replace('\'', "''")
        );
        let file = dir.join("make.ps1");
        let mut bytes = vec![0xEF, 0xBB, 0xBF];
        bytes.extend_from_slice(script.as_bytes());
        std::fs::write(&file, bytes).unwrap();
        let run = std::process::Command::new(&host)
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
            ])
            .arg(&file)
            .output()
            .expect("PowerShell host runs");
        assert!(
            run.status.success(),
            "{}",
            String::from_utf8_lossy(&run.stderr)
        );
        let json = std::fs::read(&out).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        let got = from_expc_json(&json);
        let r: Vec<(DeepCheck, CheckResult)> = got.iter().map(|o| (o.check, o.result)).collect();
        assert_eq!(
            r,
            vec![
                (DeepCheck::Sfc, CheckResult::Ok),
                (DeepCheck::Dism, CheckResult::Attention),
                (DeepCheck::Chkdsk, CheckResult::Skipped),
            ]
        );
        assert_eq!(got[1].detail, "DISM сообщает: 'repairable' <x> & y");
        assert!(
            expc_json_generated_at(&json)
                .unwrap()
                .starts_with("2026-09-28T10:00:00")
        );
    }
}
