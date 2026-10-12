//! v1.0 Event Evidence aggregation (READ-ONLY `Get-WinEvent`).
//!
//! Permanent principle: EVENT COUNT ALONE DOES NOT DETERMINE SEVERITY, and
//! every counter shown anywhere must be verifiable in the ZIP. This module
//! collects the high-repeat groups that real machines showed (Schannel,
//! WindowsUpdateClient 20, TPM, Service Control Manager, SideBySide 33,
//! Code Integrity, VSS / Volsnap, application errors) and aggregates them
//! by provider + Event ID + key fields: count, first / last seen, the latest
//! messages and the parsed fields (service, HRESULT, KB, process, module,
//! assembly …). Nothing is cleared or changed.

use crate::deep_checks::json;

pub const EVIDENCE_PREFIX: &str = "Event_Evidence_";
/// Look-back window of the aggregation.
pub const WINDOW_DAYS: u32 = 30;

/// Evidence group of an aggregated event family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Group {
    Schannel,
    WindowsUpdate,
    Tpm,
    Scm,
    SideBySide,
    CodeIntegrityKernel,
    CodeIntegrityUser,
    Vss,
    AppErrors,
    Other,
}

impl Group {
    pub fn code(self) -> &'static str {
        match self {
            Group::Schannel => "schannel",
            Group::WindowsUpdate => "windows_update",
            Group::Tpm => "tpm",
            Group::Scm => "service_control_manager",
            Group::SideBySide => "sidebyside",
            Group::CodeIntegrityKernel => "code_integrity_kernel",
            Group::CodeIntegrityUser => "code_integrity_user",
            Group::Vss => "vss_volsnap",
            Group::AppErrors => "application_errors",
            Group::Other => "other",
        }
    }

    /// EXPC stage (0-based) whose Details show this group.
    pub fn stage(self) -> usize {
        match self {
            Group::Vss => 4,
            Group::AppErrors | Group::SideBySide | Group::CodeIntegrityUser => 7,
            Group::CodeIntegrityKernel => 2,
            _ => 3,
        }
    }
}

/// One raw event as read by the collector.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RawEvent {
    pub log: String,
    pub provider: String,
    pub id: u32,
    pub time: String,
    pub message: String,
    /// `<EventData>` name/value pairs (unnamed items as `param1`…).
    pub data: Vec<(String, String)>,
    /// Windows event level (1 critical, 2 error, 3 warning, 4 information,
    /// 5 verbose); 0 = not collected (older evidence).
    pub level: u8,
    /// `System/Correlation/@ActivityID` (Code Integrity 3089 links its
    /// signature details to the blocking event through it); empty = none.
    pub correlation: String,
}

impl RawEvent {
    fn field(&self, names: &[&str]) -> Option<&str> {
        names.iter().find_map(|n| {
            self.data
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(n))
                .map(|(_, v)| v.as_str())
                .filter(|v| !v.trim().is_empty())
        })
    }
}

/// Current state of a service (SCM enrichment).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServiceInfo {
    pub name: String,
    pub display_name: String,
    pub state: String,
    pub start_mode: String,
    pub path: String,
}

/// One aggregated group entry.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Aggregate {
    pub group: Option<Group>,
    pub provider: String,
    pub id: u32,
    /// Key fields that define this aggregate (service, KB, process …).
    pub key: Vec<(String, String)>,
    pub count: u32,
    /// Events of the last 7 days relative to the collection time
    /// (`collected_at`), so "N in 7 days / M in 8–30 days" summaries are
    /// verifiable and old events are never shown as fresh.
    pub count_last_7_days: u32,
    pub first_seen: String,
    pub last_seen: String,
    /// Latest messages (newest first, at most 5, truncated).
    pub latest: Vec<String>,
    /// Interpretation category (e.g. VSS "quota_eviction").
    pub category: String,
    pub service: Option<ServiceInfo>,
    /// Windows Update 20 only: `Some(true)` = a LATER successful install
    /// (Event 19) of the SAME update (GUID / KB / title) exists;
    /// `Some(false)` = none; `None` = the failure has no identity, so no
    /// claim is made that it was fixed.
    pub wu_resolved: Option<bool>,
    /// Most severe Windows level seen (1 critical … 5 verbose); 0 = the
    /// evidence carries no level.
    pub level: u8,
}

/// Key fields that are ATTRIBUTES (collected distinct values), never the
/// identity of an aggregate: SCM timeouts / error texts, Code Integrity
/// full paths and correlated signature details.
pub const ATTRIBUTE_KEYS: [&str; 6] = [
    "TimeoutMs",
    "Error",
    "ProcessPath",
    "FilePath",
    "Signature",
    "LinkedEventIds",
];

/// Separator of collected attribute values.
fn attribute_sep(k: &str) -> &'static str {
    if k == "TimeoutMs" || k == "LinkedEventIds" {
        ","
    } else {
        " | "
    }
}

/// At most this many distinct values per attribute (evidence stays short).
const MAX_ATTRIBUTE_VALUES: usize = 4;

fn group_of(e: &RawEvent) -> Group {
    let p = e.provider.to_ascii_lowercase();
    if p == "schannel" {
        Group::Schannel
    } else if p.contains("windowsupdateclient") {
        Group::WindowsUpdate
    } else if p.contains("tpm") {
        Group::Tpm
    } else if p.contains("service control manager") {
        Group::Scm
    } else if p.contains("sidebyside") {
        Group::SideBySide
    } else if p.contains("codeintegrity") {
        if ci_is_kernel(e) {
            Group::CodeIntegrityKernel
        } else {
            Group::CodeIntegrityUser
        }
    } else if p == "vss" || p == "volsnap" || p.contains("volumesnapshot") {
        Group::Vss
    } else if p == "application error"
        || p == "application hang"
        || p == ".net runtime"
        || p == "windows error reporting"
    {
        Group::AppErrors
    } else {
        Group::Other
    }
}

/// `\Device\HarddiskVolume3\Windows\System32\x.exe` → `x.exe`.
fn file_part(path: &str) -> String {
    path.trim()
        .trim_matches('"')
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or("")
        .to_string()
}

/// Full (process, file) image paths of a Code Integrity event, from
/// EventData (`ProcessNameBuffer` / `FileNameBuffer` …) or the message:
/// "a process (\…\Program Files (x86)\…\browser.exe) attempted to load
/// \…\vulkan-1.dll that did not meet …". Paths may contain spaces and
/// parentheses, so the process path ends at the ")" that is followed by
/// "attempted to load", not at the first ")".
pub fn ci_paths(e: &RawEvent) -> (String, String) {
    let clean = |s: &str| s.trim().trim_matches('"').trim_end_matches('.').to_string();
    let m = &e.message;
    let process = e
        .field(&["ProcessNameBuffer", "ProcessName", "RequestedFileName"])
        .map(clean)
        .or_else(|| {
            let a = ["process (", "процесс ("]
                .iter()
                .find_map(|k| m.find(k).map(|i| i + k.len()))?;
            let rest = &m[a..];
            let end = [") attempted", ") попытал"]
                .iter()
                .filter_map(|k| rest.find(k))
                .min()
                .or_else(|| {
                    // Unknown wording: the last ")" before the load verb.
                    let upto = rest.find(" load").unwrap_or(rest.len());
                    rest[..upto].rfind(')')
                })?;
            Some(clean(&rest[..end]))
        })
        .unwrap_or_default();
    let file = e
        .field(&["FileNameBuffer", "File Name", "FileName"])
        .map(clean)
        .or_else(|| {
            for key in [
                "attempted to load ",
                "попытался загрузить ",
                "image integrity of the file ",
                "целостность образа файла ",
            ] {
                if let Some(a) = m.find(key) {
                    let rest = &m[a + key.len()..];
                    let end = [" that ", " because", ", который", " так как", " поскольку"]
                        .iter()
                        .filter_map(|k| rest.find(k))
                        .min()
                        .unwrap_or(rest.len());
                    return Some(clean(&rest[..end]));
                }
            }
            // 3010: "unable to load the X.cat catalog".
            let key = "unable to load the ";
            let a = m.find(key)? + key.len();
            let rest = &m[a..];
            let end = rest.find(" catalog").unwrap_or(rest.len());
            Some(clean(&rest[..end]))
        })
        .unwrap_or_default();
    (process, file)
}

/// (process, module) file names of a Code Integrity event.
pub fn ci_process_module(e: &RawEvent) -> (String, String) {
    let (process, file) = ci_paths(e);
    (file_part(&process), file_part(&file))
}

/// v1.0 Code Integrity semantics by Event ID. 3089 is NOT an incident: it
/// carries the signature details of another CI event (same Correlation
/// ActivityID). 3034 is audit mode (the image was allowed to load) and
/// 3010 a catalog that could not be loaded — no image was blocked.
pub fn ci_category(id: u32) -> &'static str {
    match id {
        3089 => "ci_signature_info",
        3033 | 3063 | 3077 | 3023 => "ci_image_blocked",
        3001 | 3002 | 3004 => "ci_image_verification_failed",
        3034 => "ci_audit_only",
        3010 => "ci_catalog_not_loaded",
        _ => "ci_other",
    }
}

/// Confirmed reason text of a Code Integrity Event ID (RU, for titles).
fn ci_reason(id: u32) -> &'static str {
    match id {
        3033 => "загрузка заблокирована: образ не соответствует уровню подписи Microsoft",
        3063 => "загрузка заблокирована: требования к общим секциям",
        3077 => "загрузка заблокирована политикой WDAC",
        3023 => "загрузка заблокирована: драйвер отозван",
        3001 => "не удалось проверить подпись драйвера",
        3002 => "не найдены постраничные хеши образа",
        3004 => "хеш файла не найден в системе",
        3034 => "аудит: образ загружен (блокировки не было)",
        3010 => "каталог не загружен",
        _ => "событие Code Integrity",
    }
}

/// Signature details of a 3089 event ("Publisher=…; Issuer=…; …"); empty
/// when the event carries none.
fn ci_signature(e: &RawEvent) -> String {
    let mut parts = Vec::new();
    for (label, names) in [
        ("Publisher", &["PublisherName"][..]),
        ("Issuer", &["IssuerName"][..]),
        ("SigningLevel", &["ValidatedSigningLevel"][..]),
        ("VerificationError", &["VerificationError"][..]),
    ] {
        if let Some(v) = e.field(names) {
            parts.push(format!("{label}={}", v.trim()));
        }
    }
    parts.join("; ")
}

/// Kernel-mode Code Integrity: the image is a driver (.sys) or the loading
/// process is the System process. User-mode CI never attaches to a device.
pub fn ci_is_kernel(e: &RawEvent) -> bool {
    let (process, module) = ci_process_module(e);
    let module = module.to_ascii_lowercase();
    let process = process.to_ascii_lowercase();
    module.ends_with(".sys") || process == "system" || process == "ntoskrnl.exe"
}

/// "KB5034441" from an update title.
pub fn kb_of(text: &str) -> Option<String> {
    let up = text.to_ascii_uppercase();
    let i = up.find("KB")?;
    let digits: String = up[i + 2..]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    (digits.len() >= 6).then(|| format!("KB{digits}"))
}

/// SideBySide 33: (executable path, missing assembly + version).
pub fn sxs_fields(e: &RawEvent) -> (String, String) {
    let m = &e.message;
    let quoted_after = |key: &str| -> Option<String> {
        let a = m.find(key)? + key.len();
        let b = m[a..].find('"')? + a;
        Some(m[a..b].to_string())
    };
    let path = quoted_after("for \"")
        .or_else(|| quoted_after("для \""))
        .or_else(|| e.field(&["param1"]).map(str::to_string))
        .unwrap_or_default();
    let assembly = (|| {
        // EN: Dependent Assembly X,…,version="v" could not be found.
        // RU: Не найдена зависимая сборка "X,…,version="v"".
        let (a, quoted) = if let Some(i) = m.find("Dependent Assembly ") {
            (i + "Dependent Assembly ".len(), false)
        } else {
            let key = "зависимая сборка \"";
            (m.find(key)? + key.len(), true)
        };
        let rest = &m[a..];
        let end = if quoted {
            rest.find("\"\"").map(|i| i + 1).unwrap_or(rest.len())
        } else {
            rest.find(" could not").unwrap_or(rest.len())
        };
        let spec = rest[..end].replace("&#x2a;", "*").replace("&quot;", "\"");
        let name = spec.split(',').next().unwrap_or("").trim().to_string();
        let ver = spec
            .split(',')
            .find_map(|p| p.trim().strip_prefix("version="))
            .map(|v| v.trim_matches('"').to_string())
            .unwrap_or_default();
        Some(if ver.is_empty() || ver == name {
            name
        } else {
            format!("{name} {ver}")
        })
    })()
    .unwrap_or_default();
    (path, assembly)
}

/// v1.0 SCM service identity: (service, timeout ms) of one SCM event.
pub fn scm_service(e: &RawEvent) -> (String, String) {
    if matches!(e.id, 7009 | 7011) {
        let timeout = e.field(&["param1"]).unwrap_or("").to_string();
        let svc = e
            .field(&["param2", "ServiceName"])
            .map(str::to_string)
            .unwrap_or_default();
        (svc, timeout)
    } else {
        (
            e.field(&["param1", "ServiceName"])
                .unwrap_or("")
                .to_string(),
            String::new(),
        )
    }
}

/// v1.0 SCM failure type by Event ID (RU, for titles).
pub fn scm_failure_type(id: u32) -> &'static str {
    match id {
        7000 => "не запустилась",
        7001 => "не запустилась из-за зависимости",
        7009 | 7011 => "таймаут ответа",
        7023 | 7024 => "завершилась с ошибкой",
        7031 | 7034 => "неожиданно завершилась",
        _ => "сбой службы",
    }
}

/// Error text of an SCM message ("… due to the following error: X" /
/// "… with the following error: X"); empty when the message has none.
pub fn scm_error_text(e: &RawEvent) -> String {
    let m = &e.message;
    for key in [
        "following error:",
        "следующей ошибки:",
        "следующей ошибкой:",
        "ошибка:",
    ] {
        if let Some(i) = m.find(key) {
            let t: String = m[i + key.len()..]
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ");
            let t = t.trim().trim_end_matches('.').trim().to_string();
            if !t.is_empty() && t != "%%0" {
                return t.chars().take(160).collect();
            }
        }
    }
    String::new()
}

/// Schannel: the SSPI client process named by the message ("The SSPI
/// client process is service_update (PID: 61408).") — PIDs differ per
/// run, so only the process name is the identity.
pub fn schannel_process(e: &RawEvent) -> String {
    let m = &e.message;
    for key in [
        "SSPI client process is ",
        "клиентский процесс SSPI: ",
        "Клиентский процесс SSPI: ",
        "процесс клиента SSPI: ",
    ] {
        if let Some(i) = m.find(key) {
            let rest = &m[i + key.len()..];
            let end = rest.find(" (").unwrap_or_else(|| {
                rest.find(|c: char| c == '.' || c == '\n')
                    .unwrap_or(rest.len())
            });
            return rest[..end].trim().to_string();
        }
    }
    String::new()
}

/// Schannel internal error / alert code of one event.
pub fn schannel_code(e: &RawEvent) -> String {
    e.field(&["ErrorState", "AlertDesc", "Error"])
        .map(str::to_string)
        .or_else(|| {
            let m = &e.message;
            let key = [
                "error state is ",
                "состояние внутренней ошибки: ",
                "код ошибки: ",
            ]
            .iter()
            .find_map(|k| m.find(k).map(|i| i + k.len()))?;
            Some(
                m[key..]
                    .chars()
                    .take_while(|c| c.is_ascii_digit())
                    .collect(),
            )
        })
        .unwrap_or_default()
}

/// TPM / TPM-WMI Event IDs whose message reports SUCCESS or status
/// information (provisioned, device identifier generated, attestation
/// health check passed, provisioning check triggered, Secure Boot keys
/// updated). Their repetition is boot-time routine, never a failure.
pub const TPM_INFO_IDS: [u32; 6] = [1025, 1282, 1038, 1041, 18, 1808];

/// Is this TPM event a problem candidate? Level decides when collected
/// (1–3 = critical / error / warning); without a level, known success IDs
/// are informational and other messages must say "fail" / "error".
pub fn tpm_is_problem(e: &RawEvent) -> bool {
    match e.level {
        1..=3 => true,
        4 | 5 => false,
        _ => {
            if TPM_INFO_IDS.contains(&e.id) {
                return false;
            }
            let m = e.message.to_lowercase();
            ["fail", "error", "не удалось", "ошибк", "сбой"]
                .iter()
                .any(|k| m.contains(k))
        }
    }
}

/// A usable process / module value: not empty, not "-", one line.
fn usable(v: &str) -> Option<String> {
    let v = v.trim();
    (!v.is_empty() && v != "-" && v != "?" && !v.contains('\n') && v.len() <= 260)
        .then(|| v.to_string())
}

/// Text after `key` up to the first of `ends` (trimmed).
fn after<'a>(m: &'a str, key: &str, ends: &[&str]) -> Option<&'a str> {
    let a = m.find(key)? + key.len();
    let rest = &m[a..];
    let end = ends
        .iter()
        .filter_map(|k| rest.find(k))
        .min()
        .unwrap_or(rest.len());
    Some(rest[..end].trim())
}

/// v1.0 application identity (process, module, exception) of an
/// Application Error 1000 / Application Hang 1002 / .NET Runtime 1026 /
/// WER event: EventData first, then the message. `None` process =
/// INSUFFICIENT DATA (never "-" and never merged with other processes).
pub fn app_identity(e: &RawEvent) -> (Option<String>, String, String) {
    let m = &e.message;
    let first_line = |m: &str, keys: &[&str]| -> Option<String> {
        keys.iter().find_map(|k| {
            m.lines()
                .find_map(|l| l.trim().strip_prefix(k))
                .and_then(usable)
        })
    };
    if e.id == 1026 && e.provider.eq_ignore_ascii_case(".net runtime") {
        // .NET 1026: EventData param1 is the whole text; the process is
        // its first line "Application: X" / "Приложение: X".
        let text = e.field(&["param1"]).unwrap_or(m);
        let process = first_line(text, &["Application: ", "Приложение: "])
            .or_else(|| first_line(m, &["Application: ", "Приложение: "]));
        let exception = after(text, "Exception Info: ", &[":", "\n"])
            .filter(|s| !s.is_empty() && !s.contains(' '))
            .map(str::to_string)
            .or_else(|| {
                after(text, "код исключения ", &[",", " ", "\n"])
                    .or_else(|| after(text, "exception code ", &[",", " ", "\n"]))
                    .filter(|s| !s.is_empty())
                    .map(|c| format!("0x{}", c.trim_start_matches("0x").to_ascii_lowercase()))
            })
            .unwrap_or_default();
        return (process, String::new(), exception);
    }
    let process = e
        .field(&["param1", "AppName"])
        .and_then(usable)
        .or_else(|| {
            [
                ("Faulting application name: ", &[","][..]),
                ("Имя сбойного приложения: ", &[","][..]),
                ("The program ", &[" version"][..]),
                ("Программа ", &[" версии", " версия"][..]),
            ]
            .iter()
            .find_map(|(k, ends)| after(m, k, ends).and_then(usable))
        });
    let module = if e.id == 1000 {
        e.field(&["param4", "ModuleName"])
            .and_then(usable)
            .or_else(|| {
                ["Faulting module name: ", "Имя сбойного модуля: "]
                    .iter()
                    .find_map(|k| after(m, k, &[","]).and_then(usable))
            })
            .unwrap_or_default()
    } else {
        String::new()
    };
    // Application Error 1000: param7 = exception code.
    let exception = if e.id == 1000 {
        e.field(&["param7", "ExceptionCode"])
            .and_then(usable)
            .map(|x| {
                let x = x.trim().trim_start_matches("0x");
                format!("0x{}", x.to_ascii_lowercase())
            })
            .unwrap_or_default()
    } else {
        String::new()
    };
    (process, module, exception)
}

/// VSS / Volsnap interpretation category. Quota utilisation alone is NOT a
/// failure (it is INFO); creation failures and storage-could-not-grow
/// deletions are operational evidence.
pub fn vss_category(e: &RawEvent) -> &'static str {
    let p = e.provider.to_ascii_lowercase();
    if p == "volsnap" {
        match e.id {
            33 => "restore_point_eviction_quota",
            25 | 35 | 36 => "shadow_copies_deleted_storage",
            _ => "volsnap_other",
        }
    } else {
        match e.id {
            8193 | 8194 | 12289 | 12293 | 12298 | 13 => "vss_operation_failure",
            // VSS service shutting down after its idle timeout: normal.
            8224 => "vss_idle_shutdown",
            _ => "vss_other",
        }
    }
}

/// Key fields of one event (the aggregation identity inside its group).
fn key_of(group: Group, e: &RawEvent) -> (Vec<(String, String)>, String) {
    let kv = |k: &str, v: String| (k.to_string(), v);
    match group {
        Group::Schannel => {
            // v1.0: identity = internal error code + SSPI client process
            // (PIDs differ per run and are not part of the identity).
            let mut key = vec![kv("ErrorCode", schannel_code(e))];
            let process = schannel_process(e);
            if !process.is_empty() {
                key.push(kv("Process", process));
            }
            (key, String::new())
        }
        Group::WindowsUpdate => {
            let title = e
                .field(&["updateTitle", "UpdateTitle"])
                .unwrap_or("")
                .to_string();
            let code = e
                .field(&["errorCode", "ErrorCode", "hr"])
                .unwrap_or("")
                .to_string();
            (
                vec![
                    kv("KB", kb_of(&title).unwrap_or_default()),
                    kv("HRESULT", code),
                    kv("Title", title),
                ],
                if e.id == 20 {
                    "install_failure".into()
                } else {
                    String::new()
                },
            )
        }
        Group::Scm => {
            // v1.0: 7009 / 7011 carry the TIMEOUT in param1 and the service in
            // param2 — the timeout is an attribute, never the identity.
            let (svc, timeout) = scm_service(e);
            let mut key = vec![kv("Service", svc)];
            if !timeout.is_empty() {
                key.push(kv("TimeoutMs", timeout));
            }
            let error = scm_error_text(e);
            if !error.is_empty() {
                key.push(kv("Error", error));
            }
            (key, String::new())
        }
        Group::SideBySide => {
            let (path, asm) = sxs_fields(e);
            // Temp folders differ per run (sdwra_<pid>_<n>): aggregate by
            // the executable file name; full paths stay in the messages.
            (
                vec![kv("Executable", file_part(&path)), kv("Assembly", asm)],
                String::new(),
            )
        }
        Group::CodeIntegrityKernel | Group::CodeIntegrityUser => {
            let (process_path, file_path) = ci_paths(e);
            let mut key = vec![
                kv("Process", file_part(&process_path)),
                kv("Module", file_part(&file_path)),
            ];
            // Full paths are attributes (evidence), not the identity.
            if !process_path.is_empty() {
                key.push(kv("ProcessPath", process_path));
            }
            if !file_path.is_empty() {
                key.push(kv("FilePath", file_path));
            }
            (key, ci_category(e.id).to_string())
        }
        Group::Vss => (Vec::new(), vss_category(e).to_string()),
        Group::AppErrors => {
            let (process, module, exception) = app_identity(e);
            let mut key = vec![
                kv("Process", process.clone().unwrap_or_default()),
                kv("Module", module),
                kv("Exception", exception),
            ];
            if process.is_none() {
                // INSUFFICIENT DATA: unidentified events are never merged
                // across different messages (= possibly different
                // processes); the message head is the identity.
                let head: String = e
                    .message
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ")
                    .chars()
                    .take(160)
                    .collect();
                key.push(kv("MessageHead", head));
            }
            (
                key,
                if process.is_none() {
                    "insufficient_data".into()
                } else {
                    String::new()
                },
            )
        }
        Group::Tpm => (
            Vec::new(),
            if tpm_is_problem(e) {
                "tpm_problem".into()
            } else {
                "tpm_informational".into()
            },
        ),
        Group::Other => (Vec::new(), String::new()),
    }
}

/// Day number of an ISO `YYYY-MM-DD…` timestamp (civil → days).
fn day_number(iso: &str) -> Option<i64> {
    let mut it = iso
        .split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty());
    let y: i64 = it.next()?.parse().ok()?;
    let m: i64 = it.next()?.parse().ok()?;
    let d: i64 = it.next()?.parse().ok()?;
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe)
}

fn is_wu(e: &RawEvent, id: u32) -> bool {
    e.id == id
        && e.provider
            .to_ascii_lowercase()
            .contains("windowsupdateclient")
}

/// Confirmed identity of one Windows Update event: update GUID, KB and
/// title (each normalised; empty when absent).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WuIdentity {
    pub guid: String,
    pub kb: String,
    pub title: String,
}

pub fn wu_identity(e: &RawEvent) -> WuIdentity {
    let guid = e
        .field(&["updateGuid", "UpdateGuid"])
        .map(|g| g.trim().trim_matches(['{', '}']).to_ascii_lowercase())
        .unwrap_or_default();
    let title = e
        .field(&["updateTitle", "UpdateTitle"])
        .map(|t| t.split_whitespace().collect::<Vec<_>>().join(" "))
        .unwrap_or_default();
    let kb = kb_of(&title)
        .or_else(|| kb_of(&e.message))
        .unwrap_or_default();
    WuIdentity {
        guid,
        kb,
        title: title.to_lowercase(),
    }
}

impl WuIdentity {
    pub fn is_known(&self) -> bool {
        !(self.guid.is_empty() && self.kb.is_empty() && self.title.is_empty())
    }

    /// Same update? Decided by the strongest identity BOTH sides carry
    /// (GUID, then KB, then exact title); otherwise not the same.
    pub fn same_update(&self, other: &WuIdentity) -> bool {
        if !self.guid.is_empty() && !other.guid.is_empty() {
            self.guid == other.guid
        } else if !self.kb.is_empty() && !other.kb.is_empty() {
            self.kb == other.kb
        } else if !self.title.is_empty() && !other.title.is_empty() {
            self.title == other.title
        } else {
            false
        }
    }
}

/// Is the Windows Update failure `fail` (Event 20) resolved by a LATER
/// successful install (Event 19) of the same update? `None` when the
/// failure carries no identity (nothing can be claimed).
pub fn wu_failure_resolved(fail: &RawEvent, events: &[RawEvent]) -> Option<bool> {
    let id = wu_identity(fail);
    if !id.is_known() {
        return None;
    }
    Some(
        events
            .iter()
            .filter(|e| is_wu(e, 19) && e.time > fail.time)
            .any(|ok| id.same_update(&wu_identity(ok))),
    )
}

/// Aggregates raw events (any order) by group + provider + id + key.
/// `collected_at` (ISO local time of the collection) is the reference of
/// the 7-day counters; when it cannot be parsed no event counts as recent.
pub fn aggregate(
    events: &[RawEvent],
    services: &[ServiceInfo],
    collected_at: &str,
) -> Vec<Aggregate> {
    let reference_day = day_number(collected_at);
    let is_ci = |e: &RawEvent| e.provider.to_ascii_lowercase().contains("codeintegrity");
    // Code Integrity 3089 → signature details by Correlation ActivityID,
    // and the IDs of the blocking events each correlation belongs to.
    let mut signatures: Vec<(&str, String)> = Vec::new();
    let mut primaries: Vec<(&str, u32)> = Vec::new();
    for e in events
        .iter()
        .filter(|e| is_ci(e) && !e.correlation.is_empty())
    {
        if e.id == 3089 {
            let sig = ci_signature(e);
            if !sig.is_empty() && !signatures.iter().any(|(c, _)| *c == e.correlation) {
                signatures.push((e.correlation.as_str(), sig));
            }
        } else {
            primaries.push((e.correlation.as_str(), e.id));
        }
    }
    let mut out: Vec<Aggregate> = Vec::new();
    let mut sorted: Vec<&RawEvent> = events.iter().collect();
    // Newest first, so "latest" messages and last_seen come first.
    sorted.sort_by(|a, b| b.time.cmp(&a.time));
    for e in sorted {
        // Successful Windows Update installs (19) are not evidence of a
        // problem: they only decide whether a failure (20) is historical
        // (`wu_failure_is_historical`), never an aggregate of their own.
        if is_wu(e, 19) {
            continue;
        }
        let group = group_of(e);
        let (mut key, category) = key_of(group, e);
        if is_ci(e) && !e.correlation.is_empty() {
            if e.id == 3089 {
                if let Some((_, id)) = primaries.iter().find(|(c, _)| *c == e.correlation) {
                    key.push(("LinkedEventIds".into(), id.to_string()));
                }
            } else if let Some((_, sig)) = signatures.iter().find(|(c, _)| *c == e.correlation) {
                key.push(("Signature".into(), sig.clone()));
            }
        }
        // Identity = key without attribute fields (SCM timeout values,
        // error texts, full paths, signatures).
        let ident = |k: &[(String, String)]| -> Vec<(String, String)> {
            k.iter()
                .filter(|(n, _)| !ATTRIBUTE_KEYS.contains(&n.as_str()))
                .cloned()
                .collect()
        };
        let at = out.iter().position(|a| {
            a.group == Some(group)
                && a.provider.eq_ignore_ascii_case(&e.provider)
                && a.id == e.id
                && ident(&a.key) == ident(&key)
        });
        let a = match at {
            Some(i) => &mut out[i],
            None => {
                let service = (group == Group::Scm)
                    .then(|| {
                        let wanted = key.first().map(|(_, v)| v.as_str()).unwrap_or("");
                        services
                            .iter()
                            .find(|s| {
                                s.display_name.eq_ignore_ascii_case(wanted)
                                    || s.name.eq_ignore_ascii_case(wanted)
                            })
                            .cloned()
                    })
                    .flatten();
                out.push(Aggregate {
                    group: Some(group),
                    provider: e.provider.clone(),
                    id: e.id,
                    key: key.clone(),
                    count: 0,
                    count_last_7_days: 0,
                    first_seen: e.time.clone(),
                    last_seen: e.time.clone(),
                    latest: Vec::new(),
                    category,
                    service,
                    // Newest-first: the first event is the newest failure
                    // of this aggregate (same KB / title by key).
                    wu_resolved: if is_wu(e, 20) {
                        wu_failure_resolved(e, events)
                    } else {
                        None
                    },
                    level: 0,
                });
                let a = out.last_mut().unwrap();
                // Attributes are (re)collected below, distinct values only.
                a.key.retain(|(k, _)| !ATTRIBUTE_KEYS.contains(&k.as_str()));
                a
            }
        };
        // Attribute values (e.g. SCM timeouts 30000 / 45000) are collected,
        // not used for grouping.
        for (k, v) in key
            .iter()
            .filter(|(k, v)| ATTRIBUTE_KEYS.contains(&k.as_str()) && !v.is_empty())
        {
            let sep = attribute_sep(k);
            match a.key.iter_mut().find(|(ak, _)| ak == k) {
                Some(slot) => {
                    let n = slot.1.split(sep).count();
                    if !slot.1.split(sep).any(|x| x == v) && n < MAX_ATTRIBUTE_VALUES {
                        slot.1 = format!("{}{sep}{v}", slot.1);
                    }
                }
                None => a.key.push((k.clone(), v.clone())),
            }
        }
        if e.level > 0 && (a.level == 0 || e.level < a.level) {
            a.level = e.level;
        }
        if group == Group::Tpm && tpm_is_problem(e) {
            a.category = "tpm_problem".into();
        }
        a.count += 1;
        if let (Some(day), Some(reference)) = (day_number(&e.time), reference_day)
            && reference - day < 7
        {
            a.count_last_7_days += 1;
        }
        if e.time < a.first_seen {
            a.first_seen = e.time.clone();
        }
        if a.latest.len() < 5 {
            let msg: String = e.message.split_whitespace().collect::<Vec<_>>().join(" ");
            a.latest.push(msg.chars().take(400).collect());
        }
    }
    out.sort_by(|a, b| {
        a.group
            .cmp(&b.group)
            .then(b.count.cmp(&a.count))
            .then(a.provider.cmp(&b.provider))
    });
    out
}

/// v1.0 class of an actionable event group. EVENT COUNT ALONE DOES NOT
/// DETERMINE SEVERITY: the class comes from the identity of the group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FindingClass {
    /// Repeated software / service failures (SCM, application crashes).
    SoftwareRecurring,
    /// Code Integrity / security-relevant software findings.
    Security,
    /// A single (below the recurrence threshold) application crash / hang /
    /// .NET exception: a finding of its own, neither recurring nor
    /// historical.
    SoftwareSingle,
    /// Old or self-resolved activity (historical WU failure, VSS quota,
    /// idle shutdowns, single service hiccups).
    Historical,
    /// Informational / routine activity shown for transparency (TPM
    /// success events, Schannel credential errors, CI audit / catalog
    /// events): repetition alone never makes it a failure.
    Informational,
}

impl FindingClass {
    pub fn code(self) -> &'static str {
        match self {
            FindingClass::SoftwareRecurring => "SOFTWARE_RECURRING",
            FindingClass::Security => "SECURITY",
            FindingClass::SoftwareSingle => "SOFTWARE_SINGLE",
            FindingClass::Historical => "HISTORICAL",
            FindingClass::Informational => "INFO",
        }
    }
}

/// One actionable incident group (unique identity), for summaries.
#[derive(Debug, Clone, PartialEq)]
pub struct Actionable {
    pub class: FindingClass,
    /// "CDPSvc (Connected Devices Platform Service) — 6× 7031".
    pub title: String,
    pub count: u32,
    pub first_seen: String,
    pub last_seen: String,
    /// EXPC stage (0-based) the group belongs to.
    pub stage: usize,
}

fn key_val<'a>(a: &'a Aggregate, k: &str) -> &'a str {
    a.key
        .iter()
        .find(|(n, _)| n == k)
        .map(|(_, v)| v.as_str())
        .unwrap_or("")
}

/// Recurrence threshold of a software / service group. A single event is
/// listed as historical context, never as a recurring problem.
pub const RECURRENCE_MIN: u32 = 3;

/// v1.0 unique actionable groups (primary metric — not raw counts).
pub fn actionable(aggs: &[Aggregate]) -> Vec<Actionable> {
    let mut out = Vec::new();
    for a in aggs {
        let Some(group) = a.group else { continue };
        let base = |class, title: String| Actionable {
            class,
            title,
            count: a.count,
            first_seen: a.first_seen.clone(),
            last_seen: a.last_seen.clone(),
            stage: group.stage(),
        };
        match group {
            Group::Scm => {
                let svc = key_val(a, "Service");
                let name = match &a.service {
                    Some(si) if !si.name.is_empty() && !si.name.eq_ignore_ascii_case(svc) => {
                        format!("{} ({svc})", si.name)
                    }
                    _ if svc.is_empty() => "?".into(),
                    _ => svc.to_string(),
                };
                let orphan = a.service.is_none() && !svc.is_empty();
                let mut title = format!(
                    "{name} — {}× SCM {} · {}",
                    a.count,
                    a.id,
                    scm_failure_type(a.id)
                );
                let error = key_val(a, "Error");
                if !error.is_empty() {
                    title.push_str(&format!(" · ошибка: {error}"));
                }
                if orphan {
                    title.push_str(" · служба не найдена (остаточная запись)");
                } else if let Some(si) = &a.service {
                    title.push_str(&format!(
                        " · сейчас: {} / {}",
                        if si.state.is_empty() { "?" } else { &si.state },
                        if si.start_mode.is_empty() {
                            "?"
                        } else {
                            &si.start_mode
                        }
                    ));
                    if si.state.eq_ignore_ascii_case("stopped") {
                        title.push_str(
                            " (остановленная служба не доказывает текущую неисправность)",
                        );
                    }
                }
                let class = if a.count >= RECURRENCE_MIN {
                    FindingClass::SoftwareRecurring
                } else {
                    FindingClass::Historical
                };
                out.push(base(class, title));
            }
            Group::AppErrors => {
                let process = key_val(a, "Process");
                let process = if process.is_empty() {
                    "INSUFFICIENT DATA (процесс не определён ни в EventData, ни в сообщении)"
                } else {
                    process
                };
                let mut title = format!(
                    "{process} — {}× {}",
                    a.count,
                    match a.id {
                        1000 => "сбой",
                        1002 => "зависание",
                        1026 => ".NET исключение",
                        _ => "событие",
                    }
                );
                let exc = key_val(a, "Exception");
                if !exc.is_empty() && exc != "0x" {
                    title.push_str(&format!(" · Exception {exc}"));
                }
                if key_val(a, "Process").is_empty() {
                    let head = key_val(a, "MessageHead");
                    if !head.is_empty() {
                        let head: String = head.chars().take(80).collect();
                        title.push_str(&format!(" · «{head}»"));
                    }
                }
                let module = key_val(a, "Module");
                if !module.is_empty() {
                    title.push_str(&format!(" · модуль {module}"));
                }
                let class = if a.count >= RECURRENCE_MIN {
                    FindingClass::SoftwareRecurring
                } else {
                    FindingClass::SoftwareSingle
                };
                out.push(base(class, title));
            }
            Group::CodeIntegrityUser | Group::CodeIntegrityKernel => {
                // 3089 = signature details of another CI event, never an
                // incident of its own (it is linked by Correlation ID).
                if a.category == "ci_signature_info" {
                    continue;
                }
                let module = match key_val(a, "Module") {
                    "" => "?",
                    m => m,
                };
                let mut title = match key_val(a, "Process") {
                    "" => format!("Code Integrity {} — файл {module}", a.id),
                    p => format!("Code Integrity {} — {module} в {p}", a.id),
                };
                title.push_str(&format!(" ×{} · {}", a.count, ci_reason(a.id)));
                let sig = key_val(a, "Signature");
                if !sig.is_empty() {
                    title.push_str(&format!(" · подпись: {sig}"));
                }
                let path = key_val(a, "FilePath");
                if !path.is_empty() && path != module {
                    title.push_str(&format!(" · {path}"));
                }
                let class = match a.category.as_str() {
                    "ci_audit_only" | "ci_catalog_not_loaded" => FindingClass::Informational,
                    _ => FindingClass::Security,
                };
                out.push(base(class, title));
            }
            Group::Tpm => {
                // Level / semantics decide, never the count alone.
                let (class, what) = if a.category == "tpm_problem" {
                    if a.count >= RECURRENCE_MIN {
                        (FindingClass::SoftwareRecurring, "предупреждение / ошибка")
                    } else {
                        (FindingClass::Historical, "предупреждение / ошибка")
                    }
                } else {
                    (FindingClass::Informational, "информационное / успешное")
                };
                out.push(base(
                    class,
                    format!("{} {} — {}× · {what}", a.provider, a.id, a.count),
                ));
            }
            Group::Schannel => {
                let code = key_val(a, "ErrorCode");
                let process = match key_val(a, "Process") {
                    "" => "процесс не указан",
                    p => p,
                };
                out.push(base(
                    FindingClass::Informational,
                    format!(
                        "Schannel {} — {process} · внутренний код {} · {}× (7 дн.: {}) · повторяющаяся ошибка TLS-клиента, сама по себе не критический отказ",
                        a.id,
                        if code.is_empty() { "?" } else { code },
                        a.count,
                        a.count_last_7_days
                    ),
                ));
            }
            Group::WindowsUpdate => {
                // Historical ONLY when a later install of the same update
                // is confirmed; another KB's success proves nothing.
                let class = if a.wu_resolved == Some(true) {
                    FindingClass::Historical
                } else {
                    FindingClass::SoftwareRecurring
                };
                let kb = key_val(a, "KB");
                out.push(base(
                    class,
                    format!(
                        "Windows Update 20 — {}{}×{}",
                        if kb.is_empty() {
                            String::new()
                        } else {
                            format!("{kb} ")
                        },
                        a.count,
                        match key_val(a, "HRESULT") {
                            "" => String::new(),
                            h => format!(" · {h}"),
                        }
                    ),
                ));
            }
            Group::Vss => {
                let class = if a.category == "vss_operation_failure" {
                    FindingClass::SoftwareRecurring
                } else {
                    FindingClass::Historical
                };
                out.push(base(
                    class,
                    format!("{} {} ({}) — {}×", a.provider, a.id, a.category, a.count),
                ));
            }
            _ => {}
        }
    }
    out.sort_by(|a, b| a.class.cmp(&b.class).then(b.count.cmp(&a.count)));
    out
}

/// Windows Update Event 20 summary: `Some(true)` only when EVERY failure
/// is followed by a successful install (Event 19) of the same update
/// (`wu_failure_resolved`); a failure without identity, or one resolved
/// only by another update, keeps it `Some(false)`. `None` = no failures.
pub fn wu_failure_is_historical(events: &[RawEvent]) -> Option<bool> {
    let mut fails = events.iter().filter(|e| is_wu(e, 20)).peekable();
    fails.peek()?;
    Some(fails.all(|f| wu_failure_resolved(f, events) == Some(true)))
}

/// One-line summary of an aggregate for Details (stage-local evidence).
pub fn aggregate_line(a: &Aggregate) -> String {
    let key: Vec<String> = a
        .key
        .iter()
        .filter(|(_, v)| !v.is_empty())
        .map(|(k, v)| format!("{k}={v}"))
        .collect();
    let mut s = format!(
        "{} #{} ×{} (7d: {}, 8–30d: {}) · {} → {}",
        a.provider,
        a.id,
        a.count,
        a.count_last_7_days,
        a.count - a.count_last_7_days,
        a.first_seen.replace('T', " "),
        a.last_seen.replace('T', " ")
    );
    if !a.category.is_empty() {
        s.push_str(&format!(" · {}", a.category));
    }
    if !key.is_empty() {
        s.push_str(&format!(" · {}", key.join(" · ")));
    }
    if let Some(svc) = &a.service {
        s.push_str(&format!(
            " · service {} ({}) {} / {}{}",
            svc.name,
            svc.display_name,
            svc.state,
            svc.start_mode,
            if svc.path.is_empty() {
                String::new()
            } else {
                format!(" / {}", svc.path)
            }
        ));
    }
    s
}

/// Evidence JSON (`Event_Evidence_<stamp>.json`).
pub fn to_json(aggs: &[Aggregate], wu_historical: Option<bool>, collected_at: &str) -> String {
    let items: Vec<String> = aggs
        .iter()
        .map(|a| {
            let key: Vec<String> = a
                .key
                .iter()
                .map(|(k, v)| format!("{}: {}", json::string(k), json::string(v)))
                .collect();
            let latest: Vec<String> = a.latest.iter().map(|m| json::string(m)).collect();
            let svc = match &a.service {
                Some(s) => format!(
                    "{{\"name\": {}, \"display_name\": {}, \"current_state\": {}, \"start_type\": {}, \"image_path\": {}}}",
                    json::string(&s.name),
                    json::string(&s.display_name),
                    json::string(&s.state),
                    json::string(&s.start_mode),
                    json::string(&s.path)
                ),
                None => "null".into(),
            };
            format!(
                "    {{\"group\": {}, \"provider\": {}, \"event_id\": {}, \"category\": {}, \"key\": {{{}}}, \"count\": {}, \"count_last_7_days\": {}, \"first_seen\": {}, \"last_seen\": {}, \"level\": {}, \"latest_messages\": [{}], \"service\": {}, \"wu_resolved_by_later_install\": {}}}",
                json::string(a.group.map(Group::code).unwrap_or("other")),
                json::string(&a.provider),
                a.id,
                json::string(&a.category),
                key.join(", "),
                a.count,
                a.count_last_7_days,
                json::string(&a.first_seen),
                json::string(&a.last_seen),
                a.level,
                latest.join(", "),
                svc,
                match a.wu_resolved {
                    Some(b) => b.to_string(),
                    None => "null".into(),
                }
            )
        })
        .collect();
    let groups: Vec<String> = actionable(aggs)
        .iter()
        .map(|g| {
            format!(
                "    {{\"class\": {}, \"title\": {}, \"count\": {}, \"first_seen\": {}, \"last_seen\": {}, \"expc_stage\": {}}}",
                json::string(g.class.code()),
                json::string(&g.title),
                g.count,
                json::string(&g.first_seen),
                json::string(&g.last_seen),
                g.stage + 1
            )
        })
        .collect();
    format!(
        "{{\n  \"format\": \"winstatediag.event_evidence/1\",\n  \"status\": \"COLLECTED\",\n  \"collected_at\": {},\n  \"window_days\": {WINDOW_DAYS},\n  \"scope\": {},\n  \"principle\": \"Event count alone does not determine severity; every counter is verifiable here.\",\n  \"windows_update_failure_historical\": {},\n  \"actionable_groups\": [\n{}\n  ],\n  \"aggregate_count\": {},\n  \"aggregates\": [\n{}\n  ]\n}}\n",
        json::string(collected_at),
        SCOPE_JSON,
        match wu_historical {
            Some(b) => b.to_string(),
            None => "null".into(),
        },
        groups.join(",\n"),
        aggs.len(),
        items.join(",\n")
    )
}

/// v1.0 counter scope: every count in this file is "events of these
/// queries in the last WINDOW_DAYS days, grouped by provider + Event ID +
/// identity key (SCM service, process, module, KB …)". Other modules (EXPC
/// stages: 14 days, Level 1–2; Driver Audit: its device-scoped queries)
/// count different scopes — never compare counters without the scope.
pub const SCOPE_JSON: &str = "{\"window_days\": 30, \"logs\": [\"System\", \"Application\", \"Microsoft-Windows-CodeIntegrity/Operational\"], \"queries\": [\"System/Schannel\", \"System/Microsoft-Windows-WindowsUpdateClient 19,20\", \"System/Microsoft-Windows-TPM-WMI\", \"System/TPM\", \"System/Service Control Manager 7000,7001,7009,7011,7023,7024,7031,7034\", \"Application/SideBySide 33,35,59,63,80\", \"CodeIntegrity/Operational 3001,3002,3004,3010,3023,3033,3034,3063,3077,3089\", \"Application/VSS\", \"System/volsnap\", \"Application/Application Error 1000\", \"Application/Application Hang 1002\", \"Application/.NET Runtime 1026\"], \"max_events_per_query\": 1500, \"grouping\": \"provider + event id + identity key (SCM: service name, timeout and error text are attributes; applications: process + module + exception, process from EventData or the message, otherwise INSUFFICIENT DATA keyed by the message head; Code Integrity: process + module, full paths and the 3089 signature details linked by Correlation ActivityID are attributes, 3089 itself is never an incident; Schannel: internal error code + SSPI client process; TPM: Level and Event ID semantics, success / information events are INFO)\", \"classes\": [\"SOFTWARE_RECURRING\", \"SECURITY\", \"SOFTWARE_SINGLE\", \"HISTORICAL\", \"INFO\"]}";

/// Read-only collector: one `WSD_EV <json>` line per event and one
/// `WSD_SVC <json>` per service referenced by SCM events.
pub const COLLECTOR_PS1: &str = r#"param([int]$Days = 30)
$ErrorActionPreference = 'SilentlyContinue'
$since = (Get-Date).AddDays(-$Days)
$queries = @(
    @{ LogName = 'System'; ProviderName = 'Schannel' },
    @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WindowsUpdateClient'; Id = 19, 20 },
    @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-TPM-WMI' },
    @{ LogName = 'System'; ProviderName = 'TPM' },
    @{ LogName = 'System'; ProviderName = 'Service Control Manager'; Id = 7000, 7001, 7009, 7011, 7023, 7024, 7031, 7034 },
    @{ LogName = 'Application'; ProviderName = 'SideBySide'; Id = 33, 35, 59, 63, 80 },
    @{ LogName = 'Microsoft-Windows-CodeIntegrity/Operational'; Id = 3001, 3002, 3004, 3010, 3023, 3033, 3034, 3063, 3077, 3089 },
    @{ LogName = 'Application'; ProviderName = 'VSS' },
    @{ LogName = 'System'; ProviderName = 'volsnap' },
    @{ LogName = 'Application'; ProviderName = 'Application Error'; Id = 1000 },
    @{ LogName = 'Application'; ProviderName = 'Application Hang'; Id = 1002 },
    @{ LogName = 'Application'; ProviderName = '.NET Runtime'; Id = 1026 }
)
$svcNames = New-Object System.Collections.Generic.HashSet[string]
foreach ($q in $queries) {
    $q.StartTime = $since
    foreach ($e in @(Get-WinEvent -FilterHashtable $q -MaxEvents 1500 -ErrorAction SilentlyContinue)) {
        $data = @()
        try {
            $x = [xml]$e.ToXml()
            $i = 0
            foreach ($d in @($x.Event.EventData.Data)) {
                $i++
                $n = [string]$d.Name; if (-not $n) { $n = "param$i" }
                $v = if ($d -is [string]) { $d } else { [string]$d.'#text' }
                $data += [PSCustomObject]@{ k = $n; v = $v }
            }
        } catch { }
        $msg = ''
        try { $msg = [string]$e.Message } catch { }
        $corr = ''
        try { $corr = [string]$x.Event.System.Correlation.ActivityID } catch { }
        $lvl = 0
        try { $lvl = [int]$e.Level } catch { }
        if ($e.ProviderName -eq 'Service Control Manager' -and $data.Count -gt 0) {
            $si = if ([int]$e.Id -in @(7009, 7011) -and $data.Count -ge 2) { 1 } else { 0 }
            [void]$svcNames.Add([string]$data[$si].v)
        }
        $o = [ordered]@{ log = [string]$e.LogName; p = [string]$e.ProviderName; id = [int]$e.Id; t = $e.TimeCreated.ToString('s'); lvl = $lvl; corr = $corr; m = $msg; d = @($data) }
        'WSD_EV ' + ($o | ConvertTo-Json -Compress -Depth 4)
    }
}
foreach ($s in $svcNames) {
    $w = Get-CimInstance Win32_Service | Where-Object { $_.DisplayName -eq $s -or $_.Name -eq $s } | Select-Object -First 1
    if ($w) { 'WSD_SVC ' + ([ordered]@{ name = [string]$w.Name; dn = [string]$w.DisplayName; st = [string]$w.State; sm = [string]$w.StartMode; path = [string]$w.PathName } | ConvertTo-Json -Compress) }
}
"#;

pub fn parse_collector(stdout: &str) -> (Vec<RawEvent>, Vec<ServiceInfo>) {
    let mut events = Vec::new();
    let mut services = Vec::new();
    for line in stdout.lines() {
        let line = line.trim_start_matches('\u{feff}');
        if let Some(j) = line.strip_prefix("WSD_EV ").and_then(json::parse) {
            let s = |k: &str| j.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
            let data = match j.get("d") {
                Some(json::Value::Arr(a)) => a.clone(),
                Some(o @ json::Value::Obj(_)) => vec![o.clone()],
                _ => Vec::new(),
            }
            .iter()
            .map(|d| {
                (
                    d.get("k")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    d.get("v")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                )
            })
            .collect();
            events.push(RawEvent {
                log: s("log"),
                provider: s("p"),
                id: match j.get("id") {
                    Some(json::Value::Num(n)) => *n as u32,
                    _ => 0,
                },
                time: s("t"),
                message: s("m"),
                data,
                level: match j.get("lvl") {
                    Some(json::Value::Num(n)) if (0.0..=255.0).contains(n) => *n as u8,
                    _ => 0,
                },
                correlation: s("corr")
                    .trim()
                    .trim_matches(['{', '}'])
                    .to_ascii_lowercase(),
            });
        } else if let Some(j) = line.strip_prefix("WSD_SVC ").and_then(json::parse) {
            let s = |k: &str| j.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
            services.push(ServiceInfo {
                name: s("name"),
                display_name: s("dn"),
                state: s("st"),
                start_mode: s("sm"),
                path: s("path"),
            });
        }
    }
    (events, services)
}

/// Runs the read-only collector.
#[cfg_attr(test, allow(dead_code))]
pub fn collect(host: &str) -> Result<(Vec<RawEvent>, Vec<ServiceInfo>), String> {
    let script = format!("& {{ {COLLECTOR_PS1} }} -Days {WINDOW_DAYS}");
    crate::ps_exec::run_powershell(host, &script, std::time::Duration::from_secs(240))
        .map(|out| parse_collector(&out))
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Collection time of the test fixtures.
    const NOW: &str = "2026-10-06T10:00:00";

    fn ev(provider: &str, id: u32, time: &str, message: &str, data: &[(&str, &str)]) -> RawEvent {
        RawEvent {
            log: "System".into(),
            provider: provider.into(),
            id,
            time: time.into(),
            message: message.into(),
            data: data
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn scm_aggregates_keep_service_fields_and_current_state() {
        let events = vec![
            ev(
                "Service Control Manager",
                7000,
                "2026-10-01T10:00:00",
                "The Foo Service service failed to start due to the following error.",
                &[("param1", "Foo Service"), ("param2", "%%2")],
            ),
            ev(
                "Service Control Manager",
                7000,
                "2026-10-03T10:00:00",
                "The Foo Service service failed to start.",
                &[("param1", "Foo Service")],
            ),
            ev(
                "Service Control Manager",
                7031,
                "2026-10-02T09:00:00",
                "The Bar service terminated unexpectedly.",
                &[("param1", "Bar")],
            ),
        ];
        let services = vec![ServiceInfo {
            name: "foosvc".into(),
            display_name: "Foo Service".into(),
            state: "Stopped".into(),
            start_mode: "Auto".into(),
            path: "C:\\Foo\\foo.exe".into(),
        }];
        let aggs = aggregate(&events, &services, NOW);
        let foo = aggs.iter().find(|a| a.id == 7000).unwrap();
        assert_eq!(foo.count, 2);
        assert_eq!(foo.first_seen, "2026-10-01T10:00:00");
        assert_eq!(foo.last_seen, "2026-10-03T10:00:00");
        assert_eq!(
            foo.key,
            vec![("Service".to_string(), "Foo Service".to_string())]
        );
        let svc = foo.service.as_ref().unwrap();
        assert_eq!(svc.name, "foosvc");
        assert_eq!(svc.state, "Stopped");
        assert_eq!(svc.start_mode, "Auto");
        assert!(aggregate_line(foo).contains("C:\\Foo\\foo.exe"));
        let bar = aggs.iter().find(|a| a.id == 7031).unwrap();
        assert_eq!(bar.count, 1);
        assert!(bar.service.is_none(), "no invented service data");
        let js = to_json(&aggs, None, "2026-10-06T10:00:00");
        assert!(crate::deep_checks::json::parse(&js).is_some());
        assert!(js.contains("\"current_state\": \"Stopped\""));
    }

    #[test]
    fn windows_update_event_20_keeps_kb_hresult_and_separates_history() {
        let fail = ev(
            "Microsoft-Windows-WindowsUpdateClient",
            20,
            "2026-09-20T03:00:00",
            "Installation Failure: Windows failed to install the following update with error 0x80070643: 2026-09 Security Update (KB5034441).",
            &[
                ("updateTitle", "2026-09 Security Update (KB5034441)"),
                ("errorCode", "0x80070643"),
            ],
        );
        let aggs = aggregate(std::slice::from_ref(&fail), &[], NOW);
        let a = &aggs[0];
        assert_eq!(a.group, Some(Group::WindowsUpdate));
        assert!(a.key.contains(&("KB".into(), "KB5034441".into())));
        assert!(a.key.contains(&("HRESULT".into(), "0x80070643".into())));
        assert_eq!(a.category, "install_failure");
        // A later successful install makes the failure historical.
        let ok = ev(
            "Microsoft-Windows-WindowsUpdateClient",
            19,
            "2026-10-01T03:00:00",
            "Installation Successful",
            &[],
        );
        // A success WITHOUT identity proves nothing about this failure.
        assert_eq!(wu_failure_is_historical(&[fail.clone(), ok]), Some(false));
        assert_eq!(
            wu_failure_is_historical(std::slice::from_ref(&fail)),
            Some(false)
        );
        assert_eq!(wu_failure_is_historical(&[]), None);
    }

    fn wu(id: u32, time: &str, kb: &str) -> RawEvent {
        let title = format!("2026-09 Cumulative Update ({kb})");
        ev(
            "Microsoft-Windows-WindowsUpdateClient",
            id,
            time,
            &format!("Installation: {title}"),
            &[("updateTitle", title.as_str()), ("errorCode", "0x80070643")],
        )
    }

    fn wu_class(events: &[RawEvent]) -> Vec<FindingClass> {
        actionable(&aggregate(events, &[], NOW))
            .iter()
            .map(|a| a.class)
            .collect()
    }

    #[test]
    fn wu_20_for_kb_a_stays_actual_after_later_19_for_kb_b() {
        let events = [
            wu(20, "2026-09-20T03:00:00", "KB5000001"),
            wu(19, "2026-10-01T03:00:00", "KB5000002"),
        ];
        let aggs = aggregate(&events, &[], NOW);
        assert_eq!(aggs.len(), 1);
        assert_eq!(aggs[0].wu_resolved, Some(false));
        assert_eq!(wu_class(&events), vec![FindingClass::SoftwareRecurring]);
        assert_eq!(wu_failure_is_historical(&events), Some(false));
        assert!(
            to_json(&aggs, Some(false), NOW).contains("\"wu_resolved_by_later_install\": false")
        );
    }

    #[test]
    fn wu_20_for_kb_a_is_historical_after_confirmed_later_19_for_kb_a() {
        let events = [
            wu(20, "2026-09-20T03:00:00", "KB5000001"),
            wu(19, "2026-10-01T03:00:00", "KB5000001"),
        ];
        assert_eq!(aggregate(&events, &[], NOW)[0].wu_resolved, Some(true));
        assert_eq!(wu_class(&events), vec![FindingClass::Historical]);
        assert_eq!(wu_failure_is_historical(&events), Some(true));
        // An EARLIER success of the same KB does not resolve a later failure.
        let earlier = [
            wu(19, "2026-09-01T03:00:00", "KB5000001"),
            wu(20, "2026-09-20T03:00:00", "KB5000001"),
        ];
        assert_eq!(wu_class(&earlier), vec![FindingClass::SoftwareRecurring]);
        // Mixed: A resolved, B not -> the summary is not "historical".
        let mixed = [
            wu(20, "2026-09-20T03:00:00", "KB5000001"),
            wu(20, "2026-09-21T03:00:00", "KB5000003"),
            wu(19, "2026-10-01T03:00:00", "KB5000001"),
        ];
        let mut classes = wu_class(&mixed);
        classes.sort();
        assert_eq!(
            classes,
            vec![FindingClass::SoftwareRecurring, FindingClass::Historical]
        );
        assert_eq!(wu_failure_is_historical(&mixed), Some(false));
    }

    #[test]
    fn wu_19_without_identity_does_not_close_any_20() {
        let ok = ev(
            "Microsoft-Windows-WindowsUpdateClient",
            19,
            "2026-10-01T03:00:00",
            "Installation Successful",
            &[],
        );
        // Identified failure + anonymous success: stays actual.
        let a = [wu(20, "2026-09-20T03:00:00", "KB5000001"), ok.clone()];
        assert_eq!(wu_class(&a), vec![FindingClass::SoftwareRecurring]);
        // Anonymous failure + anonymous success: no identity, no claim.
        let anon = ev(
            "Microsoft-Windows-WindowsUpdateClient",
            20,
            "2026-09-20T03:00:00",
            "Installation Failure",
            &[],
        );
        let b = [anon, ok];
        assert_eq!(aggregate(&b, &[], NOW)[0].wu_resolved, None);
        assert_eq!(wu_class(&b), vec![FindingClass::SoftwareRecurring]);
        assert_eq!(wu_failure_is_historical(&b), Some(false));
        // GUID decides when both carry it, even with an equal KB.
        let g = |id, t: &str, guid: &str| {
            ev(
                "Microsoft-Windows-WindowsUpdateClient",
                id,
                t,
                "x",
                &[("updateTitle", "Update (KB5000001)"), ("updateGuid", guid)],
            )
        };
        let c = [
            g(20, "2026-09-20T03:00:00", "{AAAA-1}"),
            g(19, "2026-10-01T03:00:00", "{BBBB-2}"),
        ];
        assert_eq!(wu_class(&c), vec![FindingClass::SoftwareRecurring]);
        let d = [
            g(20, "2026-09-20T03:00:00", "{AAAA-1}"),
            g(19, "2026-10-01T03:00:00", "aaaa-1"),
        ];
        assert_eq!(wu_class(&d), vec![FindingClass::Historical]);
    }

    #[test]
    fn seven_day_counter_is_relative_to_collection_time_not_newest_event() {
        // All events are 3-5 weeks old: none of them is "fresh".
        let old: Vec<RawEvent> = (0..5)
            .map(|i| {
                ev(
                    "volsnap",
                    33,
                    &format!("2026-09-{:02}T03:00:00", 10 + i),
                    "q",
                    &[],
                )
            })
            .collect();
        let a = aggregate(&old, &[], NOW);
        assert_eq!(a[0].count, 5);
        assert_eq!(a[0].count_last_7_days, 0);
        assert!(aggregate_line(&a[0]).contains("(7d: 0, 8–30d: 5)"));
        // Collected on Sep 20: only Sep 14 is within the last 7 days.
        let a = aggregate(&old, &[], "2026-09-20T12:00:00");
        assert_eq!(a[0].count_last_7_days, 1);
        // Unknown collection time: nothing is claimed as recent.
        assert_eq!(aggregate(&old, &[], "probe")[0].count_last_7_days, 0);
    }

    #[test]
    fn single_application_error_hang_dotnet_are_single_not_recurring() {
        for (provider, id) in [
            ("Application Error", 1000),
            ("Application Hang", 1002),
            (".NET Runtime", 1026),
        ] {
            let one = ev(
                provider,
                id,
                "2026-10-05T12:00:00",
                "x",
                &[("param1", "app.exe")],
            );
            let act = actionable(&aggregate(std::slice::from_ref(&one), &[], NOW));
            assert_eq!(act.len(), 1);
            assert_eq!(act[0].class, FindingClass::SoftwareSingle, "{provider}");
            assert_eq!(act[0].class.code(), "SOFTWARE_SINGLE");
            assert_ne!(act[0].class, FindingClass::Historical);
            let two = [one.clone(), one.clone()];
            assert_eq!(
                actionable(&aggregate(&two, &[], NOW))[0].class,
                FindingClass::SoftwareSingle,
                "below RECURRENCE_MIN"
            );
            let three = [one.clone(), one.clone(), one];
            assert_eq!(
                actionable(&aggregate(&three, &[], NOW))[0].class,
                FindingClass::SoftwareRecurring
            );
        }
    }

    #[test]
    fn code_integrity_splits_user_and_kernel_mode_and_aggregates_repeats() {
        let user = |t: &str| {
            ev(
                "Microsoft-Windows-CodeIntegrity",
                3033,
                t,
                "Code Integrity determined that a process (\\Device\\HarddiskVolume3\\Program Files\\Browser\\browser.exe) attempted to load \\Device\\HarddiskVolume3\\Program Files\\Vendor\\hook.dll that did not meet the Microsoft signing level requirements.",
                &[],
            )
        };
        let kernel = ev(
            "Microsoft-Windows-CodeIntegrity",
            3004,
            "2026-10-02T10:00:00",
            "Windows is unable to verify the image integrity of the file \\Device\\HarddiskVolume3\\Windows\\System32\\drivers\\bad.sys because file hash could not be found on the system.",
            &[],
        );
        let mut events: Vec<RawEvent> = (1..=40)
            .map(|d| user(&format!("2026-09-{:02}T10:00:00", (d % 28) + 1)))
            .collect();
        events.push(kernel);
        let aggs = aggregate(&events, &[], NOW);
        let u = aggs
            .iter()
            .find(|a| a.group == Some(Group::CodeIntegrityUser))
            .unwrap();
        assert_eq!(u.count, 40, "repeats aggregated, not 40 findings");
        assert!(u.key.contains(&("Process".into(), "browser.exe".into())));
        assert!(u.key.contains(&("Module".into(), "hook.dll".into())));
        let k = aggs
            .iter()
            .find(|a| a.group == Some(Group::CodeIntegrityKernel))
            .unwrap();
        assert!(k.key.contains(&("Module".into(), "bad.sys".into())));
        assert_eq!(
            Group::CodeIntegrityUser.stage(),
            7,
            "user-mode CI → app errors stage"
        );
        assert_eq!(
            Group::CodeIntegrityKernel.stage(),
            2,
            "kernel CI → devices/drivers stage"
        );
    }

    #[test]
    fn sidebyside_33_keeps_path_and_assembly_without_inventing_an_owner() {
        let e = RawEvent {
            log: "Application".into(),
            ..ev(
                "SideBySide",
                33,
                "2026-10-01T08:00:00",
                "Activation context generation failed for \"C:\\Program Files\\Tool\\tool.exe\". Dependent Assembly Microsoft.VC90.CRT,processorArchitecture=\"amd64\",publicKeyToken=\"1fc8b3b9a1e18e3b\",type=\"win32\",version=\"9.0.30729.9625\" could not be found. Please use sxstrace.exe for detailed diagnosis.",
                &[],
            )
        };
        let aggs = aggregate(&[e.clone(), e], &[], NOW);
        let a = &aggs[0];
        assert_eq!(a.count, 2);
        // Keyed by the executable file name; the full path stays in the
        // latest messages.
        assert!(a.key.contains(&("Executable".into(), "tool.exe".into())));
        assert!(a.latest[0].contains("C:\\Program Files\\Tool\\tool.exe"));
        assert!(a.key.contains(&(
            "Assembly".into(),
            "Microsoft.VC90.CRT 9.0.30729.9625".into()
        )));
        assert!(!a.key.iter().any(|(k, _)| k == "Owner"));
    }

    #[test]
    fn vss_quota_eviction_is_distinguished_from_operational_failures() {
        let mk = |p: &str, id: u32| {
            let mut e = ev(p, id, "2026-10-01T08:00:00", "x", &[]);
            e.log = "Application".into();
            e
        };
        let aggs = aggregate(
            &[mk("volsnap", 33), mk("volsnap", 25), mk("VSS", 8193)],
            &[],
            NOW,
        );
        let cats: Vec<&str> = aggs.iter().map(|a| a.category.as_str()).collect();
        assert!(cats.contains(&"restore_point_eviction_quota"));
        assert!(cats.contains(&"shadow_copies_deleted_storage"));
        assert!(cats.contains(&"vss_operation_failure"));
        assert!(aggs.iter().all(|a| a.group == Some(Group::Vss)));
    }

    #[test]
    fn schannel_and_tpm_evidence_is_aggregated_with_error_codes() {
        let s = |t: &str| {
            ev(
                "Schannel",
                36871,
                t,
                "A fatal error occurred while creating a TLS client credential. The internal error state is 10013.",
                &[],
            )
        };
        let tpm = ev(
            "Microsoft-Windows-TPM-WMI",
            1796,
            "2026-10-01T08:00:00",
            "The Secure Boot update failed",
            &[],
        );
        let aggs = aggregate(
            &[s("2026-10-01T08:00:00"), s("2026-10-02T08:00:00"), tpm],
            &[],
            NOW,
        );
        let sch = aggs
            .iter()
            .find(|a| a.group == Some(Group::Schannel))
            .unwrap();
        assert_eq!(sch.count, 2);
        assert_eq!(
            sch.key,
            vec![("ErrorCode".to_string(), "10013".to_string())]
        );
        assert_eq!(sch.latest.len(), 2);
        let t = aggs.iter().find(|a| a.group == Some(Group::Tpm)).unwrap();
        assert_eq!(t.id, 1796);
        assert_eq!(t.latest[0], "The Secure Boot update failed");
    }

    #[test]
    fn collector_output_is_parsed_and_counters_are_verifiable() {
        let out = "noise\nWSD_EV {\"log\":\"System\",\"p\":\"Service Control Manager\",\"id\":7000,\"t\":\"2026-10-01T10:00:00\",\"m\":\"failed\",\"d\":[{\"k\":\"param1\",\"v\":\"Foo Service\"}]}\nWSD_SVC {\"name\":\"foosvc\",\"dn\":\"Foo Service\",\"st\":\"Stopped\",\"sm\":\"Auto\",\"path\":\"C:\\\\foo.exe\"}\n";
        let (events, services) = parse_collector(out);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].field(&["param1"]), Some("Foo Service"));
        assert_eq!(services[0].name, "foosvc");
        let aggs = aggregate(&events, &services, NOW);
        let js = to_json(&aggs, None, "t");
        let v = crate::deep_checks::json::parse(&js).unwrap();
        assert_eq!(
            v.get("aggregate_count").and_then(|n| match n {
                crate::deep_checks::json::Value::Num(n) => Some(*n as u32),
                _ => None,
            }),
            Some(1)
        );
    }

    #[test]
    fn summary_counters_7_days_and_8_to_30_days_are_verifiable() {
        let spread: Vec<RawEvent> = (0..39)
            .map(|i| {
                let mut e = ev("volsnap", 33, "", "quota eviction", &[]);
                e.time = if i < 11 {
                    format!("2026-10-{:02}T03:00:00", 1 + (i % 6))
                } else {
                    format!("2026-09-{:02}T03:00:00", 8 + (i % 20))
                };
                e
            })
            .collect();
        let quota = aggregate(&spread, &[], NOW);
        assert_eq!(quota.len(), 1);
        assert_eq!(quota[0].count, 39);
        assert_eq!(quota[0].count_last_7_days, 11);
        assert!(
            aggregate_line(&quota[0]).contains("(7d: 11, 8–30d: 28)"),
            "{}",
            aggregate_line(&quota[0])
        );
        let js = to_json(&quota, None, "2026-10-06T10:00:00");
        assert!(js.contains("\"count\": 39, \"count_last_7_days\": 11"));
    }

    #[test]
    fn russian_sidebyside_33_aggregates_by_executable_across_temp_folders() {
        let mk = |dir: &str| {
            let mut e = ev(
                "SideBySide",
                33,
                "2026-10-05T14:02:54",
                &format!(
                    "Ошибка при создании контекста активации для \"C:\\Windows\\SystemTemp\\{dir}\\browser.exe\". Не найдена зависимая сборка \"26.8.0.1774,language=\"&#x2a;\",type=\"win32\",version=\"26.8.0.1774\"\". Используйте sxstrace.exe для подробной диагностики."
                ),
                &[],
            );
            e.log = "Application".into();
            e
        };
        let aggs = aggregate(
            &[mk("sdwra_1_2"), mk("sdwra_3_4"), mk("sdwra_5_6")],
            &[],
            NOW,
        );
        assert_eq!(aggs.len(), 1, "one aggregate across temp folders");
        assert_eq!(aggs[0].count, 3);
        assert!(
            aggs[0]
                .key
                .contains(&("Executable".into(), "browser.exe".into()))
        );
        assert!(
            aggs[0]
                .key
                .contains(&("Assembly".into(), "26.8.0.1774".into()))
        );
        assert!(
            aggs[0].latest[0].contains("SystemTemp"),
            "full path kept in the messages"
        );
        assert!(
            !aggs[0].key.iter().any(|(k, _)| k == "Owner"),
            "no invented owner"
        );
    }

    // ---- v1.0 real-case fixtures ------------------------------------------

    #[test]
    fn scm_7009_groups_by_service_and_keeps_timeouts_as_attribute() {
        let t = |svc: &str, ms: &str, time: &str| {
            ev(
                "Service Control Manager",
                7009,
                time,
                "A timeout was reached while waiting for the service to connect.",
                &[("param1", ms), ("param2", svc)],
            )
        };
        let aggs = aggregate(
            &[
                t("Rutoken Connect", "30000", "2026-10-01T10:00:00"),
                t("Rutoken Connect", "45000", "2026-10-02T10:00:00"),
                t("ScDeviceEnum", "30000", "2026-10-03T10:00:00"),
            ],
            &[],
            NOW,
        );
        assert_eq!(aggs.len(), 2, "{aggs:?}");
        let rt = aggs
            .iter()
            .find(|a| key_val(a, "Service") == "Rutoken Connect")
            .unwrap();
        assert_eq!(rt.count, 2);
        assert_eq!(key_val(rt, "TimeoutMs"), "45000,30000");
        assert!(
            aggs.iter()
                .all(|a| !["30000", "45000"].contains(&key_val(a, "Service")))
        );
    }

    #[test]
    fn cdpsvc_repeated_failures_become_an_actionable_group() {
        let events: Vec<RawEvent> = (1..=6)
            .map(|d| {
                ev(
                    "Service Control Manager",
                    7031,
                    &format!("2026-10-0{d}T09:00:00"),
                    "The Connected Devices Platform Service service terminated unexpectedly.",
                    &[
                        ("param1", "Connected Devices Platform Service"),
                        ("param2", "1"),
                    ],
                )
            })
            .collect();
        let svc = ServiceInfo {
            name: "CDPSvc".into(),
            display_name: "Connected Devices Platform Service".into(),
            state: "Running".into(),
            start_mode: "Auto".into(),
            path: "svchost.exe -k LocalService".into(),
        };
        let act = actionable(&aggregate(&events, &[svc], NOW));
        assert_eq!(act.len(), 1);
        assert_eq!(act[0].class, FindingClass::SoftwareRecurring);
        assert!(
            act[0]
                .title
                .starts_with("CDPSvc (Connected Devices Platform Service) — 6× SCM 7031"),
            "{}",
            act[0].title
        );
        assert_eq!(act[0].stage, 3);
        // An orphan service (not installed any more) is said explicitly.
        let orphan = vec![ev(
            "Service Control Manager",
            7000,
            "2026-10-01T09:00:00",
            "x",
            &[("param1", "AmmyyAdmin")],
        )];
        let a = actionable(&aggregate(&orphan, &[], NOW));
        assert_eq!(
            a[0].class,
            FindingClass::Historical,
            "single event is not recurring"
        );
        assert!(a[0].title.contains("служба не найдена"), "{}", a[0].title);
    }

    #[test]
    fn application_error_summary_names_process_and_exception() {
        let mut e = ev(
            "Application Error",
            1000,
            "2026-10-05T12:00:00",
            "Faulting application name: happd.exe",
            &[
                ("param1", "happd.exe"),
                ("param4", "ntdll.dll"),
                ("param7", "c0000005"),
            ],
        );
        e.log = "Application".into();
        let act = actionable(&aggregate(&[e], &[], NOW));
        assert_eq!(
            act[0].title,
            "happd.exe — 1× сбой · Exception 0xc0000005 · модуль ntdll.dll"
        );
        assert_eq!(act[0].stage, 7);
    }

    #[test]
    fn vss_8224_idle_and_volsnap_33_quota_are_historical_not_failures() {
        let mut idle = ev(
            "VSS",
            8224,
            "2026-10-05T12:00:00",
            "The VSS service is shutting down due to idle timeout.",
            &[],
        );
        idle.log = "Application".into();
        let quota = ev(
            "volsnap",
            33,
            "2026-10-04T12:00:00",
            "The oldest shadow copy of volume C: was deleted to keep disk space usage for shadow copies of volume C: below the user defined limit.",
            &[],
        );
        assert_eq!(vss_category(&idle), "vss_idle_shutdown");
        assert_eq!(vss_category(&quota), "restore_point_eviction_quota");
        let act = actionable(&aggregate(&[idle, quota], &[], NOW));
        assert!(
            act.iter().all(|a| a.class == FindingClass::Historical),
            "{act:?}"
        );
    }
    // ---- v1.0 Evidence Fix (Phase 02): real-world messages ----

    fn lvl(mut e: RawEvent, level: u8) -> RawEvent {
        e.level = level;
        e
    }

    fn corr(mut e: RawEvent, c: &str) -> RawEvent {
        e.correlation = c.into();
        e
    }

    #[test]
    fn tpm_success_events_are_info_never_recurring_by_count() {
        let msgs = [
            (
                "Microsoft-Windows-TPM-WMI",
                1025,
                "The TPM was successfully provisioned and is now ready for use.",
            ),
            (
                "Microsoft-Windows-TPM-WMI",
                1282,
                "The TBS device identifier has been generated.",
            ),
            (
                "Microsoft-Windows-TPM-WMI",
                1038,
                "Pre-attestation health checks confirm that the device is expected to pass attestation.",
            ),
            (
                "Microsoft-Windows-TPM-WMI",
                1041,
                "Pre-attestation health check detailed information: {\"HealthStatus\":\"Attestable\"}",
            ),
            (
                "TPM",
                18,
                "This event triggers the Trusted Platform Module (TPM) provisioning/status check to run.",
            ),
            (
                "Microsoft-Windows-TPM-WMI",
                1808,
                "This device has updated Secure Boot CA/keys.",
            ),
        ];
        for level in [0u8, 4] {
            let mut events = Vec::new();
            for (p, id, m) in msgs {
                for d in 1..=11 {
                    events.push(lvl(
                        ev(p, id, &format!("2026-10-{d:02}T08:00:00"), m, &[]),
                        level,
                    ));
                }
            }
            let act = actionable(&aggregate(&events, &[], NOW));
            assert_eq!(act.len(), 6, "{act:?}");
            for g in &act {
                assert_eq!(
                    g.class,
                    FindingClass::Informational,
                    "level {level}: {}",
                    g.title
                );
                assert_eq!(g.class.code(), "INFO");
                assert!(g.title.contains("11×"), "{}", g.title);
            }
        }
        // A real warning / error level is a problem: recurring at 3+.
        let warn: Vec<RawEvent> = (1..=3)
            .map(|d| {
                lvl(
                    ev(
                        "Microsoft-Windows-TPM-WMI",
                        1796,
                        &format!("2026-10-0{d}T08:00:00"),
                        "The Secure Boot update failed",
                        &[],
                    ),
                    2,
                )
            })
            .collect();
        assert_eq!(
            actionable(&aggregate(&warn, &[], NOW))[0].class,
            FindingClass::SoftwareRecurring
        );
        // Without a level, a single failure message is historical context.
        let one = [ev(
            "Microsoft-Windows-TPM-WMI",
            1796,
            "2026-10-01T08:00:00",
            "The Secure Boot update failed",
            &[],
        )];
        assert_eq!(
            actionable(&aggregate(&one, &[], NOW))[0].class,
            FindingClass::Historical
        );
        // Even a success ID with an ERROR level is not hidden.
        let err = [lvl(
            ev(
                "Microsoft-Windows-TPM-WMI",
                1025,
                "2026-10-01T08:00:00",
                "x",
                &[],
            ),
            2,
        )];
        assert_eq!(
            actionable(&aggregate(&err, &[], NOW))[0].class,
            FindingClass::Historical
        );
    }

    #[test]
    fn schannel_36871_groups_by_process_and_internal_code_as_info() {
        let s = |t: &str, process: &str, pid: u32| {
            ev(
                "Schannel",
                36871,
                t,
                &format!(
                    "A fatal error occurred while creating a TLS client credential. The internal error state is 10013. The SSPI client process is {process} (PID: {pid})."
                ),
                &[],
            )
        };
        let mut events = Vec::new();
        for d in 1..=30u32 {
            for k in 0..20 {
                events.push(s(
                    &format!("2026-09-{:02}T08:{k:02}:00", (d % 28) + 1),
                    "service_update",
                    61408 + d,
                ));
            }
        }
        for d in 1..=5u32 {
            events.push(s(
                &format!("2026-10-0{d}T09:00:00"),
                "OfficeC2RClient",
                49808 + d,
            ));
        }
        let aggs = aggregate(&events, &[], NOW);
        let sch: Vec<&Aggregate> = aggs
            .iter()
            .filter(|a| a.group == Some(Group::Schannel))
            .collect();
        assert_eq!(sch.len(), 2, "one group per process, PIDs are not identity");
        let su = sch
            .iter()
            .find(|a| key_val(a, "Process") == "service_update")
            .unwrap();
        assert_eq!(su.count, 600);
        assert_eq!(key_val(su, "ErrorCode"), "10013");
        let act = actionable(&aggs);
        assert_eq!(act.len(), 2);
        for g in &act {
            assert_eq!(
                g.class,
                FindingClass::Informational,
                "hundreds of repeats are not a critical failure"
            );
            assert!(
                g.title.contains("10013") && g.title.contains("7 дн."),
                "{}",
                g.title
            );
        }
        assert!(
            act.iter().any(|g| g
                .title
                .contains("service_update · внутренний код 10013 · 600×")),
            "{act:?}"
        );
        assert!(act.iter().any(|g| g.title.contains("OfficeC2RClient")));
    }

    const CI_3033_COMET: &str = "Code Integrity determined that a process (\\Device\\HarddiskVolume3\\Program Files\\Perplexity\\Comet\\Application\\comet.exe) attempted to load \\Device\\HarddiskVolume3\\Program Files\\Perplexity\\Comet\\Application\\154.0.8037.181\\vulkan-1.dll that did not meet the Microsoft signing level requirements.";
    const CI_3089: &str =
        "Signature information for another event. Match using the Correlation Id.";

    #[test]
    fn ci_3089_is_linked_by_correlation_id_and_never_an_incident() {
        let ci = "Microsoft-Windows-CodeIntegrity";
        let mut events = vec![
            corr(
                ev(ci, 3033, "2026-10-05T10:00:00", CI_3033_COMET, &[]),
                "c-1",
            ),
            corr(
                ev(ci, 3033, "2026-10-05T11:00:00", CI_3033_COMET, &[]),
                "c-2",
            ),
            corr(
                ev(
                    ci,
                    3089,
                    "2026-10-05T10:00:00",
                    CI_3089,
                    &[
                        ("PublisherName", "Khronos Group"),
                        ("IssuerName", "DigiCert"),
                        ("ValidatedSigningLevel", "4"),
                    ],
                ),
                "c-1",
            ),
            corr(
                ev(
                    ci,
                    3089,
                    "2026-10-05T11:00:00",
                    CI_3089,
                    &[
                        ("PublisherName", "Khronos Group"),
                        ("IssuerName", "DigiCert"),
                        ("ValidatedSigningLevel", "4"),
                    ],
                ),
                "c-2",
            ),
        ];
        // Hundreds of uncorrelated 3089 (older evidence without IDs).
        for i in 0..370 {
            events.push(ev(
                ci,
                3089,
                &format!("2026-09-{:02}T10:00:00", (i % 28) + 1),
                CI_3089,
                &[],
            ));
        }
        let aggs = aggregate(&events, &[], NOW);
        let blocked = aggs.iter().find(|a| a.id == 3033).unwrap();
        assert_eq!(blocked.count, 2);
        assert_eq!(blocked.category, "ci_image_blocked");
        assert_eq!(
            key_val(blocked, "Signature"),
            "Publisher=Khronos Group; Issuer=DigiCert; SigningLevel=4",
            "signature details joined by Correlation ID, distinct values only"
        );
        assert!(key_val(blocked, "FilePath").ends_with("154.0.8037.181\\vulkan-1.dll"));
        assert!(key_val(blocked, "ProcessPath").ends_with("Comet\\Application\\comet.exe"));
        let info: u32 = aggs.iter().filter(|a| a.id == 3089).map(|a| a.count).sum();
        assert_eq!(info, 372, "3089 stays verifiable in the aggregates");
        assert!(
            aggs.iter()
                .any(|a| a.id == 3089 && key_val(a, "LinkedEventIds") == "3033")
        );
        let act = actionable(&aggs);
        assert_eq!(act.len(), 1, "3089 never becomes an incident: {act:?}");
        assert_eq!(act[0].class, FindingClass::Security);
        assert!(
            act[0].title.starts_with(
                "Code Integrity 3033 — vulkan-1.dll в comet.exe ×2 · загрузка заблокирована"
            ),
            "{}",
            act[0].title
        );
        assert!(act[0].title.contains("подпись: Publisher=Khronos Group"));
    }

    #[test]
    fn ci_process_path_with_parentheses_is_parsed_whole() {
        let m = "Code Integrity determined that a process (\\Device\\HarddiskVolume3\\Program Files (x86)\\Yandex\\YandexBrowser\\Application\\browser.exe) attempted to load \\Device\\HarddiskVolume3\\Program Files (x86)\\Yandex\\YandexBrowser\\Application\\26.8.0.1774\\vk_swiftshader.dll that did not meet the Microsoft signing level requirements.";
        let e = ev(
            "Microsoft-Windows-CodeIntegrity",
            3033,
            "2026-10-08T00:59:58",
            m,
            &[],
        );
        assert_eq!(
            ci_process_module(&e),
            ("browser.exe".to_string(), "vk_swiftshader.dll".to_string())
        );
        let (pp, fp) = ci_paths(&e);
        assert!(
            pp.ends_with("Program Files (x86)\\Yandex\\YandexBrowser\\Application\\browser.exe"),
            "{pp}"
        );
        assert!(fp.ends_with("26.8.0.1774\\vk_swiftshader.dll"), "{fp}");
        let act = actionable(&aggregate(&[e], &[], NOW));
        assert!(
            !act[0].title.contains("Program Files (x86 "),
            "{}",
            act[0].title
        );
        assert!(
            act[0].title.contains("vk_swiftshader.dll в browser.exe"),
            "{}",
            act[0].title
        );
    }

    #[test]
    fn ci_file_only_events_name_the_file_and_never_an_empty_process() {
        let ci = "Microsoft-Windows-CodeIntegrity";
        let helper = "Windows is unable to verify the image integrity of the file \\Device\\HarddiskVolume3\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.26080.4-0\\DefenderSessionHelper.exe because file hash could not be found on the system. A recent hardware or software change might have installed a file that is signed incorrectly or damaged, or that might be malicious software from an unknown source.";
        let fcon = "Code Integrity is unable to verify the image integrity of the file \\Device\\HarddiskVolume3\\Windows\\System32\\fcon.dll because the set of per-page image hashes could not be found on the system.";
        let cat = "Code Integrity was unable to load the Containers-Client-SDN-Package~31bf3856ad364e35~amd64~~10.0.26100.9278.cat catalog. Status 0xC0000034.";
        let mut events: Vec<RawEvent> = (1..=9)
            .map(|d| ev(ci, 3004, &format!("2026-10-0{d}T10:00:00"), helper, &[]))
            .collect();
        events.push(ev(ci, 3002, "2026-10-01T10:00:00", fcon, &[]));
        events.push(ev(ci, 3010, "2026-10-01T10:00:00", cat, &[]));
        let act = actionable(&aggregate(&events, &[], NOW));
        assert_eq!(act.len(), 3);
        for g in &act {
            assert!(
                !g.title.contains(" в  ") && !g.title.contains("в  ×"),
                "{}",
                g.title
            );
        }
        let h = act.iter().find(|g| g.title.contains("3004")).unwrap();
        assert_eq!(h.class, FindingClass::Security);
        assert!(
            h.title.starts_with(
                "Code Integrity 3004 — файл DefenderSessionHelper.exe ×9 · хеш файла не найден"
            ),
            "{}",
            h.title
        );
        assert!(
            h.title
                .contains("\\Platform\\4.18.26080.4-0\\DefenderSessionHelper.exe"),
            "full path: {}",
            h.title
        );
        let f = act.iter().find(|g| g.title.contains("3002")).unwrap();
        assert!(f.title.contains("файл fcon.dll"), "{}", f.title);
        let c = act.iter().find(|g| g.title.contains("3010")).unwrap();
        assert_eq!(
            c.class,
            FindingClass::Informational,
            "a catalog not loaded is no image block"
        );
        assert!(
            c.title.contains("Containers-Client-SDN-Package"),
            "{}",
            c.title
        );
    }

    #[test]
    fn dotnet_1026_process_comes_from_the_first_line_en_and_ru() {
        let en = "Application: Probe.exe\nCoreCLR Version: 10.0.1226.42308\n.NET Version: 10.0.12\nDescription: The process was terminated due to an unhandled exception.\nException Info: System.InvalidCastException: Интерфейс не поддерживается\n   at System.Runtime.InteropServices.Marshal.ThrowExceptionForHR(Int32 errorCode)\n";
        let ru = "Приложение: DeepCool.exe\nВерсия платформы: v4.0.30319\nОписание. Процесс был завершен из-за необработанного исключения.\nСведения об исключении: код исключения c0000005, адрес исключения 00007FFEF9D5A12D\nСтек:\n";
        let mk = |m: &str, t: &str| {
            let mut e = ev(".NET Runtime", 1026, t, m, &[("param1", m)]);
            e.log = "Application".into();
            e
        };
        let aggs = aggregate(
            &[
                mk(en, "2026-10-05T10:00:00"),
                mk(en, "2026-10-06T09:00:00"),
                mk(ru, "2026-10-04T10:00:00"),
            ],
            &[],
            NOW,
        );
        let act = actionable(&aggs);
        assert_eq!(act.len(), 2, "{act:?}");
        let p = act
            .iter()
            .find(|g| g.title.starts_with("Probe.exe"))
            .expect("Probe.exe");
        assert_eq!(
            p.title,
            "Probe.exe — 2× .NET исключение · Exception System.InvalidCastException"
        );
        let d = act
            .iter()
            .find(|g| g.title.starts_with("DeepCool.exe"))
            .expect("DeepCool.exe");
        assert_eq!(
            d.title,
            "DeepCool.exe — 1× .NET исключение · Exception 0xc0000005"
        );
        for g in &act {
            assert!(!g.title.contains('\n'), "{}", g.title);
        }
    }

    #[test]
    fn dash_process_is_insufficient_data_and_never_merged() {
        let mk = |m: &str| {
            let mut e = ev(
                "Application Error",
                1000,
                "2026-10-05T10:00:00",
                m,
                &[("param1", "-"), ("param4", "-")],
            );
            e.log = "Application".into();
            e
        };
        let a = mk("Faulting application name: -, unknown 1");
        let b = mk("Faulting application name: -, unknown 2");
        let named = mk(
            "Faulting application name: foo.exe, version: 1.0.0.0, time stamp: 0x1 Faulting module name: bar.dll, version: 1.0",
        );
        let mut events = Vec::new();
        for _ in 0..15 {
            events.push(a.clone());
        }
        events.push(b);
        events.push(named);
        let act = actionable(&aggregate(&events, &[], NOW));
        assert_eq!(act.len(), 3, "{act:?}");
        for g in &act {
            assert!(
                !g.title.starts_with("- —") && !g.title.starts_with("? —"),
                "{}",
                g.title
            );
        }
        let unknown: Vec<&Actionable> = act
            .iter()
            .filter(|g| g.title.starts_with("INSUFFICIENT DATA"))
            .collect();
        assert_eq!(unknown.len(), 2, "different messages stay separate");
        assert!(unknown.iter().any(|g| g.count == 15));
        let f = act
            .iter()
            .find(|g| g.title.starts_with("foo.exe"))
            .expect("process from the message");
        assert!(f.title.contains("модуль bar.dll"), "{}", f.title);
    }

    #[test]
    fn scm_groups_show_failure_type_error_and_current_state() {
        let mk = |id: u32, svc: &str, m: &str, t: &str| {
            ev("Service Control Manager", id, t, m, &[("param1", svc)])
        };
        let mut events = Vec::new();
        for d in 1..=8 {
            events.push(mk(7034, "Energy Server Service queencreek", "The Energy Server Service queencreek service terminated unexpectedly. It has done this 2 time(s).", &format!("2026-10-0{}T01:40:12", d.min(9))));
        }
        for d in 1..=3 {
            events.push(mk(7000, "Intel(R) TPM Provisioning Service", "The Intel(R) TPM Provisioning Service service failed to start due to the following error: The system cannot find the file specified.", &format!("2026-10-0{d}T08:00:00")));
        }
        for d in 1..=4 {
            events.push(mk(7023, "Intel(R) Platform License Manager Service", "The Intel(R) Platform License Manager Service service terminated with the following error: Incorrect function.", &format!("2026-10-0{d}T08:00:00")));
        }
        let services = vec![
            ServiceInfo {
                name: "ESRV_SVC_QUEENCREEK".into(),
                display_name: "Energy Server Service queencreek".into(),
                state: "Running".into(),
                start_mode: "Auto".into(),
                path: String::new(),
            },
            ServiceInfo {
                name: "Intel(R) TPM Provisioning Service".into(),
                display_name: "Intel(R) TPM Provisioning Service".into(),
                state: "Stopped".into(),
                start_mode: "Manual".into(),
                path: String::new(),
            },
            ServiceInfo {
                name: "IntelPlatformLicenseManager".into(),
                display_name: "Intel(R) Platform License Manager Service".into(),
                state: "Stopped".into(),
                start_mode: "Auto".into(),
                path: String::new(),
            },
        ];
        let aggs = aggregate(&events, &services, NOW);
        let act = actionable(&aggs);
        assert_eq!(act.len(), 3, "one group per service: {act:?}");
        assert!(
            act.iter()
                .all(|g| g.class == FindingClass::SoftwareRecurring)
        );
        let q = act
            .iter()
            .find(|g| g.title.starts_with("ESRV_SVC_QUEENCREEK"))
            .unwrap();
        assert!(q.title.starts_with("ESRV_SVC_QUEENCREEK (Energy Server Service queencreek) — 8× SCM 7034 · неожиданно завершилась · сейчас: Running / Auto"), "{}", q.title);
        assert!(!q.title.contains("не доказывает"));
        let t = act
            .iter()
            .find(|g| g.title.contains("TPM Provisioning"))
            .unwrap();
        assert!(
            t.title.contains(
                "SCM 7000 · не запустилась · ошибка: The system cannot find the file specified"
            ),
            "{}",
            t.title
        );
        assert!(t.title.contains("сейчас: Stopped / Manual (остановленная служба не доказывает текущую неисправность)"), "{}", t.title);
        let l = act
            .iter()
            .find(|g| g.title.contains("License Manager"))
            .unwrap();
        assert!(
            l.title
                .contains("завершилась с ошибкой · ошибка: Incorrect function"),
            "{}",
            l.title
        );
        assert_eq!(l.first_seen, "2026-10-01T08:00:00");
        assert_eq!(l.last_seen, "2026-10-04T08:00:00");
    }

    #[test]
    fn collector_reads_level_and_correlation_activity_id() {
        let out = "WSD_EV {\"log\":\"Microsoft-Windows-CodeIntegrity/Operational\",\"p\":\"Microsoft-Windows-CodeIntegrity\",\"id\":3089,\"t\":\"2026-10-01T10:00:00\",\"lvl\":4,\"corr\":\"{A1B2C3D4-0000-0000-0000-000000000001}\",\"m\":\"Signature information\",\"d\":[{\"k\":\"PublisherName\",\"v\":\"Vendor\"}]}\nWSD_EV {\"log\":\"System\",\"p\":\"TPM\",\"id\":18,\"t\":\"2026-10-01T10:00:00\",\"m\":\"x\",\"d\":[]}\n";
        let (events, _) = parse_collector(out);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].level, 4);
        assert_eq!(
            events[0].correlation,
            "a1b2c3d4-0000-0000-0000-000000000001"
        );
        assert_eq!(events[1].level, 0, "older evidence without a level");
        assert!(events[1].correlation.is_empty());
        assert!(
            COLLECTOR_PS1.contains("Correlation.ActivityID")
                && COLLECTOR_PS1.contains("lvl = $lvl")
        );
        let js = to_json(&aggregate(&events, &[], NOW), None, NOW);
        assert!(js.contains("\"level\": 4"), "{js}");
        assert!(crate::deep_checks::json::parse(&js).is_some(), "valid JSON");
        assert!(
            crate::deep_checks::json::parse(SCOPE_JSON).is_some(),
            "valid scope JSON"
        );
    }
}
