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
    /// Events of the last 7 days (relative to the newest event collected),
    /// so "N in 7 days / M in 8–30 days" summaries are verifiable.
    pub count_last_7_days: u32,
    pub first_seen: String,
    pub last_seen: String,
    /// Latest messages (newest first, at most 5, truncated).
    pub latest: Vec<String>,
    /// Interpretation category (e.g. VSS "quota_eviction").
    pub category: String,
    pub service: Option<ServiceInfo>,
}

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

/// (process, module) of a Code Integrity message:
/// "a process (\…\svchost.exe) attempted to load \…\foo.dll".
pub fn ci_process_module(e: &RawEvent) -> (String, String) {
    let process = e
        .field(&["ProcessName", "RequestedFileName"])
        .map(file_part)
        .or_else(|| {
            let m = &e.message;
            let a = m.find("process (")? + "process (".len();
            let b = m[a..].find(')')? + a;
            Some(file_part(&m[a..b]))
        })
        .unwrap_or_default();
    let module = e
        .field(&["FileNameBuffer", "File Name", "FileName"])
        .map(file_part)
        .or_else(|| {
            let m = &e.message;
            for key in ["attempted to load ", "image integrity of the file "] {
                if let Some(a) = m.find(key) {
                    let rest = &m[a + key.len()..];
                    let end = rest
                        .find(" that ")
                        .or_else(|| rest.find(" because"))
                        .unwrap_or(rest.len());
                    return Some(file_part(rest[..end].trim_end_matches('.')));
                }
            }
            None
        })
        .unwrap_or_default();
    (process, module)
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
            let code = e
                .field(&["ErrorState", "AlertDesc", "Error"])
                .map(str::to_string)
                .or_else(|| {
                    let m = &e.message;
                    let a = m.find("error state is ")? + 15;
                    Some(m[a..].chars().take_while(|c| c.is_ascii_digit()).collect())
                })
                .unwrap_or_default();
            (vec![kv("ErrorCode", code)], String::new())
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
            let (process, module) = ci_process_module(e);
            (
                vec![kv("Process", process), kv("Module", module)],
                String::new(),
            )
        }
        Group::Vss => (Vec::new(), vss_category(e).to_string()),
        Group::AppErrors => {
            let app = e.field(&["param1", "AppName"]).unwrap_or("").to_string();
            let module = if e.id == 1000 {
                e.field(&["param4", "ModuleName"]).unwrap_or("").to_string()
            } else {
                String::new()
            };
            // Application Error 1000: param7 = exception code.
            let exception = if e.id == 1000 {
                e.field(&["param7", "ExceptionCode"])
                    .map(|x| {
                        let x = x.trim().trim_start_matches("0x");
                        format!("0x{}", x.to_ascii_lowercase())
                    })
                    .unwrap_or_default()
            } else {
                String::new()
            };
            (
                vec![
                    kv("Process", app),
                    kv("Module", module),
                    kv("Exception", exception),
                ],
                String::new(),
            )
        }
        Group::Tpm | Group::Other => (Vec::new(), String::new()),
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

/// Aggregates raw events (any order) by group + provider + id + key.
pub fn aggregate(events: &[RawEvent], services: &[ServiceInfo]) -> Vec<Aggregate> {
    let newest_day = events.iter().filter_map(|e| day_number(&e.time)).max();
    let mut out: Vec<Aggregate> = Vec::new();
    let mut sorted: Vec<&RawEvent> = events.iter().collect();
    // Newest first, so "latest" messages and last_seen come first.
    sorted.sort_by(|a, b| b.time.cmp(&a.time));
    for e in sorted {
        // Successful Windows Update installs (19) are not evidence of a
        // problem: they only decide whether a failure (20) is historical
        // (`wu_failure_is_historical`), never an aggregate of their own.
        if e.id == 19
            && e.provider
                .to_ascii_lowercase()
                .contains("windowsupdateclient")
        {
            continue;
        }
        let group = group_of(e);
        let (key, category) = key_of(group, e);
        // Identity = key without attribute fields (SCM timeout values).
        let ident = |k: &[(String, String)]| -> Vec<(String, String)> {
            k.iter()
                .filter(|(n, _)| n != "TimeoutMs")
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
                });
                out.last_mut().unwrap()
            }
        };
        // Attribute values (e.g. SCM timeouts 30000 / 45000) are collected,
        // not used for grouping.
        for (k, v) in key
            .iter()
            .filter(|(k, v)| k == "TimeoutMs" && !v.is_empty())
        {
            if !a
                .key
                .iter()
                .any(|(ak, av)| ak == k && av.split(',').any(|x| x == v))
            {
                if let Some(slot) = a.key.iter_mut().find(|(ak, _)| ak == k) {
                    slot.1 = format!("{},{v}", slot.1);
                } else {
                    a.key.push((k.clone(), v.clone()));
                }
            }
        }
        a.count += 1;
        if let (Some(day), Some(newest)) = (day_number(&e.time), newest_day)
            && newest - day < 7
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
    /// Old or self-resolved activity (historical WU failure, VSS quota,
    /// idle shutdowns, single service hiccups).
    Historical,
}

impl FindingClass {
    pub fn code(self) -> &'static str {
        match self {
            FindingClass::SoftwareRecurring => "SOFTWARE_RECURRING",
            FindingClass::Security => "SECURITY",
            FindingClass::Historical => "HISTORICAL",
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
pub fn actionable(aggs: &[Aggregate], wu_historical: Option<bool>) -> Vec<Actionable> {
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
                let mut title = format!("{name} — {}× SCM {}", a.count, a.id);
                if orphan {
                    title.push_str(" · служба не найдена (остаточная запись)");
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
                let process = if process.is_empty() { "?" } else { process };
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
                let module = key_val(a, "Module");
                if !module.is_empty() {
                    title.push_str(&format!(" · модуль {module}"));
                }
                out.push(base(FindingClass::SoftwareRecurring, title));
            }
            Group::CodeIntegrityUser | Group::CodeIntegrityKernel => {
                let title = format!(
                    "Code Integrity {} — {} в {} ×{}",
                    a.id,
                    key_val(a, "Module"),
                    key_val(a, "Process"),
                    a.count
                );
                out.push(base(FindingClass::Security, title));
            }
            Group::Tpm if a.count >= RECURRENCE_MIN => {
                out.push(base(
                    FindingClass::SoftwareRecurring,
                    format!("{} {} — {}×", a.provider, a.id, a.count),
                ));
            }
            Group::WindowsUpdate => {
                let class = if wu_historical == Some(true) {
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

/// Windows Update Event 20: a historical failure is not a currently broken
/// Windows Update. Current = no successful install (Event 19) after the
/// newest failure.
pub fn wu_failure_is_historical(events: &[RawEvent]) -> Option<bool> {
    let wu = |id: u32| {
        events
            .iter()
            .filter(move |e| {
                e.provider
                    .to_ascii_lowercase()
                    .contains("windowsupdateclient")
                    && e.id == id
            })
            .map(|e| e.time.as_str())
            .max()
    };
    let last_fail = wu(20)?;
    Some(wu(19).is_some_and(|ok| ok > last_fail))
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
                "    {{\"group\": {}, \"provider\": {}, \"event_id\": {}, \"category\": {}, \"key\": {{{}}}, \"count\": {}, \"count_last_7_days\": {}, \"first_seen\": {}, \"last_seen\": {}, \"latest_messages\": [{}], \"service\": {}}}",
                json::string(a.group.map(Group::code).unwrap_or("other")),
                json::string(&a.provider),
                a.id,
                json::string(&a.category),
                key.join(", "),
                a.count,
                a.count_last_7_days,
                json::string(&a.first_seen),
                json::string(&a.last_seen),
                latest.join(", "),
                svc
            )
        })
        .collect();
    let groups: Vec<String> = actionable(aggs, wu_historical)
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
pub const SCOPE_JSON: &str = "{\"window_days\": 30, \"logs\": [\"System\", \"Application\", \"Microsoft-Windows-CodeIntegrity/Operational\"], \"queries\": [\"System/Schannel\", \"System/Microsoft-Windows-WindowsUpdateClient 19,20\", \"System/Microsoft-Windows-TPM-WMI\", \"System/TPM\", \"System/Service Control Manager 7000,7001,7009,7011,7023,7024,7031,7034\", \"Application/SideBySide 33,35,59,63,80\", \"CodeIntegrity/Operational 3001,3002,3004,3010,3023,3033,3034,3063,3077,3089\", \"Application/VSS\", \"System/volsnap\", \"Application/Application Error 1000\", \"Application/Application Hang 1002\", \"Application/.NET Runtime 1026\"], \"max_events_per_query\": 1500, \"grouping\": \"provider + event id + identity key (SCM: service name, timeout is an attribute; applications: process + module + exception; Code Integrity: process + module)\"}";

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
        if ($e.ProviderName -eq 'Service Control Manager' -and $data.Count -gt 0) {
            $si = if ([int]$e.Id -in @(7009, 7011) -and $data.Count -ge 2) { 1 } else { 0 }
            [void]$svcNames.Add([string]$data[$si].v)
        }
        $o = [ordered]@{ log = [string]$e.LogName; p = [string]$e.ProviderName; id = [int]$e.Id; t = $e.TimeCreated.ToString('s'); m = $msg; d = @($data) }
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
        let aggs = aggregate(&events, &services);
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
        let aggs = aggregate(std::slice::from_ref(&fail), &[]);
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
        assert_eq!(wu_failure_is_historical(&[fail.clone(), ok]), Some(true));
        assert_eq!(
            wu_failure_is_historical(std::slice::from_ref(&fail)),
            Some(false)
        );
        assert_eq!(wu_failure_is_historical(&[]), None);
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
        let aggs = aggregate(&events, &[]);
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
        let aggs = aggregate(&[e.clone(), e], &[]);
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
        let aggs = aggregate(&events, &services);
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
        let quota = aggregate(&spread, &[]);
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
        let aggs = aggregate(&[mk("sdwra_1_2"), mk("sdwra_3_4"), mk("sdwra_5_6")], &[]);
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
        let act = actionable(&aggregate(&events, &[svc]), None);
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
        let a = actionable(&aggregate(&orphan, &[]), None);
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
        let act = actionable(&aggregate(&[e], &[]), None);
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
        let act = actionable(&aggregate(&[idle, quota], &[]), None);
        assert!(
            act.iter().all(|a| a.class == FindingClass::Historical),
            "{act:?}"
        );
    }
}
