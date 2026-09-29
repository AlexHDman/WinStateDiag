//! Driver Audit — read-only check of the drivers that matter for system
//! stability (display/GPU, chipset/system, storage, network, audio and
//! kernel drivers that show up in failure evidence).
//!
//! Collection is done by the embedded, read-only `DriverAudit.ps1`
//! (Get-CimInstance + Get-WinEvent only). Everything else — parsing,
//! correlation, severity, summary and the report — is pure Rust in this
//! module, so it is unit tested without Windows.
//!
//! Status rules (never age-based):
//! * PROBLEM — concrete evidence of a fault: a current PnP device error,
//!   a crash whose faulting module belongs to the driver, a Code Integrity
//!   failure of a kernel driver, or a boot driver that failed to load and is
//!   not running now.
//! * WARNING — evidence of a risk that is not a confirmed fault: display
//!   driver timeouts that recovered (TDR), a load failure in the past for a
//!   device that works now, an unsigned driver, a display adapter running on
//!   the Microsoft basic driver, a Code Integrity event for a user-mode
//!   component of the driver.
//! * OK — no such evidence. An old driver date alone is never a finding.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

#[cfg_attr(not(windows), allow(dead_code))]
pub const COLLECTOR_PS1: &[u8] = include_bytes!("../embedded/WinStateDiag/DriverAudit.ps1");
pub const SCHEMA: &str = "winstatediag.driver_audit/1";
/// Event look-back window passed to the collector.
pub const WINDOW_DAYS: u32 = 30;

// ---------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub enum Severity {
    #[default]
    Ok,
    Warning,
    Problem,
}

impl Severity {
    pub fn code(self) -> &'static str {
        match self {
            Severity::Ok => "OK",
            Severity::Warning => "WARNING",
            Severity::Problem => "PROBLEM",
        }
    }
    pub fn label_ru(self) -> &'static str {
        match self {
            Severity::Ok => "OK",
            Severity::Warning => "Внимание",
            Severity::Problem => "Проблема",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Category {
    Display,
    Chipset,
    Audio,
    Network,
    Storage,
    KernelDriver,
    Other,
}

impl Category {
    pub fn code(self) -> &'static str {
        match self {
            Category::Display => "display",
            Category::Chipset => "chipset",
            Category::Audio => "audio",
            Category::Network => "network",
            Category::Storage => "storage",
            Category::KernelDriver => "kernel_driver",
            Category::Other => "other",
        }
    }
}

/// One `DEV` record from the collector.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct RawDevice {
    pub class: String,
    pub name: String,
    pub manufacturer: String,
    pub provider: String,
    pub version: String,
    pub date: String,
    pub inf: String,
    pub error_code: Option<u32>,
    pub signed: Option<bool>,
    pub pnp_id: String,
    pub service: String,
}

/// One `SYS` record (Win32_SystemDriver).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct RawSysDriver {
    pub name: String,
    pub display_name: String,
    pub path: String,
    pub state: String,
    pub start_mode: String,
    /// "Kernel Driver", "File System Driver", ...
    pub service_type: String,
}

/// One `DRVFILE` record: read-only facts about the image of a driver named
/// in SCM 7026.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct RawDriverFile {
    pub service: String,
    pub path: String,
    pub exists: bool,
    /// Authenticode status ("Valid", "NotSigned", "HashMismatch", ...).
    pub signature: String,
    pub signer: String,
    pub company: String,
    pub version: String,
}

/// One `EVT` record.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct RawEvent {
    pub tag: String,
    pub id: u32,
    pub time: String,
    pub provider: String,
    pub props: Vec<String>,
    pub message: String,
    /// Windows event level: 1 critical, 2 error, 3 warning, 4 information.
    pub level: Option<u32>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct RawAudit {
    pub generated: String,
    pub window_days: u32,
    pub complete: bool,
    pub devices: Vec<RawDevice>,
    pub sys_drivers: Vec<RawSysDriver>,
    pub driver_files: Vec<RawDriverFile>,
    pub events: Vec<RawEvent>,
    pub errors: Vec<String>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EvidenceKind {
    PnpError,
    Crash,
    CodeIntegrity,
    BootDriverLoadFailure,
    DeviceLoadFailure,
    DisplayTimeout,
    Unsigned,
    BasicDriver,
    Disabled,
    ExpectedInactive,
}

impl EvidenceKind {
    pub fn code(self) -> &'static str {
        match self {
            EvidenceKind::PnpError => "pnp_error",
            EvidenceKind::Crash => "crash",
            EvidenceKind::CodeIntegrity => "code_integrity",
            EvidenceKind::BootDriverLoadFailure => "boot_driver_load_failure",
            EvidenceKind::DeviceLoadFailure => "device_driver_load_failure",
            EvidenceKind::DisplayTimeout => "display_timeout_recovered",
            EvidenceKind::Unsigned => "unsigned_driver",
            EvidenceKind::BasicDriver => "basic_microsoft_driver",
            EvidenceKind::Disabled => "device_disabled",
            EvidenceKind::ExpectedInactive => "expected_inactive_driver",
        }
    }
}

/// A concrete, deduplicated piece of evidence.
#[derive(Clone, Debug, PartialEq)]
pub struct Evidence {
    pub kind: EvidenceKind,
    pub severity: Severity,
    /// "Application / Application Error", "System / Display", "PnP" ...
    pub source: String,
    pub event_id: Option<u32>,
    pub first_seen: String,
    pub last_seen: String,
    pub count: u32,
    pub module: String,
    pub module_version: String,
    pub exception: String,
    pub process: String,
    /// Human-readable reason (Russian), shown in the UI and the report.
    pub reason: String,
}

impl Evidence {
    fn fact(kind: EvidenceKind, severity: Severity, source: &str, reason: String) -> Self {
        Self {
            kind,
            severity,
            source: source.into(),
            event_id: None,
            first_seen: String::new(),
            last_seen: String::new(),
            count: 1,
            module: String::new(),
            module_version: String::new(),
            exception: String::new(),
            process: String::new(),
            reason,
        }
    }

    fn dedup_key(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}|{}",
            self.kind.code(),
            self.event_id.unwrap_or(0),
            self.module.to_lowercase(),
            self.module_version,
            self.exception.to_lowercase(),
            self.process.to_lowercase()
        )
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct AuditItem {
    pub category: Category,
    /// Short label for the dashboard ("Intel UHD Graphics 630", "Аудио (Realtek)").
    pub label: String,
    pub device: String,
    pub vendor: String,
    pub provider: String,
    pub version: String,
    pub date: String,
    pub inf: String,
    pub service: String,
    pub pnp_id: String,
    pub pnp_error_code: Option<u32>,
    pub signed: Option<bool>,
    pub status: Severity,
    pub evidence: Vec<Evidence>,
}

impl AuditItem {
    fn recompute_status(&mut self) {
        self.status = self
            .evidence
            .iter()
            .map(|e| e.severity)
            .max()
            .unwrap_or(Severity::Ok);
    }

    /// Adds evidence, merging duplicates (same kind/event/module/version/
    /// exception/process) into one entry with a count and first/last time.
    pub fn add_evidence(&mut self, ev: Evidence) {
        let key = ev.dedup_key();
        if let Some(existing) = self.evidence.iter_mut().find(|e| e.dedup_key() == key) {
            existing.count += ev.count;
            if !ev.first_seen.is_empty()
                && (existing.first_seen.is_empty() || ev.first_seen < existing.first_seen)
            {
                existing.first_seen = ev.first_seen.clone();
            }
            if ev.last_seen > existing.last_seen {
                existing.last_seen = ev.last_seen.clone();
            }
            existing.severity = existing.severity.max(ev.severity);
        } else {
            self.evidence.push(ev);
        }
        self.recompute_status();
    }

    /// Main reason for the status (most severe evidence first).
    pub fn primary_reason(&self) -> Option<&Evidence> {
        self.evidence
            .iter()
            .filter(|e| e.severity == self.status && self.status != Severity::Ok)
            .max_by_key(|e| e.count)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct AuditReport {
    pub generated: String,
    pub window_days: u32,
    pub complete: bool,
    pub devices_scanned: usize,
    pub overall: Severity,
    /// Audited drivers: the relevant categories plus anything with evidence.
    pub items: Vec<AuditItem>,
    /// Evidence that could not be attributed to a present device/driver.
    /// Reported for context only; it never changes a status.
    pub unattributed: Vec<Evidence>,
    /// Drivers that are inactive by design (only an informational SCM 7026,
    /// intact Microsoft-signed image, valid configuration, no failures).
    /// Internal INFO: not an item, not counted, not in the text report.
    pub expected_inactive: Vec<Evidence>,
    pub errors: Vec<String>,
}

impl AuditReport {
    pub fn count(&self, s: Severity) -> usize {
        self.items.iter().filter(|i| i.status == s).count()
    }
}

// ---------------------------------------------------------------------
// Parsing the collector output
// ---------------------------------------------------------------------

fn parse_bool(s: &str) -> Option<bool> {
    match s.trim().to_ascii_lowercase().as_str() {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

pub fn parse_collector_output(text: &str) -> RawAudit {
    let mut raw = RawAudit {
        window_days: WINDOW_DAYS,
        ..Default::default()
    };
    for line in text.lines() {
        let line = line.trim_start_matches('\u{feff}').trim_end_matches('\r');
        let f: Vec<&str> = line.split('\t').collect();
        let get = |i: usize| f.get(i).map(|s| s.trim().to_string()).unwrap_or_default();
        match f.first().copied() {
            Some("META") => match get(1).as_str() {
                "generated" => raw.generated = get(2),
                "window_days" => raw.window_days = get(2).parse().unwrap_or(WINDOW_DAYS),
                "done" => raw.complete = true,
                _ => {}
            },
            Some("DEV") => raw.devices.push(RawDevice {
                class: get(1),
                name: get(2),
                manufacturer: get(3),
                provider: get(4),
                version: get(5),
                date: get(6),
                inf: get(7),
                error_code: get(8).parse().ok(),
                signed: parse_bool(&get(9)),
                pnp_id: get(10),
                service: get(11),
            }),
            Some("SYS") => raw.sys_drivers.push(RawSysDriver {
                name: get(1),
                display_name: get(2),
                path: get(3),
                state: get(4),
                start_mode: get(5),
                service_type: get(6),
            }),
            Some("DRVFILE") => raw.driver_files.push(RawDriverFile {
                service: get(1),
                path: get(2),
                exists: parse_bool(&get(3)) == Some(true),
                signature: get(4),
                signer: get(5),
                company: get(6),
                version: get(7),
            }),
            Some("EVT") => raw.events.push(RawEvent {
                tag: get(1),
                id: get(2).parse().unwrap_or(0),
                time: get(3),
                provider: get(4),
                props: get(5).split(" | ").map(|s| s.trim().to_string()).collect(),
                message: get(6),
                level: get(7).parse().ok(),
            }),
            Some("ERR") => raw.errors.push(format!("{}: {}", get(1), get(2))),
            _ => {}
        }
    }
    raw
}

// ---------------------------------------------------------------------
// Categorisation and labels
// ---------------------------------------------------------------------

fn contains_any(hay: &str, needles: &[&str]) -> bool {
    let h = hay.to_lowercase();
    needles.iter().any(|n| h.contains(&n.to_lowercase()))
}

const VIRTUAL_NET: &[&str] = &[
    "wan miniport",
    "virtual",
    "kernel debug",
    "loopback",
    "hyper-v",
    "vpn",
    "tap-",
    "wintun",
    "wi-fi direct",
    "teredo",
    "6to4",
    "ip-https",
    "bluetooth device",
    "remote ndis",
];

const CHIPSET_KEYWORDS: &[&str] = &[
    "chipset",
    "smbus",
    "lpc",
    "espi",
    "pci express root",
    "management engine",
    "mei ",
    "serial io",
    "gpio",
    "host bridge",
    "dram",
    "spi (flash)",
    "thermal subsystem",
    "psp",
    "amd gpio",
    "platform",
    "pcie controller",
];

pub fn categorize(dev: &RawDevice) -> Category {
    let class = dev.class.to_ascii_lowercase();
    let name = &dev.name;
    let vendorish = format!("{} {}", dev.manufacturer, dev.provider);
    match class.as_str() {
        "display" => Category::Display,
        "scsiadapter" | "hdc" => Category::Storage,
        "net" => {
            if contains_any(name, VIRTUAL_NET) {
                Category::Other
            } else {
                Category::Network
            }
        }
        "media" => Category::Audio,
        "system" => {
            if contains_any(
                &vendorish,
                &["intel", "amd", "advanced micro devices", "nvidia"],
            ) && contains_any(name, CHIPSET_KEYWORDS)
            {
                Category::Chipset
            } else {
                Category::Other
            }
        }
        _ => Category::Other,
    }
}

/// Removes ®/™/(R)/(TM) and doubled spaces.
pub fn clean_name(name: &str) -> String {
    let mut s = name.to_string();
    for t in ["(R)", "(r)", "(TM)", "(tm)", "®", "™"] {
        s = s.replace(t, "");
    }
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn is_generic_vendor(v: &str) -> bool {
    let l = v.to_lowercase();
    l.is_empty()
        || l.starts_with("(standard")
        || l.starts_with("(стандарт")
        || l.contains("стандартн")
        || l == "microsoft"
        || l.starts_with("generic")
}

/// Best vendor name for a device: manufacturer unless generic, then the
/// driver provider, then "Microsoft".
pub fn vendor_of(dev: &RawDevice) -> String {
    let pick = if !is_generic_vendor(&dev.manufacturer) {
        dev.manufacturer.clone()
    } else if !is_generic_vendor(&dev.provider) {
        dev.provider.clone()
    } else if !dev.provider.is_empty() || !dev.manufacturer.is_empty() {
        "Microsoft".to_string()
    } else {
        String::new()
    };
    let first = clean_name(&pick);
    // "Intel Corporation" -> "Intel", "Realtek Semiconductor Corp." -> "Realtek"
    let short = first
        .split([' ', ','])
        .next()
        .unwrap_or_default()
        .to_string();
    if short.eq_ignore_ascii_case("advanced") {
        "AMD".into()
    } else {
        short
    }
}

fn short_label(cat: Category, dev: &RawDevice) -> String {
    let vendor = vendor_of(dev);
    let with_vendor = |base: &str| {
        if vendor.is_empty() {
            base.to_string()
        } else {
            format!("{base} ({vendor})")
        }
    };
    match cat {
        Category::Display => clean_name(&dev.name),
        Category::Chipset => with_vendor("Чипсет"),
        Category::Audio => with_vendor("Аудио"),
        Category::Network => {
            let kind = if contains_any(&dev.name, &["wi-fi", "wifi", "wireless", "wlan", "802.11"])
            {
                "Wi-Fi"
            } else {
                "Ethernet"
            };
            if vendor.is_empty() {
                format!("Сеть ({kind})")
            } else {
                format!("Сеть ({vendor} {kind})")
            }
        }
        Category::Storage => {
            let base = if contains_any(&dev.name, &["nvm", "nvme"]) {
                "NVMe"
            } else if contains_any(&dev.name, &["raid", "rst", "optane", "vmd"]) {
                "RAID/VMD"
            } else if contains_any(&dev.name, &["sata", "ahci"]) {
                "SATA"
            } else {
                "Накопители"
            };
            with_vendor(base)
        }
        Category::KernelDriver | Category::Other => clean_name(&dev.name),
    }
}

fn pnp_error_text(code: u32) -> &'static str {
    match code {
        1 => "устройство настроено неправильно",
        3 => "драйвер повреждён или не хватает ресурсов",
        10 => "устройство не может запуститься",
        12 => "недостаточно свободных ресурсов",
        14 => "требуется перезагрузка",
        18 => "требуется переустановка драйвера",
        19 => "повреждены сведения о конфигурации в реестре",
        21 => "устройство удаляется",
        28 => "драйверы не установлены",
        29 => "устройство отключено микропрограммой",
        31 => "Windows не может загрузить драйвер",
        32 => "служба драйвера отключена",
        37 => "драйвер вернул ошибку при инициализации",
        39 => "драйвер повреждён или отсутствует",
        40 => "повреждены сведения о службе драйвера в реестре",
        41 => "драйвер загружен, но устройство не найдено",
        43 => "устройство сообщило о сбое",
        48 => "драйвер заблокирован из-за известных проблем",
        52 => "не удалось проверить цифровую подпись драйвера",
        _ => "ошибка устройства",
    }
}

// ---------------------------------------------------------------------
// Module/driver -> device correlation
// ---------------------------------------------------------------------

/// User-mode and kernel components of display drivers, by file-name prefix.
const DISPLAY_MODULES: &[(&str, &[&str])] = &[
    (
        "intel",
        &[
            "igvk", "igd", "igc", "igx", "igfx", "ig9icd", "ig8icd", "ig7icd", "ig75icd", "ig4icd",
            "igxelp", "igxess",
        ],
    ),
    (
        "nvidia",
        &[
            "nvwgf",
            "nvldumd",
            "nvoglv",
            "nvd3dum",
            "nvapi",
            "nvcuda",
            "nvlddmkm",
            "nvgpucomp",
            "nvcuvid",
            "nvencodeapi",
            "nvumdshim",
            "nvppe",
            "nvofapi",
            "nvrtum",
        ],
    ),
    (
        "amd",
        &[
            "atiumd", "atidxx", "atiadl", "aticfx", "atio6axx", "atig6", "amdxc", "amdxx",
            "amdvlk", "amdkmdag", "amdkmdap", "amdihk", "atikmdag", "amdenc", "amfrt",
        ],
    ),
];

fn file_stem_lower(path_or_name: &str) -> String {
    let base = path_or_name
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(path_or_name)
        .trim()
        .to_lowercase();
    match base.rsplit_once('.') {
        Some((stem, _)) => stem.to_string(),
        None => base,
    }
}

fn file_name(path_or_name: &str) -> String {
    path_or_name
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(path_or_name)
        .trim()
        .to_string()
}

/// Vendor keyword of the display driver a module belongs to, if any.
pub fn display_vendor_for_module(module: &str) -> Option<&'static str> {
    let stem = file_stem_lower(module);
    DISPLAY_MODULES
        .iter()
        .find(|(_, prefixes)| prefixes.iter().any(|p| stem.starts_with(p)))
        .map(|(v, _)| *v)
}

fn device_matches_vendor(dev: &AuditItem, vendor: &str) -> bool {
    let hay = format!("{} {} {}", dev.device, dev.vendor, dev.provider).to_lowercase();
    match vendor {
        "amd" => hay.contains("amd") || hay.contains("advanced micro") || hay.contains("ati "),
        v => hay.contains(v),
    }
}

// ---------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------

fn item_from_device(cat: Category, dev: &RawDevice) -> AuditItem {
    AuditItem {
        category: cat,
        label: short_label(cat, dev),
        device: clean_name(&dev.name),
        vendor: vendor_of(dev),
        provider: dev.provider.clone(),
        version: dev.version.clone(),
        date: dev.date.clone(),
        inf: dev.inf.clone(),
        service: dev.service.clone(),
        pnp_id: dev.pnp_id.clone(),
        pnp_error_code: dev.error_code,
        signed: dev.signed,
        status: Severity::Ok,
        evidence: Vec::new(),
    }
}

fn device_facts(item: &mut AuditItem, dev: &RawDevice) {
    match dev.error_code {
        None | Some(0) => {}
        Some(22) => item.add_evidence(Evidence::fact(
            EvidenceKind::Disabled,
            Severity::Ok,
            "PnP",
            "устройство отключено (код 22) — не считается неисправностью".into(),
        )),
        Some(code) => {
            let mut ev = Evidence::fact(
                EvidenceKind::PnpError,
                Severity::Problem,
                "PnP",
                format!(
                    "ошибка устройства PnP, код {code}: {}",
                    pnp_error_text(code)
                ),
            );
            ev.detail_code(code);
            item.add_evidence(ev);
        }
    }
    if dev.signed == Some(false) {
        item.add_evidence(Evidence::fact(
            EvidenceKind::Unsigned,
            Severity::Warning,
            "Win32_PnPSignedDriver",
            "драйвер не имеет действительной цифровой подписи".into(),
        ));
    }
    if item.category == Category::Display
        && (contains_any(&dev.name, &["basic display", "basic render"])
            || (dev.inf.eq_ignore_ascii_case("display.inf")
                && dev.provider.eq_ignore_ascii_case("microsoft")))
    {
        item.add_evidence(Evidence::fact(
            EvidenceKind::BasicDriver,
            Severity::Warning,
            "Win32_PnPSignedDriver",
            "видеоадаптер работает на базовом драйвере Microsoft — драйвер производителя не установлен"
                .into(),
        ));
    }
}

impl Evidence {
    fn detail_code(&mut self, code: u32) {
        self.exception = format!("CM_PROB {code}");
    }
    fn from_event(
        kind: EvidenceKind,
        severity: Severity,
        ev: &RawEvent,
        source: &str,
        reason: String,
    ) -> Self {
        Self {
            kind,
            severity,
            source: source.into(),
            event_id: Some(ev.id),
            first_seen: ev.time.clone(),
            last_seen: ev.time.clone(),
            count: 1,
            module: String::new(),
            module_version: String::new(),
            exception: String::new(),
            process: String::new(),
            reason,
        }
    }
}

pub const HISTORICAL_PREFIX: &str =
    "Историческая ошибка предыдущей версии — на текущий статус не влияет";

fn parse_version(v: &str) -> Option<Vec<u64>> {
    let parts: Option<Vec<u64>> = v.trim().split('.').map(|p| p.trim().parse().ok()).collect();
    parts.filter(|p| p.len() >= 2)
}

/// `Some(current version)` when the crashing module version is OLDER than
/// every matching installed display driver. Only for vendors whose user-mode
/// module version equals the driver version (Intel, NVIDIA); anything
/// unparsable, equal or newer stays a current problem.
fn superseded_by(
    vendor: &str,
    module_version: &str,
    targets: &[usize],
    items: &[AuditItem],
) -> Option<String> {
    if !matches!(vendor, "intel" | "nvidia") || targets.is_empty() {
        return None;
    }
    let old = parse_version(module_version)?;
    let mut current = None;
    for &i in targets {
        let installed = parse_version(&items[i].version)?;
        if installed <= old {
            return None;
        }
        current = Some(items[i].version.clone());
    }
    current
}

fn prop(ev: &RawEvent, i: usize) -> String {
    ev.props.get(i).cloned().unwrap_or_default()
}

fn normalise_exception(s: &str) -> String {
    let t = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    if t.is_empty() {
        String::new()
    } else {
        format!("0x{}", t.to_uppercase())
    }
}

struct Ctx<'a> {
    items: Vec<AuditItem>,
    sys: &'a [RawSysDriver],
    files: &'a [RawDriverFile],
    events: &'a [RawEvent],
    unattributed: Vec<Evidence>,
    expected_inactive: Vec<Evidence>,
}

impl Ctx<'_> {
    /// Items whose service / sys-driver name matches a driver name.
    fn by_driver_name(&self, driver: &str) -> Vec<usize> {
        let d = file_stem_lower(driver);
        if d.is_empty() {
            return Vec::new();
        }
        self.items
            .iter()
            .enumerate()
            .filter(|(_, it)| it.service.to_lowercase() == d)
            .map(|(i, _)| i)
            .collect()
    }

    fn sys_driver(&self, driver: &str) -> Option<&RawSysDriver> {
        let d = file_stem_lower(driver);
        self.sys.iter().find(|s| {
            s.name.to_lowercase() == d
                || file_stem_lower(&s.path) == d
                || s.display_name.eq_ignore_ascii_case(driver.trim())
        })
    }

    /// Kernel-driver item for a system driver not tied to a listed device.
    fn kernel_item(&mut self, driver: &str) -> usize {
        let sd = self.sys_driver(driver).cloned();
        let name = sd
            .as_ref()
            .map(|s| s.name.clone())
            .unwrap_or_else(|| file_stem_lower(driver));
        if let Some(i) = self.items.iter().position(|it| {
            it.category == Category::KernelDriver && it.service.eq_ignore_ascii_case(&name)
        }) {
            return i;
        }
        let display = sd
            .as_ref()
            .map(|s| s.display_name.clone())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| name.clone());
        self.items.push(AuditItem {
            category: Category::KernelDriver,
            label: format!("Драйвер {}", file_name(driver)),
            device: display,
            vendor: String::new(),
            provider: String::new(),
            version: String::new(),
            date: String::new(),
            inf: String::new(),
            service: name,
            pnp_id: String::new(),
            pnp_error_code: None,
            signed: None,
            status: Severity::Ok,
            evidence: Vec::new(),
        });
        self.items.len() - 1
    }

    /// Display items for a module/driver: exact driver-version match wins,
    /// otherwise every display device of that vendor.
    fn display_targets(&self, vendor: &str, version: &str) -> Vec<usize> {
        let candidates: Vec<usize> = self
            .items
            .iter()
            .enumerate()
            .filter(|(_, it)| it.category == Category::Display && device_matches_vendor(it, vendor))
            .map(|(i, _)| i)
            .collect();
        let exact: Vec<usize> = candidates
            .iter()
            .copied()
            .filter(|&i| !version.is_empty() && self.items[i].version == version)
            .collect();
        if exact.is_empty() { candidates } else { exact }
    }

    fn display_placeholder(&mut self, vendor: &str, module: &str) -> usize {
        let vendor_name = match vendor {
            "intel" => "Intel",
            "nvidia" => "NVIDIA",
            "amd" => "AMD",
            v => v,
        };
        self.items.push(AuditItem {
            category: Category::Display,
            label: format!("{vendor_name} Graphics"),
            device: format!("{vendor_name} Graphics (устройство не найдено, модуль {module})"),
            vendor: vendor_name.into(),
            provider: String::new(),
            version: String::new(),
            date: String::new(),
            inf: String::new(),
            service: String::new(),
            pnp_id: String::new(),
            pnp_error_code: None,
            signed: None,
            status: Severity::Ok,
            evidence: Vec::new(),
        });
        self.items.len() - 1
    }

    fn attach(&mut self, targets: &[usize], ev: &Evidence) {
        for &i in targets {
            self.items[i].add_evidence(ev.clone());
        }
    }

    fn expected_inactive_note(&mut self, ev: Evidence) {
        let key = ev.dedup_key();
        if let Some(e) = self
            .expected_inactive
            .iter_mut()
            .find(|e| e.dedup_key() == key)
        {
            e.count += 1;
            if ev.first_seen < e.first_seen {
                e.first_seen = ev.first_seen;
            }
            if ev.last_seen > e.last_seen {
                e.last_seen = ev.last_seen;
            }
        } else {
            self.expected_inactive.push(ev);
        }
    }

    fn unattributed(&mut self, mut ev: Evidence) {
        // Context only: never changes a status.
        ev.severity = Severity::Ok;
        let key = ev.dedup_key();
        if let Some(e) = self.unattributed.iter_mut().find(|e| e.dedup_key() == key) {
            e.count += 1;
            if ev.first_seen < e.first_seen {
                e.first_seen = ev.first_seen;
            }
            if ev.last_seen > e.last_seen {
                e.last_seen = ev.last_seen;
            }
        } else {
            self.unattributed.push(ev);
        }
    }
}

/// Is this SCM 7026 driver inactive by design? `Ok(detail)` only when ALL
/// facts are confirmed; otherwise `Err(failed checks)` and the normal
/// severity rules apply. Driver state (e.g. STOPPED, exit code 31) is not a
/// fault on its own and is not part of the test.
fn expected_inactive_check(
    ctx: &Ctx<'_>,
    name: &str,
    ev: &RawEvent,
) -> Result<String, Vec<String>> {
    let mut failed = Vec::new();
    if ev.level != Some(4) {
        failed.push("событие 7026 не информационное".to_string());
    }
    let stem = file_stem_lower(name);
    let Some(sd) = ctx.sys_driver(name) else {
        return Err(vec!["служба драйвера не найдена".into()]);
    };
    if !sd.service_type.eq_ignore_ascii_case("Kernel Driver") {
        failed.push(format!("тип службы «{}»", sd.service_type));
    }
    let image = file_name(&sd.path).to_lowercase();
    if !image.ends_with(".sys") || file_stem_lower(&image) != sd.name.to_lowercase() {
        failed.push(format!(
            "ImagePath «{}» не указывает на {}.sys",
            sd.path, sd.name
        ));
    }
    match ctx
        .files
        .iter()
        .find(|f| f.service.eq_ignore_ascii_case(&sd.name))
    {
        None => failed.push("нет сведений о файле драйвера".into()),
        Some(f) => {
            if !f.exists {
                failed.push(format!("файл {} отсутствует", f.path));
            } else {
                if file_name(&f.path).to_lowercase() != image {
                    failed.push("файл не совпадает с ImagePath".into());
                }
                if !f.signature.eq_ignore_ascii_case("Valid") {
                    failed.push(format!("подпись: {}", f.signature));
                } else if !f.signer.to_lowercase().contains("microsoft") {
                    failed.push("подпись не Microsoft".into());
                }
            }
        }
    }
    let mentions = |e: &RawEvent| {
        e.props.iter().any(|p| {
            p.split(|c: char| c.is_whitespace() || c == ',' || c == '\\')
                .any(|t| {
                    let t = t.trim().to_lowercase();
                    t == stem || t == format!("{stem}.sys")
                })
                || p.trim().eq_ignore_ascii_case(sd.display_name.trim())
        })
    };
    if ctx.events.iter().any(|e| e.tag == "CI" && mentions(e)) {
        failed.push("есть события Code Integrity".into());
    }
    if ctx
        .events
        .iter()
        .any(|e| (e.tag == "SCM7000" || e.tag == "SCMERR") && mentions(e))
    {
        failed.push("есть ошибки запуска службы (SCM 7000/7001/7009)".into());
    }
    if ctx
        .events
        .iter()
        .any(|e| e.tag == "SCM7026" && e.level != Some(4) && mentions(e))
    {
        failed.push("есть неинформационные события 7026".into());
    }
    if failed.is_empty() {
        let label = if sd.display_name.is_empty() {
            sd.name.clone()
        } else {
            sd.display_name.clone()
        };
        Ok(format!(
            "{label}: драйвер сейчас неактивен (ожидаемо); файл, конфигурация и цифровая подпись Microsoft в порядке. Исправление не требуется."
        ))
    } else {
        Err(failed)
    }
}

fn apply_event(ctx: &mut Ctx<'_>, ev: &RawEvent) {
    match ev.tag.as_str() {
        "APPCRASH" => {
            // Application Error 1000: 0 app, 1 app version, 3 module,
            // 4 module version, 6 exception code, 11 module path.
            let module = prop(ev, 3);
            let Some(vendor) = display_vendor_for_module(&module) else {
                return; // not a driver component: not driver evidence
            };
            let version = prop(ev, 4);
            let exception = normalise_exception(&prop(ev, 6));
            let process = prop(ev, 0);
            let mut e = Evidence::from_event(
                EvidenceKind::Crash,
                Severity::Problem,
                ev,
                "Application / Application Error",
                format!(
                    "сбой приложения {process} в модуле видеодрайвера {module} {version}{}",
                    if exception.is_empty() {
                        String::new()
                    } else {
                        format!(" (исключение {exception})")
                    }
                ),
            );
            e.module = module.clone();
            e.module_version = version.clone();
            e.exception = exception;
            e.process = process;
            let mut targets = ctx.display_targets(vendor, &version);
            // A crash in an OLDER driver build than the one installed now
            // stays as evidence but no longer drives the current status.
            if let Some(current) = superseded_by(vendor, &version, &targets, &ctx.items) {
                e.severity = Severity::Ok;
                e.reason = format!("{HISTORICAL_PREFIX}: {} (установлен {current})", e.reason);
            }
            if targets.is_empty() {
                targets = vec![ctx.display_placeholder(vendor, &module)];
            }
            ctx.attach(&targets, &e);
        }
        "TDR4101" => {
            let driver = prop(ev, 0);
            let mut e = Evidence::from_event(
                EvidenceKind::DisplayTimeout,
                Severity::Warning,
                ev,
                "System / Display",
                format!("видеодрайвер {driver} перестал отвечать и был восстановлен (TDR)"),
            );
            e.module = driver.clone();
            let mut targets = ctx.by_driver_name(&driver);
            if targets.is_empty() {
                if let Some(v) = display_vendor_for_module(&driver) {
                    targets = ctx.display_targets(v, "");
                }
            }
            if targets.is_empty() {
                targets = ctx
                    .items
                    .iter()
                    .enumerate()
                    .filter(|(_, it)| it.category == Category::Display)
                    .map(|(i, _)| i)
                    .collect();
            }
            if targets.is_empty() {
                ctx.unattributed(e);
            } else {
                ctx.attach(&targets, &e);
            }
        }
        "SCM7026" => {
            // One event lists every boot/system-start driver that failed.
            let list = ev.props.join(" ");
            for name in list
                .split(|c: char| c.is_whitespace() || c == ',' || c == '|')
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                // Semantic check: an informational 7026 for an intact,
                // Microsoft-signed, correctly configured kernel driver with no
                // related failures means "inactive by design" (e.g. the
                // Desktop Activity Moderator driver `dam`), not a fault.
                let failed_checks = match expected_inactive_check(ctx, name, ev) {
                    Ok(detail) => {
                        let mut e = Evidence::from_event(
                            EvidenceKind::ExpectedInactive,
                            Severity::Ok,
                            ev,
                            "System / Service Control Manager",
                            detail,
                        );
                        e.module = name.to_string();
                        ctx.expected_inactive_note(e);
                        continue;
                    }
                    Err(failed) => failed,
                };
                let running = ctx
                    .sys_driver(name)
                    .map(|s| s.state.eq_ignore_ascii_case("running"))
                    .unwrap_or(false);
                let (sev, tail) = if running {
                    (Severity::Warning, "; сейчас драйвер работает")
                } else {
                    (Severity::Problem, "; сейчас драйвер не запущен")
                };
                let mut e = Evidence::from_event(
                    EvidenceKind::BootDriverLoadFailure,
                    sev,
                    ev,
                    "System / Service Control Manager",
                    format!(
                        "драйвер {name} не загрузился при старте системы{tail}{}",
                        if failed_checks.is_empty() {
                            String::new()
                        } else {
                            format!(" (проверка: {})", failed_checks.join("; "))
                        }
                    ),
                );
                e.module = name.to_string();
                let mut targets = ctx.by_driver_name(name);
                if targets.is_empty() {
                    if ctx.sys_driver(name).is_some() {
                        targets = vec![ctx.kernel_item(name)];
                    } else {
                        ctx.unattributed(e);
                        continue;
                    }
                }
                ctx.attach(&targets, &e);
            }
        }
        "SCM7000" => {
            // Only kernel drivers count; ordinary services are out of scope.
            let display = prop(ev, 0);
            let Some(sd) = ctx.sys_driver(&display).cloned() else {
                return;
            };
            let running = sd.state.eq_ignore_ascii_case("running");
            let mut e = Evidence::from_event(
                EvidenceKind::BootDriverLoadFailure,
                if running {
                    Severity::Warning
                } else {
                    Severity::Problem
                },
                ev,
                "System / Service Control Manager",
                format!(
                    "не удалось запустить драйвер {} ({}){}",
                    sd.name,
                    prop(ev, 1),
                    if running {
                        "; сейчас драйвер работает"
                    } else {
                        ""
                    }
                ),
            );
            e.module = sd.name.clone();
            let mut targets = ctx.by_driver_name(&sd.name);
            if targets.is_empty() {
                targets = vec![ctx.kernel_item(&sd.name)];
            }
            ctx.attach(&targets, &e);
        }
        "KPNP219" => {
            // "The driver \Driver\X failed to load for the device Y".
            let driver = ev
                .props
                .iter()
                .find(|p| p.to_lowercase().starts_with("\\driver\\"))
                .map(|p| p["\\Driver\\".len()..].to_string())
                .unwrap_or_default();
            let device = ev
                .props
                .iter()
                .find(|p| p.contains('\\') && !p.to_lowercase().starts_with("\\driver\\"))
                .cloned()
                .unwrap_or_default();
            let target = ctx
                .items
                .iter()
                .position(|it| !it.pnp_id.is_empty() && it.pnp_id.eq_ignore_ascii_case(&device));
            let mut e = Evidence::from_event(
                EvidenceKind::DeviceLoadFailure,
                Severity::Warning,
                ev,
                "System / Kernel-PnP",
                format!("драйвер {driver} не удалось загрузить для устройства"),
            );
            e.module = driver;
            match target {
                Some(i) => {
                    // Current error -> confirmed fault; works now -> risk.
                    let failing =
                        matches!(ctx.items[i].pnp_error_code, Some(c) if c != 0 && c != 22);
                    if failing {
                        e.severity = Severity::Problem;
                    } else {
                        e.reason
                            .push_str(" (в прошлом; сейчас устройство работает)");
                    }
                    ctx.items[i].add_evidence(e);
                }
                None => ctx.unattributed(e),
            }
        }
        "CI" => {
            let file = ev
                .props
                .iter()
                .find(|p| {
                    let l = p.to_lowercase();
                    l.ends_with(".sys") || l.ends_with(".dll")
                })
                .cloned()
                .unwrap_or_default();
            if file.is_empty() {
                return;
            }
            let process = ev
                .props
                .iter()
                .find(|p| p.to_lowercase().ends_with(".exe"))
                .map(|p| file_name(p))
                .unwrap_or_default();
            let fname = file_name(&file);
            let is_kernel = fname.to_lowercase().ends_with(".sys");
            let mut e = Evidence::from_event(
                EvidenceKind::CodeIntegrity,
                if is_kernel {
                    Severity::Problem
                } else {
                    Severity::Warning
                },
                ev,
                "Microsoft-Windows-CodeIntegrity/Operational",
                format!(
                    "Code Integrity (событие {}): {} не прошёл проверку целостности/подписи{}",
                    ev.id,
                    fname,
                    if process.is_empty() {
                        String::new()
                    } else {
                        format!(" в процессе {process}")
                    }
                ),
            );
            e.module = fname.clone();
            e.process = process;
            let mut targets = ctx.by_driver_name(&fname);
            if targets.is_empty() {
                if let Some(v) = display_vendor_for_module(&fname) {
                    targets = ctx.display_targets(v, "");
                }
            }
            if targets.is_empty() && is_kernel && ctx.sys_driver(&fname).is_some() {
                targets = vec![ctx.kernel_item(&fname)];
            }
            if targets.is_empty() {
                ctx.unattributed(e);
            } else {
                ctx.attach(&targets, &e);
            }
        }
        _ => {}
    }
}

/// Turns raw collector records into the audit report.
pub fn classify(raw: &RawAudit) -> AuditReport {
    let mut ctx = Ctx {
        items: Vec::new(),
        sys: &raw.sys_drivers,
        files: &raw.driver_files,
        events: &raw.events,
        unattributed: Vec::new(),
        expected_inactive: Vec::new(),
    };
    let mut scanned = 0usize;
    for dev in &raw.devices {
        // Not present (24/45) devices are not part of the running system.
        if matches!(dev.error_code, Some(24) | Some(45)) {
            continue;
        }
        scanned += 1;
        let cat = categorize(dev);
        let mut item = item_from_device(cat, dev);
        device_facts(&mut item, dev);
        // Every device is kept for event correlation (service / instance id
        // match); clean devices outside the relevant categories are dropped
        // after the events are applied.
        ctx.items.push(item);
    }
    let mut events: Vec<&RawEvent> = raw.events.iter().collect();
    events.sort_by(|a, b| a.time.cmp(&b.time));
    for ev in events {
        apply_event(&mut ctx, ev);
    }
    let mut items: Vec<AuditItem> = ctx
        .items
        .into_iter()
        .filter(|it| it.category != Category::Other || it.status != Severity::Ok)
        .collect();
    items.sort_by(|a, b| {
        b.status
            .cmp(&a.status)
            .then(a.category.cmp(&b.category))
            .then(a.label.cmp(&b.label))
    });
    let overall = items.iter().map(|i| i.status).max().unwrap_or(Severity::Ok);
    AuditReport {
        generated: raw.generated.clone(),
        window_days: raw.window_days,
        complete: raw.complete,
        devices_scanned: scanned,
        overall,
        items,
        unattributed: ctx.unattributed,
        expected_inactive: ctx.expected_inactive,
        errors: raw.errors.clone(),
    }
}

// ---------------------------------------------------------------------
// Dashboard summary
// ---------------------------------------------------------------------

fn representative_score(it: &AuditItem) -> i32 {
    let n = it.device.to_lowercase();
    match it.category {
        Category::Chipset => {
            if n.contains("chipset") {
                0
            } else if n.contains("management engine") || n.contains("mei") {
                1
            } else if n.contains("smbus") || n.contains("lpc") || n.contains("espi") {
                2
            } else {
                5
            }
        }
        Category::Audio => {
            let v = it.vendor.to_lowercase();
            if v == "microsoft"
                || v == "nvidia"
                || n.contains("display audio")
                || n.contains("hdmi")
            {
                5
            } else {
                0
            }
        }
        Category::Network => {
            if contains_any(&n, &["wi-fi", "wifi", "wireless", "wlan", "802.11"]) {
                0
            } else {
                1
            }
        }
        Category::Storage => {
            if n.contains("nvm") {
                0
            } else if contains_any(&n, &["raid", "vmd", "rst"]) {
                1
            } else if contains_any(&n, &["sata", "ahci"]) {
                2
            } else {
                5
            }
        }
        Category::Display => {
            if contains_any(&n, &["basic display", "basic render"]) {
                5
            } else {
                0
            }
        }
        _ => 5,
    }
}

/// Compact, meaningful rows for the dashboard card: every non-OK item, plus
/// one representative per core category (up to two GPUs), ordered by
/// category; limited to `max`. Returns the rows and how many flagged items
/// did not fit.
pub fn summary_rows(report: &AuditReport, max: usize) -> (Vec<&AuditItem>, usize) {
    let mut chosen: Vec<&AuditItem> = report
        .items
        .iter()
        .filter(|i| i.status != Severity::Ok)
        .collect();
    let core = [
        (Category::Display, 2usize),
        (Category::Chipset, 1),
        (Category::Audio, 1),
        (Category::Network, 1),
        (Category::Storage, 1),
    ];
    for (cat, want) in core {
        let have = chosen.iter().filter(|i| i.category == cat).count();
        if have >= want {
            continue;
        }
        let mut pool: Vec<&AuditItem> = report
            .items
            .iter()
            .filter(|i| i.category == cat && i.status == Severity::Ok)
            .collect();
        pool.sort_by_key(|i| (representative_score(i), i.label.clone()));
        chosen.extend(pool.into_iter().take(want - have));
    }
    // Flagged items keep priority when truncating.
    chosen.sort_by(|a, b| b.status.cmp(&a.status).then(a.category.cmp(&b.category)));
    let flagged_total = chosen.iter().filter(|i| i.status != Severity::Ok).count();
    let mut rows: Vec<&AuditItem> = chosen.into_iter().take(max).collect();
    let flagged_shown = rows.iter().filter(|i| i.status != Severity::Ok).count();
    rows.sort_by(|a, b| a.category.cmp(&b.category).then(b.status.cmp(&a.status)));
    (rows, flagged_total - flagged_shown)
}

// ---------------------------------------------------------------------
// Report serialisation
// ---------------------------------------------------------------------

fn json_str(s: &str) -> String {
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
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn json_opt_str(s: &str) -> String {
    if s.is_empty() {
        "null".into()
    } else {
        json_str(s)
    }
}

fn evidence_json(e: &Evidence, ind: &str) -> String {
    format!(
        "{ind}{{\"kind\": {}, \"severity\": {}, \"source\": {}, \"event_id\": {}, \"first_seen\": {}, \"last_seen\": {}, \"count\": {}, \"module\": {}, \"module_version\": {}, \"exception\": {}, \"process\": {}, \"reason\": {}}}",
        json_str(e.kind.code()),
        json_str(if e.kind == EvidenceKind::ExpectedInactive {
            "INFO"
        } else {
            e.severity.code()
        }),
        json_str(&e.source),
        e.event_id
            .map(|v| v.to_string())
            .unwrap_or_else(|| "null".into()),
        json_opt_str(&e.first_seen),
        json_opt_str(&e.last_seen),
        e.count,
        json_opt_str(&e.module),
        json_opt_str(&e.module_version),
        json_opt_str(&e.exception),
        json_opt_str(&e.process),
        json_str(&e.reason),
    )
}

/// Structured report for the diagnostic ZIP (schema `SCHEMA`). Every item
/// says which device, which driver/version, the status and why, with the
/// concrete evidence and its source.
pub fn to_json(r: &AuditReport) -> String {
    let mut o = String::new();
    o.push_str("{\n");
    let _ = writeln!(o, "  \"schema\": {},", json_str(SCHEMA));
    let _ = writeln!(o, "  \"generated\": {},", json_opt_str(&r.generated));
    let _ = writeln!(o, "  \"window_days\": {},", r.window_days);
    let _ = writeln!(o, "  \"collection_complete\": {},", r.complete);
    let _ = writeln!(o, "  \"devices_scanned\": {},", r.devices_scanned);
    let _ = writeln!(o, "  \"overall\": {},", json_str(r.overall.code()));
    let _ = writeln!(
        o,
        "  \"counts\": {{\"problem\": {}, \"warning\": {}, \"ok\": {}}},",
        r.count(Severity::Problem),
        r.count(Severity::Warning),
        r.count(Severity::Ok)
    );
    let _ = writeln!(
        o,
        "  \"status_rules\": {},",
        json_str(
            "PROBLEM only with concrete fault evidence (PnP error, driver-module crash, kernel Code Integrity failure, boot driver not loaded); WARNING only with risk evidence (recovered display timeouts, past load failure, unsigned or basic driver, user-mode Code Integrity event); driver age alone is never a finding."
        )
    );
    o.push_str("  \"items\": [");
    for (n, it) in r.items.iter().enumerate() {
        o.push_str(if n == 0 { "\n" } else { ",\n" });
        o.push_str("    {\n");
        let _ = writeln!(o, "      \"category\": {},", json_str(it.category.code()));
        let _ = writeln!(o, "      \"label\": {},", json_str(&it.label));
        let _ = writeln!(o, "      \"device\": {},", json_str(&it.device));
        let _ = writeln!(o, "      \"vendor\": {},", json_opt_str(&it.vendor));
        let _ = writeln!(
            o,
            "      \"driver_provider\": {},",
            json_opt_str(&it.provider)
        );
        let _ = writeln!(
            o,
            "      \"driver_version\": {},",
            json_opt_str(&it.version)
        );
        let _ = writeln!(o, "      \"driver_date\": {},", json_opt_str(&it.date));
        let _ = writeln!(o, "      \"inf\": {},", json_opt_str(&it.inf));
        let _ = writeln!(o, "      \"service\": {},", json_opt_str(&it.service));
        let _ = writeln!(o, "      \"pnp_device_id\": {},", json_opt_str(&it.pnp_id));
        let _ = writeln!(
            o,
            "      \"pnp_error_code\": {},",
            it.pnp_error_code
                .map(|c| c.to_string())
                .unwrap_or_else(|| "null".into())
        );
        let _ = writeln!(
            o,
            "      \"signed\": {},",
            it.signed
                .map(|b| b.to_string())
                .unwrap_or_else(|| "null".into())
        );
        let _ = writeln!(o, "      \"status\": {},", json_str(it.status.code()));
        let reasons: Vec<String> = it
            .evidence
            .iter()
            .filter(|e| e.severity == it.status && it.status != Severity::Ok)
            .map(|e| json_str(&e.reason))
            .collect();
        let _ = writeln!(o, "      \"status_reasons\": [{}],", reasons.join(", "));
        o.push_str("      \"evidence\": [");
        for (k, e) in it.evidence.iter().enumerate() {
            o.push_str(if k == 0 { "\n" } else { ",\n" });
            o.push_str(&evidence_json(e, "        "));
        }
        o.push_str(if it.evidence.is_empty() {
            "]\n"
        } else {
            "\n      ]\n"
        });
        o.push_str("    }");
    }
    o.push_str(if r.items.is_empty() {
        "],\n"
    } else {
        "\n  ],\n"
    });
    o.push_str("  \"expected_inactive_drivers\": [");
    for (k, e) in r.expected_inactive.iter().enumerate() {
        o.push_str(if k == 0 { "\n" } else { ",\n" });
        o.push_str(&evidence_json(e, "    "));
    }
    o.push_str(if r.expected_inactive.is_empty() {
        "],\n"
    } else {
        "\n  ],\n"
    });
    o.push_str("  \"unattributed_evidence\": [");
    for (k, e) in r.unattributed.iter().enumerate() {
        o.push_str(if k == 0 { "\n" } else { ",\n" });
        o.push_str(&evidence_json(e, "    "));
    }
    o.push_str(if r.unattributed.is_empty() {
        "],\n"
    } else {
        "\n  ],\n"
    });
    let errs: Vec<String> = r.errors.iter().map(|e| json_str(e)).collect();
    let _ = writeln!(o, "  \"collection_errors\": [{}]", errs.join(", "));
    o.push_str("}\n");
    o
}

/// Human-readable companion to the JSON (same facts).
pub fn to_text(r: &AuditReport) -> String {
    let mut o = String::new();
    let _ = writeln!(o, "WinStateDiag — Проверка драйверов");
    let _ = writeln!(o, "Сформировано: {}", r.generated);
    let _ = writeln!(
        o,
        "Итог: {}  (проблем: {}, предупреждений: {}, без замечаний: {}); устройств просмотрено: {}; окно событий: {} дн.",
        r.overall.label_ru(),
        r.count(Severity::Problem),
        r.count(Severity::Warning),
        r.count(Severity::Ok),
        r.devices_scanned,
        r.window_days
    );
    let _ = writeln!(
        o,
        "Правило: статус ставится только по конкретным признакам; возраст драйвера сам по себе не считается проблемой.\n"
    );
    for it in &r.items {
        let _ = writeln!(o, "[{}] {} — {}", it.status.label_ru(), it.label, it.device);
        let _ = writeln!(
            o,
            "    версия: {}; дата: {}; поставщик: {}; INF: {}; служба: {}",
            or_na(&it.version),
            or_na(&it.date),
            or_na(&it.provider),
            or_na(&it.inf),
            or_na(&it.service)
        );
        for e in &it.evidence {
            let _ = writeln!(
                o,
                "    • {} [{}{}]{}{}",
                e.reason,
                e.source,
                e.event_id
                    .map(|i| format!(", событие {i}"))
                    .unwrap_or_default(),
                if e.count > 1 {
                    format!(" ×{}", e.count)
                } else {
                    String::new()
                },
                if e.first_seen.is_empty() {
                    String::new()
                } else if e.first_seen == e.last_seen {
                    format!(" {}", e.first_seen)
                } else {
                    format!(" {} … {}", e.first_seen, e.last_seen)
                }
            );
        }
    }
    if !r.unattributed.is_empty() {
        let _ = writeln!(
            o,
            "\nНе привязанные к текущим устройствам события (на статус не влияют):"
        );
        for e in &r.unattributed {
            let _ = writeln!(o, "    • {} [{}] ×{}", e.reason, e.source, e.count);
        }
    }
    if !r.errors.is_empty() {
        let _ = writeln!(o, "\nОшибки сбора данных:");
        for e in &r.errors {
            let _ = writeln!(o, "    • {e}");
        }
    }
    o
}

fn or_na(s: &str) -> &str {
    if s.is_empty() { "н/д" } else { s }
}

/// Writes `DriverAudit_<tag>.json` and `.txt` into `dir`.
pub fn write_report(report: &AuditReport, dir: &Path, tag: &str) -> Result<PathBuf, String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("Driver Audit: {e}"))?;
    let json = dir.join(format!("DriverAudit_{tag}.json"));
    std::fs::write(&json, to_json(report)).map_err(|e| format!("Driver Audit JSON: {e}"))?;
    let txt = dir.join(format!("DriverAudit_{tag}.txt"));
    // UTF-8 with BOM so Notepad on older Windows shows Cyrillic correctly.
    let mut bytes = vec![0xEF, 0xBB, 0xBF];
    bytes.extend_from_slice(to_text(report).as_bytes());
    std::fs::write(&txt, bytes).map_err(|e| format!("Driver Audit TXT: {e}"))?;
    Ok(json)
}

// ---------------------------------------------------------------------
// Collection (Windows only)
// ---------------------------------------------------------------------

/// Runs the read-only collector from `work_dir` and classifies the result.
pub fn run_audit(work_dir: &Path) -> Result<AuditReport, String> {
    run_audit_with_cancel(work_dir, &std::sync::atomic::AtomicBool::new(false))
}

/// As [`run_audit`]; `cancel` (the Stop button of a diagnostic run) ends
/// the collector process early. Classification is unchanged.
pub fn run_audit_with_cancel(
    work_dir: &Path,
    cancel: &std::sync::atomic::AtomicBool,
) -> Result<AuditReport, String> {
    let text = run_collector(work_dir, cancel)?;
    let raw = parse_collector_output(&text);
    if raw.devices.is_empty() && !raw.errors.is_empty() {
        return Err(format!(
            "Проверка драйверов: не удалось получить список устройств ({})",
            raw.errors.join("; ")
        ));
    }
    Ok(classify(&raw))
}

#[cfg(windows)]
fn run_collector(
    work_dir: &Path,
    cancel: &std::sync::atomic::AtomicBool,
) -> Result<String, String> {
    use crate::engine::{ProcessGuard, WaitEnd};
    use std::io::Read;
    use std::process::{Command, Stdio};
    use std::time::Duration;

    std::fs::create_dir_all(work_dir).map_err(|e| format!("Driver Audit: {e}"))?;
    let script = work_dir.join("DriverAudit.ps1");
    std::fs::write(&script, COLLECTOR_PS1).map_err(|e| format!("Driver Audit: {e}"))?;
    let mut cmd = Command::new("powershell.exe");
    cmd.args([
        "-NoLogo",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
    ])
    .arg(&script)
    .arg("-Days")
    .arg(WINDOW_DAYS.to_string())
    .stdin(Stdio::null())
    .stdout(Stdio::piped())
    .stderr(Stdio::null());
    // Hidden, and owned by this WinStateDiag (its process tree only).
    let mut guard = ProcessGuard::spawn(cmd)
        .map_err(|e| format!("Не удалось запустить проверку драйверов: {e}"))?;
    let mut stdout = guard
        .child_mut()
        .stdout
        .take()
        .ok_or("Driver Audit: нет stdout")?;
    let reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout.read_to_end(&mut buf);
        buf
    });
    match guard.wait_or_cancel(cancel, Some(Duration::from_secs(180))) {
        Ok(_) => {}
        Err(WaitEnd::Cancelled) => {
            let _ = reader.join();
            return Err("Проверка драйверов остановлена пользователем.".into());
        }
        Err(WaitEnd::TimedOut) => {
            let _ = reader.join();
            return Err("Проверка драйверов прервана по таймауту (180 с).".into());
        }
        Err(WaitEnd::Io(e)) => return Err(format!("Driver Audit: {e}")),
    }
    let bytes = reader.join().unwrap_or_default();
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(not(windows))]
fn run_collector(
    _work_dir: &Path,
    _cancel: &std::sync::atomic::AtomicBool,
) -> Result<String, String> {
    Err("Проверка драйверов доступна только в Windows.".into())
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn dev(class: &str, name: &str, mfr: &str, ver: &str, code: u32) -> RawDevice {
        RawDevice {
            class: class.into(),
            name: name.into(),
            manufacturer: mfr.into(),
            provider: mfr.into(),
            version: ver.into(),
            date: "2021-06-01".into(),
            inf: "oem12.inf".into(),
            error_code: Some(code),
            signed: Some(true),
            pnp_id: format!("PCI\\VEN_TEST&DEV_{}", name.len()),
            service: String::new(),
        }
    }

    fn evt(tag: &str, id: u32, time: &str, props: &[&str]) -> RawEvent {
        RawEvent {
            tag: tag.into(),
            id,
            time: time.into(),
            provider: String::new(),
            props: props.iter().map(|s| s.to_string()).collect(),
            message: String::new(),
            level: if tag == "SCM7026" { Some(4) } else { Some(2) },
        }
    }

    fn intel_gpu() -> RawDevice {
        let mut d = dev(
            "Display",
            "Intel(R) UHD Graphics 630",
            "Intel Corporation",
            "30.0.101.1273",
            0,
        );
        d.service = "igfx".into();
        d
    }

    fn app_crash(time: &str, module: &str, ver: &str) -> RawEvent {
        evt(
            "APPCRASH",
            1000,
            time,
            &[
                "win_state_diag.exe",
                "0.1.0.0",
                "0x00000000",
                module,
                ver,
                "0x5f3c0a11",
                "c0000005",
                "0x0000000000123456",
                "0x1a2c",
                "0x01d9",
                "C:\\AI\\WinStateDiag\\win_state_diag.exe",
                "C:\\Windows\\System32\\DriverStore\\FileRepository\\iigd_dch.inf_amd64\\igvk64.dll",
            ],
        )
    }

    fn report(devices: Vec<RawDevice>, events: Vec<RawEvent>) -> AuditReport {
        classify(&RawAudit {
            generated: "2026-09-24T10:00:00".into(),
            window_days: 30,
            complete: true,
            devices,
            sys_drivers: vec![RawSysDriver {
                name: "iaStorVD".into(),
                display_name: "Intel RST VMD Controller".into(),
                path: "C:\\Windows\\System32\\drivers\\iaStorVD.sys".into(),
                state: "Stopped".into(),
                start_mode: "Boot".into(),
                service_type: "Kernel Driver".into(),
            }],
            driver_files: vec![],
            events,
            errors: vec![],
        })
    }

    fn item<'a>(r: &'a AuditReport, needle: &str) -> &'a AuditItem {
        r.items
            .iter()
            .find(|i| i.device.contains(needle) || i.label.contains(needle))
            .unwrap_or_else(|| panic!("item {needle} not found in {:?}", r.items))
    }

    #[test]
    fn collector_script_is_read_only() {
        let ps = String::from_utf8_lossy(COLLECTOR_PS1).to_lowercase();
        assert!(ps.contains("#requires -version 5.0"));
        assert!(ps.contains("get-ciminstance") && ps.contains("get-winevent"));
        for verb in [
            "set-",
            "remove-",
            "new-item",
            "out-file",
            "add-content",
            "invoke-cimmethod",
            "start-process",
            "stop-",
            "restart-",
            "disable-",
            "enable-",
            "pnputil",
            "dism",
        ] {
            assert!(!ps.contains(verb), "collector must stay read-only: {verb}");
        }
    }

    #[test]
    fn healthy_driver_is_ok() {
        let r = report(vec![intel_gpu()], vec![]);
        let it = item(&r, "UHD");
        assert_eq!(it.status, Severity::Ok);
        assert!(it.evidence.is_empty());
        assert_eq!(r.overall, Severity::Ok);
        assert_eq!(it.label, "Intel UHD Graphics 630");
    }

    #[test]
    fn pnp_error_is_problem() {
        let r = report(
            vec![dev(
                "Net",
                "Intel(R) Wi-Fi 6 AX201",
                "Intel",
                "22.1.0.3",
                43,
            )],
            vec![],
        );
        let it = item(&r, "Wi-Fi");
        assert_eq!(it.status, Severity::Problem);
        assert!(it.evidence[0].reason.contains("код 43"));
        assert_eq!(it.label, "Сеть (Intel Wi-Fi)");
    }

    #[test]
    fn disabled_device_is_not_a_fault() {
        let r = report(
            vec![dev("MEDIA", "Realtek Audio", "Realtek", "6.0.9815.1", 22)],
            vec![],
        );
        assert_eq!(item(&r, "Realtek").status, Severity::Ok);
    }

    #[test]
    fn crash_evidence_real_case_intel_igvk64() {
        let r = report(
            vec![intel_gpu()],
            vec![app_crash(
                "2026-09-20T12:00:00",
                "igvk64.dll",
                "30.0.101.1273",
            )],
        );
        let it = item(&r, "UHD");
        assert_eq!(it.status, Severity::Problem);
        let e = &it.evidence[0];
        assert_eq!(e.kind, EvidenceKind::Crash);
        assert_eq!(e.module, "igvk64.dll");
        assert_eq!(e.module_version, "30.0.101.1273");
        assert_eq!(e.exception, "0xC0000005");
        assert_eq!(e.process, "win_state_diag.exe");
        assert_eq!(e.event_id, Some(1000));
        assert_eq!(r.overall, Severity::Problem);
    }

    fn intel_uhd750(ver: &str) -> RawDevice {
        let mut d = dev(
            "Display",
            "Intel(R) UHD Graphics 750",
            "Intel Corporation",
            ver,
            0,
        );
        d.service = "igfx".into();
        d
    }

    /// Field case: UHD 750 now on 32.0.101.7088, old igvk64.dll 30.0.101.1273
    /// crashes remain in the log -> historical evidence, status OK.
    #[test]
    fn crash_of_previous_driver_version_is_historical_not_current() {
        let r = report(
            vec![intel_uhd750("32.0.101.7088")],
            vec![
                app_crash("2026-09-18T07:00:00", "igvk64.dll", "30.0.101.1273"),
                app_crash("2026-09-20T12:00:00", "igvk64.dll", "30.0.101.1273"),
            ],
        );
        let it = item(&r, "UHD");
        assert_eq!(
            it.status,
            Severity::Ok,
            "historical crash must not raise status"
        );
        assert_eq!(r.overall, Severity::Ok);
        assert_eq!(it.evidence.len(), 1, "evidence kept (deduplicated)");
        let e = &it.evidence[0];
        assert_eq!(e.severity, Severity::Ok);
        assert_eq!(e.count, 2);
        assert!(e.reason.starts_with(HISTORICAL_PREFIX), "{}", e.reason);
        assert!(e.reason.contains("32.0.101.7088"));
        assert!(to_text(&r).contains(HISTORICAL_PREFIX));
    }

    #[test]
    fn crash_of_the_current_driver_version_is_a_current_problem() {
        let r = report(
            vec![intel_uhd750("32.0.101.7088")],
            vec![
                app_crash("2026-09-18T07:00:00", "igvk64.dll", "30.0.101.1273"),
                app_crash("2026-09-24T09:00:00", "igvk64.dll", "32.0.101.7088"),
            ],
        );
        let it = item(&r, "UHD");
        assert_eq!(it.status, Severity::Problem);
        assert_eq!(r.overall, Severity::Problem);
        assert!(
            it.evidence
                .iter()
                .any(|e| e.module_version == "32.0.101.7088" && e.severity == Severity::Problem)
        );
        assert!(
            it.evidence
                .iter()
                .any(|e| e.module_version == "30.0.101.1273" && e.severity == Severity::Ok)
        );
    }

    #[test]
    fn newer_or_unparsable_crash_versions_stay_current() {
        for v in ["33.0.101.1", "", "n/a"] {
            let r = report(
                vec![intel_uhd750("32.0.101.7088")],
                vec![app_crash("2026-09-24T09:00:00", "igvk64.dll", v)],
            );
            assert_eq!(item(&r, "UHD").status, Severity::Problem, "version {v:?}");
        }
    }

    #[test]
    fn crash_prefers_exact_version_match_among_gpus() {
        let mut nv = dev(
            "Display",
            "NVIDIA GeForce RTX 3060",
            "NVIDIA",
            "32.0.15.6169",
            0,
        );
        nv.service = "nvlddmkm".into();
        let mut old_intel = intel_gpu();
        old_intel.name = "Intel(R) Iris Xe Graphics".into();
        old_intel.version = "31.0.101.5000".into();
        let r = report(
            vec![intel_gpu(), old_intel, nv],
            vec![app_crash(
                "2026-09-20T12:00:00",
                "igvk64.dll",
                "30.0.101.1273",
            )],
        );
        assert_eq!(item(&r, "UHD").status, Severity::Problem);
        assert_eq!(item(&r, "Iris").status, Severity::Ok);
        assert_eq!(item(&r, "NVIDIA").status, Severity::Ok);
    }

    #[test]
    fn crash_in_non_driver_module_is_ignored() {
        let r = report(
            vec![intel_gpu()],
            vec![app_crash(
                "2026-09-20T12:00:00",
                "ntdll.dll",
                "10.0.26100.1",
            )],
        );
        assert_eq!(r.overall, Severity::Ok);
    }

    #[test]
    fn crash_without_device_creates_problem_placeholder() {
        let r = report(
            vec![],
            vec![app_crash(
                "2026-09-20T12:00:00",
                "igvk64.dll",
                "30.0.101.1273",
            )],
        );
        assert_eq!(r.overall, Severity::Problem);
        assert!(r.items[0].device.contains("igvk64.dll"));
    }

    #[test]
    fn code_integrity_kernel_driver_is_problem() {
        let mut stor = dev(
            "SCSIAdapter",
            "Intel RST VMD Controller 9A0B",
            "Intel",
            "19.0.1.1",
            0,
        );
        stor.service = "iaStorVD".into();
        let r = report(
            vec![stor],
            vec![evt(
                "CI",
                3033,
                "2026-09-21T08:00:00",
                &[
                    "0x0000004c",
                    "\\Device\\HarddiskVolume3\\Windows\\System32\\drivers\\iaStorVD.sys",
                    "0x00000010",
                    "System",
                ],
            )],
        );
        let it = item(&r, "VMD");
        assert_eq!(it.status, Severity::Problem);
        assert_eq!(it.evidence[0].kind, EvidenceKind::CodeIntegrity);
        assert_eq!(it.evidence[0].module, "iaStorVD.sys");
    }

    #[test]
    fn code_integrity_user_mode_component_is_warning() {
        let r = report(
            vec![intel_gpu()],
            vec![evt(
                "CI",
                3033,
                "2026-09-21T08:00:00",
                &[
                    "0x10",
                    "C:\\Windows\\System32\\igdusc64.dll",
                    "0x1",
                    "C:\\Program Files\\x\\svc.exe",
                ],
            )],
        );
        let it = item(&r, "UHD");
        assert_eq!(it.status, Severity::Warning);
        assert_eq!(it.evidence[0].process, "svc.exe");
    }

    #[test]
    fn display_timeout_is_warning() {
        let r = report(
            vec![intel_gpu()],
            vec![evt("TDR4101", 4101, "2026-09-22T09:00:00", &["igfx", ""])],
        );
        assert_eq!(item(&r, "UHD").status, Severity::Warning);
    }

    #[test]
    fn past_load_failure_on_working_device_is_warning() {
        let mut d = dev(
            "MEDIA",
            "Realtek High Definition Audio",
            "Realtek",
            "6.0.9815.1",
            0,
        );
        d.pnp_id = "HDAUDIO\\FUNC_01&VEN_10EC".into();
        let r = report(
            vec![d],
            vec![evt(
                "KPNP219",
                219,
                "2026-09-22T09:00:00",
                &[
                    "HDAUDIO\\FUNC_01&VEN_10EC",
                    "\\Driver\\RTKVHD64",
                    "0xc0000365",
                ],
            )],
        );
        let it = item(&r, "Realtek");
        assert_eq!(it.status, Severity::Warning);
        assert_eq!(it.evidence[0].module, "RTKVHD64");
    }

    #[test]
    fn unattributed_load_failure_does_not_change_status() {
        let r = report(
            vec![intel_gpu()],
            vec![evt(
                "KPNP219",
                219,
                "2026-09-22T09:00:00",
                &["SWD\\WPDBUSENUM\\GONE", "\\Driver\\WudfRd", "0xc0000365"],
            )],
        );
        assert_eq!(r.overall, Severity::Ok);
        assert_eq!(r.unattributed.len(), 1);
        assert_eq!(r.unattributed[0].severity, Severity::Ok);
    }

    #[test]
    fn boot_driver_not_running_is_problem() {
        let r = report(
            vec![],
            vec![evt("SCM7026", 7026, "2026-09-22T09:00:00", &["iaStorVD"])],
        );
        let it = item(&r, "iaStorVD");
        assert_eq!(it.category, Category::KernelDriver);
        assert_eq!(it.status, Severity::Problem);
    }

    #[test]
    fn duplicate_evidence_is_merged_with_count_and_range() {
        let r = report(
            vec![intel_gpu()],
            vec![
                app_crash("2026-09-20T12:00:00", "igvk64.dll", "30.0.101.1273"),
                app_crash("2026-09-18T07:00:00", "igvk64.dll", "30.0.101.1273"),
                app_crash("2026-09-23T21:00:00", "igvk64.dll", "30.0.101.1273"),
            ],
        );
        let it = item(&r, "UHD");
        assert_eq!(it.evidence.len(), 1);
        let e = &it.evidence[0];
        assert_eq!(e.count, 3);
        assert_eq!(e.first_seen, "2026-09-18T07:00:00");
        assert_eq!(e.last_seen, "2026-09-23T21:00:00");
    }

    #[test]
    fn missing_driver_date_and_version_is_not_a_finding() {
        let mut d = dev(
            "HDC",
            "Standard SATA AHCI Controller",
            "(Standard SATA/AHCI controller)",
            "",
            0,
        );
        d.date = String::new();
        d.provider = "Microsoft".into();
        let r = report(vec![d], vec![]);
        let it = item(&r, "SATA");
        assert_eq!(it.status, Severity::Ok);
        assert!(it.version.is_empty());
        assert_eq!(it.label, "SATA (Microsoft)");
        assert!(to_json(&r).contains("\"driver_version\": null"));
    }

    #[test]
    fn old_driver_alone_is_not_a_warning() {
        let mut d = dev(
            "MEDIA",
            "Realtek High Definition Audio",
            "Realtek",
            "6.0.1.7541",
            0,
        );
        d.date = "2015-07-15".into();
        let r = report(vec![d], vec![]);
        assert_eq!(item(&r, "Realtek").status, Severity::Ok);
        assert_eq!(r.overall, Severity::Ok);
    }

    #[test]
    fn unsigned_and_basic_display_driver_are_warnings() {
        let mut basic = dev(
            "Display",
            "Microsoft Basic Display Adapter",
            "(Standard display types)",
            "10.0.26100.1",
            0,
        );
        basic.provider = "Microsoft".into();
        basic.inf = "display.inf".into();
        let mut unsigned = dev("MEDIA", "Some Audio", "Acme", "1.0", 0);
        unsigned.signed = Some(false);
        let r = report(vec![basic, unsigned], vec![]);
        assert_eq!(item(&r, "Basic Display").status, Severity::Warning);
        assert_eq!(item(&r, "Some Audio").status, Severity::Warning);
    }

    #[test]
    fn severity_precedence_problem_over_warning_over_ok() {
        assert!(Severity::Problem > Severity::Warning && Severity::Warning > Severity::Ok);
        let r = report(
            vec![intel_gpu()],
            vec![
                evt("TDR4101", 4101, "2026-09-22T09:00:00", &["igfx", ""]),
                app_crash("2026-09-20T12:00:00", "igvk64.dll", "30.0.101.1273"),
            ],
        );
        let it = item(&r, "UHD");
        assert_eq!(it.evidence.len(), 2);
        assert_eq!(it.status, Severity::Problem);
        assert_eq!(it.primary_reason().unwrap().kind, EvidenceKind::Crash);
        // Items are ordered PROBLEM first.
        let r2 = report(
            vec![
                dev("MEDIA", "Realtek Audio", "Realtek", "1", 0),
                dev("Net", "Intel Ethernet I219-V", "Intel", "12.19", 10),
            ],
            vec![],
        );
        assert_eq!(r2.items[0].status, Severity::Problem);
        assert_eq!(r2.overall, Severity::Problem);
    }

    #[test]
    fn virtual_and_unrelated_devices_are_not_listed_when_clean() {
        let r = report(
            vec![
                dev("Net", "WAN Miniport (IP)", "Microsoft", "10.0", 0),
                dev("Keyboard", "HID Keyboard Device", "Microsoft", "10.0", 0),
                dev("Keyboard", "Broken Keyboard", "Acme", "1.0", 10),
            ],
            vec![],
        );
        assert_eq!(r.items.len(), 1);
        assert_eq!(r.items[0].status, Severity::Problem);
    }

    #[test]
    fn parse_collector_output_reads_all_record_types() {
        let text = "\u{feff}META\tgenerated\t2026-09-24T10:00:00\n\
            DEV\tDisplay\tIntel(R) UHD Graphics 630\tIntel Corporation\tIntel Corporation\t30.0.101.1273\t2022-01-10\toem45.inf\t0\tTrue\tPCI\\VEN_8086&DEV_3E92\tigfx\r\n\
            SYS\tigfx\tigfx\tC:\\Windows\\System32\\drivers\\igdkmd64.sys\tRunning\tManual\n\
            EVT\tAPPCRASH\t1000\t2026-09-20T12:00:00\tApplication Error\twin_state_diag.exe | 0.1.0.0 | x | igvk64.dll | 30.0.101.1273 | y | c0000005\tmsg\n\
            ERR\tCI\taccess denied\n\
            META\tdone\t1\n";
        let raw = parse_collector_output(text);
        assert!(raw.complete);
        assert_eq!(raw.generated, "2026-09-24T10:00:00");
        assert_eq!(raw.devices.len(), 1);
        assert_eq!(raw.devices[0].error_code, Some(0));
        assert_eq!(raw.devices[0].signed, Some(true));
        assert_eq!(raw.devices[0].service, "igfx");
        assert_eq!(raw.sys_drivers[0].state, "Running");
        assert_eq!(raw.events[0].props[3], "igvk64.dll");
        assert_eq!(raw.errors, vec!["CI: access denied".to_string()]);
        let r = classify(&raw);
        assert_eq!(r.overall, Severity::Problem);
    }

    #[test]
    fn report_serialization_carries_device_driver_status_reason_and_evidence() {
        let r = report(
            vec![
                intel_gpu(),
                dev("MEDIA", "Realtek \"HD\" Audio", "Realtek", "6.0", 0),
            ],
            vec![app_crash(
                "2026-09-20T12:00:00",
                "igvk64.dll",
                "30.0.101.1273",
            )],
        );
        let j = to_json(&r);
        assert!(j.contains("\"schema\": \"winstatediag.driver_audit/1\""));
        assert!(j.contains("\"overall\": \"PROBLEM\""));
        assert!(j.contains("\"device\": \"Intel UHD Graphics 630\""));
        assert!(j.contains("\"driver_version\": \"30.0.101.1273\""));
        assert!(j.contains("\"status\": \"PROBLEM\""));
        assert!(j.contains("\"kind\": \"crash\""));
        assert!(j.contains("\"module\": \"igvk64.dll\""));
        assert!(j.contains("\"exception\": \"0xC0000005\""));
        assert!(j.contains("\"source\": \"Application / Application Error\""));
        assert!(j.contains("Realtek \\\"HD\\\" Audio"));
        // Balanced braces/brackets as a cheap well-formedness check.
        let opens = j.matches('{').count() + j.matches('[').count();
        let closes = j.matches('}').count() + j.matches(']').count();
        assert_eq!(opens, closes);
        let t = to_text(&r);
        assert!(t.contains("[Проблема] Intel UHD Graphics 630"));
        assert!(t.contains("igvk64.dll"));
    }

    #[test]
    fn write_report_creates_json_and_txt() {
        let dir = std::env::temp_dir().join(format!("wsd-da-test-{}", std::process::id()));
        let r = report(vec![intel_gpu()], vec![]);
        let json = write_report(&r, &dir, "24-09-26_10-00-00").unwrap();
        assert!(json.is_file());
        assert!(dir.join("DriverAudit_24-09-26_10-00-00.txt").is_file());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn summary_rows_show_flagged_first_then_representatives() {
        let mut chip = dev(
            "System",
            "Intel(R) 200 Series Chipset Family SMBus",
            "Intel",
            "10.1.19600.8418",
            0,
        );
        chip.pnp_id = "PCI\\SMB".into();
        let mut chip2 = dev("System", "Intel(R) Serial IO GPIO", "Intel", "30.100", 0);
        chip2.pnp_id = "PCI\\GPIO".into();
        let r = report(
            vec![
                intel_gpu(),
                dev(
                    "Display",
                    "NVIDIA GeForce RTX 3060",
                    "NVIDIA",
                    "32.0.15.6169",
                    0,
                ),
                chip,
                chip2,
                dev(
                    "MEDIA",
                    "Realtek High Definition Audio",
                    "Realtek",
                    "6.0.9815.1",
                    0,
                ),
                dev("MEDIA", "NVIDIA High Definition Audio", "NVIDIA", "1.3", 0),
                dev("Net", "Intel(R) Wi-Fi 6 AX201", "Intel", "23.110.1.2", 0),
                dev(
                    "SCSIAdapter",
                    "Standard NVM Express Controller",
                    "(Standard NVM Express Controller)",
                    "10.0.26100.1",
                    0,
                ),
            ],
            vec![app_crash(
                "2026-09-20T12:00:00",
                "igvk64.dll",
                "30.0.101.1273",
            )],
        );
        let (rows, more) = summary_rows(&r, 6);
        assert_eq!(more, 0);
        let labels: Vec<&str> = rows.iter().map(|i| i.label.as_str()).collect();
        assert_eq!(rows.len(), 6);
        assert_eq!(rows[0].label, "Intel UHD Graphics 630");
        assert_eq!(rows[0].status, Severity::Problem);
        assert!(labels.contains(&"Чипсет (Intel)"));
        assert!(labels.contains(&"Аудио (Realtek)"));
        assert!(labels.contains(&"Сеть (Intel Wi-Fi)"));
        assert!(labels.contains(&"NVMe (Microsoft)"));
        // Many flagged items: the overflow is counted, flagged ones win.
        let many: Vec<RawDevice> = (0..9)
            .map(|i| {
                let mut d = dev("Keyboard", &format!("Broken {i}"), "Acme", "1", 10);
                d.pnp_id = format!("X\\{i}");
                d
            })
            .collect();
        let r2 = report(many, vec![]);
        let (rows2, more2) = summary_rows(&r2, 6);
        assert_eq!(rows2.len(), 6);
        assert_eq!(more2, 3);
    }

    // --- expected inactive drivers (e.g. Desktop Activity Moderator) -----

    fn dam_audit(
        file: RawDriverFile,
        sys_type: &str,
        image: &str,
        extra_events: Vec<RawEvent>,
        level_7026: Option<u32>,
    ) -> AuditReport {
        let mut e7026 = evt("SCM7026", 7026, "2026-09-24T08:00:00", &["dam"]);
        e7026.level = level_7026;
        let mut e2 = e7026.clone();
        e2.time = "2026-09-24T18:00:00".into();
        let mut events = vec![e7026, e2];
        events.extend(extra_events);
        classify(&RawAudit {
            generated: "2026-09-24T19:00:00".into(),
            window_days: 30,
            complete: true,
            devices: vec![intel_gpu()],
            sys_drivers: vec![RawSysDriver {
                name: "dam".into(),
                display_name: "Desktop Activity Moderator Driver".into(),
                path: image.into(),
                state: "Stopped".into(),
                start_mode: "System".into(),
                service_type: sys_type.into(),
            }],
            driver_files: vec![file],
            events,
            errors: vec![],
        })
    }

    fn dam_file() -> RawDriverFile {
        RawDriverFile {
            service: "dam".into(),
            path: "C:\\Windows\\system32\\drivers\\dam.sys".into(),
            exists: true,
            signature: "Valid".into(),
            signer: "CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond".into(),
            company: "Microsoft Corporation".into(),
            version: "10.0.26100.9444".into(),
        }
    }

    const DAM_IMAGE: &str = "C:\\WINDOWS\\system32\\drivers\\dam.sys";

    #[test]
    fn dam_informational_7026_is_expected_inactive_not_a_problem() {
        let r = dam_audit(dam_file(), "Kernel Driver", DAM_IMAGE, vec![], Some(4));
        assert_eq!(r.overall, Severity::Ok);
        assert_eq!(r.count(Severity::Problem), 0);
        assert_eq!(r.count(Severity::Warning), 0);
        assert!(r.items.iter().all(|i| !i.label.contains("dam")));
        assert_eq!(r.expected_inactive.len(), 1);
        let e = &r.expected_inactive[0];
        assert_eq!(e.count, 2, "repeated 7026 merged");
        assert!(e.reason.contains("Desktop Activity Moderator Driver"));
        assert!(e.reason.contains("Исправление не требуется"));
        let j = to_json(&r);
        assert!(j.contains("\"expected_inactive_drivers\""));
        assert!(j.contains("\"severity\": \"INFO\""));
        assert!(j.contains("\"overall\": \"OK\""));
        // Client-facing text report does not mention it.
        assert!(!to_text(&r).contains("dam"));
        // The dashboard card shows no problem row for it.
        let (rows, more) = summary_rows(&r, 6);
        assert!(rows.iter().all(|i| i.status == Severity::Ok) && more == 0);
    }

    #[test]
    fn damaged_or_invalid_dam_is_still_a_problem() {
        let cases: Vec<(&str, AuditReport)> = vec![
            ("invalid signature", {
                let mut f = dam_file();
                f.signature = "HashMismatch".into();
                dam_audit(f, "Kernel Driver", DAM_IMAGE, vec![], Some(4))
            }),
            ("missing file", {
                let mut f = dam_file();
                f.exists = false;
                dam_audit(f, "Kernel Driver", DAM_IMAGE, vec![], Some(4))
            }),
            ("non-Microsoft signer", {
                let mut f = dam_file();
                f.signer = "CN=Someone Else".into();
                dam_audit(f, "Kernel Driver", DAM_IMAGE, vec![], Some(4))
            }),
            (
                "wrong ImagePath",
                dam_audit(
                    dam_file(),
                    "Kernel Driver",
                    "C:\\x\\evil.sys",
                    vec![],
                    Some(4),
                ),
            ),
            (
                "wrong service type",
                dam_audit(dam_file(), "Own Process", DAM_IMAGE, vec![], Some(4)),
            ),
            (
                "Code Integrity failure",
                dam_audit(
                    dam_file(),
                    "Kernel Driver",
                    DAM_IMAGE,
                    vec![evt(
                        "CI",
                        3033,
                        "2026-09-24T09:00:00",
                        &[
                            "0x4c",
                            "\\Device\\HarddiskVolume3\\Windows\\System32\\drivers\\dam.sys",
                        ],
                    )],
                    Some(4),
                ),
            ),
            (
                "real SCM error",
                dam_audit(
                    dam_file(),
                    "Kernel Driver",
                    DAM_IMAGE,
                    vec![evt(
                        "SCMERR",
                        7009,
                        "2026-09-24T09:00:00",
                        &["30000", "Desktop Activity Moderator Driver"],
                    )],
                    Some(4),
                ),
            ),
            (
                "7026 at error level",
                dam_audit(dam_file(), "Kernel Driver", DAM_IMAGE, vec![], Some(2)),
            ),
        ];
        for (what, r) in cases {
            assert_eq!(r.overall, Severity::Problem, "{what}");
            assert!(r.expected_inactive.is_empty(), "{what}");
            let it = item(&r, "dam");
            assert_eq!(it.status, Severity::Problem, "{what}");
            assert!(
                it.evidence.iter().any(|e| e.reason.contains("проверка:")),
                "{what}"
            );
        }
    }

    #[test]
    fn parse_reads_driver_file_records_level_and_service_type() {
        let raw = parse_collector_output(
            "SYS\tdam\tDesktop Activity Moderator Driver\tC:\\WINDOWS\\system32\\drivers\\dam.sys\tStopped\tSystem\tKernel Driver\n\
             EVT\tSCM7026\t7026\t2026-09-24T08:00:00\tService Control Manager\tdam\tmsg\t4\n\
             DRVFILE\tdam\tC:\\WINDOWS\\system32\\drivers\\dam.sys\tTrue\tValid\tCN=Microsoft Windows\tMicrosoft Corporation\t10.0.26100.9444\n",
        );
        assert_eq!(raw.sys_drivers[0].service_type, "Kernel Driver");
        assert_eq!(raw.events[0].level, Some(4));
        let f = &raw.driver_files[0];
        assert!(f.exists && f.signature == "Valid" && f.version == "10.0.26100.9444");
        let r = classify(&raw);
        assert_eq!(r.overall, Severity::Ok);
        assert_eq!(r.expected_inactive.len(), 1);
    }
}
