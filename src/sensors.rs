//! Hardware sensors (v0.4.5): temperatures, voltage rails, CPU/GPU power and
//! fans from several READ-ONLY providers, normalised into one model.
//!
//! Providers (canonical priority, best first):
//! 1. `LhmInternal` — the official LibreHardwareMonitorLib bundled with
//!    WinStateDiag, loaded in a short-lived PowerShell helper. Low-level
//!    (CPU MSR, Super I/O, SMBus) sensors need the PawnIO driver; WinStateDiag
//!    NEVER installs it. Without PawnIO the library still reads GPU (NVAPI /
//!    ADL / IGCL) and storage sensors.
//! 2. `HwInfo` — HWiNFO's documented shared-memory interface, only when the
//!    user already runs HWiNFO with "Shared Memory Support" enabled.
//! 3. `LhmWmi` / `OhmWmi` — an already running LibreHardwareMonitor /
//!    OpenHardwareMonitor publishing WMI.
//! 4. Windows / vendor native: NVMe Health (storage temperature, most
//!    authoritative for disks), `nvidia-smi` (official NVIDIA CLI, query
//!    only), Storage Reliability counters, `Win32_VoltageProbe`, ACPI
//!    thermal zone.
//!
//! Rules (permanent):
//! - Values are never invented; missing stays missing (no zero fill).
//! - Min/Max are WinStateDiag SESSION sample values, not lifetime values.
//! - Only fixed ATX rails (+12V, +5V, +3.3V, 5VSB of the motherboard sensor)
//!   are classified against a nominal; dynamic rails (Vcore, VID, VCCSA,
//!   GPU core, PCIe/12VHPWR) are informational.
//! - A LOW/UNKNOWN-confidence rail never produces a red state on its own:
//!   it becomes CHECK SENSOR / VERIFY EXTERNALLY.
//! - Sensor statuses describe readings; WinStateDiag never states that a
//!   PSU is faulty.

#![cfg_attr(not(windows), allow(dead_code))]

use crate::deep_checks::json;
use crate::power::{Rail, RailStatus, classify};

// ---------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SensorKind {
    Temperature,
    Voltage,
    Power,
    Fan,
    Load,
    Current,
    /// Fan duty / other percentages (kept in raw evidence only).
    Control,
}

impl SensorKind {
    pub fn code(self) -> &'static str {
        match self {
            SensorKind::Temperature => "Temperature",
            SensorKind::Voltage => "Voltage",
            SensorKind::Power => "Power",
            SensorKind::Fan => "Fan",
            SensorKind::Load => "Load",
            SensorKind::Current => "Current",
            SensorKind::Control => "Control",
        }
    }
    pub fn unit(self) -> &'static str {
        match self {
            SensorKind::Temperature => "°C",
            SensorKind::Voltage => "V",
            SensorKind::Power => "W",
            SensorKind::Fan => "RPM",
            SensorKind::Load | SensorKind::Control => "%",
            SensorKind::Current => "A",
        }
    }
    /// LibreHardwareMonitor `SensorType` names.
    pub fn from_lhm(t: &str) -> Option<SensorKind> {
        Some(match t {
            "Temperature" => SensorKind::Temperature,
            "Voltage" => SensorKind::Voltage,
            "Power" => SensorKind::Power,
            "Fan" => SensorKind::Fan,
            "Load" => SensorKind::Load,
            "Current" => SensorKind::Current,
            "Control" => SensorKind::Control,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum HwCategory {
    Cpu,
    Gpu,
    Motherboard,
    Memory,
    Storage,
    Psu,
    Other,
}

impl HwCategory {
    pub fn code(self) -> &'static str {
        match self {
            HwCategory::Cpu => "CPU",
            HwCategory::Gpu => "GPU",
            HwCategory::Motherboard => "Motherboard",
            HwCategory::Memory => "Memory",
            HwCategory::Storage => "Storage",
            HwCategory::Psu => "PSU",
            HwCategory::Other => "Other",
        }
    }
    /// LibreHardwareMonitor `HardwareType` names.
    pub fn from_lhm(t: &str) -> HwCategory {
        match t {
            "Cpu" => HwCategory::Cpu,
            t if t.starts_with("Gpu") => HwCategory::Gpu,
            "Motherboard" | "SuperIO" | "EmbeddedController" => HwCategory::Motherboard,
            "Memory" => HwCategory::Memory,
            "Storage" => HwCategory::Storage,
            "Psu" => HwCategory::Psu,
            _ => HwCategory::Other,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Provider {
    NvmeHealth,
    /// v1.0 read-only ATA / SATA SMART (attribute 194 / 190) — disk
    /// temperatures only.
    AtaSmart,
    LhmInternal,
    HwInfo,
    LhmWmi,
    OhmWmi,
    NvidiaSmi,
    StorageReliability,
    Win32VoltageProbe,
    ThermalZone,
}

impl Provider {
    pub const ALL: [Provider; 10] = [
        Provider::NvmeHealth,
        Provider::AtaSmart,
        Provider::LhmInternal,
        Provider::HwInfo,
        Provider::LhmWmi,
        Provider::OhmWmi,
        Provider::NvidiaSmi,
        Provider::StorageReliability,
        Provider::Win32VoltageProbe,
        Provider::ThermalZone,
    ];
    pub fn code(self) -> &'static str {
        match self {
            Provider::NvmeHealth => "NVMe Health",
            Provider::AtaSmart => "ATA SMART",
            Provider::LhmInternal => "LibreHardwareMonitorLib (internal)",
            Provider::HwInfo => "HWiNFO shared memory",
            Provider::LhmWmi => "LibreHardwareMonitor WMI",
            Provider::OhmWmi => "OpenHardwareMonitor WMI",
            Provider::NvidiaSmi => "nvidia-smi",
            Provider::StorageReliability => "Windows Storage Reliability",
            Provider::Win32VoltageProbe => "Win32_VoltageProbe",
            Provider::ThermalZone => "ACPI Thermal Zone",
        }
    }
    pub fn short(self) -> &'static str {
        match self {
            Provider::NvmeHealth => "NVMe",
            Provider::AtaSmart => "SMART",
            Provider::LhmInternal => "LHM",
            Provider::HwInfo => "HWiNFO",
            Provider::LhmWmi => "LHM WMI",
            Provider::OhmWmi => "OHM WMI",
            Provider::NvidiaSmi => "nvidia-smi",
            Provider::StorageReliability => "StorRel",
            Provider::Win32VoltageProbe => "WMI probe",
            Provider::ThermalZone => "ACPI TZ",
        }
    }
    pub fn from_code(s: &str) -> Option<Provider> {
        Provider::ALL
            .into_iter()
            .find(|p| p.code() == s || p.short() == s)
    }
    /// Lower is preferred. NVMe Health is the most authoritative source
    /// for disk temperatures; it never offers anything else.
    pub fn priority(self) -> u8 {
        match self {
            Provider::NvmeHealth => 0,
            Provider::AtaSmart => 0,
            Provider::LhmInternal => 1,
            Provider::HwInfo => 2,
            Provider::LhmWmi => 3,
            Provider::OhmWmi => 4,
            Provider::NvidiaSmi => 5,
            Provider::StorageReliability => 6,
            Provider::Win32VoltageProbe => 7,
            Provider::ThermalZone => 8,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Confidence {
    High,
    Medium,
    Low,
    Unknown,
}

impl Confidence {
    pub fn code(self) -> &'static str {
        match self {
            Confidence::High => "HIGH",
            Confidence::Medium => "MEDIUM",
            Confidence::Low => "LOW",
            Confidence::Unknown => "UNKNOWN",
        }
    }
    /// Can this reading alone drive a red (CRITICAL) state?
    pub fn trusted(self) -> bool {
        matches!(self, Confidence::High | Confidence::Medium)
    }
}

/// One reading of one sensor at one sample instant, as a provider gave it.
#[derive(Debug, Clone, PartialEq)]
pub struct RawReading {
    pub provider: Provider,
    /// Provider identity of the hardware (e.g. `/gpu-nvidia/0`).
    pub hw_id: String,
    pub hw_name: String,
    pub category: HwCategory,
    /// Provider identity of the sensor (e.g. `/gpu-nvidia/0/temperature/0`).
    pub sensor_id: String,
    pub name: String,
    pub kind: SensorKind,
    pub value: Option<f64>,
    /// Board-specific mapping known to the provider (Super I/O board config,
    /// HWiNFO named rail). Drives confidence of voltage rails.
    pub board_mapped: bool,
}

/// One sensor aggregated over the sampling window.
#[derive(Debug, Clone, PartialEq)]
pub struct Sensor {
    pub provider: Provider,
    pub hw_id: String,
    pub hw_name: String,
    pub category: HwCategory,
    pub sensor_id: String,
    pub name: String,
    pub kind: SensorKind,
    /// Last valid value.
    pub value: f64,
    /// Session sample minimum / maximum (valid samples only).
    pub min: f64,
    pub max: f64,
    pub samples: u32,
    pub confidence: Confidence,
    pub timestamp: String,
}

impl Sensor {
    pub fn unit(&self) -> &'static str {
        self.kind.unit()
    }
}

/// Plausibility window per kind. Outside it the provider value is a
/// mis-scaled / unconnected channel and is dropped (never shown).
pub fn plausible(kind: SensorKind, v: f64) -> bool {
    if !v.is_finite() {
        return false;
    }
    match kind {
        // 0 °C (or less) from a PC sensor is an unconnected channel.
        SensorKind::Temperature => v > 0.0 && v < 150.0,
        SensorKind::Voltage => v > 0.05 && v < 30.0,
        SensorKind::Power => (0.0..3000.0).contains(&v),
        // 0 RPM is a legal reading (zero-RPM modes) — kept, never a failure.
        SensorKind::Fan => (0.0..30000.0).contains(&v),
        SensorKind::Load | SensorKind::Control => (0.0..=100.0).contains(&v),
        SensorKind::Current => (0.0..1000.0).contains(&v),
    }
}

fn norm(s: &str) -> String {
    s.to_ascii_lowercase()
}

/// Confidence of one sensor from its provider and kind.
pub fn confidence_of(r: &RawReading) -> Confidence {
    match (r.provider, r.kind) {
        (Provider::Win32VoltageProbe, _) | (Provider::ThermalZone, _) => Confidence::Low,
        (Provider::LhmWmi | Provider::OhmWmi, SensorKind::Voltage) => {
            if r.category == HwCategory::Motherboard && r.board_mapped {
                Confidence::Medium
            } else {
                Confidence::Low
            }
        }
        (Provider::LhmWmi | Provider::OhmWmi, _) => Confidence::Medium,
        (Provider::LhmInternal | Provider::HwInfo, SensorKind::Voltage)
            if r.category == HwCategory::Motherboard =>
        {
            if r.board_mapped {
                Confidence::High
            } else {
                // Recognised sensor chip, generic scaling.
                Confidence::Medium
            }
        }
        // A voltage on unidentified hardware cannot be qualified.
        (Provider::LhmInternal | Provider::HwInfo, SensorKind::Voltage)
            if r.category == HwCategory::Other =>
        {
            Confidence::Unknown
        }
        (Provider::LhmInternal | Provider::HwInfo, _) => Confidence::High,
        (Provider::NvmeHealth | Provider::NvidiaSmi, _) => Confidence::High,
        (Provider::StorageReliability, _) => Confidence::Medium,
        (Provider::AtaSmart, _) => Confidence::High,
    }
}

/// Accumulates samples (session min/max) per (provider, sensor id).
#[derive(Debug, Default, Clone)]
pub struct Sampler {
    sensors: Vec<Sensor>,
    pub samples_taken: u32,
}

impl Sampler {
    pub fn add_sample(&mut self, readings: &[RawReading], timestamp: &str) {
        self.samples_taken += 1;
        for r in readings {
            let Some(v) = r.value.filter(|v| plausible(r.kind, *v)) else {
                continue;
            };
            // A running CPU never draws 0 W: LibreHardwareMonitorLib reports
            // 0.0 when the RAPL MSRs are unreadable (no PawnIO). That is
            // "not available", never a value (Windows gate, MSI Z890).
            if r.kind == SensorKind::Power && r.category == HwCategory::Cpu && v <= 0.0 {
                continue;
            }
            match self
                .sensors
                .iter_mut()
                .find(|s| s.provider == r.provider && s.sensor_id == r.sensor_id)
            {
                Some(s) => {
                    s.value = v;
                    s.min = s.min.min(v);
                    s.max = s.max.max(v);
                    s.samples += 1;
                    s.timestamp = timestamp.to_string();
                }
                None => self.sensors.push(Sensor {
                    provider: r.provider,
                    hw_id: r.hw_id.clone(),
                    hw_name: r.hw_name.clone(),
                    category: r.category,
                    sensor_id: r.sensor_id.clone(),
                    name: r.name.clone(),
                    kind: r.kind,
                    value: v,
                    min: v,
                    max: v,
                    samples: 1,
                    confidence: confidence_of(r),
                    timestamp: timestamp.to_string(),
                }),
            }
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn sensors(&self) -> &[Sensor] {
        &self.sensors
    }

    pub fn into_sensors(self) -> Vec<Sensor> {
        self.sensors
    }
}

// ---------------------------------------------------------------------
// Roles (canonical meaning, independent of UI labels)
// ---------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Role {
    // Temperatures
    CpuCore,
    CpuCoreAverage,
    CpuPackage,
    GpuTemp,
    GpuHotspot,
    GpuMemory,
    BoardTemp,
    ChipsetTemp,
    VrmTemp,
    RamTemp,
    /// Disk temperature keyed by the normalised model name.
    DiskTemp(String),
    // Voltages
    AtxRail(Rail),
    DynamicVoltage(String),
    // Power
    CpuPackagePower,
    CpuCorePower,
    CpuUncorePower,
    GpuPower,
    Gpu12vhpwrPower,
    GpuPciePower,
    // Fans
    CpuFan,
    Pump,
    SystemFan(String),
    GpuFan(String),
}

/// Disk model for display: "S.M.A.R.T.:" / "Drive:" prefixes and
/// serial-like trailing "(…)" / "[…]" groups removed, whitespace collapsed
/// (serials never reach the summary or the dashboard).
pub fn disk_display(model: &str) -> String {
    let mut m = model.trim();
    for prefix in ["S.M.A.R.T.:", "Drive:"] {
        if let Some(rest) = m.strip_prefix(prefix) {
            m = rest.trim();
        }
    }
    let mut s = m.to_string();
    loop {
        let t = s.trim_end();
        if (t.ends_with(')') || t.ends_with(']'))
            && let Some(open) = t.rfind(['(', '['])
            && open > 0
        {
            s = t[..open].trim_end().to_string();
            continue;
        }
        break;
    }
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Normalised disk key (provider-independent identity of a disk model).
pub fn disk_key(model: &str) -> String {
    disk_display(model).to_ascii_lowercase()
}

/// Compact dashboard name: "Samsung SSD 9100 PRO 1TB" → "Samsung 9100".
pub fn disk_short(model: &str) -> String {
    let display = disk_display(model);
    let words: Vec<&str> = display
        .split(' ')
        .filter(|w| {
            let l = w.to_ascii_lowercase();
            !(l == "ssd"
                || l == "pro"
                || l == "series"
                || ((l.ends_with("tb") || l.ends_with("gb"))
                    && l[..l.len() - 2]
                        .chars()
                        .all(|c| c.is_ascii_digit() || c == '.')))
        })
        .take(2)
        .collect();
    if words.is_empty() {
        display.clone()
    } else {
        words.join(" ")
    }
}

/// v1.0 compact disk label for the sensor matrix (fits the name column,
/// keeps duplicate disks apart): "TOSHIBA DT02ABA400 #1" → "TOSHIBA #1",
/// "ST2000VX017-3CV102" → "ST2000", "Samsung 9100" stays.
pub fn disk_compact(label: &str) -> String {
    let (base, idx) = match label.rsplit_once(" #") {
        Some((b, n)) if !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()) => {
            (b.trim(), Some(n))
        }
        _ => (label.trim(), None),
    };
    let short = disk_short(base);
    let compact = if short.chars().count() <= 14 {
        short
    } else {
        let words: Vec<&str> = short.split(' ').collect();
        if words.len() >= 2 && words[0].chars().all(|c| c.is_ascii_alphabetic()) {
            // Vendor + long model number: the vendor names the row.
            words[0].to_string()
        } else {
            // One long model token: its leading letters + digits.
            let w = words[0];
            let letters: String = w.chars().take_while(|c| c.is_ascii_alphabetic()).collect();
            let digits: String = w[letters.len()..]
                .chars()
                .take_while(|c| c.is_ascii_digit())
                .collect();
            if !letters.is_empty() && !digits.is_empty() {
                format!("{letters}{digits}")
            } else {
                w.chars().take(12).collect()
            }
        }
    };
    match idx {
        Some(n) => format!("{compact} #{n}"),
        None => compact,
    }
}

fn has_trailing_index(n: &str) -> bool {
    n.trim_end()
        .chars()
        .last()
        .is_some_and(|c| c.is_ascii_digit())
}

/// Dynamic (non-ATX) voltage rails worth showing, by name.
const DYNAMIC_RAILS: [(&str, &str); 12] = [
    ("vid", "CPU VID"),
    ("vcore", "CPU Vcore"),
    ("cpu core", "CPU Vcore"),
    ("vccsa", "VCCSA"),
    ("vccio", "VCCIO"),
    ("vdd2", "VDD2"),
    ("vnnaon", "VNNAON"),
    ("gpu core", "GPU Core"),
    ("12vhpwr", "GPU 12VHPWR"),
    ("hvpwr", "GPU 12VHPWR"),
    ("16-pin", "GPU 12VHPWR"),
    ("pcie", "PCIe +12V"),
];

/// Integrated GPU (Intel iGPU, AMD APU graphics): a discrete GPU of the
/// same provider is preferred for the GPU summary.
fn integrated_gpu(s: &Sensor) -> bool {
    s.category == HwCategory::Gpu && {
        let id = norm(&s.hw_id);
        let n = norm(&s.hw_name);
        id.contains("intel") || n.starts_with("intel") || n.contains("radeon(tm) graphics")
    }
}

pub fn role_of(s: &Sensor) -> Option<Role> {
    let n = norm(&s.name);
    let cat = s.category;
    match s.kind {
        SensorKind::Temperature => match cat {
            HwCategory::Cpu => {
                if n.contains("distance") || n.contains("tjmax") || n.contains("max") {
                    None
                } else if n.contains("average") {
                    Some(Role::CpuCoreAverage)
                } else if n.contains("package") {
                    Some(Role::CpuPackage)
                } else if n.contains("core") && has_trailing_index(&n) {
                    Some(Role::CpuCore)
                } else {
                    None
                }
            }
            HwCategory::Gpu => {
                if n.contains("hot spot") || n.contains("hotspot") {
                    Some(Role::GpuHotspot)
                } else if n.contains("memory") {
                    Some(Role::GpuMemory)
                } else if n == "gpu core" || n == "gpu temperature" || n == "gpu" || n == "core" {
                    Some(Role::GpuTemp)
                } else {
                    None
                }
            }
            HwCategory::Motherboard => {
                if n.contains("pch") || n.contains("chipset") {
                    Some(Role::ChipsetTemp)
                } else if n.contains("mos") || n.contains("vrm") {
                    Some(Role::VrmTemp)
                } else if n == "system"
                    || n.contains("motherboard")
                    || n.contains("mainboard")
                    || n == "board"
                {
                    Some(Role::BoardTemp)
                } else {
                    None
                }
            }
            HwCategory::Memory => {
                if n.contains("dimm") || n.contains("temperature") || n.contains("spd") {
                    Some(Role::RamTemp)
                } else {
                    None
                }
            }
            HwCategory::Storage => {
                // First / composite drive temperature only.
                if n == "temperature"
                    || n == "drive temperature"
                    || n == "composite temperature"
                    || n == "temperature 1"
                    || n == "composite"
                {
                    Some(Role::DiskTemp(disk_key(&s.hw_name)))
                } else {
                    None
                }
            }
            _ => None,
        },
        SensorKind::Voltage => {
            if cat == HwCategory::Motherboard
                && let Some(rail) = Rail::from_sensor_name(&s.name)
            {
                return Some(Role::AtxRail(rail));
            }
            if matches!(
                cat,
                HwCategory::Cpu | HwCategory::Gpu | HwCategory::Motherboard
            ) {
                for (pat, label) in DYNAMIC_RAILS {
                    if n.contains(pat) {
                        return Some(Role::DynamicVoltage(label.to_string()));
                    }
                }
            }
            None
        }
        SensorKind::Power => match cat {
            HwCategory::Cpu => {
                if n.contains("uncore") || n.contains("system agent") {
                    Some(Role::CpuUncorePower)
                } else if n.contains("ia core") || n == "cpu cores" || n == "cores" {
                    Some(Role::CpuCorePower)
                } else if n.contains("package") {
                    Some(Role::CpuPackagePower)
                } else {
                    None
                }
            }
            HwCategory::Gpu => {
                if n.contains("12vhpwr") || n.contains("16-pin") || n.contains("hvpwr") {
                    Some(Role::Gpu12vhpwrPower)
                } else if n.contains("pcie") {
                    Some(Role::GpuPciePower)
                } else if n == "gpu power"
                    || n == "gpu package"
                    || n.contains("board power")
                    || n == "power draw"
                    || n == "gpu"
                {
                    Some(Role::GpuPower)
                } else {
                    None
                }
            }
            _ => None,
        },
        SensorKind::Fan => match cat {
            HwCategory::Gpu => Some(Role::GpuFan(s.name.clone())),
            HwCategory::Motherboard | HwCategory::Other => {
                if n.contains("pump") || n.contains("aio") {
                    Some(Role::Pump)
                } else if n.starts_with("cpu") {
                    Some(Role::CpuFan)
                } else {
                    Some(Role::SystemFan(s.name.clone()))
                }
            }
            _ => None,
        },
        _ => None,
    }
}

// ---------------------------------------------------------------------
// Summary: canonical values, provenance, mismatches, power state
// ---------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct Canonical {
    pub role: Role,
    /// Label from the sensor/hardware (disk model, fan name); UI labels for
    /// fixed roles come from i18n.
    pub label: String,
    pub value: f64,
    pub min: f64,
    pub max: f64,
    pub kind: SensorKind,
    pub provider: Provider,
    pub confidence: Confidence,
    /// Computed from several sensors (e.g. CPU core average).
    pub derived: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Mismatch {
    pub role: Role,
    pub canonical: (Provider, f64),
    pub other: (Provider, f64),
    pub unit: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PowerStatus {
    NoData,
    Excellent,
    /// Low/unknown-confidence reading outside tolerance: not red.
    CheckSensor,
    Attention,
    Critical,
}

impl PowerStatus {
    pub fn code(self) -> &'static str {
        match self {
            PowerStatus::NoData => "NO DATA",
            PowerStatus::Excellent => "EXCELLENT",
            PowerStatus::CheckSensor => "CHECK SENSOR / VERIFY EXTERNALLY",
            PowerStatus::Attention => "ATTENTION",
            PowerStatus::Critical => "CRITICAL",
        }
    }
    pub fn text(self, ru: bool) -> &'static str {
        match (self, ru) {
            (PowerStatus::NoData, true) => "Нет данных",
            (PowerStatus::NoData, false) => "No data",
            (PowerStatus::Excellent, true) => "Отлично",
            (PowerStatus::Excellent, false) => "Excellent",
            (PowerStatus::CheckSensor, true) => "Проверьте датчик",
            (PowerStatus::CheckSensor, false) => "Check sensor",
            (PowerStatus::Attention, true) => "Внимание!",
            (PowerStatus::Attention, false) => "Attention!",
            (PowerStatus::Critical, true) => "Критично!",
            (PowerStatus::Critical, false) => "Critical!",
        }
    }
    /// Wording for the state: readings only, never a PSU verdict.
    pub fn message(self, ru: bool) -> &'static str {
        match (self, ru) {
            (PowerStatus::NoData, true) => "Данные датчиков питания недоступны.",
            (PowerStatus::NoData, false) => "Power sensor data not available.",
            (PowerStatus::Excellent, true) => "Показания датчиков в пределах нормы.",
            (PowerStatus::Excellent, false) => "Sensor readings are within range.",
            (PowerStatus::CheckSensor, true) => {
                "Показание датчика низкой достоверности. Проверьте внешним измерением."
            }
            (PowerStatus::CheckSensor, false) => {
                "Low-confidence sensor reading. Verify with an external measurement."
            }
            (_, true) => {
                "Обнаружено отклонение линии питания. Рекомендуется подтверждение внешним тестером/мультиметром."
            }
            (_, false) => {
                "Power-line deviation detected. Confirmation with an external tester/multimeter is recommended."
            }
        }
    }
}

/// Status of one ATX rail from its worst session sample.
pub fn rail_status(rail: Rail, c: &Canonical) -> PowerStatus {
    let n = rail.nominal();
    let worst = [c.value, c.min, c.max]
        .iter()
        .map(|v| classify((v - n) / n * 100.0))
        .max()
        .unwrap_or(RailStatus::Excellent);
    match worst {
        RailStatus::Excellent => PowerStatus::Excellent,
        _ if !c.confidence.trusted() => PowerStatus::CheckSensor,
        RailStatus::Attention => PowerStatus::Attention,
        RailStatus::Critical => PowerStatus::Critical,
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Summary {
    pub temps: Vec<Canonical>,
    pub rails: Vec<(Rail, Canonical, PowerStatus)>,
    pub dynamic_voltages: Vec<Canonical>,
    pub power: Vec<Canonical>,
    pub fans: Vec<Canonical>,
    pub mismatches: Vec<Mismatch>,
}

impl Summary {
    pub fn power_status(&self) -> PowerStatus {
        self.rails
            .iter()
            .map(|(_, _, s)| *s)
            .max()
            .unwrap_or(PowerStatus::NoData)
    }
    pub fn is_empty(&self) -> bool {
        self.temps.is_empty()
            && self.rails.is_empty()
            && self.dynamic_voltages.is_empty()
            && self.power.is_empty()
            && self.fans.is_empty()
    }
}

fn mismatch_threshold(kind: SensorKind, a: f64, b: f64) -> bool {
    let d = (a - b).abs();
    match kind {
        SensorKind::Temperature => d > 5.0,
        SensorKind::Voltage => d > a.abs().max(b.abs()) * 0.02 && d > 0.05,
        SensorKind::Power => d > 5.0 && d > a.abs().max(b.abs()) * 0.20,
        SensorKind::Fan => d > 100.0 && d > a.abs().max(b.abs()) * 0.15,
        _ => false,
    }
}

fn canonical_from(role: Role, s: &Sensor) -> Canonical {
    let label = match &role {
        Role::DiskTemp(k) => match k.rsplit_once(" #") {
            Some((_, n)) if n.chars().all(|c| c.is_ascii_digit()) => {
                format!("{} #{n}", disk_display(&s.hw_name))
            }
            _ => disk_display(&s.hw_name),
        },
        _ => s.name.clone(),
    };
    Canonical {
        role,
        label,
        value: s.value,
        min: s.min,
        max: s.max,
        kind: s.kind,
        provider: s.provider,
        confidence: s.confidence,
        derived: false,
    }
}

/// Builds the canonical summary from every provider's sensors.
///
/// Per role the provider with the best priority wins; every other provider
/// whose value differs materially is recorded as a SENSOR SOURCE MISMATCH
/// (both values kept). CPU temperature = average of all cores (provider
/// "Core Average", else the mean of the per-core sensors, else Package);
/// per-core values never reach the summary.
pub fn summarize(sensors: &[Sensor]) -> Summary {
    use std::collections::BTreeMap;
    // Several physical disks of the same model (e.g. two TOSHIBA DT02ABA400)
    // must stay separate: within a provider they get "#n" by hardware id.
    let mut disk_ids: BTreeMap<(Provider, String), Vec<&str>> = BTreeMap::new();
    for s in sensors {
        if let Some(Role::DiskTemp(k)) = role_of(s) {
            let ids = disk_ids.entry((s.provider, k)).or_default();
            if !ids.contains(&s.hw_id.as_str()) {
                ids.push(&s.hw_id);
            }
        }
    }
    for ids in disk_ids.values_mut() {
        ids.sort();
    }
    let mut by_role: BTreeMap<Role, Vec<&Sensor>> = BTreeMap::new();
    for s in sensors {
        if let Some(mut r) = role_of(s) {
            if let Role::DiskTemp(k) = &r
                && let Some(ids) = disk_ids.get(&(s.provider, k.clone()))
                && ids.len() > 1
            {
                let n = ids.iter().position(|i| *i == s.hw_id).unwrap_or(0) + 1;
                r = Role::DiskTemp(format!("{k} #{n}"));
            }
            by_role.entry(r).or_default().push(s);
        }
    }
    let mut out = Summary::default();
    let mut pick = |role: Role, list: &Vec<&Sensor>| -> Canonical {
        let mut v = list.clone();
        v.sort_by_key(|s| (s.provider.priority(), integrated_gpu(s), s.confidence));
        let best = v[0];
        for other in &v[1..] {
            if other.provider != best.provider
                && mismatch_threshold(best.kind, best.value, other.value)
            {
                out.mismatches.push(Mismatch {
                    role: role.clone(),
                    canonical: (best.provider, best.value),
                    other: (other.provider, other.value),
                    unit: best.kind.unit(),
                });
            }
        }
        canonical_from(role, best)
    };
    let mut temps = Vec::new();
    let mut rails = Vec::new();
    let mut dynamic = Vec::new();
    let mut power = Vec::new();
    let mut fans = Vec::new();
    for (role, list) in &by_role {
        match role {
            Role::CpuCore | Role::CpuCoreAverage | Role::CpuPackage => {}
            Role::GpuTemp
            | Role::GpuHotspot
            | Role::GpuMemory
            | Role::BoardTemp
            | Role::ChipsetTemp
            | Role::VrmTemp
            | Role::DiskTemp(_) => temps.push(pick(role.clone(), list)),
            Role::RamTemp => {
                // RAM: hottest DIMM (max over DIMMs of the best provider).
                let best_p = list
                    .iter()
                    .map(|s| s.provider.priority())
                    .min()
                    .unwrap_or(0);
                let hottest = list
                    .iter()
                    .filter(|s| s.provider.priority() == best_p)
                    .max_by(|a, b| a.value.total_cmp(&b.value))
                    .unwrap();
                let mut c = canonical_from(Role::RamTemp, hottest);
                c.derived = list.len() > 1;
                temps.push(c);
            }
            Role::AtxRail(rail) => {
                let c = pick(role.clone(), list);
                let st = rail_status(*rail, &c);
                rails.push((*rail, c, st));
            }
            Role::DynamicVoltage(_) => dynamic.push(pick(role.clone(), list)),
            Role::CpuPackagePower
            | Role::CpuCorePower
            | Role::CpuUncorePower
            | Role::GpuPower
            | Role::Gpu12vhpwrPower
            | Role::GpuPciePower => power.push(pick(role.clone(), list)),
            Role::CpuFan | Role::Pump | Role::SystemFan(_) | Role::GpuFan(_) => {
                fans.push(pick(role.clone(), list))
            }
        }
    }
    // CPU temperature: average of all cores.
    if let Some(cpu) = cpu_temperature(&by_role) {
        temps.insert(0, cpu);
    }
    if let Some(pkg) = by_role.get(&Role::CpuPackage) {
        let c = pick(Role::CpuPackage, pkg);
        temps.insert(temps.len().min(1), c);
    }
    temps.sort_by_key(|c| temp_order(&c.role));
    rails.sort_by_key(|(r, _, _)| *r);
    power.sort_by_key(|c| power_order(&c.role));
    fans.sort_by_key(|c| fan_order(&c.role));
    out.temps = temps;
    out.rails = rails;
    out.dynamic_voltages = dynamic;
    out.power = power;
    out.fans = fans;
    out
}

fn cpu_temperature(by_role: &std::collections::BTreeMap<Role, Vec<&Sensor>>) -> Option<Canonical> {
    let best = |l: &Vec<&Sensor>| -> Option<Sensor> {
        l.iter()
            .min_by_key(|s| (s.provider.priority(), s.confidence))
            .map(|s| (*s).clone())
    };
    if let Some(avg) = by_role.get(&Role::CpuCoreAverage).and_then(best) {
        return Some(canonical_from(Role::CpuCoreAverage, &avg));
    }
    if let Some(cores) = by_role.get(&Role::CpuCore) {
        let p = cores.iter().map(|s| s.provider.priority()).min()?;
        let set: Vec<&&Sensor> = cores
            .iter()
            .filter(|s| s.provider.priority() == p)
            .collect();
        let n = set.len() as f64;
        let mean = |f: fn(&Sensor) -> f64| set.iter().map(|s| f(s)).sum::<f64>() / n;
        let first = set[0];
        return Some(Canonical {
            role: Role::CpuCoreAverage,
            label: "CPU".into(),
            value: mean(|s| s.value),
            min: mean(|s| s.min),
            max: mean(|s| s.max),
            kind: SensorKind::Temperature,
            provider: first.provider,
            confidence: first.confidence,
            derived: true,
        });
    }
    None
}

fn temp_order(r: &Role) -> (u8, String) {
    match r {
        Role::CpuCoreAverage => (0, String::new()),
        Role::CpuPackage => (1, String::new()),
        Role::GpuTemp => (2, String::new()),
        Role::GpuHotspot => (3, String::new()),
        Role::GpuMemory => (4, String::new()),
        Role::BoardTemp => (5, String::new()),
        Role::ChipsetTemp => (6, String::new()),
        Role::VrmTemp => (7, String::new()),
        Role::RamTemp => (8, String::new()),
        Role::DiskTemp(k) => (9, k.clone()),
        _ => (10, String::new()),
    }
}

fn power_order(r: &Role) -> u8 {
    match r {
        Role::CpuPackagePower => 0,
        Role::CpuCorePower => 1,
        Role::CpuUncorePower => 2,
        Role::GpuPower => 3,
        Role::Gpu12vhpwrPower => 4,
        Role::GpuPciePower => 5,
        _ => 6,
    }
}

fn fan_order(r: &Role) -> (u8, String) {
    match r {
        Role::CpuFan => (0, String::new()),
        Role::Pump => (1, String::new()),
        Role::SystemFan(n) => (2, n.clone()),
        Role::GpuFan(n) => (3, n.clone()),
        _ => (4, String::new()),
    }
}

/// Roles shown on the compact dashboard (per-core never; package and
/// secondary GPU memory / VRM stay in Details).
/// v0.4.5 colour level of one dashboard number (only the number is
/// coloured): green normal, yellow near a threshold, red critical, neutral
/// when no reliable reference exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadingLevel {
    Unknown,
    Normal,
    Near,
    Critical,
}

/// Disk temperature against the drive-reported thresholds (NVMe Identify
/// WCTEMP / CCTEMP). No threshold = Unknown (never an invented limit).
pub fn disk_temp_level(value: f64, warning: Option<f64>, critical: Option<f64>) -> ReadingLevel {
    if critical.is_some_and(|c| value >= c) {
        ReadingLevel::Critical
    } else if warning.is_some_and(|w| value >= w - 5.0) {
        ReadingLevel::Near
    } else if warning.is_some() || critical.is_some() {
        ReadingLevel::Normal
    } else {
        ReadingLevel::Unknown
    }
}

pub fn rail_level(status: PowerStatus) -> ReadingLevel {
    match status {
        PowerStatus::Excellent => ReadingLevel::Normal,
        PowerStatus::Attention | PowerStatus::CheckSensor => ReadingLevel::Near,
        PowerStatus::Critical => ReadingLevel::Critical,
        PowerStatus::NoData => ReadingLevel::Unknown,
    }
}

/// ATX reference band "11.40–12.60 V" (ATX ±5 %).
pub fn rail_reference(rail: Rail) -> String {
    let n = rail.nominal();
    // Round half up (3.135 → 3.14, 3.465 → 3.47): binary floats would
    // otherwise print the ATX +3.3V band as "3.13".
    let r = |v: f64| (v * 100.0 + 1e-6).round() / 100.0;
    format!("{:.2}–{:.2} V", r(n * 0.95), r(n * 1.05))
}

/// "W 83° / C 85°" from the drive-reported thresholds, if any.
pub fn disk_reference(warning: Option<f64>, critical: Option<f64>) -> Option<String> {
    match (warning, critical) {
        (Some(w), Some(c)) => Some(format!("W {w:.0}° / C {c:.0}°")),
        (Some(w), None) => Some(format!("W {w:.0}°")),
        (None, Some(c)) => Some(format!("C {c:.0}°")),
        (None, None) => None,
    }
}

pub fn on_dashboard(r: &Role) -> bool {
    matches!(
        r,
        Role::CpuCoreAverage
            | Role::GpuTemp
            | Role::GpuHotspot
            | Role::BoardTemp
            | Role::ChipsetTemp
            | Role::RamTemp
            | Role::DiskTemp(_)
            | Role::CpuPackagePower
            | Role::GpuPower
            | Role::CpuFan
            | Role::Pump
            | Role::SystemFan(_)
    )
}

/// Prepared (not yet wired into any verdict): an ATX-rail deviation with
/// trusted confidence PLUS Kernel-Power 41 / unexpected shutdowns /
/// bugchecks may raise suspicion of power instability. The wording is
/// fixed — never "failed PSU".
#[allow(dead_code)] // prepared for the future event correlation (v0.4.5)
pub fn power_instability_hint(
    status: PowerStatus,
    kernel_power_41: usize,
    unexpected_shutdowns: usize,
    bugchecks: usize,
) -> Option<&'static str> {
    let rail_concern = matches!(status, PowerStatus::Attention | PowerStatus::Critical);
    (rail_concern && (kernel_power_41 + unexpected_shutdowns + bugchecks) > 0)
        .then_some("possible power instability")
}

// ---------------------------------------------------------------------
// Provider status
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderState {
    Available,
    Partial,
    Unavailable,
    BlockedByWindowsSecurity,
    ProviderError,
}

impl ProviderState {
    pub fn code(self) -> &'static str {
        match self {
            ProviderState::Available => "AVAILABLE",
            ProviderState::Partial => "PARTIAL",
            ProviderState::Unavailable => "UNAVAILABLE",
            ProviderState::BlockedByWindowsSecurity => "BLOCKED_BY_WINDOWS_SECURITY",
            ProviderState::ProviderError => "PROVIDER_ERROR",
        }
    }
    pub fn from_code(s: &str) -> Option<ProviderState> {
        [
            ProviderState::Available,
            ProviderState::Partial,
            ProviderState::Unavailable,
            ProviderState::BlockedByWindowsSecurity,
            ProviderState::ProviderError,
        ]
        .into_iter()
        .find(|p| p.code() == s)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProviderReport {
    pub provider: Provider,
    pub state: ProviderState,
    pub detail: String,
}

/// Result of one sampling run.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Snapshot {
    pub captured_at: String,
    pub samples: u32,
    pub interval_ms: u32,
    pub sensors: Vec<Sensor>,
    pub providers: Vec<ProviderReport>,
    /// v1.0 lightweight process context taken while the sensors were
    /// sampled (explains a high CPU load; never a fault by itself).
    pub process_context: Option<ProcessContext>,
}

// ---------------------------------------------------------------------
// v1.0 high-CPU process context (sensor sampling)
// ---------------------------------------------------------------------

/// System CPU load from which the top processes are recorded.
pub const HIGH_CPU_THRESHOLD: f64 = 50.0;

#[derive(Debug, Clone, PartialEq, Default)]
pub struct ProcessSample {
    pub name: String,
    pub pid: u32,
    /// Share of the WHOLE machine (normalised by logical processors).
    pub cpu_percent: f64,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct ProcessContext {
    pub timestamp: String,
    pub system_cpu_percent: f64,
    pub logical_processors: u32,
    /// `system_cpu_percent >= HIGH_CPU_THRESHOLD`.
    pub high_load: bool,
    /// Top 5 by CPU — recorded only under high load.
    pub top: Vec<ProcessSample>,
}

/// Read-only snapshot: system CPU % and the processes by CPU, from the
/// formatted performance classes (queried twice: the first read of a
/// formatted counter is often 0).
pub const PROCESS_PS1: &str = r#"$ErrorActionPreference = 'SilentlyContinue'
$null = Get-CimInstance Win32_PerfFormattedData_PerfProc_Process
Start-Sleep -Milliseconds 1000
$sys = (Get-CimInstance Win32_PerfFormattedData_PerfOS_Processor -Filter "Name='_Total'").PercentProcessorTime
$p = Get-CimInstance Win32_PerfFormattedData_PerfProc_Process | Where-Object { $_.Name -ne '_Total' -and $_.Name -ne 'Idle' } | Sort-Object PercentProcessorTime -Descending | Select-Object -First 5
$o = [ordered]@{ t = (Get-Date -Format 's'); sys = [double]$sys; n = [Environment]::ProcessorCount; top = @($p | ForEach-Object { [ordered]@{ name = [string]$_.Name; pid = [int]$_.IDProcess; cpu = [double]$_.PercentProcessorTime } }) }
'WSD_PROC ' + ($o | ConvertTo-Json -Compress -Depth 3)
"#;

pub fn parse_process_context(stdout: &str) -> Option<ProcessContext> {
    let v = crate::ps_exec::marked_line(stdout, "WSD_PROC ").and_then(json::parse)?;
    let num = |x: Option<&json::Value>| match x {
        Some(json::Value::Num(n)) => Some(*n),
        _ => None,
    };
    let system = num(v.get("sys"))?;
    let n = num(v.get("n")).unwrap_or(1.0).max(1.0);
    let high = system >= HIGH_CPU_THRESHOLD;
    let items = match v.get("top") {
        Some(json::Value::Arr(a)) => a.clone(),
        Some(o @ json::Value::Obj(_)) => vec![o.clone()],
        _ => Vec::new(),
    };
    let top = if high {
        items
            .iter()
            .filter_map(|it| {
                let name = it.get("name")?.as_str()?.to_string();
                // "chrome#3" → "chrome" (perf instance suffix).
                let name = name.split('#').next().unwrap_or(&name).to_string();
                Some(ProcessSample {
                    name,
                    pid: num(it.get("pid")).unwrap_or(0.0) as u32,
                    cpu_percent: (num(it.get("cpu")).unwrap_or(0.0) / n * 10.0).round() / 10.0,
                })
            })
            .take(5)
            .collect()
    } else {
        Vec::new()
    };
    Some(ProcessContext {
        timestamp: v
            .get("t")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string(),
        system_cpu_percent: system,
        logical_processors: n as u32,
        high_load: high,
        top,
    })
}

pub fn process_context_json(p: Option<&ProcessContext>) -> String {
    let Some(p) = p else {
        return "null".into();
    };
    let top: Vec<String> = p
        .top
        .iter()
        .map(|s| {
            format!(
                "{{\"name\": {}, \"pid\": {}, \"cpu_percent\": {:.1}}}",
                json::string(&s.name),
                s.pid,
                s.cpu_percent
            )
        })
        .collect();
    format!(
        "{{\"timestamp\": {}, \"system_cpu_percent\": {:.1}, \"logical_processors\": {}, \"high_load\": {}, \"threshold_percent\": {:.0}, \"top_processes\": [{}], \"note\": \"High CPU load is context for the readings, not a fault by itself.\"}}",
        json::string(&p.timestamp),
        p.system_cpu_percent,
        p.logical_processors,
        p.high_load,
        HIGH_CPU_THRESHOLD,
        top.join(", ")
    )
}

impl Snapshot {
    /// Overall state of the sensor layer.
    pub fn state(&self) -> ProviderState {
        let s = summarize(&self.sensors);
        let has_cpu = s.temps.iter().any(|c| c.role == Role::CpuCoreAverage);
        let has_gpu = s.temps.iter().any(|c| c.role == Role::GpuTemp);
        if s.is_empty() {
            if self
                .providers
                .iter()
                .any(|p| p.state == ProviderState::BlockedByWindowsSecurity)
            {
                ProviderState::BlockedByWindowsSecurity
            } else if self
                .providers
                .iter()
                .all(|p| p.state == ProviderState::ProviderError)
                && !self.providers.is_empty()
            {
                ProviderState::ProviderError
            } else {
                ProviderState::Unavailable
            }
        } else if has_cpu && has_gpu && !s.rails.is_empty() {
            ProviderState::Available
        } else {
            ProviderState::Partial
        }
    }

    /// Provider of most canonical values (for the manifest).
    pub fn main_provider(&self) -> Option<Provider> {
        let s = summarize(&self.sensors);
        let mut count: Vec<(Provider, usize)> = Vec::new();
        for c in s
            .temps
            .iter()
            .chain(s.dynamic_voltages.iter())
            .chain(s.power.iter())
            .chain(s.fans.iter())
            .chain(s.rails.iter().map(|(_, c, _)| c))
        {
            match count.iter_mut().find(|(p, _)| *p == c.provider) {
                Some((_, n)) => *n += 1,
                None => count.push((c.provider, 1)),
            }
        }
        count
            .into_iter()
            .max_by_key(|(p, n)| (*n, std::cmp::Reverse(p.priority())))
            .map(|(p, _)| p)
    }
}

// ---------------------------------------------------------------------
// Parsers (provider outputs → RawReading)
// ---------------------------------------------------------------------

/// One `WSD_SENS <json>` line of the PowerShell sampler: an array of
/// `{p, hwid, hwtype, hw, sid, type, name, value, bm}` objects.
pub fn parse_sampler_line(line: &str) -> Option<Vec<RawReading>> {
    let v = json::parse(line.strip_prefix("WSD_SENS ")?)?;
    let rows = match v {
        json::Value::Arr(a) => a,
        o @ json::Value::Obj(_) => vec![o],
        _ => return Some(Vec::new()),
    };
    let s = |r: &json::Value, k: &str| r.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
    Some(
        rows.iter()
            .filter_map(|r| {
                let provider = Provider::from_code(&s(r, "p"))?;
                let kind = SensorKind::from_lhm(&s(r, "type"))?;
                let hwtype = s(r, "hwtype");
                let value = match r.get("value") {
                    Some(json::Value::Num(n)) => Some(*n),
                    _ => None,
                };
                Some(RawReading {
                    provider,
                    hw_id: s(r, "hwid"),
                    hw_name: s(r, "hw"),
                    category: HwCategory::from_lhm(&hwtype),
                    sensor_id: s(r, "sid"),
                    name: s(r, "name"),
                    kind,
                    value,
                    board_mapped: matches!(r.get("bm"), Some(json::Value::Bool(true))),
                })
            })
            .collect(),
    )
}

/// `WSD_SENS_STATUS {"p": provider, "state": CODE, "detail": text}` lines.
pub fn parse_status_line(line: &str) -> Option<ProviderReport> {
    let v = json::parse(line.strip_prefix("WSD_SENS_STATUS ")?)?;
    let s = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
    Some(ProviderReport {
        provider: Provider::from_code(&s("p"))?,
        state: ProviderState::from_code(&s("state"))?,
        detail: s("detail"),
    })
}

/// Parses the full sampler stdout into per-sample readings + provider
/// reports. Lines `WSD_SENS_T <iso time>` start a new sample.
pub fn parse_sampler_output(stdout: &str) -> (Vec<(String, Vec<RawReading>)>, Vec<ProviderReport>) {
    let mut samples: Vec<(String, Vec<RawReading>)> = Vec::new();
    let mut reports = Vec::new();
    for line in stdout.lines().map(str::trim) {
        if let Some(t) = line.strip_prefix("WSD_SENS_T ") {
            samples.push((t.trim().to_string(), Vec::new()));
        } else if line.starts_with("WSD_SENS_STATUS ") {
            if let Some(r) = parse_status_line(line) {
                reports.push(r);
            }
        } else if line.starts_with("WSD_SENS ")
            && let Some(rows) = parse_sampler_line(line)
        {
            if samples.is_empty() {
                samples.push((String::new(), Vec::new()));
            }
            samples.last_mut().unwrap().1.extend(rows);
        }
    }
    (samples, reports)
}

// ---- HWiNFO shared memory (documented layout, packed) -----------------

pub const HWINFO_SIGNATURE: u32 = 0x5369_5748; // "HWiS"
pub const HWINFO_SM_NAME: &str = "Global\\HWiNFO_SENS_SM2";

fn rd_u32(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(o..o + 4)?.try_into().ok()?))
}
fn rd_f64(b: &[u8], o: usize) -> Option<f64> {
    Some(f64::from_le_bytes(b.get(o..o + 8)?.try_into().ok()?))
}
fn rd_str(b: &[u8], o: usize, len: usize) -> Option<String> {
    let raw = b.get(o..o + len)?;
    let end = raw.iter().position(|c| *c == 0).unwrap_or(len);
    // ANSI (Latin-1 superset for the characters HWiNFO uses: '°').
    Some(
        raw[..end]
            .iter()
            .map(|c| *c as char)
            .collect::<String>()
            .trim()
            .to_string(),
    )
}

/// HWiNFO sensor group name → category.
pub fn hwinfo_category(sensor: &str) -> HwCategory {
    let s = sensor.trim();
    let l = norm(s);
    if l.starts_with("cpu [") || l.starts_with("cpu:") {
        HwCategory::Cpu
    } else if l.starts_with("gpu [") || l.starts_with("gpu:") {
        HwCategory::Gpu
    } else if l.starts_with("s.m.a.r.t.") || l.starts_with("drive:") {
        HwCategory::Storage
    } else if l.contains("dimm") || l.starts_with("memory") || l.starts_with("spd") {
        HwCategory::Memory
    } else if [
        "nuvoton",
        "(ite",
        " ite ",
        "fintek",
        "nct6",
        "winbond",
        "embedded controller",
        " ec)",
        "(ec",
        "asus ec",
        "msi ec",
    ]
    .iter()
    .any(|k| l.contains(k))
    {
        HwCategory::Motherboard
    } else if l.contains("psu") || l.contains("corsair link") {
        HwCategory::Psu
    } else {
        HwCategory::Other
    }
}

/// Parses a copy of the HWiNFO shared memory block. Uses the element
/// sizes from the header (forward compatible with newer revisions).
pub fn parse_hwinfo_shm(b: &[u8]) -> Result<Vec<RawReading>, String> {
    let sig = rd_u32(b, 0).ok_or("short header")?;
    if sig != HWINFO_SIGNATURE {
        return Err(if sig == 0x4441_4544 {
            "HWiNFO shared memory inactive (DEAD)".into()
        } else {
            "not an HWiNFO shared memory block".into()
        });
    }
    let off_s = rd_u32(b, 20).ok_or("header")? as usize;
    let size_s = rd_u32(b, 24).ok_or("header")? as usize;
    let num_s = rd_u32(b, 28).ok_or("header")? as usize;
    let off_r = rd_u32(b, 32).ok_or("header")? as usize;
    let size_r = rd_u32(b, 36).ok_or("header")? as usize;
    let num_r = rd_u32(b, 40).ok_or("header")? as usize;
    if size_s < 264 || size_r < 316 || num_s > 4096 || num_r > 65536 {
        return Err("unexpected HWiNFO layout".into());
    }
    if b.len() < off_s + num_s * size_s || b.len() < off_r + num_r * size_r {
        return Err("HWiNFO shared memory block truncated".into());
    }
    let mut groups = Vec::with_capacity(num_s);
    for i in 0..num_s {
        let o = off_s + i * size_s;
        let id = rd_u32(b, o).ok_or("sensor section truncated")?;
        let inst = rd_u32(b, o + 4).ok_or("sensor section truncated")?;
        let name = rd_str(b, o + 8, 128).ok_or("sensor section truncated")?;
        groups.push((format!("{id:08X}:{inst}"), name));
    }
    let mut out = Vec::with_capacity(num_r);
    for i in 0..num_r {
        let o = off_r + i * size_r;
        let t = rd_u32(b, o).ok_or("reading section truncated")?;
        let si = rd_u32(b, o + 4).ok_or("reading section truncated")? as usize;
        let rid = rd_u32(b, o + 8).ok_or("reading section truncated")?;
        let label = rd_str(b, o + 12, 128).ok_or("reading section truncated")?;
        let unit = rd_str(b, o + 268, 16).ok_or("reading section truncated")?;
        let value = rd_f64(b, o + 284).ok_or("reading section truncated")?;
        let kind = match t {
            1 => SensorKind::Temperature,
            2 => SensorKind::Voltage,
            3 => SensorKind::Fan,
            4 => SensorKind::Current,
            5 => SensorKind::Power,
            7 => SensorKind::Load,
            _ => continue,
        };
        // Temperatures in °F are converted; anything else non-°C is skipped.
        let value = match (kind, unit.as_str()) {
            (SensorKind::Temperature, u) if u.ends_with('F') => (value - 32.0) / 1.8,
            (SensorKind::Power, u) if u.contains('%') => continue,
            _ => value,
        };
        let Some((gid, gname)) = groups.get(si) else {
            continue;
        };
        let category = hwinfo_category(gname);
        let board_mapped = kind == SensorKind::Voltage
            && category == HwCategory::Motherboard
            && Rail::from_sensor_name(&label).is_some();
        let hw_name = match category {
            HwCategory::Storage => disk_display(gname),
            _ => gname.clone(),
        };
        out.push(RawReading {
            provider: Provider::HwInfo,
            hw_id: gid.clone(),
            hw_name,
            category,
            sensor_id: format!("{gid}/{rid:08X}"),
            name: label,
            kind,
            value: Some(value),
            board_mapped,
        });
    }
    Ok(out)
}

// ---------------------------------------------------------------------
// PowerShell sampler (LHM internal + WMI monitors + Windows native)
// ---------------------------------------------------------------------

/// Read-only sampler. `$LhmDir` = extracted bundled LibreHardwareMonitorLib
/// folder ('' when not bundled). Emits `WSD_SENS_T`, `WSD_SENS` and
/// `WSD_SENS_STATUS` lines. Never installs or writes anything.
pub const SAMPLER_PS1: &str = r#"param([string]$LhmDir = '', [int]$Samples = 10, [int]$IntervalMs = 1000)
$ErrorActionPreference = 'Continue'
function J($o) { ConvertTo-Json -InputObject $o -Compress -Depth 4 }
function Status($p, $state, $detail) { Write-Output ('WSD_SENS_STATUS ' + (J ([ordered]@{ p = $p; state = $state; detail = [string]$detail }))) }
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
# ---- LibreHardwareMonitorLib (internal, bundled) ----
$lhm = $null; $pawn = $false
try { $pawn = [bool](Get-CimInstance Win32_SystemDriver -Filter "Name='PawnIO'" -ErrorAction Stop | Where-Object { $_.State -eq 'Running' }) } catch { }
if ($LhmDir -and (Test-Path -LiteralPath (Join-Path $LhmDir 'LibreHardwareMonitorLib.dll'))) {
  try {
    $script:asm = @{}; Get-ChildItem -LiteralPath $LhmDir -Filter *.dll | ForEach-Object { $script:asm[[IO.Path]::GetFileNameWithoutExtension($_.Name)] = $_.FullName }
    [AppDomain]::CurrentDomain.add_AssemblyResolve({ param($s, $e) $n = (New-Object Reflection.AssemblyName($e.Name)).Name; if ($script:asm.ContainsKey($n)) { return [Reflection.Assembly]::LoadFrom($script:asm[$n]) }; return $null })
    [void][Reflection.Assembly]::LoadFrom((Join-Path $LhmDir 'LibreHardwareMonitorLib.dll'))
    $lhm = New-Object LibreHardwareMonitor.Hardware.Computer
    foreach ($f in 'IsCpuEnabled','IsGpuEnabled','IsMotherboardEnabled','IsMemoryEnabled','IsStorageEnabled','IsControllerEnabled','IsPsuEnabled') { try { $lhm.$f = $true } catch { } }
    foreach ($f in 'IsNetworkEnabled','IsBatteryEnabled') { try { $lhm.$f = $false } catch { } }
    $lhm.Open()
    $detail = if ($pawn) { 'PawnIO driver present (installed by the user)' } else { 'PawnIO low-level driver not installed: CPU/motherboard/RAM sensors unavailable (WinStateDiag never installs drivers)' }
    if (-not $admin) { $detail += '; not elevated' }
    Status 'LHM' $(if ($pawn -and $admin) { 'AVAILABLE' } else { 'PARTIAL' }) $detail
  } catch {
    $m = $_.Exception.Message
    if ($m -match 'blocked|Application Control|policy|0x800711C7|Device Guard') { Status 'LHM' 'BLOCKED_BY_WINDOWS_SECURITY' $m } else { Status 'LHM' 'PROVIDER_ERROR' $m }
    $lhm = $null
  }
} else { Status 'LHM' 'UNAVAILABLE' 'LibreHardwareMonitorLib not bundled in this build' }
# ---- WMI monitors already running ----
$wmi = @()
foreach ($ns in 'root\LibreHardwareMonitor','root\OpenHardwareMonitor') {
  $p = if ($ns -like '*Libre*') { 'LHM WMI' } else { 'OHM WMI' }
  try { $null = Get-CimInstance -Namespace $ns -ClassName Hardware -ErrorAction Stop | Select-Object -First 1; $wmi += $ns; Status $p 'AVAILABLE' 'monitor running' } catch { Status $p 'UNAVAILABLE' 'not running' }
}
$smi = (Get-Command nvidia-smi.exe -ErrorAction SilentlyContinue).Source
if ($smi) { Status 'nvidia-smi' 'AVAILABLE' $smi } else { Status 'nvidia-smi' 'UNAVAILABLE' 'not present' }
$probe = @()
try { $probe = @(Get-CimInstance Win32_VoltageProbe -ErrorAction Stop | Where-Object { $null -ne $_.CurrentReading }) } catch { }
Status 'WMI probe' $(if ($probe.Count) { 'AVAILABLE' } else { 'UNAVAILABLE' }) "$($probe.Count) probes"
$tzOk = $true
function Row($p, $hwid, $hwtype, $hw, $sid, $type, $name, $value, $bm) { [ordered]@{ p = $p; hwid = [string]$hwid; hwtype = [string]$hwtype; hw = [string]$hw; sid = [string]$sid; type = [string]$type; name = [string]$name; value = $value; bm = [bool]$bm } }
function WalkLhm($hw, $rows, $board) {
  try { $hw.Update() } catch { }
  foreach ($sh in $hw.SubHardware) { WalkLhm $sh $rows $board }
  foreach ($s in $hw.Sensors) {
    $v = $null; if ($s.Value -ne $null) { $v = [double]$s.Value }
    $bm = ([string]$hw.HardwareType -eq 'SuperIO') -and $board
    $rows.Add((Row 'LHM' $hw.Identifier $hw.HardwareType $hw.Name $s.Identifier $s.SensorType $s.Name $v $bm))
  }
}
for ($i = 0; $i -lt $Samples; $i++) {
  Write-Output ('WSD_SENS_T ' + (Get-Date).ToString('o'))
  $rows = New-Object System.Collections.Generic.List[object]
  if ($lhm) {
    foreach ($hw in $lhm.Hardware) {
      $board = ([string]$hw.HardwareType -eq 'Motherboard') -and ($hw.Name -notmatch 'Unknown')
      WalkLhm $hw $rows $board
    }
  }
  foreach ($ns in $wmi) {
    $p = if ($ns -like '*Libre*') { 'LHM WMI' } else { 'OHM WMI' }
    try {
      $hws = @{}; foreach ($h in @(Get-CimInstance -Namespace $ns -ClassName Hardware -ErrorAction Stop)) { $hws[[string]$h.Identifier] = $h }
      foreach ($s in @(Get-CimInstance -Namespace $ns -ClassName Sensor -ErrorAction Stop)) {
        $h = $hws[[string]$s.Parent]
        $rows.Add((Row $p $s.Parent $h.HardwareType $h.Name $s.Identifier $s.SensorType $s.Name ([double]$s.Value) $false))
      }
    } catch { }
  }
  if ($smi) {
    try {
      $q = & $smi --query-gpu=index,name,temperature.gpu,power.draw,fan.speed --format=csv,noheader,nounits 2>$null
      foreach ($l in @($q)) {
        $f = $l -split ',\s*'
        if ($f.Count -ge 5) {
          $num = { param($x) $d = 0.0; if ([double]::TryParse(($x -replace '[^0-9.\-]', ''), [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$d)) { $d } else { $null } }
          $id = "/nvidia-smi/$($f[0])"
          $rows.Add((Row 'nvidia-smi' $id 'GpuNvidia' $f[1] "$id/t" 'Temperature' 'GPU Temperature' (& $num $f[2]) $false))
          $rows.Add((Row 'nvidia-smi' $id 'GpuNvidia' $f[1] "$id/p" 'Power' 'GPU Power' (& $num $f[3]) $false))
          $rows.Add((Row 'nvidia-smi' $id 'GpuNvidia' $f[1] "$id/f" 'Control' 'GPU Fan' (& $num $f[4]) $false))
        }
      }
    } catch { }
  }
  if ($i -eq 0) {
    foreach ($pr in $probe) { $rows.Add((Row 'WMI probe' 'Win32_VoltageProbe' 'Motherboard' '' "probe/$($pr.DeviceID)" 'Voltage' (([string]$pr.Description + ' ' + [string]$pr.Name).Trim()) ([double]$pr.CurrentReading / 1000.0) $false)) }
    try {
      foreach ($d in @(Get-PhysicalDisk -ErrorAction Stop)) {
        $r = $d | Get-StorageReliabilityCounter -ErrorAction SilentlyContinue
        if ($r -and $r.Temperature) { $rows.Add((Row 'StorRel' "disk/$($d.DeviceId)" 'Storage' $d.FriendlyName "disk/$($d.DeviceId)/t" 'Temperature' 'Temperature' ([double]$r.Temperature) $false)) }
      }
    } catch { }
  }
  if ($tzOk) {
    try {
      foreach ($c in (Get-Counter '\Thermal Zone Information(*)\Temperature' -ErrorAction Stop).CounterSamples) {
        $rows.Add((Row 'ACPI TZ' 'acpi' 'Other' 'ACPI' "tz/$($c.InstanceName)" 'Temperature' "Thermal zone $($c.InstanceName)" ([double]$c.CookedValue - 273.15) $false))
      }
    } catch { $tzOk = $false }
  }
  # List[object] -> object[] via ToArray(): @($list) of ordered dicts fails in PowerShell.
  Write-Output ('WSD_SENS ' + (J ($rows.ToArray())))
  if ($i -lt $Samples - 1) { Start-Sleep -Milliseconds $IntervalMs }
}
if ($lhm) { try { $lhm.Close() } catch { } }
"#;

// ---------------------------------------------------------------------
// Evidence JSON
// ---------------------------------------------------------------------

pub const EVIDENCE_PREFIX: &str = "Hardware_Sensors_";

fn f(v: f64) -> String {
    if v.is_finite() {
        format!("{v:.3}")
    } else {
        "null".into()
    }
}

fn role_code(r: &Role) -> String {
    match r {
        Role::DiskTemp(k) => format!("DiskTemp:{k}"),
        Role::AtxRail(rail) => format!("AtxRail:{}", rail.label()),
        Role::DynamicVoltage(n) => format!("DynamicVoltage:{n}"),
        Role::SystemFan(n) => format!("SystemFan:{n}"),
        Role::GpuFan(n) => format!("GpuFan:{n}"),
        other => format!("{other:?}"),
    }
}

/// v1.0 Sensor Backend V2 metadata: where a status threshold for a value
/// comes from. Only fixed ATX rails are judged against a nominal; disk
/// temperatures against the drive's own reported limits; everything else
/// is informational (no invented thresholds).
pub fn threshold_source_of_role(r: &Role) -> &'static str {
    match r {
        Role::AtxRail(_) => "atx_spec_nominal_plus_minus_5_percent",
        Role::DiskTemp(_) => "drive_reported_limits_or_none",
        _ => "none_informational",
    }
}

pub fn threshold_source_of_sensor(x: &Sensor) -> &'static str {
    match (x.kind, x.category) {
        (SensorKind::Voltage, HwCategory::Motherboard | HwCategory::Psu) => {
            "atx_spec_nominal_only_for_fixed_rails"
        }
        (SensorKind::Temperature, HwCategory::Storage) => "drive_reported_limits_or_none",
        _ => "none_informational",
    }
}

fn canonical_json(c: &Canonical) -> String {
    format!(
        "{{\"role\": {}, \"label\": {}, \"value\": {}, \"min\": {}, \"max\": {}, \"unit\": {}, \"provider\": {}, \"confidence\": {}, \"derived\": {}, \"threshold_source\": {}}}",
        json::string(&role_code(&c.role)),
        json::string(&c.label),
        f(c.value),
        f(c.min),
        f(c.max),
        json::string(c.kind.unit()),
        json::string(c.provider.code()),
        json::string(c.confidence.code()),
        c.derived,
        json::string(threshold_source_of_role(&c.role))
    )
}

/// `Hardware_Sensors_<ts>.json`.
pub fn to_json(snap: &Snapshot) -> String {
    let s = summarize(&snap.sensors);
    let list = |v: &[Canonical]| -> String {
        v.iter()
            .map(|c| format!("      {}", canonical_json(c)))
            .collect::<Vec<_>>()
            .join(",\n")
    };
    let rails: Vec<String> = s
        .rails
        .iter()
        .map(|(rail, c, st)| {
            format!(
                "      {{\"line\": {}, \"nominal\": {:.2}, \"deviation_percent\": {:.2}, \"status\": {}, \"reading\": {}}}",
                json::string(rail.label()),
                rail.nominal(),
                (c.value - rail.nominal()) / rail.nominal() * 100.0,
                json::string(st.code()),
                canonical_json(c)
            )
        })
        .collect();
    let mismatches: Vec<String> = s
        .mismatches
        .iter()
        .map(|m| {
            format!(
                "    {{\"flag\": \"SENSOR SOURCE MISMATCH\", \"role\": {}, \"canonical_provider\": {}, \"canonical_value\": {}, \"other_provider\": {}, \"other_value\": {}, \"unit\": {}}}",
                json::string(&role_code(&m.role)),
                json::string(m.canonical.0.code()),
                f(m.canonical.1),
                json::string(m.other.0.code()),
                f(m.other.1),
                json::string(m.unit)
            )
        })
        .collect();
    let providers: Vec<String> = snap
        .providers
        .iter()
        .map(|p| {
            format!(
                "    {{\"provider\": {}, \"status\": {}, \"detail\": {}}}",
                json::string(p.provider.code()),
                json::string(p.state.code()),
                json::string(&p.detail)
            )
        })
        .collect();
    let sensors: Vec<String> = snap
        .sensors
        .iter()
        .map(|x| {
            format!(
                "    {{\"provider\": {}, \"hardware\": {}, \"hardware_id\": {}, \"category\": {}, \"sensor_type\": {}, \"sensor_name\": {}, \"sensor_id\": {}, \"value\": {}, \"min\": {}, \"max\": {}, \"unit\": {}, \"samples\": {}, \"confidence\": {}, \"timestamp\": {}, \"threshold_source\": {}}}",
                json::string(x.provider.code()),
                json::string(&x.hw_name),
                json::string(&x.hw_id),
                json::string(x.category.code()),
                json::string(x.kind.code()),
                json::string(&x.name),
                json::string(&x.sensor_id),
                f(x.value),
                f(x.min),
                f(x.max),
                json::string(x.unit()),
                x.samples,
                json::string(x.confidence.code()),
                json::string(&x.timestamp),
                json::string(threshold_source_of_sensor(x))
            )
        })
        .collect();
    let ps = s.power_status();
    format!(
        "{{\n  \"format\": \"winstatediag.hardware_sensors/1\",\n  \"captured_at\": {},\n  \"status\": {},\n  \"provider\": {},\n  \"lhm_bundle_version\": {},\n  \"sampling\": {{\"samples\": {}, \"interval_ms\": {}, \"min_max\": \"WinStateDiag session sample values, not lifetime hardware values\", \"load\": \"no stress applied\"}},\n  \"providers\": [\n{}\n  ],\n  \"summary\": {{\n    \"temperatures\": [\n{}\n    ],\n    \"atx_rails\": [\n{}\n    ],\n    \"dynamic_voltages\": [\n{}\n    ],\n    \"power\": [\n{}\n    ],\n    \"fans\": [\n{}\n    ]\n  }},\n  \"power_state\": {{\"status\": {}, \"note\": {}}},\n  \"mismatches\": [\n{}\n  ],\n  \"process_context\": {},\n  \"sensor_count\": {},\n  \"sensors\": [\n{}\n  ]\n}}\n",
        json::string(&snap.captured_at),
        json::string(snap.state().code()),
        json::string(snap.main_provider().map(Provider::code).unwrap_or("none")),
        if bundle::LHM_FILES.is_empty() {
            "null".to_string()
        } else {
            json::string(bundle::LHM_VERSION)
        },
        snap.samples,
        snap.interval_ms,
        providers.join(",\n"),
        list(&s.temps),
        rails.join(",\n"),
        list(&s.dynamic_voltages),
        list(&s.power),
        list(&s.fans),
        json::string(ps.code()),
        json::string(ps.message(false)),
        mismatches.join(",\n"),
        process_context_json(snap.process_context.as_ref()),
        snap.sensors.len(),
        sensors.join(",\n")
    )
}

// ---------------------------------------------------------------------
// Windows collection
// ---------------------------------------------------------------------

/// Bundled LibreHardwareMonitorLib files (generated by build.rs from
/// `third_party/LibreHardwareMonitorLib-<ver>/`; empty when absent).
pub mod bundle {
    include!(concat!(env!("OUT_DIR"), "/lhm_bundle.rs"));
}

/// Extracts the bundled library to a fresh temp folder. `None` when the
/// build carries no bundle.
pub fn extract_bundle(base: &std::path::Path) -> Result<Option<std::path::PathBuf>, String> {
    if bundle::LHM_FILES.is_empty() {
        return Ok(None);
    }
    let dir = base.join(format!(
        "lhm-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    for (name, bytes) in bundle::LHM_FILES {
        std::fs::write(dir.join(name), bytes).map_err(|e| format!("{name}: {e}"))?;
    }
    Ok(Some(dir))
}

/// Runs the sampler (and HWiNFO reads in parallel). Never panics; every
/// failure becomes a provider status.
pub fn collect(
    host: &str,
    temp_base: &std::path::Path,
    samples: u32,
    interval_ms: u32,
) -> Snapshot {
    collect_raw(host, temp_base, samples, interval_ms).0
}

/// [`collect`] plus the raw sampler stdout (validation / `--sensor-probe`).
pub fn collect_raw(
    host: &str,
    temp_base: &std::path::Path,
    samples: u32,
    interval_ms: u32,
) -> (Snapshot, String) {
    let mut raw = String::new();
    let captured_at = crate::ui::sysinfo::local_time();
    let captured_at = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        captured_at.year,
        captured_at.month,
        captured_at.day,
        captured_at.hour,
        captured_at.minute,
        captured_at.second
    );
    let mut providers = Vec::new();
    let lhm_dir = match extract_bundle(temp_base) {
        Ok(d) => d,
        Err(e) => {
            providers.push(ProviderReport {
                provider: Provider::LhmInternal,
                state: ProviderState::ProviderError,
                detail: format!("bundle extraction failed: {e}"),
            });
            None
        }
    };
    let script = format!(
        "& {{ {} }} -LhmDir '{}' -Samples {} -IntervalMs {}",
        SAMPLER_PS1,
        lhm_dir
            .as_ref()
            .map(|d| d.display().to_string().replace('\'', "''"))
            .unwrap_or_default(),
        samples,
        interval_ms
    );
    let host_owned = host.to_string();
    let timeout =
        std::time::Duration::from_millis(u64::from(samples) * u64::from(interval_ms) + 45_000);
    let proc_host = host.to_string();
    let ps =
        std::thread::spawn(move || crate::ps_exec::run_powershell(&host_owned, &script, timeout));
    // v1.0 process context, taken inside the sampling window.
    let procs = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(2500));
        crate::ps_exec::run_powershell(&proc_host, PROCESS_PS1, std::time::Duration::from_secs(40))
            .ok()
            .and_then(|out| parse_process_context(&out))
    });
    // HWiNFO shared memory, sampled alongside.
    let mut hw_sampler = Sampler::default();
    let mut hw_report: Option<ProviderReport> = None;
    for i in 0..samples {
        match read_hwinfo() {
            Ok(rows) => {
                hw_sampler.add_sample(&rows, &captured_at);
                hw_report = Some(ProviderReport {
                    provider: Provider::HwInfo,
                    state: ProviderState::Available,
                    detail: "HWiNFO running with shared memory enabled".into(),
                });
            }
            Err(e) => {
                hw_report = Some(ProviderReport {
                    provider: Provider::HwInfo,
                    state: ProviderState::Unavailable,
                    detail: e,
                });
                break;
            }
        }
        if i + 1 < samples {
            std::thread::sleep(std::time::Duration::from_millis(u64::from(interval_ms)));
        }
    }
    let mut sampler = Sampler::default();
    match ps.join() {
        Ok(Ok(out)) => {
            raw = out.clone();
            let (sets, reports) = parse_sampler_output(&out);
            for (t, rows) in &sets {
                sampler.add_sample(rows, if t.is_empty() { &captured_at } else { t });
            }
            providers.extend(reports);
        }
        Ok(Err(e)) => {
            raw = format!("sampler error: {e}");
            providers.push(ProviderReport {
                provider: Provider::LhmInternal,
                state: ProviderState::ProviderError,
                detail: format!("sensor sampler: {e}"),
            })
        }
        Err(_) => providers.push(ProviderReport {
            provider: Provider::LhmInternal,
            state: ProviderState::ProviderError,
            detail: "sensor sampler thread panicked".into(),
        }),
    }
    if let Some(dir) = lhm_dir {
        // The helper process has exited; the DLLs are no longer locked.
        let _ = std::fs::remove_dir_all(dir);
    }
    providers.extend(hw_report);
    let mut sensors = sampler.into_sensors();
    sensors.extend(hw_sampler.into_sensors());
    let process_context = procs.join().ok().flatten();
    (
        Snapshot {
            captured_at,
            samples,
            interval_ms,
            sensors,
            providers,
            process_context,
        },
        raw,
    )
}

#[cfg(windows)]
fn read_hwinfo() -> Result<Vec<RawReading>, String> {
    use std::ffi::c_void;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn OpenFileMappingW(access: u32, inherit: i32, name: *const u16) -> *mut c_void;
        fn MapViewOfFile(
            h: *mut c_void,
            access: u32,
            hi: u32,
            lo: u32,
            bytes: usize,
        ) -> *mut c_void;
        fn UnmapViewOfFile(p: *const c_void) -> i32;
        fn CloseHandle(h: *mut c_void) -> i32;
        fn VirtualQuery(p: *const c_void, info: *mut MemoryBasicInformation, len: usize) -> usize;
    }
    #[repr(C)]
    struct MemoryBasicInformation {
        base: *mut c_void,
        alloc_base: *mut c_void,
        alloc_protect: u32,
        partition: u16,
        region_size: usize,
        state: u32,
        protect: u32,
        kind: u32,
    }
    const FILE_MAP_READ: u32 = 4;
    let name: Vec<u16> = HWINFO_SM_NAME.encode_utf16().chain(Some(0)).collect();
    // SAFETY: read-only mapping of a named section; the view is copied and
    // unmapped before returning, and every pointer is null-checked.
    unsafe {
        let h = OpenFileMappingW(FILE_MAP_READ, 0, name.as_ptr());
        if h.is_null() {
            return Err("HWiNFO shared memory not available (HWiNFO not running or Shared Memory Support off)".into());
        }
        let p = MapViewOfFile(h, FILE_MAP_READ, 0, 0, 0);
        if p.is_null() {
            CloseHandle(h);
            return Err("HWiNFO shared memory could not be mapped".into());
        }
        let mut mbi = std::mem::zeroed::<MemoryBasicInformation>();
        let size = if VirtualQuery(p, &mut mbi, std::mem::size_of::<MemoryBasicInformation>()) != 0
        {
            mbi.region_size
        } else {
            0
        };
        let bytes = std::slice::from_raw_parts(p as *const u8, size).to_vec();
        UnmapViewOfFile(p);
        CloseHandle(h);
        parse_hwinfo_shm(&bytes)
    }
}

#[cfg(not(windows))]
fn read_hwinfo() -> Result<Vec<RawReading>, String> {
    Err("HWiNFO shared memory is Windows-only".into())
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

/// v1.0 shared fixture (tests and the QA `--scene` renders): the real
/// MSI PRO Z890-P reference readings, never used for live data.
#[allow(dead_code)]
pub mod fixture {
    use super::*;

    pub fn rr(
        p: Provider,
        cat: HwCategory,
        hw: &str,
        name: &str,
        kind: SensorKind,
        v: Option<f64>,
    ) -> RawReading {
        RawReading {
            provider: p,
            hw_id: format!("/{}/{hw}", cat.code()),
            hw_name: hw.into(),
            category: cat,
            sensor_id: format!("/{}/{hw}/{name}/{kind:?}", p.short()),
            name: name.into(),
            kind,
            value: v,
            board_mapped: false,
        }
    }

    pub fn sample(rows: &[RawReading]) -> Vec<Sensor> {
        let mut s = Sampler::default();
        s.add_sample(rows, "t");
        s.into_sensors()
    }

    /// The MSI PRO Z890-P reference values (AIDA64 screenshots).
    pub fn msi_reference() -> Vec<RawReading> {
        use HwCategory::*;
        use SensorKind::*;
        let h = Provider::HwInfo;
        let mut v = Vec::new();
        for (i, t) in [48.0, 50.0, 46.0, 46.0, 52.0, 52.0, 48.0, 50.0]
            .iter()
            .enumerate()
        {
            v.push(rr(
                h,
                Cpu,
                "CPU [#0]: Intel Core Ultra 7 270K Plus: DTS",
                &format!("P-core {i}"),
                Temperature,
                Some(*t),
            ));
        }
        v.push(rr(
            h,
            Cpu,
            "CPU [#0]: Intel Core Ultra 7 270K Plus: DTS",
            "CPU Package",
            Temperature,
            Some(53.0),
        ));
        v.push(rr(
            h,
            Cpu,
            "CPU [#0]: Intel Core Ultra 7 270K Plus: DTS",
            "Core Max",
            Temperature,
            Some(52.0),
        ));
        v.push(rr(
            h,
            Cpu,
            "CPU [#0]: Intel Core Ultra 7 270K Plus: Enhanced",
            "CPU Package Power",
            Power,
            Some(58.44),
        ));
        v.push(rr(
            h,
            Cpu,
            "CPU [#0]: Intel Core Ultra 7 270K Plus: Enhanced",
            "IA Cores Power",
            Power,
            Some(44.76),
        ));
        v.push(rr(
            h,
            Cpu,
            "CPU [#0]: Intel Core Ultra 7 270K Plus: Enhanced",
            "Uncore Power",
            Power,
            Some(13.62),
        ));
        v.push(rr(
            h,
            Cpu,
            "CPU [#0]: Intel Core Ultra 7 270K Plus: Enhanced",
            "Vcore",
            Voltage,
            Some(1.418),
        ));
        v.push(rr(
            h,
            Cpu,
            "CPU [#0]: Intel Core Ultra 7 270K Plus: Enhanced",
            "CPU VID",
            Voltage,
            Some(1.105),
        ));
        let board = "MSI PRO Z890-P WIFI (MS-7E34) (Nuvoton NCT6687D)";
        for (n, val) in [("+3.3V", 3.320), ("+5V", 5.020), ("+12V", 12.024)] {
            let mut r = rr(h, Motherboard, board, n, Voltage, Some(val));
            r.board_mapped = true;
            v.push(r);
        }
        v.push(rr(h, Motherboard, board, "VCCSA", Voltage, Some(1.245)));
        v.push(rr(
            h,
            Motherboard,
            board,
            "Motherboard",
            Temperature,
            Some(38.0),
        ));
        v.push(rr(h, Motherboard, board, "PCH", Temperature, Some(46.0)));
        v.push(rr(h, Motherboard, board, "MOS", Temperature, Some(43.0)));
        v.push(rr(h, Motherboard, board, "CPU", Fan, Some(1180.0)));
        v.push(rr(h, Motherboard, board, "System 1", Fan, Some(720.0)));
        v.push(rr(h, Motherboard, board, "System 2", Fan, Some(0.0)));
        let g = "GPU [#0]: NVIDIA GeForce RTX 5060";
        v.push(rr(h, Gpu, g, "GPU Temperature", Temperature, Some(36.0)));
        v.push(rr(
            h,
            Gpu,
            g,
            "GPU Hot Spot Temperature",
            Temperature,
            Some(43.0),
        ));
        v.push(rr(
            h,
            Gpu,
            g,
            "GPU Memory Junction Temperature",
            Temperature,
            Some(40.0),
        ));
        v.push(rr(h, Gpu, g, "GPU Power", Power, Some(24.03)));
        v.push(rr(h, Gpu, g, "GPU 16-pin HVPWR Power", Power, Some(17.58)));
        v.push(rr(h, Gpu, g, "PCIe +12V Input Power", Power, Some(2.50)));
        v.push(rr(h, Gpu, g, "GPU Core Voltage", Voltage, Some(0.790)));
        v.push(rr(
            h,
            Gpu,
            g,
            "PCIe +12V Input Voltage",
            Voltage,
            Some(11.923),
        ));
        v.push(rr(
            h,
            Memory,
            "DIMM Temperature Sensor",
            "DIMM[2] Temperature",
            Temperature,
            Some(39.0),
        ));
        v.push(rr(
            h,
            Memory,
            "DIMM Temperature Sensor",
            "DIMM[4] Temperature",
            Temperature,
            Some(39.0),
        ));
        v.push(rr(
            h,
            Storage,
            "Samsung SSD 9100 PRO 1TB",
            "Drive Temperature",
            Temperature,
            Some(46.0),
        ));
        v.push(rr(
            h,
            Storage,
            "Netac NVMe SSD 1TB",
            "Drive Temperature",
            Temperature,
            Some(43.0),
        ));
        v
    }
}

#[cfg(test)]
pub(crate) mod tests {
    pub(crate) use super::fixture::{msi_reference, rr, sample};
    use super::*;

    #[test]
    fn normalization_and_summary_match_the_msi_reference() {
        let s = summarize(&sample(&msi_reference()));
        let t = |r: Role| s.temps.iter().find(|c| c.role == r).map(|c| c.value);
        // CPU = average of all cores (8 sample cores → 49.0), not package.
        assert_eq!(t(Role::CpuCoreAverage), Some(49.0));
        assert_eq!(t(Role::GpuTemp), Some(36.0));
        assert_eq!(t(Role::GpuHotspot), Some(43.0));
        assert_eq!(t(Role::BoardTemp), Some(38.0));
        assert_eq!(t(Role::ChipsetTemp), Some(46.0));
        assert_eq!(t(Role::RamTemp), Some(39.0));
        assert_eq!(
            t(Role::DiskTemp("samsung ssd 9100 pro 1tb".into())),
            Some(46.0)
        );
        assert_eq!(t(Role::DiskTemp("netac nvme ssd 1tb".into())), Some(43.0));
        assert_eq!(s.rails.len(), 3);
        assert!(s.rails.iter().all(|(_, c, st)| *st == PowerStatus::Excellent
            && c.confidence == Confidence::High));
        assert_eq!(s.power_status(), PowerStatus::Excellent);
        let p = |r: Role| s.power.iter().find(|c| c.role == r).map(|c| c.value);
        assert_eq!(p(Role::CpuPackagePower), Some(58.44));
        assert_eq!(p(Role::CpuCorePower), Some(44.76));
        assert_eq!(p(Role::CpuUncorePower), Some(13.62));
        assert_eq!(p(Role::GpuPower), Some(24.03));
        assert_eq!(p(Role::Gpu12vhpwrPower), Some(17.58));
        assert_eq!(p(Role::GpuPciePower), Some(2.50));
        assert!(
            s.fans
                .iter()
                .any(|c| c.role == Role::CpuFan && c.value == 1180.0)
        );
        // 0 RPM kept as a value, not a failure.
        assert!(s.fans.iter().any(|c| c.value == 0.0));
    }

    #[test]
    fn cpu_per_core_values_never_reach_the_dashboard() {
        let s = summarize(&sample(&msi_reference()));
        assert!(!s.temps.iter().any(|c| c.role == Role::CpuCore));
        let dash: Vec<_> = s.temps.iter().filter(|c| on_dashboard(&c.role)).collect();
        assert!(
            dash.iter()
                .all(|c| !c.label.to_ascii_lowercase().starts_with("p-core"))
        );
        assert!(!on_dashboard(&Role::CpuCore) && !on_dashboard(&Role::CpuPackage));
        // Provider "Core Average" wins over the computed mean.
        let mut rows = msi_reference();
        rows.push(rr(
            Provider::HwInfo,
            HwCategory::Cpu,
            "CPU [#0]: DTS",
            "Core Average",
            SensorKind::Temperature,
            Some(47.5),
        ));
        let s = summarize(&sample(&rows));
        let cpu = s
            .temps
            .iter()
            .find(|c| c.role == Role::CpuCoreAverage)
            .unwrap();
        assert_eq!(cpu.value, 47.5);
        assert!(!cpu.derived);
    }

    #[test]
    fn temperature_filtering_drops_unconnected_channels() {
        use HwCategory::*;
        let rows = vec![
            rr(
                Provider::LhmInternal,
                Motherboard,
                "NCT6687D",
                "System",
                SensorKind::Temperature,
                Some(0.0),
            ),
            rr(
                Provider::LhmInternal,
                Motherboard,
                "NCT6687D",
                "PCH",
                SensorKind::Temperature,
                Some(-55.0),
            ),
            rr(
                Provider::LhmInternal,
                Motherboard,
                "NCT6687D",
                "MOS",
                SensorKind::Temperature,
                Some(f64::NAN),
            ),
            rr(
                Provider::LhmInternal,
                Gpu,
                "RTX",
                "GPU Core",
                SensorKind::Temperature,
                None,
            ),
        ];
        let s = summarize(&sample(&rows));
        assert!(s.temps.is_empty(), "no invented / zero values: {s:?}");
        assert!(sample(&rows).is_empty());
    }

    #[test]
    fn rails_recognised_only_on_motherboard_and_dynamic_never_classified() {
        use HwCategory::*;
        let mut r12 = rr(
            Provider::LhmInternal,
            Motherboard,
            "NCT6687D",
            "+12V",
            SensorKind::Voltage,
            Some(12.02),
        );
        r12.board_mapped = true;
        let rows = vec![
            r12,
            rr(
                Provider::LhmInternal,
                Gpu,
                "RTX",
                "PCIe +12V Input Voltage",
                SensorKind::Voltage,
                Some(11.0),
            ),
            rr(
                Provider::LhmInternal,
                Cpu,
                "CPU",
                "CPU VID",
                SensorKind::Voltage,
                Some(1.5),
            ),
            rr(
                Provider::LhmInternal,
                Cpu,
                "CPU",
                "Vcore",
                SensorKind::Voltage,
                Some(0.6),
            ),
            rr(
                Provider::LhmInternal,
                Gpu,
                "RTX",
                "GPU Core",
                SensorKind::Voltage,
                Some(0.79),
            ),
        ];
        let s = summarize(&sample(&rows));
        assert_eq!(s.rails.len(), 1, "GPU PCIe +12V is not an ATX rail");
        assert_eq!(s.rails[0].0, Rail::V12);
        assert_eq!(s.dynamic_voltages.len(), 4);
        // 11.0 V on the GPU input is far from 12 V but informational only.
        assert_eq!(s.power_status(), PowerStatus::Excellent);
    }

    #[test]
    fn source_confidence_rules() {
        use HwCategory::*;
        let mut mapped = rr(
            Provider::LhmInternal,
            Motherboard,
            "NCT",
            "+12V",
            SensorKind::Voltage,
            Some(12.0),
        );
        mapped.board_mapped = true;
        assert_eq!(confidence_of(&mapped), Confidence::High);
        let generic = rr(
            Provider::LhmInternal,
            Motherboard,
            "NCT",
            "+12V",
            SensorKind::Voltage,
            Some(12.0),
        );
        assert_eq!(confidence_of(&generic), Confidence::Medium);
        let mut wmi = rr(
            Provider::LhmWmi,
            Motherboard,
            "NCT",
            "+12V",
            SensorKind::Voltage,
            Some(12.0),
        );
        assert_eq!(confidence_of(&wmi), Confidence::Low);
        wmi.board_mapped = true;
        assert_eq!(confidence_of(&wmi), Confidence::Medium);
        let probe = rr(
            Provider::Win32VoltageProbe,
            Motherboard,
            "",
            "+12V",
            SensorKind::Voltage,
            Some(12.0),
        );
        assert_eq!(confidence_of(&probe), Confidence::Low);
        let other = rr(
            Provider::HwInfo,
            Other,
            "ACPI",
            "VIN3",
            SensorKind::Voltage,
            Some(1.0),
        );
        assert_eq!(confidence_of(&other), Confidence::Unknown);
        assert!(!Confidence::Low.trusted() && !Confidence::Unknown.trusted());
    }

    #[test]
    fn low_confidence_voltage_cannot_produce_false_critical() {
        use HwCategory::*;
        let probe = rr(
            Provider::Win32VoltageProbe,
            Motherboard,
            "",
            "+12V",
            SensorKind::Voltage,
            Some(10.8),
        );
        let s = summarize(&sample(&[probe]));
        assert_eq!(s.rails[0].2, PowerStatus::CheckSensor);
        assert_eq!(s.power_status(), PowerStatus::CheckSensor);
        assert!(s.power_status() < PowerStatus::Attention);
        // The same value from a board-mapped sensor is CRITICAL.
        let mut m = rr(
            Provider::HwInfo,
            Motherboard,
            "NCT",
            "+12V",
            SensorKind::Voltage,
            Some(10.8),
        );
        m.board_mapped = true;
        assert_eq!(
            summarize(&sample(&[m])).power_status(),
            PowerStatus::Critical
        );
    }

    #[test]
    fn power_state_wording_never_claims_psu_failure() {
        for st in [
            PowerStatus::NoData,
            PowerStatus::Excellent,
            PowerStatus::CheckSensor,
            PowerStatus::Attention,
            PowerStatus::Critical,
        ] {
            for ru in [true, false] {
                let m = st.message(ru).to_lowercase() + st.text(ru);
                for bad in ["faulty", "failed", "неисправ", "отказ", "fault"] {
                    assert!(!m.contains(bad), "{st:?}: {m}");
                }
            }
        }
        assert_eq!(PowerStatus::Attention.text(true), "Внимание!");
        assert_eq!(PowerStatus::Critical.text(true), "Критично!");
        assert_eq!(PowerStatus::NoData.text(true), "Нет данных");
        assert!(
            PowerStatus::Critical
                .message(true)
                .contains("внешним тестером/мультиметром")
        );
        assert_eq!(
            power_instability_hint(PowerStatus::Critical, 2, 0, 1),
            Some("possible power instability")
        );
        assert_eq!(power_instability_hint(PowerStatus::Critical, 0, 0, 0), None);
        assert_eq!(
            power_instability_hint(PowerStatus::CheckSensor, 3, 3, 3),
            None
        );
    }

    #[test]
    fn provider_precedence_and_source_mismatch_are_recorded() {
        use HwCategory::*;
        let rows = vec![
            rr(
                Provider::NvidiaSmi,
                Gpu,
                "RTX 5060",
                "GPU Temperature",
                SensorKind::Temperature,
                Some(48.0),
            ),
            rr(
                Provider::HwInfo,
                Gpu,
                "GPU [#0]",
                "GPU Temperature",
                SensorKind::Temperature,
                Some(36.0),
            ),
            rr(
                Provider::HwInfo,
                Gpu,
                "GPU [#0]",
                "GPU Power",
                SensorKind::Power,
                Some(24.0),
            ),
            rr(
                Provider::NvidiaSmi,
                Gpu,
                "RTX 5060",
                "GPU Power",
                SensorKind::Power,
                Some(25.0),
            ),
            rr(
                Provider::NvmeHealth,
                Storage,
                "samsung ssd 9100 pro 1tb",
                "Temperature",
                SensorKind::Temperature,
                Some(47.0),
            ),
            rr(
                Provider::HwInfo,
                Storage,
                "samsung ssd 9100 pro 1tb",
                "Drive Temperature",
                SensorKind::Temperature,
                Some(46.0),
            ),
        ];
        let s = summarize(&sample(&rows));
        let gpu = s.temps.iter().find(|c| c.role == Role::GpuTemp).unwrap();
        assert_eq!(gpu.provider, Provider::HwInfo, "HWiNFO outranks nvidia-smi");
        assert_eq!(
            s.mismatches.len(),
            1,
            "12 °C apart → SENSOR SOURCE MISMATCH"
        );
        assert_eq!(s.mismatches[0].other, (Provider::NvidiaSmi, 48.0));
        // NVMe Health is the canonical disk temperature; 1 °C is no mismatch.
        let disk = s
            .temps
            .iter()
            .find(|c| matches!(c.role, Role::DiskTemp(_)))
            .unwrap();
        assert_eq!(disk.provider, Provider::NvmeHealth);
        assert_eq!(
            s.temps
                .iter()
                .filter(|c| matches!(c.role, Role::DiskTemp(_)))
                .count(),
            1,
            "no duplicate SSD temperature"
        );
    }

    /// Windows gate (MSI Z890, no PawnIO): LHM reported CPU Package 0 W,
    /// two identical TOSHIBA disks collapsed into one, and the iGPU must
    /// not displace the discrete GPU.
    #[test]
    fn real_gate_findings_zero_cpu_power_duplicate_disks_igpu() {
        use HwCategory::*;
        let p = Provider::LhmInternal;
        let mut t1 = rr(
            p,
            Storage,
            "TOSHIBA DT02ABA400",
            "Temperature",
            SensorKind::Temperature,
            Some(28.0),
        );
        t1.hw_id = "/hdd/0".into();
        t1.sensor_id = "/hdd/0/temperature/0".into();
        let mut t2 = rr(
            p,
            Storage,
            "TOSHIBA DT02ABA400",
            "Temperature",
            SensorKind::Temperature,
            Some(25.0),
        );
        t2.hw_id = "/hdd/2".into();
        t2.sensor_id = "/hdd/2/temperature/0".into();
        let mut igpu = rr(
            p,
            Gpu,
            "Intel(R) Graphics",
            "GPU Power",
            SensorKind::Power,
            Some(0.0),
        );
        igpu.hw_id = "/gpu-intel-integrated/0".into();
        let mut dgpu = rr(
            p,
            Gpu,
            "NVIDIA GeForce RTX 5060",
            "GPU Package",
            SensorKind::Power,
            Some(53.0),
        );
        dgpu.hw_id = "/gpu-nvidia/0".into();
        let rows = vec![
            rr(
                p,
                Cpu,
                "Intel Core Ultra 7 270K Plus",
                "CPU Package",
                SensorKind::Power,
                Some(0.0),
            ),
            rr(
                p,
                Cpu,
                "Intel Core Ultra 7 270K Plus",
                "CPU Cores",
                SensorKind::Power,
                Some(0.0),
            ),
            t1,
            t2,
            igpu,
            dgpu,
        ];
        let s = summarize(&sample(&rows));
        assert!(
            !s.power
                .iter()
                .any(|c| matches!(c.role, Role::CpuPackagePower | Role::CpuCorePower)),
            "0 W CPU is not a value"
        );
        let gpu = s.power.iter().find(|c| c.role == Role::GpuPower).unwrap();
        assert_eq!(gpu.value, 53.0, "discrete GPU preferred");
        let disks: Vec<_> = s
            .temps
            .iter()
            .filter(|c| matches!(c.role, Role::DiskTemp(_)))
            .collect();
        assert_eq!(disks.len(), 2, "two physical disks stay two");
        assert!(
            disks
                .iter()
                .any(|c| c.label == "TOSHIBA DT02ABA400 #1" && c.value == 28.0)
        );
        assert!(
            disks
                .iter()
                .any(|c| c.label == "TOSHIBA DT02ABA400 #2" && c.value == 25.0)
        );
    }

    #[test]
    fn min_max_are_session_sample_values() {
        use HwCategory::*;
        let mut sm = Sampler::default();
        for v in [12.02, 11.95, 12.10, f64::NAN] {
            let mut r = rr(
                Provider::HwInfo,
                Motherboard,
                "NCT",
                "+12V",
                SensorKind::Voltage,
                Some(v),
            );
            r.board_mapped = true;
            sm.add_sample(&[r], "t");
        }
        assert_eq!(sm.samples_taken, 4);
        let s = &sm.sensors()[0];
        assert_eq!((s.min, s.max, s.value, s.samples), (11.95, 12.10, 12.10, 3));
    }

    #[test]
    fn fan_and_power_normalization() {
        use HwCategory::*;
        let rows = vec![
            rr(
                Provider::LhmInternal,
                Motherboard,
                "NCT",
                "CPU Fan",
                SensorKind::Fan,
                Some(1180.0),
            ),
            rr(
                Provider::LhmInternal,
                Motherboard,
                "NCT",
                "Pump Fan",
                SensorKind::Fan,
                Some(2400.0),
            ),
            rr(
                Provider::LhmInternal,
                Motherboard,
                "NCT",
                "System Fan #1",
                SensorKind::Fan,
                Some(0.0),
            ),
            rr(
                Provider::LhmInternal,
                Gpu,
                "RTX",
                "GPU Fan 1",
                SensorKind::Fan,
                Some(0.0),
            ),
            rr(
                Provider::LhmInternal,
                Gpu,
                "RTX",
                "GPU Fan 1",
                SensorKind::Control,
                Some(30.0),
            ),
            rr(
                Provider::LhmInternal,
                Cpu,
                "Intel",
                "CPU Package",
                SensorKind::Power,
                Some(58.4),
            ),
            rr(
                Provider::LhmInternal,
                Cpu,
                "Intel",
                "CPU Cores",
                SensorKind::Power,
                Some(44.7),
            ),
            rr(
                Provider::LhmInternal,
                Gpu,
                "RTX",
                "GPU Package",
                SensorKind::Power,
                Some(24.0),
            ),
        ];
        let s = summarize(&sample(&rows));
        let roles: Vec<Role> = s.fans.iter().map(|c| c.role.clone()).collect();
        assert_eq!(roles[0], Role::CpuFan);
        assert_eq!(roles[1], Role::Pump);
        assert!(roles.contains(&Role::SystemFan("System Fan #1".into())));
        assert!(roles.contains(&Role::GpuFan("GPU Fan 1".into())));
        assert_eq!(s.fans.len(), 4, "fan duty % is not a fan reading");
        assert_eq!(s.power.len(), 3);
        assert_eq!(s.power[0].role, Role::CpuPackagePower);
    }

    #[test]
    fn missing_data_and_provider_failure_are_honest() {
        let snap = Snapshot {
            captured_at: "t".into(),
            samples: 10,
            interval_ms: 1000,
            sensors: Vec::new(),
            providers: vec![ProviderReport {
                provider: Provider::LhmInternal,
                state: ProviderState::ProviderError,
                detail: "x".into(),
            }],
            process_context: None,
        };
        assert_eq!(snap.state(), ProviderState::ProviderError);
        let s = summarize(&snap.sensors);
        assert_eq!(s.power_status(), PowerStatus::NoData);
        let blocked = Snapshot {
            providers: vec![ProviderReport {
                provider: Provider::LhmInternal,
                state: ProviderState::BlockedByWindowsSecurity,
                detail: "WDAC".into(),
            }],
            ..snap.clone()
        };
        assert_eq!(blocked.state(), ProviderState::BlockedByWindowsSecurity);
        let js = to_json(&blocked);
        assert!(json::parse(&js).is_some(), "{js}");
        assert!(js.contains("\"sensor_count\": 0"));
        // Partial: GPU only.
        let part = Snapshot {
            sensors: sample(&[rr(
                Provider::NvidiaSmi,
                HwCategory::Gpu,
                "RTX",
                "GPU Temperature",
                SensorKind::Temperature,
                Some(48.0),
            )]),
            ..snap.clone()
        };
        assert_eq!(part.state(), ProviderState::Partial);
        let full = Snapshot {
            sensors: sample(&msi_reference()),
            ..snap
        };
        assert_eq!(full.state(), ProviderState::Available);
        assert_eq!(full.main_provider(), Some(Provider::HwInfo));
    }

    #[test]
    fn sampler_output_parses_lhm_rows() {
        let out = "WSD_SENS_STATUS {\"p\":\"LHM\",\"state\":\"PARTIAL\",\"detail\":\"PawnIO low-level driver not installed\"}\n\
WSD_SENS_T 2026-10-05T11:00:00\n\
WSD_SENS [{\"p\":\"LHM\",\"hwid\":\"/gpu-nvidia/0\",\"hwtype\":\"GpuNvidia\",\"hw\":\"NVIDIA GeForce RTX 5060\",\"sid\":\"/gpu-nvidia/0/temperature/0\",\"type\":\"Temperature\",\"name\":\"GPU Core\",\"value\":36.0,\"bm\":false},{\"p\":\"LHM\",\"hwid\":\"/intelcpu/0\",\"hwtype\":\"Cpu\",\"hw\":\"Intel\",\"sid\":\"/intelcpu/0/temperature/0\",\"type\":\"Temperature\",\"name\":\"CPU Package\",\"value\":null,\"bm\":false}]\n\
WSD_SENS_T 2026-10-05T11:00:01\n\
WSD_SENS {\"p\":\"LHM\",\"hwid\":\"/gpu-nvidia/0\",\"hwtype\":\"GpuNvidia\",\"hw\":\"NVIDIA GeForce RTX 5060\",\"sid\":\"/gpu-nvidia/0/temperature/0\",\"type\":\"Temperature\",\"name\":\"GPU Core\",\"value\":38.0,\"bm\":false}\n";
        let (sets, reports) = parse_sampler_output(out);
        assert_eq!(sets.len(), 2);
        assert_eq!(reports[0].state, ProviderState::Partial);
        let mut sm = Sampler::default();
        for (t, rows) in &sets {
            sm.add_sample(rows, t);
        }
        let s = sm.into_sensors();
        assert_eq!(s.len(), 1, "null CPU package never becomes 0");
        assert_eq!((s[0].min, s[0].max, s[0].value), (36.0, 38.0, 38.0));
        assert_eq!(s[0].category, HwCategory::Gpu);
        assert_eq!(s[0].timestamp, "2026-10-05T11:00:01");
    }

    pub(crate) fn hwinfo_block(
        groups: &[&str],
        readings: &[(u32, u32, &str, &str, f64)],
    ) -> Vec<u8> {
        let (sz_s, sz_r) = (264usize, 316usize);
        let off_s = 48usize;
        let off_r = off_s + groups.len() * sz_s;
        let mut b = vec![0u8; off_r + readings.len() * sz_r];
        b[0..4].copy_from_slice(&HWINFO_SIGNATURE.to_le_bytes());
        for (o, v) in [
            (20, off_s),
            (24, sz_s),
            (28, groups.len()),
            (32, off_r),
            (36, sz_r),
            (40, readings.len()),
        ] {
            b[o..o + 4].copy_from_slice(&(v as u32).to_le_bytes());
        }
        for (i, g) in groups.iter().enumerate() {
            let o = off_s + i * sz_s;
            b[o..o + 4].copy_from_slice(&(0xF000_0000u32 + i as u32).to_le_bytes());
            b[o + 8..o + 8 + g.len()].copy_from_slice(g.as_bytes());
        }
        for (i, (t, si, label, unit, val)) in readings.iter().enumerate() {
            let o = off_r + i * sz_r;
            b[o..o + 4].copy_from_slice(&t.to_le_bytes());
            b[o + 4..o + 8].copy_from_slice(&si.to_le_bytes());
            b[o + 8..o + 12].copy_from_slice(&(i as u32).to_le_bytes());
            b[o + 12..o + 12 + label.len()].copy_from_slice(label.as_bytes());
            let u: Vec<u8> = unit.chars().map(|c| c as u8).collect();
            b[o + 268..o + 268 + u.len()].copy_from_slice(&u);
            b[o + 284..o + 292].copy_from_slice(&val.to_le_bytes());
        }
        b
    }

    #[test]
    fn hwinfo_shared_memory_is_parsed_without_serials() {
        let b = hwinfo_block(
            &[
                "MSI PRO Z890-P WIFI (MS-7E34) (Nuvoton NCT6687D)",
                "S.M.A.R.T.: Samsung SSD 9100 PRO 1TB (S7PZNX0R123456B)",
                "GPU [#0]: NVIDIA GeForce RTX 5060",
            ],
            &[
                (2, 0, "+12V", "V", 12.024),
                (1, 0, "Motherboard", "\u{b0}C", 38.0),
                (3, 0, "CPU", "RPM", 1180.0),
                (1, 1, "Drive Temperature", "\u{b0}C", 46.0),
                (1, 2, "GPU Hot Spot Temperature", "\u{b0}F", 109.4),
                (5, 2, "GPU Power", "W", 24.03),
                (8, 2, "GPU Clock", "MHz", 2617.0),
            ],
        );
        let rows = parse_hwinfo_shm(&b).unwrap();
        assert_eq!(rows.len(), 6, "clock (OTHER) skipped");
        assert!(rows[0].board_mapped && rows[0].category == HwCategory::Motherboard);
        assert_eq!(rows[3].hw_name, "Samsung SSD 9100 PRO 1TB");
        assert!(
            !rows.iter().any(|r| r.hw_name.contains("S7PZNX")),
            "no serial"
        );
        assert!((rows[4].value.unwrap() - 43.0).abs() < 1e-9, "°F converted");
        let s = summarize(&sample(&rows));
        assert_eq!(s.rails[0].1.confidence, Confidence::High);
        assert!(s.temps.iter().any(|c| c.role == Role::GpuHotspot));
        let mut dead = b.clone();
        dead[0..4].copy_from_slice(&0x4441_4544u32.to_le_bytes());
        assert!(parse_hwinfo_shm(&dead).unwrap_err().contains("DEAD"));
        assert!(parse_hwinfo_shm(&b[..30]).is_err());
        assert!(parse_hwinfo_shm(&b[..b.len() - 10]).is_err(), "truncated");
    }

    #[test]
    fn disk_keys_drop_serials_and_prefixes() {
        assert_eq!(
            disk_key("S.M.A.R.T.: Samsung SSD 9100 PRO 1TB (S7PZNX0R123456B)"),
            "samsung ssd 9100 pro 1tb"
        );
        assert_eq!(
            disk_key("Drive: Netac NVMe SSD 1TB [AA0000000000]"),
            "netac nvme ssd 1tb"
        );
        assert_eq!(disk_key("  TOSHIBA  DT02ABA400 "), "toshiba dt02aba400");
        assert_eq!(disk_short("Samsung SSD 9100 PRO 1TB"), "Samsung 9100");
        assert_eq!(disk_short("Netac NVMe SSD 1TB"), "Netac NVMe");
        assert_eq!(disk_short("ST2000VX017-3CV102"), "ST2000VX017-3CV102");
    }

    #[test]
    fn json_evidence_is_valid_and_labels_session_min_max() {
        let snap = Snapshot {
            captured_at: "2026-10-05T11:00:00".into(),
            samples: 10,
            interval_ms: 1000,
            sensors: sample(&msi_reference()),
            providers: vec![ProviderReport {
                provider: Provider::HwInfo,
                state: ProviderState::Available,
                detail: String::new(),
            }],
            process_context: None,
        };
        let js = to_json(&snap);
        let v = json::parse(&js).expect("valid JSON");
        assert_eq!(v.get("status").and_then(|x| x.as_str()), Some("AVAILABLE"));
        assert_eq!(
            v.get("provider").and_then(|x| x.as_str()),
            Some("HWiNFO shared memory")
        );
        assert!(js.contains("session sample values, not lifetime"));
        assert!(js.contains("\"sensor_type\": \"Temperature\""));
        assert!(js.contains("\"line\": \"+12V\""));
        assert!(!js.to_lowercase().contains("faulty"));
        // v1.0 Sensor Backend V2 metadata: every value carries value, unit,
        // logical type, hardware identity, provider, timestamp, confidence
        // and its threshold source.
        let Some(json::Value::Arr(list)) = v.get("sensors") else {
            panic!("sensors array")
        };
        assert!(!list.is_empty());
        for x in list {
            for k in [
                "value",
                "unit",
                "sensor_type",
                "hardware_id",
                "provider",
                "timestamp",
                "confidence",
                "threshold_source",
            ] {
                assert!(x.get(k).is_some(), "{k} missing");
            }
        }
        assert!(js.contains("\"threshold_source\": \"atx_spec_nominal_plus_minus_5_percent\""));
    }

    #[test]
    fn sampler_script_is_read_only_and_never_installs() {
        for bad in [
            "Set-",
            "Remove-",
            "New-Service",
            "sc.exe",
            "Invoke-WebRequest",
            "Start-Process",
            "Install",
            "Register-",
            "msiexec",
            "bcdedit",
            "reg add",
        ] {
            assert!(!SAMPLER_PS1.contains(bad), "{bad}");
        }
        assert!(SAMPLER_PS1.contains("never installs drivers"));
    }

    /// Regression (Windows gate v0.4.5): rows were collected but never
    /// emitted ("Argument types do not match" from `@($list)`). A fake
    /// nvidia-smi proves the emit path end to end on the Linux harness.
    #[test]
    fn sampler_emits_rows_from_a_provider() {
        if cfg!(windows) {
            return;
        }
        let Some(host) = crate::ps_exec::test_host() else {
            return;
        };
        let dir = std::env::temp_dir().join(format!("wsd-fake-smi-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let exe = dir.join("nvidia-smi.exe");
        std::fs::write(
            &exe,
            "#!/bin/sh\necho \"0, NVIDIA GeForce RTX 5060, 48, 51.71, 0\"\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let script = format!(
            "$env:PATH = '{}' + [IO.Path]::PathSeparator + $env:PATH; & {{ {} }} -Samples 2 -IntervalMs 50",
            dir.display(),
            SAMPLER_PS1
        );
        let out =
            crate::ps_exec::run_powershell(&host, &script, std::time::Duration::from_secs(60))
                .expect("sampler runs");
        let (sets, reports) = parse_sampler_output(&out);
        assert_eq!(sets.len(), 2, "{out}");
        assert!(
            reports
                .iter()
                .any(|r| r.provider == Provider::NvidiaSmi && r.state == ProviderState::Available)
        );
        let mut sm = Sampler::default();
        for (t, rows) in &sets {
            sm.add_sample(rows, t);
        }
        let snap_sensors = sm.into_sensors();
        let s = summarize(&snap_sensors);
        assert_eq!(
            s.temps
                .iter()
                .find(|c| c.role == Role::GpuTemp)
                .map(|c| c.value),
            Some(48.0),
            "{out}"
        );
        assert_eq!(
            s.power
                .iter()
                .find(|c| c.role == Role::GpuPower)
                .map(|c| c.value),
            Some(51.71)
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn sampler_runs_without_any_provider() {
        let Some(host) = crate::ps_exec::test_host() else {
            return;
        };
        let dir = std::env::temp_dir().join(format!("wsd-sens-{}", std::process::id()));
        let snap = collect(&host, &dir, 2, 50);
        assert!(
            snap.providers
                .iter()
                .any(|p| p.provider == Provider::LhmInternal)
        );
        if !cfg!(windows) {
            assert!(
                snap.sensors.is_empty(),
                "nothing invented on a host without sensors"
            );
            assert_eq!(snap.state(), ProviderState::Unavailable);
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn compact_disk_labels_keep_duplicate_disks_apart() {
        assert_eq!(disk_compact("TOSHIBA DT02ABA400 #1"), "TOSHIBA #1");
        assert_eq!(disk_compact("TOSHIBA DT02ABA400 #2"), "TOSHIBA #2");
        assert_eq!(disk_compact("ST2000VX017-3CV102"), "ST2000");
        assert_eq!(disk_compact("Samsung 9100"), "Samsung 9100");
        assert_eq!(disk_compact("Netac NVMe"), "Netac NVMe");
    }

    #[test]
    fn high_cpu_process_snapshot_is_context_with_top_processes() {
        let out = "WSD_PROC {\"t\":\"2026-10-06T11:00:03\",\"sys\":91,\"n\":24,\"top\":[{\"name\":\"MsMpEng\",\"pid\":4120,\"cpu\":924},{\"name\":\"chrome#3\",\"pid\":9932,\"cpu\":530.4}]}";
        let p = parse_process_context(out).unwrap();
        assert!(p.high_load);
        assert_eq!(p.top.len(), 2);
        assert_eq!(p.top[0].name, "MsMpEng");
        assert_eq!(p.top[0].pid, 4120);
        assert!(
            (p.top[0].cpu_percent - 38.5).abs() < 0.01,
            "normalised by 24 CPUs"
        );
        assert_eq!(p.top[1].name, "chrome", "perf instance suffix removed");
        let js = process_context_json(Some(&p));
        assert!(crate::deep_checks::json::parse(&js).is_some());
        assert!(js.contains("not a fault by itself"));
        // Low load: system % kept, no process list.
        let low = parse_process_context("WSD_PROC {\"t\":\"t\",\"sys\":12,\"n\":8,\"top\":[{\"name\":\"x\",\"pid\":1,\"cpu\":5}]}").unwrap();
        assert!(!low.high_load && low.top.is_empty());
        assert_eq!(low.system_cpu_percent, 12.0);
        // The snapshot lands in the sensor evidence JSON.
        let snap = Snapshot {
            process_context: Some(p),
            ..Default::default()
        };
        assert!(to_json(&snap).contains("\"process_context\": {\"timestamp\""));
        assert!(PROCESS_PS1.contains("Win32_PerfFormattedData_PerfProc_Process"));
        assert!(!PROCESS_PS1.contains("Stop-Process"));
    }
}
