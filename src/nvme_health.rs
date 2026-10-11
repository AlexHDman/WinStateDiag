//! Native NVMe Health reader (v0.4.2; real Windows validated on a Samsung
//! SSD 9100 PRO and a Netac NVMe SSD against CrystalDiskInfo 9.9.1 and
//! Victoria 5.37, used as external references only).
//!
//! Reads the NVMe **SMART / Health Information** log page (LID 02h) and,
//! when the stack allows it, the **Error Information** log page (LID 01h)
//! through the Windows storage stack itself:
//!
//! `CreateFileW(\\.\PhysicalDriveN)` → `DeviceIoControl(
//! IOCTL_STORAGE_QUERY_PROPERTY)` with a `STORAGE_PROPERTY_QUERY` whose
//! additional parameters are a `STORAGE_PROTOCOL_SPECIFIC_DATA`
//! (`ProtocolTypeNvme`, `NVMeDataTypeLogPage`).
//!
//! Strictly READ-ONLY. The only request this module can build is a
//! property *query* for a log page. There is no code path for Set
//! Features, firmware download/commit, format, sanitize, device self-test
//! or any other admin command, and the device handle is never opened for
//! writing.
//!
//! Facts, not verdicts: every value is the controller's raw value (counters
//! are full 128-bit integers, never truncated). A value that could not be
//! read is `None` — never a fabricated zero. Nothing here classifies a
//! disk as healthy or failing; the conservative classification is the
//! `storage_health` correlation layer.
//!
//! Identity: a health record is bound to the SAME physical-disk identity
//! the SSD benchmark and its history use
//! (`storage_topology::physical_disk_identity`), never to a drive letter.

// The reader exists only on Windows; elsewhere the parser/model are used
// by tests and the manifest only.
#![cfg_attr(not(windows), allow(dead_code))]

use crate::deep_checks::json;
use crate::storage_topology::{PhysicalDiskInfo, physical_disk_identity};

/// NVMe log page identifiers (NVMe Base Specification, Get Log Page).
pub const LID_ERROR_INFO: u8 = 0x01;
pub const LID_SMART_HEALTH: u8 = 0x02;
/// The SMART / Health Information log page is exactly 512 bytes.
pub const SMART_LOG_LEN: usize = 512;
/// One Error Information log entry is 64 bytes.
pub const ERROR_ENTRY_LEN: usize = 64;
/// Error log entries requested first (newest first); the reader falls back
/// to a single entry when the stack refuses the larger transfer.
pub const ERROR_LOG_ENTRIES_REQUESTED: usize = 16;

/// Evidence file prefix (`NVMe_Health_<dd.MM.yy_HH-mm>_PD<n>.json`). The
/// disk tag is AFTER the timestamp so the manifest's chronological run key
/// still reads the date first.
pub const EVIDENCE_PREFIX: &str = "NVMe_Health_";

// ---------------------------------------------------------------------
// SMART / Health Information log (LID 02h)
// ---------------------------------------------------------------------

/// Parsed SMART / Health Information log. Every field is the raw value the
/// controller returned; only the temperatures are additionally converted
/// from Kelvin, and a 0 K reading ("not implemented/not reported") is
/// `None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmartHealthLog {
    pub critical_warning: u8,
    /// Composite temperature, Kelvin (raw).
    pub composite_temperature_k: u16,
    pub available_spare_percent: u8,
    pub available_spare_threshold_percent: u8,
    /// May legitimately exceed 100 (the spec allows up to 255).
    pub percentage_used: u8,
    /// Units of 1000 × 512 bytes.
    pub data_units_read: u128,
    pub data_units_written: u128,
    pub host_read_commands: u128,
    pub host_write_commands: u128,
    /// Minutes.
    pub controller_busy_time_minutes: u128,
    pub power_cycles: u128,
    pub power_on_hours: u128,
    pub unsafe_shutdowns: u128,
    pub media_and_data_integrity_errors: u128,
    pub error_information_log_entries: u128,
    /// Minutes above the warning composite temperature threshold.
    pub warning_temperature_time_minutes: u32,
    /// Minutes above the critical composite temperature threshold.
    pub critical_temperature_time_minutes: u32,
    /// Temperature Sensor 1..8, Kelvin; `None` = not implemented (0).
    pub temperature_sensors_k: [Option<u16>; 8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// Fewer bytes than the structure needs (got, needed).
    Truncated { got: usize, needed: usize },
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::Truncated { got, needed } => {
                write!(f, "truncated log page: {got} of {needed} bytes")
            }
        }
    }
}

fn u16_le(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}
fn u32_le(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}
fn u64_le(b: &[u8], at: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(a)
}
fn u128_le(b: &[u8], at: usize) -> u128 {
    let mut a = [0u8; 16];
    a.copy_from_slice(&b[at..at + 16]);
    u128::from_le_bytes(a)
}

/// Parses a SMART / Health Information log page (NVMe Base Specification
/// "SMART / Health Information (Log Page Identifier 02h)"). A buffer
/// shorter than 512 bytes is rejected as a whole — no partial record with
/// zero-filled tails.
pub fn parse_smart_log(b: &[u8]) -> Result<SmartHealthLog, ParseError> {
    if b.len() < SMART_LOG_LEN {
        return Err(ParseError::Truncated {
            got: b.len(),
            needed: SMART_LOG_LEN,
        });
    }
    let mut sensors = [None; 8];
    for (i, s) in sensors.iter_mut().enumerate() {
        let k = u16_le(b, 200 + i * 2);
        *s = (k != 0).then_some(k);
    }
    Ok(SmartHealthLog {
        critical_warning: b[0],
        composite_temperature_k: u16_le(b, 1),
        available_spare_percent: b[3],
        available_spare_threshold_percent: b[4],
        percentage_used: b[5],
        data_units_read: u128_le(b, 32),
        data_units_written: u128_le(b, 48),
        host_read_commands: u128_le(b, 64),
        host_write_commands: u128_le(b, 80),
        controller_busy_time_minutes: u128_le(b, 96),
        power_cycles: u128_le(b, 112),
        power_on_hours: u128_le(b, 128),
        unsafe_shutdowns: u128_le(b, 144),
        media_and_data_integrity_errors: u128_le(b, 160),
        error_information_log_entries: u128_le(b, 176),
        warning_temperature_time_minutes: u32_le(b, 192),
        critical_temperature_time_minutes: u32_le(b, 196),
        temperature_sensors_k: sensors,
    })
}

/// Kelvin → whole °C. 0 K means "not reported" and is `None`, never -273.
pub fn kelvin_to_celsius(k: u16) -> Option<i32> {
    (k != 0).then(|| i32::from(k) - 273)
}

impl SmartHealthLog {
    pub fn composite_temperature_c(&self) -> Option<i32> {
        kelvin_to_celsius(self.composite_temperature_k)
    }
    /// Reported sensors only: (sensor number 1..8, °C).
    pub fn temperature_sensors_c(&self) -> Vec<(usize, i32)> {
        self.temperature_sensors_k
            .iter()
            .enumerate()
            .filter_map(|(i, k)| k.and_then(kelvin_to_celsius).map(|c| (i + 1, c)))
            .collect()
    }
}

/// Critical Warning bits (NVMe Base Specification, SMART / Health log
/// byte 0). Bits 6–7 are reserved and reported as such if ever set.
pub const CRITICAL_WARNING_BITS: [(u8, &str); 6] = [
    (0, "available_spare_below_threshold"),
    (1, "temperature_threshold_exceeded"),
    (2, "nvm_subsystem_reliability_degraded"),
    (3, "media_read_only"),
    (4, "volatile_memory_backup_failed"),
    (5, "persistent_memory_region_read_only"),
];

/// Names of the set Critical Warning bits (empty for 0).
pub fn critical_warning_flags(value: u8) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = CRITICAL_WARNING_BITS
        .iter()
        .filter(|(bit, _)| value & (1 << bit) != 0)
        .map(|(_, name)| *name)
        .collect();
    if value & 0b1100_0000 != 0 {
        out.push("reserved_bits_set");
    }
    out
}

/// Data units (1000 × 512 bytes each) → bytes, exact.
pub fn data_units_to_bytes(units: u128) -> Option<u128> {
    units.checked_mul(512_000)
}

// ---------------------------------------------------------------------
// Error Information log (LID 01h)
// ---------------------------------------------------------------------

/// One Error Information log entry (64 bytes), raw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorLogEntry {
    pub error_count: u64,
    pub submission_queue_id: u16,
    pub command_id: u16,
    /// Raw Status Field (bit 0 = phase tag).
    pub status_field: u16,
    pub parameter_error_location: u16,
    pub lba: u64,
    pub namespace: u32,
    /// "Vendor Specific Information Available" (a log page id, 0 = none).
    pub vendor_specific: u8,
    pub command_specific: u64,
}

impl ErrorLogEntry {
    /// Status Code Type (bits 11:9 of the raw Status Field).
    pub fn status_code_type(&self) -> u8 {
        ((self.status_field >> 9) & 0x7) as u8
    }
    /// Status Code (bits 8:1 of the raw Status Field).
    pub fn status_code(&self) -> u8 {
        ((self.status_field >> 1) & 0xFF) as u8
    }
}

/// Parses consecutive 64-byte Error Information entries. Entries whose
/// Error Count is 0 are empty slots and are skipped. A trailing partial
/// entry is ignored (never zero-filled); a buffer with no complete entry
/// is `Truncated`.
pub fn parse_error_log(b: &[u8]) -> Result<Vec<ErrorLogEntry>, ParseError> {
    if b.len() < ERROR_ENTRY_LEN {
        return Err(ParseError::Truncated {
            got: b.len(),
            needed: ERROR_ENTRY_LEN,
        });
    }
    Ok(b.chunks_exact(ERROR_ENTRY_LEN)
        .filter(|e| u64_le(e, 0) != 0)
        .map(|e| ErrorLogEntry {
            error_count: u64_le(e, 0),
            submission_queue_id: u16_le(e, 8),
            command_id: u16_le(e, 10),
            status_field: u16_le(e, 12),
            parameter_error_location: u16_le(e, 14),
            lba: u64_le(e, 16),
            namespace: u32_le(e, 24),
            vendor_specific: e[28],
            command_specific: u64_le(e, 32),
        })
        .collect())
}

// ---------------------------------------------------------------------
// Probe model
// ---------------------------------------------------------------------

/// Why a log page could not be read. Every variant is a normal outcome
/// (unsupported controller, USB bridge without pass-through, RAID/RST,
/// non-admin, …) — never a crash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeError {
    /// ERROR_ACCESS_DENIED (5).
    AccessDenied,
    /// ERROR_INVALID_FUNCTION (1): the stack does not implement the query.
    InvalidFunction,
    /// ERROR_NOT_SUPPORTED (50) / ERROR_INVALID_PARAMETER (87): the
    /// driver/bridge does not pass NVMe log pages through.
    NotSupported(u32),
    /// The device could not be opened (Win32 error).
    OpenFailed(u32),
    /// DeviceIoControl failed with another Win32 error.
    IoctlFailed(u32),
    /// The driver answered but the descriptor was not usable.
    BadResponse(String),
}

impl ProbeError {
    pub fn status(&self) -> ProbeStatus {
        match self {
            ProbeError::AccessDenied => ProbeStatus::AccessDenied,
            ProbeError::InvalidFunction | ProbeError::NotSupported(_) => ProbeStatus::Unsupported,
            ProbeError::OpenFailed(_) | ProbeError::IoctlFailed(_) | ProbeError::BadResponse(_) => {
                ProbeStatus::Error
            }
        }
    }
    pub fn describe(&self) -> String {
        match self {
            ProbeError::AccessDenied => "access denied (Win32 error 5)".into(),
            ProbeError::InvalidFunction => {
                "invalid function (Win32 error 1): the storage stack does not pass NVMe log pages through"
                    .into()
            }
            ProbeError::NotSupported(code) => format!(
                "not supported (Win32 error {code}): driver, RAID/RST or USB bridge without NVMe pass-through"
            ),
            ProbeError::OpenFailed(code) => format!("device open failed (Win32 error {code})"),
            ProbeError::IoctlFailed(code) => format!("query failed (Win32 error {code})"),
            ProbeError::BadResponse(why) => format!("unusable response: {why}"),
        }
    }
}

/// Outcome of one probe, as written to the evidence (`status`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeStatus {
    Ok,
    Unsupported,
    AccessDenied,
    Error,
}

impl ProbeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            ProbeStatus::Ok => "OK",
            ProbeStatus::Unsupported => "UNSUPPORTED",
            ProbeStatus::AccessDenied => "ACCESS_DENIED",
            ProbeStatus::Error => "ERROR",
        }
    }
}

/// One log page as returned by a reader, plus how it was obtained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogRead {
    pub data: Vec<u8>,
    /// e.g. "StorageDeviceProtocolSpecificProperty".
    pub via: &'static str,
}

/// Read-only log page reader. The Windows implementation is
/// `windows_source::WindowsNvmeReader`; tests use synthetic readers.
pub trait NvmeLogSource {
    fn read_log_page(
        &self,
        disk_index: u32,
        log_id: u8,
        length: usize,
    ) -> Result<LogRead, ProbeError>;
    /// v0.4.5: Identify Controller (CNS 01h, 4096 bytes) — read only for
    /// the drive-reported WCTEMP / CCTEMP thresholds. Optional.
    fn read_identify_controller(&self, _disk_index: u32) -> Result<LogRead, ProbeError> {
        Err(ProbeError::NotSupported(50))
    }
}

/// Identify Controller length.
pub const IDENTIFY_LEN: usize = 4096;

/// Drive-reported composite temperature thresholds (Identify Controller
/// WCTEMP bytes 266–267, CCTEMP bytes 268–269, Kelvin). 0 / implausible
/// values mean "not reported" — never a guess.
pub fn parse_temp_thresholds(id: &[u8]) -> (Option<f64>, Option<f64>) {
    let k = |at: usize| -> Option<f64> {
        let v = u16::from_le_bytes([*id.get(at)?, *id.get(at + 1)?]);
        // 20 °C … 150 °C: anything else is not a usable threshold.
        (293..=423).contains(&v).then(|| f64::from(v) - 273.0)
    };
    (k(266), k(268))
}

/// The whole health record for one physical disk.
#[derive(Debug, Clone, PartialEq)]
pub struct NvmeHealth {
    /// Same identity as the SSD benchmark / history.
    pub physical_identity: String,
    pub disk_index: u32,
    pub model: String,
    pub bus_type: String,
    /// Local capture time, ISO-like `YYYY-MM-DDTHH:MM:SS`.
    pub captured_at: String,
    /// Windows API path that produced the data (or would have).
    pub source: String,
    pub status: ProbeStatus,
    /// Human-readable reason for a non-OK status.
    pub status_detail: Option<String>,
    pub smart: Option<SmartHealthLog>,
    pub error_log_status: ProbeStatus,
    pub error_log_detail: Option<String>,
    /// Non-empty entries read (newest first as the controller returns them).
    /// `None` when the page was not read.
    pub error_log: Option<Vec<ErrorLogEntry>>,
    /// v0.4.4: Windows Storage Reliability counters (SATA/other fallback;
    /// facts only, `None` when not read / not available).
    pub reliability: Option<StorageReliability>,
    /// v1.0: read-only ATA / SATA SMART attributes (`None` = not an ATA
    /// disk / not read).
    pub ata_smart: Option<crate::ata_smart::AtaSmart>,
    /// v0.4.5: drive-reported warning / critical composite temperature
    /// (Identify Controller WCTEMP / CCTEMP, °C); `None` = not reported.
    pub temp_warning_c: Option<f64>,
    pub temp_critical_c: Option<f64>,
}

/// v0.4.4 health routing by the Windows bus type (STORAGE_BUS_TYPE).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthRoute {
    /// Native NVMe log pages.
    Nvme,
    /// SATA/ATA: never the NVMe protocol. ATA SMART is not implemented; the
    /// Windows Storage Reliability counters are the fallback.
    AtaSata,
    /// RAID/RST, SCSI, USB, unknown: NVMe pass-through may exist (e.g. an
    /// NVMe drive behind RST or a USB bridge); a refusal is UNSUPPORTED.
    Probe,
    /// SAS, SD, MMC, virtual, Storage Spaces…: no supported provider.
    NotApplicable,
}

pub fn route(bus_type: &str) -> HealthRoute {
    match bus_type.trim() {
        "NVMe" => HealthRoute::Nvme,
        "SATA" | "ATA" | "ATAPI" => HealthRoute::AtaSata,
        "RAID" | "SCSI" | "USB" | "Unknown" | "" => HealthRoute::Probe,
        _ => HealthRoute::NotApplicable,
    }
}

/// `MSFT_StorageReliabilityCounter` facts (read-only, may be all empty).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct StorageReliability {
    pub temperature_c: Option<f64>,
    pub wear_percent: Option<f64>,
    pub power_on_hours: Option<f64>,
    pub read_errors_total: Option<f64>,
    pub read_errors_uncorrected: Option<f64>,
    pub write_errors_total: Option<f64>,
    pub write_errors_uncorrected: Option<f64>,
}

impl StorageReliability {
    pub fn is_empty(&self) -> bool {
        *self == StorageReliability::default()
    }
}

/// Read-only Windows Storage Reliability reader for `PhysicalDrive{N}`.
pub fn reliability_ps1(index: u32) -> String {
    format!(
        r#"$ErrorActionPreference = 'Continue'
$r = $null
try {{
    $d = Get-PhysicalDisk -ErrorAction Stop | Where-Object {{ [string]$_.DeviceId -eq '{index}' }} | Select-Object -First 1
    if ($d) {{ $r = $d | Get-StorageReliabilityCounter -ErrorAction Stop }}
}} catch {{ }}
$o = [ordered]@{{}}
if ($r) {{ foreach ($k in @('Temperature','Wear','PowerOnHours','ReadErrorsTotal','ReadErrorsUncorrected','WriteErrorsTotal','WriteErrorsUncorrected')) {{ $o[$k] = $r.$k }} }}
Write-Output ('WSD_REL ' + (ConvertTo-Json -InputObject ([PSCustomObject]$o) -Compress))
"#
    )
}

pub fn parse_reliability(stdout: &str) -> Option<StorageReliability> {
    let v = json::parse(crate::ps_exec::marked_line(stdout, "WSD_REL ")?)?;
    let n = |k: &str| match v.get(k) {
        Some(json::Value::Num(x)) => Some(*x),
        _ => None,
    };
    // A 0 °C / 0 h reading from an empty counter is not a value.
    let pos = |x: Option<f64>| x.filter(|v| *v > 0.0);
    Some(StorageReliability {
        temperature_c: pos(n("Temperature")),
        // v1.0 item 14: MSFT_StorageReliabilityCounter returns Wear = 0 for
        // drives that do not report wear at all — 0 is not "0 % worn".
        // Only a positive value is a reading; otherwise "no reliable data".
        wear_percent: pos(n("Wear")),
        power_on_hours: pos(n("PowerOnHours")),
        read_errors_total: n("ReadErrorsTotal"),
        read_errors_uncorrected: n("ReadErrorsUncorrected"),
        write_errors_total: n("WriteErrorsTotal"),
        write_errors_uncorrected: n("WriteErrorsUncorrected"),
    })
}

/// Reads the Storage Reliability counters of `PhysicalDrive{index}`
/// (read-only `Get-StorageReliabilityCounter`). `None` when the host could
/// not run or produced no result; an empty record means "no data".
pub fn read_reliability(host: &str, index: u32) -> Option<StorageReliability> {
    let out = crate::ps_exec::run_powershell(
        host,
        &reliability_ps1(index),
        std::time::Duration::from_secs(60),
    )
    .ok()?;
    parse_reliability(&out)
}

pub const WINDOWS_API_SOURCE: &str = "IOCTL_STORAGE_QUERY_PROPERTY + STORAGE_PROTOCOL_SPECIFIC_DATA (ProtocolTypeNvme, NVMeDataTypeLogPage) on \\\\.\\PhysicalDriveN";

/// True for buses where NVMe log pages can never apply (ATA SMART is a
/// different command set and is deliberately not implemented).
pub fn is_ata_bus(bus_type: &str) -> bool {
    route(bus_type) == HealthRoute::AtaSata
}

/// Collects the health record for `disk` through `source`. Never panics;
/// any failure becomes a status. ATA/SATA devices are not touched at all.
pub fn collect(
    source: &dyn NvmeLogSource,
    disk: &PhysicalDiskInfo,
    captured_at: &str,
) -> NvmeHealth {
    let mut h = NvmeHealth {
        physical_identity: physical_disk_identity(disk),
        disk_index: disk.index,
        model: disk.model.trim().to_string(),
        bus_type: disk.bus_type.clone(),
        captured_at: captured_at.to_string(),
        source: WINDOWS_API_SOURCE.to_string(),
        status: ProbeStatus::Unsupported,
        status_detail: None,
        smart: None,
        error_log_status: ProbeStatus::Unsupported,
        error_log_detail: None,
        error_log: None,
        reliability: None,
        ata_smart: None,
        temp_warning_c: None,
        temp_critical_c: None,
    };
    let r = route(&disk.bus_type);
    if matches!(r, HealthRoute::AtaSata | HealthRoute::NotApplicable) {
        let why = if r == HealthRoute::AtaSata {
            format!(
                "bus type {}: SMART NOT AVAILABLE — NVMe log pages do not apply; health from ATA SMART when the read succeeds (Windows Storage Reliability counters as facts)",
                disk.bus_type
            )
        } else {
            format!("bus type {}: no supported health provider", disk.bus_type)
        };
        h.status_detail = Some(why.clone());
        h.error_log_detail = Some(why);
        return h;
    }
    match source.read_log_page(disk.index, LID_SMART_HEALTH, SMART_LOG_LEN) {
        Ok(read) => match parse_smart_log(&read.data) {
            Ok(log) => {
                h.status = ProbeStatus::Ok;
                h.source = format!("{WINDOWS_API_SOURCE}; {}", read.via);
                h.smart = Some(log);
            }
            Err(e) => {
                h.status = ProbeStatus::Error;
                h.status_detail = Some(e.to_string());
            }
        },
        Err(e) => {
            h.status = e.status();
            h.status_detail = Some(e.describe());
        }
    }
    if h.status == ProbeStatus::Ok
        && let Ok(id) = source.read_identify_controller(disk.index)
    {
        let (w, c) = parse_temp_thresholds(&id.data);
        h.temp_warning_c = w;
        h.temp_critical_c = c;
    }
    if h.status != ProbeStatus::Ok {
        h.error_log_status = h.status;
        h.error_log_detail = Some("not attempted: SMART / Health log unavailable".into());
        return h;
    }
    let big = ERROR_LOG_ENTRIES_REQUESTED * ERROR_ENTRY_LEN;
    let read = source
        .read_log_page(disk.index, LID_ERROR_INFO, big)
        .or_else(|_| source.read_log_page(disk.index, LID_ERROR_INFO, ERROR_ENTRY_LEN));
    match read {
        Ok(read) => match parse_error_log(&read.data) {
            Ok(entries) => {
                h.error_log_status = ProbeStatus::Ok;
                h.error_log = Some(entries);
            }
            Err(e) => {
                h.error_log_status = ProbeStatus::Error;
                h.error_log_detail = Some(e.to_string());
            }
        },
        Err(e) => {
            h.error_log_status = e.status();
            h.error_log_detail = Some(e.describe());
        }
    }
    h
}

// ---------------------------------------------------------------------
// Evidence
// ---------------------------------------------------------------------

/// `NVMe_Health_<stamp>_PD<n>.json`.
pub fn evidence_file_name(stamp: &str, disk_index: u32) -> String {
    format!("{EVIDENCE_PREFIX}{stamp}_PD{disk_index}.json")
}

fn opt_str(v: Option<&str>) -> String {
    v.map(json::string).unwrap_or_else(|| "null".into())
}

/// 128-bit counters are written as decimal STRINGS: a JSON number above
/// 2^53 is silently rounded by most readers, and these counters must stay
/// exact.
fn counter(v: Option<u128>) -> String {
    v.map(|n| json::string(&n.to_string()))
        .unwrap_or_else(|| "null".into())
}

fn num<T: std::fmt::Display>(v: Option<T>) -> String {
    v.map(|n| n.to_string()).unwrap_or_else(|| "null".into())
}

/// Attach an ATA SMART read to a SATA health record. A successful read
/// becomes the record's health source: the stale "ATA SMART is not
/// implemented" detail is replaced so no consumer reports UNSUPPORTED.
pub fn apply_ata(h: &mut NvmeHealth, ata: crate::ata_smart::AtaSmart) {
    if ata.state == crate::ata_smart::AtaState::Ok {
        h.status_detail = Some(format!(
            "bus type {}: NVMe log pages do not apply; ATA SMART read OK ({}) — current health source",
            h.bus_type,
            ata.health()
        ));
        if !h.source.contains("ATA SMART") {
            h.source = format!("{}; ATA SMART READ DATA/THRESHOLDS", h.source);
        }
    }
    h.ata_smart = Some(ata);
}

/// v1.0 item 17: the drive temperature WITH its provenance. Order: the
/// NVMe composite sensor, ATA attribute 194/190, then the Windows Storage
/// Reliability counter. Never a board / CPU sensor, never 0.
pub fn temperature_provenance(h: &NvmeHealth) -> Option<(f64, &'static str)> {
    if let Some(c) = h.smart.as_ref().and_then(|l| l.composite_temperature_c()) {
        return Some((c as f64, "nvme_smart_composite_temperature"));
    }
    if let Some(t) = h
        .ata_smart
        .as_ref()
        .filter(|a| a.state == crate::ata_smart::AtaState::Ok)
        .and_then(|a| a.temperature_c())
    {
        return Some((t as f64, "ata_smart_attribute_194_190"));
    }
    h.reliability
        .as_ref()
        .filter(|r| !r.is_empty())
        .and_then(|r| r.temperature_c)
        .map(|t| (t, "msft_storage_reliability_counter"))
}

/// Normalized current-health record: (health_source, health_status).
/// ATA SMART is the source of truth for SATA drives — a successful ATA
/// read is never reported as UNSUPPORTED just because the NVMe log page
/// is absent (v1.0 item 13).
pub fn health_source_status(h: &NvmeHealth) -> (&'static str, &'static str) {
    if let Some(l) = h.smart.as_ref() {
        let cw = l.critical_warning;
        let status = if cw & 0b1101 != 0 {
            "PROBLEM"
        } else if cw != 0 || l.media_and_data_integrity_errors > 0 || l.percentage_used >= 100 {
            "ATTENTION"
        } else {
            "OK"
        };
        return ("nvme_smart_health_log", status);
    }
    if let Some(a) = h
        .ata_smart
        .as_ref()
        .filter(|a| a.state == crate::ata_smart::AtaState::Ok)
    {
        let status = match a.health() {
            "SMART: THRESHOLD EXCEEDED" => "PROBLEM",
            "SMART: OK" => "OK",
            _ => "ATTENTION",
        };
        return ("ata_smart", status);
    }
    ("none", h.status.as_str())
}

/// Evidence JSON (UTF-8, `\n`, fixed field order). Missing values are
/// `null`, never 0. No serial number field is added: the only device tag
/// is the physical identity the SSD benchmark evidence already records.
pub fn to_json(h: &NvmeHealth) -> String {
    let s = h.smart.as_ref();
    let mut f: Vec<String> = vec![
        format!(
            "  \"format\": {}",
            json::string("winstatediag.nvme_health/1")
        ),
        format!(
            "  \"physical_identity\": {}",
            json::string(&h.physical_identity)
        ),
        format!("  \"physical_disk_index\": {}", h.disk_index),
        format!("  \"model\": {}", json::string(&h.model)),
        format!("  \"bus_type\": {}", json::string(&h.bus_type)),
        format!("  \"captured_at\": {}", json::string(&h.captured_at)),
        format!("  \"source\": {}", json::string(&h.source)),
        format!("  \"status\": {}", json::string(h.status.as_str())),
        format!(
            "  \"status_detail\": {}",
            opt_str(h.status_detail.as_deref())
        ),
        format!(
            "  \"health_source\": {}",
            json::string(health_source_status(h).0)
        ),
        format!(
            "  \"health_status\": {}",
            json::string(health_source_status(h).1)
        ),
        format!(
            "  \"temperature\": {}",
            temperature_provenance(h)
                .map(|(c, src)| format!("{{\"celsius\": {c}, \"source\": {}}}", json::string(src)))
                .unwrap_or_else(|| "null".into())
        ),
        format!("  \"temp_warning_c\": {}", num(h.temp_warning_c)),
        format!("  \"temp_critical_c\": {}", num(h.temp_critical_c)),
    ];
    let flags = s
        .map(|l| {
            let names: Vec<String> = critical_warning_flags(l.critical_warning)
                .into_iter()
                .map(json::string)
                .collect();
            format!("[{}]", names.join(", "))
        })
        .unwrap_or_else(|| "null".into());
    let sensors = s
        .map(|l| {
            let items: Vec<String> = l
                .temperature_sensors_k
                .iter()
                .enumerate()
                .filter_map(|(i, k)| {
                    k.map(|k| {
                        format!(
                            "{{\"sensor\": {}, \"kelvin\": {}, \"celsius\": {}}}",
                            i + 1,
                            k,
                            num(kelvin_to_celsius(k))
                        )
                    })
                })
                .collect();
            format!("[{}]", items.join(", "))
        })
        .unwrap_or_else(|| "null".into());
    let smart = [
        format!(
            "    \"critical_warning\": {}",
            num(s.map(|l| l.critical_warning))
        ),
        format!("    \"critical_warning_flags\": {flags}"),
        format!(
            "    \"composite_temperature_kelvin\": {}",
            num(s.and_then(
                |l| (l.composite_temperature_k != 0).then_some(l.composite_temperature_k)
            ))
        ),
        format!(
            "    \"composite_temperature_celsius\": {}",
            num(s.and_then(|l| l.composite_temperature_c()))
        ),
        format!(
            "    \"available_spare_percent\": {}",
            num(s.map(|l| l.available_spare_percent))
        ),
        format!(
            "    \"available_spare_threshold_percent\": {}",
            num(s.map(|l| l.available_spare_threshold_percent))
        ),
        format!(
            "    \"percentage_used\": {}",
            num(s.map(|l| l.percentage_used))
        ),
        format!(
            "    \"data_units_read\": {}",
            counter(s.map(|l| l.data_units_read))
        ),
        format!(
            "    \"data_units_written\": {}",
            counter(s.map(|l| l.data_units_written))
        ),
        format!(
            "    \"data_units_read_bytes\": {}",
            counter(s.and_then(|l| data_units_to_bytes(l.data_units_read)))
        ),
        format!(
            "    \"data_units_written_bytes\": {}",
            counter(s.and_then(|l| data_units_to_bytes(l.data_units_written)))
        ),
        format!(
            "    \"host_read_commands\": {}",
            counter(s.map(|l| l.host_read_commands))
        ),
        format!(
            "    \"host_write_commands\": {}",
            counter(s.map(|l| l.host_write_commands))
        ),
        format!(
            "    \"controller_busy_time_minutes\": {}",
            counter(s.map(|l| l.controller_busy_time_minutes))
        ),
        format!(
            "    \"power_cycles\": {}",
            counter(s.map(|l| l.power_cycles))
        ),
        format!(
            "    \"power_on_hours\": {}",
            counter(s.map(|l| l.power_on_hours))
        ),
        format!(
            "    \"unsafe_shutdowns\": {}",
            counter(s.map(|l| l.unsafe_shutdowns))
        ),
        format!(
            "    \"media_and_data_integrity_errors\": {}",
            counter(s.map(|l| l.media_and_data_integrity_errors))
        ),
        format!(
            "    \"error_information_log_entries\": {}",
            counter(s.map(|l| l.error_information_log_entries))
        ),
        format!(
            "    \"warning_temperature_time_minutes\": {}",
            num(s.map(|l| l.warning_temperature_time_minutes))
        ),
        format!(
            "    \"critical_temperature_time_minutes\": {}",
            num(s.map(|l| l.critical_temperature_time_minutes))
        ),
        format!("    \"temperature_sensors\": {sensors}"),
    ];
    f.push(format!(
        "  \"smart_health_log\": {{\n{}\n  }}",
        smart.join(",\n")
    ));
    let entries = match &h.error_log {
        None => "null".into(),
        Some(list) if list.is_empty() => "[]".into(),
        Some(list) => {
            let items: Vec<String> = list
                .iter()
                .map(|e| {
                    format!(
                        "      {{\"error_count\": {}, \"sqid\": {}, \"cid\": {}, \"status_field\": {}, \"status_code_type\": {}, \"status_code\": {}, \"parameter_error_location\": {}, \"lba\": {}, \"namespace\": {}, \"vendor_specific\": {}, \"command_specific\": {}}}",
                        json::string(&e.error_count.to_string()),
                        e.submission_queue_id,
                        e.command_id,
                        e.status_field,
                        e.status_code_type(),
                        e.status_code(),
                        e.parameter_error_location,
                        json::string(&e.lba.to_string()),
                        e.namespace,
                        e.vendor_specific,
                        json::string(&e.command_specific.to_string())
                    )
                })
                .collect();
            format!("[\n{}\n    ]", items.join(",\n"))
        }
    };
    f.push(format!(
        "  \"error_information_log\": {{\n    \"status\": {},\n    \"detail\": {},\n    \"entries\": {}\n  }}",
        json::string(h.error_log_status.as_str()),
        opt_str(h.error_log_detail.as_deref()),
        entries
    ));
    f.push(match &h.reliability {
        None => "  \"storage_reliability\": null".to_string(),
        Some(r) => {
            let n = |v: Option<f64>| v.map(|x| format!("{x}")).unwrap_or_else(|| "null".into());
            format!(
                "  \"storage_reliability\": {{\"source\": \"MSFT_StorageReliabilityCounter\", \"temperature_c\": {}, \"wear_percent\": {}, \"power_on_hours\": {}, \"read_errors_total\": {}, \"read_errors_uncorrected\": {}, \"write_errors_total\": {}, \"write_errors_uncorrected\": {}}}",
                n(r.temperature_c),
                n(r.wear_percent),
                n(r.power_on_hours),
                n(r.read_errors_total),
                n(r.read_errors_uncorrected),
                n(r.write_errors_total),
                n(r.write_errors_uncorrected)
            )
        }
    });
    f.push(match &h.ata_smart {
        None => "  \"ata_smart\": null".to_string(),
        Some(s) => format!("  \"ata_smart\": {}", crate::ata_smart::to_json(s)),
    });
    f.push(format!(
        "  \"note\": {}",
        json::string(
            "Raw controller facts, not a verdict. Non-zero unsafe shutdowns, error log entries or percentage used do not by themselves mean a failing drive."
        )
    ));
    format!("{{\n{}\n}}\n", f.join(",\n"))
}

// ---------------------------------------------------------------------
// Windows reader
// ---------------------------------------------------------------------

#[cfg(windows)]
pub mod windows_source {
    //! `\\.\PhysicalDriveN` + `IOCTL_STORAGE_QUERY_PROPERTY` with
    //! `STORAGE_PROTOCOL_SPECIFIC_DATA` (NVMe log page). READ-ONLY: the
    //! handle is opened with `GENERIC_READ` (or, if that is refused, with
    //! no data access at all — the IOCTL is `FILE_ANY_ACCESS`), never with
    //! write access, and the only control code used is the property query.
    use super::{LogRead, NvmeLogSource, ProbeError};
    use std::ffi::c_void;
    use std::ptr::null_mut;

    type Handle = *mut c_void;
    type Dword = u32;

    const INVALID_HANDLE_VALUE: Handle = -1_isize as Handle;
    const GENERIC_READ: Dword = 0x8000_0000;
    const FILE_SHARE_READ: Dword = 0x0000_0001;
    const FILE_SHARE_WRITE: Dword = 0x0000_0002;
    const OPEN_EXISTING: Dword = 3;
    const IOCTL_STORAGE_QUERY_PROPERTY: Dword = 0x2D_1400;
    /// STORAGE_PROPERTY_ID::StorageAdapterProtocolSpecificProperty.
    const STORAGE_ADAPTER_PROTOCOL_SPECIFIC_PROPERTY: Dword = 49;
    /// STORAGE_PROPERTY_ID::StorageDeviceProtocolSpecificProperty.
    const STORAGE_DEVICE_PROTOCOL_SPECIFIC_PROPERTY: Dword = 50;
    const PROPERTY_STANDARD_QUERY: Dword = 0;
    /// STORAGE_PROTOCOL_TYPE::ProtocolTypeNvme.
    const PROTOCOL_TYPE_NVME: Dword = 3;
    /// STORAGE_PROTOCOL_NVME_DATA_TYPE::NVMeDataTypeLogPage.
    const NVME_DATA_TYPE_LOG_PAGE: Dword = 2;
    /// NVMeDataTypeIdentify + NVME_IDENTIFY_CNS_CONTROLLER (v0.4.5).
    const NVME_DATA_TYPE_IDENTIFY: Dword = 1;
    const NVME_IDENTIFY_CNS_CONTROLLER: Dword = 1;

    const ERROR_INVALID_FUNCTION: Dword = 1;
    const ERROR_ACCESS_DENIED: Dword = 5;
    const ERROR_NOT_SUPPORTED: Dword = 50;
    const ERROR_INVALID_PARAMETER: Dword = 87;

    unsafe extern "system" {
        fn CreateFileW(
            file_name: *const u16,
            desired_access: Dword,
            share_mode: Dword,
            security_attributes: *mut c_void,
            creation_disposition: Dword,
            flags_and_attributes: Dword,
            template_file: Handle,
        ) -> Handle;
        fn CloseHandle(handle: Handle) -> i32;
        fn DeviceIoControl(
            device: Handle,
            io_control_code: Dword,
            in_buffer: *mut c_void,
            in_buffer_size: Dword,
            out_buffer: *mut c_void,
            out_buffer_size: Dword,
            bytes_returned: *mut Dword,
            overlapped: *mut c_void,
        ) -> i32;
        fn GetLastError() -> Dword;
    }

    /// STORAGE_PROTOCOL_SPECIFIC_DATA (40 bytes).
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct StorageProtocolSpecificData {
        protocol_type: Dword,
        data_type: Dword,
        protocol_data_request_value: Dword,
        protocol_data_request_sub_value: Dword,
        protocol_data_offset: Dword,
        protocol_data_length: Dword,
        fixed_protocol_return_data: Dword,
        protocol_data_request_sub_value2: Dword,
        protocol_data_request_sub_value3: Dword,
        protocol_data_request_sub_value4: Dword,
    }

    const PSD_LEN: usize = std::mem::size_of::<StorageProtocolSpecificData>();
    /// FIELD_OFFSET(STORAGE_PROPERTY_QUERY, AdditionalParameters).
    const QUERY_HEADER_LEN: usize = 8;
    /// STORAGE_PROTOCOL_DATA_DESCRIPTOR = Version + Size + the 40-byte data.
    const DESCRIPTOR_LEN: usize = 8 + PSD_LEN;

    struct OwnedHandle(Handle);
    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            // SAFETY: a valid handle returned by CreateFileW, closed once.
            unsafe {
                CloseHandle(self.0);
            }
        }
    }

    fn open_read_only(index: u32) -> Result<OwnedHandle, ProbeError> {
        let path: Vec<u16> = format!(r"\\.\PhysicalDrive{index}")
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut last = 0;
        // GENERIC_READ first; then no data access (enough for a
        // FILE_ANY_ACCESS property query on some stacks). Never write.
        for access in [GENERIC_READ, 0] {
            // SAFETY: NUL-terminated path; all other pointers null.
            let h = unsafe {
                CreateFileW(
                    path.as_ptr(),
                    access,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    null_mut(),
                    OPEN_EXISTING,
                    0,
                    null_mut(),
                )
            };
            if h != INVALID_HANDLE_VALUE && !h.is_null() {
                return Ok(OwnedHandle(h));
            }
            // SAFETY: plain thread-local error read.
            last = unsafe { GetLastError() };
        }
        Err(match last {
            ERROR_ACCESS_DENIED => ProbeError::AccessDenied,
            code => ProbeError::OpenFailed(code),
        })
    }

    fn query(
        h: &OwnedHandle,
        property_id: Dword,
        log_id: u8,
        length: usize,
    ) -> Result<Vec<u8>, ProbeError> {
        query_typed(
            h,
            property_id,
            NVME_DATA_TYPE_LOG_PAGE,
            Dword::from(log_id),
            length,
        )
    }

    fn query_typed(
        h: &OwnedHandle,
        property_id: Dword,
        data_type: Dword,
        request_value: Dword,
        length: usize,
    ) -> Result<Vec<u8>, ProbeError> {
        let total = QUERY_HEADER_LEN + PSD_LEN + length;
        let mut buf = vec![0u8; total];
        buf[0..4].copy_from_slice(&property_id.to_le_bytes());
        buf[4..8].copy_from_slice(&PROPERTY_STANDARD_QUERY.to_le_bytes());
        let psd = StorageProtocolSpecificData {
            protocol_type: PROTOCOL_TYPE_NVME,
            data_type,
            protocol_data_request_value: request_value,
            protocol_data_request_sub_value: 0,
            protocol_data_offset: PSD_LEN as Dword,
            protocol_data_length: length as Dword,
            ..Default::default()
        };
        let fields = [
            psd.protocol_type,
            psd.data_type,
            psd.protocol_data_request_value,
            psd.protocol_data_request_sub_value,
            psd.protocol_data_offset,
            psd.protocol_data_length,
            psd.fixed_protocol_return_data,
            psd.protocol_data_request_sub_value2,
            psd.protocol_data_request_sub_value3,
            psd.protocol_data_request_sub_value4,
        ];
        for (i, v) in fields.iter().enumerate() {
            let at = QUERY_HEADER_LEN + i * 4;
            buf[at..at + 4].copy_from_slice(&v.to_le_bytes());
        }
        let mut returned: Dword = 0;
        // SAFETY: `buf` is a live, correctly sized in/out buffer.
        let ok = unsafe {
            DeviceIoControl(
                h.0,
                IOCTL_STORAGE_QUERY_PROPERTY,
                buf.as_mut_ptr().cast(),
                total as Dword,
                buf.as_mut_ptr().cast(),
                total as Dword,
                &mut returned,
                null_mut(),
            )
        };
        if ok == 0 {
            // SAFETY: plain thread-local error read.
            return Err(match unsafe { GetLastError() } {
                ERROR_ACCESS_DENIED => ProbeError::AccessDenied,
                ERROR_INVALID_FUNCTION => ProbeError::InvalidFunction,
                code @ (ERROR_NOT_SUPPORTED | ERROR_INVALID_PARAMETER) => {
                    ProbeError::NotSupported(code)
                }
                code => ProbeError::IoctlFailed(code),
            });
        }
        super::extract_protocol_data(&buf[..(returned as usize).min(total)], length)
    }

    /// The real reader. Tries the device-scope property first, then the
    /// adapter-scope one (some stacks answer only there).
    pub struct WindowsNvmeReader;

    impl NvmeLogSource for WindowsNvmeReader {
        fn read_log_page(
            &self,
            disk_index: u32,
            log_id: u8,
            length: usize,
        ) -> Result<LogRead, ProbeError> {
            let h = open_read_only(disk_index)?;
            match query(
                &h,
                STORAGE_DEVICE_PROTOCOL_SPECIFIC_PROPERTY,
                log_id,
                length,
            ) {
                Ok(data) => Ok(LogRead {
                    data,
                    via: "StorageDeviceProtocolSpecificProperty",
                }),
                Err(first) => query(
                    &h,
                    STORAGE_ADAPTER_PROTOCOL_SPECIFIC_PROPERTY,
                    log_id,
                    length,
                )
                .map(|data| LogRead {
                    data,
                    via: "StorageAdapterProtocolSpecificProperty",
                })
                .map_err(|_| first),
            }
        }

        fn read_identify_controller(&self, disk_index: u32) -> Result<LogRead, ProbeError> {
            let h = open_read_only(disk_index)?;
            let q = |prop| {
                query_typed(
                    &h,
                    prop,
                    NVME_DATA_TYPE_IDENTIFY,
                    NVME_IDENTIFY_CNS_CONTROLLER,
                    super::IDENTIFY_LEN,
                )
            };
            match q(STORAGE_DEVICE_PROTOCOL_SPECIFIC_PROPERTY) {
                Ok(data) => Ok(LogRead {
                    data,
                    via: "StorageDeviceProtocolSpecificProperty",
                }),
                Err(first) => q(STORAGE_ADAPTER_PROTOCOL_SPECIFIC_PROPERTY)
                    .map(|data| LogRead {
                        data,
                        via: "StorageAdapterProtocolSpecificProperty",
                    })
                    .map_err(|_| first),
            }
        }
    }

    const _: () = assert!(PSD_LEN == 40 && DESCRIPTOR_LEN == 48);
}

/// Validates a returned `STORAGE_PROTOCOL_DATA_DESCRIPTOR` and slices the
/// log page out of it (pure, so it is tested off Windows). Layout: Version
/// u32, Size u32, then STORAGE_PROTOCOL_SPECIFIC_DATA whose
/// ProtocolDataOffset (relative to that structure, i.e. byte 8) and
/// ProtocolDataLength locate the payload.
pub fn extract_protocol_data(out: &[u8], expected: usize) -> Result<Vec<u8>, ProbeError> {
    const DESCRIPTOR_LEN: usize = 48;
    if out.len() < DESCRIPTOR_LEN {
        return Err(ProbeError::BadResponse(format!(
            "descriptor too short ({} bytes)",
            out.len()
        )));
    }
    let version = u32_le(out, 0) as usize;
    let size = u32_le(out, 4) as usize;
    if version != DESCRIPTOR_LEN || size != DESCRIPTOR_LEN {
        return Err(ProbeError::BadResponse(format!(
            "unexpected descriptor version/size {version}/{size}"
        )));
    }
    let offset = u32_le(out, 8 + 16) as usize;
    let length = u32_le(out, 8 + 20) as usize;
    if offset < 40 || length == 0 {
        return Err(ProbeError::BadResponse(format!(
            "invalid data offset/length {offset}/{length}"
        )));
    }
    let start = 8 + offset;
    let take = length.min(expected);
    if start.checked_add(take).is_none_or(|end| end > out.len()) {
        return Err(ProbeError::BadResponse(format!(
            "payload outside buffer (offset {offset}, length {length}, buffer {})",
            out.len()
        )));
    }
    Ok(out[start..start + take].to_vec())
}

#[cfg(test)]
pub(crate) mod tests {
    #[test]
    fn identify_controller_thresholds_are_read_or_left_unknown() {
        let mut id = vec![0u8; IDENTIFY_LEN];
        id[266..268].copy_from_slice(&356u16.to_le_bytes()); // 83 °C
        id[268..270].copy_from_slice(&358u16.to_le_bytes()); // 85 °C
        assert_eq!(parse_temp_thresholds(&id), (Some(83.0), Some(85.0)));
        let zero = vec![0u8; IDENTIFY_LEN];
        assert_eq!(
            parse_temp_thresholds(&zero),
            (None, None),
            "0 = not reported"
        );
        let mut bad = vec![0u8; IDENTIFY_LEN];
        bad[266..268].copy_from_slice(&5000u16.to_le_bytes());
        assert_eq!(
            parse_temp_thresholds(&bad).0,
            None,
            "implausible is never used"
        );
        assert_eq!(parse_temp_thresholds(&[0u8; 10]), (None, None));
    }

    use super::*;
    use std::cell::RefCell;

    pub(crate) fn disk(index: u32, model: &str, serial: &str, bus: &str) -> PhysicalDiskInfo {
        PhysicalDiskInfo {
            index,
            model: model.into(),
            serial: serial.into(),
            bus_type: bus.into(),
            size_bytes: 2_000_398_934_016,
            is_ssd_like: true,
        }
    }

    /// A realistic SMART log with distinct values in every field.
    pub(crate) fn smart_bytes() -> Vec<u8> {
        let mut b = vec![0u8; SMART_LOG_LEN];
        b[0] = 0;
        b[1..3].copy_from_slice(&315u16.to_le_bytes()); // 42 °C
        b[3] = 100;
        b[4] = 10;
        b[5] = 3;
        let put =
            |b: &mut Vec<u8>, at: usize, v: u128| b[at..at + 16].copy_from_slice(&v.to_le_bytes());
        put(&mut b, 32, 61_234_567);
        put(&mut b, 48, 52_345_678);
        put(&mut b, 64, 900_000_001);
        put(&mut b, 80, 800_000_002);
        put(&mut b, 96, 1_234);
        put(&mut b, 112, 517);
        put(&mut b, 128, 4_321);
        put(&mut b, 144, 37);
        put(&mut b, 160, 0);
        put(&mut b, 176, 12);
        b[192..196].copy_from_slice(&5u32.to_le_bytes());
        b[196..200].copy_from_slice(&1u32.to_le_bytes());
        b[200..202].copy_from_slice(&318u16.to_le_bytes()); // sensor 1: 45 °C
        b[202..204].copy_from_slice(&325u16.to_le_bytes()); // sensor 2: 52 °C
        b
    }

    fn error_entry(count: u64, sqid: u16, cid: u16, status: u16, lba: u64, ns: u32) -> Vec<u8> {
        let mut e = vec![0u8; ERROR_ENTRY_LEN];
        e[0..8].copy_from_slice(&count.to_le_bytes());
        e[8..10].copy_from_slice(&sqid.to_le_bytes());
        e[10..12].copy_from_slice(&cid.to_le_bytes());
        e[12..14].copy_from_slice(&status.to_le_bytes());
        e[14..16].copy_from_slice(&0x0028u16.to_le_bytes());
        e[16..24].copy_from_slice(&lba.to_le_bytes());
        e[24..28].copy_from_slice(&ns.to_le_bytes());
        e[28] = 0;
        e
    }

    /// Reader returning canned pages / errors and recording every call.
    struct Fake {
        smart: Result<Vec<u8>, ProbeError>,
        errors: Result<Vec<u8>, ProbeError>,
        calls: RefCell<Vec<(u32, u8, usize)>>,
    }

    impl NvmeLogSource for Fake {
        fn read_log_page(&self, idx: u32, lid: u8, len: usize) -> Result<LogRead, ProbeError> {
            self.calls.borrow_mut().push((idx, lid, len));
            let r = if lid == LID_SMART_HEALTH {
                &self.smart
            } else {
                &self.errors
            };
            r.clone().map(|data| LogRead {
                data,
                via: "StorageDeviceProtocolSpecificProperty",
            })
        }
    }

    fn fake(smart: Result<Vec<u8>, ProbeError>, errors: Result<Vec<u8>, ProbeError>) -> Fake {
        Fake {
            smart,
            errors,
            calls: RefCell::new(Vec::new()),
        }
    }

    #[test]
    fn valid_smart_log_parses_every_field() {
        let l = parse_smart_log(&smart_bytes()).unwrap();
        assert_eq!(l.critical_warning, 0);
        assert_eq!(l.composite_temperature_k, 315);
        assert_eq!(l.composite_temperature_c(), Some(42));
        assert_eq!(l.available_spare_percent, 100);
        assert_eq!(l.available_spare_threshold_percent, 10);
        assert_eq!(l.percentage_used, 3);
        assert_eq!(l.data_units_read, 61_234_567);
        assert_eq!(l.data_units_written, 52_345_678);
        assert_eq!(l.host_read_commands, 900_000_001);
        assert_eq!(l.host_write_commands, 800_000_002);
        assert_eq!(l.controller_busy_time_minutes, 1_234);
        assert_eq!(l.power_cycles, 517);
        assert_eq!(l.power_on_hours, 4_321);
        assert_eq!(l.unsafe_shutdowns, 37);
        assert_eq!(l.media_and_data_integrity_errors, 0);
        assert_eq!(l.error_information_log_entries, 12);
        assert_eq!(l.warning_temperature_time_minutes, 5);
        assert_eq!(l.critical_temperature_time_minutes, 1);
    }

    #[test]
    fn critical_warning_bits_are_decoded_individually() {
        assert!(critical_warning_flags(0).is_empty());
        assert_eq!(
            critical_warning_flags(0b0000_0001),
            ["available_spare_below_threshold"]
        );
        assert_eq!(
            critical_warning_flags(0b0000_1010),
            ["temperature_threshold_exceeded", "media_read_only"]
        );
        assert_eq!(critical_warning_flags(0x3F).len(), 6);
        assert_eq!(
            critical_warning_flags(0x80),
            ["reserved_bits_set"],
            "reserved bits are reported, never silently dropped"
        );
        let mut b = smart_bytes();
        b[0] = 0x04;
        let l = parse_smart_log(&b).unwrap();
        assert_eq!(l.critical_warning, 4, "raw value kept");
        assert_eq!(
            critical_warning_flags(l.critical_warning),
            ["nvm_subsystem_reliability_degraded"]
        );
    }

    #[test]
    fn temperature_conversion_from_kelvin() {
        assert_eq!(kelvin_to_celsius(273), Some(0));
        assert_eq!(kelvin_to_celsius(315), Some(42));
        assert_eq!(kelvin_to_celsius(250), Some(-23));
        assert_eq!(kelvin_to_celsius(0), None, "0 K = not reported, not -273");
        let mut b = smart_bytes();
        b[1] = 0;
        b[2] = 0;
        assert_eq!(parse_smart_log(&b).unwrap().composite_temperature_c(), None);
    }

    #[test]
    fn percentage_used_and_spare_are_raw_values() {
        let mut b = smart_bytes();
        b[3] = 7;
        b[4] = 10;
        b[5] = 255; // allowed by the spec beyond 100
        let l = parse_smart_log(&b).unwrap();
        assert_eq!(l.available_spare_percent, 7);
        assert_eq!(l.available_spare_threshold_percent, 10);
        assert_eq!(l.percentage_used, 255, "never clamped to 100");
    }

    #[test]
    fn counters_keep_all_128_bits() {
        let mut b = smart_bytes();
        let big = u128::MAX - 12345;
        b[32..48].copy_from_slice(&big.to_le_bytes());
        let above_u64 = (1u128 << 64) + 7;
        b[128..144].copy_from_slice(&above_u64.to_le_bytes());
        let l = parse_smart_log(&b).unwrap();
        assert_eq!(l.data_units_read, big);
        assert_eq!(l.power_on_hours, above_u64);
        let json = to_json(&ok_health(l));
        assert!(json.contains(&format!("\"data_units_read\": \"{big}\"")));
        assert!(json.contains(&format!("\"power_on_hours\": \"{above_u64}\"")));
        assert_eq!(data_units_to_bytes(1), Some(512_000));
        assert_eq!(
            data_units_to_bytes(u128::MAX),
            None,
            "overflow is not faked"
        );
    }

    #[test]
    fn media_errors_are_read_from_their_own_offset() {
        let mut b = smart_bytes();
        b[160..176].copy_from_slice(&3u128.to_le_bytes());
        let l = parse_smart_log(&b).unwrap();
        assert_eq!(l.media_and_data_integrity_errors, 3);
        assert_eq!(l.error_information_log_entries, 12);
        assert_eq!(l.unsafe_shutdowns, 37);
    }

    #[test]
    fn temperature_sensors_only_when_implemented() {
        let l = parse_smart_log(&smart_bytes()).unwrap();
        assert_eq!(l.temperature_sensors_k[0], Some(318));
        assert_eq!(l.temperature_sensors_k[1], Some(325));
        assert!(l.temperature_sensors_k[2..].iter().all(Option::is_none));
        assert_eq!(l.temperature_sensors_c(), vec![(1, 45), (2, 52)]);
        let mut b = smart_bytes();
        b[214..216].copy_from_slice(&300u16.to_le_bytes());
        let l = parse_smart_log(&b).unwrap();
        assert_eq!(l.temperature_sensors_c().last(), Some(&(8, 27)));
    }

    #[test]
    fn error_log_entries_parse_and_empty_slots_are_skipped() {
        let mut b = error_entry(12, 3, 0x0041, 0x4005, 0x1_0000_0001, 1);
        b.extend(error_entry(11, 0, 7, 0x0281 << 1, 0, 0xFFFF_FFFF));
        b.extend(vec![0u8; ERROR_ENTRY_LEN]); // empty slot
        let list = parse_error_log(&b).unwrap();
        assert_eq!(list.len(), 2);
        let e = &list[0];
        assert_eq!(e.error_count, 12);
        assert_eq!(e.submission_queue_id, 3);
        assert_eq!(e.command_id, 0x41);
        assert_eq!(e.status_field, 0x4005);
        assert_eq!(e.status_code(), 0x02);
        assert_eq!(e.status_code_type(), 0);
        assert_eq!(e.parameter_error_location, 0x28);
        assert_eq!(e.lba, 0x1_0000_0001);
        assert_eq!(e.namespace, 1);
        assert_eq!(e.vendor_specific, 0);
        assert_eq!(list[1].status_code_type(), 2);
        assert_eq!(list[1].status_code(), 0x81);
    }

    #[test]
    fn truncated_and_malformed_buffers_are_rejected_without_zero_fill() {
        assert_eq!(
            parse_smart_log(&[0u8; 511]),
            Err(ParseError::Truncated {
                got: 511,
                needed: 512
            })
        );
        assert!(parse_smart_log(&[]).is_err());
        assert!(parse_error_log(&[1u8; 63]).is_err());
        // A trailing partial entry is ignored, not zero-padded into a record.
        let mut b = error_entry(1, 0, 1, 0, 5, 1);
        b.extend([0xAAu8; 10]);
        assert_eq!(parse_error_log(&b).unwrap().len(), 1);
        // Oversized buffers: only the defined layout is read.
        let mut big = smart_bytes();
        big.extend([0xFFu8; 100]);
        assert_eq!(parse_smart_log(&big).unwrap().power_cycles, 517);
    }

    #[test]
    fn protocol_descriptor_is_validated() {
        let mut out = vec![0u8; 48 + 512];
        out[0..4].copy_from_slice(&48u32.to_le_bytes());
        out[4..8].copy_from_slice(&48u32.to_le_bytes());
        out[24..28].copy_from_slice(&40u32.to_le_bytes());
        out[28..32].copy_from_slice(&512u32.to_le_bytes());
        out[48] = 0x5A;
        let data = extract_protocol_data(&out, 512).unwrap();
        assert_eq!(data.len(), 512);
        assert_eq!(data[0], 0x5A);
        // Truncated output, bad version, offset outside the buffer.
        assert!(extract_protocol_data(&out[..40], 512).is_err());
        let mut bad = out.clone();
        bad[0] = 1;
        assert!(extract_protocol_data(&bad, 512).is_err());
        let mut far = out.clone();
        far[24..28].copy_from_slice(&4000u32.to_le_bytes());
        assert!(matches!(
            extract_protocol_data(&far, 512),
            Err(ProbeError::BadResponse(_))
        ));
        let mut short = out.clone();
        short.truncate(48 + 100);
        assert!(extract_protocol_data(&short, 512).is_err());
    }

    fn ok_health(l: SmartHealthLog) -> NvmeHealth {
        let mut h = collect(
            &fake(Ok(smart_bytes()), Ok(vec![0u8; 1024])),
            &disk(1, "Samsung SSD 9100 PRO 2TB", "S7XXNOTREAL", "NVMe"),
            "2026-10-03T12:00:00",
        );
        h.smart = Some(l);
        h
    }

    #[test]
    fn collect_reads_smart_then_error_log_with_same_identity() {
        let d = disk(1, "Samsung SSD 9100 PRO 2TB", "S7XXNOTREAL", "NVMe");
        let mut errors = error_entry(12, 1, 2, 0, 9, 1);
        errors.extend(vec![0u8; 15 * ERROR_ENTRY_LEN]);
        let src = fake(Ok(smart_bytes()), Ok(errors));
        let h = collect(&src, &d, "2026-10-03T12:00:00");
        assert_eq!(h.status, ProbeStatus::Ok);
        assert_eq!(h.physical_identity, physical_disk_identity(&d));
        assert_eq!(h.disk_index, 1);
        assert!(h.source.contains("IOCTL_STORAGE_QUERY_PROPERTY"));
        assert!(h.source.contains("StorageDeviceProtocolSpecificProperty"));
        assert_eq!(h.error_log_status, ProbeStatus::Ok);
        assert_eq!(h.error_log.as_ref().unwrap().len(), 1);
        let calls = src.calls.borrow();
        assert_eq!(calls[0], (1, LID_SMART_HEALTH, 512));
        assert_eq!(calls[1], (1, LID_ERROR_INFO, 16 * 64));
        assert!(
            calls.iter().all(|(_, lid, _)| *lid == 1 || *lid == 2),
            "only the two read-only log pages are ever requested"
        );
    }

    #[test]
    fn error_log_falls_back_to_one_entry_then_reports_unsupported() {
        let d = disk(0, "Netac NVMe SSD 1TB", "", "NVMe");
        // Large request refused, single entry accepted.
        struct OneEntry;
        impl NvmeLogSource for OneEntry {
            fn read_log_page(&self, _: u32, lid: u8, len: usize) -> Result<LogRead, ProbeError> {
                match (lid, len) {
                    (LID_SMART_HEALTH, _) => Ok(LogRead {
                        data: smart_bytes(),
                        via: "StorageAdapterProtocolSpecificProperty",
                    }),
                    (_, 64) => Ok(LogRead {
                        data: vec![0u8; 64],
                        via: "StorageAdapterProtocolSpecificProperty",
                    }),
                    _ => Err(ProbeError::NotSupported(87)),
                }
            }
        }
        let h = collect(&OneEntry, &d, "t");
        assert_eq!(h.error_log_status, ProbeStatus::Ok);
        assert_eq!(h.error_log, Some(vec![]), "no errors logged ≠ unknown");
        assert_eq!(h.physical_identity, "PHYS#Netac NVMe SSD 1TB#IDX0");

        let h = collect(
            &fake(Ok(smart_bytes()), Err(ProbeError::InvalidFunction)),
            &d,
            "t",
        );
        assert_eq!(h.status, ProbeStatus::Ok);
        assert_eq!(h.error_log_status, ProbeStatus::Unsupported);
        assert_eq!(h.error_log, None, "unread log is unknown, not empty");
    }

    #[test]
    fn unsupported_and_access_denied_never_fabricate_values() {
        let d = disk(2, "USB NVMe bridge", "", "USB");
        for (err, status) in [
            (ProbeError::InvalidFunction, ProbeStatus::Unsupported),
            (ProbeError::NotSupported(50), ProbeStatus::Unsupported),
            (ProbeError::AccessDenied, ProbeStatus::AccessDenied),
            (ProbeError::OpenFailed(2), ProbeStatus::Error),
            (ProbeError::IoctlFailed(1117), ProbeStatus::Error),
            (ProbeError::BadResponse("x".into()), ProbeStatus::Error),
        ] {
            let h = collect(&fake(Err(err), Err(ProbeError::InvalidFunction)), &d, "t");
            assert_eq!(h.status, status);
            assert!(h.smart.is_none());
            assert!(h.error_log.is_none());
            assert!(h.status_detail.is_some());
            let json = to_json(&h);
            assert!(json.contains("\"critical_warning\": null"));
            assert!(json.contains("\"power_on_hours\": null"));
            assert!(json.contains("\"media_and_data_integrity_errors\": null"));
            assert!(json.contains("\"entries\": null"));
            assert!(!json.contains("\"power_on_hours\": \"0\""));
        }
        // A truncated reply is an ERROR, not a zero-filled record.
        let h = collect(&fake(Ok(vec![0u8; 100]), Ok(vec![])), &d, "t");
        assert_eq!(h.status, ProbeStatus::Error);
        assert!(h.smart.is_none());
    }

    #[test]
    fn sata_devices_are_not_touched() {
        let src = fake(Ok(smart_bytes()), Ok(vec![]));
        let h = collect(&src, &disk(3, "SATA SSD", "X", "SATA"), "t");
        assert!(src.calls.borrow().is_empty(), "no IOCTL for ATA devices");
        assert_eq!(h.status, ProbeStatus::Unsupported);
        assert!(h.status_detail.unwrap().contains("ATA SMART"));
    }

    #[test]
    fn evidence_json_is_valid_and_carries_identity_without_extra_pii() {
        let d = disk(1, "Samsung SSD 9100 PRO 2TB", "S7XXNOTREAL", "NVMe");
        let mut errors = error_entry(12, 1, 2, 0x4005, 9, 1);
        errors.extend(vec![0u8; 64]);
        let h = collect(
            &fake(Ok(smart_bytes()), Ok(errors)),
            &d,
            "2026-10-03T12:00:00",
        );
        let text = to_json(&h);
        let v = json::parse(&text).expect("valid JSON");
        assert_eq!(
            v.get("physical_identity").and_then(|x| x.as_str()),
            Some(physical_disk_identity(&d).as_str())
        );
        assert_eq!(v.get("status").and_then(|x| x.as_str()), Some("OK"));
        let smart = v.get("smart_health_log").unwrap();
        assert_eq!(
            smart.get("composite_temperature_celsius"),
            Some(&json::Value::Num(42.0))
        );
        assert_eq!(
            smart.get("data_units_written").and_then(|x| x.as_str()),
            Some("52345678")
        );
        assert_eq!(
            smart.get("unsafe_shutdowns").and_then(|x| x.as_str()),
            Some("37")
        );
        assert!(!text.contains("\"serial\""), "no separate serial field");
        assert_eq!(
            text.matches("S7XXNOTREAL").count(),
            1,
            "serial appears only inside the shared physical identity"
        );
        for verdict in ["HEALTHY", "FAILURE", "BAD", "FAILING\""] {
            assert!(!text.contains(verdict), "no verdict word {verdict}");
        }
        assert_eq!(
            evidence_file_name("03.10.26_12-00", 1),
            "NVMe_Health_03.10.26_12-00_PD1.json"
        );
    }

    /// Read-only contract: the reader can only open the disk without write
    /// access and only issue the property query; no admin command, write
    /// IOCTL or pass-through path exists in this module.
    #[test]
    fn source_is_strictly_read_only() {
        let src = include_str!("nvme_health.rs");
        let code = &src[..src.find("#[cfg(test)]\npub(crate) mod tests").unwrap()];
        for forbidden in [
            "GENERIC_WRITE",
            "GENERIC_ALL",
            "IOCTL_STORAGE_PROTOCOL_COMMAND",
            "IOCTL_SCSI_PASS_THROUGH",
            "IOCTL_ATA_PASS_THROUGH",
            "IOCTL_STORAGE_SET_PROPERTY",
            "IOCTL_STORAGE_FIRMWARE",
            "IOCTL_STORAGE_REINITIALIZE_MEDIA",
            "WriteFile",
        ] {
            assert!(!code.contains(forbidden), "{forbidden} in nvme_health.rs");
        }
        let ioctls: Vec<&str> = code
            .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .filter(|w| w.starts_with("IOCTL_"))
            .collect();
        assert!(ioctls.iter().all(|w| *w == "IOCTL_STORAGE_QUERY_PROPERTY"));
        assert!(code.contains("NVME_DATA_TYPE_LOG_PAGE: Dword = 2"));
    }

    /// The SATA fallback reader runs read-only and always yields a record
    /// (empty when the host has no Storage cmdlets / no such disk).
    #[test]
    fn reliability_reader_runs_and_never_invents_values() {
        let script = reliability_ps1(0);
        for verb in [
            "Set-",
            "Remove-",
            "Reset-",
            "Initialize-",
            "Format-",
            "Repair-",
        ] {
            assert!(!script.contains(verb), "{verb}");
        }
        assert!(is_ata_bus("SATA") && !is_ata_bus("NVMe"));
        let Some(host) = crate::ps_exec::test_host() else {
            return;
        };
        let rel = read_reliability(&host, 9999).expect("marker line");
        assert!(rel.is_empty(), "no disk 9999 → no values: {rel:?}");
    }

    /// v0.4.4 confirmed bug: a SATA disk must never get the NVMe protocol.
    #[test]
    fn routing_never_sends_nvme_protocol_to_sata() {
        assert_eq!(route("NVMe"), HealthRoute::Nvme);
        for bus in ["SATA", "ATA", "ATAPI"] {
            assert_eq!(route(bus), HealthRoute::AtaSata);
            let src = fake(Ok(smart_bytes()), Ok(vec![]));
            let h = collect(&src, &disk(2, "XrayDisk 512GB", "", bus), "t");
            assert!(src.calls.borrow().is_empty(), "{bus}: no NVMe IOCTL");
            assert_eq!(h.status, ProbeStatus::Unsupported);
            assert!(h.smart.is_none(), "no fabricated SMART");
            assert!(h.status_detail.unwrap().contains("SMART NOT AVAILABLE"));
        }
        for bus in ["SAS", "SD", "Spaces", "Virtual"] {
            assert_eq!(route(bus), HealthRoute::NotApplicable);
            let src = fake(Ok(smart_bytes()), Ok(vec![]));
            collect(&src, &disk(2, "x", "", bus), "t");
            assert!(src.calls.borrow().is_empty());
        }
        for bus in ["RAID", "USB", "SCSI", "Unknown"] {
            assert_eq!(route(bus), HealthRoute::Probe);
        }
        let rel = parse_reliability(
            "WSD_REL {\"Temperature\":38,\"Wear\":2,\"PowerOnHours\":0,\"ReadErrorsTotal\":0}",
        )
        .unwrap();
        assert_eq!(rel.temperature_c, Some(38.0));
        assert_eq!(rel.power_on_hours, None, "0 h is an empty counter");
        assert_eq!(rel.read_errors_total, Some(0.0));
        assert!(parse_reliability("WSD_REL {}").unwrap().is_empty());
        let mut h = collect(
            &fake(Ok(smart_bytes()), Ok(vec![])),
            &disk(2, "XrayDisk", "", "SATA"),
            "t",
        );
        h.reliability = Some(rel);
        let js = to_json(&h);
        assert!(json::parse(&js).is_some(), "{js}");
        assert!(js.contains("MSFT_StorageReliabilityCounter"));
    }
}
