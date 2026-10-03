//! Storage Health correlation (v0.4.2 source candidate).
//!
//! One conservative classification per PHYSICAL DISK IDENTITY
//! (`storage_topology::physical_disk_identity`, never a drive letter):
//!
//! ```text
//! physical disk identity
//!   ├─ SSD benchmark (first run + automatic retest, every pass kept)
//!   ├─ NVMe SMART / Health log            (nvme_health)
//!   ├─ NVMe Error Information log         (nvme_health)
//!   ├─ temperature (drive-reported)       (nvme_health)
//!   ├─ Windows storage events             (this module)
//!   └─ persistent benchmark history       (ssd_history)
//! ```
//!
//! Permanent rules:
//! - **UNSTABLE BENCHMARK != SSD FAILURE.** Performance variance alone is
//!   at most BENCHMARK ANOMALY (retest required / check), never a storage
//!   problem — even when the automatic retest is unstable too.
//! - Raw counters are facts, not verdicts: Unsafe Shutdowns, Error
//!   Information Log Entries and Percentage Used below 100 never raise
//!   severity by themselves.
//! - Critical Warning bits are interpreted individually.
//! - Temperature only raises severity through the drive's own threshold
//!   (Critical Warning bit 1); no invented temperature limits.
//! - Event count alone never determines severity: an event counts only by
//!   its type, recency and binding to the same physical disk.

// Event collection runs on Windows only; elsewhere it is exercised by tests.
#![cfg_attr(not(windows), allow(dead_code))]

use crate::deep_checks::json;
use crate::nvme_health::{NvmeHealth, ProbeStatus};

// ---------------------------------------------------------------------
// Inputs
// ---------------------------------------------------------------------

/// Benchmark stability, as the shared STABLE/ACCEPT/UNSTABLE thresholds
/// (app `stability_level`) classify one run. Thresholds are not changed
/// or duplicated here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BenchStability {
    Stable,
    Accept,
    Unstable,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BenchmarkFacts {
    pub stability: BenchStability,
    pub read_variation_percent: f64,
    pub write_variation_percent: f64,
}

/// Why the automatic retest did not run (fail closed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetestSkip {
    /// The selected disk/volume is no longer resolvable or writable.
    TargetUnavailable,
    /// The controller reports a condition where more write testing is
    /// inappropriate (Critical Warning bits 0–3, media errors).
    HealthForbidsWrites,
    /// The health read did not finish in time — not retested blind.
    HealthPending,
}

/// The automatic retest of an UNSTABLE first run.
#[derive(Debug, Clone, PartialEq)]
pub enum RetestOutcome {
    /// The first run was not unstable (or there is no benchmark).
    NotNeeded,
    /// Idle / second run in progress.
    Pending,
    Completed(BenchmarkFacts),
    Skipped(RetestSkip),
    Cancelled,
    /// The second run failed technically (not a disk verdict).
    Failed,
}

/// Windows event providers relevant to storage (System log).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageEventSource {
    /// `disk` (7 bad block, 11 controller error, 51 paging error,
    /// 153 IO retried, 154 IO failed / hardware error).
    Disk,
    /// `stornvme` (NVMe miniport: resets, timeouts).
    StorNvme,
    /// `storport` / `Microsoft-Windows-StorPort` (129 reset to device).
    StorPort,
    /// `Ntfs` / `Microsoft-Windows-Ntfs` (file-system consistency — may be
    /// caused by storage, power loss or software).
    Ntfs,
    /// `volmgr` (crash-dump configuration).
    VolMgr,
}

impl StorageEventSource {
    #[cfg(test)]
    pub const ALL: [StorageEventSource; 5] = [
        StorageEventSource::Disk,
        StorageEventSource::StorNvme,
        StorageEventSource::StorPort,
        StorageEventSource::Ntfs,
        StorageEventSource::VolMgr,
    ];

    /// Maps an event's ProviderName (case-insensitive) to a source.
    pub fn of_provider(provider: &str) -> Option<Self> {
        match provider.trim().to_ascii_lowercase().as_str() {
            "disk" => Some(Self::Disk),
            "stornvme" => Some(Self::StorNvme),
            "storport" | "microsoft-windows-storport" => Some(Self::StorPort),
            "ntfs" | "microsoft-windows-ntfs" => Some(Self::Ntfs),
            "volmgr" => Some(Self::VolMgr),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Disk => "Disk",
            Self::StorNvme => "StorNVMe",
            Self::StorPort => "StorPort",
            Self::Ntfs => "Ntfs",
            Self::VolMgr => "volmgr",
        }
    }
}

/// One grouped storage event (provider + id + disk), structured — not a
/// bare counter. `physical_disk_index` is set only when the event names
/// `\Device\HarddiskN` (never derived from a drive letter).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageEventRef {
    pub source: StorageEventSource,
    pub event_id: u32,
    pub first_seen: String,
    pub last_seen: String,
    pub physical_disk_index: Option<u32>,
    pub count: u32,
}

/// Disk events that indicate a device-level fault on the named disk.
const STRONG_DISK_EVENTS: [u32; 2] = [7, 154];
/// Disk events that only corroborate other evidence.
const WEAK_DISK_EVENTS: [u32; 3] = [11, 51, 153];
/// "Current" = last occurrence within this many days of the assessment.
pub const RECENT_DAYS: i64 = 7;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventsInput {
    NotCollected,
    Collected(Vec<StorageEventRef>),
}

/// Everything known about one physical disk.
#[derive(Debug, Clone)]
pub struct StorageHealthInputs {
    pub physical_identity: String,
    pub disk_index: Option<u32>,
    /// The first (user-started) benchmark run.
    pub benchmark: Option<BenchmarkFacts>,
    pub retest: RetestOutcome,
    pub nvme: Option<NvmeHealth>,
    pub events: EventsInput,
    /// Assessment time `YYYY-MM-DDTHH:MM:SS` (recency of events).
    pub assessed_at: String,
}

// ---------------------------------------------------------------------
// Result
// ---------------------------------------------------------------------

/// Conservative semantic storage states (lowest to highest concern).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum StorageState {
    Ok,
    /// Benchmark fine, but controller health could not be read.
    InsufficientData,
    /// First run UNSTABLE, automatic retest STABLE/ACCEPT, health clean.
    AnomalyNotConfirmed,
    /// First run UNSTABLE, retest not (yet) done.
    BenchmarkAnomalyRetest,
    /// Both runs UNSTABLE, health/events clean: CHECK, not a failure.
    BenchmarkAnomalyCheck,
    StorageAttention,
    StorageProblem,
}

impl StorageState {
    pub fn code(self) -> &'static str {
        match self {
            Self::Ok => "OK",
            Self::InsufficientData => "INSUFFICIENT_DATA",
            Self::AnomalyNotConfirmed => "BENCHMARK_ANOMALY_NOT_CONFIRMED",
            Self::BenchmarkAnomalyRetest => "BENCHMARK_ANOMALY_RETEST_REQUIRED",
            Self::BenchmarkAnomalyCheck => "BENCHMARK_ANOMALY_CHECK",
            Self::StorageAttention => "STORAGE_ATTENTION",
            Self::StorageProblem => "STORAGE_PROBLEM",
        }
    }

    /// Compact label for the dashboard status line (fixed width).
    pub fn short(self, ru: bool) -> &'static str {
        match (self, ru) {
            (Self::Ok, true) => "Норма",
            (Self::Ok, false) => "OK",
            (Self::InsufficientData, true) => "Нет данных NVMe",
            (Self::InsufficientData, false) => "No NVMe data",
            (Self::AnomalyNotConfirmed, true) => "Повтор в норме",
            (Self::AnomalyNotConfirmed, false) => "Retest normal",
            (Self::BenchmarkAnomalyRetest, true) => "Нужен повтор",
            (Self::BenchmarkAnomalyRetest, false) => "Retest required",
            (Self::BenchmarkAnomalyCheck, true) => "Аномалия замера",
            (Self::BenchmarkAnomalyCheck, false) => "Benchmark anomaly",
            (Self::StorageAttention, true) => "Внимание",
            (Self::StorageAttention, false) => "Attention",
            (Self::StorageProblem, true) => "Проблема",
            (Self::StorageProblem, false) => "Problem",
        }
    }

    pub fn text(self, ru: bool) -> &'static str {
        match (self, ru) {
            (Self::Ok, true) => "Норма",
            (Self::Ok, false) => "OK",
            (Self::InsufficientData, true) => "Замер в норме, нет данных здоровья",
            (Self::InsufficientData, false) => "Benchmark OK, no health data",
            (Self::AnomalyNotConfirmed, true) => "Аномалия не подтвердилась при повторе",
            (Self::AnomalyNotConfirmed, false) => "Anomaly not confirmed on retest",
            (Self::BenchmarkAnomalyRetest, true) => "Аномалия замера, нужен повтор",
            (Self::BenchmarkAnomalyRetest, false) => "Benchmark anomaly, retest required",
            (Self::BenchmarkAnomalyCheck, true) => "Аномалия замера, проверить (не отказ)",
            (Self::BenchmarkAnomalyCheck, false) => "Benchmark anomaly, check (not a failure)",
            (Self::StorageAttention, true) => "Накопитель: требует внимания",
            (Self::StorageAttention, false) => "Storage attention",
            (Self::StorageProblem, true) => "Накопитель: проблема",
            (Self::StorageProblem, false) => "Storage problem",
        }
    }
}

/// Weight of one finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Weight {
    /// Context only, never changes the state.
    Fact,
    Attention,
    Problem,
}

/// One explained reason behind the classification.
#[derive(Debug, Clone, PartialEq)]
pub enum Finding {
    CriticalWarningBit { bit: u8, name: &'static str },
    MediaErrors { count: u128, corroborated: bool },
    PercentageUsedAtLimit(u8),
    ErrorLogEntries(u128),
    UnsafeShutdowns(u128),
    HealthUnavailable(ProbeStatus),
    BenchmarkUnstable,
    RetestNormalized,
    RetestUnstable,
    RetestNotRun(RetestOutcome),
    DiskEvent(StorageEventRef, Weight),
    EventContext { groups: usize },
    EventsNotCollected,
}

impl Finding {
    pub fn weight(&self) -> Weight {
        match self {
            Finding::CriticalWarningBit { bit, .. } => {
                if matches!(bit, 0 | 2 | 3) {
                    Weight::Problem
                } else {
                    Weight::Attention
                }
            }
            Finding::MediaErrors { corroborated, .. } => {
                if *corroborated {
                    Weight::Problem
                } else {
                    Weight::Attention
                }
            }
            Finding::PercentageUsedAtLimit(_) => Weight::Attention,
            Finding::DiskEvent(_, w) => *w,
            _ => Weight::Fact,
        }
    }

    pub fn code(&self) -> String {
        match self {
            Finding::CriticalWarningBit { name, .. } => format!("critical_warning.{name}"),
            Finding::MediaErrors { .. } => "media_and_data_integrity_errors".into(),
            Finding::PercentageUsedAtLimit(_) => "percentage_used_at_or_above_100".into(),
            Finding::ErrorLogEntries(_) => "error_information_log_entries".into(),
            Finding::UnsafeShutdowns(_) => "unsafe_shutdowns".into(),
            Finding::HealthUnavailable(_) => "health_unavailable".into(),
            Finding::BenchmarkUnstable => "benchmark_unstable".into(),
            Finding::RetestNormalized => "retest_normalized".into(),
            Finding::RetestUnstable => "retest_unstable".into(),
            Finding::RetestNotRun(_) => "retest_not_run".into(),
            Finding::DiskEvent(e, _) => format!("event.{}.{}", e.source.name(), e.event_id),
            Finding::EventContext { .. } => "storage_events_context".into(),
            Finding::EventsNotCollected => "storage_events_not_collected".into(),
        }
    }

    /// Short explanation in the UI language.
    pub fn text(&self, ru: bool) -> String {
        let t = |a: &str, b: &str| if ru { a.to_string() } else { b.to_string() };
        match self {
            Finding::CriticalWarningBit { bit, name } => {
                let what = match (bit, ru) {
                    (0, true) => "резерв ниже порога",
                    (0, false) => "available spare below threshold",
                    (1, true) => "температура выше порога накопителя",
                    (1, false) => "temperature above the drive's threshold",
                    (2, true) => "надёжность накопителя снижена",
                    (2, false) => "NVM subsystem reliability degraded",
                    (3, true) => "носитель переведён в режим только чтения",
                    (3, false) => "media placed in read-only mode",
                    (4, true) => "сбой резервирования энергозависимой памяти",
                    (4, false) => "volatile memory backup failed",
                    (5, true) => "область постоянной памяти только для чтения",
                    (5, false) => "persistent memory region read-only",
                    (_, true) => "установлены зарезервированные биты",
                    (_, false) => "reserved bits set",
                };
                if ru {
                    format!("Критическое предупреждение, бит {bit}: {what} ({name})")
                } else {
                    format!("Critical Warning bit {bit}: {what}")
                }
            }
            Finding::MediaErrors {
                count,
                corroborated,
            } => match (ru, corroborated) {
                (true, false) => format!("Ошибки носителя и целостности: {count}"),
                (true, true) => format!(
                    "Ошибки носителя и целостности: {count}, подтверждены событиями этого диска"
                ),
                (false, false) => format!("Media and data integrity errors: {count}"),
                (false, true) => format!(
                    "Media and data integrity errors: {count}, corroborated by this disk's events"
                ),
            },
            Finding::PercentageUsedAtLimit(p) => {
                if ru {
                    format!(
                        "Израсходованный ресурс {p} % (оценка ресурса производителя достигнута)"
                    )
                } else {
                    format!("Percentage Used {p} % (vendor endurance estimate reached)")
                }
            }
            Finding::ErrorLogEntries(n) => {
                if ru {
                    format!("Записей журнала ошибок контроллера: {n} — факт, само по себе не отказ")
                } else {
                    format!("Error log entries: {n} — a fact, not a failure by itself")
                }
            }
            Finding::UnsafeShutdowns(n) => {
                if ru {
                    format!("Небезопасных отключений: {n} — история питания, не отказ")
                } else {
                    format!("Unsafe shutdowns: {n} — power history, not a failure")
                }
            }
            Finding::HealthUnavailable(s) => {
                if ru {
                    format!("Данные здоровья контроллера недоступны ({})", s.as_str())
                } else {
                    format!("Controller health unavailable ({})", s.as_str())
                }
            }
            Finding::BenchmarkUnstable => {
                t("Первый замер нестабилен (UNSTABLE)", "First run UNSTABLE")
            }
            Finding::RetestNormalized => t(
                "Контрольный повтор в норме: аномалия не подтвердилась",
                "Automatic retest normal: anomaly not confirmed",
            ),
            Finding::RetestUnstable => t(
                "Контрольный повтор тоже нестабилен; здоровье и события чистые — не отказ",
                "Automatic retest also UNSTABLE; health and events clean — not a failure",
            ),
            Finding::RetestNotRun(o) => {
                let why = match (o, ru) {
                    (RetestOutcome::Pending, true) => "выполняется",
                    (RetestOutcome::Pending, false) => "in progress",
                    (RetestOutcome::Cancelled, true) => "отменён пользователем",
                    (RetestOutcome::Cancelled, false) => "cancelled by the user",
                    (RetestOutcome::Failed, true) => "не выполнен (техническая ошибка замера)",
                    (RetestOutcome::Failed, false) => "did not complete (benchmark error)",
                    (RetestOutcome::Skipped(RetestSkip::TargetUnavailable), true) => {
                        "пропущен: диск/том недоступен"
                    }
                    (RetestOutcome::Skipped(RetestSkip::TargetUnavailable), false) => {
                        "skipped: disk/volume unavailable"
                    }
                    (RetestOutcome::Skipped(RetestSkip::HealthForbidsWrites), true) => {
                        "пропущен: состояние накопителя не допускает дополнительной записи"
                    }
                    (RetestOutcome::Skipped(RetestSkip::HealthForbidsWrites), false) => {
                        "skipped: drive state does not allow more write testing"
                    }
                    (RetestOutcome::Skipped(RetestSkip::HealthPending), true) => {
                        "пропущен: данные здоровья не получены вовремя"
                    }
                    (RetestOutcome::Skipped(RetestSkip::HealthPending), false) => {
                        "skipped: health data not available in time"
                    }
                    (_, true) => "не выполнен",
                    (_, false) => "not run",
                };
                if ru {
                    format!("Контрольный повтор {why}; нужен повторный замер")
                } else {
                    format!("Automatic retest {why}; retest required")
                }
            }
            Finding::DiskEvent(e, w) => {
                let tail = match (w, ru) {
                    (Weight::Fact, true) => "контекст",
                    (Weight::Fact, false) => "context",
                    (_, true) => "актуально для этого диска",
                    (_, false) => "current, this disk",
                };
                format!(
                    "{} {} ×{} ({} … {}): {tail}",
                    e.source.name(),
                    e.event_id,
                    e.count,
                    e.first_seen,
                    e.last_seen
                )
            }
            Finding::EventContext { groups } => {
                if ru {
                    format!(
                        "Другие события хранилища ({groups} групп) не привязаны к этому диску — контекст"
                    )
                } else {
                    format!(
                        "Other storage events ({groups} groups) not bound to this disk — context"
                    )
                }
            }
            Finding::EventsNotCollected => t(
                "События хранилища Windows не собраны",
                "Windows storage events not collected",
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Classification {
    pub state: StorageState,
    pub findings: Vec<Finding>,
}

// ---------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------

/// Days since 0000-03-01 for `YYYY-MM-DD…` (proleptic Gregorian).
fn day_number(iso: &str) -> Option<i64> {
    let y: i64 = iso.get(0..4)?.parse().ok()?;
    let m: i64 = iso.get(5..7)?.parse().ok()?;
    let d: i64 = iso.get(8..10)?.parse().ok()?;
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let (y, m) = if m <= 2 { (y - 1, m + 9) } else { (y, m - 3) };
    Some(365 * y + y / 4 - y / 100 + y / 400 + (153 * m + 2) / 5 + d - 1)
}

/// True when `last_seen` is within [`RECENT_DAYS`] before `now`. An
/// unparseable date is never "recent" (it cannot raise severity).
pub fn is_recent(last_seen: &str, now: &str) -> bool {
    match (day_number(last_seen), day_number(now)) {
        (Some(e), Some(n)) => (0..=RECENT_DAYS).contains(&(n - e)),
        _ => false,
    }
}

/// Whether more write testing (the automatic retest) is appropriate for
/// this disk's reported state. Unknown health does not forbid it.
pub fn retest_allowed(nvme: Option<&NvmeHealth>) -> bool {
    match nvme.and_then(|h| h.smart.as_ref()) {
        Some(s) => s.critical_warning & 0b0000_1111 == 0 && s.media_and_data_integrity_errors == 0,
        None => true,
    }
}

/// The conservative classification. Performance variance alone never
/// reaches StorageAttention/StorageProblem.
pub fn classify(inputs: &StorageHealthInputs) -> Classification {
    let mut findings: Vec<Finding> = Vec::new();
    let mut state = StorageState::Ok;
    let raise = |state: &mut StorageState, s: StorageState| *state = (*state).max(s);

    // --- Windows storage events on this physical disk -------------------
    let mut bound_strong = false;
    let mut bound_weak = false;
    match &inputs.events {
        EventsInput::NotCollected => findings.push(Finding::EventsNotCollected),
        EventsInput::Collected(list) => {
            let mut context = 0usize;
            for e in list {
                let same_disk =
                    e.physical_disk_index.is_some() && e.physical_disk_index == inputs.disk_index;
                let recent = is_recent(&e.last_seen, &inputs.assessed_at);
                if same_disk && recent && e.source == StorageEventSource::Disk {
                    if STRONG_DISK_EVENTS.contains(&e.event_id) {
                        bound_strong = true;
                        findings.push(Finding::DiskEvent(e.clone(), Weight::Attention));
                        continue;
                    }
                    if WEAK_DISK_EVENTS.contains(&e.event_id) {
                        bound_weak = true;
                        findings.push(Finding::DiskEvent(e.clone(), Weight::Fact));
                        continue;
                    }
                }
                if same_disk {
                    findings.push(Finding::DiskEvent(e.clone(), Weight::Fact));
                } else {
                    context += 1;
                }
            }
            if context > 0 {
                findings.push(Finding::EventContext { groups: context });
            }
        }
    }
    let corroborating_events = bound_strong || bound_weak;
    if bound_strong {
        raise(&mut state, StorageState::StorageAttention);
    }

    // --- Controller health ----------------------------------------------
    let smart = inputs.nvme.as_ref().and_then(|h| h.smart.as_ref());
    match smart {
        Some(s) => {
            for (bit, name) in crate::nvme_health::CRITICAL_WARNING_BITS {
                if s.critical_warning & (1 << bit) != 0 {
                    findings.push(Finding::CriticalWarningBit { bit, name });
                }
            }
            if s.critical_warning & 0b1100_0000 != 0 {
                findings.push(Finding::CriticalWarningBit {
                    bit: 6,
                    name: "reserved_bits_set",
                });
            }
            if s.media_and_data_integrity_errors > 0 {
                findings.push(Finding::MediaErrors {
                    count: s.media_and_data_integrity_errors,
                    corroborated: corroborating_events,
                });
            }
            if s.percentage_used >= 100 {
                findings.push(Finding::PercentageUsedAtLimit(s.percentage_used));
            }
            // Facts only (never a verdict by themselves).
            if s.error_information_log_entries > 0 {
                findings.push(Finding::ErrorLogEntries(s.error_information_log_entries));
            }
            if s.unsafe_shutdowns > 0 {
                findings.push(Finding::UnsafeShutdowns(s.unsafe_shutdowns));
            }
        }
        None => findings.push(Finding::HealthUnavailable(
            inputs
                .nvme
                .as_ref()
                .map(|h| h.status)
                .unwrap_or(ProbeStatus::Unsupported),
        )),
    }
    for f in &findings {
        match f.weight() {
            Weight::Problem => raise(&mut state, StorageState::StorageProblem),
            Weight::Attention => raise(&mut state, StorageState::StorageAttention),
            Weight::Fact => {}
        }
    }

    // --- Benchmark + automatic retest ------------------------------------
    let first_unstable = inputs
        .benchmark
        .as_ref()
        .is_some_and(|b| b.stability == BenchStability::Unstable);
    if first_unstable {
        findings.push(Finding::BenchmarkUnstable);
        match &inputs.retest {
            RetestOutcome::Completed(second) if second.stability != BenchStability::Unstable => {
                findings.push(Finding::RetestNormalized);
                raise(&mut state, StorageState::AnomalyNotConfirmed);
            }
            RetestOutcome::Completed(_) => {
                findings.push(Finding::RetestUnstable);
                // Weak disk events corroborating a repeated anomaly make it
                // ATTENTION; variance alone stays a CHECK.
                raise(
                    &mut state,
                    if bound_weak {
                        StorageState::StorageAttention
                    } else {
                        StorageState::BenchmarkAnomalyCheck
                    },
                );
            }
            other => {
                findings.push(Finding::RetestNotRun(other.clone()));
                raise(&mut state, StorageState::BenchmarkAnomalyRetest);
            }
        }
    }
    if state == StorageState::Ok && smart.is_none() {
        state = StorageState::InsufficientData;
    }
    Classification { state, findings }
}

// ---------------------------------------------------------------------
// Evidence
// ---------------------------------------------------------------------

pub const EVIDENCE_PREFIX: &str = "Storage_Correlation_";

/// `Storage_Correlation_<stamp>_PD<n>.json` (disk tag after the stamp, like
/// the NVMe Health evidence).
pub fn evidence_file_name(stamp: &str, disk_index: Option<u32>) -> String {
    match disk_index {
        Some(n) => format!("{EVIDENCE_PREFIX}{stamp}_PD{n}.json"),
        None => format!("{EVIDENCE_PREFIX}{stamp}.json"),
    }
}

fn bench_json(b: Option<&BenchmarkFacts>) -> String {
    match b {
        None => "null".into(),
        Some(b) => format!(
            "{{\"stability\": {}, \"read_variation_percent\": {:.3}, \"write_variation_percent\": {:.3}}}",
            json::string(match b.stability {
                BenchStability::Stable => "STABLE",
                BenchStability::Accept => "ACCEPT",
                BenchStability::Unstable => "UNSTABLE",
            }),
            b.read_variation_percent,
            b.write_variation_percent
        ),
    }
}

/// Evidence JSON of one classification (English codes, both explanations).
pub fn to_json(
    inputs: &StorageHealthInputs,
    c: &Classification,
    model: &str,
    health_file: Option<&str>,
    benchmark_files: &[String],
) -> String {
    let retest = match &inputs.retest {
        RetestOutcome::NotNeeded => "\"not_needed\"".to_string(),
        RetestOutcome::Pending => "\"pending\"".into(),
        RetestOutcome::Completed(_) => "\"completed\"".into(),
        RetestOutcome::Skipped(RetestSkip::TargetUnavailable) => {
            "\"skipped_target_unavailable\"".into()
        }
        RetestOutcome::Skipped(RetestSkip::HealthForbidsWrites) => {
            "\"skipped_health_forbids_writes\"".into()
        }
        RetestOutcome::Skipped(RetestSkip::HealthPending) => "\"skipped_health_pending\"".into(),
        RetestOutcome::Cancelled => "\"cancelled\"".into(),
        RetestOutcome::Failed => "\"failed\"".into(),
    };
    let second = match &inputs.retest {
        RetestOutcome::Completed(b) => bench_json(Some(b)),
        _ => "null".into(),
    };
    let findings: Vec<String> = c
        .findings
        .iter()
        .map(|f| {
            format!(
                "    {{\"code\": {}, \"weight\": {}, \"en\": {}, \"ru\": {}}}",
                json::string(&f.code()),
                json::string(match f.weight() {
                    Weight::Fact => "fact",
                    Weight::Attention => "attention",
                    Weight::Problem => "problem",
                }),
                json::string(&f.text(false)),
                json::string(&f.text(true))
            )
        })
        .collect();
    let files: Vec<String> = benchmark_files.iter().map(|f| json::string(f)).collect();
    format!(
        "{{\n  \"format\": \"winstatediag.storage_correlation/1\",\n  \"physical_identity\": {},\n  \"physical_disk_index\": {},\n  \"model\": {},\n  \"assessed_at\": {},\n  \"state\": {},\n  \"first_run\": {},\n  \"retest\": {},\n  \"retest_run\": {},\n  \"health_status\": {},\n  \"health_evidence\": {},\n  \"benchmark_evidence\": [{}],\n  \"events_collected\": {},\n  \"findings\": [\n{}\n  ],\n  \"rule\": {}\n}}\n",
        json::string(&inputs.physical_identity),
        inputs
            .disk_index
            .map(|n| n.to_string())
            .unwrap_or_else(|| "null".into()),
        json::string(model),
        json::string(&inputs.assessed_at),
        json::string(c.state.code()),
        bench_json(inputs.benchmark.as_ref()),
        retest,
        second,
        inputs
            .nvme
            .as_ref()
            .map(|h| json::string(h.status.as_str()))
            .unwrap_or_else(|| "null".into()),
        health_file
            .map(json::string)
            .unwrap_or_else(|| "null".into()),
        files.join(", "),
        matches!(inputs.events, EventsInput::Collected(_)),
        findings.join(",\n"),
        json::string(
            "Unstable benchmark != SSD failure; counters are facts; severity needs correlation on the same physical disk."
        )
    )
}

// ---------------------------------------------------------------------
// Windows storage event collection (read-only Get-WinEvent)
// ---------------------------------------------------------------------

/// Read-only System-log query for the storage providers (14 days, levels
/// critical/error/warning), grouped by provider + id + `\Device\HarddiskN`.
pub const EVENT_COLLECTOR_PS1: &str = r#"$ErrorActionPreference = 'Continue'
$since = (Get-Date).AddDays(-14)
$providers = @('disk','stornvme','storport','Microsoft-Windows-StorPort','Ntfs','Microsoft-Windows-Ntfs','volmgr')
$events = @()
foreach ($p in $providers) {
    try { $events += @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = $p; StartTime = $since; Level = 1,2,3 } -ErrorAction Stop) } catch { }
}
$rows = @($events | ForEach-Object {
    $d = -1
    $text = [string]$_.Message + ' ' + ((@($_.Properties) | ForEach-Object { [string]$_.Value }) -join ' ')
    if ($text -match '(?i)\\Device\\Harddisk(\d+)\\') { $d = [int]$Matches[1] }
    [PSCustomObject]@{ P = [string]$_.ProviderName; I = [int]$_.Id; D = $d; T = $_.TimeCreated }
} | Group-Object P, I, D | ForEach-Object {
    $s = @($_.Group | Sort-Object T)
    [PSCustomObject]@{ P = $s[0].P; I = $s[0].I; D = $s[0].D; N = $_.Count; F = $s[0].T.ToString('s'); L = $s[-1].T.ToString('s') }
})
Write-Output ('WSD_STORAGE_EVENTS ' + (ConvertTo-Json -InputObject @($rows) -Compress))
"#;

const EVENTS_MARKER: &str = "WSD_STORAGE_EVENTS ";

/// Parses the collector output. `None` = no valid marker line (collection
/// failed — never treated as "no events").
pub fn parse_event_output(stdout: &str) -> Option<Vec<StorageEventRef>> {
    let line = stdout.lines().find(|l| l.starts_with(EVENTS_MARKER))?;
    let v = json::parse(line[EVENTS_MARKER.len()..].trim())?;
    let rows = match &v {
        json::Value::Arr(a) => a.clone(),
        json::Value::Obj(_) => vec![v.clone()],
        json::Value::Null => Vec::new(),
        _ => return None,
    };
    let num = |r: &json::Value, k: &str| match r.get(k) {
        Some(json::Value::Num(n)) => Some(*n),
        _ => None,
    };
    let mut out = Vec::new();
    for r in &rows {
        let Some(source) = r
            .get("P")
            .and_then(|p| p.as_str())
            .and_then(StorageEventSource::of_provider)
        else {
            continue;
        };
        let (Some(id), Some(n)) = (num(r, "I"), num(r, "N")) else {
            continue;
        };
        let disk = num(r, "D").filter(|d| *d >= 0.0).map(|d| d as u32);
        out.push(StorageEventRef {
            source,
            event_id: id as u32,
            first_seen: r
                .get("F")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            last_seen: r
                .get("L")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            physical_disk_index: disk,
            count: n.max(0.0) as u32,
        });
    }
    Some(out)
}

/// `-EncodedCommand` payload: base64 of the UTF-16LE script.
fn encoded_command(script: &str) -> String {
    const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(B64[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Runs the read-only collector with `host` (hidden, own process tree,
/// 60 s limit). Any failure is `NotCollected`, never "no events".
pub fn collect_events(host: &str) -> EventsInput {
    use std::io::Read;
    use std::process::{Command, Stdio};
    let mut cmd = Command::new(host);
    cmd.args([
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-EncodedCommand",
    ])
    .arg(encoded_command(EVENT_COLLECTOR_PS1))
    .stdin(Stdio::null())
    .stdout(Stdio::piped())
    .stderr(Stdio::null());
    let Ok(mut guard) = crate::engine::ProcessGuard::spawn(cmd) else {
        return EventsInput::NotCollected;
    };
    let Some(mut stdout) = guard.child_mut().stdout.take() else {
        return EventsInput::NotCollected;
    };
    let reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout.read_to_end(&mut buf);
        buf
    });
    let never = std::sync::atomic::AtomicBool::new(false);
    if guard
        .wait_or_cancel(&never, Some(std::time::Duration::from_secs(60)))
        .is_err()
    {
        return EventsInput::NotCollected;
    }
    let bytes = reader.join().unwrap_or_default();
    match parse_event_output(&String::from_utf8_lossy(&bytes)) {
        Some(list) => EventsInput::Collected(list),
        None => EventsInput::NotCollected,
    }
}

/// `MSFT_StorageReliabilityCounter` (root/Microsoft/Windows/Storage) fields
/// relevant to SATA/HDD reliability — RESEARCH ONLY, not collected here
/// (the Hardware Report already reads Temperature, Wear, PowerOnHours,
/// ReadErrorsTotal, WriteErrorsTotal). A missing value is unknown, never 0.
#[cfg_attr(not(test), allow(dead_code))]
pub const SATA_RELIABILITY_FIELDS: [&str; 19] = [
    "DeviceId",
    "ManufactureDate",
    "Temperature",
    "TemperatureMax",
    "Wear",
    "PowerOnHours",
    "StartStopCycleCount",
    "StartStopCycleCountMax",
    "LoadUnloadCycleCount",
    "LoadUnloadCycleCountMax",
    "ReadErrorsTotal",
    "ReadErrorsCorrected",
    "ReadErrorsUncorrected",
    "WriteErrorsTotal",
    "WriteErrorsCorrected",
    "WriteErrorsUncorrected",
    "ReadLatencyMax",
    "WriteLatencyMax",
    "FlushLatencyMax",
];

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::nvme_health::tests::{disk, smart_bytes};
    use crate::nvme_health::{LogRead, NvmeLogSource, ProbeError, collect};

    struct Src(Result<Vec<u8>, ProbeError>);
    impl NvmeLogSource for Src {
        fn read_log_page(&self, _: u32, lid: u8, _: usize) -> Result<LogRead, ProbeError> {
            if lid == 2 {
                self.0.clone().map(|data| LogRead { data, via: "test" })
            } else {
                Err(ProbeError::InvalidFunction)
            }
        }
    }

    /// SMART page with the real-validation values (Samsung / Netac shape).
    pub(crate) fn smart_page(
        warning: u8,
        temp_c: u16,
        spare: u8,
        threshold: u8,
        used: u8,
        cycles: u128,
        hours: u128,
        unsafe_sd: u128,
        media: u128,
        error_entries: u128,
    ) -> Vec<u8> {
        let mut b = smart_bytes();
        b[0] = warning;
        b[1..3].copy_from_slice(&(temp_c + 273).to_le_bytes());
        b[3] = spare;
        b[4] = threshold;
        b[5] = used;
        b[112..128].copy_from_slice(&cycles.to_le_bytes());
        b[128..144].copy_from_slice(&hours.to_le_bytes());
        b[144..160].copy_from_slice(&unsafe_sd.to_le_bytes());
        b[160..176].copy_from_slice(&media.to_le_bytes());
        b[176..192].copy_from_slice(&error_entries.to_le_bytes());
        b
    }

    pub(crate) fn samsung_page() -> Vec<u8> {
        smart_page(0, 46, 100, 10, 4, 88, 7816, 68, 0, 0)
    }
    pub(crate) fn netac_page() -> Vec<u8> {
        smart_page(0, 44, 100, 1, 0, 69, 8016, 28, 0, 9)
    }

    pub(crate) fn health(page: Option<Vec<u8>>, index: u32) -> NvmeHealth {
        let d = disk(index, "Test NVMe", "", "NVMe");
        collect(
            &Src(page.ok_or(ProbeError::InvalidFunction)),
            &d,
            "2026-10-03T12:00:00",
        )
    }

    fn bench(s: BenchStability, write: f64) -> BenchmarkFacts {
        BenchmarkFacts {
            stability: s,
            read_variation_percent: 2.0,
            write_variation_percent: write,
        }
    }

    fn inputs(
        first: Option<BenchmarkFacts>,
        retest: RetestOutcome,
        page: Option<Vec<u8>>,
        events: Vec<StorageEventRef>,
    ) -> StorageHealthInputs {
        StorageHealthInputs {
            physical_identity: "PHYS#Test NVMe#IDX3".into(),
            disk_index: Some(3),
            benchmark: first,
            retest,
            nvme: Some(health(page, 3)),
            events: EventsInput::Collected(events),
            assessed_at: "2026-10-03T12:00:00".into(),
        }
    }

    fn ev(id: u32, disk: Option<u32>, last: &str, count: u32) -> StorageEventRef {
        StorageEventRef {
            source: StorageEventSource::Disk,
            event_id: id,
            first_seen: "2026-09-25T08:00:00".into(),
            last_seen: last.into(),
            physical_disk_index: disk,
            count,
        }
    }

    #[test]
    fn real_validation_values_are_clean_ok() {
        let samsung = health(Some(samsung_page()), 3);
        let s = samsung.smart.as_ref().unwrap();
        assert_eq!(
            (
                s.critical_warning,
                s.composite_temperature_c(),
                s.available_spare_percent,
                s.available_spare_threshold_percent,
                s.percentage_used
            ),
            (0, Some(46), 100, 10, 4)
        );
        assert_eq!(
            (s.power_cycles, s.power_on_hours, s.unsafe_shutdowns),
            (88, 7816, 68)
        );
        assert_eq!(
            (
                s.media_and_data_integrity_errors,
                s.error_information_log_entries
            ),
            (0, 0)
        );
        for page in [samsung_page(), netac_page()] {
            let c = classify(&inputs(
                Some(bench(BenchStability::Accept, 7.0)),
                RetestOutcome::NotNeeded,
                Some(page),
                vec![],
            ));
            assert_eq!(c.state, StorageState::Ok, "{c:?}");
        }
    }

    /// Netac: Error Log Entries 9, no media errors, Critical Warning 0 ->
    /// a fact, not a failure.
    #[test]
    fn error_log_entries_without_media_errors_are_a_fact_only() {
        let c = classify(&inputs(
            Some(bench(BenchStability::Stable, 2.0)),
            RetestOutcome::NotNeeded,
            Some(netac_page()),
            vec![],
        ));
        assert_eq!(c.state, StorageState::Ok);
        let f = c
            .findings
            .iter()
            .find(|f| matches!(f, Finding::ErrorLogEntries(9)))
            .expect("kept as a finding");
        assert_eq!(f.weight(), Weight::Fact);
        assert!(f.text(false).contains("not a failure"));
        assert!(
            c.findings
                .iter()
                .any(|f| matches!(f, Finding::UnsafeShutdowns(28)) && f.weight() == Weight::Fact)
        );
    }

    #[test]
    fn unstable_with_clean_health_requires_a_retest() {
        for pending in [
            RetestOutcome::Pending,
            RetestOutcome::Cancelled,
            RetestOutcome::Failed,
            RetestOutcome::Skipped(RetestSkip::TargetUnavailable),
        ] {
            let c = classify(&inputs(
                Some(bench(BenchStability::Unstable, 18.4)),
                pending,
                Some(samsung_page()),
                vec![],
            ));
            assert_eq!(c.state, StorageState::BenchmarkAnomalyRetest);
            assert!(c.state < StorageState::StorageAttention, "never a failure");
        }
    }

    /// Real Samsung/Netac-equivalent regression: run 1 WRITE variance above
    /// the unstable threshold, run 2 back in range, health clean.
    #[test]
    fn unstable_then_stable_retest_is_not_a_storage_failure() {
        for page in [samsung_page(), netac_page()] {
            let c = classify(&inputs(
                Some(bench(BenchStability::Unstable, 18.4)),
                RetestOutcome::Completed(bench(BenchStability::Accept, 6.2)),
                Some(page),
                vec![],
            ));
            assert_eq!(c.state, StorageState::AnomalyNotConfirmed);
            assert!(c.findings.contains(&Finding::RetestNormalized));
            assert!(
                c.findings.contains(&Finding::BenchmarkUnstable),
                "first run kept"
            );
        }
    }

    #[test]
    fn unstable_twice_with_clean_health_is_check_not_failure() {
        let c = classify(&inputs(
            Some(bench(BenchStability::Unstable, 18.4)),
            RetestOutcome::Completed(bench(BenchStability::Unstable, 15.0)),
            Some(samsung_page()),
            vec![ev(153, Some(5), "2026-10-02T10:00:00", 40)],
        ));
        assert_eq!(c.state, StorageState::BenchmarkAnomalyCheck);
        assert_ne!(c.state, StorageState::StorageProblem);
        // Weak events on the SAME disk corroborate -> attention, still not
        // a problem.
        let c = classify(&inputs(
            Some(bench(BenchStability::Unstable, 18.4)),
            RetestOutcome::Completed(bench(BenchStability::Unstable, 15.0)),
            Some(samsung_page()),
            vec![ev(153, Some(3), "2026-10-02T10:00:00", 1)],
        ));
        assert_eq!(c.state, StorageState::StorageAttention);
    }

    #[test]
    fn media_errors_need_attention_and_corroboration_makes_a_problem() {
        let page = smart_page(0, 40, 100, 10, 1, 1, 1, 0, 3, 3);
        let c = classify(&inputs(
            None,
            RetestOutcome::NotNeeded,
            Some(page.clone()),
            vec![],
        ));
        assert_eq!(c.state, StorageState::StorageAttention);
        let c = classify(&inputs(
            None,
            RetestOutcome::NotNeeded,
            Some(page.clone()),
            vec![ev(153, Some(3), "2026-10-01T10:00:00", 2)],
        ));
        assert_eq!(c.state, StorageState::StorageProblem);
        // Old or other-disk events do not corroborate.
        for e in [
            ev(153, Some(3), "2026-09-01T10:00:00", 50),
            ev(154, Some(4), "2026-10-02T10:00:00", 50),
            ev(154, None, "2026-10-02T10:00:00", 50),
        ] {
            let c = classify(&inputs(
                None,
                RetestOutcome::NotNeeded,
                Some(page.clone()),
                vec![e],
            ));
            assert_eq!(c.state, StorageState::StorageAttention);
        }
        assert!(!retest_allowed(Some(&health(Some(page), 3))));
    }

    #[test]
    fn critical_warning_bits_are_interpreted_individually() {
        let cases = [
            (0b0000_0001, StorageState::StorageProblem),
            (0b0000_0010, StorageState::StorageAttention),
            (0b0000_0100, StorageState::StorageProblem),
            (0b0000_1000, StorageState::StorageProblem),
            (0b0001_0000, StorageState::StorageAttention),
            (0b0010_0000, StorageState::StorageAttention),
            (0b1000_0000, StorageState::StorageAttention),
        ];
        for (bits, expected) in cases {
            let page = smart_page(bits, 40, 100, 10, 1, 1, 1, 0, 0, 0);
            let c = classify(&inputs(None, RetestOutcome::NotNeeded, Some(page), vec![]));
            assert_eq!(c.state, expected, "bits {bits:#010b}");
            let named = c
                .findings
                .iter()
                .filter(|f| matches!(f, Finding::CriticalWarningBit { .. }))
                .count();
            assert_eq!(named, 1, "one explained finding per bit");
        }
        // Temperature: only the drive's own threshold bit raises severity;
        // a hot reading with bit 1 clear is a fact.
        let hot = smart_page(0, 79, 100, 10, 1, 1, 1, 0, 0, 0);
        let c = classify(&inputs(None, RetestOutcome::NotNeeded, Some(hot), vec![]));
        assert_eq!(c.state, StorageState::Ok);
        assert!(!retest_allowed(Some(&health(
            Some(smart_page(0b10, 80, 100, 10, 1, 1, 1, 0, 0, 0)),
            3
        ))));
        assert!(retest_allowed(Some(&health(Some(netac_page()), 3))));
        assert!(retest_allowed(None), "unknown health does not forbid");
    }

    #[test]
    fn event_count_alone_never_raises_severity() {
        // 500 unbound / non-fault events: context only.
        let mut e = ev(129, None, "2026-10-02T10:00:00", 500);
        e.source = StorageEventSource::StorPort;
        let c = classify(&inputs(
            Some(bench(BenchStability::Stable, 1.0)),
            RetestOutcome::NotNeeded,
            Some(samsung_page()),
            vec![e, ev(153, Some(3), "2026-10-02T10:00:00", 500)],
        ));
        assert_eq!(c.state, StorageState::Ok);
        // A single recent bad-block event on the same disk: attention.
        let c = classify(&inputs(
            Some(bench(BenchStability::Stable, 1.0)),
            RetestOutcome::NotNeeded,
            Some(samsung_page()),
            vec![ev(7, Some(3), "2026-10-02T10:00:00", 1)],
        ));
        assert_eq!(c.state, StorageState::StorageAttention);
    }

    #[test]
    fn missing_health_is_insufficient_data_not_ok_or_failure() {
        let c = classify(&inputs(
            Some(bench(BenchStability::Stable, 1.0)),
            RetestOutcome::NotNeeded,
            None,
            vec![],
        ));
        assert_eq!(c.state, StorageState::InsufficientData);
        let mut i = inputs(
            Some(bench(BenchStability::Unstable, 20.0)),
            RetestOutcome::Completed(bench(BenchStability::Unstable, 20.0)),
            None,
            vec![],
        );
        i.events = EventsInput::NotCollected;
        assert_eq!(classify(&i).state, StorageState::BenchmarkAnomalyCheck);
    }

    #[test]
    fn recency_and_event_output_parsing() {
        assert!(is_recent("2026-09-28T00:00:00", "2026-10-03T12:00:00"));
        assert!(!is_recent("2026-09-20T00:00:00", "2026-10-03T12:00:00"));
        assert!(is_recent("2024-02-29T00:00:00", "2024-03-01T00:00:00"));
        assert!(!is_recent("garbage", "2026-10-03T12:00:00"));
        let out = "noise\nWSD_STORAGE_EVENTS [{\"P\":\"disk\",\"I\":153,\"D\":3,\"N\":4,\"F\":\"2026-09-30T10:00:00\",\"L\":\"2026-10-02T10:00:00\"},{\"P\":\"stornvme\",\"I\":11,\"D\":-1,\"N\":2,\"F\":\"a\",\"L\":\"b\"},{\"P\":\"WUDFRd\",\"I\":219,\"D\":-1,\"N\":1}]\n";
        let list = parse_event_output(out).unwrap();
        assert_eq!(list.len(), 2, "non-storage providers dropped");
        assert_eq!(list[0].physical_disk_index, Some(3));
        assert_eq!(list[0].count, 4);
        assert_eq!(list[1].source, StorageEventSource::StorNvme);
        assert_eq!(list[1].physical_disk_index, None);
        assert_eq!(parse_event_output("WSD_STORAGE_EVENTS []"), Some(vec![]));
        assert_eq!(
            parse_event_output("no marker"),
            None,
            "failure != no events"
        );
        let one =
            "WSD_STORAGE_EVENTS {\"P\":\"Ntfs\",\"I\":55,\"D\":-1,\"N\":1,\"F\":\"x\",\"L\":\"y\"}";
        assert_eq!(parse_event_output(one).unwrap().len(), 1);
    }

    #[test]
    fn encoded_command_is_utf16le_base64() {
        assert_eq!(encoded_command("A"), "QQA=");
        assert_eq!(encoded_command("ab"), "YQBiAA==");
        assert_eq!(encoded_command("abc"), "YQBiAGMA");
    }

    #[test]
    fn collector_script_is_read_only_and_runs() {
        for forbidden in [
            "Clear-EventLog",
            "wevtutil",
            "Remove-",
            "Set-",
            "New-Item",
            "Out-File",
            "Limit-EventLog",
        ] {
            assert!(!EVENT_COLLECTOR_PS1.contains(forbidden), "{forbidden}");
        }
        assert!(EVENT_COLLECTOR_PS1.contains("Get-WinEvent"));
        let host = if cfg!(windows) {
            Some("powershell.exe".to_string())
        } else {
            std::env::var("WSD_PWSH").ok()
        };
        let Some(host) = host else {
            eprintln!("no PowerShell host: execution skipped");
            return;
        };
        // Off Windows Get-WinEvent is absent: the script still answers with
        // a valid (empty) marker line rather than failing.
        match collect_events(&host) {
            EventsInput::Collected(list) => {
                if !cfg!(windows) {
                    assert!(list.is_empty());
                }
            }
            EventsInput::NotCollected => panic!("collector produced no marker"),
        }
    }

    #[test]
    fn correlation_evidence_is_valid_json() {
        let i = inputs(
            Some(bench(BenchStability::Unstable, 18.4)),
            RetestOutcome::Completed(bench(BenchStability::Stable, 3.0)),
            Some(netac_page()),
            vec![],
        );
        let c = classify(&i);
        let text = to_json(
            &i,
            &c,
            "Netac NVMe SSD 1TB",
            Some("NVMe_Health_03.10.26_12-00_PD3.json"),
            &[
                "SSD_Benchmark_03.10.26_11-58.json".into(),
                "SSD_Benchmark_03.10.26_12-01.json".into(),
            ],
        );
        let v = json::parse(&text).expect("valid JSON");
        assert_eq!(
            v.get("state").and_then(|x| x.as_str()),
            Some("BENCHMARK_ANOMALY_NOT_CONFIRMED")
        );
        assert_eq!(v.get("retest").and_then(|x| x.as_str()), Some("completed"));
        assert!(
            text.contains("\"stability\": \"UNSTABLE\""),
            "first run preserved"
        );
        assert!(
            text.contains("\"stability\": \"STABLE\""),
            "retest preserved"
        );
        assert_eq!(
            evidence_file_name("03.10.26_12-02", Some(3)),
            "Storage_Correlation_03.10.26_12-02_PD3.json"
        );
        for verdict in ["FAILURE", "FAILING", "\"BAD\""] {
            assert!(!text.contains(verdict));
        }
        assert!(SATA_RELIABILITY_FIELDS.contains(&"ReadErrorsUncorrected"));
        assert_eq!(StorageEventSource::ALL.len(), 5);
    }
}
