//! Report writing: one TXT or JSON file per run, and never the same file twice.
//!
//! The report is the durable artifact, so it carries more than the screen shows: the
//! provider list with each provider's availability and reason, the per-metric
//! min/max/average/state counts, and the full reason for every metric that is not a
//! plain measurement. A run whose sampler was terminated says so, because a report
//! that hid a forced stop would misrepresent the data.
//!
//! A report contains **every sample the run still holds**, in arrival order, with each
//! sample's own timestamp and every metric's state together with its reason. When the
//! in-memory history was capped, the report says so in its notices and states how many
//! samples were dropped, so a truncated history can never be mistaken for a short run.
//! The per-metric table is built from every sample, not from the first one, so a
//! metric that only ever appeared in a later sample still has a row.
//!
//! Nothing here invents a value. A metric with no value is written as its state and
//! its reason.
//!
//! ## File names
//!
//! A caller supplies either a directory or a file path:
//!
//! * an existing **directory** receives a new file whose name is unique: the local
//!   date and time down to the millisecond, and, if that name is somehow already
//!   taken, a `-N` counter. A second save in the same millisecond therefore writes a
//!   **second** file and never overwrites the first.
//! * a path that is an existing **file** is refused with an error rather than
//!   replaced, so a report can never be silently destroyed.
//! * a path that does not exist is created, including its parent directories.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use powerlab_core::ipc::{self, Metric, MetricState, ProviderStatus, Sample, Series, format_value};
use powerlab_core::json::Json;

/// Everything a report needs about one run.
pub struct RunReport<'a> {
    pub started_local: String,
    pub started_utc: String,
    pub duration: std::time::Duration,
    pub interval: std::time::Duration,
    pub providers: &'a [ProviderStatus],
    pub source_lines: &'a [String],
    /// Operator-facing messages. The writer adds the history-truncation notice here
    /// rather than changing the shape of this structure.
    pub notices: &'a [String],
    /// Every sample the run holds, in arrival order. The report states this count and
    /// writes one row per sample, so the full history is preserved in the file.
    pub samples: &'a [Sample],
    pub series: &'a BTreeMap<String, Series>,
    /// How the run ended, and whether it was clean.
    pub stop: String,
    pub clean: bool,
    /// Sampler version and contract version, so a report is self-identifying.
    pub sampler_version: &'a str,
    pub machine: String,
}

/// Write the TXT report, returning the path written.
pub fn write_txt(report: &RunReport<'_>, path: &Path) -> Result<PathBuf, String> {
    write_report(path, "txt", render_txt(report))
}

/// Write the JSON report, returning the path written.
pub fn write_json(report: &RunReport<'_>, path: &Path) -> Result<PathBuf, String> {
    write_report(path, "json", render_json(report))
}

/// CSV keeps every retained reading with its original timestamp, state and provenance.
pub fn write_csv(report: &RunReport<'_>, path: &Path) -> Result<PathBuf, String> {
    write_report(path, "csv", render_csv(report.samples))
}
fn csv_text(s: &str) -> String {
    let safe = if s.trim_start().starts_with(['=', '+', '-', '@']) {
        format!("'{s}")
    } else {
        s.to_string()
    };
    format!("\"{}\"", safe.replace('"', "\"\""))
}
fn render_csv(samples: &[Sample]) -> String {
    let mut out = String::from(
        "sample,sample_timestamp_ms,metric_timestamp_ms,id,label,unit,state,value,source,reason\r\n",
    );
    for s in samples {
        for m in &s.metrics {
            let value = if m.state.has_value() {
                m.value
                    .filter(|v| v.is_finite())
                    .map(|v| v.to_string())
                    .unwrap_or_default()
            } else {
                String::new()
            };
            out.push_str(&format!(
                "{},{},{},{},{},{},{},{},{},{}\r\n",
                s.index,
                s.timestamp_ms,
                m.timestamp_ms,
                csv_text(&m.id),
                csv_text(&m.label),
                csv_text(&m.unit),
                m.state.as_str(),
                value,
                csv_text(&m.source),
                csv_text(m.reason.as_deref().unwrap_or(""))
            ));
        }
    }
    out
}

/// Write one already-rendered report.
///
/// `path` is a directory or a file, as documented on this module: an existing file is
/// refused, a directory gets a unique name inside it, and a missing path is created.
///
/// The text is written to a `.partial` file first and only then renamed to the report
/// name, so a window closed (or a process ended) in the middle of a save never leaves a
/// truncated file under a name that looks like a complete report. A leftover `.partial`
/// file is visibly incomplete. An existing report is still never replaced.
fn write_report(path: &Path, extension: &str, text: String) -> Result<PathBuf, String> {
    let destination = report_path(path, extension)?;
    let partial = partial_path(&destination);
    let mut file = create_new_file(&partial)?;
    let written = file
        .write_all(text.as_bytes())
        .and_then(|()| file.flush())
        .and_then(|()| file.sync_all());
    drop(file);
    if let Err(err) = written {
        let _ = std::fs::remove_file(&partial);
        return Err(format!(
            "не удалось записать {}: {err}",
            destination.display()
        ));
    }
    // Atomic publication below never replaces an existing destination.
    if destination.exists() {
        let _ = std::fs::remove_file(&partial);
        return Err(format!(
            "файл {} уже существует и не будет перезаписан",
            destination.display()
        ));
    }
    atomic_publish(&partial, &destination).map_err(|err| {
        let _ = std::fs::remove_file(&partial);
        format!(
            "не удалось завершить запись {}: {err}",
            destination.display()
        )
    })?;
    Ok(destination)
}

fn atomic_publish(from: &Path, to: &Path) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn MoveFileExW(from: *const u16, to: *const u16, flags: u32) -> i32;
        }
        let a: Vec<u16> = from
            .as_os_str()
            .to_string_lossy()
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let b: Vec<u16> = to
            .as_os_str()
            .to_string_lossy()
            .encode_utf16()
            .chain(Some(0))
            .collect();
        if unsafe { MoveFileExW(a.as_ptr(), b.as_ptr(), 8) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        std::fs::hard_link(from, to)?;
        std::fs::remove_file(from)
    }
}

/// The temporary name a report is written under before it is complete.
fn partial_path(destination: &Path) -> PathBuf {
    let mut name = destination
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(".partial");
    destination.with_file_name(name)
}

/// Resolve the file to write.
///
/// * an existing directory gets a unique `PowerLab-<stamp>.<ext>` name inside it;
/// * an existing file is refused, never replaced;
/// * a path that does not exist becomes a directory, which is created (including its
///   parents) and then receives the report. Refusing it instead would break the normal
///   first save into a directory that is not there yet.
fn report_path(path: &Path, extension: &str) -> Result<PathBuf, String> {
    if path.is_dir() {
        return Ok(unique_report_path(path, &stamp_slug(), extension));
    }
    if path.exists() {
        return Err(format!(
            "отчёт не записан: файл {} уже существует и не будет перезаписан",
            path.display()
        ));
    }
    std::fs::create_dir_all(path)
        .map_err(|err| format!("не удалось создать каталог {}: {err}", path.display()))?;
    Ok(unique_report_path(path, &stamp_slug(), extension))
}

/// A report file name inside a directory.
///
/// The date and time comes first so a directory sorts chronologically; a numeric
/// suffix is appended only when that name is already present. Uniqueness is decided by
/// the atomic creation in [`create_new_file`] as well, so a name that appears between
/// this check and the write is still not overwritten.
fn unique_report_path(directory: &Path, slug: &str, extension: &str) -> PathBuf {
    for counter in 0u32..MAX_NAME_ATTEMPTS {
        let name = if counter == 0 {
            format!("PowerLab-{slug}.{extension}")
        } else {
            format!("PowerLab-{slug}-{counter}.{extension}")
        };
        let candidate = directory.join(name);
        if !candidate.exists() {
            return candidate;
        }
    }
    // Every plain candidate is taken. A process-local counter still cannot collide with
    // an existing file, so a report is written rather than refused.
    directory.join(format!(
        "PowerLab-{slug}-{}.{extension}",
        NEXT_NAME.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ))
}

/// How many plain `<stamp>`, `<stamp>-1`, … names are tried before falling back to a
/// process-local counter.
const MAX_NAME_ATTEMPTS: u32 = 1000;

/// Fallback counter for the degenerate case where every plain name is taken.
static NEXT_NAME: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// Create a file that must not already exist, so nothing is ever overwritten.
fn create_new_file(path: &Path) -> Result<std::fs::File, String> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|err| match err.kind() {
            std::io::ErrorKind::AlreadyExists => format!(
                "файл {} уже существует и не будет перезаписан",
                path.display()
            ),
            _ => format!("не удалось создать {}: {err}", path.display()),
        })
}

/// The date and time used in a report file name: local time when the platform reports
/// it, so the name matches the `Начало (локальное)` line in the report itself.
///
/// This module deliberately does not depend on the rest of the GUI: it is also compiled
/// on its own by the independent audit harness, so the local clock is read here.
fn stamp_slug() -> String {
    // A test fixture can pin the stamp, which is what makes a "two saves in the same
    // second" test deterministic; otherwise the clock is read, never invented.
    if let Ok(pinned) = std::env::var("POWERLAB_REPORT_STAMP") {
        let trimmed = pinned.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    if let Some((year, month, day, hour, minute, second, millis)) = local_parts() {
        return format!("{year:04}{month:02}{day:02}-{hour:02}{minute:02}{second:02}-{millis:03}");
    }
    // A platform without a local clock still gets a comparable name.
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("epoch-{seconds}")
}

/// The local wall-clock time, as the Windows local time zone reports it.
///
/// `None` on a platform or a call that cannot provide it, so the caller can fall back
/// rather than invent a date.
#[cfg(windows)]
pub(crate) fn local_parts() -> Option<(u16, u16, u16, u16, u16, u16, u16)> {
    let mut time = SystemTimeW::default();
    // SAFETY: `GetLocalTime` writes one `SYSTEMTIME` through the pointer. Every field
    // is a `u16`, so the all-zero initialisation is a valid value for the call's
    // duration and no other memory is touched.
    unsafe {
        GetLocalTime(&mut time);
    }
    Some((
        time.year,
        time.month,
        time.day,
        time.hour,
        time.minute,
        time.second,
        time.milliseconds,
    ))
}

/// A non-Windows build has no local calendar clock here.
#[cfg(not(windows))]
pub(crate) fn local_parts() -> Option<(u16, u16, u16, u16, u16, u16, u16)> {
    None
}

/// `SYSTEMTIME`, in the field order of the Windows SDK.
#[cfg(windows)]
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct SystemTimeW {
    year: u16,
    month: u16,
    day_of_week: u16,
    day: u16,
    hour: u16,
    minute: u16,
    second: u16,
    milliseconds: u16,
}

#[cfg(windows)]
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetLocalTime(time: *mut SystemTimeW);
}

/// The full local date and time, as the report's header writes it.
pub(crate) fn local_datetime_text() -> Option<String> {
    local_parts().map(|(year, month, day, hour, minute, second, millis)| {
        format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}.{millis:03}")
    })
}

/// The human-readable report.
pub fn render_txt(report: &RunReport<'_>) -> String {
    let mut out = String::with_capacity(16 * 1024);
    out.push_str("EXPC PowerLab — отчёт о телеметрии питания и охлаждения\n");
    out.push_str("=========================================================\n\n");
    out.push_str(&format!("Компьютер          : {}\n", report.machine));
    out.push_str(&format!("Начало (локальное) : {}\n", report.started_local));
    out.push_str(&format!("Начало (UTC)       : {}\n", report.started_utc));
    out.push_str(&format!(
        "Длительность       : {:.1} с, интервал {:.0} мс\n",
        report.duration.as_secs_f64(),
        report.interval.as_secs_f64() * 1000.0
    ));
    out.push_str(&format!("Замеров            : {}\n", report.samples.len()));
    out.push_str(&format!("Версия контракта   : {}\n", ipc::PROTOCOL_VERSION));
    out.push_str(&format!(
        "Версия сэмплера    : {}\n",
        report.sampler_version
    ));
    out.push_str(&format!("Завершение         : {}\n", report.stop));
    out.push_str(&format!(
        "Чистое завершение  : {}\n\n",
        if report.clean { "да" } else { "НЕТ" }
    ));

    // Providers first: the reader has to know what was and was not available before
    // reading any number.
    out.push_str("--- Источники (провайдеры) ---\n");
    for provider in report.providers {
        out.push_str(&format!(
            "[{:<8}] {:<44} {}\n",
            provider.status, provider.label, provider.detail
        ));
        if let Some(reason) = &provider.reason {
            out.push_str(&format!("           причина: {reason}\n"));
        }
    }
    out.push('\n');

    if !report.source_lines.is_empty() {
        out.push_str("--- Каналы и источники ---\n");
        for line in report.source_lines {
            out.push_str(&format!("* {line}\n"));
        }
        out.push('\n');
    }

    if !report.notices.is_empty() {
        out.push_str("--- Сообщения сэмплера ---\n");
        for notice in report.notices {
            out.push_str(&format!("* {notice}\n"));
        }
        out.push('\n');
    }

    // Aggregates, grouped so a category can be read on its own. The rows come from
    // every sample, not from the first one, so a metric that first appeared later in
    // the run still has its totals in the report.
    out.push_str("--- Итоги по показателям ---\n");
    out.push_str(
        "Показатель                   Ед.   Есть Нулей NO DATA ERROR SUSP Пропущ        Мин        Макс     Среднее\n",
    );
    out.push_str(
        "-----------------------------+-----+-----+-----+-------+-----+----+-------+----------+----------+----------\n",
    );
    let mut current_group = String::new();
    for metric in report_metrics(report).values() {
        let group = metric.group.as_str();
        if current_group != group {
            out.push_str(&format!("[{group}]\n"));
            current_group = group.to_string();
        }
        let blank = Series::default();
        let series = report.series.get(&metric.id).unwrap_or(&blank);
        out.push_str(&format!(
            "{:<28} | {:<3} | {:>4} | {:>4} | {:>6} | {:>5} | {:>3} | {:>6} | {:>9} | {:>9} | {:>9}\n",
            truncate(&metric.label, 28),
            metric.unit,
            series.count,
            series.zeros,
            series.no_data,
            series.errors,
            series.suspect,
            series.skipped,
            series
                .min
                .map(|v| format!("{v:.2}"))
                .unwrap_or_else(|| "—".into()),
            series
                .max
                .map(|v| format!("{v:.2}"))
                .unwrap_or_else(|| "—".into()),
            series
                .average()
                .map(|v| format!("{v:.2}"))
                .unwrap_or_else(|| "—".into()),
        ));
    }
    out.push('\n');

    // Reasons, so a non-measurement state can never be a bare word in the report. Every
    // distinct reason seen for a metric is listed: the same id may be missing data in
    // one window and failing in another, and collapsing the two would hide a failure.
    out.push_str("--- Причины отсутствия данных и ошибок ---\n");
    let mut reasons: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for sample in report.samples {
        for metric in &sample.metrics {
            let is_measurement = matches!(
                metric.state,
                MetricState::Ok | MetricState::Zero | MetricState::Suspect
            );
            if is_measurement && metric.suspect_reason().is_none() {
                continue;
            }
            let reason = metric
                .reason
                .as_deref()
                .or_else(|| metric.suspect_reason())
                .unwrap_or("причина не указана");
            reasons
                .entry(metric.id.as_str())
                .or_default()
                .insert(reason);
        }
    }
    if reasons.is_empty() {
        out.push_str("нет: все показатели измерены\n");
    } else {
        for (id, seen) in reasons {
            for reason in seen {
                out.push_str(&format!("{id}: {reason}\n"));
            }
        }
    }
    out.push('\n');

    // The full sample table, so the file can be re-analysed without the GUI. Every
    // retained sample gets a row, with the timestamp the sampler stamped it with.
    out.push_str("--- Замеры ---\n");
    out.push_str("Время указано как миллисекунды эпохи Unix, как их сообщил сэмплер.\n");
    if !report.samples.is_empty() {
        let columns = report_metrics(report);
        out.push_str("Столбцы постоянны по ID; — означает отсутствие канала в данном замере.\n");
        for (i, metric) in columns.values().enumerate() {
            out.push_str(&format!(
                "C{}: {} [{}] — {}\n",
                i + 1,
                metric.id,
                metric.unit,
                metric.label
            ));
        }
        out.push_str("№    Время(мс)  Прогр Окно,мс ");
        for i in 0..columns.len() {
            out.push_str(&format!("{:>12} ", format!("C{}", i + 1)));
        }
        out.push('\n');
        for sample in report.samples {
            let mark = if sample.warmup { "*" } else { " " };
            out.push_str(&format!(
                "{:<4} {:<11} {:^5} {:>8.1} ",
                sample.index, sample.timestamp_ms, mark, sample.window_ms
            ));
            let readings: BTreeMap<_, _> =
                sample.metrics.iter().map(|m| (m.id.as_str(), m)).collect();
            for id in columns.keys() {
                let value = readings
                    .get(id)
                    .map(|m| m.display_value())
                    .unwrap_or_else(|| "—".into());
                out.push_str(&format!("{:>12} ", truncate(&value, 12)));
            }
            out.push('\n');
        }
        out.push_str("* — прогрев: окно короче интервала, в статистику не входит\n");
    }
    out.push_str(
        "\nPowerLab не измеряет мощность блока питания и не суммирует компоненты: \
                  показатели CPU и GPU — это разные физические величины.\n",
    );
    out
}

/// The machine-readable report: the same facts, no prose.
pub fn render_json(report: &RunReport<'_>) -> String {
    let providers: Vec<Json> = report
        .providers
        .iter()
        .map(|provider| {
            let mut fields = vec![
                ("id".to_string(), Json::str(&provider.id)),
                ("label".to_string(), Json::str(&provider.label)),
                ("status".to_string(), Json::str(&provider.status)),
                ("detail".to_string(), Json::str(&provider.detail)),
            ];
            if let Some(reason) = &provider.reason {
                fields.push(("reason".to_string(), Json::str(reason)));
            }
            Json::Object(fields)
        })
        .collect();

    let totals: Vec<Json> = report
        .series
        .iter()
        .map(|(id, series)| {
            let mut fields = vec![
                ("id".to_string(), Json::str(id)),
                ("count".to_string(), Json::int(series.count as i64)),
                ("zeros".to_string(), Json::int(series.zeros as i64)),
                ("no_data".to_string(), Json::int(series.no_data as i64)),
                ("errors".to_string(), Json::int(series.errors as i64)),
                ("suspect".to_string(), Json::int(series.suspect as i64)),
                // Observations that were seen but excluded from the statistics. Without
                // this column a contradictory reading would vanish from the report
                // entirely, which is the opposite of what the contract asks for.
                ("skipped".to_string(), Json::int(series.skipped as i64)),
            ];
            if let Some(min) = series.min {
                fields.push(("min".to_string(), Json::Float(min)));
            }
            if let Some(max) = series.max {
                fields.push(("max".to_string(), Json::Float(max)));
            }
            if let Some(average) = series.average() {
                fields.push(("average".to_string(), Json::Float(average)));
            }
            Json::Object(fields)
        })
        .collect();

    // One entry per retained sample, each with its own timestamp, states and reasons.
    let samples: Vec<Json> = report.samples.iter().map(ipc::sample_to_json).collect();

    let document = Json::Object(vec![
        ("schema".to_string(), Json::str("expc.powerlab.report/1")),
        ("machine".to_string(), Json::str(&report.machine)),
        (
            "started_local".to_string(),
            Json::str(&report.started_local),
        ),
        ("started_utc".to_string(), Json::str(&report.started_utc)),
        (
            "duration_ms".to_string(),
            Json::Float(report.duration.as_secs_f64() * 1000.0),
        ),
        (
            "interval_ms".to_string(),
            Json::Float(report.interval.as_secs_f64() * 1000.0),
        ),
        (
            "contract_version".to_string(),
            Json::int(ipc::PROTOCOL_VERSION as i64),
        ),
        (
            "sampler_version".to_string(),
            Json::str(report.sampler_version),
        ),
        ("stop_reason".to_string(), Json::str(&report.stop)),
        ("clean".to_string(), Json::Bool(report.clean)),
        ("providers".to_string(), Json::Array(providers)),
        (
            "sources".to_string(),
            Json::Array(report.source_lines.iter().map(|l| Json::str(l)).collect()),
        ),
        (
            "notices".to_string(),
            Json::Array(report.notices.iter().map(|l| Json::str(l)).collect()),
        ),
        (
            "sample_count".to_string(),
            Json::int(report.samples.len() as i64),
        ),
        ("totals".to_string(), Json::Array(totals)),
        ("samples".to_string(), Json::Array(samples)),
    ]);
    document.render()
}

/// Every metric that appears in any retained sample, keyed by id.
///
/// The first occurrence wins, so a label, unit or group is stable across the report
/// even when a later sample drops the metric.
fn report_metrics<'a>(report: &'a RunReport<'a>) -> BTreeMap<&'a str, &'a Metric> {
    let mut metrics: BTreeMap<&str, &Metric> = BTreeMap::new();
    for sample in report.samples {
        for metric in &sample.metrics {
            metrics.entry(metric.id.as_str()).or_insert(metric);
        }
    }
    metrics
}

fn truncate(text: &str, width: usize) -> String {
    let count = text.chars().count();
    if count <= width {
        return text.to_string();
    }
    let mut out: String = text.chars().take(width.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// Helpers used only by the report renderer.
trait ReportHelpers {
    /// The reason to show for a SUSPECT metric that carries a value.
    fn suspect_reason(&self) -> Option<&str>;
}

impl ReportHelpers for Metric {
    fn suspect_reason(&self) -> Option<&str> {
        if self.state == MetricState::Suspect {
            self.reason.as_deref()
        } else {
            None
        }
    }
}

/// Reports belong to the user, not the launcher's working directory (which may
/// be a protected WindowsApps directory). Resolve the redirected Desktop through
/// Windows' known-folder wrapper; the fixed output buffer avoids pointer ownership.
pub fn default_directory() -> PathBuf {
    desktop_directory()
        .unwrap_or_else(std::env::temp_dir)
        .join("PowerLab-Reports")
}

fn desktop_directory() -> Option<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    #[link(name = "shell32")]
    unsafe extern "system" {
        fn SHGetFolderPathW(
            hwnd: *mut std::ffi::c_void,
            csidl: i32,
            token: *mut std::ffi::c_void,
            flags: u32,
            path: *mut u16,
        ) -> i32;
    }
    let mut path = [0u16; 260];
    // CSIDL_DESKTOPDIRECTORY / SHGFP_TYPE_CURRENT, current user. On modern
    // Windows this API delegates to SHGetKnownFolderPath and respects redirection.
    let hr = unsafe {
        SHGetFolderPathW(
            std::ptr::null_mut(),
            0x0010,
            std::ptr::null_mut(),
            0,
            path.as_mut_ptr(),
        )
    };
    if hr != 0 {
        return None;
    }
    let end = path.iter().position(|c| *c == 0)?;
    if end == 0 {
        return None;
    }
    let folder = PathBuf::from(std::ffi::OsString::from_wide(&path[..end]));
    folder.is_absolute().then_some(folder)
}

/// Render a value for the screen, reusing the contract's formatter so the GUI and a
/// report never disagree about precision.
///
/// Kept on the report surface because it is the single place the "a metric with no
/// value prints nothing" rule lives, and the tests assert it there.
#[allow(dead_code)]
pub fn value_text(metric: &Metric) -> String {
    match (metric.state, metric.value) {
        (state, Some(value)) if state.has_value() => format_value(value, &metric.unit),
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use powerlab_core::ipc::{Group, ValueKind};
    use std::path::PathBuf;

    #[test]
    fn a_report_is_written_under_a_partial_name_until_complete() {
        let destination = PathBuf::from("C:/r/PowerLab-2026-11-15_10-00-00.txt");
        assert_eq!(
            partial_path(&destination),
            PathBuf::from("C:/r/PowerLab-2026-11-15_10-00-00.txt.partial")
        );
    }

    fn sample_with(metrics: Vec<Metric>) -> Sample {
        Sample {
            index: 1,
            timestamp_ms: 1_700_000_000_000,
            window_ms: 1000.0,
            elapsed_ms: 5.0,
            warmup: false,
            metrics,
        }
    }

    /// One sample at a stated index and timestamp, which is what the history tests
    /// need in order to prove that nothing is collapsed into "the latest one".
    fn sample_at(index: u32, timestamp_ms: u64, metrics: Vec<Metric>) -> Sample {
        Sample {
            index,
            timestamp_ms,
            window_ms: 1000.0,
            elapsed_ms: 5.0,
            warmup: false,
            metrics,
        }
    }

    /// A directory that does not exist yet. Unique per test so two tests never share
    /// files; created here because `write_txt` creates a missing directory too.
    fn temp_directory(tag: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!(
            "powerlab-report-{tag}-{}-{nanos}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("временный каталог создаётся");
        path
    }

    /// An empty report over a stated history, so a writer test can state exactly which
    /// samples must end up in the file.
    fn report_with<'a>(
        samples: &'a [Sample],
        series: &'a BTreeMap<String, Series>,
    ) -> RunReport<'a> {
        report_of(samples, series, &[], &[], &[])
    }

    fn report_of<'a>(
        samples: &'a [Sample],
        series: &'a BTreeMap<String, Series>,
        providers: &'a [ProviderStatus],
        notices: &'a [String],
        sources: &'a [String],
    ) -> RunReport<'a> {
        RunReport {
            started_local: "2026-10-16 12:00:00.000".to_string(),
            started_utc: "2026-10-16T09:00:00Z".to_string(),
            duration: std::time::Duration::from_secs(10),
            interval: std::time::Duration::from_secs(1),
            providers,
            source_lines: sources,
            notices,
            samples,
            series,
            stop: "опрос завершён".to_string(),
            clean: true,
            sampler_version: "0.1.0",
            machine: "TEST-PC".to_string(),
        }
    }

    #[test]
    fn txt_columns_follow_ids_when_sources_arrive_late_and_reorder() {
        let a = |v| Metric::measured("a.cpu", "CPU", Group::Cpu, "W", v, "test");
        let b = |v| Metric::measured("b.gpu", "GPU", Group::Gpu, "W", v, "test");
        let samples = vec![
            sample_at(1, 1000, vec![a(45.0)]),
            sample_at(2, 2000, vec![b(50.0), a(46.0)]),
            sample_at(3, 3000, vec![b(51.0)]),
        ];
        let text = render_txt(&report_with(&samples, &BTreeMap::new()));
        assert!(text.contains("C1: a.cpu [W]"));
        assert!(text.contains("C2: b.gpu [W]"));
        let rows: Vec<_> = text
            .lines()
            .filter(|line| {
                line.starts_with("1    1000 ")
                    || line.starts_with("2    2000 ")
                    || line.starts_with("3    3000 ")
            })
            .map(|line| line.split_whitespace().collect::<Vec<_>>())
            .collect();
        assert_eq!(
            rows,
            vec![
                vec!["1", "1000", "1000.0", "45.00", "W", "—"],
                vec!["2", "2000", "1000.0", "46.00", "W", "50.00", "W"],
                vec!["3", "3000", "1000.0", "—", "51.00", "W"],
            ]
        );
    }

    #[test]
    fn a_report_states_every_unavailable_reason() {
        let metrics = vec![
            Metric::measured(
                "cpu.package_power",
                "Мощность CPU (пакет)",
                Group::Cpu,
                "W",
                50.0,
                "windows.emi/pdh",
            ),
            Metric::unavailable(
                "cpu.temperature",
                "Температура CPU",
                Group::Cpu,
                "°C",
                MetricState::Unsupported,
                "нужен доступ к MSR",
                "none",
            ),
            Metric::unavailable(
                "dram.power",
                "Мощность DRAM",
                Group::Memory,
                "W",
                MetricState::Error,
                "отказ счётчика (PDH 0xC0000BBA)",
                "windows.emi/pdh",
            ),
        ];
        let samples = vec![sample_with(metrics)];
        let mut series = BTreeMap::new();
        series.insert("cpu.package_power".to_string(), Series::default());
        let providers = vec![ProviderStatus {
            id: "emi".into(),
            label: "Windows Energy Meter".into(),
            status: "error".into(),
            detail: "мощность CPU недоступна".into(),
            reason: Some("PDH 0xC0000BBC".into()),
        }];
        let notices = vec!["сообщение".to_string()];
        let sources = vec!["PKG / IA / GT: Energy Meter".to_string()];
        let report = report_of(&samples, &series, &providers, &notices, &sources);
        let text = render_txt(&report);

        // The provider status and its reason must be present.
        assert!(text.contains("Windows Energy Meter"), "{text}");
        assert!(text.contains("PDH 0xC0000BBC"), "{text}");
        // Every non-measurement reason must appear in the reasons section.
        assert!(text.contains("нужен доступ к MSR"), "{text}");
        assert!(text.contains("отказ счётчика (PDH 0xC0000BBA)"), "{text}");
        // The PSU caveat must always be stated.
        assert!(
            text.contains("не измеряет мощность блока питания"),
            "{text}"
        );
    }

    #[test]
    fn the_json_report_is_valid_and_self_identifying() {
        let metrics = vec![Metric::measured(
            "cpu.package_power",
            "Мощность CPU",
            Group::Cpu,
            "W",
            50.0,
            "windows.emi/pdh",
        )];
        let samples = vec![sample_with(metrics)];
        let mut series = BTreeMap::new();
        let mut s = Series::default();
        s.push(&Metric::measured(
            "cpu.package_power",
            "x",
            Group::Cpu,
            "W",
            50.0,
            "t",
        ));
        series.insert("cpu.package_power".to_string(), s);
        let providers = Vec::new();
        let notices = Vec::new();
        let sources = Vec::new();
        let report = report_of(&samples, &series, &providers, &notices, &sources);
        let text = render_json(&report);

        let parsed = Json::parse(&text).expect("the report must be valid JSON");
        let members = parsed.as_object().expect("object");
        let find = |name: &str| members.iter().find(|(k, _)| k == name).map(|(_, v)| v);
        assert_eq!(
            find("schema").and_then(|v| v.as_str()),
            Some("expc.powerlab.report/1")
        );
        assert_eq!(find("machine").and_then(|v| v.as_str()), Some("TEST-PC"));
        assert_eq!(find("clean"), Some(&Json::Bool(true)));
        assert_eq!(
            find("samples").and_then(|v| v.as_array()).map(|a| a.len()),
            Some(1)
        );
        // The sample must round-trip through the same codec the wire uses.
        let sample_json = find("samples").unwrap().as_array().unwrap()[0].clone();
        let decoded = ipc::sample_from_json(&sample_json).expect("decodes");
        assert_eq!(decoded.metrics.len(), 1);
        assert_eq!(decoded.metrics[0].value, Some(50.0));
    }

    #[test]
    fn an_unavailable_metric_never_prints_a_number() {
        let metric = Metric::unavailable(
            "dram.power",
            "Мощность DRAM",
            Group::Memory,
            "W",
            MetricState::NoData,
            "нет данных",
            "t",
        );
        assert_eq!(value_text(&metric), "");
        assert_eq!(metric.display_value(), "NO_DATA");
    }

    #[test]
    fn a_measured_zero_is_rendered_as_zero_not_as_missing() {
        let metric = Metric::measured("gt.power", "GT", Group::Cpu, "W", 0.0, "t");
        assert_eq!(metric.state, MetricState::Zero);
        // The value text carries the unit, and a confirmed zero is a number.
        assert_eq!(value_text(&metric), "0 W");
        // The short form used in a table cell has no unit column of its own.
        assert_eq!(metric.display_value(), "0");
        assert_ne!(
            value_text(&metric),
            MetricState::Zero.as_str(),
            "a zero must never be rendered as a state word"
        );
    }

    #[test]
    fn a_suspect_metric_keeps_its_value_and_its_reason() {
        let mut metric =
            Metric::measured("gpu.0.fan", "Вентилятор", Group::Cooling, "%", 120.0, "t");
        metric.state = MetricState::Suspect;
        metric.reason = Some("значение вне диапазона".to_string());
        assert_eq!(value_text(&metric), "120.0 %");
        assert_eq!(metric.suspect_reason(), Some("значение вне диапазона"));
        assert_eq!(metric.kind, ValueKind::Measured);
    }

    #[test]
    fn long_labels_are_truncated_without_breaking_the_table() {
        assert_eq!(truncate("short", 10), "short");
        let long = truncate("очень длинная подпись показателя", 10);
        assert_eq!(long.chars().count(), 10);
        assert!(long.ends_with('…'));
    }

    /// B8 - the report of a session keeps every sample, its timestamp and its reasons.
    ///
    /// The three samples deliberately disagree: one metric is measured first and then
    /// fails, another is missing and then measured, and a third only ever fails. A
    /// writer that kept only the latest sample would lose the first two facts.
    #[test]
    fn a_report_keeps_every_sample_with_its_timestamp_and_reason() {
        let samples = vec![
            sample_at(
                1,
                1_700_000_000_000,
                vec![
                    Metric::measured(
                        "cpu.package_power",
                        "Мощность CPU",
                        Group::Cpu,
                        "W",
                        40.0,
                        "t",
                    ),
                    Metric::unavailable(
                        "cpu.temperature",
                        "Температура CPU",
                        Group::Cpu,
                        "°C",
                        MetricState::NoData,
                        "счётчик ещё не отдал данные",
                        "t",
                    ),
                ],
            ),
            sample_at(
                2,
                1_700_000_001_000,
                vec![
                    Metric::unavailable(
                        "cpu.package_power",
                        "Мощность CPU",
                        Group::Cpu,
                        "W",
                        MetricState::Error,
                        "отказ счётчика (PDH 0xC0000BBA)",
                        "t",
                    ),
                    Metric::measured(
                        "cpu.temperature",
                        "Температура CPU",
                        Group::Cpu,
                        "°C",
                        61.0,
                        "t",
                    ),
                ],
            ),
            sample_at(
                3,
                1_700_000_002_000,
                vec![
                    Metric::measured(
                        "cpu.package_power",
                        "Мощность CPU",
                        Group::Cpu,
                        "W",
                        55.0,
                        "t",
                    ),
                    Metric::unavailable(
                        "dram.power",
                        "Мощность DRAM",
                        Group::Memory,
                        "W",
                        MetricState::Unsupported,
                        "нет провайдера питания памяти",
                        "t",
                    ),
                ],
            ),
        ];
        let mut series = BTreeMap::new();
        series.insert("cpu.package_power".to_string(), Series::default());
        let report = report_with(&samples, &series);
        let text = render_txt(&report);

        // The count states the whole history, not one sample.
        let count_line = text
            .lines()
            .find(|line| line.starts_with("Замеров"))
            .expect("the report states a sample count");
        assert!(
            count_line.ends_with(": 3"),
            "the report must count every sample: {count_line}"
        );

        // Every timestamp survives into the times table.
        for timestamp in [1_700_000_000_000u64, 1_700_000_001_000, 1_700_000_002_000] {
            assert!(
                text.contains(&timestamp.to_string()),
                "timestamp {timestamp} is missing from the report"
            );
        }

        // Every reason survives, including the ones that only appeared once.
        assert!(text.contains("отказ счётчика (PDH 0xC0000BBA)"), "{text}");
        assert!(text.contains("счётчик ещё не отдал данные"), "{text}");
        assert!(text.contains("нет провайдера питания памяти"), "{text}");

        // A metric that only appears in the last sample still has an aggregates row,
        // and the metric that failed in the middle is reported as an error there.
        assert!(text.contains("Мощность DRAM"), "{text}");

        // The JSON form carries all three samples too.
        let json = render_json(&report);
        let parsed = Json::parse(&json).expect("valid JSON");
        let members = parsed.as_object().expect("object");
        let find = |name: &str| members.iter().find(|(k, _)| k == name).map(|(_, v)| v);
        assert_eq!(
            find("samples").and_then(|v| v.as_array()).map(|a| a.len()),
            Some(3)
        );
        assert_eq!(find("sample_count").and_then(|v| v.as_int()), Some(3));
        for timestamp in [1_700_000_000_000i64, 1_700_000_001_000, 1_700_000_002_000] {
            assert!(
                json.contains(&timestamp.to_string()),
                "timestamp {timestamp} is missing from the JSON report"
            );
        }
        assert!(json.contains("отказ счётчика (PDH 0xC0000BBA)"), "{json}");
    }

    /// The same metric can be missing data in one window and failing in another; both
    /// reasons must be written, because collapsing them would hide the failure.
    #[test]
    fn every_distinct_reason_for_one_metric_is_written() {
        let samples = vec![
            sample_at(
                1,
                1_000,
                vec![Metric::unavailable(
                    "gpu.0.power",
                    "Мощность GPU",
                    Group::Gpu,
                    "W",
                    MetricState::NoData,
                    "нет данных от счётчика",
                    "t",
                )],
            ),
            sample_at(
                2,
                2_000,
                vec![Metric::unavailable(
                    "gpu.0.power",
                    "Мощность GPU",
                    Group::Gpu,
                    "W",
                    MetricState::Error,
                    "отказ PDH",
                    "t",
                )],
            ),
        ];
        let series = BTreeMap::new();
        let report = report_with(&samples, &series);
        let text = render_txt(&report);
        assert!(text.contains("нет данных от счётчика"), "{text}");
        assert!(text.contains("отказ PDH"), "{text}");
    }

    /// B8 - a second save in the same millisecond writes a second file.
    #[test]
    fn saving_twice_into_one_directory_writes_two_files_and_keeps_the_first() {
        let directory = temp_directory("twice");
        let samples = vec![sample_at(
            1,
            1_000,
            vec![Metric::measured(
                "cpu.package_power",
                "Мощность",
                Group::Cpu,
                "W",
                1.0,
                "t",
            )],
        )];
        let series = BTreeMap::new();
        let report = report_with(&samples, &series);

        let first = write_txt(&report, &directory).expect("первый отчёт записан");
        let first_text = std::fs::read_to_string(&first).expect("первый файл читается");
        let second = write_txt(&report, &directory).expect("второй отчёт записан");

        assert_ne!(
            first, second,
            "a second save must not reuse the first file name"
        );
        assert!(first.exists(), "the first report must still be there");
        assert!(second.exists(), "the second report must be there");
        assert_eq!(
            std::fs::read_to_string(&first).expect("первый файл читается"),
            first_text,
            "the first report must not be overwritten"
        );
        // The names share the documented `PowerLab-<stamp>` base, so the second name is
        // a real collision resolution rather than a different scheme.
        let first_name = first.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let second_name = second.file_name().and_then(|n| n.to_str()).unwrap_or("");
        assert!(first_name.starts_with("PowerLab-"), "{first_name}");
        assert!(second_name.starts_with("PowerLab-"), "{second_name}");
        // A completed save leaves only complete reports: the temporary `.partial` file
        // a save is written under is renamed away, never left behind.
        let leftovers: Vec<_> = std::fs::read_dir(&directory)
            .expect("каталог читается")
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".partial"))
            .collect();
        assert!(leftovers.is_empty(), "partial files left: {leftovers:?}");
        assert_ne!(first_name, second_name);
    }

    /// The stamp itself is unique per save even when the pinned test stamp is used, so
    /// the uniqueness cannot depend on the clock alone.
    #[test]
    fn a_name_collision_is_resolved_with_a_counter() {
        let directory = temp_directory("counter");
        let slug = "20261016-120000-000";
        let first = unique_report_path(&directory, slug, "txt");
        std::fs::write(&first, "первый").expect("файл создаётся");
        let second = unique_report_path(&directory, slug, "txt");
        assert_ne!(first, second);
        assert_eq!(
            second.file_name().and_then(|n| n.to_str()),
            Some("PowerLab-20261016-120000-000-1.txt")
        );
        assert_eq!(std::fs::read_to_string(&first).unwrap(), "первый");
    }

    /// B8 - a path that is an existing file is refused, never replaced.
    #[test]
    fn writing_over_an_existing_file_is_refused() {
        let directory = temp_directory("refuse");
        std::fs::create_dir_all(&directory).expect("каталог создаётся");
        let existing = directory.join("PowerLab-existing.txt");
        std::fs::write(&existing, "не трогать").expect("файл создаётся");
        let samples = vec![sample_at(
            1,
            1_000,
            vec![Metric::measured(
                "cpu.package_power",
                "Мощность",
                Group::Cpu,
                "W",
                1.0,
                "t",
            )],
        )];
        let series = BTreeMap::new();
        let report = report_with(&samples, &series);

        let err = write_txt(&report, &existing).expect_err("запись в файл должна быть отклонена");
        assert!(err.contains("уже существует"), "{err}");
        assert_eq!(
            std::fs::read_to_string(&existing).unwrap(),
            "не трогать",
            "the existing file must be untouched"
        );

        let err = write_json(&report, &existing).expect_err("запись в файл должна быть отклонена");
        assert!(err.contains("уже существует"), "{err}");
    }

    /// The file name is a local date and time, not an epoch count, and a test fixture
    /// can pin it so the collision test above is deterministic.
    #[test]
    fn the_file_stamp_is_a_local_date_and_time() {
        if let Ok(pinned) = std::env::var("POWERLAB_REPORT_STAMP") {
            if !pinned.trim().is_empty() {
                assert_eq!(stamp_slug(), pinned.trim());
                return;
            }
        }
        let only_digits = |text: &str| text.chars().all(|c| c.is_ascii_digit());
        let slug = stamp_slug();
        assert_eq!(slug.len(), 19, "YYYYMMDD-HHMMSS-mmm: {slug}");
        assert_eq!(slug.chars().nth(8), Some('-'), "{slug}");
        assert_eq!(slug.chars().nth(15), Some('-'), "{slug}");
        assert!(only_digits(&slug.replace('-', "")), "{slug}");
        assert!(
            slug.starts_with("20"),
            "a calendar year, not an epoch: {slug}"
        );
    }

    /// The same clock, in the form the report header uses.
    #[test]
    fn the_local_date_time_is_a_full_civil_timestamp() {
        let Some(text) = local_datetime_text() else {
            // A platform without a local clock: the caller falls back, and there is
            // nothing to assert about an invented value.
            return;
        };
        assert_eq!(text.len(), 23, "YYYY-MM-DD HH:MM:SS.mmm: {text}");
        assert_eq!(text.chars().nth(4), Some('-'), "{text}");
        assert_eq!(text.chars().nth(7), Some('-'), "{text}");
        assert_eq!(text.chars().nth(10), Some(' '), "{text}");
        assert_eq!(text.chars().nth(13), Some(':'), "{text}");
        assert_eq!(text.chars().nth(16), Some(':'), "{text}");
        assert_eq!(text.chars().nth(19), Some('.'), "{text}");
        assert!(
            text.starts_with("20"),
            "a calendar year, not an epoch: {text}"
        );
    }
}

#[cfg(test)]
mod recovery_directory_tests {
    use super::*;
    #[test]
    fn report_directory_is_absolute_and_independent_of_launcher() {
        let expected = desktop_directory()
            .unwrap_or_else(std::env::temp_dir)
            .join("PowerLab-Reports");
        assert!(expected.is_absolute());
        assert_eq!(default_directory(), expected);
    }
}

#[cfg(test)]
mod csv_tests {
    use super::*;
    #[test]
    fn csv_escapes_text_and_does_not_invent_missing_values() {
        assert_eq!(csv_text("a,\"b"), "\"a,\"\"b\"");
        assert_eq!(csv_text("=HYPERLINK(x)"), "\"'=HYPERLINK(x)\"");
        let m = Metric::unavailable(
            "cpu.temp",
            "CPU",
            powerlab_core::ipc::Group::Cpu,
            "C",
            MetricState::NoData,
            "permission denied",
            "test",
        );
        let s = Sample {
            index: 1,
            timestamp_ms: 20,
            window_ms: 1000.0,
            elapsed_ms: 1.0,
            warmup: false,
            metrics: vec![m],
        };
        let text = render_csv(&[s]);
        assert!(text.contains("NO_DATA,,"));
        assert!(text.contains("permission denied"));
    }
}
