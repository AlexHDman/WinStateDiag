//! v1.0 items 15 + 18: per-disk storage session history.
//!
//! Every storage assessment is one SESSION with an identity
//! (SessionId / StartTime / EndTime / Status / producer_version). Only a
//! COMPLETED session is a baseline: a cancelled or still-running session
//! never becomes the "current state" and never anchors a delta.
//!
//! The NVMe Error Information Log counter is compared between the latest
//! COMPLETED session of the same physical disk and the session being
//! completed now:
//!
//! * `FIRST_COMPLETED` — no earlier completed session for this disk;
//! * `STABLE`          — the counter did not change;
//! * `DELTA`           — the counter grew (a fact with the exact numbers,
//!                       never a failure verdict by itself);
//! * `COUNTER_RESET`   — the counter went down (firmware reset / different
//!                       drive behind the same identity) — no delta claimed;
//! * `UNKNOWN`         — a value is missing on either side.
//!
//! Stored as `Reports\WinStateDiag_StorageHistory.json` (UTF-8, local
//! only, no serial numbers — the physical identity the evidence already
//! uses). Read-only towards the disk: this is the app's own report file.

use crate::deep_checks::json;

pub const FILE_NAME: &str = "WinStateDiag_StorageHistory.json";
/// Records kept per physical disk (oldest dropped first).
pub const KEEP_PER_DISK: usize = 50;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionStatus {
    Completed,
    Cancelled,
    /// The run ended technically (e.g. the retest failed): history only.
    Failed,
}

impl SessionStatus {
    pub fn code(self) -> &'static str {
        match self {
            SessionStatus::Completed => "COMPLETED",
            SessionStatus::Cancelled => "CANCELLED",
            SessionStatus::Failed => "FAILED",
        }
    }
    fn parse(s: &str) -> Option<Self> {
        match s {
            "COMPLETED" => Some(SessionStatus::Completed),
            "CANCELLED" => Some(SessionStatus::Cancelled),
            "FAILED" => Some(SessionStatus::Failed),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SessionRecord {
    pub session_id: String,
    pub physical_identity: String,
    pub start_time: String,
    pub end_time: String,
    pub status: SessionStatus,
    pub producer_version: String,
    pub storage_state: String,
    pub error_log_entries: Option<u64>,
    pub media_errors: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorLogDelta {
    FirstCompleted,
    Stable {
        value: u64,
    },
    Delta {
        previous: u64,
        current: u64,
        previous_session: String,
    },
    CounterReset {
        previous: u64,
        current: u64,
    },
    Unknown,
    /// The history file could not be read / parsed: no baseline is
    /// claimed (never silently treated as a first session).
    HistoryUnavailable,
}

impl ErrorLogDelta {
    pub fn code(&self) -> &'static str {
        match self {
            ErrorLogDelta::FirstCompleted => "FIRST_COMPLETED",
            ErrorLogDelta::Stable { .. } => "STABLE",
            ErrorLogDelta::Delta { .. } => "DELTA",
            ErrorLogDelta::CounterReset { .. } => "COUNTER_RESET",
            ErrorLogDelta::Unknown => "UNKNOWN",
            ErrorLogDelta::HistoryUnavailable => "HISTORY_UNAVAILABLE",
        }
    }

    /// The COMPLETED session the delta was measured against.
    pub fn previous_session(&self) -> Option<&str> {
        match self {
            ErrorLogDelta::Delta {
                previous_session, ..
            } => Some(previous_session),
            _ => None,
        }
    }

    pub fn text(&self, ru: bool) -> String {
        match (self, ru) {
            (ErrorLogDelta::FirstCompleted, true) => {
                "Журнал ошибок NVMe: первая завершённая сессия для этого диска — сравнивать не с чем".into()
            }
            (ErrorLogDelta::FirstCompleted, false) => {
                "NVMe error log: first completed session for this disk — nothing to compare".into()
            }
            (ErrorLogDelta::Stable { value }, true) => {
                format!("Журнал ошибок NVMe: без изменений с прошлой завершённой сессии ({value})")
            }
            (ErrorLogDelta::Stable { value }, false) => {
                format!("NVMe error log: unchanged since the last completed session ({value})")
            }
            (ErrorLogDelta::Delta { previous, current, .. }, true) => format!(
                "Журнал ошибок NVMe: +{} с прошлой завершённой сессии ({previous} → {current}) — факт, не отказ",
                current - previous
            ),
            (ErrorLogDelta::Delta { previous, current, .. }, false) => format!(
                "NVMe error log: +{} since the last completed session ({previous} → {current}) — a fact, not a failure",
                current - previous
            ),
            (ErrorLogDelta::CounterReset { previous, current }, true) => format!(
                "Журнал ошибок NVMe: счётчик уменьшился ({previous} → {current}) — сброс, прирост не оценивается"
            ),
            (ErrorLogDelta::CounterReset { previous, current }, false) => format!(
                "NVMe error log: counter decreased ({previous} → {current}) — reset, no delta claimed"
            ),
            (ErrorLogDelta::Unknown, true) => "Журнал ошибок NVMe: сравнение невозможно (нет значения)".into(),
            (ErrorLogDelta::Unknown, false) => "NVMe error log: comparison not possible (value missing)".into(),
            (ErrorLogDelta::HistoryUnavailable, true) => {
                "Журнал ошибок NVMe: история сессий недоступна (файл не прочитан) — сравнение не выполнялось".into()
            }
            (ErrorLogDelta::HistoryUnavailable, false) => {
                "NVMe error log: session history unavailable (file not readable) — no comparison made".into()
            }
        }
    }
}

/// The latest COMPLETED session of `identity` (by end time, then order),
/// excluding `except_session` (the session being completed now).
pub fn latest_completed<'a>(
    records: &'a [SessionRecord],
    identity: &str,
    except_session: &str,
) -> Option<&'a SessionRecord> {
    records
        .iter()
        .enumerate()
        .filter(|(_, r)| {
            r.physical_identity == identity
                && r.status == SessionStatus::Completed
                && r.session_id != except_session
        })
        .max_by(|(ia, a), (ib, b)| a.end_time.cmp(&b.end_time).then(ia.cmp(ib)))
        .map(|(_, r)| r)
}

pub fn delta(previous: Option<&SessionRecord>, current: Option<u64>) -> ErrorLogDelta {
    let Some(prev) = previous else {
        return ErrorLogDelta::FirstCompleted;
    };
    match (prev.error_log_entries, current) {
        (Some(p), Some(c)) if c == p => ErrorLogDelta::Stable { value: c },
        (Some(p), Some(c)) if c > p => ErrorLogDelta::Delta {
            previous: p,
            current: c,
            previous_session: prev.session_id.clone(),
        },
        (Some(p), Some(c)) => ErrorLogDelta::CounterReset {
            previous: p,
            current: c,
        },
        _ => ErrorLogDelta::Unknown,
    }
}

/// v1.0: the delta of the session being completed now against the latest
/// COMPATIBLE completed session of the same physical disk — completed,
/// another session, and carrying the counter. A completed session without
/// the counter (other source, read failure) never anchors a delta and
/// never turns the result into FIRST_COMPLETED: when earlier completed
/// sessions exist but none is comparable, the result is UNKNOWN.
pub fn delta_against_history(
    records: &[SessionRecord],
    identity: &str,
    except_session: &str,
    current: Option<u64>,
) -> ErrorLogDelta {
    let completed = |r: &&SessionRecord| {
        r.physical_identity == identity
            && r.status == SessionStatus::Completed
            && r.session_id != except_session
    };
    if current.is_none() {
        return if records.iter().any(|r| completed(&r)) {
            ErrorLogDelta::Unknown
        } else {
            ErrorLogDelta::FirstCompleted
        };
    }
    let comparable: Vec<SessionRecord> = records
        .iter()
        .filter(completed)
        .filter(|r| r.error_log_entries.is_some())
        .cloned()
        .collect();
    match latest_completed(&comparable, identity, except_session) {
        Some(prev) => delta(Some(prev), current),
        None if records.iter().any(|r| completed(&r)) => ErrorLogDelta::Unknown,
        None => ErrorLogDelta::FirstCompleted,
    }
}

fn num(v: Option<u64>) -> String {
    v.map(|n| n.to_string()).unwrap_or_else(|| "null".into())
}

pub fn record_json(r: &SessionRecord) -> String {
    format!(
        "{{\"session_id\": {}, \"physical_identity\": {}, \"start_time\": {}, \"end_time\": {}, \"status\": {}, \"producer_version\": {}, \"storage_state\": {}, \"error_log_entries\": {}, \"media_errors\": {}}}",
        json::string(&r.session_id),
        json::string(&r.physical_identity),
        json::string(&r.start_time),
        json::string(&r.end_time),
        json::string(r.status.code()),
        json::string(&r.producer_version),
        json::string(&r.storage_state),
        num(r.error_log_entries),
        num(r.media_errors),
    )
}

pub fn to_json(records: &[SessionRecord]) -> String {
    let items: Vec<String> = records
        .iter()
        .map(|r| format!("    {}", record_json(r)))
        .collect();
    format!(
        "{{\n  \"format\": \"winstatediag.storage_history/1\",\n  \"sessions\": [\n{}\n  ]\n}}\n",
        items.join(",\n")
    )
}

/// Tolerant parser: unknown / damaged records are skipped, never invented.
pub fn parse(text: &str) -> Vec<SessionRecord> {
    let Some(v) = json::parse(text.trim_start_matches('\u{feff}')) else {
        return Vec::new();
    };
    let Some(json::Value::Arr(items)) = v.get("sessions") else {
        return Vec::new();
    };
    let s = |o: &json::Value, k: &str| o.get(k).and_then(|x| x.as_str()).map(str::to_string);
    let n = |o: &json::Value, k: &str| match o.get(k) {
        Some(json::Value::Num(x)) if *x >= 0.0 => Some(*x as u64),
        _ => None,
    };
    items
        .iter()
        .filter_map(|o| {
            Some(SessionRecord {
                session_id: s(o, "session_id")?,
                physical_identity: s(o, "physical_identity")?,
                start_time: s(o, "start_time").unwrap_or_default(),
                end_time: s(o, "end_time").unwrap_or_default(),
                status: SessionStatus::parse(&s(o, "status")?)?,
                producer_version: s(o, "producer_version").unwrap_or_default(),
                storage_state: s(o, "storage_state").unwrap_or_default(),
                error_log_entries: n(o, "error_log_entries"),
                media_errors: n(o, "media_errors"),
            })
        })
        .collect()
}

/// Strict parser for the whole file: a file that is not valid history JSON
/// is an error (it must never be mistaken for an empty history and then
/// overwritten). Individual damaged records are still skipped.
pub fn parse_strict(text: &str) -> Result<Vec<SessionRecord>, String> {
    let v = json::parse(text.trim_start_matches('\u{feff}'))
        .ok_or_else(|| "history file is not valid JSON".to_string())?;
    match v.get("sessions") {
        Some(json::Value::Arr(_)) => Ok(parse(text)),
        _ => Err("history file has no \"sessions\" array".into()),
    }
}

/// Loads the history. A missing file is an empty history; an unreadable
/// or corrupt file is an error and the file is left untouched.
pub fn load(path: &std::path::Path) -> Result<Vec<SessionRecord>, String> {
    match std::fs::read(path) {
        Ok(bytes) => {
            let text =
                String::from_utf8(bytes).map_err(|_| format!("{}: not UTF-8", path.display()))?;
            parse_strict(&text).map_err(|e| format!("{}: {e}", path.display()))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

/// Atomic save: the history is written to a temporary file in the same
/// directory, flushed, read back and verified, and only then renamed over
/// the previous file (replace-existing). On any error the previous file is
/// left as it was and the temporary file is removed.
pub fn save_atomic(path: &std::path::Path, records: &[SessionRecord]) -> Result<(), String> {
    use std::io::Write;
    let dir = path
        .parent()
        .ok_or_else(|| format!("{}: no parent directory", path.display()))?;
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let tmp = path.with_extension(format!("json.tmp-{}", std::process::id()));
    let text = to_json(records);
    let result = (|| -> Result<(), String> {
        let mut f = std::fs::File::create(&tmp).map_err(|e| format!("{}: {e}", tmp.display()))?;
        f.write_all(text.as_bytes())
            .and_then(|_| f.sync_all())
            .map_err(|e| format!("{}: {e}", tmp.display()))?;
        drop(f);
        let back = std::fs::read_to_string(&tmp).map_err(|e| format!("{}: {e}", tmp.display()))?;
        if parse_strict(&back).map(|r| r.len()) != Ok(records.len()) {
            return Err(format!(
                "{}: verification after write failed",
                tmp.display()
            ));
        }
        std::fs::rename(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// Adds / replaces (same session + disk) a record and trims per disk.
pub fn upsert(records: &mut Vec<SessionRecord>, rec: SessionRecord) {
    records.retain(|r| {
        !(r.session_id == rec.session_id && r.physical_identity == rec.physical_identity)
    });
    let identity = rec.physical_identity.clone();
    records.push(rec);
    let count = records
        .iter()
        .filter(|r| r.physical_identity == identity)
        .count();
    if count > KEEP_PER_DISK {
        let mut drop = count - KEEP_PER_DISK;
        records.retain(|r| {
            if drop > 0 && r.physical_identity == identity {
                drop -= 1;
                false
            } else {
                true
            }
        });
    }
}

/// New per-run session id: `WSD-<yyyyMMdd-HHmmss>-<pid>`.
pub fn new_session_id(stamp_compact: &str) -> String {
    format!("WSD-{stamp_compact}-{}", std::process::id())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(id: &str, end: &str, status: SessionStatus, log: Option<u64>) -> SessionRecord {
        SessionRecord {
            session_id: id.into(),
            physical_identity: "PHYS#Samsung SSD 980 1TB#IDX0".into(),
            start_time: end.into(),
            end_time: end.into(),
            status,
            producer_version: "1.0".into(),
            storage_state: "OK".into(),
            error_log_entries: log,
            media_errors: Some(0),
        }
    }

    #[test]
    fn only_compatible_completed_sessions_anchor_the_delta() {
        let disk = "PHYS#Samsung SSD 980 1TB#IDX0";
        let mut h = vec![
            rec(
                "S1",
                "2026-10-01T10:00:00",
                SessionStatus::Completed,
                Some(5),
            ),
            // Newer completed session WITHOUT the counter: not comparable.
            rec("S2", "2026-10-02T10:00:00", SessionStatus::Completed, None),
            // Cancelled with a value: never a baseline.
            rec(
                "S3",
                "2026-10-03T10:00:00",
                SessionStatus::Cancelled,
                Some(1),
            ),
        ];
        let d = delta_against_history(&h, disk, "NOW", Some(9));
        assert_eq!(d.code(), "DELTA", "{d:?}");
        assert_eq!(d.previous_session(), Some("S1"));
        // Only non-comparable completed sessions: UNKNOWN, never FIRST.
        h.remove(0);
        assert_eq!(
            delta_against_history(&h, disk, "NOW", Some(9)).code(),
            "UNKNOWN"
        );
        // Really nothing completed before: FIRST_COMPLETED.
        h.retain(|r| r.status != SessionStatus::Completed);
        assert_eq!(
            delta_against_history(&h, disk, "NOW", Some(9)).code(),
            "FIRST_COMPLETED"
        );
        // Another disk's history is never compared.
        let other = vec![rec(
            "S9",
            "2026-10-01T10:00:00",
            SessionStatus::Completed,
            Some(1),
        )];
        let mut o = other.clone();
        o[0].physical_identity = "PHYS#B".into();
        assert_eq!(
            delta_against_history(&o, disk, "NOW", Some(9)).code(),
            "FIRST_COMPLETED"
        );
        // The session being completed now is never its own baseline.
        let own = vec![rec(
            "NOW",
            "2026-10-01T10:00:00",
            SessionStatus::Completed,
            Some(1),
        )];
        assert_eq!(
            delta_against_history(&own, disk, "NOW", Some(9)).code(),
            "FIRST_COMPLETED"
        );
    }

    #[test]
    fn stable_counter_between_completed_sessions() {
        let h = vec![rec(
            "S1",
            "2026-10-01T10:00:00",
            SessionStatus::Completed,
            Some(7816),
        )];
        let prev = latest_completed(&h, "PHYS#Samsung SSD 980 1TB#IDX0", "S2");
        assert_eq!(
            delta(prev, Some(7816)),
            ErrorLogDelta::Stable { value: 7816 }
        );
    }

    #[test]
    fn delta_counter_names_both_values_and_is_not_a_failure() {
        let h = vec![rec(
            "S1",
            "2026-10-01T10:00:00",
            SessionStatus::Completed,
            Some(7816),
        )];
        let d = delta(
            latest_completed(&h, "PHYS#Samsung SSD 980 1TB#IDX0", "S2"),
            Some(7830),
        );
        assert_eq!(d.code(), "DELTA");
        assert!(d.text(true).contains("+14"));
        assert!(d.text(true).contains("7816 → 7830"));
        assert!(d.text(true).contains("не отказ"));
    }

    #[test]
    fn cancelled_or_failed_session_is_never_the_baseline() {
        let h = vec![
            rec(
                "S1",
                "2026-10-01T10:00:00",
                SessionStatus::Completed,
                Some(100),
            ),
            rec(
                "S2",
                "2026-10-05T10:00:00",
                SessionStatus::Cancelled,
                Some(150),
            ),
            rec(
                "S3",
                "2026-10-06T10:00:00",
                SessionStatus::Failed,
                Some(160),
            ),
        ];
        let prev = latest_completed(&h, "PHYS#Samsung SSD 980 1TB#IDX0", "S4").unwrap();
        assert_eq!(prev.session_id, "S1");
        assert_eq!(latest_completed(&h, "PHYS#Other#IDX9", "S4"), None);
        assert_eq!(delta(None, Some(5)), ErrorLogDelta::FirstCompleted);
        assert_eq!(delta(Some(prev), Some(90)).code(), "COUNTER_RESET");
        assert_eq!(delta(Some(prev), None), ErrorLogDelta::Unknown);
    }

    #[test]
    fn history_roundtrips_and_trims_per_disk() {
        let mut h = Vec::new();
        for i in 0..(KEEP_PER_DISK + 3) {
            upsert(
                &mut h,
                rec(
                    &format!("S{i}"),
                    &format!("2026-10-01T10:{:02}:00", i % 60),
                    SessionStatus::Completed,
                    Some(i as u64),
                ),
            );
        }
        assert_eq!(h.len(), KEEP_PER_DISK);
        assert_eq!(h[0].session_id, "S3");
        let back = parse(&to_json(&h));
        assert_eq!(back, h);
        // Same session re-recorded replaces, not duplicates.
        upsert(
            &mut h,
            rec(
                "S10",
                "2026-10-09T10:00:00",
                SessionStatus::Completed,
                Some(1),
            ),
        );
        assert_eq!(h.iter().filter(|r| r.session_id == "S10").count(), 1);
        assert!(parse("not json").is_empty());
    }

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("wsd_history_{name}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn atomic_save_replaces_and_leaves_no_temp_file() {
        let d = temp_dir("atomic");
        let p = d.join(FILE_NAME);
        assert_eq!(load(&p), Ok(Vec::new()), "missing file = empty history");
        let h1 = vec![rec(
            "S1",
            "2026-10-01T10:00:00",
            SessionStatus::Completed,
            Some(1),
        )];
        save_atomic(&p, &h1).unwrap();
        let mut h2 = h1.clone();
        upsert(
            &mut h2,
            rec(
                "S2",
                "2026-10-02T10:00:00",
                SessionStatus::Completed,
                Some(2),
            ),
        );
        save_atomic(&p, &h2).unwrap();
        assert_eq!(load(&p).unwrap(), h2);
        let leftovers: Vec<_> = std::fs::read_dir(&d)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name() != FILE_NAME)
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn corrupt_or_partial_history_is_an_error_not_an_empty_history() {
        let d = temp_dir("corrupt");
        let p = d.join(FILE_NAME);
        let good = to_json(&[rec(
            "S1",
            "2026-10-01T10:00:00",
            SessionStatus::Completed,
            Some(1),
        )]);
        // Partial write (truncated file).
        std::fs::write(&p, &good[..good.len() / 2]).unwrap();
        assert!(load(&p).is_err());
        // Valid JSON, but not a history.
        std::fs::write(&p, "{\"x\": 1}").unwrap();
        assert!(load(&p).is_err());
        std::fs::write(&p, [0xffu8, 0xfe, 0x00]).unwrap();
        assert!(load(&p).is_err());
        assert_eq!(delta(None, Some(1)).code(), "FIRST_COMPLETED");
        assert_eq!(
            ErrorLogDelta::HistoryUnavailable.code(),
            "HISTORY_UNAVAILABLE"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn failed_save_keeps_the_previous_history() {
        let d = temp_dir("failsave");
        let p = d.join(FILE_NAME);
        let h1 = vec![rec(
            "S1",
            "2026-10-01T10:00:00",
            SessionStatus::Completed,
            Some(1),
        )];
        save_atomic(&p, &h1).unwrap();
        // The temporary file cannot be created: a directory occupies its name.
        let tmp = p.with_extension(format!("json.tmp-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let mut h2 = h1.clone();
        upsert(
            &mut h2,
            rec(
                "S2",
                "2026-10-02T10:00:00",
                SessionStatus::Completed,
                Some(2),
            ),
        );
        assert!(save_atomic(&p, &h2).is_err());
        assert_eq!(load(&p).unwrap(), h1, "previous history intact");
        // The destination cannot be replaced (it is a directory): error too.
        let _ = std::fs::remove_dir_all(&tmp);
        let q = d.join("dir_target.json");
        std::fs::create_dir_all(&q).unwrap();
        assert!(save_atomic(&q, &h2).is_err());
        assert!(
            !q.with_extension(format!("json.tmp-{}", std::process::id()))
                .exists()
        );
        let _ = std::fs::remove_dir_all(&d);
    }
}
