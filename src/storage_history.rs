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
}

impl ErrorLogDelta {
    pub fn code(&self) -> &'static str {
        match self {
            ErrorLogDelta::FirstCompleted => "FIRST_COMPLETED",
            ErrorLogDelta::Stable { .. } => "STABLE",
            ErrorLogDelta::Delta { .. } => "DELTA",
            ErrorLogDelta::CounterReset { .. } => "COUNTER_RESET",
            ErrorLogDelta::Unknown => "UNKNOWN",
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
}
