//! v0.4.5 freeze / hang incident intelligence (read-only).
//!
//! An *incident* is one unexpected stop of Windows: Kernel-Power 41 and/or
//! EventLog 6008 logged at the next boot (one boot = one incident). Those
//! events carry the boot time, not the moment the machine stopped, so the
//! collector takes the last System event written before that boot (the
//! machine's last sign of life) and reads the System / Application events of
//! the 10 minutes before it, plus `%SystemRoot%\LiveKernelReports` (listing
//! only). This module turns that into a conservative verdict:
//!
//! * hang: CONFIRMED only with direct evidence (App Hang 1002, a display
//!   TDR / LiveKernelEvent, a WATCHDOG live kernel report); otherwise
//!   NOT CONFIRMED — an unexpected shutdown can also be a reset or power
//!   loss;
//! * BSOD: REGISTERED only with a BugCheck (KP41 BugcheckCode ≠ 0 or a
//!   BugCheck event of the same boot);
//! * probable subsystem GPU / STORAGE / DRIVER / UNKNOWN with confidence
//!   HIGH / MEDIUM / LOW, from the correlated events only. No culprit is
//!   ever invented: without signals the cause is NOT DETERMINED.

use crate::deep_checks::json;

/// Evidence prefix (manifest module `freeze_hang_incidents`).
pub const EVIDENCE_PREFIX: &str = "Incidents_";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorrelatedEvent {
    pub time: String,
    pub log: String,
    pub provider: String,
    pub id: u32,
    pub level: u32,
    pub message: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LiveKernelReport {
    pub name: String,
    /// Report folder (WATCHDOG, NDIS, USBHUB3, …).
    pub folder: String,
    pub size: u64,
    pub time: String,
    /// v1.0: full path of the report file (empty in older evidence).
    pub path: String,
}

impl LiveKernelReport {
    /// v1.0 identity of a report FILE: full path (case-insensitive; folder +
    /// name when the path is missing) + size + time. Two reports with the
    /// same file name in different folders, or the same name rewritten with
    /// another size / time, are different reports; only the very same file
    /// listed twice is one.
    pub fn identity(&self) -> (String, u64, String) {
        let path = if self.path.trim().is_empty() {
            format!("{}\\{}", self.folder.trim(), self.name.trim())
        } else {
            self.path.trim().to_string()
        };
        (path.to_lowercase(), self.size, self.time.clone())
    }
}

/// Removes repeated listings of the same report file (`identity`), keeping
/// the first occurrence and the order.
pub fn dedup_live_kernel_reports(reports: Vec<LiveKernelReport>) -> Vec<LiveKernelReport> {
    let mut seen = Vec::new();
    reports
        .into_iter()
        .filter(|r| {
            let id = r.identity();
            if seen.contains(&id) {
                false
            } else {
                seen.push(id);
                true
            }
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Incident {
    /// Time the incident was logged (the following boot).
    pub logged: String,
    /// Boot start (Kernel-General 12), when found.
    pub boot: String,
    /// Last System event before that boot (last sign of life).
    pub last_activity: String,
    /// "KP41" and/or "EL6008".
    pub sources: Vec<String>,
    /// Kernel-Power 41 BugcheckCode (0 = none recorded).
    pub bugcheck_code: u64,
    pub events: Vec<CorrelatedEvent>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Subsystem {
    Gpu,
    Storage,
    Driver,
    Unknown,
}

impl Subsystem {
    pub fn code(self) -> &'static str {
        match self {
            Subsystem::Gpu => "GPU",
            Subsystem::Storage => "STORAGE",
            Subsystem::Driver => "DRIVER",
            Subsystem::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    High,
    Medium,
    Low,
}

impl Confidence {
    pub fn code(self) -> &'static str {
        match self {
            Confidence::High => "HIGH",
            Confidence::Medium => "MEDIUM",
            Confidence::Low => "LOW",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub hang_confirmed: bool,
    pub bsod_registered: bool,
    /// `None` = CAUSE NOT DETERMINED.
    pub subsystem: Option<Subsystem>,
    pub confidence: Confidence,
    /// Human-readable evidence lines that produced the verdict.
    pub signals: Vec<String>,
    /// v1.0.1: the dump analysis of this boot's BugCheck, when it names a
    /// specific driver. It outranks the event-signal subsystem guess.
    pub dump_cause: Option<DumpCause>,
}

/// v1.0.1: cause established by the crash-dump analysis of the same boot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DumpCause {
    pub dump: String,
    pub bugcheck: String,
    /// e.g. `RvNetMP60.sys`.
    pub module: String,
    /// Software owner and whether the installed file confirms it.
    pub owner: Option<(String, bool)>,
    /// `HIGH` / `MEDIUM` / `PARSER_INCOMPLETE` (never absolute).
    pub confidence: String,
}

impl DumpCause {
    pub fn label(&self) -> String {
        match &self.owner {
            Some((o, true)) => format!("{} / {o}", self.module),
            Some((o, false)) => format!("{} / {o} (by module name)", self.module),
            None => self.module.clone(),
        }
    }
}

impl Verdict {
    /// "HANG CONFIRMED / BSOD NOT REGISTERED / CAUSE NOT DETERMINED".
    pub fn headline(&self) -> String {
        format!(
            "{} / {} / {}",
            if self.hang_confirmed {
                "HANG CONFIRMED"
            } else {
                "HANG NOT CONFIRMED"
            },
            if self.bsod_registered {
                "BSOD REGISTERED"
            } else {
                "BSOD NOT REGISTERED"
            },
            match (&self.dump_cause, self.subsystem) {
                (Some(d), _) => format!(
                    "PROBABLE DRIVER {} ({}, dump analysis)",
                    d.label(),
                    d.confidence
                ),
                (None, Some(s)) => format!(
                    "PROBABLE SUBSYSTEM {} ({})",
                    s.code(),
                    self.confidence.code()
                ),
                (None, None) => "CAUSE NOT DETERMINED".into(),
            }
        )
    }
}

/// Signal strength: kernel-level signals (TDR, LiveKernelEvent, storage
/// resets) weigh 2, softer ones 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Signal {
    subsystem: Subsystem,
    kernel: bool,
    hang: bool,
}

fn lc(s: &str) -> String {
    s.to_ascii_lowercase()
}

/// Classification of one correlated event (None = context only).
fn signal_of(e: &CorrelatedEvent) -> Option<Signal> {
    let p = lc(&e.provider);
    let m = lc(&e.message);
    let gpu_driver = ["nvlddmkm", "amdkmdag", "amdwddmg", "igfx", "dxgkrnl"];
    // Display TDR: "Display driver … stopped responding and has
    // successfully recovered" (Display 4101).
    if (p == "display" && e.id == 4101) || gpu_driver.iter().any(|g| p.contains(g)) {
        return Some(Signal {
            subsystem: Subsystem::Gpu,
            kernel: true,
            hang: p == "display" || m.contains("stopped responding"),
        });
    }
    if m.contains("livekernelevent") {
        // 141 / 117 / 1a8 = video engine / TDR live dumps.
        let gpu = ["141", "117", "1a8", "watchdog"]
            .iter()
            .any(|c| m.contains(c));
        return Some(Signal {
            subsystem: if gpu {
                Subsystem::Gpu
            } else {
                Subsystem::Driver
            },
            kernel: true,
            hang: true,
        });
    }
    if [
        "storport", "stornvme", "storahci", "iastor", "volmgr", "ntfs",
    ]
    .iter()
    .any(|s| p.contains(s))
        || p == "disk"
    {
        return Some(Signal {
            subsystem: Subsystem::Storage,
            kernel: e.level <= 2 || matches!(e.id, 129 | 153 | 157 | 7 | 11 | 51),
            hang: false,
        });
    }
    if p == "application hang" && e.id == 1002 {
        return Some(Signal {
            subsystem: Subsystem::Unknown,
            kernel: false,
            hang: true,
        });
    }
    if p == "service control manager"
        && matches!(e.id, 7000 | 7009 | 7011 | 7023 | 7024 | 7031 | 7034)
    {
        return Some(Signal {
            subsystem: Subsystem::Driver,
            kernel: false,
            hang: false,
        });
    }
    None
}

fn lkr_signal(r: &LiveKernelReport) -> Signal {
    let f = r.folder.to_ascii_uppercase();
    Signal {
        subsystem: if f.contains("WATCHDOG") && !f.contains("PDC") {
            Subsystem::Gpu
        } else {
            Subsystem::Driver
        },
        kernel: true,
        hang: true,
    }
}

/// Seconds since 0000 of an ISO `YYYY-MM-DDTHH:MM:SS` (comparison only).
fn secs(t: &str) -> Option<i64> {
    let b = t.as_bytes();
    if b.len() < 19 {
        return None;
    }
    let n = |r: std::ops::Range<usize>| t.get(r)?.parse::<i64>().ok();
    let (y, mo, d) = (n(0..4)?, n(5..7)?, n(8..10)?);
    let (h, mi, s) = (n(11..13)?, n(14..16)?, n(17..19)?);
    // Days from a simple civil calendar (exact enough for ordering and
    // minute windows inside a year boundary).
    let days = y * 372 + mo * 31 + d;
    Some(((days * 24 + h) * 60 + mi) * 60 + s)
}

/// Live kernel reports written within the incident window (10 minutes
/// before the last sign of life until the boot).
pub fn reports_in_window<'a>(
    inc: &Incident,
    reports: &'a [LiveKernelReport],
) -> Vec<&'a LiveKernelReport> {
    let (Some(last), boot) = (secs(&inc.last_activity), secs(&inc.boot)) else {
        return Vec::new();
    };
    let end = boot.unwrap_or(last + 120);
    reports
        .iter()
        .filter(|r| secs(&r.time).is_some_and(|t| t >= last - 600 && t <= end))
        .collect()
}

/// Conservative verdict of one incident. `bugcheck_same_boot`: a BugCheck
/// event (WER 1001 / KP41 code) was logged for the same boot.
pub fn classify(inc: &Incident, reports: &[LiveKernelReport], bugcheck_same_boot: bool) -> Verdict {
    let mut signals: Vec<(Signal, String)> = inc
        .events
        .iter()
        .filter_map(|e| {
            signal_of(e).map(|s| {
                (
                    s,
                    format!(
                        "{} {} #{} {}",
                        e.time.replace('T', " "),
                        e.provider,
                        e.id,
                        short(&e.message)
                    ),
                )
            })
        })
        .collect();
    for r in reports_in_window(inc, reports) {
        signals.push((
            lkr_signal(r),
            format!(
                "{} LiveKernelReports\\{}\\{}",
                r.time.replace('T', " "),
                r.folder,
                r.name
            ),
        ));
    }
    let hang_confirmed = signals.iter().any(|(s, _)| s.hang);
    let bsod_registered = inc.bugcheck_code != 0 || bugcheck_same_boot;
    let mut score = [0u32; 3];
    let mut kernel = [0u32; 3];
    for (s, _) in &signals {
        let i = match s.subsystem {
            Subsystem::Gpu => 0,
            Subsystem::Storage => 1,
            Subsystem::Driver => 2,
            Subsystem::Unknown => continue,
        };
        score[i] += if s.kernel { 2 } else { 1 };
        kernel[i] += u32::from(s.kernel);
    }
    let best = (0..3).max_by_key(|&i| score[i]).unwrap_or(0);
    let tie = (0..3).filter(|&i| score[i] == score[best]).count() > 1;
    let (subsystem, confidence) = if score[best] == 0 || tie {
        (None, Confidence::Low)
    } else {
        let sub = [Subsystem::Gpu, Subsystem::Storage, Subsystem::Driver][best];
        let conf = if kernel[best] >= 2 && score[best] >= 4 {
            Confidence::High
        } else if kernel[best] >= 1 {
            Confidence::Medium
        } else {
            Confidence::Low
        };
        (Some(sub), conf)
    };
    Verdict {
        hang_confirmed,
        bsod_registered,
        subsystem,
        confidence,
        signals: signals.into_iter().map(|(_, l)| l).collect(),
        dump_cause: None,
    }
}

fn short(m: &str) -> String {
    let t: String = m.chars().take(120).collect();
    if m.chars().count() > 120 {
        format!("{t}…")
    } else {
        t
    }
}

fn s(v: &json::Value, k: &str) -> String {
    v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string()
}

fn num(v: &json::Value, k: &str) -> f64 {
    match v.get(k) {
        Some(json::Value::Num(n)) => *n,
        Some(json::Value::Str(t)) => t.trim().parse().unwrap_or(0.0),
        _ => 0.0,
    }
}

fn arr(v: Option<&json::Value>) -> Vec<json::Value> {
    match v {
        Some(json::Value::Arr(a)) => a.clone(),
        Some(o @ json::Value::Obj(_)) => vec![o.clone()],
        _ => Vec::new(),
    }
}

/// `incidents` array of the crash inventory JSON.
pub fn parse_incidents(v: Option<&json::Value>) -> Vec<Incident> {
    arr(v)
        .iter()
        .map(|i| Incident {
            logged: s(i, "t"),
            boot: s(i, "boot"),
            last_activity: s(i, "last"),
            sources: match i.get("src") {
                Some(json::Value::Arr(a)) => a
                    .iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect(),
                Some(json::Value::Str(t)) => vec![t.clone()],
                _ => Vec::new(),
            },
            bugcheck_code: num(i, "code").max(0.0) as u64,
            events: arr(i.get("ev"))
                .iter()
                .map(|e| CorrelatedEvent {
                    time: s(e, "t"),
                    log: s(e, "log"),
                    provider: s(e, "prov"),
                    id: num(e, "id") as u32,
                    level: num(e, "lvl") as u32,
                    message: s(e, "msg"),
                })
                .collect(),
        })
        .collect()
}

pub fn parse_live_kernel_reports(v: Option<&json::Value>) -> Vec<LiveKernelReport> {
    dedup_live_kernel_reports(
        arr(v)
            .iter()
            .map(|r| LiveKernelReport {
                name: s(r, "name"),
                folder: s(r, "dir"),
                size: num(r, "size").max(0.0) as u64,
                time: s(r, "t"),
                path: s(r, "path"),
            })
            .collect(),
    )
}

/// Evidence JSON (`Incidents_<stamp>.json`): every incident with its
/// verdict, correlated events and the live kernel reports.
/// v1.0.1: one sampling window and counting rule for EXPC stage 07, the
/// crash inventory, Incidents.json and the crash Details.
pub const WINDOW_DAYS: u32 = 30;
pub const COUNTING_RULE: &str = "one unexpected shutdown = one boot: Kernel-Power 41 and EventLog 6008 logged within 15 minutes are one incident; BugCheck = WER 1001 or Kernel-Power 41 with a non-zero code, deduplicated within 15 minutes";
/// Incidents with full event timelines (the count above is the total).
pub const MAX_LISTED_INCIDENTS: usize = 5;

pub fn to_json(
    incidents: &[(Incident, Verdict)],
    unexpected_shutdowns: usize,
    reports: &[LiveKernelReport],
) -> String {
    let q = json::string;
    let mut o = String::from("{\n");
    let status = if incidents.is_empty() {
        "NO_INCIDENTS"
    } else if incidents.iter().any(|(_, v)| v.hang_confirmed) {
        "HANG_CONFIRMED"
    } else {
        "UNEXPECTED_SHUTDOWN"
    };
    o.push_str(&format!("  \"status\": {},\n", q(status)));
    o.push_str(&format!(
        "  \"unexpected_shutdowns\": {unexpected_shutdowns},\n"
    ));
    o.push_str(&format!("  \"window_days\": {WINDOW_DAYS},\n"));
    o.push_str(&format!("  \"counting_rule\": {},\n", q(COUNTING_RULE)));
    o.push_str(&format!("  \"incident_count\": {},\n", incidents.len()));
    o.push_str("  \"incidents\": [");
    for (n, (i, v)) in incidents.iter().enumerate() {
        o.push_str(if n == 0 { "\n" } else { ",\n" });
        o.push_str("    {\n");
        o.push_str(&format!("      \"logged\": {},\n", q(&i.logged)));
        o.push_str(&format!("      \"boot\": {},\n", q(&i.boot)));
        o.push_str(&format!(
            "      \"last_activity\": {},\n",
            q(&i.last_activity)
        ));
        o.push_str(&format!(
            "      \"sources\": [{}],\n",
            i.sources
                .iter()
                .map(|x| q(x))
                .collect::<Vec<_>>()
                .join(", ")
        ));
        o.push_str(&format!("      \"bugcheck_code\": {},\n", i.bugcheck_code));
        o.push_str(&format!(
            "      \"hang\": {},\n",
            q(if v.hang_confirmed {
                "CONFIRMED"
            } else {
                "NOT_CONFIRMED"
            })
        ));
        o.push_str(&format!(
            "      \"bsod\": {},\n",
            q(if v.bsod_registered {
                "REGISTERED"
            } else {
                "NOT_REGISTERED"
            })
        ));
        o.push_str(&format!(
            "      \"probable_subsystem\": {},\n",
            q(v.subsystem
                .map(|s| s.code())
                .unwrap_or("CAUSE_NOT_DETERMINED"))
        ));
        o.push_str(&format!(
            "      \"confidence\": {},\n",
            q(v.confidence.code())
        ));
        o.push_str(&format!(
            "      \"dump_cause\": {},\n",
            match &v.dump_cause {
                None => "null".to_string(),
                Some(d) => format!(
                    "{{\"dump\": {}, \"bugcheck\": {}, \"module\": {}, \"software_owner\": {}, \"owner_confirmed\": {}, \"confidence\": {}}}",
                    q(&d.dump),
                    q(&d.bugcheck),
                    q(&d.module),
                    d.owner
                        .as_ref()
                        .map(|(o, _)| q(o))
                        .unwrap_or_else(|| "null".into()),
                    d.owner.as_ref().is_some_and(|(_, c)| *c),
                    q(&d.confidence)
                ),
            }
        ));
        o.push_str(&format!(
            "      \"signals\": [{}],\n",
            v.signals
                .iter()
                .map(|x| q(x))
                .collect::<Vec<_>>()
                .join(", ")
        ));
        o.push_str("      \"events\": [");
        for (k, e) in i.events.iter().enumerate() {
            o.push_str(if k == 0 { "\n" } else { ",\n" });
            o.push_str(&format!(
                "        {{ \"time\": {}, \"log\": {}, \"provider\": {}, \"id\": {}, \"level\": {}, \"message\": {} }}",
                q(&e.time),
                q(&e.log),
                q(&e.provider),
                e.id,
                e.level,
                q(&e.message)
            ));
        }
        o.push_str(if i.events.is_empty() {
            "]\n"
        } else {
            "\n      ]\n"
        });
        o.push_str("    }");
    }
    o.push_str(if incidents.is_empty() {
        "],\n"
    } else {
        "\n  ],\n"
    });
    o.push_str("  \"live_kernel_reports\": [");
    for (k, r) in reports.iter().enumerate() {
        o.push_str(if k == 0 { "\n" } else { ",\n" });
        o.push_str(&format!(
            "    {{ \"folder\": {}, \"name\": {}, \"path\": {}, \"size\": {}, \"time\": {} }}",
            q(&r.folder),
            q(&r.name),
            q(&r.path),
            r.size,
            q(&r.time)
        ));
    }
    o.push_str(if reports.is_empty() { "]\n" } else { "\n  ]\n" });
    o.push_str("}\n");
    o
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn ev(time: &str, provider: &str, id: u32, level: u32, msg: &str) -> CorrelatedEvent {
        CorrelatedEvent {
            time: time.into(),
            log: "System".into(),
            provider: provider.into(),
            id,
            level,
            message: msg.into(),
        }
    }

    pub fn incident(events: Vec<CorrelatedEvent>, code: u64) -> Incident {
        Incident {
            logged: "2026-10-04T21:14:10".into(),
            boot: "2026-10-04T21:13:40".into(),
            last_activity: "2026-10-04T20:58:02".into(),
            sources: vec!["KP41".into(), "EL6008".into()],
            bugcheck_code: code,
            events,
        }
    }

    #[test]
    fn no_signals_means_cause_not_determined_and_no_hang_claim() {
        let v = classify(&incident(vec![], 0), &[], false);
        assert!(!v.hang_confirmed, "a reset or power loss is possible");
        assert!(!v.bsod_registered);
        assert_eq!(v.subsystem, None);
        assert_eq!(
            v.headline(),
            "HANG NOT CONFIRMED / BSOD NOT REGISTERED / CAUSE NOT DETERMINED"
        );
    }

    #[test]
    fn tdr_and_nvlddmkm_before_the_stop_point_to_gpu_with_high_confidence() {
        let inc = incident(
            vec![
                ev(
                    "2026-10-04T20:55:10",
                    "Display",
                    4101,
                    3,
                    "Display driver nvlddmkm stopped responding and has successfully recovered.",
                ),
                ev(
                    "2026-10-04T20:57:44",
                    "nvlddmkm",
                    153,
                    2,
                    "Restarting TDR occurred on GPUID:100",
                ),
                ev(
                    "2026-10-04T20:56:00",
                    "Application Hang",
                    1002,
                    2,
                    "The program explorer.exe stopped interacting with Windows",
                ),
            ],
            0,
        );
        let v = classify(&inc, &[], false);
        assert!(v.hang_confirmed);
        assert!(!v.bsod_registered);
        assert_eq!(v.subsystem, Some(Subsystem::Gpu));
        assert_eq!(v.confidence, Confidence::High);
        assert!(
            v.headline()
                .starts_with("HANG CONFIRMED / BSOD NOT REGISTERED / PROBABLE SUBSYSTEM GPU")
        );
        assert_eq!(v.signals.len(), 3);
    }

    #[test]
    fn single_storage_reset_is_medium_and_app_hang_alone_names_no_subsystem() {
        let st = classify(
            &incident(
                vec![ev(
                    "2026-10-04T20:57:00",
                    "stornvme",
                    11,
                    2,
                    "The driver detected a controller error on \\Device\\RaidPort1.",
                )],
                0,
            ),
            &[],
            false,
        );
        assert_eq!(st.subsystem, Some(Subsystem::Storage));
        assert_eq!(st.confidence, Confidence::Medium);
        assert!(!st.hang_confirmed, "storage error alone is not a hang");
        let app = classify(
            &incident(
                vec![ev(
                    "2026-10-04T20:57:00",
                    "Application Hang",
                    1002,
                    2,
                    "chrome.exe hang",
                )],
                0,
            ),
            &[],
            false,
        );
        assert!(app.hang_confirmed);
        assert_eq!(app.subsystem, None, "an app hang names no culprit");
    }

    #[test]
    fn bugcheck_code_or_same_boot_bugcheck_registers_bsod_and_ties_stay_undetermined() {
        assert!(classify(&incident(vec![], 0x139), &[], false).bsod_registered);
        assert!(classify(&incident(vec![], 0), &[], true).bsod_registered);
        let tie = classify(
            &incident(
                vec![
                    ev("2026-10-04T20:57:00", "stornvme", 11, 2, "controller error"),
                    ev(
                        "2026-10-04T20:57:10",
                        "nvlddmkm",
                        13,
                        2,
                        "Graphics exception",
                    ),
                ],
                0,
            ),
            &[],
            false,
        );
        assert_eq!(tie.subsystem, None, "conflicting signals: no guess");
    }

    #[test]
    fn watchdog_live_kernel_report_in_window_counts_others_do_not() {
        let r = |t: &str, f: &str| LiveKernelReport {
            name: "WATCHDOG-20261004-2057.dmp".into(),
            folder: f.into(),
            size: 1,
            time: t.into(),
            ..Default::default()
        };
        let reports = [
            r("2026-10-04T20:57:30", "WATCHDOG"),
            r("2026-09-01T10:00:00", "NDIS"),
        ];
        let inc = incident(vec![], 0);
        assert_eq!(reports_in_window(&inc, &reports).len(), 1);
        let v = classify(&inc, &reports, false);
        assert!(v.hang_confirmed);
        assert_eq!(v.subsystem, Some(Subsystem::Gpu));
        assert_eq!(v.confidence, Confidence::Medium);
    }

    #[test]
    fn evidence_json_is_parseable_and_carries_the_verdict() {
        let inc = incident(
            vec![ev("2026-10-04T20:57:44", "nvlddmkm", 153, 2, "TDR \"x\"")],
            0,
        );
        let v = classify(&inc, &[], false);
        let j = to_json(&[(inc, v)], 3, &[]);
        let parsed = json::parse(&j).expect("valid JSON");
        assert_eq!(
            parsed.get("status").and_then(|x| x.as_str()),
            Some("UNEXPECTED_SHUTDOWN")
        );
        assert!(j.contains("\"probable_subsystem\": \"GPU\""));
        assert!(j.contains("\"unexpected_shutdowns\": 3"));
        let empty = to_json(&[], 0, &[]);
        assert!(json::parse(&empty).is_some());
    }

    #[test]
    fn parses_collector_shapes() {
        let v = json::parse(r#"{"incidents":[{"t":"2026-10-04T21:14:10","boot":"2026-10-04T21:13:40","last":"2026-10-04T20:58:02","src":["KP41","EL6008"],"code":"0","ev":{"t":"2026-10-04T20:57:44","log":"System","prov":"nvlddmkm","id":153,"lvl":2,"msg":"x"}}],"lkr":[{"name":"a.dmp","dir":"WATCHDOG","size":10,"t":"2026-10-04T20:57:30"}]}"#).unwrap();
        let inc = parse_incidents(v.get("incidents"));
        assert_eq!(inc.len(), 1);
        assert_eq!(inc[0].events.len(), 1, "single event object accepted");
        assert_eq!(inc[0].sources, ["KP41", "EL6008"]);
        let lkr = parse_live_kernel_reports(v.get("lkr"));
        assert_eq!(lkr[0].folder, "WATCHDOG");
    }

    /// v1.0: live kernel reports are deduplicated by full path + size +
    /// time — never by the file name alone.
    #[test]
    fn live_kernel_reports_dedup_by_full_path_size_and_time() {
        let v = json::parse(r#"{"lkr":[
            {"name":"WATCHDOG-20261004-2057.dmp","dir":"WATCHDOG","path":"C:\\Windows\\LiveKernelReports\\WATCHDOG\\WATCHDOG-20261004-2057.dmp","size":10,"t":"2026-10-04T20:57:30"},
            {"name":"WATCHDOG-20261004-2057.dmp","dir":"WATCHDOG","path":"C:\\WINDOWS\\LiveKernelReports\\WATCHDOG\\WATCHDOG-20261004-2057.dmp","size":10,"t":"2026-10-04T20:57:30"},
            {"name":"WATCHDOG-20261004-2057.dmp","dir":"old","path":"C:\\Windows\\LiveKernelReports\\WATCHDOG\\old\\WATCHDOG-20261004-2057.dmp","size":10,"t":"2026-10-04T20:57:30"},
            {"name":"WATCHDOG-20261004-2057.dmp","dir":"WATCHDOG","path":"C:\\Windows\\LiveKernelReports\\WATCHDOG\\WATCHDOG-20261004-2057.dmp","size":12,"t":"2026-10-05T08:00:00"},
            {"name":"a.dmp","dir":"NDIS","size":3,"t":"2026-10-01T10:00:00"},
            {"name":"a.dmp","dir":"NDIS","size":3,"t":"2026-10-01T10:00:00"}
        ]}"#)
        .unwrap();
        let r = parse_live_kernel_reports(v.get("lkr"));
        assert_eq!(r.len(), 4, "{r:?}");
        assert_eq!(
            r.iter()
                .filter(|x| x.name == "WATCHDOG-20261004-2057.dmp")
                .count(),
            3,
            "same name, different folder / size / time = different reports"
        );
        assert!(r[0].path.ends_with("WATCHDOG-20261004-2057.dmp"));
        let js = to_json(&[], 0, &r);
        assert!(
            js.contains("\"path\": \"C:\\\\Windows\\\\LiveKernelReports"),
            "{js}"
        );
    }
}
