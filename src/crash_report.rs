//! v1.0 items 38–49: the crash analyzer REPORT model.
//!
//! One pure model feeds every view — the Hardware card counters, the
//! crash Details window, its Copy / Save text and the session evidence —
//! so the numbers can never disagree (item 40 / 49). Sections:
//!
//! * СОСТОЯНИЕ          — one conservative headline;
//! * ЧТО ОБНАРУЖЕНО     — counted facts (BugChecks, dumps, shutdowns,
//!                        LiveKernelReports grouped by kind);
//! * ИНЦИДЕНТЫ          — one table row per BSOD / unexpected shutdown;
//! * ВЕРОЯТНАЯ ПРИЧИНА  — evidence in priority order: dump analysis →
//!                        Driver Audit → incident signals → live reports;
//!                        hardware vs system state kept apart (item 46);
//! * ЧТО ПРОВЕРИТЬ      — actionable, never automatic (item 48);
//! * raw WinDbg output  — collapsible, last (rendered by the window).
//!
//! Read-only: this only formats evidence already collected.

use crate::crash_dump::{Confidence, DebuggerStatus, DumpAnalysis, DumpKind, Inventory};
use crate::incidents::LiveKernelReport;

/// The single source of every crash counter (item 40).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Counters {
    /// Unexpected shutdowns (Kernel-Power 41 / EventLog 6008, one per
    /// boot) — never fewer than the incidents listed.
    pub unexpected_shutdowns: usize,
    /// BugCheck events (WER 1001 / Kernel-Power 41 with a code, deduped).
    pub bugchecks: usize,
    pub dumps: usize,
    pub minidumps: usize,
    pub full_dumps: usize,
    pub live_kernel_reports: usize,
    pub incidents: usize,
}

impl Counters {
    pub fn of(inv: &Inventory) -> Self {
        Self {
            unexpected_shutdowns: inv.unexpected_shutdowns.max(inv.incidents.len()),
            bugchecks: inv.bugchecks.len(),
            dumps: inv.dumps.len(),
            minidumps: inv
                .dumps
                .iter()
                .filter(|d| d.kind == DumpKind::Mini)
                .count(),
            full_dumps: inv
                .dumps
                .iter()
                .filter(|d| d.kind == DumpKind::Full)
                .count(),
            live_kernel_reports: inv.live_kernel_reports.len(),
            incidents: inv.incidents.len(),
        }
    }

    /// The one counters line used by the card, Details, export and
    /// evidence.
    pub fn line(&self, ru: bool) -> String {
        if ru {
            format!(
                "За {} дн.: неожиданные выключения: {} · BugCheck / BSOD: {} · Дампы (все файлы): {} · LiveKernelReports: {}",
                crate::incidents::WINDOW_DAYS,
                self.unexpected_shutdowns,
                self.bugchecks,
                self.dumps,
                self.live_kernel_reports
            )
        } else {
            format!(
                "Last {} days: unexpected shutdowns: {} · BugCheck / BSOD: {} · Dumps (all files): {} · LiveKernelReports: {}",
                crate::incidents::WINDOW_DAYS,
                self.unexpected_shutdowns,
                self.bugchecks,
                self.dumps,
                self.live_kernel_reports
            )
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Ok,
    Info,
    Attention,
    Problem,
}

impl Level {
    pub fn code(self) -> &'static str {
        match self {
            Level::Ok => "OK",
            Level::Info => "INFO",
            Level::Attention => "ATTENTION",
            Level::Problem => "PROBLEM",
        }
    }
}

// ---------------------------------------------------------------------
// LiveKernelReports (item 39)
// ---------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LkrGroup {
    pub folder: String,
    pub count: usize,
    pub first: String,
    pub last: String,
    pub meaning: String,
    /// The kind points at the graphics driver (TDR / video watchdog).
    pub graphics: bool,
}

/// What a LiveKernelReports folder means. A live kernel report is written
/// when Windows RECOVERED from a kernel problem — it is not a BSOD.
pub fn lkr_meaning(folder: &str, ru: bool) -> (String, bool) {
    let f = folder.to_ascii_uppercase();
    let (ru_t, en_t, gfx) = if f.contains("PDC") || f.contains("POW32K") || f.contains("POWER") {
        (
            "таймаут управления питанием (сон / пробуждение)",
            "power-management timeout (sleep / resume)",
            false,
        )
    } else if f.contains("WATCHDOG") || f.contains("DXG") || f.contains("VIDEO") {
        (
            "видеодрайвер не ответил вовремя (TDR); Windows восстановила работу без BSOD",
            "graphics driver did not respond in time (TDR); Windows recovered without a BSOD",
            true,
        )
    } else if f.contains("USB") {
        (
            "сбой контроллера / хаба USB, восстановлен",
            "USB controller / hub failure, recovered",
            false,
        )
    } else if f.contains("NDIS") {
        (
            "сетевой драйвер перестал отвечать, восстановлен",
            "network driver stopped responding, recovered",
            false,
        )
    } else {
        (
            "живой дамп ядра: сбой компонента ядра, восстановлен без BSOD",
            "live kernel dump: kernel component failure, recovered without a BSOD",
            false,
        )
    };
    ((if ru { ru_t } else { en_t }).to_string(), gfx)
}

pub fn lkr_groups(reports: &[LiveKernelReport], ru: bool) -> Vec<LkrGroup> {
    let mut out: Vec<LkrGroup> = Vec::new();
    for r in reports {
        // v1.0 evidence fix: grouped by report KIND (first folder below
        // LiveKernelReports), so `WATCHDOG\old\…` counts as WATCHDOG; each
        // distinct object (path + size + time) is still counted once.
        let folder = r.kind();
        match out
            .iter_mut()
            .find(|g| g.folder.eq_ignore_ascii_case(&folder))
        {
            Some(g) => {
                g.count += 1;
                if !r.time.is_empty() && (g.first.is_empty() || r.time < g.first) {
                    g.first = r.time.clone();
                }
                if r.time > g.last {
                    g.last = r.time.clone();
                }
            }
            None => {
                let (meaning, graphics) = lkr_meaning(&folder, ru);
                out.push(LkrGroup {
                    folder,
                    count: 1,
                    first: r.time.clone(),
                    last: r.time.clone(),
                    meaning,
                    graphics,
                });
            }
        }
    }
    out.sort_by(|a, b| b.last.cmp(&a.last));
    out
}

// ---------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncidentRow {
    pub time: String,
    pub kind: String,
    pub code: String,
    pub dump: String,
    pub cause: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub level: Level,
    pub state: String,
    pub found: Vec<String>,
    pub incidents: Vec<IncidentRow>,
    pub cause: Vec<String>,
    /// v1.0.1 «ПОЧЕМУ СДЕЛАН ВЫВОД»: the evidence behind the cause.
    pub why: Vec<String>,
    pub checks: Vec<String>,
    pub counters: Counters,
}

fn t(ru: bool, a: &str, b: &str) -> String {
    if ru { a.to_string() } else { b.to_string() }
}

fn day(iso: &str) -> String {
    iso.replace('T', " ").chars().take(16).collect()
}

fn minutes(iso: &str) -> Option<i64> {
    let n = |r: std::ops::Range<usize>| iso.get(r)?.parse::<i64>().ok();
    let days = n(0..4)? * 372 + n(5..7)? * 31 + n(8..10)?;
    Some((days * 24 + n(11..13)?) * 60 + n(14..16)?)
}

/// A third-party driver named by a completed analysis with at least
/// MEDIUM confidence: the strongest evidence there is (item 45).
fn strongest_analysis(analyses: &[DumpAnalysis]) -> Option<&DumpAnalysis> {
    analyses
        .iter()
        .filter(|a| matches!(a.confidence, Confidence::High | Confidence::Medium))
        .max_by_key(|a| a.confidence)
}

fn module_label(a: &DumpAnalysis) -> Option<String> {
    a.probable_module()
}

pub fn build(inv: &Inventory, analyses: &[DumpAnalysis], ru: bool) -> Report {
    let counters = Counters::of(inv);
    let lkr = lkr_groups(&inv.live_kernel_reports, ru);
    let verdicts = crate::crash_dump::incident_verdicts(inv, analyses);
    let best = strongest_analysis(analyses);

    // --- СОСТОЯНИЕ -------------------------------------------------------
    let (level, state) = if counters.bugchecks > 0 {
        let lvl = if best.is_some() {
            Level::Problem
        } else {
            Level::Attention
        };
        let s = if ru {
            format!(
                "Зарегистрированы критические сбои Windows (BSOD): {}. Дампов памяти: {}.",
                counters.bugchecks, counters.dumps
            )
        } else {
            format!(
                "Windows critical failures (BSOD) registered: {}. Memory dumps: {}.",
                counters.bugchecks, counters.dumps
            )
        };
        (lvl, s)
    } else if counters.unexpected_shutdowns > 0 {
        (
            Level::Attention,
            if ru {
                format!(
                    "Неожиданные отключения без BSOD: {}. Код BugCheck не зарегистрирован.",
                    counters.unexpected_shutdowns
                )
            } else {
                format!(
                    "Unexpected shutdowns without a BSOD: {}. No BugCheck code registered.",
                    counters.unexpected_shutdowns
                )
            },
        )
    } else if !lkr.is_empty() {
        (
            Level::Info,
            t(
                ru,
                "BSOD и неожиданных отключений нет; есть живые отчёты ядра (Windows восстановилась сама).",
                "No BSOD or unexpected shutdowns; live kernel reports present (Windows recovered by itself).",
            ),
        )
    } else {
        (
            Level::Ok,
            t(
                ru,
                "BSOD, неожиданных отключений и живых отчётов ядра за 60 дней не обнаружено.",
                "No BSOD, unexpected shutdowns or live kernel reports in 60 days.",
            ),
        )
    };

    // --- ЧТО ОБНАРУЖЕНО --------------------------------------------------
    // The counters line is rendered from `Report::counters` by every view.
    let mut found: Vec<String> = Vec::new();
    let mut codes: Vec<(u32, usize, String)> = Vec::new();
    for b in &inv.bugchecks {
        match codes.iter_mut().find(|c| c.0 == b.code) {
            Some(c) => {
                c.1 += 1;
                if b.time > c.2 {
                    c.2 = b.time.clone();
                }
            }
            None => codes.push((b.code, 1, b.time.clone())),
        }
    }
    for (code, n, last) in &codes {
        let name = analyses
            .iter()
            .find(|a| a.bugcheck_code() == Some(*code))
            .and_then(|a| a.parsed.bugcheck_name.clone())
            .map(|n| format!(" {n}"))
            .unwrap_or_default();
        found.push(if ru {
            format!(
                "BugCheck 0x{code:08X}{name} — {n}×, последний {}",
                day(last)
            )
        } else {
            format!("BugCheck 0x{code:08X}{name} — {n}×, last {}", day(last))
        });
    }
    if counters.dumps > 0 {
        found.push(if ru {
            format!(
                "Дампы памяти: малых {}, полных (MEMORY.DMP) {}",
                counters.minidumps, counters.full_dumps
            )
        } else {
            format!(
                "Memory dumps: minidumps {}, full (MEMORY.DMP) {}",
                counters.minidumps, counters.full_dumps
            )
        });
    }
    for g in &lkr {
        found.push(if ru {
            format!(
                "LiveKernelReports\\{} — {}× ({} … {}): {}",
                g.folder,
                g.count,
                day(&g.first),
                day(&g.last),
                g.meaning
            )
        } else {
            format!(
                "LiveKernelReports\\{} — {}× ({} … {}): {}",
                g.folder,
                g.count,
                day(&g.first),
                day(&g.last),
                g.meaning
            )
        });
    }
    for n in &inv.notes {
        found.push(n.clone());
    }

    // --- ИНЦИДЕНТЫ -------------------------------------------------------
    let mut rows: Vec<IncidentRow> = Vec::new();
    for b in &inv.bugchecks {
        let a = analyses.iter().find(|a| {
            a.bugcheck.as_ref().is_some_and(|x| x.time == b.time)
                || (a.bugcheck.is_none() && a.bugcheck_code() == Some(b.code))
        });
        let dump = inv
            .dumps
            .iter()
            .find(|d| inv.bugcheck_for(d).is_some_and(|x| x.time == b.time))
            .map(|d| d.name.clone())
            .unwrap_or_else(|| t(ru, "нет дампа", "no dump"));
        let cause = match a {
            Some(a) => module_label(a)
                .map(|m| format!("{m} ({})", a.confidence.code()))
                .unwrap_or_else(|| t(ru, "не определена", "not determined")),
            None => t(ru, "анализ не выполнялся", "not analyzed"),
        };
        rows.push(IncidentRow {
            time: day(&b.time),
            kind: "BSOD".into(),
            code: format!("0x{:08X}", b.code),
            dump,
            cause,
        });
    }
    for (inc, v) in &verdicts {
        // The same boot as a BugCheck row is that row, not a second one.
        let same = inv.bugchecks.iter().any(|b| {
            matches!((minutes(&b.time), minutes(&inc.logged)), (Some(a), Some(c)) if (a - c).abs() <= 15)
        });
        if same {
            continue;
        }
        let kind = if v.hang_confirmed {
            t(ru, "Зависание → отключение", "Hang → shutdown")
        } else {
            t(ru, "Неожиданное отключение", "Unexpected shutdown")
        };
        let cause = match v.subsystem {
            Some(s) => format!("{} ({})", s.code(), v.confidence.code()),
            None => t(ru, "не определена", "not determined"),
        };
        rows.push(IncidentRow {
            time: day(&inc.logged),
            kind,
            code: "—".into(),
            dump: "—".into(),
            cause,
        });
    }
    rows.sort_by(|a, b| b.time.cmp(&a.time));

    // --- ВЕРОЯТНАЯ ПРИЧИНА (evidence priority, item 45) -------------------
    let mut cause: Vec<String> = Vec::new();
    let mut why: Vec<String> = Vec::new();
    let incomplete = analyses
        .iter()
        .find(|a| a.confidence == crate::crash_dump::Confidence::ParserIncomplete);
    if let Some(a) = best {
        let m = module_label(a).unwrap_or_default();
        let owner = match a.software_owner() {
            Some((o, true)) => format!(" / {o}"),
            Some((o, false)) if ru => format!(" / {o} (по имени модуля)"),
            Some((o, false)) => format!(" / {o} (by module name)"),
            None => String::new(),
        };
        cause.push(if ru {
            format!(
                "Драйвер {m}{owner} — вероятная причина исторического BSOD; достоверность {} (обоснованная, не абсолютная).",
                a.confidence.code()
            )
        } else {
            format!(
                "Driver {m}{owner} — probable cause of the historical BSOD; confidence {} (reasoned, not absolute).",
                a.confidence.code()
            )
        });
        if let Some(r) = a.resolution.as_ref().filter(|r| r.present)
            && !r.service_name.is_empty()
        {
            cause.push(if ru {
                format!("Служба {} ({}).", r.service_name, r.service_state)
            } else {
                format!("Service {} ({}).", r.service_name, r.service_state)
            });
        }
        // ПОЧЕМУ СДЕЛАН ВЫВОД: the debugger's own fields + stack evidence.
        let code = a
            .bugcheck_code()
            .map(|c| format!("0x{c:X}"))
            .unwrap_or_else(|| "—".into());
        why.push(format!(
            "BugCheck {code}{}{}",
            a.parsed
                .bugcheck_name
                .as_deref()
                .map(|n| format!(" {n}"))
                .unwrap_or_default(),
            a.parsed
                .bugcheck_parameters
                .first()
                .map(|p| format!(" · Arg1 {p}"))
                .unwrap_or_default()
        ));
        for (k, v) in [
            ("MODULE_NAME", &a.parsed.module_name),
            ("IMAGE_NAME", &a.parsed.image_name),
            ("SYMBOL_NAME", &a.parsed.symbol_name),
            ("FAILURE_BUCKET_ID", &a.parsed.failure_bucket_id),
            ("PROCESS_NAME", &a.parsed.process_name),
        ] {
            if let Some(v) = v {
                why.push(format!("{k}: {v}"));
            }
        }
        let frames = a.module_frames();
        if !frames.is_empty() {
            why.push(if ru {
                format!(
                    "Стек вызовов: {} кадр(а) модуля ({})",
                    frames.len(),
                    frames
                        .iter()
                        .take(3)
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            } else {
                format!(
                    "Call stack: {} frame(s) of the module ({})",
                    frames.len(),
                    frames
                        .iter()
                        .take(3)
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            });
        }
        why.push(if ru {
            format!(
                "Символы: {} · анализ: {}",
                a.parsed.symbol_status().code(),
                a.status.code()
            )
        } else {
            format!(
                "Symbols: {} · analysis: {}",
                a.parsed.symbol_status().code(),
                a.status.code()
            )
        });
        if let Some(l) = a.linked.first() {
            why.push(if ru {
                format!(
                    "Driver Audit подтверждает: [{}] {} — {} ×{}",
                    l.status.label_ru(),
                    l.device,
                    l.kind.code(),
                    l.count.max(1)
                )
            } else {
                format!(
                    "Driver Audit corroborates: [{}] {} — {} ×{}",
                    l.status.code(),
                    l.device,
                    l.kind.code(),
                    l.count.max(1)
                )
            });
        }
        why.push(t(
            ru,
            "ntoskrnl / nt! в стеке — обработчик ошибки ядра, не причина сам по себе.",
            "ntoskrnl / nt! in the stack is the kernel's failure handler, not a cause by itself.",
        ));
        why.push(t(
            ru,
            "Это исторический сбой: продолжающаяся неисправность без новых событий не утверждается.",
            "This is a historical failure: no ongoing fault is claimed without new events.",
        ));
    } else if let Some(a) = incomplete {
        let m = crate::crash_dump::raw_module_candidate(&a.raw_output).unwrap_or_default();
        cause.push(if ru {
            format!(
                "PARSER_INCOMPLETE: вывод WinDbg называет модуль {m}, но структурированный разбор неполон — см. «Технические данные WinDbg». Это не «причина не определена»."
            )
        } else {
            format!(
                "PARSER_INCOMPLETE: the WinDbg output names module {m} but the structured parse is incomplete — see the raw WinDbg data. This is not \"cause not determined\"."
            )
        });
    } else if analyses
        .iter()
        .any(|a| a.status == crate::crash_dump::AnalysisStatus::Completed)
    {
        cause.push(t(
            ru,
            "Анализ дампа выполнен, но конкретный драйвер не установлен (ядро / повреждение памяти / нет символов). Причина не определена.",
            "Dump analysis completed but no specific driver was established (kernel / memory corruption / no symbols). Cause not determined.",
        ));
    }
    if let Some((_, v)) = verdicts.iter().find(|(_, v)| v.subsystem.is_some()) {
        cause.push(if ru {
            format!(
                "Сигналы инцидентов: подсистема {} ({}).",
                v.subsystem.map(|s| s.code()).unwrap_or("?"),
                v.confidence.code()
            )
        } else {
            format!(
                "Incident signals: subsystem {} ({}).",
                v.subsystem.map(|s| s.code()).unwrap_or("?"),
                v.confidence.code()
            )
        });
    }
    if lkr.iter().any(|g| g.graphics) {
        cause.push(t(
            ru,
            "Живые отчёты ядра указывают на видеодрайвер (TDR) — восстановленные сбои, не BSOD.",
            "Live kernel reports point at the graphics driver (TDR) — recovered failures, not a BSOD.",
        ));
    }
    // Hardware vs system state (item 46): a hardware cause is only ever a
    // hypothesis to test, never a conclusion from a dump.
    let memory = analyses.iter().any(|a| a.memory_test_recommended);
    if memory {
        cause.push(t(
            ru,
            "Аппаратная причина (память) не исключена — это гипотеза для проверки, не вывод.",
            "A hardware cause (memory) is not excluded — a hypothesis to test, not a conclusion.",
        ));
    }
    if cause.is_empty() {
        cause.push(match level {
            Level::Ok => t(
                ru,
                "Сбоев нет — причина не требуется.",
                "No failures — no cause needed.",
            ),
            _ => t(
                ru,
                "Причина не определена: недостаточно доказательств (нет дампа или анализа).",
                "Cause not determined: not enough evidence (no dump or analysis).",
            ),
        });
    }

    // --- ЧТО ПРОВЕРИТЬ (item 48) -----------------------------------------
    let mut checks: Vec<String> = Vec::new();
    if let Some(a) = best {
        let m = module_label(a).unwrap_or_default();
        let target = match a.software_owner() {
            Some((o, _)) => format!("{m} ({o})"),
            None => m.clone(),
        };
        checks.push(if ru {
            format!(
                "Сбой исторический: проверьте, повторяется ли BSOD. При повторении обновите {target} у производителя или временно отключите это ПО (вручную) и понаблюдайте."
            )
        } else {
            format!(
                "Historical failure: check whether the BSOD repeats. If it does, update {target} from the vendor or temporarily disable that software (manually) and observe."
            )
        });
    }
    if memory {
        checks.push(t(
            ru,
            "Проверьте оперативную память (Средство проверки памяти Windows или MemTest86).",
            "Test the memory (Windows Memory Diagnostic or MemTest86).",
        ));
    }
    if counters.bugchecks > 0 && counters.dumps == 0 {
        checks.push(t(
            ru,
            "Дампов нет: включите малые дампы памяти (Система → Дополнительно → Загрузка и восстановление) и проверьте свободное место на системном диске.",
            "No dumps: enable small memory dumps (System → Advanced → Startup and Recovery) and check free space on the system drive.",
        ));
    }
    if counters.minidumps > 0 && !inv.debugger.usable() {
        checks.push(t(
            ru,
            "Для анализа дампов установите WinDbg (официальный пакет Microsoft) кнопкой в карточке.",
            "To analyze the dumps, install WinDbg (official Microsoft package) with the card button.",
        ));
    }
    if lkr.iter().any(|g| g.graphics) {
        checks.push(t(
            ru,
            "Установите актуальный драйвер видеокарты с сайта производителя.",
            "Install the current graphics driver from the GPU vendor.",
        ));
    }
    if counters.unexpected_shutdowns > counters.bugchecks {
        checks.push(t(
            ru,
            "Отключения без BSOD: проверьте питание (БП / батарея / розетка), перегрев и что происходило перед отключением.",
            "Shutdowns without a BSOD: check power (PSU / battery / outlet), overheating and what happened right before.",
        ));
    }
    if checks.is_empty() {
        checks.push(t(ru, "Действий не требуется.", "No action needed."));
    }

    Report {
        level,
        state,
        found,
        incidents: rows,
        cause,
        why,
        checks,
        counters,
    }
}

/// The report as plain text (Copy / Save / evidence) — the same sections
/// in the same order as the window.
pub fn to_text(r: &Report, ru: bool) -> String {
    let mut o = String::new();
    let h = |o: &mut String, title: &str| o.push_str(&format!("\r\n{title}\r\n"));
    h(&mut o, if ru { "СОСТОЯНИЕ" } else { "STATE" });
    o.push_str(&format!("[{}] {}\r\n", r.level.code(), r.state));
    h(
        &mut o,
        if ru {
            "ЧТО ОБНАРУЖЕНО"
        } else {
            "FINDINGS"
        },
    );
    o.push_str(&format!("• {}\r\n", r.counters.line(ru)));
    for l in &r.found {
        o.push_str(&format!("• {l}\r\n"));
    }
    h(
        &mut o,
        if ru {
            "ИНЦИДЕНТЫ"
        } else {
            "INCIDENTS"
        },
    );
    if r.incidents.is_empty() {
        o.push_str(if ru { "нет\r\n" } else { "none\r\n" });
    }
    for i in &r.incidents {
        o.push_str(&format!(
            "{} | {} | {} | {} | {}\r\n",
            i.time, i.kind, i.code, i.dump, i.cause
        ));
    }
    h(
        &mut o,
        if ru {
            "ВЕРОЯТНАЯ ПРИЧИНА"
        } else {
            "PROBABLE CAUSE"
        },
    );
    for l in &r.cause {
        o.push_str(&format!("{l}\r\n"));
    }
    if !r.why.is_empty() {
        h(
            &mut o,
            if ru {
                "ПОЧЕМУ СДЕЛАН ВЫВОД"
            } else {
                "WHY THIS CONCLUSION"
            },
        );
        for l in &r.why {
            o.push_str(&format!("• {l}\r\n"));
        }
    }
    h(
        &mut o,
        if ru {
            "ЧТО ПРОВЕРИТЬ"
        } else {
            "WHAT TO CHECK"
        },
    );
    for l in &r.checks {
        o.push_str(&format!("• {l}\r\n"));
    }
    o
}

/// Debugger state machine text (item 41): package vs backend vs usable.
pub fn debugger_line(d: &DebuggerStatus, ru: bool) -> String {
    match (d, ru) {
        (DebuggerStatus::Installed { cdb }, true) => {
            format!("WinDbg: модуль анализа cdb найден ({cdb})")
        }
        (DebuggerStatus::Installed { cdb }, false) => {
            format!("WinDbg: cdb analysis backend found ({cdb})")
        }
        (DebuggerStatus::PackageOnly { package }, true) => format!(
            "WinDbg: пакет установлен ({package}), но консольный модуль анализа cdb не найден — анализ недоступен"
        ),
        (DebuggerStatus::PackageOnly { package }, false) => format!(
            "WinDbg: package installed ({package}) but the cdb analysis backend was not found — analysis unavailable"
        ),
        (DebuggerStatus::NotInstalled, true) => "WinDbg: не установлен".into(),
        (DebuggerStatus::NotInstalled, false) => "WinDbg: not installed".into(),
        (DebuggerStatus::Error(e), true) => format!("WinDbg: ошибка проверки — {e}"),
        (DebuggerStatus::Error(e), false) => format!("WinDbg: detection error — {e}"),
    }
}

/// Install mini-journal (item 42): 4–6 human lines distilled from the raw
/// winget output; the raw log stays available separately.
pub fn install_journal(raw: &[String], after: Option<&DebuggerStatus>, ru: bool) -> Vec<String> {
    let mut out = vec![t(
        ru,
        "Источник: официальный пакет Microsoft.WinDbg (winget, источник winget); UAC — системный.",
        "Source: official Microsoft.WinDbg package (winget, winget source); UAC is the system prompt.",
    )];
    let low = |l: &String| l.to_ascii_lowercase();
    if let Some(f) = raw.iter().find(|l| low(l).contains("found ")) {
        out.push(format!("{} {}", t(ru, "Пакет:", "Package:"), f.trim()));
    }
    if let Some(p) = raw.iter().rev().find(|l| {
        low(l).contains(" mb /") || low(l).contains(" kb /") || low(l).contains("downloading")
    }) {
        out.push(format!("{} {}", t(ru, "Загрузка:", "Download:"), p.trim()));
    }
    let all = raw.iter().map(low).collect::<Vec<_>>().join("\n");
    let result = if all.contains("successfully installed") {
        t(ru, "Установка: успешно.", "Install: succeeded.")
    } else if all.contains("already installed")
        || all.contains("no newer package")
        || all.contains("no available upgrade")
    {
        t(
            ru,
            "Установка: пакет уже установлен.",
            "Install: package already installed.",
        )
    } else if let Some(r) = raw.iter().rev().find(|l| low(l).starts_with("result:")) {
        format!(
            "{} {}",
            t(ru, "Установка:", "Install:"),
            r.trim_start_matches("result:").trim()
        )
    } else {
        t(ru, "Установка: выполняется…", "Install: in progress…")
    };
    out.push(result);
    if let Some(d) = after {
        out.push(format!(
            "{} {}",
            t(ru, "Проверка:", "Check:"),
            debugger_line(d, ru)
        ));
    }
    out.truncate(6);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crash_dump::{BugcheckEvent, BugcheckSource, DumpFile};

    fn inv() -> Inventory {
        Inventory {
            bugchecks: Vec::new(),
            dumps: Vec::new(),
            debugger: DebuggerStatus::NotInstalled,
            notes: Vec::new(),
            unexpected_shutdowns: 0,
            incidents: Vec::new(),
            live_kernel_reports: Vec::new(),
        }
    }

    fn lkr(folder: &str, time: &str) -> LiveKernelReport {
        LiveKernelReport {
            name: format!("{folder}-x.dmp"),
            folder: folder.into(),
            size: 1,
            time: time.into(),
            ..Default::default()
        }
    }

    #[test]
    fn clean_machine_is_ok_with_no_action() {
        let r = build(&inv(), &[], true);
        assert_eq!(r.level, Level::Ok);
        assert_eq!(r.checks, ["Действий не требуется."]);
        assert!(r.incidents.is_empty());
    }

    #[test]
    fn live_kernel_reports_are_grouped_explained_and_not_bsod() {
        let mut i = inv();
        i.live_kernel_reports = vec![
            lkr("WATCHDOG", "2026-10-01T10:00:00"),
            lkr("WATCHDOG", "2026-10-03T11:00:00"),
            lkr("USBXHCI", "2026-09-20T09:00:00"),
        ];
        let g = lkr_groups(&i.live_kernel_reports, true);
        assert_eq!(g.len(), 2);
        assert_eq!((g[0].folder.as_str(), g[0].count), ("WATCHDOG", 2));
        assert_eq!(g[0].first, "2026-10-01T10:00:00");
        assert!(g[0].graphics && g[0].meaning.contains("без BSOD"));
        let r = build(&i, &[], true);
        assert_eq!(r.level, Level::Info);
        assert!(r.state.contains("BSOD и неожиданных отключений нет"));
        assert!(r.checks.iter().any(|c| c.contains("драйвер видеокарты")));
        assert!(r.counters.bugchecks == 0 && r.counters.live_kernel_reports == 3);
    }

    #[test]
    fn counters_are_one_source_for_every_view() {
        let mut i = inv();
        i.unexpected_shutdowns = 2;
        i.bugchecks = vec![BugcheckEvent {
            time: "2026-10-02T08:00:00".into(),
            source: BugcheckSource::Wer1001,
            code: 0x139,
            params: vec![3],
            dump_path: None,
        }];
        i.dumps = vec![DumpFile {
            path: "C:\\Windows\\Minidump\\100226-1.dmp".into(),
            name: "100226-1.dmp".into(),
            size: 1,
            modified: "2026-10-02T07:59:00".into(),
            kind: DumpKind::Mini,
        }];
        let r = build(&i, &[], true);
        assert_eq!(r.counters, Counters::of(&i));
        assert_eq!(
            crate::crash_dump::counts_line(&i),
            Counters::of(&i).line(false)
        );
        assert!(to_text(&r, true).contains(&Counters::of(&i).line(true)));
        assert_eq!(
            r.level,
            Level::Attention,
            "not analyzed → no culprit claimed"
        );
        assert_eq!(r.incidents.len(), 1);
        assert_eq!(r.incidents[0].dump, "100226-1.dmp");
        assert!(r.checks.iter().any(|c| c.contains("WinDbg")));
        assert!(
            r.checks.iter().any(|c| c.contains("питание")),
            "2 shutdowns > 1 BSOD"
        );
    }

    #[test]
    fn install_journal_is_short_and_says_package_vs_backend() {
        let raw: Vec<String> = [
            "Found WinDbg [Microsoft.WinDbg] Version 1.2506.12002.0",
            "Downloading https://windbg.download.prss.microsoft.com/…",
            "  12.0 MB / 48.0 MB",
            "  48.0 MB / 48.0 MB",
            "Successfully verified installer hash",
            "Starting package install...",
            "Successfully installed",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let j = install_journal(
            &raw,
            Some(&DebuggerStatus::PackageOnly {
                package: "Microsoft.WinDbg 1.2506.12002.0".into(),
            }),
            true,
        );
        assert!((4..=6).contains(&j.len()), "{j:?}");
        assert!(j[0].contains("официальный пакет Microsoft.WinDbg"));
        assert!(j.iter().any(|l| l.contains("48.0 MB / 48.0 MB")));
        assert!(j.iter().any(|l| l == "Установка: успешно."));
        assert!(j.last().unwrap().contains("cdb не найден"));
    }

    /// v1.0.1: EXPC stage 07, the crash inventory, Incidents.json and the
    /// crash Details count with ONE window and ONE rule, and say so.
    #[test]
    fn counting_window_and_rule_are_shared_and_explicit() {
        let days = crate::incidents::WINDOW_DAYS;
        assert_eq!(days, 30);
        assert!(crate::crash_dump::INVENTORY_PS1.contains(&format!("AddDays(-{days})")));
        let expc = include_str!("../embedded/EXPC-Diagnostic/EXPC-Diagnostic.ps1");
        assert!(expc.contains(&format!("$start = (Get-Date).AddDays(-{days})")));
        assert!(expc.contains("одно выключение = одна загрузка"));
        assert!(
            expc.contains("($t - $clustered[-1]).TotalMinutes -gt 15.0"),
            "per-boot clustering"
        );
        assert!(
            expc.contains("Kernel-Power 41 с кодом"),
            "coded KP41 counted as BugCheck"
        );
        let mut i = inv();
        i.unexpected_shutdowns = 5;
        let c = Counters::of(&i);
        assert!(
            c.line(true)
                .starts_with("За 30 дн.: неожиданные выключения: 5")
        );
        assert!(
            c.line(false)
                .starts_with("Last 30 days: unexpected shutdowns: 5")
        );
        assert!(crate::incidents::COUNTING_RULE.contains("15 minutes"));
    }
}
