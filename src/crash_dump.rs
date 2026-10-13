//! Crash Dump / BSOD Analyzer (v0.4.4).
//!
//! Workflow (read-only towards the system):
//!
//! ```text
//! BugCheck detected (WER 1001 / Kernel-Power 41)
//!   → matching minidump (%SystemRoot%\Minidump, CrashControl settings)
//!   → debugger availability (cdb.exe / cdbX64.exe — never the WinDbg GUI)
//!   → headless `cdb -z <dump> -y <symbols> -c "!analyze -v; q"` (timeout)
//!   → raw output kept + structured summary
//!   → correlation with Driver Audit evidence (strongest linked first)
//!   → confidence (HIGH / MEDIUM / LOW / CAUSE NOT DETERMINED)
//! ```
//!
//! Dumps are only read (copied into the report); they are never modified
//! or deleted. A failing analysis never blocks the rest of the report.
//! "Probably caused by" is a debugger heuristic, not a verdict, and
//! `ntoskrnl.exe` is never blamed merely for appearing on the stack.

#![cfg_attr(not(windows), allow(dead_code))]

use crate::deep_checks::json;
use crate::driver_audit::{AuditReport, EvidenceKind, Severity};

/// Evidence prefix (manifest module `crash_dump_analysis`).
pub const EVIDENCE_PREFIX: &str = "CrashDump_";
/// Only the most recent dumps are analyzed automatically.
pub const MAX_ANALYZED_DUMPS: usize = 3;
/// Default limit for one headless analysis.
#[cfg_attr(test, allow(dead_code))]
pub const ANALYSIS_TIMEOUT_SECS: u64 = 300;
/// Official Microsoft symbol server.
pub const MS_SYMBOL_SERVER: &str = "https://msdl.microsoft.com/download/symbols";
/// Official Microsoft distribution of WinDbg (includes cdbX64.exe).
pub const WINDBG_WINGET_ID: &str = "Microsoft.WinDbg";
pub const WINDBG_DOWNLOAD_URL: &str = "https://aka.ms/windbg/download";

// ---------------------------------------------------------------------
// Inventory (BugChecks, dumps, debugger)
// ---------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BugcheckSource {
    /// Microsoft-Windows-WER-SystemErrorReporting 1001.
    Wer1001,
    /// Microsoft-Windows-Kernel-Power 41 with a non-zero BugcheckCode.
    KernelPower41,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BugcheckEvent {
    pub time: String,
    pub source: BugcheckSource,
    pub code: u32,
    pub params: Vec<u64>,
    /// Dump path named by the event (WER 1001), if any.
    pub dump_path: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DumpKind {
    Mini,
    /// MEMORY.DMP (kernel/complete) — recorded, not copied, not analyzed
    /// automatically (size).
    Full,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DumpFile {
    pub path: String,
    pub name: String,
    pub size: u64,
    pub modified: String,
    pub kind: DumpKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DebuggerStatus {
    /// Headless console debugger found.
    Installed {
        cdb: String,
    },
    /// v1.0 item 41: the WinDbg app package is installed but its console
    /// analysis backend (cdb) was not found — analysis is NOT available.
    PackageOnly {
        package: String,
    },
    NotInstalled,
    Error(String),
}

impl DebuggerStatus {
    /// Analysis can run (the cdb backend was found).
    pub fn usable(&self) -> bool {
        matches!(self, DebuggerStatus::Installed { .. })
    }

    pub fn code(&self) -> &'static str {
        match self {
            DebuggerStatus::Installed { .. } => "INSTALLED",
            DebuggerStatus::PackageOnly { .. } => "PACKAGE ONLY (NO CDB BACKEND)",
            DebuggerStatus::NotInstalled => "NOT INSTALLED",
            DebuggerStatus::Error(_) => "ERROR",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inventory {
    pub bugchecks: Vec<BugcheckEvent>,
    pub dumps: Vec<DumpFile>,
    pub debugger: DebuggerStatus,
    /// Collector problems (e.g. Minidump folder not readable).
    pub notes: Vec<String>,
    /// v0.4.5: unexpected shutdowns (Kernel-Power 41 / EventLog 6008, one
    /// per boot) in the inventory window, BugCheck or not.
    pub unexpected_shutdowns: usize,
    /// v0.4.5: the newest incidents with their correlated events.
    pub incidents: Vec<crate::incidents::Incident>,
    /// v0.4.5: `%SystemRoot%\LiveKernelReports` listing (read only).
    pub live_kernel_reports: Vec<crate::incidents::LiveKernelReport>,
}

/// Overall crash state for the Hardware page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrashState {
    NoCrashes,
    BugcheckNoDump,
    DumpsFound,
}

impl Inventory {
    pub fn state(&self) -> CrashState {
        if !self.dumps.is_empty() {
            CrashState::DumpsFound
        } else if !self.bugchecks.is_empty() {
            CrashState::BugcheckNoDump
        } else {
            CrashState::NoCrashes
        }
    }

    /// Dumps to analyze: newest minidumps first (BugCheck-linked ones are
    /// naturally among them), at most [`MAX_ANALYZED_DUMPS`].
    pub fn analysis_queue(&self) -> Vec<&DumpFile> {
        let mut mini: Vec<&DumpFile> = self
            .dumps
            .iter()
            .filter(|d| d.kind == DumpKind::Mini)
            .collect();
        mini.sort_by(|a, b| b.modified.cmp(&a.modified));
        mini.truncate(MAX_ANALYZED_DUMPS);
        mini
    }

    /// The BugCheck event a dump belongs to: the event naming it, else the
    /// event logged within two hours after the dump was written.
    pub fn bugcheck_for(&self, dump: &DumpFile) -> Option<&BugcheckEvent> {
        let named = self.bugchecks.iter().find(|b| {
            b.dump_path
                .as_deref()
                .and_then(|p| p.rsplit(['\\', '/']).next())
                .is_some_and(|n| n.eq_ignore_ascii_case(&dump.name))
        });
        named.or_else(|| {
            let d = minutes(&dump.modified)?;
            self.bugchecks
                .iter()
                .find(|b| minutes(&b.time).is_some_and(|t| (-5..=120).contains(&(t - d))))
        })
    }
}

/// Minutes since an epoch for `YYYY-MM-DDTHH:MM[:SS]` (ordering only).
fn minutes(iso: &str) -> Option<i64> {
    let n = |r: std::ops::Range<usize>| iso.get(r).and_then(|x| x.parse::<i64>().ok());
    let (y, mo, d, h, mi) = (n(0..4)?, n(5..7)?, n(8..10)?, n(11..13)?, n(14..16)?);
    let (yy, mm) = if mo <= 2 {
        (y - 1, mo + 9)
    } else {
        (y, mo - 3)
    };
    let days = 365 * yy + yy / 4 - yy / 100 + yy / 400 + (153 * mm + 2) / 5 + d;
    Some((days * 24 + h) * 60 + mi)
}

/// `0x0000009f (0x3, 0xffff..., ...)` → (code, params).
pub fn parse_wer_bugcheck(text: &str) -> Option<(u32, Vec<u64>)> {
    let t = text.trim();
    let hex = |s: &str| {
        let s = s.trim().trim_start_matches("0x").trim_start_matches("0X");
        u64::from_str_radix(s, 16).ok()
    };
    let (code_part, rest) = match t.find('(') {
        Some(i) => (&t[..i], &t[i + 1..]),
        None => (t, ""),
    };
    let code = u32::try_from(hex(code_part)?).ok()?;
    let params = rest
        .trim_end_matches(')')
        .split(',')
        .filter(|p| !p.trim().is_empty())
        .filter_map(hex)
        .collect();
    Some((code, params))
}

/// Read-only inventory collector (PowerShell). Prints one
/// `WSD_CRASH <json>` line.
pub const INVENTORY_PS1: &str = r#"$ErrorActionPreference = 'Continue'
# v1.0.1: the same 30-day window as EXPC stage 07 (incidents::WINDOW_DAYS).
$since = (Get-Date).AddDays(-30)
$bc = @()
try {
    $bc += @(Get-WinEvent -FilterHashtable @{ LogName='System'; ProviderName='Microsoft-Windows-WER-SystemErrorReporting'; Id=1001; StartTime=$since } -ErrorAction Stop | ForEach-Object {
        [PSCustomObject]@{ t = $_.TimeCreated.ToString('s'); src = 'WER1001'; p = @($_.Properties | ForEach-Object { [string]$_.Value }) } })
} catch { }
try {
    $bc += @(Get-WinEvent -FilterHashtable @{ LogName='System'; ProviderName='Microsoft-Windows-Kernel-Power'; Id=41; StartTime=$since } -ErrorAction Stop | ForEach-Object {
        [PSCustomObject]@{ t = $_.TimeCreated.ToString('s'); src = 'KP41'; p = @($_.Properties | Select-Object -First 5 | ForEach-Object { [string]$_.Value }) } })
} catch { }
$notes = @()
$dirs = @()
$fullPath = ''
try {
    $cc = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -ErrorAction Stop
    if ($cc.MinidumpDir) { $dirs += [Environment]::ExpandEnvironmentVariables([string]$cc.MinidumpDir) }
    if ($cc.DumpFile) { $fullPath = [Environment]::ExpandEnvironmentVariables([string]$cc.DumpFile) }
} catch { $notes += 'CrashControl not readable' }
if ($env:SystemRoot) {
    $dirs += (Join-Path $env:SystemRoot 'Minidump')
    if (-not $fullPath) { $fullPath = Join-Path $env:SystemRoot 'MEMORY.DMP' }
}
$dumps = @()
# v1.0: one folder once — case-insensitive, without a trailing "\"
# (CrashControl "%SystemRoot%\Minidump" and $env:SystemRoot\Minidump are
# usually the same folder in another letter case).
$dirs = @($dirs | Where-Object { $_ } | ForEach-Object { ([string]$_).TrimEnd('\') } | Sort-Object -Unique)
foreach ($d in $dirs) {
    try {
        if (Test-Path -LiteralPath $d) {
            $dumps += @(Get-ChildItem -LiteralPath $d -Filter *.dmp -File -ErrorAction Stop | ForEach-Object {
                [PSCustomObject]@{ path = $_.FullName; name = $_.Name; size = [int64]$_.Length; t = $_.LastWriteTime.ToString('s'); kind = 'mini' } })
        }
    } catch { $notes += ('Dump folder not readable: ' + $d) }
}
try {
    if ($fullPath -and (Test-Path -LiteralPath $fullPath)) {
        $f = Get-Item -LiteralPath $fullPath -ErrorAction Stop
        $dumps += [PSCustomObject]@{ path = $f.FullName; name = $f.Name; size = [int64]$f.Length; t = $f.LastWriteTime.ToString('s'); kind = 'full' }
    }
} catch { $notes += 'MEMORY.DMP not readable' }
$cdb = ''
foreach ($root in @(${env:ProgramFiles(x86)}, $env:ProgramFiles)) {
    if ($root -and -not $cdb) {
        $c = Join-Path $root 'Windows Kits\10\Debuggers\x64\cdb.exe'
        if (Test-Path -LiteralPath $c) { $cdb = $c }
    }
}
if (-not $cdb) {
    foreach ($n in @('cdbX64.exe', 'cdb.exe')) {
        if (-not $cdb) {
            $cmd = Get-Command $n -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($cmd) { $cdb = $cmd.Source }
        }
    }
}
# v1.0 item 41: the WinDbg app package (official Microsoft.WinDbg) is a
# separate fact from its console backend: package found + no cdb = the
# analysis is NOT available (never reported as installed).
$pkg = ''
try {
    $p = Get-AppxPackage -Name 'Microsoft.WinDbg' -ErrorAction Stop | Sort-Object Version -Descending | Select-Object -First 1
    if ($p) {
        $pkg = ('Microsoft.WinDbg ' + [string]$p.Version)
        if (-not $cdb -and $p.InstallLocation) {
            foreach ($rel in @('amd64\cdb.exe', 'x64\cdb.exe')) {
                $c = Join-Path $p.InstallLocation $rel
                if (-not $cdb -and (Test-Path -LiteralPath $c)) { $cdb = $c }
            }
        }
    }
} catch { }
if (-not $cdb -and $env:LOCALAPPDATA) {
    $alias = Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps\cdbX64.exe'
    if (Test-Path -LiteralPath $alias) { $cdb = $alias }
}
# v0.4.5 freeze / hang incidents: Kernel-Power 41 + EventLog 6008 (one
# boot = one incident), the last System event before that boot and the
# System / Application events of the 10 minutes before it. Read-only.
$raw = @()
try { $raw += @(Get-WinEvent -FilterHashtable @{ LogName='System'; ProviderName='Microsoft-Windows-Kernel-Power'; Id=41; StartTime=$since } -ErrorAction Stop | ForEach-Object {
    [PSCustomObject]@{ t = $_.TimeCreated; src = 'KP41'; code = [string](@($_.Properties)[0].Value) } }) } catch { }
try { $raw += @(Get-WinEvent -FilterHashtable @{ LogName='System'; ProviderName='EventLog'; Id=6008; StartTime=$since } -ErrorAction Stop | ForEach-Object {
    [PSCustomObject]@{ t = $_.TimeCreated; src = 'EL6008'; code = '0' } }) } catch { }
$groups = New-Object System.Collections.Generic.List[object]
foreach ($e in @($raw | Sort-Object t -Descending)) {
    $g = $null
    foreach ($x in $groups) { if ([math]::Abs(($x.t - $e.t).TotalMinutes) -le 15) { $g = $x; break } }
    if ($g) { $g.src += @($e.src); if ($e.src -eq 'KP41') { $g.code = $e.code } }
    else { $groups.Add([PSCustomObject]@{ t = $e.t; src = @($e.src); code = $e.code }) }
}
$want = 'Application Hang|Application Error|Windows Error Reporting|^Display$|nvlddmkm|amdkmdag|amdwddmg|igfx|dxgkrnl|storport|stornvme|storahci|iaStor|^disk$|Ntfs|volmgr|WHEA-Logger|Service Control Manager|\.NET Runtime'
$inc = New-Object System.Collections.Generic.List[object]
foreach ($g in @($groups | Select-Object -First 5)) {
    $T = $g.t
    $boot = $null
    try { $boot = Get-WinEvent -FilterHashtable @{ LogName='System'; ProviderName='Microsoft-Windows-Kernel-General'; Id=12; StartTime=$T.AddMinutes(-30); EndTime=$T.AddSeconds(5) } -MaxEvents 1 -ErrorAction Stop } catch { }
    $B = if ($boot) { $boot.TimeCreated } else { $T.AddMinutes(-2) }
    $last = $null
    try { $last = Get-WinEvent -FilterHashtable @{ LogName='System'; StartTime=$B.AddDays(-14); EndTime=$B.AddSeconds(-2) } -MaxEvents 1 -ErrorAction Stop } catch { }
    $L = if ($last) { $last.TimeCreated } else { $B }
    $ev = @()
    foreach ($log in @('System', 'Application')) {
        try {
            $ev += @(Get-WinEvent -FilterHashtable @{ LogName=$log; StartTime=$L.AddMinutes(-10); EndTime=$L.AddSeconds(1) } -MaxEvents 400 -ErrorAction Stop |
                Where-Object { $_.ProviderName -match $want -and ($_.Level -le 3 -or $_.ProviderName -eq 'Windows Error Reporting') } |
                Select-Object -First 60 | ForEach-Object {
                    $m = ''
                    try { $m = [string]$_.Message } catch { }
                    $m = ($m -replace '\s+', ' ')
                    if ($m.Length -gt 240) { $m = $m.Substring(0, 240) }
                    [PSCustomObject]@{ t = $_.TimeCreated.ToString('s'); log = $log; prov = [string]$_.ProviderName; id = [int]$_.Id; lvl = [int]$_.Level; msg = $m } })
        } catch { }
    }
    $inc.Add([PSCustomObject]@{ t = $T.ToString('s'); boot = $B.ToString('s'); last = $L.ToString('s'); src = @($g.src | Select-Object -Unique); code = [string]$g.code; ev = @($ev) })
}
$lkr = @()
if ($env:SystemRoot) {
    $lkrRoot = Join-Path $env:SystemRoot 'LiveKernelReports'
    try {
        if (Test-Path -LiteralPath $lkrRoot) {
            $lkr = @(Get-ChildItem -LiteralPath $lkrRoot -Recurse -File -Filter *.dmp -ErrorAction Stop | Sort-Object LastWriteTime -Descending | Select-Object -First 50 | ForEach-Object {
                [PSCustomObject]@{ name = $_.Name; dir = $_.Directory.Name; path = $_.FullName; size = [int64]$_.Length; t = $_.LastWriteTime.ToString('s') } })
        }
    } catch { $notes += 'LiveKernelReports not readable' }
}
$out = [PSCustomObject]@{ bugchecks = @($bc); dumps = @($dumps); cdb = $cdb; pkg = $pkg; notes = @($notes); shutdowns = $groups.Count; incidents = $inc.ToArray(); lkr = @($lkr) }
Write-Output ('WSD_CRASH ' + (ConvertTo-Json -InputObject $out -Depth 5 -Compress))
"#;

const INVENTORY_MARKER: &str = "WSD_CRASH ";

/// "Unexpected shutdowns: N · BugCheck / BSOD: N · Dumps: N".
pub fn counts_line(inv: &Inventory) -> String {
    // v1.0 item 40: one counter source for every view.
    crate::crash_report::Counters::of(inv).line(false)
}

/// Verdict of every incident (BugCheck of the same boot = within 15 min).
pub fn incident_verdicts(
    inv: &Inventory,
    analyses: &[DumpAnalysis],
) -> Vec<(crate::incidents::Incident, crate::incidents::Verdict)> {
    inv.incidents
        .iter()
        .map(|i| {
            let boot_bugcheck =
                inv.bugchecks
                    .iter()
                    .find(|b| match (minutes(&b.time), minutes(&i.logged)) {
                        (Some(a), Some(c)) => (a - c).abs() <= 15,
                        _ => false,
                    });
            let mut v =
                crate::incidents::classify(i, &inv.live_kernel_reports, boot_bugcheck.is_some());
            // v1.0.1: the dump analysis of this boot's BugCheck names the
            // driver — the verdict must not say "cause not determined".
            v.dump_cause = boot_bugcheck.and_then(|b| {
                analyses
                    .iter()
                    .find(|a| a.bugcheck.as_ref().is_some_and(|x| x.time == b.time))
                    .and_then(|a| {
                        let module = a.probable_module()?;
                        Some(crate::incidents::DumpCause {
                            dump: a.dump.name.clone(),
                            bugcheck: format!(
                                "0x{:08X}{}",
                                a.bugcheck_code().unwrap_or(b.code),
                                a.parsed
                                    .bugcheck_name
                                    .as_deref()
                                    .map(|n| format!(" {n}"))
                                    .unwrap_or_default()
                            ),
                            module,
                            owner: a.software_owner(),
                            confidence: a.confidence.code().to_string(),
                        })
                    })
            });
            (i.clone(), v)
        })
        .collect()
}

/// One incident for the stage / crash Details windows.
pub fn incident_line(i: &crate::incidents::Incident) -> String {
    format!(
        "Incident {} · last activity {} · {} · events {}",
        i.logged.replace('T', " "),
        i.last_activity.replace('T', " "),
        i.sources.join("+"),
        i.events.len()
    )
}

fn strs(v: Option<&json::Value>) -> Vec<String> {
    match v {
        Some(json::Value::Arr(a)) => a
            .iter()
            .map(|x| match x {
                json::Value::Str(s) => s.clone(),
                json::Value::Num(n) => format!("{n}"),
                _ => String::new(),
            })
            .collect(),
        Some(json::Value::Str(s)) => vec![s.clone()],
        _ => Vec::new(),
    }
}

fn arr(v: Option<&json::Value>) -> Vec<json::Value> {
    match v {
        Some(json::Value::Arr(a)) => a.clone(),
        Some(o @ json::Value::Obj(_)) => vec![o.clone()],
        _ => Vec::new(),
    }
}

/// Parses the inventory collector output. `None` = no marker (collection
/// failed — never "no crashes").
pub fn parse_inventory(stdout: &str) -> Option<Inventory> {
    let v = json::parse(crate::ps_exec::marked_line(stdout, INVENTORY_MARKER)?)?;
    let mut bugchecks: Vec<BugcheckEvent> = Vec::new();
    for b in arr(v.get("bugchecks")) {
        let time = b
            .get("t")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        let p = strs(b.get("p"));
        let ev = match b.get("src").and_then(|x| x.as_str()) {
            Some("WER1001") => {
                p.first()
                    .and_then(|t| parse_wer_bugcheck(t))
                    .map(|(code, params)| BugcheckEvent {
                        time: time.clone(),
                        source: BugcheckSource::Wer1001,
                        code,
                        params,
                        dump_path: p
                            .get(1)
                            .filter(|s| s.to_ascii_lowercase().ends_with(".dmp"))
                            .cloned(),
                    })
            }
            Some("KP41") => {
                let num = |i: usize| p.get(i).and_then(|s| s.trim().parse::<u64>().ok());
                match num(0) {
                    Some(code) if code != 0 => Some(BugcheckEvent {
                        time: time.clone(),
                        source: BugcheckSource::KernelPower41,
                        code: code as u32,
                        params: (1..5).filter_map(num).collect(),
                        dump_path: None,
                    }),
                    _ => None,
                }
            }
            _ => None,
        };
        let Some(ev) = ev else { continue };
        // One crash is usually logged by both providers: keep one entry
        // (WER first, it names the dump).
        let dup = bugchecks.iter().any(|e| {
            e.code == ev.code
                && match (minutes(&e.time), minutes(&ev.time)) {
                    (Some(a), Some(b)) => (a - b).abs() <= 15,
                    _ => false,
                }
        });
        if !dup {
            bugchecks.push(ev);
        }
    }
    bugchecks.sort_by(|a, b| b.time.cmp(&a.time));
    let dumps: Vec<DumpFile> = arr(v.get("dumps"))
        .iter()
        .filter_map(|d| {
            Some(DumpFile {
                path: d.get("path")?.as_str()?.to_string(),
                name: d.get("name")?.as_str()?.to_string(),
                size: match d.get("size") {
                    Some(json::Value::Num(n)) if *n >= 0.0 => *n as u64,
                    _ => 0,
                },
                modified: d
                    .get("t")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string(),
                kind: if d.get("kind").and_then(|x| x.as_str()) == Some("full") {
                    DumpKind::Full
                } else {
                    DumpKind::Mini
                },
            })
        })
        .collect();
    // v1.0: the same dump FILE listed twice (two spellings of one folder)
    // is one dump — identity = full path (case-insensitive) + size + time,
    // never the file name alone.
    let mut seen: Vec<(String, u64, String)> = Vec::new();
    let dumps: Vec<DumpFile> = dumps
        .into_iter()
        .filter(|d| {
            let id = (
                d.path.trim().trim_end_matches('\\').to_lowercase(),
                d.size,
                d.modified.clone(),
            );
            if seen.contains(&id) {
                false
            } else {
                seen.push(id);
                true
            }
        })
        .collect();
    let cdb = v
        .get("cdb")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    Some(Inventory {
        bugchecks,
        dumps,
        debugger: {
            let pkg = v
                .get("pkg")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .trim()
                .to_string();
            match (cdb.is_empty(), pkg.is_empty()) {
                (false, _) => DebuggerStatus::Installed { cdb },
                (true, false) => DebuggerStatus::PackageOnly { package: pkg },
                (true, true) => DebuggerStatus::NotInstalled,
            }
        },
        notes: strs(v.get("notes")),
        unexpected_shutdowns: match v.get("shutdowns") {
            Some(json::Value::Num(n)) if *n > 0.0 => *n as usize,
            _ => 0,
        },
        incidents: crate::incidents::parse_incidents(v.get("incidents")),
        live_kernel_reports: crate::incidents::parse_live_kernel_reports(v.get("lkr")),
    })
}

/// Runs the inventory collector (Windows: `powershell.exe`).
pub fn collect_inventory(host: &str) -> Result<Inventory, String> {
    let out =
        crate::ps_exec::run_powershell(host, INVENTORY_PS1, std::time::Duration::from_secs(90))
            .map_err(|e| e.to_string())?;
    parse_inventory(&out).ok_or_else(|| "crash inventory produced no result".to_string())
}

// ---------------------------------------------------------------------
// Headless analysis
// ---------------------------------------------------------------------

/// `srv*<cache>*<Microsoft symbol server>`.
pub fn symbol_path(cache: &std::path::Path) -> String {
    format!("srv*{}*{MS_SYMBOL_SERVER}", cache.display())
}

/// The cdb command line (read-only: `-z` opens the dump file only).
pub fn cdb_args(dump: &str, symbols: &str) -> Vec<String> {
    vec![
        "-z".into(),
        dump.into(),
        "-y".into(),
        symbols.into(),
        "-c".into(),
        "!analyze -v; q".into(),
    ]
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnalysisStatus {
    Completed,
    TimedOut,
    Failed(String),
    /// Debugger not installed — inventory only (evidence vocabulary;
    /// the app never queues an analysis without a debugger).
    #[allow(dead_code)]
    NotRun,
}

impl AnalysisStatus {
    pub fn code(&self) -> &'static str {
        match self {
            AnalysisStatus::Completed => "COMPLETED",
            AnalysisStatus::TimedOut => "TIMED_OUT",
            AnalysisStatus::Failed(_) => "FAILED",
            AnalysisStatus::NotRun => "NOT_RUN",
        }
    }
}

/// v1.0: one headless `!analyze -v` run with every debugger output line handed to
/// `on_line` while cdb runs (real stage feedback). Same status rules.
#[cfg_attr(test, allow(dead_code))]
pub fn run_analysis_observed(
    cdb: &str,
    dump: &str,
    symbol_cache: &std::path::Path,
    timeout: std::time::Duration,
    on_line: impl FnMut(&str) + Send + 'static,
) -> (AnalysisStatus, String) {
    let _ = std::fs::create_dir_all(symbol_cache);
    let mut cmd = std::process::Command::new(cdb);
    cmd.args(cdb_args(dump, &symbol_path(symbol_cache)));
    match crate::ps_exec::run_capture_observed(cmd, timeout, on_line) {
        Ok((text, true)) => (AnalysisStatus::TimedOut, text),
        Ok((text, false)) => {
            if text.contains("BUGCHECK_CODE")
                || text.contains("Bugcheck Analysis")
                || text.contains("Exception Analysis")
            {
                (AnalysisStatus::Completed, text)
            } else {
                (AnalysisStatus::Failed("no !analyze output".into()), text)
            }
        }
        Err(e) => (AnalysisStatus::Failed(e.to_string()), String::new()),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolStatus {
    Ok,
    /// Some module symbols missing (kernel symbols fine).
    Partial,
    /// Kernel symbols missing/wrong — the stack is not trustworthy.
    Failed,
}

impl SymbolStatus {
    pub fn code(self) -> &'static str {
        match self {
            SymbolStatus::Ok => "OK",
            SymbolStatus::Partial => "PARTIAL",
            SymbolStatus::Failed => "FAILED",
        }
    }
}

/// Fields extracted from `!analyze -v` output.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParsedAnalysis {
    pub bugcheck_code: Option<u32>,
    pub bugcheck_name: Option<String>,
    pub bugcheck_parameters: Vec<String>,
    pub failure_bucket_id: Option<String>,
    pub module_name: Option<String>,
    pub image_name: Option<String>,
    pub process_name: Option<String>,
    pub probably_caused_by: Option<String>,
    /// v1.0.1: `SYMBOL_NAME` (e.g. `RvNetMP60+2572`).
    pub symbol_name: Option<String>,
    pub stack_text: Vec<String>,
    pub symbol_errors: Vec<String>,
    /// v1.1: WinDbg itself shortens PROCESS_NAME to the 14 characters of
    /// the kernel's image-name field (e.g. `RvControlSvc.e`); the parser
    /// never cuts it further. True when the debugger's short form is all
    /// the dump text offers (no full `….exe` name to restore it from).
    pub process_name_truncated: bool,
}

fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    line.strip_prefix(key)
        .and_then(|r| r.trim_start_matches([' ', '\t']).strip_prefix(':'))
        .map(str::trim)
        .filter(|v| !v.is_empty())
}

/// Removes DML markup (`<link cmd="…">x</link>`, `<exec …>`) and ANSI
/// colour sequences a debugger may emit, keeping the visible text.
fn plain_line(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\u{1b}' => {
                // ESC [ … letter
                if chars.peek() == Some(&'[') {
                    chars.next();
                    for d in chars.by_ref() {
                        if d.is_ascii_alphabetic() {
                            break;
                        }
                    }
                }
            }
            '<' => {
                // Only well-formed DML tags are removed; a lone '<' stays.
                let rest: String = chars.clone().take(8).collect();
                let tag = rest.trim_start_matches('/');
                if ["link", "exec", "b>", "i>", "u>", "col", "/col"]
                    .iter()
                    .any(|t| tag.starts_with(t))
                {
                    for d in chars.by_ref() {
                        if d == '>' {
                            break;
                        }
                    }
                } else {
                    out.push(c);
                }
            }
            _ => out.push(c),
        }
    }
    out.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

/// Sets `slot` only when it is still empty: repeated keys (a second
/// `!analyze` block, KEY_VALUES echoes) never overwrite the first value.
fn first(slot: &mut Option<String>, v: &str) {
    if slot.is_none() && !v.trim().is_empty() {
        *slot = Some(v.trim().to_string());
    }
}

pub fn parse_analyze_output(text: &str) -> ParsedAnalysis {
    let mut p = ParsedAnalysis::default();
    let lines: Vec<String> = text.lines().map(plain_line).collect();
    let mut kv_key: Option<String> = None;
    let mut i = 0;
    while i < lines.len() {
        let t = lines[i].trim();
        // KEY_VALUES_STRING block: "Key  : Failure.Bucket" / "Value: …".
        if let Some(k) = field(t, "Key") {
            kv_key = Some(k.to_string());
            i += 1;
            continue;
        }
        if let (Some(k), Some(v)) = (kv_key.take(), field(t, "Value")) {
            match k.as_str() {
                "Failure.Bucket" => {
                    if p.failure_bucket_id.is_none() {
                        p.failure_bucket_id = Some(v.to_string());
                    }
                }
                "Bugcheck.Code.LegacyAPI" | "Bugcheck.Code.TargetModel" => {
                    if p.bugcheck_code.is_none() {
                        p.bugcheck_code = u32::from_str_radix(v.trim_start_matches("0x"), 16).ok();
                    }
                }
                _ => {}
            }
            i += 1;
            continue;
        }
        if let Some(v) = field(t, "BUGCHECK_CODE") {
            if p.bugcheck_code.is_none() {
                p.bugcheck_code = u32::from_str_radix(v.trim_start_matches("0x"), 16).ok();
            }
        } else if let Some(v) = field(t, "BUGCHECK_STR") {
            first(&mut p.bugcheck_name, v);
        } else if let Some(n) = (1..=4).find(|n| t.starts_with(&format!("BUGCHECK_P{n}"))) {
            if let Some(v) = field(t, &format!("BUGCHECK_P{n}"))
                && p.bugcheck_parameters.len() < 4
            {
                p.bugcheck_parameters.push(v.to_string());
            }
        } else if let Some(v) = field(t, "FAILURE_BUCKET_ID") {
            // The explicit field wins over the KEY_VALUES echo.
            p.failure_bucket_id = Some(v.to_string());
        } else if let Some(v) = field(t, "MODULE_NAME") {
            first(&mut p.module_name, v);
        } else if let Some(v) = field(t, "IMAGE_NAME") {
            first(&mut p.image_name, v);
        } else if let Some(v) = field(t, "PROCESS_NAME") {
            first(&mut p.process_name, v);
        } else if let Some(v) = field(t, "SYMBOL_NAME") {
            first(&mut p.symbol_name, v);
        } else if let Some(v) = t.strip_prefix("Probably caused by") {
            let v = v.trim_start_matches([' ', ':', '\t']).trim();
            let module = v.split_whitespace().next().unwrap_or("").to_string();
            if !module.is_empty() {
                first(&mut p.probably_caused_by, &module);
            }
        } else if t.starts_with("STACK_TEXT") && t.trim_end().ends_with(':') {
            i += 1;
            // Tolerate one blank line right after the header.
            if i < lines.len() && lines[i].trim().is_empty() {
                i += 1;
            }
            let fresh = p.stack_text.is_empty();
            while i < lines.len() && !lines[i].trim().is_empty() {
                if fresh && p.stack_text.len() < 40 {
                    p.stack_text.push(lines[i].trim().to_string());
                }
                i += 1;
            }
            continue;
        } else if is_bugcheck_banner(t) && p.bugcheck_name.is_none() {
            p.bugcheck_name = t.split_whitespace().next().map(str::to_string);
        } else {
            let l = t.to_ascii_lowercase();
            if l.contains("symbols can not be loaded")
                || l.contains("symbol file could not be found")
                || l.contains("symbols could not be loaded")
                || l.contains("kernel symbols are wrong")
                || l.contains("unable to load image")
                || l.contains("symbol loading may be unreliable")
            {
                p.symbol_errors.push(t.to_string());
            }
        }
        i += 1;
    }
    // v1.1: a verdict field present ANYWHERE in the raw text (a prompt or
    // other prefix before the key, a second block) is never left empty.
    for (slot, key) in [
        (&mut p.module_name, "MODULE_NAME"),
        (&mut p.image_name, "IMAGE_NAME"),
        (&mut p.process_name, "PROCESS_NAME"),
    ] {
        if slot.is_none() {
            *slot = raw_field(&lines, key);
        }
    }
    if let Some(name) = p.process_name.clone() {
        let (full, truncated) = restore_process_name(&name, &lines);
        p.process_name = Some(full);
        p.process_name_truncated = truncated;
    }
    p
}

/// The value of `KEY:` anywhere in a line (the key must start a word).
fn raw_field(lines: &[String], key: &str) -> Option<String> {
    lines.iter().find_map(|l| {
        let mut from = 0;
        while let Some(rel) = l[from..].find(key) {
            let at = from + rel;
            let before_ok = l[..at]
                .chars()
                .next_back()
                .is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '_'));
            if before_ok && let Some(v) = field(&l[at..], key) {
                return Some(v.to_string());
            }
            from = at + key.len();
        }
        None
    })
}

/// v1.1: WinDbg prints at most 14 characters of a process image name
/// (`RvControlSvc.e`). When the same dump text names the full image
/// (`RvControlSvc.exe` in a path, an `IMAGE_NAME` or `!process` line) the
/// full name is restored; otherwise the short form is kept as the debugger
/// printed it and flagged (never shortened further, never guessed).
fn restore_process_name(name: &str, lines: &[String]) -> (String, bool) {
    let n = name.trim();
    let looks_short = n.chars().count() == 14 && !n.to_ascii_lowercase().ends_with(".exe");
    if !looks_short {
        return (n.to_string(), false);
    }
    let low = n.to_ascii_lowercase();
    for l in lines {
        for token in l.split(|c: char| {
            c.is_whitespace() || matches!(c, '\\' | '/' | '"' | '\'' | '(' | ')' | ',' | ';')
        }) {
            let t = token.trim_matches(|c: char| c == ':' || c == '`');
            let tl = t.to_ascii_lowercase();
            if tl.len() > low.len() && tl.starts_with(&low) && tl.ends_with(".exe") {
                return (t.to_string(), false);
            }
        }
    }
    (n.to_string(), true)
}

/// v1.1: debugger service noise that is not analysis content (NatVis
/// visualizer (un)loading, the Debugger Extensions Gallery start-up). It
/// is hidden from the main Crash Analyzer view only; the raw evidence
/// keeps every original line.
pub fn is_debugger_noise(line: &str) -> bool {
    let t = line.trim();
    let l = t.to_ascii_lowercase();
    l.starts_with("natvis script")
        || l.contains("debugger extensions gallery")
        || l.starts_with("extensionrepository")
        || l.starts_with("useexperimentalfeaturefornugetshare")
        || l.starts_with("allownugetexeupdate")
        || l.starts_with("noninteractivenuget")
        || l.starts_with("allownugetmscredentialproviderinstall")
        || l.starts_with("allowparallelinitializationoflocalrepositories")
        || l.starts_with("enableredirecttochakrajsprovider")
        || l.starts_with("-- configuring repositories")
        || l.starts_with("----> repository")
        || l.starts_with("database path")
        || l.starts_with("inaccessible repositories")
        || (l.starts_with("timeout") && l.contains("ms"))
}

/// `text` without debugger service noise (main view only).
pub fn without_debugger_noise(text: &str) -> String {
    text.lines()
        .filter(|l| !is_debugger_noise(l))
        .collect::<Vec<_>>()
        .join("\n")
}

/// v1.0.1 PARSER_INCOMPLETE guard: a specific (non-core) module that the
/// RAW debugger text names in its verdict fields (`MODULE_NAME`,
/// `IMAGE_NAME`, `SYMBOL_NAME`, `Probably caused by`, the failure bucket's
/// `!module` part). Used only when the structured parse lost it.
pub fn raw_module_candidate(raw: &str) -> Option<String> {
    for line in raw.lines().map(plain_line) {
        let t = line.trim();
        for key in ["MODULE_NAME", "IMAGE_NAME", "SYMBOL_NAME"] {
            if let Some(i) = t.find(key) {
                let rest = t[i + key.len()..].trim_start_matches([' ', '\t', ':']);
                let m = module_stem(rest);
                if !m.is_empty() && !is_generic_module(&m) {
                    return Some(m);
                }
            }
        }
        if let Some(i) = t.find("Probably caused by") {
            let rest = t[i + 18..].trim_start_matches([' ', '\t', ':']);
            let m = module_stem(rest);
            if !m.is_empty() && !is_generic_module(&m) {
                return Some(m);
            }
        }
        if (t.contains("FAILURE_BUCKET_ID")
            || t.contains("Failure.Bucket")
            || t.starts_with("Value:"))
            && let Some(m) = bucket_module(t)
        {
            return Some(m);
        }
    }
    // Last resort: a non-core `Module+0x…` stack frame.
    raw.lines().map(plain_line).find_map(|l| {
        let frame = l.rsplit(" : ").next()?.trim().to_string();
        let (name, off) = frame.split_once('+')?;
        (off.starts_with("0x") && !name.contains('!'))
            .then(|| module_stem(name))
            .filter(|m| !m.is_empty() && !is_generic_module(m))
    })
}

/// `0x139_3_CORRUPT_LIST_ENTRY_RvNetMP60!unknown_function` → `rvnetmp60`.
fn bucket_module(text: &str) -> Option<String> {
    let bang = text.find('!')?;
    let head = &text[..bang];
    let token = head.rsplit(['_', ' ', ':', '\t']).next().unwrap_or("");
    let m = module_stem(token);
    (!m.is_empty() && !is_generic_module(&m) && !m.chars().all(|c| c.is_ascii_hexdigit()))
        .then_some(m)
}

/// `DRIVER_POWER_STATE_FAILURE (9f)` banner line.
fn is_bugcheck_banner(t: &str) -> bool {
    let mut parts = t.split_whitespace();
    let (Some(name), Some(code), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    name.len() > 4
        && name
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
        && code.starts_with('(')
        && code.ends_with(')')
        && code[1..code.len() - 1]
            .chars()
            .all(|c| c.is_ascii_hexdigit())
}

impl ParsedAnalysis {
    pub fn symbol_status(&self) -> SymbolStatus {
        let kernel = self.symbol_errors.iter().any(|e| {
            let l = e.to_ascii_lowercase();
            l.contains("kernel symbols are wrong")
                || l.contains("symbols can not be loaded because symbol path is not initialized")
                || l.contains("ntoskrnl")
                || l.contains("ntkrnlmp")
                || l.contains("nt!")
        });
        // v1.0.1: a third-party driver without public symbols is the
        // normal case ("symbols could not be loaded for RvNetMP60.sys"); it
        // does not make the kernel analysis unreliable.
        let implicated = self.implicated_module();
        let other = self.symbol_errors.iter().any(|e| {
            let l = e.to_ascii_lowercase();
            !implicated
                .as_deref()
                .is_some_and(|m| !is_generic_module(m) && l.contains(m))
        });
        if kernel {
            SymbolStatus::Failed
        } else if !other {
            SymbolStatus::Ok
        } else {
            SymbolStatus::Partial
        }
    }

    /// The module the debugger implicates (MODULE_NAME → IMAGE_NAME →
    /// "Probably caused by"), lower-cased, without extension.
    pub fn implicated_module(&self) -> Option<String> {
        self.module_name
            .as_deref()
            .or(self.image_name.as_deref())
            .or(self.symbol_name.as_deref())
            .or(self.probably_caused_by.as_deref())
            .map(module_stem)
            .filter(|m| !m.is_empty())
            .or_else(|| self.failure_bucket_id.as_deref().and_then(bucket_module))
    }

    pub fn memory_corruption(&self) -> bool {
        let b = self
            .failure_bucket_id
            .as_deref()
            .unwrap_or("")
            .to_ascii_lowercase();
        b.contains("memory_corruption")
            || b.contains("pool_corruption")
            || self
                .implicated_module()
                .is_some_and(|m| m == "memory_corruption" || m == "pool_corruption")
    }
}

/// `nvlddmkm.sys` / `nvlddmkm` / `NVLDDMKM+0x1234` → `nvlddmkm`.
pub fn module_stem(name: &str) -> String {
    let n = name.trim().trim_start_matches('(').to_ascii_lowercase();
    let n = n.split(['+', '!', ' ', '(']).next().unwrap_or("");
    let n = n.rsplit(['\\', '/']).next().unwrap_or(n);
    n.strip_suffix(".sys")
        .or_else(|| n.strip_suffix(".exe"))
        .or_else(|| n.strip_suffix(".dll"))
        .unwrap_or(n)
        .to_string()
}

/// Core kernel / generic frames that are never blamed by themselves.
pub fn is_generic_module(stem: &str) -> bool {
    matches!(
        stem,
        "nt" | "ntoskrnl"
            | "ntkrnlmp"
            | "ntkrnlpa"
            | "ntkrpamp"
            | "hal"
            | "memory_corruption"
            | "pool_corruption"
            | "unknown_module"
            | "unknown_image"
            | "unknown"
            | "hardware"
            | "hardware_disk"
    )
}

// ---------------------------------------------------------------------
// Driver Audit correlation (strongest linked evidence)
// ---------------------------------------------------------------------

/// Evidence priority (lower = stronger): current PnP/device error →
/// kernel-driver / load failure → Code Integrity → vendor user-mode crash.
pub fn evidence_priority(kind: EvidenceKind) -> u8 {
    match kind {
        EvidenceKind::PnpError => 1,
        EvidenceKind::BootDriverLoadFailure
        | EvidenceKind::DeviceLoadFailure
        | EvidenceKind::DisplayTimeout
        | EvidenceKind::BugcheckDump => 2,
        EvidenceKind::CodeIntegrity => 3,
        EvidenceKind::Crash => 4,
        _ => 5,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkedEvidence {
    pub device: String,
    pub status: Severity,
    pub kind: EvidenceKind,
    pub priority: u8,
    pub event_id: Option<u32>,
    pub count: u32,
    pub last_seen: String,
    pub text: String,
}

/// Driver Audit evidence linked to `module` (by service name, evidence
/// module or driver file), strongest first. User-mode crashes never
/// outrank a kernel-driver failure of the same stack.
pub fn correlate(module: &str, report: Option<&AuditReport>) -> Vec<LinkedEvidence> {
    let Some(report) = report else {
        return Vec::new();
    };
    let m = module_stem(module);
    if m.is_empty() || is_generic_module(&m) {
        return Vec::new();
    }
    let mut out: Vec<LinkedEvidence> = Vec::new();
    for item in &report.items {
        let item_match = module_stem(&item.service) == m;
        for e in &item.evidence {
            if item_match || module_stem(&e.module) == m {
                out.push(LinkedEvidence {
                    device: item.device.clone(),
                    status: item.status,
                    kind: e.kind,
                    priority: evidence_priority(e.kind),
                    event_id: e.event_id,
                    count: e.count,
                    last_seen: e.last_seen.clone(),
                    text: e.reason.clone(),
                });
            }
        }
        if item_match && item.pnp_error_code.is_some_and(|c| c != 0 && c != 22) {
            out.push(LinkedEvidence {
                device: item.device.clone(),
                status: item.status,
                kind: EvidenceKind::PnpError,
                priority: 1,
                event_id: None,
                count: 1,
                last_seen: String::new(),
                text: format!(
                    "current PnP error code {}",
                    item.pnp_error_code.unwrap_or_default()
                ),
            });
        }
    }
    out.sort_by(|a, b| {
        a.priority
            .cmp(&b.priority)
            .then(b.status.cmp(&a.status))
            .then(b.count.cmp(&a.count))
    });
    out.dedup();
    out
}

// ---------------------------------------------------------------------
// Confidence
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    NotDetermined,
    /// v1.0.1: the raw debugger text names a specific module but the
    /// structured parse lost it — never reported as "cause not determined".
    ParserIncomplete,
    Low,
    Medium,
    High,
}

impl Confidence {
    pub fn code(self) -> &'static str {
        match self {
            Confidence::NotDetermined => "CAUSE NOT DETERMINED",
            Confidence::ParserIncomplete => "PARSER_INCOMPLETE",
            Confidence::Low => "LOW",
            Confidence::Medium => "MEDIUM",
            Confidence::High => "HIGH",
        }
    }

    /// v1.1: the user-facing word with the canonical identifier kept in
    /// brackets — «средняя (MEDIUM)».
    pub fn label(self, ru: bool) -> String {
        let word = match (self, ru) {
            (Confidence::NotDetermined, true) => "причина не определена",
            (Confidence::NotDetermined, false) => "cause not determined",
            (Confidence::ParserIncomplete, true) => "разбор неполный",
            (Confidence::ParserIncomplete, false) => "parse incomplete",
            (Confidence::Low, true) => "низкая",
            (Confidence::Low, false) => "low",
            (Confidence::Medium, true) => "средняя",
            (Confidence::Medium, false) => "medium",
            (Confidence::High, true) => "высокая",
            (Confidence::High, false) => "high",
        };
        format!("{word} ({})", self.code())
    }
}

/// HIGH: specific module + matching Driver Audit / kernel evidence.
/// MEDIUM: specific (non-core) module without corroboration.
/// LOW: generic kernel frame, memory corruption, missing kernel symbols.
/// CAUSE NOT DETERMINED: no analysis or no implicated module.
pub fn confidence(
    status: &AnalysisStatus,
    parsed: &ParsedAnalysis,
    linked: &[LinkedEvidence],
) -> Confidence {
    if *status != AnalysisStatus::Completed {
        return Confidence::NotDetermined;
    }
    let Some(module) = parsed.implicated_module() else {
        return Confidence::NotDetermined;
    };
    if parsed.symbol_status() == SymbolStatus::Failed
        || parsed.memory_corruption()
        || is_generic_module(&module)
    {
        return Confidence::Low;
    }
    let corroborated = linked.iter().any(|l| l.priority <= 3);
    match (corroborated, parsed.symbol_status()) {
        (true, SymbolStatus::Ok) => Confidence::High,
        (true, _) => Confidence::Medium,
        (false, _) => Confidence::Medium,
    }
}

/// Memory diagnostics are recommended (never concluded) for memory
/// corruption, generic kernel corruption, 0x139 without a third-party
/// culprit, memory-manager bugchecks and low-confidence results.
pub fn recommend_memory_test(code: Option<u32>, parsed: &ParsedAnalysis, conf: Confidence) -> bool {
    let third_party = parsed
        .implicated_module()
        .is_some_and(|m| !is_generic_module(&m));
    parsed.memory_corruption()
        || matches!(code, Some(0x1A | 0x4E | 0x12B))
        || (code == Some(0x139) && !third_party)
        || conf == Confidence::Low
}

// ---------------------------------------------------------------------
// Result + evidence
// ---------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct DumpAnalysis {
    pub dump: DumpFile,
    pub bugcheck: Option<BugcheckEvent>,
    pub status: AnalysisStatus,
    pub parsed: ParsedAnalysis,
    pub linked: Vec<LinkedEvidence>,
    pub confidence: Confidence,
    pub memory_test_recommended: bool,
    pub raw_output: String,
    /// v1.0 `lmvm` facts of the implicated module (None: not run / absent).
    pub module_info: Option<ModuleInfo>,
    /// v1.0 installed driver / service / device behind that module.
    pub resolution: Option<DriverResolution>,
}

impl DumpAnalysis {
    pub fn build(
        dump: DumpFile,
        bugcheck: Option<BugcheckEvent>,
        status: AnalysisStatus,
        raw_output: String,
        report: Option<&AuditReport>,
    ) -> Self {
        let parsed = parse_analyze_output(&raw_output);
        let linked = parsed
            .implicated_module()
            .map(|m| correlate(&m, report))
            .unwrap_or_default();
        let mut conf = confidence(&status, &parsed, &linked);
        if conf == Confidence::NotDetermined
            && status == AnalysisStatus::Completed
            && raw_module_candidate(&raw_output).is_some()
        {
            conf = Confidence::ParserIncomplete;
        }
        let code = parsed.bugcheck_code.or(bugcheck.as_ref().map(|b| b.code));
        let memory =
            status == AnalysisStatus::Completed && recommend_memory_test(code, &parsed, conf);
        Self {
            dump,
            bugcheck,
            status,
            parsed,
            linked,
            confidence: conf,
            memory_test_recommended: memory,
            raw_output,
            module_info: None,
            resolution: None,
        }
    }

    /// v1.0: attaches the module metadata and the driver resolution found
    /// for the implicated module (dump-driven correlation).
    pub fn with_module(
        mut self,
        info: Option<ModuleInfo>,
        resolution: Option<DriverResolution>,
    ) -> Self {
        self.module_info = info;
        self.resolution = resolution;
        self
    }

    /// The implicated third-party module that dump-driven correlation
    /// resolves (never a generic kernel frame / memory corruption).
    pub fn third_party_module(&self) -> Option<String> {
        if self.status != AnalysisStatus::Completed || self.parsed.memory_corruption() {
            return None;
        }
        self.parsed
            .implicated_module()
            .filter(|m| !is_generic_module(m))
    }

    pub fn bugcheck_code(&self) -> Option<u32> {
        self.parsed
            .bugcheck_code
            .or(self.bugcheck.as_ref().map(|b| b.code))
    }

    /// The module shown to the user: a specific module, or nothing when
    /// the cause is not determined (ntoskrnl is never blamed alone).
    pub fn probable_module(&self) -> Option<String> {
        match self.confidence {
            Confidence::High | Confidence::Medium => self
                .parsed
                .image_name
                .clone()
                .or(self.parsed.module_name.clone())
                .or(self
                    .parsed
                    .symbol_name
                    .as_deref()
                    .map(|s| format!("{}.sys", module_stem(s))))
                .or(self.parsed.probably_caused_by.clone())
                .or_else(|| self.parsed.implicated_module().map(|m| format!("{m}.sys"))),
            // The raw text names it although the parse lost it: shown,
            // explicitly labelled PARSER_INCOMPLETE by the caller.
            Confidence::ParserIncomplete => raw_module_candidate(&self.raw_output),
            _ => None,
        }
    }

    /// v1.0.1: stack frames that belong to the implicated module (the
    /// evidence that the module was executing at the failure).
    pub fn module_frames(&self) -> Vec<String> {
        let Some(m) = self.parsed.implicated_module() else {
            return Vec::new();
        };
        self.parsed
            .stack_text
            .iter()
            .filter_map(|l| l.rsplit(" : ").next())
            .filter(|f| module_stem(f) == m)
            .map(|f| f.trim().to_string())
            .collect()
    }

    /// v1.0.1: the software component that owns the implicated driver.
    /// `(name, confirmed)`: confirmed = the installed file's own version
    /// resource / signer says so; otherwise a known module-name mapping
    /// (shown as "by module name", never as fact).
    pub fn software_owner(&self) -> Option<(String, bool)> {
        let m = self.third_party_module()?;
        if let Some(r) = self.resolution.as_ref().filter(|r| r.present) {
            let text = format!("{} {} {}", r.product, r.company, r.signer).to_ascii_lowercase();
            if let Some(known) = known_owner(&m)
                && known.1.iter().any(|k| text.contains(k))
            {
                return Some((known.0.to_string(), true));
            }
            if !r.product.is_empty() && !r.product.starts_with("(QA") {
                return Some((r.product.clone(), true));
            }
        }
        known_owner(&m).map(|(n, _)| (n.to_string(), false))
    }
}

/// Module-name → software owner, used only as a labelled hint; the keys
/// are what the installed file's version resource / signer must contain to
/// CONFIRM it.
fn known_owner(stem: &str) -> Option<(&'static str, &'static [&'static str])> {
    match stem {
        "rvnetmp60" | "rvnetmp" => Some(("Radmin VPN", &["radmin", "famatech"])),
        _ => None,
    }
}

/// `CrashDump_Summary_<stamp>_<NN>.json` etc.
pub fn evidence_names(stamp: &str, n: usize, original: &str) -> (String, String, String) {
    (
        format!("{EVIDENCE_PREFIX}Analysis_{stamp}_{n:02}.txt"),
        format!("{EVIDENCE_PREFIX}Summary_{stamp}_{n:02}.json"),
        format!("{EVIDENCE_PREFIX}Dump_{stamp}_{n:02}_{original}"),
    )
}

fn opt(v: Option<&str>) -> String {
    v.map(json::string).unwrap_or_else(|| "null".into())
}

/// Structured summary (no local user paths: the dump is named, not its
/// folder).
pub fn summary_json(a: &DumpAnalysis, copied_dump: Option<&str>, analysis_file: &str) -> String {
    let params: Vec<String> = a
        .parsed
        .bugcheck_parameters
        .iter()
        .map(|p| json::string(p))
        .collect();
    let stack: Vec<String> = a
        .parsed
        .stack_text
        .iter()
        .take(20)
        .map(|p| json::string(p))
        .collect();
    let drivers: Vec<String> = a
        .linked
        .iter()
        .map(|l| {
            json::string(&format!(
                "[{}] {} — {} ×{}{}",
                l.status.code(),
                l.device,
                l.kind.code(),
                l.count.max(1),
                if l.last_seen.is_empty() {
                    String::new()
                } else {
                    format!(" (last {})", l.last_seen)
                }
            ))
        })
        .collect();
    let events: Vec<String> = a
        .linked
        .iter()
        .filter_map(|l| {
            l.event_id
                .map(|id| json::string(&format!("Event ID {id} ×{} — {}", l.count.max(1), l.text)))
        })
        .collect();
    let code = a
        .bugcheck_code()
        .map(|c| json::string(&format!("0x{c:08X}")))
        .unwrap_or_else(|| "null".into());
    let list = |v: &[String]| {
        if v.is_empty() {
            "[]".to_string()
        } else {
            format!("[{}]", v.join(", "))
        }
    };
    format!(
        "{{\n  \"format\": \"winstatediag.crash_dump/1\",\n  \"dump_file\": {},\n  \"dump_kind\": {},\n  \"dump_size\": {},\n  \"dump_timestamp\": {},\n  \"dump_copy_in_report\": {},\n  \"raw_analysis_file\": {},\n  \"bugcheck_event_time\": {},\n  \"bugcheck_code\": {},\n  \"bugcheck_name\": {},\n  \"bugcheck_parameters\": {},\n  \"FAILURE_BUCKET_ID\": {},\n  \"MODULE_NAME\": {},\n  \"IMAGE_NAME\": {},\n  \"PROCESS_NAME\": {},\n  \"SYMBOL_NAME\": {},\n  \"STACK_TEXT\": {},\n  \"module_stack_frames\": {},\n  \"probable_module\": {},\n  \"software_owner\": {},\n  \"software_owner_confirmed\": {},\n  \"symbol_status\": {},\n  \"analysis_status\": {},\n  \"analysis_detail\": {},\n  \"confidence\": {},\n  \"memory_test_recommended\": {},\n  \"linked_driver_evidence\": {},\n  \"linked_event_evidence\": {},\n  \"module_metadata\": {},\n  \"driver_resolution\": {},\n  \"note\": {}\n}}\n",
        json::string(&a.dump.name),
        json::string(match a.dump.kind {
            DumpKind::Mini => "minidump",
            DumpKind::Full => "memory_dmp",
        }),
        a.dump.size,
        json::string(&a.dump.modified),
        opt(copied_dump),
        json::string(analysis_file),
        opt(a.bugcheck.as_ref().map(|b| b.time.as_str())),
        code,
        opt(a.parsed.bugcheck_name.as_deref()),
        list(&params),
        opt(a.parsed.failure_bucket_id.as_deref()),
        opt(a.parsed.module_name.as_deref()),
        opt(a.parsed.image_name.as_deref()),
        opt(a.parsed.process_name.as_deref()),
        opt(a.parsed.symbol_name.as_deref()),
        list(&stack),
        list(
            &a.module_frames()
                .iter()
                .map(|f| json::string(f))
                .collect::<Vec<_>>()
        ),
        opt(a.probable_module().as_deref()),
        opt(a.software_owner().map(|(o, _)| o).as_deref()),
        a.software_owner().is_some_and(|(_, c)| c),
        json::string(if a.status == AnalysisStatus::Completed {
            a.parsed.symbol_status().code()
        } else {
            "UNKNOWN"
        }),
        json::string(a.status.code()),
        match &a.status {
            AnalysisStatus::Failed(e) => json::string(e),
            _ => "null".into(),
        },
        json::string(a.confidence.code()),
        a.memory_test_recommended,
        list(&drivers),
        list(&events),
        module_info_json(a.module_info.as_ref()),
        resolution_json(a.resolution.as_ref()),
        json::string(
            "Debugger output is a heuristic, not a verdict. ntoskrnl/generic kernel frames are never blamed by themselves. A memory test is a recommendation, not a conclusion."
        ),
    )
}

fn module_info_json(m: Option<&ModuleInfo>) -> String {
    let Some(m) = m else {
        return "null".into();
    };
    format!(
        "{{\"module\": {}, \"image_name\": {}, \"image_path\": {}, \"timestamp\": {}, \"file_version\": {}, \"product_version\": {}, \"company\": {}, \"product_name\": {}, \"file_description\": {}, \"source\": \"lmvm\"}}",
        json::string(&m.module),
        json::string(&m.image_name),
        json::string(&m.image_path),
        json::string(&m.timestamp),
        json::string(&m.file_version),
        json::string(&m.product_version),
        json::string(&m.company),
        json::string(&m.product_name),
        json::string(&m.file_description)
    )
}

fn resolution_json(r: Option<&DriverResolution>) -> String {
    let Some(r) = r else {
        return "null".into();
    };
    let devices: Vec<String> = r
        .devices
        .iter()
        .map(|d| {
            format!(
                "{{\"name\": {}, \"status\": {}, \"present\": {}, \"problem_code\": {}}}",
                json::string(&d.name),
                json::string(&d.status),
                d.present,
                d.problem_code
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "null".into())
            )
        })
        .collect();
    format!(
        "{{\"module\": {}, \"present_on_this_computer\": {}, \"driver_file\": {}, \"file_version\": {}, \"publisher\": {}, \"product\": {}, \"signature_status\": {}, \"signer\": {}, \"service\": {}, \"service_display_name\": {}, \"service_state\": {}, \"start_mode\": {}, \"inf\": {}, \"driver_provider\": {}, \"devices\": [{}], \"driver_audit\": \"dump-driven item (outside the normal audit scope when not already audited)\"}}",
        json::string(&r.module),
        r.present,
        json::string(&r.file),
        json::string(&r.file_version),
        json::string(&r.company),
        json::string(&r.product),
        json::string(&r.signature_status),
        json::string(&r.signer),
        json::string(&r.service_name),
        json::string(&r.service_display),
        json::string(&r.service_state),
        json::string(&r.start_mode),
        json::string(&r.inf),
        json::string(&r.provider),
        devices.join(", ")
    )
}

/// Raw analysis TXT (UTF-8 with BOM, CRLF): header + debugger output.
pub fn analysis_txt(a: &DumpAnalysis, cdb: Option<&str>) -> Vec<u8> {
    let mut t = String::new();
    t.push_str("WinStateDiag — Crash Dump analysis (raw debugger output)\r\n");
    t.push_str(&format!(
        "Dump: {} ({} bytes, {})\r\n",
        a.dump.name, a.dump.size, a.dump.modified
    ));
    t.push_str(&format!("Debugger: {}\r\n", cdb.unwrap_or("not installed")));
    t.push_str("Command: cdb -z <dump> -y srv*<cache>*https://msdl.microsoft.com/download/symbols -c \"!analyze -v; q\"\r\n");
    t.push_str(&format!("Status: {}\r\n", a.status.code()));
    t.push_str(&format!("Confidence: {}\r\n", a.confidence.code()));
    t.push_str("------------------------------------------------------------\r\n");
    t.push_str(&a.raw_output.replace("\r\n", "\n").replace('\n', "\r\n"));
    if let Some(m) = &a.module_info {
        t.push_str("\r\n------------------------------------------------------------\r\n");
        t.push_str(&format!("lmvm {}\r\n", m.module));
        t.push_str(&m.raw);
        t.push_str("\r\n");
    }
    if let Some(r) = &a.resolution {
        t.push_str("\r\n------------------------------------------------------------\r\n");
        t.push_str("Installed driver resolution (read-only):\r\n");
        for l in resolution_lines(r, false) {
            t.push_str(&format!("  {l}\r\n"));
        }
    }
    let mut out = vec![0xEF, 0xBB, 0xBF];
    out.extend_from_slice(t.as_bytes());
    out
}

// ---------------------------------------------------------------------
// v1.0 analysis progress: REAL stages, never an invented percentage
// ---------------------------------------------------------------------

/// Visible stages of one dump analysis. Reached stages are read from the
/// debugger's own output (`stage_of_cdb_line`) or set by the worker around
/// the real steps; there is no percentage because cdb reports none.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AnalysisStage {
    PrepareDump,
    LoadSymbols,
    RunAnalyze,
    ParseStack,
    CorrelateDriverAudit,
    BuildReport,
}

impl AnalysisStage {
    pub const ALL: [AnalysisStage; 6] = [
        AnalysisStage::PrepareDump,
        AnalysisStage::LoadSymbols,
        AnalysisStage::RunAnalyze,
        AnalysisStage::ParseStack,
        AnalysisStage::CorrelateDriverAudit,
        AnalysisStage::BuildReport,
    ];

    pub fn text(self, ru: bool) -> &'static str {
        match (self, ru) {
            (AnalysisStage::PrepareDump, true) => "Подготовка dump",
            (AnalysisStage::PrepareDump, false) => "Preparing dump",
            (AnalysisStage::LoadSymbols, true) => "Загрузка symbols",
            (AnalysisStage::LoadSymbols, false) => "Loading symbols",
            (AnalysisStage::RunAnalyze, true) => "Запуск !analyze -v",
            (AnalysisStage::RunAnalyze, false) => "Running !analyze -v",
            (AnalysisStage::ParseStack, true) => "Разбор stack",
            (AnalysisStage::ParseStack, false) => "Parsing stack",
            (AnalysisStage::CorrelateDriverAudit, true) => "Корреляция с Driver Audit",
            (AnalysisStage::CorrelateDriverAudit, false) => "Correlating with Driver Audit",
            (AnalysisStage::BuildReport, true) => "Формирование отчёта",
            (AnalysisStage::BuildReport, false) => "Building the report",
        }
    }
}

/// The stage a cdb output line proves was reached (callers keep the
/// highest stage seen; a line never moves the progress backwards).
pub fn stage_of_cdb_line(line: &str) -> Option<AnalysisStage> {
    let l = line.trim();
    if l.contains("STACK_TEXT:") {
        Some(AnalysisStage::ParseStack)
    } else if l.contains("Bugcheck Analysis")
        || l.contains("Exception Analysis")
        || l.starts_with("KEY_VALUES_STRING")
    {
        Some(AnalysisStage::RunAnalyze)
    } else if l.starts_with("Symbol search path is")
        || l.contains("Loading Kernel Symbols")
        || l.contains("Loading User Symbols")
        || l.contains("Loading unloaded module list")
    {
        Some(AnalysisStage::LoadSymbols)
    } else {
        None
    }
}

/// Colour of the finished analysis (green / yellow / red), from the real
/// results only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnalysisOutcome {
    /// Completed with full symbols and a determined result.
    Completed,
    /// Completed, but symbols incomplete or confidence LOW / not determined.
    CompletedIncomplete,
    /// Every analysis failed or timed out.
    Failed,
}

pub fn analysis_outcome(analyses: &[DumpAnalysis]) -> Option<AnalysisOutcome> {
    if analyses.is_empty() {
        return None;
    }
    let completed: Vec<&DumpAnalysis> = analyses
        .iter()
        .filter(|a| a.status == AnalysisStatus::Completed)
        .collect();
    if completed.is_empty() {
        return Some(AnalysisOutcome::Failed);
    }
    let incomplete = completed.iter().any(|a| {
        a.parsed.symbol_status() != SymbolStatus::Ok
            || matches!(a.confidence, Confidence::Low | Confidence::NotDetermined)
    });
    Some(if incomplete {
        AnalysisOutcome::CompletedIncomplete
    } else {
        AnalysisOutcome::Completed
    })
}

// ---------------------------------------------------------------------
// v1.0 module metadata (`lmvm <module>`)
// ---------------------------------------------------------------------

/// The cdb command line for module metadata (read-only, dump file only).
pub fn lmvm_args(dump: &str, symbols: &str, module: &str) -> Vec<String> {
    vec![
        "-z".into(),
        dump.into(),
        "-y".into(),
        symbols.into(),
        "-c".into(),
        format!("lmvm {module}; q"),
    ]
}

/// `lmvm` facts of the implicated module (minidumps often lack the version
/// resource; what is absent stays empty — never guessed).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ModuleInfo {
    pub module: String,
    pub image_name: String,
    pub image_path: String,
    pub timestamp: String,
    pub file_version: String,
    pub product_version: String,
    pub company: String,
    pub product_name: String,
    pub file_description: String,
    /// The raw lmvm block (evidence).
    pub raw: String,
}

pub fn parse_lmvm(module: &str, text: &str) -> Option<ModuleInfo> {
    let mut info = ModuleInfo {
        module: module.to_string(),
        ..Default::default()
    };
    let mut raw = Vec::new();
    let mut inside = false;
    for line in text.lines() {
        let t = line.trim();
        // The block starts at "start end module name" and its module line.
        if t.starts_with("start ") && t.contains("module name") {
            inside = true;
        }
        if inside && !t.is_empty() && !t.starts_with("quit:") {
            raw.push(line.trim_end().to_string());
        }
        let val = |key: &str| {
            t.strip_prefix(key)
                .map(|v| v.trim_start_matches(':').trim().to_string())
        };
        if let Some(v) = val("Image path") {
            info.image_path = v;
        } else if let Some(v) = val("Image name") {
            info.image_name = v;
        } else if let Some(v) = val("Timestamp") {
            info.timestamp = v;
        } else if let Some(v) = val("File version") {
            info.file_version = v;
        } else if let Some(v) = val("Product version") {
            info.product_version = v;
        } else if let Some(v) = val("CompanyName") {
            info.company = v;
        } else if let Some(v) = val("ProductName") {
            info.product_name = v;
        } else if let Some(v) = val("FileDescription") {
            info.file_description = v;
        }
    }
    info.raw = raw.join("\r\n");
    (!info.image_name.is_empty() || !info.image_path.is_empty() || !info.timestamp.is_empty())
        .then_some(info)
}

/// Runs `lmvm <module>` headless (read-only). `None` when the module is not
/// in the dump's module list or the debugger produced nothing usable.
#[cfg_attr(test, allow(dead_code))]
pub fn run_lmvm(
    cdb: &str,
    dump: &str,
    symbol_cache: &std::path::Path,
    module: &str,
    timeout: std::time::Duration,
) -> Option<ModuleInfo> {
    let mut cmd = std::process::Command::new(cdb);
    cmd.args(lmvm_args(dump, &symbol_path(symbol_cache), module));
    let out = crate::ps_exec::run_capture(cmd, timeout).ok()?;
    parse_lmvm(module, &String::from_utf8_lossy(&out))
}

// ---------------------------------------------------------------------
// v1.0 dump-driven driver resolution (read-only)
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolvedDevice {
    pub name: String,
    pub status: String,
    pub present: bool,
    pub problem_code: Option<u32>,
}

/// The installed driver / service / device / package behind a module named
/// by a dump. `present == false` means the driver file and service are no
/// longer on this machine (said explicitly, the culprit is not dropped).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DriverResolution {
    pub module: String,
    pub present: bool,
    pub file: String,
    pub file_version: String,
    pub company: String,
    pub product: String,
    pub signature_status: String,
    pub signer: String,
    pub service_name: String,
    pub service_display: String,
    pub service_state: String,
    pub start_mode: String,
    pub inf: String,
    pub provider: String,
    pub devices: Vec<ResolvedDevice>,
}

/// Read-only resolver: driver file (System32\drivers, DriverStore), its
/// version resource and Authenticode signature, the kernel service using
/// it, the PnP devices bound to that service and their INF / provider.
pub const RESOLVE_PS1: &str = r#"param([string]$Stem)
$ErrorActionPreference = 'SilentlyContinue'
# A hidden console-less host may skip module auto-loading: load explicitly.
Import-Module Microsoft.PowerShell.Security -ErrorAction SilentlyContinue
$r = [ordered]@{ module = $Stem; present = $false; file = ''; ver = ''; company = ''; product = ''; sig = ''; signer = ''; svc = ''; svcDisplay = ''; svcState = ''; start = ''; inf = ''; provider = ''; devices = @() }
$name = "$Stem.sys"
$cands = @()
$cands += Join-Path $env:SystemRoot "System32\drivers\$name"
$svcObj = Get-CimInstance Win32_SystemDriver | Where-Object { $_.Name -ieq $Stem -or ($_.PathName -and ([IO.Path]::GetFileName(($_.PathName -replace '^\\\?\?\\','')) -ieq $name)) } | Select-Object -First 1
if ($svcObj) {
    $r.svc = [string]$svcObj.Name; $r.svcDisplay = [string]$svcObj.DisplayName; $r.svcState = [string]$svcObj.State; $r.start = [string]$svcObj.StartMode
    $p = [string]$svcObj.PathName
    $p = $p -replace '^\\\?\?\\','' -replace '^\\SystemRoot\\', ($env:SystemRoot + '\') -replace '^System32\\', ($env:SystemRoot + '\System32\')
    if ($p) { $cands = @($p) + $cands }
}
$repo = Join-Path $env:SystemRoot 'System32\DriverStore\FileRepository'
foreach ($f in @(Get-ChildItem -LiteralPath $repo -Filter $name -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 3)) { $cands += $f.FullName }
foreach ($c in $cands) {
    if ($c -and (Test-Path -LiteralPath $c)) {
        $it = Get-Item -LiteralPath $c
        $r.file = $it.FullName; $r.present = $true
        $r.ver = [string]$it.VersionInfo.FileVersion; $r.company = [string]$it.VersionInfo.CompanyName; $r.product = [string]$it.VersionInfo.ProductName
        $s = Get-AuthenticodeSignature -LiteralPath $it.FullName
        if ($s) { $r.sig = [string]$s.Status; if ($s.SignerCertificate) { $r.signer = [string]$s.SignerCertificate.Subject } }
        break
    }
}
if ($r.svc) {
    foreach ($d in @(Get-CimInstance Win32_PnPEntity | Where-Object { $_.Service -ieq $r.svc })) {
        $r.devices += [PSCustomObject]@{ name = [string]$d.Name; status = [string]$d.Status; present = [bool]$d.Present; code = [int]$d.ConfigManagerErrorCode }
        $sd = Get-CimInstance Win32_PnPSignedDriver | Where-Object { $_.DeviceID -eq $d.DeviceID } | Select-Object -First 1
        if ($sd -and -not $r.inf) { $r.inf = [string]$sd.InfName; $r.provider = [string]$sd.DriverProviderName }
    }
}
if ($r.svc -and -not $r.present) { $r.present = $true }
'WSD_DRV ' + ($r | ConvertTo-Json -Compress -Depth 4)
"#;

pub fn parse_resolution(stem: &str, stdout: &str) -> DriverResolution {
    let mut r = DriverResolution {
        module: stem.to_string(),
        ..Default::default()
    };
    let Some(v) = crate::ps_exec::marked_line(stdout, "WSD_DRV ").and_then(json::parse) else {
        return r;
    };
    let s = |k: &str| {
        v.get(k)
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .trim()
            .to_string()
    };
    r.present = matches!(v.get("present"), Some(json::Value::Bool(true)));
    r.file = s("file");
    r.file_version = s("ver");
    r.company = s("company");
    r.product = s("product");
    r.signature_status = s("sig");
    r.signer = s("signer");
    r.service_name = s("svc");
    r.service_display = s("svcDisplay");
    r.service_state = s("svcState");
    r.start_mode = s("start");
    r.inf = s("inf");
    r.provider = s("provider");
    for d in arr(v.get("devices")) {
        let name = d
            .get("name")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        if name.is_empty() {
            continue;
        }
        r.devices.push(ResolvedDevice {
            name,
            status: d
                .get("status")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            present: matches!(d.get("present"), Some(json::Value::Bool(true))),
            problem_code: match d.get("code") {
                Some(json::Value::Num(n)) if *n > 0.0 => Some(*n as u32),
                _ => None,
            },
        });
    }
    r
}

/// Runs the read-only resolver for `stem` (no changes to the system).
#[cfg_attr(test, allow(dead_code))]
pub fn resolve_driver(host: &str, stem: &str) -> DriverResolution {
    let script = format!("& {{ {RESOLVE_PS1} }} -Stem '{}'", stem.replace('\'', "''"));
    match crate::ps_exec::run_powershell(host, &script, std::time::Duration::from_secs(90)) {
        Ok(out) => parse_resolution(stem, &out),
        Err(_) => DriverResolution {
            module: stem.to_string(),
            ..Default::default()
        },
    }
}

/// Human-readable resolution lines (Details / TXT).
pub fn resolution_lines(r: &DriverResolution, ru: bool) -> Vec<String> {
    let mut out = Vec::new();
    if !r.present {
        out.push(if ru {
            format!(
                "{}.sys: драйвер / служба на этом компьютере не найдены (возможно, удалены после сбоя)",
                r.module
            )
        } else {
            format!(
                "{}.sys: driver / service not found on this computer (possibly removed after the crash)",
                r.module
            )
        });
        return out;
    }
    let lbl = |ru_s: &str, en: &str| if ru { ru_s.to_string() } else { en.to_string() };
    let mut kv = |k: String, v: &str| {
        if !v.is_empty() {
            out.push(format!("{k}: {v}"));
        }
    };
    kv(lbl("Файл драйвера", "Driver file"), &r.file);
    kv(lbl("Версия", "Version"), &r.file_version);
    kv(lbl("Издатель", "Publisher"), &r.company);
    kv(lbl("Продукт", "Product"), &r.product);
    kv(lbl("Подпись", "Signature"), &r.signature_status);
    kv(lbl("Подписант", "Signer"), &r.signer);
    kv(
        lbl("Служба", "Service"),
        &if r.service_name.is_empty() {
            String::new()
        } else {
            format!(
                "{} ({}) · {} · {}",
                r.service_name, r.service_display, r.service_state, r.start_mode
            )
        },
    );
    kv(lbl("INF / поставщик", "INF / provider"), &{
        if r.inf.is_empty() && r.provider.is_empty() {
            String::new()
        } else {
            format!("{} · {}", r.inf, r.provider)
        }
    });
    if r.devices.is_empty() {
        out.push(lbl(
            "Устройство: не найдено (драйвер без устройства или устройство удалено)",
            "Device: none found (device-less driver or device removed)",
        ));
    }
    for d in &r.devices {
        out.push(format!(
            "{}: {} · {}{}{}",
            lbl("Устройство", "Device"),
            d.name,
            d.status,
            if d.present { "" } else { " · not present" },
            d.problem_code
                .map(|c| format!(" · PnP code {c}"))
                .unwrap_or_default()
        ));
    }
    out
}

/// v1.0 dump-driven Driver Audit extension: a probable third-party kernel
/// module named by a dump is ALWAYS represented in Driver Audit, even when
/// it was outside the normally audited device set (real case: 0x139 /
/// RvNetMP60.sys with "0 problems / 0 warnings"). An existing item with
/// that service gets the dump evidence; otherwise a new item is added.
/// Generic kernel frames (ntoskrnl, hal, memory_corruption …) never are.
/// The base report is not changed; confidence of the analysis was computed
/// from the base report only (the dump never corroborates itself).
pub fn extend_audit(base: &AuditReport, analyses: &[DumpAnalysis]) -> AuditReport {
    use crate::driver_audit::{AuditItem, Category, Evidence};
    let mut report = base.clone();
    for a in analyses
        .iter()
        .filter(|a| a.status == AnalysisStatus::Completed)
    {
        let Some(stem) = a.parsed.implicated_module() else {
            continue;
        };
        if is_generic_module(&stem) || a.parsed.memory_corruption() {
            continue;
        }
        let severity = if a.confidence == Confidence::High {
            Severity::Problem
        } else {
            Severity::Warning
        };
        let code = a
            .bugcheck_code()
            .map(|c| format!("0x{c:08X}"))
            .unwrap_or_else(|| "?".into());
        let image = a
            .parsed
            .image_name
            .clone()
            .unwrap_or_else(|| format!("{stem}.sys"));
        let reason = format!(
            "BugCheck {code}{} — дамп {} указывает модуль {image} (уверенность {}); вывод отладчика — эвристика, не вердикт",
            a.parsed
                .bugcheck_name
                .as_deref()
                .map(|n| format!(" {n}"))
                .unwrap_or_default(),
            a.dump.name,
            a.confidence.code()
        );
        let ev = Evidence {
            kind: EvidenceKind::BugcheckDump,
            severity,
            source: "Crash dump / !analyze -v".into(),
            event_id: None,
            first_seen: a.dump.modified.clone(),
            last_seen: a.dump.modified.clone(),
            count: 1,
            module: image.clone(),
            module_version: a
                .module_info
                .as_ref()
                .map(|m| m.file_version.clone())
                .filter(|v| !v.is_empty())
                .or_else(|| a.resolution.as_ref().map(|r| r.file_version.clone()))
                .unwrap_or_default(),
            exception: String::new(),
            process: a.parsed.process_name.clone().unwrap_or_default(),
            reason,
        };
        let res = a.resolution.as_ref();
        let service = res
            .map(|r| r.service_name.clone())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| stem.clone());
        if let Some(item) = report.items.iter_mut().find(|it| {
            module_stem(&it.service) == stem || module_stem(&it.service) == module_stem(&service)
        }) {
            item.add_evidence(ev);
            continue;
        }
        let device = match res {
            Some(r) if !r.present => format!("{image} — драйвер не найден (удалён?)"),
            Some(r) if !r.devices.is_empty() => r
                .devices
                .iter()
                .map(|d| d.name.clone())
                .collect::<Vec<_>>()
                .join("; "),
            _ => format!("{image} — устройство не найдено"),
        };
        let mut item = AuditItem {
            category: Category::Other,
            label: format!("{image} (дамп BSOD)"),
            device,
            vendor: res.map(|r| r.company.clone()).unwrap_or_default(),
            provider: res.map(|r| r.provider.clone()).unwrap_or_default(),
            version: res.map(|r| r.file_version.clone()).unwrap_or_default(),
            date: String::new(),
            inf: res.map(|r| r.inf.clone()).unwrap_or_default(),
            service,
            pnp_id: String::new(),
            pnp_error_code: res.and_then(|r| r.devices.iter().find_map(|d| d.problem_code)),
            signed: res.and_then(|r| match r.signature_status.as_str() {
                "Valid" => Some(true),
                "" => None,
                _ => Some(false),
            }),
            status: severity,
            evidence: Vec::new(),
        };
        item.add_evidence(ev);
        report.items.push(item);
    }
    report.overall = report
        .items
        .iter()
        .map(|i| i.status)
        .max()
        .unwrap_or(Severity::Ok)
        .max(base.overall);
    report
}

// ---------------------------------------------------------------------
// v1.0 embedded WinDbg installer (official winget package, hidden console)
// ---------------------------------------------------------------------

/// Visible installer stages, read from winget's own output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum InstallStage {
    Preparing,
    Downloading,
    Installing,
    Verifying,
}

impl InstallStage {
    pub fn text(self, ru: bool) -> &'static str {
        match (self, ru) {
            (InstallStage::Preparing, true) => "Подготовка...",
            (InstallStage::Preparing, false) => "Preparing...",
            (InstallStage::Downloading, true) => "Загрузка пакета...",
            (InstallStage::Downloading, false) => "Downloading the package...",
            (InstallStage::Installing, true) => "Установка...",
            (InstallStage::Installing, false) => "Installing...",
            (InstallStage::Verifying, true) => "Проверка cdb.exe...",
            (InstallStage::Verifying, false) => "Checking cdb.exe...",
        }
    }
}

/// winget arguments: the official Microsoft package, exact id, the winget
/// source only, no interactive prompts inside the hidden console. Package
/// agreements are accepted because the user explicitly clicked "Install".
pub fn winget_install_args() -> Vec<String> {
    [
        "install",
        "--id",
        WINDBG_WINGET_ID,
        "-e",
        "--source",
        "winget",
        "--accept-source-agreements",
        "--accept-package-agreements",
        "--disable-interactivity",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

/// Stage + real percentage (only when winget printed one) of an installer
/// output line.
pub fn install_progress_of_line(line: &str) -> (Option<InstallStage>, Option<u8>) {
    let l = line.trim().to_ascii_lowercase();
    let stage = if l.contains("successfully installed") || l.contains("already installed") {
        Some(InstallStage::Verifying)
    } else if l.contains("starting package install") || l.contains("installing") {
        Some(InstallStage::Installing)
    } else if l.contains("downloading")
        || l.contains("successfully verified installer hash")
        || l.contains(" mb /")
        || l.contains(" kb /")
    {
        Some(InstallStage::Downloading)
    } else if l.contains("found ") {
        Some(InstallStage::Preparing)
    } else {
        None
    };
    // "12.3 MB / 50.0 MB" → real percentage.
    let pct = (|| {
        let (a, b) = l.split_once(" / ")?;
        let num = |s: &str, take_last: bool| -> Option<f64> {
            let parts: Vec<&str> = s.split_whitespace().collect();
            let (n, unit) = if take_last {
                (parts.get(parts.len().checked_sub(2)?)?, parts.last()?)
            } else {
                (parts.first()?, parts.get(1)?)
            };
            let v: f64 = n.parse().ok()?;
            let mul = match *unit {
                "kb" => 1.0,
                "mb" => 1024.0,
                "gb" => 1024.0 * 1024.0,
                _ => return None,
            };
            Some(v * mul)
        };
        let done = num(a, true)?;
        let total = num(b, false)?;
        (total > 0.0).then(|| ((done / total) * 100.0).clamp(0.0, 100.0) as u8)
    })();
    (stage, pct)
}

/// Result of the hidden install.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallResult {
    pub success: bool,
    pub exit_text: String,
    pub log: String,
}

/// Runs the official winget install HIDDEN (no console window), output
/// captured line by line into `on_line`. Only ever called after an
/// explicit click. UAC, if Windows requires it, is the normal system UAC.
#[cfg(windows)]
#[cfg_attr(test, allow(dead_code))]
pub fn run_debugger_install(on_line: impl FnMut(&str) + Send + 'static) -> InstallResult {
    let mut cmd = std::process::Command::new("winget");
    cmd.args(winget_install_args());
    match crate::ps_exec::run_capture_observed(cmd, std::time::Duration::from_secs(900), on_line) {
        Ok((log, timed_out)) => {
            let low = log.to_ascii_lowercase();
            let success = !timed_out
                && (low.contains("successfully installed") || low.contains("already installed"));
            InstallResult {
                success,
                exit_text: if timed_out {
                    "timed out".into()
                } else if success {
                    "OK".into()
                } else {
                    low.lines()
                        .rev()
                        .find(|l| !l.trim().is_empty())
                        .unwrap_or("")
                        .trim()
                        .to_string()
                },
                log,
            }
        }
        Err(e) => InstallResult {
            success: false,
            exit_text: e.to_string(),
            log: String::new(),
        },
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::driver_audit::{AuditItem, Category, Evidence};

    pub(crate) const NVIDIA_ANALYZE: &str = r#"
*******************************************************************************
*                                                                             *
*                        Bugcheck Analysis                                    *
*                                                                             *
*******************************************************************************

VIDEO_TDR_FAILURE (116)
Attempt to reset the display driver and recover from timeout failed.
Arguments:
Arg1: ffffe20fb1a8c010, Optional pointer to internal TDR recovery context (TDR_RECOVERY_CONTEXT).

Debugging Details:
------------------

BUGCHECK_CODE:  116

BUGCHECK_P1: ffffe20fb1a8c010

BUGCHECK_P2: fffff8066a2fd2c0

BUGCHECK_P3: ffffffffc000009a

BUGCHECK_P4: 4

PROCESS_NAME:  System

STACK_TEXT:
ffff8a06`1c9df9f8 fffff806`6a0e3c4e     : 00000000`00000116 ffffe20f`b1a8c010 : nt!KeBugCheckEx
ffff8a06`1c9dfa00 fffff806`6a0b3a2d     : fffff806`6a2fd2c0 ffffe20f`b1a8c010 : dxgkrnl!TdrBugcheckOnTimeout+0xfe
ffff8a06`1c9dfa40 fffff806`6a0b4d9c     : ffffe20f`00000101 00000000`00000000 : nvlddmkm+0x7d2c0

SYMBOL_NAME:  nvlddmkm+7d2c0

MODULE_NAME: nvlddmkm

IMAGE_NAME:  nvlddmkm.sys

FAILURE_BUCKET_ID:  0x116_IMAGE_nvlddmkm.sys

Followup:     MachineOwner
---------
"#;

    fn dump(name: &str, t: &str) -> DumpFile {
        DumpFile {
            path: format!(r"C:\Windows\Minidump\{name}"),
            name: name.into(),
            size: 2_621_440,
            modified: t.into(),
            kind: DumpKind::Mini,
        }
    }

    fn ev(
        kind: EvidenceKind,
        sev: Severity,
        module: &str,
        id: Option<u32>,
        count: u32,
    ) -> Evidence {
        Evidence {
            kind,
            severity: sev,
            source: "test".into(),
            event_id: id,
            first_seen: "2026-10-01T10:00:00".into(),
            last_seen: "2026-10-03T10:00:00".into(),
            count,
            module: module.into(),
            module_version: String::new(),
            exception: String::new(),
            process: String::new(),
            reason: format!("{} evidence", kind.code()),
        }
    }

    pub(crate) fn nvidia_report() -> AuditReport {
        let item = AuditItem {
            category: Category::Display,
            label: "NVIDIA GeForce GT 1030".into(),
            device: "NVIDIA GeForce GT 1030".into(),
            vendor: "NVIDIA".into(),
            provider: "NVIDIA".into(),
            version: "32.0.15.6094".into(),
            date: "2024-08-14".into(),
            inf: "oem42.inf".into(),
            service: "nvlddmkm".into(),
            pnp_id: "PCI\\VEN_10DE&DEV_1D01".into(),
            pnp_error_code: Some(0),
            signed: Some(true),
            status: Severity::Problem,
            evidence: vec![
                ev(
                    EvidenceKind::Crash,
                    Severity::Warning,
                    "nvapi64.dll",
                    Some(1000),
                    38,
                ),
                ev(
                    EvidenceKind::DeviceLoadFailure,
                    Severity::Problem,
                    "nvlddmkm",
                    Some(14),
                    17,
                ),
            ],
        };
        AuditReport {
            items: vec![item],
            ..Default::default()
        }
    }

    #[test]
    fn wer_bugcheck_text_is_parsed() {
        let (code, p) = parse_wer_bugcheck("0x00000116 (0xffffe20fb1a8c010, 0xfffff8066a2fd2c0, 0xffffffffc000009a, 0x0000000000000004)").unwrap();
        assert_eq!(code, 0x116);
        assert_eq!(p.len(), 4);
        assert_eq!(p[3], 4);
        assert_eq!(parse_wer_bugcheck("garbage"), None);
    }

    #[test]
    fn inventory_parses_bugchecks_dumps_and_debugger() {
        let out = r#"noise
WSD_CRASH {"bugchecks":[{"t":"2026-10-03T09:12:40","src":"WER1001","p":["0x00000116 (0xffffe20fb1a8c010, 0xfffff8066a2fd2c0, 0xffffffffc000009a, 0x0000000000000004)","C:\\Windows\\Minidump\\100326-10421-01.dmp","1f2e"]},{"t":"2026-10-03T09:11:58","src":"KP41","p":["278","18446708906380136464","1","2","4"]},{"t":"2026-09-20T08:00:00","src":"KP41","p":["0","0","0","0","0"]}],"dumps":[{"path":"C:\\Windows\\Minidump\\100326-10421-01.dmp","name":"100326-10421-01.dmp","size":2621440,"t":"2026-10-03T09:10:02","kind":"mini"},{"path":"C:\\Windows\\MEMORY.DMP","name":"MEMORY.DMP","size":1073741824,"t":"2026-10-03T09:10:05","kind":"full"}],"cdb":"C:\\Users\\u\\AppData\\Local\\Microsoft\\WindowsApps\\cdbX64.exe","notes":[]}
"#;
        let inv = parse_inventory(out).unwrap();
        assert_eq!(
            inv.bugchecks.len(),
            1,
            "WER + KP41 of one crash merged; code 0 ignored"
        );
        assert_eq!(inv.bugchecks[0].code, 0x116);
        assert_eq!(inv.state(), CrashState::DumpsFound);
        assert_eq!(inv.analysis_queue().len(), 1, "MEMORY.DMP not queued");
        let d = inv.analysis_queue()[0].clone();
        assert_eq!(inv.bugcheck_for(&d).map(|b| b.code), Some(0x116));
        assert!(matches!(inv.debugger, DebuggerStatus::Installed { .. }));
        assert_eq!(parse_inventory("nothing"), None, "failure ≠ no crashes");
    }

    #[test]
    fn crash_states_bugcheck_without_dump_and_none() {
        let mut inv = Inventory {
            bugchecks: vec![],
            dumps: vec![],
            debugger: DebuggerStatus::NotInstalled,
            notes: vec![],
            unexpected_shutdowns: 0,
            incidents: vec![],
            live_kernel_reports: vec![],
        };
        assert_eq!(inv.state(), CrashState::NoCrashes);
        inv.bugchecks.push(BugcheckEvent {
            time: "2026-10-03T09:12:40".into(),
            source: BugcheckSource::KernelPower41,
            code: 0x139,
            params: vec![],
            dump_path: None,
        });
        assert_eq!(inv.state(), CrashState::BugcheckNoDump);
        inv.dumps.push(dump("a.dmp", "2026-10-03T09:10:00"));
        assert_eq!(inv.state(), CrashState::DumpsFound);
        assert_eq!(
            inv.bugcheck_for(&inv.dumps[0]).map(|b| b.code),
            Some(0x139),
            "time window link"
        );
        let far = dump("b.dmp", "2026-09-01T09:10:00");
        assert!(inv.bugcheck_for(&far).is_none());
    }

    #[test]
    fn analyze_output_is_parsed() {
        let p = parse_analyze_output(NVIDIA_ANALYZE);
        assert_eq!(p.bugcheck_code, Some(0x116));
        assert_eq!(p.bugcheck_name.as_deref(), Some("VIDEO_TDR_FAILURE"));
        assert_eq!(p.bugcheck_parameters.len(), 4);
        assert_eq!(p.module_name.as_deref(), Some("nvlddmkm"));
        assert_eq!(p.image_name.as_deref(), Some("nvlddmkm.sys"));
        assert_eq!(p.process_name.as_deref(), Some("System"));
        assert_eq!(
            p.failure_bucket_id.as_deref(),
            Some("0x116_IMAGE_nvlddmkm.sys")
        );
        assert_eq!(p.stack_text.len(), 3);
        assert_eq!(p.symbol_status(), SymbolStatus::Ok);
        assert_eq!(p.implicated_module().as_deref(), Some("nvlddmkm"));
    }

    #[test]
    fn third_party_culprit_with_driver_audit_is_high_and_strongest_first() {
        let report = nvidia_report();
        let a = DumpAnalysis::build(
            dump("100326-10421-01.dmp", "2026-10-03T09:10:02"),
            None,
            AnalysisStatus::Completed,
            NVIDIA_ANALYZE.into(),
            Some(&report),
        );
        assert_eq!(a.confidence, Confidence::High);
        assert_eq!(a.probable_module().as_deref(), Some("nvlddmkm.sys"));
        // Kernel-driver evidence (Event 14) outranks the user-mode crash.
        assert_eq!(a.linked[0].kind, EvidenceKind::DeviceLoadFailure);
        assert_eq!(a.linked[0].event_id, Some(14));
        assert_eq!(a.linked.last().unwrap().kind, EvidenceKind::Crash);
        assert!(!a.memory_test_recommended);
        // Without Driver Audit corroboration: MEDIUM.
        let b = DumpAnalysis::build(
            dump("x.dmp", "t"),
            None,
            AnalysisStatus::Completed,
            NVIDIA_ANALYZE.into(),
            None,
        );
        assert_eq!(b.confidence, Confidence::Medium);
    }

    #[test]
    fn ntoskrnl_only_and_memory_corruption_are_low_and_not_blamed() {
        let nt = NVIDIA_ANALYZE
            .replace("MODULE_NAME: nvlddmkm", "MODULE_NAME: nt")
            .replace("IMAGE_NAME:  nvlddmkm.sys", "IMAGE_NAME:  ntkrnlmp.exe")
            .replace("BUGCHECK_CODE:  116", "BUGCHECK_CODE:  139")
            .replace(
                "FAILURE_BUCKET_ID:  0x116_IMAGE_nvlddmkm.sys",
                "FAILURE_BUCKET_ID:  0x139_3_CORRUPT_LIST_ENTRY_nt!KiProcessExpiredTimerList",
            );
        let a = DumpAnalysis::build(
            dump("x.dmp", "t"),
            None,
            AnalysisStatus::Completed,
            nt,
            Some(&nvidia_report()),
        );
        assert_eq!(a.confidence, Confidence::Low);
        assert_eq!(a.probable_module(), None, "ntoskrnl is never blamed alone");
        assert!(a.linked.is_empty());
        assert!(
            a.memory_test_recommended,
            "0x139 without third-party culprit"
        );
        let mem = NVIDIA_ANALYZE
            .replace("MODULE_NAME: nvlddmkm", "MODULE_NAME: memory_corruption")
            .replace(
                "IMAGE_NAME:  nvlddmkm.sys",
                "IMAGE_NAME:  memory_corruption",
            )
            .replace("0x116_IMAGE_nvlddmkm.sys", "MEMORY_CORRUPTION_ONE_BIT");
        let m = DumpAnalysis::build(
            dump("x.dmp", "t"),
            None,
            AnalysisStatus::Completed,
            mem,
            None,
        );
        assert_eq!(m.confidence, Confidence::Low);
        assert!(m.memory_test_recommended);
    }

    #[test]
    fn symbol_failure_timeout_and_missing_debugger() {
        let bad = format!(
            "*** ERROR: Symbol file could not be found.  Defaulted to export symbols for ntkrnlmp.exe -\n*** WARNING: Kernel symbols are WRONG. Please fix symbols to do analysis.\n{NVIDIA_ANALYZE}"
        );
        let a = DumpAnalysis::build(
            dump("x.dmp", "t"),
            None,
            AnalysisStatus::Completed,
            bad,
            Some(&nvidia_report()),
        );
        assert_eq!(a.parsed.symbol_status(), SymbolStatus::Failed);
        assert_eq!(
            a.confidence,
            Confidence::Low,
            "symbols incomplete → lower confidence"
        );
        assert!(!a.raw_output.is_empty(), "raw output kept");
        for st in [
            AnalysisStatus::TimedOut,
            AnalysisStatus::NotRun,
            AnalysisStatus::Failed("x".into()),
        ] {
            let t = DumpAnalysis::build(dump("x.dmp", "t"), None, st.clone(), String::new(), None);
            assert_eq!(t.confidence, Confidence::NotDetermined);
            assert!(!t.memory_test_recommended);
            let js = summary_json(&t, None, "a.txt");
            assert!(json::parse(&js).is_some());
            assert!(js.contains(st.code()));
            assert!(js.contains("CAUSE NOT DETERMINED"));
        }
        assert_eq!(DebuggerStatus::NotInstalled.code(), "NOT INSTALLED");
        assert_eq!(DebuggerStatus::Error("x".into()).code(), "ERROR");
    }

    #[test]
    fn evidence_files_txt_and_json() {
        let report = nvidia_report();
        let a = DumpAnalysis::build(
            dump("100326-10421-01.dmp", "2026-10-03T09:10:02"),
            None,
            AnalysisStatus::Completed,
            NVIDIA_ANALYZE.into(),
            Some(&report),
        );
        let (txt, js, dmp) = evidence_names("04.10.26_10-00", 1, "100326-10421-01.dmp");
        assert_eq!(txt, "CrashDump_Analysis_04.10.26_10-00_01.txt");
        assert_eq!(js, "CrashDump_Summary_04.10.26_10-00_01.json");
        assert_eq!(dmp, "CrashDump_Dump_04.10.26_10-00_01_100326-10421-01.dmp");
        let raw = analysis_txt(&a, Some("cdbX64.exe"));
        let raw = String::from_utf8_lossy(&raw);
        assert!(
            raw.contains("VIDEO_TDR_FAILURE"),
            "full debugger output kept"
        );
        assert!(raw.contains("\r\n"));
        let text = summary_json(&a, Some(&dmp), &txt);
        let v = json::parse(&text).expect("valid JSON");
        for key in [
            "dump_file",
            "dump_timestamp",
            "bugcheck_code",
            "bugcheck_name",
            "bugcheck_parameters",
            "FAILURE_BUCKET_ID",
            "MODULE_NAME",
            "IMAGE_NAME",
            "PROCESS_NAME",
            "STACK_TEXT",
            "probable_module",
            "symbol_status",
            "analysis_status",
            "confidence",
            "linked_driver_evidence",
            "linked_event_evidence",
        ] {
            assert!(v.get(key).is_some(), "{key}");
        }
        assert_eq!(
            v.get("bugcheck_code").and_then(|x| x.as_str()),
            Some("0x00000116")
        );
        assert_eq!(v.get("confidence").and_then(|x| x.as_str()), Some("HIGH"));
        assert!(!text.contains("Minidump\\\\"), "no local folder path");
        assert!(text.contains("Event ID 14"));
    }

    #[test]
    fn analyzer_is_read_only_and_headless() {
        let args = cdb_args(
            r"C:\Windows\Minidump\a.dmp",
            &symbol_path(std::path::Path::new(r"C:\sym")),
        );
        assert_eq!(args[0], "-z", "dump opened read-only");
        assert!(args.iter().any(|a| a == "!analyze -v; q"));
        assert!(args[3].starts_with("srv*") && args[3].ends_with(MS_SYMBOL_SERVER));
        // CRLF checkouts (core.autocrlf): match on LF.
        let src = include_str!("crash_dump.rs").replace("\r\n", "\n");
        let code = &src[..src.find("#[cfg(test)]\npub(crate) mod tests").unwrap()];
        for forbidden in [
            "remove_file",
            "Remove-Item",
            "windbg.exe\"",
            ".kill",
            "bcdedit",
            "Set-ItemProperty",
        ] {
            assert!(!code.contains(forbidden), "{forbidden}");
        }
        assert!(INVENTORY_PS1.contains("Get-WinEvent"));
        assert!(!INVENTORY_PS1.contains("Remove-"));
    }

    #[test]
    fn inventory_collector_runs() {
        let Some(host) = crate::ps_exec::test_host() else {
            return;
        };
        let inv = collect_inventory(&host).expect("collector answers");
        if !cfg!(windows) {
            assert!(inv.bugchecks.is_empty());
        }
    }

    // ---- v1.0 dump-driven correlation, lmvm, progress, installer ----

    const CASE_0X139_ANALYZE: &str = include_str!("../src/app_qa_scenes.rs");

    fn case_raw() -> String {
        // The client case "C1" 0x139 fixture lives in the QA scenes file.
        let a = CASE_0X139_ANALYZE
            .find("pub(super) const CASE_0X139_ANALYZE: &str = r#\"")
            .unwrap();
        let rest = &CASE_0X139_ANALYZE[a..];
        let start = rest.find('\n').unwrap() + 1;
        let end = rest.find("\"#;").unwrap();
        rest[start..end].to_string()
    }

    fn case_dump() -> DumpFile {
        DumpFile {
            path: "C:\\Windows\\Minidump\\100326-9500-01.dmp".into(),
            name: "100326-9500-01.dmp".into(),
            size: 1,
            modified: "2026-10-03T00:34:41".into(),
            kind: DumpKind::Mini,
        }
    }

    fn empty_audit() -> AuditReport {
        AuditReport {
            generated: String::new(),
            window_days: 30,
            complete: true,
            devices_scanned: 169,
            overall: Severity::Ok,
            items: Vec::new(),
            unattributed: Vec::new(),
            software_findings: Vec::new(),
            expected_inactive: Vec::new(),
            errors: Vec::new(),
        }
    }

    #[test]
    fn rvnetmp60_style_culprit_extends_driver_audit_beyond_its_scope() {
        let base = empty_audit();
        let a = DumpAnalysis::build(
            case_dump(),
            None,
            AnalysisStatus::Completed,
            case_raw(),
            Some(&base),
        );
        assert_eq!(a.bugcheck_code(), Some(0x139));
        assert_eq!(a.third_party_module().as_deref(), Some("rvnetmp60"));
        // No corroboration in the base audit: MEDIUM, never HIGH from the
        // dump itself.
        assert_eq!(a.confidence, Confidence::Medium);
        let resolved = a.clone().with_module(
            parse_lmvm(
                "rvnetmp60",
                "start             end                 module name\nfffff806`4c7f0000 fffff806`4c80a000   RvNetMP60   (deferred)\n    Image path: \\SystemRoot\\System32\\drivers\\RvNetMP60.sys\n    Image name: RvNetMP60.sys\n    Timestamp:        Thu Mar 14 10:21:44 2024 (65F2A7C8)\n    CheckSum:         0001A2B3\n    File version:     6.0.0.12\n    CompanyName:      Vendor Ltd\n",
            ),
            Some(DriverResolution {
                module: "rvnetmp60".into(),
                present: true,
                file: "C:\\Windows\\System32\\drivers\\RvNetMP60.sys".into(),
                file_version: "6.0.0.12".into(),
                company: "Vendor Ltd".into(),
                service_name: "RvNetMP60".into(),
                service_state: "Running".into(),
                signature_status: "Valid".into(),
                ..Default::default()
            }),
        );
        let m = resolved.module_info.as_ref().unwrap();
        assert_eq!(m.image_name, "RvNetMP60.sys");
        assert_eq!(m.file_version, "6.0.0.12");
        assert_eq!(m.company, "Vendor Ltd");
        assert!(m.timestamp.starts_with("Thu Mar 14"));
        // Driver Audit: was "0 problems / 0 warnings" — now the culprit is
        // an item with kernel-driver (priority 2) dump evidence.
        assert_eq!(base.count(Severity::Warning), 0);
        let ext = extend_audit(&base, std::slice::from_ref(&resolved));
        assert_eq!(ext.count(Severity::Warning), 1);
        let item = &ext.items[0];
        assert_eq!(item.service, "RvNetMP60");
        assert_eq!(item.signed, Some(true));
        assert!(item.label.contains("RvNetMP60.sys"));
        assert_eq!(item.evidence[0].kind, EvidenceKind::BugcheckDump);
        assert_eq!(evidence_priority(EvidenceKind::BugcheckDump), 2);
        assert!(item.evidence[0].reason.contains("0x00000139"));
        // The base audit is untouched.
        assert!(base.items.is_empty());
        // Evidence JSON carries metadata + resolution.
        let js = summary_json(&resolved, None, "a.txt");
        assert!(crate::deep_checks::json::parse(&js).is_some(), "{js}");
        assert!(js.contains("\"module_metadata\": {\"module\": \"rvnetmp60\""));
        assert!(js.contains("\"present_on_this_computer\": true"));
        let txt = String::from_utf8(analysis_txt(&resolved, Some("cdbX64.exe"))).unwrap();
        assert!(txt.contains("lmvm rvnetmp60") && txt.contains("Installed driver resolution"));
    }

    #[test]
    fn removed_driver_is_said_explicitly_and_generic_frames_are_never_added() {
        let base = empty_audit();
        let a = DumpAnalysis::build(
            case_dump(),
            None,
            AnalysisStatus::Completed,
            case_raw(),
            Some(&base),
        )
        .with_module(
            None,
            Some(DriverResolution {
                module: "rvnetmp60".into(),
                present: false,
                ..Default::default()
            }),
        );
        let ext = extend_audit(&base, std::slice::from_ref(&a));
        assert!(ext.items[0].device.contains("не найден"));
        assert!(
            resolution_lines(a.resolution.as_ref().unwrap(), false)[0]
                .contains("not found on this computer")
        );
        // ntoskrnl-only / memory corruption: no dump-driven item.
        let nt = DumpAnalysis::build(
            case_dump(),
            None,
            AnalysisStatus::Completed,
            case_raw().replace("RvNetMP60", "nt"),
            Some(&base),
        );
        assert_eq!(nt.third_party_module(), None);
        assert!(extend_audit(&base, &[nt]).items.is_empty());
    }

    #[test]
    fn existing_audit_item_with_the_service_gets_the_dump_evidence() {
        let mut base = empty_audit();
        base.items.push(crate::driver_audit::AuditItem {
            category: crate::driver_audit::Category::Network,
            label: "VPN".into(),
            device: "Virtual Network Adapter".into(),
            vendor: String::new(),
            provider: String::new(),
            version: String::new(),
            date: String::new(),
            inf: String::new(),
            service: "RvNetMP60".into(),
            pnp_id: String::new(),
            pnp_error_code: None,
            signed: Some(true),
            status: Severity::Ok,
            evidence: Vec::new(),
        });
        let a = DumpAnalysis::build(
            case_dump(),
            None,
            AnalysisStatus::Completed,
            case_raw(),
            Some(&base),
        );
        let ext = extend_audit(&base, &[a]);
        assert_eq!(ext.items.len(), 1, "no duplicate item");
        assert_eq!(ext.items[0].status, Severity::Warning);
    }

    #[test]
    fn strongest_evidence_priority_keeps_kernel_above_user_mode() {
        assert!(
            evidence_priority(EvidenceKind::PnpError)
                < evidence_priority(EvidenceKind::BugcheckDump)
        );
        assert!(
            evidence_priority(EvidenceKind::BugcheckDump)
                < evidence_priority(EvidenceKind::CodeIntegrity)
        );
        assert!(
            evidence_priority(EvidenceKind::CodeIntegrity) < evidence_priority(EvidenceKind::Crash)
        );
    }

    #[test]
    fn analysis_progress_uses_real_debugger_stages_never_a_percentage() {
        assert_eq!(
            stage_of_cdb_line("Symbol search path is: srv*C:\\sym*https://msdl"),
            Some(AnalysisStage::LoadSymbols)
        );
        assert_eq!(
            stage_of_cdb_line("Loading Kernel Symbols"),
            Some(AnalysisStage::LoadSymbols)
        );
        assert_eq!(
            stage_of_cdb_line(
                "*                        Bugcheck Analysis                                    *"
            ),
            Some(AnalysisStage::RunAnalyze)
        );
        assert_eq!(
            stage_of_cdb_line("STACK_TEXT:  "),
            Some(AnalysisStage::ParseStack)
        );
        assert_eq!(stage_of_cdb_line("random line 42%"), None);
        assert!(AnalysisStage::LoadSymbols < AnalysisStage::ParseStack);
        assert_eq!(AnalysisStage::ALL.len(), 6);
        assert_eq!(AnalysisStage::ALL[0].text(true), "Подготовка dump");
        assert_eq!(
            AnalysisStage::ALL[4].text(true),
            "Корреляция с Driver Audit"
        );
        // Outcome colours.
        let ok = DumpAnalysis::build(
            case_dump(),
            None,
            AnalysisStatus::Completed,
            case_raw(),
            None,
        );
        assert_eq!(
            analysis_outcome(std::slice::from_ref(&ok)),
            Some(AnalysisOutcome::Completed)
        );
        let failed = DumpAnalysis::build(
            case_dump(),
            None,
            AnalysisStatus::TimedOut,
            String::new(),
            None,
        );
        assert_eq!(analysis_outcome(&[failed]), Some(AnalysisOutcome::Failed));
        let low = DumpAnalysis::build(
            case_dump(),
            None,
            AnalysisStatus::Completed,
            case_raw().replace("RvNetMP60", "nt"),
            None,
        );
        assert_eq!(
            analysis_outcome(&[low]),
            Some(AnalysisOutcome::CompletedIncomplete)
        );
        assert_eq!(analysis_outcome(&[]), None);
    }

    #[test]
    fn embedded_installer_is_official_hidden_explicit_and_never_bypasses_uac() {
        let args = winget_install_args();
        assert_eq!(
            &args[..5],
            ["install", "--id", "Microsoft.WinDbg", "-e", "--source"]
        );
        assert!(args.contains(&"--disable-interactivity".to_string()));
        // CRLF checkouts (core.autocrlf): match on LF.
        let src = include_str!("crash_dump.rs").replace("\r\n", "\n");
        let code = &src[..src.find("#[cfg(test)]\npub(crate) mod tests").unwrap()];
        // No visible console window, no UAC tricks.
        for forbidden in ["cmd.exe", "runas", "-Verb", "ShellExecute", "--silent"] {
            assert!(!code.contains(forbidden), "{forbidden}");
        }
        assert!(
            code.contains(
                "run_capture_observed(cmd, std::time::Duration::from_secs(900), on_line)"
            )
        );
        // Captured output → real stages; a percentage only when printed.
        assert_eq!(
            install_progress_of_line("Found WinDbg [Microsoft.WinDbg] Version 1.2410"),
            (Some(InstallStage::Preparing), None)
        );
        assert_eq!(
            install_progress_of_line("  ██████████▒▒▒▒  12.5 MB / 50.0 MB"),
            (Some(InstallStage::Downloading), Some(25))
        );
        assert_eq!(
            install_progress_of_line("Starting package install..."),
            (Some(InstallStage::Installing), None)
        );
        assert_eq!(
            install_progress_of_line("Successfully installed"),
            (Some(InstallStage::Verifying), None)
        );
        assert_eq!(install_progress_of_line("something else"), (None, None));
    }

    #[test]
    fn lmvm_without_the_module_is_none_never_invented() {
        assert_eq!(parse_lmvm("x", "start end module name\n\nquit:"), None);
        assert_eq!(
            lmvm_args("a.dmp", "srv*c", "rvnetmp60")[5],
            "lmvm rvnetmp60; q"
        );
    }

    // ---- v1.0.1 Phase 01: crash analyzer correctness ------------------

    /// Modern WinDbg (cdbX64) `!analyze -v` as GALINA-HOME produced it
    /// (sanitized: machine identity removed): KEY_VALUES block, trailing
    /// spaces, tabs, a symbol warning for the third-party driver, DML
    /// link markup and a SECOND analyze echo with other values.
    const MODERN_0X139: &str = "\
*******************************************************************************\n\
*                        Bugcheck Analysis                                    *\n\
*******************************************************************************\n\
\n\
KERNEL_SECURITY_CHECK_FAILURE (139)\n\
A kernel component has corrupted a critical data structure.\n\
Arguments:\n\
Arg1: 0000000000000003, A LIST_ENTRY has been corrupted (i.e. double remove).\n\
\n\
*** ERROR: Module load completed but symbols could not be loaded for RvNetMP60.sys\n\
\n\
KEY_VALUES_STRING: 1\n\
\n\
    Key  : Analysis.CPU.mSec\n\
    Value: 1406\n\
\n\
    Key  : Failure.Bucket\n\
    Value: 0x139_3_CORRUPT_LIST_ENTRY_RvNetMP60!unknown_function\n\
\n\
BUGCHECK_CODE:  139\n\
\n\
BUGCHECK_P1: 3\n\
\n\
BUGCHECK_P2: ffffd30c7a5e6f10\n\
\n\
PROCESS_NAME:  RvControlSvc.e\n\
\n\
STACK_TEXT:  \n\
ffffd30c`7a5e6c08 fffff806`2a1c4ea9     : 00000000`00000139 00000000`00000003 : nt!KeBugCheckEx\n\
ffffd30c`7a5e6c10 fffff806`2a1c53b2     : 00000000`00000000 00000000`00000000 : nt!KiBugCheckDispatch+0x69\n\
ffffd30c`7a5e6f30 fffff806`4c7f2572     : ffffb808`11d2a1a0 ffffb808`0f4c2000 : nt!KiRaiseSecurityCheckFailure+0x33d\n\
ffffd30c`7a5e70c8 fffff806`4c7f2f11     : 00000000`00000000 00000000`00000000 : RvNetMP60+0x2572\n\
ffffd30c`7a5e70d0 fffff806`4c7f0b12     : 00000000`00000000 00000000`00000000 : RvNetMP60+0x2f11\n\
\n\
\tSYMBOL_NAME:  RvNetMP60+2572 \n\
\n\
MODULE_NAME: <link cmd=\"lmDvmRvNetMP60\">RvNetMP60</link>\n\
\n\
IMAGE_NAME:  RvNetMP60.sys\n\
\n\
FAILURE_BUCKET_ID:  0x139_3_CORRUPT_LIST_ENTRY_RvNetMP60!unknown_function\n\
\n\
Followup:     MachineOwner\n\
---------\n\
\n\
MODULE_NAME: nt\n\
IMAGE_NAME:  ntkrnlmp.exe\n";

    fn modern() -> DumpAnalysis {
        DumpAnalysis::build(
            case_dump(),
            None,
            AnalysisStatus::Completed,
            MODERN_0X139.to_string(),
            None,
        )
    }

    #[test]
    fn modern_windbg_output_keeps_every_field_and_names_the_driver() {
        let a = modern();
        let p = &a.parsed;
        assert_eq!(p.bugcheck_code, Some(0x139));
        assert_eq!(p.bugcheck_parameters.first().map(String::as_str), Some("3"));
        assert_eq!(
            p.module_name.as_deref(),
            Some("RvNetMP60"),
            "DML stripped, first value kept"
        );
        assert_eq!(
            p.image_name.as_deref(),
            Some("RvNetMP60.sys"),
            "repeated key never overrides"
        );
        assert_eq!(
            p.symbol_name.as_deref(),
            Some("RvNetMP60+2572"),
            "tab-indented key"
        );
        assert_eq!(
            p.process_name.as_deref(),
            Some("RvControlSvc.e"),
            "Windows' 14-char image name kept as is"
        );
        assert_eq!(
            p.failure_bucket_id.as_deref(),
            Some("0x139_3_CORRUPT_LIST_ENTRY_RvNetMP60!unknown_function")
        );
        assert_eq!(p.stack_text.len(), 5, "STACK_TEXT with trailing spaces");
        assert_eq!(a.module_frames(), ["RvNetMP60+0x2572", "RvNetMP60+0x2f11"]);
        // A missing-symbols line for the third-party driver itself is normal.
        assert_eq!(p.symbol_status(), SymbolStatus::Ok);
        assert_eq!(a.confidence, Confidence::Medium, "reasoned, not absolute");
        assert_eq!(a.probable_module().as_deref(), Some("RvNetMP60.sys"));
        assert_eq!(a.third_party_module().as_deref(), Some("rvnetmp60"));
        assert!(!a.memory_test_recommended || p.implicated_module().is_none());
        // The raw debugger text is preserved verbatim for the evidence.
        assert_eq!(a.raw_output, MODERN_0X139);
        // Owner by module name only (no installed-file confirmation here).
        assert_eq!(a.software_owner(), Some(("Radmin VPN".to_string(), false)));
    }

    #[test]
    fn key_values_bucket_alone_still_implicates_the_driver() {
        let only_kv = "BUGCHECK_CODE:  139\n    Key  : Failure.Bucket\n    Value: 0x139_3_CORRUPT_LIST_ENTRY_RvNetMP60!unknown_function\n";
        let a = DumpAnalysis::build(
            case_dump(),
            None,
            AnalysisStatus::Completed,
            only_kv.into(),
            None,
        );
        assert_eq!(a.parsed.implicated_module().as_deref(), Some("rvnetmp60"));
        assert_eq!(a.confidence, Confidence::Medium);
        assert_eq!(a.probable_module().as_deref(), Some("rvnetmp60.sys"));
    }

    #[test]
    fn raw_module_without_structured_fields_is_parser_incomplete_not_undetermined() {
        // The verdict fields are missing (truncated capture) but the stack
        // still names the driver.
        let raw = "BUGCHECK_CODE:  139\nSome header\nffffd30c`7a5e70c8 fffff806`4c7f2f11 : 00000000`00000000 : nt!KiBugCheckDispatch+0x69\nffffd30c`7a5e70c8 fffff806`4c7f2f11 : 00000000`00000000 : RvNetMP60+0x2572\n";
        let a = DumpAnalysis::build(
            case_dump(),
            None,
            AnalysisStatus::Completed,
            raw.into(),
            None,
        );
        assert_eq!(a.parsed.implicated_module(), None);
        assert_eq!(a.confidence, Confidence::ParserIncomplete);
        assert_eq!(a.confidence.code(), "PARSER_INCOMPLETE");
        assert_eq!(a.probable_module().as_deref(), Some("rvnetmp60"));
        // ntoskrnl-only output stays "not determined" / LOW, never blamed.
        let nt = "BUGCHECK_CODE:  139\nSTACK_TEXT:\nx : nt!KeBugCheckEx\nx : nt!KiBugCheckDispatch+0x69\n\nMODULE_NAME: nt\nIMAGE_NAME:  ntkrnlmp.exe\n";
        let b = DumpAnalysis::build(
            case_dump(),
            None,
            AnalysisStatus::Completed,
            nt.into(),
            None,
        );
        assert_eq!(b.confidence, Confidence::Low);
        assert_eq!(b.probable_module(), None);
    }

    #[test]
    fn incident_verdict_uses_the_dump_analysis_of_the_same_boot() {
        let a = DumpAnalysis::build(
            case_dump(),
            Some(BugcheckEvent {
                time: "2026-10-03T00:36:10".into(),
                source: BugcheckSource::Wer1001,
                code: 0x139,
                params: vec![3],
                dump_path: None,
            }),
            AnalysisStatus::Completed,
            MODERN_0X139.to_string(),
            None,
        );
        let inc = crate::incidents::Incident {
            logged: "2026-10-03T00:36:40".into(),
            boot: "2026-10-03T00:36:05".into(),
            last_activity: "2026-10-03T00:34:00".into(),
            sources: vec!["KP41".into(), "EL6008".into()],
            bugcheck_code: 0x139,
            events: Vec::new(),
        };
        let inv = Inventory {
            bugchecks: vec![a.bugcheck.clone().unwrap()],
            dumps: vec![case_dump()],
            debugger: DebuggerStatus::NotInstalled,
            notes: Vec::new(),
            unexpected_shutdowns: 5,
            incidents: vec![inc],
            live_kernel_reports: Vec::new(),
        };
        let without = incident_verdicts(&inv, &[]);
        assert!(without[0].1.headline().contains("CAUSE NOT DETERMINED"));
        let with = incident_verdicts(&inv, std::slice::from_ref(&a));
        let v = &with[0].1;
        assert!(v.headline().contains("PROBABLE DRIVER RvNetMP60.sys / Radmin VPN (by module name) (MEDIUM, dump analysis)"), "{}", v.headline());
        let json = crate::incidents::to_json(&with, inv.unexpected_shutdowns, &[]);
        assert!(json.contains("\"module\": \"RvNetMP60.sys\""), "{json}");
        assert!(json.contains("\"window_days\": 30"), "{json}");
        assert!(json.contains("\"counting_rule\""), "{json}");
        assert!(json.contains("\"unexpected_shutdowns\": 5"), "{json}");
    }
}

#[cfg(test)]
mod dump_identity_tests {
    use super::*;

    /// v1.0: one dump file listed through two spellings of one folder is
    /// counted once; the same NAME in another folder is another dump.
    #[test]
    fn the_same_dump_file_is_counted_once_by_full_path_size_and_time() {
        let out = r#"WSD_CRASH {"bugchecks":[],"dumps":[{"path":"C:\\Windows\\Minidump\\100326-10421-01.dmp","name":"100326-10421-01.dmp","size":2621440,"t":"2026-10-03T09:10:02","kind":"mini"},{"path":"C:\\WINDOWS\\Minidump\\100326-10421-01.dmp","name":"100326-10421-01.dmp","size":2621440,"t":"2026-10-03T09:10:02","kind":"mini"},{"path":"D:\\Dumps\\100326-10421-01.dmp","name":"100326-10421-01.dmp","size":2621440,"t":"2026-10-03T09:10:02","kind":"mini"}],"cdb":"","notes":[]}"#;
        let inv = parse_inventory(out).expect("inventory");
        assert_eq!(inv.dumps.len(), 2, "{:?}", inv.dumps);
        assert!(INVENTORY_PS1.contains("Sort-Object -Unique)"));
        assert!(INVENTORY_PS1.contains("path = $_.FullName; size"));
    }
}
