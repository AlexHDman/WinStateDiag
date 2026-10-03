//! Orchestration layer around the proven, unmodified PowerShell diagnostic
//! engine (EXPC Diagnostic + Hardware Diagnostic + ReportStorage session
//! packaging). This module does not reimplement any diagnostic logic: it
//! extracts the embedded baseline scripts into a per-session temp runtime
//! directory, drives them as hidden child processes (feeding the same
//! answers a human would type at the console), and relocates the resulting
//! session ZIP next to the portable EXE.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;

use crate::report_package::{
    EvidenceFile, SharedPackage, USER_CANCELLED, evidence_stamp, identity_date, lock,
};
use std::time::SystemTime;

#[cfg(windows)]
use std::os::windows::process::CommandExt;

// No console window is allowed to flash for background diagnostic runs.
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

// ---------------------------------------------------------------------
// Embedded baseline (see docs/BASELINE.json). Unmodified except
// Hardware-Diagnostic.ps1, which gained the additive `-WsdViewer` mode
// (hidden collection -> WinStateDiag persists evidence -> viewer without
// manual save buttons); its other modes are byte-for-byte unchanged.
// ---------------------------------------------------------------------

const COMPATIBILITY_PSM1: &[u8] = include_bytes!("../embedded/WinStateDiag/Compatibility.psm1");
const REPORT_STORAGE_PSM1: &[u8] = include_bytes!("../embedded/WinStateDiag/ReportStorage.psm1");
const EXPC_DIAGNOSTIC_PS1: &[u8] =
    include_bytes!("../embedded/EXPC-Diagnostic/EXPC-Diagnostic.ps1");
const HARDWARE_DIAGNOSTIC_PS1: &[u8] =
    include_bytes!("../embedded/Hardware-Report/Hardware-Diagnostic.ps1");
const HARDWARE_PASSPORT_PSM1: &[u8] =
    include_bytes!("../embedded/Hardware-Report/HardwarePassport.psm1");

/// Total number of numbered steps EXPC-Diagnostic.ps1 always walks through
/// (skipped steps still print "Пропущено:" so the count stays accurate for
/// every mode).
pub const EXPC_STEP_COUNT: u32 = 14;

/// Human-readable labels for each of the 14 EXPC pipeline steps, indexed 0..13
/// (step 1 is index 0). Taken verbatim from the Invoke-Step -Title values in
/// EXPC-Diagnostic.ps1; do NOT change order or wording unless the PS1 changes.
pub const EXPC_STEP_LABELS: [&str; 14] = [
    "Сведения о системе, железе, Windows и аптайме",
    "Накопители, свободное место и показатели надёжности",
    "Проблемные устройства Plug and Play — только присутствующие сейчас",
    "Критические и ошибочные события System за 14 дней",
    "VSS Shadow Storage и события Volsnap",
    "WHEA / CPER за 30 дней — классификация Severity",
    "Неожиданные выключения, Kernel-Power и BSOD за 30 дней",
    "Ошибки приложений за 14 дней",
    "Результаты Windows Memory Diagnostic",
    "Антивирус и состояние Microsoft Defender",
    "SFC — проверка целостности системных файлов (/verifyonly)",
    "DISM — диагностика хранилища компонентов (/ScanHealth)",
    "CHKDSK — онлайн-проверка",
    "BIOS, основные драйверы и firmware — контроль версий",
];

/// Which steps are deep-check-only (SFC=10, DISM=11, CHKDSK=12; 0-indexed).
/// `true` means the step may be skipped when deep checks are disabled.
pub const EXPC_DEEP_FLAGS: [bool; 14] = [
    false, false, false, false, false, false, false, false, false, false, true, true, true, false,
];

/// Relative weight of each step for aggregate progress calculation.
/// Fast steps get ~1.0; long deep-check steps are heavier.
pub const EXPC_WEIGHTS: [f32; 14] = [
    1.0, 1.0, 0.5, 0.8, 0.5, 0.5, 0.8, 0.8, 0.3, 0.5, 8.0, 10.0, 5.0, 1.0,
];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DiagnosticMode {
    Standard,
    CustomDeepChecks,
    Full,
}

#[derive(Clone, Copy, Default, Debug)]
pub struct DeepChecks {
    pub sfc: bool,
    pub dism: bool,
    pub chkdsk: bool,
}

pub struct SessionRequest {
    pub client_name: String,
    /// Computer name shown in the GUI; part of the report identity.
    pub computer_name: String,
    pub mode: DiagnosticMode,
    pub deep_checks: DeepChecks,
    pub include_hardware: bool,
    /// Set by the Stop button: no further stage starts, and the running
    /// child process tree of THIS session is terminated.
    pub cancel: Arc<AtomicBool>,
    /// The session report package every module contributes to.
    pub package: SharedPackage,
}

#[derive(Clone, Debug)]
pub enum Stage {
    Preparing,
    SystemDiagnostics,
    HardwareReport,
    Packaging,
    Complete,
}

#[derive(Debug)]
pub enum EngineEvent {
    Stage(Stage),
    ExpcProgress {
        percent: u32,
        message: String,
    },
    Log(String),
    /// Result of the read-only Driver Audit run inside the session.
    DriverAudit(Result<Box<crate::driver_audit::AuditReport>, String>),
    /// v0.4.0: diagnostic RESULT of the SFC / DISM / CHKDSK deep checks of
    /// this run, read from its EXPC evidence (separate from progress).
    DeepChecks(Vec<crate::deep_checks::DeepCheckOutcome>),
    /// v0.4.1: every EXPC check of this run (all steps), as classified by
    /// EXPC itself — shown in the EXPC details window.
    ExpcChecks(Vec<crate::deep_checks::ExpcCheck>),
    Finished(Result<PathBuf, String>),
    /// The user stopped the run. `zip_path` is the session package when it
    /// holds evidence (already collected evidence is never discarded).
    Cancelled {
        zip_path: Option<PathBuf>,
        note: String,
    },
}

fn send(tx: &Sender<EngineEvent>, event: EngineEvent) {
    let _ = tx.send(event);
}

/// The steps of one diagnostic run, in order.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SessionStep {
    Expc,
    Hardware,
    DriverAudit,
}

impl SessionStep {
    pub fn label(self) -> &'static str {
        match self {
            Self::Expc => "EXPC Diagnostic",
            Self::Hardware => "Hardware Report",
            Self::DriverAudit => "Проверка драйверов",
        }
    }

    /// Evidence files this step writes.
    fn owns(self, file_name: &str) -> bool {
        match self {
            Self::Expc => file_name.starts_with("EXPC_"),
            Self::Hardware => file_name.starts_with("Hardware_"),
            Self::DriverAudit => file_name.starts_with("DriverAudit_"),
        }
    }
}

#[derive(Debug)]
pub(crate) enum StepError {
    Failed(String),
    Cancelled,
}

impl From<String> for StepError {
    fn from(message: String) -> Self {
        Self::Failed(message)
    }
}

/// What one run has done so far (for an honest cancellation record).
#[derive(Default)]
struct RunProgress {
    reports_root: Option<PathBuf>,
    current: Option<SessionStep>,
    completed: Vec<SessionStep>,
}

/// The work behind each step. The real implementation drives the embedded
/// PowerShell engine; tests use a scripted backend.
pub(crate) trait SessionBackend {
    /// Prepares the runtime; returns the folder the steps write evidence to.
    fn prepare(&mut self, tx: &Sender<EngineEvent>) -> Result<PathBuf, String>;
    fn run_expc(&mut self, req: &SessionRequest, tx: &Sender<EngineEvent>)
    -> Result<(), StepError>;
    fn run_hardware(
        &mut self,
        req: &SessionRequest,
        tx: &Sender<EngineEvent>,
    ) -> Result<(), StepError>;
    /// A Driver Audit failure is logged and never fails the run; only a
    /// cancellation is returned.
    fn run_driver_audit(
        &mut self,
        req: &SessionRequest,
        tx: &Sender<EngineEvent>,
    ) -> Result<(), StepError>;
    fn cleanup(&mut self);
}

/// Runs one full diagnostic session on the calling thread. Intended to be
/// spawned on a background `std::thread` by the UI layer; every step is
/// reported back through `tx` so the GUI can render real progress.
pub fn run_session(req: SessionRequest, tx: Sender<EngineEvent>) {
    let mut backend = PsBackend::default();
    run_session_with(&req, &tx, &mut backend);
}

pub(crate) fn run_session_with(
    req: &SessionRequest,
    tx: &Sender<EngineEvent>,
    backend: &mut dyn SessionBackend,
) {
    let started = SystemTime::now();
    let started_local = crate::ui::sysinfo::local_time();
    let mut progress = RunProgress::default();
    let outcome = run_pipeline(req, tx, backend, started, &mut progress);
    match outcome {
        Ok(final_zip) => {
            send(tx, EngineEvent::Stage(Stage::Complete));
            send(tx, EngineEvent::Finished(Ok(final_zip)));
        }
        Err(StepError::Failed(err)) => send(tx, EngineEvent::Finished(Err(err))),
        Err(StepError::Cancelled) => {
            let (zip_path, note) = salvage_cancelled_run(req, &progress, started, started_local);
            send(tx, EngineEvent::Cancelled { zip_path, note });
        }
    }
    // Best-effort cleanup; a failure here must not fail the session.
    backend.cleanup();
}

fn check_cancel(req: &SessionRequest) -> Result<(), StepError> {
    if req.cancel.load(Ordering::SeqCst) {
        Err(StepError::Cancelled)
    } else {
        Ok(())
    }
}

fn run_pipeline(
    req: &SessionRequest,
    tx: &Sender<EngineEvent>,
    backend: &mut dyn SessionBackend,
    started: SystemTime,
    progress: &mut RunProgress,
) -> Result<PathBuf, StepError> {
    send(tx, EngineEvent::Stage(Stage::Preparing));
    send(tx, EngineEvent::Log("Подготовка runtime...".into()));
    check_cancel(req)?;
    let reports = backend.prepare(tx)?;
    progress.reports_root = Some(reports.clone());
    check_cancel(req)?;

    send(tx, EngineEvent::Stage(Stage::SystemDiagnostics));
    progress.current = Some(SessionStep::Expc);
    backend.run_expc(req, tx)?;
    check_cancel(req)?;
    // 2 s tolerance for coarse file-system timestamps.
    let since = started
        .checked_sub(std::time::Duration::from_secs(2))
        .unwrap_or(started);
    if !new_files_since(&reports, since, &["txt", "json"]) {
        return Err(StepError::Failed(
            "EXPC Diagnostic завершился, но ожидаемые TXT/JSON отчёты не найдены.".into(),
        ));
    }
    progress.completed.push(SessionStep::Expc);

    if req.include_hardware {
        send(tx, EngineEvent::Stage(Stage::HardwareReport));
        progress.current = Some(SessionStep::Hardware);
        let hw_started_at = SystemTime::now()
            .checked_sub(std::time::Duration::from_secs(2))
            .unwrap_or_else(SystemTime::now);
        backend.run_hardware(req, tx)?;
        check_cancel(req)?;
        if !new_files_since(&reports, hw_started_at, &["json"]) {
            return Err(StepError::Failed(
                "Hardware Report завершился, но Hardware_*.json не был создан.".into(),
            ));
        }
        progress.completed.push(SessionStep::Hardware);
    }

    progress.current = Some(SessionStep::DriverAudit);
    backend.run_driver_audit(req, tx)?;
    check_cancel(req)?;
    progress.completed.push(SessionStep::DriverAudit);
    progress.current = None;

    // Packaging: the run's evidence joins the session package (the same
    // ZIP that Hardware Report / SSD benchmark / Driver Audit update).
    send(tx, EngineEvent::Stage(Stage::Packaging));
    let files = collect_runtime_evidence(&reports, started)?;
    if files.is_empty() {
        return Err(StepError::Failed(format!(
            "Файлы отчёта не найдены в runtime: {}",
            reports.display()
        )));
    }
    if let Some(run) = crate::deep_checks::from_evidence_files(
        files.iter().map(|f| (f.name.as_str(), f.bytes.as_slice())),
    ) {
        send(tx, EngineEvent::DeepChecks(run.outcomes));
        send(tx, EngineEvent::ExpcChecks(run.checks));
    }
    let date = identity_date(crate::ui::sysinfo::local_time());
    let final_zip = lock(&req.package)
        .contribute(&req.client_name, &req.computer_name, &date, files)
        .map_err(StepError::Failed)?;
    Ok(final_zip)
}

/// Files the run wrote (runtime `Reports\` and its dated sub-folders),
/// read into memory; hidden folders/files and ZIPs are ignored.
fn collect_runtime_evidence(root: &Path, since: SystemTime) -> Result<Vec<EvidenceFile>, String> {
    let since = since
        .checked_sub(std::time::Duration::from_secs(2))
        .unwrap_or(since);
    let mut dirs = vec![root.to_path_buf()];
    dirs.extend(subdirectories(root).into_iter().filter(|d| {
        !d.file_name()
            .map(|n| n.to_string_lossy().starts_with('.'))
            .unwrap_or(true)
    }));
    let mut files = Vec::new();
    for dir in dirs {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        let mut paths: Vec<PathBuf> = entries
            .flatten()
            .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
            .filter(|e| {
                let name = e.file_name().to_string_lossy().to_string();
                !name.starts_with('.') && !name.to_ascii_lowercase().ends_with(".zip")
            })
            .filter(|e| {
                e.metadata()
                    .and_then(|m| m.modified())
                    .map(|t| t >= since)
                    .unwrap_or(false)
            })
            .map(|e| e.path())
            .collect();
        paths.sort();
        for p in paths {
            files.push(EvidenceFile::read(&p)?);
        }
    }
    Ok(files)
}

/// `EXPC_x.txt` -> `EXPC_x_USER_CANCELLED.txt`.
fn cancelled_name(name: &str) -> String {
    match name.rfind('.') {
        Some(i) if i > 0 => format!("{}_{USER_CANCELLED}{}", &name[..i], &name[i..]),
        _ => format!("{name}_{USER_CANCELLED}"),
    }
}

/// Cancellation: keeps what the run already collected (files of the
/// interrupted step are marked `_USER_CANCELLED`), adds a run-status record
/// (`STATUS=USER_CANCELLED`) and updates the session package. Nothing is
/// created when there is no evidence at all.
fn salvage_cancelled_run(
    req: &SessionRequest,
    progress: &RunProgress,
    started: SystemTime,
    started_local: crate::ui::sysinfo::LocalTime,
) -> (Option<PathBuf>, String) {
    let mut files = progress
        .reports_root
        .as_deref()
        .map(|r| collect_runtime_evidence(r, started).unwrap_or_default())
        .unwrap_or_default();
    if let Some(step) = progress.current {
        for f in &mut files {
            if step.owns(&f.name) {
                f.name = cancelled_name(&f.name);
            }
        }
    }
    let mut package = lock(&req.package);
    if files.is_empty() && package.final_zip().is_none() {
        return (
            None,
            "Данные ещё не были собраны — отчёт не создавался.".into(),
        );
    }
    let now = crate::ui::sysinfo::local_time();
    files.push(run_status_record(progress, started_local, now));
    match package.contribute(
        &req.client_name,
        &req.computer_name,
        &identity_date(now),
        files,
    ) {
        Ok(zip) => (
            Some(zip),
            "Собранные данные сохранены в отчёт сессии (запуск помечен USER_CANCELLED).".into(),
        ),
        Err(err) => (package.final_zip(), format!("[ERROR] {err}")),
    }
}

fn run_status_record(
    progress: &RunProgress,
    started: crate::ui::sysinfo::LocalTime,
    stopped: crate::ui::sysinfo::LocalTime,
) -> EvidenceFile {
    let completed = if progress.completed.is_empty() {
        "нет".to_string()
    } else {
        progress
            .completed
            .iter()
            .map(|s| s.label())
            .collect::<Vec<_>>()
            .join(", ")
    };
    let interrupted = progress
        .current
        .map(|s| s.label())
        .unwrap_or("подготовка / между этапами");
    let text = format!(
        "WinStateDiag — статус запуска диагностики\r\n\
         STATUS=USER_CANCELLED\r\n\
         Результат: диагностика остановлена пользователем и НЕ завершена.\r\n\
         Начало: {} {}\r\n\
         Остановлено: {} {}\r\n\
         Прерванный этап: {interrupted}\r\n\
         Завершённые этапы: {completed}\r\n\
         Файлы прерванного этапа сохранены с пометкой _{USER_CANCELLED} и неполны.\r\n",
        started.date_dmy(),
        started.hms(),
        stopped.date_dmy(),
        stopped.hms(),
    );
    let mut bytes = vec![0xEF, 0xBB, 0xBF];
    bytes.extend_from_slice(text.as_bytes());
    EvidenceFile::new(
        format!(
            "EXPC_Diagnostic_{USER_CANCELLED}_{}-{:02}.txt",
            evidence_stamp(stopped),
            stopped.second
        ),
        bytes,
    )
}

// ---------------------------------------------------------------------
// Real backend: the embedded PowerShell engine.
// ---------------------------------------------------------------------

#[derive(Default)]
struct PsBackend {
    runtime: Option<Runtime>,
    session_id: String,
}

impl PsBackend {
    fn runtime(&self) -> Result<&Runtime, StepError> {
        self.runtime
            .as_ref()
            .ok_or_else(|| StepError::Failed("runtime не подготовлен".into()))
    }
}

impl SessionBackend for PsBackend {
    fn prepare(&mut self, _tx: &Sender<EngineEvent>) -> Result<PathBuf, String> {
        let session_id = get_session_id()?;
        let runtime = extract_runtime(&session_id)?;
        initialize_session(&runtime.report_storage, &session_id)?;
        let reports = runtime.reports_root();
        self.session_id = session_id;
        self.runtime = Some(runtime);
        Ok(reports)
    }

    fn run_expc(
        &mut self,
        req: &SessionRequest,
        tx: &Sender<EngineEvent>,
    ) -> Result<(), StepError> {
        let script = self.runtime()?.expc_diagnostic.clone();
        run_expc_diagnostic(&script, req, tx, &runtime_marker(&self.session_id))
    }

    fn run_hardware(
        &mut self,
        req: &SessionRequest,
        tx: &Sender<EngineEvent>,
    ) -> Result<(), StepError> {
        let script = self.runtime()?.hardware_diagnostic.clone();
        run_hardware_diagnostic(&script, req, tx, &runtime_marker(&self.session_id))
    }

    fn run_driver_audit(
        &mut self,
        req: &SessionRequest,
        tx: &Sender<EngineEvent>,
    ) -> Result<(), StepError> {
        let session_id = self.session_id.clone();
        run_driver_audit(self.runtime()?, &session_id, req, tx)
    }

    fn cleanup(&mut self) {
        if let Some(rt) = self.runtime.take() {
            let _ = fs::remove_dir_all(&rt.root);
        }
    }
}

// ---------------------------------------------------------------------
// Driver Audit (read-only; its report joins the session ZIP). A failure
// here is logged and never fails the diagnostic session.
// ---------------------------------------------------------------------

fn run_driver_audit(
    runtime: &Runtime,
    session_id: &str,
    req: &SessionRequest,
    tx: &Sender<EngineEvent>,
) -> Result<(), StepError> {
    use crate::driver_audit::{self, Severity};
    send(
        tx,
        EngineEvent::Log("Проверка драйверов (только чтение)...".into()),
    );
    // Evidence is collected from Reports/<dd-MM-yy>; the session id starts
    // with the same dd-MM-yy.
    let day = session_id.split('_').next().unwrap_or(session_id);
    let day_dir = runtime.reports_root().join(day);
    match driver_audit::run_audit_with_cancel(&runtime.root.join("DriverAudit"), &req.cancel) {
        Ok(report) => {
            send(
                tx,
                EngineEvent::Log(format!(
                    "Проверка драйверов: {} (проблем: {}, предупреждений: {})",
                    report.overall.label_ru(),
                    report.count(Severity::Problem),
                    report.count(Severity::Warning)
                )),
            );
            if let Err(err) = driver_audit::write_report(&report, &day_dir, session_id) {
                send(tx, EngineEvent::Log(format!("[WARN] {err}")));
            }
            send(tx, EngineEvent::DriverAudit(Ok(Box::new(report))));
            Ok(())
        }
        Err(_) if req.cancel.load(Ordering::SeqCst) => Err(StepError::Cancelled),
        Err(err) => {
            send(tx, EngineEvent::Log(format!("[WARN] {err}")));
            send(tx, EngineEvent::DriverAudit(Err(err)));
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------
// Child processes owned by this WinStateDiag session.
// ---------------------------------------------------------------------

/// Why waiting for a child ended early.
pub(crate) enum WaitEnd {
    Cancelled,
    TimedOut,
    Io(std::io::Error),
}

/// A hidden child process together with every process it starts.
///
/// Windows: the child is placed in its own Job Object (kill-on-close), so
/// terminating the job ends exactly this process tree (PowerShell and e.g.
/// the sfc/dism/chkdsk it runs) and nothing else; if the job cannot be
/// created, `taskkill /T /PID <pid>` ends the tree rooted at OUR child's
/// PID. Unrelated powershell.exe processes are never touched.
/// Other hosts (tests): the child leads its own process group.
pub(crate) struct ProcessGuard {
    child: Child,
    #[cfg(windows)]
    job: Option<job::Job>,
}

impl ProcessGuard {
    pub(crate) fn spawn(mut cmd: Command) -> std::io::Result<Self> {
        #[cfg(windows)]
        cmd.creation_flags(CREATE_NO_WINDOW);
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt as _;
            cmd.process_group(0);
        }
        let child = cmd.spawn()?;
        #[cfg(windows)]
        let job = job::Job::for_child(&child);
        Ok(Self {
            child,
            #[cfg(windows)]
            job,
        })
    }

    pub(crate) fn child_mut(&mut self) -> &mut Child {
        &mut self.child
    }

    // Only the Unix process-tree test reads the raw PID.
    #[cfg_attr(any(not(test), not(unix)), allow(dead_code))]
    pub(crate) fn id(&self) -> u32 {
        self.child.id()
    }

    fn is_running(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    /// Terminates this child and every process it started — nothing else.
    pub(crate) fn kill_tree(&mut self) {
        #[cfg(windows)]
        {
            match &self.job {
                Some(job) => job.terminate(),
                None => {
                    let mut kill = Command::new("taskkill.exe");
                    kill.args(["/F", "/T", "/PID", &self.child.id().to_string()])
                        .stdin(Stdio::null())
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .creation_flags(CREATE_NO_WINDOW);
                    let _ = kill.status();
                }
            }
        }
        #[cfg(unix)]
        {
            unsafe extern "C" {
                fn kill(pid: i32, sig: i32) -> i32;
            }
            // The child leads its own process group: signal exactly it.
            const SIGKILL: i32 = 9;
            unsafe {
                kill(-(self.child.id() as i32), SIGKILL);
            }
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    /// Waits for the child to exit; a cancellation (or the optional
    /// timeout) terminates its process tree instead.
    pub(crate) fn wait_or_cancel(
        &mut self,
        cancel: &AtomicBool,
        timeout: Option<std::time::Duration>,
    ) -> Result<std::process::ExitStatus, WaitEnd> {
        let started = std::time::Instant::now();
        loop {
            match self.child.try_wait() {
                Ok(Some(status)) => return Ok(status),
                Ok(None) => {}
                Err(e) => return Err(WaitEnd::Io(e)),
            }
            if cancel.load(Ordering::SeqCst) {
                self.kill_tree();
                return Err(WaitEnd::Cancelled);
            }
            if timeout.is_some_and(|t| started.elapsed() > t) {
                self.kill_tree();
                return Err(WaitEnd::TimedOut);
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }
}

impl Drop for ProcessGuard {
    /// No orphans: a child still running when its owner goes away is ended.
    fn drop(&mut self) {
        if self.is_running() {
            self.kill_tree();
        }
    }
}

#[cfg(windows)]
mod job {
    use std::ffi::c_void;
    use std::os::windows::io::AsRawHandle;
    use std::process::Child;

    #[repr(C)]
    #[derive(Default)]
    struct BasicLimit {
        per_process_user_time_limit: i64,
        per_job_user_time_limit: i64,
        limit_flags: u32,
        minimum_working_set_size: usize,
        maximum_working_set_size: usize,
        active_process_limit: u32,
        affinity: usize,
        priority_class: u32,
        scheduling_class: u32,
    }

    #[repr(C)]
    #[derive(Default)]
    struct IoCounters {
        counts: [u64; 6],
    }

    #[repr(C)]
    #[derive(Default)]
    struct ExtendedLimit {
        basic: BasicLimit,
        io: IoCounters,
        process_memory_limit: usize,
        job_memory_limit: usize,
        peak_process_memory_used: usize,
        peak_job_memory_used: usize,
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateJobObjectW(attributes: *mut c_void, name: *const u16) -> *mut c_void;
        fn SetInformationJobObject(
            job: *mut c_void,
            class: i32,
            info: *mut c_void,
            len: u32,
        ) -> i32;
        fn AssignProcessToJobObject(job: *mut c_void, process: *mut c_void) -> i32;
        fn TerminateJobObject(job: *mut c_void, exit_code: u32) -> i32;
        fn CloseHandle(handle: *mut c_void) -> i32;
    }

    const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION: i32 = 9;
    const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: u32 = 0x2000;

    pub struct Job(*mut c_void);

    // The handle is only used through the owning ProcessGuard.
    unsafe impl Send for Job {}

    impl Job {
        pub fn for_child(child: &Child) -> Option<Job> {
            unsafe {
                let handle = CreateJobObjectW(std::ptr::null_mut(), std::ptr::null());
                if handle.is_null() {
                    return None;
                }
                let job = Job(handle);
                let mut info = ExtendedLimit::default();
                info.basic.limit_flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                let ok = SetInformationJobObject(
                    handle,
                    JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                    &mut info as *mut ExtendedLimit as *mut c_void,
                    std::mem::size_of::<ExtendedLimit>() as u32,
                );
                if ok == 0 {
                    return None;
                }
                if AssignProcessToJobObject(handle, child.as_raw_handle() as *mut c_void) == 0 {
                    return None;
                }
                Some(job)
            }
        }

        pub fn terminate(&self) {
            unsafe {
                TerminateJobObject(self.0, 1);
            }
        }
    }

    impl Drop for Job {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

// ---------------------------------------------------------------------
// Runtime extraction
// ---------------------------------------------------------------------

struct Runtime {
    root: PathBuf,
    expc_diagnostic: PathBuf,
    hardware_diagnostic: PathBuf,
    report_storage: PathBuf,
}

impl Runtime {
    fn reports_root(&self) -> PathBuf {
        self.root.join("Reports")
    }
}

fn extract_runtime(session_id: &str) -> Result<Runtime, String> {
    let root = std::env::temp_dir().join("WinStateDiag").join(session_id);
    let expc_dir = root.join("EXPC-Diagnostic");
    let hw_dir = root.join("Hardware-Diagnostic");

    fs::create_dir_all(&expc_dir).map_err(|e| format!("Не удалось создать runtime: {e}"))?;
    fs::create_dir_all(&hw_dir).map_err(|e| format!("Не удалось создать runtime: {e}"))?;

    write_embedded(&root.join("Compatibility.psm1"), COMPATIBILITY_PSM1)?;
    write_embedded(&root.join("ReportStorage.psm1"), REPORT_STORAGE_PSM1)?;
    write_embedded(&expc_dir.join("EXPC-Diagnostic.ps1"), EXPC_DIAGNOSTIC_PS1)?;
    write_embedded(
        &hw_dir.join("Hardware-Diagnostic.ps1"),
        HARDWARE_DIAGNOSTIC_PS1,
    )?;
    write_embedded(
        &hw_dir.join("HardwarePassport.psm1"),
        HARDWARE_PASSPORT_PSM1,
    )?;

    Ok(Runtime {
        expc_diagnostic: expc_dir.join("EXPC-Diagnostic.ps1"),
        hardware_diagnostic: hw_dir.join("Hardware-Diagnostic.ps1"),
        report_storage: root.join("ReportStorage.psm1"),
        root,
    })
}

fn write_embedded(path: &Path, bytes: &[u8]) -> Result<(), String> {
    fs::write(path, bytes).map_err(|e| format!("Не удалось записать {}: {e}", path.display()))
}

// ---------------------------------------------------------------------
// PowerShell process helpers
// ---------------------------------------------------------------------

fn powershell_command() -> Command {
    let mut cmd = Command::new("powershell.exe");
    cmd.arg("-NoLogo")
        .arg("-NoProfile")
        .arg("-ExecutionPolicy")
        .arg("Bypass");
    cmd
}

fn spawn_hidden(mut cmd: Command) -> std::io::Result<Child> {
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd.spawn()
}

/// Gets the session id using the exact same format the proven launcher
/// (`Run_WinDiagProbe.bat`) uses, so the naming convention stays identical.
fn get_session_id() -> Result<String, String> {
    let mut cmd = powershell_command();
    cmd.arg("-Command")
        .arg("Get-Date -Format dd-MM-yy_HH-mm-ss");
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let output = spawn_hidden(cmd)
        .and_then(|c| c.wait_with_output())
        .map_err(|e| format!("Не удалось получить SessionId: {e}"))?;
    let id = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if id.is_empty() {
        return Err("SessionId пуст.".into());
    }
    Ok(id)
}

fn initialize_session(report_storage: &Path, session_id: &str) -> Result<(), String> {
    let script = format!(
        "Import-Module '{}' -Force; Initialize-WinDiagSession -SessionId '{}' | Out-Null",
        ps_quote_path(report_storage),
        session_id
    );
    let mut cmd = powershell_command();
    cmd.arg("-Command").arg(script);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let output = spawn_hidden(cmd)
        .and_then(|c| c.wait_with_output())
        .map_err(|e| format!("Не удалось запустить Initialize-WinDiagSession: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "Initialize-WinDiagSession завершился с ошибкой: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(())
}

/// PowerShell single-quoted string literal escaping (double any embedded
/// single quote). Paths from `std::env::temp_dir()` never contain them in
/// practice, but this keeps the call correct regardless.
fn ps_quote_path(path: &Path) -> String {
    path.display().to_string().replace('\'', "''")
}

// ---------------------------------------------------------------------
// EXPC Diagnostic (interactive baseline, driven non-interactively via
// redirected stdin -- the exact same prompts a human answers at the
// console, in the exact same order. The baseline script itself is never
// modified.)
// ---------------------------------------------------------------------

/// Builds the exact newline-separated stdin answer sequence EXPC-Diagnostic
/// expects for modes 1/2/3, in the exact order its own `Read-Host` calls
/// occur (see EXPC-Diagnostic.ps1: Company name -> Station name -> Mode ->
/// [SFC, DISM, CHKDSK if mode 2] -> final "press Enter to exit"). Pulled
/// out as a pure function so the sequence can be unit tested without
/// spawning a real process.
fn build_expc_answers(req: &SessionRequest) -> String {
    let mut answers = String::new();
    answers.push_str(req.client_name.trim());
    answers.push('\n');
    answers.push('\n'); // station name: accept the auto-detected computer name
    let mode_digit = match req.mode {
        DiagnosticMode::Standard => "1",
        DiagnosticMode::CustomDeepChecks => "2",
        DiagnosticMode::Full => "3",
    };
    answers.push_str(mode_digit);
    answers.push('\n');
    if matches!(req.mode, DiagnosticMode::CustomDeepChecks) {
        answers.push_str(if req.deep_checks.sfc { "y" } else { "n" });
        answers.push('\n');
        answers.push_str(if req.deep_checks.dism { "y" } else { "n" });
        answers.push('\n');
        answers.push_str(if req.deep_checks.chkdsk { "y" } else { "n" });
        answers.push('\n');
    }
    answers.push('\n'); // final "Press Enter to exit"
    answers
}

fn run_expc_diagnostic(
    script_path: &Path,
    req: &SessionRequest,
    tx: &Sender<EngineEvent>,
    marker: &str,
) -> Result<(), StepError> {
    let mut cmd = powershell_command();
    cmd.arg("-File").arg(script_path);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut guard = ProcessGuard::spawn(cmd)
        .map_err(|e| StepError::Failed(format!("Не удалось запустить EXPC Diagnostic: {e}")))?;

    // Build the full answer sequence up front; Read-Host on the other end
    // simply blocks until a line is available, so exact timing does not
    // matter as long as the order matches the script's own prompt order.
    let answers = build_expc_answers(req);

    if let Some(mut stdin) = guard.child_mut().stdin.take() {
        std::thread::spawn(move || {
            let _ = stdin.write_all(answers.as_bytes());
            // Dropping `stdin` here closes the pipe (EOF) once the write
            // finishes, which is fine even if the script already exited.
        });
    }

    let stderr_thread = guard.child_mut().stderr.take().map(|stderr| {
        let stderr_tx = tx.clone();
        let marker = marker.to_string();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                if let Some(line) = mask_runtime_line(&line, &marker, true) {
                    send(&stderr_tx, EngineEvent::Log(format!("[stderr] {line}")));
                }
            }
        })
    });

    let stdout_thread = guard.child_mut().stdout.take().map(|stdout| {
        let out_tx = tx.clone();
        let marker = marker.to_string();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if let Some((percent, message)) = parse_expc_progress(&line) {
                    send(&out_tx, EngineEvent::ExpcProgress { percent, message });
                } else if let Some(line) = mask_runtime_line(&line, &marker, false) {
                    send(&out_tx, EngineEvent::Log(line));
                }
            }
        })
    });

    let waited = guard.wait_or_cancel(&req.cancel, None);
    for thread in [stdout_thread, stderr_thread].into_iter().flatten() {
        let _ = thread.join();
    }
    let status = match waited {
        Ok(status) => status,
        Err(WaitEnd::Cancelled) => return Err(StepError::Cancelled),
        Err(WaitEnd::TimedOut) => {
            return Err(StepError::Failed(
                "EXPC Diagnostic: превышено время ожидания.".into(),
            ));
        }
        Err(WaitEnd::Io(e)) => {
            return Err(StepError::Failed(format!(
                "EXPC Diagnostic: ошибка ожидания процесса: {e}"
            )));
        }
    };

    if !status.success() {
        return Err(StepError::Failed(format!(
            "EXPC Diagnostic завершился с кодом {:?}.",
            status.code()
        )));
    }
    Ok(())
}

/// ASCII tail of the internal runtime path (`...\WinStateDiag\<sid>`);
/// it survives even when PowerShell mangles a Cyrillic %TEMP% prefix.
fn runtime_marker(session_id: &str) -> String {
    format!("WinStateDiag\\{session_id}")
}

const RUNTIME_PLACEHOLDER: &str = "[временная папка]";

/// Journal hygiene: the internal %TEMP% runtime is never shown as a report
/// location. Output lines naming it (and the bare "Reports:" header) are
/// dropped; error lines (`keep`) are kept with the path masked.
fn mask_runtime_line(line: &str, marker: &str, keep: bool) -> Option<String> {
    if line.trim() == "Reports:" {
        return None;
    }
    let mut out = line.to_string();
    while let Some(at) = out.find(marker) {
        // Start of the path: its drive ("X:\") before the marker, if any.
        let head = &out[..at];
        let start = head
            .rfind(":\\")
            .and_then(|i| i.checked_sub(1))
            .filter(|&i| head.as_bytes()[i].is_ascii_alphabetic())
            .unwrap_or(at);
        out.replace_range(start..at + marker.len(), RUNTIME_PLACEHOLDER);
    }
    if out != line && !keep {
        return None;
    }
    Some(out)
}

fn parse_expc_progress(line: &str) -> Option<(u32, String)> {
    let payload = line.strip_prefix("WSD_PROGRESS|")?;
    let (percent, message) = payload.split_once('|')?;
    let percent = percent.parse::<u32>().ok()?.min(100);
    let message = message.trim();
    if message.is_empty() {
        return None;
    }
    Some((percent, message.to_string()))
}

// ---------------------------------------------------------------------
// Hardware Diagnostic (already fully non-interactive; -Sta is required
// because the proven script loads System.Windows.Forms).
// ---------------------------------------------------------------------

fn run_hardware_diagnostic(
    script_path: &Path,
    req: &SessionRequest,
    tx: &Sender<EngineEvent>,
    marker: &str,
) -> Result<(), StepError> {
    let mut cmd = powershell_command();
    cmd.arg("-Sta")
        .arg("-File")
        .arg(script_path)
        .arg("-NoGui")
        .arg("-ExportAll");
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());

    let mut guard = ProcessGuard::spawn(cmd)
        .map_err(|e| StepError::Failed(format!("Не удалось запустить Hardware Report: {e}")))?;

    let stdout_thread = guard.child_mut().stdout.take().map(|stdout| {
        let out_tx = tx.clone();
        let marker = marker.to_string();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if let Some(line) = mask_runtime_line(&line, &marker, false) {
                    send(&out_tx, EngineEvent::Log(line));
                }
            }
        })
    });

    let waited = guard.wait_or_cancel(&req.cancel, None);
    if let Some(thread) = stdout_thread {
        let _ = thread.join();
    }
    let status = match waited {
        Ok(status) => status,
        Err(WaitEnd::Cancelled) => return Err(StepError::Cancelled),
        Err(WaitEnd::TimedOut) => {
            return Err(StepError::Failed(
                "Hardware Report: превышено время ожидания.".into(),
            ));
        }
        Err(WaitEnd::Io(e)) => {
            return Err(StepError::Failed(format!(
                "Hardware Report: ошибка ожидания процесса: {e}"
            )));
        }
    };
    if !status.success() {
        return Err(StepError::Failed(format!(
            "Hardware Report завершился с кодом {:?}.",
            status.code()
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------
// Hardware Report "Смотреть": hidden collection -> evidence persisted into
// the session package -> THEN the viewer window. No console window; the
// viewer's "Открыть папку отчёта" is the session folder under <EXE>\Reports.
// ---------------------------------------------------------------------

/// Hidden collection may take a while on slow servers; this only guards
/// against a hung collector (the viewer itself has no time limit).
const HARDWARE_COLLECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(600);

#[derive(Debug)]
pub enum HardwareEvent {
    /// Collection finished; the report files are being written.
    Saving,
    /// The collected evidence was persisted (ZIP path) or not; the viewer
    /// opens next either way.
    Persisted(Result<PathBuf, String>),
    /// "Обновить" in the viewer produced new evidence.
    Refreshed(Result<PathBuf, String>),
    /// Collection failed; no viewer.
    Failed(String),
    /// The viewer was closed.
    Closed,
}

pub struct HardwareViewRequest {
    pub client_name: String,
    pub computer_name: String,
    pub date: String,
    /// The session report folder (`<EXE>\Reports\<...>`), resolved once.
    pub report_dir: PathBuf,
    pub package: SharedPackage,
}

/// Runs the whole "Смотреть" flow on the calling (background) thread.
pub fn run_hardware_view(req: HardwareViewRequest, tx: Sender<HardwareEvent>) {
    // Each viewer launch gets its own internal working folder; it is
    // removed when the viewer closes and is never shown to the user.
    let tag = format!(
        "view-{}",
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or_default()
    );
    let runtime = match extract_runtime(&tag) {
        Ok(rt) => rt,
        Err(err) => {
            let _ = tx.send(HardwareEvent::Failed(err));
            return;
        }
    };
    let event = match hardware_view_inner(&req, &runtime, &tx) {
        Ok(()) => HardwareEvent::Closed,
        Err(err) => HardwareEvent::Failed(err),
    };
    // The internal working folder goes away before the UI hears "closed".
    let _ = fs::remove_dir_all(&runtime.root);
    let _ = tx.send(event);
}

fn hardware_view_inner(
    req: &HardwareViewRequest,
    runtime: &Runtime,
    tx: &Sender<HardwareEvent>,
) -> Result<(), String> {
    use std::sync::mpsc::RecvTimeoutError;
    let mut cmd = powershell_command();
    cmd.arg("-Sta")
        .arg("-File")
        .arg(&runtime.hardware_diagnostic)
        .arg("-WsdViewer")
        .arg("-ReportFolder")
        .arg(&req.report_dir);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut guard = ProcessGuard::spawn(cmd)
        .map_err(|e| format!("Не удалось запустить Hardware Report: {e}"))?;
    let mut stdin = guard.child_mut().stdin.take();
    let stdout = guard
        .child_mut()
        .stdout
        .take()
        .ok_or("Hardware Report: нет вывода процесса.")?;
    let (line_tx, line_rx) = std::sync::mpsc::channel::<String>();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if line_tx.send(line).is_err() {
                break;
            }
        }
    });

    let started = std::time::Instant::now();
    let mut shown = false;
    let mut last_error = String::new();
    loop {
        match line_rx.recv_timeout(std::time::Duration::from_millis(200)) {
            Ok(line) => {
                let line = line.trim().to_string();
                if line == "WSD_HW_PHASE|report" {
                    let _ = tx.send(HardwareEvent::Saving);
                } else if let Some(base) = line.strip_prefix("WSD_HW_SAVED|") {
                    let result = persist_hardware_evidence(req, &runtime.reports_root(), base);
                    if shown {
                        let _ = tx.send(HardwareEvent::Refreshed(result));
                    } else {
                        let _ = tx.send(HardwareEvent::Persisted(result));
                        // Evidence is persisted: now the viewer may open.
                        if let Some(mut input) = stdin.take() {
                            let _ = input.write_all(b"SHOW\r\n");
                            let _ = input.flush();
                        }
                        shown = true;
                    }
                } else if line.starts_with("[ERROR]") {
                    last_error = line;
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                if !shown && started.elapsed() > HARDWARE_COLLECT_TIMEOUT {
                    guard.kill_tree();
                    let _ = reader.join();
                    return Err("Сбор данных об оборудовании не завершился за 10 минут.".into());
                }
            }
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
    let _ = reader.join();
    drop(stdin);
    let status = guard
        .child_mut()
        .wait()
        .map_err(|e| format!("Hardware Report: ошибка ожидания процесса: {e}"))?;
    if !shown {
        return Err(if last_error.is_empty() {
            format!(
                "Hardware Report завершился (код {:?}) без данных.",
                status.code()
            )
        } else {
            last_error
        });
    }
    Ok(())
}

/// Copies `<base>.txt/.json/.html` from the internal working folder into
/// the session package (evidence persisted, ZIP updated).
fn persist_hardware_evidence(
    req: &HardwareViewRequest,
    runtime_reports: &Path,
    base: &str,
) -> Result<PathBuf, String> {
    let files = find_hardware_files(runtime_reports, base.trim())?;
    lock(&req.package).contribute(&req.client_name, &req.computer_name, &req.date, files)
}

fn find_hardware_files(root: &Path, base: &str) -> Result<Vec<EvidenceFile>, String> {
    if base.is_empty() || base.contains(['/', '\\']) {
        return Err(format!(
            "Hardware Report: некорректное имя отчёта «{base}»."
        ));
    }
    let mut dirs = vec![root.to_path_buf()];
    dirs.extend(subdirectories(root));
    let mut files = Vec::new();
    for ext in ["txt", "json", "html"] {
        let name = format!("{base}.{ext}");
        if let Some(path) = dirs.iter().map(|d| d.join(&name)).find(|p| p.is_file()) {
            files.push(EvidenceFile::read(&path)?);
        }
    }
    if files.is_empty() {
        return Err(format!("Hardware Report: файлы {base}.* не найдены."));
    }
    Ok(files)
}

// ---------------------------------------------------------------------
// Session packaging + relocation next to the portable EXE
// ---------------------------------------------------------------------

/// Searches the temp runtime's `Reports\` tree for a ZIP matching the
/// session id. Returns the first valid candidate (exists, is_file, size > 0).
/// This is the fallback when the path returned by PowerShell stdout is
/// encoding-mangled or otherwise invalid.
#[cfg_attr(not(test), allow(dead_code))] // superseded by report_package
fn discover_session_zip(reports_root: &Path, session_id: &str) -> Option<PathBuf> {
    let expected_name = format!("EXPC_Diagnostics_{session_id}.zip");

    // Check each date subdirectory (the normal location).
    for sub in subdirectories(reports_root) {
        let candidate = sub.join(&expected_name);
        if is_valid_zip(&candidate) {
            return Some(candidate);
        }
    }

    // Also check directly in reports_root (defensive).
    let candidate = reports_root.join(&expected_name);
    if is_valid_zip(&candidate) {
        return Some(candidate);
    }

    None
}

/// Returns `true` when `path` exists as a regular file with non-zero size.
#[cfg_attr(not(test), allow(dead_code))] // superseded by report_package
fn is_valid_zip(path: &Path) -> bool {
    fs::metadata(path)
        .map(|m| m.is_file() && m.len() > 0)
        .unwrap_or(false)
}

/// Windows-invalid file name characters that must never reach the name.
const INVALID_FILE_NAME_CHARS: [char; 9] = ['\\', '/', ':', '*', '?', '"', '<', '>', '|'];

/// Cleans one name part: invalid characters (and control characters) become
/// spaces, whitespace runs collapse to one space, and leading/trailing
/// spaces and dots are dropped (Windows rejects trailing dots/spaces).
fn sanitize_name_part(raw: &str) -> String {
    let replaced: String = raw
        .chars()
        .map(|c| {
            if INVALID_FILE_NAME_CHARS.contains(&c) || c.is_control() {
                ' '
            } else {
                c
            }
        })
        .collect();
    let collapsed = replaced.split_whitespace().collect::<Vec<_>>().join(" ");
    collapsed
        .trim_matches(|c: char| c == '.' || c.is_whitespace())
        .to_string()
}

/// Previous archive naming (`<ClientName> <CompanyName> - DD-MM-YY.zip`),
/// superseded by [`report_base_name`]; kept with its regression tests.
///
/// Builds the final archive file name:
/// `<ClientName> <CompanyName> - DD-MM-YY.zip`, omitting empty parts and
/// not repeating the company when it is effectively the same as the client
/// (case-insensitive, whitespace-normalised). No time, no technical
/// prefixes. When both parts are empty the name is just `DD-MM-YY.zip`.
#[cfg_attr(not(test), allow(dead_code))]
fn final_zip_file_name(client: &str, company: &str, date: &str) -> String {
    const MAX_NAME_CHARS: usize = 120;
    let client = sanitize_name_part(client);
    let mut company = sanitize_name_part(company);
    if !company.is_empty() && company.to_lowercase() == client.to_lowercase() {
        company.clear();
    }
    let mut base = [client, company]
        .into_iter()
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    if base.chars().count() > MAX_NAME_CHARS {
        base = base.chars().take(MAX_NAME_CHARS).collect::<String>();
        base = base
            .trim_end_matches(|c: char| c == '.' || c.is_whitespace())
            .to_string();
    }
    let date = sanitize_name_part(date);
    if base.is_empty() {
        format!("{date}.zip")
    } else {
        format!("{base} - {date}.zip")
    }
}

/// `dir/name`, or `dir/<stem> (2).zip`, `(3)`, ... when that file already
/// exists — the name has no time part, so a second report for the same
/// client on the same day must never overwrite the first one.
fn unique_destination(dir: &Path, file_name: &str) -> PathBuf {
    let first = dir.join(file_name);
    if !first.exists() {
        return first;
    }
    let (stem, ext) = match file_name.rsplit_once('.') {
        Some((s, e)) => (s.to_string(), format!(".{e}")),
        None => (file_name.to_string(), String::new()),
    };
    (2..)
        .map(|n| dir.join(format!("{stem} ({n}){ext}")))
        .find(|p| !p.exists())
        .unwrap_or(first)
}

/// Test-only convenience: relocate keeping the temp archive's own name.
#[cfg(test)]
fn relocate_zip(temp_zip: &Path, exe_dir: &Path) -> Result<PathBuf, String> {
    let file_name = temp_zip
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("Не удалось определить имя ZIP-файла.")?
        .to_string();
    relocate_zip_as(temp_zip, exe_dir, &file_name)
}

/// Report identity used for the final folder and the ZIP:
/// `<Client> - <Computer> - DD-MM-YY`, or `<Computer> - DD-MM-YY` without a
/// client. Parts are trimmed and made Windows-safe; empty parts are omitted
/// (nothing is invented).
pub fn report_base_name(client: &str, computer: &str, date: &str) -> String {
    const MAX_PART_CHARS: usize = 80;
    let cap = |s: String| -> String {
        if s.chars().count() <= MAX_PART_CHARS {
            return s;
        }
        s.chars()
            .take(MAX_PART_CHARS)
            .collect::<String>()
            .trim_end_matches(|c: char| c == '.' || c.is_whitespace())
            .to_string()
    };
    let parts = [
        cap(sanitize_name_part(client)),
        cap(sanitize_name_part(computer)),
        sanitize_name_part(date),
    ];
    let base = parts
        .into_iter()
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join(" - ");
    if base.is_empty() {
        "WinStateDiag".into()
    } else {
        base
    }
}

/// `root/base`, or `root/base (2)`, `(3)`, ... when that folder (or a file
/// with that name) already exists: an existing report folder is never
/// reused or overwritten.
pub fn unique_report_dir(root: &Path, base: &str) -> PathBuf {
    let first = root.join(base);
    if !first.exists() {
        return first;
    }
    (2..)
        .map(|n| root.join(format!("{base} ({n})")))
        .find(|p| !p.exists())
        .unwrap_or(first)
}

/// Places the verified session ZIP at
/// `<EXE dir>\Reports\<base>\<base>.zip` (a new folder per report). The
/// temporary source is never modified; on failure an empty new folder is
/// removed again and the source stays where it is.
/// Test access to the real final-placement step (temp ZIP -> Reports).
#[cfg(test)]
pub fn place_final_report_for_tests(
    temp_zip: &Path,
    exe_dir: &Path,
    base: &str,
) -> Result<PathBuf, String> {
    place_final_report(temp_zip, exe_dir, base)
}

#[cfg_attr(not(test), allow(dead_code))] // superseded by report_package
fn place_final_report(temp_zip: &Path, exe_dir: &Path, base: &str) -> Result<PathBuf, String> {
    let src_len = validate_zip_source(temp_zip, exe_dir)?;
    let reports = exe_dir.join("Reports");
    fs::create_dir_all(&reports).map_err(|e| {
        format!(
            "Не удалось создать папку отчётов: {e}\n— путь: {}",
            reports.display()
        )
    })?;
    let dest_dir = unique_report_dir(&reports, base);
    fs::create_dir(&dest_dir).map_err(|e| {
        format!(
            "Не удалось создать папку отчёта: {e}\n— путь: {}",
            dest_dir.display()
        )
    })?;
    let dest_path = unique_destination(&dest_dir, &format!("{base}.zip"));
    match copy_and_verify(temp_zip, &dest_path, src_len) {
        Ok(()) => Ok(dest_path),
        Err(err) => {
            let _ = fs::remove_file(&dest_path);
            let _ = fs::remove_dir(&dest_dir); // only succeeds when empty
            Err(err)
        }
    }
}

/// The folder that holds a final report (what "Открыть папку" opens).
pub fn report_folder_of(report: &Path) -> PathBuf {
    report
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| report.to_path_buf())
}

#[cfg_attr(not(test), allow(dead_code))] // superseded by report_package
fn validate_zip_source(temp_zip: &Path, exe_dir: &Path) -> Result<u64, String> {
    if !temp_zip.is_file() {
        let parent_exists = temp_zip.parent().map(|p| p.exists()).unwrap_or(false);
        return Err(format!(
            "ZIP-источник не найден.\n\
             — путь: {}\n\
             — родительская папка существует: {parent_exists}\n\
             — exe_dir: {}",
            temp_zip.display(),
            exe_dir.display()
        ));
    }
    let src_len = fs::metadata(temp_zip).map(|m| m.len()).unwrap_or(0);
    if src_len == 0 {
        return Err(format!(
            "ZIP-источник пуст (0 байт): {}",
            temp_zip.display()
        ));
    }
    Ok(src_len)
}

/// Copies and verifies size and the ZIP signature (`PK`) of the copy.
#[cfg_attr(not(test), allow(dead_code))] // superseded by report_package
fn copy_and_verify(temp_zip: &Path, dest_path: &Path, src_len: u64) -> Result<(), String> {
    fs::copy(temp_zip, dest_path).map_err(|e| {
        format!(
            "Не удалось скопировать ZIP отчёта: {e}\n— источник: {}\n— назначение: {}",
            temp_zip.display(),
            dest_path.display()
        )
    })?;
    let dest_len = fs::metadata(dest_path).map(|m| m.len()).unwrap_or(0);
    if dest_len != src_len {
        return Err(format!(
            "Размер копии ({dest_len}) не совпадает с источником ({src_len}): {}",
            dest_path.display()
        ));
    }
    let mut sig = [0u8; 2];
    let ok = fs::File::open(dest_path)
        .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut sig))
        .is_ok();
    if !ok || &sig != b"PK" {
        return Err(format!(
            "Скопированный файл не является ZIP-архивом: {}",
            dest_path.display()
        ));
    }
    Ok(())
}

/// Copies the session ZIP from the temp runtime's `Reports\<date>\` folder
/// to `<EXE dir>\Reports\<date>\` under `file_name`, reusing the date folder
/// name PowerShell itself picked (so Rust never has to reimplement its date
/// formatting).
#[cfg_attr(not(test), allow(dead_code))]
fn relocate_zip_as(temp_zip: &Path, exe_dir: &Path, file_name: &str) -> Result<PathBuf, String> {
    // --- source validation ------------------------------------------------
    if !temp_zip.is_file() {
        let parent_exists = temp_zip.parent().map(|p| p.exists()).unwrap_or(false);
        return Err(format!(
            "ZIP-источник не найден.\n\
             — путь: {}\n\
             — родительская папка существует: {parent_exists}\n\
             — exe_dir: {}",
            temp_zip.display(),
            exe_dir.display()
        ));
    }

    let src_len = fs::metadata(temp_zip).map(|m| m.len()).unwrap_or(0);
    if src_len == 0 {
        return Err(format!(
            "ZIP-источник пуст (0 байт): {}",
            temp_zip.display()
        ));
    }

    // --- destination construction -----------------------------------------
    let date_dir_name = temp_zip
        .parent()
        .and_then(|p| p.file_name())
        .ok_or("Не удалось определить папку даты отчёта.")?;

    let dest_dir = exe_dir.join("Reports").join(date_dir_name);
    fs::create_dir_all(&dest_dir).map_err(|e| {
        format!(
            "Не удалось создать папку назначения: {e}\n— путь: {}",
            dest_dir.display()
        )
    })?;
    let dest_path = unique_destination(&dest_dir, file_name);

    // --- copy -------------------------------------------------------------
    fs::copy(temp_zip, &dest_path).map_err(|e| {
        let src_exists = temp_zip.exists();
        let src_is_file = temp_zip.is_file();
        let parent_exists = temp_zip.parent().map(|p| p.exists()).unwrap_or(false);
        format!(
            "Не удалось скопировать ZIP отчёта: {e}\n\
             — источник: {}\n\
             — существует: {src_exists}, файл: {src_is_file}, размер: {src_len}\n\
             — родительская папка существует: {parent_exists}\n\
             — назначение: {}",
            temp_zip.display(),
            dest_path.display()
        )
    })?;

    // --- destination verification -----------------------------------------
    let dest_len = fs::metadata(&dest_path).map(|m| m.len()).unwrap_or(0);
    if dest_len == 0 {
        return Err(format!(
            "ZIP скопирован, но файл назначения пуст: {}",
            dest_path.display()
        ));
    }
    if dest_len != src_len {
        return Err(format!(
            "Размер копии ({dest_len}) не совпадает с источником ({src_len}): {}",
            dest_path.display()
        ));
    }

    Ok(dest_path)
}

/// True if `dir` or any of its immediate subdirectories (Reports\<date>\ is
/// one level below the `Reports\` root returned by `Runtime::reports_root`)
/// has at least one file with a matching extension modified at/after
/// `since`.
fn new_files_since(dir: &Path, since: SystemTime, extensions: &[&str]) -> bool {
    has_matching_file(dir, since, extensions)
        || subdirectories(dir)
            .iter()
            .any(|sub| has_matching_file(sub, since, extensions))
}

fn has_matching_file(dir: &Path, since: SystemTime, extensions: &[&str]) -> bool {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return false,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
            continue;
        };
        if !extensions.iter().any(|want| want.eq_ignore_ascii_case(ext)) {
            continue;
        }
        if let Ok(meta) = entry.metadata() {
            if let Ok(modified) = meta.modified() {
                if modified >= since {
                    return true;
                }
            }
        }
    }
    false
}

fn subdirectories(dir: &Path) -> Vec<PathBuf> {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };
    entries
        .flatten()
        .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
        .map(|e| e.path())
        .collect()
}

// ---------------------------------------------------------------------
// Progress presentation (pure, unit-tested math; the GUI layer only
// renders whatever this returns).
// ---------------------------------------------------------------------

pub fn stage_label(stage: &Stage) -> &'static str {
    match stage {
        Stage::Preparing => "Preparing / Подготовка",
        Stage::SystemDiagnostics => "System diagnostics / Диагностика Windows",
        Stage::HardwareReport => "Hardware Report / Сбор данных об оборудовании",
        Stage::Packaging => "Packaging / Упаковка отчёта",
        Stage::Complete => "Complete / Готово",
    }
}

/// Computes the overall session progress as a single 0.0..=1.0 fraction,
/// taking into account the current stage, weighted EXPC step progress,
/// and whether hardware report is included.
///
/// This replaces the coarse `stage_fraction` with a weighted scheme that
/// gives long-running deep checks (SFC, DISM, CHKDSK) proportionally more
/// visual space. The function is pure and deterministic.
///
/// `step_weights` is an array of accumulated credit for each EXPC step:
///   - pending / not yet started = 0%
///   - indeterminate running (no native %) = 10% of weight
///   - determinate running (has NN% from PS1) = 10% + 80% × (NN/100) of weight
///   - done or skipped = 100% of weight
///
/// For simplicity the caller passes `expc_credit` as the sum of per-step
/// credit (each in 0.0..=step_weight).
pub fn session_fraction(stage: &Stage, expc_credit: f32, total_weight: f32, hardware: bool) -> f32 {
    // Session timeline allocation:
    //   Preparing:         0.00 .. 0.03
    //   SystemDiagnostics: 0.03 .. expc_end
    //   HardwareReport:    expc_end .. 0.90  (only if hardware)
    //   Packaging:         0.90 .. 0.97
    //   Complete:          1.00
    let expc_end: f32 = if hardware { 0.70 } else { 0.90 };

    match stage {
        Stage::Preparing => 0.02,
        Stage::SystemDiagnostics => {
            let frac = if total_weight <= 0.0 {
                0.0
            } else {
                (expc_credit / total_weight).clamp(0.0, 1.0)
            };
            0.03 + frac * (expc_end - 0.03)
        }
        Stage::HardwareReport => {
            // EXPC is done, hardware is running but indeterminate
            expc_end + (0.90 - expc_end) * 0.5
        }
        Stage::Packaging => 0.93,
        Stage::Complete => 1.0,
    }
}

/// Opens Windows Explorer with the given file pre-selected.
/// Opens Explorer with the given file selected — used for "Открыть отчёт".
/// Opens the final report with its Windows associated action
/// (ShellExecuteW "open"); Unicode paths and spaces are passed as UTF-16.
pub fn open_report(path: &Path) -> Result<(), String> {
    if !path.is_file() {
        return Err(format!("Файл отчёта не найден: {}", path.display()));
    }
    shell_open(path).map_err(|e| format!("Не удалось открыть отчёт: {e}"))
}

/// Opens Explorer directly in the report's own folder.
pub fn open_report_folder(report: &Path) -> Result<(), String> {
    let dir = report_folder_of(report);
    if !dir.is_dir() {
        return Err(format!("Папка отчёта не найдена: {}", dir.display()));
    }
    shell_open(&dir).map_err(|e| format!("Не удалось открыть папку: {e}"))
}

// Unit tests never launch the Windows shell.
#[cfg(all(windows, not(test)))]
fn shell_open(target: &Path) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    #[link(name = "shell32")]
    unsafe extern "system" {
        fn ShellExecuteW(
            hwnd: isize,
            op: *const u16,
            file: *const u16,
            params: *const u16,
            dir: *const u16,
            show: i32,
        ) -> isize;
    }
    const SW_SHOWNORMAL: i32 = 1;
    let wide = |s: &std::ffi::OsStr| {
        s.encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<u16>>()
    };
    let op = wide(std::ffi::OsStr::new("open"));
    let file = wide(target.as_os_str());
    let rc = unsafe {
        ShellExecuteW(
            0,
            op.as_ptr(),
            file.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        )
    };
    if rc > 32 {
        Ok(())
    } else {
        Err(format!("ShellExecute код {rc}"))
    }
}

#[cfg(any(not(windows), test))]
fn shell_open(target: &Path) -> Result<(), String> {
    Err(format!(
        "открытие через оболочку Windows недоступно: {}",
        target.display()
    ))
}

/// The only path "Открыть отчёт" may open: the final ZIP of the completed
/// session, which must lie under `<EXE dir>\Reports\` and exist as a file.
/// There is no fallback to any temporary or packaging path.
pub fn verify_final_report(report: &Path, reports_root: &Path) -> Result<PathBuf, String> {
    if !report.starts_with(reports_root) {
        return Err(format!(
            "Путь отчёта вне папки Reports ({}): {}",
            reports_root.display(),
            report.display()
        ));
    }
    if !report.is_file() {
        return Err(format!("Итоговый отчёт не найден: {}", report.display()));
    }
    Ok(report.to_path_buf())
}

#[allow(dead_code)]
pub fn reveal_in_explorer(path: &Path) -> Result<(), String> {
    Command::new("explorer.exe")
        .arg(format!("/select,{}", path.display()))
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("Не удалось открыть проводник: {e}"))
}

/// Opens the ZIP report's containing folder directly (no file selected).
#[allow(dead_code)]
pub fn open_containing_folder(path: &Path) -> Result<(), String> {
    let dir = path.parent().unwrap_or(path);
    Command::new("explorer.exe")
        .arg(dir)
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("Не удалось открыть папку: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_request(mode: DiagnosticMode, deep_checks: DeepChecks) -> SessionRequest {
        SessionRequest {
            client_name: "  ACME  ".into(),
            computer_name: "SERVER".into(),
            mode,
            deep_checks,
            include_hardware: true,
            cancel: Arc::new(AtomicBool::new(false)),
            package: Arc::new(std::sync::Mutex::new(
                crate::report_package::SessionPackage::for_exe_dir(Path::new(
                    "C:\\AI\\WinStateDiag",
                )),
            )),
        }
    }

    // --- embedded baseline sanity -------------------------------------

    #[test]
    fn embedded_baseline_files_are_not_empty() {
        assert!(!COMPATIBILITY_PSM1.is_empty());
        assert!(!REPORT_STORAGE_PSM1.is_empty());
        assert!(!EXPC_DIAGNOSTIC_PS1.is_empty());
        assert!(!HARDWARE_DIAGNOSTIC_PS1.is_empty());
        assert!(!HARDWARE_PASSPORT_PSM1.is_empty());
    }

    #[test]
    fn embedded_scripts_declare_read_only_intent() {
        // Cheap guard against accidentally embedding a different/edited
        // copy of the baseline: the proven scripts start with a
        // `#requires -Version 5.0` shebang-equivalent.
        let expc = String::from_utf8_lossy(EXPC_DIAGNOSTIC_PS1);
        assert!(expc.contains("#requires -Version 5.0"));
        let hw = String::from_utf8_lossy(HARDWARE_DIAGNOSTIC_PS1);
        assert!(hw.contains("#requires -Version 5.0"));
    }

    // --- temp extraction -------------------------------------------------

    #[test]
    fn extract_runtime_writes_the_expected_layout() {
        let session_id = format!("unit-test-{}", std::process::id());
        let runtime = extract_runtime(&session_id).expect("extraction should succeed");

        assert!(runtime.root.join("Compatibility.psm1").is_file());
        assert!(runtime.report_storage.is_file());
        assert!(runtime.expc_diagnostic.is_file());
        assert!(runtime.hardware_diagnostic.is_file());
        assert!(
            runtime
                .hardware_diagnostic
                .parent()
                .unwrap()
                .join("HardwarePassport.psm1")
                .is_file()
        );

        let _ = fs::remove_dir_all(&runtime.root);
    }

    // --- mode -> stdin answer mapping ------------------------------------

    #[test]
    fn standard_mode_sends_client_station_and_mode_only() {
        let req = base_request(DiagnosticMode::Standard, DeepChecks::default());
        let answers = build_expc_answers(&req);
        assert_eq!(answers, "ACME\n\n1\n\n");
    }

    #[test]
    fn full_mode_sends_mode_three_with_no_deep_check_prompts() {
        let req = base_request(DiagnosticMode::Full, DeepChecks::default());
        let answers = build_expc_answers(&req);
        assert_eq!(answers, "ACME\n\n3\n\n");
    }

    #[test]
    fn custom_mode_sends_yes_no_for_each_selected_deep_check_in_order() {
        let req = base_request(
            DiagnosticMode::CustomDeepChecks,
            DeepChecks {
                sfc: true,
                dism: false,
                chkdsk: true,
            },
        );
        let answers = build_expc_answers(&req);
        assert_eq!(answers, "ACME\n\n2\ny\nn\ny\n\n");
    }

    #[test]
    fn client_name_is_trimmed_but_may_be_empty() {
        let req = base_request(DiagnosticMode::Standard, DeepChecks::default());
        assert!(build_expc_answers(&req).starts_with("ACME\n"));

        let mut empty_client = base_request(DiagnosticMode::Standard, DeepChecks::default());
        empty_client.client_name = "   ".into();
        assert!(build_expc_answers(&empty_client).starts_with('\n'));
    }

    // --- progress mapping --------------------------------------------------

    // --- Reports\<date>\ discovery (no hard-coded date math in Rust) ------

    #[test]
    fn new_files_since_finds_files_written_into_a_dated_subfolder() {
        let base = std::env::temp_dir().join(format!("wsd-test-{}", std::process::id()));
        let dated = base.join("17-09-26");
        fs::create_dir_all(&dated).unwrap();

        let before = SystemTime::now();
        std::thread::sleep(std::time::Duration::from_millis(20));
        fs::write(dated.join("EXPC_report.json"), b"{}").unwrap();

        assert!(new_files_since(&base, before, &["json"]));
        assert!(!new_files_since(&base, SystemTime::now(), &["json"]));

        let _ = fs::remove_dir_all(&base);
    }

    // --- zip relocation path derivation ------------------------------------

    #[test]
    fn relocate_zip_places_file_under_exe_dir_reports_same_date_folder() {
        let temp_root = std::env::temp_dir().join(format!("wsd-zip-test-{}", std::process::id()));
        let dated = temp_root.join("17-09-26");
        fs::create_dir_all(&dated).unwrap();
        let zip_path = dated.join("EXPC_Diagnostics_17-09-26_12-00-00.zip");
        fs::write(&zip_path, b"PK\x03\x04").unwrap();

        let exe_dir = std::env::temp_dir().join(format!("wsd-exe-test-{}", std::process::id()));
        let result = relocate_zip(&zip_path, &exe_dir).expect("relocation should succeed");

        assert_eq!(
            result,
            exe_dir
                .join("Reports")
                .join("17-09-26")
                .join("EXPC_Diagnostics_17-09-26_12-00-00.zip")
        );
        assert!(result.is_file());

        let _ = fs::remove_dir_all(&temp_root);
        let _ = fs::remove_dir_all(&exe_dir);
    }

    // --- PowerShell single-quote escaping -----------------------------------

    #[test]
    fn ps_quote_path_escapes_single_quotes() {
        let path = Path::new("C:\\Users\\O'Brien\\WinStateDiag");
        assert_eq!(ps_quote_path(path), "C:\\Users\\O''Brien\\WinStateDiag");
    }

    #[test]
    fn expc_progress_protocol_parses_and_clamps() {
        assert_eq!(
            parse_expc_progress("WSD_PROGRESS|42|Storage diagnostics"),
            Some((42, "Storage diagnostics".to_string()))
        );
        assert_eq!(
            parse_expc_progress("WSD_PROGRESS|140|Done"),
            Some((100, "Done".to_string()))
        );
        assert_eq!(parse_expc_progress("ordinary log line"), None);
        assert_eq!(parse_expc_progress("WSD_PROGRESS|bad|Stage"), None);
    }

    // --- new: progress protocol edge cases --------------------------------

    #[test]
    fn progress_parses_zero_percent() {
        assert_eq!(
            parse_expc_progress("WSD_PROGRESS|0|Начало"),
            Some((0, "Начало".to_string()))
        );
    }

    #[test]
    fn progress_parses_hundred_percent() {
        assert_eq!(
            parse_expc_progress("WSD_PROGRESS|100|Готово"),
            Some((100, "Готово".to_string()))
        );
    }

    #[test]
    fn progress_parses_interpolated_deep_check_event() {
        // The new format emitted during SFC/DISM/CHKDSK polling
        assert_eq!(
            parse_expc_progress("WSD_PROGRESS|73|SFC /verifyonly — 45%"),
            Some((73, "SFC /verifyonly — 45%".to_string()))
        );
    }

    #[test]
    fn progress_rejects_empty_message() {
        assert_eq!(parse_expc_progress("WSD_PROGRESS|50|"), None);
        assert_eq!(parse_expc_progress("WSD_PROGRESS|50|   "), None);
    }

    #[test]
    fn progress_rejects_no_pipe() {
        assert_eq!(parse_expc_progress("WSD_PROGRESS|50"), None);
    }

    #[test]
    fn progress_handles_unicode_messages() {
        let result = parse_expc_progress(
            "WSD_PROGRESS|7|Сведения о системе, железе, Windows и аптайме — завершено",
        );
        assert!(result.is_some());
        let (pct, msg) = result.unwrap();
        assert_eq!(pct, 7);
        assert!(msg.contains("завершено"));
    }

    // --- new: EXPC constants consistency ----------------------------------

    #[test]
    fn expc_constants_have_correct_length() {
        assert_eq!(EXPC_STEP_LABELS.len(), EXPC_STEP_COUNT as usize);
        assert_eq!(EXPC_DEEP_FLAGS.len(), EXPC_STEP_COUNT as usize);
        assert_eq!(EXPC_WEIGHTS.len(), EXPC_STEP_COUNT as usize);
    }

    #[test]
    fn expc_deep_flags_match_known_deep_steps() {
        // Steps 11, 12, 13 (0-indexed: 10, 11, 12) are SFC, DISM, CHKDSK
        assert!(EXPC_DEEP_FLAGS[10]);
        assert!(EXPC_DEEP_FLAGS[11]);
        assert!(EXPC_DEEP_FLAGS[12]);
        // All others should be false
        for i in 0..10 {
            assert!(!EXPC_DEEP_FLAGS[i], "step {} should not be deep", i + 1);
        }
        assert!(!EXPC_DEEP_FLAGS[13], "step 14 should not be deep");
    }

    #[test]
    fn expc_weights_are_positive() {
        for (i, &w) in EXPC_WEIGHTS.iter().enumerate() {
            assert!(w > 0.0, "weight for step {} must be positive", i + 1);
        }
    }

    #[test]
    fn expc_total_weight_is_reasonable() {
        let total: f32 = EXPC_WEIGHTS.iter().sum();
        assert!(total > 10.0, "total weight should be > 10");
        assert!(total < 100.0, "total weight should be < 100");
    }

    // --- new: session_fraction tests --------------------------------------

    #[test]
    fn session_fraction_preparing_is_small() {
        let f = session_fraction(&Stage::Preparing, 0.0, 30.7, true);
        assert!(f > 0.0);
        assert!(f < 0.05);
    }

    #[test]
    fn session_fraction_zero_credit_at_diagnostics_start() {
        let total: f32 = EXPC_WEIGHTS.iter().sum();
        let f = session_fraction(&Stage::SystemDiagnostics, 0.0, total, true);
        assert!(f >= 0.03);
        assert!(f < 0.05);
    }

    #[test]
    fn session_fraction_full_credit_at_diagnostics_end() {
        let total: f32 = EXPC_WEIGHTS.iter().sum();
        let f = session_fraction(&Stage::SystemDiagnostics, total, total, true);
        assert!((f - 0.70).abs() < 0.01);
    }

    #[test]
    fn session_fraction_full_credit_no_hardware() {
        let total: f32 = EXPC_WEIGHTS.iter().sum();
        let f = session_fraction(&Stage::SystemDiagnostics, total, total, false);
        assert!((f - 0.90).abs() < 0.01);
    }

    #[test]
    fn session_fraction_complete_is_one() {
        let total: f32 = EXPC_WEIGHTS.iter().sum();
        assert_eq!(session_fraction(&Stage::Complete, total, total, true), 1.0);
        assert_eq!(session_fraction(&Stage::Complete, 0.0, total, false), 1.0);
    }

    #[test]
    fn session_fraction_is_monotonic_through_stages() {
        let total: f32 = EXPC_WEIGHTS.iter().sum();
        let f_prep = session_fraction(&Stage::Preparing, 0.0, total, true);
        let f_diag_start = session_fraction(&Stage::SystemDiagnostics, 0.0, total, true);
        let f_diag_mid = session_fraction(&Stage::SystemDiagnostics, total * 0.5, total, true);
        let f_diag_end = session_fraction(&Stage::SystemDiagnostics, total, total, true);
        let f_hw = session_fraction(&Stage::HardwareReport, total, total, true);
        let f_pack = session_fraction(&Stage::Packaging, total, total, true);
        let f_done = session_fraction(&Stage::Complete, total, total, true);

        assert!(f_prep <= f_diag_start);
        assert!(f_diag_start <= f_diag_mid);
        assert!(f_diag_mid <= f_diag_end);
        assert!(f_diag_end <= f_hw);
        assert!(f_hw <= f_pack);
        assert!(f_pack <= f_done);
    }

    #[test]
    fn session_fraction_never_reaches_one_before_complete() {
        let total: f32 = EXPC_WEIGHTS.iter().sum();
        assert!(session_fraction(&Stage::Packaging, total, total, true) < 1.0);
        assert!(session_fraction(&Stage::HardwareReport, total, total, true) < 1.0);
        assert!(session_fraction(&Stage::SystemDiagnostics, total, total, true) < 1.0);
    }

    // =====================================================================
    // ZIP finalization regression tests (A–K)
    // =====================================================================

    /// Helper: create a temp dir tree with a session ZIP inside a dated
    /// subfolder and return (reports_root, zip_path, exe_dir).
    fn setup_zip_scenario(tag: &str, date: &str, sid: &str) -> (PathBuf, PathBuf, PathBuf) {
        let base = std::env::temp_dir().join(format!("wsd-{tag}-{}", std::process::id()));
        let reports = base.join("Reports");
        let dated = reports.join(date);
        fs::create_dir_all(&dated).unwrap();
        let zip = dated.join(format!("EXPC_Diagnostics_{sid}.zip"));
        fs::write(&zip, b"PK\x03\x04fake-zip-content").unwrap();
        let exe_dir = std::env::temp_dir().join(format!("wsd-exe-{tag}-{}", std::process::id()));
        (reports, zip, exe_dir)
    }

    fn cleanup(paths: &[&Path]) {
        for p in paths {
            let _ = fs::remove_dir_all(p);
        }
    }

    // A. ZIP directly in runtime Reports root (no date subfolder)
    #[test]
    fn discover_zip_directly_in_reports_root() {
        let base = std::env::temp_dir().join(format!("wsd-A-{}", std::process::id()));
        let reports = base.join("Reports");
        fs::create_dir_all(&reports).unwrap();
        let zip = reports.join("EXPC_Diagnostics_22-09-26_12-00-00.zip");
        fs::write(&zip, b"PK\x03\x04").unwrap();

        let found = discover_session_zip(&reports, "22-09-26_12-00-00");
        assert!(found.is_some());
        assert_eq!(found.unwrap(), zip);
        cleanup(&[&base]);
    }

    // B. ZIP in Reports\DD-MM-YY (normal case)
    #[test]
    fn discover_zip_in_dated_subfolder() {
        let (reports, zip, exe_dir) = setup_zip_scenario("B", "22-09-26", "22-09-26_12-00-00");
        let found = discover_session_zip(&reports, "22-09-26_12-00-00");
        assert!(found.is_some());
        assert_eq!(found.unwrap(), zip);
        cleanup(&[reports.parent().unwrap(), &exe_dir]);
    }

    // C. Different date subfolder name
    #[test]
    fn discover_zip_alternative_date_folder() {
        let (reports, zip, exe_dir) = setup_zip_scenario("C", "01-01-27", "01-01-27_08-30-00");
        let found = discover_session_zip(&reports, "01-01-27_08-30-00");
        assert!(found.is_some());
        assert_eq!(found.unwrap(), zip);
        cleanup(&[reports.parent().unwrap(), &exe_dir]);
    }

    // D. Path with spaces
    #[test]
    fn relocate_zip_with_spaces_in_path() {
        let base = std::env::temp_dir().join(format!("wsd D spaces test {}", std::process::id()));
        let dated = base.join("22-09-26");
        fs::create_dir_all(&dated).unwrap();
        let zip = dated.join("EXPC_Diagnostics_22-09-26_12-00-00.zip");
        fs::write(&zip, b"PK\x03\x04content").unwrap();

        let exe_dir = std::env::temp_dir().join(format!("wsd exe D spaces {}", std::process::id()));
        let result = relocate_zip(&zip, &exe_dir).expect("spaces should not break relocation");
        assert!(result.is_file());
        assert!(fs::metadata(&result).unwrap().len() > 0);

        cleanup(&[&base, &exe_dir]);
    }

    // E. Unicode path components
    #[test]
    fn relocate_zip_with_unicode_path() {
        let base = std::env::temp_dir().join(format!("wsd-E-Тест-Юникод-{}", std::process::id()));
        let dated = base.join("22-09-26");
        fs::create_dir_all(&dated).unwrap();
        let zip = dated.join("EXPC_Diagnostics_22-09-26_12-00-00.zip");
        fs::write(&zip, b"PK\x03\x04unicode-test").unwrap();

        let exe_dir =
            std::env::temp_dir().join(format!("wsd-exe-E-Кириллица-{}", std::process::id()));
        let result = relocate_zip(&zip, &exe_dir).expect("Unicode paths must work");
        assert!(result.is_file());
        assert!(fs::metadata(&result).unwrap().len() > 0);

        cleanup(&[&base, &exe_dir]);
    }

    // F. Destination Reports does not exist → created automatically
    #[test]
    fn relocate_zip_creates_destination_reports_dir() {
        let (reports, zip, exe_dir) = setup_zip_scenario("F", "22-09-26", "22-09-26_12-00-00");
        assert!(!exe_dir.join("Reports").exists());
        let result = relocate_zip(&zip, &exe_dir).expect("should create Reports dir");
        assert!(exe_dir.join("Reports").join("22-09-26").is_dir());
        assert!(result.is_file());
        cleanup(&[reports.parent().unwrap(), &exe_dir]);
    }

    // G. Multiple old ZIPs + one current session → discovery picks current
    #[test]
    fn discover_zip_picks_current_session_among_old() {
        let base = std::env::temp_dir().join(format!("wsd-G-{}", std::process::id()));
        let reports = base.join("Reports");
        let dated = reports.join("22-09-26");
        fs::create_dir_all(&dated).unwrap();

        // Old ZIPs from previous sessions
        fs::write(
            dated.join("EXPC_Diagnostics_22-09-26_08-00-00.zip"),
            b"PK-old1",
        )
        .unwrap();
        fs::write(
            dated.join("EXPC_Diagnostics_22-09-26_09-00-00.zip"),
            b"PK-old2",
        )
        .unwrap();
        // Current session ZIP
        let current = dated.join("EXPC_Diagnostics_22-09-26_12-00-00.zip");
        fs::write(&current, b"PK-current").unwrap();

        let found = discover_session_zip(&reports, "22-09-26_12-00-00");
        assert!(found.is_some());
        assert_eq!(found.unwrap(), current);
        cleanup(&[&base]);
    }

    // H. ZIP missing → diagnostic error contains searched paths
    #[test]
    fn discover_zip_returns_none_when_missing() {
        let base = std::env::temp_dir().join(format!("wsd-H-{}", std::process::id()));
        let reports = base.join("Reports");
        fs::create_dir_all(&reports).unwrap();

        let found = discover_session_zip(&reports, "22-09-26_12-00-00");
        assert!(found.is_none());
        cleanup(&[&base]);
    }

    // H2. relocate_zip with non-existent source gives detailed error
    #[test]
    fn relocate_zip_nonexistent_source_gives_diagnostic_error() {
        let fake_zip = PathBuf::from("C:\\nonexistent\\path\\to\\report.zip");
        let exe_dir = std::env::temp_dir().join(format!("wsd-H2-{}", std::process::id()));

        let err = relocate_zip(&fake_zip, &exe_dir).unwrap_err();
        assert!(err.contains("ZIP-источник не найден"), "got: {err}");
        assert!(err.contains("nonexistent"), "error must mention the path");
        cleanup(&[&exe_dir]);
    }

    // I. Source preserved when destination copy fails
    #[test]
    fn source_zip_preserved_after_failed_relocation() {
        let (reports, zip, _exe_dir) = setup_zip_scenario("I", "22-09-26", "22-09-26_12-00-00");
        let src_len_before = fs::metadata(&zip).unwrap().len();

        // Try to relocate to an invalid destination (empty OsStr as exe_dir)
        // — the important thing is that the source file is NOT deleted.
        let _ = relocate_zip(&zip, Path::new(""));

        // Source must still exist with original size
        assert!(zip.is_file());
        assert_eq!(fs::metadata(&zip).unwrap().len(), src_len_before);
        cleanup(&[reports.parent().unwrap()]);
    }

    // J. Destination after copy exists and size > 0
    #[test]
    fn relocate_zip_destination_verified_after_copy() {
        let (reports, zip, exe_dir) = setup_zip_scenario("J", "22-09-26", "22-09-26_14-00-00");
        let src_len = fs::metadata(&zip).unwrap().len();

        let dest = relocate_zip(&zip, &exe_dir).expect("relocation should succeed");
        assert!(dest.is_file());
        let dest_len = fs::metadata(&dest).unwrap().len();
        assert!(dest_len > 0);
        assert_eq!(dest_len, src_len, "dest size must match source");

        cleanup(&[reports.parent().unwrap(), &exe_dir]);
    }

    // K. C:\TOOLS scenario: exe_dir is a short root-level path
    #[test]
    fn relocate_zip_ctools_equivalent_scenario() {
        // Simulate C:\TOOLS by using a short temp path
        let src_base = std::env::temp_dir().join(format!("wsd-K-src-{}", std::process::id()));
        let dated = src_base.join("22-09-26");
        fs::create_dir_all(&dated).unwrap();
        let zip = dated.join("EXPC_Diagnostics_22-09-26_15-30-00.zip");
        fs::write(&zip, b"PK\x03\x04real-content-here").unwrap();

        let exe_dir = std::env::temp_dir().join(format!("TOOLS-{}", std::process::id()));
        let result = relocate_zip(&zip, &exe_dir).expect("TOOLS-like path must work");

        assert_eq!(
            result,
            exe_dir
                .join("Reports")
                .join("22-09-26")
                .join("EXPC_Diagnostics_22-09-26_15-30-00.zip")
        );
        assert!(result.is_file());
        assert!(fs::metadata(&result).unwrap().len() > 0);

        // Verify no dependency on C:\AI or working directory
        assert!(!result.to_string_lossy().contains("AI\\WinStateDiag"));

        cleanup(&[&src_base, &exe_dir]);
    }

    // Discovery ignores zero-length files
    #[test]
    fn discover_zip_ignores_zero_length_files() {
        let base = std::env::temp_dir().join(format!("wsd-zero-{}", std::process::id()));
        let reports = base.join("Reports");
        let dated = reports.join("22-09-26");
        fs::create_dir_all(&dated).unwrap();
        // Zero-length ZIP
        fs::write(dated.join("EXPC_Diagnostics_22-09-26_12-00-00.zip"), b"").unwrap();

        let found = discover_session_zip(&reports, "22-09-26_12-00-00");
        assert!(found.is_none(), "zero-length file must be ignored");
        cleanup(&[&base]);
    }

    // is_valid_zip helper tests
    #[test]
    fn is_valid_zip_rejects_nonexistent() {
        assert!(!is_valid_zip(Path::new("C:\\no\\such\\file.zip")));
    }

    #[test]
    fn is_valid_zip_rejects_directory() {
        let dir = std::env::temp_dir().join(format!("wsd-dir-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        assert!(!is_valid_zip(&dir));
        cleanup(&[&dir]);
    }

    #[test]
    fn is_valid_zip_accepts_nonempty_file() {
        let base = std::env::temp_dir().join(format!("wsd-valid-{}", std::process::id()));
        fs::create_dir_all(&base).unwrap();
        let f = base.join("test.zip");
        fs::write(&f, b"PK\x03\x04").unwrap();
        assert!(is_valid_zip(&f));
        cleanup(&[&base]);
    }

    // ---- Final archive name: "<Client> <Company> - DD-MM-YY.zip" ----

    #[test]
    fn zip_name_client_and_company() {
        assert_eq!(
            final_zip_file_name("Иван Петров", "Мегастрой", "23-09-26"),
            "Иван Петров Мегастрой - 23-09-26.zip"
        );
    }

    #[test]
    fn zip_name_client_only() {
        assert_eq!(
            final_zip_file_name("Иван Петров", "", "23-09-26"),
            "Иван Петров - 23-09-26.zip"
        );
        assert_eq!(
            final_zip_file_name("Иван Петров", "   ", "23-09-26"),
            "Иван Петров - 23-09-26.zip"
        );
    }

    #[test]
    fn zip_name_company_only() {
        assert_eq!(
            final_zip_file_name("", "Мегастрой", "23-09-26"),
            "Мегастрой - 23-09-26.zip"
        );
    }

    #[test]
    fn zip_name_same_client_and_company_not_duplicated() {
        assert_eq!(
            final_zip_file_name("Мегастрой", "  мегастрой ", "23-09-26"),
            "Мегастрой - 23-09-26.zip"
        );
    }

    #[test]
    fn zip_name_invalid_chars_and_spaces_cleaned() {
        assert_eq!(
            final_zip_file_name("  ООО \"Рога/Копыта\"  ", "A:B*C?", "23-09-26"),
            "ООО Рога Копыта A B C - 23-09-26.zip"
        );
        let name = final_zip_file_name("x<y>z|w\\v", "", "23-09-26");
        assert!(!name.chars().any(|c| INVALID_FILE_NAME_CHARS.contains(&c)));
        assert!(!name.contains("  "));
    }

    #[test]
    fn zip_name_has_no_time_or_technical_prefix() {
        let name = final_zip_file_name("Иван Петров", "", "23-09-26");
        for bad in ["EXPC", "WinStateDiag", "Diagnostic", "Report", "_"] {
            assert!(!name.contains(bad), "{name} must not contain {bad}");
        }
    }

    #[test]
    fn zip_name_without_any_names_is_date_only() {
        assert_eq!(final_zip_file_name(" ", "", "23-09-26"), "23-09-26.zip");
    }

    #[test]
    fn relocate_as_uses_final_name_and_never_overwrites() {
        let (reports, zip, exe_dir) = setup_zip_scenario("NAME", "23-09-26", "23-09-26_10-00-00");
        let first = relocate_zip_as(&zip, &exe_dir, "Иван Петров - 23-09-26.zip").unwrap();
        assert_eq!(
            first,
            exe_dir
                .join("Reports")
                .join("23-09-26")
                .join("Иван Петров - 23-09-26.zip")
        );
        let second = relocate_zip_as(&zip, &exe_dir, "Иван Петров - 23-09-26.zip").unwrap();
        assert_eq!(
            second,
            exe_dir
                .join("Reports")
                .join("23-09-26")
                .join("Иван Петров - 23-09-26 (2).zip")
        );
        assert!(first.is_file() && second.is_file());
        cleanup(&[reports.parent().unwrap(), &exe_dir]);
    }

    // --- report identity: Reports\<Client> - <Computer> - DD-MM-YY\ -------

    #[test]
    fn report_name_client_computer_date() {
        assert_eq!(
            report_base_name("Мегастрой", "SERVER", "24-09-26"),
            "Мегастрой - SERVER - 24-09-26"
        );
        assert_eq!(
            report_base_name("Acme Ltd", "MSI", "24-09-26"),
            "Acme Ltd - MSI - 24-09-26"
        );
    }

    #[test]
    fn report_name_without_client_is_computer_and_date() {
        assert_eq!(
            report_base_name("", "SERVER", "24-09-26"),
            "SERVER - 24-09-26"
        );
        assert_eq!(
            report_base_name("   \t ", "SERVER", "24-09-26"),
            "SERVER - 24-09-26"
        );
    }

    #[test]
    fn report_name_trims_and_sanitizes() {
        assert_eq!(
            report_base_name("  Иванов И.И.  ", " MSI ", "24-09-26"),
            "Иванов И.И - MSI - 24-09-26"
        );
        let n = report_base_name("A<B>:C\"D/E\\F|G?H*", "PC", "24-09-26");
        assert!(!n.chars().any(|c| INVALID_FILE_NAME_CHARS.contains(&c)));
        assert_eq!(n, "A B C D E F G H - PC - 24-09-26");
        let n = report_base_name("Клиент ... ", "PC.", "24-09-26");
        assert_eq!(n, "Клиент - PC - 24-09-26");
        assert!(!n.ends_with('.') && !n.ends_with(' '));
    }

    #[test]
    fn report_folder_collision_gets_suffix_and_never_overwrites() {
        let (reports, zip, exe_dir) = setup_zip_scenario("rid", "24-09-26", "24-09-26_10-00-00");
        let base = report_base_name("Мегастрой", "SERVER", "24-09-26");
        let first = place_final_report(&zip, &exe_dir, &base).unwrap();
        assert_eq!(
            first,
            exe_dir
                .join("Reports")
                .join("Мегастрой - SERVER - 24-09-26")
                .join("Мегастрой - SERVER - 24-09-26.zip")
        );
        let first_bytes = fs::read(&first).unwrap();
        let second = place_final_report(&zip, &exe_dir, &base).unwrap();
        assert_eq!(
            second,
            exe_dir
                .join("Reports")
                .join("Мегастрой - SERVER - 24-09-26 (2)")
                .join("Мегастрой - SERVER - 24-09-26.zip")
        );
        assert_eq!(
            fs::read(&first).unwrap(),
            first_bytes,
            "first report untouched"
        );
        assert!(zip.is_file(), "temporary source preserved");
        cleanup(&[reports.parent().unwrap(), &exe_dir]);
    }

    #[test]
    fn open_folder_targets_the_current_session_folder() {
        let (reports, zip, exe_dir) = setup_zip_scenario("rfold", "24-09-26", "24-09-26_11-00-00");
        let a = place_final_report(&zip, &exe_dir, "SERVER - 24-09-26").unwrap();
        let b = place_final_report(&zip, &exe_dir, "SERVER - 24-09-26").unwrap();
        assert_eq!(
            report_folder_of(&b),
            exe_dir.join("Reports").join("SERVER - 24-09-26 (2)")
        );
        assert_ne!(report_folder_of(&a), report_folder_of(&b));
        assert!(report_folder_of(&b).is_dir());
        cleanup(&[reports.parent().unwrap(), &exe_dir]);
    }

    #[test]
    fn final_report_is_validated_and_source_preserved_on_failure() {
        let (reports, zip, exe_dir) = setup_zip_scenario("rval", "24-09-26", "24-09-26_12-00-00");
        // Not a ZIP (no PK signature): rejected, no half-made folder left.
        let bogus = zip.with_file_name("bogus.zip");
        fs::write(&bogus, b"not a zip").unwrap();
        let err = place_final_report(&bogus, &exe_dir, "PC - 24-09-26").unwrap_err();
        assert!(err.contains("не является ZIP"));
        assert!(!exe_dir.join("Reports").join("PC - 24-09-26").exists());
        assert!(bogus.is_file(), "source kept");
        // Missing source: clear error, nothing created.
        let missing = zip.with_file_name("missing.zip");
        assert!(place_final_report(&missing, &exe_dir, "PC - 24-09-26").is_err());
        // Valid source: same size, PK signature.
        let ok = place_final_report(&zip, &exe_dir, "PC - 24-09-26").unwrap();
        assert_eq!(
            fs::metadata(&ok).unwrap().len(),
            fs::metadata(&zip).unwrap().len()
        );
        cleanup(&[reports.parent().unwrap(), &exe_dir]);
    }

    #[test]
    fn report_paths_with_spaces_and_unicode_work() {
        let (reports, zip, exe_dir) =
            setup_zip_scenario("r uni ё", "24-09-26", "24-09-26_13-00-00");
        let base = report_base_name("ООО «Ромашка» и партнёры", "ПК-БУХ 01", "24-09-26");
        let dest = place_final_report(&zip, &exe_dir, &base).unwrap();
        assert!(dest.is_file());
        assert_eq!(
            dest.file_name().unwrap().to_str().unwrap(),
            "ООО «Ромашка» и партнёры - ПК-БУХ 01 - 24-09-26.zip"
        );
        cleanup(&[reports.parent().unwrap(), &exe_dir]);
    }
}

/// Unified session package + Stop (cancellation) at pipeline level, with a
/// scripted backend (no PowerShell on the test host).
#[cfg(test)]
mod session_pipeline_tests {
    use super::*;
    use crate::report_package::{SessionPackage, read_zip};
    use std::sync::Mutex;
    use std::sync::mpsc::channel;
    #[cfg(unix)]
    use std::time::Duration;

    #[derive(Clone, Copy, PartialEq)]
    enum Plan {
        Complete,
        /// Stop pressed while EXPC's child process tree is running.
        StopDuringExpc,
        /// Stop pressed while Hardware Report runs (EXPC finished).
        StopDuringHardware,
        /// Stop pressed before anything was collected.
        StopBeforeStart,
    }

    struct Scripted {
        root: PathBuf,
        plan: Plan,
        ran: Arc<Mutex<Vec<&'static str>>>,
        // Written/read only by the Unix process-tree scenario.
        #[cfg_attr(not(unix), allow(dead_code))]
        grandchild: Arc<Mutex<Option<u32>>>,
    }

    impl Scripted {
        fn day(&self) -> PathBuf {
            self.root.join("24-09-26")
        }

        /// A real child process with its own child ("PowerShell running
        /// sfc"), cancelled through the same ProcessGuard as production.
        #[cfg(unix)]
        fn run_tree_until_cancel(&self, req: &SessionRequest) -> Result<(), StepError> {
            let pid_file = self.root.join("grandchild.pid");
            let mut cmd = Command::new("sh");
            cmd.arg("-c")
                .arg(format!(
                    "sleep 60 & echo $! > '{}'; wait",
                    pid_file.display()
                ))
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            let mut guard = ProcessGuard::spawn(cmd).unwrap();
            let t0 = std::time::Instant::now();
            while !pid_file.is_file() && t0.elapsed() < Duration::from_secs(5) {
                std::thread::sleep(Duration::from_millis(20));
            }
            std::thread::sleep(Duration::from_millis(50));
            let pid: u32 = fs::read_to_string(&pid_file)
                .unwrap()
                .trim()
                .parse()
                .unwrap();
            *self.grandchild.lock().unwrap() = Some(pid);
            // The user presses Stop while the tree runs.
            let cancel = Arc::clone(&req.cancel);
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(200));
                cancel.store(true, Ordering::SeqCst);
            });
            match guard.wait_or_cancel(&req.cancel, Some(Duration::from_secs(20))) {
                Err(WaitEnd::Cancelled) => Err(StepError::Cancelled),
                _ => panic!("expected cancellation"),
            }
        }

        /// Other hosts: the Stop request arrives during the step (the
        /// Windows Job Object path itself is exercised on Windows only).
        #[cfg(not(unix))]
        fn run_tree_until_cancel(&self, req: &SessionRequest) -> Result<(), StepError> {
            req.cancel.store(true, Ordering::SeqCst);
            Err(StepError::Cancelled)
        }
    }

    impl SessionBackend for Scripted {
        fn prepare(&mut self, _tx: &Sender<EngineEvent>) -> Result<PathBuf, String> {
            fs::create_dir_all(self.day()).unwrap();
            self.ran.lock().unwrap().push("prepare");
            Ok(self.root.clone())
        }
        fn run_expc(
            &mut self,
            req: &SessionRequest,
            _tx: &Sender<EngineEvent>,
        ) -> Result<(), StepError> {
            self.ran.lock().unwrap().push("expc");
            // EXPC writes its TXT progressively (BOM + completed steps).
            fs::write(self.day().join("EXPC_24.09.26_10-30.txt"), "шаг 1 OK\r\n").unwrap();
            if self.plan == Plan::StopDuringExpc {
                return self.run_tree_until_cancel(req);
            }
            fs::write(self.day().join("EXPC_24.09.26_10-30.json"), "{}").unwrap();
            Ok(())
        }
        fn run_hardware(
            &mut self,
            req: &SessionRequest,
            _tx: &Sender<EngineEvent>,
        ) -> Result<(), StepError> {
            self.ran.lock().unwrap().push("hardware");
            fs::write(self.day().join("Hardware_24.09.26_10-40.txt"), "HW").unwrap();
            if self.plan == Plan::StopDuringHardware {
                return self.run_tree_until_cancel(req);
            }
            fs::write(self.day().join("Hardware_24.09.26_10-40.json"), "{}").unwrap();
            Ok(())
        }
        fn run_driver_audit(
            &mut self,
            _req: &SessionRequest,
            _tx: &Sender<EngineEvent>,
        ) -> Result<(), StepError> {
            self.ran.lock().unwrap().push("driver_audit");
            fs::write(self.day().join("DriverAudit_24-09-26_10-50-00.json"), "{}").unwrap();
            Ok(())
        }
        fn cleanup(&mut self) {
            self.ran.lock().unwrap().push("cleanup");
        }
    }

    struct Run {
        events: Vec<EngineEvent>,
        ran: Vec<&'static str>,
        #[cfg_attr(not(unix), allow(dead_code))]
        grandchild: Option<u32>,
        package: SharedPackage,
        base: PathBuf,
    }

    fn run(plan: Plan, tag: &str, existing: Option<SharedPackage>) -> Run {
        let base = std::env::temp_dir().join(format!("wsd-cancel-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let exe = base.join("Портативная WinStateDiag");
        let package = existing.unwrap_or_else(|| {
            Arc::new(Mutex::new(SessionPackage::new(exe.join("Reports"), None)))
        });
        let req = SessionRequest {
            client_name: "Алексей".into(),
            computer_name: "MSI".into(),
            mode: DiagnosticMode::Standard,
            deep_checks: DeepChecks::default(),
            include_hardware: true,
            cancel: Arc::new(AtomicBool::new(plan == Plan::StopBeforeStart)),
            package: Arc::clone(&package),
        };
        let ran = Arc::new(Mutex::new(Vec::new()));
        let grandchild = Arc::new(Mutex::new(None));
        let mut backend = Scripted {
            root: base.join("runtime").join("Reports"),
            plan,
            ran: Arc::clone(&ran),
            grandchild: Arc::clone(&grandchild),
        };
        let (tx, rx) = channel();
        run_session_with(&req, &tx, &mut backend);
        drop(tx);
        let ran = ran.lock().unwrap().clone();
        let grandchild = *grandchild.lock().unwrap();
        Run {
            events: rx.iter().collect(),
            ran,
            grandchild,
            package,
            base,
        }
    }

    fn cancelled(events: &[EngineEvent]) -> Option<(&Option<PathBuf>, &String)> {
        events.iter().find_map(|e| match e {
            EngineEvent::Cancelled { zip_path, note } => Some((zip_path, note)),
            _ => None,
        })
    }

    #[cfg(unix)]
    fn alive(pid: u32) -> bool {
        // A killed process may linger as a zombie of PID 1 in containers.
        match fs::read_to_string(format!("/proc/{pid}/stat")) {
            Ok(stat) => !stat
                .rsplit(')')
                .next()
                .unwrap_or("")
                .trim_start()
                .starts_with('Z'),
            Err(_) => false,
        }
    }

    #[test]
    fn complete_run_updates_the_session_package() {
        let r = run(Plan::Complete, "ok", None);
        let zip = r
            .events
            .iter()
            .find_map(|e| match e {
                EngineEvent::Finished(Ok(z)) => Some(z.clone()),
                _ => None,
            })
            .expect("finished");
        assert!(zip.starts_with(r.base.join("Портативная WinStateDiag").join("Reports")));
        let names: Vec<String> = read_zip(&zip)
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        for n in [
            "EXPC_24.09.26_10-30.txt",
            "EXPC_24.09.26_10-30.json",
            "Hardware_24.09.26_10-40.json",
            "DriverAudit_24-09-26_10-50-00.json",
        ] {
            assert!(names.contains(&n.to_string()), "{n}");
        }
        assert_eq!(r.ran.last(), Some(&"cleanup"));
        let _ = fs::remove_dir_all(&r.base);
    }

    /// Stop during an active child process tree: the tree dies, nothing
    /// unrelated is touched, later stages never start, partial evidence is
    /// kept and marked, the run is recorded as USER_CANCELLED.
    #[test]
    fn stop_during_expc_stops_the_run_and_keeps_marked_evidence() {
        let r = run(Plan::StopDuringExpc, "expc", None);
        // Remaining stages did not run.
        assert_eq!(r.ran, vec!["prepare", "expc", "cleanup"]);
        assert!(
            !r.events
                .iter()
                .any(|e| matches!(e, EngineEvent::Finished(_)))
        );
        assert!(!r.events.iter().any(|e| matches!(
            e,
            EngineEvent::Stage(Stage::HardwareReport | Stage::Packaging | Stage::Complete)
        )));
        let (zip, _note) = cancelled(&r.events).expect("Cancelled event");
        let zip = zip.clone().expect("partial evidence packaged");
        let entries = read_zip(&zip).unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(
            names.contains(&"EXPC_24.09.26_10-30_USER_CANCELLED.txt"),
            "{names:?}"
        );
        assert!(
            !names.contains(&"EXPC_24.09.26_10-30.txt"),
            "never presented as complete"
        );
        let status = entries
            .iter()
            .find(|e| e.name.starts_with("EXPC_Diagnostic_USER_CANCELLED_"))
            .expect("run status record");
        let text = String::from_utf8_lossy(&status.bytes);
        assert!(text.contains("STATUS=USER_CANCELLED"));
        assert!(text.contains("Прерванный этап: EXPC Diagnostic"));
        assert!(text.contains("Завершённые этапы: нет"));
        // EXPC is not a completed module.
        let pkg = crate::report_package::lock(&r.package);
        assert!(
            !pkg.completed_modules()
                .contains(&crate::report_package::EvidenceModule::Expc)
        );
        drop(pkg);
        let _ = fs::remove_dir_all(&r.base);
    }

    #[test]
    fn stop_during_hardware_keeps_completed_expc_evidence_as_is() {
        let r = run(Plan::StopDuringHardware, "hw", None);
        assert_eq!(r.ran, vec!["prepare", "expc", "hardware", "cleanup"]);
        let (zip, _) = cancelled(&r.events).unwrap();
        let entries = read_zip(zip.as_ref().unwrap()).unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"EXPC_24.09.26_10-30.txt"));
        assert!(names.contains(&"EXPC_24.09.26_10-30.json"));
        assert!(names.contains(&"Hardware_24.09.26_10-40_USER_CANCELLED.txt"));
        let status = entries
            .iter()
            .find(|e| e.name.starts_with("EXPC_Diagnostic_USER_CANCELLED_"))
            .unwrap();
        let text = String::from_utf8_lossy(&status.bytes);
        assert!(text.contains("Завершённые этапы: EXPC Diagnostic"));
        assert!(text.contains("Прерванный этап: Hardware Report"));
        let _ = fs::remove_dir_all(&r.base);
    }

    #[test]
    fn stop_before_any_evidence_creates_no_report() {
        let r = run(Plan::StopBeforeStart, "none", None);
        assert_eq!(r.ran, vec!["cleanup"]);
        let (zip, note) = cancelled(&r.events).unwrap();
        assert!(zip.is_none());
        assert!(note.contains("не создавался"));
        assert!(
            !r.base
                .join("Портативная WinStateDiag")
                .join("Reports")
                .exists()
        );
        let _ = fs::remove_dir_all(&r.base);
    }

    #[test]
    fn stop_without_new_evidence_marks_the_existing_package() {
        let base = std::env::temp_dir().join(format!("wsd-existing-pkg-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let pkg = SessionPackage::new(base.join("exe").join("Reports"), None);
        let shared = Arc::new(Mutex::new(pkg));
        let hw = crate::report_package::EvidenceFile::new(
            "Hardware_24.09.26_09-00.json",
            b"{}".to_vec(),
        );
        let zip = crate::report_package::lock(&shared)
            .contribute("", "MSI", "24-09-26", vec![hw])
            .unwrap();
        let r = run(Plan::StopBeforeStart, "pre", Some(Arc::clone(&shared)));
        let (z, _) = cancelled(&r.events).unwrap();
        assert_eq!(z.as_ref(), Some(&zip), "same session package");
        let names: Vec<String> = read_zip(&zip)
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert!(names.contains(&"Hardware_24.09.26_09-00.json".to_string()));
        assert!(
            names
                .iter()
                .any(|n| n.starts_with("EXPC_Diagnostic_USER_CANCELLED_"))
        );
        let _ = fs::remove_dir_all(&r.base);
        let _ = fs::remove_dir_all(&base);
    }

    /// Stop during an active child process tree: the whole tree of THIS
    /// session ends (no orphan), an unrelated process is untouched.
    #[cfg(unix)]
    #[test]
    fn stop_kills_only_the_session_process_tree() {
        let mut unrelated = Command::new("sleep").arg("60").spawn().unwrap();
        let r = run(Plan::StopDuringExpc, "tree", None);
        let gc = r.grandchild.expect("grandchild started");
        let t0 = std::time::Instant::now();
        while alive(gc) && t0.elapsed() < Duration::from_secs(3) {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(!alive(gc), "grandchild process terminated");
        assert!(
            matches!(unrelated.try_wait(), Ok(None)),
            "unrelated process survives"
        );
        let _ = unrelated.kill();
        let _ = unrelated.wait();
        let _ = fs::remove_dir_all(&r.base);
    }

    #[cfg(unix)]
    #[test]
    fn process_guard_drop_leaves_no_orphans() {
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg("sleep 60 & wait");
        let guard = ProcessGuard::spawn(cmd).unwrap();
        let pid = guard.id();
        drop(guard);
        assert!(!alive(pid));
    }

    #[test]
    fn journal_never_shows_the_temp_runtime_as_a_report_location() {
        let marker = runtime_marker("24-09-26_10-00-00");
        let file_line = "Файл отчёта     : C:\\Users\\Алексей\\AppData\\Local\\Temp\\WinStateDiag\\24-09-26_10-00-00\\Reports\\24-09-26\\EXPC_24.09.26_10-00.txt";
        assert_eq!(mask_runtime_line(file_line, &marker, false), None);
        assert_eq!(mask_runtime_line("Reports:", &marker, false), None);
        let err =
            "Ошибка в C:\\Temp\\WinStateDiag\\24-09-26_10-00-00\\EXPC-Diagnostic\\x.ps1: строка 5";
        let masked = mask_runtime_line(err, &marker, true).unwrap();
        assert_eq!(
            masked,
            "Ошибка в [временная папка]\\EXPC-Diagnostic\\x.ps1: строка 5"
        );
        assert!(!masked.contains("Temp"));
        assert_eq!(
            mask_runtime_line("[1/14] Сведения о системе", &marker, false).as_deref(),
            Some("[1/14] Сведения о системе")
        );
    }
}

/// v0.3.7: the EXPC Defender summary must describe each component exactly
/// as `Get-MpComputerStatus` reports it. A field report had
/// AntivirusEnabled=True, AMServiceEnabled=True,
/// RealTimeProtectionEnabled=False, yet the summary read as if all three
/// were disabled. The raw evidence block itself is untouched.
#[cfg(test)]
mod defender_summary_tests {
    use super::EXPC_DIAGNOSTIC_PS1;
    use std::process::Command;

    fn script() -> String {
        String::from_utf8_lossy(EXPC_DIAGNOSTIC_PS1).replace("\r\n", "\n")
    }

    /// Exactly the classification functions of the embedded script.
    fn summary_functions() -> String {
        let s = script();
        let start = s
            .find("function ConvertTo-DefenderFlag {")
            .expect("ConvertTo-DefenderFlag in EXPC-Diagnostic.ps1");
        let end = s[start..]
            .find("function Write-DiagResult {")
            .map(|i| start + i)
            .expect("summary functions precede Write-DiagResult");
        s[start..end].to_string()
    }

    #[test]
    fn defender_summary_no_longer_lumps_all_three_components_together() {
        let s = script();
        assert!(!s.contains("об отключённом Antivirus/AMService/RealTimeProtection"));
        assert!(!s.contains(
            "-not $mp.AntivirusEnabled -or -not $mp.AMServiceEnabled -or -not $mp.RealTimeProtectionEnabled"
        ));
        assert!(s.contains("$defender = Get-DefenderStateSummary"));
        assert!(s.contains("-RealTimeProtectionEnabled $mp.RealTimeProtectionEnabled"));
        // Raw evidence block unchanged: the same properties are still logged.
        assert!(s.contains(
            "$mp | Select-Object AntivirusEnabled, AMServiceEnabled, RealTimeProtectionEnabled,"
        ));
        // Read-only: the fix never changes Defender settings.
        let f = summary_functions();
        for forbidden in [
            "Set-MpPreference",
            "Start-Service",
            "Set-Service",
            "Add-MpPreference",
        ] {
            assert!(!f.contains(forbidden), "{forbidden}");
        }
    }

    /// PowerShell host for executing the embedded functions: always
    /// `powershell.exe` on Windows; elsewhere `WSD_PWSH` or `pwsh` on PATH.
    fn powershell() -> Option<String> {
        if cfg!(windows) {
            return Some("powershell.exe".into());
        }
        if let Ok(p) = std::env::var("WSD_PWSH") {
            return Some(p);
        }
        Command::new("pwsh")
            .args(["-NoProfile", "-Command", "exit 0"])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|_| "pwsh".to_string())
    }

    fn hex_utf8(hex: &str) -> String {
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        String::from_utf8(bytes).unwrap()
    }

    struct Row {
        status: String,
        enabled: String,
        disabled: String,
        unknown: String,
        detail: String,
    }

    #[test]
    fn defender_summary_describes_every_combination_accurately() {
        let Some(host) = powershell() else {
            eprintln!("defender summary: no PowerShell host available, execution skipped");
            return;
        };
        // (case, AntivirusEnabled, AMServiceEnabled, RealTimeProtectionEnabled)
        let cases = [
            ("ttt", "$true", "$true", "$true"),
            ("ttf", "$true", "$true", "$false"),
            ("ftf", "$false", "$true", "$false"),
            ("fff", "$false", "$false", "$false"),
            ("nnn", "$null", "$null", "$null"),
            ("tnt", "$true", "$null", "$true"),
            ("fnt", "$false", "$null", "$true"),
            ("str", "'True'", "'True'", "'False'"),
            ("odd", "'yes'", "$true", "$true"),
            (
                "mis",
                "$m.AntivirusEnabled",
                "$m.AMServiceEnabled",
                "$m.RealTimeProtectionEnabled",
            ),
        ];
        let mut ps = String::new();
        ps.push_str(&summary_functions());
        ps.push_str(
            "\n$m = [PSCustomObject]@{ AntivirusEnabled = $true; AMServiceEnabled = $true }\n",
        );
        for (name, a, b, c) in cases {
            ps.push_str(&format!(
                "$r = Get-DefenderStateSummary -AntivirusEnabled {a} -AMServiceEnabled {b} -RealTimeProtectionEnabled {c}\n\
                 $hex = ([System.Text.Encoding]::UTF8.GetBytes($r.Detail) | ForEach-Object {{ $_.ToString('x2') }}) -join ''\n\
                 Write-Output ('{name}|' + $r.Status + '|' + ($r.Enabled -join ',') + '|' + ($r.Disabled -join ',') + '|' + ($r.Unknown -join ',') + '|' + $hex)\n"
            ));
        }
        let dir = std::env::temp_dir().join(format!("wsd-defender-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("defender_summary_test.ps1");
        let mut bytes = vec![0xEF, 0xBB, 0xBF];
        bytes.extend_from_slice(ps.replace('\n', "\r\n").as_bytes());
        std::fs::write(&file, bytes).unwrap();
        let out = Command::new(&host)
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
            ])
            .arg(&file)
            .output()
            .expect("PowerShell host runs");
        let _ = std::fs::remove_dir_all(&dir);
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success(),
            "{stdout}\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let rows: std::collections::HashMap<String, Row> = stdout
            .lines()
            .filter_map(|l| {
                let f: Vec<&str> = l.trim().split('|').collect();
                (f.len() == 6).then(|| {
                    (
                        f[0].to_string(),
                        Row {
                            status: f[1].into(),
                            enabled: f[2].into(),
                            disabled: f[3].into(),
                            unknown: f[4].into(),
                            detail: hex_utf8(f[5]),
                        },
                    )
                })
            })
            .collect();
        assert_eq!(rows.len(), cases.len(), "{stdout}");
        let check = |case: &str, status: &str, enabled: &str, disabled: &str, unknown: &str| {
            let r = &rows[case];
            assert_eq!(
                (
                    r.status.as_str(),
                    r.enabled.as_str(),
                    r.disabled.as_str(),
                    r.unknown.as_str()
                ),
                (status, enabled, disabled, unknown),
                "case {case}: {}",
                r.detail
            );
            assert!(r.detail.starts_with("Microsoft Defender: "), "{}", r.detail);
            r.detail.clone()
        };

        let all_on = check(
            "ttt",
            "OK",
            "Antivirus,AMService,RealTimeProtection",
            "",
            "",
        );
        assert_eq!(
            all_on,
            "Microsoft Defender: включено — Antivirus, AMService, RealTimeProtection."
        );

        // The field report: only real-time protection is off.
        let rtp_off = check(
            "ttf",
            "ATTENTION",
            "Antivirus,AMService",
            "RealTimeProtection",
            "",
        );
        assert_eq!(
            rtp_off,
            "Microsoft Defender: отключено — RealTimeProtection; включено — Antivirus, AMService."
        );
        assert!(!rtp_off.contains("отключено — Antivirus"));

        let two_off = check(
            "ftf",
            "ATTENTION",
            "AMService",
            "Antivirus,RealTimeProtection",
            "",
        );
        assert_eq!(
            two_off,
            "Microsoft Defender: отключено — Antivirus, RealTimeProtection; включено — AMService."
        );

        let all_off = check(
            "fff",
            "ATTENTION",
            "",
            "Antivirus,AMService,RealTimeProtection",
            "",
        );
        assert_eq!(
            all_off,
            "Microsoft Defender: отключено — Antivirus, AMService, RealTimeProtection."
        );

        // Unknown / missing values are never reported as disabled.
        let none = check(
            "nnn",
            "UNKNOWN",
            "",
            "",
            "Antivirus,AMService,RealTimeProtection",
        );
        assert_eq!(
            none,
            "Microsoft Defender: не определено — Antivirus, AMService, RealTimeProtection."
        );
        let one_unknown = check(
            "tnt",
            "UNKNOWN",
            "Antivirus,RealTimeProtection",
            "",
            "AMService",
        );
        assert!(!one_unknown.contains("отключено"));
        check(
            "fnt",
            "ATTENTION",
            "RealTimeProtection",
            "Antivirus",
            "AMService",
        );
        check(
            "str",
            "ATTENTION",
            "Antivirus,AMService",
            "RealTimeProtection",
            "",
        );
        check(
            "odd",
            "UNKNOWN",
            "AMService,RealTimeProtection",
            "",
            "Antivirus",
        );
        let missing = check(
            "mis",
            "UNKNOWN",
            "Antivirus,AMService",
            "",
            "RealTimeProtection",
        );
        assert!(missing.contains("не определено — RealTimeProtection"));
    }
}

/// v0.4.0 read-only contract: the deep checks only ever DIAGNOSE; repair
/// commands exist solely as display text.
#[cfg(test)]
mod read_only_contract_tests {
    use super::EXPC_DIAGNOSTIC_PS1;

    #[test]
    fn deep_checks_run_only_read_only_commands() {
        let ps = String::from_utf8_lossy(EXPC_DIAGNOSTIC_PS1).replace("\r\n", "\n");
        let args: Vec<&str> = ps
            .lines()
            .map(str::trim)
            .filter(|l| l.starts_with("-Arguments "))
            .collect();
        assert_eq!(
            args,
            [
                "-Arguments '/verifyonly' `",
                "-Arguments '/Online /Cleanup-Image /ScanHealth /NoRestart /English' `",
                "-Arguments (\"{0} /scan\" -f $env:SystemDrive) `",
            ]
        );
        for repair in [
            "/scannow",
            "/RestoreHealth",
            "/spotfix",
            " /f\"",
            " /f'",
            "/offlinescanandfix",
        ] {
            assert!(
                !args.iter().any(|a| a.contains(repair)),
                "{repair} would be a repair"
            );
        }
        // Rust never starts sfc / DISM / chkdsk itself.
        for src in [
            include_str!("engine.rs"),
            include_str!("app.rs"),
            include_str!("deep_checks.rs"),
            include_str!("manifest.rs"),
            include_str!("report_package.rs"),
        ] {
            for exe in ["\"sfc", "\"dism", "\"chkdsk", "\"DISM", "\"SFC", "\"CHKDSK"] {
                assert!(
                    !src.contains(&format!("Command::new({exe}")),
                    "a deep check tool must never be started from Rust"
                );
            }
        }
    }
}

/// v0.4.2 Hardware Report precision: GPU memory never shown from a capped
/// 32-bit source or a GPU name; DDR speeds are reported data rates (MT/s),
/// not measured clocks.
#[cfg(test)]
mod hardware_precision_tests {
    use super::{HARDWARE_DIAGNOSTIC_PS1, HARDWARE_PASSPORT_PSM1};
    use std::process::Command;

    fn module() -> String {
        String::from_utf8_lossy(HARDWARE_PASSPORT_PSM1).replace("\r\n", "\n")
    }

    fn between(s: &str, from: &str, to: &str) -> String {
        let a = s.find(from).unwrap_or_else(|| panic!("{from}"));
        let b = a + s[a..].find(to).unwrap_or_else(|| panic!("{to}"));
        s[a..b].to_string()
    }

    fn powershell() -> Option<String> {
        if cfg!(windows) {
            return Some("powershell.exe".into());
        }
        if let Ok(p) = std::env::var("WSD_PWSH") {
            return Some(p);
        }
        Command::new("pwsh")
            .args(["-NoProfile", "-Command", "exit 0"])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|_| "pwsh".to_string())
    }

    #[test]
    fn hardware_report_text_uses_mt_s_and_marks_values_as_reported() {
        let ps = String::from_utf8_lossy(HARDWARE_DIAGNOSTIC_PS1);
        assert!(!ps.contains("RatedSpeedMHz) MHz"));
        assert!(!ps.contains("ConfiguredClockMHz) MHz"));
        assert!(!ps.contains("+' MHz'}else{'speed unavailable'}"));
        assert!(ps.contains("(SMBIOS-reported data rate, not measured)"));
        assert!(ps.contains("+' MT/s'}else{'speed unavailable'}"));
        let m = module();
        assert!(m.contains("SpeedSource = 'SMBIOS/WMI (reported, not measured)'"));
        // VRAM: precedence function only sees raw memory values — no GPU
        // name, no model table.
        let f = between(
            &m,
            "function Resolve-HardwareGpuMemory {",
            "# Read-only: the display driver",
        );
        assert!(!f.contains("Name"), "no model-name input");
        assert!(
            !f.to_ascii_lowercase().contains("rtx") && !f.to_ascii_lowercase().contains("radeon")
        );
        assert!(m.contains("VRAM=$mem.Display"));
    }

    /// v0.4.2 real iGPU case: a ~28 GB driver value on an integrated GPU
    /// is shared/system graphics memory, never "VRAM 28 GB"; a discrete
    /// card's 64-bit value stays dedicated VRAM. No model names involved.
    #[test]
    fn igpu_shared_memory_is_not_labelled_dedicated_vram() {
        let m = module();
        let f = between(
            &m,
            "function Resolve-HardwareGpuMemoryKind {",
            "# Read-only: the DirectX adapter records",
        );
        assert!(!f.contains("Name"), "no model-name input");
        for brand in ["intel", "nvidia", "rtx", "radeon", "uhd", "iris"] {
            assert!(!f.to_ascii_lowercase().contains(brand), "{brand}");
        }
        let Some(host) = powershell() else {
            eprintln!("no PowerShell host: execution skipped");
            return;
        };
        let mut ps = String::new();
        ps.push_str("[System.Threading.Thread]::CurrentThread.CurrentCulture = [System.Globalization.CultureInfo]::InvariantCulture\n");
        ps.push_str(&between(
            &m,
            "function ConvertTo-HardwareSize {",
            "function Get-HardwareMemoryType {",
        ));
        ps.push_str(&between(
            &m,
            "function Format-HardwareMemoryRate {",
            "# Read-only: the DirectX adapter records",
        ));
        ps.push_str(&between(
            &m,
            "# The DirectX record of one PnP device",
            "# Read-only: the display driver",
        ));
        ps.push_str(
            "function K($n, $mem, $dx, $loc) { $k = Resolve-HardwareGpuMemoryKind -Memory $mem -DirectX $dx -LocationInfo $loc; Write-Output ($n + '|' + $k.Kind + '|' + [string]$k.DedicatedBytes + '|' + [string]$k.SharedBytes + '|' + $k.Display) }\n\
             $q8 = Resolve-HardwareGpuMemory -AdapterRam 4293918720 -RegistryQword ([uint64]8589934592)\n\
             $q28 = Resolve-HardwareGpuMemory -AdapterRam 2147483648 -RegistryQword ([uint64]30064771072)\n\
             $dxRtx = [PSCustomObject]@{ VendorId = 0x10DE; DeviceId = 0x2D05; DedicatedVideoMemory = [uint64]8546971648; SharedSystemMemory = [uint64]17095983104 }\n\
             $dxIgpu = [PSCustomObject]@{ VendorId = 0x8086; DeviceId = 0xA7A0; DedicatedVideoMemory = [uint64]134217728; SharedSystemMemory = [uint64]17095983104 }\n\
             K 'discrete_dx' $q8 $dxRtx 'PCI bus 1, device 0, function 0'\n\
             K 'discrete_nodx' $q8 $null 'PCI bus 1, device 0, function 0'\n\
             K 'igpu_dx' $q28 $dxIgpu 'PCI bus 0, device 2, function 0'\n\
             K 'igpu_nodx' $q28 $null 'PCI bus 0, device 2, function 0'\n\
             K 'none' (Resolve-HardwareGpuMemory) $null $null\n\
             $rows = @($dxRtx, $dxIgpu)\n\
             Write-Output ('sel|' + [string](Select-HardwareGpuDirectX -Rows $rows -PnpDeviceId 'PCI\\VEN_8086&DEV_A7A0&SUBSYS_1&REV_04\\3&1').DedicatedVideoMemory + '|' + [string]($null -eq (Select-HardwareGpuDirectX -Rows @($dxIgpu, $dxIgpu) -PnpDeviceId 'PCI\\VEN_8086&DEV_A7A0')))\n",
        );
        let dir = std::env::temp_dir().join(format!("wsd-igpu-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("t.ps1");
        let mut bytes = vec![0xEF, 0xBB, 0xBF];
        bytes.extend_from_slice(ps.as_bytes());
        std::fs::write(&file, bytes).unwrap();
        let out = Command::new(&host)
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
            ])
            .arg(&file)
            .output()
            .expect("PowerShell runs");
        let _ = std::fs::remove_dir_all(&dir);
        let text = String::from_utf8_lossy(&out.stdout).to_string();
        assert!(
            out.status.success(),
            "{text}\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let row = |name: &str| -> Vec<String> {
            text.lines()
                .find(|l| l.starts_with(&format!("{name}|")))
                .unwrap_or_else(|| panic!("{name}: {text}"))
                .trim()
                .split('|')
                .map(str::to_string)
                .collect()
        };
        // Discrete card: the reliable 64-bit value stays dedicated VRAM.
        assert_eq!(
            row("discrete_dx")[1..5],
            ["dedicated", "8589934592", "17095983104", "8.00 GB"]
        );
        assert_eq!(row("discrete_nodx")[1..3], ["dedicated", "8589934592"]);
        // Integrated GPU: ~28 GB is never shown as dedicated VRAM.
        let igpu = row("igpu_dx");
        assert_eq!(igpu[1..3], ["shared", "134217728"]);
        assert!(igpu[4].contains("Dedicated video memory 128"), "{igpu:?}");
        assert!(igpu[4].contains("not dedicated VRAM"), "{igpu:?}");
        assert!(!igpu[4].starts_with("28"), "{igpu:?}");
        let nodx = row("igpu_nodx");
        assert_eq!(nodx[1..3], ["driver_reported", ""]);
        assert!(nodx[4].contains("Graphics memory reported by driver"));
        assert_eq!(row("none")[1..3], ["unknown", ""]);
        assert_eq!(row("none")[4], "Not reliably determined");
        assert_eq!(row("sel")[1..3], ["134217728", "True"], "unique match only");
    }

    #[test]
    fn vram_and_memory_rate_rules_run_in_powershell() {
        let Some(host) = powershell() else {
            eprintln!("no PowerShell host: execution skipped");
            return;
        };
        let m = module();
        let mut ps = String::new();
        ps.push_str("[System.Threading.Thread]::CurrentThread.CurrentCulture = [System.Globalization.CultureInfo]::InvariantCulture\n");
        ps.push_str(&between(
            &m,
            "function ConvertTo-HardwareSize {",
            "function Get-HardwareMemoryType {",
        ));
        ps.push_str(&between(
            &m,
            "function Format-HardwareMemoryRate {",
            "# Read-only: the display driver",
        ));
        ps.push_str(
            "function Show($n, $r) { Write-Output ($n + '|' + [string]$r.Bytes + '|' + $r.Source + '|' + $r.Reliable + '|' + $r.Display + '|' + [bool]$r.Note) }\n\
             Show 'qw_over_capped' (Resolve-HardwareGpuMemory -AdapterRam 4293918720 -RegistryQword ([uint64]8589934592))\n\
             Show 'qw_bytes' (Resolve-HardwareGpuMemory -AdapterRam $null -RegistryQword ([byte[]](0,0,0,0,2,0,0,0)))\n\
             Show 'wmi_ok' (Resolve-HardwareGpuMemory -AdapterRam 2147483648)\n\
             Show 'wmi_capped' (Resolve-HardwareGpuMemory -AdapterRam 4293918720)\n\
             Show 'wmi_negative' (Resolve-HardwareGpuMemory -AdapterRam -1048576)\n\
             Show 'none' (Resolve-HardwareGpuMemory)\n\
             Show 'conflict' (Resolve-HardwareGpuMemory -AdapterRam 2147483648 -RegistryDword 1073741824)\n\
             Show 'qw_wins' (Resolve-HardwareGpuMemory -AdapterRam 2147483648 -RegistryQword ([uint64]8589934592))\n\
             Show 'dword_only' (Resolve-HardwareGpuMemory -RegistryDword 1073741824)\n\
             Write-Output ('rate|' + (Format-HardwareMemoryRate 7667) + '|' + (Format-HardwareMemoryRate 3200) + '|' + (Format-HardwareMemoryRate '1600') + '|' + (Format-HardwareMemoryRate 0) + '|' + (Format-HardwareMemoryRate $null) + '|' + (Format-HardwareMemoryRate 'n/a') + '|' + (Format-HardwareMemoryRate 7667 -Approximate))\n",
        );
        let dir = std::env::temp_dir().join(format!("wsd-hwprec-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("t.ps1");
        let mut bytes = vec![0xEF, 0xBB, 0xBF];
        bytes.extend_from_slice(ps.as_bytes());
        std::fs::write(&file, bytes).unwrap();
        let out = Command::new(&host)
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
            ])
            .arg(&file)
            .output()
            .expect("PowerShell runs");
        let _ = std::fs::remove_dir_all(&dir);
        let text = String::from_utf8_lossy(&out.stdout).to_string();
        assert!(
            out.status.success(),
            "{text}\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let row = |name: &str| -> Vec<String> {
            text.lines()
                .find(|l| l.starts_with(&format!("{name}|")))
                .unwrap_or_else(|| panic!("{name}: {text}"))
                .trim()
                .split('|')
                .map(str::to_string)
                .collect()
        };
        // 64-bit driver value wins over the saturated 32-bit "4.00 GB".
        assert_eq!(
            row("qw_over_capped")[1..5],
            [
                "8589934592",
                "registry:HardwareInformation.qwMemorySize",
                "True",
                "8.00 GB"
            ]
        );
        assert_eq!(
            row("qw_bytes")[1..4],
            [
                "8589934592",
                "registry:HardwareInformation.qwMemorySize",
                "True"
            ]
        );
        // A representable 32-bit value is shown with its source.
        assert_eq!(
            row("wmi_ok")[1..5],
            [
                "2147483648",
                "wmi:Win32_VideoController.AdapterRAM",
                "True",
                "2.00 GB"
            ]
        );
        // Saturated / signed-saturated values are never shown as VRAM.
        for n in ["wmi_capped", "wmi_negative"] {
            assert_eq!(
                row(n)[1..6],
                ["", "none", "False", "Not reliably determined", "True"],
                "{n}"
            );
        }
        assert_eq!(
            row("none")[1..5],
            ["", "none", "False", "Not reliably determined"]
        );
        // Two 32-bit sources that disagree: not determined, documented.
        assert_eq!(
            row("conflict")[1..6],
            ["", "conflict", "False", "Not reliably determined", "True"]
        );
        // Documented precedence: the 64-bit value, with a note.
        assert_eq!(
            row("qw_wins")[1..6],
            [
                "8589934592",
                "registry:HardwareInformation.qwMemorySize",
                "True",
                "8.00 GB",
                "True"
            ]
        );
        assert_eq!(
            row("dword_only")[1..4],
            [
                "1073741824",
                "registry:HardwareInformation.MemorySize",
                "True"
            ]
        );
        assert_eq!(
            row("rate")[1..],
            [
                "7667 MT/s",
                "3200 MT/s",
                "1600 MT/s",
                "Unavailable",
                "Unavailable",
                "Unavailable",
                "~7667 MT/s"
            ]
        );
        assert!(!text.contains("MHz"));
    }
}

/// v0.4.2 icon isolation: WinStateDiag has no system-tray code; the EXE,
/// window, taskbar and Alt+Tab icon all come from `assets\icon.ico` via the
/// Windows resource (build.rs). The prepared tray artwork is a separate,
/// unwired asset and never replaces that pipeline.
#[cfg(test)]
mod icon_isolation_tests {
    fn ico_sizes(bytes: &[u8]) -> Vec<u32> {
        let n = u16::from_le_bytes([bytes[4], bytes[5]]) as usize;
        (0..n)
            .map(|i| {
                let w = bytes[6 + 16 * i] as u32;
                if w == 0 { 256 } else { w }
            })
            .collect()
    }

    #[test]
    fn exe_and_window_icon_pipeline_is_unchanged_and_tray_asset_is_separate() {
        let build = include_str!("../build.rs");
        assert!(build.contains("res.set_icon(\"assets/icon.ico\")"));
        assert!(!build.contains("tray-icon"));
        let main = include_str!("main.rs");
        assert!(
            !main.contains("with_icon"),
            "window icon still from the EXE resource"
        );
        assert!(!main.contains("tray"));
        let app_icon: &[u8] = include_bytes!("../assets/icon.ico");
        let tray_icon: &[u8] = include_bytes!("../assets/tray-icon.ico");
        assert_ne!(app_icon, tray_icon);
        assert_eq!(
            ico_sizes(app_icon),
            [256, 128, 96, 72, 64, 48, 32, 24, 16],
            "application icon untouched"
        );
        let mut tray = ico_sizes(tray_icon);
        tray.sort_unstable();
        assert_eq!(tray, [16, 20, 24, 32, 40], "tray sizes incl. 125%/150% DPI");
        // No source file wires the tray asset (no tray implementation).
        for src in [
            include_str!("app.rs"),
            include_str!("main.rs"),
            include_str!("../build.rs"),
        ] {
            assert!(!src.contains(&["tray-icon", ".ico"].concat()));
        }
    }
}
