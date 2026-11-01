//! Unified session report package — REPORTS-001 (Phase06).
//!
//! All archives: <EXE>/Reports/<Client>-<Computer>-DD.MM.YY-HH.MM.zip.
//! Collisions reserve (2), (3), ... without adopting a historical archive.
//! Desktop packages defer publication until orchestration is idle. The low-level
//! `new` API retains immediate publication for compatibility with standalone callers.
//! Evidence/candidate live in per-user EXPC/WinStateDiag/Work.
//! Publication verifies a staged copy across volumes before an atomic rename.
//! Legacy user reports are never removed.
//!
//! Candidate bytes are flushed and CRC/name/size validated before one rename.
//! Initial publication never replaces an existing file; updates replace only
//! the current package's verified destination. Failure keeps earlier ZIP and
//! loose evidence. No partial ZIP is published with a finished filename.
//!
//! finalize() validates every loose file against the archive, persists SSD
//! history in per-user History, removes only matched files and its own marker,
//! then removes the empty workspace. Unknown files/subdirectories are retained.
//! Later contributions restore evidence from the ZIP before rebuilding; raw
//! evidence and manifest are preserved; servicing/log/history snapshots use
//! explicit nested ZIP paths, never arbitrary recursive Reports ingestion.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::engine::report_base_name;

/// RC9 portable report naming contract. Client is never inferred from hardware.
fn diagnostic_zip_base(client: &str, computer: &str, date: &str, time: &str) -> String {
    let client = client.trim_matches(|c: char| c.is_whitespace() || ['-', '_', '.'].contains(&c));
    let computer =
        computer.trim_matches(|c: char| c.is_whitespace() || ['-', '_', '.'].contains(&c));
    let date = date.replace('-', ".");
    let time = time
        .split(['-', '.'])
        .take(2)
        .map(|part| {
            part.parse::<u8>()
                .map(|v| format!("{v:02}"))
                .unwrap_or_else(|_| "unknown".into())
        })
        .collect::<Vec<_>>()
        .join(".");
    report_base_name(client, computer, &format!("{date}-{time}")).replace(" - ", "-")
}

#[test]
fn rc4_zip_contract() {
    assert_eq!(
        diagnostic_zip_base("ExampleClient", "MSI", "20-10-26", "8-36-0"),
        "ExampleClient-MSI-20.10.26-08.36"
    );
    for (client, pc, expected) in [
        ("ExampleClient", "MSI", "ExampleClient-MSI-20.10.26-08.30"),
        ("ExampleOrg", "SERVER", "ExampleOrg-SERVER-20.10.26-08.30"),
        (" ", "MSI", "MSI-20.10.26-08.30"),
        ("Клиент", "ПК", "Клиент-ПК-20.10.26-08.30"),
    ] {
        assert_eq!(
            diagnostic_zip_base(client, pc, "20-10-26", "08-30-59"),
            expected
        );
    }
}

fn archive_name(name: &str) -> String {
    if let Some(parts) = servicing_parts(name) {
        return parts.join("/");
    }
    match name {
        "Servicing_dism.log" => "Logs/Servicing/dism.log".into(),
        "Servicing_CBS.log" => "Logs/Servicing/CBS.log".into(),
        "Servicing_Result.json" => "Logs/Servicing/Result.json".into(),
        "Session_Journal.txt" => "Logs/Session_Journal.txt".into(),
        STARTUP_LOG_FILE => format!("Logs/{name}"),
        _ => name.into(),
    }
}

// Only our explicit GUID-based namespace is allowed through flat staging.
fn servicing_parts(name: &str) -> Option<Vec<&str>> {
    let parts: Vec<_> = name.splitn(4, "__").collect();
    if parts.first() != Some(&"WindowsServicingLogs")
        || !(parts.len() == 3 || parts.len() == 4)
        || parts[1].len() != 32
        || !parts[1].bytes().all(|c| c.is_ascii_hexdigit())
        || parts
            .iter()
            .any(|p| p.is_empty() || p.contains(['/', '\\', ':']) || *p == "..")
    {
        return None;
    }
    match parts.as_slice() {
        [_, _, "Result.json"] => Some(parts),
        [_, _, "CBS" | "DISM", _] => Some(parts),
        _ => None,
    }
}

fn safe_archive_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= u16::MAX as usize
        && !name.contains(['\\', ':', '\0'])
        && name
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

/// Reserved slot for the permanent graphical-report instruction.
pub const GRAPHIC_REPORT_FILE: &str = "GRAPHIC_REPORT.md";
pub const SSD_HISTORY_FILE: &str = "ssd_benchmark_history.log";
pub const STARTUP_LOG_FILE: &str = "startup_graphics.log";
/// Marker in the name of evidence from an interrupted (user-cancelled) run.
pub const USER_CANCELLED: &str = "USER_CANCELLED";

/// Canonical `assets\GRAPHIC_REPORT.md`, embedded at build time when it
/// exists (see build.rs). Nothing is invented when it is missing.
const GRAPHIC_REPORT_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/GRAPHIC_REPORT.md"));
const GRAPHIC_REPORT_STATE: &str = env!("WSD_GRAPHIC_REPORT_TEMPLATE");

/// The embedded GRAPHIC_REPORT.md template, if the build had one.
pub fn embedded_graphic_template() -> Option<Vec<u8>> {
    (GRAPHIC_REPORT_STATE == "present").then(|| GRAPHIC_REPORT_BYTES.to_vec())
}

pub type SharedPackage = Arc<Mutex<SessionPackage>>;

/// Locks the shared package; a poisoned lock (a panicking worker) still
/// yields the data, which is only ever mutated through complete steps.
pub fn lock(package: &SharedPackage) -> std::sync::MutexGuard<'_, SessionPackage> {
    package.lock().unwrap_or_else(|e| e.into_inner())
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum EvidenceModule {
    Expc,
    Hardware,
    DriverAudit,
    SsdBenchmark,
    /// Native NVMe Health evidence (read-only).
    NvmeHealth,
    /// Storage correlation (benchmark + health + events) per disk.
    StorageCorrelation,
    /// v0.4.4: Crash Dump / BSOD analysis (original dumps, raw debugger
    /// output, structured summaries).
    CrashDump,
    /// v0.4.4: Group Policy / ADMX health.
    GroupPolicyAdmx,
    /// v0.4.5: hardware sensors (temperatures, rails, power, fans; replaces
    /// the v0.4.4 power-only module).
    HardwareSensors,
    /// v0.4.5: freeze / hang incident intelligence (Kernel-Power 41 /
    /// EventLog 6008 timelines, LiveKernelReports listing).
    FreezeIncidents,
    /// v1.0: aggregated event evidence (Schannel, Windows Update, TPM, SCM,
    /// SideBySide, Code Integrity, VSS / Volsnap, application errors).
    EventEvidence,
}

impl EvidenceModule {
    /// Module a completed evidence file belongs to (by its name prefix).
    /// Evidence from an interrupted run never counts as completed.
    pub fn of_file_name(name: &str) -> Option<Self> {
        if name.contains(USER_CANCELLED) {
            return None;
        }
        // Before "Hardware_": the sensor evidence shares that prefix.
        if name.starts_with(crate::sensors::EVIDENCE_PREFIX) {
            return Some(Self::HardwareSensors);
        }
        if name.starts_with("EXPC_") {
            Some(Self::Expc)
        } else if name.starts_with("Hardware_") {
            Some(Self::Hardware)
        } else if name.starts_with("DriverAudit_") {
            Some(Self::DriverAudit)
        } else if name.starts_with("SSD_Benchmark_") {
            Some(Self::SsdBenchmark)
        } else if name.starts_with(crate::nvme_health::EVIDENCE_PREFIX)
            || name.starts_with("Ata_Smart_")
        {
            Some(Self::NvmeHealth)
        } else if name.starts_with(crate::storage_health::EVIDENCE_PREFIX) {
            Some(Self::StorageCorrelation)
        } else if name.starts_with(crate::crash_dump::EVIDENCE_PREFIX) {
            Some(Self::CrashDump)
        } else if name.starts_with(crate::gpo_admx::EVIDENCE_PREFIX) {
            Some(Self::GroupPolicyAdmx)
        } else if name.starts_with(crate::incidents::EVIDENCE_PREFIX) {
            Some(Self::FreezeIncidents)
        } else if name.starts_with(crate::events::EVIDENCE_PREFIX) {
            Some(Self::EventEvidence)
        } else {
            None
        }
    }
}

/// One evidence file, held in memory so it no longer depends on the
/// temporary location it was produced in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceFile {
    pub name: String,
    pub bytes: Vec<u8>,
}

impl EvidenceFile {
    pub fn new(name: impl Into<String>, bytes: Vec<u8>) -> Self {
        Self {
            name: name.into(),
            bytes,
        }
    }

    pub fn read(path: &Path) -> Result<Self, String> {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| format!("Недопустимое имя файла: {}", path.display()))?
            .to_string();
        let bytes =
            fs::read(path).map_err(|e| format!("Не удалось прочитать {}: {e}", path.display()))?;
        Ok(Self { name, bytes })
    }
}

/// Final report identity, resolved once per running WinStateDiag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackageIdentity {
    pub base: String,
    /// Private intermediate workspace, never the user's Folder action target.
    pub report_dir: PathBuf,
    pub zip_path: PathBuf,
}

impl PackageIdentity {
    /// Evidence lives directly in the report folder (the ZIP mirrors it).
    pub fn evidence_dir(&self) -> PathBuf {
        self.report_dir.clone()
    }
}

/// `COMPUTERNAME` as the GUI shows it (report identity).
pub fn computer_name() -> String {
    std::env::var("COMPUTERNAME").unwrap_or_else(|_| "UNKNOWN-PC".into())
}

/// `<EXE>\Reports\Logs`: saved journals and the start-up log (application
/// logs, never a report session folder).
pub fn logs_dir(reports_root: &Path) -> PathBuf {
    persistent_dir(reports_root).join("Logs")
}

/// Portable application state, separate from user-facing completed ZIPs.
pub fn persistent_dir(reports_root: &Path) -> PathBuf {
    crate::app_paths::data_root(reports_root.parent().unwrap_or(reports_root))
}

pub fn storage_history_path(reports_root: &Path) -> PathBuf {
    persistent_dir(reports_root).join(crate::storage_history::FILE_NAME)
}

/// Read-only legacy fallback. Never remove or overwrite a legacy user file.
pub fn storage_history_source(reports_root: &Path) -> PathBuf {
    let current = storage_history_path(reports_root);
    if current.exists() {
        current
    } else {
        reports_root.join(crate::storage_history::FILE_NAME)
    }
}

/// The report folder of exactly this Client + Computer + date under `root`:
/// `<Client> - <Computer> - <date>` or `<Computer> - <date>` (empty Client).
/// An existing folder with that exact name (case-insensitive) is reused, so
/// same-day runs of the same client accumulate; otherwise the new name (not
/// created here). v1.0 Client Identity: a folder of ANOTHER client (or the
/// client-less one) is never adopted or renamed — its evidence belongs to
/// that other identity.
#[cfg(test)]
pub fn find_or_new_report_dir(root: &Path, client: &str, computer: &str, date: &str) -> PathBuf {
    let wanted = report_base_name(client, computer, date);
    let wanted_l = wanted.to_lowercase();
    let mut existing: Vec<String> = fs::read_dir(root)
        .map(|rd| {
            rd.flatten()
                .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
                .map(|e| e.file_name().to_string_lossy().to_string())
                .filter(|n| n.to_lowercase() == wanted_l)
                .collect()
        })
        .unwrap_or_default();
    existing.sort();
    match existing.into_iter().next() {
        Some(name) => root.join(name),
        None => root.join(wanted),
    }
}

/// Private workspace reservation owner, never included in the ZIP.
/// Removed by finalize only after the archive and loose evidence are verified.
pub const SESSION_MARKER: &str = ".wsd-session";

/// `session.session_id` of a report ZIP's manifest, if readable.
fn zip_session_id(zip: &Path) -> Option<String> {
    let manifest = read_zip(zip)
        .ok()?
        .into_iter()
        .find(|e| e.name == crate::manifest::MANIFEST_FILE)?;
    let v = crate::deep_checks::json::parse(std::str::from_utf8(&manifest.bytes).ok()?)?;
    v.get("session")?
        .get("session_id")?
        .as_str()
        .map(str::to_string)
}

/// v1.0 identity of one diagnostic session / separate module operation:
/// fixed when the user starts it and never taken from the live input
/// fields afterwards.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionIdentity {
    pub session_id: String,
    /// Trimmed; may be empty (then only the computer names the report).
    pub client: String,
    pub computer: String,
}

impl SessionIdentity {
    /// Freezes the current Client / Computer input under `session_id`
    /// (an empty Computer falls back to `COMPUTERNAME`).
    pub fn new(session_id: &str, client: &str, computer: &str) -> Self {
        let computer = computer.trim();
        Self {
            session_id: session_id.to_string(),
            client: client.trim().to_string(),
            computer: if computer.is_empty() {
                computer_name()
            } else {
                computer.to_string()
            },
        }
    }

    /// Same Client and Computer (the session id is not compared).
    pub fn same_identity(&self, client: &str, computer: &str) -> bool {
        let other = Self::new("", client, computer);
        self.client == other.client && self.computer == other.computer
    }
}

// TODO(Sanitized Report, P3 — v0.3.6 only prepares the extension point, does
// not implement it): a future `build_sanitized_zip(&SessionPackage) -> Vec<u8>`
// would reuse `list_files`/`build_zip` below but run each evidence file's
// text through a masking pass first (MAC addresses, motherboard serial,
// Windows ProductId, other unique per-machine identifiers) before zipping,
// while leaving the normal Service Report (`update_zip`/`build_zip`) exactly
// as it is today. Not wired into the UI or CLI; no behavior change here.

pub struct SessionPackage {
    reports_root: PathBuf,
    archive_time: String,
    identity: Option<PackageIdentity>,
    /// Computer name of the report identity (manifest).
    computer: String,
    /// A verified rebuild happened since the last `finalize`.
    needs_finalize: bool,
    completed: BTreeSet<EvidenceModule>,
    /// Driver Audit evidence offered to a package that is neither resolved
    /// nor bound to a session: joins it when the first module creates it.
    pending: Vec<EvidenceFile>,
    zip_ready: bool,
    /// Desktop orchestration publishes only after all workers are idle.
    deferred: bool,
    startup_offset: usize,
    template: Option<Vec<u8>>,
    /// v1.0 (system, hardware) state codes for the manifest.
    states: Option<(String, String)>,
    state_reasons: Vec<String>,
    execution_override: Option<String>,
    state_reasons_dirty: bool,
    /// v1.0 Client Identity: the session this package belongs to. Once
    /// bound, its Client / Computer name the report; the values callers
    /// pass are ignored, so a later edit of the input fields never leaks in.
    session: Option<SessionIdentity>,
    #[cfg(test)]
    pub fail_next_replace: bool,
}

impl SessionPackage {
    pub fn new(reports_root: PathBuf, template: Option<Vec<u8>>) -> Self {
        Self {
            reports_root,
            archive_time: {
                let t = crate::ui::sysinfo::local_time();
                format!("{:02}-{:02}-{:02}", t.hour, t.minute, t.second)
            },
            identity: None,
            computer: String::new(),
            needs_finalize: false,
            completed: BTreeSet::new(),
            pending: Vec::new(),
            zip_ready: false,
            deferred: false,
            startup_offset: 0,
            template,
            states: None,
            state_reasons: Vec::new(),
            execution_override: None,
            state_reasons_dirty: false,
            session: None,
            #[cfg(test)]
            fail_next_replace: false,
        }
    }

    /// v1.0: binds this (still unresolved) package to one session.
    pub fn bind_session(&mut self, session: SessionIdentity) {
        self.startup_offset = fs::metadata(logs_dir(&self.reports_root).join(STARTUP_LOG_FILE))
            .map(|m| m.len() as usize)
            .unwrap_or(0);
        let t = crate::ui::sysinfo::local_time();
        self.archive_time = format!("{:02}-{:02}-{:02}", t.hour, t.minute, t.second);
        self.computer = session.computer.clone();
        self.session = Some(session);
    }

    /// The session this package belongs to, if bound.
    pub fn session(&self) -> Option<&SessionIdentity> {
        self.session.as_ref()
    }

    /// Nothing resolved, bound or pending yet (a just-created package).
    pub fn is_fresh(&self) -> bool {
        self.identity.is_none() && self.session.is_none() && self.pending.is_empty()
    }

    /// A new, empty package of the same Reports folder and template, bound
    /// to `session` (the next session of this WinStateDiag). The previous
    /// package — and every operation still holding it — keeps its own
    /// identity.
    pub fn successor(&self, session: SessionIdentity) -> Self {
        let mut next = Self::new(self.reports_root.clone(), self.template.clone());
        next.deferred = self.deferred;
        next.bind_session(session);
        next
    }

    /// v1.0: the current (system, hardware) state codes written into the
    /// manifest at the next rebuild.
    pub fn set_execution_override(&mut self, value: Option<&str>) -> bool {
        let next = value.map(str::to_string);
        if self.execution_override == next {
            return false;
        }
        self.execution_override = next;
        self.state_reasons_dirty = true;
        true
    }
    pub fn set_state_reasons(&mut self, reasons: Vec<String>) -> bool {
        if self.state_reasons == reasons {
            return false;
        }
        self.state_reasons = reasons;
        self.state_reasons_dirty = true;
        true
    }

    pub fn set_states(&mut self, system: &str, hardware: &str) {
        self.states = Some((system.to_string(), hardware.to_string()));
    }

    /// v1.1 RC: sets the states and, when they changed after the final ZIP
    /// exists, rebuilds it so `manifest.json` never keeps a stale state.
    /// Packaged evidence is restored first (a finalized folder holds only
    /// the ZIP), exactly like [`contribute`]. Returns true when rebuilt.
    pub fn refresh_states(&mut self, system: &str, hardware: &str) -> Result<bool, String> {
        let wanted = Some((system.to_string(), hardware.to_string()));
        if self.states == wanted && !self.state_reasons_dirty {
            return Ok(false);
        }
        let previous = self.states.clone();
        self.states = wanted;
        if self.identity.is_none() {
            return Ok(false);
        }
        let id = self.identity.clone().ok_or("Отчёт сессии ещё не создан.")?;
        let result = self
            .verify_owner(&id)
            .and_then(|_| restore_loose(&id))
            .and_then(|_| self.rebuild());
        if result.is_err() {
            self.states = previous;
        }
        if result.is_ok() {
            self.state_reasons_dirty = false;
        }
        result.map(|_| true)
    }

    fn verify_owner(&self, id: &PackageIdentity) -> Result<(), String> {
        if let Some(session) = &self.session
            && id.zip_path.exists()
            && zip_session_id(&id.zip_path).as_deref() != Some(session.session_id.as_str())
        {
            return Err(
                "Report ZIP does not belong to the current session; files preserved.".into(),
            );
        }
        Ok(())
    }

    /// Package for the portable EXE folder (`<exe_dir>\Reports`) with the
    /// embedded GRAPHIC_REPORT.md.
    pub fn for_exe_dir(exe_dir: &Path) -> Self {
        let mut package = Self::new(exe_dir.join("Reports"), embedded_graphic_template());
        package.deferred = true;
        package
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn identity(&self) -> Option<&PackageIdentity> {
        self.identity.as_ref()
    }

    /// Modules whose evidence completed successfully in this session.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn completed_modules(&self) -> &BTreeSet<EvidenceModule> {
        &self.completed
    }

    /// Reserves an archive name once, with an exclusive sibling workspace.
    /// Existing flat ZIPs and workspaces are skipped; legacy folders untouched.
    pub fn resolve(
        &mut self,
        client: &str,
        computer: &str,
        date: &str,
    ) -> Result<PackageIdentity, String> {
        if let Some(id) = &self.identity {
            return Ok(id.clone());
        }
        let bound = self.session.clone();
        let (client, computer) = match &bound {
            Some(s) => (s.client.as_str(), s.computer.as_str()),
            None => (client, computer),
        };
        if !computer.trim().is_empty() {
            self.computer = computer.trim().to_string();
        }
        let computer = if computer.trim().is_empty() {
            computer_name()
        } else {
            computer.to_string()
        };
        let base = diagnostic_zip_base(client, &computer, date, &self.archive_time);
        let work_root = persistent_dir(&self.reports_root).join("Work");
        fs::create_dir_all(&work_root).map_err(|e| {
            format!(
                "Cannot create report workspace {}: {e}",
                work_root.display()
            )
        })?;
        let mut reserved = None;
        for n in 1..10000 {
            let name = if n == 1 {
                base.clone()
            } else {
                format!("{base} ({n})")
            };
            let dir = work_root.join(&name);
            if self.reports_root.join(format!("{name}.zip")).exists() {
                continue;
            }
            match fs::create_dir(&dir) {
                Ok(()) => {
                    if self.reports_root.join(format!("{name}.zip")).exists() {
                        let _ = fs::remove_dir(&dir);
                        continue;
                    }
                    if let Some(s) = &bound {
                        fs::write(dir.join(SESSION_MARKER), &s.session_id).map_err(|e| {
                            format!("Cannot mark report workspace {}: {e}", dir.display())
                        })?;
                    }
                    reserved = Some(dir);
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => {
                    return Err(format!(
                        "Cannot reserve report workspace {}: {e}",
                        dir.display()
                    ));
                }
            }
        }
        let report_dir = reserved.ok_or("No free report archive name")?;
        let base = report_dir
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| report_base_name(client, &computer, date));
        let report_dir = if self.deferred {
            let session = self
                .session
                .as_ref()
                .ok_or("Session identity required before report collection")?;
            if !safe_archive_name(&session.session_id) || session.session_id.contains('/') {
                return Err("Invalid session identity".into());
            }
            let dir = report_dir.join(&session.session_id);
            fs::create_dir(&dir).map_err(|e| format!("Session workspace: {e}"))?;
            dir
        } else {
            report_dir
        };
        let id = PackageIdentity {
            zip_path: self.reports_root.join(format!("{base}.zip")),
            report_dir,
            base,
        };
        self.identity = Some(id.clone());
        Ok(id)
    }

    /// Final verified ZIP of this session, if the last update succeeded.
    pub fn final_zip(&self) -> Option<PathBuf> {
        let id = self.identity.as_ref()?;
        (self.zip_ready && !(self.deferred && self.needs_finalize) && id.zip_path.is_file())
            .then(|| id.zip_path.clone())
    }

    pub fn pending_publication(&self, path: &Path) -> bool {
        self.deferred
            && self.needs_finalize
            && self.identity.as_ref().is_some_and(|id| id.zip_path == path)
    }

    pub fn snapshot_session_journal(&mut self, journal: &[String]) -> Result<(), String> {
        if !self.deferred || !self.needs_finalize {
            return Ok(());
        }
        let Some(session) = &self.session else {
            return Ok(());
        };
        let Some(start) = journal
            .iter()
            .rposition(|line| line.contains(&session.session_id))
        else {
            return Ok(());
        };
        let id = self.identity.as_ref().ok_or("No session workspace")?;
        write_new_file(
            &id.report_dir.join("Session_Journal.txt"),
            journal[start..].join("\r\n").as_bytes(),
        )?;
        self.rebuild()?;
        Ok(())
    }

    /// Adds evidence (persisted first) and updates the ZIP.
    pub fn contribute(
        &mut self,
        client: &str,
        computer: &str,
        date: &str,
        files: Vec<EvidenceFile>,
    ) -> Result<PathBuf, String> {
        self.contribute_named(client, computer, date, files)
            .map(|(zip, _)| zip)
    }

    /// v1.0: [`contribute`] that also returns the names the files were
    /// STORED under (input order). A same-day collision stores a file as
    /// `<stem>_NN`; evidence that references other evidence (storage
    /// correlation → benchmark / health) must use these exact names.
    pub fn contribute_named(
        &mut self,
        client: &str,
        computer: &str,
        date: &str,
        files: Vec<EvidenceFile>,
    ) -> Result<(PathBuf, Vec<String>), String> {
        let wanted: Vec<String> = files.iter().map(|f| f.name.clone()).collect();
        let id = match self.resolve(client, computer, date) {
            Ok(id) => id,
            Err(error) => {
                self.pending.extend(files);
                return Err(error);
            }
        };
        self.verify_owner(&id)?;
        let evidence_dir = id.evidence_dir();
        fs::create_dir_all(&evidence_dir).map_err(|e| {
            format!(
                "Не удалось создать папку отчёта: {e}\n— путь: {}",
                id.report_dir.display()
            )
        })?;
        let mut all = std::mem::take(&mut self.pending);
        all.extend(files);
        // Earlier evidence that lives only in the (cleaned) ZIP comes back
        // first; if the ZIP cannot be read, the new evidence is still kept
        // as loose files and the existing ZIP is left untouched.
        let restored = restore_loose(&id);
        self.attach_startup_log(&id);
        let stored = match store_evidence(&evidence_dir, &all) {
            Ok(names) => names,
            Err(err) => {
                // Nothing is lost: what was not stored stays pending.
                self.pending = all;
                return Err(err);
            }
        };
        for (_, name) in &stored {
            if let Some(m) = EvidenceModule::of_file_name(name) {
                self.completed.insert(m);
            }
        }
        // Names of THIS call's files (pending files from before come first).
        let mut names = Vec::with_capacity(wanted.len());
        let mut pool = stored.clone();
        for w in &wanted {
            match pool.iter().rposition(|(o, _)| o == w) {
                Some(i) => names.push(pool.remove(i).1),
                None => names.push(w.clone()),
            }
        }
        restored?;
        self.rebuild().map(|zip| (zip, names))
    }

    /// The report folder for an update outside `contribute` (SSD history
    /// append): resolved, created, and with packaged evidence restored.
    pub fn open_for_update(
        &mut self,
        client: &str,
        computer: &str,
        date: &str,
    ) -> Result<PackageIdentity, String> {
        let id = self.resolve(client, computer, date)?;
        self.verify_owner(&id)?;
        fs::create_dir_all(&id.report_dir).map_err(|e| {
            format!(
                "Не удалось создать папку отчёта: {e}\n— путь: {}",
                id.report_dir.display()
            )
        })?;
        restore_loose(&id)?;
        self.attach_startup_log(&id);
        Ok(id)
    }

    /// v1.0 Startup Idle: the start-up log lives in `Reports\Logs`; a
    /// session takes its current snapshot into its own folder (append-only:
    /// a copy that is not a continuation of the folder's one is left alone).
    fn attach_startup_log(&self, id: &PackageIdentity) {
        let Ok(mut current) = fs::read(logs_dir(&self.reports_root).join(STARTUP_LOG_FILE)) else {
            return;
        };
        if self.deferred {
            current = current
                .get(self.startup_offset..)
                .unwrap_or_default()
                .to_vec();
        }
        let target = id.report_dir.join(STARTUP_LOG_FILE);
        match fs::read(&target) {
            Ok(old) if old == current || !current.starts_with(&old) => {}
            _ => {
                let _ = write_new_file(&target, &current);
            }
        }
    }

    /// A verified rebuild is waiting for `finalize`.
    pub fn needs_finalize(&self) -> bool {
        self.needs_finalize
    }

    /// Final step of a successful package: leaves only the verified ZIP in
    /// the report folder. Returns removed loose files, or empty if already
    /// finalized. Unverified/new loose evidence is an error, never a silent
    /// success. Errors never remove anything further.
    pub fn finalize(&mut self) -> Result<Vec<String>, String> {
        // One attempt per verified rebuild: after any outcome (also an
        // error) the next attempt waits for the next successful update, so
        // a problem is reported once and never retried every frame.
        let result = self.finalize_once();
        self.needs_finalize = false;
        result
    }

    fn finalize_once(&mut self) -> Result<Vec<String>, String> {
        let id = self.identity.clone().ok_or("Отчёт сессии ещё не создан.")?;
        self.verify_owner(&id)?;
        if self.deferred && self.needs_finalize {
            // Fail closed on unexpected hidden files, ZIPs, or subdirectories.
            // They are not part of list_files and must never be silently deleted.
            for entry in fs::read_dir(&id.report_dir).map_err(|e| e.to_string())? {
                let entry = entry.map_err(|e| e.to_string())?;
                let name = entry.file_name().to_string_lossy().to_string();
                if !entry.file_type().map_err(|e| e.to_string())?.is_file()
                    || ((name.starts_with('.') || name.to_ascii_lowercase().ends_with(".zip"))
                        && name != SESSION_MARKER
                        && name != ".session-ready.zip")
                {
                    return Err(
                        "ERROR: unexpected workspace entry; all session data preserved".into(),
                    );
                }
            }
            let candidate = id.report_dir.join(".session-ready.zip");
            let entries = read_zip(&candidate)?;
            if self.session.as_ref().map(|s| s.session_id.as_str())
                != zip_session_id(&candidate).as_deref()
            {
                return Err(
                    "ERROR: candidate session identity mismatch; workspace preserved".into(),
                );
            }
            for path in list_files(&id.report_dir) {
                let mut evidence = EvidenceFile::read(&path)?;
                evidence.name = archive_name(&evidence.name);
                if !entries.contains(&evidence) {
                    return Err("ERROR: unarchived evidence; workspace preserved".into());
                }
            }
            publish_archive(&candidate, &id.zip_path, self.zip_ready).map_err(|e| {
                format!("ERROR: archive publication failed: {e}; workspace preserved")
            })?;
            self.zip_ready = true;
        }
        if !self.zip_ready || !id.zip_path.is_file() {
            return Err("Итоговый ZIP не готов — файлы отчёта сохранены.".into());
        }
        // 1. The final ZIP must be readable and CRC-valid right now.
        let packaged = read_zip(&id.zip_path)?;
        if packaged.is_empty() {
            return Err("Итоговый ZIP пуст — файлы отчёта сохранены.".into());
        }
        let manifest_ok = packaged.iter().any(|e| {
            e.name == crate::manifest::MANIFEST_FILE
                && std::str::from_utf8(&e.bytes)
                    .ok()
                    .and_then(crate::deep_checks::json::parse)
                    .is_some()
        });
        if !manifest_ok {
            return Err(
                "В итоговом ZIP нет корректного manifest.json — файлы отчёта сохранены.".into(),
            );
        }
        // 2. Every loose file must be packaged byte for byte; anything newer
        //    (not yet in the ZIP) means this is not a final state.
        let loose = list_files(&id.report_dir);
        for path in &loose {
            let mut file = EvidenceFile::read(path)?;
            file.name = archive_name(&file.name);
            if !packaged.iter().any(|e| *e == file) {
                return Err(format!(
                    "Unarchived or changed report file: {}; files preserved.",
                    file.name
                ));
            }
        }
        // 3. Persistent SSD history outlives the session copy.
        let history = id.report_dir.join(SSD_HISTORY_FILE);
        if history.is_file() {
            let text = fs::read_to_string(&history)
                .map_err(|e| format!("Не удалось прочитать {}: {e}", history.display()))?;
            crate::ssd_history::merge_into(
                &crate::ssd_history::canonical_history_path(&self.reports_root),
                &crate::ssd_history::parse_history(&text),
            )
            .map_err(|e| format!("История SSD не сохранена ({e}) — файлы отчёта сохранены."))?;
        }
        // 4. Remove exactly those loose files (the ZIP is never touched).
        let mut removed = Vec::new();
        for path in loose {
            if path.parent() != Some(id.report_dir.as_path()) || path == id.zip_path {
                continue;
            }
            fs::remove_file(&path)
                .map_err(|e| format!("Не удалось удалить {}: {e}", path.display()))?;
            removed.push(
                path.file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default(),
            );
        }
        // 5. The package is still intact.
        read_zip(&id.zip_path)?;
        // Only our marker and empty workspace; never recursive/user cleanup.
        let marker = id.report_dir.join(SESSION_MARKER);
        if marker.is_file() {
            fs::remove_file(&marker).map_err(|e| e.to_string())?;
        }
        if id.report_dir.is_dir()
            && let Err(e) = fs::remove_dir(&id.report_dir)
            && e.kind() != std::io::ErrorKind::DirectoryNotEmpty
        {
            return Err(format!(
                "Workspace preserved {}: {e}",
                id.report_dir.display()
            ));
        }
        if self.deferred
            && !id.report_dir.exists()
            && let Some(reservation) = id.report_dir.parent()
        {
            let marker = reservation.join(SESSION_MARKER);
            if fs::read_to_string(&marker).ok().as_deref()
                == self.session.as_ref().map(|s| s.session_id.as_str())
            {
                fs::remove_file(&marker).map_err(|e| e.to_string())?;
                fs::remove_dir(reservation).map_err(|e| e.to_string())?;
                // Remove only the now-empty shared container. Another session
                // can race with this operation; remove_dir never removes it.
                let work_root = reservation.parent().ok_or("Workspace has no parent")?;
                match fs::remove_dir(work_root) {
                    Ok(()) => {}
                    Err(e)
                        if matches!(
                            e.kind(),
                            std::io::ErrorKind::DirectoryNotEmpty | std::io::ErrorKind::NotFound
                        ) => {}
                    Err(e) => {
                        return Err(format!("ZIP verified; empty workspace cleanup failed: {e}"));
                    }
                }
            }
        }
        Ok(removed)
    }

    /// Driver Audit evidence: joins the package if it exists or is bound to
    /// a session (v1.0: an explicit run always is), otherwise waits in
    /// memory for the first module that creates the package. Returns the
    /// ZIP when updated now.
    /// v1.1 tests: evidence held back until a report exists.
    #[cfg(test)]
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    pub fn offer(&mut self, files: Vec<EvidenceFile>) -> Result<Option<PathBuf>, String> {
        let exists = self.identity.as_ref().is_some();
        match exists || self.session.is_some() {
            true => {
                let date = identity_date(crate::ui::sysinfo::local_time());
                let zip = self.contribute("", "", &date, files)?;
                Ok(Some(zip))
            }
            false => {
                self.pending.extend(files);
                Ok(None)
            }
        }
    }

    /// Rebuilds the ZIP from all persisted evidence. On any failure the
    /// previous final ZIP stays exactly as it was.
    pub fn rebuild(&mut self) -> Result<PathBuf, String> {
        self.needs_finalize = false;
        let id = self.identity.clone().ok_or("Отчёт сессии ещё не создан.")?;
        self.verify_owner(&id)?;
        // Older builds restored generated summaries as loose evidence. Keep
        // their bytes as explicitly historical evidence, never as current state.
        for name in ["State_Summary.json", "State_Summary.txt"] {
            let old = id.report_dir.join(name);
            if old.is_file() {
                let target = (1..1000)
                    .map(|n| id.report_dir.join(format!("Historical_{n:03}_{name}")))
                    .find(|p| !p.exists())
                    .ok_or("Cannot preserve historical state summary")?;
                fs::rename(&old, &target).map_err(|e| format!("Cannot preserve {name}: {e}"))?;
            }
        }
        let mut entries: Vec<EvidenceFile> = Vec::new();
        let mut names: BTreeSet<String> = BTreeSet::new();
        for path in list_files(&id.evidence_dir()) {
            let file = EvidenceFile::read(&path)?;
            // The manifest is generated, never taken from the folder.
            if matches!(
                file.name.as_str(),
                crate::manifest::MANIFEST_FILE | "State_Summary.json" | "State_Summary.txt"
            ) {
                continue;
            }
            names.insert(file.name.clone());
            entries.push(file);
        }
        if entries.is_empty() {
            return Err("Нет данных для отчёта сессии.".into());
        }
        // The template is a real file of the folder too (ZIP = folder).
        if let Some(template) = &self.template {
            if !names.contains(GRAPHIC_REPORT_FILE) {
                write_new_file(&id.report_dir.join(GRAPHIC_REPORT_FILE), template)?;
                entries.push(EvidenceFile::new(GRAPHIC_REPORT_FILE, template.clone()));
                entries.sort_by(|a, b| a.name.cmp(&b.name));
            }
        }
        if let Some((system, hardware)) = &self.states {
            let note = self.state_reasons.join("\n");
            let execution = self.execution_override.as_deref().unwrap_or_else(|| {
                crate::diag_state::execution_status(system, hardware, &self.state_reasons)
            });
            let coverage = crate::diag_state::coverage_status(
                if matches!(execution, "ERROR" | "CANCELLED") {
                    execution
                } else {
                    system
                },
                hardware,
                &self.state_reasons,
            );
            let findings = crate::diag_state::findings_status(system, hardware);
            let reasons_json = self
                .state_reasons
                .iter()
                .map(|s| crate::deep_checks::json::string(s))
                .collect::<Vec<_>>()
                .join(",");
            entries.push(EvidenceFile::new(
                "State_Summary.json",
                format!(
                    "{{\"system\":{},\"hardware\":{},\"execution_status\":\"{execution}\",\"coverage_status\":\"{coverage}\",\"findings_status\":\"{findings}\",\"producer_version\":\"{}\",\"reason\":{},\"reasons\":[{reasons_json}]}}\n",
                    crate::deep_checks::json::string(system),
                    crate::deep_checks::json::string(hardware),
                    crate::APP_VERSION,
                    crate::deep_checks::json::string(&note)
                )
                .into_bytes(),
            ));
            entries.push(EvidenceFile::new(
                "State_Summary.txt",
                format!("System: {system}\r\nHardware: {hardware}\r\nExecution: {execution}\r\nCoverage: {coverage}\r\nFindings: {findings}\r\nWinStateDiag: {}\r\n{note}\r\n", crate::APP_VERSION).into_bytes(),
            ));
        }
        let (windows_product, windows_build) = crate::ui::sysinfo::windows_edition_and_full_build();
        for file in &mut entries {
            file.name = archive_name(&file.name);
        }
        // Explicit cumulative-history snapshots, never enumerate other sessions.
        // Original persistent history remains untouched and outside the package.
        crate::ssd_history::merge_into(
            &crate::ssd_history::canonical_history_path(&self.reports_root),
            &crate::ssd_history::load_all_history(&self.reports_root),
        )
        .map_err(|e| format!("History preservation failed: {e}"))?;
        let local_history = id.report_dir.join(SSD_HISTORY_FILE);
        if local_history.is_file() {
            let text = fs::read_to_string(&local_history).map_err(|e| e.to_string())?;
            crate::ssd_history::merge_into(
                &crate::ssd_history::canonical_history_path(&self.reports_root),
                &crate::ssd_history::parse_history(&text),
            )
            .map_err(|e| format!("History preservation failed: {e}"))?;
        }
        for (source, name) in [(
            crate::ssd_history::canonical_history_path(&self.reports_root),
            "History/ssd_benchmark_history.log",
        )] {
            if source.is_file() {
                let bytes = fs::read(&source)
                    .map_err(|e| format!("History snapshot {}: {e}", source.display()))?;
                if !entries
                    .iter()
                    .any(|f| f.name == SSD_HISTORY_FILE && f.bytes == bytes)
                {
                    entries.push(EvidenceFile::new(name, bytes));
                }
            }
        }
        let history_source = storage_history_source(&self.reports_root);
        let (history_status, history_reason) = match fs::read(&history_source) {
            Ok(bytes) => {
                entries.push(EvidenceFile::new("WinStateDiagStorageHistory.json", bytes));
                ("INCLUDED", "Cumulative storage assessment history snapshot; original preserved".to_string())
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => ("NOT_PRESENT", "Persistent history file not present. History is created by completed per-disk storage assessment, not hardware inventory alone.".to_string()),
            Err(e) => ("ERROR", format!("History snapshot could not be read: {e}; original preserved")),
        };
        if self.deferred {
            entries.push(EvidenceFile::new("StorageHistory_Export.json", format!("{{\"status\":{},\"reason\":{},\"source\":{},\"archive_entry\":\"WinStateDiagStorageHistory.json\"}}", crate::deep_checks::json::string(history_status),crate::deep_checks::json::string(&history_reason),crate::deep_checks::json::string(crate::storage_history::FILE_NAME)).into_bytes()));
        }
        let ctx = crate::manifest::ManifestContext {
            producer_version: crate::manifest::PRODUCER_VERSION.to_string(),
            system_state: self.states.as_ref().map(|s| s.0.clone()),
            hardware_state: self.states.as_ref().map(|s| s.1.clone()),
            session: self
                .session
                .as_ref()
                .map(|s| (s.session_id.clone(), s.client.clone())),
            package: id
                .zip_path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default(),
            computer_name: if self.computer.is_empty() {
                computer_name()
            } else {
                self.computer.clone()
            },
            created_at: crate::ui::sysinfo::local_time(),
            windows_product,
            windows_build,
        };
        entries.push(EvidenceFile::new(
            crate::manifest::MANIFEST_FILE,
            crate::manifest::build(&ctx, &entries),
        ));
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        #[cfg(test)]
        let fail = std::mem::replace(&mut self.fail_next_replace, false);
        #[cfg(not(test))]
        let fail = false;
        fs::create_dir_all(&self.reports_root).map_err(|e| {
            format!(
                "Cannot create Reports {}: {e}; evidence: {}",
                self.reports_root.display(),
                id.report_dir.display()
            )
        })?;
        if self.deferred {
            let candidate = id.report_dir.join(".session-ready.zip");
            write_zip_staged(
                &candidate,
                &id.report_dir,
                &entries,
                fail,
                candidate.exists(),
            )?;
        } else {
            write_zip_staged(&id.zip_path, &id.report_dir, &entries, fail, self.zip_ready)?;
            self.zip_ready = true;
        }
        self.needs_finalize = true;
        Ok(id.zip_path)
    }
}

/// Writes each file into `dir` (flat). An identical existing file is kept
/// as is; a different file with the same name never overwrites it: the
/// whole group sharing that stem gets the first free `_NN` suffix.
/// Returns `(original name, stored name)` for every file, in input order
/// (a collision gives the stored file its first free `_NN` name).
fn store_evidence(dir: &Path, files: &[EvidenceFile]) -> Result<Vec<(String, String)>, String> {
    let mut stems: Vec<String> = Vec::new();
    for f in files {
        let stem = split_name(&f.name).0.to_string();
        if !stems.contains(&stem) {
            stems.push(stem);
        }
    }
    let mut stored = Vec::new();
    for stem in stems {
        let group: Vec<&EvidenceFile> = files
            .iter()
            .filter(|f| split_name(&f.name).0 == stem)
            .collect();
        let target_name = |n: u32, f: &EvidenceFile| -> String {
            let (s, ext) = split_name(&f.name);
            if n == 1 {
                f.name.clone()
            } else {
                format!("{s}_{n:02}{ext}")
            }
        };
        let fits = |n: u32| {
            group.iter().all(|f| {
                let p = dir.join(target_name(n, f));
                match fs::read(&p) {
                    Ok(existing) => existing == f.bytes,
                    Err(_) => !p.exists(),
                }
            })
        };
        let n = (1..1000)
            .find(|&n| fits(n))
            .ok_or_else(|| format!("Не удалось подобрать имя для {stem}"))?;
        for f in group {
            let name = target_name(n, f);
            let path = dir.join(&name);
            if !path.is_file() {
                write_new_file(&path, &f.bytes)?;
            }
            stored.push((f.name.clone(), name));
        }
    }
    // Input order (the grouping above is per stem).
    let mut ordered = Vec::with_capacity(stored.len());
    for f in files {
        if let Some(i) = stored.iter().position(|(o, _)| *o == f.name) {
            ordered.push(stored.remove(i));
        }
    }
    ordered.extend(stored);
    Ok(ordered)
}

/// Append-only logs: written meanwhile by other code (start-up log, SSD
/// history), so their packaged content is merged, never replaced.
fn is_append_log(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n == SSD_HISTORY_FILE || n.starts_with(STARTUP_LOG_FILE)
}

/// Puts back into the report folder every ZIP entry that is not there as a
/// loose file (after `finalize` removed them), so the next rebuild starts
/// from the complete evidence. Never overwrites a different loose file:
/// append-only logs are merged (packaged lines first), anything else gets
/// the first free `_NN` name. No ZIP yet = nothing to do.
fn restore_loose(id: &PackageIdentity) -> Result<(), String> {
    fs::create_dir_all(&id.report_dir)
        .map_err(|e| format!("Cannot restore evidence workspace: {e}"))?;
    if !id.zip_path.is_file() {
        return Ok(());
    }
    let packaged = read_zip(&id.zip_path).map_err(|e| {
        format!(
            "Итоговый ZIP не читается, он оставлен без изменений: {e}\n— путь: {}",
            id.zip_path.display()
        )
    })?;
    for mut e in packaged {
        e.name = match e.name.as_str() {
            _ if servicing_parts(&e.name.replace('/', "__")).is_some() => e.name.replace('/', "__"),
            "Logs/Servicing/dism.log" => "Servicing_dism.log".into(),
            "Logs/Servicing/CBS.log" => "Servicing_CBS.log".into(),
            "Logs/Servicing/Result.json" => "Servicing_Result.json".into(),
            "Logs/startup_graphics.log" => STARTUP_LOG_FILE.into(),
            "Logs/Session_Journal.txt" => "Session_Journal.txt".into(),
            "History/ssd_benchmark_history.log"
            | "WinStateDiagStorageHistory.json"
            | "StorageHistory_Export.json" => continue,
            _ if e.name.contains('/') => {
                return Err("Unexpected nested archive evidence; preserved".into());
            }
            _ => e.name,
        };
        if matches!(
            e.name.as_str(),
            crate::manifest::MANIFEST_FILE | "State_Summary.json" | "State_Summary.txt"
        ) {
            continue;
        }
        let path = id.report_dir.join(&e.name);
        match fs::read(&path) {
            Ok(existing) if existing == e.bytes => {}
            Ok(existing) if is_append_log(&e.name) => {
                if !existing.starts_with(&e.bytes) {
                    let mut merged = e.bytes.clone();
                    if !merged.ends_with(b"\n") && !merged.is_empty() {
                        merged.extend_from_slice(b"\r\n");
                    }
                    merged.extend_from_slice(&existing);
                    write_new_file(&path, &merged)?;
                }
            }
            Ok(_) => {
                let (stem, ext) = split_name(&e.name);
                let free = (2..1000)
                    .map(|n| id.report_dir.join(format!("{stem}_{n:02}{ext}")))
                    .find(|p| match fs::read(p) {
                        Ok(b) => b == e.bytes,
                        Err(_) => !p.exists(),
                    })
                    .ok_or_else(|| format!("Не удалось подобрать имя для {}", e.name))?;
                if !free.is_file() {
                    write_new_file(&free, &e.bytes)?;
                }
            }
            Err(_) => write_new_file(&path, &e.bytes)?,
        }
    }
    Ok(())
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let tmp = path.with_file_name(format!(
        ".{}.part",
        path.file_name().unwrap_or_default().to_string_lossy()
    ));
    fs::write(&tmp, bytes)
        .and_then(|_| fs::rename(&tmp, path))
        .map_err(|e| {
            let _ = fs::remove_file(&tmp);
            format!("Не удалось сохранить {}: {e}", path.display())
        })
}

fn split_name(name: &str) -> (&str, &str) {
    match name.rfind('.') {
        Some(i) if i > 0 => (&name[..i], &name[i..]),
        _ => (name, ""),
    }
}

/// The report folder's artifacts: regular, non-hidden files except ZIPs
/// (the package itself), sorted by name. This is exactly what the ZIP holds.
pub fn list_files(dir: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = fs::read_dir(dir)
        .map(|rd| {
            rd.flatten()
                .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
                .filter(|e| {
                    let n = e.file_name().to_string_lossy().to_lowercase();
                    !n.starts_with('.') && !n.ends_with(".zip")
                })
                .map(|e| e.path())
                .collect()
        })
        .unwrap_or_default();
    files.sort();
    files
}

// ---------------------------------------------------------------------
// Atomic ZIP update
// ---------------------------------------------------------------------

fn publish_archive(source: &Path, target: &Path, replace: bool) -> std::io::Result<()> {
    if source.parent() == target.parent() {
        return rename_archive(source, target, replace);
    }
    // AppData and the portable Reports folder may be on different volumes.
    // Copy into an exclusively-created, non-final destination, flush and verify
    // it before the same-volume atomic rename. A failure never exposes a ZIP.
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let pending = target.with_file_name(format!(".wsd-{}-{stamp}.partial", std::process::id()));
    let mut out = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&pending)?;
    let result = (|| {
        std::io::copy(&mut fs::File::open(source)?, &mut out)?;
        out.sync_all()?;
        drop(out);
        let before = read_zip(source).map_err(std::io::Error::other)?;
        let after = read_zip(&pending).map_err(std::io::Error::other)?;
        if before != after {
            return Err(std::io::Error::other("ZIP transfer verification failed"));
        }
        rename_archive(&pending, target, replace)?;
        fs::remove_file(source)
    })();
    if pending.exists() {
        let _ = fs::remove_file(&pending);
    }
    result
}

#[cfg(windows)]
fn rename_archive(source: &Path, target: &Path, replace: bool) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    // canonicalize supplies extended-length Windows paths, including Unicode.
    let source = fs::canonicalize(source)?;
    let target = fs::canonicalize(
        target
            .parent()
            .ok_or_else(|| std::io::Error::other("ZIP has no parent"))?,
    )?
    .join(
        target
            .file_name()
            .ok_or_else(|| std::io::Error::other("ZIP has no filename"))?,
    );
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn MoveFileExW(source: *const u16, target: *const u16, flags: u32) -> i32;
    }
    let source: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let target: Vec<u16> = target.as_os_str().encode_wide().chain(Some(0)).collect();
    // Same-volume atomic rename; no COPY_ALLOWED. First publication cannot
    // replace any existing archive, even if it appeared after reservation.
    let flags = 8 | u32::from(replace); // WRITE_THROUGH, optional REPLACE_EXISTING
    let ok = unsafe { MoveFileExW(source.as_ptr(), target.as_ptr(), flags) };
    if ok == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
fn rename_archive(source: &Path, target: &Path, replace: bool) -> std::io::Result<()> {
    if replace {
        fs::rename(source, target)
    } else {
        fs::hard_link(source, target)?;
        fs::remove_file(source)
    }
}

#[cfg(test)]
fn write_zip_atomically(
    final_zip: &Path,
    entries: &[EvidenceFile],
    fail: bool,
) -> Result<(), String> {
    let dir = final_zip.parent().ok_or("Некорректный путь ZIP.")?;
    write_zip_staged(final_zip, dir, entries, fail, final_zip.exists())
}

fn write_zip_staged(
    final_zip: &Path,
    dir: &Path,
    entries: &[EvidenceFile],
    fail: bool,
    replace: bool,
) -> Result<(), String> {
    let candidate = dir.join(format!(
        ".{}.candidate",
        final_zip.file_name().unwrap_or_default().to_string_lossy()
    ));
    let bytes = build_zip(entries, crate::ui::sysinfo::local_time())?;
    let result = (|| {
        (|| -> std::io::Result<()> {
            use std::io::Write;
            let mut f = fs::File::create(&candidate)?;
            f.write_all(&bytes)?;
            f.sync_all()
        })()
        .map_err(|e| {
            format!(
                "Не удалось записать ZIP: {e}\n— путь: {}",
                candidate.display()
            )
        })?;
        validate_zip(&candidate, entries)?;
        if fail {
            return Err("имитация сбоя замены ZIP (тест)".to_string());
        }
        // Same folder, same volume: the rename replaces the previous ZIP
        // in one step (MoveFileEx REPLACE_EXISTING on Windows).
        publish_archive(&candidate, final_zip, replace).map_err(|e| {
            format!(
                "Не удалось заменить ZIP (файл открыт другой программой?): {e}\n— путь: {}",
                final_zip.display()
            )
        })
    })();
    if let Err(err) = result {
        let _ = fs::remove_file(&candidate);
        return Err(format!(
            "ZIP отчёта не обновлён; предыдущая версия сохранена. {err}"
        ));
    }
    let len = fs::metadata(final_zip).map(|m| m.len()).unwrap_or(0);
    if len != bytes.len() as u64 {
        return Err(format!(
            "ZIP после замены имеет неверный размер ({len}): {}",
            final_zip.display()
        ));
    }
    Ok(())
}

static CRC_TABLE: std::sync::OnceLock<[u32; 256]> = std::sync::OnceLock::new();

pub fn crc32(data: &[u8]) -> u32 {
    let table = CRC_TABLE.get_or_init(|| {
        let mut t = [0u32; 256];
        for (i, slot) in t.iter_mut().enumerate() {
            let mut c = i as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 {
                    0xEDB8_8320 ^ (c >> 1)
                } else {
                    c >> 1
                };
            }
            *slot = c;
        }
        t
    });
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc = table[((crc ^ b as u32) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc ^ 0xFFFF_FFFF
}

fn dos_time(t: crate::ui::sysinfo::LocalTime) -> (u16, u16) {
    let year = t.year.clamp(1980, 2107);
    let time = (t.hour << 11) | (t.minute << 5) | (t.second / 2);
    let date = ((year - 1980) << 9) | (t.month.clamp(1, 12) << 5) | t.day.clamp(1, 31);
    (time, date)
}

/// Text evidence uses raw DEFLATE (ZIP method 8); binary evidence uses STORE.
pub fn build_zip(
    entries: &[EvidenceFile],
    now: crate::ui::sysinfo::LocalTime,
) -> Result<Vec<u8>, String> {
    const FLAG_UTF8: u16 = 0x0800;
    if entries.len() >= u16::MAX as usize {
        return Err("Слишком много файлов для ZIP.".into());
    }
    let (time, date) = dos_time(now);
    let mut out: Vec<u8> = Vec::new();
    let mut central: Vec<u8> = Vec::new();
    let put16 = |v: &mut Vec<u8>, x: u16| v.extend_from_slice(&x.to_le_bytes());
    let put32 = |v: &mut Vec<u8>, x: u32| v.extend_from_slice(&x.to_le_bytes());
    for e in entries {
        if !safe_archive_name(&e.name) {
            return Err(format!("Недопустимое имя в ZIP: {}", e.name));
        }
        let size = u32::try_from(e.bytes.len()).map_err(|_| "Файл слишком большой для ZIP.")?;
        let offset = u32::try_from(out.len()).map_err(|_| "ZIP слишком большой.")?;
        let crc = crc32(&e.bytes);
        let text = Path::new(&e.name)
            .extension()
            .and_then(|s| s.to_str())
            .is_some_and(|s| {
                matches!(
                    s.to_ascii_lowercase().as_str(),
                    "txt" | "json" | "html" | "htm" | "log" | "csv" | "xml" | "md"
                )
            });
        let payload = if text {
            use std::io::Write;
            let mut encoder =
                flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::fast());
            encoder.write_all(&e.bytes).map_err(|e| e.to_string())?;
            encoder.finish().map_err(|e| e.to_string())?
        } else {
            e.bytes.clone()
        };
        let compressed_size = u32::try_from(payload.len()).map_err(|_| "ZIP entry too large")?;
        let method = if text { 8 } else { 0 };
        let name = e.name.as_bytes();
        // Local file header.
        put32(&mut out, 0x0403_4b50);
        put16(&mut out, 20);
        put16(&mut out, FLAG_UTF8);
        put16(&mut out, method);
        put16(&mut out, time);
        put16(&mut out, date);
        put32(&mut out, crc);
        put32(&mut out, compressed_size);
        put32(&mut out, size);
        put16(&mut out, name.len() as u16);
        put16(&mut out, 0);
        out.extend_from_slice(name);
        out.extend_from_slice(&payload);
        // Central directory record.
        put32(&mut central, 0x0201_4b50);
        put16(&mut central, 20);
        put16(&mut central, 20);
        put16(&mut central, FLAG_UTF8);
        put16(&mut central, method);
        put16(&mut central, time);
        put16(&mut central, date);
        put32(&mut central, crc);
        put32(&mut central, compressed_size);
        put32(&mut central, size);
        put16(&mut central, name.len() as u16);
        put16(&mut central, 0);
        put16(&mut central, 0);
        put16(&mut central, 0);
        put16(&mut central, 0);
        put32(&mut central, 0x20);
        put32(&mut central, offset);
        central.extend_from_slice(name);
    }
    let cd_offset = u32::try_from(out.len()).map_err(|_| "ZIP слишком большой.")?;
    let cd_size = central.len() as u32;
    out.extend_from_slice(&central);
    put32(&mut out, 0x0605_4b50);
    put16(&mut out, 0);
    put16(&mut out, 0);
    put16(&mut out, entries.len() as u16);
    put16(&mut out, entries.len() as u16);
    put32(&mut out, cd_size);
    put32(&mut out, cd_offset);
    put16(&mut out, 0);
    Ok(out)
}

/// Reads a stored ZIP back (every entry's CRC-32 is checked).
pub fn read_zip(path: &Path) -> Result<Vec<EvidenceFile>, String> {
    let data = fs::read(path).map_err(|e| format!("ZIP не читается: {e}"))?;
    parse_zip(&data)
}

pub fn parse_zip(data: &[u8]) -> Result<Vec<EvidenceFile>, String> {
    let bad = |what: &str| format!("ZIP повреждён: {what}");
    let u16_at = |i: usize| -> Result<u16, String> {
        data.get(i..i + 2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .ok_or_else(|| bad("выход за границы"))
    };
    let u32_at = |i: usize| -> Result<u32, String> {
        data.get(i..i + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
            .ok_or_else(|| bad("выход за границы"))
    };
    if data.len() < 22 {
        return Err(bad("слишком короткий"));
    }
    let eocd = (0..=data.len() - 22)
        .rev()
        .take(65_557)
        .find(|&i| u32_at(i).map(|v| v == 0x0605_4b50).unwrap_or(false))
        .ok_or_else(|| bad("нет конца каталога"))?;
    let count = u16_at(eocd + 10)? as usize;
    let mut p = u32_at(eocd + 16)? as usize;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        if u32_at(p)? != 0x0201_4b50 {
            return Err(bad("запись каталога"));
        }
        let method = u16_at(p + 10)?;
        let crc = u32_at(p + 16)?;
        let csize = u32_at(p + 20)? as usize;
        let usize_ = u32_at(p + 24)? as usize;
        let nlen = u16_at(p + 28)? as usize;
        let elen = u16_at(p + 30)? as usize;
        let clen = u16_at(p + 32)? as usize;
        let local = u32_at(p + 42)? as usize;
        let name = data.get(p + 46..p + 46 + nlen).ok_or_else(|| bad("имя"))?;
        let name = String::from_utf8(name.to_vec()).map_err(|_| bad("имя не UTF-8"))?;
        if !safe_archive_name(&name) || out.iter().any(|e: &EvidenceFile| e.name == name) {
            return Err(bad("unsafe or duplicate entry name"));
        }
        if !matches!(method, 0 | 8) || (method == 0 && csize != usize_) {
            return Err(bad("неподдерживаемое сжатие"));
        }
        if u32_at(local)? != 0x0403_4b50 {
            return Err(bad("локальный заголовок"));
        }
        let lnlen = u16_at(local + 26)? as usize;
        let lelen = u16_at(local + 28)? as usize;
        if data.get(local + 30..local + 30 + lnlen) != Some(name.as_bytes()) {
            return Err(bad("имя в локальном заголовке"));
        }
        let start = local + 30 + lnlen + lelen;
        let payload = data
            .get(start..start + csize)
            .ok_or_else(|| bad("данные"))?;
        let bytes = if method == 8 {
            use std::io::Read;
            let decoder = flate2::read::DeflateDecoder::new(payload);
            let mut bytes = Vec::new();
            decoder
                .take(usize_ as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| bad("DEFLATE"))?;
            bytes
        } else {
            payload.to_vec()
        };
        if bytes.len() != usize_ {
            return Err(bad("uncompressed size"));
        }
        if crc32(&bytes) != crc {
            return Err(bad(&format!("CRC {name}")));
        }
        out.push(EvidenceFile { name, bytes });
        p += 46 + nlen + elen + clen;
    }
    Ok(out)
}

/// The candidate must contain exactly `expected`, byte for byte.
pub fn validate_zip(path: &Path, expected: &[EvidenceFile]) -> Result<(), String> {
    let got = read_zip(path)?;
    if got.len() != expected.len() {
        return Err(format!(
            "ZIP содержит {} файлов вместо {}",
            got.len(),
            expected.len()
        ));
    }
    for (g, e) in got.iter().zip(expected) {
        if g != e {
            return Err(format!("ZIP: файл {} не совпадает с источником", e.name));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------
// Date helpers (report identity + evidence names)
// ---------------------------------------------------------------------

/// `DD-MM-YY` of the local date (report identity).
pub fn identity_date(t: crate::ui::sysinfo::LocalTime) -> String {
    format!("{:02}-{:02}-{:02}", t.day, t.month, t.year % 100)
}

/// `dd.MM.yy_HH-mm` (same style as the PowerShell evidence names).
pub fn evidence_stamp(t: crate::ui::sysinfo::LocalTime) -> String {
    format!(
        "{:02}.{:02}.{:02}_{:02}-{:02}",
        t.day,
        t.month,
        t.year % 100,
        t.hour,
        t.minute
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::sysinfo::LocalTime;

    fn now() -> LocalTime {
        LocalTime {
            year: 2026,
            month: 9,
            day: 24,
            hour: 10,
            minute: 30,
            second: 12,
        }
    }

    #[test]
    fn rc8_field_distinct_snapshots_and_history_scopes_survive_one_zip() {
        let Ok(root) = std::env::var("WSD_RC8_FIELD_ROOT") else {
            return;
        };
        let root = PathBuf::from(root);
        let exe = scratch("rc8-field-zip");
        let mut p = SessionPackage::for_exe_dir(&exe);
        p.bind_session(SessionIdentity::new("rc8-field-session", "CLIENT", "PC"));
        let history = crate::ssd_history::canonical_history_path(&exe.join("Reports"));
        fs::create_dir_all(history.parent().unwrap()).unwrap();
        let cumulative = fs::read(root.join("History__ssd_benchmark_history.log")).unwrap();
        fs::write(&history, &cumulative).unwrap();
        let files: Vec<_> = fs::read_dir(&root)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| {
                let n = p.file_name().unwrap().to_string_lossy();
                n.starts_with("Hardware_")
                    || n.starts_with("NVMe_")
                    || n.starts_with("SSD_Benchmark_")
                    || n == SSD_HISTORY_FILE
            })
            .map(|p| EvidenceFile::read(&p).unwrap())
            .collect();
        assert_eq!(
            files.iter().filter(|f| f.name.starts_with("NVMe_")).count(),
            4
        );
        let zip = p.contribute("", "", "23-10-26", files.clone()).unwrap();
        assert!(!zip.exists(), "no intermediate public archive");
        // Same bytes/name contributed twice are stored only once.
        p.contribute("", "", "", files.clone()).unwrap();
        p.finalize().unwrap();
        let entries = read_zip(&zip).unwrap();
        for f in &files {
            assert_eq!(entries.iter().filter(|e| *e == f).count(), 1, "{}", f.name);
        }
        assert!(
            entries
                .iter()
                .any(|f| f.name == "History/ssd_benchmark_history.log" && f.bytes == cumulative)
        );
        assert_eq!(fs::read_dir(exe.join("Reports")).unwrap().count(), 1);
        assert_eq!(fs::read(&history).unwrap(), cumulative);
        let _ = fs::remove_dir_all(exe);
    }

    #[test]
    fn rc7_identical_history_is_once_and_unique_dumps_are_preserved() {
        let exe = scratch("rc7-history");
        let mut p = SessionPackage::for_exe_dir(&exe);
        p.bind_session(SessionIdentity::new("rc7-history-session", "CLIENT", "PC"));
        let root = exe.join("Reports");
        let history = crate::ssd_history::canonical_history_path(&root);
        fs::create_dir_all(history.parent().unwrap()).unwrap();
        fs::write(&history, b"history").unwrap();
        let zip = p
            .contribute(
                "",
                "",
                "20-10-26",
                vec![
                    EvidenceFile::new(SSD_HISTORY_FILE, b"history".to_vec()),
                    EvidenceFile::new("WATCHDOG_one.dmp", b"unique dump one".to_vec()),
                    EvidenceFile::new("WATCHDOG_two.dmp", b"unique dump two".to_vec()),
                    EvidenceFile::new("EXPC_current.txt", b"diagnostic".to_vec()),
                ],
            )
            .unwrap();
        p.finalize().unwrap();
        let entries = read_zip(&zip).unwrap();
        assert_eq!(
            entries
                .iter()
                .filter(|e| e.name.ends_with(SSD_HISTORY_FILE))
                .count(),
            1
        );
        assert!(
            entries
                .iter()
                .any(|e| e.name == "WATCHDOG_one.dmp" && e.bytes == b"unique dump one")
        );
        assert!(
            entries
                .iter()
                .any(|e| e.name == "WATCHDOG_two.dmp" && e.bytes == b"unique dump two")
        );
        assert_eq!(fs::read(&history).unwrap(), b"history");
        let _ = fs::remove_dir_all(exe);
    }

    #[test]
    fn rc6_full_session_publishes_one_zip_after_all_contributors() {
        let exe = scratch("rc6-full-session");
        let mut package = SessionPackage::for_exe_dir(&exe);
        package.bind_session(SessionIdentity::new("rc6-full-session", "Client", "PC"));
        let mut result = None;
        for name in [
            "EXPC_current.txt",
            "Hardware_current.json",
            "DriverAudit_current.json",
            "CryptoPro_current.json",
        ] {
            let path = package
                .contribute(
                    "",
                    "",
                    "21-10-26",
                    vec![EvidenceFile::new(name, b"{}".to_vec())],
                )
                .unwrap();
            if let Some(previous) = &result {
                assert_eq!(previous, &path);
            }
            result = Some(path);
            assert_eq!(
                fs::read_dir(exe.join("Reports")).unwrap().count(),
                0,
                "no intermediate archives in Reports"
            );
        }
        let workspace = package.identity().unwrap().report_dir.clone();
        package.finalize().unwrap();
        let zip = result.unwrap();
        assert_eq!(package.final_zip(), Some(zip.clone()));
        assert_eq!(fs::read_dir(exe.join("Reports")).unwrap().count(), 1);
        let entries = read_zip(&zip).unwrap();
        for name in [
            "EXPC_current.txt",
            "Hardware_current.json",
            "DriverAudit_current.json",
            "CryptoPro_current.json",
            "manifest.json",
        ] {
            assert!(entries.iter().any(|e| e.name == name));
        }
        assert!(!workspace.exists());
        assert!(!entries.iter().any(|e| e.name.ends_with(".zip")));
        package.finalize().unwrap();
        assert_eq!(fs::read_dir(exe.join("Reports")).unwrap().count(), 1);
        fs::remove_dir_all(exe).unwrap();
    }

    #[test]
    #[ignore = "requires the private, read-only MSI RC1 ZIP via WSD_MSI_RC1_FIXTURE"]
    fn rc2_private_msi_fixture() {
        let source = PathBuf::from(std::env::var_os("WSD_MSI_RC1_FIXTURE").expect("fixture path"));
        let original = fs::read(&source).unwrap();
        let input = read_zip(&source).unwrap();
        let evidence: Vec<_> = input
            .iter()
            .filter(|e| e.name.starts_with("EXPC_") && e.name.ends_with(".json"))
            .cloned()
            .collect();
        assert_eq!(evidence.len(), 1);
        let exe = scratch("rc2-private-msi");
        let mut package = SessionPackage::for_exe_dir(&exe);
        package.bind_session(SessionIdentity::new("rc2-fixture", "ExampleClient", "MSI"));
        let zip = package
            .contribute("", "", "20-10-26", evidence.clone())
            .unwrap();
        package.finalize().unwrap();
        assert_eq!(zip.file_name().unwrap(), "ExampleClient-MSI-20-10-26.zip");
        let output = read_zip(&zip).unwrap();
        assert!(
            output.contains(&evidence[0]),
            "raw evidence must be unchanged"
        );
        let manifest = output.iter().find(|e| e.name == "manifest.json").unwrap();
        let value =
            crate::deep_checks::json::parse(std::str::from_utf8(&manifest.bytes).unwrap()).unwrap();
        let modules = value.get("modules").unwrap().as_arr().unwrap();
        let expc = modules
            .iter()
            .find(|m| m.get("name").and_then(|v| v.as_str()) == Some("expc_diagnostic"))
            .unwrap();
        let checks = expc.get("checks").unwrap().as_arr().unwrap();
        let dism = checks
            .iter()
            .find(|c| c.get("check").and_then(|v| v.as_str()) == Some("DISM"))
            .unwrap();
        assert_eq!(dism.get("result_status").unwrap().as_str(), Some("OK"));
        assert_eq!(
            value
                .get("storage_history")
                .unwrap()
                .get("status")
                .unwrap()
                .as_str(),
            Some("NOT_PRESENT")
        );
        assert_eq!(fs::read(&source).unwrap(), original, "source ZIP changed");
        fs::remove_dir_all(exe).unwrap();
    }

    #[test]
    fn rc2_session_client_and_owned_workspace_cleanup() {
        for (client, computer) in [("ExampleClient", "MSI"), ("ExampleOrg", "SERVER")] {
            let exe = scratch(&format!("rc2-cleanup-{computer}"));
            let root = exe.join("Reports");
            fs::create_dir_all(&root).unwrap();
            fs::write(root.join(crate::storage_history::FILE_NAME), b"[]").unwrap();
            fs::write(root.join("old.zip"), b"old-user-archive").unwrap();
            let mut p = SessionPackage::for_exe_dir(&exe);
            p.bind_session(SessionIdentity::new("owned", client, computer));
            p.archive_time = "08-30-59".into();
            let zip = p
                .contribute("WRONG-CLIENT", "WRONG-PC", "20-10-26", hw())
                .unwrap();
            assert_eq!(
                zip.file_name().unwrap().to_string_lossy(),
                format!("{client}-{computer}-20.10.26-08.30.zip")
            );
            p.finalize().unwrap();
            assert!(!persistent_dir(&exe.join("Reports")).join("Work").exists());
            assert!(
                read_zip(&zip)
                    .unwrap()
                    .iter()
                    .any(|e| e.name == "WinStateDiagStorageHistory.json" && e.bytes == b"[]")
            );
            assert_eq!(
                fs::read(root.join(crate::storage_history::FILE_NAME)).unwrap(),
                b"[]"
            );
            assert_eq!(fs::read(root.join("old.zip")).unwrap(), b"old-user-archive");

            let foreign = persistent_dir(&exe.join("Reports")).join("Work/foreign-session");
            fs::create_dir_all(&foreign).unwrap();
            fs::write(foreign.join("evidence.txt"), b"foreign").unwrap();
            let mut next = p.successor(SessionIdentity::new("owned-next", client, computer));
            let next_zip = next.contribute("", "", "20-10-26", hw()).unwrap();
            let workspace = next.identity().unwrap().report_dir.clone();
            next.finalize().unwrap();
            assert!(!workspace.exists());
            assert!(next_zip.is_file() && zip.is_file());
            assert_eq!(fs::read(foreign.join("evidence.txt")).unwrap(), b"foreign");
            fs::remove_dir_all(exe).unwrap();
        }
    }

    #[test]
    fn rc2_unexpected_workspace_data_is_preserved() {
        let exe = scratch("rc2-unknown-workspace");
        let mut p = SessionPackage::for_exe_dir(&exe);
        p.bind_session(SessionIdentity::new("owned", "ExampleOrg", "SERVER"));
        let zip = p.contribute("", "", "20-10-26", hw()).unwrap();
        let workspace = p.identity().unwrap().report_dir.clone();
        fs::write(workspace.join(".unexpected"), b"recover-me").unwrap();
        assert!(p.finalize().is_err());
        assert!(!zip.exists());
        assert_eq!(
            fs::read(workspace.join(".unexpected")).unwrap(),
            b"recover-me"
        );
        assert!(workspace.join(".session-ready.zip").is_file());
        assert!(!list_files(&workspace).is_empty());
        fs::remove_dir_all(exe).unwrap();
    }

    #[test]
    fn rc2_client_filename_and_history_absence_are_explicit() {
        let exe = scratch("rc2-history");
        let mut p = SessionPackage::for_exe_dir(&exe);
        p.bind_session(SessionIdentity::new("rc2", "ExampleClient", "MSI"));
        let zip = p
            .contribute("ignored", "ignored", "20-10-26", hw())
            .unwrap();
        assert!(
            zip.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("ExampleClient-MSI-20.10.26-")
        );
        p.finalize().unwrap();
        let entries = read_zip(&zip).unwrap();
        assert!(
            !entries
                .iter()
                .any(|e| e.name == "WinStateDiagStorageHistory.json")
        );
        let manifest = entries.iter().find(|e| e.name == "manifest.json").unwrap();
        let parsed =
            crate::deep_checks::json::parse(std::str::from_utf8(&manifest.bytes).unwrap()).unwrap();
        assert_eq!(
            parsed
                .get("storage_history")
                .unwrap()
                .get("status")
                .unwrap()
                .as_str(),
            Some("NOT_PRESENT")
        );
        let mut second = p.successor(SessionIdentity::new("rc2-next", "ExampleClient", "MSI"));
        let next = second.contribute("", "", "20-10-26", hw()).unwrap();
        assert_ne!(next, zip);
        second.finalize().unwrap();
        assert_eq!(read_zip(&zip).unwrap(), entries);
        fs::remove_dir_all(exe).unwrap();
    }

    #[test]
    fn rc4_reports_only_zip_history_persists_and_snapshot_is_not_metadata() {
        let exe = scratch("rc4-flat");
        let reports = exe.join("Reports");
        fs::create_dir_all(persistent_dir(&reports)).unwrap();
        fs::write(storage_history_path(&reports), b"[]").unwrap();
        for seq in 0..2 {
            let mut p = SessionPackage::for_exe_dir(&exe);
            p.bind_session(SessionIdentity::new(
                &format!("s{seq}"),
                "ExampleOrg",
                "SERVER",
            ));
            p.archive_time = "08-36-00".into();
            let zip = p.contribute("", "", "20-10-26", hw()).unwrap();
            p.finalize().unwrap();
            let files = read_zip(&zip).unwrap();
            let history = files
                .iter()
                .find(|e| e.name == "WinStateDiagStorageHistory.json")
                .unwrap();
            let status = files
                .iter()
                .find(|e| e.name == "StorageHistory_Export.json")
                .unwrap();
            assert_eq!(history.bytes, b"[]");
            assert_ne!(status.bytes, history.bytes);
            assert!(String::from_utf8_lossy(&status.bytes).contains("INCLUDED"));
            assert!(!persistent_dir(&exe.join("Reports")).join("Work").exists());
            assert_eq!(fs::read(storage_history_path(&reports)).unwrap(), b"[]");
        }
        let files: Vec<_> = fs::read_dir(&reports).unwrap().flatten().collect();
        assert_eq!(files.len(), 2);
        assert!(
            files
                .iter()
                .all(|e| e.path().extension().is_some_and(|ext| ext == "zip"))
        );
        assert!(
            reports
                .join("ExampleOrg-SERVER-20.10.26-08.36.zip")
                .exists()
        );
        assert!(
            reports
                .join("ExampleOrg-SERVER-20.10.26-08.36 (2).zip")
                .exists()
        );
        fs::remove_dir_all(exe).unwrap();
    }

    #[test]
    fn servicing_full_names_survive_finalize_restore_and_repeated_runs() {
        let exe = scratch("servicing-full");
        let mut package = SessionPackage::for_exe_dir(&exe);
        package.bind_session(SessionIdentity::new("session", "CLIENT", "PC"));
        let mut archive = PathBuf::new();
        for id in ["a".repeat(32), "b".repeat(32)] {
            let mut files = vec![EvidenceFile::new(
                format!("WindowsServicingLogs__{id}__Result.json"),
                br#"{"status":"PARTIAL","snapshot_atomic":false}"#.to_vec(),
            )];
            for (area, name) in [
                ("CBS", "CBS.log"),
                ("CBS", "CbsPersist_recent.cab"),
                ("DISM", "dism.log"),
            ] {
                files.push(EvidenceFile::new(
                    format!("WindowsServicingLogs__{id}__{area}__{name}"),
                    b"full evidence".to_vec(),
                ));
            }
            archive = package.contribute("", "", "20-10-26", files).unwrap();
            package.finalize().unwrap();
        }
        let entries = read_zip(&archive).unwrap();
        for id in ["a".repeat(32), "b".repeat(32)] {
            for name in [
                "Result.json",
                "CBS/CBS.log",
                "CBS/CbsPersist_recent.cab",
                "DISM/dism.log",
            ] {
                assert!(
                    entries
                        .iter()
                        .any(|e| e.name == format!("WindowsServicingLogs/{id}/{name}"))
                );
            }
        }
        let manifest = entries.iter().find(|e| e.name == "manifest.json").unwrap();
        let value =
            crate::deep_checks::json::parse(std::str::from_utf8(&manifest.bytes).unwrap()).unwrap();
        let collections = value
            .get("windows_servicing_logs")
            .unwrap()
            .as_arr()
            .unwrap();
        assert_eq!(collections.len(), 2);
        assert!(
            collections
                .iter()
                .all(|c| c.get("status").and_then(|v| v.as_str()) == Some("PARTIAL"))
        );
        assert!(!package.identity().unwrap().report_dir.exists());
        fs::remove_dir_all(exe).unwrap();
    }

    #[test]
    fn stable_export_defers_publication_and_checks_nested_servicing_and_history() {
        let exe = scratch("stable-export");
        let root = exe.join("Reports");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(
            crate::ssd_history::canonical_history_path(&root)
                .parent()
                .unwrap(),
        )
        .unwrap();
        fs::write(root.join(crate::storage_history::FILE_NAME), b"[]").unwrap();
        fs::write(
            crate::ssd_history::canonical_history_path(&root),
            b"history",
        )
        .unwrap();
        fs::write(root.join("foreign.txt"), b"foreign").unwrap();
        let mut p = SessionPackage::for_exe_dir(&exe);
        p.bind_session(SessionIdentity::new(
            "current-session",
            "PRIVATE_CLIENT",
            "TEST-PC",
        ));
        let zip = p
            .contribute(
                "",
                "",
                "20-10-26",
                vec![
                    EvidenceFile::new("EXPC_current.txt", b"main".to_vec()),
                    EvidenceFile::new("Servicing_dism.log", b"dism".to_vec()),
                    EvidenceFile::new("Servicing_CBS.log", b"cbs".to_vec()),
                    EvidenceFile::new("Servicing_Result.json", b"{}".to_vec()),
                ],
            )
            .unwrap();
        assert!(!zip.exists());
        assert!(p.final_zip().is_none());
        assert!(p.pending_publication(&zip));
        assert!(
            p.identity()
                .unwrap()
                .report_dir
                .ends_with("current-session")
        );
        assert!(
            zip.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("PRIVATE_CLIENT-TEST-PC-20.10.26-")
        );
        p.finalize().unwrap();
        let entries = read_zip(&zip).unwrap();
        for name in [
            "EXPC_current.txt",
            "Logs/Servicing/dism.log",
            "Logs/Servicing/CBS.log",
            "Logs/Servicing/Result.json",
            "History/ssd_benchmark_history.log",
            "WinStateDiagStorageHistory.json",
            "manifest.json",
        ] {
            assert!(entries.iter().any(|e| e.name == name), "{name}");
        }
        assert!(!entries.iter().any(|e| e.name == "foreign.txt"));
        if let Some(out) = std::env::var_os("WSD_EXPORT_FIXTURE_DIR") {
            let out = PathBuf::from(out);
            fs::create_dir_all(&out).unwrap();
            fs::copy(&zip, out.join("servicing-corruption-fixture.zip")).unwrap();
        }
        assert_eq!(fs::read(root.join("foreign.txt")).unwrap(), b"foreign");
        for bad in ["../x", "Logs/../../x", "C:/x", "Logs//x", "Logs/./x"] {
            assert!(build_zip(&[EvidenceFile::new(bad, vec![])], now()).is_err());
        }
        let mut second = p.successor(SessionIdentity::new("next-session", "", "TEST-PC"));
        let next = second.contribute("", "", "20-10-26", hw()).unwrap();
        assert_ne!(zip, next);
        second.finalize().unwrap();
        if let Some(out) = std::env::var_os("WSD_EXPORT_FIXTURE_DIR") {
            fs::copy(&next, PathBuf::from(out).join("clean-fixture.zip")).unwrap();
        }
        assert!(
            !read_zip(&next)
                .unwrap()
                .iter()
                .any(|e| e.name.starts_with("Logs/Servicing/"))
        );
        fs::remove_dir_all(exe).unwrap();
    }

    #[test]
    fn deferred_publication_rejects_changed_evidence_and_keeps_workspace() {
        let exe = scratch("deferred-error");
        let mut p = SessionPackage::for_exe_dir(&exe);
        p.bind_session(SessionIdentity::new("session-error", "", "PC"));
        let zip = p.contribute("", "", "20-10-26", hw()).unwrap();
        let dir = p.identity().unwrap().report_dir.clone();
        fs::write(dir.join("new-unarchived.txt"), b"new evidence").unwrap();
        assert!(p.finalize().is_err());
        assert!(!zip.exists());
        assert!(p.final_zip().is_none());
        assert!(dir.join("new-unarchived.txt").is_file());
        fs::remove_dir_all(exe).unwrap();
    }

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("wsd-pkg-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn reports001_flat_migration_keeps_old_files_and_all_evidence() {
        let exe = scratch("flat-migration");
        let reports = exe.join("Reports");
        let old_dir = reports.join("old-session");
        fs::create_dir_all(&old_dir).unwrap();
        fs::write(old_dir.join("old.zip"), b"historical archive").unwrap();
        fs::write(reports.join("old.zip"), b"root historical archive").unwrap();
        let mut pkg = package(&exe, Some("template"));
        pkg.archive_time = "12-34-56".into();
        let zip = pkg.contribute("Клиент:/", "MSI", "20-10-26", hw()).unwrap();
        assert_eq!(zip.parent(), Some(reports.as_path()));
        let name = zip.file_name().unwrap().to_string_lossy();
        assert!(name.contains("MSI-20.10.26-12.34"));
        assert!(!name.contains([':', '/', '\\']));
        let workspace = pkg.identity().unwrap().report_dir.clone();
        assert!(!workspace.starts_with(&reports));
        pkg.finalize().unwrap();
        assert!(!workspace.exists());
        for file in hw() {
            assert!(read_zip(&zip).unwrap().contains(&file));
        }
        assert_eq!(
            fs::read(old_dir.join("old.zip")).unwrap(),
            b"historical archive"
        );
        assert_eq!(
            fs::read(reports.join("old.zip")).unwrap(),
            b"root historical archive"
        );
        assert_eq!(fs::read_dir(&reports).unwrap().count(), 3);
        let _ = fs::remove_dir_all(exe);
    }

    #[test]
    fn reports001_first_publish_never_overwrites_a_racing_archive() {
        let exe = scratch("flat-race");
        let mut pkg = package(&exe, None);
        let id = pkg.resolve("", "PC", "20-10-26").unwrap();
        fs::create_dir_all(exe.join("Reports")).unwrap();
        fs::write(&id.zip_path, b"another publisher").unwrap();
        // Exercise the publication primitive directly: no replacement flag.
        assert!(write_zip_staged(&id.zip_path, &id.report_dir, &hw(), false, false).is_err());
        assert_eq!(fs::read(&id.zip_path).unwrap(), b"another publisher");
        assert!(fs::read_dir(&id.report_dir).unwrap().next().is_none());
        let _ = fs::remove_dir_all(exe);
    }

    #[test]
    fn reports001_concurrent_same_second_runs_are_unique() {
        let exe = scratch("flat-concurrent");
        let mut threads = Vec::new();
        for index in 0..8 {
            let exe = exe.clone();
            threads.push(std::thread::spawn(move || {
                let mut pkg = package(&exe, None);
                pkg.bind_session(SessionIdentity::new(
                    &format!("test-{index}"),
                    "Клиент",
                    "PC",
                ));
                pkg.archive_time = "12-34-56".into();
                let zip = pkg.contribute("", "", "20-10-26", hw()).unwrap();
                pkg.finalize().unwrap();
                (zip, format!("test-{index}"))
            }));
        }
        let mut paths = BTreeSet::new();
        for thread in threads {
            let (zip, session) = thread.join().unwrap();
            assert_eq!(zip_session_id(&zip), Some(session));
            assert!(paths.insert(zip));
        }
        assert_eq!(paths.len(), 8);
        assert_eq!(fs::read_dir(exe.join("Reports")).unwrap().count(), 8);
        assert_eq!(
            fs::read_dir(persistent_dir(&exe.join("Reports")).join("Work"))
                .unwrap()
                .count(),
            0
        );
        let _ = fs::remove_dir_all(exe);
    }

    #[test]
    fn reports001_failed_first_publish_keeps_evidence_not_a_finished_zip() {
        let exe = scratch("flat-fail");
        let mut pkg = package(&exe, None);
        pkg.fail_next_replace = true;
        assert!(pkg.contribute("", "PC", "20-10-26", hw()).is_err());
        let id = pkg.identity().unwrap();
        assert!(!id.zip_path.exists());
        assert!(pkg.final_zip().is_none());
        assert_eq!(fs::read_dir(exe.join("Reports")).unwrap().count(), 0);
        for f in hw() {
            assert_eq!(fs::read(id.report_dir.join(&f.name)).unwrap(), f.bytes);
        }
        assert!(pkg.finalize().is_err());
        let _ = fs::remove_dir_all(exe);
    }

    #[test]
    fn reports001_unwritable_destination_preserves_workspace() {
        let exe = scratch("flat-write-error");
        fs::write(exe.join("Reports"), b"not a directory").unwrap();
        let mut pkg = package(&exe, None);
        let err = pkg.contribute("", "PC", "20-10-26", hw()).unwrap_err();
        assert!(err.contains("Cannot create Reports") && err.contains("evidence:"));
        assert_eq!(fs::read(exe.join("Reports")).unwrap(), b"not a directory");
        let id = pkg.identity().unwrap();
        for f in hw() {
            assert_eq!(fs::read(id.report_dir.join(&f.name)).unwrap(), f.bytes);
        }
        let _ = fs::remove_dir_all(exe);
    }

    #[test]
    fn reports001_workspace_failure_keeps_pending_evidence_for_retry() {
        let exe = scratch("flat-workspace-error");
        let blocker = persistent_dir(&exe.join("Reports")).join("Work");
        fs::create_dir_all(blocker.parent().unwrap()).unwrap();
        fs::write(&blocker, b"fixture blocker").unwrap();
        let mut pkg = package(&exe, None);
        assert!(pkg.contribute("", "PC", "20-10-26", hw()).is_err());
        assert_eq!(pkg.pending_len(), hw().len());
        assert!(!exe.join("Reports").exists());
        fs::remove_file(&blocker).unwrap(); // only this test's blocker
        let zip = pkg.contribute("", "PC", "20-10-26", vec![]).unwrap();
        for f in hw() {
            assert!(read_zip(&zip).unwrap().contains(&f));
        }
        pkg.finalize().unwrap();
        let _ = fs::remove_dir_all(exe);
    }

    #[cfg(windows)]
    #[test]
    fn reports001_windows_access_denied_keeps_previous_zip_and_new_evidence() {
        let exe = scratch("flat-denied");
        let mut pkg = package(&exe, None);
        let zip = pkg.contribute("", "PC", "20-10-26", hw()).unwrap();
        let before = fs::read(&zip).unwrap();
        let original = fs::metadata(&zip).unwrap().permissions();
        let mut readonly = original.clone();
        readonly.set_readonly(true);
        fs::set_permissions(&zip, readonly).unwrap();
        let result = pkg.contribute("", "PC", "20-10-26", ssd());
        fs::set_permissions(&zip, original).unwrap();
        let error = result.unwrap_err();
        assert!(error.contains("os error 5"), "{error}");
        assert_eq!(fs::read(&zip).unwrap(), before);
        assert!(
            pkg.identity()
                .unwrap()
                .report_dir
                .join("SSD_Benchmark_24.09.26_10-35.txt")
                .is_file()
        );
        assert!(pkg.finalize().is_err());
        let _ = fs::remove_dir_all(exe);
    }

    fn package(exe_dir: &Path, template: Option<&str>) -> SessionPackage {
        SessionPackage::new(
            exe_dir.join("Reports"),
            template.map(|t| t.as_bytes().to_vec()),
        )
    }

    /// Evidence names in the ZIP. v0.4.0: every package also carries the
    /// generated `manifest.json` (asserted here), which is not evidence.
    fn names(zip: &Path) -> Vec<String> {
        let all: Vec<String> = read_zip(zip).unwrap().into_iter().map(|e| e.name).collect();
        assert!(
            all.iter().any(|n| n == crate::manifest::MANIFEST_FILE),
            "ZIP carries manifest.json: {all:?}"
        );
        all.into_iter()
            .filter(|n| n != crate::manifest::MANIFEST_FILE)
            .collect()
    }

    fn hw() -> Vec<EvidenceFile> {
        vec![
            EvidenceFile::new("Hardware_24.09.26_10-30.txt", b"HW TXT".to_vec()),
            EvidenceFile::new("Hardware_24.09.26_10-30.json", b"{\"hw\":1}".to_vec()),
            EvidenceFile::new("Hardware_24.09.26_10-30.html", b"<html>hw</html>".to_vec()),
        ]
    }

    fn ssd() -> Vec<EvidenceFile> {
        vec![
            EvidenceFile::new("SSD_Benchmark_24.09.26_10-35.txt", b"SSD".to_vec()),
            EvidenceFile::new("SSD_Benchmark_24.09.26_10-35.json", b"{}".to_vec()),
        ]
    }

    fn drivers() -> Vec<EvidenceFile> {
        vec![
            EvidenceFile::new("DriverAudit_24-09-26_10-40-00.json", b"{}".to_vec()),
            EvidenceFile::new("DriverAudit_24-09-26_10-40-00.txt", b"DA".to_vec()),
        ]
    }

    fn expc() -> Vec<EvidenceFile> {
        vec![
            EvidenceFile::new("EXPC_24.09.26_10-45.txt", b"EXPC".to_vec()),
            EvidenceFile::new("EXPC_24.09.26_10-45.json", b"{}".to_vec()),
        ]
    }

    #[test]
    fn zip_roundtrip_with_python_compatible_layout() {
        let files = vec![
            EvidenceFile::new("a.txt", b"hello".to_vec()),
            EvidenceFile::new("Отчёт клиента.txt", "Привет".as_bytes().to_vec()),
            EvidenceFile::new("empty.log", Vec::new()),
        ];
        let bytes = build_zip(&files, now()).unwrap();
        assert_eq!(&bytes[..2], b"PK");
        assert_eq!(parse_zip(&bytes).unwrap(), files);
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn corrupt_or_truncated_zip_is_rejected() {
        let files = vec![EvidenceFile::new("a.txt", b"hello world".to_vec())];
        let mut bytes = build_zip(&files, now()).unwrap();
        assert!(parse_zip(&bytes[..bytes.len() - 5]).is_err());
        bytes[40] ^= 0xFF; // flip a data byte -> CRC mismatch
        assert!(parse_zip(&bytes).is_err());
        assert!(parse_zip(&[]).is_err());
    }

    /// A. Hardware-only session creates the report folder and ZIP.
    #[test]
    fn hardware_only_session_creates_the_package() {
        let exe = scratch("a");
        let mut pkg = package(&exe, None);
        let zip = pkg.contribute("Клиент", "MSI", "24-09-26", hw()).unwrap();
        let dir = exe.join("Reports");
        assert_eq!(zip.parent(), Some(dir.as_path()));
        assert!(dir.is_dir() && zip.is_file());
        assert_eq!(pkg.final_zip(), Some(zip.clone()));
        let n = names(&zip);
        for f in hw() {
            assert!(n.contains(&f.name), "{} in ZIP", f.name);
        }
        assert!(
            !n.iter().any(|x| x.contains('/') || x.contains('\\')),
            "flat ZIP"
        );
        assert!(pkg.completed_modules().contains(&EvidenceModule::Hardware));
        let _ = fs::remove_dir_all(&exe);
    }

    /// C + D. All modules, in two different orders: one cumulative package.
    #[test]
    fn all_modules_in_any_order_are_cumulative() {
        let orders: [[fn() -> Vec<EvidenceFile>; 4]; 2] =
            [[hw, ssd, drivers, expc], [expc, drivers, ssd, hw]];
        for (i, order) in orders.iter().enumerate() {
            let exe = scratch(&format!("cd{i}"));
            let mut pkg = package(&exe, None);
            let mut zips = BTreeSet::new();
            for part in order {
                zips.insert(pkg.contribute("Клиент", "PC", "24-09-26", part()).unwrap());
            }
            assert_eq!(zips.len(), 1, "one package path");
            let zip = zips.into_iter().next().unwrap();
            let n = names(&zip);
            for f in hw().into_iter().chain(ssd()).chain(drivers()).chain(expc()) {
                assert!(n.contains(&f.name), "{} retained", f.name);
            }
            assert_eq!(pkg.completed_modules().len(), 4);
            let dirs = fs::read_dir(exe.join("Reports")).unwrap().count();
            assert_eq!(dirs, 1, "exactly one report folder");
            let _ = fs::remove_dir_all(&exe);
        }
    }

    /// E. Optional files missing: the package is still valid.
    #[test]
    fn missing_optional_files_keep_the_package_valid() {
        let exe = scratch("e");
        let mut pkg = package(&exe, None);
        let zip = pkg.contribute("", "PC", "24-09-26", ssd()).unwrap();
        let n = names(&zip);
        assert_eq!(n.len(), 2);
        assert!(!n.contains(&GRAPHIC_REPORT_FILE.to_string()));
        assert!(!n.contains(&STARTUP_LOG_FILE.to_string()));
        let _ = fs::remove_dir_all(&exe);
    }

    #[test]
    fn failed_update_preserves_the_previous_zip() {
        let exe = scratch("f");
        let mut pkg = package(&exe, None);
        let zip = pkg.contribute("", "PC", "24-09-26", hw()).unwrap();
        let before = fs::read(&zip).unwrap();
        pkg.fail_next_replace = true;
        let err = pkg.contribute("", "PC", "24-09-26", ssd()).unwrap_err();
        assert!(err.contains("предыдущая версия сохранена"), "{err}");
        assert_eq!(fs::read(&zip).unwrap(), before, "previous ZIP intact");
        assert!(read_zip(&zip).is_ok());
        let id = pkg.identity().unwrap().clone();
        assert!(
            id.evidence_dir()
                .join("SSD_Benchmark_24.09.26_10-35.txt")
                .is_file()
        );
        let leftovers: Vec<_> = fs::read_dir(&id.report_dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.ends_with(".candidate"))
            .collect();
        assert!(leftovers.is_empty(), "no candidate left behind");
        // The next successful update includes the kept evidence.
        let zip2 = pkg.rebuild().unwrap();
        assert!(names(&zip2).contains(&"SSD_Benchmark_24.09.26_10-35.txt".to_string()));
        let _ = fs::remove_dir_all(&exe);
    }

    #[test]
    fn a_corrupt_candidate_never_replaces_the_final_zip() {
        let exe = scratch("f2");
        let dir = exe.join("r");
        fs::create_dir_all(&dir).unwrap();
        let zip = dir.join("x.zip");
        let good = vec![EvidenceFile::new("a.txt", b"a".to_vec())];
        write_zip_atomically(&zip, &good, false).unwrap();
        let before = fs::read(&zip).unwrap();
        // Validation against different expected content must fail.
        let cand = dir.join("c.zip");
        fs::write(&cand, build_zip(&good, now()).unwrap()).unwrap();
        assert!(validate_zip(&cand, &[EvidenceFile::new("a.txt", b"b".to_vec())]).is_err());
        assert_eq!(fs::read(&zip).unwrap(), before);
        let _ = fs::remove_dir_all(&exe);
    }

    /// G. Cyrillic client/computer and a Cyrillic path with spaces.
    #[test]
    fn unicode_identity_and_paths_work() {
        let exe = scratch("g").join("Портативная папка WinStateDiag");
        let mut pkg = package(&exe, None);
        let zip = pkg
            .contribute("ООО «Ромашка»", "БУХГАЛТЕРИЯ-ПК", "24-09-26", hw())
            .unwrap();
        assert_eq!(zip.parent(), Some(exe.join("Reports").as_path()));
        assert!(
            zip.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("ООО «Ромашка»-БУХГАЛТЕРИЯ-ПК-24.09.26-")
        );
        assert_eq!(names(&zip).len(), 3);
        let _ = fs::remove_dir_all(exe.parent().unwrap());
    }

    /// H. The package never lives in TEMP-style runtime folders.
    #[test]
    fn package_paths_are_under_the_exe_reports_folder() {
        let exe = scratch("h");
        let mut pkg = package(&exe, None);
        let zip = pkg.contribute("", "PC", "24-09-26", hw()).unwrap();
        assert!(zip.starts_with(exe.join("Reports")));
        let id = pkg.identity().unwrap();
        assert!(
            id.report_dir
                .starts_with(persistent_dir(&exe.join("Reports")).join("Work"))
        );
        let s = zip.to_string_lossy().to_lowercase();
        assert!(!s.contains("wsd-open-") && !s.contains("\\view-") && !s.contains("/view-"));
        let _ = fs::remove_dir_all(&exe);
    }

    #[test]
    fn identity_is_resolved_once_per_session() {
        let exe = scratch("id");
        let mut pkg = package(&exe, None);
        let a = pkg.resolve("", "PC", "24-09-26");
        let b = pkg.resolve("Другой клиент", "PC", "25-09-26");
        assert_eq!(a, b);
        let _ = fs::remove_dir_all(&exe);
    }

    #[test]
    fn same_name_different_content_never_overwrites_evidence() {
        let exe = scratch("dup");
        let mut pkg = package(&exe, None);
        pkg.contribute("", "PC", "24-09-26", hw()).unwrap();
        // Identical re-contribution: nothing duplicated.
        let zip = pkg.contribute("", "PC", "24-09-26", hw()).unwrap();
        assert_eq!(names(&zip).len(), 3);
        // Same names, new content: a suffixed set is added.
        let mut refreshed = hw();
        for f in &mut refreshed {
            f.bytes.extend_from_slice(b" v2");
        }
        let zip = pkg.contribute("", "PC", "24-09-26", refreshed).unwrap();
        let n = names(&zip);
        assert_eq!(n.len(), 6);
        assert!(n.contains(&"Hardware_24.09.26_10-30_02.json".to_string()));
        let _ = fs::remove_dir_all(&exe);
    }

    #[test]
    fn offered_evidence_waits_for_the_first_module_and_creates_nothing() {
        let exe = scratch("offer");
        let mut pkg = package(&exe, None);
        assert_eq!(pkg.offer(drivers()).unwrap(), None);
        assert!(
            !exe.join("Reports").exists(),
            "no report folder at start-up"
        );
        let zip = pkg.contribute("", "PC", "24-09-26", hw()).unwrap();
        let n = names(&zip);
        assert!(n.contains(&"DriverAudit_24-09-26_10-40-00.json".to_string()));
        // Once the package exists, offered evidence goes straight in.
        let later = vec![EvidenceFile::new(
            "DriverAudit_24-09-26_11-00-00.txt",
            b"x".to_vec(),
        )];
        let zip2 = pkg.offer(later).unwrap().unwrap();
        assert_eq!(zip, zip2);
        assert!(names(&zip2).contains(&"DriverAudit_24-09-26_11-00-00.txt".to_string()));
        let _ = fs::remove_dir_all(&exe);
    }

    #[test]
    fn cancelled_evidence_is_not_a_completed_module() {
        assert_eq!(
            EvidenceModule::of_file_name("EXPC_24.09.26_10-45_USER_CANCELLED.txt"),
            None
        );
        assert_eq!(
            EvidenceModule::of_file_name("EXPC_24.09.26_10-45.txt"),
            Some(EvidenceModule::Expc)
        );
    }

    fn zip_matches_folder(zip: &Path) {
        let dir = persistent_dir(zip.parent().unwrap())
            .join("Work")
            .join(zip.file_stem().unwrap());
        let mut folder: Vec<EvidenceFile> = list_files(&dir)
            .iter()
            .map(|p| {
                let mut f = EvidenceFile::read(p).unwrap();
                f.name = archive_name(&f.name);
                f
            })
            .collect();
        folder.sort_by(|a, b| a.name.cmp(&b.name));
        let mut zipped = read_zip(zip).unwrap();
        // v0.4.0: plus the generated manifest (never a loose file).
        assert!(
            zipped
                .iter()
                .any(|e| e.name == crate::manifest::MANIFEST_FILE)
        );
        assert!(!dir.join(crate::manifest::MANIFEST_FILE).exists());
        zipped.retain(|e| e.name != crate::manifest::MANIFEST_FILE);
        zipped.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(zipped, folder, "ZIP = report folder, 1:1");
    }

    /// B. Hardware -> SSD: same ZIP, Hardware kept, SSD and its history log
    /// (inside the report folder) added, no "(2)".
    #[test]
    fn hardware_then_ssd_updates_the_same_package() {
        let exe = scratch("b");
        let reports = exe.join("Reports");
        let mut pkg = package(&exe, None);
        let first = pkg.contribute("", "MSI", "24-09-26", hw()).unwrap();
        let dir = pkg.identity().unwrap().report_dir.clone();
        fs::write(dir.join(SSD_HISTORY_FILE), b"history line\n").unwrap();
        let second = pkg.contribute("", "MSI", "24-09-26", ssd()).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.parent(), Some(reports.as_path()));
        assert!(!reports.join("MSI - 24-09-26 (2)").exists());
        let n = names(&second);
        for f in hw().into_iter().chain(ssd()) {
            assert!(n.contains(&f.name));
        }
        assert!(n.contains(&SSD_HISTORY_FILE.to_string()));
        zip_matches_folder(&second);
        let _ = fs::remove_dir_all(&exe);
    }

    #[test]
    fn graphic_report_template_and_startup_log_are_embedded_when_present() {
        let exe = scratch("tpl");
        let dir = logs_dir(&exe.join("Reports"));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(STARTUP_LOG_FILE), b"renderer ok").unwrap();
        let mut pkg = package(&exe, Some("# canonical template"));
        let zip = pkg.contribute("", "PC", "24-09-26", hw()).unwrap();
        let entries = read_zip(&zip).unwrap();
        let tpl = entries
            .iter()
            .find(|e| e.name == GRAPHIC_REPORT_FILE)
            .unwrap();
        assert_eq!(tpl.bytes, b"# canonical template");
        assert!(
            entries
                .iter()
                .any(|e| e.name == archive_name(STARTUP_LOG_FILE))
        );
        assert!(
            pkg.identity()
                .unwrap()
                .report_dir
                .join(GRAPHIC_REPORT_FILE)
                .is_file(),
            "template is a folder file too"
        );
        zip_matches_folder(&zip);
        let _ = fs::remove_dir_all(&exe);
    }

    /// J + rule 3. Two consecutive runs (new sessions) of the same PC and
    /// date use ONE folder; nothing old is overwritten; a same-named result
    /// gets _02; the ZIP mirrors the folder.
    #[test]
    fn repeated_runs_have_separate_archives_and_never_overwrite() {
        let exe = scratch("j");
        let mut first = package(&exe, None);
        first.archive_time = "12-30-00".into();
        let z1 = first.contribute("", "PC", "24-09-26", hw()).unwrap();
        let before = fs::read(&z1).unwrap();
        first.finalize().unwrap();
        let mut second = package(&exe, None);
        second.archive_time = "12-30-00".into();
        let z2 = second.contribute("", "PC", "24-09-26", ssd()).unwrap();
        assert_eq!(z1.file_name().unwrap(), "PC-24.09.26-12.30.zip");
        assert_eq!(z2.file_name().unwrap(), "PC-24.09.26-12.30 (2).zip");
        assert_eq!(fs::read(&z1).unwrap(), before);
        assert_eq!(fs::read_dir(exe.join("Reports")).unwrap().count(), 2);
        assert!(!names(&z2).iter().any(|n| n.starts_with("Hardware_")));
        zip_matches_folder(&z2);
        let _ = fs::remove_dir_all(&exe);
    }

    fn manifest_session(zip: &Path) -> (String, String, String) {
        let m = read_zip(zip)
            .unwrap()
            .into_iter()
            .find(|e| e.name == crate::manifest::MANIFEST_FILE)
            .unwrap();
        let v = crate::deep_checks::json::parse(std::str::from_utf8(&m.bytes).unwrap()).unwrap();
        let s = v.get("session").unwrap();
        let get = |o: &crate::deep_checks::json::Value, k: &str| {
            o.get(k).unwrap().as_str().unwrap().to_string()
        };
        (
            get(s, "session_id"),
            get(s, "client_name"),
            get(&v, "computer_name"),
        )
    }

    /// v1.0 Client Identity: each session reports under the Client /
    /// Computer frozen at its start; a folder of another client (or the
    /// client-less one) of the same PC and date is never adopted, renamed or
    /// written to, and the start-up log (Reports\Logs) joins as a snapshot.
    #[test]
    fn sessions_never_reuse_another_clients_identity() {
        let exe = scratch("ident");
        let reports = exe.join("Reports");
        let bare = reports.join("MSI - 24-09-26");
        fs::create_dir_all(&bare).unwrap();
        fs::write(bare.join("Hardware_bare.txt"), b"bare session").unwrap();
        fs::create_dir_all(logs_dir(&reports)).unwrap();
        fs::write(logs_dir(&reports).join(STARTUP_LOG_FILE), b"startup\r\n").unwrap();

        // Session 1: client A. The live values a caller passes later
        // (a stale or edited input field) are ignored once bound.
        let mut a = package(&exe, None);
        a.bind_session(SessionIdentity::new("S-1", "  Клиент ", "MSI"));
        let zip_a = a.contribute("STALE", "OTHER-PC", "24-09-26", hw()).unwrap();
        let dir_a = reports.join("Клиент - MSI - 24-09-26");
        assert_eq!(zip_a.parent(), Some(reports.as_path()));
        assert_eq!(
            manifest_session(&zip_a),
            ("S-1".into(), "Клиент".into(), "MSI".into())
        );
        assert!(names(&zip_a).contains(&archive_name(STARTUP_LOG_FILE)));
        // The client-less folder is untouched.
        assert_eq!(
            fs::read(bare.join("Hardware_bare.txt")).unwrap(),
            b"bare session"
        );
        assert!(!names(&zip_a).contains(&"Hardware_bare.txt".to_string()));

        // Session 2: another client on the same PC and date: own folder.
        let mut b = package(&exe, None);
        b.bind_session(SessionIdentity::new("S-2", "Боб", "MSI"));
        let zip_b = b.contribute("Клиент", "MSI", "24-09-26", hw()).unwrap();
        assert_eq!(zip_b.parent(), Some(reports.as_path()));
        assert_eq!(
            manifest_session(&zip_b),
            ("S-2".into(), "Боб".into(), "MSI".into())
        );
        assert!(zip_a.is_file());

        // Session 3: empty client: only the computer names the report.
        let mut c = package(&exe, None);
        c.bind_session(SessionIdentity::new("S-3", "   ", "MSI"));
        let zip_c = c.contribute("Боб", "MSI", "24-09-26", hw()).unwrap();
        // The client-less folder of the same date belongs to another
        // (earlier) session: this session gets its own.
        assert_eq!(zip_c.parent(), Some(reports.as_path()));
        assert_eq!(
            manifest_session(&zip_c),
            ("S-3".into(), String::new(), "MSI".into())
        );
        assert!(!names(&zip_c).contains(&"Hardware_bare.txt".to_string()));

        // The same client again in a NEW session: its own folder and ZIP;
        // the first session's report is left exactly as it was.
        let zip_a_bytes = fs::read(&zip_a).unwrap();
        let mut a2 = package(&exe, None);
        a2.bind_session(SessionIdentity::new("S-4", "Клиент", "MSI"));
        let zip_a2 = a2.contribute("", "", "24-09-26", hw()).unwrap();
        assert_eq!(zip_a2.parent(), Some(reports.as_path()));
        assert_eq!(manifest_session(&zip_a2).0, "S-4");
        assert_eq!(fs::read(&zip_a).unwrap(), zip_a_bytes);
        // Within one session every contribution stays in its own folder.
        let again = a.contribute("", "", "24-09-26", hw()).unwrap();
        assert_eq!(again, zip_a);
        assert_eq!(manifest_session(&zip_a).0, "S-1");

        // N1: two sessions of the same identity that both resolve BEFORE
        // either one writes anything still get different folders (the
        // first resolve reserves its folder with the session marker).
        let mut p1 = package(&exe, None);
        p1.bind_session(SessionIdentity::new("S-7", "Ева", "MSI"));
        let mut p2 = package(&exe, None);
        p2.bind_session(SessionIdentity::new("S-8", "Ева", "MSI"));
        let id1 = p1.resolve("", "", "24-09-26").unwrap();
        let id2 = p2.resolve("", "", "24-09-26").unwrap();
        assert_ne!(id1.report_dir, id2.report_dir);
        assert_eq!(
            fs::read_to_string(id1.report_dir.join(SESSION_MARKER)).unwrap(),
            "S-7"
        );
        let z2 = p2.contribute("", "", "24-09-26", hw()).unwrap();
        let z1 = p1.contribute("", "", "24-09-26", hw()).unwrap();
        assert_eq!(manifest_session(&z1).0, "S-7");
        assert_eq!(manifest_session(&z2).0, "S-8");
        assert!(!names(&z1).contains(&SESSION_MARKER.to_string()));
        // A resolve again in the same session finds its own folder.
        assert_eq!(
            p1.resolve("", "", "24-09-26").unwrap().report_dir,
            id1.report_dir
        );

        // Clients whose names sanitize to the same folder text never merge.
        let mut x = package(&exe, None);
        x.bind_session(SessionIdentity::new("S-5", "A/B", "MSI"));
        let zip_x = x.contribute("", "", "24-09-26", hw()).unwrap();
        let mut y = package(&exe, None);
        y.bind_session(SessionIdentity::new("S-6", "A:B", "MSI"));
        let zip_y = y.contribute("", "", "24-09-26", hw()).unwrap();
        assert_ne!(zip_x, zip_y);
        assert_eq!(manifest_session(&zip_x).1, "A/B");
        assert_eq!(manifest_session(&zip_y).1, "A:B");

        // Unbound (legacy) lookups reuse only exactly their own folder.
        assert_eq!(
            find_or_new_report_dir(&reports, "Клиент", "MSI", "24-09-26"),
            dir_a
        );
        assert_eq!(
            find_or_new_report_dir(&reports, "Ева", "MSI", "24-09-26"),
            reports.join("Ева - MSI - 24-09-26")
        );
        // No runtime artifacts next to the folder.
        let root_files: Vec<_> = fs::read_dir(&reports)
            .unwrap()
            .flatten()
            .filter(|e| e.file_type().unwrap().is_file())
            .collect();
        assert!(!root_files.is_empty());
        assert!(
            root_files
                .iter()
                .all(|e| e.path().extension().is_some_and(|x| x == "zip"))
        );
        let _ = fs::remove_dir_all(&exe);
    }
}

/// v0.4.0: ZIP-only final report folder, fail-safe (see module docs).
#[cfg(test)]
mod finalize_tests {
    use super::*;
    use crate::manifest::MANIFEST_FILE;
    use crate::ssd_history::{self, HistoryEntry};

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("wsd-fin-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn package(exe: &Path) -> SessionPackage {
        SessionPackage::new(exe.join("Reports"), Some(b"# graphic".to_vec()))
    }

    fn f(name: &str, body: &str) -> EvidenceFile {
        EvidenceFile::new(name, body.as_bytes().to_vec())
    }

    fn loose(dir: &Path) -> Vec<String> {
        if !dir.exists() {
            return Vec::new();
        }
        let mut v: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        v.sort();
        v
    }

    fn zip_names(zip: &Path) -> Vec<String> {
        read_zip(zip).unwrap().into_iter().map(|e| e.name).collect()
    }

    fn entry(ts: u64, read: f64) -> HistoryEntry {
        HistoryEntry {
            timestamp_unix: ts,
            disk_identity: "PHYS#Samsung 9100 PRO#S1".into(),
            block_size: 1_048_576,
            queue_depth: 1,
            test_file_size: 1_073_741_824,
            pass_count: 3,
            read_mib_s: read,
            write_mib_s: read / 2.0,
        }
    }

    #[test]
    fn verified_final_package_leaves_only_the_zip() {
        let exe = scratch("only");
        let mut pkg = package(&exe);
        pkg.contribute(
            "Клиент",
            "MSI",
            "28-09-26",
            vec![f("EXPC_a.txt", "E"), f("EXPC_a.json", "{}")],
        )
        .unwrap();
        let zip = pkg
            .contribute(
                "",
                "",
                "",
                vec![f("Hardware_b.json", "{}"), f("Hardware_b.html", "<h>")],
            )
            .unwrap();
        let before = fs::read(&zip).unwrap();
        let dir = pkg.identity().unwrap().report_dir.clone();
        assert!(loose(&dir).len() > 1);
        assert!(pkg.needs_finalize());
        let removed = pkg.finalize().unwrap();
        assert_eq!(removed.len(), 5, "{removed:?}");
        assert_eq!(loose(&dir), Vec::<String>::new());
        // The ZIP itself is untouched and complete (evidence + manifest).
        assert_eq!(fs::read(&zip).unwrap(), before);
        let names = zip_names(&zip);
        for n in [
            "EXPC_a.txt",
            "EXPC_a.json",
            "Hardware_b.json",
            "Hardware_b.html",
            GRAPHIC_REPORT_FILE,
            MANIFEST_FILE,
        ] {
            assert!(names.contains(&n.to_string()), "{n}");
        }
        assert!(!pkg.needs_finalize());
        let _ = fs::remove_dir_all(&exe);
    }

    #[test]
    fn cleanup_never_runs_before_a_verified_zip() {
        let exe = scratch("early");
        let mut pkg = package(&exe);
        // No package at all.
        assert!(pkg.finalize().is_err());
        // Package whose last rebuild failed: the new evidence is loose and
        // NOT in the ZIP, so nothing at all is removed.
        let _zip = pkg
            .contribute("", "MSI", "28-09-26", vec![f("EXPC_a.txt", "E")])
            .unwrap();
        pkg.fail_next_replace = true;
        assert!(
            pkg.contribute("", "", "", vec![f("SSD_Benchmark_b.txt", "S")])
                .is_err()
        );
        let dir = pkg.identity().unwrap().report_dir.clone();
        let before = loose(&dir);
        assert!(before.contains(&"SSD_Benchmark_b.txt".to_string()));
        assert!(pkg.finalize().is_err());
        assert_eq!(loose(&dir), before, "failed package keeps every file");
        let _ = fs::remove_dir_all(&exe);
    }

    #[test]
    fn corrupt_zip_preserves_all_loose_evidence() {
        let exe = scratch("corrupt");
        let mut pkg = package(&exe);
        let zip = pkg
            .contribute("", "MSI", "28-09-26", vec![f("EXPC_a.txt", "E")])
            .unwrap();
        let dir = pkg.identity().unwrap().report_dir.clone();
        let mut bytes = fs::read(&zip).unwrap();
        let n = bytes.len();
        bytes[n / 3] ^= 0xFF;
        fs::write(&zip, &bytes).unwrap();
        let before = loose(&dir);
        assert!(pkg.finalize().is_err());
        // Reported once, not retried every frame.
        assert!(!pkg.needs_finalize());
        assert_eq!(loose(&dir), before);
        assert_eq!(
            fs::read(&zip).unwrap(),
            bytes,
            "the ZIP is never deleted or rewritten"
        );
        // A later update does not overwrite the unreadable ZIP either; the
        // new evidence is kept as a loose file.
        assert!(
            pkg.contribute("", "", "", vec![f("Hardware_c.json", "{}")])
                .is_err()
        );
        assert!(dir.join("Hardware_c.json").is_file());
        assert_eq!(fs::read(&zip).unwrap(), bytes);
        let _ = fs::remove_dir_all(&exe);
    }

    #[test]
    fn cleanup_touches_only_the_current_session_folder() {
        let exe = scratch("scope");
        let reports = exe.join("Reports");
        // Unrelated content under Reports.
        let other = reports.join("Боб - OTHER-PC - 27-09-26");
        fs::create_dir_all(&other).unwrap();
        fs::write(other.join("EXPC_old.txt"), "old").unwrap();
        fs::create_dir_all(reports.join("Logs")).unwrap();
        fs::write(reports.join("Logs").join("WinStateDiag_Log_x.txt"), "log").unwrap();
        let mut pkg = package(&exe);
        let _zip = pkg
            .contribute("", "MSI", "28-09-26", vec![f("EXPC_a.txt", "E")])
            .unwrap();
        let dir = pkg.identity().unwrap().report_dir.clone();
        // Hidden leftovers and sub-folders inside the session folder stay.
        fs::write(dir.join(".something.part"), "p").unwrap();
        fs::create_dir_all(dir.join("keep")).unwrap();
        fs::write(dir.join("keep").join("x.txt"), "x").unwrap();
        pkg.finalize().unwrap();
        let mut expected = vec![".something.part".to_string(), "keep".to_string()];
        expected.sort();
        assert_eq!(loose(&dir), expected);
        assert!(dir.join("keep").join("x.txt").is_file());
        assert!(other.join("EXPC_old.txt").is_file());
        assert!(
            reports
                .join("Logs")
                .join("WinStateDiag_Log_x.txt")
                .is_file()
        );
        let _ = fs::remove_dir_all(&exe);
    }

    #[test]
    fn later_update_after_cleanup_keeps_all_earlier_evidence() {
        let exe = scratch("later");
        let mut pkg = package(&exe);
        pkg.contribute(
            "",
            "MSI",
            "28-09-26",
            vec![f("EXPC_a.txt", "E"), f("EXPC_a.json", "{}")],
        )
        .unwrap();
        pkg.finalize().unwrap();
        // SSD benchmark after diagnostics (same running app).
        let zip = pkg
            .contribute("", "", "", vec![f("SSD_Benchmark_b.txt", "S")])
            .unwrap();
        let names = zip_names(&zip);
        for n in [
            "EXPC_a.txt",
            "EXPC_a.json",
            "SSD_Benchmark_b.txt",
            GRAPHIC_REPORT_FILE,
        ] {
            assert!(names.contains(&n.to_string()), "{n} kept: {names:?}");
        }
        assert_eq!(
            names.iter().filter(|n| *n == GRAPHIC_REPORT_FILE).count(),
            1
        );
        assert_eq!(names.iter().filter(|n| *n == MANIFEST_FILE).count(), 1);
        pkg.finalize().unwrap();
        assert_eq!(loose(zip.parent().unwrap()).len(), 1);
        let _ = fs::remove_dir_all(&exe);
    }

    #[test]
    fn repeated_same_day_run_does_not_adopt_the_previous_archive() {
        let exe = scratch("sameday");
        let mut first = package(&exe);
        let zip1 = first
            .contribute("Клиент", "MSI", "28-09-26", vec![f("EXPC_a.txt", "A")])
            .unwrap();
        first.finalize().unwrap();
        let before = fs::read(&zip1).unwrap();
        let mut second = package(&exe);
        let zip2 = second
            .contribute(
                "Клиент",
                "MSI",
                "28-09-26",
                vec![f("EXPC_a.txt", "B"), f("EXPC_c.txt", "C")],
            )
            .unwrap();
        assert_ne!(zip1, zip2);
        assert_eq!(fs::read(&zip1).unwrap(), before);
        assert!(
            read_zip(&zip2)
                .unwrap()
                .iter()
                .any(|e| e.name == "EXPC_a.txt" && e.bytes == b"B")
        );
        second.finalize().unwrap();
        assert_eq!(loose(zip2.parent().unwrap()).len(), 2);
        let _ = fs::remove_dir_all(&exe);
    }

    #[test]
    fn append_only_logs_written_after_cleanup_are_merged_not_replaced() {
        let exe = scratch("logs");
        let mut pkg = package(&exe);
        let id = pkg.resolve("", "MSI", "28-09-26").unwrap();
        fs::create_dir_all(&id.report_dir).unwrap();
        fs::write(id.report_dir.join(STARTUP_LOG_FILE), "line 1\r\n").unwrap();
        pkg.contribute("", "", "", vec![f("EXPC_a.txt", "E")])
            .unwrap();
        pkg.finalize().unwrap();
        // The next launch appends to a fresh loose start-up log.
        fs::create_dir_all(&id.report_dir).unwrap();
        fs::write(id.report_dir.join(STARTUP_LOG_FILE), "line 2\r\n").unwrap();
        let zip = pkg
            .contribute("", "", "", vec![f("Hardware_b.json", "{}")])
            .unwrap();
        let log = read_zip(&zip)
            .unwrap()
            .into_iter()
            .find(|e| e.name == archive_name(STARTUP_LOG_FILE))
            .unwrap();
        assert_eq!(log.bytes, b"line 1\r\nline 2\r\n");
        let _ = fs::remove_dir_all(&exe);
    }

    #[test]
    fn ssd_history_survives_cleanup_for_later_comparison() {
        let exe = scratch("history");
        let reports = exe.join("Reports");
        let mut pkg = package(&exe);
        // Benchmark A: session copy of the history + evidence, packaged.
        let id = pkg.open_for_update("", "MSI", "28-09-26").unwrap();
        let session_log = id.report_dir.join(SSD_HISTORY_FILE);
        ssd_history::append_entry(&session_log, &entry(1_000, 3000.0)).unwrap();
        pkg.contribute("", "", "", vec![f("SSD_Benchmark_a.txt", "A")])
            .unwrap();
        pkg.finalize().unwrap();
        assert!(
            !session_log.exists(),
            "session copy removed with the loose evidence"
        );
        // Persistent history keeps A, and comparison still finds it.
        let canonical = ssd_history::canonical_history_path(&reports);
        assert_eq!(
            ssd_history::load_history(&canonical),
            vec![entry(1_000, 3000.0)]
        );
        let b = entry(2_000, 3100.0);
        let all = ssd_history::load_all_history(&reports);
        assert_eq!(
            ssd_history::find_previous_compatible(&all, &b),
            Some(entry(1_000, 3000.0))
        );
        // Benchmark B later: the session copy is restored from the ZIP
        // first, so the packaged history holds A and B.
        let id = pkg.open_for_update("", "", "").unwrap();
        ssd_history::append_entry(&id.report_dir.join(SSD_HISTORY_FILE), &b).unwrap();
        ssd_history::merge_into(&canonical, std::slice::from_ref(&b)).unwrap();
        let zip = pkg
            .contribute("", "", "", vec![f("SSD_Benchmark_b.txt", "B")])
            .unwrap();
        let packaged = read_zip(&zip)
            .unwrap()
            .into_iter()
            .find(|e| e.name == SSD_HISTORY_FILE)
            .unwrap();
        let text = String::from_utf8(packaged.bytes).unwrap();
        assert_eq!(
            ssd_history::parse_history(&text),
            vec![entry(1_000, 3000.0), b.clone()]
        );
        pkg.finalize().unwrap();
        // Each run counted once although it is in both places meanwhile.
        let all = ssd_history::load_all_history(&reports);
        assert_eq!(all, vec![entry(1_000, 3000.0), b]);
        let _ = fs::remove_dir_all(&exe);
    }

    #[test]
    fn refresh_states_rebuilds_finalized_zip_without_losing_evidence() {
        let exe = scratch("states");
        let mut pkg = package(&exe);
        pkg.set_states("OK", "OK");
        let zip = pkg
            .contribute("Клиент", "MSI", "28-09-26", vec![f("EXPC_a.txt", "E")])
            .unwrap();
        pkg.finalize().unwrap();
        let manifest = |zip: &Path| {
            let e = read_zip(zip).unwrap();
            let m = e.iter().find(|e| e.name == MANIFEST_FILE).unwrap();
            String::from_utf8(m.bytes.clone()).unwrap()
        };
        assert!(manifest(&zip).contains("\"OK\""));
        // Unchanged states: no rebuild.
        assert!(!pkg.refresh_states("OK", "OK").unwrap());
        // A later Driver Audit problem reaches the packaged manifest.
        assert!(
            pkg.refresh_states("ATTENTION_DRIVER_PROBLEM", "OK")
                .unwrap()
        );
        let m = manifest(&zip);
        assert!(m.contains("ATTENTION_DRIVER_PROBLEM"), "{m}");
        assert!(pkg.refresh_states("PARTIAL", "PARTIAL").unwrap());
        let files = read_zip(&zip).unwrap();
        let state = files
            .iter()
            .find(|f| f.name == "State_Summary.json")
            .unwrap();
        let state =
            crate::deep_checks::json::parse(std::str::from_utf8(&state.bytes).unwrap()).unwrap();
        assert_eq!(
            state.get("hardware").and_then(|x| x.as_str()),
            Some("PARTIAL")
        );
        let txt = files
            .iter()
            .find(|f| f.name == "State_Summary.txt")
            .unwrap();
        assert!(String::from_utf8_lossy(&txt.bytes).contains("Hardware: PARTIAL"));
        assert!(manifest(&zip).contains("\"hardware\": \"PARTIAL\""));
        assert!(zip_names(&zip).contains(&"EXPC_a.txt".to_string()));
        assert!(!pkg.finalize().unwrap().is_empty());
        assert!(list_files(zip.parent().unwrap()).is_empty());
        assert!(
            pkg.finalize().unwrap().is_empty(),
            "already finalized is a valid no-op"
        );
        assert!(
            !zip_names(&zip)
                .iter()
                .any(|n| n.starts_with("State_Summary_"))
        );
        let _ = fs::remove_dir_all(&exe);
    }

    #[test]
    fn refresh_states_before_any_zip_only_sets_states() {
        let exe = scratch("states0");
        let mut pkg = package(&exe);
        assert!(!pkg.refresh_states("PARTIAL", "NO_DATA").unwrap());
        let zip = pkg
            .contribute("", "MSI", "28-09-26", vec![f("EXPC_a.txt", "E")])
            .unwrap();
        let e = read_zip(&zip).unwrap();
        let m = e.iter().find(|e| e.name == MANIFEST_FILE).unwrap();
        assert!(String::from_utf8_lossy(&m.bytes).contains("PARTIAL"));
        let _ = fs::remove_dir_all(&exe);
    }

    #[test]
    fn phase04_stale_summary_is_preserved_and_finalize_retries_after_failure() {
        let exe = scratch("phase04_summary");
        let mut pkg = package(&exe);
        pkg.set_states("OK", "OK");
        let zip = pkg
            .contribute("", "MSI", "19-10-26", vec![f("EXPC_a.txt", "E")])
            .unwrap();
        pkg.finalize().unwrap();
        let dir = pkg.identity().unwrap().report_dir.clone();
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("State_Summary.json"), b"historical bytes").unwrap();
        pkg.fail_next_replace = true;
        assert!(pkg.refresh_states("PARTIAL", "NO_DATA").is_err());
        assert!(
            pkg.refresh_states("PARTIAL", "NO_DATA").unwrap(),
            "failed refresh must not poison retry"
        );
        let files = read_zip(&zip).unwrap();
        assert!(
            files
                .iter()
                .any(|f| f.name.starts_with("Historical_") && f.bytes == b"historical bytes")
        );
        assert!(!pkg.finalize().unwrap().is_empty());
        assert!(list_files(&dir).is_empty());
        let _ = fs::remove_dir_all(exe);
    }

    #[test]
    fn rc10_execution_contract_matches_json_txt_manifest_and_one_zip() {
        let exe = scratch("rc10_execution");
        let mut pkg = package(&exe);
        pkg.set_states("PARTIAL", "NO_DATA");
        pkg.set_execution_override(Some("CANCELLED"));
        let zip = pkg
            .contribute("", "MSI", "29-10-26", vec![f("EXPC_a.txt", "E")])
            .unwrap();
        pkg.finalize().unwrap();
        let bytes = fs::read(&zip).unwrap();
        pkg.finalize().unwrap();
        assert_eq!(
            bytes,
            fs::read(&zip).unwrap(),
            "unchanged finalize is idempotent"
        );
        let files = read_zip(&zip).unwrap();
        for name in ["State_Summary.json", MANIFEST_FILE] {
            let text =
                String::from_utf8_lossy(&files.iter().find(|f| f.name == name).unwrap().bytes);
            let v = crate::deep_checks::json::parse(&text).unwrap();
            assert_eq!(
                v.get("execution_status").unwrap().as_str(),
                Some("CANCELLED")
            );
        }
        assert!(
            String::from_utf8_lossy(
                &files
                    .iter()
                    .find(|f| f.name == "State_Summary.txt")
                    .unwrap()
                    .bytes
            )
            .contains("Execution: CANCELLED")
        );
    }

    #[test]
    fn phase04_foreign_session_zip_cannot_be_restored_rebuilt_or_finalized() {
        let exe = scratch("phase04_owner");
        let mut pkg = package(&exe);
        pkg.bind_session(SessionIdentity::new("owned-session", "client", "MSI"));
        pkg.set_states("OK", "OK");
        let zip = pkg
            .contribute("", "", "19-10-26", vec![f("EXPC_a.txt", "original")])
            .unwrap();
        let before = fs::read(&zip).unwrap();
        // Simulate a stale handle accidentally rebound to another session.
        pkg.session = Some(SessionIdentity::new("other-session", "client", "MSI"));
        assert!(pkg.refresh_states("PARTIAL", "NO_DATA").is_err());
        assert!(pkg.rebuild().is_err());
        assert!(pkg.finalize().is_err());
        assert!(
            pkg.contribute("", "", "", vec![f("EXPC_new.txt", "new")])
                .is_err()
        );
        assert_eq!(fs::read(&zip).unwrap(), before);
        assert_eq!(
            fs::read(pkg.identity().unwrap().report_dir.join("EXPC_a.txt")).unwrap(),
            b"original"
        );
        assert!(
            !pkg.identity()
                .unwrap()
                .report_dir
                .join("EXPC_new.txt")
                .exists()
        );
        let _ = fs::remove_dir_all(exe);
    }
}

#[test]
fn rc9_empty_name_segments_and_invalid_time_do_not_abort() {
    for c in ["", "-", " - ", "___", "...", " _-._ ", " - _ "] {
        assert_eq!(
            diagnostic_zip_base(c, " ..MSI-_ ", "27-10-26", "8-30"),
            "MSI-27.10.26-08.30"
        );
    }
    assert!(diagnostic_zip_base("", "PC", "27-10-26", "bad-30").contains("unknown"));
}
