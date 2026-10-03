//! Unified session report package.
//!
//! One running WinStateDiag owns ONE report destination:
//! `<EXE>\Reports\<Client> - <Computer> - DD-MM-YY\<same>.zip`.
//! Every diagnostic module (EXPC Diagnostic, Hardware Report, Driver Audit,
//! SSD benchmark) contributes its evidence to that package as soon as it has
//! it; the user never has to save anything by hand.
//!
//! * Evidence is persisted first, as plain files, in the hidden
//!   `<report dir>\.evidence\` folder (never only in %TEMP%).
//! * The ZIP is then rebuilt from all evidence (flat, no sub-folders) plus
//!   the optional shared files (`ssd_benchmark_history.log`,
//!   `startup_graphics.log`, `GRAPHIC_REPORT.md`).
//! * The rebuild is atomic: candidate ZIP next to the final one -> full
//!   validation (structure, names, sizes, CRC-32 of every entry) -> rename
//!   over the final ZIP. A failure leaves the previous valid ZIP untouched,
//!   and a zero-byte or corrupt final ZIP is never produced.
//!
//! The ZIP writer is a small self-contained implementation (method 0,
//! "stored"; UTF-8 names flag) so the package needs no extra crate and can
//! be fully verified.
//!
//! v0.4.0 report folder lifecycle (ZIP-only final folder, fail-safe):
//!
//! 1. Evidence is stored as loose files in the report folder (as before).
//! 2. Every update rebuilds the ZIP from ALL loose files, plus a generated
//!    `manifest.json` (never a loose file), writes it to a candidate,
//!    re-reads and CRC-validates every entry, then atomically replaces the
//!    final ZIP. A failure keeps the previous ZIP and every loose file.
//! 3. `finalize()` — called by the app only when nothing is running and the
//!    last diagnostic run did not fail or get stopped — re-reads the final
//!    ZIP, requires every loose file of the folder to be inside it byte for
//!    byte, copies SSD history lines into the persistent
//!    `Reports\History\ssd_benchmark_history.log`, and only then removes
//!    those loose files (never the ZIP, never sub-folders, never hidden
//!    files, never another folder). Any mismatch or error: nothing is
//!    removed.
//! 4. Before any later update of the same package (another module, SSD
//!    benchmark after diagnostics, a repeated same-day run), the loose
//!    evidence is restored from the verified ZIP first (`restore_loose`), so
//!    the cumulative package never loses earlier evidence. Append-only logs
//!    written meanwhile (`startup_graphics.log`, history) are merged with
//!    their packaged content instead of replacing it.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::engine::report_base_name;

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
}

impl EvidenceModule {
    /// Module a completed evidence file belongs to (by its name prefix).
    /// Evidence from an interrupted run never counts as completed.
    pub fn of_file_name(name: &str) -> Option<Self> {
        if name.contains(USER_CANCELLED) {
            return None;
        }
        if name.starts_with("EXPC_") {
            Some(Self::Expc)
        } else if name.starts_with("Hardware_") {
            Some(Self::Hardware)
        } else if name.starts_with("DriverAudit_") {
            Some(Self::DriverAudit)
        } else if name.starts_with("SSD_Benchmark_") {
            Some(Self::SsdBenchmark)
        } else if name.starts_with(crate::nvme_health::EVIDENCE_PREFIX) {
            Some(Self::NvmeHealth)
        } else if name.starts_with(crate::storage_health::EVIDENCE_PREFIX) {
            Some(Self::StorageCorrelation)
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

/// The ONE report folder of a PC and a date under `root`:
/// `<Client> - <Computer> - <date>` or `<Computer> - <date>`.
/// An existing folder of that PC+date is reused (preferring the one with
/// `client`, then any client, then the bare one); otherwise the new name
/// (not created here). A bare folder is renamed to include `client` once a
/// client is known, when that is possible.
pub fn find_or_new_report_dir(root: &Path, client: &str, computer: &str, date: &str) -> PathBuf {
    let bare = report_base_name("", computer, date);
    let wanted = report_base_name(client, computer, date);
    let bare_l = bare.to_lowercase();
    let suffix = format!(" - {bare_l}");
    let mut candidates: Vec<String> = fs::read_dir(root)
        .map(|rd| {
            rd.flatten()
                .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
                .map(|e| e.file_name().to_string_lossy().to_string())
                .filter(|n| {
                    let l = n.to_lowercase();
                    l == bare_l || l.ends_with(&suffix)
                })
                .collect()
        })
        .unwrap_or_default();
    candidates.sort();
    let pick = candidates
        .iter()
        .find(|n| n.to_lowercase() == wanted.to_lowercase())
        .or_else(|| candidates.iter().find(|n| n.to_lowercase() != bare_l))
        .or_else(|| candidates.first())
        .cloned();
    match pick {
        None => root.join(wanted),
        Some(name) if name.to_lowercase() == bare_l && wanted != bare => {
            let from = root.join(&name);
            let to = root.join(&wanted);
            if !to.exists() && fs::rename(&from, &to).is_ok() {
                // The package ZIP is derived; the old-named one goes away.
                let _ = fs::remove_file(to.join(format!("{name}.zip")));
                to
            } else {
                from
            }
        }
        Some(name) => root.join(name),
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
    identity: Option<PackageIdentity>,
    /// Computer name of the report identity (manifest).
    computer: String,
    /// A verified rebuild happened since the last `finalize`.
    needs_finalize: bool,
    completed: BTreeSet<EvidenceModule>,
    /// Evidence offered before the package existed (automatic start-up
    /// Driver Audit): joins the package when the first module creates it.
    pending: Vec<EvidenceFile>,
    zip_ready: bool,
    template: Option<Vec<u8>>,
    #[cfg(test)]
    pub fail_next_replace: bool,
}

impl SessionPackage {
    pub fn new(reports_root: PathBuf, template: Option<Vec<u8>>) -> Self {
        Self {
            reports_root,
            identity: None,
            computer: String::new(),
            needs_finalize: false,
            completed: BTreeSet::new(),
            pending: Vec::new(),
            zip_ready: false,
            template,
            #[cfg(test)]
            fail_next_replace: false,
        }
    }

    /// Package for the portable EXE folder (`<exe_dir>\Reports`) with the
    /// embedded GRAPHIC_REPORT.md.
    pub fn for_exe_dir(exe_dir: &Path) -> Self {
        Self::new(exe_dir.join("Reports"), embedded_graphic_template())
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

    /// Resolves the report destination once; later calls return the same
    /// identity. One PC + one date = one report folder: an existing folder
    /// of that PC and date (an earlier run, the start-up log) is reused;
    /// new results never overwrite old ones (see `store_evidence`).
    pub fn resolve(&mut self, client: &str, computer: &str, date: &str) -> PackageIdentity {
        if let Some(id) = &self.identity {
            return id.clone();
        }
        if !computer.trim().is_empty() {
            self.computer = computer.trim().to_string();
        }
        let report_dir = find_or_new_report_dir(&self.reports_root, client, computer, date);
        let base = report_dir
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| report_base_name(client, computer, date));
        let id = PackageIdentity {
            zip_path: report_dir.join(format!("{base}.zip")),
            report_dir,
            base,
        };
        self.identity = Some(id.clone());
        id
    }

    /// Final verified ZIP of this session, if the last update succeeded.
    pub fn final_zip(&self) -> Option<PathBuf> {
        let id = self.identity.as_ref()?;
        (self.zip_ready && id.zip_path.is_file()).then(|| id.zip_path.clone())
    }

    /// Adds evidence (persisted first) and updates the ZIP.
    pub fn contribute(
        &mut self,
        client: &str,
        computer: &str,
        date: &str,
        files: Vec<EvidenceFile>,
    ) -> Result<PathBuf, String> {
        let id = self.resolve(client, computer, date);
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
        let stored = match store_evidence(&evidence_dir, &all) {
            Ok(names) => names,
            Err(err) => {
                // Nothing is lost: what was not stored stays pending.
                self.pending = all;
                return Err(err);
            }
        };
        for name in &stored {
            if let Some(m) = EvidenceModule::of_file_name(name) {
                self.completed.insert(m);
            }
        }
        restored?;
        self.rebuild()
    }

    /// The report folder for an update outside `contribute` (SSD history
    /// append): resolved, created, and with packaged evidence restored.
    pub fn open_for_update(
        &mut self,
        client: &str,
        computer: &str,
        date: &str,
    ) -> Result<PackageIdentity, String> {
        let id = self.resolve(client, computer, date);
        fs::create_dir_all(&id.report_dir).map_err(|e| {
            format!(
                "Не удалось создать папку отчёта: {e}\n— путь: {}",
                id.report_dir.display()
            )
        })?;
        restore_loose(&id)?;
        Ok(id)
    }

    /// A verified rebuild is waiting for `finalize`.
    pub fn needs_finalize(&self) -> bool {
        self.needs_finalize
    }

    /// Final step of a successful package: leaves only the verified ZIP in
    /// the report folder. Returns the removed loose files (empty when the
    /// folder is not in a state where removal is proven safe — nothing is
    /// removed then). Errors never remove anything further.
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
            let file = EvidenceFile::read(path)?;
            if !packaged.iter().any(|e| *e == file) {
                return Ok(Vec::new());
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
        Ok(removed)
    }

    /// Evidence produced automatically (start-up Driver Audit): joins the
    /// package if it exists, otherwise waits in memory for the first
    /// module that creates the package. Returns the ZIP when updated now.
    pub fn offer(&mut self, files: Vec<EvidenceFile>) -> Result<Option<PathBuf>, String> {
        match self.identity.clone() {
            Some(id) if id.report_dir.is_dir() => {
                let zip = self.contribute("", "", "", files)?;
                Ok(Some(zip))
            }
            _ => {
                self.pending.extend(files);
                Ok(None)
            }
        }
    }

    /// Rebuilds the ZIP from all persisted evidence. On any failure the
    /// previous final ZIP stays exactly as it was.
    pub fn rebuild(&mut self) -> Result<PathBuf, String> {
        let id = self.identity.clone().ok_or("Отчёт сессии ещё не создан.")?;
        let mut entries: Vec<EvidenceFile> = Vec::new();
        let mut names: BTreeSet<String> = BTreeSet::new();
        for path in list_files(&id.evidence_dir()) {
            let file = EvidenceFile::read(&path)?;
            // The manifest is generated, never taken from the folder.
            if file.name == crate::manifest::MANIFEST_FILE {
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
        let (windows_product, windows_build) = crate::ui::sysinfo::windows_edition_and_full_build();
        let ctx = crate::manifest::ManifestContext {
            producer_version: crate::manifest::PRODUCER_VERSION.to_string(),
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
        write_zip_atomically(&id.zip_path, &entries, fail)?;
        self.zip_ready = true;
        self.needs_finalize = true;
        Ok(id.zip_path)
    }
}

/// Writes each file into `dir` (flat). An identical existing file is kept
/// as is; a different file with the same name never overwrites it: the
/// whole group sharing that stem gets the first free `_NN` suffix.
fn store_evidence(dir: &Path, files: &[EvidenceFile]) -> Result<Vec<String>, String> {
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
            stored.push(name);
        }
    }
    Ok(stored)
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
    if !id.zip_path.is_file() {
        return Ok(());
    }
    let packaged = read_zip(&id.zip_path).map_err(|e| {
        format!(
            "Итоговый ZIP не читается, он оставлен без изменений: {e}\n— путь: {}",
            id.zip_path.display()
        )
    })?;
    for e in packaged {
        if e.name == crate::manifest::MANIFEST_FILE {
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

fn write_zip_atomically(
    final_zip: &Path,
    entries: &[EvidenceFile],
    fail: bool,
) -> Result<(), String> {
    let dir = final_zip.parent().ok_or("Некорректный путь ZIP.")?;
    let candidate = dir.join(format!(
        ".{}.candidate",
        final_zip.file_name().unwrap_or_default().to_string_lossy()
    ));
    let bytes = build_zip(entries, crate::ui::sysinfo::local_time())?;
    let result = (|| {
        fs::write(&candidate, &bytes).map_err(|e| {
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
        fs::rename(&candidate, final_zip).map_err(|e| {
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

/// Builds a flat ZIP (stored entries, UTF-8 names).
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
        if e.name.is_empty() || e.name.contains(['/', '\\']) {
            return Err(format!("Недопустимое имя в ZIP: {}", e.name));
        }
        let size = u32::try_from(e.bytes.len()).map_err(|_| "Файл слишком большой для ZIP.")?;
        let offset = u32::try_from(out.len()).map_err(|_| "ZIP слишком большой.")?;
        let crc = crc32(&e.bytes);
        let name = e.name.as_bytes();
        // Local file header.
        put32(&mut out, 0x0403_4b50);
        put16(&mut out, 20);
        put16(&mut out, FLAG_UTF8);
        put16(&mut out, 0);
        put16(&mut out, time);
        put16(&mut out, date);
        put32(&mut out, crc);
        put32(&mut out, size);
        put32(&mut out, size);
        put16(&mut out, name.len() as u16);
        put16(&mut out, 0);
        out.extend_from_slice(name);
        out.extend_from_slice(&e.bytes);
        // Central directory record.
        put32(&mut central, 0x0201_4b50);
        put16(&mut central, 20);
        put16(&mut central, 20);
        put16(&mut central, FLAG_UTF8);
        put16(&mut central, 0);
        put16(&mut central, time);
        put16(&mut central, date);
        put32(&mut central, crc);
        put32(&mut central, size);
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
        if method != 0 || csize != usize_ {
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
        let bytes = data
            .get(start..start + csize)
            .ok_or_else(|| bad("данные"))?
            .to_vec();
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

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("wsd-pkg-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
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
        let zip = pkg.contribute("Алексей", "MSI", "24-09-26", hw()).unwrap();
        let dir = exe.join("Reports").join("Алексей - MSI - 24-09-26");
        assert_eq!(zip, dir.join("Алексей - MSI - 24-09-26.zip"));
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
        assert!(zip.ends_with(
            "Reports/ООО «Ромашка» - БУХГАЛТЕРИЯ-ПК - 24-09-26/ООО «Ромашка» - БУХГАЛТЕРИЯ-ПК - 24-09-26.zip"
        ) || zip.ends_with(
            "Reports\\ООО «Ромашка» - БУХГАЛТЕРИЯ-ПК - 24-09-26\\ООО «Ромашка» - БУХГАЛТЕРИЯ-ПК - 24-09-26.zip"
        ));
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
        assert!(id.report_dir.starts_with(exe.join("Reports")));
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
        let dir = zip.parent().unwrap();
        let mut folder: Vec<EvidenceFile> = list_files(dir)
            .iter()
            .map(|p| EvidenceFile::read(p).unwrap())
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
        assert_eq!(
            first,
            reports.join("MSI - 24-09-26").join("MSI - 24-09-26.zip")
        );
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
        let dir = exe.join("Reports").join("PC - 24-09-26");
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
        assert!(entries.iter().any(|e| e.name == STARTUP_LOG_FILE));
        assert!(
            dir.join(GRAPHIC_REPORT_FILE).is_file(),
            "template is a folder file too"
        );
        zip_matches_folder(&zip);
        let _ = fs::remove_dir_all(&exe);
    }

    /// J + rule 3. Two consecutive runs (new sessions) of the same PC and
    /// date use ONE folder; nothing old is overwritten; a same-named result
    /// gets _02; the ZIP mirrors the folder.
    #[test]
    fn repeated_runs_share_one_folder_and_never_overwrite() {
        let exe = scratch("j");
        let reports = exe.join("Reports");
        let mut first = package(&exe, None);
        let z1 = first.contribute("", "PC", "24-09-26", hw()).unwrap();
        let old_txt = fs::read(z1.parent().unwrap().join("Hardware_24.09.26_10-30.txt")).unwrap();
        let mut second = package(&exe, None);
        let mut again = hw();
        for f in &mut again {
            f.bytes.extend_from_slice(b" run2");
        }
        let z2 = second.contribute("", "PC", "24-09-26", again).unwrap();
        assert_eq!(z1, z2, "one PC + one date = one folder");
        assert_eq!(fs::read_dir(&reports).unwrap().count(), 1);
        let dir = z2.parent().unwrap();
        assert_eq!(
            fs::read(dir.join("Hardware_24.09.26_10-30.txt")).unwrap(),
            old_txt
        );
        assert!(dir.join("Hardware_24.09.26_10-30_02.txt").is_file());
        let n = names(&z2);
        assert!(n.contains(&"Hardware_24.09.26_10-30.txt".to_string()));
        assert!(n.contains(&"Hardware_24.09.26_10-30_02.txt".to_string()));
        zip_matches_folder(&z2);
        let _ = fs::remove_dir_all(&exe);
    }

    /// The start-up log creates `<Computer> - <date>` before a client is
    /// known; the first module with a client renames that same folder.
    #[test]
    fn bare_startup_folder_becomes_the_client_folder() {
        let exe = scratch("bare");
        let reports = exe.join("Reports");
        let bare = reports.join("MSI - 24-09-26");
        fs::create_dir_all(&bare).unwrap();
        fs::write(bare.join(STARTUP_LOG_FILE), b"startup").unwrap();
        let mut pkg = package(&exe, None);
        let zip = pkg.contribute("Алексей", "MSI", "24-09-26", hw()).unwrap();
        let dir = reports.join("Алексей - MSI - 24-09-26");
        assert_eq!(zip, dir.join("Алексей - MSI - 24-09-26.zip"));
        assert!(!bare.exists());
        assert!(names(&zip).contains(&STARTUP_LOG_FILE.to_string()));
        // Later lookups (start-up log lines) find the same folder.
        assert_eq!(find_or_new_report_dir(&reports, "", "MSI", "24-09-26"), dir);
        // Another client on the same PC and date: still the one folder.
        assert_eq!(
            find_or_new_report_dir(&reports, "Боб", "MSI", "24-09-26"),
            dir
        );
        // No runtime artifacts next to the folder.
        let root_files: Vec<_> = fs::read_dir(&reports)
            .unwrap()
            .flatten()
            .filter(|e| e.file_type().unwrap().is_file())
            .collect();
        assert!(root_files.is_empty());
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
            "Алексей",
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
        let dir = zip.parent().unwrap().to_path_buf();
        assert!(loose(&dir).len() > 1);
        assert!(pkg.needs_finalize());
        let removed = pkg.finalize().unwrap();
        assert_eq!(removed.len(), 5, "{removed:?}");
        assert_eq!(
            loose(&dir),
            [zip.file_name().unwrap().to_string_lossy().to_string()]
        );
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
        let zip = pkg
            .contribute("", "MSI", "28-09-26", vec![f("EXPC_a.txt", "E")])
            .unwrap();
        pkg.fail_next_replace = true;
        assert!(
            pkg.contribute("", "", "", vec![f("SSD_Benchmark_b.txt", "S")])
                .is_err()
        );
        let dir = zip.parent().unwrap().to_path_buf();
        let before = loose(&dir);
        assert!(before.contains(&"SSD_Benchmark_b.txt".to_string()));
        assert_eq!(pkg.finalize().unwrap(), Vec::<String>::new());
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
        let dir = zip.parent().unwrap().to_path_buf();
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
        let zip = pkg
            .contribute("", "MSI", "28-09-26", vec![f("EXPC_a.txt", "E")])
            .unwrap();
        let dir = zip.parent().unwrap().to_path_buf();
        // Hidden leftovers and sub-folders inside the session folder stay.
        fs::write(dir.join(".something.part"), "p").unwrap();
        fs::create_dir_all(dir.join("keep")).unwrap();
        fs::write(dir.join("keep").join("x.txt"), "x").unwrap();
        pkg.finalize().unwrap();
        let mut expected = vec![
            ".something.part".to_string(),
            zip.file_name().unwrap().to_string_lossy().to_string(),
            "keep".to_string(),
        ];
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
    fn repeated_same_day_run_extends_the_same_zip() {
        let exe = scratch("sameday");
        let mut first = package(&exe);
        let zip1 = first
            .contribute("Алексей", "MSI", "28-09-26", vec![f("EXPC_a.txt", "A")])
            .unwrap();
        first.finalize().unwrap();
        // A second launch of WinStateDiag the same day, same PC.
        let mut second = package(&exe);
        let zip2 = second
            .contribute(
                "Алексей",
                "MSI",
                "28-09-26",
                vec![f("EXPC_a.txt", "B"), f("EXPC_c.txt", "C")],
            )
            .unwrap();
        assert_eq!(zip1, zip2, "one folder, one ZIP per PC and date");
        let zipped = read_zip(&zip2).unwrap();
        let body = |n: &str| zipped.iter().find(|e| e.name == n).map(|e| e.bytes.clone());
        // Never overwritten: the earlier run's file is kept, the new one
        // with the same name got the next free suffix.
        assert_eq!(body("EXPC_a.txt").unwrap(), b"A");
        assert_eq!(body("EXPC_a_02.txt").unwrap(), b"B");
        assert_eq!(body("EXPC_c.txt").unwrap(), b"C");
        second.finalize().unwrap();
        assert_eq!(loose(zip2.parent().unwrap()).len(), 1);
        let _ = fs::remove_dir_all(&exe);
    }

    #[test]
    fn append_only_logs_written_after_cleanup_are_merged_not_replaced() {
        let exe = scratch("logs");
        let mut pkg = package(&exe);
        let id = pkg.resolve("", "MSI", "28-09-26");
        fs::create_dir_all(&id.report_dir).unwrap();
        fs::write(id.report_dir.join(STARTUP_LOG_FILE), "line 1\r\n").unwrap();
        pkg.contribute("", "", "", vec![f("EXPC_a.txt", "E")])
            .unwrap();
        pkg.finalize().unwrap();
        // The next launch appends to a fresh loose start-up log.
        fs::write(id.report_dir.join(STARTUP_LOG_FILE), "line 2\r\n").unwrap();
        let zip = pkg
            .contribute("", "", "", vec![f("Hardware_b.json", "{}")])
            .unwrap();
        let log = read_zip(&zip)
            .unwrap()
            .into_iter()
            .find(|e| e.name == STARTUP_LOG_FILE)
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
}
