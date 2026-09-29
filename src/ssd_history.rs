//! Lightweight SSD/NVMe benchmark history.
//!
//! Not a database: a single append-only, pipe-delimited text file living
//! next to the existing evidence/report tree (`<exe_dir>\Reports\`), in
//! keeping with WinStateDiag's portable, read-only-diagnostic philosophy.
//! A corrupt or hand-edited line is skipped rather than failing the whole
//! read — history is a convenience, never a source of truth for the
//! diagnostic itself.
//!
//! "Compatible" comparisons (current vs. previous) require the same disk
//! identity (volume serial number, not just a drive letter, which can be
//! reassigned) and the same benchmark profile (block size, queue depth,
//! test file size, pass count). Different disks or different profiles are
//! never compared against each other.

use std::ffi::OsStr;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr::null_mut;
use std::time::{SystemTime, UNIX_EPOCH};

unsafe extern "system" {
    fn GetVolumeInformationW(
        root_path_name: *const u16,
        volume_name_buffer: *mut u16,
        volume_name_size: u32,
        volume_serial_number: *mut u32,
        maximum_component_length: *mut u32,
        file_system_flags: *mut u32,
        file_system_name_buffer: *mut u16,
        file_system_name_size: u32,
    ) -> i32;
}

/// A single completed, successful benchmark run.
#[derive(Debug, Clone, PartialEq)]
pub struct HistoryEntry {
    pub timestamp_unix: u64,
    pub disk_identity: String,
    pub block_size: usize,
    pub queue_depth: u32,
    pub test_file_size: u64,
    pub pass_count: u32,
    pub read_mib_s: f64,
    pub write_mib_s: f64,
}

impl HistoryEntry {
    /// Two entries are "compatible" (safe to compare as current/previous)
    /// only when they are the same physical disk and the same test profile.
    pub fn is_compatible_with(&self, other: &HistoryEntry) -> bool {
        self.disk_identity == other.disk_identity
            && self.block_size == other.block_size
            && self.queue_depth == other.queue_depth
            && self.test_file_size == other.test_file_size
            && self.pass_count == other.pass_count
    }

    fn serialize(&self) -> String {
        // Pipe-delimited, one entry per line. Disk identity never contains
        // '|' (see disk_identity_for), so no escaping is needed.
        format!(
            "{}|{}|{}|{}|{}|{}|{}|{}",
            self.timestamp_unix,
            self.disk_identity,
            self.block_size,
            self.queue_depth,
            self.test_file_size,
            self.pass_count,
            self.read_mib_s,
            self.write_mib_s
        )
    }

    fn parse(line: &str) -> Option<HistoryEntry> {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return None;
        }
        let parts: Vec<&str> = line.split('|').collect();
        if parts.len() != 8 {
            return None;
        }
        let read_mib_s: f64 = parts[6].parse().ok()?;
        let write_mib_s: f64 = parts[7].parse().ok()?;
        if !read_mib_s.is_finite()
            || !write_mib_s.is_finite()
            || read_mib_s < 0.0
            || write_mib_s < 0.0
        {
            return None;
        }
        Some(HistoryEntry {
            timestamp_unix: parts[0].parse().ok()?,
            disk_identity: parts[1].to_string(),
            block_size: parts[2].parse().ok()?,
            queue_depth: parts[3].parse().ok()?,
            test_file_size: parts[4].parse().ok()?,
            pass_count: parts[5].parse().ok()?,
            read_mib_s,
            write_mib_s,
        })
    }
}

/// `<exe_dir>\Reports\ssd_benchmark_history.log` — alongside the existing
/// evidence/report tree, not a new top-level location.
#[cfg_attr(not(test), allow(dead_code))] // legacy location (read-only now)
pub fn history_file_path(exe_dir: &Path) -> PathBuf {
    exe_dir.join("Reports").join("ssd_benchmark_history.log")
}

/// Every history known under `<exe>\Reports`: each report folder's
/// `ssd_benchmark_history.log` plus the legacy root file (read only), so a
/// new run compares against earlier days too.
pub fn load_all_history(reports_root: &Path) -> Vec<HistoryEntry> {
    let name = "ssd_benchmark_history.log";
    let mut all = load_history(&reports_root.join(name));
    if let Ok(rd) = fs::read_dir(reports_root) {
        for e in rd.flatten() {
            if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                all.extend(load_history(&e.path().join(name)));
            }
        }
    }
    all.sort_by_key(|e| e.timestamp_unix);
    // The same run can be both in the persistent history and in a report
    // folder's copy: count it once.
    let mut seen: Vec<String> = Vec::new();
    all.retain(|e| {
        let key = e.serialize();
        if seen.contains(&key) {
            false
        } else {
            seen.push(key);
            true
        }
    });
    all
}

/// v0.4.0: the persistent SSD history of this portable WinStateDiag,
/// `<exe>\Reports\History\ssd_benchmark_history.log`. It is application
/// state, not session evidence: the report folder's copy goes into the
/// ZIP (and is then removed with the other loose evidence), this file
/// stays so later benchmarks still compare against earlier results.
/// `load_all_history` reads it like any report folder's history.
pub fn canonical_history_path(reports_root: &Path) -> PathBuf {
    reports_root
        .join("History")
        .join("ssd_benchmark_history.log")
}

/// Entries of a history text (corrupt lines skipped).
pub fn parse_history(text: &str) -> Vec<HistoryEntry> {
    text.lines().filter_map(HistoryEntry::parse).collect()
}

/// Appends to `path` every entry it does not already hold (idempotent).
pub fn merge_into(path: &Path, entries: &[HistoryEntry]) -> io::Result<()> {
    let existing: Vec<String> = load_history(path).iter().map(|e| e.serialize()).collect();
    let mut added: Vec<String> = Vec::new();
    for e in entries {
        let line = e.serialize();
        if !existing.contains(&line) && !added.contains(&line) {
            added.push(line);
        }
    }
    if added.is_empty() {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    for line in added {
        writeln!(file, "{line}")?;
    }
    Ok(())
}

/// Loads all readable entries. Missing file = empty history (first run).
/// Corrupt lines are silently skipped — never a hard failure.
pub fn load_history(path: &Path) -> Vec<HistoryEntry> {
    match fs::read_to_string(path) {
        Ok(content) => content.lines().filter_map(HistoryEntry::parse).collect(),
        Err(_) => Vec::new(),
    }
}

/// Appends one successful benchmark result. Creates the Reports directory
/// if it does not exist yet (e.g. no diagnostic session has run there).
pub fn append_entry(path: &Path, entry: &HistoryEntry) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "{}", entry.serialize())?;
    Ok(())
}

/// Most recent entry compatible with `current`, excluding `current` itself
/// (compare by identity, not just equality, so the just-appended run never
/// matches itself when it is passed in as `current`).
pub fn find_previous_compatible(
    history: &[HistoryEntry],
    current: &HistoryEntry,
) -> Option<HistoryEntry> {
    history
        .iter()
        .filter(|e| e.is_compatible_with(current) && e.timestamp_unix < current.timestamp_unix)
        .max_by_key(|e| e.timestamp_unix)
        .cloned()
}

/// Factual percentage delta of `current` vs `previous`. `None` when the
/// comparison would be meaningless (zero/negative/non-finite baseline).
pub fn delta_percent(current: f64, previous: f64) -> Option<f64> {
    if !previous.is_finite() || !current.is_finite() || previous <= 0.0 {
        return None;
    }
    Some((current - previous) / previous * 100.0)
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Best-effort drive root ("C:\\") for an arbitrary path.
fn drive_root(dir: &Path) -> String {
    let s = dir.to_string_lossy();
    if let Some(colon_pos) = s.find(':') {
        if colon_pos >= 1 {
            let drive_letter = &s[colon_pos - 1..colon_pos + 1];
            return format!("{drive_letter}\\");
        }
    }
    "\\".to_string()
}

/// Stable identity for the physical disk backing `dir`'s drive: the volume
/// serial number, which survives drive-letter reassignment far better than
/// the letter alone. Falls back to a clearly-marked "unknown" identity if
/// the OS call fails (still self-consistent, never fabricated).
pub fn disk_identity_for(dir: &Path) -> String {
    let root = drive_root(dir);
    let wide: Vec<u16> = OsStr::new(&root)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut serial: u32 = 0;
    let ok = unsafe {
        GetVolumeInformationW(
            wide.as_ptr(),
            null_mut(),
            0,
            &mut serial,
            null_mut(),
            null_mut(),
            null_mut(),
            0,
        )
    };
    if ok != 0 {
        format!("{root}#{serial:08X}")
    } else {
        format!("{root}#UNKNOWN")
    }
}

/// Identity to actually store in a [`HistoryEntry`] (v0.3.6, multi-SSD):
/// prefers `physical` — a `storage_topology::physical_disk_identity` model+
/// serial string, which stays correct across drive-letter reassignment and
/// never confuses two different physical SSDs — and only falls back to the
/// older volume-serial identity (`disk_identity_for`) when no physical-disk
/// identity is available. Existing history written before v0.3.6 keeps
/// comparing correctly against itself (same fallback identity, unchanged);
/// it simply won't match a physical-identity entry from a later run on the
/// same disk, which is the safe direction to fail in (no previous rather
/// than a wrongly-matched previous).
pub fn disk_identity_with_physical(dir: &Path, physical: Option<&str>) -> String {
    match physical {
        Some(id) if !id.is_empty() => id.to_string(),
        _ => disk_identity_for(dir),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(ts: u64, disk: &str, read: f64, write: f64) -> HistoryEntry {
        HistoryEntry {
            timestamp_unix: ts,
            disk_identity: disk.to_string(),
            block_size: 1024 * 1024,
            queue_depth: 4,
            test_file_size: 512 * 1024 * 1024,
            pass_count: 4,
            read_mib_s: read,
            write_mib_s: write,
        }
    }

    // 1. first run / no previous
    #[test]
    fn no_previous_on_first_run() {
        let history: Vec<HistoryEntry> = Vec::new();
        let current = entry(1000, "C:\\#AAAAAAAA", 500.0, 400.0);
        assert!(find_previous_compatible(&history, &current).is_none());
    }

    // 2. same disk + same profile -> compatible, found
    #[test]
    fn same_disk_same_profile_is_compatible() {
        let previous = entry(900, "C:\\#AAAAAAAA", 480.0, 390.0);
        let history = vec![previous.clone()];
        let current = entry(1000, "C:\\#AAAAAAAA", 500.0, 400.0);
        let found = find_previous_compatible(&history, &current).expect("should find previous");
        assert_eq!(found.timestamp_unix, previous.timestamp_unix);
    }

    // 3. different disk -> not compatible
    #[test]
    fn different_disk_is_not_compatible() {
        let previous = entry(900, "D:\\#BBBBBBBB", 480.0, 390.0);
        let history = vec![previous];
        let current = entry(1000, "C:\\#AAAAAAAA", 500.0, 400.0);
        assert!(find_previous_compatible(&history, &current).is_none());
    }

    // 4. different profile -> not compatible
    #[test]
    fn different_profile_is_not_compatible() {
        let mut previous = entry(900, "C:\\#AAAAAAAA", 480.0, 390.0);
        previous.block_size = 4 * 1024; // different block size
        let history = vec![previous];
        let current = entry(1000, "C:\\#AAAAAAAA", 500.0, 400.0);
        assert!(find_previous_compatible(&history, &current).is_none());
    }

    // 5. corrupt history ignored safely
    #[test]
    fn corrupt_lines_are_skipped_not_fatal() {
        let content =
            "not-a-valid-line\n1000|C:\\#AAAAAAAA|1048576|4|536870912|4|500.0|400.0\n|||\nbanana\n";
        let parsed: Vec<HistoryEntry> = content.lines().filter_map(HistoryEntry::parse).collect();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].timestamp_unix, 1000);
    }

    // 6. delta positive
    #[test]
    fn delta_positive_when_current_faster() {
        let d = delta_percent(550.0, 500.0).unwrap();
        assert!((d - 10.0).abs() < 0.001);
    }

    // 7. delta negative
    #[test]
    fn delta_negative_when_current_slower() {
        let d = delta_percent(450.0, 500.0).unwrap();
        assert!((d - (-10.0)).abs() < 0.001);
    }

    // 8. zero/invalid values handled safely
    #[test]
    fn delta_none_on_invalid_baseline() {
        assert!(delta_percent(500.0, 0.0).is_none());
        assert!(delta_percent(500.0, -10.0).is_none());
        assert!(delta_percent(500.0, f64::NAN).is_none());
        assert!(delta_percent(f64::INFINITY, 500.0).is_none());

        // A malformed line with a negative speed must not parse as a valid entry.
        let bad = "1000|C:\\#AAAAAAAA|1048576|4|536870912|4|-5.0|400.0";
        assert!(HistoryEntry::parse(bad).is_none());
    }

    // 9. successful current becomes previous on next compatible run
    #[test]
    fn round_trip_append_and_reload_then_becomes_previous() {
        let dir = std::env::temp_dir().join(format!("wsd-ssd-history-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let path = history_file_path(&dir);

        let run1 = entry(1000, "C:\\#AAAAAAAA", 500.0, 400.0);
        append_entry(&path, &run1).expect("append should succeed");

        let reloaded = load_history(&path);
        assert_eq!(reloaded.len(), 1);
        assert_eq!(reloaded[0], run1);

        let run2 = entry(2000, "C:\\#AAAAAAAA", 520.0, 410.0);
        append_entry(&path, &run2).expect("append should succeed");
        let reloaded = load_history(&path);
        assert_eq!(reloaded.len(), 2);

        let previous = find_previous_compatible(&reloaded, &run2).expect("run1 should be previous");
        assert_eq!(previous.timestamp_unix, run1.timestamp_unix);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_history_file_yields_empty_history() {
        let dir =
            std::env::temp_dir().join(format!("wsd-ssd-history-missing-{}", std::process::id()));
        let path = history_file_path(&dir);
        assert!(load_history(&path).is_empty());
    }

    #[test]
    fn drive_root_extracts_letter_from_windows_path() {
        assert_eq!(drive_root(Path::new("C:\\Users\\test")), "C:\\");
        assert_eq!(drive_root(Path::new("D:\\temp")), "D:\\");
    }

    // v0.3.6 multi-SSD: physical-disk-identity keying.

    #[test]
    fn disk_identity_with_physical_prefers_the_physical_identity() {
        let id = disk_identity_with_physical(Path::new("C:\\Reports"), Some("PHYS#Samsung#S1"));
        assert_eq!(id, "PHYS#Samsung#S1");
    }

    #[test]
    fn disk_identity_with_physical_falls_back_without_one() {
        // No physical identity supplied (e.g. enumeration failed): falls
        // back to the pre-v0.3.6 volume-based identity, never panics.
        let id = disk_identity_with_physical(Path::new("C:\\Reports"), None);
        assert!(id.starts_with("C:\\#"));
        let id_empty = disk_identity_with_physical(Path::new("C:\\Reports"), Some(""));
        assert!(id_empty.starts_with("C:\\#"));
    }

    /// Two different physical SSDs benchmarked in the same session/history
    /// file each keep their own, separate previous/current comparison — a
    /// Samsung's previous result is never offered as "previous" for a
    /// Netac, even though both entries live in the same history log.
    #[test]
    fn two_physical_disks_keep_independent_history_even_in_one_log() {
        let samsung_prev = entry(900, "PHYS#Samsung 9100 PRO#S1", 6000.0, 5500.0);
        let netac_prev = entry(910, "PHYS#Netac NV7000T#S2", 3000.0, 2800.0);
        let history = vec![samsung_prev.clone(), netac_prev.clone()];

        let samsung_current = entry(2000, "PHYS#Samsung 9100 PRO#S1", 6100.0, 5600.0);
        let found = find_previous_compatible(&history, &samsung_current).expect("Samsung previous");
        assert_eq!(found.timestamp_unix, samsung_prev.timestamp_unix);

        let netac_current = entry(2010, "PHYS#Netac NV7000T#S2", 3050.0, 2850.0);
        let found = find_previous_compatible(&history, &netac_current).expect("Netac previous");
        assert_eq!(found.timestamp_unix, netac_prev.timestamp_unix);

        // Never cross-matched: a Samsung run must never surface a Netac
        // "previous" or vice versa.
        assert_ne!(
            find_previous_compatible(&history, &samsung_current)
                .unwrap()
                .disk_identity,
            netac_prev.disk_identity
        );
    }

    /// A drive-letter change (the same physical disk reassigned from D: to
    /// E:, say) must not lose history: the physical identity does not
    /// mention a letter at all, so it stays compatible.
    #[test]
    fn physical_identity_survives_a_drive_letter_change() {
        let previous = entry(900, "PHYS#Netac NV7000T#S2", 3000.0, 2800.0);
        let history = vec![previous.clone()];
        // Same physical disk, now reachable at a different letter — the
        // identity we store never encoded the letter, so it is unaffected.
        let current = entry(2000, "PHYS#Netac NV7000T#S2", 3050.0, 2850.0);
        let found = find_previous_compatible(&history, &current).expect("still compatible");
        assert_eq!(found.timestamp_unix, previous.timestamp_unix);
    }
}
