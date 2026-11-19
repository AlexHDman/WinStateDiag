//! Per-user state; no preferences beside the portable EXE.
use std::{
    fs,
    path::{Path, PathBuf},
};
pub fn data_root(exe: &Path) -> PathBuf {
    #[cfg(test)]
    return exe.join(".test-user-profile");
    #[cfg(not(test))]
    {
        let _ = exe;
        std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
            .join("EXPC")
            .join("WinStateDiag")
    }
}
/// Copy recognized data only; originals and conflicting versions survive.
pub fn migrate_legacy(exe: &Path) -> std::io::Result<()> {
    let root = data_root(exe);
    fs::create_dir_all(&root)?;
    copy_missing(
        &exe.join("WinStateDiag.client"),
        &root.join("WinStateDiag.client.legacy-unverified"),
    )?;
    for name in ["WinStateDiag.lang"] {
        copy_missing(&exe.join(name), &root.join(name))?;
    }
    copy_tree(&exe.join("WinStateDiagData"), &root)?;
    copy_tree(&exe.join("Reports/Logs"), &root.join("Logs"))?;
    copy_tree(&exe.join("Reports/History"), &root.join("History"))?;
    for name in [
        "WinStateDiag_StorageHistory.json",
        "ssd_benchmark_history.log",
    ] {
        copy_missing(&exe.join("Reports").join(name), &root.join(name))?;
    }
    Ok(())
}
fn copy_missing(source: &Path, target: &Path) -> std::io::Result<()> {
    use std::io::Write;
    if is_link(source)? || !source.is_file() {
        return Ok(());
    }
    let bytes = fs::read(source)?;
    let mut target = target.to_path_buf();
    if target.exists() {
        if fs::read(&target)? == bytes {
            return Ok(());
        }
        let mut hash = 0xcbf29ce484222325u64;
        for b in &bytes {
            hash = (hash ^ u64::from(*b)).wrapping_mul(0x100000001b3);
        }
        target = target.with_file_name(format!(
            "{}.legacy-{hash:016x}",
            target.file_name().unwrap().to_string_lossy()
        ));
        if target.exists() {
            return if fs::read(&target)? == bytes {
                Ok(())
            } else {
                Err(std::io::Error::other(
                    "Legacy conflict backup differs; originals preserved",
                ))
            };
        }
    }
    fs::create_dir_all(target.parent().unwrap())?;
    let mut out = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&target)?;
    let saved = out.write_all(&bytes).and_then(|_| out.sync_all());
    drop(out);
    if saved.is_err() {
        // Only the file exclusively created above is ours to remove.
        let _ = fs::remove_file(&target);
    }
    saved
}
fn is_link(path: &Path) -> std::io::Result<bool> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        Ok(meta.file_attributes() & 0x400 != 0)
    }
    #[cfg(not(windows))]
    Ok(meta.file_type().is_symlink())
}
fn copy_tree(source: &Path, target: &Path) -> std::io::Result<()> {
    if is_link(source)? || !source.is_dir() {
        return Ok(());
    }
    for e in fs::read_dir(source)? {
        let e = e?;
        let ty = e.file_type()?;
        if is_link(&e.path())? {
            continue;
        }
        if ty.is_dir() {
            copy_tree(&e.path(), &target.join(e.file_name()))?;
        } else if ty.is_file() {
            copy_missing(&e.path(), &target.join(e.file_name()))?;
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rc6_migrates_reports_history_and_logs_preserving_originals() {
        let exe = std::env::temp_dir().join(format!("wsd-rc6-old-reports-{}", std::process::id()));
        fs::create_dir_all(exe.join("Reports/History")).unwrap();
        fs::create_dir_all(exe.join("Reports/Logs")).unwrap();
        fs::write(exe.join("Reports/History/ssd_benchmark_history.log"), "old").unwrap();
        fs::write(exe.join("Reports/Logs/session.log"), "evidence").unwrap();
        fs::write(exe.join("Reports/client.zip"), "do not migrate archive").unwrap();
        migrate_legacy(&exe).unwrap();
        assert_eq!(
            fs::read(data_root(&exe).join("History/ssd_benchmark_history.log")).unwrap(),
            b"old"
        );
        assert!(data_root(&exe).join("Logs/session.log").is_file());
        assert!(!data_root(&exe).join("client.zip").exists());
        fs::write(
            data_root(&exe).join("History/ssd_benchmark_history.log"),
            "current",
        )
        .unwrap();
        migrate_legacy(&exe).unwrap();
        migrate_legacy(&exe).unwrap();
        assert_eq!(
            fs::read(data_root(&exe).join("History/ssd_benchmark_history.log")).unwrap(),
            b"current"
        );
        assert_eq!(
            fs::read(exe.join("Reports/History/ssd_benchmark_history.log")).unwrap(),
            b"old"
        );
        fs::remove_dir_all(exe).unwrap();
    }

    #[test]
    fn migration_preserves_confirmed_client_history_conflicts_and_originals() {
        let exe = std::env::temp_dir().join(format!("wsd-rc6-migrate-{}", std::process::id()));
        fs::create_dir_all(exe.join("WinStateDiagData/History")).unwrap();
        fs::write(exe.join("WinStateDiag.client"), "Client").unwrap();
        fs::write(exe.join("WinStateDiagData/History/disk.json"), "history").unwrap();
        migrate_legacy(&exe).unwrap();
        fs::write(data_root(&exe).join("WinStateDiag.client"), "Confirmed").unwrap();
        migrate_legacy(&exe).unwrap();
        migrate_legacy(&exe).unwrap();
        assert_eq!(
            fs::read_to_string(data_root(&exe).join("WinStateDiag.client")).unwrap(),
            "Confirmed"
        );
        assert_eq!(
            fs::read_to_string(data_root(&exe).join("History/disk.json")).unwrap(),
            "history"
        );
        assert!(exe.join("WinStateDiag.client").exists());
        fs::remove_dir_all(exe).unwrap();
    }
}

#[cfg(test)]
#[test]
fn rc10_foreign_portable_client_is_preserved_without_activation() {
    let exe = std::env::temp_dir().join(format!("wsd-rc10-foreign-{}", std::process::id()));
    std::fs::create_dir_all(&exe).unwrap();
    std::fs::write(exe.join("WinStateDiag.client"), "Foreign client").unwrap();
    migrate_legacy(&exe).unwrap();
    assert!(!data_root(&exe).join("WinStateDiag.client").exists());
    assert_eq!(
        std::fs::read_to_string(data_root(&exe).join("WinStateDiag.client.legacy-unverified"))
            .unwrap(),
        "Foreign client"
    );
    assert!(exe.join("WinStateDiag.client").exists());
}
