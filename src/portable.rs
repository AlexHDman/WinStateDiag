//! Single-EXE payload preparation. No driver installation, execution or UAC here.
use std::os::windows::fs::OpenOptionsExt;
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
struct Entry {
    name: &'static str,
    size: u64,
    sha: &'static str,
    offset: usize,
    length: usize,
}
include!(concat!(env!("OUT_DIR"), "/portable-payload.rs"));
const BLOB: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/portable-payload.bin"));
pub struct Prepared {
    pub root: PathBuf,
    _guards: Vec<File>,
}
fn fail(s: impl ToString) -> String {
    s.to_string()
}
fn safe_name(name: &str) -> bool {
    !name.is_empty()
        && name.split('/').all(|p| {
            !p.is_empty()
                && p != "."
                && p != ".."
                && !p.contains(['\\', ':'])
                && !p.ends_with(['.', ' '])
                && !p.chars().any(char::is_control)
        })
}
/// Directory handles prevent replacing an ancestor after validation.
fn hold_dir(path: &Path) -> Result<File, String> {
    let meta = fs::symlink_metadata(path).map_err(fail)?;
    use std::os::windows::fs::MetadataExt;
    if !meta.is_dir() || meta.file_attributes() & 0x400 != 0 {
        return Err(format!(
            "Небезопасный служебный каталог: {}",
            path.display()
        ));
    }
    OpenOptions::new()
        .read(true)
        .share_mode(3)
        .custom_flags(0x02000000)
        .open(path)
        .map_err(fail)
}
fn directories(
    path: &Path,
    guards: &mut Vec<File>,
    seen: &mut std::collections::BTreeSet<PathBuf>,
) -> Result<(), String> {
    let mut parents: Vec<_> = path.ancestors().collect();
    parents.reverse();
    for p in parents {
        if !seen.insert(p.to_path_buf()) {
            continue;
        }
        if !p.exists() {
            match fs::create_dir(p) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(fail(e)),
            }
        }
        guards.push(hold_dir(p)?);
    }
    Ok(())
}
fn verify(file: &mut File, entry: &Entry) -> Result<(), String> {
    if file.metadata().map_err(fail)?.len() != entry.size {
        return Err(format!("Размер компонента не совпадает: {}", entry.name));
    }
    file.rewind().map_err(fail)?;
    if crate::content_hash::sha256(file).map_err(fail)? != entry.sha {
        return Err(format!("SHA256 компонента не совпадает: {}", entry.name));
    }
    Ok(())
}

fn reject_unexpected(
    root: &Path,
    dir: &Path,
    names: &std::collections::BTreeSet<String>,
    count: &mut usize,
) -> Result<(), String> {
    use std::os::windows::fs::MetadataExt;
    for entry in fs::read_dir(dir).map_err(fail)? {
        let entry = entry.map_err(fail)?;
        *count += 1;
        if *count > ENTRIES.len() * 4 + 64 {
            return Err("Слишком много объектов в служебном каталоге".into());
        }
        let path = entry.path();
        let meta = fs::symlink_metadata(&path).map_err(fail)?;
        if meta.file_attributes() & 0x400 != 0 {
            return Err("Ссылка в служебном каталоге запрещена".into());
        }
        let name = path
            .strip_prefix(root)
            .map_err(fail)?
            .to_string_lossy()
            .replace('\\', "/")
            .to_ascii_lowercase();
        if meta.is_dir() {
            let prefix = format!("{name}/");
            if !names.iter().any(|n| n.starts_with(&prefix)) {
                return Err(format!("Неизвестный каталог зависимостей: {name}"));
            }
            reject_unexpected(root, &path, names, count)?;
        } else if name != "prepare.lock" && !names.contains(&name) {
            return Err(format!(
                "Неизвестный компонент сохранён; запуск запрещён: {name}"
            ));
        }
    }
    Ok(())
}

fn extract(root: &Path, entries: &[Entry], blob: &[u8]) -> Result<Prepared, String> {
    let mut guards = vec![];
    let mut seen = std::collections::BTreeSet::new();
    directories(root, &mut guards, &mut seen)?;
    // Persistent file, exclusively opened. The OS releases the lock even on a crash.
    let lock_path = root.join("prepare.lock");
    let until = Instant::now() + Duration::from_secs(30);
    let lock = loop {
        match OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .share_mode(0)
            .open(&lock_path)
        {
            Ok(f) => break f,
            Err(e) if e.raw_os_error() == Some(32) && Instant::now() < until => {
                std::thread::sleep(Duration::from_millis(30))
            }
            Err(e) => return Err(format!("Подготовка зависимостей: {e}")),
        }
    };
    let names = entries
        .iter()
        .map(|e| e.name.to_ascii_lowercase())
        .collect();
    reject_unexpected(root, root, &names, &mut 0)?;
    for entry in entries {
        if !safe_name(entry.name) || entry.size > 32 * 1024 * 1024 {
            return Err("Небезопасная запись встроенного ресурса".into());
        }
        let bytes = blob
            .get(
                entry.offset
                    ..entry
                        .offset
                        .checked_add(entry.length)
                        .ok_or("Payload bounds")?,
            )
            .ok_or("Payload bounds")?;
        let path = root.join(entry.name);
        directories(
            path.parent().ok_or("Payload parent")?,
            &mut guards,
            &mut seen,
        )?;
        if !path.exists() {
            // No replacement: foreign/corrupt files are preserved and fail closed.
            let mut out = OpenOptions::new()
                .write(true)
                .create_new(true)
                .share_mode(0)
                .open(&path)
                .map_err(fail)?;
            let result = (|| {
                let mut decoder = flate2::read::GzDecoder::new(bytes).take(entry.size + 1);
                let count = io::copy(&mut decoder, &mut out).map_err(fail)?;
                if count != entry.size {
                    return Err(format!("Повреждён встроенный ресурс {}", entry.name));
                }
                out.flush().and_then(|_| out.sync_all()).map_err(fail)
            })();
            drop(out);
            if let Err(error) = result {
                let _ = fs::remove_file(&path);
                return Err(error);
            }
        }
        use std::os::windows::fs::MetadataExt;
        let meta = fs::symlink_metadata(&path).map_err(fail)?;
        if !meta.is_file() || meta.file_attributes() & 0x400 != 0 {
            return Err(format!("Подмена компонента: {}", entry.name));
        }
        let mut file = OpenOptions::new()
            .read(true)
            .share_mode(1)
            .open(&path)
            .map_err(fail)?;
        verify(&mut file, entry)?;
        guards.push(file);
    }
    drop(lock);
    Ok(Prepared {
        root: root.into(),
        _guards: guards,
    })
}
pub fn prepare() -> Result<Prepared, String> {
    let base = std::env::var_os("LOCALAPPDATA")
        .ok_or("LOCALAPPDATA недоступен; зависимости не подготовлены")?;
    let root = PathBuf::from(base)
        .join("EXPC/WinStateDiag/Runtime")
        .join(format!("{}-{}", crate::APP_VERSION, &PAYLOAD_ID[..16]));
    extract(&root, ENTRIES, BLOB)
}
pub fn license_text() -> &'static str {
    "WinDiag / PowerLab — EXPC.\nLibreHardwareMonitorLib и совместимые библиотеки — MPL-2.0.\nPawnIO.Modules — LGPL-2.1-or-later; соответствующие исходники сохранены.\nОфициальный неизменённый PawnIO installer — отдельные условия namazso.\n.NET runtime и Rust-зависимости — собственные лицензии и Third Party Notices.\nПолные тексты, уведомления и соответствующие исходники доступны ниже. Установка драйвера выполняется только по отдельному нажатию."
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reject_unsafe_paths() {
        for n in [
            "../x", "/root", "C:/x", "a\\b", "a//b", "a/..", "a:stream", "a.",
        ] {
            assert!(!safe_name(n), "{n}")
        }
        assert!(safe_name("PowerLab/hardware-helper/x.dll"));
    }
    #[test]
    fn indexed_payload_is_bounded_and_unique() {
        let mut names = std::collections::BTreeSet::new();
        for e in ENTRIES {
            assert!(safe_name(e.name));
            assert!(names.insert(e.name));
            assert!(
                BLOB.get(e.offset..e.offset.checked_add(e.length).unwrap())
                    .is_some()
            );
            assert!(e.size <= 32 * 1024 * 1024);
        }
        let mut chunks = std::collections::BTreeMap::new();
        for entry in ENTRIES {
            let current = (entry.offset, entry.length, entry.size);
            if let Some(prior) = chunks.insert(entry.sha, current) {
                assert_eq!(prior, current);
            }
        }
        assert!(chunks.len() < ENTRIES.len());
        assert_eq!(
            chunks.values().map(|(_, length, _)| *length).sum::<usize>(),
            BLOB.len()
        );
        assert!(names.contains("PowerLab/powerlab-sampler.exe"));
        assert!(
            names
                .iter()
                .any(|n| n.contains("PawnIO.Modules-0.2.2-source.zip"))
        );
    }
    #[test]
    fn corruption_fails_closed_and_preserves_foreign_file() {
        let root = std::env::temp_dir().join(format!(
            "wsd-payload-corrupt-{}",
            crate::repair::operation_id()
        ));
        fs::create_dir(&root).unwrap();
        fs::write(root.join("test.txt"), b"foreign").unwrap();
        let e = Entry {
            name: "test.txt",
            size: 7,
            sha: "INVALID",
            offset: 0,
            length: 0,
        };
        assert!(extract(&root, &[e], &[]).is_err());
        assert_eq!(fs::read(root.join("test.txt")).unwrap(), b"foreign");
    }
    #[test]
    #[ignore = "Extracts full embedded payload; explicit Windows POC"]
    fn embedded_payload_concurrent_and_repeat() {
        let base = std::env::temp_dir().join(format!(
            "WinDiag тест с пробелами {}",
            crate::repair::operation_id()
        ));
        let workers: Vec<_> = (0..3)
            .map(|_| {
                let base = base.clone();
                std::thread::spawn(move || extract(&base, ENTRIES, BLOB).unwrap())
            })
            .collect();
        for t in workers {
            let p = t.join().unwrap();
            assert!(p.root.join("PowerLab/powerlab-sampler.exe").is_file());
        }
        let p = extract(&base, ENTRIES, BLOB).unwrap();
        assert!(p.root.join("licenses/hardware/LICENSE").is_file());
        println!("PAYLOAD POC PASS root={}", base.display());
    }
}

pub fn license_entries() -> impl Iterator<Item = (&'static str, u64)> {
    ENTRIES
        .iter()
        .filter(|e| e.name.starts_with("licenses/") || e.name.starts_with("PowerLab/licenses/"))
        .map(|e| (e.name, e.size))
}

pub fn payload_id() -> &'static str {
    PAYLOAD_ID
}
pub fn entry_count() -> usize {
    ENTRIES.len()
}

#[cfg(test)]
mod trust_tests {
    use super::*;
    #[test]
    fn payload_matches_original_pinned_runtime() {
        let manifest = powerlab_core::json::Json::parse(include_str!(
            "../third_party/powerlab-runtime/SHA256SUMS.json"
        ))
        .unwrap();
        for (name, hash) in manifest.as_object().unwrap() {
            let expected = format!("PowerLab/{name}");
            let entry = ENTRIES.iter().find(|e| e.name == expected).unwrap();
            assert_eq!(Some(entry.sha), hash.as_str());
        }
    }
    #[test]
    fn lifetime_locks_prevent_component_replacement() {
        let root = std::env::temp_dir().join(format!(
            "wsd-payload-lease-{}",
            crate::repair::operation_id()
        ));
        fs::create_dir(&root).unwrap();
        fs::write(root.join("safe.txt"), b"abc").unwrap();
        let entry = Entry {
            name: "safe.txt",
            size: 3,
            sha: "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD",
            offset: 0,
            length: 0,
        };
        let held = extract(&root, &[entry], &[]).unwrap();
        assert!(
            OpenOptions::new()
                .write(true)
                .open(root.join("safe.txt"))
                .is_err()
        );
        assert!(fs::rename(root.join("safe.txt"), root.join("replaced")).is_err());
        drop(held);
        assert!(
            OpenOptions::new()
                .write(true)
                .open(root.join("safe.txt"))
                .is_ok()
        );
    }
}

#[cfg(test)]
mod shipping_tests {
    use super::*;
    #[test]
    #[ignore = "Reads shipping PE and extracts only its pinned embedded resource; explicit acceptance"]
    fn shipping_pe_resource_and_runtime_live() {
        let exe = PathBuf::from(std::env::var_os("WSD_SHIPPING_EXE").expect("shipping exe"));
        let evidence = PathBuf::from(std::env::var_os("WSD_POWERLAB_EVIDENCE").expect("evidence"));
        let pe = fs::read(&exe).unwrap();
        let offset = pe
            .windows(64)
            .position(|b| b == &BLOB[..64])
            .expect("payload absent from delivered PE");
        let shipped = &pe[offset..offset + BLOB.len()];
        assert_eq!(crate::content_hash::sha256(shipped).unwrap(), PAYLOAD_ID);
        let root = evidence.join("Извлечённые зависимости из EXE");
        let held = extract(&root, ENTRIES, shipped).unwrap();
        let mut monitor = crate::powerlab::Monitor::default();
        monitor.runtime = Some(root.join("PowerLab/powerlab-sampler.exe"));
        monitor.report_dir = evidence.join("Reports");
        monitor.start();
        let until = Instant::now() + Duration::from_secs(50);
        while monitor.samples() < 5 && monitor.running() && Instant::now() < until {
            monitor.pump();
            std::thread::sleep(Duration::from_millis(10));
        }
        monitor.stop();
        while monitor.running() && Instant::now() < until {
            monitor.pump();
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!monitor.running());
        assert!(monitor.samples() >= 5, "{}", monitor.message);
        fs::write(
            evidence.join("ui-presentation-snapshot.json"),
            monitor.presentation_receipt(),
        )
        .unwrap();
        let before = monitor.samples();
        monitor.open_window();
        monitor.open = false;
        monitor.open_window();
        assert_eq!(before, monitor.samples());
        for _ in 0..2 {
            for format in ["txt", "json", "csv"] {
                monitor.export(format, "Клиент проверка");
                while monitor.saving() && Instant::now() < until {
                    monitor.pump();
                    std::thread::sleep(Duration::from_millis(10));
                }
                assert!(
                    monitor.message.starts_with("Сохранено:"),
                    "{}",
                    monitor.message
                );
            }
        }
        monitor.start();
        while monitor.samples() < before + 3 && monitor.running() && Instant::now() < until {
            monitor.pump();
            std::thread::sleep(Duration::from_millis(10));
        }
        monitor.stop();
        while monitor.running() && Instant::now() < until {
            monitor.pump();
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!monitor.running());
        assert!(monitor.samples() >= before + 3, "{}", monitor.message);
        let files: Vec<_> = fs::read_dir(&monitor.report_dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        assert_eq!(files.len(), 6);
        for file in files.iter().filter(|f| f.extension().unwrap() == "json") {
            let value =
                powerlab_core::json::Json::parse(&fs::read_to_string(file).unwrap()).unwrap();
            assert!(matches!(
                value.get("clean"),
                Some(powerlab_core::json::Json::Bool(true))
            ));
            assert_eq!(
                value.get("sample_count").and_then(|j| j.as_int()),
                Some(before as i64)
            );
        }
        fs::write(evidence.join("shipping-resource-live.txt"),format!("EXE={}\nPayload SHA256={}\nEntries={}\nSamples {} -> {}\nExports TXT/JSON/CSV 2 each\nGUI NOT RUN; component LIVE only\n",exe.display(),PAYLOAD_ID,ENTRIES.len(),before,monitor.samples())).unwrap();
        drop(held);
    }
    #[test]
    fn unknown_cache_component_is_preserved_and_rejected() {
        let root = std::env::temp_dir().join(format!(
            "wsd-payload-unknown-{}",
            crate::repair::operation_id()
        ));
        fs::create_dir(&root).unwrap();
        fs::write(root.join("injected.dll"), b"foreign").unwrap();
        assert!(extract(&root, &[], &[]).is_err());
        assert_eq!(fs::read(root.join("injected.dll")).unwrap(), b"foreign");
    }
}
