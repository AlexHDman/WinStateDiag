use super::*;
use crate::report_package::{EvidenceFile, build_zip};
use std::io::Cursor;

fn root(tag: &str) -> PathBuf {
    super::super::tests::temp(tag)
}
fn source(root: &Path) -> Input {
    let zip = root.join("Клиент-ПК-16.11.26-20.00.zip");
    let files = [EvidenceFile::new("State_Summary.txt", "SENSORS: PARTIAL\nТемпература GPU: 36.5 °C\nCPU: Intel Core i7\npassword=sample-test-secret\n".as_bytes().to_vec()), EvidenceFile::new("manifest.json", br#"{"mode":"full","client":"Sample Client","computer":"TEST-PC","session_id":"test-session"}"#.to_vec())];
    fs::write(
        &zip,
        build_zip(&files, crate::ui::sysinfo::local_time()).unwrap(),
    )
    .unwrap();
    Input::zip(zip)
}
fn no_pending(root: &Path) {
    assert!(
        !fs::read_dir(root)
            .unwrap()
            .filter_map(Result::ok)
            .any(|e| e.file_name().to_string_lossy().starts_with(".wsd-ai-"))
    );
}
// Preserve the frozen 1.4 generator oracle. Only the public version header changes;
// all diagnostic bytes, masking, BOM and newlines remain compared exactly.
fn legacy_for_current_version() -> String {
    let original = include_str!("../scripts/fixtures/ai-zip/legacy-ai.txt");
    assert_eq!(original.matches("VERSION: 1.4 | EXPORT_SCHEMA:").count(), 1);
    original.replacen(
        "VERSION: 1.4 | EXPORT_SCHEMA:",
        &format!("VERSION: {} | EXPORT_SCHEMA:", crate::APP_VERSION),
        1,
    )
}
#[test]
fn unchanged_generator_utf8_is_byte_identical_to_pre_change_fixture() {
    let root = root("zip golden кириллица и пробелы");
    let input = source(&root);
    let out = export(&input, &root).unwrap();
    let expected = legacy_for_current_version();
    assert_eq!(exported_text(&out.path), expected);
    assert_eq!(out.text_bytes, expected.len() as u64);
    assert!(out.zip_bytes < out.text_bytes);
    assert_eq!(
        out.path.file_name().unwrap(),
        "Клиент-ПК-16.11.26-20.00.AI.zip"
    );
    let mut zip = File::open(&out.path).unwrap();
    let entries = zip_index(&mut zip).unwrap();
    assert_eq!(entries[0].name, "Клиент-ПК-16.11.26-20.00.AI.txt");
    assert_eq!(entries[0].method, 8);
    no_pending(&root);
}
#[test]
fn parallel_repeat_keeps_old_txt_zip_sources_and_foreign_temps() {
    let root = root("collision");
    let input = source(&root);
    let old_txt = root.join("Клиент-ПК-16.11.26-20.00.AI.txt");
    let old_zip = root.join("Клиент-ПК-16.11.26-20.00.AI.zip");
    let foreign = root.join("foreign.partial");
    for p in [&old_txt, &old_zip, &foreign] {
        fs::write(p, b"previous user file").unwrap();
    }
    let before = fs::read(input.zip.as_ref().unwrap()).unwrap();
    let workers: Vec<_> = (0..3)
        .map(|_| {
            let input = input.clone();
            let root = root.clone();
            std::thread::spawn(move || export(&input, &root).unwrap())
        })
        .collect();
    let mut paths = BTreeSet::new();
    for worker in workers {
        let out = worker.join().unwrap();
        assert!(paths.insert(out.path.clone()));
        assert_eq!(exported_text(&out.path), legacy_for_current_version());
        let mut zip = File::open(&out.path).unwrap();
        let name = zip_index(&mut zip).unwrap()[0].name.clone();
        assert_eq!(
            name,
            out.path.file_stem().unwrap().to_string_lossy().to_string() + ".txt"
        );
    }
    for p in [&old_txt, &old_zip, &foreign] {
        assert_eq!(fs::read(p).unwrap(), b"previous user file");
    }
    assert_eq!(fs::read(input.zip.unwrap()).unwrap(), before);
    no_pending(&root);
}
#[test]
fn failed_generation_cleans_only_owned_temps_and_no_final_archive() {
    let root = root("failed generation");
    let input = source(&root);
    fs::write(input.zip.as_ref().unwrap(), b"invalid ZIP").unwrap();
    assert!(export(&input, &root).is_err());
    no_pending(&root);
    assert_eq!(fs::read_dir(root).unwrap().count(), 1);
}
#[test]
fn deflate_crc_truncation_and_wrong_text_are_rejected_before_publication() {
    let root = root("verify failure");
    let plain_path = root.join("expected.txt");
    fs::write(&plain_path, "UTF-8 данные\n".repeat(2000)).unwrap();
    let path = root.join("owned.partial");
    let mut zip = Cursor::new(Vec::new());
    write_zip(
        &mut File::open(&plain_path).unwrap(),
        &mut zip,
        "Результат.AI.txt",
    )
    .unwrap();
    let good = zip.into_inner();
    fs::write(&path, &good).unwrap();
    assert!(
        verify(
            &path,
            &mut File::open(&plain_path).unwrap(),
            "Результат.AI.txt"
        )
        .is_ok()
    );
    for corruption in 0..4 {
        let mut bad = good.clone();
        match corruption {
            0 => {
                bad.pop();
            }
            1 => {
                bad[14] ^= 1;
            }
            2 => {
                let p = bad
                    .windows(4)
                    .position(|s| s == [0x50, 0x4b, 1, 2])
                    .unwrap();
                bad[p + 16] ^= 1;
            }
            _ => {
                bad[60] ^= 0x80;
            }
        }
        fs::write(&path, bad).unwrap();
        assert!(
            verify(
                &path,
                &mut File::open(&plain_path).unwrap(),
                "Результат.AI.txt"
            )
            .is_err(),
            "case {corruption}"
        );
    }
    fs::write(&path, good).unwrap();
    fs::write(&plain_path, "DIFFERENT").unwrap();
    assert!(
        verify(
            &path,
            &mut File::open(&plain_path).unwrap(),
            "Результат.AI.txt"
        )
        .is_err()
    );
    assert!(!root.join("Результат.AI.zip").exists());
}
struct FailWrite {
    inner: Cursor<Vec<u8>>,
    allowance: usize,
}
impl Write for FailWrite {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        if b.len() > self.allowance {
            return Err(io::Error::other("simulated disk full"));
        }
        self.allowance -= b.len();
        self.inner.write(b)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl Seek for FailWrite {
    fn seek(&mut self, p: SeekFrom) -> io::Result<u64> {
        self.inner.seek(p)
    }
}
#[test]
fn write_errors_in_header_deflate_and_directory_never_report_success() {
    let bytes = b"streaming data\n".repeat(6000);
    let mut reference = Cursor::new(Vec::new());
    write_zip(&mut Cursor::new(&bytes), &mut reference, "x.AI.txt").unwrap();
    // Seek-back patch adds 12 writes beyond the final file length.
    let total_written = reference.get_ref().len() + 12;
    for allowance in [0, 40, total_written - 1] {
        let mut out = FailWrite {
            inner: Cursor::new(Vec::new()),
            allowance,
        };
        assert!(write_zip(&mut Cursor::new(&bytes), &mut out, "x.AI.txt").is_err());
    }
}
#[test]
fn publication_race_never_replaces_an_existing_archive() {
    let root = root("publish race");
    let source = root.join("own.partial");
    let final_path = root.join("existing.AI.zip");
    fs::write(&source, b"new").unwrap();
    fs::write(&final_path, b"old").unwrap();
    assert!(crate::report_package::rename_archive(&source, &final_path, false).is_err());
    assert_eq!(fs::read(&final_path).unwrap(), b"old");
    assert_eq!(fs::read(&source).unwrap(), b"new");
}
#[test]
#[ignore = "explicit local before/after comparison, requires captured pre-change fixtures"]
fn windows_large_oracle_comparison() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("release-evidence/v1.4/ai-zip-20261116/Сравнение AI с пробелами");
    for tag in ["small", "large"] {
        let dir = root.join(tag);
        let input = Input::zip(dir.join("Клиент-ПК-16.11.26-20.00.zip"));
        let before = fs::read(input.zip.as_ref().unwrap()).unwrap();
        let out = export(&input, &dir).unwrap();
        let oracle = dir.join("Клиент-ПК-16.11.26-20.00.AI.txt");
        assert_eq!(
            exported_text(&out.path).as_bytes(),
            fs::read(&oracle).unwrap()
        );
        assert_eq!(fs::read(input.zip.unwrap()).unwrap(), before);
        assert_eq!(out.limited, 0);
        println!(
            "VERIFIED {tag}: TXT={} ZIP={} {}",
            out.text_bytes,
            out.zip_bytes,
            out.path.display()
        );
        no_pending(&dir);
    }
}

#[test]
fn export_into_session_directory_does_not_include_own_temporary_files() {
    let root = root("same directory");
    fs::write(root.join("State_Summary.txt"), "PARTIAL: GPU 36 °C").unwrap();
    let input = Input {
        zip: None,
        directory: Some(root.clone()),
        base: "Client-PC-16.11.26".into(),
    };
    let out = export(&input, &root).unwrap();
    assert_eq!(out.included, 1);
    assert_eq!(out.omitted, 0);
    let text = exported_text(out.path);
    assert!(text.contains("ENTRIES: 1"));
    assert!(!text.contains(".partial"));
    no_pending(&root);
}
