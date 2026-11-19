use super::*;
use crate::report_package::{EvidenceFile, build_zip};
pub(super) fn temp(tag: &str) -> PathBuf {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target/ai-export-tests")
        .join(format!(
            "wind_ai_{}_{}_{}",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
    fs::create_dir_all(&p).unwrap();
    p
}
fn archive(root: &Path, files: &[(&str, &[u8])]) -> PathBuf {
    let items: Vec<_> = files
        .iter()
        .map(|(n, b)| EvidenceFile::new(*n, b.to_vec()))
        .collect();
    let p = root.join("Клиент-ПК-10.11.26-12.34.zip");
    fs::write(
        &p,
        build_zip(&items, crate::ui::sysinfo::local_time()).unwrap(),
    )
    .unwrap();
    p
}
#[test]
fn complete_and_repeat_are_read_only_and_preserve_reference_format() {
    let dir = temp("повтор");
    let p = archive(
        &dir,
        &[
            (
                "State_Summary.txt",
                b"SFC: INTEGRITY_VIOLATIONS\nDISM: CLEAN",
            ),
            (
                "manifest.json",
                br#"{"mode":"full","client":"PrivateName"}"#,
            ),
            (
                "Hardware.json",
                br#"{"model":"CPU Model","SerialNumber":"serial-123"}"#,
            ),
        ],
    );
    let before = fs::read(&p).unwrap();
    let input = Input::zip(p.clone());
    let first = export(&input, &dir).unwrap();
    let second = export(&input, &dir).unwrap();
    assert_ne!(first.path, second.path);
    assert_eq!(fs::read(&p).unwrap(), before);
    let text = exported_text(first.path);
    assert!(text.starts_with('\u{feff}'));
    assert!(text.contains("FILE: State_Summary.txt | BYTES:"));
    assert_eq!(text.matches("========== END FILE ==========").count(), 3);
    assert!(text.contains("INTEGRITY_VIOLATIONS"));
    assert!(text.contains("CPU Model"));
    assert!(!text.contains("serial-123"));
    assert!(!text.contains("PrivateName"));
}
#[test]
fn no_zip_uses_saved_session_and_states_incomplete() {
    let dir = temp("fallback");
    let data = dir.join("data");
    fs::create_dir(&data).unwrap();
    fs::write(data.join("Hardware.txt"), "RAM 48 GiB").unwrap();
    let o = export(
        &Input {
            zip: Some(dir.join("missing.zip")),
            directory: Some(data.clone()),
            base: "PC-10.11.26".into(),
        },
        &dir,
    )
    .unwrap();
    assert!(o.incomplete);
    assert!(exported_text(o.path).contains("ZIP отсутствует"));
    assert!(data.join("Hardware.txt").exists());
}
#[test]
fn corrupted_zip_fails_without_silently_using_directory() {
    let dir = temp("bad");
    let p = dir.join("bad.zip");
    fs::write(&p, b"corrupt").unwrap();
    fs::write(dir.join("safe.txt"), b"not fallback").unwrap();
    assert!(
        export(
            &Input {
                zip: Some(p),
                directory: Some(dir.clone()),
                base: "bad".into()
            },
            &dir
        )
        .is_err()
    );
    assert!(!dir.join("bad.AI.zip").exists());
}
#[test]
fn crc_damage_omitted_but_other_evidence_survives() {
    let dir = temp("crc");
    let p = archive(&dir, &[("a.txt", b"FINAL SUCCESS"), ("b.txt", b"second")]);
    let mut b = fs::read(&p).unwrap();
    let i = b.windows(4).position(|x| x == [0x50, 0x4b, 1, 2]).unwrap();
    b[i + 16] ^= 1;
    fs::write(&p, b).unwrap();
    let o = export(&Input::zip(p), &dir).unwrap();
    assert_eq!(o.omitted, 1);
    assert!(o.incomplete);
    assert!(exported_text(o.path).contains("CRC"));
}
#[test]
fn utf8_utf16le_be_and_oem_auto_decode() {
    let text = "Защита ресурсов Windows обнаружила нарушения целостности. Проверка завершена";
    assert_eq!(decode(text.as_bytes(), "x.txt").unwrap().0, text);
    for (be, bom) in [(false, true), (true, true), (false, false), (true, false)] {
        let mut b = if bom {
            if be { vec![254, 255] } else { vec![255, 254] }
        } else {
            vec![]
        };
        for c in text.encode_utf16() {
            b.extend(if be { c.to_be_bytes() } else { c.to_le_bytes() });
        }
        assert_eq!(decode(&b, "x.txt").unwrap().0, text);
    }
    #[cfg(windows)]
    {
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn WideCharToMultiByte(
                cp: u32,
                f: u32,
                s: *const u16,
                n: i32,
                o: *mut u8,
                c: i32,
                d: *const u8,
                u: *mut i32,
            ) -> i32;
        }
        let w: Vec<_> = text.encode_utf16().collect();
        for cp in [1251, 866] {
            let mut b = vec![0u8; w.len() * 2];
            let n = unsafe {
                WideCharToMultiByte(
                    cp,
                    0,
                    w.as_ptr(),
                    w.len() as i32,
                    b.as_mut_ptr(),
                    b.len() as i32,
                    std::ptr::null(),
                    std::ptr::null_mut(),
                )
            };
            b.truncate(n as usize);
            assert_eq!(decode(&b, "stdout.bin").unwrap().0, text, "cp {cp}");
        }
    }
}
#[test]
fn binary_and_broken_utf16_are_not_text() {
    assert!(decode(&[255, 254, 65], "a.txt").is_err());
    assert!(decode(&[0, 1, 2, 3, 128, 0, 0], "a.txt").is_err());
}
#[test]
fn secrets_nested_fields_tokens_paths_and_pem_do_not_escape() {
    let mut r = Redactor::default();
    let s = r#"{"password":{"nested":"secret-value"},"\u0074oken":"secret-token","SerialNumber":"sensitive-serial","Model":"RTX Example","UserName":"private-user"}
Authorization: Bearer secretvalue12345
https://user:secretpass@example.test/
-----BEGIN PRIVATE KEY-----
secretpem
-----END PRIVATE KEY-----
C:\Users\PrivatePerson\file.log
<Data Name="Password">xmlsecret</Data>
https://example.test/path?access_token=opaque-query-credential
client_secret=opaque-client-credential
refreshToken=opaque-refresh-credential
"#;
    let masked = r.redact(s).unwrap();
    for secret in [
        "secret-value",
        "secret-token",
        "sensitive-serial",
        "private-user",
        "secretvalue",
        "secretpass",
        "secretpem",
        "PrivatePerson",
        "xmlsecret",
        "opaque-query-credential",
        "opaque-client-credential",
        "opaque-refresh-credential",
    ] {
        assert!(!masked.contains(secret), "leaked {secret}: {masked}");
    }
    assert!(masked.contains("RTX Example"));
}
#[test]
fn mask_ids_stable_across_files() {
    let mut r = Redactor::default();
    let a = r.redact(r#"{"serial":"SAME"}"#).unwrap();
    let b = r.redact(r#"{"SerialNumber":"SAME"}"#).unwrap();
    assert!(a.contains("ID_0001"));
    assert!(b.contains("ID_0001"));
}
#[test]
fn missing_fields_are_listed_without_running_collectors() {
    let dir = temp("basic");
    let p = archive(&dir, &[("Hardware.txt", b"CPU model")]);
    let o = export(&Input::zip(p), &dir).unwrap();
    let t = exported_text(o.path);
    assert!(t.contains("NOT_AVAILABLE: DriverAudit"));
    assert!(t.contains("не собиралось заново"));
}
#[test]
fn large_logs_keep_middle_errors_and_last_result() {
    let mut t = "routine record\n".repeat(100000);
    t.push_str("CRITICAL SFC cannot repair middle.dll\n");
    t.push_str(&"normal line\n".repeat(100000));
    t.push_str("Operation result: 0x800f081f\nFINAL RESULT: FAILED\n");
    let (out, lost) = selected_text(&t, 200000);
    assert!(lost > 0);
    assert!(out.contains("middle.dll"));
    assert!(out.contains("FINAL RESULT: FAILED"));
    assert!(out.len() < 200000);
}
#[test]
fn giant_minified_line_preserves_error_context() {
    let s = format!(
        "{} CRITICAL unique-middle-error {} FINAL_RESULT",
        "x".repeat(200000),
        "y".repeat(200000)
    );
    let (t, n) = selected_text(&s, 160000);
    assert!(n > 0);
    assert!(t.contains("unique-middle-error"));
    assert!(t.contains("FINAL_RESULT"));
}
#[test]
fn unsupported_binary_and_secret_files_are_inventory_only() {
    let dir = temp("skip");
    let p = archive(
        &dir,
        &[
            ("State_Summary.txt", b"OK"),
            ("passwords.txt", b"never-copy-me"),
            ("memory.dmp", b"binary-secret"),
        ],
    );
    let o = export(&Input::zip(p), &dir).unwrap();
    let t = exported_text(o.path);
    assert_eq!(o.omitted, 2);
    assert!(!t.contains("never-copy-me"));
    assert!(!t.contains("binary-secret"));
    assert!(t.contains("OMITTED: memory.dmp"));
}
#[test]
fn unicode_paths_and_no_overwrite() {
    let dir = temp("Кириллица spaces");
    let p = archive(&dir, &[("Паспорт.txt", "Данные CPU".as_bytes())]);
    let before = fs::read(&p).unwrap();
    let out = export(&Input::zip(p.clone()), &dir).unwrap();
    assert!(
        out.path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .ends_with(".AI.zip")
    );
    assert!(exported_text(out.path).contains("FILE: Паспорт.txt"));
    assert_eq!(before, fs::read(p).unwrap());
}
#[test]
fn output_failure_does_not_touch_archive() {
    let dir = temp("writefail");
    let p = archive(&dir, &[("a.txt", b"data")]);
    let b = fs::read(&p).unwrap();
    let dest = dir.join("block");
    fs::write(&dest, b"do not overwrite").unwrap();
    assert!(export(&Input::zip(p.clone()), &dest).is_err());
    assert_eq!(fs::read(p).unwrap(), b);
    assert_eq!(fs::read(dest).unwrap(), b"do not overwrite");
}
#[test]
fn oversize_claim_cannot_allocate_or_inflate() {
    let dir = temp("size");
    let p = archive(&dir, &[("a.txt", b"data")]);
    let mut bytes = fs::read(&p).unwrap();
    let cd = bytes
        .windows(4)
        .position(|x| x == [0x50, 0x4b, 1, 2])
        .unwrap();
    bytes[cd + 24..cd + 28].copy_from_slice(&((MAX_ENTRY + 1) as u32).to_le_bytes());
    fs::write(&p, bytes).unwrap();
    assert!(export(&Input::zip(p), &dir).is_err());
}
#[test]
fn unsafe_archive_name_rejected() {
    let dir = temp("path");
    let p = archive(&dir, &[("abc.txt", b"test")]);
    let mut b = fs::read(&p).unwrap();
    for i in 0..b.len() - 7 {
        if &b[i..i + 7] == b"abc.txt" {
            b[i..i + 7].copy_from_slice(b"../.txt");
        }
    }
    fs::write(&p, b).unwrap();
    assert!(export(&Input::zip(p), &dir).is_err());
}
#[test]
fn error_before_output_does_not_create_file() {
    let dir = temp("none");
    assert!(
        export(
            &Input {
                zip: None,
                directory: None,
                base: "no".into()
            },
            &dir
        )
        .is_err()
    );
    assert_eq!(fs::read_dir(dir).unwrap().count(), 0);
}
#[test]
#[ignore = "private read-only field replay via WSD_AI_INPUT / WSD_AI_OUTPUT"]
fn field_replay() {
    let p = PathBuf::from(std::env::var_os("WSD_AI_INPUT").unwrap());
    let dst = PathBuf::from(std::env::var_os("WSD_AI_OUTPUT").unwrap());
    let before = fs::read(&p).unwrap();
    let o = export(&Input::zip(p.clone()), &dst).unwrap();
    assert_eq!(fs::read(&p).unwrap(), before);
    let t = exported_text(&o.path);
    assert_eq!(
        t.matches("========== END FILE ==========").count(),
        o.included
    );
    assert!(t.contains("FILE: manifest.json"));
    println!(
        "included={} omitted={} limited={} masked={} bytes={} archive_unchanged=true",
        o.included,
        o.omitted,
        o.limited,
        o.masked,
        t.len()
    );
}

#[test]
fn unlabelled_repetitions_and_ipv6_are_masked_without_hiding_model() {
    let mut r = Redactor::default();
    r.learn(r#"{"Serial":"UNIQUE-123456","InstanceId":"USB\\private-device","physical_identity":"PHYS#Model#UNIQUE-123456"}"#).unwrap();
    r.prepare().unwrap();
    let t=r.redact("Disk Model UNIQUE-123456\nUSB\\private-device\nPHYS#Model#UNIQUE-123456\n2001:db8::1234\n12:30:45").unwrap();
    assert!(!t.contains("UNIQUE-123456"));
    assert!(!t.contains("private-device"));
    assert!(!t.contains("2001:db8"));
    assert!(t.contains("Disk Model"));
    assert!(t.contains("12:30:45"));
}
