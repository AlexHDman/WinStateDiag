use super::*;
fn root(tag: &str) -> PathBuf {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target/ai-analysis-tests")
        .join(format!(
            "{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
    std::fs::create_dir_all(&path).unwrap();
    path
}
fn txt(text: &str) -> Prepared {
    let path = root("тест кириллицы").join("Сохранённый отчёт.txt");
    std::fs::write(&path, text).unwrap();
    prepare(
        Source::Txt(path),
        vec!["ТестовыйКлиент".into(), "TEST-PC-123".into()],
        &AtomicBool::new(false),
    )
    .unwrap()
}
pub(super) fn response() -> String {
    let structured = object(vec![
        (
            "overview",
            Json::str("ТЕСТОВЫЙ ОТВЕТ, не OpenAI. Требуется проверка целостности."),
        ),
        (
            "issues",
            Json::Array(vec![Json::str(
                "ATTENTION: SFC INTEGRITY_VIOLATIONS, источник SFC.txt",
            )]),
        ),
        (
            "facts",
            Json::Array(vec![Json::str("SFC обнаружил нарушения")]),
        ),
        (
            "hypotheses",
            Json::Array(vec![Json::str("Причина не установлена")]),
        ),
        (
            "next_steps",
            Json::Array(vec![Json::str("Сверить CBS без автоматического ремонта")]),
        ),
        (
            "client_summary",
            Json::str("Проверка целостности требует внимания."),
        ),
    ])
    .render();
    object(vec![
        ("status", Json::str("completed")),
        ("model", Json::str("synthetic-model")),
        (
            "usage",
            object(vec![
                ("input_tokens", Json::Int(123)),
                ("output_tokens", Json::Int(45)),
                ("total_tokens", Json::Int(168)),
            ]),
        ),
        (
            "output",
            Json::Array(vec![object(vec![
                ("type", Json::str("message")),
                (
                    "content",
                    Json::Array(vec![object(vec![
                        ("type", Json::str("output_text")),
                        ("text", Json::str(&structured)),
                    ])]),
                ),
            ])]),
        ),
    ])
    .render()
}
#[test]
fn captured_request_redacts_secrets_keeps_evidence_and_exact_preview() {
    let raw = r#"Client: ТестовыйКлиент
ComputerName: TEST-PC-123
UserName: PrivateUser
SerialNumber: SECRET-SERIAL-123
Contact: private.person@example.test
Path: C:\Users\PrivateUser\Documents\private-file.txt
Password: bad-fixture-password
api_key=sk-proj-SYNTHETIC_TEST_NOT_A_REAL_KEY_123456
Authorization: Bearer SYNTHETIC_TOKEN_123456789
{"client":"ТестовыйКлиент","password":"json-password","serial":"SECRET-SERIAL-123"}
BIOS version: 1.2.3.4
Driver version: 31.0.15.1234
CPU: Intel Core i7-12700
Board: PRO H610M-G DDR4
2026-11-18 12:34:56 EventID 41 WHEA 17 3.328 V 65 C 0x800f081f
SFC INTEGRITY_VIOLATIONS — подтверждено SFC.txt
DISM CLEAN
PrivateUser repeats in a log; TEST-PC-123 repeats too
"#;
    let p = txt(raw);
    let body = request(&p, "gpt-4.1-mini", &p.digest).unwrap();
    let j = Json::parse(&body).unwrap();
    assert_eq!(string(&j, "input"), p.text);
    for forbidden in [
        "ТестовыйКлиент",
        "TEST-PC-123",
        "PrivateUser",
        "SECRET-SERIAL-123",
        "private.person@example.test",
        "bad-fixture-password",
        "SYNTHETIC_TEST_NOT_A_REAL_KEY",
        "SYNTHETIC_TOKEN",
        "json-password",
        "private-file.txt",
    ] {
        assert!(
            !body.contains(forbidden),
            "leaked synthetic field {forbidden}"
        );
    }
    for kept in [
        "1.2.3.4",
        "31.0.15.1234",
        "i7-12700",
        "H610M-G DDR4",
        "2026-11-18 12:34:56",
        "EventID 41",
        "WHEA 17",
        "3.328 V",
        "65 C",
        "0x800f081f",
        "INTEGRITY_VIOLATIONS",
        "DISM CLEAN",
    ] {
        assert!(p.text.contains(kept), "lost diagnostic {kept}");
    }
    assert_eq!(string(&j, "instructions"), INSTRUCTIONS);
    assert_eq!(j.get("store"), Some(&Json::Bool(false)));
    assert!(array(&j, "tools").is_empty());
    assert_eq!(string(&j, "tool_choice"), "none");
    assert_eq!(std::fs::read_to_string(&p.source).unwrap(), raw);
    let out = root("captured");
    std::fs::write(out.join("synthetic-outgoing-request.json"), body).unwrap();
}
#[test]
fn request_rejects_changed_copy_and_invalid_model() {
    let mut p = txt("SFC CLEAN");
    assert_eq!(
        request(&p, "gpt-4.1-mini", "different"),
        Err(Error::NotReviewed)
    );
    p.text.push_str("changed");
    assert_eq!(
        request(&p, "gpt-4.1-mini", &p.digest),
        Err(Error::NotReviewed)
    );
    assert_eq!(
        request(&p, "bad model\r\nheader", &p.digest),
        Err(Error::Model)
    );
    assert!(!valid_model("sk-proj-SYNTHETIC_NOT_A_MODEL_123456"));
}
#[test]
fn large_text_retains_middle_error_and_final_result() {
    let mut raw = "normal diagnostic line\n".repeat(60000);
    let middle = raw.len() / 2;
    raw.insert_str(middle, "\nCRITICAL 0x800f081f COMPONENT_CORRUPT\n");
    raw.push_str("\nFINAL RESULT SFC INTEGRITY_VIOLATIONS\n");
    let p = txt(&raw);
    assert!(p.text.len() <= MAX_INPUT);
    assert!(p.omitted_blocks > 0);
    assert!(p.text.contains("COMPONENT_CORRUPT"));
    assert!(p.text.contains("FINAL RESULT"));
    assert!(p.text.contains("LIMITED"));
}
#[test]
fn utf16_and_oem_are_decoded_without_changing_source() {
    let root = root("encoding");
    for (name, bytes) in [
        (
            "utf16.txt",
            [
                vec![0xff, 0xfe],
                "Состояние SFC: нарушений нет"
                    .encode_utf16()
                    .flat_map(u16::to_le_bytes)
                    .collect(),
            ]
            .concat(),
        ),
        ("utf8.txt", "Состояние DISM CLEAN".as_bytes().to_vec()),
        ("oem.txt", vec![0x8f, 0xe0, 0xa8, 0xa2, 0xa5, 0xe2]),
    ] {
        let path = root.join(name);
        std::fs::write(&path, &bytes).unwrap();
        let p = prepare(Source::Txt(path.clone()), vec![], &AtomicBool::new(false)).unwrap();
        assert!(!p.text.is_empty());
        assert_eq!(std::fs::read(path).unwrap(), bytes);
    }
}
#[test]
fn completed_zip_and_missing_zip_materials_are_read_only() {
    let root = root("session");
    let zip = root.join("Сеанс.zip");
    let bytes = crate::report_package::build_zip(
        &[
            crate::report_package::EvidenceFile::new(
                "State_Summary.txt",
                b"SFC INTEGRITY_VIOLATIONS".to_vec(),
            ),
            crate::report_package::EvidenceFile::new(
                "Hardware.txt",
                b"Board: PRO H610M-G DDR4".to_vec(),
            ),
        ],
        crate::ui::sysinfo::local_time(),
    )
    .unwrap();
    std::fs::write(&zip, &bytes).unwrap();
    let p = prepare(
        Source::Session(crate::ai_export::Input::zip(zip.clone())),
        vec![],
        &AtomicBool::new(false),
    )
    .unwrap();
    assert!(p.text.contains("State_Summary.txt"));
    assert!(p.text.contains("INTEGRITY_VIOLATIONS"));
    assert_eq!(std::fs::read(zip).unwrap(), bytes);
    std::fs::write(root.join("State_Summary.txt"), "SFC CLEAN").unwrap();
    let p = prepare(
        Source::Session(crate::ai_export::Input {
            zip: None,
            directory: Some(root.clone()),
            base: "Session".into(),
        }),
        vec![],
        &AtomicBool::new(false),
    )
    .unwrap();
    assert!(p.text.contains("SFC CLEAN"));
}
#[test]
fn source_errors_and_pre_send_cancel_do_not_launch_network() {
    assert!(matches!(
        prepare(
            Source::Txt(root("missing").join("absent.txt")),
            vec![],
            &AtomicBool::new(false)
        ),
        Err(Error::Source(_))
    ));
    assert!(matches!(
        prepare(
            Source::Txt(PathBuf::from("no-file")),
            vec![],
            &AtomicBool::new(true)
        ),
        Err(Error::Cancelled)
    ));
    assert_eq!(
        transport::mock_process(
            Path::new("DO-NOT-LAUNCH.exe"),
            &[],
            String::new(),
            &AtomicBool::new(true),
            Duration::from_secs(1)
        ),
        Err(Error::Cancelled)
    );
    let bad = root("bad").join("bad.zip");
    std::fs::write(&bad, b"damaged").unwrap();
    assert!(
        prepare(
            Source::Session(crate::ai_export::Input::zip(bad)),
            vec![],
            &AtomicBool::new(false)
        )
        .is_err()
    );
}
#[test]
fn http_error_classes_are_safe_and_distinct() {
    for (status, body, expected) in [
        (
            401,
            r#"{"error":{"message":"sk-proj-DO_NOT_ECHO"}}"#,
            HttpProblem::Authentication,
        ),
        (403, "", HttpProblem::Access),
        (400, r#"{"error":{"param":"model"}}"#, HttpProblem::Model),
        (
            404,
            r#"{"error":{"code":"model_not_found"}}"#,
            HttpProblem::Model,
        ),
        (404, "", HttpProblem::Rejected),
        (
            429,
            r#"{"error":{"code":"credit_balance_exhausted"}}"#,
            HttpProblem::Quota,
        ),
        (
            429,
            r#"{"error":{"code":"project_spend_limit_exceeded"}}"#,
            HttpProblem::Quota,
        ),
        (
            429,
            r#"{"error":{"type":"insufficient_quota"}}"#,
            HttpProblem::Quota,
        ),
        (
            429,
            r#"{"error":{"code":"rate_limit_exceeded"}}"#,
            HttpProblem::RateLimit,
        ),
        (500, "private backend error", HttpProblem::Server),
    ] {
        let e = classify_http(status, body, "req_TestCase");
        assert!(matches!(&e, Error::Http(h)
            if h.status==status && h.problem==expected && h.request_id.as_deref()==Some("req_TestCase")));
        assert!(!e.message().contains("DO_NOT_ECHO"));
        assert!(!e.message().contains("private backend"));
    }
    let Error::Http(detail) = classify_http(
        401,
        r#"{"error":{"code":"sk-proj-synthetic-reflection!","type":"my-secret@example.test"}}"#,
        "req_sk-proj-synthetic-reflection!",
    ) else {
        panic!("HTTP status missing")
    };
    assert_eq!(detail.details(), vec!["HTTP 401"]);
    assert_ne!(Error::Network.message(), Error::Timeout.message());
}
#[test]
fn response_five_sections_usage_partial_and_no_tools_execution() {
    let body = response();
    let a = parse_response(&body, "requested-model").unwrap();
    assert_eq!(a.sections.len(), 5);
    assert!(!a.incomplete);
    assert!(a.sections[1].contains("SFC.txt"));
    assert_eq!(
        a.usage,
        Some(Usage {
            input: 123,
            output: 45,
            total: 168
        })
    );
    assert_eq!(a.model, "synthetic-model");
    let no_usage = body.replace("\"usage\":{", "\"unknown_usage\":{");
    assert_eq!(
        usage_text(&parse_response(&no_usage, "requested").unwrap().usage),
        "Расход не получен"
    );
    let partial = r#"{"status":"incomplete","output":[{"type":"message","content":[{"type":"output_text","text":"Partial evidence"}]}]}"#;
    let a = parse_response(partial, "requested").unwrap();
    assert!(a.incomplete);
    assert!(a.raw_partial.is_some());
    assert_eq!(a.model, "Не указана в ответе");
    assert!(
        parse_response(
            r#"{"status":"completed","output":[{"type":"function_call","name":"repair"}]}"#,
            "requested"
        )
        .is_err()
    );
}
#[test]
fn save_is_utf8_unique_and_does_not_change_report() {
    let p = txt("Сохранённый исходник SFC CLEAN");
    let hash = crate::content_hash::sha256(std::fs::read(&p.source).unwrap().as_slice()).unwrap();
    let a = parse_response(&response(), "test").unwrap();
    let first = save(&a, &p.source).unwrap();
    let second = save(&a, &p.source).unwrap();
    assert_ne!(first, second);
    let text = std::fs::read_to_string(first).unwrap();
    assert!(text.contains("ТЕСТОВЫЙ ОТВЕТ"));
    assert!(text.contains("input_tokens: 123"));
    assert_eq!(
        crate::content_hash::sha256(std::fs::read(&p.source).unwrap().as_slice()).unwrap(),
        hash
    );
    assert!(save(&a, &root("write-error").join("missing/nofile.txt")).is_err());
}
#[test]
fn credentials_reject_header_injection_without_writing_anything() {
    assert_eq!(credentials::save("short"), Err(Error::InvalidKey));
    assert_eq!(
        credentials::save("test\r\nheader-with-long-text"),
        Err(Error::InvalidKey)
    );
    let mut test = "synthetic-password".to_string();
    credentials::wipe(&mut test);
    assert!(test.is_empty());
}
#[test]
#[ignore = "Read only own credential presence; no API request and no secret output"]
fn configured_credential_presence_only() {
    println!("OWN_OPENAI_CREDENTIAL_PRESENT={:?}", credentials::present());
}
#[test]
fn mock_process_launch_timeout_and_cancel() {
    let program = Path::new("C:\\Windows\\System32\\cmd.exe");
    let c = AtomicBool::new(false);
    assert!(
        transport::mock_process(
            program,
            &["/d", "/c", "echo synthetic-result"],
            String::new(),
            &c,
            Duration::from_secs(5)
        )
        .unwrap()
        .contains("synthetic-result")
    );
    assert_eq!(
        transport::mock_process(
            Path::new("no-such-worker.exe"),
            &[],
            String::new(),
            &c,
            Duration::from_secs(1)
        ),
        Err(Error::Worker)
    );
    // A wait-only fixture, never a diagnostic or a repair command.
    assert_eq!(
        transport::mock_process(
            Path::new("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
            &[
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Start-Sleep -Seconds 10"
            ],
            String::new(),
            &c,
            Duration::from_millis(150)
        ),
        Err(Error::Timeout)
    );
}
#[test]
#[ignore = "Explicit local report replay; requires WSD_AI_REAL_TXT, no API"]
fn real_cyrillic_txt_replay_keeps_source_sha256() {
    let path = PathBuf::from(std::env::var("WSD_AI_REAL_TXT").expect("explicit local report path"));
    let before = crate::content_hash::sha256(std::fs::File::open(&path).unwrap()).unwrap();
    let p = prepare(Source::Txt(path.clone()), vec![], &AtomicBool::new(false)).unwrap();
    assert!(p.text.chars().any(|c| ('А'..='я').contains(&c)));
    let body = request(&p, "gpt-4.1-mini", &p.digest).unwrap();
    assert_eq!(string(&Json::parse(&body).unwrap(), "input"), p.text);
    let after = crate::content_hash::sha256(std::fs::File::open(path).unwrap()).unwrap();
    assert_eq!(before, after);
    println!(
        "REAL_TXT_REPLAY source_sha256={before}; source_bytes={}; prepared_bytes={}; omitted_blocks={}; source_unchanged=true; network=NOT_RUN",
        p.source_bytes,
        p.text.len(),
        p.omitted_blocks
    );
}
#[test]
fn cancellation_stops_owned_mock_worker_without_retry() {
    use std::sync::Arc;
    let cancel = Arc::new(AtomicBool::new(false));
    let trigger = cancel.clone();
    let t = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(200));
        trigger.store(true, Ordering::Release);
    });
    let started = std::time::Instant::now();
    let result = transport::mock_process(
        Path::new("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
        &[
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Start-Sleep -Seconds 10",
        ],
        String::new(),
        &cancel,
        Duration::from_secs(15),
    );
    t.join().unwrap();
    assert_eq!(result, Err(Error::Cancelled));
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[test]
fn source_filename_in_old_export_is_masked_without_guessing_identity() {
    let path = root("source-label").join("SyntheticClient-PRIVATE-HOST-18.11.26.AI.txt");
    std::fs::write(&path,"SOURCE: SyntheticClient-PRIVATE-HOST-18.11.26.zip\nCPU: Intel Core i7-12700\nFINAL SFC CLEAN").unwrap();
    let p = prepare(Source::Txt(path), vec![], &AtomicBool::new(false)).unwrap();
    assert!(!p.text.contains("SyntheticClient"));
    assert!(!p.text.contains("PRIVATE-HOST"));
    assert!(p.text.contains("i7-12700"));
    assert!(p.text.contains("SFC CLEAN"));
}

#[test]
fn archive_type_and_unpack_budget_are_validated() {
    use crate::report_package::{EvidenceFile, build_zip};
    let dir = root("zip-boundaries");
    let archive = dir.join("Проверка структуры.zip");
    let cancel = AtomicBool::new(false);
    let load = || match prepare(Source::Zip(archive.clone()), vec![], &cancel) {
        Ok(_) => panic!("malformed ZIP accepted"),
        Err(e) => e.message(),
    };
    let write = |files: &[EvidenceFile]| {
        let zip = build_zip(files, crate::ui::sysinfo::local_time()).unwrap();
        std::fs::write(&archive, &zip).unwrap();
        zip
    };
    write(&[EvidenceFile::new("random.txt", b"not WinDiag".to_vec())]);
    assert!(load().contains("отсутствует manifest.json"));
    let manifest = || {
        EvidenceFile::new(
            "manifest.json",
            br#"{"producer":"WinDiag","producer_version":"1.12"}"#.to_vec(),
        )
    };
    write(&[manifest()]);
    assert!(load().contains("отсутствует State_Summary.json"));
    write(&[
        manifest(),
        EvidenceFile::new("State_Summary.json", b"invalid json".to_vec()),
    ]);
    assert!(load().contains("Повреждён JSON State_Summary.json"));
    write(&[EvidenceFile::new(
        "Bad.AI.txt",
        b"not an AI package".to_vec(),
    )]);
    assert!(load().contains("отсутствует заголовок пакета"));
    write(&[EvidenceFile::new(
        "Incomplete.AI.txt",
        "EXPC WINDIAG — AI DIAGNOSTIC PACKAGE\nEXPORT_SCHEMA: 1\n"
            .as_bytes()
            .to_vec(),
    )]);
    assert!(load().contains("отсутствует manifest.json или State_Summary"));
    let mut zip = write(&[
        manifest(),
        EvidenceFile::new("State_Summary.json", b"{}".to_vec()),
    ]);
    let cd_offset = zip.len() - 6;
    let cd = u32::from_le_bytes(zip[cd_offset..cd_offset + 4].try_into().unwrap()) as usize;
    assert_eq!(&zip[cd..cd + 4], b"PK\x01\x02");
    zip[cd + 24..cd + 28].copy_from_slice(&(257u32 * 1024 * 1024).to_le_bytes());
    std::fs::write(&archive, zip).unwrap();
    assert!(load().contains("Распакованные материалы ZIP превышают предел"));
    std::fs::write(&archive, b"bad ZIP").unwrap();
    assert!(load().contains("повреждён"));
}

#[test]
#[ignore = "requires owner-provided local archives, no uploads or copies"]
fn field_replay_both_zip_formats_preserves_bytes_and_previews() {
    for var in ["WSD_V112_FIELD_ZIP", "WSD_V112_FIELD_AI_ZIP"] {
        let path = PathBuf::from(std::env::var_os(var).expect("local archive path"));
        let hash_before = crate::content_hash::sha256(std::fs::File::open(&path).unwrap()).unwrap();
        let p = prepare(Source::Zip(path.clone()), vec![], &AtomicBool::new(false))
            .unwrap_or_else(|e| panic!("{var}: {}", e.message()));
        assert_eq!(p.archive_sha256.as_deref(), Some(hash_before.as_str()));
        assert!(p.source_bytes > 0);
        assert!(!p.text.is_empty());
        assert!(p.text.len() <= MAX_INPUT);
        assert!(p.text.contains("PRIMARY_MATERIALS"));
        assert!(!p.facts.cpu.is_empty(), "hardware passport was not parsed");
        assert!(!p.facts.date.is_empty(), "session date was not parsed");
        let body = request(&p, "gpt-4.1-mini", &p.digest).unwrap();
        assert_eq!(string(&Json::parse(&body).unwrap(), "input"), p.text);
        assert_eq!(
            hash_before,
            crate::content_hash::sha256(std::fs::File::open(&path).unwrap()).unwrap()
        );
        println!(
            "{var}: ZIP verified, bytes={}, preview={}, omissions={}",
            p.source_bytes,
            p.text.len(),
            p.omissions.len()
        );
    }
}

#[test]
fn regional_403_is_distinct_and_keeps_safe_error_code() {
    let problem = classify_http(
        403,
        r#"{"error":{"code":"unsupported_country_region_territory","type":"request_forbidden","message":"fixture private text"}}"#,
        "req_RegionalFixture",
    );
    assert_eq!(
        problem.message(),
        "OpenAI API недоступен для региона текущего подключения (HTTP 403)"
    );
    let Error::Http(details) = problem else {
        panic!("expected HTTP failure")
    };
    assert_eq!(details.problem, HttpProblem::Region);
    assert_eq!(
        details.code.as_deref(),
        Some("unsupported_country_region_territory")
    );
    assert_eq!(details.request_id.as_deref(), Some("req_RegionalFixture"));
    assert!(!details.details().join(" ").contains("fixture private text"));
}
