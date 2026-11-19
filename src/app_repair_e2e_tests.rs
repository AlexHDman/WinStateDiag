//! Real egui pointer click -> production dispatcher -> backend -> harmless OS mock
//! process -> actual stdout/stderr capture -> classification -> verification -> ZIP.
use super::*;
use crate::repair::{self, Failure, Output, Plan, Runner};
use std::collections::VecDeque;
#[derive(Clone)]
struct Scenario {
    code: i32,
    text: String,
    spawn_error: bool,
}
type ProcessCalls = Arc<Mutex<Vec<(String, Vec<String>, bool)>>>;
struct MockProcess {
    dir: PathBuf,
    steps: VecDeque<Scenario>,
    calls: ProcessCalls,
}
impl Runner for MockProcess {
    fn set_directory(&mut self, p: &Path) {
        self.dir = p.to_owned();
    }
    fn run(
        &mut self,
        p: &Plan,
        verify: bool,
        cancel: &AtomicBool,
        progress: &repair::SharedProgress,
    ) -> Result<Output, Failure> {
        let next = self
            .steps
            .pop_front()
            .expect("unexpected extra process/confirmation");
        repair::native_process_with(
            Path::new("C:/Windows/System32"),
            &self.dir.join(p.check.key()),
            p,
            verify,
            cancel,
            progress,
            |target, args| {
                self.calls.lock().unwrap().push((
                    target.file_name().unwrap().to_string_lossy().into(),
                    args.to_vec(),
                    verify,
                ));
                if next.spawn_error {
                    return std::process::Command::new(
                        self.dir.join("definitely-missing-mock.exe"),
                    );
                }
                let script = format!(
                    "[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);[Console]::WriteLine('37%');Start-Sleep -Milliseconds 250;[Console]::Error.WriteLine('mock stderr');[Console]::WriteLine('{}');exit {}",
                    next.text.replace('\'', "''"),
                    next.code
                );
                let mut cmd = std::process::Command::new("powershell.exe");
                cmd.args([
                    "-NoProfile",
                    "-NonInteractive",
                    "-EncodedCommand",
                    &crate::ps_exec::encoded_command(&script),
                ]);
                cmd
            },
        )
    }
}
fn frame(
    app: &mut WinStateDiagApp,
    ctx: &egui::Context,
    events: Vec<egui::Event>,
) -> Vec<(String, Rect)> {
    let vm = app.build_vm(0.016, 1.0);
    let mut actions = vec![];
    let mut output = ctx.run_ui(
        egui::RawInput {
            screen_rect: Some(Rect::from_min_size(egui::Pos2::ZERO, vec2(1500.0, 1600.0))),
            events,
            ..Default::default()
        },
        |ui| {
            crate::ui::pages::draw_stages_table(ui, egui::Pos2::ZERO, &vm, &mut actions);
            app.repair_window(ui.ctx());
        },
    );
    fn collect(s: &egui::Shape, t: &mut Vec<(String, Rect)>) {
        match s {
            egui::Shape::Text(s) => t.push((
                s.galley.text().into(),
                s.galley.rect.translate(s.pos.to_vec2()),
            )),
            egui::Shape::Vec(v) => v.iter().for_each(|s| collect(s, t)),
            _ => {}
        }
    }
    let mut text = vec![];
    for s in &output.shapes {
        collect(&s.shape, &mut text)
    }
    output.textures_delta.clear();
    for action in actions {
        app.apply(action)
    }
    text
}
fn click(app: &mut WinStateDiagApp, ctx: &egui::Context, label: &str) {
    let mut texts = vec![];
    for _ in 0..3 {
        texts = frame(app, ctx, vec![])
    }
    let at = texts
        .iter()
        .find(|(t, _)| t == label)
        .unwrap_or_else(|| panic!("No {label}: {texts:?}"))
        .1
        .center();
    for event in [
        egui::Event::PointerMoved(at),
        egui::Event::PointerButton {
            pos: at,
            button: egui::PointerButton::Primary,
            pressed: true,
            modifiers: Default::default(),
        },
        egui::Event::PointerButton {
            pos: at,
            button: egui::PointerButton::Primary,
            pressed: false,
            modifiers: Default::default(),
        },
    ] {
        frame(app, ctx, vec![event]);
    }
}
fn finding(check: DeepCheck) -> DeepCheckOutcome {
    DeepCheckOutcome {
        check,
        result: CheckResult::Attention,
        detail: if check == DeepCheck::Sfc {
            "INTEGRITY_VIOLATIONS"
        } else {
            "REPAIRABLE"
        }
        .into(),
        source: deep_checks::ResultSource::ExpcJson,
    }
}
fn step(code: i32, text: &str) -> Scenario {
    Scenario {
        code,
        text: text.into(),
        spawn_error: false,
    }
}
#[test]
fn single_click_process_pipeline_and_failures() {
    let _serial = repair::TEST_REPAIR_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target/repair-e2e")
        .join(repair::operation_id());
    std::fs::create_dir_all(&root).unwrap();
    let clean_sfc = "Windows Resource Protection did not find any integrity violations.";
    let clean_dism = "No component store corruption detected.";
    for (name, check, combined, admin, uac_error, steps, expected, expected_calls) in [
        (
            "sfc",
            DeepCheck::Sfc,
            false,
            true,
            None,
            vec![step(0, "done"), step(0, clean_sfc)],
            "SUCCESS_VERIFIED",
            2,
        ),
        (
            "dism",
            DeepCheck::Dism,
            false,
            true,
            None,
            vec![step(0, "done"), step(0, clean_dism)],
            "SUCCESS_VERIFIED",
            2,
        ),
        (
            "combined",
            DeepCheck::Dism,
            true,
            true,
            None,
            vec![
                step(0, "done"),
                step(0, clean_dism),
                step(0, "done"),
                step(0, clean_sfc),
            ],
            "SUCCESS_VERIFIED",
            4,
        ),
        (
            "exit-error",
            DeepCheck::Sfc,
            false,
            true,
            None,
            vec![step(5, "access denied")],
            "FAILED",
            1,
        ),
        (
            "spawn-error",
            DeepCheck::Dism,
            false,
            true,
            None,
            vec![Scenario {
                code: 0,
                text: String::new(),
                spawn_error: true,
            }],
            "FAILED",
            1,
        ),
        (
            "verification-unavailable",
            DeepCheck::Dism,
            false,
            true,
            None,
            vec![
                step(0, "The restore operation completed successfully."),
                Scenario {
                    code: 0,
                    text: String::new(),
                    spawn_error: true,
                },
            ],
            "VERIFICATION_FAILED",
            2,
        ),
        (
            "partial",
            DeepCheck::Sfc,
            false,
            true,
            None,
            vec![
                step(0, "done"),
                step(0, "Windows Resource Protection found integrity violations."),
            ],
            "PARTIAL",
            2,
        ),
        (
            "uac-declined",
            DeepCheck::Sfc,
            false,
            false,
            Some("UAC cancelled (os error 1223)"),
            vec![],
            "CANCELLED",
            0,
        ),
        (
            "uac-accepted",
            DeepCheck::Dism,
            false,
            false,
            None,
            vec![step(0, "done"), step(0, clean_dism)],
            "SUCCESS_VERIFIED",
            2,
        ),
    ] {
        let dir = root.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        let mut app = WinStateDiagApp::default();
        app.client_name = "SYNTHETIC".into();
        app.computer_name = "TEST-PC".into();
        app.reports_root = dir.join("Reports");
        app.package = Arc::new(Mutex::new(SessionPackage::new(
            app.reports_root.clone(),
            None,
        )));
        app.deep_check_results = if combined {
            vec![finding(DeepCheck::Dism), finding(DeepCheck::Sfc)]
        } else {
            vec![finding(check)]
        };
        app.repair_ui.admin = Some(admin);
        app.repair_ui.log_root = Some(dir.join("Repair"));
        app.repair_ui.elevation_error = uac_error.map(str::to_owned);
        let calls = Arc::new(Mutex::new(vec![]));
        app.repair_ui.runner = Some(Box::new(MockProcess {
            dir: PathBuf::new(),
            steps: steps.into(),
            calls: Arc::clone(&calls),
        }));
        let ctx = egui::Context::default();
        crate::ui::fonts::install(&ctx);
        click(
            &mut app,
            &ctx,
            if combined {
                "DISM → SFC"
            } else {
                "Исправить"
            },
        );
        assert!(
            app.repair_ui.pending.is_none(),
            "second confirmation {name}"
        );
        assert!(app.repair_busy(), "did not start {name}");
        assert_eq!(app.repair_ui.elevation_requests, usize::from(!admin));
        let vm = app.build_vm(0.016, 1.0);
        assert_eq!(vm.stages[check.step_index()].right_text, "RUNNING");
        assert!(!vm.stages[check.step_index()].repair_available);
        assert!(
            frame(&mut app, &ctx, vec![])
                .iter()
                .all(|(s, _)| !s.starts_with("Подтверждаю"))
        );
        let start = Instant::now();
        let mut saw_percent = false;
        while app.repair_busy() {
            let p = app.repair_ui.progress.lock().unwrap().clone();
            saw_percent |= p.percent == Some(37.0);
            app.poll_repair();
            assert!(
                start.elapsed() < Duration::from_secs(20),
                "hung mock {name}"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            app.repair_ui.reports.last().unwrap().status,
            expected,
            "{name}"
        );
        let calls = calls.lock().unwrap();
        assert_eq!(calls.len(), expected_calls, "{name}");
        for (exe, args, verify) in calls.iter() {
            let expected = match (exe.as_str(), *verify) {
                ("sfc.exe", false) => vec!["/scannow"],
                ("sfc.exe", true) => vec!["/verifyonly"],
                ("dism.exe", false) => vec!["/Online", "/Cleanup-Image", "/RestoreHealth"],
                ("dism.exe", true) => vec!["/Online", "/Cleanup-Image", "/ScanHealth"],
                _ => panic!("unexpected real command"),
            };
            assert_eq!(args, &expected);
        }
        if combined {
            assert_eq!(
                calls.iter().map(|c| c.0.as_str()).collect::<Vec<_>>(),
                vec!["dism.exe", "dism.exe", "sfc.exe", "sfc.exe"]
            );
        }
        if expected_calls > 0 && name != "spawn-error" {
            assert!(saw_percent, "missing real stdout progress {name}");
            let op = app.repair_ui.directory.as_ref().unwrap().join(check.key());
            assert!(op.join("repair-stdout.bin").exists());
            assert!(op.join("repair-stderr.bin").exists());
            assert!(op.join("repair-completion.json").exists());
        }
        app.sync_manifest_states();
        app.finalize_report_if_idle();
        let package = report_package::lock(&app.package);
        let zip = package.final_zip().unwrap_or_else(|| {
            panic!(
                "{name}: packaging={:?}; journal={}",
                package.packaging_error(),
                app.journal.technical_text()
            )
        });
        drop(package);
        let files = report_package::read_zip(&zip).unwrap();
        assert!(
            files
                .iter()
                .any(|f| f.name.starts_with("Repair_") && f.name.ends_with(".json")),
            "missing result evidence {name}"
        );
        if expected_calls > 0 && name != "spawn-error" {
            for suffix in [
                "repair-command.json",
                "repair-stdout.bin",
                "repair-stderr.bin",
                "repair-completion.json",
            ] {
                assert!(
                    files
                        .iter()
                        .any(|f| f.name.starts_with("Repair/") && f.name.ends_with(suffix)),
                    "missing raw Repair evidence {name} {suffix}"
                );
            }
        }
        println!(
            "E2E {name}: one pointer click -> {expected_calls} mock OS processes -> {expected}; evidence verified"
        );
        drop(calls);
        if name == "exit-error" {
            let previous = app.repair_ui.directory.clone().unwrap();
            app.repair_ui.open = false;
            app.repair_ui.runner = Some(Box::new(MockProcess {
                dir: PathBuf::new(),
                steps: vec![step(0, "done"), step(0, clean_sfc)].into(),
                calls: Arc::new(Mutex::new(vec![])),
            }));
            click(&mut app, &ctx, "Исправить");
            assert!(app.repair_busy());
            assert!(app.repair_ui.pending.is_none());
            assert_ne!(app.repair_ui.directory.as_ref().unwrap(), &previous);
            let start = Instant::now();
            while app.repair_busy() {
                app.poll_repair();
                assert!(start.elapsed() < Duration::from_secs(20));
                std::thread::sleep(Duration::from_millis(10));
            }
            assert_eq!(
                app.repair_ui.reports.last().unwrap().status,
                "SUCCESS_VERIFIED"
            );
            assert!(previous.is_dir(), "previous attempt evidence retained");
            println!("E2E retry in same application: unique directory; SUCCESS_VERIFIED");
        }
    }
}
#[test]
fn unique_operations_and_yellow_buttons() {
    assert_ne!(repair::operation_id(), repair::operation_id());
    let (fill, _, text) =
        crate::ui::paint::button_colors(crate::ui::paint::ButtonKind::Repair, true, false, false);
    assert_eq!(fill, c::YELLOW_WARNING);
    assert!(text.r() < 50 && text.g() < 50 && text.b() < 50);
}
