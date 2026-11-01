//! v1.1 final integration regression tests (app level): startup
//! orchestration, CryptoPro / Driver Audit / WinDbg / crash preflight,
//! client identity isolation, re-checks, confirmations, cancellation,
//! concurrency, Hardware Passport 2.0 and RU / EN / DPI.

use super::*;
use crate::deep_checks::json;

/// Exercises the native immediate-viewport callback with egui's real
/// multi-pass runner, without creating an OS window or using a GPU.
struct NativeDetailsHarness {
    ctx: egui::Context,
    state: std::rc::Rc<std::cell::RefCell<NativeDetailsState>>,
}

#[derive(Default)]
struct NativeDetailsState {
    input: egui::RawInput,
    output: Option<egui::FullOutput>,
    callbacks: usize,
    force_discard: bool,
}

impl NativeDetailsHarness {
    fn new() -> Self {
        let ctx = egui::Context::default();
        crate::ui::fonts::install(&ctx);
        ctx.set_embed_viewports(false);
        let state = std::rc::Rc::new(std::cell::RefCell::new(NativeDetailsState::default()));
        let shared = state.clone();
        egui::Context::set_immediate_viewport_renderer(move |ctx, mut viewport| {
            let (mut input, force_discard) = {
                let mut state = shared.borrow_mut();
                (std::mem::take(&mut state.input), state.force_discard)
            };
            input.viewport_id = viewport.ids.this;
            input.viewports.insert(
                viewport.ids.this,
                egui::ViewportInfo {
                    parent: Some(viewport.ids.parent),
                    inner_rect: input.screen_rect,
                    ..Default::default()
                },
            );
            let mut callbacks = 0;
            let mut output = ctx.run_ui(input, |ui| {
                callbacks += 1;
                (viewport.viewport_ui_cb)(ui);
                if force_discard && ui.ctx().current_pass_index() == 0 {
                    ui.ctx().request_discard("Details regression: second pass");
                }
            });
            output.textures_delta.clear();
            let mut state = shared.borrow_mut();
            state.callbacks = callbacks;
            state.output = Some(output);
        });
        Self { ctx, state }
    }

    fn render(
        &self,
        size: egui::Vec2,
        force_discard: bool,
        events: Vec<egui::Event>,
        mut draw: impl FnMut(&egui::Context),
    ) -> egui::FullOutput {
        {
            let mut state = self.state.borrow_mut();
            state.input = egui::RawInput {
                screen_rect: Some(Rect::from_min_size(egui::Pos2::ZERO, size)),
                events,
                ..Default::default()
            };
            state.force_discard = force_discard;
            state.output = None;
        }
        let mut parent = self
            .ctx
            .run_ui(egui::RawInput::default(), |ui| draw(ui.ctx()));
        parent.textures_delta.clear();
        let mut output = self.state.borrow_mut().output.take().unwrap();
        // Actions such as Copy are applied by the parent after the child
        // callback returns. Inspect both outputs; no OS clipboard is used.
        output
            .platform_output
            .commands
            .extend(parent.platform_output.commands);
        output
    }
}

impl Drop for NativeDetailsHarness {
    fn drop(&mut self) {
        // The renderer is thread-local. Release the captured test state;
        // later tests on this worker use embedded viewports by default.
        egui::Context::set_immediate_viewport_renderer(|_, _| {
            panic!("native Details test renderer is not installed")
        });
    }
}

fn native_texts(output: &egui::FullOutput) -> Vec<(String, Rect)> {
    output
        .shapes
        .iter()
        .filter_map(|clipped| match &clipped.shape {
            egui::Shape::Text(t) => Some((
                t.galley.text().to_string(),
                clipped.shape.visual_bounding_rect(),
            )),
            _ => None,
        })
        .collect()
}

#[test]
fn detail_window_native_callback_renders_every_pass() {
    let harness = NativeDetailsHarness::new();
    let mut open = true;
    for frame in 0..12 {
        let mut result = None;
        let output = harness.render(vec2(640.0, 520.0), true, vec![], |ctx| {
            result = detail_window(
                ctx,
                "multipass",
                "Details",
                [640.0, 520.0],
                &mut open,
                |ui| {
                    egui::Grid::new("multipass_grid").show(ui, |ui| {
                        ui.label("persistent detail value");
                        ui.end_row();
                    });
                    42
                },
            );
        });
        assert_eq!(harness.state.borrow().callbacks, 2, "frame {frame}");
        assert_eq!(result, Some(42), "final callback result, frame {frame}");
        assert!(
            native_texts(&output)
                .iter()
                .any(|(t, _)| t == "persistent detail value"),
            "final pass lost the content, frame {frame}"
        );
        assert!(open);
    }
}

#[test]
fn phase03_b1_disk_ok_without_sensors_is_partial_not_fault() {
    let mut app = WinStateDiagApp::default();
    assert_eq!(app.state_codes().1, "NO_DATA");
    app.sensors = Some(sensors::Snapshot::default());
    assert_eq!(app.state_codes().1, "NO_DATA");
    app.ata_scan = Some(vec![AtaDisk {
        index: 0,
        model: "Fixture SATA".into(),
        bus: "SATA".into(),
        smart: crate::ata_smart::AtaSmart {
            state: crate::ata_smart::AtaState::Ok,
            detail: String::new(),
            attributes: vec![crate::ata_smart::Attribute {
                id: 194,
                current: 100,
                worst: 100,
                threshold: Some(0),
                raw: 30,
            }],
        },
    }]);
    assert_eq!(app.state_codes().1, "PARTIAL");
    assert_ne!(app.system_state_vm().hardware.tone, Tone::Success);
    app.sensors = Some(sensors::Snapshot {
        sensors: sensors::tests::sample(&sensors::tests::msi_reference()),
        ..Default::default()
    });
    assert_eq!(
        app.state_codes().1,
        "OK",
        "complete trusted fixture still permits OK"
    );
    app.sensors_error = Some("fixture access denied".into());
    assert_eq!(app.state_codes().1, "PARTIAL");
    app.ata_scan.as_mut().unwrap()[0]
        .smart
        .attributes
        .push(crate::ata_smart::Attribute {
            id: 197,
            current: 100,
            worst: 100,
            threshold: Some(0),
            raw: 1,
        });
    assert_eq!(
        app.state_codes().1,
        "ATTENTION",
        "missing sensors must not hide real disk evidence"
    );
    app.ata_scan = None;
    assert_eq!(app.state_codes().1, "NO_DATA");
}

/// UI-PASSPORT-001: model-level guard only; OS minimization still needs LIVE QA.
#[test]
fn passport_idle_frames_never_request_minimize_or_close_and_can_reopen() {
    let mut app = WinStateDiagApp::default();
    app.passport2_json = Some(crate::passport2::QA_PASSPORT_JSON.into());
    let harness = NativeDetailsHarness::new();
    for _opening in 0..3 {
        app.passport2_open = true;
        for frame in 0..20 {
            let size = if frame % 2 == 0 {
                vec2(1060.0, 860.0)
            } else {
                vec2(700.0, 520.0)
            };
            let output = harness.render(size, true, vec![], |ctx| app.passport2_window(ctx));
            assert!(app.passport2_open);
            for viewport in output.viewport_output.values() {
                assert!(!viewport.commands.iter().any(|command| matches!(
                    command,
                    egui::ViewportCommand::Minimized(true) | egui::ViewportCommand::Close
                )));
            }
            assert!(!native_texts(&output).is_empty());
        }
        app.passport2_open = false;
    }
}

#[test]
fn passport_native_repeated_render_preserves_every_card_and_copy() {
    for lang in [Language::Ru, Language::En] {
        let mut app = WinStateDiagApp::default();
        app.language = lang;
        app.passport2_json = Some(crate::passport2::QA_PASSPORT_JSON.into());
        app.passport2_open = true;
        let view = app.passport2_view().unwrap();
        let d = i18n::t(lang);
        let summary = crate::passport2::summary_text(&view, d);
        assert_eq!(view.cards.len(), 8);
        let harness = NativeDetailsHarness::new();
        let size = vec2(1060.0, 2400.0);
        let mut copy_pos = egui::Pos2::ZERO;
        for frame in 0..16 {
            // Natural Grid sizing passes first, then deliberately repeat
            // every frame to ensure contents survive the final pass.
            let output = harness.render(size, frame >= 4, vec![], |ctx| app.passport2_window(ctx));
            let texts = native_texts(&output);
            if frame >= 2 {
                for card in &view.cards {
                    for expected in std::iter::once(&card.title)
                        .chain(card.rows.iter().map(|r| &r.value).filter(|v| !v.is_empty()))
                    {
                        assert!(
                            texts.iter().any(|(t, _)| t == expected),
                            "{lang:?}, frame {frame}, missing {expected}"
                        );
                        assert!(summary.contains(expected), "copy lacks {expected}");
                    }
                }
                for button in [d.pp_refresh, d.pp_copy, d.pp_save, d.pp_close] {
                    assert!(texts.iter().any(|(t, _)| t == button), "missing {button}");
                }
                copy_pos = texts
                    .iter()
                    .find(|(t, _)| t == d.pp_copy)
                    .unwrap()
                    .1
                    .center();
            }
            assert_eq!(app.passport2_view().unwrap(), view);
        }
        harness.render(size, true, pointer_button(copy_pos, true), |ctx| {
            app.passport2_window(ctx)
        });
        let copied = harness.render(size, true, pointer_button(copy_pos, false), |ctx| {
            app.passport2_window(ctx)
        });
        let copies: Vec<_> = copied
            .platform_output
            .commands
            .iter()
            .filter_map(|cmd| match cmd {
                egui::OutputCommand::CopyText(text) => Some(text),
                _ => None,
            })
            .collect();
        assert_eq!(copies, vec![&summary], "one exact summary per click");
        assert!(matches!(app.passport2_status, Some(ExportStatus::Copied)));
        assert_eq!(app.passport2_view().unwrap(), view);
        let close_pos = native_texts(&copied)
            .iter()
            .find(|(t, _)| t == d.pp_close)
            .unwrap()
            .1
            .center();
        harness.render(size, true, pointer_button(close_pos, true), |ctx| {
            app.passport2_window(ctx)
        });
        harness.render(size, true, pointer_button(close_pos, false), |ctx| {
            app.passport2_window(ctx)
        });
        assert!(!app.passport2_open, "Close survives a discarded pass");
    }
}

fn pointer_button(pos: egui::Pos2, pressed: bool) -> Vec<egui::Event> {
    vec![
        egui::Event::PointerMoved(pos),
        egui::Event::PointerButton {
            pos,
            button: egui::PointerButton::Primary,
            pressed,
            modifiers: egui::Modifiers::NONE,
        },
    ]
}

#[test]
fn passport_native_scroll_and_resize_keep_content_and_footer() {
    let mut app = WinStateDiagApp::default();
    app.language = Language::Ru;
    app.passport2_json = Some(crate::passport2::QA_PASSPORT_JSON.into());
    app.passport2_open = true;
    let original = app.passport2_view().unwrap();
    let summary = crate::passport2::summary_text(&original, &i18n::RU);
    let harness = NativeDetailsHarness::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut cpu_y = Vec::new();
    for size in [vec2(640.0, 520.0), vec2(1060.0, 860.0), vec2(420.0, 300.0)] {
        for frame in 0..24 {
            let events = if frame >= 4 {
                vec![
                    egui::Event::PointerMoved(egui::pos2(100.0, 55.0)),
                    egui::Event::MouseWheel {
                        unit: egui::MouseWheelUnit::Point,
                        delta: vec2(0.0, if frame < 14 { -180.0 } else { 180.0 }),
                        phase: egui::TouchPhase::Move,
                        modifiers: egui::Modifiers::NONE,
                    },
                ]
            } else {
                vec![]
            };
            let output = harness.render(size, true, events, |ctx| app.passport2_window(ctx));
            let texts = native_texts(&output);
            if frame >= 2 {
                for button in [
                    i18n::RU.pp_refresh,
                    i18n::RU.pp_copy,
                    i18n::RU.pp_save,
                    i18n::RU.pp_close,
                ] {
                    let bounds = texts
                        .iter()
                        .find(|(t, _)| t == button)
                        .unwrap_or_else(|| panic!("{size:?} frame {frame}: missing {button}"))
                        .1;
                    assert!(
                        bounds.min.x >= 0.0
                            && bounds.max.x <= size.x + 0.5
                            && bounds.min.y >= 0.0
                            && bounds.max.y <= size.y + 0.5,
                        "{button}: {bounds:?} outside {size:?}"
                    );
                }
            }
            for clipped in &output.shapes {
                if let egui::Shape::Text(t) = &clipped.shape {
                    let bounds = clipped.shape.visual_bounding_rect();
                    if clipped.clip_rect.intersects(bounds) {
                        seen.insert(t.galley.text().to_string());
                        if size.x == 640.0 && t.galley.text() == i18n::RU.pp_cpu {
                            cpu_y.push(bounds.min.y);
                        }
                    }
                }
            }
            assert_eq!(app.passport2_view().unwrap(), original);
            assert_eq!(
                crate::passport2::summary_text(&app.passport2_view().unwrap(), &i18n::RU),
                summary
            );
        }
    }
    assert!(
        cpu_y.windows(2).any(|ys| (ys[0] - ys[1]).abs() > 5.0),
        "wheel input must actually scroll the body: {cpu_y:?}"
    );
    for card in &original.cards {
        assert!(
            seen.contains(&card.title),
            "never visible while scrolling: {}",
            card.title
        );
    }
    // Return to a tall viewport after scrolling/resizing: every card's
    // actual values must still render, not merely remain in the model.
    let mut last = Vec::new();
    for _ in 0..12 {
        last = native_texts(&harness.render(vec2(1060.0, 2400.0), true, vec![], |ctx| {
            app.passport2_window(ctx)
        }));
    }
    for card in &original.cards {
        for expected in std::iter::once(&card.title)
            .chain(card.rows.iter().map(|r| &r.value).filter(|v| !v.is_empty()))
        {
            assert!(
                last.iter().any(|(t, _)| t == expected),
                "lost after resize: {expected}"
            );
        }
    }
}

#[test]
fn other_details_native_windows_survive_repeated_layout_passes() {
    let windows: [(&str, fn(&mut WinStateDiagApp, &egui::Context)); 8] = [
        ("crypto-details", WinStateDiagApp::crypto_details_window),
        ("driver-details", WinStateDiagApp::drivers_window),
        ("disk-details", WinStateDiagApp::raw_passes_window),
        ("crash-analyzer", WinStateDiagApp::crash_details_window),
        ("sensor-details", WinStateDiagApp::sensors_details_window),
        ("stage-details", WinStateDiagApp::stage_details_window),
        ("expc", WinStateDiagApp::expc_details_window),
        ("gpo", WinStateDiagApp::gpo_details_window),
    ];
    for (scene, draw) in windows {
        let mut app = WinStateDiagApp::default();
        app.language = Language::Ru;
        app.seed_qa_scene(if scene == "expc" {
            "stage-details"
        } else {
            scene
        });
        app.expc_details_open = true;
        app.gpo_details_open = true;
        let harness = NativeDetailsHarness::new();
        let size = vec2(1400.0, 2400.0);
        let mut expected = Vec::new();
        for _ in 0..4 {
            expected =
                native_texts(&harness.render(size, false, vec![], |ctx| draw(&mut app, ctx)));
        }
        assert_eq!(
            expected
                .iter()
                .any(|(t, _)| t == i18n::RU.journal_viewer_close),
            scene != "crypto-details",
            "{scene}: Close footer policy"
        );
        assert!(expected.len() > 1, "{scene}: no baseline contents");
        for frame in 0..12 {
            let output = harness.render(size, true, vec![], |ctx| draw(&mut app, ctx));
            assert_eq!(harness.state.borrow().callbacks, 2);
            let actual = native_texts(&output);
            for (text, _) in &expected {
                assert!(
                    actual.iter().any(|(t, _)| t == text),
                    "{scene}, frame {frame}, lost {text}"
                );
            }
        }
        if scene == "crypto-details" {
            harness.render(
                size,
                true,
                vec![egui::Event::Key {
                    key: egui::Key::Escape,
                    physical_key: None,
                    pressed: true,
                    repeat: false,
                    modifiers: egui::Modifiers::NONE,
                }],
                |ctx| draw(&mut app, ctx),
            );
        } else {
            let close_pos = expected
                .iter()
                .find(|(t, _)| t == i18n::RU.journal_viewer_close)
                .unwrap()
                .1
                .center();
            harness.render(size, true, pointer_button(close_pos, true), |ctx| {
                draw(&mut app, ctx)
            });
            harness.render(size, true, pointer_button(close_pos, false), |ctx| {
                draw(&mut app, ctx)
            });
        }
        let still_open = match scene {
            "crypto-details" => app.crypto_details_open,
            "driver-details" => app.drivers_open,
            "disk-details" => app.raw_passes_open,
            "crash-analyzer" => app.crash_details_open,
            "sensor-details" => app.sensors_details_open,
            "stage-details" => app.stage_details.is_some(),
            "expc" => app.expc_details_open,
            "gpo" => app.gpo_details_open,
            _ => unreachable!(),
        };
        assert!(
            !still_open,
            "{scene}: Close was lost during a repeated layout pass"
        );
    }
}

fn app_in(tag: &str) -> (WinStateDiagApp, PathBuf) {
    let exe = std::env::temp_dir()
        .join(format!("wsd-v11-{tag}-{}", std::process::id()))
        .join("WinStateDiag");
    let _ = std::fs::remove_dir_all(exe.parent().unwrap());
    std::fs::create_dir_all(&exe).unwrap();
    let mut app = WinStateDiagApp::default();
    app.reports_root = exe.join("Reports");
    app.language_pref_dir = exe.clone();
    app.language = Language::Ru;
    app.computer_name = "MSI".into();
    app.package = Arc::new(Mutex::new(SessionPackage::new(exe.join("Reports"), None)));
    (app, exe)
}

fn cleanup(exe: &Path) {
    let _ = std::fs::remove_dir_all(exe.parent().unwrap());
}

fn audit() -> AuditReport {
    crate::details::tests::report()
}

fn inventory(debugger: crash_dump::DebuggerStatus) -> crash_dump::Inventory {
    crash_dump::Inventory {
        bugchecks: Vec::new(),
        dumps: vec![crash_dump::DumpFile {
            path: "C:\\Windows\\Minidump\\010100-00001-01.dmp".into(),
            name: "010100-00001-01.dmp".into(),
            size: 1024,
            modified: "2026-10-03T00:34:41".into(),
            kind: crash_dump::DumpKind::Mini,
        }],
        debugger,
        notes: Vec::new(),
        unexpected_shutdowns: 1,
        incidents: Vec::new(),
        live_kernel_reports: Vec::new(),
    }
}

/// Delivers a finished Driver Audit through the real poll path.
fn deliver_audit(app: &mut WinStateDiagApp, result: Result<AuditReport, String>) {
    let (tx, rx) = std::sync::mpsc::channel();
    app.driver_audit = DriverAuditState::Running(rx);
    tx.send(result).unwrap();
    app.poll_driver_audit();
}

/// Delivers a finished crash inventory scan through the real poll path.
fn deliver_scan(app: &mut WinStateDiagApp, inv: crash_dump::Inventory) {
    let (tx, rx) = std::sync::mpsc::channel();
    tx.send(CrashMsg::Inventory(Ok(inv))).unwrap();
    drop(tx);
    app.crash_rx = Some(rx);
    app.crash.busy = CrashBusy::Scanning;
    app.poll_crash();
}

// ---------------- 1. asynchronous startup ----------------

#[test]
fn startup_preflight_includes_passport_without_blocking_or_full_diagnostics() {
    let (mut app, exe) = app_in("async");
    let t0 = Instant::now();
    app.start_preflight();
    assert!(
        t0.elapsed() < Duration::from_millis(500),
        "never blocks the GUI"
    );
    assert_eq!(
        app.collector_requests,
        ["passport", "cryptopro", "crash_scan"]
    );
    assert!(matches!(app.driver_audit, DriverAuditState::Idle));
    assert_eq!(app.crypto_origin, CheckOrigin::Preflight);
    assert_eq!(app.crash.scan_origin, Some(CheckOrigin::Preflight));
    assert!(
        app.preflight_started
            .as_ref()
            .is_some_and(|s| s.origin == CheckOrigin::Preflight)
    );
    // Once per launch: a second call starts nothing.
    app.start_preflight();
    assert_eq!(app.collector_requests.len(), 3);
    // No EXPC session, no other module.
    assert!(matches!(app.state, RunState::Idle));
    assert!(app.sensors_rx.is_none() && app.passport_rx.is_none());
    assert!(app.gpo_rx.is_none() && app.events_rx.is_none() && app.ata_rx.is_none());
    cleanup(&exe);
}

// ---------------- 2. startup without session / report ----------------

#[test]
fn phase05_passport_refresh_failure_never_reuses_stale_inventory() {
    let (mut app, exe) = app_in("phase05_inventory");
    app.passport = Some(Ok(passport::Passport {
        cpu: "OLD CPU".into(),
        ..Default::default()
    }));
    app.start_passport();
    assert!(app.passport.is_none());
    let (tx, rx) = std::sync::mpsc::channel();
    app.passport_rx = Some(rx);
    let before = app.collector_requests.len();
    app.start_passport();
    assert_eq!(
        app.collector_requests.len(),
        before,
        "no overlapping collector"
    );
    assert!(
        app.passport_rows().is_empty(),
        "collecting, not old inventory"
    );
    drop(tx);
    app.poll_passport();
    assert!(matches!(&app.passport, Some(Err(e)) if e.contains("without a result")));
    assert_eq!(app.passport_rows().len(), 5);
    assert!(
        !app.passport_rows()
            .iter()
            .any(|r| r.value.contains("OLD CPU"))
    );
    let (tx, rx) = std::sync::mpsc::channel();
    app.passport_rx = Some(rx);
    tx.send(Err("timed out".into())).unwrap();
    app.poll_passport();
    assert!(matches!(&app.passport, Some(Err(e)) if e == "timed out"));
    assert!(matches!(app.state, RunState::Idle));
    assert!(report_package::lock(&app.package).is_fresh());
    cleanup(&exe);
}

#[test]
fn phase05_a1_remains_expanded_across_repaints_data_and_page_changes() {
    let (mut app, exe) = app_in("phase05_a1");
    let ctx = egui::Context::default();
    crate::ui::fonts::install(&ctx);
    for frame in 0..24 {
        app.apply(Action::SetPage(Page::Hardware));
        app.apply(Action::SetPage(Page::Diagnostics));
        app.passport = match frame % 3 {
            0 => None,
            1 => Some(Ok(passport::Passport {
                cpu: format!("Intel CPU {frame}"),
                ..Default::default()
            })),
            _ => Some(Err("source unavailable".into())),
        };
        let vm = app.build_vm(0.016, f64::from(frame));
        let labels = [
            &i18n::RU.passport_windows,
            &i18n::RU.passport_cpu,
            &i18n::RU.passport_ram,
            &i18n::RU.passport_board,
            &i18n::RU.passport_bios,
        ];
        let text = shown_texts(&ctx, |ui| {
            crate::ui::pages::draw_passport(ui, egui::Pos2::ZERO, &vm)
        });
        for label in labels {
            assert!(
                text.iter().any(|s| s == label),
                "missing {label} at frame {frame}"
            );
        }
    }
    // A1 is always expanded: no collapsible widget or data-dependent ID exists.
    let source = include_str!("ui/pages.rs");
    let body = source
        .split("pub fn draw_passport(")
        .nth(1)
        .unwrap()
        .split("pub fn passport_card_value_color")
        .next()
        .unwrap();
    assert!(!body.contains("Collapsing") && !body.contains("auto_id"));
    cleanup(&exe);
}

#[test]
fn rc4_a1_async_delivery_disconnect_and_repaint_keep_all_rows() {
    let (mut app, exe) = app_in("rc4-a1-async");
    let ctx = egui::Context::default();
    crate::ui::fonts::install(&ctx);
    for success in [true, false] {
        let (tx, rx) = std::sync::mpsc::channel();
        app.passport_rx = Some(rx);
        app.passport = None;
        app.poll_passport();
        assert!(app.passport_rx.is_some());
        if success {
            tx.send(Ok(passport::Passport {
                cpu: "RC4 fixture CPU".into(),
                ..Default::default()
            }))
            .unwrap();
        }
        drop(tx);
        app.poll_passport();
        assert!(app.passport_rx.is_none());
        assert_eq!(app.passport.as_ref().unwrap().is_ok(), success);
        for frame in 0..8 {
            app.apply(Action::SetPage(Page::Hardware));
            app.apply(Action::SetPage(Page::Diagnostics));
            let vm = app.build_vm(0.016, f64::from(frame));
            let text = shown_texts(&ctx, |ui| {
                crate::ui::pages::draw_passport(ui, egui::Pos2::ZERO, &vm)
            });
            for label in [
                i18n::RU.passport_cpu,
                i18n::RU.passport_ram,
                i18n::RU.passport_board,
                i18n::RU.passport_bios,
                i18n::RU.passport_windows,
            ] {
                assert!(text.iter().any(|s| s == label));
            }
        }
    }
    cleanup(&exe);
}

#[test]
fn rc4_crypto_compact_native_layout_has_no_text_overlap() {
    let mut app = WinStateDiagApp::default();
    app.language = Language::Ru;
    app.seed_qa_scene("crypto-details");
    app.crypto_detection = cryptopro::Detection::Installed(std::path::PathBuf::from(format!(
        "C:\\{}\\cpverify.exe",
        "long-provider-directory\\".repeat(12)
    )));
    let harness = NativeDetailsHarness::new();
    for size in [vec2(580.0, 390.0), vec2(420.0, 300.0), vec2(760.0, 460.0)] {
        let output = harness.render(size, true, vec![], |ctx| app.crypto_details_window(ctx));
        let texts = native_texts(&output);
        assert!(!texts.iter().any(|(t, _)| t == "Копировать"));
        let values: Vec<_> = app
            .crypto_detail_rows()
            .iter()
            .filter(|r| r.value != "—")
            .filter_map(|r| {
                texts
                    .iter()
                    .find(|(t, _)| t == &r.value)
                    .map(|(_, rect)| rect.min.x)
            })
            .collect();
        assert!(values.len() >= 3);
        assert!(
            values.iter().all(|x| (*x - values[0]).abs() <= 1.1),
            "value column must align: {values:?}"
        );
        for (index, (a, ar)) in texts.iter().enumerate() {
            for (b, br) in &texts[index + 1..] {
                assert!(
                    !ar.shrink(0.5).intersects(br.shrink(0.5)),
                    "overlap: {a:?} / {b:?} at {size:?}"
                );
            }
        }
        assert!(app.crypto_details_open);
    }
}

#[test]
fn rc4_b1_async_refresh_status_page_changes_keep_native_window_open() {
    let mut app = WinStateDiagApp::default();
    app.passport2_open = true;
    let harness = NativeDetailsHarness::new();
    for event in [
        HardwareEvent::Passport(crate::passport2::QA_PASSPORT_JSON.into()),
        HardwareEvent::Saving,
        HardwareEvent::Refreshed(Err("fixture export denied".into())),
        HardwareEvent::Closed,
        HardwareEvent::Failed("fixture collector timeout".into()),
    ] {
        app.apply_hardware_event(event);
        app.apply(Action::SetPage(Page::Diagnostics));
        app.apply(Action::SetPage(Page::Hardware));
        for _ in 0..3 {
            let output = harness.render(vec2(700.0, 520.0), true, vec![], |ctx| {
                app.passport2_window(ctx)
            });
            assert!(app.passport2_open);
            assert!(!native_texts(&output).is_empty());
            for viewport in output.viewport_output.values() {
                assert!(!viewport.commands.iter().any(|c| matches!(
                    c,
                    egui::ViewportCommand::Close | egui::ViewportCommand::Minimized(true)
                )));
            }
        }
    }
}

#[test]
fn rc4_b1_footer_does_not_consume_the_scroll_body_on_repaint() {
    let mut app = WinStateDiagApp::default();
    app.passport2_open = true;
    app.passport2_json = Some(crate::passport2::QA_PASSPORT_JSON.into());
    let harness = NativeDetailsHarness::new();
    for _ in 0..30 {
        let output = harness.render(vec2(1060.0, 860.0), true, vec![], |ctx| {
            app.passport2_window(ctx)
        });
        let texts = native_texts(&output);
        let footer = texts
            .iter()
            .find(|(text, _)| text == i18n::RU.pp_refresh)
            .unwrap();
        assert!(footer.1.top() > 600.0, "body collapsed: {:?}", footer.1);
    }
}

#[test]
fn preflight_results_create_no_session_report_or_held_evidence() {
    let (mut app, exe) = app_in("noreport");
    app.start_preflight();
    // Explicit legacy-result fixture; startup itself must never launch A5.
    app.driver_origin = CheckOrigin::Preflight;
    deliver_audit(&mut app, Ok(audit()));
    deliver_scan(
        &mut app,
        inventory(crash_dump::DebuggerStatus::NotInstalled),
    );
    let (tx, rx) = std::sync::mpsc::channel();
    tx.send(CryptoEvent::Checked(
        cryptopro::Detection::NotInstalled,
        cryptopro::HashState::NotInstalled,
    ))
    .unwrap();
    app.crypto_rx = Some(rx);
    app.poll_crypto();
    let package = report_package::lock(&app.package);
    assert!(package.is_fresh(), "no report / session / ZIP");
    assert!(package.session().is_none());
    assert!(package.final_zip().is_none());
    assert_eq!(
        package.pending_len(),
        0,
        "nothing held back for a later client report"
    );
    drop(package);
    assert!(!exe.join("Reports").exists(), "no report folder");
    cleanup(&exe);
}

// ---------------- 3. auto Driver Audit ----------------

#[test]
fn legacy_preflight_driver_result_keeps_origin_and_time() {
    let (mut app, exe) = app_in("autodrv");
    app.start_preflight();
    // Explicit legacy-result fixture; startup itself must never launch A5.
    app.driver_origin = CheckOrigin::Preflight;
    deliver_audit(&mut app, Ok(audit()));
    assert!(matches!(app.driver_audit, DriverAuditState::Done(_)));
    let stamp = app.driver_checked.clone().expect("checked");
    assert_eq!(stamp.origin, CheckOrigin::Preflight);
    assert_eq!(stamp.at.len(), 19, "{}", stamp.at);
    assert_eq!(app.driver_history.len(), 1);
    let vm = app.build_vm(0.0, 0.0);
    assert!(matches!(vm.drivers, DriversVm::Done { .. }));
    assert!(
        vm.drivers_caption
            .as_deref()
            .is_some_and(|c| c.starts_with(i18n::RU.origin_preflight_short)),
        "{:?}",
        vm.drivers_caption
    );
    assert!(vm.drivers_check_enabled);
    assert!(
        app.journal
            .iter()
            .any(|e| e.message.starts_with(i18n::RU.origin_preflight)),
        "the journal line says it was a preflight check"
    );
    cleanup(&exe);
}

// ---------------- 4. auto CryptoPro: see startup_idle_tests ----------------

#[test]
fn auto_cryptopro_never_rehashes_and_its_check_is_read_only() {
    let (mut app, exe) = app_in("autocrypto");
    app.start_preflight();
    assert!(!app.collector_requests.contains(&"cryptopro_rehash"));
    // The preflight check found NO HASH: ReHash is only offered.
    app.crypto = Some(cryptopro::HashState::NoHash);
    assert!(app.crypto_rx.is_none());
    assert!(!app.crypto_rehash_confirm);
    assert!(!app.collector_requests.contains(&"cryptopro_rehash"));
    // The check itself is cpverify -rv only (source contract).
    let src = include_str!("cryptopro.rs").replace("\r\n", "\n");
    let check = &src[src.find("pub fn check(").unwrap()..];
    let check = &check[..check.find("\n}\n").unwrap()];
    assert!(check.contains("\"-rv\""));
    assert!(!check.contains("\"-rm\""));
    cleanup(&exe);
}

// ---------------- 5. auto WinDbg detection ----------------

#[test]
fn auto_windbg_detection_states() {
    let (mut app, exe) = app_in("windbg");
    let d = &i18n::RU;
    assert_eq!(
        app.crash_vm().debugger,
        d.windbg_unknown,
        "before detection"
    );
    for (status, expected) in [
        (
            crash_dump::DebuggerStatus::Installed {
                cdb: "C:\\cdb.exe".into(),
            },
            d.windbg_backend_ready,
        ),
        (
            crash_dump::DebuggerStatus::PackageOnly {
                package: "Microsoft.WinDbg 1.2506".into(),
            },
            d.windbg_package_only,
        ),
        (crash_dump::DebuggerStatus::NotInstalled, d.windbg_not_found),
        (
            crash_dump::DebuggerStatus::Error("x".into()),
            d.windbg_unknown,
        ),
    ] {
        app.start_crash_scan_as(CheckOrigin::Preflight);
        deliver_scan(&mut app, inventory(status));
        assert_eq!(app.crash_vm().debugger, expected);
    }
    // No install is ever started by the detection.
    assert!(!app.collector_requests.contains(&"windbg_install"));
    assert!(matches!(app.crash.install, InstallState::Idle));
    cleanup(&exe);
}

// ---------------- 6. crash discovery without debugger execution ----------------

#[test]
fn preflight_crash_discovery_never_runs_the_debugger() {
    let (mut app, exe) = app_in("nodebug");
    app.start_preflight();
    deliver_scan(
        &mut app,
        inventory(crash_dump::DebuggerStatus::Installed {
            cdb: "C:\\cdb.exe".into(),
        }),
    );
    assert!(app.crash.analyses.is_empty(), "no !analyze");
    assert!(app.crash.progress.is_none());
    assert_eq!(app.crash.busy, CrashBusy::Idle);
    assert!(app.crash_rx.is_none());
    let checked = app.crash.inventory_checked.clone().unwrap();
    assert_eq!(checked.origin, CheckOrigin::Preflight);
    assert!(
        app.crash_vm()
            .counts
            .contains(i18n::RU.origin_preflight_short)
    );
    // The explicit «Analyze» on a preflight listing scans again for its own
    // session first (never analyzes the preflight listing into a report).
    app.client_name = "Клиент".into();
    app.start_crash_analysis();
    assert!(app.crash_analyze_after_scan);
    assert_eq!(app.crash.scan_origin, Some(CheckOrigin::Manual));
    cleanup(&exe);
}

// ---------------- 7. client identity isolation ----------------

#[test]
fn preflight_results_never_join_the_client_session() {
    let (mut app, exe) = app_in("isolation");
    app.start_preflight();
    // Preflight Driver Audit and crash scan are still running when the
    // user starts the full diagnostic for a client.
    let (dtx, drx) = std::sync::mpsc::channel();
    app.driver_audit = DriverAuditState::Running(drx);
    let (ctx_, crx) = std::sync::mpsc::channel();
    app.crash_rx = Some(crx);
    app.crash.busy = CrashBusy::Scanning;
    app.client_name = "Клиент А".into();
    app.start_diagnostics();
    assert!(app.is_running());
    let session = app.session_identity().expect("full session");
    assert_eq!(session.client, "Клиент А");
    assert!(
        app.crash.rescan_for_session,
        "the session gets its own scan"
    );
    // The preflight Driver Audit was cancelled (the engine audits for the
    // session) — its late result has nowhere to go …
    assert!(matches!(app.driver_audit, DriverAuditState::Idle));
    assert!(
        app.driver_draining.is_some(),
        "drained until its worker ends"
    );
    dtx.send(Ok(audit())).unwrap();
    app.poll_driver_audit();
    assert!(app.driver_draining.is_none());
    assert!(
        matches!(app.driver_audit, DriverAuditState::Idle),
        "result discarded"
    );
    // … and the preflight crash listing arrives during the session …
    ctx_.send(CrashMsg::Inventory(Ok(inventory(
        crash_dump::DebuggerStatus::NotInstalled,
    ))))
    .unwrap();
    drop(ctx_);
    let requests = app.collector_requests.len();
    app.poll_crash();
    // … and none of them is evidence of the client session.
    assert_eq!(
        report_package::lock(&app.package).pending_len(),
        0,
        "preflight audit not offered"
    );
    assert!(
        app.crash.inventory_session.is_none(),
        "preflight listing observed by no session"
    );
    assert_eq!(
        app.collector_requests[requests..],
        ["crash_scan"],
        "a fresh SESSION scan follows"
    );
    assert_eq!(app.crash.scan_origin, Some(CheckOrigin::Session));
    let zip = report_package::lock(&app.package).final_zip();
    if let Some(zip) = zip {
        let names: Vec<String> = report_package::read_zip(&zip)
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert!(
            !names.iter().any(|n| n.starts_with("DriverAudit_")),
            "{names:?}"
        );
        assert!(
            !names
                .iter()
                .any(|n| n.starts_with(incidents::EVIDENCE_PREFIX)),
            "{names:?}"
        );
    }
    cleanup(&exe);
}

// ---------------- 8. repeated CryptoPro re-check ----------------

#[test]
fn crypto_recheck_is_fresh_read_only_and_never_parallel() {
    let (mut app, exe) = app_in("recheck");
    app.crypto = Some(cryptopro::HashState::HashOk);
    app.crypto_checked = Some(CheckStamp::now(CheckOrigin::Preflight));
    app.apply(Action::CryptoRecheck);
    assert_eq!(app.collector_requests, ["cryptopro"]);
    assert_eq!(app.crypto_origin, CheckOrigin::Manual);
    assert!(
        app.crypto.is_none(),
        "the previous state is not shown as current"
    );
    assert!(app.crypto_inventory.is_none());
    // While a check runs, ⟳ is disabled and a click starts nothing.
    let (tx, rx) = std::sync::mpsc::channel();
    app.crypto_rx = Some(rx);
    assert!(!app.build_vm(0.0, 0.0).crypto_recheck_enabled);
    app.apply(Action::CryptoRecheck);
    assert_eq!(app.collector_requests.len(), 1, "no parallel check");
    tx.send(CryptoEvent::Checked(
        cryptopro::Detection::NotInstalled,
        cryptopro::HashState::HashOk,
    ))
    .unwrap();
    app.poll_crypto();
    assert_eq!(
        app.crypto_checked.as_ref().map(|s| s.origin),
        Some(CheckOrigin::Manual)
    );
    // Every ⟳ is a new check.
    app.apply(Action::CryptoRecheck);
    assert_eq!(app.collector_requests.len(), 2);
    cleanup(&exe);
}

// ---------------- 9. ReHash explicit confirmation ----------------

#[test]
fn rehash_explicit_click_starts_once_and_never_runs_during_a_check() {
    let (mut app, exe) = app_in("rehash");
    app.crypto = Some(cryptopro::HashState::NoHash);
    // A check is running: no ReHash, not even the confirmation.
    let (_tx, rx) = std::sync::mpsc::channel();
    app.crypto_rx = Some(rx);
    app.apply(Action::CryptoRehashRequest);
    assert!(!app.crypto_rehash_confirm);
    app.crypto_rx = None;
    // Explicit click is the authorization; no modal or automatic execution.
    assert!(!app.collector_requests.contains(&"cryptopro_rehash"));
    app.apply(Action::CryptoRehashRequest);
    assert!(!app.crypto_rehash_confirm);
    assert!(app.crypto_rx.is_some());
    // Repeated clicks while running cannot start another operation.
    app.apply(Action::CryptoRehashRequest);
    assert_eq!(
        app.collector_requests
            .iter()
            .filter(|r| **r == "cryptopro_rehash")
            .count(),
        1
    );
    assert!(app.crypto_rx.is_some());
    let src = include_str!("cryptopro.rs").replace("\r\n", "\n");
    let rehash = &src[src.find("pub fn rehash(").unwrap()..];
    let rehash = &rehash[..rehash.find("\n}\n").unwrap()];
    assert!(
        rehash.find("\"-rm\"").unwrap() < rehash.rfind("check(det, runner)").unwrap(),
        "verified again (cpverify -rv) after ReHash"
    );
    // v1.1 UI contract: the confirmation is its own window (opened by
    // the card's round button) with the warning; Details only points to
    // the card and has no ReHash action of its own.
    let ctx = egui::Context::default();
    crate::ui::fonts::install(&ctx);
    app.crypto_rx = None;
    app.crypto = Some(cryptopro::HashState::NoHash);
    app.crypto_details_open = true;
    let mut details = Vec::new();
    for _ in 0..3 {
        details = shown_texts(&ctx, |ui| app.crypto_details_window(ui.ctx()));
    }
    assert!(
        !details
            .iter()
            .any(|t| t == i18n::RU.crypto_rehash_from_card_note)
    );
    assert!(!details.iter().any(|t| t == i18n::RU.crypto_rehash_action));
    app.crypto_rehash_confirm = true;
    let mut texts = Vec::new();
    for _ in 0..3 {
        texts = shown_texts(&ctx, |ui| app.crypto_rehash_confirm_window(ui.ctx()));
    }
    assert!(
        texts.iter().any(|t| t.contains("ИЗМЕНЯЕТ СИСТЕМУ")),
        "{texts:?}"
    );
    assert!(
        texts
            .iter()
            .any(|t| t == i18n::RU.crypto_rehash_confirm_yes)
    );
    cleanup(&exe);
}

// ---------------- 10. Driver Audit manual re-check ----------------

#[test]
fn driver_manual_recheck_replaces_on_success_and_keeps_on_failure() {
    let (mut app, exe) = app_in("drvrecheck");
    deliver_audit(&mut app, Ok(audit()));
    app.client_name = "Клиент".into();
    app.apply(Action::CheckDrivers);
    assert_eq!(app.collector_requests, ["driver_audit"]);
    assert_eq!(app.driver_origin, CheckOrigin::Manual);
    // Only this module: no EXPC session, no other collector.
    assert!(matches!(app.state, RunState::Idle));
    // A failed re-check keeps the last good result.
    let Some(prev) = (match std::mem::replace(&mut app.driver_audit, DriverAuditState::Idle) {
        DriverAuditState::Done(r) => Some(r),
        _ => None,
    }) else {
        panic!("done")
    };
    app.driver_previous = Some(prev);
    deliver_audit(&mut app, Err("timeout".into()));
    assert!(matches!(app.driver_audit, DriverAuditState::Done(_)));
    assert!(
        app.driver_history
            .last()
            .is_some_and(|e| e.outcome.contains("timeout"))
    );
    // A successful re-check replaces it.
    deliver_audit(&mut app, Ok(audit()));
    assert!(app.driver_previous.is_none());
    assert_eq!(app.driver_history.len(), 3);
    // Running: «Проверка» disabled, a click starts nothing.
    let (_tx, rx) = std::sync::mpsc::channel();
    app.driver_audit = DriverAuditState::Running(rx);
    assert!(!app.build_vm(0.0, 0.0).drivers_check_enabled);
    let before = app.collector_requests.len();
    app.apply(Action::CheckDrivers);
    assert_eq!(app.collector_requests.len(), before, "no parallel scan");
    cleanup(&exe);
}

#[test]
fn driver_history_clear_needs_confirmation_and_touches_nothing_else() {
    let (mut app, exe) = app_in("drvclear");
    deliver_audit(&mut app, Ok(audit()));
    deliver_audit(&mut app, Ok(audit()));
    let ctx = egui::Context::default();
    app.apply_history_act(&ctx, v11::HistoryAct::ClearRequest);
    assert!(app.driver_history_clear_confirm);
    assert_eq!(app.driver_history.len(), 2, "not before confirmation");
    app.apply_history_act(&ctx, v11::HistoryAct::ClearCancelled);
    assert_eq!(app.driver_history.len(), 2);
    app.apply_history_act(&ctx, v11::HistoryAct::ClearRequest);
    app.apply_history_act(&ctx, v11::HistoryAct::ClearConfirmed);
    assert!(app.driver_history.is_empty());
    // The audit result and the session journal stay.
    assert!(matches!(app.driver_audit, DriverAuditState::Done(_)));
    assert!(app.journal.len() >= 2);
    // Save = the CURRENT Driver Audit report only (Save As / logs dir).
    app.apply_history_act(&ctx, v11::HistoryAct::SaveReport);
    match &app.driver_export_status {
        Some(ExportStatus::Saved(p)) => {
            let text = std::fs::read_to_string(p).unwrap();
            assert!(text.contains(&driver_audit::to_text(&audit())[..40]));
        }
        other => panic!("{other:?}"),
    }
    cleanup(&exe);
}

// ---------------- 11. cancel / close during background checks ----------------

#[test]
fn closing_the_app_cancels_background_processes() {
    let (mut app, exe) = app_in("close");
    let cancel = Arc::new(AtomicBool::new(false));
    app.session_cancel = Some(Arc::clone(&cancel));
    app.crash.rescan_for_session = true;
    app.crypto_recheck_for_session = true;
    app.crash_analyze_after_scan = true;
    let flag = AtomicBool::new(false);
    app.shutdown(&flag);
    assert!(flag.load(Ordering::SeqCst));
    assert!(
        cancel.load(Ordering::SeqCst),
        "the running diagnostic stops"
    );
    assert!(!app.crash.rescan_for_session && !app.crypto_recheck_for_session);
    assert!(!app.crash_analyze_after_scan, "nothing new starts");
    // A waiting collector ends its process tree on the shutdown flag.
    #[cfg(windows)]
    {
        let mut cmd = std::process::Command::new("ping");
        cmd.args(["-n", "30", "127.0.0.1"])
            .stdout(std::process::Stdio::null());
        let mut guard = engine::ProcessGuard::spawn(cmd).unwrap();
        let never = AtomicBool::new(false);
        let t0 = Instant::now();
        let r = guard.wait_or_cancel_with(&never, &flag, Some(Duration::from_secs(60)));
        assert!(matches!(r, Err(engine::WaitEnd::Cancelled)));
        assert!(t0.elapsed() < Duration::from_secs(10));
    }
    // The real app close calls it with the global flag.
    let src = include_str!("app.rs").replace("\r\n", "\n");
    assert!(src.contains("    fn on_exit(&mut self) {\n        self.shutdown(&engine::SHUTDOWN);"));
    let lib = include_str!("lib.rs").replace("\r\n", "\n");
    let on_exit = &lib[lib.find("    fn on_exit(&mut self) {").unwrap()..];
    assert!(on_exit[..200].contains("self.inner.on_exit();"));
    cleanup(&exe);
}

// ---------------- 12. concurrent action rejection ----------------

#[test]
fn concurrent_actions_are_rejected() {
    let (mut app, exe) = app_in("concurrent");
    // Crash scan already running: a second scan claims / starts nothing.
    let (_tx, rx) = std::sync::mpsc::channel();
    app.crash_rx = Some(rx);
    app.crash.scan_origin = Some(CheckOrigin::Manual);
    app.start_crash_scan_as(CheckOrigin::Manual);
    assert!(app.op_packages.get("crash").is_none());
    assert_eq!(app.crash.scan_origin, Some(CheckOrigin::Manual));
    // Analysis while scanning: rejected.
    app.crash.busy = CrashBusy::Scanning;
    app.start_crash_analysis();
    assert!(!app.crash_analyze_after_scan);
    // Passport refresh while a collection runs: journaled, not started.
    let (_htx, hrx) = std::sync::mpsc::channel();
    app.hardware = HardwareViewState::Collecting {
        rx: hrx,
        started: Instant::now(),
        saving: false,
    };
    let before = app.collector_requests.len();
    app.start_hardware_view();
    assert_eq!(app.collector_requests.len(), before);
    cleanup(&exe);
}

// ---------------- 13. Hardware Passport single-page layout ----------------

fn shown_texts(ctx: &egui::Context, mut f: impl FnMut(&mut egui::Ui)) -> Vec<String> {
    fn walk(shape: &egui::Shape, acc: &mut Vec<String>) {
        match shape {
            egui::Shape::Text(t) => acc.push(t.galley.text().to_string()),
            egui::Shape::Vec(v) => v.iter().for_each(|s| walk(s, acc)),
            _ => {}
        }
    }
    let input = egui::RawInput {
        screen_rect: Some(Rect::from_min_size(egui::Pos2::ZERO, vec2(1400.0, 1200.0))),
        ..Default::default()
    };
    let mut out = ctx.run_ui(input, |ui| f(ui));
    out.textures_delta.clear();
    let mut acc = Vec::new();
    for c in &out.shapes {
        walk(&c.shape, &mut acc);
    }
    acc
}

#[test]
fn hardware_passport_is_one_page_with_all_cards_and_a_fixed_footer() {
    for (lang, d) in [(Language::Ru, &i18n::RU), (Language::En, &i18n::EN)] {
        let (mut app, exe) = app_in("passport");
        app.language = lang;
        app.apply_hardware_event(engine::HardwareEvent::Passport(
            crate::passport2::QA_PASSPORT_JSON.to_string(),
        ));
        assert!(app.passport2_open);
        let ctx = egui::Context::default();
        crate::ui::fonts::install(&ctx);
        let mut texts = Vec::new();
        for _ in 0..3 {
            texts = shown_texts(&ctx, |ui| app.passport2_window(ui.ctx()));
        }
        for title in [
            d.pp_cpu,
            d.pp_ram,
            d.pp_board,
            d.pp_bios,
            d.pp_storage,
            d.pp_gpu,
        ] {
            assert!(texts.iter().any(|t| t == title), "{lang:?}: {title}");
        }
        for button in [d.pp_refresh, d.pp_copy, d.pp_save, d.pp_close] {
            assert!(texts.iter().any(|t| t == button), "{lang:?}: {button}");
        }
        // No tab navigation and no universal verdict.
        for gone in ["Обзор", "Raw JSON", "ОБЩИЙ СТАТУС", "Overview"] {
            assert!(!texts.iter().any(|t| t == gone), "{gone}");
        }
        assert!(texts.iter().any(|t| t == d.pp_legend_measured));
        cleanup(&exe);
    }
}

#[test]
fn hardware_passport_copy_save_and_close() {
    let (mut app, exe) = app_in("ppexport");
    app.passport2_json = Some(crate::passport2::QA_PASSPORT_JSON.to_string());
    app.passport2_open = true;
    let view = app.passport2_view().unwrap();
    let text = crate::passport2::summary_text(&view, &i18n::RU);
    assert!(text.contains("Intel(R) Core(TM) Ultra 7 270K Plus"));
    let ctx = egui::Context::default();
    app.passport2_status =
        Some(app.export_text(&ctx, ExportAction::Save, "HardwarePassport", &text));
    match &app.passport2_status {
        Some(ExportStatus::Saved(p)) => {
            assert!(std::fs::read_to_string(p).unwrap().contains("[Процессор]"))
        }
        other => panic!("{other:?}"),
    }
    cleanup(&exe);
}

// ---------------- 14. crash parser field consistency ----------------

#[test]
fn crash_fields_are_filled_from_raw_and_process_name_is_never_cut() {
    let raw = "BUGCHECK_CODE:  139\n0: kd> MODULE_NAME: RvNetMP60\n3: kd> IMAGE_NAME:  RvNetMP60.sys\nPROCESS_NAME:  RvControlSvc.e\nImage path: C:\\Program Files\\Famatech\\Radmin VPN\\RvControlSvc.exe\n";
    let p = crash_dump::parse_analyze_output(raw);
    assert_eq!(p.module_name.as_deref(), Some("RvNetMP60"));
    assert_eq!(p.image_name.as_deref(), Some("RvNetMP60.sys"));
    assert_eq!(p.process_name.as_deref(), Some("RvControlSvc.exe"));
    assert!(!p.process_name_truncated);
    // Only the debugger's short form: kept as printed, flagged.
    let p = crash_dump::parse_analyze_output("PROCESS_NAME:  RvControlSvc.e\n");
    assert_eq!(p.process_name.as_deref(), Some("RvControlSvc.e"));
    assert!(p.process_name_truncated);
    // A full name stays untouched (the parser never shortens).
    let p = crash_dump::parse_analyze_output("PROCESS_NAME:  VeryLongProcessName.exe\n");
    assert_eq!(p.process_name.as_deref(), Some("VeryLongProcessName.exe"));
    assert!(!p.process_name_truncated);
    // Not a key inside another identifier.
    let p = crash_dump::parse_analyze_output("XMODULE_NAME: nope\n");
    assert_eq!(p.module_name, None);
}

#[test]
fn natvis_noise_is_hidden_from_the_main_view_but_kept_raw() {
    let raw = "start\nNatVis script unloaded from 'C:\\x\\atlmfc.natvis'\nImage path: x\n----> Repository : UserExtensions, Enabled: true\nend";
    let clean = crash_dump::without_debugger_noise(raw);
    assert!(!clean.contains("NatVis"));
    assert!(!clean.contains("Repository"));
    assert!(clean.contains("Image path: x"));
    assert!(raw.contains("NatVis"), "raw untouched");
}

#[test]
fn statuses_are_localized_with_canonical_ids() {
    assert_eq!(
        crash_dump::Confidence::Medium.label(true),
        "средняя (MEDIUM)"
    );
    assert_eq!(
        crash_dump::Confidence::Medium.label(false),
        "medium (MEDIUM)"
    );
    assert_eq!(crash_dump::Confidence::Medium.code(), "MEDIUM");
    let v = incidents::Verdict {
        hang_confirmed: false,
        bsod_registered: true,
        subsystem: None,
        confidence: incidents::Confidence::Low,
        signals: Vec::new(),
        dump_cause: None,
    };
    let ru = v.headline_localized(true);
    assert!(
        ru.contains("зависание не подтверждено (HANG NOT CONFIRMED)"),
        "{ru}"
    );
    assert!(ru.contains("(BSOD REGISTERED)"));
    assert!(
        v.headline().starts_with("HANG NOT CONFIRMED"),
        "canonical kept"
    );
    // The crash card / details show the localized forms.
    let (mut app, exe) = app_in("crashloc");
    app.crash.inventory = Some(Ok(qa_scenes::qa_inventory()));
    app.crash.analyses = vec![qa_scenes::qa_analysis()];
    let vm = app.crash_vm();
    assert!(
        vm.rows.iter().any(|r| r.value == "средняя (MEDIUM)"),
        "{:?}",
        vm.rows
    );
    assert!(vm.headline.contains("средняя (MEDIUM)"));
    // 0x139 → RvNetMP60.sys → Radmin VPN → MEDIUM stays.
    let a = &app.crash.analyses[0];
    assert_eq!(a.confidence, crash_dump::Confidence::Medium);
    assert_eq!(a.probable_module().as_deref(), Some("RvNetMP60.sys"));
    // Evidence keeps the canonical identifier.
    let ev = crash_dump::summary_json(a, None, "analysis.txt");
    let v = json::parse(&ev).unwrap();
    assert_eq!(v.get("confidence").and_then(|x| x.as_str()), Some("MEDIUM"));
    cleanup(&exe);
}

// ---------------- 15. RU / EN / DPI ----------------

#[test]
fn v11_texts_exist_in_both_languages() {
    let pairs = [
        (i18n::RU.origin_preflight, i18n::EN.origin_preflight),
        (i18n::RU.crypto_details_title, i18n::EN.crypto_details_title),
        (
            i18n::RU.crypto_rehash_warning,
            i18n::EN.crypto_rehash_warning,
        ),
        (i18n::RU.driver_check_button, i18n::EN.driver_check_button),
        (i18n::RU.driver_history_clear, i18n::EN.driver_history_clear),
        (i18n::RU.pp_title, i18n::EN.pp_title),
        (i18n::RU.pp_unconfirmed_title, i18n::EN.pp_unconfirmed_title),
        (i18n::RU.windbg_backend_ready, i18n::EN.windbg_backend_ready),
    ];
    for (ru, en) in pairs {
        assert!(!ru.is_empty() && !en.is_empty());
        assert_ne!(ru, en);
        assert!(
            !en.chars().any(|c| ('\u{0400}'..='\u{04FF}').contains(&c)),
            "{en}"
        );
    }
}

#[test]
fn passport_layout_follows_the_window_width_and_dpi() {
    let view = crate::passport2::build(
        crate::passport2::QA_PASSPORT_JSON,
        &crate::passport2::Texts {
            ru: true,
            d: &i18n::RU,
        },
    )
    .unwrap();
    // Card titles' left edges: one column narrow (or at 150 % DPI on the
    // same physical width), two columns wide.
    let xs = |width: f32, ppp: f32| {
        let ctx = egui::Context::default();
        crate::ui::fonts::install(&ctx);
        ctx.set_pixels_per_point(ppp);
        let mut xs: Vec<f32> = Vec::new();
        for _ in 0..3 {
            let input = egui::RawInput {
                screen_rect: Some(Rect::from_min_size(egui::Pos2::ZERO, vec2(width, 2400.0))),
                ..Default::default()
            };
            let mut out = ctx.run_ui(input, |ui| v11::passport_body(ui, &i18n::RU, &view));
            out.textures_delta.clear();
            xs.clear();
            for c in &out.shapes {
                if let egui::Shape::Text(t) = &c.shape
                    && (t.galley.text() == i18n::RU.pp_cpu || t.galley.text() == i18n::RU.pp_ram)
                {
                    xs.push(c.shape.visual_bounding_rect().min.x);
                }
            }
        }
        xs
    };
    let wide = xs(1100.0, 1.0);
    assert_eq!(wide.len(), 2);
    assert!((wide[0] - wide[1]).abs() > 100.0, "two columns: {wide:?}");
    let narrow = xs(700.0, 1.0);
    assert_eq!(narrow.len(), 2);
    assert!(
        (narrow[0] - narrow[1]).abs() < 20.0,
        "one column: {narrow:?}"
    );
    // 1100 physical px at 150 % = 733 points: one column, nothing lost.
    let dpi = xs(1100.0 / 1.5, 1.5);
    assert!((dpi[0] - dpi[1]).abs() < 20.0, "{dpi:?}");
}

#[test]
fn dashboard_crypto_and_driver_headers_fit_at_100_125_150() {
    for scale in [1.0_f32, 1.25, 1.5] {
        for lang in [Language::Ru, Language::En] {
            let ctx = egui::Context::default();
            crate::ui::fonts::install(&ctx);
            ctx.set_pixels_per_point(scale);
            let vm = crate::ui::fixture::master_vm_in(lang);
            let d = i18n::t(lang);
            let mut boxes: Vec<(String, Rect)> = Vec::new();
            for _ in 0..3 {
                let input = egui::RawInput {
                    screen_rect: Some(Rect::from_min_size(
                        egui::Pos2::ZERO,
                        vec2(
                            crate::ui::tokens::CANVAS_W / scale,
                            crate::ui::tokens::CANVAS_H / scale,
                        ),
                    )),
                    ..Default::default()
                };
                let mut client = String::new();
                let mut mode = engine::DiagnosticMode::Standard;
                let mut deep = engine::DeepChecks::default();
                let mut hw = true;
                let mut path = String::new();
                let mut out = ctx.run_ui(input, |ui| {
                    let mut controls = Controls {
                        client_name: &mut client,
                        mode: &mut mode,
                        deep_checks: &mut deep,
                        include_hardware: &mut hw,
                        benchmark_path: &mut path,
                    };
                    let mut actions = Vec::new();
                    dashboard::draw(ui, egui::pos2(0.0, 0.0), &vm, &mut controls, &mut actions);
                });
                out.textures_delta.clear();
                boxes.clear();
                for c in &out.shapes {
                    if let egui::Shape::Text(t) = &c.shape {
                        boxes.push((t.galley.text().to_string(), c.shape.visual_bounding_rect()));
                    }
                }
            }
            let find = |s: &str| boxes.iter().find(|(t, _)| t == s).map(|(_, r)| *r);
            let title = find(d.driver_title).expect("driver title");
            let check = find(d.driver_check_button).expect("check button");
            assert!(
                title.max.x < check.min.x,
                "{lang:?} {scale}: title {title:?} overlaps «{}» {check:?}",
                d.driver_check_button
            );
            let name = find("CryptoPro").expect("name");
            assert!(
                name.max.x
                    <= crate::ui::tokens::layout::CRYPTO_RECHECK_CENTER[0]
                        - crate::ui::tokens::layout::CRYPTO_RECHECK_D / 2.0
                        + 1.0,
                "{lang:?} {scale}: CryptoPro name runs into ⟳"
            );
        }
    }
}

// ---------------- PR #4 review round 1 regressions ----------------

/// P1: preflight results are display-only — the manifest states and the
/// crash-dump correlation of a client report never use them.
#[test]
fn preflight_results_never_feed_report_states_or_correlation() {
    let (mut app, exe) = app_in("derived");
    app.start_preflight();
    // Explicit legacy-result fixture; startup itself must never launch A5.
    app.driver_origin = CheckOrigin::Preflight;
    let mut bad = audit();
    bad.overall = Severity::Problem;
    deliver_audit(&mut app, Ok(bad));
    let mut inv = inventory(crash_dump::DebuggerStatus::NotInstalled);
    inv.bugchecks = vec![crash_dump::BugcheckEvent {
        time: local_iso(sysinfo::local_time()),
        code: 0x139,
        params: Vec::new(),
        dump_path: None,
        source: crash_dump::BugcheckSource::Wer1001,
    }];
    app.start_crash_scan_as(CheckOrigin::Preflight);
    deliver_scan(&mut app, inv.clone());
    // Shown on the cards …
    assert!(app.audit_report().is_some());
    assert!(matches!(app.crash.inventory, Some(Ok(_))));
    // … but never a report's state or correlation input.
    assert!(app.report_audit().is_none());
    assert!(app.report_inventory().is_none());
    assert_eq!(app.state_codes().0, "NO_DATA");
    // The same data from a SESSION / manual run is used.
    app.start_crash_scan_as(CheckOrigin::Manual);
    deliver_scan(&mut app, inv);
    app.driver_origin = CheckOrigin::Manual;
    let mut bad = audit();
    bad.overall = Severity::Problem;
    deliver_audit(&mut app, Ok(bad));
    assert!(app.report_audit().is_some());
    assert_eq!(app.state_codes().0, "ATTENTION_BSOD");
    cleanup(&exe);
}

/// P1: a full diagnostic cancels a running app-side audit (its process
/// tree ends) — the engine's audit is the only one; no manual audit can
/// start during the session.
#[test]
fn start_diagnostics_cancels_the_running_preflight_audit() {
    let (mut app, exe) = app_in("drvcancel");
    app.start_preflight();
    let (tx, rx) = std::sync::mpsc::channel::<Result<AuditReport, String>>();
    app.driver_audit = DriverAuditState::Running(rx);
    let cancel = app.new_driver_cancel();
    app.client_name = "Клиент".into();
    app.start_diagnostics();
    assert!(cancel.load(Ordering::SeqCst), "process tree ends");
    assert!(matches!(app.driver_audit, DriverAuditState::Idle));
    assert!(
        app.journal
            .iter()
            .any(|e| e.message == i18n::RU.driver_cancelled_for_session)
    );
    drop(tx);
    // During the session «Проверка» is disabled and starts nothing.
    assert!(!app.build_vm(0.0, 0.0).drivers_check_enabled);
    let before = app.collector_requests.len();
    app.apply(Action::CheckDrivers);
    assert_eq!(app.collector_requests.len(), before);
    cleanup(&exe);
}

/// P2: whatever CryptoPro operation runs when a diagnostic starts (⟳ or a
/// ReHash), the session gets its own fresh check right after it.
#[test]
fn session_gets_its_own_crypto_check_after_a_manual_check_or_rehash() {
    for rehash in [false, true] {
        let (mut app, exe) = app_in("cryptosession");
        let (tx, rx) = std::sync::mpsc::channel();
        app.crypto_rx = Some(rx);
        app.crypto_origin = CheckOrigin::Manual;
        app.client_name = "Клиент".into();
        app.start_diagnostics();
        assert!(app.crypto_recheck_for_session, "rehash={rehash}");
        let before = app.collector_requests.len();
        if rehash {
            tx.send(CryptoEvent::Rehashed(cryptopro::RehashOutcome {
                state: cryptopro::HashState::HashOk,
                journal: vec!["[PASS] ReHash".into()],
            }))
            .unwrap();
        } else {
            tx.send(CryptoEvent::Checked(
                cryptopro::Detection::NotInstalled,
                cryptopro::HashState::HashOk,
            ))
            .unwrap();
        }
        app.poll_crypto();
        assert_eq!(app.collector_requests[before..], ["cryptopro"]);
        assert_eq!(app.crypto_origin, CheckOrigin::Session);
        assert!(!app.crypto_recheck_for_session);
        cleanup(&exe);
    }
}

/// P2: a failed attempt never re-stamps the result that stays shown.
#[test]
fn failed_audit_keeps_the_time_and_origin_of_the_shown_result() {
    let (mut app, exe) = app_in("drvstamp");
    app.start_preflight();
    // Explicit legacy-result fixture; startup itself must never launch A5.
    app.driver_origin = CheckOrigin::Preflight;
    deliver_audit(&mut app, Ok(audit()));
    let shown = app.driver_checked.clone().unwrap();
    assert_eq!(shown.origin, CheckOrigin::Preflight);
    // Engine audit of a session fails: the preflight result stays, with
    // its own stamp; the failure is in the history.
    app.client_name = "Клиент".into();
    app.start_diagnostics();
    let (tx, rx) = std::sync::mpsc::channel();
    tx.send(engine::EngineEvent::DriverAudit(Err(
        "collector failed".into()
    )))
    .unwrap();
    if let RunState::Running { rx: run_rx, .. } = &mut app.state {
        *run_rx = rx;
    }
    app.poll_engine();
    assert!(matches!(app.driver_audit, DriverAuditState::Done(_)));
    assert_eq!(app.driver_checked.as_ref(), Some(&shown));
    assert!(app.driver_history.last().is_some_and(
        |e| e.outcome.contains("collector failed") && e.stamp.origin == CheckOrigin::Session
    ));
    assert!(!app.system_basis_complete());
    assert!(
        app.state_reasons()
            .iter()
            .any(|r| r.contains("A5 collector [COVERAGE/ERROR]"))
    );
    cleanup(&exe);
}

// ---------------- PR #4 review round 2 regressions ----------------

/// The pending session check survives the end of the diagnostic; Stop
/// cancels it.
#[test]
fn pending_session_checks_survive_the_run_end_and_stop_cancels_them() {
    // CryptoPro: the diagnostic ended before the running check did.
    let (mut app, exe) = app_in("pendingend");
    let (tx, rx) = std::sync::mpsc::channel();
    app.crypto_rx = Some(rx);
    app.crypto_origin = CheckOrigin::Manual;
    app.client_name = "Клиент".into();
    app.start_diagnostics();
    assert!(app.crypto_recheck_for_session);
    app.state = RunState::Idle;
    let before = app.collector_requests.len();
    tx.send(CryptoEvent::Checked(
        cryptopro::Detection::NotInstalled,
        cryptopro::HashState::HashOk,
    ))
    .unwrap();
    app.poll_crypto();
    assert_eq!(app.collector_requests[before..], ["cryptopro"]);
    assert_eq!(app.crypto_origin, CheckOrigin::Session);
    // Crash: the preflight scan ends after the run; the fresh scan still
    // belongs to the session's package.
    let session_package = Arc::clone(&app.package);
    app.crash.rescan_for_session = true;
    app.crash.rescan_package = Some(Arc::clone(&session_package));
    app.crash.scan_origin = Some(CheckOrigin::Preflight);
    deliver_scan(
        &mut app,
        inventory(crash_dump::DebuggerStatus::NotInstalled),
    );
    assert_eq!(app.crash.scan_origin, Some(CheckOrigin::Session));
    assert!(Arc::ptr_eq(&app.package_of("crash"), &session_package));
    cleanup(&exe);
    // Stop cancels both pending requests.
    let (mut app, exe) = app_in("pendingstop");
    let (_tx, rx) = std::sync::mpsc::channel();
    app.crypto_rx = Some(rx);
    app.crypto_origin = CheckOrigin::Manual;
    app.client_name = "Клиент".into();
    app.start_diagnostics();
    app.crash.rescan_for_session = true;
    app.request_stop();
    assert!(!app.crypto_recheck_for_session && !app.crash.rescan_for_session);
    assert!(app.crash.rescan_package.is_none());
    cleanup(&exe);
}

/// A cancelled audit blocks the next one until its worker has finished.
#[test]
fn cancelled_audit_blocks_the_next_one_until_it_ended() {
    let (mut app, exe) = app_in("draining");
    let (tx, rx) = std::sync::mpsc::channel::<Result<AuditReport, String>>();
    app.driver_audit = DriverAuditState::Running(rx);
    let _cancel = app.new_driver_cancel();
    app.client_name = "Клиент".into();
    app.start_diagnostics();
    assert!(app.driver_draining.is_some());
    // The diagnostic stops at once; the cancelled worker still runs.
    app.state = RunState::Idle;
    assert!(!app.build_vm(0.0, 0.0).drivers_check_enabled);
    let before = app.collector_requests.len();
    app.apply(Action::CheckDrivers);
    assert_eq!(app.collector_requests.len(), before, "no overlap");
    // The worker reports (cancelled) — only now a new audit may start.
    tx.send(Err("stopped".into())).unwrap();
    app.poll_driver_audit();
    assert!(app.driver_draining.is_none());
    assert!(app.build_vm(0.0, 0.0).drivers_check_enabled);
    app.apply(Action::CheckDrivers);
    assert_eq!(app.collector_requests.len(), before + 1);
    // One working folder per run.
    let src = include_str!("app.rs").replace("\r\n", "\n");
    assert!(src.contains("format!(\"driver-audit-{}-{run}\", std::process::id())"));
    cleanup(&exe);
}

/// The passport footer stays fully reachable in the narrowest window.
#[test]
fn passport_footer_wraps_in_a_narrow_window() {
    let ctx = egui::Context::default();
    crate::ui::fonts::install(&ctx);
    let mut boxes: Vec<(String, Rect)> = Vec::new();
    for _ in 0..3 {
        let input = egui::RawInput {
            screen_rect: Some(Rect::from_min_size(egui::Pos2::ZERO, vec2(420.0, 600.0))),
            ..Default::default()
        };
        let mut out = ctx.run_ui(input, |ui| {
            let _ =
                v11::passport_footer(ui, &i18n::RU, Some("2026-10-13 13:06"), false, true, None);
        });
        out.textures_delta.clear();
        boxes.clear();
        for c in &out.shapes {
            if let egui::Shape::Text(t) = &c.shape {
                boxes.push((t.galley.text().to_string(), c.shape.visual_bounding_rect()));
            }
        }
    }
    for b in [
        i18n::RU.pp_refresh,
        i18n::RU.pp_copy,
        i18n::RU.pp_save,
        i18n::RU.pp_close,
    ] {
        let r = boxes
            .iter()
            .find(|(t, _)| t == b)
            .map(|(_, r)| *r)
            .unwrap_or_else(|| panic!("{b} missing"));
        assert!(r.max.x <= 420.0 + 0.5, "{b} cut off: {r:?}");
    }
}

/// The dump-cause branch of the incident headline is localized too.
#[test]
fn dump_cause_confidence_is_localized_in_the_headline() {
    let v = incidents::Verdict {
        hang_confirmed: false,
        bsod_registered: true,
        subsystem: None,
        confidence: incidents::Confidence::Low,
        signals: Vec::new(),
        dump_cause: Some(incidents::DumpCause {
            dump: "010100-00001-01.dmp".into(),
            bugcheck: "0x00000139".into(),
            module: "RvNetMP60.sys".into(),
            owner: Some(("Radmin VPN".into(), true)),
            confidence: "MEDIUM".into(),
        }),
    };
    let ru = v.headline_localized(true);
    assert!(ru.contains("средняя (MEDIUM)"), "{ru}");
    assert!(v.headline().contains("MEDIUM"), "canonical kept");
    assert_eq!(incidents::confidence_label("ODD", true), "ODD");
}

// ---------------- PR #4 review round 3 regressions ----------------

/// Stop, then the late preflight listing: no rescan is re-queued.
#[test]
fn late_preflight_listing_after_stop_queues_no_rescan() {
    let (mut app, exe) = app_in("stoplate");
    app.start_preflight();
    let (tx, rx) = std::sync::mpsc::channel();
    app.crash_rx = Some(rx);
    app.crash.busy = CrashBusy::Scanning;
    app.client_name = "Клиент".into();
    app.start_diagnostics();
    app.request_stop();
    assert!(app.is_running(), "the engine has not reported yet");
    let before = app.collector_requests.len();
    tx.send(CrashMsg::Inventory(Ok(inventory(
        crash_dump::DebuggerStatus::NotInstalled,
    ))))
    .unwrap();
    drop(tx);
    app.poll_crash();
    assert!(!app.crash.rescan_for_session);
    assert_eq!(app.collector_requests.len(), before, "nothing restarted");
    cleanup(&exe);
}

/// Session B gets its own checks although session A's checks still run.
#[test]
fn a_new_session_queues_its_own_checks_behind_an_earlier_session() {
    let (mut app, exe) = app_in("twosessions");
    app.client_name = "A".into();
    app.start_diagnostics();
    let a = app.current_session_id().unwrap();
    // A's checks are still running when A ends and B starts.
    let (_ctx, crx) = std::sync::mpsc::channel();
    app.crash_rx = Some(crx);
    app.crash.scan_origin = Some(CheckOrigin::Session);
    app.crash.scan_session = Some(a.clone());
    let (_ytx, yrx) = std::sync::mpsc::channel();
    app.crypto_rx = Some(yrx);
    app.crypto_origin = CheckOrigin::Session;
    app.crypto_op_session = Some(a.clone());
    app.state = RunState::Idle;
    app.client_name = "B".into();
    app.start_diagnostics();
    let b = app.current_session_id().unwrap();
    assert_ne!(a, b);
    assert!(app.crash.rescan_for_session, "B gets its own crash scan");
    assert!(
        app.crypto_recheck_for_session,
        "B gets its own CryptoPro check"
    );
    let pkg = app.crash.rescan_package.clone().unwrap();
    assert_eq!(
        report_package::lock(&pkg)
            .session()
            .map(|s| s.session_id.clone()),
        Some(b)
    );
    cleanup(&exe);
}

/// The full passport window at the minimum allowed size: every footer
/// control stays inside the window.
#[test]
fn passport_window_at_minimum_size_keeps_the_footer_visible() {
    let (mut app, exe) = app_in("ppmin");
    app.passport2_json = Some(crate::passport2::QA_PASSPORT_JSON.to_string());
    app.passport2_open = true;
    app.passport2_status = Some(ExportStatus::Failed(
        "a long export error message that wraps over several lines in a narrow window".into(),
    ));
    let ctx = egui::Context::default();
    crate::ui::fonts::install(&ctx);
    let mut boxes: Vec<(String, Rect)> = Vec::new();
    for _ in 0..4 {
        let input = egui::RawInput {
            screen_rect: Some(Rect::from_min_size(egui::Pos2::ZERO, vec2(420.0, 300.0))),
            ..Default::default()
        };
        let mut out = ctx.run_ui(input, |ui| {
            egui::Area::new(egui::Id::new("pp_min"))
                .fixed_pos(egui::Pos2::ZERO)
                .show(ui.ctx(), |ui| {
                    ui.set_max_size(vec2(420.0, 300.0));
                    let d = &i18n::RU;
                    let _ = v11::passport_footer(
                        ui,
                        d,
                        Some("2026-10-13 13:06"),
                        false,
                        true,
                        app.passport2_status.as_ref().map(|s| s.text(d)).as_ref(),
                    );
                });
        });
        out.textures_delta.clear();
        boxes.clear();
        for c in &out.shapes {
            if let egui::Shape::Text(t) = &c.shape {
                boxes.push((t.galley.text().to_string(), c.shape.visual_bounding_rect()));
            }
        }
    }
    let footer_bottom = boxes.iter().map(|(_, r)| r.max.y).fold(0.0_f32, f32::max);
    // Footer height fits a 300-point window together with a title bar and
    // a minimal page sliver.
    assert!(
        footer_bottom < 300.0 - 24.0 - 30.0,
        "footer {footer_bottom}"
    );
    for b in [i18n::RU.pp_refresh, i18n::RU.pp_close] {
        let r = boxes.iter().find(|(t, _)| t == b).map(|(_, r)| *r).unwrap();
        assert!(r.max.x <= 420.5 && r.max.y <= 300.0, "{b}: {r:?}");
    }
    let src = include_str!("app_v11.rs").replace("\r\n", "\n");
    assert!(src.contains("let body_h = (ui.available_height() - footer_h).max(24.0);"));
    cleanup(&exe);
}

#[test]
fn v1210_gui_execution_and_raw_journal_contract() {
    let (mut app, exe) = app_in("v1210_status");
    app.package = Arc::new(Mutex::new(SessionPackage::for_exe_dir(&exe)));
    report_package::lock(&app.package).bind_session(SessionIdentity::new(
        "v1210-test-session",
        "",
        "MSI",
    ));
    app.journal.push("Начало v1210-test-session".into());
    app.state = RunState::Done {
        zip_path: "report.zip".into(),
    };
    app.expc_checks = vec![deep_checks::ExpcCheck {
        key: "SFC".into(),
        status: "UNKNOWN".into(),
        detail: "unrecognized".into(),
    }];
    let vm = app.build_vm(0.0, 0.0);
    assert!(vm.operation.subtitle.contains("Выполнение завершено"));
    assert!(
        vm.operation.subtitle.contains("Покрытие ограничено")
            || vm.operation.subtitle.contains("Нет данных")
    );
    app.driver_audit = DriverAuditState::Done(Box::new(AuditReport {
        complete: true,
        devices_scanned: 297,
        errors: vec!["Get-WindowsDriver: 0xC0040009; scope=DRIVER_PACKAGE_COLLECTION".into()],
        ..Default::default()
    }));
    let vm = app.build_vm(0.0, 0.0);
    assert!(
        vm.operation
            .subtitle
            .contains("Завершено с ошибками выполнения")
    );
    assert_eq!(app.audit_report().unwrap().overall, Severity::Ok);
    assert!(
        app.state_reasons()
            .iter()
            .any(|r| r.contains("[COVERAGE/ERROR]") && r.contains("0xC0040009"))
    );
    app.driver_audit = DriverAuditState::Idle;
    app.expc_checks.push(deep_checks::ExpcCheck {
        key: "Step 07".into(),
        status: "ERROR".into(),
        detail: "exception".into(),
    });
    let vm = app.build_vm(0.0, 0.0);
    assert!(
        vm.operation
            .subtitle
            .contains("Завершено с ошибками выполнения")
    );
    assert_eq!(vm.operation.tone, Tone::Error);
    let original = "A5_PROGRESS|Native date fallback: 48/53; 31.0 s";
    let mut journal = SessionJournal::default();
    journal.push(original.into());
    assert!(
        journal
            .full_text(i18n::t(Language::Ru))
            .contains("Проверка дат драйверов: 48 из 53 · 31 с")
    );
    assert!(journal.technical_text().contains(original));
    app.journal.push(original.into());
    assert!(
        app.build_vm(0.0, 0.0)
            .journal
            .last()
            .unwrap()
            .message
            .contains("Проверка дат драйверов: 48 из 53 · 31 с")
    );
    // The production synchronization path feeds the same summary to all report formats.
    app.manifest_states_checked = None;
    app.sync_manifest_states();
    let zip = {
        let mut package = report_package::lock(&app.package);
        let zip = package
            .contribute(
                "",
                "MSI",
                "30-10-26",
                vec![report_package::EvidenceFile::new(
                    "EXPC_test.txt",
                    b"test".to_vec(),
                )],
            )
            .unwrap();
        package
            .snapshot_session_journal(
                &app.journal
                    .entries
                    .iter()
                    .map(SessionJournal::technical_line)
                    .collect::<Vec<_>>(),
            )
            .unwrap();
        package.finalize().unwrap();
        zip
    };
    let files = report_package::parse_zip(&std::fs::read(zip).unwrap()).unwrap();
    for name in ["State_Summary.json", "manifest.json"] {
        let bytes = &files.iter().find(|f| f.name == name).unwrap().bytes;
        let value = json::parse(std::str::from_utf8(bytes).unwrap()).unwrap();
        assert_eq!(
            value.get("execution_status").unwrap().as_str(),
            Some("COMPLETED_WITH_ERRORS")
        );
        assert_eq!(
            value.get("coverage_status").unwrap().as_str(),
            Some("LIMITED")
        );
        assert_eq!(
            value.get("producer_version").unwrap().as_str(),
            Some(crate::APP_VERSION)
        );
    }
    assert!(files.iter().any(|f| f.name == "State_Summary.txt"
        && String::from_utf8_lossy(&f.bytes).contains("Execution: COMPLETED_WITH_ERRORS")));
    assert!(
        files
            .iter()
            .any(|f| String::from_utf8_lossy(&f.bytes).contains(original))
    );
}

#[test]
fn v1211_repair_request_gate_and_immutable_zip_evidence() {
    use crate::repair;
    let (mut app, exe) = app_in("v1211_repair");
    assert!(!app.repair_busy());
    assert!(app.repair_ui.pending.is_none());
    app.package = Arc::new(Mutex::new(SessionPackage::for_exe_dir(&exe)));
    report_package::lock(&app.package).bind_session(SessionIdentity::new(
        "v1211-repair",
        "Клиент",
        "MSI",
    ));
    app.client_name = "Клиент".into();
    app.journal.push("Начало v1211-repair".into());
    app.state = RunState::Done {
        zip_path: "report.zip".into(),
    };
    for status in &mut app.expc_tracker.status {
        *status = SubStageStatus::Done;
    }
    let original = DeepCheckOutcome {
        check: DeepCheck::Sfc,
        result: CheckResult::Attention,
        detail: "SFC /verifyonly обнаружил признаки нарушения целостности.".into(),
        source: deep_checks::ResultSource::ExpcJson,
    };
    app.deep_check_results = vec![original.clone()];
    app.expc_checks = vec![deep_checks::ExpcCheck {
        key: "SFC".into(),
        status: "ATTENTION".into(),
        detail: original.detail.clone(),
    }];
    assert!(app.build_vm(0.0, 0.0).stages[10].repair_available);
    assert!(!app.build_vm(0.0, 0.0).stages[11].repair_available);
    app.apply(Action::RequestRepair(10));
    assert!(app.repair_ui.pending.is_some());
    assert!(!app.repair_busy());
    let (tx, rx) = std::sync::mpsc::channel();
    app.repair_ui.rx = Some(rx);
    app.apply(Action::Start);
    assert!(matches!(app.state, RunState::Done { .. }));
    app.apply(Action::Reset);
    assert_eq!(app.deep_check_results[0], original);
    assert!(!app.build_vm(0.0, 0.0).stages[10].repair_available);
    app.repair_ui.rx = None;
    drop(tx);
    let original_bytes = b"Original EXPC: SFC INTEGRITY_VIOLATIONS";
    app.contribute_evidence(
        "repair",
        "Initial",
        vec![EvidenceFile::new(
            "EXPC_original.txt",
            original_bytes.to_vec(),
        )],
    );
    let report = repair::Report {
        id: "fake-success".into(),
        plan: repair::plan(&original, "C:").unwrap(),
        status: "SUCCESS".into(),
        message: "Повторная проверка чистая".into(),
        repair: Some(repair::Output {
            code: Some(0),
            text: "completed".into(),
            scheduled: false,
        }),
        verification: Some(repair::Output {
            code: Some(0),
            text: "Windows Resource Protection did not find any integrity violations.".into(),
            scheduled: false,
        }),
        verified: Some(CheckResult::Ok),
        reboot: false,
    };
    app.accept_repair_report(report);
    assert_eq!(
        app.deep_check_results[0], original,
        "original never overwritten"
    );
    assert_eq!(app.deep_check_at(10).unwrap().result, CheckResult::Ok);
    assert!(!app.build_vm(0.0, 0.0).stages[10].repair_available);
    assert!(
        app.diag_checks()
            .iter()
            .any(|c| c.key == "SFC" && c.status == "OK")
    );
    assert!(
        !app.diag_checks()
            .iter()
            .any(|c| c.key == "SFC" && c.status == "ATTENTION")
    );
    app.manifest_states_checked = None;
    app.sync_manifest_states();
    let mut pkg = report_package::lock(&app.package);
    pkg.finalize().unwrap();
    let zip = pkg.final_zip().unwrap().to_path_buf();
    drop(pkg);
    let files = report_package::parse_zip(&std::fs::read(zip).unwrap()).unwrap();
    assert_eq!(
        files
            .iter()
            .find(|f| f.name == "EXPC_original.txt")
            .unwrap()
            .bytes,
        original_bytes
    );
    for name in ["Repair_fake-success.json", "Repair_fake-success.txt"] {
        assert!(files.iter().any(|f| f.name == name));
    }
    let manifest = String::from_utf8(
        files
            .iter()
            .find(|f| f.name == "manifest.json")
            .unwrap()
            .bytes
            .clone(),
    )
    .unwrap();
    assert!(manifest.contains("\"repairs\""));
    assert!(manifest.contains("SUCCESS"));
    assert!(manifest.contains("Repair_fake-success.json"));
}
#[test]
fn v1211_firmware_actual_font_width_at_windows_scales() {
    let ctx = egui::Context::default();
    crate::ui::fonts::install(&ctx);
    for ppp in [1.0, 1.25, 1.5, 1.75, 2.0] {
        ctx.set_pixels_per_point(ppp);
        for _ in 0..2 {
            let mut output = ctx.run_ui(egui::RawInput::default(), |ui| {
                let cols = crate::ui::pages::stage_table_columns(0.0);
                let width = cols[2] - cols[1] - 10.0;
                let label = i18n::RU.stage_short[13];
                assert_eq!(label, "BIOS / Драйверы / Firmware");
                let style = crate::ui::pages::firmware_label_style(ui.painter(), label, width);
                let galley = ui.painter().layout_no_wrap(
                    label.into(),
                    crate::ui::fonts::font(style),
                    egui::Color32::WHITE,
                );
                assert!(
                    galley.size().x <= width,
                    "{ppp}: {} > {width}",
                    galley.size().x
                );
                println!(
                    "A9 Firmware ppp={ppp} font={} width={:.2}/{width}",
                    style.size,
                    galley.size().x
                );
            });
            output.textures_delta.clear();
        }
    }
}

#[test]
fn v1211_a9_repair_button_hit_test_only_requests_confirmation() {
    let (mut app, _exe) = app_in("v1211_hit");
    app.state = RunState::Done {
        zip_path: "test.zip".into(),
    };
    for state in &mut app.expc_tracker.status {
        *state = SubStageStatus::Done;
    }
    app.deep_check_results = vec![DeepCheckOutcome {
        check: DeepCheck::Sfc,
        result: CheckResult::Attention,
        detail: "SFC /verifyonly обнаружил признаки нарушения целостности.".into(),
        source: deep_checks::ResultSource::ExpcJson,
    }];
    let vm = app.build_vm(0.0, 0.0);
    let ctx = egui::Context::default();
    crate::ui::fonts::install(&ctx);
    let mut actions = Vec::new();
    let mut point = None;
    for _ in 0..2 {
        let mut output = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(Rect::from_min_size(egui::Pos2::ZERO, vec2(1400.0, 1150.0))),
                ..Default::default()
            },
            |ui| crate::ui::pages::draw_stages_table(ui, egui::Pos2::ZERO, &vm, &mut actions),
        );
        point = native_texts(&output)
            .into_iter()
            .find(|(text, _)| text == "Repair")
            .map(|(_, rect)| rect.center());
        output.textures_delta.clear();
    }
    assert!(actions.is_empty());
    assert!(app.repair_ui.pending.is_none());
    let point = point.expect("Repair must render in the finding cell");
    let cols = crate::ui::pages::stage_table_columns(
        crate::ui::tokens::layout::STAGE_TABLE_CARD[0] - 1.0 + 16.0,
    );
    assert!(point.x >= cols[4] && point.x < cols[5]);
    for pressed in [true, false] {
        let mut output = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(Rect::from_min_size(egui::Pos2::ZERO, vec2(1400.0, 1150.0))),
                events: pointer_button(point, pressed),
                ..Default::default()
            },
            |ui| crate::ui::pages::draw_stages_table(ui, egui::Pos2::ZERO, &vm, &mut actions),
        );
        output.textures_delta.clear();
    }
    assert_eq!(
        actions
            .iter()
            .filter(|a| matches!(a, Action::RequestRepair(10)))
            .count(),
        1
    );
    for action in actions {
        app.apply(action);
    }
    assert!(app.repair_ui.pending.is_some());
    assert!(!app.repair_busy());
}
