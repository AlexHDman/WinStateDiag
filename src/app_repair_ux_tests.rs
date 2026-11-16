use super::*;
fn texts(shape: &egui::Shape, out: &mut Vec<String>) {
    match shape {
        egui::Shape::Text(s) => out.push(s.galley.text().into()),
        egui::Shape::Vec(shapes) => {
            for s in shapes {
                texts(s, out);
            }
        }
        _ => {}
    }
}
#[test]
fn compact_popup_is_over_a9_without_technical_text_or_state_mutation() {
    for (size, ppp) in [
        (vec2(1500.0, 1300.0), 1.0),
        (vec2(1100.0, 900.0), 1.25),
        (vec2(900.0, 740.0), 1.5),
        (vec2(420.0, 300.0), 1.0),
    ] {
        for percent in [None, Some(25.5), Some(100.0), Some(f32::NAN)] {
            let ctx = egui::Context::default();
            ctx.set_pixels_per_point(ppp);
            crate::ui::fonts::install(&ctx);
            let a9 = Rect::from_min_max(
                egui::pos2(size.x * 0.43, size.y * 0.3),
                size.to_pos2() - vec2(12.0, 12.0),
            );
            ctx.data_mut(|d| d.insert_temp(egui::Id::new("repair_a9_anchor"), a9));
            let mut app = WinStateDiagApp::default();
            app.repair_ui.open = true;
            let (_tx, rx) = mpsc::channel();
            app.repair_ui.rx = Some(rx);
            app.repair_ui.message = "RAW ERROR 0x800f081f".into();
            *app.repair_ui.progress.lock().unwrap() = repair::Progress {
                check: Some(DeepCheck::Sfc),
                phase: "RUNNING internal phase".into(),
                percent,
                latest: "DEBUG raw stdout, 100% текущего этапа".into(),
            };
            let mut content = Vec::new();
            for frame in 0..14 {
                let mut output = ctx.run_ui(
                    egui::RawInput {
                        screen_rect: Some(Rect::from_min_size(egui::Pos2::ZERO, size)),
                        time: Some(frame as f64 * 0.1),
                        events: if frame > 3 && size.x < 500.0 {
                            vec![
                                egui::Event::PointerMoved(egui::pos2(size.x * 0.75, size.y * 0.7)),
                                egui::Event::MouseWheel {
                                    unit: egui::MouseWheelUnit::Point,
                                    delta: vec2(0.0, -80.0),
                                    phase: egui::TouchPhase::Move,
                                    modifiers: Default::default(),
                                },
                            ]
                        } else {
                            vec![]
                        },
                        ..Default::default()
                    },
                    |_| app.repair_window(&ctx),
                );
                output.textures_delta.clear();
                for shape in output.shapes {
                    texts(&shape.shape, &mut content);
                }
            }
            let content = content.join("\n");
            for expected in [
                "Исправление выполняется",
                "Восстановление системных файлов Windows",
                "После завершения будет выполнена повторная проверка",
            ] {
                assert!(content.contains(expected), "{size:?}: {content}");
            }
            for forbidden in [
                "RUNNING",
                "DEBUG",
                "RAW",
                "0x800f081f",
                "%",
                "Код команды",
                "не сообщил процент",
                "100%",
                "Не выполнять следующие шаги",
            ] {
                assert!(
                    !content.contains(forbidden),
                    "{size:?}: leaked {forbidden}: {content}"
                );
            }
            let popup = ctx
                .data(|d| d.get_temp::<Rect>(egui::Id::new("repair_popup_test_rect")))
                .unwrap();
            let area = repair_popup_layout(&ctx).0;
            assert!(
                popup.left() >= area.left() - 1.0,
                "{size:?}: left overlap {popup:?} {area:?}"
            );
            assert!(
                popup.right() <= area.right() + 1.0,
                "{size:?}: right overflow {popup:?} {area:?}"
            );
            assert!(
                popup.top() >= -1.0 && popup.bottom() <= size.y + 1.0,
                "{popup:?}"
            );
            assert!(
                app.journal
                    .entries
                    .iter()
                    .any(|e| e.message.contains("DEBUG raw stdout"))
            );
            assert!(app.repair_busy());
            assert!(!app.repair_ui.cancel.load(Ordering::SeqCst));
            assert!(app.repair_ui.pending.is_none());
            assert_eq!(
                app.repair_ui.progress.lock().unwrap().latest,
                "DEBUG raw stdout, 100% текущего этапа"
            );
            assert_eq!(
                app.journal
                    .entries
                    .iter()
                    .filter(|e| e.message.contains("RAW ERROR 0x800f081f"))
                    .count(),
                1
            );
        }
    }
}
#[test]
fn bar_distinguishes_unknown_from_zero_and_animates_inside_one_track() {
    let track = Rect::from_min_size(egui::pos2(10.0, 20.0), vec2(400.0, 10.0));
    assert_eq!(repair_progress_segment(track, Some(0.0), 0.0).width(), 0.0);
    assert_eq!(
        repair_progress_segment(track, Some(25.0), 0.0).width(),
        100.0
    );
    assert_eq!(repair_progress_segment(track, Some(100.0), 0.0), track);
    let a = repair_progress_segment(track, None, 0.0);
    let b = repair_progress_segment(track, None, 0.3);
    assert_ne!(a.left(), b.left());
    assert_eq!(a.size(), b.size());
    for invalid in [None, Some(f32::NAN), Some(-1.0), Some(101.0)] {
        for t in 0..100 {
            let bar = repair_progress_segment(track, invalid, t as f64 * 0.1);
            assert!(track.contains_rect(bar));
            assert!((bar.width() - 100.0).abs() < 0.001);
        }
    }
}
#[test]
fn result_popup_keeps_error_codes_in_journal_only() {
    let mut app = WinStateDiagApp::default();
    app.repair_ui.open = true;
    app.repair_ui.message = "BLOCKED: internal HRESULT 0x800f081f".into();
    let ctx = egui::Context::default();
    crate::ui::fonts::install(&ctx);
    let mut content = Vec::new();
    for _ in 0..4 {
        let mut output = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(Rect::from_min_size(egui::Pos2::ZERO, vec2(1400.0, 1100.0))),
                ..Default::default()
            },
            |_| app.repair_window(&ctx),
        );
        output.textures_delta.clear();
        content.clear();
        for s in output.shapes {
            texts(&s.shape, &mut content);
        }
    }
    let content = content.join("\n");
    assert!(content.contains("Исправление не запущено"));
    assert!(content.contains("Открыть журнал"));
    assert!(!content.contains("HRESULT") && !content.contains("BLOCKED"));
    assert!(
        app.journal
            .entries
            .iter()
            .any(|e| e.message.contains("0x800f081f"))
    );
}
