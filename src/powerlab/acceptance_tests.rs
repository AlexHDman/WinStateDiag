use super::*;
fn sample(i: u32, value: f64) -> Sample {
    let mut m = Metric::measured(
        "cpu.package_power",
        "CPU Package",
        Group::Cpu,
        "W",
        value,
        "fixture",
    );
    m.timestamp_ms = i as u64 * 1000;
    m.sensor = Some("PKG".into());
    m.hardware = Some("cpu/0".into());
    Sample {
        index: i,
        timestamp_ms: i as u64 * 1000,
        window_ms: 1000.,
        elapsed_ms: 0.,
        warmup: false,
        metrics: vec![m],
    }
}
#[test]
fn close_reopen_preserves_measurements_and_client_export() {
    let mut m = Monitor::default();
    m.apply(SamplerEvent::Sample(Box::new(sample(1, 20.))));
    m.open_window();
    m.stop();
    m.open = false;
    m.open_window();
    assert!(m.open);
    assert_eq!(m.samples(), 1);
    assert!(m.focus);
}
#[test]
fn rights_preserves_session_and_never_automatically_installs() {
    let mut m = Monitor::default();
    m.apply(SamplerEvent::Sample(Box::new(sample(1, 20.))));
    m.request_rights();
    assert!(m.pending && m.elevated);
    assert_eq!(m.samples(), 1);
    let code = include_str!("elevation.rs");
    assert!(!code.contains("PawnIO_setup"));
    assert!(!code.contains("TerminateProcess"));
}
#[test]
fn b3_consumes_same_stream_with_raw_provenance() {
    let mut m = Monitor::default();
    m.apply(SamplerEvent::Sample(Box::new(sample(1, 20.))));
    let b = m.b3_snapshot();
    assert_eq!(b.sensors.len(), 1);
    assert_eq!(b.sensors[0].value, 20.);
    assert!(b.hardware_metadata.unwrap().contains("cpu.package_power"));
}
#[test]
fn duplicate_timestamps_do_not_bias_statistics() {
    let mut m = Monitor::default();
    let s = sample(1, 20.);
    m.apply(SamplerEvent::Sample(Box::new(s.clone())));
    m.apply(SamplerEvent::Sample(Box::new(s)));
    assert_eq!(m.series["cpu.package_power"].count, 1);
    assert_eq!(m.samples(), 2);
}
#[test]
fn error_cannot_become_zero_in_b3_or_display() {
    let mut s = sample(1, 0.);
    s.metrics[0].state = MetricState::Error;
    s.metrics[0].value = None;
    s.metrics[0].reason = Some("mock PDH malformed".into());
    let mut m = Monitor::default();
    m.apply(SamplerEvent::Sample(Box::new(s)));
    assert!(m.b3_snapshot().sensors.is_empty());
    assert!(!display_value(&m.latest["cpu.package_power"]).contains("0 W"));
}
#[test]
fn bounded_notices_retain_errors_over_info() {
    let mut m = Monitor::default();
    m.notice("error: keep".into());
    for i in 0..1000 {
        m.notice(format!("info: {i}"))
    }
    assert_eq!(m.notices.len(), 240);
    assert!(m.notices.iter().any(|x| x == "error: keep"));
}
#[test]
fn resume_monotonic_sequence_and_full_history() {
    let mut m = Monitor::default();
    for i in 1..=3 {
        m.apply(SamplerEvent::Sample(Box::new(sample(i, i as f64))));
    }
    m.apply(SamplerEvent::Stopped(supervisor::StopReason::OperatorStop));
    m.apply(SamplerEvent::Sample(Box::new(sample(1, 9.))));
    assert_eq!(m.history.last().unwrap().index, 4);
    assert_eq!(m.series["cpu.package_power"].max, Some(9.));
}
#[test]
fn layout_dpi_no_identity_cards_or_duplicate_units() {
    for dpi in [1., 1.25, 1.5] {
        let ctx = egui::Context::default();
        crate::app::apply_theme(&ctx);
        crate::ui::fonts::install(&ctx);
        ctx.set_pixels_per_point(dpi);
        let mut m = Monitor::default();
        m.apply(SamplerEvent::Sample(Box::new(sample(1, 20.))));
        for _ in 0..3 {
            let input = egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(850., 800.),
                )),
                ..Default::default()
            };
            let mut output = ctx.run_ui(input, |ui| {
                assert_eq!(m.draw(ui, "ACCESS_DENIED", false, "Клиент"), Action::None);
            });
            assert!(!output.shapes.is_empty());
            output.textures_delta.clear();
        }
        assert_eq!(display_value(&m.latest["cpu.package_power"]), "20.00 W");
    }
}
#[test]
#[ignore = "Explicit packaged Windows integration LIVE, no GUI/UAC"]
fn packaged_monitor_live_export_restart() {
    let evidence = PathBuf::from(std::env::var("WSD_POWERLAB_EVIDENCE").expect("evidence"));
    let runtime = PathBuf::from(std::env::var("WSD_POWERLAB_SAMPLER").expect("packaged sampler"));
    let seconds: u64 = std::env::var("WSD_POWERLAB_SECONDS")
        .unwrap_or("12".into())
        .parse()
        .unwrap();
    let mut m = Monitor::default();
    m.runtime = Some(runtime);
    m.report_dir = evidence.join("exports");
    m.start();
    let deadline = Instant::now() + Duration::from_secs(seconds + 40);
    let begin = Instant::now();
    let mut max_pump = Duration::ZERO;
    while begin.elapsed() < Duration::from_secs(seconds) && m.running() {
        let t = Instant::now();
        m.pump();
        max_pump = max_pump.max(t.elapsed());
        std::thread::sleep(Duration::from_millis(10));
    }
    let t = Instant::now();
    m.stop();
    let stop_request = t.elapsed();
    while m.running() && Instant::now() < deadline {
        m.pump();
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!m.running(), "{}", m.message);
    assert!(m.clean, "{}", m.message);
    assert!(
        m.samples() >= (seconds.saturating_sub(8)) as usize,
        "only {} samples: {}",
        m.samples(),
        m.message
    );
    assert!(
        m.latest
            .values()
            .any(|x| x.id.starts_with("lhm/") && x.usable_value().is_some()),
        "LHM was not connected"
    );
    let before = m.samples();
    for _ in 0..2 {
        for format in ["txt", "json", "csv"] {
            m.export(format, "Клиент сеанса");
            while m.saving() && Instant::now() < deadline {
                m.pump();
                std::thread::sleep(Duration::from_millis(10));
            }
            assert!(m.message.starts_with("Сохранено:"), "{}", m.message);
        }
    }
    let files = std::fs::read_dir(&m.report_dir)
        .unwrap()
        .map(|p| p.unwrap().path())
        .collect::<Vec<_>>();
    assert_eq!(files.len(), 6);
    for p in &files {
        if p.extension().unwrap() == "json" {
            let text = std::fs::read_to_string(p).unwrap();
            let j = powerlab_core::json::Json::parse(&text).unwrap();
            assert_eq!(
                j.get("sample_count").and_then(|v| v.as_int()),
                Some(before as i64)
            );
            assert!(text.contains("Клиент сеанса"));
        }
    }
    let capture = m
        .history
        .iter()
        .map(|s| powerlab_core::ipc::sample_to_json(s).render() + "\n")
        .collect::<String>();
    std::fs::write(evidence.join("samples.jsonl"), capture).unwrap();
    m.open_window();
    m.stop();
    m.open = false;
    m.open_window();
    assert_eq!(m.samples(), before);
    m.start();
    let restart = Instant::now() + Duration::from_secs(10);
    while m.samples() < before + 3 && m.running() && Instant::now() < restart {
        m.pump();
        std::thread::sleep(Duration::from_millis(10));
    }
    m.stop();
    while m.running() && Instant::now() < deadline {
        m.pump();
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(m.clean && !m.running());
    assert!(m.samples() >= before + 3, "{}", m.message);
    let text = format!(
        "samples_before_restart={before}\nsamples_after_restart={}\nstop_request_ms={:.3}\nmax_pump_ms={:.3}\nclean={}\n",
        m.samples(),
        stop_request.as_secs_f64() * 1000.,
        max_pump.as_secs_f64() * 1000.,
        m.clean
    );
    std::fs::write(evidence.join("live-result.txt"), &text).unwrap();
    println!("{text}");
    assert!(stop_request < Duration::from_millis(30));
    assert!(max_pump < Duration::from_millis(250));
}

#[test]
fn runtime_hashes_are_anchored_in_windiag_not_editable_sidecar() {
    let source = include_str!("mod.rs");
    assert!(
        source.contains("include_str!(\"../../third_party/powerlab-runtime/SHA256SUMS.json\")")
    );
    assert!(!source.contains("read_to_string(root.join(\"SHA256SUMS.json\"))"));
    assert!(crate::ps_exec::compact_command(&format!("{}{}", PINNED_RUNTIME, "test")).is_ok());
}
#[test]
fn suspect_reading_never_becomes_confirmed_b3_value() {
    let mut m = Monitor::default();
    let mut s = sample(1, -10.);
    s.metrics[0].state = MetricState::Suspect;
    s.metrics[0].reason = Some("negative power".into());
    m.apply(SamplerEvent::Sample(Box::new(s)));
    assert!(m.b3_snapshot().sensors.is_empty());
    assert!(display_value(&m.latest["cpu.package_power"]).starts_with("Проверить:"));
}

#[test]
fn localized_native_labels_retain_b3_canonical_power_and_temperature() {
    let mut m = Monitor::default();
    let mut s = sample(1, 20.);
    s.metrics[0].label = "Мощность CPU (пакет)".into();
    let mut gpu = Metric::measured(
        "gpu.0.temperature",
        "Температура GPU",
        Group::Gpu,
        "°C",
        40.,
        "NVML",
    );
    gpu.timestamp_ms = 1000;
    gpu.hardware = Some("nvml/index/0".into());
    gpu.sensor = Some("nvml:temperature".into());
    s.metrics.push(gpu);
    m.apply(SamplerEvent::Sample(Box::new(s)));
    let snapshot = m.b3_snapshot();
    let summary = crate::sensors::summarize(&snapshot.sensors);
    assert!(
        summary
            .power
            .iter()
            .any(|x| x.role == crate::sensors::Role::CpuPackagePower)
    );
    assert!(
        summary
            .temps
            .iter()
            .any(|x| x.role == crate::sensors::Role::GpuTemp)
    );
}

#[test]
fn ready_sensor_cannot_leave_stale_discovery_progress() {
    let mut monitor = Monitor::default();
    let mut sample = sample(1, 20.);
    let mut ready = Metric::measured(
        "lhm.ready",
        "Hardware discovery complete",
        Group::System,
        "",
        1.,
        "helper",
    );
    ready.timestamp_ms = 1000;
    ready.sensor = Some("discovery".into());
    sample.metrics.push(ready);
    monitor.apply(SamplerEvent::Sample(Box::new(sample)));
    assert!(monitor.latest["lhm.ready"].usable_value().is_some());
    let source = include_str!("view.rs");
    assert!(source.contains("self.owns_reader() && !discovery_complete"));
}
