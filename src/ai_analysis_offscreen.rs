//! Genuine egui pixels rendered offscreen on Microsoft WARP. No host window/input.
use super::*;
use eframe::{egui_wgpu, wgpu};
use std::sync::mpsc;
use std::{
    future::Future,
    io::Write,
    task::{Context, Poll, Wake, Waker},
};
fn wait<F: Future>(future: F) -> F::Output {
    struct ThreadWake(std::thread::Thread);
    impl Wake for ThreadWake {
        fn wake(self: Arc<Self>) {
            self.0.unpark()
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.unpark()
        }
    }
    let waker = Waker::from(Arc::new(ThreadWake(std::thread::current())));
    let mut ctx = Context::from_waker(&waker);
    let mut future = std::pin::pin!(future);
    loop {
        match future.as_mut().poll(&mut ctx) {
            Poll::Ready(v) => return v,
            Poll::Pending => std::thread::park_timeout(Duration::from_millis(100)),
        }
    }
}
fn png(path: &std::path::Path, width: u32, height: u32, pixels: &[u8]) {
    fn crc(bytes: &[u8]) -> u32 {
        let mut c = !0u32;
        for b in bytes {
            c ^= *b as u32;
            for _ in 0..8 {
                c = (c >> 1) ^ if c & 1 != 0 { 0xedb88320 } else { 0 }
            }
        }
        !c
    }
    fn chunk(out: &mut Vec<u8>, kind: &[u8; 4], bytes: &[u8]) {
        out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(kind);
        out.extend_from_slice(bytes);
        let mut both = kind.to_vec();
        both.extend_from_slice(bytes);
        out.extend_from_slice(&crc(&both).to_be_bytes());
    }
    let mut out = b"\x89PNG\r\n\x1a\n".to_vec();
    let mut header = width.to_be_bytes().to_vec();
    header.extend_from_slice(&height.to_be_bytes());
    header.extend_from_slice(&[8, 6, 0, 0, 0]);
    chunk(&mut out, b"IHDR", &header);
    let mut z = flate2::write::ZlibEncoder::new(vec![], flate2::Compression::default());
    for row in pixels.chunks_exact(width as usize * 4) {
        z.write_all(&[0]).unwrap();
        z.write_all(row).unwrap();
    }
    chunk(&mut out, b"IDAT", &z.finish().unwrap());
    chunk(&mut out, b"IEND", &[]);
    std::fs::write(path, out).unwrap();
}
#[test]
#[ignore = "Offscreen genuine egui AI analysis, synthetic response only"]
fn ai_analysis_dpi_screenshots() {
    let evidence = PathBuf::from(std::env::var("WSD_AI_EVIDENCE").unwrap());
    let mut app = WinStateDiagApp::default();
    let scene = std::env::var("WSD_AI_QA_STATE").unwrap_or("preview".into());
    let source = evidence.join("Синтетический отчёт.txt");
    std::fs::write(&source,"EXPC WinDiag — синтетический контроль UI\nClient: SyntheticClient\nComputerName: TEST-PC-123\nBoard: PRO H610M-G DDR4\nCPU: Intel Core i7-12700\nBIOS version: 1.R0\nSFC INTEGRITY_VIOLATIONS — источник SFC.txt\nDISM CLEAN\nEventID 41: неожиданное завершение работы, причина не установлена\nVSS: данных недостаточно\nТЕСТОВЫЙ ПРЕДПРОСМОТР: не результат OpenAI").unwrap();
    let prepared = crate::ai_analysis::prepare(
        crate::ai_analysis::Source::Txt(source.clone()),
        vec![],
        &AtomicBool::new(false),
    )
    .unwrap();
    app.ai_analysis.open = scene != "a6";
    app.ai_analysis.prepared = Some(prepared);
    app.ai_analysis.message = "Текст подготовлен. Проверь копию перед отправкой.".into();
    if scene == "result" {
        app.ai_analysis.result_tab = true;
        app.ai_analysis.result = Some((crate::ai_analysis::Analysis{archive_sha256:None, facts: Default::default(),
            sections:["ТЕСТОВЫЙ ОТВЕТ, не OpenAI. Требуется проверка целостности Windows.".into(),"ATTENTION: SFC INTEGRITY_VIOLATIONS, источник SFC.txt. Событие 41 — контекст без доказанной причины.".into(),"Факт: SFC обнаружил нарушения. Гипотеза о причине требует проверки CBS. VSS: данных недостаточно.".into(),"1. Сверить первичный SFC.txt и CBS. 2. После явного решения пользователя повторить проверку. Ремонт автоматически не выполнялся.".into(),"Компьютер требует проверки целостности Windows; причина выключения не установлена.".into()],
            raw_partial:None,model:"synthetic-model".into(),requested_model:"gpt-4.1-mini".into(),usage:Some(crate::ai_analysis::Usage{input:123,output:45,total:168}),incomplete:false,created_at:"2026-11-19 · MOCK".into()},source.clone()));
    }
    if let Ok(path) = std::env::var("WSD_V111_FIELD_ZIP") {
        let (text, _) = crate::ai_export::analysis_session(
            &crate::ai_export::Input::zip(path.into()),
            &AtomicBool::new(false),
        )
        .unwrap();
        let facts = crate::report_facts::Facts::parse(&text);
        if let Some((a, _)) = &mut app.ai_analysis.result {
            a.facts = facts.clone();
        }
        if scene == "benchmark" {
            app.passport = Some(Ok(crate::passport::Passport {
                cpu: facts.cpu.clone(),
                board: facts.board.clone(),
                bios: facts.bios.clone(),
                ram: facts.ram.clone(),
                windows: facts.windows.clone(),
                ..Default::default()
            }));
        }
        if scene == "result" {
            let poster = crate::poster::create(&facts, None, &source, true).unwrap();
            println!("LOCAL_POSTER={}", poster.path.display());
        }
    }
    if let Ok(capture) = std::env::var("WSD_POWERLAB_CAPTURE") {
        for line in std::fs::read_to_string(capture).unwrap().lines() {
            let j = powerlab_core::json::Json::parse(line).unwrap();
            if let Ok(sample) = powerlab_core::ipc::sample_from_json(j.get("sample").unwrap_or(&j))
            {
                app.powerlab.replay_sample(sample);
            }
        }
        app.sensors = Some(app.powerlab.b3_snapshot());
    }
    if scene == "b3" {
        app.page = Page::Hardware;
        app.ai_analysis.open = false;
    }
    if scene == "benchmark" {
        app.ai_analysis.open = false;
        app.client_report.benchmark_open = true;
    }
    if scene == "powerlab" {
        app.powerlab.open = true;
    }
    if scene == "repair-en" {
        app.page = Page::Repair;
        app.language = Language::En;
        app.ai_analysis.open = false;
    }
    if matches!(scene.as_str(), "about-ru" | "about-en") {
        app.ai_analysis.open = false;
        app.language = if scene == "about-ru" {
            Language::Ru
        } else {
            Language::En
        };
        app.about.open = true;
    }
    if matches!(scene.as_str(), "poster" | "print-preview") {
        let zip =
            PathBuf::from(std::env::var_os("WSD_V112_POSTER_ZIP").expect("replay source ZIP"));
        let before = crate::content_hash::sha256(std::fs::File::open(&zip).unwrap()).unwrap();
        let document = crate::poster::sample_from_zip(&zip, &evidence).unwrap();
        assert_eq!(
            before,
            crate::content_hash::sha256(std::fs::File::open(&zip).unwrap()).unwrap()
        );
        println!(
            "POSTER_FIELD_REPLAY pages={} source_unchanged=true sha256={before}",
            document.light.len()
        );
        app.ai_analysis.open = false;
        app.client_report.poster_open = scene == "poster";
        app.client_report.print_open = scene == "print-preview";
        app.client_report.poster = Some(document);
    }
    let mut descriptor = wgpu::InstanceDescriptor::new_without_display_handle();
    descriptor.backends = wgpu::Backends::DX12;
    let instance = wgpu::Instance::new(descriptor);
    let adapters = wait(instance.enumerate_adapters(wgpu::Backends::DX12));
    let adapter = adapters
        .into_iter()
        .find(|a| a.get_info().device_type == wgpu::DeviceType::Cpu)
        .expect("Microsoft WARP is required; never silently choose a vendor adapter");
    println!("OFFSCREEN adapter={:?}", adapter.get_info());
    let (device, queue) = wait(adapter.request_device(&wgpu::DeviceDescriptor::default())).unwrap();
    let sizes = if matches!(scene.as_str(), "a6" | "b3" | "repair-en") {
        vec![
            (1., "100", 1378., 1172.),
            (1.25, "125", 1378., 1172.),
            (1.5, "150", 1378., 1172.),
        ]
    } else {
        vec![
            (1., "100", 1448., 1086.),
            (1.25, "125", 1448., 1086.),
            (1.5, "150", 1448., 1086.),
            (1., "narrow", 760., 640.),
        ]
    };
    for (dpi, name, logical_w, logical_h) in sizes {
        let context = egui::Context::default();
        crate::app::apply_theme(&context);
        crate::ui::fonts::install(&context);
        // Match production root fitting; rendering an unscaled 1376-point header
        // into a 1000-point test canvas would invent clipping absent from fit_scale.
        let fit = if scene == "a6" && name == "narrow" {
            crate::ui::fit_pixels_per_point(logical_w, logical_h)
                .max(crate::ui::MIN_PIXELS_PER_POINT)
        } else {
            1.
        };
        context.set_pixels_per_point(dpi * fit);
        context.all_styles_mut(|style| style.animation_time = 0.);
        let mut renderer = egui_wgpu::Renderer::new(
            &device,
            wgpu::TextureFormat::Rgba8Unorm,
            egui_wgpu::RendererOptions::PREDICTABLE,
        );
        let width = (logical_w * dpi) as u32;
        let height = (logical_h * dpi) as u32;
        let texture = device.create_texture(&wgpu::TextureDescriptor {
            label: Some("AI analysis offscreen"),
            size: wgpu::Extent3d {
                width,
                height,
                depth_or_array_layers: 1,
            },
            mip_level_count: 1,
            sample_count: 1,
            dimension: wgpu::TextureDimension::D2,
            format: wgpu::TextureFormat::Rgba8Unorm,
            usage: wgpu::TextureUsages::RENDER_ATTACHMENT | wgpu::TextureUsages::COPY_SRC,
            view_formats: &[],
        });
        for frame_index in 0..8 {
            let mut input = egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(logical_w / fit, logical_h / fit),
                )),
                ..Default::default()
            };
            if frame_index == 1 && (scene == "b3-bottom" || scene == "running-bottom") {
                input
                    .events
                    .push(egui::Event::PointerMoved(egui::pos2(200., 500.)));
                input.events.push(egui::Event::MouseWheel {
                    unit: egui::MouseWheelUnit::Point,
                    phase: egui::TouchPhase::Move,
                    delta: egui::vec2(0., -3000.),
                    modifiers: Default::default(),
                });
            }
            input.time = Some(frame_index as f64 * 0.25);
            context.set_embed_viewports(true);
            let mut output = context.run_ui(input, |ui| {
                if scene == "a6" || scene == "b3" {
                    let vm = app.build_vm(0., 0.);
                    let mut actions = vec![];
                    let mut controls = Controls {
                        client_name: &mut app.client_name,
                        mode: &mut app.mode,
                        deep_checks: &mut app.deep_checks,
                        include_hardware: &mut app.include_hardware,
                        benchmark_path: &mut app.benchmark_path,
                    };
                    dashboard::draw(ui, egui::Pos2::ZERO, &vm, &mut controls, &mut actions);
                } else if matches!(scene.as_str(), "benchmark" | "poster" | "print-preview") {
                    app.client_report_windows(&context);
                } else if matches!(scene.as_str(), "about-ru" | "about-en") {
                    app.about.show(&context, scene == "about-ru");
                } else if scene == "repair-en" {
                    app.repair_center_page(&context);
                } else if scene == "powerlab" {
                    app.powerlab.window(&context, "NOT_TESTED", false, "");
                } else {
                    app.ai_analysis_window(&context);
                }
            });
            if frame_index == 7 {
                let expected: &[&str] = match scene.as_str() {
                    "about-ru" => &[
                        "Что нового",
                        "Обновление",
                        "Скопировать сведения",
                        "Лицензии",
                    ],
                    "about-en" => &["What's new", "Update", "Copy details", "Licenses"],
                    "poster" => &["Тёмный", "Светлый", "Печать"],
                    "print-preview" => &["Выбрать принтер", "Отмена"],
                    _ => &[],
                };
                fn visible(shape: &egui::Shape, clip: egui::Rect, expected: &str) -> bool {
                    match shape {
                        egui::Shape::Text(t) => {
                            clip.contains(t.pos) && t.galley.text().contains(expected)
                        }
                        egui::Shape::Vec(items) => {
                            items.iter().any(|item| visible(item, clip, expected))
                        }
                        _ => false,
                    }
                }
                for label in expected {
                    assert!(
                        output
                            .shapes
                            .iter()
                            .any(|s| visible(&s.shape, s.clip_rect, label)),
                        "missing {label} in {scene}/{name}"
                    );
                }
            }
            for (id, delta) in &output.textures_delta.set {
                for image in delta {
                    renderer.update_texture(&device, &queue, *id, image);
                }
            }
            let jobs = context.tessellate(output.shapes, output.pixels_per_point);
            let screen = egui_wgpu::ScreenDescriptor {
                size_in_pixels: [width, height],
                pixels_per_point: output.pixels_per_point,
            };
            let mut encoder = device.create_command_encoder(&Default::default());
            let commands = renderer.update_buffers(&device, &queue, &mut encoder, &jobs, &screen);
            let view = texture.create_view(&Default::default());
            {
                let pass = encoder.begin_render_pass(&wgpu::RenderPassDescriptor {
                    label: Some("AI analysis pixels"),
                    color_attachments: &[Some(wgpu::RenderPassColorAttachment {
                        view: &view,
                        depth_slice: None,
                        resolve_target: None,
                        ops: wgpu::Operations {
                            load: wgpu::LoadOp::Clear(wgpu::Color {
                                r: 0.02,
                                g: 0.04,
                                b: 0.08,
                                a: 1.,
                            }),
                            store: wgpu::StoreOp::Store,
                        },
                    })],
                    depth_stencil_attachment: None,
                    timestamp_writes: None,
                    occlusion_query_set: None,
                    multiview_mask: None,
                });
                renderer.render(&mut pass.forget_lifetime(), &jobs, &screen);
            }
            queue.submit(commands.into_iter().chain(Some(encoder.finish())));
            for id in &output.textures_delta.free {
                renderer.free_texture(id);
            }
            output.textures_delta.clear();
        }
        let stride = (width * 4).div_ceil(256) * 256;
        let buffer = device.create_buffer(&wgpu::BufferDescriptor {
            label: None,
            size: (stride * height) as u64,
            usage: wgpu::BufferUsages::COPY_DST | wgpu::BufferUsages::MAP_READ,
            mapped_at_creation: false,
        });
        let mut encoder = device.create_command_encoder(&Default::default());
        encoder.copy_texture_to_buffer(
            texture.as_image_copy(),
            wgpu::TexelCopyBufferInfo {
                buffer: &buffer,
                layout: wgpu::TexelCopyBufferLayout {
                    offset: 0,
                    bytes_per_row: Some(stride),
                    rows_per_image: None,
                },
            },
            texture.size(),
        );
        queue.submit(Some(encoder.finish()));
        let (tx, rx) = mpsc::channel();
        buffer.slice(..).map_async(wgpu::MapMode::Read, move |r| {
            let _ = tx.send(r);
        });
        device
            .poll(wgpu::PollType::Wait {
                submission_index: None,
                timeout: Some(Duration::from_secs(10)),
            })
            .unwrap();
        rx.recv_timeout(Duration::from_secs(10)).unwrap().unwrap();
        let bytes = buffer.slice(..).get_mapped_range().unwrap();
        let mut rgba = vec![];
        for row in bytes.chunks_exact(stride as usize) {
            rgba.extend_from_slice(&row[..width as usize * 4]);
        }
        png(
            &evidence.join(format!("{scene}-{name}.png")),
            width,
            height,
            &rgba,
        );
        drop(bytes);
        buffer.unmap();
    }
}
