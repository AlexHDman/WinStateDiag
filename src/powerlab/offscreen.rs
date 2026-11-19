//! Genuine egui pixels rendered offscreen on Microsoft WARP. No host window/input.
use super::*;
use eframe::{egui_wgpu, wgpu};
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
#[ignore = "Offscreen DX12 WARP render; captured Windows sensor data required"]
fn actual_data_dpi_screenshots() {
    let evidence = PathBuf::from(std::env::var("WSD_POWERLAB_EVIDENCE").unwrap());
    let capture = PathBuf::from(std::env::var("WSD_POWERLAB_CAPTURE").unwrap());
    let mut monitor = Monitor::default();
    for line in std::fs::read_to_string(capture).unwrap().lines() {
        let j = powerlab_core::json::Json::parse(line).unwrap();
        let v = j.get("sample").unwrap_or(&j);
        if let Ok(sample) = powerlab_core::ipc::sample_from_json(v) {
            monitor.apply(SamplerEvent::Sample(Box::new(sample)));
        }
    }
    monitor.message = format!(
        "Мониторинг завершён · {} измерений · реальные данные контрольного ПК",
        monitor.samples()
    );
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
    for (dpi, name, logical_w, logical_h) in [
        (1., "100", 1378., 1172.),
        (1.25, "125", 1378., 1172.),
        (1.5, "150", 1378., 1172.),
        (1., "narrow", 900., 720.),
    ] {
        let context = egui::Context::default();
        crate::app::apply_theme(&context);
        crate::ui::fonts::install(&context);
        context.set_pixels_per_point(dpi);
        let mut renderer = egui_wgpu::Renderer::new(
            &device,
            wgpu::TextureFormat::Rgba8Unorm,
            egui_wgpu::RendererOptions::PREDICTABLE,
        );
        let width = (logical_w * dpi) as u32;
        let height = (logical_h * dpi) as u32;
        let texture = device.create_texture(&wgpu::TextureDescriptor {
            label: Some("PowerLab offscreen"),
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
        for _ in 0..3 {
            let input = egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(logical_w, logical_h),
                )),
                ..Default::default()
            };
            let mut output = context.run_ui(input, |ui| {
                egui::Frame::new()
                    .fill(c::BG_CARD)
                    .inner_margin(16)
                    .show(ui, |ui| {
                        let _ = monitor.draw(ui, "ACCESS_DENIED", false, "Клиент");
                    });
            });
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
                    label: Some("PowerLab pixels"),
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
            &evidence.join(format!("PowerLab-{name}.png")),
            width,
            height,
            &rgba,
        );
        drop(bytes);
        buffer.unmap();
    }
}
