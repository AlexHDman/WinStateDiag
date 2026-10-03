// WinStateDiag - portable Windows state diagnostic center.
// A minimal GUI + session/orchestration layer around the proven, unmodified
// EXPC Diagnostic / Hardware Report PowerShell engine (see src/engine.rs).
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod cryptopro;
mod deep_checks;
mod details;
mod driver_audit;
mod engine;
mod graphics_startup;
mod graphics_wgpu;
pub mod i18n;
mod manifest;
mod nvme_health;
mod report_package;
pub mod ssd_history;
pub mod storage_benchmark;
mod storage_health;
pub mod storage_topology;
mod ui;

use graphics_startup::{GraphicsMode, Role, StartupLog};
use std::path::PathBuf;

/// Single source of truth for the displayed application version: the actual
/// Cargo package version, so the title bar never drifts from what shipped.
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let handshake = std::env::var(graphics_startup::ENV_HANDSHAKE).ok();
    let code = match graphics_startup::parse_role(&args, handshake.as_deref()) {
        // Safe Graphics Startup: the bootstrap only supervises renderer
        // children (normal, then safe) and never renders itself.
        Ok(Role::Bootstrap) => graphics_startup::run_bootstrap(&args),
        Ok(Role::Renderer { mode, supervised }) => run_renderer(
            &args,
            mode,
            handshake.filter(|_| supervised).map(PathBuf::from),
        ),
        Err(err) => {
            let log = StartupLog::open("startup");
            log.line(&format!("invalid arguments: {err}"));
            graphics_startup::show_native_error(&format!(
                "WinStateDiag: {err}\n\nЖурнал запуска: {}",
                log.path().display()
            ));
            graphics_startup::EXIT_INVALID_MODE
        }
    };
    std::process::exit(code);
}

/// Renderer process: runs the GUI in `mode`. Never starts another process.
fn run_renderer(args: &[String], mode: GraphicsMode, handshake: Option<PathBuf>) -> i32 {
    let log = StartupLog::open(&format!("renderer:{}", mode.name()));
    log.line(&format!(
        "renderer start: {} ({}); {}",
        mode.name(),
        mode.description(),
        graphics_startup::environment_summary()
    ));

    let reference = args.iter().any(|a| a == "--visual-reference");
    let mut title = format!("WinStateDiag — v{APP_VERSION}");
    if reference {
        title.push_str("  [VISUAL REFERENCE]");
    }
    if mode == GraphicsMode::Safe {
        title.push_str("  [безопасный графический режим]");
    }
    // Initial size = reference canvas at 80%; the first frame fits it to the
    // monitor and the canvas then scales uniformly with the window.
    let mut options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title(title.clone())
            .with_inner_size([ui::tokens::CANVAS_W * 0.8, ui::tokens::CANVAS_H * 0.8])
            .with_min_inner_size([640.0_f32, 516.0_f32]),
        ..Default::default()
    };
    graphics_wgpu::configure(&mut options.wgpu_options, mode);

    let supervised = handshake.is_some();
    let creator_log = log.clone();
    let result = eframe::run_native(
        &title,
        options,
        Box::new(move |cc| {
            ui::fonts::install(&cc.egui_ctx);
            let adapter = cc
                .wgpu_render_state
                .as_ref()
                .map(|rs| graphics_wgpu::describe(&rs.adapter.get_info()))
                .unwrap_or_else(|| "unknown".into());
            if let Some(rs) = cc.wgpu_render_state.as_ref() {
                let all: Vec<String> = rs
                    .available_adapters
                    .iter()
                    .map(|a| graphics_wgpu::describe(&a.get_info()))
                    .collect();
                creator_log.line(&format!("available DX12 adapters: {}", all.join("; ")));
            }
            creator_log.line(&format!("renderer initialised: adapter {adapter}"));
            let mut inner = app::WinStateDiagApp::default();
            if mode == GraphicsMode::Safe {
                inner.push_notice(
                    "WinStateDiag запущен в безопасном графическом режиме. \
                     Обнаружена проблема инициализации стандартного графического режима."
                        .into(),
                );
            }
            Ok(Box::new(StartupGuard {
                inner,
                frames: 0,
                handshake,
                detail: format!("mode {}, adapter {adapter}", mode.name()),
                log: creator_log,
            }))
        }),
    );
    match result {
        Ok(()) => 0,
        Err(err) => {
            log.line(&format!("renderer initialisation failed: {err}"));
            if !supervised {
                // Started by hand (no supervisor): report directly.
                graphics_startup::show_native_error(&format!(
                    "WinStateDiag: не удалось запустить графический режим «{}».\n\n{err}\n\nЖурнал запуска: {}",
                    mode.name(),
                    log.path().display()
                ));
            }
            graphics_startup::EXIT_RENDERER_INIT_FAILED
        }
    }
}

/// Wraps the application to report "first frame painted" to the bootstrap.
struct StartupGuard {
    inner: app::WinStateDiagApp,
    frames: u32,
    handshake: Option<PathBuf>,
    detail: String,
    log: StartupLog,
}

impl eframe::App for StartupGuard {
    fn logic(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        self.inner.logic(ctx, frame);
    }

    fn ui(&mut self, ui: &mut egui::Ui, frame: &mut eframe::Frame) {
        self.inner.ui(ui, frame);
        self.frames = self.frames.saturating_add(1);
        // ui() of frame 2 runs after frame 1 was presented.
        if self.frames == 2 {
            self.log
                .line(&format!("first frame presented ({})", self.detail));
            if let Some(path) = self.handshake.take() {
                graphics_startup::signal_ready(&path, &self.detail);
            }
        }
        if self.frames < 3 {
            ui.ctx().request_repaint();
        }
    }
}
