//! Renderer settings for the Safe Graphics Startup modes (see
//! `graphics_startup.rs`).
//!
//! eframe's default wgpu setup requests `Backends::PRIMARY | Backends::GL`
//! (egui-wgpu `WgpuSetupCreateNew::without_display_handle`). On Windows that
//! is Vulkan + DX12 + OpenGL (WGL), and wgpu-core `Instance::new` initialises
//! EVERY requested backend up front, before any adapter is chosen:
//! * Vulkan loads every installed Vulkan ICD. This is where the earlier
//!   incident crashed: Intel `igvk64.dll` 0xC0000005.
//! * WGL loads `opengl32.dll` and the vendor OpenGL ICD. This is the path
//!   where the legacy AMD driver shows "LoadLibrary failed with error 87" and
//!   ends the process.
//!
//! Both modes therefore request DX12 only. DX12 adapter enumeration still
//! calls D3D12CreateDevice on each DXGI adapter. That is the standard
//! Windows path, and it is the one remaining vendor-driver touch point in
//! both modes.

use crate::graphics_startup::GraphicsMode;
use eframe::egui_wgpu::{self, WgpuSetup};
use eframe::wgpu;
use std::sync::Arc;

/// Applies the renderer settings of `mode` to eframe's wgpu configuration.
pub fn configure(config: &mut egui_wgpu::WgpuConfiguration, mode: GraphicsMode) {
    if let WgpuSetup::CreateNew(create) = &mut config.wgpu_setup {
        create.instance_descriptor.backends = wgpu::Backends::DX12;
        match mode {
            GraphicsMode::Normal => {
                create.power_preference = wgpu::PowerPreference::HighPerformance;
                create.native_adapter_selector = None;
            }
            GraphicsMode::Safe => {
                create.native_adapter_selector = Some(Arc::new(select_software_adapter));
            }
        }
    }
}

/// Safe mode: the Microsoft WARP adapter (DeviceType::Cpu), which is
/// Microsoft code and independent of the GPU vendor driver for rendering and
/// presenting.
fn select_software_adapter(
    adapters: &[wgpu::Adapter],
    surface: Option<&wgpu::Surface<'_>>,
) -> Result<wgpu::Adapter, String> {
    adapters
        .iter()
        .find(|a| {
            a.get_info().device_type == wgpu::DeviceType::Cpu
                && surface.is_none_or(|s| a.is_surface_supported(s))
        })
        .cloned()
        .ok_or_else(|| {
            format!(
                "no Microsoft WARP (software) DX12 adapter among: {}",
                adapters
                    .iter()
                    .map(|a| describe(&a.get_info()))
                    .collect::<Vec<_>>()
                    .join("; ")
            )
        })
}

/// Short adapter description for the startup log.
pub fn describe(info: &wgpu::AdapterInfo) -> String {
    let driver = [info.driver.as_str(), info.driver_info.as_str()]
        .iter()
        .filter(|s| !s.is_empty())
        .copied()
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "{} [{:?}, {:?}{}]",
        info.name,
        info.backend,
        info.device_type,
        if driver.is_empty() {
            String::new()
        } else {
            format!(", driver {driver}")
        }
    )
}
