# Safe Graphics Startup

- **Status:** implemented 2026-09-24.
- **Real-machine acceptance on SERVER:** still pending (WAITING_FOR_REAL_MACHINE).

## 1. Incidents (kept separate)

| # | Machine | Symptom | Driver component |
|---|---|---|---|
| A | earlier PC | crash 0xC0000005 during GUI initialisation (Application Error 1000) | Intel `igvk64.dll`, the Intel **Vulkan** ICD |
| B | SERVER, Windows 11 Pro 26200, RDP session. GPUs: Microsoft Remote Display Adapter, AMD Radeon HD 7450 (driver 15.201.2401.1001, 2015), Intel UHD 730 | dialog "LoadLibrary failed with error 87", then ExitCode 87; no Application Error event | legacy AMD **OpenGL** ICD. This dialog is a known AMD OpenGL driver failure, typically seen over Remote Desktop. |

## 2. Audit of the previous startup (v0.1.0, before this change)

- **Versions:** `eframe` 0.36.2 with default features: `wgpu`, `accesskit`, `default_fonts`, `links`, `wayland`, `x11`, `web_screen_reader`, `winit/default`.
  - The `glow` feature is **not** enabled. `egui_glow`/`glutin` appear in Cargo.lock only as optional entries.
  - `egui-wgpu` 0.36.2 (default features, so `wgpu/default`); `wgpu`/`wgpu-core`/`wgpu-hal` 30.0.1.
- **Renderer:** eframe `Renderer::Wgpu`, the only one compiled. There was no renderer fallback.
- **Backends compiled on Windows:** DX12, Vulkan, GLES (via WGL on Windows).
- **Backends requested:** egui-wgpu's default is `Backends::from_env().unwrap_or(PRIMARY | GL)`. On Windows that means Vulkan + DX12 + GL.
- **Where graphics starts:** `main.rs` → `eframe::run_native` → `run_wgpu` → `WgpuWinitApp` → `egui_wgpu::RenderState::create`. The wgpu instance comes from `WgpuSetup::new_instance`.
  - `wgpu-core` `Instance::new` initialises **every requested backend immediately**, before any adapter is chosen: `try_add_hal` runs for Vulkan, then Metal, then DX12, then GLES.
  - The Vulkan instance loads all Vulkan ICDs (incident A).
  - The WGL instance calls `LoadLibraryA("opengl32.dll")`, then `ChoosePixelFormat`/`wglCreateContext`, which loads the vendor OpenGL ICD (incident B).
- **Catching the failure:**
  - A controlled wgpu error comes back as `Err` from `run_native`; main returned it, giving exit code 1.
  - A native crash, or a driver that calls ExitProcess, cannot be caught in-process. `catch_unwind` does not help, and release builds use `panic = "abort"`.
- **What exit code 87 means here:**
  - Our code has no `process::exit` in the GUI binary.
  - A Rust panic would give 0xC0000409, and an `Err` from main gives 1.
  - So exit 87 did not come from WinStateDiag code. It is `ERROR_INVALID_PARAMETER` from the driver's LoadLibrary failure, and the process was ended from inside the driver. That also explains why no crash event was recorded.
- **Can eframe be re-run in the same process?** For controlled errors, technically yes: eframe reuses its thread-local winit event loop when `run_and_return` is set. It is useless against a native crash or ExitProcess, so the fallback runs in a separate process.

## 3. Architecture

```
WinStateDiag.exe                     (bootstrap: supervises, never renders)
  └─ WinStateDiag.exe --graphics-mode=normal   (child, WSD_GRAPHICS_HANDSHAKE=<file>)
        painted first frame? ── yes → bootstrap waits for it and exits with its exit code
        exit ≠ 0 / crash / no frame in 60 s
  └─ WinStateDiag.exe --graphics-mode=safe     (child)
        painted first frame? ── yes → same as above
        otherwise → native MessageBox (user32, no egui) with the startup-log path
```

| Mode | Backends | Adapter | Protects against |
|---|---|---|---|
| normal | **DX12 only**; the Vulkan loader and OpenGL/WGL are never loaded | hardware, `HighPerformance` (WARP only if no hardware adapter qualifies) | incidents A and B: both are backends that are no longer initialised |
| safe | DX12 only | **Microsoft WARP** (`DeviceType::Cpu`), picked by `native_adapter_selector` | vendor driver failures while rendering or presenting on the GPU |

**No loop:**
- Only the bootstrap spawns processes.
- A child carries `--graphics-mode=`, so it is always a renderer.
- `decide()` allows exactly one path, normal → safe, and nothing after safe.
- An invalid or duplicate `--graphics-mode=` value is a startup error with exit code 2, and nothing is spawned.
- Running with `--graphics-mode=normal` or `--graphics-mode=safe` by hand starts that renderer directly, without supervision.

**Handshake:** the child writes the handshake file in `ui()` of frame 2, which runs after frame 1 has been presented. A child that exits with code 0 before its first frame counts as a clean exit, not a failure.

**Remaining limitation (both modes):** DX12 adapter enumeration calls `D3D12CreateDevice` on every DXGI adapter. If a vendor D3D12 driver itself crashes at that point, both modes fail and the final native error appears with the log.

**Glow/OpenGL:** not used as a fallback. It is not compiled, and OpenGL is exactly the path that fails in incident B.

## 4. Startup log

`<EXE folder>\Reports\startup_graphics.log`. If that folder is not writable, the log goes to `%TEMP%\WinStateDiag\startup_graphics.log`. It is rotated to `.old` above 512 KB.

Each line contains the date, time, role and pid. Recorded events:

- **Environment:** app version, Windows edition and build, session RDP/local.
- **Attempt:** each requested renderer.
- **Child renderer:** the DX12 adapters it sees, the adapter chosen, and "first frame presented".
- **Failures:** exit code decoded (e.g. `87 (0x00000057) — ERROR_INVALID_PARAMETER…`, `0xC0000005 — access violation`), timeout, spawn error.
- **Outcome:** the fallback decision, the mode that succeeded, and the application's exit code.

No user names, client names or paths other than the log path.

## 5. User experience

- Safe mode:
  - The window title ends with "[безопасный графический режим]".
  - The journal shows one INFO line: "WinStateDiag запущен в безопасном графическом режиме. Обнаружена проблема инициализации стандартного графического режима."
- The dashboard layout and the Visual Master geometry are unchanged: the offline render is byte-identical.

## 6. Files

- `src/graphics_startup.rs`: roles, decision table, supervisor, handshake, log, native message box, RDP detection, 11 unit tests.
- `src/graphics_wgpu.rs`: DX12-only configuration and the WARP selector. Type-checked against the real egui-wgpu 0.36.2 / wgpu 30.0.1.
- `src/main.rs`: role dispatch, renderer process, first-frame guard.
- `src/app.rs`: `push_notice()` only.

## 7. Acceptance (still open)

On SERVER, in the same RDP session where v0.1.0 fails with error 87, the new EXE must:

1. open;
2. show the dashboard;
3. not crash;
4. have a log that shows which mode worked;
5. still run diagnostics.

Until then the result is WAITING_FOR_REAL_MACHINE.
