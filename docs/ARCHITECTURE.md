# WinStateDiag — architecture (v0.4.0)

## Scope

WinStateDiag determines and records the current state of a Windows computer. It is read-only: no repair, no recovery, no automatic modification of Windows. The only user-confirmed exception is the CryptoPro ReHash action.

## Components

| Area | Location | Role |
|---|---|---|
| GUI | `src/app.rs`, `src/ui/` | egui/eframe dashboard (RU/EN, `src/i18n.rs`), measured layout tokens (`src/ui/tokens.rs`, see `UI_VISUAL_MASTER.md`). |
| Safe Graphics | `src/graphics_startup.rs`, `src/graphics_wgpu.rs` | Normal renderer with automatic WARP fallback, `startup_graphics.log` (see `SAFE_GRAPHICS_STARTUP.md`). |
| Diagnostic engine | `embedded/` + `src/engine.rs` | Proven PowerShell scripts embedded into the EXE and run hidden: EXPC Diagnostic (14 steps), Hardware Report. The Rust side orchestrates, tracks progress and collects evidence. |
| Deep-check results | `src/deep_checks.rs` | SFC / DISM / CHKDSK result state (OK / ATTENTION / ERROR / UNKNOWN / SKIPPED) read from the EXPC JSON, then the TXT, then conservative classification of the tool output. Separate from progress. |
| Driver Audit | `src/driver_audit.rs`, `embedded/WinStateDiag/DriverAudit.ps1` | Read-only driver inventory and classification (see `DRIVER_AUDIT.md`). |
| SSD / NVMe | `src/storage_topology.rs`, `src/storage_benchmark.rs`, `src/ssd_history.rs` | Physical disk enumeration (SSD/NVMe only), benchmark, per-disk history. |
| CryptoPro | `src/cryptopro.rs` | HASH status and confirmed ReHash. |
| Report package | `src/report_package.rs`, `src/manifest.rs` | Cumulative per-PC/per-date ZIP with `manifest.json`. |

## Report lifecycle

1. Evidence of each module is stored in `Reports\<Client> - <Computer> - DD-MM-YY\`.
2. Each update rebuilds the ZIP from all evidence plus a generated `manifest.json`, writes a candidate file, re-reads and CRC-checks every entry, then atomically replaces the final ZIP. On failure the previous ZIP and every file are kept.
3. When nothing is running and the last diagnostic run neither failed nor was stopped, the final ZIP is verified again; only if every loose file is inside it byte for byte are the loose files removed (SSD history lines are first copied to `Reports\History\`). The folder then holds only the ZIP.
4. A later update of the same package (another module, a same-day rerun) first restores the evidence from the ZIP, so nothing earlier is lost.
