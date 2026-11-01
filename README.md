# WinStateDiag 1.2.11

Portable Windows diagnostics with explicitly confirmed contextual repair.

This branch is a clean source checkpoint accepted by the owner with known limitations. It intentionally has no parent commits, so private engineering history is not reachable. Existing repository branches and tags are preserved separately.

## Features

- Read-only Windows checks: PnP, VSS, WHEA, events, SFC, DISM and CHKDSK.
- Hardware passport, driver audit, storage evidence and CryptoPro details/ReHash.
- Separate execution, coverage and finding states; one final ZIP per diagnostic session.
- A5 runs on explicit request or as part of a requested diagnostic session, not automatically at startup.
- Contextual SFC/DISM/CHKDSK repair requires a confirmed finding, elevated rights and explicit confirmation. CHKDSK boot scheduling requires separate consent. Repair evidence never replaces original diagnostic evidence.
- Portable directory: WinStateDiag.exe and Reports/. Settings, history and working files live in the user profile.

## Build and test

Use Windows x64, Rust MSVC (validated with rustc 1.98.1), Visual Studio C++ build tools and Windows PowerShell 5.1. Cargo.lock pins Rust dependencies.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/release/fetch_lhm.ps1
cargo fmt --check
cargo check --locked
cargo clippy --all-targets --locked
cargo test --locked
Get-ChildItem scripts/Test-*.ps1 | ForEach-Object { powershell -NoProfile -ExecutionPolicy Bypass -File $_.FullName }
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/sandbox/Test-SandboxSafety.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/make_release.ps1 -PreserveBuildCache
```

The LHM fetch script uses official NuGet sources and pinned SHA256 values; it installs no driver/service. Generated binaries are not stored in Git. The sandbox safety script validates orchestration without launching a guest. Do not run separate GUI/live probe scripts without an approved environment.

## Validation and limitations

The preserved control EXE passed 780 Rust tests (2 explicitly ignored), 10 PowerShell suites, reproducible same-environment release builds and a local Defender scan. These are recorded checks, not proof of native GUI/UAC or real repair acceptance. See [checkpoint](docs/CHECKPOINT_1.2.11.md) for scope and the retained artifact hash.

Fixtures in this branch are synthetic/anonymized. Optional private-field replay tests require separately supplied anonymized inputs and are not self-contained LIVE tests. The original customer files are neither included nor modified.

## Dependencies

LibreHardwareMonitorLib is MPL-2.0; bundled dependency notices are under third_party/. Packages are obtained through scripts/release/fetch_lhm.ps1. No PawnIO driver is installed by this project.
