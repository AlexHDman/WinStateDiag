# EXPC WinDiag 1.12

WinDiag is a portable Windows diagnostic application. This branch contains the sources and build inputs for the 1.12 candidate.

## Build

Use Windows x64, the Rust MSVC toolchain, and the Windows SDK with its resource compiler.

```powershell
cargo build --release --locked --bin win_state_diag
cargo test --lib --locked
```

The executable is produced at `target/release/win_state_diag.exe`. The local packaging script is `scripts/make_release.ps1`.

WinDiag reads Windows diagnostics, builds reports, renders client posters, previews A4 printing, and can prepare a masked AI request for explicit submission. The portable executable includes its PowerLab runtime and the original standalone hardware support packages. The WinDiag executable uses an administrator manifest.

## Distribution notices

`licenses/hardware` and `third_party/powerlab-runtime/licenses` contain notices and corresponding sources for the bundled hardware components and runtime. The official PawnIO installer is redistributed unchanged under its separate terms. See `third_party/PawnIO-2.2.0/NOTICE.txt`.

The sources for the embedded Rust helper interfaces are in `third_party/powerlab-core`. Git does not contain client reports or working-session evidence.

Native Windows acceptance of the 1.12 application is still in progress.
