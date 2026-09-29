# Changelog

## [0.4.0] - 2026-09-29 - first public release

Portable read-only Windows diagnostic center (Windows 10/11 x64). WinStateDiag diagnoses and reports; it never repairs Windows automatically.

### Added
- Finalized diagnostic dashboard (approved visual master), RU/EN interface switchable live.
- EXPC PC Diagnostics with Standard / Deep checks / Full modes and a Stop button that keeps already collected evidence.
- SFC / DISM / CHKDSK diagnostic result states (OK / ATTENTION / ERROR), shown separately from completion: a check can be 100% complete and still report a finding (e.g. DISM "component store is repairable"). The finding is explained in the dashboard and journal; the manual repair command is shown as text only and never executed.
- Hardware Report (hardware inventory) and read-only Driver Audit with per-device details.
- SSD/NVMe benchmark per physical disk (HDDs excluded, up to three disks), stability rating, per-disk history and comparison with the previous run; persistent history in `Reports\History\`.
- CryptoPro HASH status with user-confirmed ReHash.
- Safe Graphics startup with automatic software (WARP) renderer fallback.
- Session journal with a full-journal viewer (Save as UTF-8 text / Copy).
- Cumulative per-PC, per-date report ZIP with `manifest.json` (schema 1.0: modules, evidence files, deep-check results; no local paths or serial numbers).
- Verified ZIP-only completed report folder: loose evidence is removed only after the final ZIP is re-read and verified; on any doubt everything is kept.
- Footer shows the full Windows build including the update revision.

### Fixed
- Microsoft Defender summary now describes Antivirus, AMService and RealTimeProtection individually instead of reporting all three as disabled when only one is.

## [0.3.3] - 2026-09-24 - "Открыть отчёт" opens only the final Reports ZIP
### Fixed
- "Открыть отчёт" / "Открыть папку" no longer take a path from the UI: the app resolves it only from the completed session state (the final ZIP copied to `<EXE folder>\Reports\<Client> - <Computer> - DD-MM-YY\`), verifies it lies under `Reports` and is an existing file, and otherwise journals `[ERROR]` with the exact expected path. There is no fallback to the temporary packaging ZIP or `%TEMP%`.
- Unit tests can no longer launch the Windows shell (a test had opened its own `%TEMP%\wsd-open-*` ZIP during `cargo test`); openers are injected in tests.
### Added
- Regression test: temporary ZIP path != opened path, opened path == final Reports ZIP (Cyrillic + spaces), folder == its parent, missing final ZIP -> `[ERROR]`, nothing opened.

## [0.3.0] - 2026-09-24 - Final polish, portable release
### Added
- Client field: soft 1 px violet attention pulse (1.8 s) while the client name is empty.
- Result: "Открыть отчёт" opens the final ZIP with its Windows associated action and pulses with a 1 px amber perimeter until opened once; "Открыть папку" (restrained violet perimeter) opens the exact report folder of the session.
- Report identity: `Reports\<Client> - <Computer> - DD-MM-YY\<Client> - <Computer> - DD-MM-YY.zip` (client omitted when empty; Windows-safe; `(2)`, `(3)` suffix instead of overwriting; copy verified by size and ZIP signature).
- Driver Audit: semantic "expected inactive driver" classification (e.g. Desktop Activity Moderator `dam`): informational SCM 7026 + intact Microsoft-signed image + valid configuration + no Code Integrity / SCM failures = internal INFO, not counted and not shown in the client report.
- `scripts\make_release.ps1`: the only way to produce a user-testable EXE (`dist\WinStateDiag-vX.Y.Z\WinStateDiag.exe`, SHA256 verified against the fresh build).
### Kept
- Safe Graphics Startup (D3D12 normal, WARP safe, startup_graphics.log), 14-stage EXPC, Hardware Report, SSD benchmark/history, approved GUI.
- Known OPEN bug: incomplete RAM / DIMM detection on X79G (docs\KNOWN_BUGS.md).

## [0.2.0] - 2026-09-24 - Safe Graphics Startup (dist folder only; the EXE still reported v0.1.0)
### Added
- Bootstrap + renderer child processes, DX12-only normal mode, WARP safe mode, startup log.

## [0.1.0] - Milestone 02 bootstrap
### Added
- Rust project skeleton (`win_state_diag`).
- Embedded legacy PowerShell diagnostic engine (EXPC Diagnostic, Hardware Report) as the working baseline.
