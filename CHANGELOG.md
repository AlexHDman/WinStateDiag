# Changelog

## [0.4.3] - 2026-10-03 - storage health, diagnostic accuracy

Includes all changes of the internal 0.4.2 test build (never published).

### Fixed
- EXPC Diagnostic Results: INFO steps (e.g. 14 BIOS / drivers / firmware) now have their own "Info" counter; every represented step is counted exactly once (steps without a final result yet are shown as "No result yet" only when present).
- Hardware Report GPU memory: a saturated 32-bit value (e.g. "4.00 GB" for an 8 GB card) is no longer shown as VRAM. Precedence: display-driver `HardwareInformation.qwMemorySize` (64-bit) → a representable 32-bit value → "Not reliably determined"; raw source values and the source used are kept in the evidence. No GPU-name guessing.
- Hardware Report GPU memory kind (real iGPU case): an integrated GPU whose driver reports a very large value (e.g. ~28 GB) is no longer shown as "VRAM 28 GB". The Windows DirectX adapter record (`DedicatedVideoMemory` / `SharedSystemMemory`, matched by PCI vendor/device id) separates dedicated video memory from shared system graphics memory; without that record an adapter on PCI bus 0 is "graphics memory reported by driver (dedicated VRAM not confirmed)". Discrete cards keep their reliable 64-bit VRAM. New JSON fields `VRAMKind`, `VRAMKindReason`, `DedicatedVideoMemoryBytes`, `SharedSystemMemoryBytes`, `DriverReportedMemoryBytes`; `VRAMBytes` means dedicated memory only.
- Hardware Report memory speed: SMBIOS speeds are shown as data rates in MT/s ("rated 7667 MT/s, configured 7667 MT/s (SMBIOS-reported data rate, not measured)"), not MHz. JSON keeps the old fields and adds `RatedSpeedMTs`, `ConfiguredSpeedMTs`, `RatedSpeed`, `ConfiguredSpeed`, `SpeedSource`.
- Driver Audit, Kernel-PnP 219 (confirmed on several real machines): a historical "driver failed to load" event (e.g. WUDFRd) for a device that exists now with PnP ErrorCode 0 is HISTORICAL / INFO — it stays visible in Details/evidence but no longer raises the audit to WARNING, whatever its count. A current PnP error stays PROBLEM; an unknown current state stays WARNING.
- `manifest.json` per-disk modules: with several physical disks tested, `ssd_benchmark`, `nvme_health` and `storage_correlation` now list `disks` — per physical disk (`disk_key` = FNV-1a of the physical identity, `physical_disk_index`, `model`, `status`, `evidence`, `latest_evidence`). Grouping uses the physical identity in the evidence, never a drive letter; no serial is written. Schema stays 1.0 (additive).

### Changed
- Driver Check summary: "Без ошибок / No errors" → "Проверено без замечаний / Checked OK" (it counts audited driver items without findings, not all devices).
- `manifest.json` (schema 1.0, additive): each module lists `latest_evidence`, the files of its newest completed run, so a repeated same-day package names its current result unambiguously.
- SSD benchmark JSON (additive): `run_role` (`initial` / `automatic_retest`), `physical_disk_index`, `model`. Benchmark thresholds and measurement logic are unchanged.

### Added
- **Native NVMe Health reader** (`src/nvme_health.rs`). Read-only SMART / Health Information log (LID 02h) and Error Information log (LID 01h) via `IOCTL_STORAGE_QUERY_PROPERTY` + `STORAGE_PROTOCOL_SPECIFIC_DATA` (`ProtocolTypeNvme`, `NVMeDataTypeLogPage`). Validated on real NVMe drives (Samsung 9100 PRO, Netac, NX-512 2280, Patriot P300) against CrystalDiskInfo and Victoria (validation references only — never bundled, called or parsed). Evidence `NVMe_Health_<date>_<time>_PD<n>.json`.
- **Storage correlation** (`src/storage_health.rs`), per physical disk: benchmark (first run + retest) + NVMe health (Critical Warning bits individually, media/data integrity errors, Error Log Entries, drive-reported temperature threshold) + Windows storage events (Disk / StorNVMe / StorPort / Ntfs / volmgr, read-only `Get-WinEvent`, bound to a disk only via `\Device\HarddiskN`). States: OK, benchmark OK but no NVMe data, anomaly not confirmed on retest, BENCHMARK ANOMALY / RETEST REQUIRED, benchmark anomaly CHECK (not a failure), STORAGE ATTENTION, STORAGE PROBLEM. Permanent rule: **unstable benchmark ≠ SSD failure**; Error Log Entries / Unsafe Shutdowns / Percentage Used < 100 are facts, never verdicts; event count alone never sets severity. Evidence `Storage_Correlation_<date>_<time>_PD<n>.json`.
- **Automatic benchmark retest**: an UNSTABLE first run is followed by a short idle (10 s) and exactly ONE confirmation retest of the same physical disk. Both runs are kept in the evidence (`SSD_Benchmark_*_retest.*`), history and Details window; the dashboard shows the first run in its note. No retest after a cancel, a technical failure, a target that is no longer resolvable, a health read that did not arrive in time, or a controller state where more write testing is inappropriate (Critical Warning bits 0–3, media errors) — fail closed.
- SSD Details window: both runs' passes, the storage assessment with its explained findings, and the NVMe HEALTH facts (RU/EN). The SSD card status colour comes from the correlation, not from a raw counter.
- `assets\tray-icon.ico`: tray-size frames (16/20/24/32/40) of the existing icon, prepared only — WinStateDiag has no tray implementation; EXE/window/taskbar icons unchanged.
- `docs\DIAGNOSTIC_FEEDBACK.md`: real-machine lessons (real issue / check / historical-noise / WinStateDiag issue) and the next backlog (Evidence Intelligence / cross-module consistency — documented, not implemented).
- `docs\WINSTATEDIAG_PRO_AI.md`: design of the future Pro AI analysis (provider presets incl. YandexGPT via Yandex Cloud, custom OpenAI-compatible endpoint, API-key security contract) and the WinRepair Pro handoff. Documentation only.

## [0.4.1] - released - diagnostic UX patch

### Changed
- Driver Check details: the one-line technical summary is replaced by a compact SUMMARY header with counters (problems, warnings, no errors, devices, total events) and an Info tooltip that explains the status rule. No date/time in the header. The Driver Audit classification and the driver list are unchanged.
- "Run again" is now the prominent primary action of the Driver Check window (same re-check as before).

### Added
- Driver Check: "Copy issues" / "Save issues" export one plain-text block of problems and warnings only (device, provider, driver date, INF, service, Hardware ID, evidence, event count, latest event). Save writes UTF-8 to `Reports\Logs\WinStateDiag_DriverIssues_<date>_<time>.txt` and shows the path.
- EXPC stages card: "Details" button opening the "EXPC Diagnostic Results" window — summary counters, findings first with their stage numbers, explanations from the existing EXPC / deep-check results, suggested repair commands shown as text only (with "Copy command"), Copy / Save / Close. WinStateDiag still never runs repair commands.

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
