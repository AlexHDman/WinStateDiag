# WinStateDiag — architecture (v1.0)

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
| NVMe Health | `src/nvme_health.rs` | Read-only NVMe SMART / Health + Error Information log pages via `IOCTL_STORAGE_QUERY_PROPERTY` (real Windows validated), bound to the benchmark's physical-disk identity; evidence `NVMe_Health_*.json`. |
| Storage correlation | `src/storage_health.rs` | Per physical disk: benchmark + automatic retest + NVMe health + storage System events (read-only `Get-WinEvent`). Conservative states; "unstable benchmark ≠ SSD failure"; evidence `Storage_Correlation_*.json`. |
| Crash Dump analyzer | `src/crash_dump.rs` | v0.4.4. BugCheck (WER 1001 / Kernel-Power 41) + minidump / MEMORY.DMP inventory, debugger detection, headless `cdb !analyze -v` with timeout and local symbol cache, confidence model and Driver Audit correlation; original dump copied (read only); evidence `CrashDump_Analysis_*.txt`, `CrashDump_Summary_*.json`. Debugger install only on an explicit click (official winget `Microsoft.WinDbg`). |
| Power diagnostics | `src/power.rs` | v0.4.4. PSU rails (+12V/+5V/+3.3V/5VSB) through a sensor-provider abstraction (LibreHardwareMonitor / OpenHardwareMonitor WMI, Win32_VoltageProbe). SENSOR DATA NOT AVAILABLE without data; never "PSU faulty"; evidence `Power_Sensors_*.json` on explicit refresh. |
| Group Policy / ADMX health | `src/gpo_admx.rs` | v0.4.4. Read-only local / Central Store ADMX/ADML inventory, domain and SYSVOL reachability, generation check only against the official Microsoft reference (https://aka.ms/Windows11/26H2/GPsettings) placed in `Reference\`; evidence `GroupPolicy_ADMX_Health_*.json`. |
| Hardware sensors | `src/sensors.rs` | v0.4.5. Read-only sensor layer: provider abstraction (NVMe Health, bundled LibreHardwareMonitorLib helper, HWiNFO shared memory, LHM/OHM WMI, nvidia-smi, Storage Reliability, Win32_VoltageProbe, ACPI TZ), normalisation, roles, precedence + mismatch, confidence, ATX-rail status, evidence `Hardware_Sensors_*.json`. Replaces the v0.4.4 power-only reader (`src/power.rs` keeps rail identity/classification). |
| Freeze / hang incidents | `src/incidents.rs` (+ collector in `src/crash_dump.rs`) | v0.4.5. Kernel-Power 41 / EventLog 6008 incidents (one per boot), the 10 minutes before the last sign of life, LiveKernelReports listing; conservative verdict (hang / BSOD / probable subsystem + confidence, else CAUSE NOT DETERMINED); evidence `Incidents_*.json`. |
| Computer passport | `src/passport.rs` | v0.4.5. Windows / CPU / RAM / motherboard for the Diagnostics page (read-only CIM). |
| PowerShell runner | `src/ps_exec.rs` | v0.4.4. Shared `-EncodedCommand` runner with timeout / process-tree guard for the read-only collectors. v1.0: UTF-8 output + no progress records (`PS_PRELUDE`), `PSModulePath` cleared for the Windows PowerShell 5.1 child (started from a PS7 session it otherwise loads PS7's modules and loses e.g. `Get-AuthenticodeSignature`), and `run_capture_observed` (line-by-line stdout/stderr for real stage feedback, bounded drain). |
| Event evidence | `src/events.rs` | v1.0. Read-only aggregation of Schannel, WindowsUpdateClient 20 (KB / HRESULT / title; historical vs current from later 19), TPM, Service Control Manager (+ current service state, start type, image path), SideBySide 33 (executable + missing assembly; no invented owner), Code Integrity (kernel vs user mode), VSS / Volsnap categories, application errors. Count, 7-day count, first / last seen, latest messages; evidence `Event_Evidence_*.json`; shown stage-locally in EXPC Details. |
| ATA / SATA SMART | `src/ata_smart.rs` | v1.0. Strictly read-only `SMART_GET_VERSION` + `SMART_RCV_DRIVE_DATA` (READ DATA 0xD0 / READ THRESHOLDS 0xD1 only). Health = the drive's own thresholds + sector counters as facts; UNSUPPORTED for NVMe / bridges / RAID (never a failure). All SATA disks (HDDs too) feed the SMART card, the sensor matrix (`Provider::AtaSmart`) and `Ata_Smart_*.json`. |
| Save As / icons | `src/win_dialog.rs`, `src/win_icon.rs` | v1.0. Standard `GetSaveFileNameW` for every Details window (current module text only); crisp multi-size window icons from the EXE's own icon resource (`WM_SETICON` small/big on every native window, Details viewports included). |
| QA scenes | `src/app_qa_scenes.rs` | v1.0. `--visual-reference --scene <name>` renders the real UI on fixture data (Diagnostics, Hardware, sensor / stage / disk Details, BSOD analysis running). QA only. |
| Pages | `src/ui/pages.rs` | v0.4.4. Page tabs and the cards of the Diagnostics / Hardware pages (stage table, GPO, compact journal, system state, power, SMART, crash, Test 1 / Test 2). |
| CryptoPro | `src/cryptopro.rs` | HASH status and confirmed ReHash. |
| Report package | `src/report_package.rs`, `src/manifest.rs` | Cumulative per-PC/per-date ZIP with `manifest.json`. |

## Report lifecycle

1. Evidence of each module is stored in `Reports\<Client> - <Computer> - DD-MM-YY\`.
2. Each update rebuilds the ZIP from all evidence plus a generated `manifest.json`, writes a candidate file, re-reads and CRC-checks every entry, then atomically replaces the final ZIP. On failure the previous ZIP and every file are kept.
3. When nothing is running and the last diagnostic run neither failed nor was stopped, the final ZIP is verified again; only if every loose file is inside it byte for byte are the loose files removed (SSD history lines are first copied to `Reports\History\`). The folder then holds only the ZIP.
4. A later update of the same package (another module, a same-day rerun) first restores the evidence from the ZIP, so nothing earlier is lost.

## Repeated runs (v0.4.2 audit)

One package per PC and date is cumulative by design: a repeated same-day run of a module adds its evidence next to the earlier run (never overwriting; colliding names get `_02`, `_03`, …). `manifest.json` lists every file per module in `evidence` and, since v0.4.2, the files of the newest completed run in `latest_evidence`; the SFC/DISM/CHKDSK `checks` are read from that same run. Readers interpret `latest_evidence` as the current result; earlier runs remain as history.

## v1.0 evidence rules

- **Stored names, exact references.** `SessionPackage::contribute_named` returns the names files were stored under (same-day collisions get `_NN`). Storage correlation references exactly those benchmark / retest / NVMe health files; the automatic retest is named after its own initial run (`<initial>_retest`) and records `captured_at` + `retest_of`.
- **Current state per disk.** The manifest orders each disk's runs by the evidence's own timestamp (legacy files: file-name key, a retest directly after its base) and points `latest_evidence` / `current_sequence` at the final confirmed run (UNSTABLE → retest → ACCEPT ends on the retest). Earlier runs stay in `evidence` as history. `storage_correlation` disks add `current_benchmark_evidence` / `current_health_evidence`.
- **Crash evidence set.** `crash_dump_analysis.latest_evidence` = original `.dmp` copy + `CrashDump_Analysis` + `CrashDump_Summary` of the newest analyzed crash.
- **Two states.** `manifest.json` `state.system` (OK / ATTENTION_BSOD / ATTENTION_HANG / ATTENTION_UNEXPECTED_SHUTDOWN / ATTENTION_DRIVER_PROBLEM / NO_DATA) and `state.hardware` (OK / ATTENTION / CRITICAL / NO_DATA) are separate: hardware OK never means "computer healthy".
- **Dump-driven Driver Audit.** A probable third-party kernel module named by a dump is resolved read-only (lmvm metadata, driver file, version, Authenticode signer, service, devices, INF / provider; "removed" said explicitly) and always shown in Driver Audit (`EvidenceKind::BugcheckDump`, priority 2). Confidence still uses the base audit only, so a dump never corroborates itself.
- **Cross-module consistency.** An OK EXPC stage 04 / 07 is qualified when Driver Audit holds significant System-log evidence / the crash inventory holds BugChecks.
- **CHKDSK.** Execution and finding are separate: `finding_class` CLEAN / REPAIRED / PROBLEMS_FOUND / FAILED; an online repair is ATTENTION ("ИСПРАВЛЕНО / ВНИМАНИЕ"), never plain OK.
- **startup_graphics.log** keeps history; each launch starts with a `SESSION START` block (timestamp, producer version, computer, graphics mode).

## Version policy (v1.0)

Releases are `major.minor` (v1.0, v1.1 …; generations v2.0 …). Cargo keeps a full semver (`1.0.0`); `build.rs` derives the display version (`WSD_DISPLAY_VERSION` = "1.0") used by the title, the manifest `producer_version`, the EXE FileVersion / ProductVersion strings and the release folder `dist\WinStateDiag-v1.0`. `scripts\make_release.ps1` hashes every older release before and after and fails if one changed.

## UI rule (v0.4.5)

The dashboard is a summary: every block answers OK / Attention / Critical / Not checked. Evidence lives behind [Детали], and each Details opens only its own module. An EXPC row opens only that stage; the stage-table header opens the 14-stage summary. Details windows are egui immediate viewports: separate OS windows that are movable, resizable and may sit outside the main window.

## Icons and logo

- The EXE icon comes from `assets\icon.ico` through the Windows resource (`build.rs`, resource id 1).
- v1.0: every native window (main + Details viewports) gets that resource icon at the system small / large sizes through `WM_SETICON` (`src/win_icon.rs`), so the titlebar / taskbar / Alt+Tab use the purpose-made 16/24/32/48 px frames instead of a shrunken 256 px image. `ViewportBuilder::with_icon` (256 px frame) stays as the initial icon.
- WinStateDiag has no system-tray implementation. `assets\tray-icon.ico` (16/20/24/32/40 px, same artwork) is prepared and not wired.
- v1.0 header logo: the approved FULL logo `assets\new_logo_full.png` (Design + EXPC + head emblem + both slogans). That PNG has the transparency checkerboard baked into its pixels; `scripts\key_logo.py` keys out only the neutral checker (every opaque artwork pixel keeps its exact RGB), keeps the 3:1 aspect and writes `assets\expc-header-logo-full.rgba` (624×208 = 2× the 312×104 slot). Both page bodies are drawn `BODY_SHIFT` (32 px) lower so the logo is not shrunk.

## v1.0 Stable: normalized records

- **Storage.** Health of a physical disk = one normalized record: `nvme_health::health_source_status`, `nvme_health` (NVMe log) or `ata_smart`. `NVMe_Health_*.json`, `Storage_Correlation_*.json`, the manifest (prefers `health_status`), the SMART card and Details all read it. Correlation adds:
  - `evidence_scope` (what was checked);
  - `temperature` (value + provenance);
  - `session` (SessionId / start / end / status / producer_version);
  - `error_log_delta` against the latest COMPLETED session in `Reports\WinStateDiag_StorageHistory.json` (`src/storage_history.rs`).
- **Crash.** `src/crash_report.rs` builds one report (state, findings, incident table, probable cause by evidence priority, what to check, counters) used by the card counters, the Details window, Copy / Save and evidence. The debugger state machine is NOT INSTALLED / PACKAGE ONLY / INSTALLED.
- **Events.** `events::actionable` produces named actionable groups (SoftwareRecurring / Security / Historical) with an explicit `scope`. EXPC uses the same rules: provider identity, service grouping, recurrence ≥ 3.
- **Sensors.** Every value carries provider, hardware identity, logical type, unit, timestamp, confidence and `threshold_source`. Safe provider chain only (`docs\SENSOR_BACKEND_V2_RESEARCH.md`).
- **DISM.** Repair Intelligence verdicts, read-only (`docs\DISM_REPAIR_INTELLIGENCE.md`).
- **Header logo.** v1.0 uses `assets\logo_Header_right.png` (2030×775), keyed by `scripts\key_logo.py` into `expc-header-logo-full.rgba` (545×208, exact aspect), slot 272.41×104.

## Future

See `WINSTATEDIAG_PRO_AI.md` (AI analysis and WinRepair Pro handoff — design only).

