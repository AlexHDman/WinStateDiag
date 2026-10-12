# Changelog

## [1.0] - unreleased - v1.0 Stable candidate (master consolidation, evidence intelligence, live fixes)

### v1.0 Startup Idle / Client Identity microfix (2026-10-13)
- **Startup Idle:** a launch no longer starts the Driver Audit, the CryptoPro check, or the crash-inventory, sensor, passport and ATA SMART reads, and creates no report folder, session or ZIP. The initial state is IDLE / «Ожидание запуска». The cards show honest idle states: «Проверка драйверов не запускалась», CryptoPro «НЕ ПРОВЕРЕНО». Only the SSD/NVMe disk selector is filled at launch. It runs in the background with in-process device queries: no subprocess, no SMART, nothing written. The writability probe moved to the explicit benchmark start.
- The start-up log moved to `Reports\Logs\startup_graphics.log`. Each session copies a snapshot of it into its own report.
- **Client Identity:** «Запустить диагностику» freezes Client / Computer and opens a new session with a unique SessionId (`WSD-<stamp>-<pid>-<NN>`). All evidence, the manifest and the ZIP of that session use the frozen identity. The manifest gains an additive `session { session_id, client_name }`. Each session gets its own folder and ZIP: `<Client> - <Computer> - <date>`, or `… (2)` when that folder holds another session. The folder is reserved atomically on first use with a hidden `.wsd-session` marker; the marker is not in the ZIP. A different client, or a name that sanitizes to the same text, never shares a report: the old adoption and renaming of same-PC/date folders is gone. An empty Client reports under the Computer only. Storage history / correlation use the same SessionId.
- **Explicit modules** (sensors, Hardware with passport + ATA SMART, crash analyzer (scans first), SSD benchmark, GPO, Driver Audit «Запустить проверку») start only themselves. They join the current session while Client / Computer are unchanged and open a new one when they changed. During a running diagnostic they join that session. A module still running when another session opens reports into the session it was started in. This includes a storage run's pending health / correlation / history record and the crash analysis that follows a scan. A new session for a different identity clears the previous finished result view, so Open report never shows another client's ZIP.
- Regression tests cover:
  - startup starts no collector or subprocess (runtime + source contract) and creates no Reports / session / ZIP;
  - page switching starts nothing;
  - identity in manifest + evidence; a re-run with another client; empty client; cancel; separate modules; RU / EN;
  - the independent-review findings: module ownership across sessions, analyze-after-scan channel, Open report after a new session, storage SessionId, per-session folders, name-collision isolation.

### v1.0 Stable consolidation (2026-10-10)
Every confirmed real-machine defect became a deterministic regression test (Linux harness 536 tests; Windows gate re-runs the full suite).

**Events / system**
- Event identity: `Microsoft-Windows-Hyper-V-Hypervisor` 41 ("hypervisor launch failed") is never Kernel-Power; unexpected shutdown = `Microsoft-Windows-Kernel-Power` 41 or `EventLog` 6008 only. Storage IDs count only from the storage provider family.
- System Event Log summary = actionable groups (hardware-critical / recurring software-service / historical), e.g. «Повторяющиеся ошибки ПО/служб: N групп (…); аппаратно-критических событий не обнаружено.» Raw counts are secondary.
- SCM 7009 / 7011 grouped by service (param2), the timeout is an attribute ("45000,30000"); CDPSvc-style recurring failures (≥ 3) become named actionable groups; orphan services marked.
- Application errors: «happd.exe — 1× сбой · Exception 0xc0000005 · модуль ntdll.dll».
- Counter scope (`scope` + `actionable_groups` in Event Evidence): time window, logs, provider/ID filters, grouping key.
- VSS: Volsnap 33 (quota eviction) and VSS 8224 (idle shutdown) are normal activity, not failures.
- Pending reboot: PendingFileRenameOperations alone (CBS = False, WU = False) → INFO «ожидается очистка/переименование файлов после обновления ПО».
- GPO / ADMX on a standalone PC: harmless local mismatches → INFO.
- Windows build vs Get-HotFix list → «System / Build and updates» INFO with build, last listed KB and why a mismatch is not an error.
- DISM Repair Intelligence (read-only): CLEAN / HISTORICAL_REPAIRED / HISTORICAL_ONLY / CURRENT_CORRUPTION / RECURRENT_CORRUPTION / UNKNOWN from the current ScanHealth + dism.log / CBS.log lines written before this run. Never runs RestoreHealth. See `docs\DISM_REPAIR_INTELLIGENCE.md`.

**Drivers / Code Integrity**
- No "unsigned driver" WARNING without identity: SIGCHK facts (Authenticode + catalog) per device; unconfirmed → «подпись не подтверждена текущим методом проверки» (Aladdin case); no identity → НЕДОСТАТОЧНО ДАННЫХ.
- Package identity from `Get-WindowsDriver` (PublishedName / OriginalName / Provider / Class); a PublishedName mapped to conflicting devices (oem16.inf: Kaspersky + Intel Graphics) → mapping conflict evidence, never a delete recommendation.
- Code Integrity findings not mapped to a PnP device stay as SOFTWARE / SECURITY findings (e.g. CI 3004 DefenderSessionHelper.exe); kernel-driver CI and user-mode CI separate.

**Storage**
- SATA benchmark impossible speed (≈ 2.5–3 GB/s on SATA): root causes = benchmark target path and disk identity could diverge (target now always re-derived from the selected physical disk; mismatch refuses to run) and no transport plausibility gate (host RAM-cache filters / misreported bus). Results above the transport ceiling (SATA 600 MB/s + 10 %) → «ЗАМЕР НЕДОСТОВЕРЕН / РЕЗУЛЬТАТ НЕ ПРИНЯТ», never stored as performance; `SSD_Benchmark_*_INVALID.json` keeps the evidence.
- ATA SMART is the health source of truth for SATA: normalized `health_source` / `health_status` in NVMe_Health and Storage Correlation; manifest prefers `health_status`; correlation classifies ATA thresholds / sector counters (no more UNSUPPORTED / "health unavailable" with SMART present).
- Wear = 0 from the Storage Reliability counter → «нет надёжных данных» (null), not "0 % worn".
- NVMe error-log delta between COMPLETED sessions per disk (`Reports\WinStateDiag_StorageHistory.json`): FIRST_COMPLETED / STABLE / DELTA / COUNTER_RESET / UNKNOWN; cancelled sessions never anchor.
- Correlation evidence scope, temperature provenance (NVMe composite / ATA 194 / reliability counter) and session identity (SessionId, start, end, status, producer_version).

**Crash / WinDbg**
- Crash analyzer redesign: СОСТОЯНИЕ → ЧТО ОБНАРУЖЕНО → ИНЦИДЕНТЫ (table) → ВЕРОЯТНАЯ ПРИЧИНА (evidence priority, hardware only as a hypothesis) → ЧТО ПРОВЕРИТЬ, then detailed dump analysis with raw WinDbg output collapsed. Copy / Save export uses the same sections.
- LiveKernelReports grouped and explained (WATCHDOG = recovered TDR, USB, NDIS, power watchdog) — never a BSOD.
- One counter source (`crash_report::Counters`) for card, Details, export and evidence.
- WinDbg state machine: NOT INSTALLED / PACKAGE ONLY (no cdb backend) / INSTALLED; the final install state is decided by independent re-detection (Get-AppxPackage Microsoft.WinDbg + backend path), never by the winget exit text ("No newer package" = installed). 4–6 line install mini-journal; full winget output collapsed.
- Client 0x139 / RvNetMP60 regression fixture (synthetic, sanitized).

**UI**
- Right header logo from `assets\logo_Header_right.png` (exact 2030:775 proportions, keyed checkerboard, no crop / recolour).
- Passport adds «BIOS  <SMBIOSBIOSVersion> (date)» after Плата; LPDDR shown as «… · распаянная, SMBIOS: N устр.», never N×module.
- The idle «Диагностика не выполнялась» block is removed; ЖУРНАЛ is larger and carries [Отчёт] [Папка].
- Sensor READ indicator: cyan spinner with READ and the real elapsed timer (00:01 …), ERROR state; Refresh disabled while reading.
- SMART / NVMe block lists physical disks individually (#1 / #2 for identical models), never a bus category row.
- Sensor Backend V2: research (`docs\SENSOR_BACKEND_V2_RESEARCH.md`, `research\sensor_backend_v2\*`), every sensor value carries `threshold_source`; safe chain unchanged (no WinRing0, no driver installs).


First release under the v1.0 version policy (`major.minor`; next v1.1 …, generations v2.0 …). Local release candidate `dist\WinStateDiag-v1.0` for user visual / live approval. No tag, no push, no GitHub release. Older `dist` releases are untouched (hashed before / after by the release script).

### Visual master
- Full approved EXPC header logo (Design + EXPC + head emblem + both slogans) from `assets\new_logo_full.png`: the baked-in checkerboard is keyed out without touching artwork pixels (`scripts\key_logo.py`), 3:1 aspect kept (312×104 slot, 2× asset). Both page bodies moved down 32 px instead of shrinking the logo.
- Header: title left, Start centred, compact text-width page tabs (bright violet active with soft glow, near-background inactive), RU / EN stacked, logo right.
- Crisp application icon on every window (titlebar, taskbar, Alt+Tab, Details viewports) from the EXE's multi-size icon resource (`WM_SETICON`).
- Diagnostics: compact КОМПЬЮТЕР passport (Windows / CPU / RAM / board), very small separate GROUP POLICY / ADMX card, compact report row (no large Result card on either page), journal, 14-stage table.
- EXPC active-diagnostics focus: 1 px violet frame, calm breathing outer glow and a violet current row — only while a stage really runs.
- Hardware: sensor card rebuilt as the 4-column matrix «Наименование | T°C | Volt | Watt» with every expected row (CPU, motherboard, PCH, RAM, GPU, GPU hotspot, every disk incl. SATA HDDs, +12V / +5V / +3.3V); «Нет данных» for missing values (0 W counters too), «—» where meaningless; thin-framed «Эталон» table (ATX bands, drive-reported NVMe thresholds, «динамический», «без фикс. эталона»); only numbers are coloured. SMART / Health card lists the selected NVMe disk's key facts and every SATA disk.
- BSOD card: large indeterminate ring with «АНАЛИЗ» + elapsed time and the real stages (Подготовка dump → Загрузка symbols → Запуск !analyze -v → Разбор stack → Корреляция с Driver Audit → Формирование отчёта), «Загрузка символов Microsoft...» while the symbol cache grows, green / yellow / red outcome. No fake percentage.
- Embedded WinDbg installer: after the explicit click the official `winget install --id Microsoft.WinDbg` runs hidden (no console window), output captured into real stages (Подготовка / Загрузка пакета / Установка / Проверка cdb.exe; a percentage only when winget prints one), automatic re-detection, «АНАЛИЗАТОР УСТАНОВЛЕН» / «Не удалось установить анализатор» + Повторить / Детали with the local install journal. UAC is never hidden or bypassed.

### Details windows
- All Details (sensors, EXPC stage, EXPC summary, Driver Audit, Disk Benchmark, Crash Dump, Group Policy) are large resizable OS windows (defaults ≥ 900 px wide) with the standard action bar: Копировать / Сохранить как... (standard Windows Save dialog, current module only) / Открыть папку отчёта (where meaningful) / Закрыть.
- Disk Benchmark Details rebuilt: ДЕТАЛИ ЗАМЕРА — <model>; disk identity (physical disk, volume / system role, interface, capacity), Test 1 and Test 2 (read, write, spreads, duration, status), comparison (Δ read / Δ write, interpretation), SMART / NVMe health facts, final storage assessment, last 5 runs of this disk.
- Crash Details: BugCheck, dump, FAILURE_BUCKET_ID, MODULE / IMAGE / PROCESS_NAME, full STACK_TEXT, probable module, lmvm metadata, installed driver resolution, Driver Audit correlation, confidence, symbols, raw debugger output, freeze / hang incidents, install journal.
- Sensor Details: process context section; EXPC stage Details: stage-local event evidence, CHKDSK finding class, consistency note.

### Evidence intelligence
- Dump-driven Driver Audit: a probable third-party kernel module named by a dump (real case 0x139 / RvNetMP60.sys) is resolved read-only (lmvm, driver file, version, Authenticode signer, service, devices, INF / provider; "removed" said explicitly) and always appears in Driver Audit (BugcheckDump evidence, priority 2). Confidence still uses the base audit only.
- Event evidence (`Event_Evidence_*.json`, manifest `event_evidence`): Schannel, WindowsUpdateClient 20 (KB / HRESULT / title; historical vs current), TPM, SCM (+ current service state, start type, image path), SideBySide 33 (executable + missing assembly), Code Integrity user vs kernel mode, VSS / Volsnap categories (quota eviction vs operational failure), application errors — count, 7-day count, first / last seen, latest messages. Every summary counter is verifiable.
- Read-only ATA / SATA SMART (READ DATA / READ THRESHOLDS only): health, reallocated / pending / uncorrectable sectors, temperature, power-on hours, vendor wear; UNSUPPORTED for bridges / RAID / NVMe. Evidence `Ata_Smart_*.json`.
- High-CPU process context during sensor sampling (system CPU %, top 5 processes from 50 %).
- GPO / ADMX: the local PolicyDefinitions store is evaluated separately (also on standalone PCs: Central Store NOT APPLICABLE + local status).
- Cross-module consistency: an OK EXPC stage 04 / 07 is qualified when Driver Audit / the crash inventory holds significant evidence. System state adds hangs and unexpected shutdowns; hardware state adds SATA SMART. Manifest `state.system` / `state.hardware` are separate.
- startup_graphics.log: SESSION START block per launch (timestamp, producer version, computer, graphics mode).

### Fixed
- SSD final state: the manifest pointed at a stale UNSTABLE run after UNSTABLE → retest → STABLE; per-disk `latest_evidence` / `current_sequence` now follow the evidence timestamps.
- Storage correlation referenced the first run's benchmark / health files; it now references the exact stored files of its own run (the package returns stored names; the retest is named `<initial>_retest` and records `captured_at` / `retest_of`).
- CHKDSK online repair reported as OK → ATTENTION with `finding_class` REPAIRED («ИСПРАВЛЕНО / ВНИМАНИЕ»), RU / EN.
- Crash manifest `latest_evidence` = the complete evidence set (dump + analysis + summary).
- Mixed RAM capacities / speeds and configured-below-rated are INFO context, never a hardware WARNING.
- PowerShell collectors: UTF-8 output (Cyrillic was decoded lossily); `PSModulePath` cleared for the 5.1 child (from a PS7 session the Security module failed to load and signatures were empty).
- Manifest legacy ordering bug (date dots of a bare stem taken for an extension), found by the new tests.
- +3.3V reference band rounded half up: 3.14–3.47 V.

### Version / build
- Cargo `1.0.0`, displayed "1.0" everywhere (title, manifest `producer_version`, EXE FileVersion / ProductVersion strings, `dist\WinStateDiag-v1.0`). The `requireAdministrator` manifest stays on the shipped binary only; the binary has no test harness (`test = false`); `cargo test` runs unelevated.
- Headless validation hooks: `--smart-probe`, `--evidence-probe`, `--dump-probe`; QA scenes `--visual-reference --scene <name>`.

## [0.4.5] - unreleased - local live-test release candidate

Local release candidate (`dist\WinStateDiag-v0.4.5`) for user visual / live approval. No tag, no push, no GitHub release.

### Consolidation pass (sensors UX, per-stage details, crash/hang, branding)
- **Dashboard = summary, Details = evidence.** Every [Детали] opens the evidence of that module only.
- **Per-stage EXPC Details.** The row [Детали] opens ONLY that stage (status, duration, result, explanation, its EXPC records, its own sources, its own journal lines, Copy / Save / Close). The header [Детали] keeps the global 14-stage summary. Stage 07 adds the crash inventory and the freeze/hang incidents; stage 14 adds the Driver Audit counts.
- **Details windows are real OS windows** (egui immediate viewports): large, movable, resizable, allowed outside the main window. They apply to Sensors, the EXPC stage, the EXPC summary, Driver Audit, Crash and GPO. Where a backend cannot open another native window, the same content is embedded.
- **Diagnostics page:**
  - Client copy icon: "Клиент: X\nКомпьютер: Y", or only the computer line when no client is entered. EN uses Client / Computer. No state change.
  - Compact "КОМПЬЮТЕР" passport: Windows, CPU, RAM, motherboard (read-only CIM collector, no disks).
  - GPO / ADMX reduced to a thin row inside the passport (status + Проверить + Детали).
  - The large Result card is replaced by a compact report row (Открыть отчёт / Папка).
- **Hardware page:**
  - Driver Audit and Result are no longer duplicated here.
  - The sensor card ("ДАТЧИКИ  T°C / Volt / Watt") is a vertical table: ТЕМПЕРАТУРЫ / ПИТАНИЕ / МОЩНОСТЬ, names left, values in one aligned column.
  - A thin cyan reference column shows the ATX ±5 % band for +12V/+5V/+3.3V/5VSB, the drive-reported NVMe WCTEMP / CCTEMP ("W 83° / C 85°"), "динамический" for Vcore/VID/GPU core, and otherwise "без фикс. эталона". No universal temperature limit is invented.
  - Only the number is coloured (green normal, yellow near threshold, red critical, neutral without a reference). No dots or checkmarks.
  - "Состояние ПИТАНИЯ: Отлично / Внимание! / Критично! / Нет данных". Concerning wording: "Обнаружено отклонение линии питания. Рекомендуется подтверждение внешним тестером/мультиметром." There is never a PSU verdict.
  - Provider strings (PARTIAL · LHM…) moved to the sensor Details window, which gained a Reference column and Copy / Save / Close.
- **NVMe Identify Controller** (read-only IOCTL, CNS 01h) supplies the WCTEMP / CCTEMP thresholds. They are recorded in `NVMe_Health_*.json` (`temp_warning_c`, `temp_critical_c`).
- **Test 1 / Test 2 live UX:**
  - The active block pulses cyan with an mm:ss clock and live READ/WRITE MB/s; values are 1.5× larger.
  - A finished block is marked ГОТОВ with its final values and STABLE / ACCEPT / UNSTABLE; a pending block stays subdued.
  - The automatic retest is labelled "ПОВТОРНЫЙ ТЕСТ — подтверждение результата".
- **BSOD / shutdown consistency.** The crash card shows "Неожиданные выключения: N · BugCheck / BSOD: N · Дампы: N". The wordings are:
  - "Внимание — обнаружено неожиданное выключение. BSOD не подтверждён."
  - "BugCheck обнаружен, dump не найден."
  - "BSOD обнаружен · Dump найден · <analysis status>".
- **Freeze / hang incident intelligence** (`src/incidents.rs`, read-only):
  - Kernel-Power 41 + EventLog 6008 make one incident per boot.
  - It collects the last System event before that boot and the System/Application events of the 10 minutes before it: App Hang 1002, App Error 1000, WER 1001 / LiveKernelEvent, Display 4101 TDR, nvlddmkm/amdkmdag/igfx, StorPort/stornvme/disk/Ntfs, WHEA, SCM failures.
  - It also lists the `%SystemRoot%\LiveKernelReports` dumps (listing only).
  - Verdict: "HANG CONFIRMED / NOT CONFIRMED · BSOD REGISTERED / NOT REGISTERED · PROBABLE SUBSYSTEM GPU/STORAGE/DRIVER (HIGH/MEDIUM/LOW)" or "CAUSE NOT DETERMINED". Conflicting or absent signals never name a culprit.
  - Evidence `Incidents_<ts>.json`, manifest module `freeze_hang_incidents` (result_status, incident_count).
  - `win_state_diag.exe --incident-probe <out.json>` is a headless hook for live tests (also writes the passport summary).
- **Branding:**
  - The header wordmark + emblem is regenerated from the canonical new `assets\logo.png` ("Design" masked out, alpha-correct downscale, 368×92 for a 184×46 slot); the artwork itself is unchanged.
  - The window / taskbar / Alt+Tab icon is now set explicitly from the 256 px frame of the approved ruler/pencil `assets\icon.ico`. eframe had replaced it with egui's default icon.
  - The tray asset is unchanged (16/20/24/32/40, same family). There is still no tray runtime.
- **Hardware Report button:** while the module really runs, a thin gold light travels along its border.

### Added
- **Hardware sensors layer** (`src/sensors.rs`), read-only. It covers temperatures, ATX rails, dynamic voltages, CPU/GPU power and fans.
  - Each sensor carries: hardware identity, category, sensor type, raw name, current value, session min/max, unit, provider, confidence and timestamp.
  - Sampling is about 10 s at 1 sample/s with no load applied. Min/Max are labelled as WinStateDiag session values, not lifetime values.
- **Providers**, best first:
  - NVMe Health for disk temperatures (authoritative).
  - The official LibreHardwareMonitorLib, bundled. It runs in a short-lived helper, is extracted to a temp folder and removed afterwards.
  - HWiNFO shared memory, only when HWiNFO already runs with shared memory enabled.
  - Running LibreHardwareMonitor / OpenHardwareMonitor WMI.
  - `nvidia-smi` (query only).
  - Windows Storage Reliability.
  - `Win32_VoltageProbe`.
  - ACPI thermal zone.
- **Provider disagreements are kept:** both values are recorded and Details flag SENSOR SOURCE MISMATCH.
- **Provider and layer states:** AVAILABLE / PARTIAL / UNAVAILABLE / BLOCKED_BY_WINDOWS_SECURITY / PROVIDER_ERROR.
- **Hardware page "ДАТЧИКИ" card (compact):**
  - Temperatures: CPU (average of all cores), GPU, GPU hotspot, board, PCH, RAM, each disk.
  - ATX rails with "СОСТОЯНИЕ ПИТАНИЯ" (Отлично / Внимание! / Критично! / Нет данных).
  - CPU/GPU power and fans.
  - "Детали" window with TEMPERATURE / VOLTAGE / POWER / FANS tables (sensor, current, min, max, unit, source, confidence), providers and mismatches.
- **Source confidence** HIGH / MEDIUM / LOW / UNKNOWN. A LOW/UNKNOWN rail outside tolerance shows CHECK SENSOR / VERIFY EXTERNALLY, never red.
  - Dynamic rails (Vcore, VID, VCCSA, GPU core, PCIe/12VHPWR) are informational.
  - The wording never claims a faulty PSU.
- **Evidence and manifest:** `Hardware_Sensors_<ts>.json` and manifest module `hardware_sensors` (status, provider, sensor_count, evidence, latest_evidence).
- **`win_state_diag.exe --sensor-probe <out.json>`:** a headless validation hook with no GUI that writes the same JSON.

### Changed
- The v0.4.4 power-only WMI module (`Power_Sensors_*`, manifest `power_sensors`) is replaced by `hardware_sensors`.
- Build: the `requireAdministrator` manifest is linked into `WinStateDiag.exe` only (`rustc-link-arg-bin`), no longer into every artifact via winresource. The code moved to a library crate (`src/lib.rs`, thin `src/main.rs`, bin `test = false`), so `cargo test` harnesses run without elevation. The shipped EXE's manifest (UAC, DPI, supportedOS) is unchanged.

### Security
- Nothing is installed:
  - No kernel driver or service.
  - PawnIO is never installed, and HVCI / the vulnerable-driver blocklist are never touched.
  - WinRing0 is not used.
- Low-level CPU/board/RAM sensors through the internal provider need PawnIO already installed by the user. Otherwise that provider reports PARTIAL.

## [0.4.4] - unreleased - source candidate: two-page UI, crash dump analyzer

Source candidate only. The Windows build and the first live validation (client case) are still pending.

### Added
- **Two pages in one window**: ДИАГНОСТИКА / DIAGNOSTICS and ОБОРУДОВАНИЕ / HARDWARE tabs under a common header (WinStateDiag, Start Diagnostics, RU/EN, EXPC). The active tab has a violet glow and border; purple is used only for page navigation. Switching pages changes only what is drawn. Disk selection, benchmark, audit, crash and journal state are kept.
- **Diagnostics page**: Client, Computer, modes, CryptoPro, overall progress, Driver Audit, report result, compact journal (Open / Clear), and a 14-stage table (№, stage, execution, result, short finding, duration, Details). SSD, SMART, power, temperatures and crash details moved to the Hardware page.
- **Hardware page**: Hardware Report, a system-state card (hardware state and system state shown separately, e.g. "ATTENTION — BSOD detected"), Power, Driver Audit, report, SMART/NVMe, SSD benchmark with Test 1 / Test 2 blocks, and Crash Dump.
- **Crash Dump / BSOD analyzer** (`src/crash_dump.rs`, read-only):
  - BugCheck detection from WER 1001 and Kernel-Power 41 over 60 days.
  - Minidump / MEMORY.DMP discovery via CrashControl.
  - Debugger detection: INSTALLED / NOT INSTALLED / ERROR.
  - "Установить анализатор" starts the official `winget install --id Microsoft.WinDbg` in a visible window, only on an explicit click. The fallback is the official download page. The debugger is re-detected afterwards.
  - Headless `cdb -z <dump> -y <local cache + msdl> -c "!analyze -v; q"` with a timeout, for the 3 newest minidumps.
  - Evidence per dump: the original `.dmp` copy (the source is only read), `CrashDump_Analysis_<ts>.txt` and `CrashDump_Summary_<ts>.json`.
  - Confidence: HIGH / MEDIUM / LOW / CAUSE NOT DETERMINED. ntoskrnl/hal/generic modules alone are never blamed.
  - Driver Audit correlation by evidence priority: PnP → kernel/boot → Code Integrity → user-mode.
  - The memory-test follow-up is a recommendation only.
- **Power diagnostics** (`src/power.rs`, "СОСТОЯНИЕ ПИТАНИЯ"):
  - Rails +12V / +5V / +3.3V / 5VSB with nominal, current, deviation, session min/max and status (Отлично ≤3 %, Внимание! ≤5 %, Критично! >5 %).
  - Provider abstraction: LibreHardwareMonitor / OpenHardwareMonitor WMI, then Win32_VoltageProbe. Only explicitly labelled sensors are used.
  - Without data the state is SENSOR DATA NOT AVAILABLE. Source and confidence are shown.
  - The PSU is never called faulty. The conclusion is a deviation plus a recommendation for external verification.
- **Group Policy / ADMX health** (`src/gpo_admx.rs`, Diagnostics page, auxiliary module; the 14 stages are not renumbered):
  - Standalone / domain detection and a SYSVOL reachability probe with a timeout.
  - Local and Central Store inventory: ADMX/ADML, missing ADML, revisions, undefined `supportedOn` references.
  - States: OK / OUTDATED / MISMATCH / CENTRAL STORE NOT FOUND / NOT APPLICABLE / UNREACHABLE / INSUFFICIENT DATA.
  - The generation comparison uses the official Microsoft 26H2 reference (https://aka.ms/Windows11/26H2/GPsettings) only when the spreadsheet is placed in `Reference\` next to the EXE. It is never downloaded, and nothing is inferred from file names or timestamps.
  - Evidence `GroupPolicy_ADMX_Health_<ts>.json`.
  - Nothing is copied, repaired or changed (no gpupdate, no SYSVOL writes).
- `manifest.json` modules `crash_dump_analysis` (status, evidence, latest_evidence, dump_count, analyzed_count, analysis_status, confidence), `group_policy_admx_health` and `power_sensors`.

### Fixed
- Storage routing: `STORAGE_BUS_TYPE` 11 is SATA and 10 is SAS (previously "SATA/SD"). The NVMe protocol query is no longer sent to SATA disks.
  - SATA/ATA disks use the Windows Storage Reliability counters, or report SMART NOT AVAILABLE / INSUFFICIENT DATA.
  - USB/RAID/RST disks without a provider are UNSUPPORTED.
  - Values are never fabricated.
- EXPC VSS: ≥85 % shadow-storage use alone is INFO. ATTENTION needs Volsnap / VSS operational failures (recent, or older failures together with near-limit use).
- EXPC driver dates: a future date or negative age is DATE ANOMALY / INFO, with the negative age hidden. Age alone is AGE INFO, never REVIEW OLD or WARNING. A future BIOS date is DATE ANOMALY.

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
