# WinStateDiag — Diagnostic Feedback

This document holds engineering lessons from real diagnostic machines. Cases are anonymized and generalized: no client names, computer names or serial numbers.

Status: **v1.0.** Items marked *backlog* are not implemented; they record what future evidence or classification must do. The v1.0 section at the end closes several earlier backlog items.

## Permanent principles

1. **Event count alone does not determine severity.** Severity depends on:
   - event type and source;
   - context;
   - recency and repetition;
   - the current device state;
   - corroborating evidence;
   - confirmed system impact.
2. **Facts before verdicts.**
   - Raw values are stored exactly as the source reports them.
   - A value that could not be read is *unknown* (`null` / "n/a"), never 0.
3. **Physical disk identity, not drive letters.** Storage facts are correlated per physical disk (`storage_topology::physical_disk_identity`). C:, D:, E: are only volume mappings.
4. **Unstable benchmark ≠ SSD failure.** Performance variance alone is at most a benchmark anomaly (retest required / check), even after two unstable runs.
5. **Read-only.** WinStateDiag never repairs. Repair commands are shown as text only.

## Classification categories

| Category | Meaning |
|---|---|
| **A. REAL ISSUE** | A confirmed current problem on the machine. |
| **B. CHECK / ATTENTION** | An anomaly that needs correlation or a retest. |
| **C. HISTORICAL / NOISE** | Old or isolated evidence without current impact. |
| **D. WINSTATEDIAG ISSUE** | A tool-side problem: collection gap, classification error, contradictory summary, wrong terminology or unit, encoding issue, or another diagnostic-tool limitation. |
| **INSUFFICIENT DATA** (v1.0) | A technical state, not a category of fault: the evidence needed for a verdict could not be collected (SMART blocked by a bridge / RAID path, a store that is absent, a reference that is missing). It is never shown as OK and never as a failure. |

## Real-machine lessons (v0.4.2 – v0.4.3)

| Lesson | Category | Status |
|---|---|---|
| Native NVMe Health matches two independent tools | — | **Real Windows validated** |
| UNSTABLE benchmark with clean SMART/Health | B | Automatic retest + correlation implemented |
| Error Information Log Entries > 0 without media errors | C (fact) | Never a fault verdict |
| WUDFRd / Kernel-PnP 219 on a device that works now | C | HISTORICAL / INFO implemented |
| VRAM 32-bit truncation (8 GB card shown as 4 GB) | D | Fixed |
| iGPU shared memory shown as "VRAM ~28 GB" | D | Fixed |
| DDR speed in MHz instead of MT/s | D | Fixed |
| EXPC INFO steps without their own counter | D | Fixed (Info counter) |
| One global `latest_evidence` for several physical disks | D | Fixed (per-disk `latest_evidence`) |
| Error Log Entries = 4702 on a healthy NVMe drive (Patriot P300) | C (fact) | Never a fault verdict |
| NVIDIA device: user-mode crash shown instead of stronger kernel-driver evidence | D | Strongest linked evidence (v0.4.4); dump evidence priority 2 (v1.0) |
| System Event Log summary "OK" while a significant kernel event was already evidence | D | v1.0: cross-module consistency note |
| Repeated unattributed user-mode Code Integrity event hidden behind an overall OK | B / D | v1.0: Code Integrity aggregation (user vs kernel mode) |

### Native NVMe Health: real Windows validation

The reader's results were compared with **CrystalDiskInfo 9.9.1** and **Victoria 5.37**. Both tools are independent validation references only. They are not bundled, called, parsed or required, and the code was not tuned to match them.

| Field | Samsung SSD 9100 PRO 1TB | Netac NVMe SSD 1TB |
|---|---|---|
| Critical Warning | 0 | 0 |
| Composite temperature | ~45–46 °C | ~43–44 °C |
| Available Spare | 100 % | 100 % |
| Available Spare Threshold | 10 % | 1 % |
| Percentage Used | 4 % | 0 % |
| Health equivalent (100 − Percentage Used) | 96 % | 100 % |
| Power Cycles | 88 | 69 |
| Power On Hours | 7816 | 8016 |
| Unsafe Shutdowns | 68 | 28 |
| Media and Data Integrity Errors | 0 | 0 |
| Error Information Log Entries | 0 | **9** (confirmed independently by CrystalDiskInfo and Victoria) |

**Result:** WinStateDiag, CrystalDiskInfo and Victoria agreed on every field above for both drives.

Data Units Read/Written were also consistent once display units are accounted for:

- one NVMe data unit is 1000 × 512 bytes;
- WinStateDiag stores the raw 128-bit unit count plus exact bytes;
- the other tools show GB/TB in their own units.

Later checks extended the validation to more physical NVMe drives, again against CrystalDiskInfo and Victoria:

- Samsung 9100 PRO;
- Netac NVMe;
- NX-512 2280;
- Patriot P300.

**Status: NATIVE NVME HEALTH READER — REAL WINDOWS VALIDATED.**

### Lesson: Error Log Entries alone are not a failure (C, fact)

The Netac drive reported Error Information Log Entries = 9. At the same time:

- Critical Warning was 0;
- Media and Data Integrity Errors were 0;
- Percentage Used was 0;
- its SMART status was GOOD.

The error log often records aborted or invalid commands issued by host software. The 9 stays factual evidence, shown and stored. It is never a fault verdict, and it does not change the storage state.

A second real case confirms the rule at a much larger count. A Patriot P300 reported:

- Error Information Log Entries = **4702**;
- Critical Warning = 0;
- Media and Data Integrity Errors = 0;
- SMART/Health otherwise good.

The counter stays factual evidence. It is not sufficient for a STORAGE PROBLEM verdict, however large it is.

The same applies to:

- Unsafe Shutdowns > 0 (power history);
- Percentage Used below 100.

### Lesson: UNSTABLE benchmark + clean SMART/Health (B)

Real case: one run's WRITE spread exceeded the UNSTABLE threshold. At the same time:

- Critical Warning was 0;
- there were no media errors;
- there was no corroborating storage event.

A repeated run was back in range. The cause is benchmark variance (background I/O, thermal or cache state), not the disk.

Implemented in v0.4.2:

1. A first run that is UNSTABLE triggers a short idle (10 s) and then **one** automatic confirmation retest of the same physical disk.
2. Both runs are kept in the evidence (`SSD_Benchmark_*` and `SSD_Benchmark_*_retest`), in the history and in the Details window. The dashboard note shows the first run.
3. The final state depends on the retest:
   - The retest is STABLE/ACCEPT and health is clean: **anomaly not confirmed on retest**, not a failure.
   - Both runs are UNSTABLE and health/events are clean: **BENCHMARK ANOMALY — CHECK**, not a failure.
4. There is no retest (fail closed) when:
   - the user cancelled;
   - the run failed technically;
   - the disk or volume is no longer resolvable;
   - the health read did not arrive in time;
   - the controller reports Critical Warning bits 0–3 or media errors (more write testing would be inappropriate).

### Storage correlation rules (implemented, `src/storage_health.rs`)

#### States

| State | Shown as (EN) |
|---|---|
| OK | OK |
| Benchmark OK, no NVMe health | "No NVMe data" (unsupported, SATA, RAID/RST, USB bridge, access denied) |
| Anomaly not confirmed on retest | "Retest normal" |
| BENCHMARK ANOMALY / RETEST REQUIRED | Retest required |
| BENCHMARK ANOMALY / CHECK | Benchmark anomaly (not a failure) |
| STORAGE ATTENTION | Attention |
| STORAGE PROBLEM | Problem |

#### Rules

| Evidence | Effect |
|---|---|
| Critical Warning bits 0, 2, 3 (spare below threshold, reliability degraded, media read-only) | PROBLEM (each bit explained individually) |
| Critical Warning bits 1, 4, 5 (drive temperature threshold, volatile backup failed, PMR read-only) and reserved bits | ATTENTION |
| Media and Data Integrity Errors > 0 | ATTENTION; PROBLEM when corroborated by a recent Disk event on the same physical disk |
| Percentage Used ≥ 100 (the vendor endurance estimate is reached) | ATTENTION |
| Temperature | Raised only through the drive's own threshold (Critical Warning bit 1). No invented limits; a current reading is a fact. |
| Error Log Entries, Unsafe Shutdowns, Percentage Used < 100 | Facts only |
| Recent Disk 7 / 154 bound to `\Device\HarddiskN` of the same disk | ATTENTION |
| Recent Disk 11 / 51 / 153 on the same disk | Only corroborates other evidence. It turns a repeated benchmark anomaly into ATTENTION and corroborates media errors. |
| Older events, events for other disks, or events not bound to a disk (most StorNVMe/StorPort/Ntfs/volmgr) | Context only, whatever their count |

#### Events and evidence

- **Recency:** "recent" means the last occurrence was within 7 days of the assessment.
- **Collection:** events come from a read-only `Get-WinEvent` over the System log for 14 days, levels 1–3:
  - providers `disk`, `stornvme`, `storport`, `Microsoft-Windows-StorPort`, `Ntfs`, `Microsoft-Windows-Ntfs`, `volmgr`;
  - grouped by provider, ID and disk.
- **Failure handling:** a collection failure is "not collected", never "no events".
- **Evidence:** each assessment writes `Storage_Correlation_<date>_<time>_PD<n>.json`, containing:
  - the state and both runs;
  - the retest outcome;
  - the health status and the evidence file names;
  - every finding with its weight and an RU/EN explanation.

### Lesson: WUDFRd / Kernel-PnP 219 (C, implemented)

This was confirmed on several real machines: historical Kernel-PnP 219 events ("WUDFRd failed to load", for example ×3) for a device that exists now, with PnP ErrorCode 0 and working.

- **Now:** such events are **INFO / HISTORICAL**. They stay visible in the Driver Audit Details and evidence, but they do not raise the audit to WARNING, whatever their count.
- **WARNING / PROBLEM remains when:**
  - the current PnP state is bad (PROBLEM);
  - the current state is unknown (WARNING, fail closed);
  - other current evidence on the same device (a current driver/module load failure, Code Integrity, …) drives its own status.

### Lesson: GPU memory semantics (D, implemented)

- **32-bit truncation:** an 8 GB discrete card was shown as "4.00 GB" from the saturated 32-bit `AdapterRAM`. The 64-bit `HardwareInformation.qwMemorySize` is now used first, and a saturated value is never shown.
- **iGPU shared memory:** an Intel integrated GPU's driver reported ~28 GB. That is shared or system graphics memory, not dedicated VRAM.
  - The DirectX adapter record (`DedicatedVideoMemory`, `SharedSystemMemory`, matched by PCI VEN/DEV) now separates the two.
  - Without the record, an adapter on PCI bus 0 is "graphics memory reported by driver (dedicated VRAM not confirmed)".
  - Discrete cards keep the reliable 64-bit VRAM. No GPU-model hard-coding.

### Lesson: DDR terminology (D, implemented)

- SMBIOS speeds are data rates in **MT/s**, not MHz, and are marked "reported, not measured".
- JEDEC base, configured, XMP and profile data stay conceptually separate.
- Mixed DIMMs running at a conservative JEDEC rate are not automatically a fault when memory and WHEA evidence is clean. Interpretation is *backlog*.

### Lesson: EXPC Info counter (D, implemented)

INFO steps (for example step 14, BIOS / drivers / firmware) have their own "Info" counter. Every represented step is counted exactly once.

### Lesson: per-disk `latest_evidence` (D, implemented)

**Problem:** a real v0.4.2 report with two NVMe disks (PD3 and PD4), each with several runs, had a single global `latest_evidence`. That made it ambiguous which file was the current result for which disk.

**Fix:** `ssd_benchmark`, `nvme_health` and `storage_correlation` now list `disks`, with one entry per physical disk. Each entry has:

- `disk_key` (FNV-1a of the physical identity; no serial);
- `physical_disk_index`, `model` and `status`;
- that disk's `evidence` and `latest_evidence`.

Grouping uses the physical identity stored in the evidence, never a drive letter. All earlier runs stay in the cumulative daily package, and the schema stays 1.0.

## Real case, October 2026: a Windows server with an NVIDIA GT 1030

This case is generalized; client-identifying details are omitted. It produced three findings about how WinStateDiag presents evidence. None of them is implemented in v0.4.3; they are the next development backlog.

### Finding 1: NVIDIA evidence priority (D, backlog)

An NVIDIA GeForce GT 1030 was correctly classified as **PROBLEM**, but the evidence Driver Audit showed was incomplete and wrongly prioritized. The diagnostic package held two kinds of evidence for the same device stack:

| Layer | Evidence | Count in the diagnostic window |
|---|---|---|
| Kernel driver | `nvlddmkm`, System log, Event ID 14 | 17 |
| User-mode NVIDIA stack | `nvcontainer.exe`, fault module `nvapi64.dll`, exception `0xC0000005`, Application Error Event ID 1000 | 38 |

Driver Check mainly surfaced the user-mode crash. The stronger kernel-driver evidence was present elsewhere in the package but was not shown first.

### Approved future rule: strongest linked evidence

A device's diagnostic status should be based on the strongest **confirmed** evidence that can be reliably linked to that device.

Evidence priority, strongest first:

1. a current PnP / device error;
2. a kernel-driver failure or driver load failure;
3. Code Integrity evidence reliably linked to that device or driver;
4. a vendor user-mode component crash.

A user-mode crash must not replace or outrank direct kernel-driver evidence when both refer to the same device stack.

Desired presentation:

```text
[PROBLEM] NVIDIA GeForce GT 1030

Evidence:
• NVIDIA kernel-driver failure:
  nvlddmkm
  System / Event ID 14
  count: 17

• NVIDIA user-mode component failure:
  nvcontainer.exe → nvapi64.dll
  exception 0xC0000005
  Application / Event ID 1000
  count: 38
```

### Finding 2: cross-module consistency (D, backlog)

The same diagnostic package contained `nvlddmkm` Event ID 14 ×17. Yet the aggregated System Event Log result could still state "OK — no significant events detected". The package contradicted itself.

**Future rule:** once a significant event has been accepted as evidence for a device or system problem, no other WinStateDiag module may summarize the same evidence domain as clean without qualification. This needs a shared, consistent evidence-interpretation layer.

### Finding 3: repeated Code Integrity event (B / D, backlog)

The package contained Code Integrity Event 3033 for `cpsspap.dll`, about 136 times.

- Unattributed user-mode Code Integrity evidence must **not** be artificially attached to a present PnP device.
- Repeated CI evidence also must not disappear behind an overall OK.

Desired future representation: **ATTENTION / Code Integrity**, aggregated by:

- process;
- module;
- event ID;
- count;
- first seen and last seen.

Repetition makes the evidence worth surfacing, but count alone does not prove a hardware or driver failure. Severity still depends on:

- source and type;
- kernel vs user mode;
- current impact;
- signature and load state;
- device correlation;
- recency and context.

### WUDFRd 219 in this case: the approved rule stays

Older notes on this machine said a historical WUDFRd Event 219 could remain WARNING. That older behaviour is **not** restored. The approved rule from several real machines stays as implemented in v0.4.2 / v0.4.3:

- **INFO / HISTORICAL:** a historical Kernel-PnP 219 (WUDFRd) on a device that exists now, with PnP ErrorCode 0, works, and has no corroborating current failure.
- **The evidence stays visible** in Details.
- **WARNING / PROBLEM** requires current corroborating evidence.

## Rules kept for later phases

### Code Integrity (B/C, rule; full redesign is backlog)

- Repeated **user-mode** Code Integrity events (a DLL failing signature or policy checks) should be aggregated and surfaced as diagnostic context. Repetition alone does not establish a driver or hardware fault.
- Kernel-mode or system-driver CI events have a different significance from ordinary user-mode DLL events.
- Unattributed CI evidence is preserved as is.
- Full Event Intelligence is a later phase.

### Backlog (not implemented)

- **SCM 7000 / 7009 / 7031:** future evidence should include:
  - ServiceName and DisplayName;
  - Message or EventData;
  - timestamp and count;
  - the current state, StartType and ImagePath.
- **Windows Update Event 20:** package/KB, HRESULT, message, timestamp, count and recurrence, not only a counter.
- **SideBySide Event 33:** executable path, missing assembly and version, publisher or signature, and the owning application, where determinable.
- **Intel ME:** the MEI **driver** and the ME **firmware** are separate entities. Their versions must never be compared as if they were the same thing.
- **Unicode / mojibake:** Russian client and computer names must survive every step without mojibake: input → model → JSON → TXT → HTML → ZIP.
- **JEDEC / XMP / mixed-DIMM** interpretation (see DDR above).
- **SATA/HDD reliability:** `MSFT_StorageReliabilityCounter` fields are documented below. ATA SMART is not implemented.
- **Evidence Intelligence / cross-module consistency** (next development phase):
  - strongest-linked-evidence priority;
  - NVIDIA `nvlddmkm` kernel-driver correlation;
  - Code Integrity aggregation;
  - SCM, Windows Update and SideBySide enrichment;
  - one shared evidence interpretation across all modules.

## Native NVMe Health Reader: reference

### Windows API

- **Device:** `CreateFileW("\\.\PhysicalDriveN")`. It is opened with `GENERIC_READ` first, then with no data access. It is never opened with write access.
- **Call:** `DeviceIoControl(IOCTL_STORAGE_QUERY_PROPERTY)` with:
  - `StorageDeviceProtocolSpecificProperty` (50), with a fallback to `StorageAdapterProtocolSpecificProperty` (49);
  - `PropertyStandardQuery`;
  - `STORAGE_PROTOCOL_SPECIFIC_DATA` with `ProtocolTypeNvme` and `NVMeDataTypeLogPage`.
- **Log pages:**
  - 02h SMART / Health: 512 bytes.
  - 01h Error Information: 16 × 64 bytes first, then 1 entry, otherwise UNSUPPORTED.
- **Response check:** the reply is validated as `STORAGE_PROTOCOL_DATA_DESCRIPTOR`.
- **Read-only guarantee:** no Set Features, firmware, format, sanitize, self-test or pass-through command exists, and a unit test scans the source for them.
- **Counters:** the 128-bit counters are written to JSON as decimal strings, exact.

### Supported and unsupported scenarios

| Scenario | Result |
|---|---|
| NVMe on `stornvme` (Samsung 9100 PRO, Netac, NX-512 2280, Patriot P300) | OK, real-validated |
| Vendor NVMe driver | OK, or UNSUPPORTED |
| Intel RST / RAID / VMD | Usually UNSUPPORTED |
| USB NVMe bridge | UNSUPPORTED without pass-through |
| Not administrator | ACCESS_DENIED / UNSUPPORTED, never a crash |
| SATA / ATA | UNSUPPORTED without touching the device; ATA SMART is not implemented |
| Truncated or malformed reply | ERROR; no zero-filled record |

### SATA / HDD: `MSFT_StorageReliabilityCounter` (research)

- **Already read:** the Hardware Report reads `Temperature`, `Wear`, `PowerOnHours`, `ReadErrorsTotal` and `WriteErrorsTotal`.
- **Available fields:**
  - identity and age: `DeviceId`, `ManufactureDate`, `PowerOnHours`;
  - temperature and wear: `Temperature`, `TemperatureMax`, `Wear`;
  - cycle counts: `StartStopCycleCount(Max)`, `LoadUnloadCycleCount(Max)`;
  - error counts: `ReadErrorsTotal`, `ReadErrorsCorrected`, `ReadErrorsUncorrected`, `WriteErrorsTotal`, `WriteErrorsCorrected`, `WriteErrorsUncorrected`;
  - latency: `ReadLatencyMax`, `WriteLatencyMax`, `FlushLatencyMax`.
- **Caveats:**
  - Values are filled by the driver and are often empty behind USB and RAID. An empty value is unknown, not 0.
  - The class needs administrator rights.

## v0.4.4 lessons (source candidate; Windows / client live validation pending)

### SATA disk routed to the NVMe protocol (WinStateDiag issue, fixed)

- **Cause:** `STORAGE_BUS_TYPE` 11 was labelled "SATA/SD" and 10 "SATA". SAS and SATA were therefore confused, and a SATA disk could reach the NVMe log-page query.
- **Fix:** the full winioctl mapping (10 SAS, 11 SATA, 12 SD, … 17 NVMe) and an explicit route:
  - NVMe → native reader.
  - SATA/ATA → Storage Reliability counters, otherwise SMART NOT AVAILABLE / INSUFFICIENT DATA.
  - USB/RAID/RST → a provider if one exists, otherwise UNSUPPORTED.
- **Rule:** `ProtocolTypeNvme` is never sent to a SATA disk. Missing values stay missing.

### VSS shadow storage (classification)

- ≥85 % use of the shadow-storage limit alone is **INFO**. Windows deletes old shadows by design.
- **ATTENTION** needs Volsnap 25/33/35/36 or VSS 8193/12289 operational failures: recent ones (7 days), or older ones (30 days) combined with near-limit use.

### Driver dates (classification)

- A future date or negative age is **DATE ANOMALY / INFO** (often a placeholder date in the INF), and no negative age is shown.
- Age alone is **AGE INFO**. It is never REVIEW OLD or WARNING, because old inbox drivers are often the current ones.

### Crash dump analysis: confidence model

- **HIGH:** a third-party module from `!analyze -v`, with good symbols, corroborated by Driver Audit evidence for the same driver (PnP, kernel/boot/TDR or Code Integrity).
- **MEDIUM:** a third-party module without that corroboration, or with partial symbols.
- **LOW:** only a generic or OS module (ntoskrnl, hal, win32k…), failed symbols, or signs of memory corruption.
- **CAUSE NOT DETERMINED:** no usable module, or the analysis did not complete (timeout or error).
- ntoskrnl / hal alone are never named as the cause.
- **Correlation priority:** PnP → kernel / boot / TDR → Code Integrity → user-mode crash.
- **Memory:** a memory-test *recommendation*, never a conclusion. It is given for:
  - memory-corruption signs;
  - bugchecks 0x1A / 0x4E / 0x12B;
  - 0x139 without a third-party module;
  - any LOW result.
- **Read-only:**
  - The original dump is only read and copied into the report.
  - The debugger is installed only on an explicit click, via the official winget `Microsoft.WinDbg` package or the official download page.

### Group Policy / ADMX health: lesson

- **Real-world trigger:** after a Windows feature update (25H2 → 26H2), the Central Store's ADMX templates can lag behind the clients. GPMC then shows unknown or undefined settings, or ADML resource errors.
- **Detecting this is diagnostic, not a repair:**
  - WinStateDiag never copies ADMX/ADML, never touches SYSVOL, never runs gpupdate and never downloads templates.
  - A standalone computer is **NOT APPLICABLE**, not an error.
  - A domain member that cannot reach SYSVOL is **UNREACHABLE**, never "Central Store not found".
- **Version evidence:**
  - The template generation is never inferred from file names or timestamps.
  - OUTDATED / OK requires the official Microsoft reference for the same release, or explicit `supportedOn` definitions. Otherwise the result is **INSUFFICIENT DATA**.
  - 25H2 and 26H2 are handled separately.
  - Local vs Central Store differences are informational.
- **Official reference for 26H2:** https://aka.ms/Windows11/26H2/GPsettings ("Windows 11 and Windows Server 2019 Policy Settings — 26H2" spreadsheet, Microsoft Download Center id 108849).
  - WinStateDiag reads it only if an administrator places the `.xlsx` in `Reference\` next to the EXE.
  - The reference URL is written into every `GroupPolicy_ADMX_Health_*.json`.

## v0.4.5 lessons: low-level hardware sensors (source candidate)

### Real case: MSI PRO Z890-P WIFI, Core Ultra 7 270K Plus, RTX 5060

- **What AIDA64 showed** (validation reference only, never a dependency):
  - board 38 °C, CPU 54 °C, PCH 46 °C, GPU 36 °C, GPU hotspot 43 °C, DIMM 39 °C, Samsung 9100 46 °C, Netac 43 °C;
  - +3.3 V 3.320, +5 V 5.020, +12 V 12.024, Vcore 1.418, VID 1.105;
  - CPU package 58.44 W, IA cores 44.76 W, GPU 24.03 W, GPU 12VHPWR 17.58 W.
- **What v0.4.4 showed:** SENSOR DATA NOT AVAILABLE. Real sensors existed; WinStateDiag simply had no provider that could reach them.
- **Machine security state:** Memory Integrity (HVCI) on and the Microsoft vulnerable-driver blocklist on.

### Why the backend choice is constrained by Windows security

- **CPU MSR, Super I/O (board rails, fans) and SMBus (DIMM temperatures)** need ring-0 port/MSR access through a kernel driver.
- **WinRing0** (used by LibreHardwareMonitor up to 0.9.4 and by OpenHardwareMonitor) is flagged by Microsoft Defender as `VulnerableDriver:WinNT/Winring0` and is on the vulnerable-driver blocklist. It is rejected.
- **LibreHardwareMonitorLib 0.9.5+** uses the signed **PawnIO** driver instead.
  - PawnIO is installed separately by its own setup as a persistent kernel driver service.
  - WinStateDiag never installs it and never asks to.
  - When the user has installed PawnIO (for example for another monitoring tool), the internal provider uses it automatically.
- **Without PawnIO,** LibreHardwareMonitorLib still reads GPU (NVAPI/ADL/IGCL) and storage sensors. The provider then reports PARTIAL.
- **Never done for sensors:** disabling HVCI / Memory Integrity, disabling the blocklist, whitelisting a driver, installing a service, or using unofficial forks/binaries.

### Provider order and provenance

- **Provider order:** NVMe Health (disks), internal LibreHardwareMonitorLib, HWiNFO shared memory, LHM/OHM WMI, nvidia-smi, Windows Storage Reliability, Win32_VoltageProbe, ACPI thermal zone.
  - HWiNFO shared memory is used only if the user already runs HWiNFO with Shared Memory Support enabled.
  - LHM/OHM WMI is used only if such a monitor is already running.
- **Disagreement between providers** is never hidden. Both values are kept, the higher-priority provider is canonical, and Details show SENSOR SOURCE MISMATCH.
- **NVMe temperatures** from the native NVMe Health reader are canonical. No second, contradictory SSD temperature is shown.

### Classification rules (permanent)

- **CPU temperature on the dashboard** = average of all cores. Per-core values stay in the raw JSON only.
- **ATX rails:** only the motherboard's +12 V / +5 V / +3.3 V / 5VSB are rated against a nominal (≤3 % Отлично, ≤5 % Внимание!, else Критично!).
  - Dynamic rails (Vcore, VID, VCCSA, VCCIO, VDD2, GPU core, PCIe/12VHPWR inputs) are informational and never rated.
- **Confidence:**
  - HIGH: board-specific mapping (named rail of a Super I/O chip from LHM/HWiNFO).
  - MEDIUM: recognised chip with generic scaling, or a running LHM/OHM monitor with a board mapping.
  - LOW: a generic WMI probe or ACPI thermal zone.
  - A LOW/UNKNOWN rail outside tolerance becomes CHECK SENSOR / VERIFY EXTERNALLY, never red.
- **Wording:** "Обнаружено отклонение линии питания. Показание датчика требует подтверждения внешним измерением." WinStateDiag never states that a PSU is faulty.
  - Future correlation (rail deviation + Kernel-Power 41 + unexpected shutdown + BugCheck) may say "possible power instability", nothing stronger.
- **Fans:** 0 RPM is a legal reading (zero-RPM modes). It is not a failure on its own.
- **Min/Max:** WinStateDiag session sample values (about 10 s at 1 sample/s, no load applied), not lifetime hardware values.
- **No invented values:** 0 °C channels and null values are dropped, never shown.

## v0.4.5 consolidation lessons (local release candidate)

- **Dashboard vs Details.** The dashboard only answers OK / Attention / Critical / Not checked. Raw evidence and provider/debug strings ("PARTIAL · LHM…") belong behind [Детали].
- **Details are local.** An EXPC row's [Детали] shows that stage only: its EXPC records, its own sources (07: crash inventory + incidents; 14: Driver Audit) and its own journal lines. The header [Детали] stays the 14-stage summary. Regression tests cover the click target and the content.
- **Details windows are OS windows** (immediate viewports). Users need them larger than, and outside of, the main window.
- **Sensor references.**
  - Only defensible references are shown: the ATX ±5 % band, the drive-reported NVMe WCTEMP / CCTEMP, "динамический" for dynamic rails, otherwise "без фикс. эталона".
  - No universal temperature thresholds; no CPU/GPU limit unless reliably known (none in this pass).
  - Only the number is coloured; a missing reference stays neutral.
- **Autonomous sensor coverage is PARTIAL** on the MSI test PC (no PawnIO, no ring-0 provider). HWiNFO shared memory is an optional enhancement, never a requirement. Severity never changes because a provider is absent.
- **Unexpected shutdown ≠ BSOD.**
  - The crash card counts unexpected shutdowns, BugChecks and dumps separately.
  - A Kernel-Power 41 without a BugCheck says "BSOD не подтверждён".
  - A freeze is "HANG CONFIRMED" only with direct evidence (App Hang, TDR / LiveKernelEvent, WATCHDOG live report). Otherwise it is "HANG NOT CONFIRMED", because it could be a reset or power loss.
  - The probable subsystem needs signals; ties and absence give "CAUSE NOT DETERMINED". KP41/6008 carry the boot time, so the timeline is anchored at the last System event before that boot.
- **Branding.** `assets\logo.png` and `assets\expc-symbol.png` are canonical and never regenerated; only derived assets (header RGBA) are rebuilt from them. The window icon must be set in code because eframe installs egui's default icon otherwise.
- **Client/Computer copy** never changes diagnostic state.

## v1.0 lessons (local release candidate)

Cases are anonymised: MSI test PC, a home PC with a 0x139 BSOD, several NVMe drives (Samsung 9100 PRO, Netac, Patriot P300, NX-512), two Windows servers and two office PCs.

| Lesson | Category | v1.0 |
|---|---|---|
| 0x139 KERNEL_SECURITY_CHECK_FAILURE dump names a VPN miniport (`RvNetMP60.sys`, process `RvControlSvc`) while Driver Audit says "0 problems / 0 warnings" — the module was outside the audited device set | D | **Fixed.** Dump-driven extension: lmvm + read-only driver resolution; the culprit is always a Driver Audit item (BugcheckDump, priority 2); confidence still from the base audit. |
| SSD sequence ACCEPT → UNSTABLE (`_02`, same minute) → retest ACCEPT; manifest kept the stale UNSTABLE as `latest_evidence`; the second correlation referenced the FIRST run's benchmark and health files | D | **Fixed.** Stored names returned by the package; retest named after its own run; manifest picks the current run by the evidence timestamp and lists `current_sequence`; correlation references the exact runs. |
| CHKDSK "Windows обнаружила проблемы, которые были исправлены в оперативном режиме" reported as OK | D | **Fixed.** `finding_class` REPAIRED → ATTENTION ("ИСПРАВЛЕНО / ВНИМАНИЕ"); execution and finding are separate; RU/EN tests. |
| Collector text with Cyrillic decoded from the OEM code page (event messages, update titles, service names) | D | **Fixed.** UTF-8 output for every collector. |
| Launched from a PowerShell 7 session, the 5.1 collectors inherited PS7's `PSModulePath` and silently lost `Get-AuthenticodeSignature` (empty signature) | D | **Fixed.** `PSModulePath` cleared for the child; regression test. |
| Sensor pass at 88–96 % CPU load claimed "no stress" without saying where the load came from | D | **Fixed.** Process snapshot during sampling (system CPU %, top 5 processes when ≥ 50 %); context, never a fault. |
| Mixed DIMM capacities raised a hardware WARNING on a machine with clean WHEA and memory tests | D | **Fixed.** Mixed capacities / speeds and configured-below-rated are INFO context. |
| "System events: OK" next to Driver Audit evidence from the System log | D | **Fixed.** Cross-module consistency qualifies the OK stage. |
| Summary counters ("11 VSS events in 7 days / 28 in 8–30 days") not verifiable in the ZIP | D | **Fixed.** `Event_Evidence_*.json`: count, 7-day count, first / last, latest messages, parsed fields; shown stage-locally. |
| SideBySide 33 from a browser self-updater: one event per temp folder (`sdwra_<pid>_<n>`) | C | Aggregated by executable + assembly (66 events → one line); full paths kept in the messages; no owner invented. |
| Repeated user-mode Code Integrity (hundreds of events) | B / C | Aggregated (process + module); kernel-mode CI stays separate and stronger; count alone is not severity. |
| Windows Update Event 20 (store app packages, 0x80073d02) repeated | C | Historical when a later install (19) succeeded; KB / HRESULT / title kept. |
| SATA HDDs had no SMART at all (Storage Reliability only) | D | **Fixed where the path allows.** Read-only ATA SMART (READ DATA / THRESHOLDS); MSI: 3 SATA HDDs OK, NVMe honestly UNSUPPORTED on this path. |
| Approved full EXPC logo delivered with a baked-in checkerboard | D (asset) | Keyed without touching artwork pixels (`scripts/key_logo.py`); body shifted, logo not shrunk. |
| Titlebar icon tiny / blurry (256 px frame shrunk by Windows) | D | Resource icon at system sizes via `WM_SETICON`. |

Permanent principle (unchanged): **EVENT COUNT ALONE DOES NOT DETERMINE SEVERITY.**

## Process

After the user approves an implementation, the steps are:

1. code;
2. tests;
3. CHANGELOG;
4. this document;
5. KNOWN_BUGS, where appropriate;
6. commit;
7. push.

The README describes only public functionality that already works.


## v1.0 Stable consolidation — real-case feedback closed (2026-10-10)

Sanitized real cases (machines anonymised), each now a regression test:

| Case | Wrong before | Now |
|---|---|---|
| Server with Hyper-V unavailable | Hypervisor 41 → 6 "unexpected shutdowns" | Hypervisor INFO; Kernel-Power only by provider |
| Workstation services | 7009 grouped by 30000 / 45000; CDPSvc ×6 hidden | grouped by service; CDPSvc actionable |
| Office PC | "1 application error" | «happd.exe — 1× сбой · Exception 0x…» |
| Office PC | VSS faulty (Volsnap 33 / 8224) | normal activity |
| Office PC | Pending reboot from software cleanup | INFO cleanup |
| Several | empty unsigned-driver WARNING; Aladdin "no valid signature" | identity required; "not confirmed by current method" |
| Workstation | oem16.inf = Kaspersky + Intel Graphics | mapping conflict, no delete advice |
| Workstation | CI 3004 DefenderSessionHelper missing | software / security finding |
| SATA SSD | 2.5–3 GB/s benchmark | BENCHMARK INVALID |
| SATA disks | SMART present but UNSUPPORTED in manifest / correlation | ATA health source of truth |
| Patriot NVMe | absolute 4710 error-log entries alarming | delta between completed sessions |
| Notebook LPDDR5 | 8 SMBIOS devices read as 8 modules | «распаянная, SMBIOS: 8 устр.» |
| MSI | WinDbg installed shown as not installed | re-detection, package / backend states |
