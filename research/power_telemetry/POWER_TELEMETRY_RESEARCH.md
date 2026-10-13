# Power Telemetry Research (v1.0, research only)

Status: **research complete for the MSI reference machine; nothing is in
production.** The Power Backend below is a proposal for approval. The
production sensor backend (`src/sensors.rs`, bundled LHM helper) is
unchanged.

Companion files:

- `probe/Power-Telemetry-Probe.ps1` — the separate read-only probe.
- `logs/` — raw probe output (git-ignored: it names the machine).
- Earlier sensor research: `docs/SENSOR_BACKEND_V2_RESEARCH.md`,
  `research/sensor_backend_v2/`.

## 1. Rules (unchanged)

These are never done:

- no WinRing0;
- no disabling of Memory Integrity (HVCI) or of the Vulnerable Driver Blocklist;
- no EC, Super-I/O or SMBus writes;
- no automatic installation of a driver, HWiNFO, AIDA64 or PawnIO.

A missing value stays **NO DATA**. It is never 0 and never estimated.

**CPU package power and GPU board power are not PSU power.**

- They are component measurements, not the power a power supply delivers.
- They are never labelled as PSU power, wall power or "system power".
- They are never summed into such a value.

## 2. Probe (step 4)

`Power-Telemetry-Probe.ps1` is separate from the product: it is not
embedded and not linked into `WinStateDiag.exe`.

**What it reads:**

- Windows performance counters through CIM:
  - Processor Information;
  - GPU Engine;
  - Thermal Zone Information;
  - Energy Meter / Power Meter.
- `MSAcpi_ThermalZoneTemperature`.
- The CIM probe classes (`Win32_Fan`, `Win32_VoltageProbe`, `Win32_TemperatureProbe`, `Win32_CurrentProbe`).
- SMBIOS processor data.
- `nvidia-smi --query-gpu` (query only).

**What it only detects:**

- HWiNFO and AIDA64 shared memory, read-only and only if the user already runs them;
- LHM / OHM WMI;
- PawnIO;
- Intel PMT;
- AMD Ryzen Master SDK;
- OEM WMI classes;
- OEM monitoring software.

It also lists third-party ring-0 I/O drivers that are already loaded, as a security observation.

Each value row carries:

- `parameter`;
- `sensor_identity`;
- `value`;
- `unit`;
- `source`;
- `timestamp`;
- `confidence`;
- `note`.

## 3. Live result — MSI reference machine (2026-10-13)

Machine and conditions:

- MSI PRO Z890-P WIFI (MS-7E34), desktop;
- Intel Core Ultra 7 270K Plus;
- NVIDIA RTX 5060 + Intel iGPU;
- Windows 11 Pro 26300;
- HVCI on, Vulnerable Driver Blocklist on;
- probe ran elevated;
- PawnIO absent; HWiNFO, AIDA64, LHM and OHM not running.

| Parameter | Result | Source | Confidence | Value seen |
|---|---|---|---|---|
| CPU Package Power (W) | **PASS** | Windows Energy Meter (EMI) `RAPL_Package0_PKG` | HIGH | 28–36 W idle, 61–100 W under a 4-thread load, back to 39 W after |
| CPU cores power (PP0), iGPU (PP1) | PASS (extra) | EMI `RAPL_Package0_PP0` / `_PP1` | HIGH | 19–21 W / 0.02–0.08 W |
| CPU Package Temperature | **NO DATA** | — | — | ACPI `\_TZ.TZ00` = 27.9 °C is a firmware zone, not the package (LOW, not counted) |
| CPU Vcore / VID | **NO DATA** | — | — | `Win32_Processor.CurrentVoltage` = 1.2 V is a static SMBIOS value (LOW, not counted) |
| Motherboard +12V / +5V / +3.3V | **NO DATA** | — | — | `Win32_VoltageProbe`: no instances |
| CPU / SYS fan RPM | **NO DATA** | — | — | `Win32_Fan`: no instances. An Intel IPF Fan Participant exists, but no user-mode read API is used |
| CPU Load (%) | **PASS** | PDH `Processor Information(_Total)\% Processor Utility` | HIGH | 3–34 % |
| GPU Load (%) | **PASS** | NVML (`nvidia-smi`) HIGH; PDH GPU Engine per LUID MEDIUM | HIGH | 5 % |
| GPU Power (W) | **PASS** | NVML board power draw | HIGH | 11.8–11.9 W (limit 155 W) |
| GPU temperature / fan | PASS (extra) | NVML | HIGH | 32 °C / 0 % (zero-RPM) |
| DIMM temperature / DRAM power | **NO DATA** | EMI `RAPL_Package0_DRAM` = 0 → NO DATA | — | DRAM RAPL is not supported on this platform |
| PCH temperature | **NO DATA** | — | — | |

Summary:

- **PASS 5 / 9** requested parameters: CPU Package Power, CPU Load, GPU Load, GPU Power, plus GPU temperature as an extra.
- **NO DATA 5**: CPU Package Temperature, Vcore/VID, ATX rails, fans, DIMM/PCH.
- **PARTIAL: none.**

Validation level of CPU Package Power: **plausibility only.**

- The value tracked a controlled load (idle → load → idle).
- A reference comparison with HWiNFO / AIDA64 was **NOT RUN**: neither tool was running, and the probe never starts or installs them.

## 4. Providers evaluated

| Provider | What it gives | How | Security | Licensing / dependency | Verdict |
|---|---|---|---|---|---|
| **Windows Energy Meter Interface (EMI)** — PDH "Energy Meter" / `IOCTL_EMI_*` | CPU package / cores / iGPU / DRAM / PSys power, when the platform publishes an EMI device. On this Intel desktop the publisher is the Intel IPF / DTT driver (RAPL) | user-mode read of a Windows counter set (CIM `Win32_PerfFormattedData_PowerMeterCounter_EnergyMeter`, or PDH, or the EMI IOCTLs) | no driver of ours; the platform driver is Microsoft-signed and delivered by OEM / Windows Update | part of Windows | **USE** (new: the safe native source of CPU package power) |
| PDH Processor Information / GPU Engine | CPU load, per-adapter GPU engine load | read-only counters | none | Windows | **USE** |
| ACPI thermal zones (PDH Thermal Zone, `MSAcpi_ThermalZoneTemperature`) | firmware zones | read-only | none | Windows | **LOW only.** Never a CPU package temperature |
| CIM probe classes (`Win32_Fan`, `Win32_VoltageProbe`, …) | SMBIOS descriptors | read-only | none | Windows | **LOW only**; empty on this desktop |
| Intel PMT (Platform Monitoring Technology) | SoC telemetry (temperatures, power, residencies) | Windows driver present (Intel PMT Driver, PMT IPF Extension Provider); no documented public user-mode API for third-party apps on Windows | Intel-signed driver, already installed | Intel SDK / IPF licence terms to be reviewed | **RESEARCH / DETECT ONLY** |
| Intel IPF (Innovation Platform Framework, successor of DTT) | processor, fan and generic participants; the EMI RAPL above | through EMI (above); the direct IPF client API is not used | Intel-signed, installed | IPF SDK licence not reviewed | **INDIRECT** (via EMI) |
| AMD Ryzen Master Monitoring SDK | Ryzen CPU temperature, power, voltages | needs Ryzen Master installed with its AMD driver; AMD CPUs only | ring-0 AMD driver of a separate product; past CVEs in that driver family | AMD SDK EULA (redistribution limits), not reviewed | **OPTIONAL, NOT NOW.** Detect only; no AMD machine for a live pass |
| LibreHardwareMonitorLib 0.9.6 (bundled) | GPU and storage; CPU, board, rails and fans only through ring-0 (PawnIO since 0.9.5) | in-process helper (existing production path) | no WinRing0; ships PawnIO modules but no `.sys` | MPL-2.0, pinned, hash-verified (`scripts/release/lhm_bundle.sha256`) | **UNCHANGED** (production) |
| HWiNFO Shared Memory | widest coverage: CPU, board rails, fans, DIMM | read-only map, only when the user runs it with SM on | HWiNFO uses its own signed driver | free version: SM time-limited (12 h); reading is allowed | **OPTIONAL, read only if already running** |
| AIDA64 shared memory | wide coverage | read-only map | own driver | commercial, per-seat | **REFERENCE ONLY** |
| NVIDIA NVML (`nvidia-smi` / driver `nvml.dll`) | GPU power, temperature, load, fan % | read-only queries | driver-installed, NVIDIA-signed | NVML ships with the driver | **USE** |
| AMD ADLX / Intel IGCL | AMD / Intel GPU telemetry | read-only query APIs of the installed driver | driver DLLs | ADLX and IGCL SDK headers are open-source (MIT) per the vendors; not re-verified | **CANDIDATE** (no AMD / Intel-dGPU machine here) |
| OEM WMI (MSI) | on this MSI: BIOS settings classes only (`MSI_BiosSetting`, `MSI_BootOption`, …), no sensors | — | these classes can CHANGE BIOS settings, so they are never called | — | **NO TELEMETRY.** Never used |
| OEM WMI (Dell / HP / Lenovo) | board temperatures and fans on some models | read-only CIM | vendor-signed | — | **FUTURE**, per-vendor, when present (no machine here) |
| PawnIO | ring-0 port / MSR / PCI I/O through scripted modules | signed kernel driver | see §5 | licence per the project, not reviewed; not bundled | **DETECT ONLY** |
| WinRing0 / inpout / "tiny bundled driver" | everything | — | known vulnerable or blocked | — | **NEVER** |

## 5. Security / licensing / dependency audit

1. **New dependencies: none.** The EMI path is a Windows counter set. The probe is plain PowerShell. `nvidia-smi` is part of the NVIDIA driver.
2. **PawnIO (security research only).**
   - It is a signed generic ring-0 interpreter: whoever can open it (administrators) can perform port, MSR and PCI-config I/O through modules.
   - From a defender's point of view it is a privileged I/O primitive. It is safer than WinRing0 (signed, HVCI-compatible, admin-only access per the project), but it widens what admin-level malware can do.
   - We have not audited it. It is never installed or bundled; it is only detected.
3. **Third-party ring-0 drivers already loaded on the MSI** (observation only; nothing was changed):

   | Driver | Signer | Note |
   |---|---|---|
   | `MsIo64.sys` | Microsoft Windows Hardware Compatibility Publisher | MSI I/O driver |
   | `NTIOLib_X64.sys` (two services, MSI Center / Mystic Light) | MICRO-STAR INTERNATIONAL CO., LTD. | MSI I/O library driver |

   Public CVE records exist for these driver families:
   - `MsIo64.sys`: CVE-2021-27965;
   - `NTIOLib_X64.sys`: CVE-2021-44899 / -44900 / -44901 / -44903 and CVE-2026-6102.

   **Whether the installed hashes are the fixed versions was NOT verified.**
   - Recording this is a finding for the user's attention, not a WinStateDiag action.
   - WinStateDiag never uses these drivers.
4. **HVCI and the Vulnerable Driver Blocklist** were on during the probe. No setting was read-modify-written.
5. **Licensing.**
   - HWiNFO: free version SM limit.
   - AIDA64: commercial.
   - AMD Ryzen Master SDK: EULA.
   - Intel IPF / PMT SDK terms: still need a licence review before any direct use.
   - EMI, PDH and NVML through the driver need no extra licence.

## 6. Coverage by platform (expected; only MSI verified live)

| Class | CPU package power | CPU temperature | Rails / fans / DIMM | CPU / GPU load | GPU power |
|---|---|---|---|---|---|
| Intel desktop with IPF / DTT driver (verified: MSI Z890) | EMI RAPL — **PASS** | NO DATA | NO DATA | PASS | NVML PASS (NVIDIA); ADLX / IGCL candidate |
| Intel desktop without IPF / DTT | expected NO DATA (EMI class registered, no instances) — UNVERIFIED | NO DATA | NO DATA | PASS | as above |
| Intel / AMD laptops | EMI often present (battery / PSys / RAPL) — UNVERIFIED | ACPI zone LOW | OEM WMI on some models — UNVERIFIED | PASS | vendor API |
| AMD desktop | EMI provider unknown — UNVERIFIED; Ryzen Master SDK only with Ryzen Master installed | NO DATA (natively) | NO DATA | PASS | vendor API |
| ARM64 (Snapdragon) | EMI is the documented Windows path for PMIC energy channels — UNVERIFIED | ACPI zones | NO DATA | PASS | Adreno: PDH engine load only |
| OEM (Dell / HP / Lenovo) | as by CPU vendor | OEM WMI candidate | OEM WMI candidate | PASS | vendor API |

## 7. Proposed Power Backend (NOT implemented — for approval)

**Model.** One value record per reading:

- `parameter` (e.g. `CPU_PACKAGE_POWER`);
- `sensor_identity` (provider + channel / device id);
- `value`, `unit`;
- `source`;
- `timestamp`;
- `confidence` (HIGH / MEDIUM / LOW);
- `scope`: `cpu_package`, `cpu_cores`, `igpu`, `gpu_board`, …; never `psu`.

**Providers** (read-only, user mode, no new binary dependency):

1. `EmiProvider`. It reads the EMI channels and maps the RAPL domain from the last name part: `PKG` / `PP0` / `PP1` / `DRAM` / `PSYS`. A 0 on DRAM = NO DATA.
   - Preferred implementation: the documented `IOCTL_EMI_GET_*` on the EMI device interface (energy / time deltas), with the CIM counter set as a fallback.
2. `PdhLoadProvider`: CPU utility and per-LUID GPU engine load.
3. `NvmlProvider`: dynamic load of the driver's `nvml.dll`, query functions only. It is absent when there is no NVIDIA driver.
4. Candidates after a licence review: `AdlxProvider`, `IgclProvider`.
5. Existing: the bundled LHM helper (GPU / storage) and the optional HWiNFO SM / LHM WMI readers.
6. LOW: ACPI thermal zones (never red on their own).

**UI rule.**

- Shown: "CPU (package, RAPL)" and "GPU (board)" power.
- Not shown: any total called "power consumption" or "PSU load". If a sum is ever shown, it is labelled "sum of measured components (not PSU / wall power)".

**Not covered by any safe source on this desktop:** CPU package temperature, Vcore/VID, ATX rails, fans, DIMM/PCH. These stay NO DATA with the reason shown. Coverage comes only through the user's own HWiNFO (SM) or PawnIO-backed LHM.

## 8. Recommendation

**Safe provider to adopt next (after approval):**

- Windows EMI for CPU package, cores and iGPU power;
- PDH for CPU and GPU load;
- NVML for NVIDIA GPU power.

All three are already proven live on the MSI. They need:

- no driver;
- no new third-party binary;
- no licence beyond Windows and the GPU driver.

Before production:

- a reference comparison of EMI PKG power against HWiNFO on the MSI, with the user running HWiNFO;
- a live pass on one AMD desktop and one laptop.

## Sources

- Microsoft: Energy Meter Interface (EMI) — `IOCTL_EMI_GET_METADATA` / `IOCTL_EMI_GET_MEASUREMENT` (Windows driver documentation, `emi.h`).
- NVIDIA: NVML / `nvidia-smi` documentation.
- CVE records: [OpenCVE — MSI vendor](https://app.opencve.io/cve/?vendor=msi), [CVE-2026-6102](https://app.opencve.io/cve/CVE-2026-6102), [cvelogic — MSI](https://www.cvelogic.com/vendor/msi).
- HWiNFO Shared Memory limits: see `docs/SENSOR_BACKEND_V2_RESEARCH.md` sources.
