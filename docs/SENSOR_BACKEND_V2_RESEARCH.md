# Universal Sensor Backend V2 — research and decision (v1.0)

Status: **research complete for v1.0, implementation = safe chain only**.
Scope: every Windows machine class WinStateDiag meets, not only the MSI
reference machine.

Machine classes considered:

- Intel and AMD desktops;
- Intel and AMD notebooks;
- Snapdragon / ARM64;
- workstations;
- OEM desktops and notebooks (Dell, HP, Lenovo, Acer …) and DIY boards (MSI, ASUS, Gigabyte, ASRock);
- mini PCs.

Companion files:

- `research/sensor_backend_v2/LIVE_MATRIX.md` — what each provider delivered on real hardware.
- `research/sensor_backend_v2/SECURITY_AUDIT.md` — per-provider security review.
- `research/sensor_backend_v2/PROVIDER_RECOMMENDATION.md` — the decision and the chain.

## 1. Hard rules (unchanged, permanent)

- No WinRing0 / WinRing0x64. It is flagged as `VulnerableDriver:WinNT/Winring0` by Microsoft Defender.
- No disabling of Memory Integrity (HVCI) or of the Vulnerable Driver Blocklist.
- No test-signed or unsigned kernel driver. No EC, Super-I/O or BIOS writes.
- No automatic PawnIO, HWiNFO or AIDA64 installation.
- **"Нет данных" is better than unsafe telemetry.** A missing value stays missing and is never 0.

## 2. What the telemetry needs, and where it can safely come from

| Telemetry | Where it physically lives | Safe user-mode path | Needs a kernel driver? |
|---|---|---|---|
| Storage temperature (NVMe) | NVMe SMART / Health log page | `IOCTL_STORAGE_QUERY_PROPERTY` (NVMe protocol data), read-only | No |
| Storage temperature (SATA) | ATA SMART attr 194/190 | `SMART_RCV_DRIVE_DATA`, read-only | No |
| GPU temp / power / voltage / fan | GPU driver | NVAPI / ADL / IGCL through LHM; `nvidia-smi` | No |
| CPU temperature / package power | MSR (Intel `IA32_PACKAGE_THERM_STATUS`, RAPL; AMD SMN) | none in stock Windows | **Yes** (ring-0 MSR read) |
| Board / PCH temps, +12V/+5V/+3.3V, Vcore, fans, pump | Super-I/O LPC chip or EC | none in stock Windows (vendor WMI on some OEMs) | **Yes** (port I/O) |
| DIMM temperatures | SPD hub / TS on SMBus | none in stock Windows | **Yes** (SMBus) |
| Notebook CPU temperature | ACPI thermal zone (EC) | `MSAcpi_ThermalZoneTemperature` (often absent, coarse) | No, but low confidence |
| ARM64 (Snapdragon) | SoC thermal framework | ACPI thermal zones; no public MSR equivalent | No |

**Conclusion:** without a ring-0 helper, a Windows application can safely
read the following:

- storage health and temperatures;
- GPU telemetry;
- coarse ACPI thermal zones;
- any values already published by a running monitoring tool.

CPU package temperature and power, the ATX rails, fans and DIMM
temperatures **physically require privileged port/MSR/SMBus access**.

## 3. Candidates evaluated

| Provider | What it adds | Security status | Verdict for v1.0 |
|---|---|---|---|
| Windows native (NVMe IOCTL, ATA SMART, Storage Reliability) | disks | read-only, no driver | **USE** (canonical for disks) |
| LibreHardwareMonitorLib 0.9.6 (bundled, nuget.org, MPL-2.0) | GPU, storage; CPU/board **only if PawnIO is present** | no WinRing0 since 0.9.5. It ships PawnIO modules (`.bin`) only, with no `.sys` and no installer; `build.rs` embeds `.dll` files only | **USE** (in-process helper, read-only) |
| PawnIO (namazso) | signed scriptable ring-0 I/O used by LHM ≥ 0.9.5, FanControl, OpenRGB | signed, designed to stay HVCI-compatible and to replace WinRing0. Third-party kernel driver; not audited by us | **DETECT ONLY.** Used when the user already installed it; never installed by WinStateDiag |
| HWiNFO Shared Memory | widest coverage (CPU, board, rails, fans, DIMM) | uses its own signed driver. The free version enables Shared Memory for 12 h at a time, Pro has no limit | **OPTIONAL**: read only when already running with Shared Memory on |
| LHM / OHM WMI (already running app) | depends on that app | read-only WMI read | **OPTIONAL** |
| AIDA64 shared memory / WMI | wide coverage | commercial; licensing per seat | **REFERENCE ONLY** (manual comparison, not a provider) |
| `nvidia-smi` | NVIDIA GPU | official vendor CLI, query only | **USE** as fallback |
| `Win32_VoltageProbe`, ACPI thermal zone | sometimes anything | often empty or fake values | **USE with LOW confidence**; never drives a red state |
| OEM services (Dell Command \| Monitor, HP / Lenovo WMI) | board temps / fans on some models | vendor WMI, read-only | **FUTURE**: per-vendor WMI read when present (not in v1.0) |
| Intel PMT / AMD SMN / Ryzen Master SDK | CPU telemetry | need driver or vendor SDK | **NO** (driver / licensing) |
| WinRing0 / inpout / "bundled tiny driver" | everything | known-vulnerable / unsigned / HVCI-blocked | **NEVER** |

## 4. Decision

The safe chain for v1.0, in canonical priority order:

1. NVMe Health and ATA SMART.
2. LibreHardwareMonitorLib (internal). Its CPU and board sensors light up only when the user's own PawnIO is present.
3. HWiNFO Shared Memory, only if already running.
4. LHM WMI and OHM WMI, only if already running.
5. `nvidia-smi`.
6. Storage Reliability counters.
7. `Win32_VoltageProbe` and the ACPI thermal zone (LOW confidence).

Missing CPU, board, rail and fan values are shown as **"Нет данных"**. The
Details window explains why: no safe user-mode access, and PawnIO is not
installed by WinStateDiag.

## 5. Value metadata (implemented)

Every value in `Hardware_Sensors_<stamp>.json` carries:

- `value`, `unit`;
- `sensor_type` (logical type);
- `hardware` + `hardware_id` (hardware identity);
- `provider`;
- `timestamp`;
- `confidence`;
- `threshold_source`.

`threshold_source` is one of:

- `atx_spec_nominal_plus_minus_5_percent` / `atx_spec_nominal_only_for_fixed_rails`;
- `drive_reported_limits_or_none`;
- `none_informational`.

Canonical summary values additionally carry `role` and `derived`.

## 6. What a future v1.x could add (not now)

- Per-vendor read-only OEM WMI providers (Dell / HP / Lenovo), when present.
- ARM64: Windows thermal-zone consumer (`Win32_PerfFormattedData_Counters_ThermalZoneInformation`) as a LOW/MEDIUM provider.
- A "PawnIO present" guidance text with the official project link. Still never an installer.

## Sources

- Microsoft: [VulnerableDriver:WinNT/Winring0 alert](https://support.microsoft.com/en-us/windows/security/threat-malware-protection/microsoft-defender-antivirus-alert-vulnerabledriver-winnt-winring0)
- PCWorld: [If Windows Defender flags WinRing0 …](https://www.pcworld.com/article/2912435/if-windows-defender-flags-winring0-on-your-gaming-pc-pay-attention.html)
- OpenRGB: [Switch from WinRing0 to PawnIO](https://gitlab.com/CalcProgrammer1/OpenRGB/-/merge_requests/2885)
- ZenTimings: [WinRing0 cleanup after move to PawnIO](https://github.com/irusanov/ZenTimings/discussions/90)
- HWiNFO: [Important changes to HWiNFO64 (Shared Memory limits)](https://www.hwinfo.com/forum/threads/important-changes-to-hwinfo64-coming-soon.7092)
