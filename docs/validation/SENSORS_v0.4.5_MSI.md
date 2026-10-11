# Sensor validation — v0.4.5 — MSI PRO Z890-P WIFI (MS-7E34)

Status: **autonomous pass DONE (2026-10-05 15:52, HWiNFO + AIDA64 closed): PARTIAL.** Second pass with HWiNFO Shared Memory: pending.
The comparison columns are filled from `Claude outputs\v045_wsd_sensors.json`. That file is produced by `Claude outputs\v045_windows_gate.cmd`, which runs `win_state_diag.exe --sensor-probe`. Serial numbers are omitted.

## Machine

| Item | Value |
|---|---|
| Board | Micro-Star PRO Z890-P WIFI (MS-7E34) |
| CPU | Intel Core Ultra 7 270K Plus |
| GPU | NVIDIA GeForce RTX 5060 (driver 32.0.16.1692) + Intel Graphics |
| OS | Windows 11 Pro, build 26300 |
| Memory Integrity (HVCI) | ON (VBS running, HVCI service running) |
| Vulnerable driver blocklist | ON |
| PawnIO | not installed |
| LHM / OHM WMI | not running |
| HWiNFO | kernel driver loaded (`HWiNFO_x64_206.sys`) |
| nvidia-smi | present (`C:\Windows\system32\nvidia-smi.exe`) |

Source: `Claude outputs\v045_sensor_probe.log`, a read-only probe.

## Reference: AIDA64 (validation reference only; never a dependency)

### Temperatures (°C)

| Sensor | AIDA64 | WinStateDiag | Provider | Δ |
|---|---|---|---|---|
| Motherboard ("Системная плата") | 38 | pending | | |
| CPU (AIDA "ЦП") | 54 | pending: core average | | |
| CPU package ("Весь ЦП") | 53 | pending | | |
| CPU cores, average of 24 | 48.2 (computed) | pending | | |
| PCH | 46 | pending | | |
| GPU | 36 | pending | | |
| GPU hotspot | 43 | pending | | |
| GPU memory | 40 | pending | | |
| DIMM2 / DIMM4 | 39 / 39 | pending | | |
| Samsung SSD 9100 PRO 1TB | 46 | pending | | |
| Netac NVMe SSD 1TB | 43 | pending | | |

### Voltages (V)

| Rail | AIDA64 | WinStateDiag | Class |
|---|---|---|---|
| +3.3V | 3.320 | pending | ATX (rated) |
| +5V | 5.020 | pending | ATX (rated) |
| +12V | 12.024 | pending | ATX (rated) |
| CPU Vcore | 1.418 | pending | dynamic (info) |
| CPU VID | 1.105 | pending | dynamic (info) |
| VDD2 / VNNAON / VCCIO / VCCSA | 1.432 / 0.767 / 1.288 / 1.245 | pending | dynamic (info) |
| GPU core | 0.790 | pending | dynamic (info) |
| GPU PCIe / 12VHPWR input | 11.923 / 11.915 | pending | informational |

### Power (W)

| Sensor | AIDA64 | WinStateDiag |
|---|---|---|
| CPU package | 58.44 | pending |
| CPU IA cores | 44.76 | pending |
| CPU GT cores | 0.06 | pending |
| CPU uncore | 13.62 | pending |
| GPU | 24.03 | pending |
| GPU PCIe | 2.50 | pending |
| GPU 12VHPWR | 17.58 | pending |

### Fans

AIDA64 screenshots did not include fans: not compared.

## Expected coverage on this machine (no PawnIO, HVCI on)

| Group | Provider able to read it without weakening security |
|---|---|
| GPU temperature / hotspot / power / fans | LibreHardwareMonitorLib (NVAPI), nvidia-smi |
| SSD temperatures | NVMe Health (native), LibreHardwareMonitorLib (storage) |
| CPU temperatures / power, board rails, PCH, fans, DIMM | **only** via a ring-0 provider: HWiNFO shared memory (if the user runs HWiNFO with shared memory enabled), or LibreHardwareMonitorLib with PawnIO installed by the user |

WinStateDiag does not install PawnIO or any driver. On this machine the board rails therefore depend on HWiNFO shared memory being enabled.

## Autonomous pass — WinStateDiag alone (HWiNFO + AIDA64 closed)

- **Gate:** `Claude outputs\v045_windows_gate.cmd`, elevated, fail-closed. `GATE_RESULT=PASS`.
  - LHM fetch: exit 0. fmt/check: PASS. Tests: 415/415. Release build: PASS.
- **Probe:** `win_state_diag.exe --sensor-probe`. State PARTIAL, 116 sensors, main provider LibreHardwareMonitorLib (internal).
- **Security state:**
  - HVCI running, vulnerable-driver blocklist = 1, PawnIO driver absent.
  - New drivers/services after the run: **none**. v0.4.3 / v0.4.4 dist hashes unchanged.

| Provider | State | Detail |
|---|---|---|
| LibreHardwareMonitorLib 0.9.6 (bundled) | PARTIAL | loaded; PawnIO not installed → no MSR / Super I/O / SMBus |
| nvidia-smi | AVAILABLE | official NVIDIA CLI |
| LHM / OHM WMI | UNAVAILABLE | not running |
| Win32_VoltageProbe | UNAVAILABLE | 0 probes |
| HWiNFO shared memory | UNAVAILABLE | closed for this pass |

### Autonomous values vs AIDA64

The AIDA64 figures were captured earlier, so an instantaneous match is not expected.

| Sensor | WinStateDiag (autonomous) | AIDA64 | Note |
|---|---|---|---|
| CPU temperature | **NOT AVAILABLE** | 54 °C | needs MSR access (PawnIO); LHM reports null |
| Board temperature | **NOT AVAILABLE** | 38 °C | Super I/O not reachable (no Motherboard hardware enumerated) |
| PCH temperature | **NOT AVAILABLE** | 46 °C | same |
| GPU temperature | 46.5 °C (LHM NVAPI); 44.1 °C in the direct LHM sample | 36 °C | different time and load |
| GPU hotspot | **NOT AVAILABLE** | 43 °C | LHM 0.9.6 exposes no hotspot for this RTX 5060; GPU memory junction 48 °C is available |
| +12V / +5V / +3.3V | **NOT AVAILABLE** | 12.024 / 5.020 / 3.320 | Super I/O; status = Нет данных |
| CPU package power | **NOT AVAILABLE** | 58.44 W | LHM returns 0.0 W without MSR. Treated as missing since this run (see fix) |
| GPU power | 53.0 W (LHM "GPU Package"); 51.7 W nvidia-smi earlier | 24.03 W | different load |
| CPU fan / system fans | **NOT AVAILABLE** | (not captured) | Super I/O |
| GPU fan | 0 RPM | — | zero-RPM mode; not a failure |
| Samsung SSD 9100 PRO | 45 °C (composite) | 46 °C | ✔ |
| Netac NVMe SSD 1TB | 43 °C (composite) | 43 °C | ✔ |
| ST2000VX017 | 32 °C | 32 °C | ✔ |
| TOSHIBA DT02ABA400 ×2 | 28 °C / 25 °C | 28 / 26 °C | the second disk was merged into the first in the probe; fixed since (see below) |

**Verdict: PARTIAL.** Autonomously, WinStateDiag reads the GPU (temperature, memory junction, power, core voltage, fan) and every disk temperature. CPU, board, PCH, ATX rails, CPU power and board fans are unavailable without a ring-0 provider. WinStateDiag never installs one.

### Fixes from this pass (source only; validated on the Linux harness, 419/419)

1. **CPU power of 0.0 W** from LHM without MSR access is now "not available", never a value.
2. **Two physical disks of the same model** stay separate ("TOSHIBA DT02ABA400 #1 / #2").
3. **The integrated GPU** never displaces the discrete GPU in the summary.

### LibreHardwareMonitorLib package audit

- **Source:** nuget.org, owner `lhm`. MPL-2.0, upstream commit `3d331e3370efb858411f19511373eff65a218701`.
- **Package hashes:** nupkg SHA256 `60DB5E0D…4039197`; DLL `runtimes/win-x64/lib/net472/LibreHardwareMonitorLib.dll` SHA256 `6EBC1943…30F66BF0`. The DLL is not Authenticode-signed.
- **Embedded resources:** only PawnIO *modules*, i.e. `.bin` Pawn programs (IntelMSR, LpcIO, SmbusI801, …). There is no `.sys` driver and no installer.
- **PawnIO API surface:** the `PawnIo` class exposes `IsInstalled`, `IsLoaded`, `Version`, `LoadModuleFromResource`, `Execute`, `Close`. There is no install method. `IsInstalled=False` on this PC.
- **Dependencies:**
  - DiskInfoToolkit 1.1.2, BlackSharp.Core 1.0.7 and RAMSPDToolkit-NDD 1.4.2 (MPL-2.0);
  - HidSharp 2.6.4 (Apache-2.0, LICENSE.txt);
  - System.* packages (MIT).
- **Full SHA256 list:** `Claude outputs\v045_lhm_fetch_probe.log`.

## Consolidation pass — PASS A (autonomous) and PASS B (HWiNFO optional)

### PASS A — HWiNFO and AIDA64 closed (Windows gate 2026-10-05 17:28, `Claude outputs\v045c_gate.log`)

- Gate PASS: fmt, check, 444/444 Windows tests, release build.
- `--sensor-probe`: **PARTIAL**, 112 sensors. The bundled LHM provider is PARTIAL because PawnIO is not installed.
- No new drivers or services. v0.4.3 / v0.4.4 hashes are unchanged.
- **Coverage is the same as the autonomous table above:**
  - Available: GPU temperature, GPU memory junction, GPU power, GPU core voltage, GPU fan, and every disk temperature (NVMe composite + Storage Reliability).
  - NOT AVAILABLE: CPU temperature, board, PCH, +12V / +5V / +3.3V, CPU package power, CPU and system fans.
  - The dashboard shows these as missing (no rows / "Нет данных"), never 0.
- Regression fixes confirmed in the build: CPU 0 W is treated as missing; TOSHIBA #1 / #2 stay separate; the discrete GPU is preferred.
- `--incident-probe` on this PC:
  - **Passport:** Windows 11 Pro 26H2 (26300.9550) · Intel Core Ultra 7 270K Plus · 24C/24T · 48 GB DDR5-7667 (2×24 GB) · MSI PRO Z890-P WIFI (MS-7E34).
  - **Counts:** Unexpected shutdowns 2 · BugCheck / BSOD 0 · Dumps 0.
  - **Incident 2026-10-05 14:24** (the PC froze during this work and was reset): last activity 14:18:22. There are no correlated events in the 10 minutes before the stop and no LiveKernelReports. Verdict: **HANG NOT CONFIRMED / BSOD NOT REGISTERED / CAUSE NOT DETERMINED**. That is honest: nothing in the logs shows a hang or a subsystem.
  - **Incident 2026-10-01 08:31:** same verdict.

### PASS B — HWiNFO running with Shared Memory Support, AIDA64 closed

NOT RUN yet: it needs the user to start HWiNFO with Shared Memory enabled. Run `Claude outputs\v045_passB_probe.cmd`; it refuses to run without HWiNFO and with AIDA64 open. The comparison table will be filled from `v045_passB_sensors.json`.

| Sensor | AUTONOMOUS | HWiNFO OPTIONAL ENHANCED |
|---|---|---|
| CPU | not available | pending |
| Motherboard | not available | pending |
| PCH | not available | pending |
| +12V / +5V / +3.3V | not available | pending |
| CPU Package Power | not available | pending |
| GPU Power | available (LHM NVAPI) | pending |
| CPU Fan / System Fans | not available | pending |

Severity never changes because a provider is absent; HWiNFO is never required.
