# Sensor Backend V2 — provider recommendation (v1.0 decision)

## Chain (canonical priority, best first)

| # | Provider | Always on? | Covers | Confidence |
|---|---|---|---|---|
| 0 | NVMe Health / ATA SMART | yes | disk temperatures (canonical) | HIGH |
| 1 | LibreHardwareMonitorLib 0.9.6 (internal) | yes | GPU, storage; CPU/board/rails/fans only with the user's PawnIO | HIGH (board rails MEDIUM unless board-mapped) |
| 2 | HWiNFO Shared Memory | only if already running | CPU, board, rails, fans, DIMM | HIGH |
| 3 | LHM WMI / OHM WMI | only if already running | as that app | MEDIUM |
| 4 | `nvidia-smi` | if present | NVIDIA GPU | MEDIUM |
| 5 | Storage Reliability counters | yes | disk temperature (fallback) | MEDIUM |
| 6 | `Win32_VoltageProbe`, ACPI thermal zone | yes | anything exposed | LOW (never red alone) |

Not used:

- WinRing0;
- any bundled kernel driver;
- automatic PawnIO, HWiNFO or AIDA64 installation;
- AIDA64 as a provider (reference only);
- vendor CPU SDKs.

## Thresholds

| Value | Threshold source (`threshold_source`) |
|---|---|
| +12V / +5V / +3.3V / 5VSB | ATX nominal ± 5 % (`atx_spec_nominal_plus_minus_5_percent`), only when board-mapped (MEDIUM+) |
| Disk temperature | drive-reported WCTEMP / CCTEMP (NVMe) or none (`drive_reported_limits_or_none`) |
| Vcore, VID, GPU core, PCIe/12VHPWR | none: dynamic (`none_informational`) |
| Everything else | none (`none_informational`) |

## Expected coverage

- **Any Windows x64 machine, autonomous:**
  - disks, and GPU when exposed by the vendor driver;
  - CPU, board, rails and fans shown as "Нет данных", with the reason given in Details.
- **With the user's own PawnIO:** CPU temperature and package power, plus Super-I/O rails and fans on boards that LHM supports.
- **With HWiNFO running (Shared Memory on):** the widest coverage. This is optional PASS B and does not block a release.
