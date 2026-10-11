# Sensor Backend V2 — live matrix

Real machines only; nothing below is extrapolated. "—" = not tested on that
class (no hardware available in this pass).

## Reference machine: MSI (Intel desktop, RTX 5060)

Conditions:

- autonomous pass, HWiNFO and AIDA64 closed;
- HVCI on, Vulnerable Driver Blocklist on;
- PawnIO absent;
- LHM 0.9.6 bundled.

| Telemetry | Safe chain (autonomous) | Provider | Note |
|---|---|---|---|
| CPU temperature | Нет данных | — | needs MSR access (PawnIO) |
| CPU package power | Нет данных | — | LHM returns 0.0 W without MSR → treated as missing |
| Board / PCH temperature | Нет данных | — | Super-I/O needs port I/O |
| +12V / +5V / +3.3V | Нет данных | — | Super-I/O |
| CPU / SYS fans, pump | Нет данных | — | Super-I/O |
| DIMM temperature | Нет данных | — | SMBus |
| GPU temperature | 46.5 °C | LHM (NVAPI) | |
| GPU memory junction | 48 °C | LHM (NVAPI) | |
| GPU power | 53 W | LHM (NVAPI) | |
| GPU core voltage | yes | LHM (NVAPI) | |
| GPU fan | 0 RPM | LHM (NVAPI) | zero-RPM mode, valid reading |
| GPU hotspot | not exposed | — | LHM 0.9.6 on RTX 5060 |
| NVMe temperatures | Samsung 45 °C, Netac 43 °C | NVMe Health (composite) | canonical for disks |
| SATA temperatures | ST2000 32 °C, TOSHIBA 28 / 25 °C | ATA SMART 194 | two identical models stay #1 / #2 |

Result: **PARTIAL**, truthful. 116 raw sensors were read. Nothing was
invented, and no driver or service was added.

## Pass B (optional, not blocking v1.0)

HWiNFO Shared Memory on the same machine: **NOT RUN in this pass.** The user
did not have HWiNFO running, and WinStateDiag never starts or installs it.

## Other classes

| Class | Status |
|---|---|
| AMD desktop | — (no live machine in this pass) |
| Intel / AMD notebook | — |
| Snapdragon / ARM64 | — (the LHM x64 helper does not run; native disk providers do) |
| OEM desktop / workstation / mini PC | — |

Expected behaviour on these classes is the same safe chain:

- disks and GPU when exposed by the vendor driver;
- CPU, board, rails and fans as "Нет данных" unless the user's own PawnIO or a running HWiNFO / LHM / OHM is present.
