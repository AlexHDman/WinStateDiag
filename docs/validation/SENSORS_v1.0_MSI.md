# Sensor validation — v1.0 — MSI PRO Z890-P WIFI (MS-7E34)

Date: 2026-10-06. Read-only probes of the v1.0 source build (`win_state_diag.exe --sensor-probe`, `--smart-probe`, `--evidence-probe`). No driver, service or third-party tool was installed. Serial numbers omitted.

## Machine

| Item | Value |
|---|---|
| CPU / board | Intel Core Ultra 7 270K Plus / MSI PRO Z890-P WIFI |
| GPU | NVIDIA GeForce RTX 5060 (driver 32.0.16.1692) + Intel Graphics |
| Disks | Samsung SSD 9100 PRO 1TB (NVMe), Netac NVMe SSD 1TB, 2 × TOSHIBA DT02ABA400 (SATA HDD), Seagate ST2000VX017 (SATA HDD) |
| Memory Integrity / vulnerable-driver blocklist | ON / ON |
| PawnIO | not installed (never installed by WinStateDiag) |
| HWiNFO | **not installed** on this PC |
| AIDA64 | closed |

## PASS A — autonomous (HWiNFO closed, AIDA64 closed): **PARTIAL**

Provider: bundled LibreHardwareMonitorLib helper (PARTIAL: "PawnIO low-level driver not installed: CPU/motherboard/RAM sensors unavailable"), nvidia-smi present, LHM/OHM WMI not running, Win32_VoltageProbe 0 probes, HWiNFO shared memory not available.

| Sensor | Value | Provider |
|---|---|---|
| GPU core temperature | 29.6 °C | LHM (internal) |
| GPU memory junction | 32 °C | LHM (internal) |
| GPU power | 9.5 W | LHM (internal) |
| Samsung 9100 PRO | 44 °C | LHM (internal) / NVMe Health |
| Netac NVMe | 43 °C | LHM (internal) / NVMe Health |
| ST2000VX017 | 31–32 °C | LHM (internal) / ATA SMART |
| TOSHIBA DT02ABA400 #1 | 28 °C | LHM (internal) / ATA SMART |
| TOSHIBA DT02ABA400 #2 | 25 °C | LHM (internal) / ATA SMART |
| CPU temp, board, PCH, +12V / +5V / +3.3V, CPU package power, CPU / system fans | **Нет данных** (expected without a ring-0 provider) | — |

The two identical TOSHIBA models stay separate rows (#1 / #2). The dashboard shows every expected row; missing values read «Нет данных», a 0 W counter is never shown as "0 W".

Process context of the sampling window: system CPU 21 %, below the 50 % threshold → no top-process list (context only).

## PASS B — HWiNFO running with Shared Memory Support: **NOT RUN**

HWiNFO is not installed on this PC and WinStateDiag validation never installs third-party software. The HWiNFO shared-memory reader is covered by its parser tests (`sensors::tests`), and the v0.4.5 MSI comparison against AIDA64 remains the reference for CPU / board / rail values when HWiNFO is available.

| Sensor | PASS A (autonomous) | PASS B (HWiNFO) |
|---|---|---|
| CPU temperature | Нет данных | not run |
| Board temperature | Нет данных | not run |
| PCH | Нет данных | not run |
| +12V / +5V / +3.3V | Нет данных | not run |
| CPU package power | Нет данных | not run |
| GPU power | 9.5 W | not run |
| CPU fan / system fans | Нет данных | not run |

## ATA SMART (read-only, `--smart-probe`)

| Disk | Bus | ATA SMART | Temp | Power-on hours | Reallocated / pending / uncorrectable |
|---|---|---|---|---|---|
| TOSHIBA DT02ABA400 #1 | SATA | OK | 28 °C | 35 559 | 0 / 0 / 0 |
| TOSHIBA DT02ABA400 #2 | SATA | OK | 25 °C | 35 574 | 0 / 0 / 0 |
| ST2000VX017-3CV102 | SATA | OK | 32 °C | 10 598 | 0 / 0 / 0 |
| Samsung SSD 9100 PRO 1TB | NVMe | UNSUPPORTED (NVMe path; NVMe Health is used) | — | — | — |
| Netac NVMe SSD 1TB | NVMe | UNSUPPORTED (NVMe path; NVMe Health is used) | — | — | — |

## Collectors validated live

| Collector | Result |
|---|---|
| Event evidence (30 days) | 1 352 events → 49 aggregates in ~2 s; Schannel 36871 ×612 (ErrorCode 10013), WU 20 with HRESULT / title, SCM 7023 / 7031 / 7034 with current service state / start type / image path, SideBySide 33 ×66 → one aggregate, Cyrillic intact |
| Driver resolver (`nvlddmkm`) | DriverStore file, version 32.0.16.1692, NVIDIA, Authenticode Valid (Microsoft WHCP signer), service Running / Manual, oem269.inf, RTX 5060 OK |
| cdb pipeline (benign user-mode dump of a process WinStateDiag started) | COMPLETED; real stages LoadSymbols 0.4 s → RunAnalyze 4.1 s → ParseStack 10.8 s; no third-party module → CAUSE NOT DETERMINED (nothing fabricated); `lmvm` output format matches the parser |
