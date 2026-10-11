# Sensor Backend V2 — security audit

## Rules checked

| Rule | Status in v1.0 | Evidence |
|---|---|---|
| No WinRing0 / WinRing0x64 | PASS | LHM 0.9.6 has no WinRing0. `build.rs` embeds only the `.dll` files of the audited bundle (extension filter), so no `.sys` driver can be shipped; the PawnIO modules are `.bin` resources inside the LHM DLL |
| Memory Integrity untouched | PASS | no registry or policy write anywhere in the sensor path |
| Vulnerable Driver Blocklist untouched | PASS | same |
| No unsigned / test-signed kernel driver | PASS | WinStateDiag ships no driver |
| No EC / Super-I/O writes | PASS | the sensor helper calls only LHM read APIs (`Update()`, `Sensors`). Fan control (`Control.SetSoftware`) is never called |
| No BIOS change | PASS | — |
| No automatic PawnIO install | PASS | presence is only detected (`Win32_SystemDriver Name='PawnIO'`); the LHM PawnIO API has no install entry point |
| No automatic HWiNFO / AIDA64 install | PASS | shared memory is opened read-only (`OpenFileMapping`, `FILE_MAP_READ`) only if it already exists |

## Per provider

- **LibreHardwareMonitorLib (bundled).**
  - Source and licence: official nuget.org package, MPL-2.0.
  - Runs in a short-lived hidden PowerShell helper with WinStateDiag's existing (elevated) token.
  - Risk: loads managed code into that process.
  - Mitigations:
    - pinned version 0.9.6;
    - hash recorded at build;
    - no network access;
    - helper killed after the sampling window.
- **PawnIO** (third-party, user-installed only).
  - A signed kernel driver that executes vendor-supplied PawnIO scripts.
  - It is designed as the safe WinRing0 replacement and is used by LHM ≥ 0.9.5, FanControl and OpenRGB.
  - It is still a ring-0 component that we have not audited ourselves.
  - Decision: never installed, never bundled as `.sys`. Used only through LHM when the user installed it.
- **HWiNFO Shared Memory.**
  - Read-only memory map.
  - The licence allows reading it; the free version time-limits Shared Memory to 12 h.
  - Decision: optional provider when it is already running.
- **AIDA64.** Commercial; reference only.
- **WMI providers** (LHM / OHM WMI, `Win32_VoltageProbe`, ACPI thermal zone): read-only CIM queries.

## Residual risks (accepted, documented)

- LHM managed code runs with the app's elevated token: accepted, because the package is pinned, official and read-only.
- `Win32_VoltageProbe` and ACPI thermal zones can return nonsense: they are marked LOW confidence and never produce a red state on their own.
