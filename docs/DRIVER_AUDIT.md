# Driver Audit (read-only)

## Purpose

The Driver Audit checks the drivers that matter for stability and puts concrete evidence into the diagnostic report:

- display/GPU;
- chipset/system;
- storage (NVMe, SATA, RAID/VMD);
- network (Wi-Fi, Ethernet);
- audio;
- kernel drivers that appear in failure evidence.

It never changes the system.

## Pipeline

1. **Collector.** `embedded/WinStateDiag/DriverAudit.ps1` is a new embedded file; the existing baseline scripts are unchanged. It uses only `Get-CimInstance` (`Win32_PnPEntity`, `Win32_PnPSignedDriver`, `Win32_SystemDriver`) and `Get-WinEvent`. The event window is 30 days:
   - Application / Application Error 1000;
   - System / Service Control Manager 7026 and 7000;
   - System / Kernel-PnP 219;
   - System / Display 4101;
   - Microsoft-Windows-CodeIntegrity/Operational 3001, 3002, 3004, 3033, 3063, 3077.

   Output is tab-separated UTF-8 records (`META`, `DEV`, `SYS`, `EVT`, `ERR`).
2. **Classifier.** `src/driver_audit.rs` does parsing, categorisation, event correlation, deduplication, severity, the dashboard summary and JSON/TXT serialisation. It is pure Rust and unit tested.
3. **When it runs:**
   - in the background at program start, to fill the dashboard card;
   - inside every diagnostic session, after EXPC and Hardware Report and before packaging. In a session it writes `DriverAudit_<session>.json` and `.txt` into the session's day folder, so both files are included in the ZIP.
   - A failure is logged and never fails the session.

## Status rules

Driver age is never a finding.

| Status | Evidence required |
|---|---|
| PROBLEM (red) | A current PnP device error (any `ConfigManagerErrorCode` except 0, 22, 24 or 45). A crash (Application Error 1000) whose faulting module belongs to the device's driver. A Code Integrity failure of a kernel driver (`.sys`). A boot/system driver that failed to load (7026/7000) and is not running now. A Kernel-PnP 219 load failure on a device that currently has an error. |
| WARNING (amber) | A display timeout that was recovered (TDR 4101). A past load failure (219) or boot failure (7026/7000) where the device or driver works now. An unsigned driver. A display adapter on the Microsoft basic driver. A Code Integrity event for a user-mode component (`.dll`) of the driver. |
| OK (green) | None of the above. |

- Precedence: PROBLEM > WARNING > OK, per item and overall.
- Identical evidence (kind, event, module, version, exception, process) is merged into one entry with a count and a first/last time.
- A disabled device (code 22) is noted as information and is not treated as a fault.
- Evidence that cannot be attributed to a present device or driver is kept in `unattributed_evidence` for context. It never changes a status.

## Correlation

- **Crash modules.** These are mapped to the vendor's display driver by file-name prefix:
  - Intel: `igvk*`, `igd*`, `igc*`, `igx*`, …
  - NVIDIA: `nvwgf*`, `nvoglv*`, `nvlddmkm`, …
  - AMD: `atiumd*`, `amdxc*`, `amdkmdag`, …

  An exact match between the module version and the device's driver version wins. If no device matches, a placeholder item carries the evidence.
- **Driver names.** Names from 7026, 7000, 4101 and Code Integrity events are matched to the device `Service` or to `Win32_SystemDriver`.

### Reference case

This is an example of the evidence model; nothing about it is hard-coded.

- **Device:** Intel Graphics (iGPU), driver 30.0.101.1273.
- **Event:** Application Error 1000 in `win_state_diag.exe`.
- **Faulting module:** `igvk64.dll` 30.0.101.1273, exception 0xC0000005.
- **Result:** item PROBLEM, with evidence `kind = crash`, module, version, exception, process, event id 1000 and the first/last time.

## Report schema (`winstatediag.driver_audit/1`)

**Top level:** `overall`, `counts`, `devices_scanned`, `window_days`, `generated`, `collection_complete`, `status_rules`.

**`items[]`** fields:

- `category`, `label`, `device`, `vendor`
- `driver_provider`, `driver_version`, `driver_date`, `inf`
- `service`, `pnp_device_id`, `pnp_error_code`, `signed`
- `status`, `status_reasons[]`
- `evidence[]`, each with: `kind`, `severity`, `source`, `event_id`, `first_seen`, `last_seen`, `count`, `module`, `module_version`, `exception`, `process`, `reason`

**Also at top level:** `unattributed_evidence[]` and `collection_errors[]`.

## UI

- The "ПРОВЕРКА ДРАЙВЕРОВ" card sits in the left column, between the stages card and the result card. Its geometry is in UI_VISUAL_MASTER.md §12.
- "Подробнее" opens the full list: every audited driver with its fields, reasons and evidence, plus a re-run button.
