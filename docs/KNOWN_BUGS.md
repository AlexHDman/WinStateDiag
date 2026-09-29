# WinStateDiag — Known bugs

## BUG: incomplete RAM / DIMM detection on X79G

- **Status:** OPEN. Confirmed on a real client PC. Audit done 2026-09-24; not fixed yet.
- **Module:** Hardware Diagnostics (Hardware Report).
- **Severity:** wrong data in the report. This is not a hardware fault.

### Reproduction (real client PC)

| | Actual | WinStateDiag Hardware Diagnostics |
|---|---|---|
| Board / CPU | X79G, Intel Xeon E5-2650 v2 | — |
| RAM installed | 16 GB (4 × 4 GB DDR3-1600 ECC Registered, Samsung M393B5170GB0-CK0 in DIMM-A1, A2, B1, B2) | **8 GB** |
| Modules | 4 | **2 modules** |
| Windows | ~15.9 GB usable / 16 GB installed | — |
| AIDA64 | all 4 × 4 GB modules | — |

### Audit: where RAM detection lives

Hardware Diagnostics is the embedded PowerShell baseline. `src/engine.rs` embeds it byte-for-byte with `include_bytes!` and runs it as `Hardware-Diagnostic.ps1 -NoGui -ExportAll`. The Rust GUI does not compute or show RAM.

| What | File / function | How it works now |
|---|---|---|
| Raw collection | `embedded/Hardware-Report/HardwarePassport.psm1` → `Get-HardwareSource` | `MemoryModules = Win32_PhysicalMemory`, `MemoryArrays = Win32_PhysicalMemoryArray`, `System = Win32_ComputerSystem` (read, but not used for RAM). |
| CIM/WMI access | `embedded/WinStateDiag/Compatibility.psm1` → `Get-CompatInstance` | `Get-CimInstance`; if that throws, `Get-WmiObject` on the same class. There is no other RAM source or fallback: no SMBIOS raw table, no `GetPhysicallyInstalledSystemMemory`, no `TotalPhysicalMemory`. |
| DIMM rows | `HardwarePassport.psm1` → `New-HardwarePassport`, `$ramRows` | One row per `Win32_PhysicalMemory` instance, 1:1. No filtering, deduplication or dropping. |
| **Total RAM** | `New-HardwarePassport`, `Ram.TotalBytes` / `Ram.Total` | `SUM(Win32_PhysicalMemory.Capacity)`. Nothing else. |
| **DIMM count** | `New-HardwarePassport`, `Ram.ModuleCount` | `$ramRows.Count`, which is the number of `Win32_PhysicalMemory` instances. |
| Slots | `Ram.DeclaredSlots` | `SUM(Win32_PhysicalMemoryArray.MemoryDevices)`. Shown only; never compared with ModuleCount. |
| RAM state | `$ramState` | UNKNOWN when there are no rows; WARNING for mixed capacities or speeds, or underclocking; INFO/OK otherwise. An incomplete inventory is not detected. |
| Output: TXT | `Hardware-Diagnostic.ps1` → `New-HardwareReportLines` (lines 41, 72–77) | `RAM: <Total>, <ModuleCount> module(s)` and a `[RAM]` section. |
| Output: JSON | `Save-HardwareReport` JSON | Passport `ConvertTo-Json`. |
| Output: HTML | `Save-HardwareReport` HTML | Built from the same passport (`New-HardwareReportLines`). |
| Output: Viewer GUI | `Get-HardwareOverviewValues` (line 214); `Update-HardwareGui` RAM grid and footer (lines 241–242) | `Ram="<Total> …<ModuleCount> модулей"`, `Total installed: <Total> … Detected: <ModuleCount>`. |
| Output: console | line 352 | `RAM: …; N module(s)`. |

`EXPC-Diagnostic.ps1` step 1 uses a different source, `Win32_ComputerSystem.TotalPhysicalMemory` (`RAM_GB`). So on that PC the EXPC report should show about 16 GB while Hardware Diagnostics shows 8 GB.

### Audit conclusion

- "8 GB / 2 modules" is produced by `New-HardwarePassport` from exactly **two `Win32_PhysicalMemory` instances**. The processing maps instances 1:1. No code path can turn 4 returned instances into 2.
- Therefore WMI/CIM `Win32_PhysicalMemory` returned only 2 modules on this PC. This class is populated from SMBIOS Type 17 (Memory Device). AIDA64 reads module SPD directly over SMBus, so it sees all 4.
- The most likely root cause is an incomplete SMBIOS Type 17 table in the X79G BIOS. This is known for X79 boards of this class. It is **not yet proven by raw data from that PC**.
- WinStateDiag's own defect: it treats the DIMM inventory as the source of truth for installed RAM. It has no independent total and no completeness check.

### Raw data still to capture on the X79G (read-only)

```powershell
Get-CimInstance Win32_PhysicalMemory | Select BankLabel,DeviceLocator,Capacity,PartNumber,Speed,SMBIOSMemoryType,TypeDetail | Format-Table -Auto
Get-CimInstance Win32_PhysicalMemoryArray | Select MemoryDevices,MaxCapacity,MaxCapacityEx | Format-List
(Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory
Get-CimInstance -Namespace root\wmi MSSmBios_RawSMBiosTables | Select-Object -Expand SMBiosData | Set-Content -Encoding Byte smbios_raw.bin
```

These answer two questions:

1. Does WMI list 2 or 4 instances?
2. How many Type 17 entries does the raw SMBIOS table hold, and with what sizes?

### Minimal fix (next, separate stage)

The fix is in `HardwarePassport.psm1` → `New-HardwarePassport` only. Keep two separate concepts:

- **A. Installed RAM.** Use an independent source: `GetPhysicallyInstalledSystemMemory` (kernel32, SMBIOS-based total, via the existing Add-Type pattern). Fall back to `Win32_ComputerSystem.TotalPhysicalMemory`, which is already collected. Only if both are unavailable, use SUM(DIMMs), labelled as such.
- **B. DIMM inventory.** Keep it as-is from `Win32_PhysicalMemory`: count, slot/bank, capacity, manufacturer, part number, speed, type.
- **New fields:**
  - `InstalledBytes` and `InstalledSource`
  - `EnumeratedDimms` and `EnumeratedBytes`
  - `InventoryComplete`: false when the enumerated sum is materially below the installed total
  - a reason: "DIMM inventory incomplete (firmware/SMBIOS reports N modules)"
- **Rules:**
  - Never invent missing modules.
  - Do not treat an incomplete inventory as a memory fault.
  - RAM state is at most INFO for this case: no WARNING and no FAIL.
- **Outputs:** TXT, HTML, viewer and console read `Ram.Total` (now the installed total) and add "Enumerated DIMMs: N; DIMM inventory: incomplete".
- **Tests:** a Pester/fixture source with 2 × 4 GB DIMMs and TotalPhysicalMemory ≈ 16 GB should give Installed 16 GB, Enumerated 2, incomplete, and no FAIL.
