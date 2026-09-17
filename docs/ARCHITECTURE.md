# WinStateDiag

Portable Windows State Diagnostic Center

## Scope

WinStateDiag is a diagnostic and reporting utility.

It determines and records the current state of a Windows computer.

It does NOT provide:
- Repair
- Recovery
- automatic Windows modification

Those capabilities belong to the separate future WinRepair Pro project.

## Session

Each diagnostic session contains:

Client
- manually entered
- optional

Computer
- detected automatically

Date/time
- detected automatically

## EXPC Diagnostic

The new GUI exposes three modes:

1. SFC + DISM + CHKDSK
2. Deep Diagnostic
3. Full Automatic Diagnostic

The exact implementation of these modes must be mapped from the
existing proven EXPC-Diagnostic PowerShell engine.

Legacy Step-by-Step and Exit menu entries are not exposed in the GUI.

## Hardware Report

Hardware Report is an inventory/passport module.

It is NOT presented as a hardware diagnostic.

User interface:
- concise visual hardware overview
- detailed sections for visual inspection
- View/Open Report action
- normal window X to close

Manual TXT/JSON/HTML export controls are not required.

For machine/AI analysis:

Hardware_Report.json is generated automatically and included
inside the final diagnostic archive.

The JSON export is an internal report artifact and does not need
to be exposed as a normal user control.

## Final workflow

1. Enter client name if required.
2. Computer name is detected automatically.
3. Select diagnostic mode.
4. Run diagnostics.
5. Collect Hardware Report.
6. Create one diagnostic session archive.
7. Display completion status.
8. Open/View Report when required.

## Portable distribution target

WinStateDiag.exe
Reports\

Reports is generated automatically.

No BAT launcher is required in the final release.
No LNK launcher is required in the final release.
No visible PowerShell scripts are required in the final release.

## Migration rule

The proven PowerShell diagnostic engine remains byte-for-byte
unchanged during the first Rust integration stages.

Behavior is migrated only after mapping and regression verification.
