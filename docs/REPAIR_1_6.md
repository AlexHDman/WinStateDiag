# WinDiag 1.6 Repair

STATUS: implementation candidate; owner LIVE acceptance pending.

Opening Repair and reading history do not execute a repair. Each modifying action requires a selected, current plan and explicit confirmation. The global servicing mutex and GUI interlock block conflicting work. Read-only workers may be cancelled; servicing is not force-killed on elapsed time. No automatic reboot.

| Block | Implemented | Limits / acceptance |
|---|---|---|
| C1 Windows | Existing contextual DISM/SFC engine, individual or combined plan, source selection, verification and dependent-step gate | Real recovery and UAC are owner LIVE gates |
| C2 Update | Error/service inventory, preservation of update evidence, selected Download-cache rename, original service-state restoration | No universal policy/ACL/service reset; next update success remains unverified |
| C3 Volumes | Exact local NTFS volume selection, read-only CHKDSK, explicitly planned spotfix and follow-up check | No /r, forced dismount or automatic scheduling/reboot; hardware failure is not repaired |
| C4 Maintenance | Bounded category analysis, component analysis/cleanup, per-file verified thumbnail DB cleanup | Other temp/browser/developer/WER/dump/recycle/recovery categories are analysis-only. Windows.old/recovery deletion is unavailable; no bulk delete |
| C5 Programs | Registry inventory without Installer-provider side effects, selected signed local MSI metadata and hash, install/repair/remove, exact product/context revalidation, Intel Chipset selection | Unsigned/network/reparse/hardlink packages and EXE/Store operations are blocked. Damaged registration may require the original matching signed MSI. No registry surgery or DriverStore removal |
| C6 Execution | Plan preview/confirmation, stale-plan/object checks, rights/busy/reboot preflight, real exit codes, busy indicator/time and durable stdout/stderr logs | Actual Windows/UAC behaviour requires isolated/user LIVE. Long servicing waits rather than unsafe forced termination |
| C7 History | Per-computer persistent records, inclusion in diagnostic/AI packages, bounded CRC-checked report comparison | Missing/different computer, schema or hardware fingerprint blocks comparison. Status changes are not proof of a physical repair |

The existing violet AI action and secondary report folder are retained. AI export uses completed saved evidence without a rescan, never overwrites the source ZIP and writes a verified UTF-8 text package in AI.zip.

## Microsoft diagnostic CAB

The supplied CAB hash and Microsoft Authenticode signature were verified locally. Its package manifest is 1.3 and requires the Windows Troubleshooting Platform, elevation and interaction; its scripts can alter Installer registration/files and service parameters. Legacy MSDT compatibility with current Windows is not established. The package and its old removal code are not redistributed or executed. Supported MSI mechanisms work independently.

Primary references: [MSI command-line options](https://learn.microsoft.com/en-us/windows/win32/msi/command-line-options), [MSI error codes](https://learn.microsoft.com/en-us/windows/win32/msi/error-codes), [Windows Update troubleshooting](https://learn.microsoft.com/en-us/troubleshoot/windows-client/installing-updates-features-roles/additional-resources-for-windows-update), [MSDT retirement](https://support.microsoft.com/en-us/windows/experience/deprecation-of-microsoft-support-diagnostic-tool-msdt-and-msdt-troubleshooters).

## Validation

Rust unit/integration, PowerShell AST-isolated/mock scenarios, a harmless native fixture process and handle-based cleanup of self-created fixture files are separate from real Windows repair. No working Windows repair, application installation/removal, real cache deletion, service change or interactive GUI/UAC was performed for development acceptance.

Owner acceptance: inspect header/page C at normal DPI; complete ordinary/full diagnostics; review a plan without launching it; then use an isolated machine/VM for DISM/SFC, volume, Update and disposable MSI scenarios. Check source/result logs, reboot/partial/error states, same-machine history, mismatch rejection and repeated AI.zip while retaining original archives. Stop if unrelated data changes.
