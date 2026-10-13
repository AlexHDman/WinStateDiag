# EXPC Backlog — WinStateDiag

Planned / observed only; nothing here is done unless `docs/EXPC_CHECKPOINT.md` says so.

| Priority | Item | Evidence / note |
|---|---|---|
| P3 | The startup-log snapshot is not refreshed within a session whose folder already holds a copy, if `Reports\Logs\startup_graphics.log` was rotated (it no longer continues the copy) | `SessionPackage::attach_startup_log`; new sessions get their own folder, so this only affects one long session. From the PR #1 independent review (non-blocking) |
| P3 | Older session packages that receive late evidence are finalized only while a module still references them (`op_packages`) | `finalize_report_if_idle`; their ZIP is always valid, only loose files could remain |
| P3 | Timing-sensitive test `graphics_startup::tests::normal_controlled_failure_tries_safe` (80 ms deadline in the fake-child harness) failed once under full-suite load on 2026-10-13, then passed 5/5 alone and 3/3 full runs | pre-existing harness, unchanged by the Startup Idle fix |
| P3 | Repository pointer to the EXPC protocol in `CLAUDE.md` / `AGENTS.md` (protocol §7) | not added in the microfix (scope) |
| P2 (awaiting approval) | Power Backend: Windows EMI (CPU package / cores / iGPU power), PDH load, NVML GPU power | `research/power_telemetry/POWER_TELEMETRY_RESEARCH.md` §7–8. Needs:<br>• the user's decision<br>• an EMI vs HWiNFO reference comparison on MSI (HWiNFO run by the user)<br>• one AMD + one laptop live pass |
| P3 | CryptoPro licence term (expiry) | No documented read-only Windows source; reported НЕ ОПРЕДЕЛЁН. Candidate: CSP `PP_LICENSE` provider param (value / format undocumented publicly) — needs CryptoPro SDK documentation |
| INFO (user's system) | MSI: MSI Center loaded `MsIo64.sys` + `NTIOLib_X64.sys` (2 services) — driver families with public CVEs; installed versions not verified | power probe 2026-10-13 security observation; WinStateDiag never uses them. Not a WinStateDiag defect |
| P3 | EN UI: Driver Audit evidence linked from a crash dump is Russian text («дамп BSOD … указывает модуль …») | `crash_dump` → Driver Audit link reason (pre-v1.1); seen in the v1.1 driver-details EN render |
| P3 | Live GUI acceptance of v1.1 (MSI desktop, real 125 / 150 % DPI, resize of the Passport 2.0 window, ⟳ / ReHash flows on a NO HASH machine) | offscreen QA only so far (protocol §6: NIGHT GUI GATE / user-scheduled) |
| P3 | Hardware-Report WinForms viewer code stays in the embedded script (not shown since v1.1) | `embedded/Hardware-Report/Hardware-Diagnostic.ps1` `-WsdViewer` reply `SKIP`; remove in a later cleanup |
| P1 — automated fix verified, live pending | Hardware Passport cards disappear after initial rendering while Copy still contains the data | User live observation on v1.1. MICROFIX 01 reproduces the native `FnOnce` / `add.take()` multi-pass failure, replaces it with replayable `FnMut` and retains actions between passes. Full suite 641/641; real GUI acceptance of the microfix NOT RUN. See checkpoint for build hash. |
| CLOSED (automated coverage) | Passport 2.0 minimum-size coverage previously rendered only the footer | MICROFIX 01 adds full native-callback window rendering, scroll input, repeated passes and resize down to 420×300, checking footer bounds and all card values after resize. This does not claim physical DPI / desktop acceptance. |
