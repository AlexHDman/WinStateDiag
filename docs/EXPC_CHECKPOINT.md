# EXPC Checkpoint — WinStateDiag

Protocol: `C:\AI\EXPC_DEVELOPMENT_PROTOCOL.md` (v1.2). Project-specific safety / release contract (`scripts/release/`, fail-closed gate) overrides it.

| Field | Value |
|---|---|
| Project | WinStateDiag v1.0 RC |
| Lifecycle stage / development state | stabilization (v1.0 RC) / active (user-ordered evidence-fix task) |
| Task mode | implement (evidence fixes) + research (power telemetry) |
| Task | Evidence Fix + Power Telemetry Research |
| Agent / Model / Effort / Environment | Claude Code Terminal / Opus 5.5 / headless, Windows 11 (MSI PRO Z890-P) |
| Phase | Implemented on `fix/v1.0-evidence-power-research` → PR → independent Codex review → merge → clean-HEAD gate |
| Branch@SHA | base `main@a3d99a3` (last gate PASS: dist SHA256 `6D9BC061…53C3`) |
| Completed | **Fixes:**<br>• NVMe history: STABLE without a previous completed session → FIRST_COMPLETED / NO_BASELINE<br>• LiveKernelReports: per-object identity, kind from path, session<br>• Application Summary: identity from EventData / WER / .NET; unknown events not merged<br>• CryptoPro: read-only startup inventory (registry only)<br>**Research:** power telemetry (`research/power_telemetry/`). Native EMI RAPL gives CPU package power on MSI; the Power Backend is NOT in production (awaiting approval) |
| Tests / Gate | `cargo fmt`, `check --all-targets`, `test` 599/599 PASS (branch); gate pending on the merge HEAD |
| Artifact / version / SHA256 | pending gate (`dist\WinStateDiag-v1.0\WinStateDiag.exe`) |
| Open blockers | CryptoPro licence term: no documented read-only source on Windows (reported НЕ ОПРЕДЕЛЁН). EMI power reference comparison vs HWiNFO NOT RUN. Live acceptance NOT RUN: MSI GUI, GALINA-HOME |
| Next action | Gate PASS on the merge HEAD → MSI full live diagnostic ZIP review. No tag / GitHub Release without approval |
