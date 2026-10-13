# EXPC Checkpoint — WinStateDiag

Protocol: `C:\AI\EXPC_DEVELOPMENT_PROTOCOL.md` (v1.2). Project-specific safety / release contract (`scripts/release/`, fail-closed gate) overrides it.

| Field | Value |
|---|---|
| Project | WinStateDiag v1.1 |
| Lifecycle stage / development state | stabilization / active for the user-authorized MICROFIX 01 only; STOP after this microfix |
| Task mode | implement → regression → build → commit/push to the existing fix branch; no merge/tag/release |
| Task | v1.1 MICROFIX 01 — Hardware Passport render (2026-10-13) |
| Agent / Model / Effort / Environment | Codex / GPT-6 family (exact variant and effort not exposed) / Windows PowerShell, HEADLESS; no desktop interaction |
| Phase | Rendering callback lifecycle fixed and validated; remaining GUI fixes / PR / review / merge / release gate are subsequent work |
| Branch@SHA | `fix/v1.1-live-polish` (microfix commit containing this checkpoint); clean starting HEAD `977d42623436c532e3939fef7caf5a4c4319cdf6`, equal to remote main and fix branch before commit |
| Root cause / reproduction | `detail_window` consumed `FnOnce` through `add.take()`. Native egui can call the renderer again after Grid sizing/discard; the last pass then had no content. Before the fix the native callback regression returned `None` instead of `Some(42)`; the full Passport regression lost «Процессор» on repeated layout. Tests use real egui immediate-viewport/multi-pass APIs without an OS window. |
| Completed | `FnMut` renders every pass. Callback action selections survive subsequent passes and execute once after rendering (Copy/Close/recheck/history). No collector/model/design/layout/assets/version changes. Four new regressions: 12+ renders, all eight cards and values, exact Copy output once per click (RU/EN), scroll/resize including 420×300 and footer bounds, and eight other Details windows with Close across repeated passes. |
| Tests / Gate | CLI TESTS: PASS, `cargo test` **641/641**; targeted v1.1 suite **36/36**. `cargo fmt --check`, `cargo check --all-targets`, `cargo build --release`: PASS. OFFSCREEN QA: GPU captures NOT RUN; headless native-callback regressions PASS. LIVE GUI GATE: NOT RUN. No new release gate; previous gate at `977d426` is PASS (637 tests, original dist hash below), not evidence for this microfix. |
| Artifact / version / SHA256 | Build only: `target\release\win_state_diag.exe`, display/FileVersion/ProductVersion **1.1**, Cargo **1.1.0**, 17,334,784 bytes, SHA256 `9141FE28EB5C85DAC3BA4C1704EA7C846E7C9129E1F6E50DDDD86659ADCCD4BE`. This is not a newly gated dist candidate. |
| Preserved candidate | `dist\WinStateDiag-v1.1\WinStateDiag.exe` unchanged: SHA256 `F3E7A10DE4BA49034F6850496DBEDA4E1888FCDB174FE236B3185265C6FD10EA`; previous gate `release-evidence/v1.1/gate_20261013-142256_977d42623436`. Older dist builds were not touched. |
| Open blockers | Physical Passport/Details acceptance still NOT RUN. Remaining GUI audit findings are outside this microfix. CryptoPro licence term remains NOT DETERMINED. A new exact-HEAD release gate and real required acceptance remain necessary before release. |
| Next action | STOP after authorized commit/push to `fix/v1.1-live-polish`. Next user stage: WinStateDiag v1.1 remaining GUI Fix → PR → Review → Merge → Release Gate. No main update, merge, tag or GitHub Release in MICROFIX 01. |
