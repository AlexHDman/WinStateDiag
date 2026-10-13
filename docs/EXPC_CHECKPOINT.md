# EXPC Checkpoint — WinStateDiag

Protocol: `C:\AI\EXPC_DEVELOPMENT_PROTOCOL.md` (v1.2). Project-specific safety / release contract (`scripts/release/`, fail-closed gate) overrides it.

## Current checkpoint — MICROFIX 01 FINAL VALIDATION (2026-10-13)

| Field | Value |
|---|---|
| Status / stage / state | **PARTIAL**; stabilization; validation stopped at environment blockers; no further implementation |
| Task mode / agent / environment | Final validation only; Codex / GPT-6 family (exact variant/effort not exposed); Windows, HEADLESS/BACKGROUND |
| Branch@SHA | `fix/v1.1-live-polish` @ `b74cece932d5fd6d39e99faedfbc9c0c2346ea6e` |
| Git / concurrency | Clean before checks; no parallel Cargo/Rust/test processes before or after sequential checks. Only this checkpoint is modified by final validation. |
| GitHub remote | **NOT VERIFIED**: `git ls-remote` cannot connect to `github.com:443`. Local `origin/fix/v1.1-live-polish` equals HEAD, but this does not verify current server state. No blind push. |
| CIM | **NOT VERIFIED**: current process belongs to `CodexSandboxUsers`, Medium integrity, administrator role disabled. `Winmgmt` is Running. Independent CIM and WMI reads both return access denied; CIM reports `0x80041003`. Evidence identifies current process/environment access denial; WMI corruption and a requirement for elevation are not established. No unrestricted-user comparison, UAC, ACL/service/system changes. |
| CLI TESTS | `cargo fmt --check`: PASS; `cargo check --all-targets --offline`: PASS; `cargo test --offline`: exit 101, **640 passed / 1 failed**, `passport::tests::collector_runs` lacks CIM data. That environment-dependent acceptance is **NOT VERIFIED**; full suite is not PASS. |
| MICROFIX 01 / OFFSCREEN QA | Existing `app::v11_tests`: **36/36 PASS**, including native repeated callbacks, every Passport card and Copy, scroll/resize/footer and other Details windows. Headless native-callback fixtures only; GPU capture NOT RUN. No demonstrated Microfix defect; source/design/collector unchanged. |
| BUILD | `cargo build --release --offline`: PASS. `target\release\win_state_diag.exe`, 17,334,784 bytes, SHA256 `9141FE28EB5C85DAC3BA4C1704EA7C846E7C9129E1F6E50DDDD86659ADCCD4BE`. Existing dist SHA256 remains `F3E7A10DE4BA49034F6850496DBEDA4E1888FCDB174FE236B3185265C6FD10EA`. |
| LIVE GUI | **NOT RUN**; not implied by regression PASS |
| Evidence | `target/microfix01-final-20261013T180025/` contains diagnostic summary and individual command logs. Historical implementation checkpoint retained below. |
| Commit / push | **BLOCKED** for this checkpoint: session permission profile makes `.git` read-only; GitHub is also unreachable. No new commit/push/merge/tag/release. |
| Remaining blockers / next action | Authorized environment with CIM and GitHub access is required to verify the collector and current remote HEAD, then commit/push this checkpoint only to `fix/v1.1-live-polish`. Physical GUI remains a separate acceptance step. STOP. |

## Historical implementation checkpoint (retained unchanged)

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
