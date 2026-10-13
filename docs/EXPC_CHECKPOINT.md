# EXPC Checkpoint — WinStateDiag

Protocol: `C:\AI\EXPC_DEVELOPMENT_PROTOCOL.md` (v1.2). Project-specific safety / release contract (`scripts/release/`, fail-closed gate) overrides it.

| Field | Value |
|---|---|
| Project | WinStateDiag v1.1 |
| Lifecycle stage / development state | release preparation (v1.1 candidate) / active (user-ordered final integration) |
| Task mode | implement → test → release gate (no tag / GitHub Release) |
| Task | v1.1 Final Integration |
| Agent / Model / Effort / Environment | Claude Code Terminal / Opus 5.5 / High / headless, Windows 11 (MSI PRO Z890-P) |
| Phase | `feature/v1.1-final-integration` → PR → independent Codex review → merge → clean-HEAD gate |
| Branch@SHA | base `main@da06df0` (v1.0 RC gate PASS: dist SHA256 `A3172CE8…6482`) |
| Completed | **Code:**<br>• startup preflight with origin / time<br>• app-close cancellation<br>• CryptoPro card / Details / confirmed ReHash<br>• Driver Audit «Проверка» + check history<br>• Hardware Passport 2.0<br>• crash parser / labels polish<br>• version 1.1<br>**QA:**<br>• offscreen QA scenes RU / EN / DPI 100–150 % rendered and reviewed (OFFSCREEN QA, not a live GUI pass)<br>**Old builds:** v0.4.5 and v1.0 `A3172CE8…`, superseded `6D9BC061` / `2A8052A2` / `846859E2` / `5BCB30DF` preserved |
| Tests / Gate | `cargo fmt --check`, `check --all-targets`, `test` 637/637, `build --release` (branch). Gate pending on the merge HEAD |
| Artifact / version / SHA256 | pending gate (`dist\WinStateDiag-v1.1\WinStateDiag.exe`) |
| Open blockers | LIVE GUI NOT RUN (MSI desktop gate, DPI on a real monitor). GALINA-HOME live NOT RUN. CryptoPro licence term NOT DETERMINED (no read-only Windows source) |
| Next action | MSI + GALINA-HOME live check of v1.1, then a decision on the GitHub Release. No tag / Release without approval |
