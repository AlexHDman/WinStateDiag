# EXPC Checkpoint — WinStateDiag

Protocol: `C:\AI\EXPC_DEVELOPMENT_PROTOCOL.md` (v1.1). Project-specific safety / release contract (`scripts/release/`, fail-closed gate) overrides it.

| Field | Value |
|---|---|
| Project | WinStateDiag v1.0 RC |
| Task | Startup Idle / Client Identity microfix |
| Agent / Model / Effort / Environment | Claude Code Terminal / Opus 5.5 / headless, Windows 11 (MSI) |
| Phase | Implemented on `fix/v1.0-startup-idle`, PR → `main`; next: release gate on the merge HEAD |
| Branch@SHA | base `main@92b754a` (last gate PASS: dist SHA256 `2A8052A2…8E8B`) |
| Completed | Launch:<br>• no collector / subprocess / report / session (IDLE «Ожидание запуска»)<br>• the disk selector is filled in the background, write-free<br>• start-up log → `Reports\Logs`<br>Start:<br>• freezes Client/Computer + unique SessionId<br>• own folder/ZIP per session<br>• manifest `session { session_id, client_name }`<br>Modules:<br>• explicit modules start only themselves and report into the session they started in<br>Independent PR review (Codex, gpt-6-astra):<br>• round 1 FAIL (6 findings)<br>• round 2 FAIL (N1–N4 concurrency cases)<br>• all fixed with regression tests |
| Tests / Gate | `cargo fmt --check`, `check --all-targets`, `test` 589/589, `build --release` PASS (branch). Gate: pending on the merge HEAD (`scripts\release\release_gate.cmd <sha>`) |
| Artifact / version / SHA256 | pending gate (`dist\WinStateDiag-v1.0\WinStateDiag.exe`); previous RC `2A8052A2E5447B0ECB5F595630045344322CECFD51285B3D8ECF0663D6588E8B` is backed up in `release-evidence\v1.0\superseded\` by the gate |
| Open blockers | Live acceptance NOT RUN: MSI interactive GUI / DPI check of the idle start, GALINA-HOME live checklist |
| Next action | Gate PASS on the merge HEAD → MSI + GALINA live acceptance (user-scheduled). No tag / GitHub Release without approval |
