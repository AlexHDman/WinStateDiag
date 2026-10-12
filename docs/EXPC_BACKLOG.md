# EXPC Backlog — WinStateDiag

Planned / observed only; nothing here is done unless `docs/EXPC_CHECKPOINT.md` says so.

| Priority | Item | Evidence / note |
|---|---|---|
| P3 | The startup-log snapshot is not refreshed within a session whose folder already holds a copy, if `Reports\Logs\startup_graphics.log` was rotated (it no longer continues the copy) | `SessionPackage::attach_startup_log`; new sessions get their own folder, so this only affects one long session. From the PR #1 independent review (non-blocking) |
| P3 | Older session packages that receive late evidence are finalized only while a module still references them (`op_packages`) | `finalize_report_if_idle`; their ZIP is always valid, only loose files could remain |
| P3 | `MAX_LISTED_INCIDENTS` unused (compiler warning) | `src/incidents.rs:473` |
| P3 | Repository pointer to the EXPC protocol in `CLAUDE.md` / `AGENTS.md` (protocol §7) | not added in the microfix (scope) |
