# EXPC Backlog — WinStateDiag

Planned / observed only; nothing here is done unless `docs/EXPC_CHECKPOINT.md` says so.

| Priority | Item | Evidence / note |
|---|---|---|
| P2 | SSD/NVMe selector enumeration still runs at launch (in-process IOCTL; writes and deletes a `.wsd_write_probe.tmp` on each fixed volume to test writability) | `storage_topology::windows_source::probe_writable`. Not a diagnostic collection; could become lazy (on Benchmark) if a strictly write-free launch is required |
| P3 | A UI-thread module that is still running when the user starts a separate module with a changed Client contributes to the newer session | `begin_operation`: engine / Hardware view keep their own package; sensors / GPO / crash / ATA contribute to the current package on completion |
| P3 | `MAX_LISTED_INCIDENTS` unused (compiler warning) | `src/incidents.rs:473` |
| P3 | Repository pointer to the EXPC protocol in `CLAUDE.md` / `AGENTS.md` (protocol §7) | not added in the microfix (scope) |
