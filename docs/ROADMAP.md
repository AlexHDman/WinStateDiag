# Current owner-authorized scope — WinDiag 1.6

Repair C1–C7 is the active implementation/acceptance scope, superseding the historical repair exclusion below. PowerLab/PawnIO/LHM changes are out of scope; their delivered 1.5 implementation is preserved. See REPAIR_1_6.md for supported operations and limitations. No merge/tag/Release is authorized. Owner LIVE acceptance follows automated validation.

---

# Roadmap

WinStateDiag v0.4.0 is feature-complete and frozen.

Future work is limited to:
- confirmed bugs (see `KNOWN_BUGS.md`);
- compatibility fixes;
- validated user feedback.

Out of scope for WinStateDiag: repair or recovery functionality, Windows Server, x86, Linux/macOS, installer, telemetry, auto-updater.

The machine-readable `manifest.json` in every report is designed so that separate tools can consume WinStateDiag reports in the future; no such integration is part of WinStateDiag today.

## Development order after v1.1 (recorded 2026-10-19)

v1.1 RC → PowerLab → RAM Health → v2.0 → page C → v3.0.

- **Page C**: a third page for deep diagnostic modules, planned after v2.0 only.
  - v1.1 has two pages (A «ДИАГНОСТИКА», B «ОБОРУДОВАНИЕ»; see `docs/UI_CONTRACT_V1_1.md`).
  - Nothing moves to page C before it exists.
  - The network module is deferred.
- **PowerLab** stays a separate research branch/worktree. This roadmap is not permission to integrate it into the v1.1 RC.
