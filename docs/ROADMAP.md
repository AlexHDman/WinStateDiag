# Roadmap

WinStateDiag v0.4.0 is feature-complete and frozen.

Future work is limited to:
- confirmed bugs (see `KNOWN_BUGS.md`);
- compatibility fixes;
- validated user feedback.

Out of scope for WinStateDiag: repair or recovery functionality, Windows Server, x86, Linux/macOS, installer, telemetry, auto-updater.

The machine-readable `manifest.json` in every report is designed so that separate tools can consume WinStateDiag reports in the future; no such integration is part of WinStateDiag today.
