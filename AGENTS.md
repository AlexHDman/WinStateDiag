# WinStateDiag contributor instructions
Preserve the existing diagnostic architecture and read-only defaults. Repair requires explicit user confirmation. Do not run repair, hardware stress or interactive desktop tests as incidental validation.
Use fmt, check, clippy, Rust tests and PowerShell regression tests for scoped changes. Keep LIVE acceptance distinct from automated evidence.
Publish only synthetic/anonymized fixtures. Never commit customer reports, local logs, credentials or generated binaries. Existing releases and user data must be preserved. No force push or history rewrite without explicit authorization.
