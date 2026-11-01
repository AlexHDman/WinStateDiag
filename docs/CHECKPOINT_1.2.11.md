# Working checkpoint 1.2.11

Owner-approved working control point, with known limitations. Subsequent fixes belong to a later version.

Preserved Windows control artifact: `dist/WinStateDiag-v1.2.11/WinStateDiag.exe`.
SHA256: `C942CDD9CA68742C3658FD12A130296E8BC430DDD0F2D7249AA230DA7622306E`.
Version metadata: 1.2.11 / numeric 1.2.11.0. The binary is retained locally, not uploaded or rebuilt for publication.

The source snapshot preserves diagnostic behavior. Publication-only differences are anonymized test/visual-reference examples, synthetic regression fixtures, public documentation and repository hygiene. The preserved EXE was built before these non-diagnostic substitutions; byte identity of a newly built EXE from this public tree is not claimed.

Recorded original validation: 780 passed / 0 failed / 2 ignored; 10 PowerShell suites; fmt/check/clippy exit0 (warnings remain); repeated release build hash identical; local Defender scan found no threats. No repair commands were executed during development.

Native GUI/UAC, actual SFC/DISM repairs, boot-time CHKDSK and post-reboot verification require owner-controlled acceptance. A scheduled CHKDSK is REBOOT_REQUIRED, not completed repair. After reboot run diagnostics explicitly. No automatic reboot or startup repair.

This publication is an independent root history. It does not rewrite or replace existing local/remote branches or tags and does not create a GitHub Release.

Publication validation (2026-11-02): anonymized tree passes 780 Rust tests (0 failed, 2 ignored), all 10 PowerShell suites, fmt/check/clippy (warnings retained). No release binary was rebuilt. Synthetic examples and resource images were reviewed; required third-party copyright/author notices are retained.
