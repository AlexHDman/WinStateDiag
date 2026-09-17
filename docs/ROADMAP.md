# Roadmap

WinStateDiag stays a small, portable, read-only diagnostic utility. No scope expansion is planned beyond the items below.

## Near term
- Finish the Rust orchestration layer around the existing PowerShell diagnostic engine.
- Automatic ZIP report assembly in `Reports\<date>\<session>.zip`.
- Package Hardware Report JSON into the diagnostic ZIP automatically.
- Ship `WinStateDiag.exe` as the single portable entry point.

## Planned, not implemented
- Optional AI Analysis module with pluggable providers: ChatGPT, Claude, Gemini, Grok, DeepSeek, Qwen, local AI, custom.
  Possible future connection methods: browser/account authorization (where a provider officially allows it), API, local AI endpoint, custom provider.
  Not implemented, not researched, no SDKs added at this stage.

## Out of scope
- Repair / recovery functionality.
- Windows Server, x86, Linux/macOS support.
- Web server, database, telemetry, auto-updater, installer, CI/CD.
