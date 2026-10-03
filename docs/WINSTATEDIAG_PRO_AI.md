# WinStateDiag Pro — AI Analysis (design, not implemented)

Status: **architecture document only.** WinStateDiag v0.4.2 contains no AI code. It has no network calls, provider SDKs, API keys or authentication.

## 1. Product split

| | WinStateDiag (current, free) | WinStateDiag Pro (future) |
|---|---|---|
| Role | Diagnostic **producer**. It is read-only and never repairs anything. | Adds **AI interpretation** of an existing diagnostic package. |
| Output | A verified cumulative ZIP plus `manifest.json` (schema 1.0). | A structured technical analysis of that ZIP. |
| Network | None required. | Only for the provider the user explicitly selects. |

Collecting diagnostics never depends on the internet or on any AI provider. The ZIP and its `manifest.json` are the source artifact. AI analysis is a separate layer that reads them.

## 2. Data flow

```
WinStateDiag diagnostics
    → verified ZIP + manifest.json            (unchanged, offline)
    → AI Analysis layer                       (Pro)
        ├─ builds the analysis payload from the manifest and selected evidence
        ├─ shows the user exactly what will be sent, and to whom
        └─ the user confirms
    → selected provider (replaceable transport)
    → structured technical analysis           (saved next to the ZIP, never inside it)
```

- The provider is a **replaceable transport**. Prompting and payload rules belong to the Analysis layer, not to a provider.
- The payload is built from `manifest.json`. The manifest already records each module's evidence files, `latest_evidence` (the current run on a same-day repeated package) and the SFC/DISM/CHKDSK result states. Full evidence files are attached only when the user chooses them.
- The repository's `AI_ANALYSIS_PROMPT.md` is the current manual prompt. It is the starting point for the Analysis layer's prompt.

## 3. Providers: two levels, no hard-coded list

Providers are **data** (a preset registry plus user-defined entries), not code paths. Adding one must not change the Analysis layer.

### Level 1: presets

| Preset | Notes |
|---|---|
| ChatGPT / OpenAI | OpenAI API |
| Claude | Anthropic API |
| Gemini | Google Gemini API |
| Grok | xAI API |
| DeepSeek | DeepSeek API |
| Qwen | Alibaba Cloud Model Studio API |
| YandexGPT | **Yandex Cloud Foundation Models API (YandexGPT)**, not the consumer Alice interface |

A preset is only a pre-filled provider definition, holding the endpoint, API style, default model and auth scheme. The user can edit or remove it.

### Level 2: custom provider

A custom AI URL pointing to an OpenAI-compatible endpoint.

| Field | Meaning |
|---|---|
| Endpoint URL | Base URL of an OpenAI-compatible API |
| Model | Model name as the server expects it |
| API key / auth reference | A **reference** to a protected secret (see §4), never the key itself in settings |
| Optional settings | Extra headers, timeouts, context limit, organisation/project ids, if needed later |

This covers future use with **Ollama**, **LM Studio** and other OpenAI-compatible local or remote servers. None of these integrations, and no dependency on them, exists in v0.4.2.

## 4. Security contract (mandatory for any future implementation)

1. **API keys must never appear in:**
   - the diagnostic ZIP;
   - `manifest.json`;
   - the session journal and saved journal logs;
   - copied or saved diagnostic text (Copy/Save issues, EXPC results);
   - crash or other evidence;
   - screenshots of the UI (keys are always masked);
   - the Git repository or any committed configuration file.
2. **Storage:** keys are stored only in protected, Windows-local, per-user storage, such as DPAPI-protected data or Windows Credential Manager. The final choice requires research before implementation. Settings files hold only a reference or alias.
3. **No silent upload:** nothing leaves the PC without an explicit user action. Before sending, the user sees:
   - the provider name;
   - the endpoint host;
   - the exact payload, which is inspectable and can be copied.
4. **Least data:** the default payload is the manifest plus a summary. Raw evidence files, hardware serial numbers and client or computer names are sent only if the user opts in.
5. **Diagnostics stay read-only and offline.** The AI layer cannot trigger repair actions.

## 5. Future WinRepair Pro handoff (design only)

```
WinStateDiag  → verified ZIP + manifest.json  → WinRepair Pro → interpretation / proposed repair / repair execution
(producer)                                       (consumer)
```

- WinStateDiag remains the **diagnostic producer**. Repair actions belong only to WinRepair Pro. WinStateDiag shows repair commands as text and never executes them.
- WinRepair Pro should eventually **prefer a fresh, compatible WinStateDiag package** over immediately rescanning the whole PC. It decides compatibility and freshness from `manifest.json`:
  - `schema_version`;
  - `producer_version`;
  - `created_at`;
  - `computer_name`;
  - `windows.build`;
  - per-module `latest_evidence`.
- **Existing WinRepair scanners are not removed.** Research on multiple real PCs must first establish which scanners WinStateDiag evidence can replace. Others must stay as fallback or live verification, for example re-checking right before and after a repair. Fallback scanners remain until proven redundant.
- WinRepair Pro is not modified by WinStateDiag work.

## 6. Out of scope until separately approved

- Any network code, SDK or provider authentication.
- Storing API keys.
- Ollama or LM Studio dependencies.
- Integration with WinRepair Pro.
