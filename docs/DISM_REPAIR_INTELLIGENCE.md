# DISM / WinSxS Repair Intelligence (v1.0)

WinStateDiag stays **diagnostic and read-only**. It never runs `DISM /RestoreHealth`, `sfc /scannow` or any repair. Repair Intelligence only explains the component-store state for an engineer, and for a future WinRepair Pro.

## Inputs

1. **Current verification.** Stage 12 runs `DISM /Online /Cleanup-Image /ScanHealth` and records its result line:
   - No component store corruption detected;
   - repairable;
   - cannot be repaired.
2. **Historical evidence.** The last 8 MB of `%windir%\Logs\DISM\dism.log` and `%windir%\Logs\CBS\CBS.log`, read **before** this ScanHealth starts:
   - corruption lines: `component store is repairable`, `Corruption detected`, `CSI Corrupt`, `STATUS_SXS_COMPONENT_STORE_CORRUPT`, `0x80073712`;
   - repair lines: `The restore operation completed successfully`, `Repair complete`, `corruption repaired`.
3. **Current-run lines.** The lines appended to dism.log by this run stay a separate, scoped evidence block.

## Verdicts (`Get-DismRepairIntelligence`)

| Verdict | When | Status |
|---|---|---|
| CLEAN | current = clean, no historical corruption | OK |
| HISTORICAL_REPAIRED | current = clean, historical corruption and a later successful repair | INFO: «историческая запись, не текущая проблема» |
| HISTORICAL_ONLY | current = clean, old corruption lines without a recorded repair | INFO |
| CURRENT_CORRUPTION | current run reports corruption, no earlier repair | ATTENTION (repairable) / ERROR (not repairable). Repair is manual only |
| RECURRENT_CORRUPTION | current run reports corruption AND an earlier successful repair exists | ATTENTION: «ПОВТОРНОЕ ПОВРЕЖДЕНИЕ … проверьте накопитель и память»; no advice to simply repeat RestoreHealth |
| UNKNOWN | the result line was not recognised (ERROR if DISM exited non-zero) | UNKNOWN / ERROR |

When stage 12 is not run (deep checks are off by default), the current state is **not verified**. History alone never makes it OK.

## Evidence written

The EXPC TXT log contains:

- the verdict;
- the current result;
- the date of the last historical corruption and of the last repair;
- up to 6 historical CBS / DISM lines;
- the scoped current-run dism.log lines.

The check `DISM` carries the status and the Russian explanation.

## Limits

- Logs older than the 8 MB window, or rotated into `CbsPersist_*.log` / `.cab`, are not read.
- An SFC result is reported by stage 11 separately and is not merged into the DISM verdict.

## Tests

`engine.rs`: `dism_repair_intelligence_separates_current_historical_and_recurrent` covers all six verdicts.
