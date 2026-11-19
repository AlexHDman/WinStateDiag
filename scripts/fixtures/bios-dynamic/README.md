# Dynamic BIOS provider evidence

Retrieved on 2026-11-15 UTC (local testing continued 2026-11-16). See sources.json for official request/final URLs, response hashes and retrieval records. These are public manufacturer responses, not client reports.

- MSI: PRO Z890-P WIFI and B450 TOMAHAWK MAX, unchanged JSON catalogues.
- ASUS: TUF GAMING B550-PLUS and PRIME B660M-K D4, unchanged JSON plus exact title elements extracted from official support HTML.
- Gigabyte: full product index; X570 AORUS ELITE and B550 AORUS ELITE V2 catalogues; exact page titles for B550 and B760M DS3H DDR4. HTML numeric entities are retained.
- ASRock: only a sanitized structural excerpt of the actual access-challenge response. No successful catalogue was obtained. Synthetic successful markup in bios_dynamic_tests.rs verifies the contract, not real site compatibility or hardware acceptance.

The previous five model fixtures remain regression cases. Their MSI status objects were restored from the corresponding preserved official responses; these fixtures otherwise retain their original extracted fields.

Some raw research records contain an overbroad `challenge` heuristic (a page mentioning CAPTCHA). That heuristic is not a success/failure classification. Production detects the actual challenge response and verifies exact page/API content.

Live network checks use bios_net and are opt-in. Replay fixtures are never LIVE acceptance. No firmware is downloaded or executed by the implementation/tests.
