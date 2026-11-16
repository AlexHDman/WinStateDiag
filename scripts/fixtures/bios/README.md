# BIOS catalogue fixtures (WinDiag 1.4, 2026-11-15)

Public factual metadata only. No local machine, customer, serial-number or credential data.
The production checker always fetches the current official catalogue; these snapshots are regression inputs, not a bundled latest-version list.

Verified exact profiles:
- MSI PRO H610M-G DDR4 / 7D46 branch 1.
- MSI PRO B760M-A DDR4 / 7D99 branch 1.
- MSI MAG Z790 TOMAHAWK WIFI / 7D91 branch H.
- ASUS PRIME B760-PLUS D4.
- Gigabyte B760M DS3H DDR4, PCB rev. 1.x, official product ID 8701 (not GEN5).

Sources:
- https://www.msi.com/api/v1/product/support/panel?product=PRO-H610M-G-DDR4&type=bios
- https://www.msi.com/api/v1/product/support/panel?product=PRO-B760M-A-DDR4&type=bios
- https://www.msi.com/api/v1/product/support/panel?product=MAG-Z790-TOMAHAWK-WIFI&type=bios
- https://www.asus.com/support/webapi/ProductV2/GetPDBIOS?website=us&model=PRIME%20B760-PLUS%20D4&pdhashedid=&pdid=99999&cpu=&siteID=www&sitelang=
- https://www.gigabyte.com/iisApplicationNuxt/api/proxy/api/v1.0/Support/global/DownloadCenter/2/GetProducts
- https://www.gigabyte.com/iisApplicationNuxt/api/proxy/api/v1.0/Consumer/global/GetProductTabDataAsync/Support/8701

MSI mapping proof: downloaded official ZIPs were inspected without executing firmware or utilities. Family/branch/aliases are scoped to the exact models above; a matching chipset or MS-code alone is insufficient.

| Public package | Firmware member | Readme version | Confirmed short alias | ZIP SHA256 |
|---|---|---|---|---|
| 7D46v1R | E7D46IMS.1R0 | V1.R | 1.R0 | d5fec71c9e5d37d15c88cc7ad0258e1ac0644ac9b9d9473b3cefa9c2e272325f |
| 7D99v1J | E7D99IMS.1J0 | V1.J | 1.J0 | e7aa2bffd5c69719b593d7c4133bb2076e5094fa8af7fced46f15eeeee6db734 |
| 7D91vHI | E7D91IMS.HI0 | V17.I | 17.I0 | 67d806ecd79c422f07e6edaa74e4a7bde57bb44be09d09653662b14b560832d4 |

MSI official package URLs: https://download.msi.com/bos_exe/mb/{public-version}.zip (official download-2.msi.com redirects observed during manual research).
This download host is not used by the runtime metadata checker.

Comparison rules, within the above profiles only: MSI branch plus base-36 revision, numeric prerelease below that stable revision; ASUS four-digit numeric revision; Gigabyte F-number, letter-suffixed preview below the same final number. Stable and explicit beta labels are parsed separately. Unlabelled preview suffixes remain unconfirmed, not asserted stable/beta. Installed version must occur in the fetched catalogue before any update/current verdict. Unknown/newer/different-branch firmware never receives a downgrade recommendation.

Source metadata preserves file version/date/model and package path. Long vendor prose and unrelated products were omitted from test fixtures. Raw source responses and inspected package hashes remain in local release-evidence. Original filenames/case changes in ASUS and both Gigabyte package-name formats are intentional regression cases.

ASRock and OEM/laptop firmware: not implemented without a verified complete, exact-model catalogue. ASRock product pages returned a challenge page to the local reader; a global recent-updates list alone is insufficient to match installed firmware. This is an explicit unsupported state, not a successful empty adapter.
