# WinStateDiag — Visual Master Specification

Status: measured specification used by the fixed-geometry UI (`src/ui/*`).
Master image: `docs/UI_VISUAL_MASTER.png` (the only visual master).
This document is the measured contract. The code tokens in `src/ui/tokens.rs` mirror it one to one.

## 1. Master canvas and coordinate system

| Item | Value |
|---|---|
| Master file | `docs/UI_VISUAL_MASTER.png`, RGB, **W = 1374 px, H = 1145 px** (native pixel size, no DPI metadata) |
| Master content | Full window: 1px outer frame, custom title bar (y 1–36, separator y 37), client area, status bar (separator y 1107, bar y 1108–1143) |
| Client canvas | Master crop `x 1..1372, y 38..1143`, which is **1372 × 1106 px** |
| Canvas origin | Master (1, 38) maps to canvas (0, 0): `canvas = master − (1, 38)` (`tokens::mpos/mrect`) |
| Units | All geometry is in **master pixels**. Rects are given as `x, y, w, h`. A card rect runs from the first border pixel to the last border pixel + 1, and the 1px border is drawn inside it |
| Normalised | `x/W, y/H, w/W, h/H` relative to the full 1374 × 1145 master (table §5) |

## 2. Reference viewport / DPI (VISUAL_REFERENCE mode)

The master has no DPI metadata. **Assumption (explicit):** the master is a 1:1 render at 100 % scale.
The reference target is therefore:

| Parameter | Value |
|---|---|
| Physical reference resolution (client) | 1372 × 1106 px |
| Logical viewport | 1372 × 1106 points |
| egui pixels_per_point | **1.0** (forced) |
| egui zoom factor | `1 / native_pixels_per_point` (e.g. 0.8 on a 125 % display) |
| Window inner size command | `1372/native × 1106/native` winit logical units, so the physical size is 1372 × 1106 |
| Relation | physical px = logical points × pixels_per_point = points × 1.0 |

Mode switch: `win_state_diag.exe --visual-reference --capture <file.png>`. This mode renders the master fixture (`src/ui/fixture.rs`). Its values are QA-only and never appear in a normal launch. The EXE captures its own framebuffer with egui's screenshot command, writes the PNG plus a JSON of the viewport/DPI facts, and exits.
The comparison is valid only for this viewport. Normal mode scales the same canvas uniformly: `ppp = min(phys_w/1372, phys_h/1106)`, clamped at 0.6, below which the canvas scrolls. This preserves proportions with no overlap or clipping.

## 3. Macro grid (measured, border centre-lines)

| Token | Value |
|---|---|
| Outer margin left / right | 17 / 15.4 px |
| Left column | x 18 → 546 (w 528) |
| Right column | x 564 → 1357 (w 793) |
| Column gap | 18 px (18.5 centre-to-centre) |
| Cards top | y 112 (both columns) |
| Vertical card gaps | left 10.2 (median; 10.0–11.9), right 11.6 |
| Card | fill `#071928`, border 1px `#264864`, radius 7, no gradient, no brighter/active variant |
| Card padding (text inset) | left column 20, right column 17. Title baseline 27.3 below card top (right column); 23.5–26.2 (left column, per card) |
| Inner card (Modules) | fill `#0a1b2d`, border `#132a3f`, radius 6 |
| Window background | flat `#000c18` (no gradient) |

Card rects (master px):

| Card | x | y | w | h |
|---|---:|---:|---:|---:|
| CLIENT_COMPUTER | 18 | 112 | 528 | 96 |
| EXPC_DIAGNOSTIC | 18 | 218 | 528 | 121 |
| HARDWARE_REPORT | 18 | 349 | 528 | 95 |
| DIAGNOSTIC_STAGES (master) | 18 | 454 | 528 | 210 |
| DRIVERS (master) | 18 | 674 | 528 | 271 |
| RESULT | 18 | 956 | 528 | 88 |
| START_BUTTON | 113 | 1055 | 339 | 42 |
| OVERALL_PROGRESS | 564 | 112 | 793 | 240 |
| └ MODULES (inner) | 979 | 152 | 362 | 184 |
| CURRENT_OPERATION | 564 | 363 | 793 | 118 |
| SSD_SUMMARY | 564 | 493 | 793 | 290 |
| JOURNAL | 564 | 794 | 793 | 280 |
| STATUS_BAR | 1 | 1108 | 1372 | 36 |

## 4. Component specifications

**Overall ring:** centre (705.3, 246.1). Outer diameter 181, track and active thickness 13, track `#12273d`. Starts at 12 o'clock and sweeps clockwise. Flat start cap, round leading cap. Gradient along the arc: `#0075ff` (0°) → `#007aff` (45°) → `#00befd` (90°) → `#00c6fe` (180°), darkening to `#009cfc` over the last ~18°. Inside: percent 40 px Bold (baseline 257.1), status 16 px Semibold (baseline 285.1). The time block (clock and hourglass icons at x 812/814) sits at text x 854: label baselines 204.5 / 275.5, value baselines 227.1 / 300.4.
**Modules (same card):** title "Модули диагностики" 17 px Semibold at (995, baseline 179.1). Rows at y 193 / 238 / 283, x 993, w 334, h 39, radius 5, fill `#0b1e32` (active row `#0c203b`). Icon centre x 1012.5, label x 1043, status right-aligned at 1314.

**SSD rings (READ and WRITE have identical geometry):** centres (696, 636.6) and (909.6, 636.6), sharing baseline and vertical centre. The outer ring has diameter 196 and stroke 12.5, with a conic gradient: READ `#0072fc→#0283f9(180°)→#00c5ff(270°)→#06a7ff→#0b8ffe`; WRITE `#3bfa6c→#44fb65(90°)→#01f996(150°)→#46fc74(180°)→#4ffa6d(270°)→#1af272`. The inner ring has diameter 153: a thin track of 1.5 px (`#221745` / `#032f34`) plus a bright "previous" arc (stroke 5, 71.8°→292° through the bottom, gradient brighter towards 285°) in violet `#8232ee` / teal `#00b8bb`, which is drawn only when a compatible previous result exists. Text is centred: label baseline 590.2 (19 px Semibold, `#02a0fa` / `#04fba1`), current baseline 635.3 (39 px Semibold, `#028ef7` / `#03f7ae`), previous baseline 674.0 (25.5 px Semibold, `#b23df8` / `#00f8f6`), delta baseline 765.0 (20.5 px Semibold, `#35f67e`). There is no clipping: the canvas margins exceed the stroke extents.
**SSD metadata:** labels at x 1040, values at x 1155. First baseline 553, row pitch 27.9. The Стабильность row has a dot (r 8).
**SSD actions:** primary 1004,730 173×39 (power icon); secondary 1193,729 148×41.

**Progress bars (always continuous, never segmented):**

| Variant | Geometry | Track / border | Fills |
|---|---|---|---|
| Stage | x 300, w 173 (pending 159), h 12, radius 6, row top + 8 | `#0c1f30` / `#204263`; pending `#152e46` / `#345471` | done `#03f97e`, running `#00a5fc`, error `#f04a4c` |
| Current operation (wide) | 580,449 676×18, radius 9 | `#142d44` / `#2e506b` | `#0077fe`; complete `#03f97e` |
| Indeterminate | sliding highlight, 30 % width, 1.7 s cycle | — | same as running |

**Buttons (one family, `paint::button`):**

| Kind | Normal | Hover | Pressed | Disabled | Border | Radius |
|---|---|---|---|---|---|---|
| PRIMARY | `#0071fd` | `#1d86ff` | `#005dd1` | `#16283a`, text `#5d7189` | same as fill | 6 |
| SECONDARY | `#10253b` | `#173350` | `#0b1b2c` | `#16283a` | `#315472` (hover `#3d7bb0`) | 6 |

Main Start button: 339 × 42 at (113, 1055), 19.5 px text with a play icon. SSD primary: 173 × 39, 13.5 px text.

**Stage rows:** first row at y 489, pitch 28.5, row x 37, w 490, h 28. Icon centre row x + 12, Ø 22. Number x 74, label x 105, text baseline row top + 19.2. Percent x 485; "Ожидание" x 468. The active row has fill `#012041`, radius 4.
**Journal:** panel 580,834 762×224, fill `#041321`, border `#10273b`. Monospace 14.3 px (Consolas). First baseline 856, pitch 21.1, timestamp x 589, message x 674. Clear button 1216,804 125×31 with a trash icon.
**Status bar:** separator y 1107 `#243d53`, fill `#010f1c`, text 14.5 px `#bcc3cf` at baseline 1132. Left text at x 18; right segments right-aligned to x 1344, with 1px dividers `#66768a`.

## 5. Component geometry table (absolute master px + normalised)

Measured by the Visual-Measurement agent from line profiles and circle fits; confidence ±0.5 px for edges and ±1 px for font size.

| ID | Parent | X | Y | W | H | x/W | y/H | w/W | h/H | Notes |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| ROOT | — | 0 | 0 | 1374 | 1145 | 0.0000 | 0.0000 | 1.0000 | 1.0000 | fill #000c18; border 1px #233041..#2f3f4d window frame, rounded top corners r~8 |
| TITLE_BAR | ROOT | 1 | 1 | 1372 | 36 | 0.0007 | 0.0009 | 0.9985 | 0.0314 | fill #061827 |
| TITLE_ICON | TITLE_BAR | 20 | 9 | 26 | 21 | 0.0146 | 0.0079 | 0.0189 | 0.0183 |  |
| TITLE_TEXT | TITLE_BAR | 65 | 13 | 170 | 17 | 0.0473 | 0.0114 | 0.1237 | 0.0148 |  |
| TITLE_VERSION | TITLE_BAR | 1164 | 14 | 42 | 13 | 0.8472 | 0.0122 | 0.0306 | 0.0114 |  |
| WIN_MIN | TITLE_BAR | 1241 | 24 | 14 | 2 | 0.9032 | 0.0210 | 0.0102 | 0.0017 |  |
| WIN_MAX | TITLE_BAR | 1287 | 13 | 13 | 14 | 0.9367 | 0.0114 | 0.0095 | 0.0122 |  |
| WIN_CLOSE | TITLE_BAR | 1338 | 14 | 12 | 12 | 0.9738 | 0.0122 | 0.0087 | 0.0105 |  |
| CLIENT_AREA | ROOT | 1 | 39 | 1372 | 1068 | 0.0007 | 0.0341 | 0.9985 | 0.9328 | fill #000c18 |
| HEADER | CLIENT_AREA | 18 | 40 | 1339 | 72 | 0.0131 | 0.0349 | 0.9745 | 0.0629 |  |
| HEADER_ICON | HEADER | 22 | 50 | 56 | 47 | 0.0160 | 0.0437 | 0.0408 | 0.0410 |  |
| APP_TITLE | HEADER | 100 | 48 | 226 | 34 | 0.0728 | 0.0419 | 0.1645 | 0.0297 |  |
| APP_SUBTITLE | HEADER | 100 | 86 | 259 | 17 | 0.0728 | 0.0751 | 0.1885 | 0.0148 |  |
| SLOGAN | HEADER | 1104 | 58 | 232 | 37 | 0.8035 | 0.0507 | 0.1689 | 0.0323 |  |
| LEFT_COLUMN | CLIENT_AREA | 18 | 112 | 528 | 985 | 0.0131 | 0.0978 | 0.3843 | 0.8603 |  |
| RIGHT_COLUMN | CLIENT_AREA | 564 | 112 | 794 | 962 | 0.4105 | 0.0978 | 0.5779 | 0.8402 |  |
| CLIENT_COMPUTER | LEFT_COLUMN | 18 | 112 | 528 | 97 | 0.0131 | 0.0978 | 0.3843 | 0.0847 | fill #071928; border_width 1 |
| LABEL_CLIENT | CLIENT_COMPUTER | 39 | 136 | 64 | 15 | 0.0284 | 0.1188 | 0.0466 | 0.0131 |  |
| LABEL_COMPUTER | CLIENT_COMPUTER | 39 | 174 | 103 | 18 | 0.0284 | 0.1520 | 0.0750 | 0.0157 |  |
| FIELD_CLIENT | CLIENT_COMPUTER | 172 | 129 | 344 | 30 | 0.1252 | 0.1127 | 0.2504 | 0.0262 | fill #0f263b; border_width 1 |
| FIELD_COMPUTER | CLIENT_COMPUTER | 172 | 168 | 344 | 30 | 0.1252 | 0.1467 | 0.2504 | 0.0262 | fill #0f263b; border_width 1 |
| EXPC_DIAGNOSTIC | LEFT_COLUMN | 18 | 218 | 528 | 121 | 0.0131 | 0.1904 | 0.3843 | 0.1057 | fill #071928; border_width 1 |
| EXPC_TITLE | EXPC_DIAGNOSTIC | 38 | 228 | 131 | 17 | 0.0277 | 0.1991 | 0.0953 | 0.0148 |  |
| EXPC_RADIO_1 | EXPC_DIAGNOSTIC | 40 | 251 | 23 | 23 | 0.0291 | 0.2192 | 0.0167 | 0.0201 | center [51.0, 262.5]; outer_diameter 23 |
| EXPC_RADIO_1_LABEL | EXPC_DIAGNOSTIC | 80 | 257 | 194 | 15 | 0.0582 | 0.2245 | 0.1412 | 0.0131 |  |
| EXPC_RADIO_2 | EXPC_DIAGNOSTIC | 40 | 281 | 23 | 23 | 0.0291 | 0.2454 | 0.0167 | 0.0201 | center [51.0, 292.5]; outer_diameter 23 |
| EXPC_RADIO_2_LABEL | EXPC_DIAGNOSTIC | 81 | 287 | 190 | 15 | 0.0590 | 0.2507 | 0.1383 | 0.0131 |  |
| EXPC_RADIO_3 | EXPC_DIAGNOSTIC | 40 | 310 | 23 | 23 | 0.0291 | 0.2707 | 0.0167 | 0.0201 | center [51.0, 321.0]; outer_diameter 23 |
| EXPC_RADIO_3_LABEL | EXPC_DIAGNOSTIC | 81 | 316 | 55 | 12 | 0.0590 | 0.2760 | 0.0400 | 0.0105 |  |
| HARDWARE_REPORT | LEFT_COLUMN | 18 | 349 | 528 | 96 | 0.0131 | 0.3048 | 0.3843 | 0.0838 | fill #071928; border_width 1 |
| HW_TITLE | HARDWARE_REPORT | 38 | 360 | 137 | 17 | 0.0277 | 0.3144 | 0.0997 | 0.0148 |  |
| HW_CHECKBOX | HARDWARE_REPORT | 43 | 386 | 24 | 24 | 0.0313 | 0.3371 | 0.0175 | 0.0210 | fill #0271fc; center [54.5, 397.5] |
| HW_CHECK_LABEL | HARDWARE_REPORT | 88 | 392 | 121 | 15 | 0.0640 | 0.3424 | 0.0881 | 0.0131 |  |
| HW_CAPTION | HARDWARE_REPORT | 87 | 419 | 202 | 13 | 0.0633 | 0.3659 | 0.1470 | 0.0114 |  |
| HW_BUTTON | HARDWARE_REPORT | 382 | 378 | 141 | 38 | 0.2780 | 0.3301 | 0.1026 | 0.0332 | fill #10253b; border_width 1 |
| DIAGNOSTIC_STAGES | LEFT_COLUMN | 18 | 454 | 528 | 211 | 0.0131 | 0.3965 | 0.3843 | 0.1843 | fill #071928; border_width 1 |
| STAGES_TITLE | DIAGNOSTIC_STAGES | 38 | 466 | 278 | 17 | 0.0277 | 0.4070 | 0.2023 | 0.0148 |  |
| STAGE_ROW_1 | DIAGNOSTIC_STAGES | 37 | 489 | 490 | 28 | 0.0269 | 0.4271 | 0.3566 | 0.0245 |  |
| STAGE_ROW_1_ICON | STAGE_ROW_1 | 39 | 493 | 22 | 21 | 0.0284 | 0.4306 | 0.0160 | 0.0183 | center [49.5, 503.0] |
| STAGE_ROW_1_NUMBER | STAGE_ROW_1 | 74 | 497 | 16 | 12 | 0.0539 | 0.4341 | 0.0116 | 0.0105 |  |
| STAGE_ROW_1_LABEL | STAGE_ROW_1 | 106 | 498 | 134 | 13 | 0.0771 | 0.4349 | 0.0975 | 0.0114 |  |
| STAGE_ROW_1_BAR_TRACK | STAGE_ROW_1 | 300 | 497 | 173 | 12 | 0.2183 | 0.4341 | 0.1259 | 0.0105 | fill #0c1f30 |
| STAGE_ROW_1_BAR_FILL | STAGE_ROW_1 | 300 | 498 | 173 | 11 | 0.2183 | 0.4349 | 0.1259 | 0.0096 |  |
| STAGE_ROW_1_PERCENT | STAGE_ROW_1 | 485 | 498 | 36 | 11 | 0.3530 | 0.4349 | 0.0262 | 0.0096 |  |
| STAGE_ROW_2 | DIAGNOSTIC_STAGES | 37 | 516 | 490 | 28 | 0.0269 | 0.4507 | 0.3566 | 0.0245 |  |
| STAGE_ROW_2_ICON | STAGE_ROW_2 | 38 | 520 | 22 | 22 | 0.0277 | 0.4541 | 0.0160 | 0.0192 | center [48.5, 530.5] |
| STAGE_ROW_2_NUMBER | STAGE_ROW_2 | 74 | 526 | 16 | 12 | 0.0539 | 0.4594 | 0.0116 | 0.0105 |  |
| STAGE_ROW_2_LABEL | STAGE_ROW_2 | 106 | 526 | 167 | 14 | 0.0771 | 0.4594 | 0.1215 | 0.0122 |  |
| STAGE_ROW_2_BAR_TRACK | STAGE_ROW_2 | 300 | 524 | 173 | 12 | 0.2183 | 0.4576 | 0.1259 | 0.0105 | fill #0c1f30 |
| STAGE_ROW_2_BAR_FILL | STAGE_ROW_2 | 300 | 526 | 173 | 12 | 0.2183 | 0.4594 | 0.1259 | 0.0105 |  |
| STAGE_ROW_2_PERCENT | STAGE_ROW_2 | 485 | 526 | 36 | 11 | 0.3530 | 0.4594 | 0.0262 | 0.0096 |  |
| STAGE_ROW_3 | DIAGNOSTIC_STAGES | 37 | 546 | 490 | 28 | 0.0269 | 0.4769 | 0.3566 | 0.0245 |  |
| STAGE_ROW_3_ICON | STAGE_ROW_3 | 38 | 549 | 22 | 22 | 0.0277 | 0.4795 | 0.0160 | 0.0192 | center [48.5, 560.0] |
| STAGE_ROW_3_NUMBER | STAGE_ROW_3 | 74 | 554 | 16 | 12 | 0.0539 | 0.4838 | 0.0116 | 0.0105 |  |
| STAGE_ROW_3_LABEL | STAGE_ROW_3 | 105 | 554 | 158 | 15 | 0.0764 | 0.4838 | 0.1150 | 0.0131 |  |
| STAGE_ROW_3_BAR_TRACK | STAGE_ROW_3 | 300 | 554 | 173 | 12 | 0.2183 | 0.4838 | 0.1259 | 0.0105 | fill #0c1f30 |
| STAGE_ROW_3_BAR_FILL | STAGE_ROW_3 | 300 | 555 | 104 | 12 | 0.2183 | 0.4847 | 0.0757 | 0.0105 |  |
| STAGE_ROW_3_PERCENT | STAGE_ROW_3 | 485 | 554 | 29 | 12 | 0.3530 | 0.4838 | 0.0211 | 0.0105 |  |
| STAGE_ROW_4 | DIAGNOSTIC_STAGES | 37 | 574 | 490 | 28 | 0.0269 | 0.5013 | 0.3566 | 0.0245 |  |
| STAGE_ROW_4_ICON | STAGE_ROW_4 | 37 | 577 | 23 | 23 | 0.0269 | 0.5039 | 0.0167 | 0.0201 | center [48.0, 588.0] |
| STAGE_ROW_4_NUMBER | STAGE_ROW_4 | 74 | 583 | 16 | 12 | 0.0539 | 0.5092 | 0.0116 | 0.0105 |  |
| STAGE_ROW_4_LABEL | STAGE_ROW_4 | 106 | 583 | 107 | 14 | 0.0771 | 0.5092 | 0.0779 | 0.0122 |  |
| STAGE_ROW_4_BAR_TRACK | STAGE_ROW_4 | 300 | 582 | 173 | 12 | 0.2183 | 0.5083 | 0.1259 | 0.0105 | fill #0c1f30 |
| STAGE_ROW_4_BAR_FILL | STAGE_ROW_4 | 300 | 583 | 65 | 12 | 0.2183 | 0.5092 | 0.0473 | 0.0105 |  |
| STAGE_ROW_4_PERCENT | STAGE_ROW_4 | 485 | 583 | 29 | 11 | 0.3530 | 0.5092 | 0.0211 | 0.0096 |  |
| STAGE_ROW_5 | DIAGNOSTIC_STAGES | 37 | 602 | 490 | 28 | 0.0269 | 0.5258 | 0.3566 | 0.0245 |  |
| STAGE_ROW_5_ICON | STAGE_ROW_5 | 38 | 606 | 23 | 22 | 0.0277 | 0.5293 | 0.0167 | 0.0192 | center [49.0, 616.5] |
| STAGE_ROW_5_NUMBER | STAGE_ROW_5 | 74 | 612 | 16 | 11 | 0.0539 | 0.5345 | 0.0116 | 0.0096 |  |
| STAGE_ROW_5_LABEL | STAGE_ROW_5 | 105 | 612 | 138 | 14 | 0.0764 | 0.5345 | 0.1004 | 0.0122 |  |
| STAGE_ROW_5_BAR_TRACK | STAGE_ROW_5 | 300 | 610 | 159 | 12 | 0.2183 | 0.5328 | 0.1157 | 0.0105 | fill #0c1f30 |
| STAGE_ROW_5_PERCENT | STAGE_ROW_5 | 468 | 612 | 64 | 13 | 0.3406 | 0.5345 | 0.0466 | 0.0114 |  |
| STAGE_ROW_6 | DIAGNOSTIC_STAGES | 37 | 632 | 490 | 28 | 0.0269 | 0.5520 | 0.3566 | 0.0245 |  |
| STAGE_ROW_6_ICON | STAGE_ROW_6 | 38 | 635 | 23 | 22 | 0.0277 | 0.5546 | 0.0167 | 0.0192 | center [49.0, 645.5] |
| STAGE_ACTIVE_HIGHLIGHT | DIAGNOSTIC_STAGES | 37 | 546 | 490 | 28 | 0.0269 | 0.4769 | 0.3566 | 0.0245 | fill #012041 |
| DRIVERS | LEFT_COLUMN | 18 | 674 | 528 | 272 | 0.0131 | 0.5886 | 0.3843 | 0.2376 | fill #071928; border_width 1 |
| DRIVERS_ALERT_ICON | DRIVERS | 30 | 680 | 37 | 33 | 0.0218 | 0.5939 | 0.0269 | 0.0288 |  |
| DRIVERS_TITLE | DRIVERS | 75 | 687 | 170 | 18 | 0.0546 | 0.6000 | 0.1237 | 0.0157 |  |
| DRIVERS_BUTTON | DRIVERS | 412 | 684 | 115 | 34 | 0.2999 | 0.5974 | 0.0837 | 0.0297 | fill #10253b |
| DRIVER_ROW_1 | DRIVERS | 30 | 722 | 504 | 25 | 0.0218 | 0.6306 | 0.3668 | 0.0218 |  |
| DRIVER_ROW_2 | DRIVERS | 30 | 747 | 504 | 25 | 0.0218 | 0.6524 | 0.3668 | 0.0218 |  |
| DRIVER_ROW_3 | DRIVERS | 30 | 772 | 504 | 25 | 0.0218 | 0.6742 | 0.3668 | 0.0218 |  |
| DRIVER_ROW_4 | DRIVERS | 30 | 798 | 504 | 25 | 0.0218 | 0.6969 | 0.3668 | 0.0218 |  |
| DRIVER_ROW_5 | DRIVERS | 30 | 824 | 504 | 25 | 0.0218 | 0.7197 | 0.3668 | 0.0218 |  |
| DRIVER_ROW_6 | DRIVERS | 30 | 850 | 504 | 25 | 0.0218 | 0.7424 | 0.3668 | 0.0218 |  |
| DRIVERS_TABLE | DRIVERS | 39 | 724 | 478 | 147 | 0.0284 | 0.6323 | 0.3479 | 0.1284 |  |
| DRIVERS_WARNBOX | DRIVERS | 30 | 880 | 504 | 56 | 0.0218 | 0.7686 | 0.3668 | 0.0489 | fill #2e1622; border_width 1 |
| RESULT | LEFT_COLUMN | 18 | 956 | 528 | 89 | 0.0131 | 0.8349 | 0.3843 | 0.0777 | fill #071928; border_width 1 |
| RESULT_TITLE | RESULT | 38 | 969 | 85 | 13 | 0.0277 | 0.8463 | 0.0619 | 0.0114 |  |
| RESULT_ICON | RESULT | 40 | 996 | 31 | 37 | 0.0291 | 0.8699 | 0.0226 | 0.0323 |  |
| RESULT_LINE1 | RESULT | 92 | 999 | 212 | 14 | 0.0670 | 0.8725 | 0.1543 | 0.0122 |  |
| RESULT_LINE2 | RESULT | 92 | 1021 | 322 | 14 | 0.0670 | 0.8917 | 0.2344 | 0.0122 |  |
| START_BUTTON | LEFT_COLUMN | 113 | 1055 | 339 | 42 | 0.0822 | 0.9214 | 0.2467 | 0.0367 | fill #0071fd; border none |
| OVERALL_PROGRESS | RIGHT_COLUMN | 564 | 112 | 794 | 240 | 0.4105 | 0.0978 | 0.5779 | 0.2096 | fill #071928; border_width 1 |
| OVERALL_TITLE | OVERALL_PROGRESS | 581 | 127 | 209 | 15 | 0.4229 | 0.1109 | 0.1521 | 0.0131 |  |
| OVERALL_RING | OVERALL_PROGRESS | 615 | 156 | 182 | 182 | 0.4476 | 0.1362 | 0.1325 | 0.1590 | center [705.26, 246.07]; outer_diameter 181.0 |
| OVERALL_PERCENT | OVERALL_RING | 667 | 228 | 77 | 30 | 0.4854 | 0.1991 | 0.0560 | 0.0262 |  |
| OVERALL_STATUS | OVERALL_RING | 662 | 274 | 88 | 15 | 0.4818 | 0.2393 | 0.0640 | 0.0131 |  |
| TIME_BLOCK | OVERALL_PROGRESS | 812 | 192 | 133 | 115 | 0.5910 | 0.1677 | 0.0968 | 0.1004 |  |
| TIME_ICON_CLOCK | TIME_BLOCK | 812 | 192 | 26 | 27 | 0.5910 | 0.1677 | 0.0189 | 0.0236 |  |
| TIME_LABEL_ELAPSED | TIME_BLOCK | 854 | 194 | 49 | 13 | 0.6215 | 0.1694 | 0.0357 | 0.0114 |  |
| TIME_VALUE_ELAPSED | TIME_BLOCK | 854 | 214 | 67 | 14 | 0.6215 | 0.1869 | 0.0488 | 0.0122 |  |
| TIME_ICON_HOURGLASS | TIME_BLOCK | 814 | 263 | 22 | 28 | 0.5924 | 0.2297 | 0.0160 | 0.0245 |  |
| TIME_LABEL_ETA | TIME_BLOCK | 854 | 265 | 91 | 13 | 0.6215 | 0.2314 | 0.0662 | 0.0114 |  |
| TIME_VALUE_ETA | TIME_BLOCK | 854 | 287 | 77 | 14 | 0.6215 | 0.2507 | 0.0560 | 0.0122 |  |
| MODULES | OVERALL_PROGRESS | 979 | 152 | 362 | 184 | 0.7125 | 0.1328 | 0.2635 | 0.1607 | fill #0a1b2d; border_width 1 |
| MODULES_TITLE | MODULES | 995 | 167 | 157 | 15 | 0.7242 | 0.1459 | 0.1143 | 0.0131 |  |
| MODULE_ROW_1 | MODULES | 993 | 193 | 334 | 39 | 0.7227 | 0.1686 | 0.2431 | 0.0341 | fill #0b1e32 |
| MODULE_ROW_1_ICON | MODULE_ROW_1 | 1002 | 200 | 22 | 23 | 0.7293 | 0.1747 | 0.0160 | 0.0201 | center [1012.5, 211.5] |
| MODULE_ROW_1_LABEL | MODULE_ROW_1 | 1043 | 206 | 110 | 15 | 0.7591 | 0.1799 | 0.0801 | 0.0131 |  |
| MODULE_ROW_1_STATUS | MODULE_ROW_1 | 1237 | 206 | 77 | 12 | 0.9003 | 0.1799 | 0.0560 | 0.0105 |  |
| MODULE_ROW_2 | MODULES | 993 | 238 | 334 | 39 | 0.7227 | 0.2079 | 0.2431 | 0.0341 | fill #0b1e32 |
| MODULE_ROW_2_ICON | MODULE_ROW_2 | 1002 | 245 | 22 | 23 | 0.7293 | 0.2140 | 0.0160 | 0.0201 | center [1012.5, 256.0] |
| MODULE_ROW_2_LABEL | MODULE_ROW_2 | 1043 | 250 | 113 | 15 | 0.7591 | 0.2183 | 0.0822 | 0.0131 |  |
| MODULE_ROW_2_STATUS | MODULE_ROW_2 | 1224 | 251 | 89 | 12 | 0.8908 | 0.2192 | 0.0648 | 0.0105 |  |
| MODULE_ROW_3 | MODULES | 993 | 283 | 334 | 40 | 0.7227 | 0.2472 | 0.2431 | 0.0349 | fill #0b1e32 |
| MODULE_ROW_3_ICON | MODULE_ROW_3 | 1002 | 291 | 22 | 23 | 0.7293 | 0.2541 | 0.0160 | 0.0201 | center [1012.5, 302.0] |
| MODULE_ROW_3_LABEL | MODULE_ROW_3 | 1043 | 297 | 67 | 14 | 0.7591 | 0.2594 | 0.0488 | 0.0122 |  |
| MODULE_ROW_3_STATUS | MODULE_ROW_3 | 1242 | 297 | 72 | 14 | 0.9039 | 0.2594 | 0.0524 | 0.0122 |  |
| CURRENT_OPERATION | RIGHT_COLUMN | 564 | 363 | 794 | 119 | 0.4105 | 0.3170 | 0.5779 | 0.1039 | fill #071928; border_width 1 |
| CUROP_TITLE | CURRENT_OPERATION | 581 | 377 | 151 | 16 | 0.4229 | 0.3293 | 0.1099 | 0.0140 |  |
| CUROP_NAME | CURRENT_OPERATION | 582 | 404 | 141 | 20 | 0.4236 | 0.3528 | 0.1026 | 0.0175 |  |
| CUROP_SUBTITLE | CURRENT_OPERATION | 582 | 429 | 305 | 15 | 0.4236 | 0.3747 | 0.2220 | 0.0131 |  |
| CUROP_BAR_TRACK | CURRENT_OPERATION | 580 | 449 | 676 | 18 | 0.4221 | 0.3921 | 0.4920 | 0.0157 | fill #142d44 |
| CUROP_BAR_FILL | CUROP_BAR_TRACK | 580 | 450 | 381 | 17 | 0.4221 | 0.3930 | 0.2773 | 0.0148 |  |
| CUROP_PERCENT | CURRENT_OPERATION | 1296 | 447 | 38 | 17 | 0.9432 | 0.3904 | 0.0277 | 0.0148 |  |
| SSD_SUMMARY | RIGHT_COLUMN | 564 | 493 | 794 | 290 | 0.4105 | 0.4306 | 0.5779 | 0.2533 | fill #071928; border_width 1 |
| SSD_TITLE | SSD_SUMMARY | 581 | 506 | 281 | 18 | 0.4229 | 0.4419 | 0.2045 | 0.0157 |  |
| READ_RING | SSD_SUMMARY | 598 | 539 | 197 | 196 | 0.4352 | 0.4707 | 0.1434 | 0.1712 | center [696.0, 636.56] |
| READ_LABEL | READ_RING | 673 | 577 | 47 | 14 | 0.4898 | 0.5039 | 0.0342 | 0.0122 |  |
| READ_CURRENT | READ_RING | 648 | 607 | 99 | 29 | 0.4716 | 0.5301 | 0.0721 | 0.0253 |  |
| READ_PREVIOUS | READ_RING | 665 | 656 | 64 | 19 | 0.4840 | 0.5729 | 0.0466 | 0.0166 |  |
| READ_DELTA | SSD_SUMMARY | 668 | 750 | 56 | 16 | 0.4862 | 0.6550 | 0.0408 | 0.0140 |  |
| WRITE_RING | SSD_SUMMARY | 812 | 540 | 196 | 195 | 0.5910 | 0.4716 | 0.1426 | 0.1703 | center [909.56, 637.06] |
| WRITE_LABEL | WRITE_RING | 870 | 577 | 80 | 14 | 0.6332 | 0.5039 | 0.0582 | 0.0122 |  |
| WRITE_CURRENT | WRITE_RING | 863 | 608 | 95 | 28 | 0.6281 | 0.5310 | 0.0691 | 0.0245 |  |
| WRITE_PREVIOUS | WRITE_RING | 878 | 656 | 66 | 19 | 0.6390 | 0.5729 | 0.0480 | 0.0166 |  |
| WRITE_DELTA | SSD_SUMMARY | 882 | 750 | 54 | 16 | 0.6419 | 0.6550 | 0.0393 | 0.0140 |  |
| SSD_METADATA | SSD_SUMMARY | 1040 | 542 | 262 | 155 | 0.7569 | 0.4734 | 0.1907 | 0.1354 |  |
| SSD_ACTIONS | SSD_SUMMARY | 1004 | 729 | 337 | 40 | 0.7307 | 0.6367 | 0.2453 | 0.0349 |  |
| SSD_BTN_PRIMARY | SSD_ACTIONS | 1004 | 730 | 173 | 39 | 0.7307 | 0.6376 | 0.1259 | 0.0341 | fill #0071fd; border none |
| SSD_BTN_SECONDARY | SSD_ACTIONS | 1193 | 729 | 148 | 41 | 0.8683 | 0.6367 | 0.1077 | 0.0358 | fill #10253a; border_width 1 |
| JOURNAL | RIGHT_COLUMN | 564 | 794 | 794 | 280 | 0.4105 | 0.6934 | 0.5779 | 0.2445 | fill #071928; border_width 1 |
| JOURNAL_TITLE | JOURNAL | 581 | 807 | 66 | 17 | 0.4229 | 0.7048 | 0.0480 | 0.0148 |  |
| JOURNAL_CLEAR_BUTTON | JOURNAL | 1216 | 804 | 125 | 31 | 0.8850 | 0.7022 | 0.0910 | 0.0271 | fill #12283e |
| JOURNAL_LOG_PANEL | JOURNAL | 580 | 834 | 762 | 224 | 0.4221 | 0.7284 | 0.5546 | 0.1956 | fill #041321; border_width 1 |
| JOURNAL_SCROLLBAR | JOURNAL_LOG_PANEL | 1327 | 836 | 15 | 221 | 0.9658 | 0.7301 | 0.0109 | 0.1930 |  |
| STATUS_BAR | ROOT | 1 | 1108 | 1372 | 36 | 0.0007 | 0.9677 | 0.9985 | 0.0314 | fill #010f1c |

## 6. Colour tokens (glyph-core / flat-region medians)

| Token | Hex | Token | Hex |
|---|---|---|---|
| BG_ROOT | `#000c18` | BG_CARD | `#071928` |
| BG_CARD_INNER | `#0a1b2d` | BG_ROW | `#0b1e32` |
| BG_ROW_ACTIVE | `#012041` | BG_FIELD | `#0f263b` |
| BORDER_NORMAL | `#264864` | BORDER_INNER | `#132a3f` |
| BORDER_FIELD | `#244560` | BORDER_ACTIVE (hover) | `#3d7bb0` |
| TEXT_PRIMARY | `#f4f7fa` | TEXT_BODY | `#c8d6e3` |
| TEXT_SECONDARY | `#a3bbd2` | TEXT_MUTED | `#8ba7c4` |
| TEXT_TITLE (card titles) | `#5ef7ff` | TEXT_SUBTITLE | `#abeffb` |
| TEXT_SLOGAN | `#6688a8` | BLUE_PRIMARY | `#0071fd` |
| BLUE_BRIGHT | `#1d86ff` | BLUE_DARK | `#005dd1` |
| BLUE_ACCENT (icons) | `#0198f0` | BLUE_PROGRESS | `#0077fe` |
| BLUE_STAGE | `#00a5fc` | GREEN_SUCCESS | `#1ff274` |
| GREEN_PROGRESS | `#03f97e` | GREEN_WRITE | `#44fb66` |
| VIOLET_PREVIOUS_READ | `#8232ee` | TEAL_PREVIOUS_WRITE | `#00b8bb` |
| YELLOW_WARNING | `#f0c83a` | RED_ERROR | `#f04a4c` |
| PROGRESS_TRACK | `#0c1f30` | RING_TRACK | `#12273d` |
| PENDING (stage ring) | `#a4bbdc` | STATUS_BAR_FILL | `#010f1c` |
| PENDING_MODULE | `#97b0d1` | ICON_TIME (clock / hourglass) | `#01aeff` |
| TEXT_STAGE_RUNNING | `#cfdbea` | TEXT_STAGE_RUNNING_PERCENT | `#dfe8f2` |
| TEXT_STAGE_PENDING | `#d6dfe9` | BUTTON_SUBTLE_TEXT ("Очистить") | `#d7e2ec` |
| RADIO_RING_OFF | `#23415d` | RADIO_FILL_OFF | `#0a1c2c` |
| JOURNAL_TIMESTAMP | `#bec4d0` | | |

## 7. Typography scale (Segoe UI family + Consolas, loaded from `%WINDIR%\Fonts`)

In egui 0.36 the font size is the em size, so these values compare directly with the master (cap height ÷ 0.70).

Sizes below are fitted to the ink widths of the **real Windows capture** (`docs/visual/actual_reference.png`, Segoe UI, ppp 1.0) against the master. epaint 0.36 scales glyphs continuously, so widths are linear in the size, and fractional sizes are meaningful. The master (an image render) is not typographically uniform: identical roles differ by ±3 % between cards, and Latin runs are relatively wider than Cyrillic ones. A few roles therefore have their own measured token.

| Style | px | Weight | Colour | Instances |
|---|---:|---|---|---|
| APP_TITLE | 36 | Semibold | `#fbfcfd` | "WinStateDiag" (baseline 75.2) |
| APP_SUBTITLE | 17.15 | Regular | `#abeffb` | subtitle |
| SLOGAN | 17.2 | Regular | `#6688a8` | 2 lines, block right edge x 1337 |
| TITLE_EXPC / TITLE_HARDWARE / TITLE_STAGES / TITLE_RESULT | 17.75 / 18 / 17.8 / 17.4 | Semibold | `#5ef7ff` | left-column card titles (x 37 / 37 / 36 / 36) |
| TITLE_OVERALL / TITLE_OPERATION / TITLE_SSD / TITLE_JOURNAL | 17.6 / 17.4 / 18.4 / 18.2 | Semibold | `#5ef7ff` | right-column card titles |
| CARD_TITLE | 17.6 | Semibold | `#5ef7ff` | fallback |
| SECTION_TITLE | 16.6 | Semibold | `#5ef7ff` | "Модули диагностики" (x 994) |
| LABEL_LARGE | 19.3 | Semibold | `#fbfcfd` | Клиент / Компьютер (x 38) |
| BODY | 15.6 | Regular | `#f4f7fa` | radios, fields, module labels, result line 1 |
| CHECK_LABEL | 16.2 | Regular | `#f4f7fa` | "Hardware Report" checkbox label |
| STAGE_LABEL / STAGE_LABEL_LATIN | 14.75 / 15 | Regular | done `#f4f7fa`, running `#cfdbea`, pending `#d6dfe9` | stage names (Latin-only labels use the second size) |
| BODY_SMALL | 15 | Regular | as above; running % `#dfe8f2` | stage numbers and percentages |
| STAGE_PENDING | 14 | Regular | `#b0c2d4` | "Ожидание" in stage rows |
| BODY_SECONDARY | 15.9 | Regular | `#a3bbd2` | operation subtitle, result line 2 |
| SSD_META_LABEL / SSD_META_VALUE | 14.9 / 16.1 | Regular | `#a3bbd2` / tone | SSD metadata |
| CAPTION | 14.2 | Regular | `#a3bbd2` / muted | HW caption, SSD idle captions |
| TIME_LABEL | 13.5 | Regular | muted / secondary | "Прошло", "Осталось (ETA)" |
| MUTED | 15 | Regular | tone | module statuses (right-aligned) |
| METRIC_LARGE | 41.5 | Semibold | `#fbfcfd` | ring percent |
| RING_STATUS | 15.2 | Regular | `#f4f7fa` | "Выполняется" under the percent |
| METRIC_MEDIUM | 26 | Semibold | violet / teal | SSD previous (+1.5 px right of ring centre) |
| METRIC_SMALL | 18.5 | Regular | `#f4f7fa` | elapsed / ETA values |
| SSD_CURRENT | 39 | Regular | `#028ef7` / `#03f7ae` | SSD current (+1.5 px right of ring centre) |
| SSD_RING_LABEL | 19 | Semibold | `#02a0fa` / `#04fba1` | READ / WRITE |
| DELTA | 20 | Semibold | `#35f67e` | +3.2 % |
| OPERATION_TITLE | 20.5 | Semibold | `#fbfcfd` | "SFC /verifyonly" |
| PROGRESS_PERCENT | 21 | Semibold | `#fbfcfd` | "58%" (right edge x 1335) |
| BUTTON_TEXT_LARGE | 19.1 | Regular | white | Start button |
| BUTTON_TEXT | 16 | Regular | `#f4f7fa` | Смотреть |
| BUTTON_TEXT_SMALL | 13.5 | Regular | white / `#f4f7fa` / `#d7e2ec` | SSD buttons, Очистить |
| MONO | 14.3 | Consolas | `#bec4d0` / `#bfc7d1` | journal |
| STATUS_BAR / STATUS_LEFT | 14.5 / 13.5 | Regular | `#bcc3cf` | status bar right / left |

Button icon boxes (measured): Play = text size, gap 10.95; Power = 18 px (1.33 × size), gap 10; Trash = 17 × 19, gap 15.

## 8. Intentional, documented differences from the master

| # | Master element | Implementation | Reason |
|---|---|---|---|
| 1 | "ПРОВЕРКА ДРАЙВЕРОВ" card | Built (2026-09-24) at the master geometry from the real Driver Audit (see §12 and `docs/DRIVER_AUDIT.md`). Status words: "Проблема" / "Внимание" / "OK"; the master's "Устаревший" is not used because driver age alone is never a finding. Device glyphs are generic (no brand logos). | Semantic rule of the audit. |
| 2 | Custom dark title bar with "v0.1.0" at the right | Native Windows title bar "WinStateDiag — v0.1.0" | Window chrome is not app content. A custom undecorated title bar was not requested and would change the approved window behaviour. |
| 3 | Stage bars: 68 % drawn as 60 %, 42 % as 38 %; CURRENT 58 % drawn as 56 % | Fills are exactly proportional to the value | Inconsistency in the master render. A truthful bar wins. |
| 4 | Stage list shows 5 rows + "…" | Same (5-row window that follows the active stage; the "…" row lists hidden stages on hover) | — |
| 5 | "Стабильность STABLE" next to "Write spread ACCEPTABLE" | Overall = worst of READ/WRITE, so the live app shows ACCEPTABLE in that case | Never fabricate a verdict. The reference fixture copies the master text literally. |
| 6 | Slight glow/blur halos (AI render) | Crisp strokes | Not reproducible as a design token. |
| 7 | Card titles vary 17.4–18.4 px between cards | Per-card title tokens (TITLE_*), fitted to the master | Measured, see §7. |
| 8 | Journal timestamps: digits 11 px tall in the master, 9 px in Consolas at the same advance | Consolas 14.3 px (widths match within 1 px) | Font face difference. A taller mono face at the same advance is not available on stock Windows. |
| 9 | Em dash in journal lines is wider in the master (lines with "—" are 5–8 px longer) | Consolas em dash (one cell) | Font face difference. |

## 9. Visual QA workflow

1. `powershell -ExecutionPolicy Bypass -File scripts\visual_qa.ps1` runs fmt/check/test/build, launches the real EXE with `--visual-reference --capture docs\visual\actual_reference.png`, and writes `docs\visual\qa_run.log`.
2. The comparison crops the master to the client canvas (`x 1..1372, y 38..1143`). It measures card edges in **both** images independently and reports ΔX/ΔY/ΔW/ΔH per component, a per-pixel diff heatmap, and the mean absolute difference.
3. Remaining differences must be explained by platform/font/rasterisation limits, or be corrected.

## 10. Real-capture diff iteration (MSI, 2026-09-23)

The baseline is the real capture `docs/visual/actual_reference.png` (real EXE, `--visual-reference`, all QA steps PASS). Tools: per-element ink boxes (master vs actual), line and segment splitting for unmeasured text, and per-element ink/background colour medians.

| Metric | Real capture (before) | After fixes |
|---|---|---|
| Card edges | within ±1 px | unchanged (no card geometry touched) |
| Text elements (65), mean \|ΔW\| | 3.11 px (max 9) | 0.78 px (max 2.5), predicted |
| Text elements within ±2.5 px (x, w) | 25 / 65 | 65 / 65, predicted |
| Icons (radio, header, stage, module, button icons) | up to ±4 px | within ±1 px (offline render, font-independent) |
| Ink colour Δ (max channel), median / >24 | 6 / 25 elements | 6 / 13 (11 are the intentional driver rows) |
| Mean abs pixel diff (RGB sum) | 33.92 (11.12 % > 60) | offline harness 37.24 → 35.98 (substitute fonts); real value needs the next capture |

"Predicted" means the next real capture is computed from the measured real widths and the size change (w' = w × new/old; alignment-aware x). A Regular/Semibold width ratio of 0.965 and a Semibold/Bold ratio of 0.975 are assumed for the four weight changes (APP_TITLE, METRIC_LARGE, SSD_CURRENT, RING_STATUS).


## 11. Final real capture (MSI, 2026-09-23 23:54, ppp 1.0, 96 DPI)

All steps PASS: fmt, check, test (65/65), build --release, EXE launch, capture.

| Metric | Capture 1 | Capture 2 (final) |
|---|---|---|
| Card edges | ±1 px | ±1 px (two detector outliers checked by pixel profile: identical rows) |
| Text (65): mean \|ΔX\| / \|ΔW\| | 0.88 / 3.11 px | 0.45 / 1.48 px |
| Text within ±2 px (x, w) / ±3 px | 25 / 41 | 50 / 58 |
| Icons (radio, header, stage, module, button) | up to ±4 px | ±1 px (SSD power icon x −2) |
| Rings (overall, READ, WRITE) outer radius | — | ±1 px |
| Mean abs pixel diff (RGB sum), pixels > 60 | 33.92, 11.12 % | 32.15, 10.76 % |
| Ink colour Δ median (excluding driver rows) | 6 | 6 |

Segoe UI is TrueType-hinted by egui 0.36 (skrifa), so advances are pixel-quantized: small size changes (≤ 2 %) do not always change the rendered width. The remaining +4/+5 px on five long strings (app title, stages / overall / modules titles, stage row 2) are within 2 % of their width and are recorded as rendering differences.

Capture 2 showed one regression: SSD current numbers at Regular 41.5 were 6–7 px too wide. SSD_CURRENT is now Regular 39. This needs one more capture to confirm.

## 12. Driver Audit card (2026-09-24)

Geometry (master px): card `[18, 674, 528, 272]`; state icon centre (48.5, 696.5) Ø24; title x 75, baseline 703; "Подробнее" button `[412, 684, 114, 34]`; rows: baselines 739.1 + k·25.64 (k = 0..5), icon centre x 49 (19 px box), name x 75, version x 276, status icon centre x 418 Ø16, status text x 435; alert strip `[30, 880, 504, 55]` r 6, icon `[41, 896, 24, 23]`, text x 82, baselines 903 / 922. The stages card returns to the master rect `[18, 454, 528, 211]`.

Colours are master samples (tokens `DRIVER_*`, `ALERT_*`). Initial text sizes (TITLE_DRIVERS 17, DRIVER_NAME 15.6, DRIVER_VERSION 14.2, DRIVER_STATUS 15, ALERT_TEXT 14.2) are estimates until the next real Windows capture is compared.

States: running (indeterminate bar), unavailable (reason), done. When done: up to 6 rows. Every flagged item comes first, then one representative per core category (up to two GPUs), ordered by category. The alert strip appears only with problems (red) or warnings (amber). Without findings a green line replaces the strip.

