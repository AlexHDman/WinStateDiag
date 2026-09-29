//! Design tokens measured from the canonical Visual Master
//! (`assets/UI_VISUAL_MASTER.png`, 1378x1142). Single source of truth for
//! geometry, colour and typography — no other UI file may introduce its own
//! magic palette values or card coordinates.
//!
//! COORDINATE SYSTEM
//! -----------------
//! All geometry below is expressed in **master pixels** (the full PNG,
//! native Windows title bar and frame included), exactly as measured, so
//! every number can be traced back to the master. The application's client
//! area corresponds to the master crop `x 1..=1376, y 33..=1140`; `mpos()`
//! converts a master coordinate into a point inside the dashboard canvas.

// The token catalogue is complete by design (it documents the whole measured
// grid, see docs/UI_VISUAL_MASTER.md); not every token is referenced by code.
#![allow(dead_code)]

use egui::{Color32, Pos2, Rect, pos2, vec2};

// ---------------------------------------------------------------------------
// Reference canvas
// ---------------------------------------------------------------------------

/// Native pixel size of the visual master image.
pub const MASTER_SIZE: [f32; 2] = [1378.0, 1142.0];
/// Master pixel that maps to canvas (0, 0).
pub const CANVAS_ORIGIN_IN_MASTER: [f32; 2] = [1.0, 33.0];
/// Reference canvas (client area) size in points. In reference mode
/// pixels_per_point is forced to 1.0, so this is also the physical size.
pub const CANVAS_W: f32 = 1376.0;
pub const CANVAS_H: f32 = 1108.0;

/// Master rect (x, y, w, h in master px) -> canvas rect relative to `origin`.
pub fn mrect(origin: Pos2, x: f32, y: f32, w: f32, h: f32) -> Rect {
    Rect::from_min_size(mpos(origin, x, y), vec2(w, h))
}

/// Master point -> canvas point relative to `origin`.
pub fn mpos(origin: Pos2, x: f32, y: f32) -> Pos2 {
    pos2(
        origin.x + x - CANVAS_ORIGIN_IN_MASTER[0],
        origin.y + y - CANVAS_ORIGIN_IN_MASTER[1],
    )
}

// ---------------------------------------------------------------------------
// Layout tokens (master px). Card rects: x0 = first border pixel,
// x1 = last border pixel + 1 (border is drawn inside).
// ---------------------------------------------------------------------------

pub mod layout {
    //! Every value below was re-measured on the canonical Visual Master
    //! `assets/UI_VISUAL_MASTER.png` (1378x1142, native Windows chrome
    //! included). Coordinates are full-image master pixels; the client area
    //! starts at master (1, 33) — see `CANVAS_ORIGIN_IN_MASTER`. Where the
    //! approved written corrections differ from the PNG (compact RU/EN
    //! buttons, fixed three-slot SSD row, orthogonal connector, restrained
    //! ring strokes, Current Operation folded into the status bar), the
    //! correction wins and is commented at the token.

    /// [x, y, w, h]
    pub type R = [f32; 4];

    pub const LEFT_COLUMN_X: f32 = 19.0;
    pub const LEFT_COLUMN_WIDTH: f32 = 539.0;
    pub const RIGHT_COLUMN_X: f32 = 571.0;
    pub const RIGHT_COLUMN_WIDTH: f32 = 788.0;
    /// Card title x (left column / right column).
    pub const LEFT_TITLE_X: f32 = 41.0;
    pub const RIGHT_TITLE_X: f32 = 587.0;

    pub const CARD_RADIUS: u8 = 7;
    pub const CARD_BORDER_WIDTH: f32 = 1.0;
    pub const CARD_PADDING_X_LEFT_COL: f32 = 20.0;
    pub const CARD_PADDING_X_RIGHT_COL: f32 = 16.0;
    pub const INNER_CARD_RADIUS: u8 = 6;
    pub const ROW_RADIUS: u8 = 5;

    // ---- Header ----
    pub const HEADER_ICON: R = [27.0, 55.0, 54.0, 49.0];
    pub const APP_TITLE_X: f32 = 110.0;
    pub const APP_TITLE_BASELINE: f32 = 79.0;
    pub const APP_SUBTITLE_BASELINE: f32 = 106.5;
    /// Right-hand header group [RU] [EN] [EXPC], treated as ONE unit and
    /// vertically centred on y = 76 (the master's header composition line).
    /// RU/EN: compact buttons, ~35% larger than the 30x18 previous pass
    /// (explicit correction; the PNG's 56x44 pills are intentionally not
    /// reproduced).
    pub const HEADER_GROUP_CENTER_Y: f32 = 76.0;
    pub const LANG_BUTTON_RU: R = [1013.0, 66.0, 36.0, 20.0];
    pub const LANG_BUTTON_EN: R = [1057.0, 66.0, 36.0, 20.0];
    /// EXPC wordmark + emblem (derived transparent asset, unchanged
    /// artwork), right edge on the master's logo right edge (x 1351).
    pub const EXPC_HEADER_LOGO: R = [1109.0, 56.0, 242.0, 40.0];

    // ---- Left column ----
    pub const CLIENT_CARD: R = [19.0, 121.0, 341.0, 95.0];
    pub const CLIENT_LABEL_X: f32 = 41.0;
    pub const CLIENT_LABEL_BASELINES: [f32; 2] = [157.5, 197.5];
    pub const CLIENT_FIELD: R = [163.0, 134.0, 185.0, 36.0];
    pub const COMPUTER_FIELD: R = [163.0, 174.0, 185.0, 36.0];
    pub const FIELD_TEXT_INSET_X: f32 = 20.0;
    pub const FIELD_RADIUS: u8 = 4;
    /// Seconds per full attention-pulse cycle (Client field, report button).
    pub const ATTENTION_PULSE_PERIOD: f64 = 1.8;

    pub const DIAGNOSTIC_CARD: R = [19.0, 226.0, 341.0, 126.0];
    pub const DIAGNOSTIC_TITLE_BASELINE: f32 = 249.5;
    pub const RADIO_CENTER_X: f32 = 52.5;
    pub const RADIO_CENTERS_Y: [f32; 3] = [274.0, 304.0, 334.0];
    pub const RADIO_DIAMETER: f32 = 24.0;
    pub const RADIO_LABEL_X: f32 = 84.0;
    pub const RADIO_LABEL_BASELINES: [f32; 3] = [280.5, 310.5, 340.5];
    /// SFC / DISM / CHKDSK: compact column at the right of the EXPC card.
    pub const DEEP_TOGGLES_X: f32 = 272.0;

    /// CryptoPro: one tall card spanning the Client + EXPC rows.
    pub const CRYPTO_CARD: R = [373.0, 121.0, 185.0, 232.0];
    /// Simplified red CryptoPro mark (outer shield removed).
    pub const CRYPTO_LOGO: R = [388.0, 139.0, 50.0, 50.0];
    pub const CRYPTO_NAME_X: f32 = 447.0;
    pub const CRYPTO_NAME_BASELINE: f32 = 169.5;
    /// Status check (disc) — centred in the card, directly above HASH.
    pub const CRYPTO_ICON: R = [437.0, 207.0, 58.0, 58.0];
    /// HASH sits 14px under the check: check + HASH read as one object.
    pub const CRYPTO_STATUS_BASELINE: f32 = 293.5;
    /// ReHash / Проверка: comfortable side margins, bottom of the card.
    pub const CRYPTO_BUTTON: R = [388.0, 309.0, 156.0, 37.0];

    pub const HARDWARE_CARD: R = [19.0, 364.0, 539.0, 89.0];
    pub const HARDWARE_TITLE_BASELINE: f32 = 386.5;
    pub const HW_CHECKBOX: R = [45.0, 402.0, 25.0, 25.0];
    pub const HW_CHECK_LABEL_X: f32 = 91.0;
    pub const HW_CHECK_LABEL_BASELINE: f32 = 415.5;
    pub const HW_CAPTION_X: f32 = 91.0;
    pub const HW_CAPTION_BASELINE: f32 = 440.5;
    pub const HW_BUTTON: R = [386.0, 393.0, 152.0, 42.0];

    /// Five stage rows plus an "…" row (the window follows the active
    /// stage; hidden stages are listed on hover).
    pub const STAGES_CARD: R = [19.0, 463.0, 539.0, 223.0];
    pub const STAGE_VISIBLE_ROWS: usize = 5;
    pub const STAGES_TITLE_BASELINE: f32 = 490.5;
    pub const STAGE_ROW_FIRST_Y: f32 = 502.0;
    pub const STAGE_ROW_PITCH: f32 = 30.0;
    pub const STAGE_ROW_X: f32 = 30.0;
    pub const STAGE_ROW_W: f32 = 518.0;
    pub const STAGE_ROW_H: f32 = 29.0;
    pub const STAGE_ICON_CENTER_DX: f32 = 21.5; // from row x
    pub const STAGE_ICON_DIAMETER: f32 = 22.0;
    pub const STAGE_NUMBER_X: f32 = 84.0;
    pub const STAGE_LABEL_X: f32 = 120.0;
    pub const STAGE_TEXT_BASELINE_DY: f32 = 19.5; // from row top
    pub const STAGE_BAR_X: f32 = 318.0;
    pub const STAGE_BAR_W: f32 = 160.0;
    pub const STAGE_BAR_W_PENDING: f32 = 146.0;
    pub const STAGE_BAR_H: f32 = 12.0;
    pub const STAGE_BAR_DY: f32 = 9.0; // from row top
    pub const STAGE_PERCENT_X: f32 = 495.0;
    pub const STAGE_PENDING_TEXT_X: f32 = 473.0;

    // ПРОВЕРКА ДРАЙВЕРОВ / DRIVER CHECK.
    pub const DRIVERS_CARD: R = [19.0, 697.0, 539.0, 274.0];
    pub const DRIVERS_STATE_ICON_CENTER: [f32; 2] = [51.5, 720.5];
    pub const DRIVERS_STATE_ICON_DIAMETER: f32 = 22.0;
    pub const DRIVERS_TITLE_X: f32 = 90.0;
    pub const DRIVERS_TITLE_BASELINE: f32 = 724.5;
    pub const DRIVERS_BUTTON: R = [420.0, 703.0, 118.0, 32.0];
    pub const DRIVER_ROW_FIRST_BASELINE: f32 = 757.8;
    pub const DRIVER_ROW_PITCH: f32 = 28.15;
    pub const DRIVER_ROWS_MAX: usize = 6;
    pub const DRIVER_ICON_CENTER_X: f32 = 51.0;
    pub const DRIVER_ICON_SIZE: f32 = 18.0;
    pub const DRIVER_NAME_X: f32 = 95.0;
    pub const DRIVER_VERSION_X: f32 = 296.0;
    pub const DRIVER_STATUS_ICON_CENTER_X: f32 = 426.5;
    pub const DRIVER_STATUS_ICON_DIAMETER: f32 = 18.0;
    pub const DRIVER_STATUS_TEXT_X: f32 = 448.0;
    /// Row hover band / content right edge inside the Driver card.
    pub const DRIVER_ROW_LEFT_X: f32 = 30.0;
    pub const DRIVER_ROW_RIGHT_X: f32 = 546.0;
    pub const DRIVERS_ALERT: R = [28.0, 913.0, 521.0, 48.0];
    pub const DRIVERS_ALERT_RADIUS: u8 = 6;
    pub const DRIVERS_ALERT_ICON: R = [41.0, 923.0, 30.0, 27.0];
    pub const DRIVERS_ALERT_TEXT_X: f32 = 95.0;
    pub const DRIVERS_ALERT_BASELINES: [f32; 2] = [931.5, 951.5];

    pub const RESULT_CARD: R = [19.0, 981.0, 539.0, 86.0];
    pub const RESULT_TITLE_BASELINE: f32 = 1003.5;
    pub const RESULT_ICON: R = [42.0, 1019.0, 31.0, 37.0];
    pub const RESULT_TEXT_X: f32 = 110.0;
    pub const RESULT_LINE_BASELINES: [f32; 2] = [1030.5, 1052.5];
    pub const RESULT_BUTTON_REPORT: R = [301.0, 1011.0, 113.0, 40.0];
    pub const RESULT_BUTTON_FOLDER: R = [425.0, 1011.0, 113.0, 40.0];

    pub const START_BUTTON: R = [116.0, 1071.0, 330.0, 38.0];

    // ---- Right column ----
    pub const OVERALL_CARD: R = [571.0, 121.0, 788.0, 245.0];
    pub const OVERALL_TITLE_BASELINE: f32 = 149.5;
    pub const OVERALL_RING_CENTER: [f32; 2] = [700.0, 258.0];
    pub const OVERALL_RING_OUTER_DIAMETER: f32 = 177.0;
    /// ~27% thinner than the master's 13px stroke (explicit correction:
    /// the ring is supporting information, not the focal point).
    pub const OVERALL_RING_TRACK_THICKNESS: f32 = 9.5;
    pub const OVERALL_RING_ACTIVE_THICKNESS: f32 = 9.5;
    /// Arc starts at 12 o'clock and sweeps clockwise (degrees, 0 = up).
    pub const OVERALL_RING_START_DEG: f32 = 0.0;
    pub const OVERALL_PERCENT_BASELINE: f32 = 271.5;
    pub const OVERALL_STATUS_BASELINE: f32 = 296.5;
    pub const TIME_ICON_CLOCK: R = [810.0, 205.0, 30.0, 30.0];
    pub const TIME_ICON_HOURGLASS: R = [812.0, 277.0, 26.0, 33.0];
    pub const TIME_TEXT_X: f32 = 858.0;
    pub const TIME_LABEL_BASELINES: [f32; 2] = [214.5, 287.5];
    pub const TIME_VALUE_BASELINES: [f32; 2] = [240.5, 313.5];
    pub const MODULES_CARD: R = [976.0, 161.0, 366.0, 184.0];
    pub const MODULES_TITLE_X: f32 = 992.0;
    pub const MODULES_TITLE_BASELINE: f32 = 187.5;
    pub const MODULE_ROWS_Y: [f32; 3] = [201.0, 249.5, 298.0];
    pub const MODULE_ROW_X: f32 = 986.0;
    pub const MODULE_ROW_W: f32 = 346.0;
    pub const MODULE_ROW_H: f32 = 40.0;
    pub const MODULE_ICON_CENTER_X: f32 = 1008.5;
    pub const MODULE_ICON_DIAMETER: f32 = 25.0;
    pub const MODULE_LABEL_X: f32 = 1041.0;
    pub const MODULE_STATUS_RIGHT_X: f32 = 1324.0;
    pub const MODULE_TEXT_BASELINE_DY: f32 = 25.5;

    // SSD / NVMe card — occupies the master's full right-column band
    // between Overall Progress and the Log (the former Current Operation
    // card is folded into the status bar, see STATUS_*).
    pub const SSD_CARD: R = [571.0, 378.0, 788.0, 577.0];
    pub const SSD_TITLE_X: f32 = 587.0;
    pub const SSD_TITLE_BASELINE: f32 = 402.5;
    pub const SSD_SUBTITLE_X: f32 = 587.0;
    pub const SSD_SUBTITLE_BASELINE: f32 = 427.5;

    /// FIXED THREE-SLOT disk row: always three card positions, so the
    /// section never reflows when a 3rd SSD appears/disappears. Empty
    /// slots render as a neutral "No SSD detected" card. Four SSDs use a
    /// compact 2x2 grid inside the SAME band (never growing the card).
    pub const SSD_SLOT_X: [f32; 3] = [583.0, 840.0, 1097.0];
    pub const SSD_SLOT_Y: f32 = 442.0;
    pub const SSD_SLOT_W: f32 = 249.0;
    pub const SSD_SLOT_H: f32 = 128.0;
    pub const SSD_SLOT_GRID_X: [f32; 2] = [583.0, 969.0];
    pub const SSD_SLOT_GRID_Y: [f32; 2] = [442.0, 509.0];
    pub const SSD_SLOT_GRID_W: f32 = 377.0;
    pub const SSD_SLOT_GRID_H: f32 = 61.0;
    /// Slot-relative placement (dx, dy from the slot's top-left).
    pub const SSD_SLOT_MARK_CENTER: [f32; 2] = [20.5, 21.0];
    pub const SSD_SLOT_MARK_DIAMETER: f32 = 21.0;
    pub const SSD_SLOT_ICON_CENTER: [f32; 2] = [42.0, 66.0];
    pub const SSD_SLOT_ICON_SIZE: f32 = 38.0;
    pub const SSD_SLOT_TEXT_DX: f32 = 77.0;
    pub const SSD_SLOT_BASELINES_DY: [f32; 3] = [44.0, 71.0, 97.0];

    /// READ/WRITE group frame. Rings sit inside with a uniform ≥17px gap;
    /// the delta line keeps ≥12px of air above the frame's bottom edge.
    pub const SSD_RING_FRAME: R = [582.0, 597.0, 403.0, 226.0];
    pub const READ_RING_CENTER: [f32; 2] = [683.5, 697.0];
    pub const WRITE_RING_CENTER: [f32; 2] = [883.5, 697.0];
    pub const RING_OUTER_DIAMETER: f32 = 166.0;
    /// ~27% thinner than the previous 9.6px (explicit correction).
    pub const RING_OUTER_STROKE: f32 = 7.0;
    pub const RING_INNER_DIAMETER: f32 = 132.0;
    pub const RING_INNER_STROKE: f32 = 3.2;
    pub const RING_INNER_TRACK_STROKE: f32 = 1.2;
    /// Bright "previous" arc on the inner ring (degrees, 0 = up, clockwise).
    pub const RING_INNER_ARC_DEG: [f32; 2] = [71.8, 292.0];
    pub const RING_LABEL_BASELINE: f32 = 661.5;
    pub const RING_CURRENT_BASELINE: f32 = 696.5;
    pub const RING_PREVIOUS_BASELINE: f32 = 730.5;
    pub const RING_UNIT_BASELINE: f32 = 755.0;
    pub const RING_DELTA_BASELINE: f32 = 806.0;
    /// Horizontal offset of the ring numbers from the ring centre.
    pub const RING_VALUE_DX: f32 = 1.0;

    /// Selected Drive Information panel (always visible).
    pub const SSD_INFO_PANEL: R = [997.0, 584.0, 352.0, 243.0];
    pub const SSD_INFO_TITLE_X: f32 = 1013.0;
    pub const SSD_INFO_TITLE_BASELINE: f32 = 608.5;
    pub const SSD_INFO_LABEL_X: f32 = 1014.0;
    pub const SSD_INFO_VALUE_X: f32 = 1151.0;
    pub const SSD_INFO_FIRST_BASELINE: f32 = 641.5;
    pub const SSD_INFO_PITCH: f32 = 28.3;
    pub const SSD_INFO_DOT_DIAMETER: f32 = 20.0;
    pub const SSD_INFO_NOTE: R = [1005.0, 773.0, 336.0, 48.0];
    pub const SSD_INFO_NOTE_ICON_CENTER: [f32; 2] = [1025.5, 797.0];
    pub const SSD_INFO_NOTE_TEXT_X: f32 = 1053.0;
    pub const SSD_INFO_NOTE_BASELINES: [f32; 2] = [792.0, 810.0];

    /// Run Test / Details: one row, equal heights, clear air above (frame)
    /// and below (metadata strip).
    pub const SSD_BUTTON_PRIMARY: R = [583.0, 834.0, 217.0, 37.0];
    pub const SSD_BUTTON_SECONDARY: R = [817.0, 834.0, 151.0, 37.0];

    /// Lower metadata strip: 2 rows x 3 columns
    /// (Profile | Passes | Duration / Read spread | Write spread | Stability).
    pub const SSD_META_STRIP: R = [582.0, 882.0, 767.0, 64.0];
    pub const SSD_META_COL_X: [f32; 3] = [582.0, 838.0, 1093.0];
    pub const SSD_META_COL_W: f32 = 256.0;
    pub const SSD_META_LABEL_DX: f32 = 11.0;
    pub const SSD_META_VALUE_DX: f32 = 124.0;
    pub const SSD_META_BASELINES: [f32; 2] = [904.0, 936.0];

    pub const JOURNAL_CARD: R = [571.0, 966.0, 788.0, 133.0];
    pub const JOURNAL_TITLE_BASELINE: f32 = 988.5;
    pub const JOURNAL_CLEAR_BUTTON: R = [1224.0, 970.0, 117.0, 29.0];
    /// v0.3.7 full-journal viewer: same size/height as Clear, 8 px to its left.
    pub const JOURNAL_OPEN_BUTTON: R = [1099.0, 970.0, 117.0, 29.0];
    pub const JOURNAL_PANEL: R = [588.0, 1001.0, 761.0, 93.0];
    pub const JOURNAL_LINE_PITCH: f32 = 18.0;
    pub const JOURNAL_FIRST_BASELINE: f32 = 1014.5;
    /// Baseline offset of a journal line inside its pitch-high row.
    pub const JOURNAL_LINE_BASELINE_DY: f32 = 13.5;
    pub const JOURNAL_TIMESTAMP_X: f32 = 596.0;
    pub const JOURNAL_MESSAGE_X: f32 = 675.0;
    pub const JOURNAL_SCROLLBAR_X: [f32; 2] = [1331.0, 1347.0];

    // ---- Status bar (also carries the compact Current Operation) ----
    pub const STATUS_SEPARATOR_Y: f32 = 1110.0;
    pub const STATUS_BAR: R = [1.0, 1111.0, 1376.0, 30.0];
    pub const STATUS_BAR_RIGHT_EDGE_X: f32 = 1377.0;
    pub const STATUS_TEXT_LEFT_X: f32 = 19.0;
    pub const STATUS_TEXT_RIGHT_X: f32 = 1347.0;
    pub const STATUS_BASELINE: f32 = 1130.5;
    /// Compact progress bar of the running operation (after its text).
    pub const STATUS_OP_BAR_W: f32 = 140.0;
    pub const STATUS_OP_BAR_H: f32 = 6.0;

    // ---- Controls ----
    pub const BUTTON_RADIUS: u8 = 6;
    pub const PROGRESS_BAR_RADIUS: u8 = 6;
}

// ---------------------------------------------------------------------------
// Colour tokens (median of flat regions / glyph cores in the master).
// ---------------------------------------------------------------------------

pub mod color {
    use super::Color32;
    const fn hex(v: u32) -> Color32 {
        Color32::from_rgb((v >> 16) as u8, (v >> 8) as u8, v as u8)
    }

    pub const BG_ROOT: Color32 = hex(0x000c18);
    pub const BG_CARD: Color32 = hex(0x071928);
    pub const BG_CARD_INNER: Color32 = hex(0x0a1b2d);
    pub const BG_ROW: Color32 = hex(0x0b1e32);
    pub const BG_ROW_ACTIVE: Color32 = hex(0x012041);
    pub const BG_ROW_ACTIVE_SOFT: Color32 = hex(0x0b1f36);
    pub const BG_FIELD: Color32 = hex(0x0f263b);
    pub const BG_JOURNAL: Color32 = hex(0x041321);

    pub const BORDER_NORMAL: Color32 = hex(0x264864);
    pub const BORDER_INNER: Color32 = hex(0x132a3f);
    pub const BORDER_FIELD: Color32 = hex(0x244560);
    pub const BORDER_ACTIVE: Color32 = hex(0x3d7bb0);
    pub const BORDER_JOURNAL: Color32 = hex(0x10273b);

    pub const TEXT_PRIMARY: Color32 = hex(0xf4f7fa);
    pub const TEXT_BODY: Color32 = hex(0xc8d6e3);
    pub const TEXT_SECONDARY: Color32 = hex(0xa3bbd2);
    pub const TEXT_MUTED: Color32 = hex(0x8ba7c4);
    pub const TEXT_SLOGAN: Color32 = hex(0x6688a8);
    pub const TEXT_TITLE: Color32 = hex(0x5ef7ff);
    /// Header subtitle: the master's saturated cyan (title family).
    pub const TEXT_SUBTITLE: Color32 = hex(0x35e6f5);
    pub const TEXT_PENDING: Color32 = hex(0xb0c2d4);

    pub const BLUE_PRIMARY: Color32 = hex(0x0071fd);
    pub const BLUE_BRIGHT: Color32 = hex(0x1d86ff);
    pub const BLUE_DARK: Color32 = hex(0x005dd1);
    pub const BLUE_ACCENT: Color32 = hex(0x0198f0);
    pub const BLUE_PROGRESS: Color32 = hex(0x0077fe);
    pub const BLUE_STAGE: Color32 = hex(0x00a5fc);
    pub const BLUE_STATUS: Color32 = hex(0x0ebdf0);

    pub const GREEN_SUCCESS: Color32 = hex(0x1ff274);
    pub const GREEN_PROGRESS: Color32 = hex(0x03f97e);
    pub const GREEN_WRITE: Color32 = hex(0x44fb66);
    pub const GREEN_DELTA: Color32 = hex(0x35f67e);

    pub const VIOLET_PREVIOUS_READ: Color32 = hex(0x8232ee);
    pub const VIOLET_TRACK: Color32 = hex(0x221745);
    pub const TEAL_PREVIOUS_WRITE: Color32 = hex(0x00b8bb);
    pub const TEAL_TRACK: Color32 = hex(0x032f34);
    /// Inner "previous" arcs: brighter towards the left (≈285°).
    pub const READ_PREVIOUS_ARC_STOPS: [(f32, Color32); 5] = [
        (0.0, hex(0x7424cc)),
        (72.0, hex(0x7424cc)),
        (180.0, hex(0x8232ee)),
        (285.0, hex(0x9e1fed)),
        (360.0, hex(0x9a22ea)),
    ];
    pub const WRITE_PREVIOUS_ARC_STOPS: [(f32, Color32); 5] = [
        (0.0, hex(0x00a5a9)),
        (72.0, hex(0x00a5a9)),
        (180.0, hex(0x00b8bb)),
        (285.0, hex(0x00ebe8)),
        (360.0, hex(0x00e0de)),
    ];
    pub const READ_LABEL: Color32 = hex(0x02a0fa);
    pub const READ_CURRENT: Color32 = hex(0x028ef7);
    pub const READ_PREVIOUS_TEXT: Color32 = hex(0xb23df8);
    /// Attention accents (1px perimeters; never change geometry).
    /// Client field pulse: the SSD READ "previous" violet.
    pub const ATTENTION_CLIENT: Color32 = hex(0xa04af4);
    /// "Открыть отчёт" pulse: warm amber of the warning family.
    pub const ATTENTION_REPORT: Color32 = hex(0xf0c24a);
    /// "Открыть папку": restrained static violet perimeter.
    pub const ACCENT_FOLDER: Color32 = hex(0x6b4aa8);
    pub const WRITE_LABEL: Color32 = hex(0x04fba1);
    pub const WRITE_CURRENT: Color32 = hex(0x03f7ae);
    pub const WRITE_PREVIOUS_TEXT: Color32 = hex(0x00f8f6);

    /// Overall ring gradient (along the arc, start -> end).
    pub const RING_BLUE_START: Color32 = hex(0x0075ff);
    pub const RING_BLUE_PEAK: Color32 = hex(0x00c6fe);
    /// READ outer ring conic gradient stops (0 = 12 o'clock, clockwise).
    pub const READ_RING_STOPS: [(f32, Color32); 5] = [
        (0.0, hex(0x0072fc)),
        (180.0, hex(0x0283f9)),
        (270.0, hex(0x00c5ff)),
        (315.0, hex(0x06a7ff)),
        (360.0, hex(0x0b8ffe)),
    ];
    /// WRITE outer ring conic gradient stops.
    pub const WRITE_RING_STOPS: [(f32, Color32); 6] = [
        (0.0, hex(0x3bfa6c)),
        (90.0, hex(0x44fb65)),
        (150.0, hex(0x01f996)),
        (180.0, hex(0x46fc74)),
        (270.0, hex(0x4ffa6d)),
        (360.0, hex(0x1af272)),
    ];

    pub const YELLOW_WARNING: Color32 = hex(0xf0c83a);
    /// One restrained gold accent family shared by: active RU/EN, the
    /// selected SSD card, the SSD connector and the READ/WRITE frame —
    /// tuned to sit with the EXPC gold logo, never fluorescent.
    pub const GOLD_ACCENT: Color32 = hex(0xe3bd2d);
    /// Subdued inactive language outline / text.
    pub const LANG_INACTIVE: Color32 = hex(0x2f628b);
    pub const LANG_INACTIVE_TEXT: Color32 = hex(0x9cc3e2);
    /// Empty SSD slot (no eligible SSD/NVMe in that position).
    pub const SSD_SLOT_EMPTY_BORDER: Color32 = hex(0x1b3650);
    pub const SSD_SLOT_EMPTY_TEXT: Color32 = hex(0x5d7894);
    pub const RED_ERROR: Color32 = hex(0xf04a4c);
    // Driver Audit card (master samples).
    pub const DRIVER_NAME: Color32 = hex(0xcfdbe8);
    pub const DRIVER_NAME_PROBLEM: Color32 = hex(0xf85350);
    pub const DRIVER_VERSION: Color32 = hex(0xbacee0);
    pub const DRIVER_STATUS_PROBLEM: Color32 = hex(0xfe4548);
    pub const DRIVER_STATUS_PROBLEM_TEXT: Color32 = hex(0xea5952);
    pub const DRIVER_STATUS_OK: Color32 = hex(0x1dfb79);
    pub const DRIVER_STATUS_OK_TEXT: Color32 = hex(0x22e66e);
    pub const DRIVER_STATUS_WARN: Color32 = hex(0xffe23a);
    pub const DRIVER_STATUS_WARN_TEXT: Color32 = hex(0xf2cf47);
    pub const DRIVER_ICON_GPU: Color32 = hex(0x8ff29c);
    pub const DRIVER_ICON_CHIP: Color32 = hex(0xfed32d);
    pub const DRIVER_ICON_AUDIO: Color32 = hex(0xffe04e);
    pub const DRIVER_ICON_NET: Color32 = hex(0xffe848);
    pub const DRIVER_ICON_STORAGE: Color32 = hex(0x61b7ff);
    pub const DRIVER_ICON_OTHER: Color32 = hex(0xa3badb);
    pub const DRIVER_ICON_PROBLEM: Color32 = hex(0xf74143);
    pub const ALERT_PROBLEM_FILL: Color32 = hex(0x2e1622);
    pub const ALERT_PROBLEM_BORDER: Color32 = hex(0x6a2b37);
    pub const ALERT_PROBLEM_ICON: Color32 = hex(0xffb4ae);
    pub const ALERT_PROBLEM_TEXT_1: Color32 = hex(0xe5bac1);
    pub const ALERT_PROBLEM_TEXT_2: Color32 = hex(0xdeafb9);
    pub const ALERT_WARN_FILL: Color32 = hex(0x2a2414);
    pub const ALERT_WARN_BORDER: Color32 = hex(0x6a5a2b);
    pub const ALERT_WARN_ICON: Color32 = hex(0xffd866);
    pub const ALERT_WARN_TEXT_1: Color32 = hex(0xeadcb4);
    pub const ALERT_WARN_TEXT_2: Color32 = hex(0xdcceaa);

    pub const PROGRESS_TRACK: Color32 = hex(0x0c1f30);
    pub const PROGRESS_TRACK_BORDER: Color32 = hex(0x204263);
    pub const PROGRESS_TRACK_PENDING: Color32 = hex(0x152e46);
    pub const PROGRESS_TRACK_PENDING_BORDER: Color32 = hex(0x345471);
    pub const PROGRESS_TRACK_WIDE: Color32 = hex(0x142d44);
    pub const PROGRESS_TRACK_WIDE_BORDER: Color32 = hex(0x2e506b);
    pub const RING_TRACK: Color32 = hex(0x12273d);
    pub const PENDING: Color32 = hex(0xa4bbdc);
    /// Pending module ring (slightly dimmer than the stage-row ring).
    pub const PENDING_MODULE: Color32 = hex(0x97b0d1);
    /// Stage-row text: running rows are a touch dimmer than done rows,
    /// pending rows a touch brighter than TEXT_BODY (master samples).
    pub const TEXT_STAGE_RUNNING: Color32 = hex(0xcfdbea);
    pub const TEXT_STAGE_RUNNING_PERCENT: Color32 = hex(0xdfe8f2);
    pub const TEXT_STAGE_PENDING: Color32 = hex(0xd6dfe9);
    pub const ICON_TIME: Color32 = hex(0x01aeff);
    pub const BUTTON_SUBTLE_TEXT: Color32 = hex(0xd7e2ec);
    pub const RADIO_UNSELECTED: Color32 = hex(0x1f3952);
    /// Unselected option radio: brighter 2.5px ring on a slightly lifted disc.
    pub const RADIO_RING_OFF: Color32 = hex(0x23415d);
    pub const RADIO_FILL_OFF: Color32 = hex(0x0a1c2c);

    pub const BUTTON_SECONDARY_FILL: Color32 = hex(0x10253b);
    pub const BUTTON_SECONDARY_HOVER: Color32 = hex(0x173350);
    pub const BUTTON_SECONDARY_PRESSED: Color32 = hex(0x0b1b2c);
    pub const BUTTON_SECONDARY_BORDER: Color32 = hex(0x315472);
    pub const BUTTON_DISABLED_FILL: Color32 = hex(0x16283a);
    pub const BUTTON_DISABLED_TEXT: Color32 = hex(0x5d7189);

    pub const SCROLL_TRACK: Color32 = hex(0x091b2c);
    pub const SCROLL_TRACK_BORDER: Color32 = hex(0x12283c);
    pub const SCROLL_THUMB: Color32 = hex(0x2f4f6d);
    pub const SCROLL_THUMB_HOVER: Color32 = hex(0x3b6186);
    pub const SCROLL_ARROW: Color32 = hex(0x385a7e);
    pub const ICON_TRASH: Color32 = hex(0xb3b6dc);
    /// Headline white (app title, big metrics) is brighter than body text.
    pub const TEXT_HEADLINE: Color32 = hex(0xfbfcfd);

    pub const STATUS_BAR_FILL: Color32 = hex(0x010f1c);
    pub const STATUS_BAR_SEPARATOR: Color32 = hex(0x243d53);
    pub const STATUS_BAR_TEXT: Color32 = hex(0xbcc3cf);
    pub const STATUS_BAR_DIVIDER: Color32 = hex(0x66768a);

    pub const JOURNAL_TIMESTAMP: Color32 = hex(0xbec4d0);
    pub const JOURNAL_MESSAGE: Color32 = hex(0xbfc7d1);
    pub const JOURNAL_MESSAGE_DIM: Color32 = hex(0x8a99ac);

    // ---- Status / progress visual intensity (restrained hierarchy) ----
    // "Intensity" k blends a colour from the card background (k = 0) to
    // its full value (k = 1): information (numbers, labels, buttons) stays
    // at full strength, progress decoration is quieter.
    /// Running stage bar: slow blue breathing between these bounds.
    pub const STAGE_RUNNING_INTENSITY_MIN: f32 = 0.65;
    pub const STAGE_RUNNING_INTENSITY_MAX: f32 = 0.75;
    /// Seconds per full breath (65% -> 75% -> 65%).
    pub const STAGE_RUNNING_PULSE_PERIOD: f64 = 2.6;
    /// Completed stage bar: static quiet green.
    pub const STAGE_DONE_INTENSITY: f32 = 0.60;
    /// Overall progress ring (completed green and running blue).
    pub const OVERALL_RING_INTENSITY: f32 = 0.65;
    /// READ/WRITE outer (current) rings and the quieter inner (previous) arcs.
    pub const RW_RING_INTENSITY: f32 = 0.68;
    pub const RW_PREVIOUS_RING_INTENSITY: f32 = 0.56;
}

// ---------------------------------------------------------------------------
// Typography tokens (logical px == points at ppp 1; egui font size is the
// em size, so these are directly comparable with the master measurements).
// ---------------------------------------------------------------------------

pub mod typography {
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum Weight {
        Regular,
        Semibold,
        Bold,
        Mono,
    }

    #[derive(Clone, Copy, Debug)]
    pub struct TextStyle {
        pub size: f32,
        pub weight: Weight,
    }

    const fn s(size: f32, weight: Weight) -> TextStyle {
        TextStyle { size, weight }
    }
    use Weight::*;

    // Sizes fitted to the master's measured ink widths (real Windows capture,
    // Segoe UI, ppp 1.0; see docs/UI_VISUAL_MASTER.md §Typography). The
    // master's glyph widths vary by a few percent between elements, so a
    // few roles carry their own measured size instead of sharing one.
    /// Header RU/EN language switch (v0.3.6 Visual Master alignment, §2:
    /// shrunk alongside the button itself).
    pub const LANG_BUTTON: TextStyle = s(12.5, Semibold);
    pub const APP_TITLE: TextStyle = s(37.0, Semibold);
    pub const APP_SUBTITLE: TextStyle = s(19.3, Regular);
    pub const SLOGAN: TextStyle = s(17.2, Regular);
    /// Generic card title (fallback for titles without a measured size).
    pub const CARD_TITLE: TextStyle = s(17.6, Semibold);
    pub const TITLE_EXPC: TextStyle = s(17.75, Semibold);
    pub const TITLE_HARDWARE: TextStyle = s(18.0, Semibold);
    pub const TITLE_STAGES: TextStyle = s(17.8, Semibold);
    pub const TITLE_RESULT: TextStyle = s(17.4, Semibold);
    pub const TITLE_OVERALL: TextStyle = s(17.6, Semibold);
    pub const TITLE_OPERATION: TextStyle = s(17.4, Semibold);
    pub const TITLE_SSD: TextStyle = s(20.0, Semibold);
    pub const TITLE_JOURNAL: TextStyle = s(18.2, Semibold);
    pub const SECTION_TITLE: TextStyle = s(16.6, Semibold);
    pub const LABEL_LARGE: TextStyle = s(17.5, Semibold);
    pub const BODY: TextStyle = s(15.6, Regular);
    pub const BODY_STRONG: TextStyle = s(15.6, Semibold);
    /// CryptoPro card status / action and the compact deep-check toggles.
    /// HASH / NO HASH / … — large enough to read as one object with the check.
    pub const CRYPTO_STATUS: TextStyle = s(20.0, Semibold);
    pub const CRYPTO_NAME: TextStyle = s(18.5, Semibold);
    pub const CRYPTO_ACTION: TextStyle = s(15.0, Regular);
    /// The large `—` (NOT INSTALLED) status indicator, sized with the other
    /// ~42px status icons (HASH OK / NO HASH / CHECK ERROR).
    pub const CRYPTO_STATUS_ICON: TextStyle = s(34.0, Semibold);
    pub const DEEP_TOGGLE: TextStyle = s(12.8, Regular);
    /// "Hardware Report" checkbox label.
    pub const CHECK_LABEL: TextStyle = s(16.2, Regular);
    /// Stage numbers and percentages.
    pub const BODY_SMALL: TextStyle = s(15.0, Regular);
    pub const STAGE_LABEL: TextStyle = s(14.75, Regular);
    /// Latin-only stage labels (the master sets them ~2% wider).
    pub const STAGE_LABEL_LATIN: TextStyle = s(15.0, Regular);
    /// Right-hand "Ожидание" of pending stage rows.
    pub const STAGE_PENDING: TextStyle = s(14.0, Regular);
    pub const BODY_SECONDARY: TextStyle = s(15.9, Regular);
    pub const SSD_META_LABEL: TextStyle = s(15.2, Regular);
    pub const SSD_META_VALUE: TextStyle = s(15.6, Regular);
    /// Lower SSD metadata strip (Profile / Passes / … / Stability).
    pub const SSD_STRIP_LABEL: TextStyle = s(14.0, Regular);
    pub const SSD_STRIP_VALUE: TextStyle = s(14.0, Semibold);
    /// Temp-file note inside the Selected Drive Information panel.
    pub const SSD_NOTE: TextStyle = s(12.0, Regular);
    pub const CAPTION: TextStyle = s(14.2, Regular);
    /// "Прошло" / "Осталось (ETA)".
    pub const TIME_LABEL: TextStyle = s(13.5, Regular);
    pub const MUTED: TextStyle = s(15.0, Regular);
    pub const METRIC_LARGE: TextStyle = s(41.5, Semibold);
    pub const METRIC_MEDIUM: TextStyle = s(26.0, Semibold);
    pub const METRIC_SMALL: TextStyle = s(18.5, Regular);
    pub const RING_STATUS: TextStyle = s(15.2, Regular);
    /// Scaled down with the ring (196 -> 150) so the current-value number
    /// still fits comfortably inside the smaller ring.
    pub const SSD_CURRENT: TextStyle = s(32.0, Semibold);
    pub const SSD_PREVIOUS: TextStyle = s(27.0, Semibold);
    pub const SSD_UNIT: TextStyle = s(14.0, Regular);
    pub const SSD_RING_LABEL: TextStyle = s(15.5, Semibold);
    /// Disk-selector card text (v0.3.6 UI finalization).
    pub const SSD_DISK_LETTER: TextStyle = s(15.5, Semibold);
    /// Real Windows volume label next to the letter (data, never localized).
    pub const SSD_DISK_VOLUME_LABEL: TextStyle = s(15.0, Regular);
    pub const SSD_DISK_MODEL: TextStyle = s(14.2, Regular);
    pub const SSD_DISK_BUS: TextStyle = s(13.5, Regular);
    pub const SSD_DISK_BADGE: TextStyle = s(10.5, Semibold);
    pub const DELTA: TextStyle = s(20.0, Semibold);
    pub const OPERATION_TITLE: TextStyle = s(20.5, Semibold);
    pub const PROGRESS_PERCENT: TextStyle = s(21.0, Semibold);
    pub const BUTTON_TEXT_LARGE: TextStyle = s(19.1, Regular);
    pub const BUTTON_TEXT: TextStyle = s(16.0, Regular);
    // Driver Audit card (initial fit to the master; see UI_VISUAL_MASTER.md §12).
    pub const TITLE_DRIVERS: TextStyle = s(17.0, Semibold);
    pub const DRIVER_NAME: TextStyle = s(15.6, Regular);
    pub const DRIVER_VERSION: TextStyle = s(14.2, Regular);
    pub const DRIVER_STATUS: TextStyle = s(15.0, Regular);
    pub const ALERT_TEXT: TextStyle = s(14.2, Regular);
    pub const BUTTON_TEXT_SMALL: TextStyle = s(13.5, Regular);
    pub const MONO: TextStyle = s(13.5, Mono);
    pub const STATUS_BAR: TextStyle = s(14.5, Regular);
    /// Left status text ("Готов к работе").
    pub const STATUS_LEFT: TextStyle = s(13.5, Regular);
}
