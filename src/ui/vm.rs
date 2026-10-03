//! Presentation view-model. Every string, fraction and status that the
//! dashboard shows lives here; the renderer only reads it. Live mode builds
//! it from the real application state (app.rs), the QA reference fixture
//! (fixture.rs) fills it literally. No backend type is modified.

pub use crate::i18n::Language;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RowState {
    Pending,
    Running,
    Done,
    Skipped,
    Error,
}

/// v0.4.0: diagnostic RESULT of a completed deep-check row (SFC / DISM /
/// CHKDSK). Independent of progress: "100%" still means the check ran to
/// completion; this says what it found.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StageFinding {
    Ok,
    Attention,
    Error,
    Unknown,
}

#[derive(Clone, Debug)]
pub struct StageRow {
    pub number: usize,
    pub label: String,
    pub full_label: String,
    pub state: RowState,
    /// Determinate fill (0..1). `None` while running = indeterminate.
    pub fraction: Option<f32>,
    pub right_text: String,
    pub active: bool,
    /// Deep-check result (only for a completed SFC / DISM / CHKDSK row).
    pub finding: Option<StageFinding>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ModuleState {
    Pending,
    Running,
    Done,
    Error,
    NotSelected,
}

#[derive(Clone, Debug)]
pub struct ModuleRow {
    pub label: String,
    pub state: ModuleState,
    pub status_text: String,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tone {
    Idle,
    Running,
    Success,
    Warning,
    Error,
}

#[derive(Clone, Debug)]
pub struct OverallVm {
    pub fraction: f32,
    pub percent_text: String,
    pub status_text: String,
    pub tone: Tone,
    pub elapsed: String,
    pub eta: String,
    pub modules: Vec<ModuleRow>,
}

#[derive(Clone, Debug)]
pub struct OperationVm {
    pub name: String,
    pub subtitle: String,
    pub fraction: Option<f32>,
    pub percent_text: String,
    pub indeterminate: bool,
    pub tone: Tone,
}

#[derive(Clone, Debug)]
pub struct MetaRow {
    pub label: String,
    pub value: String,
    pub value_tone: Tone,
    /// Draw a status dot before the value (Стабильность row).
    pub dot: bool,
}

/// One clickable card in the physical-disk selector (v0.3.6 multi-SSD/NVMe
/// UI finalization). Every field is read-only display data resolved once by
/// the app layer from `storage_topology`; the card itself never edits a
/// path — WinStateDiag always knows which writable volume backs the
/// selected physical disk.
#[derive(Clone, Debug, PartialEq)]
pub struct DiskEntryVm {
    /// Drive letter of the chosen writable volume, e.g. "C:", or "—" when
    /// this disk currently has no writable volume.
    pub drive_letter: String,
    /// The REAL Windows volume label of that same mapped volume (e.g.
    /// "Win11", "Data") — data, never localized, never invented. `None`
    /// when the volume has no label (the card then shows only the letter).
    pub volume_label: Option<String>,
    /// e.g. "Samsung 9100 PRO 1TB".
    pub model: String,
    /// e.g. "1 TB".
    pub capacity: String,
    /// Exactly as Windows reports it (e.g. "NVMe", "SATA") — never a
    /// guessed PCIe generation.
    pub interface: String,
    /// `None` when Windows did not report a serial for this device.
    pub serial: Option<String>,
    /// True only for the physical disk that backs `SystemDrive` — shown
    /// with the small Windows-logo glyph; every other SSD/NVMe gets the
    /// neutral disk glyph.
    pub is_system: bool,
    /// False when this disk currently has no writable volume WinStateDiag
    /// can benchmark (card stays selectable, but the Start button explains
    /// why it can't run instead of silently falling back to `C:`).
    pub has_target: bool,
}

#[derive(Clone, Debug)]
pub enum SsdVm {
    Idle,
    Running {
        fraction: f32,
        status: String,
        elapsed: String,
        /// v0.4.2: note lines during the automatic retest (first run kept
        /// visible); `None` = the usual temp-file note.
        note: Option<[String; 2]>,
    },
    Done {
        /// v0.4.2 storage correlation result for the status line (text,
        /// tone); `None` until it is known.
        status: Option<(String, Tone)>,
        /// Two note lines replacing the temp-file note when an automatic
        /// retest was involved (first run kept visible).
        note: Option<[String; 2]>,
        read_current: String,
        read_previous: Option<String>,
        read_delta: Option<f64>,
        write_current: String,
        write_previous: Option<String>,
        write_delta: Option<f64>,
        meta: Vec<MetaRow>,
    },
    Failed(String),
    Cancelled,
}

#[derive(Clone, Debug)]
pub enum ResultVm {
    Idle,
    Running,
    Done {
        path_display: String,
        /// Soft amber pulse on "Открыть отчёт" until the report is opened.
        attention: bool,
    },
    Failed {
        message: String,
    },
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StartVm {
    Start { enabled: bool },
    Running,
    NewDiagnostic,
}

#[derive(Clone, Debug)]
pub struct JournalLine {
    pub timestamp: String,
    pub message: String,
    pub dim: bool,
}

/// Generic device-category glyphs for the Driver Audit card (no brand logos).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DeviceIcon {
    Gpu,
    Chip,
    Audio,
    Wifi,
    Ethernet,
    Storage,
    Kernel,
    Generic,
}

#[derive(Clone, Debug)]
pub struct DriverRow {
    pub icon: DeviceIcon,
    pub name: String,
    pub version: String,
    /// Success = OK, Warning = Внимание, Error = Проблема.
    pub tone: Tone,
    pub status_text: String,
    /// Hover text: full device name and the reason for the status.
    pub tooltip: String,
}

#[derive(Clone, Debug)]
pub enum DriversVm {
    Running,
    /// Collection failed or is unavailable; the message says why.
    Unavailable(String),
    Done {
        overall: Tone,
        rows: Vec<DriverRow>,
        /// Flagged items that did not fit on the card.
        more: usize,
        /// Alert strip (only with problems/warnings): tone + two lines.
        alert: Option<(Tone, String, String)>,
        /// Green state line when nothing was found.
        ok_line: String,
    },
}

#[derive(Clone, Debug)]
pub struct DashboardVm {
    pub controls_enabled: bool,
    /// Stop button: shown and enabled only while EXPC Diagnostic runs.
    pub stop_enabled: bool,
    /// CryptoPro card: exactly one current state.
    pub crypto: CryptoVm,
    pub computer_name: String,
    pub stages: Vec<StageRow>,
    pub overall: OverallVm,
    pub operation: OperationVm,
    pub ssd: SsdVm,
    pub ssd_controls_enabled: bool,
    /// Physical SSD/NVMe selector (v0.3.6): every candidate disk, and which
    /// one benchmarking currently targets. Empty when no SSD/NVMe could be
    /// enumerated (never invented, never silently assumed to be `C:`).
    pub ssd_disks: Vec<DiskEntryVm>,
    pub ssd_selected: usize,
    pub drivers: DriversVm,
    pub result: ResultVm,
    pub start: StartVm,
    pub journal: Vec<JournalLine>,
    /// Live mode follows the newest line; the QA fixture shows the top.
    pub journal_follow_tail: bool,
    pub status_left: String,
    pub status_right: Vec<String>,
    /// Animation clock (seconds). Frozen in reference mode.
    pub time: f64,
    pub animate: bool,
    /// Active UI language (v0.3.6 bilingual pass). Every draw function
    /// reads `crate::i18n::t(vm.lang)` for its static text instead of
    /// hardcoding a language.
    pub lang: Language,
}

/// UI -> app intents, applied after rendering (keeps borrows disjoint).
/// CryptoPro card state (one card, one state at a time).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CryptoVm {
    /// Read-only check (or ReHash) in progress.
    Checking,
    HashOk,
    NoHash,
    NotInstalled,
    CheckError,
}

#[derive(Clone, Debug)]
pub enum Action {
    /// NO HASH clicked: ask for confirmation of the ReHash.
    CryptoRehashRequest,
    /// A physical-disk card was clicked directly (v0.3.6 UI finalization):
    /// select exactly that candidate index. No dropdown, no cycling.
    SelectSsdDisk(usize),
    /// Header RU/EN switch clicked: change the active UI language
    /// immediately (no restart, no window recreation).
    SetLanguage(Language),
    Start,
    /// Stop the running diagnostic (graceful request; only this session's
    /// own process tree is terminated).
    Stop,
    Reset,
    /// Open the FINAL verified report of the completed session (the app
    /// resolves the path from its own state; the UI never supplies one).
    OpenReport,
    /// Open the folder of that same final report.
    OpenFolder,
    BenchmarkStart,
    BenchmarkCancel,
    ViewHardware,
    ClearLog,
    /// v0.3.7: open the full session journal viewer.
    OpenJournal,
    ShowRawPasses,
    ShowDrivers,
    /// v0.4.1: open the EXPC diagnostic results window.
    ShowExpcDetails,
}

// Stage short labels / descriptions moved to `crate::i18n::Dict` (v0.3.6
// bilingual pass) — `i18n::t(lang).stage_short` / `.stage_description`.

/// The Client field asks for attention (purple pulse) only while empty.
pub fn client_attention(client: &str) -> bool {
    client.trim().is_empty()
}

/// Soft pulse level 0..1 (cosine ease, `period` seconds per full cycle).
pub fn pulse_level(time: f64, period: f64) -> f32 {
    let phase = (time / period).fract();
    (0.5 - 0.5 * (phase * std::f64::consts::TAU).cos()) as f32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_pulse_only_while_empty() {
        assert!(client_attention(""));
        assert!(client_attention("   \t "));
        assert!(!client_attention("Мегастрой"));
        assert!(!client_attention("Acme Ltd"));
        assert!(!client_attention("  Иванов И.И.  "));
    }

    #[test]
    fn pulse_is_smooth_and_periodic() {
        assert!(pulse_level(0.0, 1.8) < 0.001);
        assert!((pulse_level(0.9, 1.8) - 1.0).abs() < 0.001);
        assert!((pulse_level(1.8, 1.8) - pulse_level(0.0, 1.8)).abs() < 0.001);
        for i in 0..100 {
            let v = pulse_level(i as f64 * 0.037, 1.8);
            assert!((0.0..=1.0).contains(&v));
        }
    }
}
