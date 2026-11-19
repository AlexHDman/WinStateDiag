//! PowerLab IPC contract — version 1.
//!
//! The GUI never touches hardware. It starts a **separate sampler process** and
//! exchanges newline-delimited JSON messages with it. Everything in this module is
//! the frozen contract between those two processes.
//!
//! ## Why a separate process
//!
//! The providers call synchronous Windows APIs (`PdhCollectQueryData`, the NVML
//! entry points) that can block for an unbounded time. No safe-Rust mechanism can
//! interrupt such a call, and this project never force-terminates threads. Running
//! the providers in their own process makes the whole lifetime controllable: the
//! supervisor can terminate the process, which releases every resource the process
//! held, including a driver handle inside a blocked call.
//!
//! ## Wire format
//!
//! One JSON object per line, UTF-8, `\n` terminated. Both directions use the same
//! envelope so a reader can always tell what it has:
//!
//! * sampler -> GUI: [`SamplerMessage`]
//! * GUI -> sampler: [`HostMessage`]
//!
//! The `v` field is the contract version. A reader must reject a message whose
//! version it does not know rather than guess: a silently misinterpreted sample is
//! worse than a refused one.

use std::collections::{BTreeMap, VecDeque};
use std::fmt;

/// Contract version carried by every message.
pub const PROTOCOL_VERSION: u32 = 1;

/// Longest single line the reader will accept, in bytes.
///
/// A provider that goes wrong could otherwise make the reader allocate without
/// bound. The cap is generous for one sample (a full snapshot with every metric is
/// a few kilobytes) and small enough to bound memory.
pub const MAX_LINE_BYTES: usize = 1 << 20;

/// How many consecutive unparsable lines the reader tolerates before giving up.
pub const MAX_CONSECUTIVE_PARSE_ERRORS: u32 = 8;

// ---------------------------------------------------------------------------
// Metric states and provenance
// ---------------------------------------------------------------------------

/// The state of one reading.
///
/// These are the states the acceptance criteria name, and they are deliberately
/// distinct: `NoData` is not "OK", `Zero` is a real measurement of zero, and
/// `Error` is a technical failure that must never be presented as missing data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricState {
    /// A measured value.
    Ok,
    /// A measured value that is exactly zero.
    ///
    /// This state is a claim *about the number*, not a label that may be attached to
    /// any reading: it must carry `0.0` and nothing else. A `ZERO` that carries a
    /// non-zero number contradicts itself (the state says "the measurement was zero",
    /// the number says otherwise), and it is refused by [`Metric::is_consistent`] and
    /// by [`metric_from_json`] rather than repaired in either direction — reading the
    /// number would average a non-zero reading under a zero state, and overwriting it
    /// with `0.0` would invent a measurement nobody made.
    Zero,
    /// The channel exists but published nothing usable.
    NoData,
    /// The channel does not exist on this machine or needs a provider that is not
    /// present. Not a failure of this program.
    Unsupported,
    /// A real failure: registration failed, the counter reported an error status,
    /// or the read failed. Carries a concrete reason and **never** a value: an
    /// error that still carried a usable number could be averaged into a report.
    Error,
    /// A value that is present but not trustworthy (implausible, or read while the
    /// counter was in a transient state). The value is kept and flagged.
    Suspect,
    /// Two providers disagree about the same quantity.
    Conflict,
}

impl MetricState {
    /// The stable wire/code name.
    pub fn as_str(self) -> &'static str {
        match self {
            MetricState::Ok => "OK",
            MetricState::Zero => "ZERO",
            MetricState::NoData => "NO_DATA",
            MetricState::Unsupported => "UNSUPPORTED",
            MetricState::Error => "ERROR",
            MetricState::Suspect => "SUSPECT",
            MetricState::Conflict => "CONFLICT",
        }
    }

    /// Parse the wire name. Unknown names are an error, never a default.
    pub fn parse(value: &str) -> Result<Self, ContractError> {
        Ok(match value {
            "OK" => MetricState::Ok,
            "ZERO" => MetricState::Zero,
            "NO_DATA" => MetricState::NoData,
            "UNSUPPORTED" => MetricState::Unsupported,
            "ERROR" => MetricState::Error,
            "SUSPECT" => MetricState::Suspect,
            "CONFLICT" => MetricState::Conflict,
            other => {
                return Err(ContractError::UnknownState(other.to_string()));
            }
        })
    }

    /// Does this state carry a usable measurement?
    pub fn has_value(self) -> bool {
        matches!(
            self,
            MetricState::Ok | MetricState::Zero | MetricState::Suspect
        )
    }

    /// Must this state carry a value, or must it not?
    ///
    /// `Ok`, `Zero` and `Suspect` describe a number (a good one, a confirmed zero,
    /// or one that is kept but flagged). Every other state describes the *absence*
    /// of a number, so a value next to it is a contradiction, not a detail.
    pub fn requires_value(self) -> bool {
        self.has_value()
    }
}

/// How a value was obtained. Never present an estimate as a measurement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueKind {
    /// Read from a sensor or counter.
    Measured,
    /// Computed from measured values by a stated rule.
    Derived,
    /// Modelled or extrapolated. Only ever shown as an estimate.
    Estimate,
}

impl ValueKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ValueKind::Measured => "measured",
            ValueKind::Derived => "derived",
            ValueKind::Estimate => "estimate",
        }
    }

    pub fn parse(value: &str) -> Result<Self, ContractError> {
        Ok(match value {
            "measured" => ValueKind::Measured,
            "derived" => ValueKind::Derived,
            "estimate" => ValueKind::Estimate,
            other => return Err(ContractError::UnknownKind(other.to_string())),
        })
    }
}

/// How much the value should be trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl Confidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Confidence::Low => "low",
            Confidence::Medium => "medium",
            Confidence::High => "high",
        }
    }

    pub fn parse(value: &str) -> Result<Self, ContractError> {
        Ok(match value {
            "low" => Confidence::Low,
            "medium" => Confidence::Medium,
            "high" => Confidence::High,
            other => return Err(ContractError::UnknownConfidence(other.to_string())),
        })
    }
}

/// Which group a metric belongs to in the UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Group {
    Cpu,
    Gpu,
    Motherboard,
    Memory,
    Battery,
    Cooling,
    Storage,
    System,
}

impl Group {
    pub fn as_str(self) -> &'static str {
        match self {
            Group::Cpu => "CPU",
            Group::Gpu => "GPU",
            Group::Motherboard => "Motherboard",
            Group::Memory => "RAM",
            Group::Battery => "Battery",
            Group::Cooling => "Cooling",
            Group::Storage => "Storage",
            Group::System => "System",
        }
    }

    pub fn parse(value: &str) -> Result<Self, ContractError> {
        Ok(match value {
            "CPU" => Group::Cpu,
            "GPU" => Group::Gpu,
            "Motherboard" => Group::Motherboard,
            "RAM" => Group::Memory,
            "Battery" => Group::Battery,
            "Cooling" => Group::Cooling,
            "Storage" => Group::Storage,
            "System" => Group::System,
            other => return Err(ContractError::UnknownGroup(other.to_string())),
        })
    }

    /// Display order in the UI.
    pub const ALL: [Group; 8] = [
        Group::Cpu,
        Group::Gpu,
        Group::Motherboard,
        Group::Memory,
        Group::Battery,
        Group::Cooling,
        Group::Storage,
        Group::System,
    ];
}

/// Everything the UI needs about one metric.
///
/// The acceptance criteria require every reading to identify itself: id, value,
/// unit, provider, sensor identity, timestamp, kind, confidence, validity and a
/// reason when it is not OK.
#[derive(Debug, Clone, PartialEq)]
pub struct Metric {
    /// Stable identifier, e.g. `cpu.package_power`. Never localised.
    pub id: String,
    /// Human label (Russian, matching the rest of the module).
    pub label: String,
    pub group: Group,
    pub unit: String,
    pub state: MetricState,
    /// The value, present exactly when `state.has_value()`.
    ///
    /// The two directions are both enforced, not merely documented: a state that
    /// describes a measurement must carry a finite number, and a state that
    /// describes the absence of one must not carry any number at all. A reader
    /// that sees a contradiction must refuse the metric — see
    /// [`Metric::is_consistent`] and [`metric_from_json`].
    pub value: Option<f64>,
    pub raw_value: Option<f64>,
    pub raw_unit: Option<String>,
    pub hardware: Option<String>,
    pub kind: ValueKind,
    pub confidence: Confidence,
    /// Provider identity, e.g. `windows.emi/pdh:Energy Meter`.
    pub source: String,
    /// The concrete sensor or counter behind the value, when known.
    pub sensor: Option<String>,
    /// Milliseconds since the Unix epoch, as reported by the sampler.
    pub timestamp_ms: u64,
    /// Why this is not `OK`/`ZERO`. Required for every non-value state.
    pub reason: Option<String>,
    /// Short extra facts (raw counter value, min/max limits, board mapping).
    pub notes: Vec<String>,
}

impl Metric {
    /// Build an unavailable metric. `reason` is mandatory so a state can never be
    /// reported without an explanation.
    pub fn unavailable(
        id: &str,
        label: &str,
        group: Group,
        unit: &str,
        state: MetricState,
        reason: impl Into<String>,
        source: &str,
    ) -> Self {
        Metric {
            id: id.to_string(),
            label: label.to_string(),
            group,
            unit: unit.to_string(),
            state,
            value: None,
            raw_value: None,
            raw_unit: None,
            hardware: None,
            kind: ValueKind::Measured,
            confidence: Confidence::Low,
            source: source.to_string(),
            sensor: None,
            timestamp_ms: 0,
            reason: Some(reason.into()),
            notes: Vec::new(),
        }
    }

    /// Build a measured metric.
    pub fn measured(
        id: &str,
        label: &str,
        group: Group,
        unit: &str,
        value: f64,
        source: &str,
    ) -> Self {
        if !value.is_finite() {
            return Self::unavailable(
                id,
                label,
                group,
                unit,
                MetricState::Error,
                "non-finite provider result rejected",
                source,
            );
        }
        // A measured zero is a measurement, not missing data; the state records
        // that distinction so the two can never be conflated downstream.
        let state = if value == 0.0 {
            MetricState::Zero
        } else {
            MetricState::Ok
        };
        Metric {
            id: id.to_string(),
            label: label.to_string(),
            group,
            unit: unit.to_string(),
            state,
            value: Some(value),
            raw_value: Some(value),
            raw_unit: Some(unit.to_string()),
            hardware: None,
            kind: ValueKind::Measured,
            confidence: Confidence::High,
            source: source.to_string(),
            sensor: None,
            timestamp_ms: 0,
            reason: None,
            notes: Vec::new(),
        }
    }

    pub fn with_sensor(mut self, sensor: &str) -> Self {
        self.sensor = Some(sensor.to_string());
        self
    }

    pub fn with_confidence(mut self, confidence: Confidence) -> Self {
        self.confidence = confidence;
        self
    }

    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.notes.push(note.into());
        self
    }

    /// Rendered form used by the TXT report and the UI.
    pub fn display_value(&self) -> String {
        match (self.state, self.value) {
            // The bare "0" is printed only when the number really is zero. Printing it
            // for a contradictory `ZERO` + `42.0` pair would fabricate the very zero
            // measurement the decoder refuses, so such a metric shows the number it
            // actually carries: a visible contradiction beats a quiet repair, and a
            // reader of the table can see that the state and the number disagree.
            (MetricState::Zero, Some(value)) => {
                if value == 0.0 {
                    "0".to_string()
                } else {
                    format_value(value, &self.unit)
                }
            }
            (state, Some(value)) if state.has_value() => format_value(value, &self.unit),
            _ => self.state.as_str().to_string(),
        }
    }

    /// Is `state` and `value` a possible pair?
    ///
    /// The invariant a metric must satisfy before anyone may compute with it:
    ///
    /// * `OK`, `ZERO` and `SUSPECT` describe a number, so the value must be present
    ///   and finite. A non-finite number is not a measurement, and `None` means the
    ///   number was lost — either way the pair is refused rather than read as zero.
    /// * `ZERO` makes a stronger claim than "a number is present": it asserts that the
    ///   measurement *was* zero, so the number must be `0.0`. Accepting `ZERO` with
    ///   `42.0` would let a non-zero reading be read as a confirmed zero by the very
    ///   predicate that the aggregator and the reader share. `-0.0` is accepted: it is
    ///   numerically equal to zero, and [`Metric::measured`] classifies exactly this
    ///   way, so refusing it would make that constructor mint metrics its own decoder
    ///   rejects.
    /// * `ERROR`, `NO_DATA`, `UNSUPPORTED` and `CONFLICT` describe the absence of a
    ///   number. A value next to one of them is a claim nobody verified, so it is
    ///   refused rather than kept "just in case".
    ///
    /// This is a pure predicate, so both the JSON reader and the aggregation code
    /// can share one definition of the rule instead of restating it.
    pub fn is_consistent(&self) -> bool {
        match self.value {
            Some(value) => match self.state {
                // A zero state with a non-zero number is contradictory in the same way
                // that an error with a number is: one field denies what the other
                // asserts. `value == 0.0` is also true for `-0.0`, which is deliberate.
                MetricState::Zero => value.is_finite() && value == 0.0,
                state => state.has_value() && value.is_finite(),
            },
            None => !self.state.requires_value(),
        }
    }

    /// The value when this metric may be used as a number, `None` otherwise.
    ///
    /// Deliberately not `metric.value`: callers that average, sum or chart values
    /// must go through this, so a metric that lost its number can never contribute
    /// a false zero to a statistic — and a `ZERO` that carries a non-zero number
    /// cannot contribute that number either.
    pub fn usable_value(&self) -> Option<f64> {
        if !self.is_consistent() {
            return None;
        }
        match self.value {
            Some(value) if self.state.has_value() && value.is_finite() => Some(value),
            _ => None,
        }
    }
}

/// Format a number with a sensible, unit-aware precision and never with a
/// misleading number of digits.
pub fn format_value(value: f64, unit: &str) -> String {
    if !value.is_finite() {
        return "не число".to_string();
    }
    // A confirmed zero is exactly zero and needs no decimals: "0.0000 W" reads as if
    // the digits carried information, whereas a zero measurement is unambiguous.
    let text = if value == 0.0 {
        "0".to_string()
    } else {
        let magnitude = value.abs();
        match unit {
            // Watts span three orders of magnitude across PKG and GT, so the precision
            // follows the magnitude instead of being fixed.
            "W" | "mW" => {
                if magnitude < 0.01 {
                    format!("{value:.4}")
                } else if magnitude < 1.0 {
                    format!("{value:.3}")
                } else if magnitude < 100.0 {
                    format!("{value:.2}")
                } else {
                    format!("{value:.1}")
                }
            }
            "V" => format!("{value:.3}"),
            "°C" => format!("{value:.1}"),
            "RPM" => format!("{value:.0}"),
            "%" => format!("{value:.1}"),
            "MHz" => format!("{value:.0}"),
            "mWh" | "mAh" => format!("{value:.0}"),
            _ => format!("{value:.2}"),
        }
    };
    if unit.is_empty() {
        text
    } else {
        format!("{text} {unit}")
    }
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

/// One measurement cycle.
#[derive(Debug, Clone, PartialEq)]
pub struct Sample {
    /// Monotonic index from 1.
    pub index: u32,
    /// Milliseconds since the Unix epoch.
    pub timestamp_ms: u64,
    /// The length of the measurement window this sample represents.
    pub window_ms: f64,
    /// How long the sampler actually spent collecting it.
    pub elapsed_ms: f64,
    /// True while the window is shorter than the interval, so statistics must not
    /// treat it as a full sample.
    pub warmup: bool,
    pub metrics: Vec<Metric>,
}

/// A problem the sampler wants the operator to see, independent of any metric.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notice {
    /// `info`, `warning` or `error`.
    pub level: String,
    pub text: String,
}

/// A provider's identity and availability, reported once at startup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderStatus {
    /// Stable id, e.g. `emi`, `nvml`, `lhm`, `battery`.
    pub id: String,
    pub label: String,
    /// `available`, `partial`, `absent` or `error`.
    pub status: String,
    /// What it contributes.
    pub detail: String,
    /// Why it is not fully available.
    pub reason: Option<String>,
}

/// sampler -> GUI.
#[derive(Debug, Clone, PartialEq)]
pub enum SamplerMessage {
    /// First message: identity and configuration echo.
    Hello {
        version: u32,
        sampler_version: String,
        /// A random token the host must echo to prove it is the parent that owns
        /// this pipe (a stale sampler from a previous session stays inert).
        session_token: String,
        /// Wall-clock milliseconds at sampler start.
        started_ms: u64,
        interval_ms: u64,
        kind: String,
    },
    /// Providers resolved at startup, before the first sample.
    Providers {
        version: u32,
        providers: Vec<ProviderStatus>,
    },
    Sample {
        version: u32,
        sample: Sample,
    },
    /// A one-off message for the operator.
    Notice {
        version: u32,
        notice: Notice,
    },
    /// Clean completion: the sampler stopped because it was asked to.
    Bye {
        version: u32,
        reason: String,
        samples: u32,
        /// False when the sampler could not fully release a resource.
        clean: bool,
    },
    /// Terminal failure.
    Fatal {
        version: u32,
        reason: String,
    },
}

impl SamplerMessage {
    pub fn version(&self) -> u32 {
        match self {
            SamplerMessage::Hello { version, .. }
            | SamplerMessage::Providers { version, .. }
            | SamplerMessage::Sample { version, .. }
            | SamplerMessage::Notice { version, .. }
            | SamplerMessage::Bye { version, .. }
            | SamplerMessage::Fatal { version, .. } => *version,
        }
    }
}

/// GUI -> sampler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostMessage {
    /// Sent once, immediately, so the sampler can refuse a stale host.
    Attach { version: u32, session_token: String },
    /// Ask for a clean stop. The sampler replies with `Bye`.
    Stop { version: u32 },
}

/// Why a message could not be accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContractError {
    /// The line was not valid JSON.
    Malformed(String),
    /// The envelope was well-formed but not a message this version defines.
    UnknownMessage(String),
    /// A field was absent.
    MissingField(String),
    /// A field had the wrong JSON type.
    WrongType {
        field: String,
        expected: &'static str,
    },
    /// A string field held a value outside the contract's vocabulary.
    UnknownState(String),
    UnknownKind(String),
    UnknownConfidence(String),
    UnknownGroup(String),
    /// The version is not the one this build speaks.
    VersionMismatch {
        got: u32,
        want: u32,
    },
    /// A required reason was absent for a non-value state.
    MissingReason(String),
    /// A state that describes a measurement arrived without a usable number.
    MissingValue(String),
    /// A state that describes the absence of a number arrived carrying one.
    UnexpectedValue(String),
    /// A `ZERO` state arrived carrying a number that is not zero.
    ///
    /// Kept apart from [`ContractError::UnexpectedValue`] because the difference
    /// matters to whoever reads the log: there the state denies having a number at
    /// all, here the state and the number make two incompatible claims about the same
    /// measurement, which points at a provider that mislabelled a real reading.
    ZeroWithNonZeroValue(String),
}

impl fmt::Display for ContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ContractError::Malformed(detail) => write!(f, "некорректный JSON: {detail}"),
            ContractError::UnknownMessage(kind) => write!(f, "неизвестный тип сообщения: {kind}"),
            ContractError::MissingField(field) => write!(f, "отсутствует поле: {field}"),
            ContractError::WrongType { field, expected } => {
                write!(f, "поле {field} должно быть {expected}")
            }
            ContractError::UnknownState(state) => write!(f, "неизвестное состояние: {state}"),
            ContractError::UnknownKind(kind) => write!(f, "неизвестный тип значения: {kind}"),
            ContractError::UnknownConfidence(value) => {
                write!(f, "неизвестная достоверность: {value}")
            }
            ContractError::UnknownGroup(value) => write!(f, "неизвестная группа: {value}"),
            ContractError::VersionMismatch { got, want } => {
                write!(
                    f,
                    "версия контракта {got} не поддерживается (ожидается {want})"
                )
            }
            ContractError::MissingReason(id) => {
                write!(f, "показатель {id} не в состоянии OK/ZERO без причины")
            }
            ContractError::MissingValue(id) => {
                write!(
                    f,
                    "показатель {id} объявляет измерение, но не несёт числового значения"
                )
            }
            ContractError::UnexpectedValue(id) => {
                write!(
                    f,
                    "показатель {id} не является измерением, но несёт значение"
                )
            }
            ContractError::ZeroWithNonZeroValue(id) => {
                write!(
                    f,
                    "показатель {id} объявлен как ZERO, но несёт ненулевое значение"
                )
            }
        }
    }
}

impl std::error::Error for ContractError {}

// ---------------------------------------------------------------------------
// Serialisation
// ---------------------------------------------------------------------------

/// Serialise a [`Metric`] to a JSON value.
///
/// Fields that carry no information are omitted rather than sent as `null`, which
/// keeps the wire small, but a non-value state always carries its reason.
///
/// The writer does not police the state/value pair beyond what JSON can express: a
/// contradictory pair such as `ZERO` + `42.0` is written out as-is so that the
/// reader can refuse it loudly. Dropping the number here would hide the peer's
/// mistake behind a `MissingValue` error instead of reporting the contradiction,
/// and the one case where the writer must drop a number — a non-finite value, which
/// JSON cannot represent at all — is signalled by the missing field.
pub fn metric_to_json(metric: &Metric) -> crate::json::Json {
    use crate::json::Json;
    let mut fields: Vec<(String, Json)> = vec![
        ("id".into(), Json::str(&metric.id)),
        ("label".into(), Json::str(&metric.label)),
        ("group".into(), Json::str(metric.group.as_str())),
        ("unit".into(), Json::str(&metric.unit)),
        ("state".into(), Json::str(metric.state.as_str())),
        ("kind".into(), Json::str(metric.kind.as_str())),
        ("confidence".into(), Json::str(metric.confidence.as_str())),
        ("source".into(), Json::str(&metric.source)),
        ("ts".into(), Json::int(metric.timestamp_ms as i64)),
    ];
    if let Some(value) = metric.value {
        // Only a finite number is ever sent: JSON has no NaN literal, and a
        // non-finite value must have been classified as SUSPECT or ERROR instead.
        if value.is_finite() {
            fields.push(("value".into(), Json::Float(value)));
        }
    }
    if let Some(raw) = metric.raw_value.filter(|v| v.is_finite()) {
        fields.push(("raw_value".into(), Json::Float(raw)));
    }
    if let Some(unit) = &metric.raw_unit {
        fields.push(("raw_unit".into(), Json::str(unit)));
    }
    if let Some(id) = &metric.hardware {
        fields.push(("hardware_id".into(), Json::str(id)));
    }
    if let Some(sensor) = &metric.sensor {
        fields.push(("sensor".into(), Json::str(sensor)));
    }
    if let Some(reason) = &metric.reason {
        fields.push(("reason".into(), Json::str(reason)));
    }
    if !metric.notes.is_empty() {
        fields.push((
            "notes".into(),
            Json::Array(metric.notes.iter().map(|n| Json::str(n)).collect()),
        ));
    }
    Json::Object(fields)
}

/// Parse a [`Metric`], rejecting anything that would hide a failure.
///
/// The reader is fail-closed about the `state` ↔ `value` pair: a contradiction is an
/// error, never something to repair. Filling in a missing number with zero would
/// invent a measurement, and dropping a value that arrived next to `ERROR` would
/// hide that the peer sent two mutually exclusive claims.
pub fn metric_from_json(value: &crate::json::Json) -> Result<Metric, ContractError> {
    use crate::json::Json;
    let obj = value.as_object().ok_or(ContractError::WrongType {
        field: "metric".into(),
        expected: "object",
    })?;
    let get = |name: &str| -> Option<&Json> { obj.iter().find(|(k, _)| k == name).map(|(_, v)| v) };
    let text = |name: &str| -> Result<String, ContractError> {
        get(name)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| ContractError::MissingField(name.to_string()))
    };

    let id = text("id")?;
    let state = MetricState::parse(&text("state")?)?;
    let value = match get("value") {
        Some(Json::Float(v)) => Some(*v),
        Some(Json::Int(v)) => Some(*v as f64),
        Some(Json::Null) | None => None,
        Some(_) => {
            return Err(ContractError::WrongType {
                field: "value".into(),
                expected: "number",
            })
        }
    };
    // A present-but-not-a-string reason has to be refused rather than read as "no
    // reason", otherwise `"reason": 7` would silence the explanation requirement.
    let reason = match get("reason") {
        Some(Json::String(text)) => Some(text.clone()),
        Some(Json::Null) | None => None,
        Some(_) => {
            return Err(ContractError::WrongType {
                field: "reason".into(),
                expected: "string",
            })
        }
    };

    // A state without a value must explain itself; otherwise the GUI would show a
    // bare "NO DATA" with no way to find out why. `UNSUPPORTED` is the one
    // exception: "this machine has no such sensor" is itself the explanation.
    if !state.has_value()
        && value.is_none()
        && reason.is_none()
        && state != MetricState::Unsupported
    {
        return Err(ContractError::MissingReason(id));
    }
    // A state that claims a measurement must actually carry one. `SUSPECT` without a
    // number means the number was dropped, and a dropped number must say why; but
    // `OK`/`ZERO` without a number is a contradiction no reason can repair, because
    // the state itself asserts that a measurement exists.
    if state.requires_value() && value.is_none() {
        let suspect_with_reason = state == MetricState::Suspect && reason.is_some();
        if !suspect_with_reason {
            return Err(if reason.is_some() {
                ContractError::MissingValue(id)
            } else {
                ContractError::MissingReason(id)
            });
        }
    }
    // A number that arrived with a value-bearing state must also be a real number.
    // A non-finite value is not a measurement and must never become one silently.
    if let Some(number) = value {
        if !number.is_finite() {
            return Err(ContractError::WrongType {
                field: "value".into(),
                expected: "a finite number",
            });
        }
    }
    // A state that describes the absence of a number must not carry one.
    if !state.requires_value() && value.is_some() {
        return Err(ContractError::UnexpectedValue(id));
    }
    // `ZERO` asserts a measurement that was exactly zero, so a different number next
    // to it is a contradiction. It is refused rather than repaired: keeping the number
    // would let a 42 W reading be reported as a confirmed zero, and replacing it with
    // `0.0` would invent a measurement. Checked after the finiteness rule above so a
    // non-finite number still reports the more precise reason.
    if let (MetricState::Zero, Some(number)) = (state, value) {
        if number != 0.0 {
            return Err(ContractError::ZeroWithNonZeroValue(id));
        }
    }

    let notes = match get("notes") {
        Some(Json::Array(items)) => items
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect(),
        _ => Vec::new(),
    };

    Ok(Metric {
        id,
        label: text("label")?,
        group: Group::parse(&text("group")?)?,
        unit: text("unit")?,
        state,
        value,
        raw_value: get("raw_value").and_then(Json::as_f64),
        raw_unit: get("raw_unit").and_then(Json::as_str).map(str::to_string),
        hardware: get("hardware_id")
            .and_then(Json::as_str)
            .map(str::to_string),
        kind: ValueKind::parse(&text("kind")?)?,
        confidence: Confidence::parse(&text("confidence")?)?,
        source: text("source")?,
        sensor: get("sensor")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        timestamp_ms: get("ts").and_then(|v| v.as_int()).unwrap_or(0).max(0) as u64,
        reason,
        notes,
    })
}

pub fn sample_to_json(sample: &Sample) -> crate::json::Json {
    use crate::json::Json;
    Json::Object(vec![
        ("index".into(), Json::int(sample.index as i64)),
        ("ts".into(), Json::int(sample.timestamp_ms as i64)),
        ("window_ms".into(), Json::Float(sample.window_ms)),
        ("elapsed_ms".into(), Json::Float(sample.elapsed_ms)),
        ("warmup".into(), Json::Bool(sample.warmup)),
        (
            "metrics".into(),
            Json::Array(sample.metrics.iter().map(metric_to_json).collect()),
        ),
    ])
}

pub fn sample_from_json(value: &crate::json::Json) -> Result<Sample, ContractError> {
    use crate::json::Json;
    let obj = value.as_object().ok_or(ContractError::WrongType {
        field: "sample".into(),
        expected: "object",
    })?;
    let get = |name: &str| -> Option<&Json> { obj.iter().find(|(k, _)| k == name).map(|(_, v)| v) };
    let metrics = match get("metrics") {
        Some(Json::Array(items)) => items
            .iter()
            .map(metric_from_json)
            .collect::<Result<Vec<_>, _>>()?,
        _ => return Err(ContractError::MissingField("metrics".into())),
    };
    let number = |name: &str| -> f64 {
        match get(name) {
            Some(Json::Float(v)) => *v,
            Some(Json::Int(v)) => *v as f64,
            _ => 0.0,
        }
    };
    Ok(Sample {
        index: get("index").and_then(|v| v.as_int()).unwrap_or(0).max(0) as u32,
        timestamp_ms: get("ts").and_then(|v| v.as_int()).unwrap_or(0).max(0) as u64,
        window_ms: number("window_ms"),
        elapsed_ms: number("elapsed_ms"),
        warmup: matches!(get("warmup"), Some(Json::Bool(true))),
        metrics,
    })
}

pub fn provider_to_json(provider: &ProviderStatus) -> crate::json::Json {
    use crate::json::Json;
    let mut fields = vec![
        ("id".into(), Json::str(&provider.id)),
        ("label".into(), Json::str(&provider.label)),
        ("status".into(), Json::str(&provider.status)),
        ("detail".into(), Json::str(&provider.detail)),
    ];
    if let Some(reason) = &provider.reason {
        fields.push(("reason".into(), Json::str(reason)));
    }
    Json::Object(fields)
}

pub fn provider_from_json(value: &crate::json::Json) -> Result<ProviderStatus, ContractError> {
    use crate::json::Json;
    let obj = value.as_object().ok_or(ContractError::WrongType {
        field: "provider".into(),
        expected: "object",
    })?;
    let get = |name: &str| -> Option<&Json> { obj.iter().find(|(k, _)| k == name).map(|(_, v)| v) };
    let text = |name: &str| -> Result<String, ContractError> {
        get(name)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| ContractError::MissingField(name.to_string()))
    };
    Ok(ProviderStatus {
        id: text("id")?,
        label: text("label")?,
        status: text("status")?,
        detail: text("detail")?,
        reason: get("reason")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
    })
}

/// Serialise one sampler message as a single JSON line (without the newline).
pub fn encode_sampler(message: &SamplerMessage) -> String {
    use crate::json::Json;
    let json = match message {
        SamplerMessage::Hello {
            version,
            sampler_version,
            session_token,
            started_ms,
            interval_ms,
            kind,
        } => Json::Object(vec![
            ("v".into(), Json::int(*version as i64)),
            ("t".into(), Json::str("hello")),
            ("sampler_version".into(), Json::str(sampler_version)),
            ("session_token".into(), Json::str(session_token)),
            ("started_ms".into(), Json::int(*started_ms as i64)),
            ("interval_ms".into(), Json::int(*interval_ms as i64)),
            ("kind".into(), Json::str(kind)),
        ]),
        SamplerMessage::Providers { version, providers } => Json::Object(vec![
            ("v".into(), Json::int(*version as i64)),
            ("t".into(), Json::str("providers")),
            (
                "providers".into(),
                Json::Array(providers.iter().map(provider_to_json).collect()),
            ),
        ]),
        SamplerMessage::Sample { version, sample } => Json::Object(vec![
            ("v".into(), Json::int(*version as i64)),
            ("t".into(), Json::str("sample")),
            ("sample".into(), sample_to_json(sample)),
        ]),
        SamplerMessage::Notice { version, notice } => Json::Object(vec![
            ("v".into(), Json::int(*version as i64)),
            ("t".into(), Json::str("notice")),
            ("level".into(), Json::str(&notice.level)),
            ("text".into(), Json::str(&notice.text)),
        ]),
        SamplerMessage::Bye {
            version,
            reason,
            samples,
            clean,
        } => Json::Object(vec![
            ("v".into(), Json::int(*version as i64)),
            ("t".into(), Json::str("bye")),
            ("reason".into(), Json::str(reason)),
            ("samples".into(), Json::int(*samples as i64)),
            ("clean".into(), Json::Bool(*clean)),
        ]),
        SamplerMessage::Fatal { version, reason } => Json::Object(vec![
            ("v".into(), Json::int(*version as i64)),
            ("t".into(), Json::str("fatal")),
            ("reason".into(), Json::str(reason)),
        ]),
    };
    json.render()
}

/// Parse one sampler message.
pub fn decode_sampler(line: &str) -> Result<SamplerMessage, ContractError> {
    use crate::json::Json;
    let json = Json::parse(line).map_err(|err| ContractError::Malformed(err.to_string()))?;
    let obj = json.as_object().ok_or(ContractError::WrongType {
        field: "message".into(),
        expected: "object",
    })?;
    let get = |name: &str| -> Option<&Json> { obj.iter().find(|(k, _)| k == name).map(|(_, v)| v) };
    let text = |name: &str| -> Result<String, ContractError> {
        get(name)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| ContractError::MissingField(name.to_string()))
    };
    let version = get("v")
        .and_then(|v| v.as_int())
        .ok_or_else(|| ContractError::MissingField("v".into()))? as u32;
    if version != PROTOCOL_VERSION {
        return Err(ContractError::VersionMismatch {
            got: version,
            want: PROTOCOL_VERSION,
        });
    }
    let kind = text("t")?;
    Ok(match kind.as_str() {
        "hello" => SamplerMessage::Hello {
            version,
            sampler_version: text("sampler_version")?,
            session_token: text("session_token")?,
            started_ms: get("started_ms")
                .and_then(|v| v.as_int())
                .unwrap_or(0)
                .max(0) as u64,
            interval_ms: get("interval_ms")
                .and_then(|v| v.as_int())
                .unwrap_or(0)
                .max(0) as u64,
            kind: text("kind")?,
        },
        "providers" => {
            let providers = match get("providers") {
                Some(Json::Array(items)) => items.iter().map(provider_from_json).collect::<Result<
                    Vec<_>,
                    _,
                >>(
                )?,
                _ => return Err(ContractError::MissingField("providers".into())),
            };
            SamplerMessage::Providers { version, providers }
        }
        "sample" => {
            let sample =
                get("sample").ok_or_else(|| ContractError::MissingField("sample".into()))?;
            SamplerMessage::Sample {
                version,
                sample: sample_from_json(sample)?,
            }
        }
        "notice" => SamplerMessage::Notice {
            version,
            notice: Notice {
                level: text("level")?,
                text: text("text")?,
            },
        },
        "bye" => SamplerMessage::Bye {
            version,
            reason: text("reason")?,
            samples: get("samples").and_then(|v| v.as_int()).unwrap_or(0).max(0) as u32,
            clean: matches!(get("clean"), Some(Json::Bool(true))),
        },
        "fatal" => SamplerMessage::Fatal {
            version,
            reason: text("reason")?,
        },
        other => return Err(ContractError::UnknownMessage(other.to_string())),
    })
}

/// Serialise one host message as a single JSON line (without the newline).
pub fn encode_host(message: &HostMessage) -> String {
    use crate::json::Json;
    let json = match message {
        HostMessage::Attach {
            version,
            session_token,
        } => Json::Object(vec![
            ("v".into(), Json::int(*version as i64)),
            ("t".into(), Json::str("attach")),
            ("session_token".into(), Json::str(session_token)),
        ]),
        HostMessage::Stop { version } => Json::Object(vec![
            ("v".into(), Json::int(*version as i64)),
            ("t".into(), Json::str("stop")),
        ]),
    };
    json.render()
}

/// Parse one host message.
pub fn decode_host(line: &str) -> Result<HostMessage, ContractError> {
    use crate::json::Json;
    let json = Json::parse(line).map_err(|err| ContractError::Malformed(err.to_string()))?;
    let obj = json.as_object().ok_or(ContractError::WrongType {
        field: "message".into(),
        expected: "object",
    })?;
    let get = |name: &str| -> Option<&Json> { obj.iter().find(|(k, _)| k == name).map(|(_, v)| v) };
    let version = get("v")
        .and_then(|v| v.as_int())
        .ok_or_else(|| ContractError::MissingField("v".into()))? as u32;
    if version != PROTOCOL_VERSION {
        return Err(ContractError::VersionMismatch {
            got: version,
            want: PROTOCOL_VERSION,
        });
    }
    let kind = get("t")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ContractError::MissingField("t".into()))?;
    Ok(match kind {
        "attach" => HostMessage::Attach {
            version,
            session_token: get("session_token")
                .and_then(|v| v.as_str())
                .ok_or_else(|| ContractError::MissingField("session_token".into()))?
                .to_string(),
        },
        "stop" => HostMessage::Stop { version },
        other => return Err(ContractError::UnknownMessage(other.to_string())),
    })
}

// ---------------------------------------------------------------------------
// Aggregates used by the report writer
// ---------------------------------------------------------------------------

/// Running statistics for one metric id.
///
/// `count` is the number of **usable numbers** observed, and it is exactly the
/// denominator of [`Series::average`]. A metric that arrived without a usable number
/// is never counted there: it lands in `skipped` (plus the counter for its state)
/// so the absence stays visible without being averaged as a zero.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Series {
    /// Observations that carried a usable finite number; the average's denominator.
    pub count: u64,
    /// Observations confirmed as an exactly-zero measurement, so this counter can only
    /// grow together with `count`. An inconsistent `ZERO` never reaches it.
    pub zeros: u64,
    pub no_data: u64,
    pub errors: u64,
    pub suspect: u64,
    /// Observations that were seen but carried no usable number, so they were
    /// excluded from `count`, `min`, `max`, `sum`, `points` and `average`.
    pub skipped: u64,
    pub min: Option<f64>,
    pub max: Option<f64>,
    pub sum: f64,
    /// The most recent values in arrival order, for the charts. Bounded by
    /// [`Series::MAX_POINTS`]: once full, the **oldest** value is dropped, so a long
    /// session keeps charting what is happening now instead of freezing on its first
    /// values. The statistics above are computed from every value regardless.
    pub points: VecDeque<f64>,
    /// Values that were measured but are no longer in `points` because the chart history
    /// is bounded (the oldest ones). They are still in `count`, `sum`, `min` and `max`.
    pub points_dropped: u64,
}

impl Series {
    /// Upper bound on the plotted history kept per metric.
    ///
    /// The statistics (`count`, `sum`, `min`, `max`, `average`) are exact over the whole
    /// run; only the values retained **for the charts** are bounded, so an eight-hour
    /// session cannot grow the GUI's memory without limit. Whatever is left out is
    /// counted in `points_dropped` rather than silently forgotten. The window slides:
    /// the newest values are kept.
    pub const MAX_POINTS: usize = 10_000;

    /// Observe one metric. Warm-up samples are excluded by the caller.
    ///
    /// Only a measured state (`OK`/`ZERO`, and `SUSPECT` when it still carries its
    /// number) with a finite value reaches the statistics. Everything else is
    /// counted as what it is: a zero, a missing value, an error, or a value that was
    /// dropped. A metric without a value can therefore never contribute `0.0`, and a
    /// metric whose state and number disagree (a `ZERO` carrying `42.0`) contributes
    /// nothing at all: it is a skip, not a zero and not a measurement.
    pub fn push(&mut self, metric: &Metric) {
        let usable = metric.usable_value();
        match metric.state {
            // The zero counter follows the number, not the label: a `ZERO` whose
            // number is missing or non-zero is not a confirmed zero measurement, so
            // counting it here would let the report claim "нулей 1" for a reading that
            // carried 42 W. Such a metric lands in `skipped` below.
            MetricState::Zero => {
                if usable.is_some() {
                    self.zeros += 1;
                    self.note_measurement();
                }
            }
            MetricState::Ok => {
                if usable.is_some() {
                    self.note_measurement();
                }
            }
            MetricState::Suspect => {
                self.suspect += 1;
                if usable.is_some() {
                    self.note_measurement();
                }
            }
            MetricState::NoData => self.no_data += 1,
            MetricState::Unsupported => {}
            MetricState::Error => self.errors += 1,
            MetricState::Conflict => self.suspect += 1,
        }
        // The number reaches the statistics through exactly one call, so the
        // denominator can never disagree with what `sum` and `points` hold.
        if let Some(number) = usable {
            self.observe(number);
        } else {
            // Seen, but not usable as a number: counted as a skip, never as a zero.
            self.skipped += 1;
        }
    }

    /// Record one usable number: it is the only path into `count`, and `count` is
    /// the only denominator [`Series::average`] uses.
    fn note_measurement(&mut self) {
        self.count += 1;
    }

    /// How many observations were seen but carried no usable number.
    pub fn skipped(&self) -> u64 {
        self.skipped
    }

    /// The number of usable values behind the statistics.
    ///
    /// Equal to `count`, and named separately so a caller can state the denominator
    /// without restating how `push` classifies a metric.
    pub fn observed(&self) -> u64 {
        self.count
    }

    fn observe(&mut self, value: f64) {
        if !value.is_finite() {
            return;
        }
        self.min = Some(self.min.map_or(value, |m| m.min(value)));
        self.max = Some(self.max.map_or(value, |m| m.max(value)));
        self.sum += value;
        if self.points.len() >= Self::MAX_POINTS {
            self.points.pop_front();
            self.points_dropped += 1;
        }
        self.points.push_back(value);
    }

    /// The mean of the usable numbers, or `None` when there is not a single one.
    ///
    /// `None` is the honest answer for "every observation was a failure or carried
    /// no number": a mean of nothing is not zero. The denominator is `count` — the number
    /// of usable numbers — and never the (bounded) chart history.
    pub fn average(&self) -> Option<f64> {
        if self.count == 0 {
            None
        } else {
            Some(self.sum / self.count as f64)
        }
    }
}

/// Statistics for every metric seen during a run.
pub type SeriesMap = BTreeMap<String, Series>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_chart_history_is_bounded_while_the_statistics_stay_exact() {
        let mut series = Series::default();
        let total = Series::MAX_POINTS + 25;
        for index in 0..total {
            series.push(&Metric::measured(
                "x",
                "X",
                Group::Cpu,
                "W",
                index as f64,
                "mock",
            ));
        }
        assert_eq!(series.points.len(), Series::MAX_POINTS);
        assert_eq!(series.points_dropped, 25);
        // The window slides: the chart shows the newest values, not the first ones.
        assert_eq!(series.points.front().copied(), Some(25.0));
        assert_eq!(series.points.back().copied(), Some((total - 1) as f64));
        assert_eq!(series.count, total as u64);
        assert_eq!(series.min, Some(0.0));
        assert_eq!(series.max, Some((total - 1) as f64));
        // The mean covers every measured value, not just the retained window.
        let expected = (0..total).map(|index| index as f64).sum::<f64>() / total as f64;
        assert!((series.average().expect("a mean") - expected).abs() < 1e-9);
    }

    fn metric_round_trip(metric: &Metric) {
        let line = encode_sampler(&SamplerMessage::Sample {
            version: PROTOCOL_VERSION,
            sample: Sample {
                index: 1,
                timestamp_ms: 1_700_000_000_000,
                window_ms: 1000.0,
                elapsed_ms: 12.5,
                warmup: false,
                metrics: vec![metric.clone()],
            },
        });
        let decoded = decode_sampler(&line).expect("decodes");
        match decoded {
            SamplerMessage::Sample { sample, .. } => {
                assert_eq!(sample.metrics.len(), 1);
                assert_eq!(&sample.metrics[0], metric);
            }
            other => panic!("expected a sample, got {other:?}"),
        }
    }

    #[test]
    fn every_state_survives_a_round_trip() {
        for state in [
            MetricState::Ok,
            MetricState::Zero,
            MetricState::NoData,
            MetricState::Unsupported,
            MetricState::Error,
            MetricState::Suspect,
            MetricState::Conflict,
        ] {
            // Each value-bearing state is built with a number that its own state
            // permits. This test used to give `ZERO` the value `1.5`, which only
            // round-tripped because the reader had no rule for the pair; now the pair
            // is refused, so the test builds the metric the contract actually allows
            // (`ZERO` + `0.0`) and asserts up front that it is consistent.
            let metric = if state.has_value() {
                let value = if state == MetricState::Zero { 0.0 } else { 1.5 };
                let mut m = Metric::measured("x.y", "Y", Group::Cpu, "W", value, "test");
                m.state = state;
                m
            } else {
                Metric::unavailable("x.y", "Y", Group::Cpu, "W", state, "причина", "test")
            };
            assert!(metric.is_consistent(), "{state:?} must be consistent");
            metric_round_trip(&metric);
        }
    }

    #[test]
    fn a_state_without_a_value_and_without_a_reason_is_rejected() {
        // Hand-build the forbidden shape: an ERROR with neither value nor reason.
        let line = r#"{"v":1,"t":"sample","sample":{"index":1,"ts":0,"metrics":[{"id":"a","label":"A","group":"CPU","unit":"W","state":"ERROR","kind":"measured","confidence":"low","source":"s"}]}}"#;
        let err = decode_sampler(line).expect_err("must be rejected");
        assert_eq!(err, ContractError::MissingReason("a".to_string()));
    }

    #[test]
    fn an_unknown_state_is_never_defaulted() {
        let line = r#"{"v":1,"t":"sample","sample":{"index":1,"ts":0,"metrics":[{"id":"a","label":"A","group":"CPU","unit":"W","state":"OKAY","kind":"measured","confidence":"low","source":"s","value":1.0}]}}"#;
        let err = decode_sampler(line).expect_err("must be rejected");
        assert_eq!(err, ContractError::UnknownState("OKAY".to_string()));
    }

    #[test]
    fn a_wrong_version_is_rejected_rather_than_guessed() {
        let line = r#"{"v":99,"t":"stop"}"#;
        let err = decode_host(line).expect_err("must be rejected");
        assert_eq!(
            err,
            ContractError::VersionMismatch {
                got: 99,
                want: PROTOCOL_VERSION
            }
        );
    }

    #[test]
    fn a_non_finite_value_is_never_put_on_the_wire() {
        // JSON has no NaN literal, so a non-finite value must have been classified
        // as SUSPECT or ERROR with a reason before it is encoded. The encoder drops
        // the number; the round trip stays valid and the state is preserved.
        let mut metric = Metric::measured("x.y", "Y", Group::Cpu, "W", 1.0, "test");
        metric.value = Some(f64::NAN);
        metric.state = MetricState::Suspect;
        metric.reason = Some("счётчик вернул не числовое значение".to_string());
        let line = encode_sampler(&SamplerMessage::Sample {
            version: PROTOCOL_VERSION,
            sample: Sample {
                index: 1,
                timestamp_ms: 0,
                window_ms: 0.0,
                elapsed_ms: 0.0,
                warmup: false,
                metrics: vec![metric],
            },
        });
        eprintln!("DBG line={line}");
        assert!(!line.contains("NaN"), "{line}");
        assert!(
            !line.contains("\"value\""),
            "the number must be omitted: {line}"
        );
        // It must still be readable, and the SUSPECT state must survive.
        match decode_sampler(&line).expect("decodes") {
            SamplerMessage::Sample { sample, .. } => {
                assert_eq!(sample.metrics[0].state, MetricState::Suspect);
                assert!(sample.metrics[0].value.is_none());
                assert!(sample.metrics[0].reason.is_some());
            }
            other => panic!("expected a sample, got {other:?}"),
        }
    }

    #[test]
    fn a_measured_zero_is_a_measurement_not_missing_data() {
        let metric = Metric::measured("gt.power", "GT", Group::Cpu, "W", 0.0, "test");
        assert_eq!(metric.state, MetricState::Zero);
        assert!(metric.state.has_value());
        assert_eq!(metric.display_value(), "0");
        metric_round_trip(&metric);
    }

    /// The independent audit's case, asserted at every layer of the pipeline rather
    /// than only in the decoder: a `ZERO` that carries `42.0` must be refused, not
    /// repaired into a zero and not accepted as an ordinary measurement.
    #[test]
    fn a_zero_state_that_carries_a_nonzero_measurement_is_refused() {
        let mut metric = Metric::measured("x", "X", Group::Cpu, "W", 42.0, "mock");
        metric.state = MetricState::Zero;

        assert!(
            !metric.is_consistent(),
            "ZERO with 42 W states two incompatible things at once"
        );
        assert_eq!(
            metric.usable_value(),
            None,
            "the number must not reach a statistic under a zero state"
        );
        assert_ne!(
            metric.display_value(),
            "0",
            "the table must not print a fabricated zero for a 42 W reading"
        );
        assert_eq!(metric.display_value(), format_value(42.0, "W"));

        // The written form keeps the number, so the contradiction is visible on the
        // wire instead of being hidden by the writer.
        let json = metric_to_json(&metric);
        assert!(
            json.as_object()
                .expect("an object")
                .iter()
                .any(|(k, _)| k == "value"),
            "the writer must not silently drop the number: {}",
            json.render()
        );
        assert_eq!(
            metric_from_json(&json).expect_err("ZERO with 42 must be refused"),
            ContractError::ZeroWithNonZeroValue("x".to_string())
        );

        // And the whole message, not only the metric, is refused: a sample with one
        // contradictory reading must not be delivered half-checked.
        let line = r#"{"v":1,"t":"sample","sample":{"index":1,"ts":0,"metrics":[{"id":"x","label":"X","group":"CPU","unit":"W","state":"ZERO","kind":"measured","confidence":"high","source":"mock","value":42.0}]}}"#;
        assert_eq!(
            decode_sampler(line).expect_err("must be rejected"),
            ContractError::ZeroWithNonZeroValue("x".to_string())
        );

        // The other direction of the same state: a ZERO that lost its number is a
        // contradiction too, and it is refused with the existing missing-value error.
        let mut without_number = Metric::measured("x", "X", Group::Cpu, "W", 0.0, "mock");
        without_number.value = None;
        without_number.reason = Some("read failed".to_string());
        assert!(!without_number.is_consistent());
        assert_eq!(without_number.usable_value(), None);
        assert_eq!(
            metric_from_json(&metric_to_json(&without_number))
                .expect_err("ZERO without a number must be refused"),
            ContractError::MissingValue("x".to_string())
        );

        // With no reason either, the older explanation requirement still decides the
        // error, because a zero that lost its number has to say what happened to it.
        let mut bare = Metric::measured("x", "X", Group::Cpu, "W", 0.0, "mock");
        bare.value = None;
        assert_eq!(
            metric_from_json(&metric_to_json(&bare)).expect_err("must be refused"),
            ContractError::MissingReason("x".to_string())
        );
    }

    /// A zero measurement is accepted on the wire in the exact shape the state
    /// describes, and `-0.0` counts as that shape.
    ///
    /// The decision on `-0.0` is deliberate: IEEE 754 makes `-0.0 == 0.0` true, and
    /// [`Metric::measured`] classifies a reading as `ZERO` with that same comparison.
    /// Rejecting `-0.0` here would make that constructor mint metrics its own reader
    /// refuses, so a negative zero is treated as the zero it numerically is. The sign
    /// carries no measurement (it is not an error code), so nothing is lost; the
    /// display and the statistics both render it as a plain zero.
    #[test]
    fn a_zero_state_accepts_only_a_real_zero() {
        let zero = Metric::measured("x", "X", Group::Cpu, "W", 0.0, "mock");
        assert!(zero.is_consistent());
        assert_eq!(zero.usable_value(), Some(0.0));

        let negative_zero = Metric::measured("x", "X", Group::Cpu, "W", -0.0, "mock");
        assert_eq!(
            negative_zero.state,
            MetricState::Zero,
            "the constructor classifies -0.0 as a zero measurement"
        );
        assert!(
            negative_zero.is_consistent(),
            "-0.0 is numerically zero, so the pair is not contradictory"
        );
        assert_eq!(negative_zero.usable_value(), Some(0.0));
        assert_eq!(negative_zero.display_value(), "0");
        metric_round_trip(&negative_zero);

        for value in [0.0, -0.0] {
            let line = format!(
                r#"{{"v":1,"t":"sample","sample":{{"index":1,"ts":0,"metrics":[{{"id":"x","label":"X","group":"CPU","unit":"W","state":"ZERO","kind":"measured","confidence":"high","source":"mock","value":{value:?}}}]}}}}"#
            );
            let decoded = decode_sampler(&line).expect("a real zero must be accepted");
            match decoded {
                SamplerMessage::Sample { sample, .. } => {
                    assert_eq!(sample.metrics[0].state, MetricState::Zero);
                    assert_eq!(sample.metrics[0].value, Some(value));
                    assert_eq!(sample.metrics[0].usable_value(), Some(0.0));
                }
                other => panic!("expected a sample, got {other:?}"),
            }
        }

        // Every other number is a contradiction, including a tiny one: a reading of
        // 1e-12 W is a measurement of almost nothing, not a confirmed zero.
        for value in [42.0, -1.0, 1e-12, f64::MIN_POSITIVE, f64::MAX, f64::MIN] {
            let mut metric = Metric::measured("x", "X", Group::Cpu, "W", value, "mock");
            metric.state = MetricState::Zero;
            assert!(!metric.is_consistent(), "ZERO + {value:?} must be refused");
            assert_eq!(metric.usable_value(), None, "ZERO + {value:?}");
            assert_eq!(
                metric_from_json(&metric_to_json(&metric))
                    .expect_err("a non-zero number under ZERO must be refused"),
                ContractError::ZeroWithNonZeroValue("x".to_string()),
                "ZERO + {value:?}"
            );
        }

        // A non-finite number keeps its own, more precise, error: it is not a number
        // at all, so "ZERO carrying a non-zero number" would be the wrong diagnosis.
        for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let mut metric = Metric::measured("x", "X", Group::Cpu, "W", 1.0, "mock");
            metric.state = MetricState::Zero;
            metric.value = Some(value);
            assert!(!metric.is_consistent(), "ZERO + {value:?} must be refused");
            // A non-finite number is never written, so the wire form is a ZERO with no
            // number and no reason — refused as an unexplained missing measurement
            // rather than as a bad one, which is what the writer leaves behind.
            assert_eq!(
                metric_from_json(&metric_to_json(&metric)),
                Err(ContractError::MissingReason("x".to_string())),
                "ZERO + {value:?}"
            );
        }
    }

    /// The aggregation path: a contradictory zero contributes nothing, and in
    /// particular it is not counted as a zero measurement.
    #[test]
    fn a_contradictory_zero_contributes_nothing_to_the_statistics() {
        let mut contradictory = Metric::measured("x", "X", Group::Cpu, "W", 42.0, "mock");
        contradictory.state = MetricState::Zero;
        let mut series = Series::default();
        series.push(&contradictory);
        assert_eq!(series.count, 0, "42 W must not be counted as a measurement");
        assert_eq!(
            series.zeros, 0,
            "and it must not be counted as a zero either"
        );
        assert_eq!(series.skipped(), 1, "it is a skip: seen, but not usable");
        assert_eq!(series.average(), None);
        assert!(series.points.is_empty());
        assert_eq!(series.min, None);
        assert_eq!(series.max, None);
        assert_eq!(series.sum, 0.0);

        // A real zero still is a zero measurement: the counter moved with the number,
        // not away from the state it belongs to.
        let mut series = Series::default();
        series.push(&Metric::measured("x", "X", Group::Cpu, "W", 0.0, "mock"));
        assert_eq!(series.count, 1);
        assert_eq!(series.zeros, 1);
        assert_eq!(series.skipped(), 0);
        assert_eq!(series.average(), Some(0.0));
        assert_eq!(series.points, vec![0.0]);
    }

    /// The constructors are the only place `core` decides which state a number gets,
    /// so they are checked exhaustively here: `Metric::measured` may label a reading
    /// `ZERO` only when the reading really is zero.
    #[test]
    fn the_core_constructors_never_label_a_nonzero_number_as_zero() {
        for value in [
            0.0,
            -0.0,
            f64::MIN_POSITIVE,
            -f64::MIN_POSITIVE,
            1e-323,
            1.0,
            -42.0,
            f64::MAX,
            f64::MIN,
        ] {
            let metric = Metric::measured("x", "X", Group::Cpu, "W", value, "mock");
            assert!(
                metric.is_consistent(),
                "Metric::measured({value:?}) must build a consistent metric"
            );
            assert_eq!(
                metric.state == MetricState::Zero,
                value == 0.0,
                "Metric::measured({value:?}) must label ZERO exactly for a zero reading"
            );
        }

        // A non-finite reading is never a measurement: no state/constructor can make
        // one usable, so a provider that hands over NaN cannot leak it into a number.
        for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let metric = Metric::measured("x", "X", Group::Cpu, "W", value, "mock");
            assert_ne!(
                metric.state,
                MetricState::Zero,
                "a non-finite reading is not a confirmed zero"
            );
            assert!(
                metric.is_consistent(),
                "rejected non-finite result must be a valid ERROR record"
            );
            assert_eq!(metric.state, MetricState::Error);
            assert!(metric.reason.is_some());
            assert_eq!(metric.usable_value(), None, "{value:?}");
        }

        // `Metric::unavailable` can only build the states that describe an absent
        // number; asking it for ZERO yields the contradictory pair, which is refused
        // rather than accepted with a silent default.
        let broken = Metric::unavailable(
            "x",
            "X",
            Group::Cpu,
            "W",
            MetricState::Zero,
            "причина",
            "mock",
        );
        assert!(broken.value.is_none());
        assert!(!broken.is_consistent());
        assert_eq!(
            metric_from_json(&metric_to_json(&broken)),
            Err(ContractError::MissingValue("x".to_string()))
        );
    }

    #[test]
    fn an_unavailable_metric_never_pretends_to_have_a_value() {
        let metric = Metric::unavailable(
            "dram.power",
            "DRAM",
            Group::Memory,
            "W",
            MetricState::Unsupported,
            "нет провайдера",
            "test",
        );
        assert_eq!(metric.display_value(), "UNSUPPORTED");
        assert!(metric.value.is_none());
        metric_round_trip(&metric);
    }

    #[test]
    fn series_separate_zeros_no_data_and_errors() {
        let mut series = Series::default();
        series.push(&Metric::measured("a", "A", Group::Cpu, "W", 0.0, "t"));
        series.push(&Metric::measured("a", "A", Group::Cpu, "W", 4.0, "t"));
        series.push(&Metric::unavailable(
            "a",
            "A",
            Group::Cpu,
            "W",
            MetricState::NoData,
            "нет данных",
            "t",
        ));
        series.push(&Metric::unavailable(
            "a",
            "A",
            Group::Cpu,
            "W",
            MetricState::Error,
            "отказ",
            "t",
        ));
        assert_eq!(
            series.count, 2,
            "count is the number of usable values: zeros and values are measurements"
        );
        assert_eq!(series.zeros, 1);
        assert_eq!(series.no_data, 1);
        assert_eq!(series.errors, 1);
        assert_eq!(
            series.skipped(),
            2,
            "the NO_DATA and the ERROR were seen but carried no number"
        );
        assert_eq!(
            series.observed(),
            series.count,
            "the denominator and the usable count are one number"
        );
        assert_eq!(series.min, Some(0.0));
        assert_eq!(series.max, Some(4.0));
        assert_eq!(series.sum, 4.0);
        assert_eq!(series.average(), Some(2.0));
        assert_eq!(series.points, vec![0.0, 4.0]);
    }

    /// One observation of a metric that carries no usable number must not turn the
    /// mean into a zero: a mean of nothing is `None`, not `0.0`.
    #[test]
    fn an_observation_without_a_number_never_averages_to_zero() {
        let mut s = Series::default();
        s.push(&Metric::unavailable(
            "x",
            "X",
            Group::Cpu,
            "W",
            MetricState::Suspect,
            "not numeric",
            "mock",
        ));
        assert_eq!(s.average(), None, "a dropped number is not a zero");
        assert_eq!(s.count, 0);
        assert_eq!(s.observed(), 0);
        assert_eq!(s.skipped(), 1);
        assert_eq!(s.suspect, 1);
        assert!(s.points.is_empty());
        assert_eq!(s.min, None);
        assert_eq!(s.max, None);
        assert_eq!(s.sum, 0.0);

        // The same for every other state that cannot carry a number, and for a
        // metric whose state claims one but whose number was lost.
        for state in [
            MetricState::NoData,
            MetricState::Error,
            MetricState::Unsupported,
            MetricState::Conflict,
        ] {
            let mut s = Series::default();
            s.push(&Metric::unavailable(
                "x",
                "X",
                Group::Cpu,
                "W",
                state,
                "причина",
                "mock",
            ));
            assert_eq!(s.average(), None, "{state:?} must not average to zero");
            assert_eq!(s.count, 0, "{state:?}");
            assert_eq!(s.skipped(), 1, "{state:?}");
        }

        let mut lost = Metric::measured("x", "X", Group::Cpu, "W", 5.0, "mock");
        lost.value = None;
        lost.reason = Some("read failed".into());
        let mut s = Series::default();
        s.push(&lost);
        assert_eq!(
            s.average(),
            None,
            "an OK state without a number is not a zero"
        );
        assert_eq!(s.count, 0);
        assert_eq!(s.skipped(), 1);

        // A metric that still carries its (suspect) number does count.
        let mut keeps_value = Metric::measured("x", "X", Group::Cpu, "W", 7.0, "mock");
        keeps_value.state = MetricState::Suspect;
        keeps_value.reason = Some("значение вне диапазона".into());
        let mut s = Series::default();
        s.push(&keeps_value);
        assert_eq!(s.average(), Some(7.0));
        assert_eq!(s.count, 1);
        assert_eq!(s.skipped(), 0);
        assert_eq!(s.suspect, 1);

        // A non-finite number is not a measurement either.
        let mut not_a_number = Metric::measured("x", "X", Group::Cpu, "W", 1.0, "mock");
        not_a_number.state = MetricState::Suspect;
        not_a_number.value = Some(f64::NAN);
        not_a_number.reason = Some("счётчик вернул не числовое значение".into());
        let mut s = Series::default();
        s.push(&not_a_number);
        assert_eq!(s.average(), None);
        assert_eq!(s.count, 0);
        assert_eq!(s.skipped(), 1);
    }

    #[test]
    fn a_state_which_claims_a_measurement_must_carry_one() {
        // Scenario 1: `Metric::measured` whose value was then dropped.
        let mut metric = Metric::measured("x", "X", Group::Cpu, "W", 1.0, "mock");
        metric.value = None;
        metric.reason = Some("read failed".to_string());
        assert!(
            !metric.is_consistent(),
            "OK without a number is a contradiction"
        );
        assert!(metric.usable_value().is_none());
        let json = metric_to_json(&metric);
        assert!(
            json.as_object().unwrap().iter().all(|(k, _)| k != "value"),
            "a dropped value must not be written as a number: {}",
            json.render()
        );
        assert!(
            metric_from_json(&json).is_err(),
            "the reader must refuse a state that claims a measurement it does not carry"
        );

        // The raw wire form of the same contradiction, for every value-bearing state.
        for state in ["OK", "ZERO"] {
            let line = format!(
                r#"{{"v":1,"t":"sample","sample":{{"index":1,"ts":0,"metrics":[{{"id":"a","label":"A","group":"CPU","unit":"W","state":"{state}","kind":"measured","confidence":"low","source":"s","reason":"read failed"}}]}}}}"#
            );
            let err = decode_sampler(&line).expect_err("must be rejected");
            assert_eq!(err, ContractError::MissingValue("a".to_string()), "{state}");
        }

        // With no reason at all the existing explanation requirement still wins.
        let line = r#"{"v":1,"t":"sample","sample":{"index":1,"ts":0,"metrics":[{"id":"a","label":"A","group":"CPU","unit":"W","state":"OK","kind":"measured","confidence":"low","source":"s"}]}}"#;
        assert_eq!(
            decode_sampler(line).expect_err("must be rejected"),
            ContractError::MissingReason("a".to_string())
        );

        // A non-finite number is refused rather than rounded into a measurement.
        let line = r#"{"v":1,"t":"sample","sample":{"index":1,"ts":0,"metrics":[{"id":"a","label":"A","group":"CPU","unit":"W","state":"OK","kind":"measured","confidence":"low","source":"s","value":1e400}]}}"#;
        assert!(
            decode_sampler(line).is_err(),
            "a non-finite number is not a value"
        );
    }

    #[test]
    fn a_state_which_is_not_a_measurement_must_not_carry_a_value() {
        // Scenario 2: an error that still carries a usable number.
        let mut metric = Metric::measured("x", "X", Group::Cpu, "W", 42.0, "mock");
        metric.state = MetricState::Error;
        metric.reason = Some("read failed".to_string());
        assert!(
            !metric.is_consistent(),
            "an error cannot be a usable measurement"
        );
        assert!(metric.usable_value().is_none());
        let json = metric_to_json(&metric);
        assert!(
            metric_from_json(&json).is_err(),
            "the reader must refuse a value next to a state that describes its absence"
        );

        // The raw wire form, for every state that describes an absent number.
        for state in ["ERROR", "NO_DATA", "CONFLICT", "UNSUPPORTED"] {
            let line = format!(
                r#"{{"v":1,"t":"sample","sample":{{"index":1,"ts":0,"metrics":[{{"id":"a","label":"A","group":"CPU","unit":"W","state":"{state}","kind":"measured","confidence":"low","source":"s","value":42.0,"reason":"read failed"}}]}}}}"#
            );
            let err = decode_sampler(&line).expect_err("must be rejected");
            assert_eq!(
                err,
                ContractError::UnexpectedValue("a".to_string()),
                "{state}"
            );
        }

        // The same shape through the writer, without a reason.
        let mut error = Metric::unavailable(
            "x",
            "X",
            Group::Cpu,
            "W",
            MetricState::Error,
            "read failed",
            "mock",
        );
        error.value = Some(42.0);
        let json = metric_to_json(&error);
        assert!(metric_from_json(&json).is_err());
    }

    #[test]
    fn consistent_metrics_still_round_trip() {
        // OK with a value, ZERO with a measured zero, and ERROR without either.
        metric_round_trip(&Metric::measured(
            "ok.metric",
            "OK",
            Group::Cpu,
            "W",
            1.5,
            "t",
        ));
        metric_round_trip(&Metric::measured(
            "zero.metric",
            "T",
            Group::Cpu,
            "W",
            0.0,
            "t",
        ));
        metric_round_trip(&Metric::unavailable(
            "error.metric",
            "E",
            Group::Cpu,
            "W",
            MetricState::Error,
            "PDH 0xC0000BBC",
            "t",
        ));
        metric_round_trip(&Metric::unavailable(
            "no.data.metric",
            "N",
            Group::Cpu,
            "W",
            MetricState::NoData,
            "канал не опубликован",
            "t",
        ));
        // A suspect metric that kept its number keeps both the number and the reason.
        let mut suspect = Metric::measured("suspect.metric", "S", Group::Cpu, "W", 120.0, "t");
        suspect.state = MetricState::Suspect;
        suspect.reason = Some("значение вне диапазона".to_string());
        assert!(suspect.is_consistent());
        metric_round_trip(&suspect);

        for metric in [
            Metric::measured("ok.metric", "OK", Group::Cpu, "W", 1.0, "t"),
            Metric::measured("zero.metric", "Z", Group::Cpu, "W", 0.0, "t"),
            Metric::unavailable(
                "error.metric",
                "E",
                Group::Cpu,
                "W",
                MetricState::Error,
                "read failed",
                "t",
            ),
        ] {
            assert!(metric.is_consistent(), "{} must be consistent", metric.id);
        }
    }

    #[test]
    fn a_reason_that_is_not_a_string_is_refused_rather_than_dropped() {
        // `"reason": 7` must not be read as "no reason", or a failure could arrive
        // without the explanation the report has to print.
        let line = r#"{"v":1,"t":"sample","sample":{"index":1,"ts":0,"metrics":[{"id":"a","label":"A","group":"CPU","unit":"W","state":"ERROR","kind":"measured","confidence":"low","source":"s","reason":7}]}}"#;
        let err = decode_sampler(line).expect_err("must be rejected");
        assert_eq!(
            err,
            ContractError::WrongType {
                field: "reason".to_string(),
                expected: "string",
            }
        );
    }

    #[test]
    fn a_value_that_is_not_a_number_is_still_refused() {
        let line = r#"{"v":1,"t":"sample","sample":{"index":1,"ts":0,"metrics":[{"id":"a","label":"A","group":"CPU","unit":"W","state":"OK","kind":"measured","confidence":"low","source":"s","value":"1.0"}]}}"#;
        let err = decode_sampler(line).expect_err("must be rejected");
        assert_eq!(
            err,
            ContractError::WrongType {
                field: "value".to_string(),
                expected: "number",
            }
        );
    }

    #[test]
    fn a_reason_survives_the_wire_for_every_state_that_needs_one() {
        for state in [
            MetricState::Error,
            MetricState::NoData,
            MetricState::Suspect,
            MetricState::Conflict,
        ] {
            let reason = format!("причина для {}", state.as_str());
            let metric =
                Metric::unavailable("x.y", "Y", Group::Cpu, "W", state, reason.clone(), "mock");
            let json = metric_to_json(&metric);
            let restored = metric_from_json(&json).expect("a consistent metric must decode");
            assert_eq!(restored.reason.as_deref(), Some(reason.as_str()));
            assert_eq!(restored.state, state);
            assert_eq!(restored.value, None);
            metric_round_trip(&metric);
        }
    }

    #[test]
    fn every_line_has_no_trailing_newline_or_embedded_break() {
        let line = encode_sampler(&SamplerMessage::Bye {
            version: PROTOCOL_VERSION,
            reason: "остановлено оператором".to_string(),
            samples: 7,
            clean: true,
        });
        assert!(!line.contains('\n'));
        assert!(!line.contains('\r'));
        decode_sampler(&line).expect("decodes");
    }
}
