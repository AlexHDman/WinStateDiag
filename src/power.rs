//! ATX power rails (v0.4.4, reduced in v0.4.5): rail identity, nominal and
//! the ATX-tolerance classification of a SENSOR READING. Collection,
//! providers and confidence live in [`crate::sensors`].
//!
//! These are sensor readings, never a diagnosis of the power supply: the
//! only conclusion is "power-line deviation detected — confirm with an
//! external measurement (PSU tester / multimeter)".

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Rail {
    V12,
    V5,
    V3_3,
    V5Sb,
}

impl Rail {
    #[allow(dead_code)]
    pub const ALL: [Rail; 4] = [Rail::V12, Rail::V5, Rail::V3_3, Rail::V5Sb];

    pub fn label(self) -> &'static str {
        match self {
            Rail::V12 => "+12V",
            Rail::V5 => "+5V",
            Rail::V3_3 => "+3.3V",
            Rail::V5Sb => "5VSB",
        }
    }

    pub fn nominal(self) -> f64 {
        match self {
            Rail::V12 => 12.0,
            Rail::V5 | Rail::V5Sb => 5.0,
            Rail::V3_3 => 3.3,
        }
    }

    /// Maps an explicitly labelled sensor name to a rail. Generic names
    /// ("Voltage #3", "VIN2") are NOT mapped — their rail is unknown.
    pub fn from_sensor_name(name: &str) -> Option<Rail> {
        let n: String = name
            .to_ascii_uppercase()
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        if n.contains("5VSB") || n.contains("VSB") || n.contains("STANDBY") || n.contains("+5VSTBY")
        {
            return Some(Rail::V5Sb);
        }
        if n.contains("12V") || n == "+12" || n.contains("VIN12") {
            return Some(Rail::V12);
        }
        if n.contains("3.3V") || n.contains("3,3V") || n.contains("3VCC") || n.contains("+3.3") {
            return Some(Rail::V3_3);
        }
        if (n.contains("+5V") || n == "5V" || n.contains("5VCC"))
            && !n.contains("1.5V")
            && !n.contains("2.5V")
        {
            return Some(Rail::V5);
        }
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RailStatus {
    Excellent,
    Attention,
    Critical,
}

// Texts kept for evidence vocabulary / tests (sensors.rs uses PowerStatus).
#[allow(dead_code)]
impl RailStatus {
    pub fn text(self, ru: bool) -> &'static str {
        match (self, ru) {
            (RailStatus::Excellent, true) => "Отлично",
            (RailStatus::Excellent, false) => "Excellent",
            (RailStatus::Attention, true) => "Внимание!",
            (RailStatus::Attention, false) => "Attention",
            (RailStatus::Critical, true) => "Критично!",
            (RailStatus::Critical, false) => "Critical",
        }
    }
    pub fn code(self) -> &'static str {
        match self {
            RailStatus::Excellent => "EXCELLENT",
            RailStatus::Attention => "ATTENTION",
            RailStatus::Critical => "CRITICAL",
        }
    }
}

/// ATX design guide tolerance is ±5 % for +12V/+5V/+3.3V/5VSB. Within
/// ±3 % the reading is "Excellent", up to ±5 % "Attention", beyond the
/// ATX tolerance "Critical" — always as a sensor reading.
pub fn classify(deviation_percent: f64) -> RailStatus {
    let d = deviation_percent.abs();
    if d <= 3.0 {
        RailStatus::Excellent
    } else if d <= 5.0 {
        RailStatus::Attention
    } else {
        RailStatus::Critical
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rails_are_mapped_only_from_explicit_labels() {
        assert_eq!(Rail::from_sensor_name("+12V"), Some(Rail::V12));
        assert_eq!(Rail::from_sensor_name("+5V"), Some(Rail::V5));
        assert_eq!(Rail::from_sensor_name("+3.3V"), Some(Rail::V3_3));
        assert_eq!(Rail::from_sensor_name("+5V Standby"), Some(Rail::V5Sb));
        assert_eq!(Rail::from_sensor_name("5VSB"), Some(Rail::V5Sb));
        assert_eq!(Rail::from_sensor_name("Voltage #3"), None);
        assert_eq!(Rail::from_sensor_name("CPU Core"), None);
        assert_eq!(Rail::from_sensor_name("+1.5V"), None);
        assert_eq!(Rail::ALL.len(), 4);
    }

    #[test]
    fn statuses_follow_atx_tolerance() {
        assert_eq!(classify(0.0), RailStatus::Excellent);
        assert_eq!(classify(-2.9), RailStatus::Excellent);
        assert_eq!(classify(4.2), RailStatus::Attention);
        assert_eq!(classify(-5.0), RailStatus::Attention);
        assert_eq!(classify(-6.1), RailStatus::Critical);
        assert_eq!(RailStatus::Critical.text(true), "Критично!");
        assert_eq!(RailStatus::Attention.code(), "ATTENTION");
    }
}
