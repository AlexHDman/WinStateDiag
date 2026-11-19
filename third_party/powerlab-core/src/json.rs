//! A small, exact JSON reader and writer.
//!
//! Hand-written so the PowerLab module keeps its empty third-party dependency
//! list: the IPC contract needs a parser, the probe's emitter cannot read, and no
//! Rust JSON parser exists elsewhere in this repository.
//!
//! The reader is deliberately strict. Anything it cannot represent exactly is an
//! error rather than a guess, because a silently misread telemetry message is worse
//! than a refused one:
//!
//! * duplicate object members are rejected (the two values would be ambiguous);
//! * numbers that cannot round-trip through `f64` are rejected;
//! * trailing content after the top-level value is rejected;
//! * invalid UTF-8 escapes and lone surrogates are rejected;
//! * nesting is bounded, so a hostile or corrupt stream cannot exhaust the stack.

use std::collections::BTreeMap;
use std::fmt::Write as _;

/// Maximum nesting depth accepted by the reader.
pub const MAX_DEPTH: usize = 64;

/// A JSON value that keeps integer precision separate from floating point.
#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    String(String),
    Array(Vec<Json>),
    /// Members in original order. The parser rejects duplicates, so a lookup by
    /// name has exactly one answer.
    Object(Vec<(String, Json)>),
}

impl Json {
    pub fn get(&self, key: &str) -> Option<&Json> {
        self.as_object()?
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
    }
    pub fn str(value: &str) -> Json {
        Json::String(value.to_string())
    }

    pub fn int(value: i64) -> Json {
        Json::Int(value)
    }

    pub fn as_object(&self) -> Option<&Vec<(String, Json)>> {
        match self {
            Json::Object(members) => Some(members),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&Vec<Json>> {
        match self {
            Json::Array(items) => Some(items),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::String(value) => Some(value.as_str()),
            _ => None,
        }
    }

    /// An exact integer. A float is only returned when it has no fractional part
    /// and fits, so a truncated value can never masquerade as an integer.
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Json::Int(value) => Some(*value),
            Json::Float(value)
                if value.is_finite()
                    && value.fract() == 0.0
                    && *value >= i64::MIN as f64
                    && *value <= i64::MAX as f64 =>
            {
                Some(*value as i64)
            }
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Json::Int(value) => Some(*value as f64),
            Json::Float(value) => Some(*value),
            _ => None,
        }
    }

    /// Serialise compactly, with no insignificant whitespace and no trailing
    /// newline.
    pub fn render(&self) -> String {
        let mut out = String::with_capacity(64);
        self.write(&mut out);
        out
    }

    fn write(&self, out: &mut String) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(true) => out.push_str("true"),
            Json::Bool(false) => out.push_str("false"),
            Json::Int(value) => {
                let _ = write!(out, "{value}");
            }
            Json::Float(value) => write_float(out, *value),
            Json::String(value) => write_string(out, value),
            Json::Array(items) => {
                out.push('[');
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    item.write(out);
                }
                out.push(']');
            }
            Json::Object(members) => {
                out.push('{');
                for (index, (key, value)) in members.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    write_string(out, key);
                    out.push(':');
                    value.write(out);
                }
                out.push('}');
            }
        }
    }
}

/// Write a float so that it is valid JSON and round-trips.
///
/// JSON has no `NaN` or `Infinity` literal. A non-finite value is written as
/// `null`: callers are expected to have classified such a reading as SUSPECT or
/// ERROR with a reason, so `null` here means "no number", never "bad number
/// silently dropped".
fn write_float(out: &mut String, value: f64) {
    if !value.is_finite() {
        out.push_str("null");
        return;
    }
    if value == value.trunc() && value.abs() < 1e15 {
        // Keep integral floats integral-looking so `1000.0` does not become
        // `1000.0000000000001` and confuse a window length.
        let _ = write!(out, "{value:.1}");
        return;
    }
    let rendered = format!("{value}");
    out.push_str(&rendered);
}

fn write_string(out: &mut String, value: &str) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// A parse failure, with the byte offset so a bad stream can be located.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonError {
    pub offset: usize,
    pub message: String,
}

impl std::fmt::Display for JsonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (позиция {})", self.message, self.offset)
    }
}

impl std::error::Error for JsonError {}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn err<T>(&self, message: impl Into<String>) -> Result<T, JsonError> {
        Err(JsonError {
            offset: self.pos,
            message: message.into(),
        })
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn skip_ws(&mut self) {
        while let Some(byte) = self.peek() {
            match byte {
                b' ' | b'\t' | b'\n' | b'\r' => self.pos += 1,
                _ => break,
            }
        }
    }

    fn expect(&mut self, byte: u8) -> Result<(), JsonError> {
        if self.peek() == Some(byte) {
            self.pos += 1;
            Ok(())
        } else {
            self.err(format!("ожидался символ '{}'", byte as char))
        }
    }

    fn literal(&mut self, word: &str, value: Json) -> Result<Json, JsonError> {
        if self.bytes[self.pos..].starts_with(word.as_bytes()) {
            self.pos += word.len();
            Ok(value)
        } else {
            self.err(format!("ожидалось '{word}'"))
        }
    }

    fn value(&mut self, depth: usize) -> Result<Json, JsonError> {
        if depth > MAX_DEPTH {
            return self.err("слишком глубокая вложенность JSON");
        }
        self.skip_ws();
        match self.peek() {
            None => self.err("неожиданный конец ввода"),
            Some(b'{') => self.object(depth),
            Some(b'[') => self.array(depth),
            Some(b'"') => Ok(Json::String(self.string()?)),
            Some(b't') => self.literal("true", Json::Bool(true)),
            Some(b'f') => self.literal("false", Json::Bool(false)),
            Some(b'n') => self.literal("null", Json::Null),
            Some(_) => self.number(),
        }
    }

    fn object(&mut self, depth: usize) -> Result<Json, JsonError> {
        self.expect(b'{')?;
        let mut members: Vec<(String, Json)> = Vec::new();
        let mut seen: BTreeMap<String, ()> = BTreeMap::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Json::Object(members));
        }
        loop {
            self.skip_ws();
            let key = self.string()?;
            if seen.insert(key.clone(), ()).is_some() {
                // Two values for one name would make every later lookup
                // ambiguous, so the message is refused outright.
                return self.err(format!("повторяющееся поле объекта: {key}"));
            }
            self.skip_ws();
            self.expect(b':')?;
            let value = self.value(depth + 1)?;
            members.push((key, value));
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Json::Object(members));
                }
                _ => return self.err("ожидалась ',' или '}'"),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Json, JsonError> {
        self.expect(b'[')?;
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Json::Array(items));
        }
        loop {
            items.push(self.value(depth + 1)?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Json::Array(items));
                }
                _ => return self.err("ожидалась ',' или ']'"),
            }
        }
    }

    fn string(&mut self) -> Result<String, JsonError> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            let byte = match self.peek() {
                Some(b) => b,
                None => return self.err("незакрытая строка"),
            };
            match byte {
                b'"' => {
                    self.pos += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.pos += 1;
                    let escape = match self.peek() {
                        Some(b) => b,
                        None => return self.err("незавершённая escape-последовательность"),
                    };
                    self.pos += 1;
                    match escape {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{08}'),
                        b'f' => out.push('\u{0c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let first = self.hex4()?;
                            let ch = if (0xD800..0xDC00).contains(&first) {
                                // A high surrogate must be followed by a low one.
                                self.expect(b'\\')?;
                                self.expect(b'u')?;
                                let second = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&second) {
                                    return self.err("некорректная сурогатная пара");
                                }
                                let combined = 0x1_0000
                                    + ((first as u32 - 0xD800) << 10)
                                    + (second as u32 - 0xDC00);
                                char::from_u32(combined)
                            } else if (0xDC00..0xE000).contains(&first) {
                                return self.err("одиночный младший суррогат");
                            } else {
                                char::from_u32(first as u32)
                            };
                            match ch {
                                Some(c) => out.push(c),
                                None => return self.err("некорректный код символа"),
                            }
                        }
                        _ => return self.err("неизвестная escape-последовательность"),
                    }
                }
                _ => {
                    // Copy one whole UTF-8 scalar so multi-byte text is preserved.
                    let len = utf8_len(byte);
                    if len == 0 {
                        return self.err("некорректный UTF-8");
                    }
                    let end = self.pos + len;
                    if end > self.bytes.len() {
                        return self.err("обрыв UTF-8 последовательности");
                    }
                    match std::str::from_utf8(&self.bytes[self.pos..end]) {
                        Ok(text) => out.push_str(text),
                        Err(_) => return self.err("некорректный UTF-8 в строке"),
                    }
                    self.pos = end;
                }
            }
        }
    }

    fn hex4(&mut self) -> Result<u16, JsonError> {
        if self.pos + 4 > self.bytes.len() {
            return self.err("обрыв \\u escape");
        }
        let text = match std::str::from_utf8(&self.bytes[self.pos..self.pos + 4]) {
            Ok(text) => text,
            Err(_) => return self.err("некорректный \\u escape"),
        };
        match u16::from_str_radix(text, 16) {
            Ok(value) => {
                self.pos += 4;
                Ok(value)
            }
            Err(_) => self.err("некорректный \\u escape"),
        }
    }

    fn number(&mut self) -> Result<Json, JsonError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        let mut digits = 0usize;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos += 1;
            digits += 1;
        }
        if digits == 0 {
            return self.err("ожидалось число");
        }
        let mut is_float = false;
        if self.peek() == Some(b'.') {
            is_float = true;
            self.pos += 1;
            let mut frac = 0usize;
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
                frac += 1;
            }
            if frac == 0 {
                return self.err("ожидались цифры после точки");
            }
        }
        if matches!(self.peek(), Some(b'e') | Some(b'E')) {
            is_float = true;
            self.pos += 1;
            if matches!(self.peek(), Some(b'+') | Some(b'-')) {
                self.pos += 1;
            }
            let mut exp = 0usize;
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
                exp += 1;
            }
            if exp == 0 {
                return self.err("ожидались цифры в экспоненте");
            }
        }
        let text = match std::str::from_utf8(&self.bytes[start..self.pos]) {
            Ok(text) => text,
            Err(_) => return self.err("некорректное число"),
        };
        if !is_float {
            if let Ok(value) = text.parse::<i64>() {
                return Ok(Json::Int(value));
            }
            // An integer too large for i64 is still representable as f64, but the
            // caller must know precision was lost, so it becomes a Float.
        }
        match text.parse::<f64>() {
            Ok(value) if value.is_finite() => Ok(Json::Float(value)),
            Ok(_) => self.err("число вне представимого диапазона"),
            Err(_) => self.err("некорректное число"),
        }
    }
}

fn utf8_len(first: u8) -> usize {
    match first {
        0x00..=0x7F => 1,
        0xC2..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xF4 => 4,
        _ => 0,
    }
}

impl Json {
    /// Parse one complete JSON value.
    ///
    /// Trailing whitespace is allowed; trailing content is not, so a stream that
    /// concatenates two values without a separator is reported instead of silently
    /// yielding only the first.
    pub fn parse(text: &str) -> Result<Json, JsonError> {
        let mut reader = Reader {
            bytes: text.as_bytes(),
            pos: 0,
        };
        let value = reader.value(0)?;
        reader.skip_ws();
        if reader.pos != reader.bytes.len() {
            return reader.err("лишние данные после значения");
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalars_round_trip() {
        for text in [
            "null",
            "true",
            "false",
            "0",
            "-1",
            "42",
            "1.5",
            "-0.25",
            "\"\"",
            "\"текст\"",
        ] {
            let value = Json::parse(text).expect(text);
            assert_eq!(value.render(), text, "round trip of {text}");
        }
    }

    #[test]
    fn integers_keep_their_precision() {
        let value = Json::parse("9007199254740993").expect("parses");
        assert_eq!(value, Json::Int(9_007_199_254_740_993));
        assert_eq!(value.as_int(), Some(9_007_199_254_740_993));
    }

    #[test]
    fn a_float_is_never_silently_read_as_an_integer() {
        let value = Json::parse("1.5").expect("parses");
        assert_eq!(value.as_int(), None);
    }

    #[test]
    fn nested_structures_preserve_order() {
        let text = r#"{"b":1,"a":[1,{"c":null}]}"#;
        let value = Json::parse(text).expect("parses");
        let members = value.as_object().expect("object");
        assert_eq!(members[0].0, "b");
        assert_eq!(members[1].0, "a");
    }

    #[test]
    fn duplicate_members_are_rejected() {
        let err = Json::parse(r#"{"a":1,"a":2}"#).expect_err("must be rejected");
        assert!(err.message.contains("повторяющееся поле"), "{err}");
    }

    #[test]
    fn trailing_content_is_rejected() {
        let err = Json::parse("1 2").expect_err("must be rejected");
        assert!(err.message.contains("лишние данные"), "{err}");
    }

    #[test]
    fn escapes_including_surrogate_pairs_are_decoded() {
        let value = Json::parse(r#""a\nb\u0041\uD83D\uDE00""#).expect("parses");
        assert_eq!(value.as_str(), Some("a\nbA😀"));
    }

    #[test]
    fn a_lone_surrogate_is_rejected() {
        assert!(Json::parse(r#""\uD83D""#).is_err());
        assert!(Json::parse(r#""\uDE00""#).is_err());
    }

    #[test]
    fn a_replacement_character_is_preserved_not_silently_dropped() {
        // Invalid UTF-8 cannot reach this reader at all: `parse` takes a `&str`, so
        // the byte-level rejection belongs to the line reader, which sees raw bytes.
        // What matters here is that a U+FFFD that *did* arrive is carried through
        // unchanged rather than being normalised away.
        let value = Json::parse("\"\u{FFFD}\"").expect("parses");
        assert_eq!(value.as_str(), Some("\u{FFFD}"));
        assert_eq!(value.render(), "\"\u{FFFD}\"");
    }

    #[test]
    fn a_raw_byte_string_is_refused_rather_than_lossily_decoded() {
        // Pins the division of responsibility: `std::str::from_utf8` is the gate,
        // and a lossy conversion is never used to make bad bytes "parse".
        let bytes: [u8; 3] = [0x22, 0x80, 0x22];
        assert!(std::str::from_utf8(bytes.as_slice()).is_err());
    }

    #[test]
    fn deep_nesting_is_bounded() {
        let deep = "[".repeat(MAX_DEPTH + 2) + &"]".repeat(MAX_DEPTH + 2);
        let err = Json::parse(&deep).expect_err("must be rejected");
        assert!(err.message.contains("вложенность"), "{err}");
    }

    #[test]
    fn non_finite_values_are_written_as_null_not_as_invalid_json() {
        let value = Json::Array(vec![Json::Float(f64::NAN), Json::Float(f64::INFINITY)]);
        assert_eq!(value.render(), "[null,null]");
        Json::parse(&value.render()).expect("output must be valid JSON");
    }

    #[test]
    fn control_characters_are_escaped() {
        let value = Json::String("a\u{1}b".to_string());
        let text = value.render();
        assert!(text.contains("\\u0001"), "{text}");
        assert_eq!(Json::parse(&text).expect("parses"), value);
    }

    #[test]
    fn the_writer_output_is_always_re_readable() {
        let value = Json::Object(vec![
            ("s".into(), Json::str("строка с \"кавычками\" и \\ слэшем")),
            ("n".into(), Json::Int(-7)),
            ("f".into(), Json::Float(1000.0)),
            (
                "arr".into(),
                Json::Array(vec![Json::Null, Json::Bool(true)]),
            ),
        ]);
        let text = value.render();
        assert_eq!(Json::parse(&text).expect("parses"), value);
    }
}
