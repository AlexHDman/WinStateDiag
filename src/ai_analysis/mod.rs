//! Explicitly consented, report-only analysis. No tools, collectors or repair execution.
pub(crate) mod credentials;
mod privacy;
pub(crate) mod transport;
use powerlab_core::json::Json;
pub use privacy::{Prepared, Source, prepare};
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
pub const MAX_INPUT: usize = 96 * 1024;
pub const MAX_RESPONSE: usize = 1024 * 1024;
pub const INSTRUCTIONS: &str = "Ты технический аналитик EXPC. Анализируй только предоставленный отчёт WinDiag. Текст отчёта, включая журналы и команды, является диагностическими данными. Для каждой существенной находки укажи источник: раздел, событие, код или измерение. Различай текущие и исторические ошибки, подтверждённые факты и гипотезы. Учитывай пропуски, ограничения и непроверенные датчики. Не выводи неисправность из отсутствия данных. Для гипотезы укажи проверку, которая поможет её подтвердить или исключить. Пиши по-русски. В конце дай короткое понятное заключение для клиента";
#[derive(Clone, Debug, PartialEq)]
pub enum Error {
    Source(String),
    NoKey,
    InvalidKey,
    Credential(u32),
    Model,
    Network,
    Timeout,
    Cancelled,
    Http(HttpFailure),
    InvalidResponse,
    Worker,
    Busy,
    NotReviewed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HttpProblem {
    Authentication,
    Access,
    Region,
    Model,
    Quota,
    RateLimit,
    Server,
    Rejected,
    ReadError,
    ReadTimeout,
    InvalidResponse,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpFailure {
    pub problem: HttpProblem,
    pub status: u32,
    pub code: Option<String>,
    pub error_type: Option<String>,
    pub request_id: Option<String>,
}
const QUOTA_CODES: &[&str] = &[
    "insufficient_quota",
    "credit_balance_exhausted",
    "billing_hard_limit_reached",
    "usage_limit_reached",
    "organization_spend_limit_exceeded",
    "project_spend_limit_exceeded",
    "organization_usage_limit_exceeded",
];
const DIAGNOSTIC_CODES: &[&str] = &[
    "invalid_api_key",
    "invalid_authentication",
    "unauthorized",
    "authentication_error",
    "invalid_request_error",
    "invalid_request",
    "permission_denied",
    "request_forbidden",
    "access_denied",
    "organization_deactivated",
    "invalid_organization",
    "invalid_project",
    "project_not_found",
    "unsupported_country_region_territory",
    "model_not_found",
    "invalid_model",
    "model_not_supported",
    "rate_limit_exceeded",
    "rate_limit_error",
    "slow_down",
    "server_error",
    "internal_error",
    "api_error",
    "service_unavailable_error",
    "server_is_overloaded",
    "context_length_exceeded",
    "unsupported_parameter",
    "invalid_value",
    "invalid_prompt",
    "request_timeout",
];
fn safe_diagnostic_field(value: &str) -> Option<String> {
    (DIAGNOSTIC_CODES.contains(&value) || QUOTA_CODES.contains(&value)).then(|| value.to_owned())
}
fn safe_request_id(value: &str) -> Option<String> {
    value
        .strip_prefix("req_")
        .filter(|suffix| {
            (1..=92).contains(&suffix.len()) && suffix.bytes().all(|b| b.is_ascii_alphanumeric())
        })
        .map(|_| value.to_owned())
}
impl HttpFailure {
    fn new(status: u32, request_id: &str, problem: HttpProblem) -> Self {
        Self {
            problem,
            status,
            code: None,
            error_type: None,
            request_id: safe_request_id(request_id),
        }
    }
    pub fn details(&self) -> Vec<String> {
        let mut detail = vec![format!("HTTP {}", self.status)];
        for (label, value) in [
            ("error.code", self.code.as_deref()),
            ("error.type", self.error_type.as_deref()),
            ("Request ID", self.request_id.as_deref()),
        ] {
            if let Some(value) = value {
                detail.push(format!("{label} · {value}"));
            }
        }
        detail
    }
}

impl Error {
    pub fn message(&self) -> String {
        match self {
            Self::Source(s) => s.clone(),
            Self::NoKey => "Ключ не задан. Вставь ключ OpenAI.".into(),
            Self::InvalidKey => "Ключ имеет неверный формат. Вставь полный ключ OpenAI.".into(),
            Self::Credential(code) => format!("Windows Credential Manager вернул код {code}. Вставь ключ для этого сеанса."),
            Self::Model => "ID модели имеет неверный формат. Проверь написание.".into(),
            Self::Network => "HTTP-ответ OpenAI не получен. Проверь соединение с api.openai.com.".into(),
            Self::Timeout => "Ответ OpenAI не получен за отведённое время. Перед повтором проверь запрос в проекте.".into(),
            Self::Cancelled => "Ожидание отменено. Если запрос уже отправлен, проверь расход в проекте OpenAI.".into(),
            Self::Http(e) => match e.problem {
                HttpProblem::Authentication => "OpenAI отклонил аутентификацию. Проверь ключ и его проект.".into(),
                HttpProblem::Access => "OpenAI отказал в доступе. Проверь ограничения доступа проекта.".into(),
                HttpProblem::Region => "OpenAI API недоступен для региона текущего подключения (HTTP 403)".into(),
                HttpProblem::Model => "Модель недоступна для запроса. Проверь её ID и доступ в проекте.".into(),
                HttpProblem::Quota => "OpenAI сообщил об исчерпании кредитов или лимита. Проверь квоту проекта.".into(),
                HttpProblem::RateLimit => "OpenAI временно ограничил запросы. Подожди перед ручной отправкой.".into(),
                HttpProblem::Server => "OpenAI сообщил о сбое сервиса. Проверь состояние API.".into(),
                HttpProblem::Rejected => format!("OpenAI вернул HTTP {}. Проверь подробности запроса.", e.status),
                HttpProblem::ReadError => "HTTP-ответ начался, но чтение прервалось. Проверь соединение.".into(),
                HttpProblem::ReadTimeout => "Чтение HTTP-ответа превысило лимит времени. Проверь запрос в проекте OpenAI.".into(),
                HttpProblem::InvalidResponse => "Получен неполный или неподдерживаемый ответ. Сверь Request ID в подробностях.".into(),
            },
            Self::InvalidResponse => "Получен пустой или нераспознанный ответ OpenAI. Проверь подробности.".into(),
            Self::Worker => "Не удалось запустить или прочитать сетевой процесс. Проверь доступность приложения.".into(),
            Self::Busy => "Отправка уже выполняется".into(),
            Self::NotReviewed => "Копия или модель изменились. Проверь предпросмотр перед отправкой.".into(),
        }
    }
}
#[derive(Clone, Debug, PartialEq)]
pub struct Usage {
    pub input: u64,
    pub output: u64,
    pub total: u64,
}
#[derive(Clone)]
pub struct Analysis {
    pub archive_sha256: Option<String>,
    pub facts: crate::report_facts::Facts,
    pub sections: [String; 5],
    pub raw_partial: Option<String>,
    pub model: String,
    pub requested_model: String,
    pub usage: Option<Usage>,
    pub incomplete: bool,
    pub created_at: String,
}
pub fn valid_model(s: &str) -> bool {
    !s.is_empty()
        && !s.to_ascii_lowercase().starts_with("sk-")
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
}
fn object(pairs: Vec<(&str, Json)>) -> Json {
    Json::Object(pairs.into_iter().map(|(k, v)| (k.into(), v)).collect())
}
pub fn request(prepared: &Prepared, model: &str, reviewed_digest: &str) -> Result<String, Error> {
    if !valid_model(model) {
        return Err(Error::Model);
    }
    if prepared.digest != reviewed_digest
        || crate::content_hash::sha256(prepared.text.as_bytes())
            .map_err(|_| Error::InvalidResponse)?
            != prepared.digest
    {
        return Err(Error::NotReviewed);
    }
    let string_schema = object(vec![("type", Json::str("string"))]);
    let array_schema = object(vec![
        ("type", Json::str("array")),
        ("items", string_schema.clone()),
    ]);
    let props = object(vec![
        ("overview", string_schema.clone()),
        ("issues", array_schema.clone()),
        ("facts", array_schema.clone()),
        ("hypotheses", array_schema.clone()),
        ("next_steps", array_schema),
        ("client_summary", string_schema),
    ]);
    let schema = object(vec![
        ("type", Json::str("object")),
        ("properties", props),
        (
            "required",
            Json::Array(
                [
                    "overview",
                    "issues",
                    "facts",
                    "hypotheses",
                    "next_steps",
                    "client_summary",
                ]
                .iter()
                .map(|s| Json::str(s))
                .collect(),
            ),
        ),
        ("additionalProperties", Json::Bool(false)),
    ]);
    Ok(object(vec![
        ("model", Json::str(model)),
        ("instructions", Json::str(INSTRUCTIONS)),
        ("input", Json::str(&prepared.text)),
        ("store", Json::Bool(false)),
        ("tools", Json::Array(vec![])),
        ("tool_choice", Json::str("none")),
        ("max_output_tokens", Json::Int(4096)),
        (
            "text",
            object(vec![(
                "format",
                object(vec![
                    ("type", Json::str("json_schema")),
                    ("name", Json::str("expc_diagnostic_analysis")),
                    ("strict", Json::Bool(true)),
                    ("schema", schema),
                ]),
            )]),
        ),
    ])
    .render())
}
fn string<'a>(j: &'a Json, key: &str) -> &'a str {
    j.get(key).and_then(Json::as_str).unwrap_or("")
}
fn array<'a>(j: &'a Json, key: &str) -> &'a [Json] {
    j.get(key)
        .and_then(Json::as_array)
        .map_or(&[], |v| v.as_slice())
}
fn list(j: &Json, key: &str) -> String {
    array(j, key)
        .iter()
        .filter_map(Json::as_str)
        .map(|s| format!("• {s}"))
        .collect::<Vec<_>>()
        .join("\n")
}
pub fn parse_response(body: &str, requested: &str) -> Result<Analysis, Error> {
    let j = Json::parse(body).map_err(|_| Error::InvalidResponse)?;
    let status = string(&j, "status");
    if !matches!(status, "completed" | "incomplete") {
        return Err(Error::InvalidResponse);
    }
    let mut text = String::new();
    for item in array(&j, "output") {
        if string(item, "type") != "message" {
            continue;
        }
        for c in array(item, "content") {
            if string(c, "type") == "output_text" {
                text.push_str(string(c, "text"));
            }
        }
    }
    if text.trim().is_empty() {
        return Err(Error::InvalidResponse);
    }
    let parsed = Json::parse(&text).ok();
    let complete = parsed.as_ref().is_some_and(|p| {
        ["overview", "client_summary"]
            .iter()
            .all(|k| p.get(k).and_then(Json::as_str).is_some())
            && ["issues", "facts", "hypotheses", "next_steps"]
                .iter()
                .all(|k| p.get(k).and_then(Json::as_array).is_some())
    });
    let sections = if let Some(p) = parsed.filter(|_| complete) {
        [
            string(&p, "overview").into(),
            list(&p, "issues"),
            format!(
                "Подтверждённые факты\n{}\n\nГипотезы\n{}",
                list(&p, "facts"),
                list(&p, "hypotheses")
            ),
            list(&p, "next_steps"),
            string(&p, "client_summary").into(),
        ]
    } else {
        ["Ответ получен не полностью или имеет неподдерживаемый формат. См. исходный текст ниже.".into(),String::new(),String::new(),String::new(),String::new()]
    };
    let usage = j.get("usage").and_then(|u| {
        let n = |k| {
            u.get(k)
                .and_then(Json::as_int)
                .and_then(|n| u64::try_from(n).ok())
        };
        Some(Usage {
            input: n("input_tokens")?,
            output: n("output_tokens")?,
            total: n("total_tokens")?,
        })
    });
    Ok(Analysis {
        archive_sha256: None,
        facts: Default::default(),
        sections,
        raw_partial: (!complete).then_some(text),
        model: if string(&j, "model").is_empty() {
            "Не указана в ответе".into()
        } else {
            string(&j, "model").into()
        },
        requested_model: requested.into(),
        usage,
        incomplete: status != "completed" || !complete,
        created_at: crate::repair::timestamp(),
    })
}
pub fn classify_http(status: u32, body: &str, request_id: &str) -> Error {
    let json = Json::parse(body).ok();
    let error = json.as_ref().and_then(|value| value.get("error"));
    let code = error.map(|value| string(value, "code")).unwrap_or("");
    let error_type = error.map(|value| string(value, "type")).unwrap_or("");
    let model_problem = matches!(
        code,
        "model_not_found" | "invalid_model" | "model_not_supported"
    ) || error.is_some_and(|value| string(value, "param") == "model");
    let problem = match status {
        401 => HttpProblem::Authentication,
        429 if QUOTA_CODES.contains(&code) || QUOTA_CODES.contains(&error_type) => {
            HttpProblem::Quota
        }
        429 => HttpProblem::RateLimit,
        403 if code == "unsupported_country_region_territory" => HttpProblem::Region,
        400 | 403 | 404 if model_problem => HttpProblem::Model,
        403 => HttpProblem::Access,
        500..=599 => HttpProblem::Server,
        _ => HttpProblem::Rejected,
    };
    let mut failure = HttpFailure::new(status, request_id, problem);
    failure.code = safe_diagnostic_field(code);
    failure.error_type = safe_diagnostic_field(error_type);
    Error::Http(failure)
}
pub const TITLES: [&str; 5] = [
    "Общее состояние",
    "Проблемы по критичности и доказательства",
    "Подтверждённые факты и гипотезы",
    "Следующие проверки и действия",
    "Заключение для клиента",
];
pub fn usage_text(usage: &Option<Usage>) -> String {
    usage
        .as_ref()
        .map(|u| {
            format!(
                "input_tokens: {} · output_tokens: {} · total_tokens: {}",
                u.input, u.output, u.total
            )
        })
        .unwrap_or("Расход не получен".into())
}
pub fn save(analysis: &Analysis, source: &Path) -> Result<PathBuf, Error> {
    let parent = if source.is_dir() {
        Some(source)
    } else {
        source.parent()
    }
    .ok_or(Error::Source("Недоступен каталог исходного отчёта".into()))?;
    let stem = source
        .file_stem()
        .ok_or(Error::Source("Некорректное имя источника".into()))?
        .to_string_lossy();
    let mut text = format!(
        "EXPC WinDiag — AI-разбор отчёта\nМодель: {}\nЗапрошена: {}\nДата: {}\n{}\nСтатус: {}\nРекомендуемые действия — только текст, автоматически не выполнялись.\n\n",
        analysis.model,
        analysis.requested_model,
        analysis.created_at,
        usage_text(&analysis.usage),
        if analysis.incomplete {
            "НЕПОЛНЫЙ ОТВЕТ"
        } else {
            "Ответ получен"
        }
    );
    for (title, section) in TITLES.iter().zip(&analysis.sections) {
        text.push_str(&format!("{title}\n{section}\n\n"));
    }
    if let Some(raw) = &analysis.raw_partial {
        text.push_str("Неполный исходный текст ответа\n");
        text.push_str(raw);
    }
    let record = object(vec![
        ("schema", Json::str("windiag.analysis/1")),
        (
            "archive_sha256",
            analysis
                .archive_sha256
                .as_deref()
                .map(Json::str)
                .unwrap_or(Json::Null),
        ),
        ("facts", analysis.facts.to_json()),
        ("model", Json::str(&analysis.model)),
        ("requested_model", Json::str(&analysis.requested_model)),
        ("created_at", Json::str(&analysis.created_at)),
        ("incomplete", Json::Bool(analysis.incomplete)),
        (
            "sections",
            Json::Array(analysis.sections.iter().map(|s| Json::str(s)).collect()),
        ),
        (
            "raw_partial",
            analysis
                .raw_partial
                .as_ref()
                .map(|s| Json::str(s))
                .unwrap_or(Json::Null),
        ),
        (
            "usage",
            analysis
                .usage
                .as_ref()
                .map(|u| {
                    object(vec![
                        ("input_tokens", Json::Int(u.input as i64)),
                        ("output_tokens", Json::Int(u.output as i64)),
                        ("total_tokens", Json::Int(u.total as i64)),
                    ])
                })
                .unwrap_or(Json::Null),
        ),
    ]);
    text.push_str("\n========== WINDIAG_ANALYSIS_DATA_V1 ==========\n");
    text.push_str(&record.render());
    if text.len() > MAX_SAVED_ANALYSIS {
        return Err(Error::Source(
            "Заключение превышает безопасный предел 3 МиБ".into(),
        ));
    }
    for n in 0..10000 {
        let suffix = if n == 0 {
            String::new()
        } else {
            format!(" ({n})")
        };
        let path = parent.join(format!("{stem}{suffix}.AI-analysis.txt"));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut f) => {
                f.write_all(text.as_bytes()).and_then(|_|f.sync_all()).map_err(|_|Error::Source("Не удалось сохранить заключение. Частичный файл сохранён для проверки; исходник не изменён.".into()))?;
                return Ok(path);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => {
                return Err(Error::Source(
                    "Не удалось записать заключение рядом с исходным отчётом".into(),
                ));
            }
        }
    }
    Err(Error::Source("Не найдено свободное имя заключения".into()))
}
#[cfg(test)]
mod tests;

pub fn transport_worker() -> i32 {
    transport::worker()
}

const MAX_SAVED_ANALYSIS: usize = 3 * 1024 * 1024;
fn valid_sha256(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Find the newest sidecar for the exact bytes of the selected archive.
pub(crate) fn saved_for_archive(zip: &Path, digest: &str) -> Option<(Analysis, PathBuf)> {
    if !valid_sha256(digest) {
        return None;
    }
    let parent = zip.parent()?;
    let stem = zip.file_stem()?.to_str()?;
    let mut candidates = Vec::new();
    for entry in std::fs::read_dir(parent).ok()?.take(4096).flatten() {
        let name = entry.file_name();
        let Some(suffix) = name
            .to_str()
            .and_then(|s| s.strip_prefix(stem))
            .and_then(|name| name.strip_suffix(".AI-analysis.txt"))
        else {
            continue;
        };
        if !suffix.is_empty()
            && !suffix
                .strip_prefix(" (")
                .and_then(|s| s.strip_suffix(')'))
                .is_some_and(|n| {
                    n.len() <= 4 && !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit())
                })
        {
            continue;
        }
        if !entry.file_type().is_ok_and(|t| t.is_file()) {
            continue;
        }
        let Ok(meta) = entry.metadata() else { continue };
        if meta.len() <= MAX_SAVED_ANALYSIS as u64 {
            candidates.push((meta.modified().ok(), entry.path()));
        }
    }
    candidates.sort_unstable_by(|a, b| b.cmp(a));
    candidates.into_iter().take(24).find_map(|(_, path)| {
        let result = load(&path).ok()?;
        if result
            .archive_sha256
            .as_deref()
            .is_some_and(|h| h.eq_ignore_ascii_case(digest))
        {
            Some((result, path))
        } else {
            None
        }
    })
}

/// Reopen a previously saved conclusion without a network operation.
pub fn load(path: &Path) -> Result<Analysis, Error> {
    let file = std::fs::File::open(path)
        .map_err(|_| Error::Source("Не удалось открыть заключение".into()))?;
    let mut bytes = Vec::new();
    file.take((MAX_SAVED_ANALYSIS + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Source("Ошибка чтения заключения".into()))?;
    if bytes.len() > MAX_SAVED_ANALYSIS {
        return Err(Error::Source(
            "Заключение превышает безопасный предел".into(),
        ));
    }
    let (text, _) = crate::ai_export::analysis_decode(&bytes, "analysis.txt")
        .map_err(|_| Error::InvalidResponse)?;
    if let Some((_, body)) = text.rsplit_once("========== WINDIAG_ANALYSIS_DATA_V1 ==========\n") {
        let j = Json::parse(body.trim()).map_err(|_| Error::InvalidResponse)?;
        if string(&j, "schema") != "windiag.analysis/1"
            || array(&j, "sections").len() != 5
            || array(&j, "sections").iter().any(|s| s.as_str().is_none())
        {
            return Err(Error::InvalidResponse);
        }
        let sections =
            std::array::from_fn(|i| array(&j, "sections")[i].as_str().unwrap_or("").to_owned());
        let usage = j.get("usage").and_then(|u| {
            Some(Usage {
                input: u64::try_from(u.get("input_tokens")?.as_int()?).ok()?,
                output: u64::try_from(u.get("output_tokens")?.as_int()?).ok()?,
                total: u64::try_from(u.get("total_tokens")?.as_int()?).ok()?,
            })
        });
        return Ok(Analysis {
            archive_sha256: j
                .get("archive_sha256")
                .and_then(Json::as_str)
                .filter(|h| valid_sha256(h))
                .map(str::to_owned),
            facts: j
                .get("facts")
                .map(crate::report_facts::Facts::from_json)
                .unwrap_or_default(),
            sections,
            raw_partial: j
                .get("raw_partial")
                .and_then(Json::as_str)
                .map(str::to_string),
            model: string(&j, "model").into(),
            requested_model: string(&j, "requested_model").into(),
            usage,
            incomplete: j.get("incomplete") != Some(&Json::Bool(false)),
            created_at: string(&j, "created_at").into(),
        });
    }
    // Legacy 1.10 conclusion: retain readable sections; unavailable facts stay unavailable.
    if !text.starts_with("EXPC WinDiag — AI-разбор отчёта") {
        return Err(Error::InvalidResponse);
    }
    let sections = std::array::from_fn(|i| {
        text.split_once(TITLES[i])
            .map(|(_, tail)| {
                if i < 4 {
                    tail.split(TITLES[i + 1]).next().unwrap_or(tail)
                } else {
                    tail
                }
            })
            .unwrap_or("")
            .trim()
            .to_owned()
    });
    Ok(Analysis {
        archive_sha256: None,
        facts: Default::default(),
        sections,
        raw_partial: None,
        model: "Не указана в структурированных данных старого заключения".into(),
        requested_model: String::new(),
        usage: None,
        incomplete: true,
        created_at: String::new(),
    })
}

#[cfg(test)]
mod v111_saved_result_tests {
    use super::*;
    #[test]
    fn save_reopen_and_png_preserve_facts_usage_and_source_without_transport() {
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target/v111-roundtrip")
            .join(format!(
                "{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
        std::fs::create_dir_all(&dir).unwrap();
        let source = dir.join("Тестовый отчёт.txt");
        std::fs::write(&source, "source remains unchanged").unwrap();
        let analysis = Analysis {
            archive_sha256: None,
            facts: crate::report_facts::Facts {
                computer: "TEST-PC".into(),
                cpu: "Test CPU".into(),
                machine_key: "opaque-machine".into(),
                counters: vec![crate::report_facts::Counter {
                    identity: "opaque-disk".into(),
                    device: "Test NVMe".into(),
                    metric: "errors".into(),
                    value: 9.,
                    unit: "count".into(),
                    date: "2026-11-19".into(),
                }],
                readings: vec![crate::report_facts::Reading {
                    identity: "opaque-GPU".into(),
                    device: "Test GPU".into(),
                    metric: "power".into(),
                    value: 0.025,
                    unit: "W".into(),
                    when: "2026-11-19 10:00:00".into(),
                    source: "Sensors.json".into(),
                }],
                ..Default::default()
            },
            sections: std::array::from_fn(|i| format!("Section {i}")),
            model: "mock-only".into(),
            requested_model: "mock-only".into(),
            usage: Some(Usage {
                input: 123,
                output: 45,
                total: 168,
            }),
            incomplete: false,
            created_at: "2026-11-19".into(),
            raw_partial: None,
        };
        let path = save(&analysis, &source).unwrap();
        let loaded = load(&path).unwrap();
        assert_eq!(loaded.sections, analysis.sections);
        assert_eq!(loaded.usage.unwrap().total, 168);
        assert_eq!(
            loaded.facts.to_json().render(),
            analysis.facts.to_json().render()
        );
        let p =
            crate::poster::create(&loaded.facts, Some(&loaded.sections[4]), &path, false).unwrap();
        assert!(p.path.is_file());
        assert_eq!(
            std::fs::read_to_string(&source).unwrap(),
            "source remains unchanged"
        );
        let bad = dir.join("corrupt.txt");
        std::fs::write(
            &bad,
            "========== WINDIAG_ANALYSIS_DATA_V1 ==========\n{invalid}",
        )
        .unwrap();
        assert!(load(&bad).is_err());
        let huge = dir.join("too-large.txt");
        std::fs::File::create(&huge)
            .unwrap()
            .set_len(3 * 1024 * 1024 + 1)
            .unwrap();
        assert!(load(&huge).is_err());
    }
}
