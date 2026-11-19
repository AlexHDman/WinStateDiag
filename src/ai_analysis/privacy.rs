use super::*;
#[derive(Clone)]
pub struct Prepared {
    pub facts: crate::report_facts::Facts,
    pub text: String,
    pub digest: String,
    pub source: PathBuf,
    pub archive_sha256: Option<String>,
    pub source_bytes: usize,
    pub omitted_blocks: usize,
    pub omissions: Vec<String>,
    pub encoding: String,
}
#[derive(Clone)]
pub enum Source {
    Zip(PathBuf),
    #[cfg(test)]
    Txt(PathBuf),
    #[cfg(test)]
    Session(crate::ai_export::Input),
}
fn protect_versions(text: &str) -> (String, Vec<(String, String)>) {
    let re=regex::Regex::new(r#"(?im)(?:version|версия|build|сборка|biosversion|driver version|версия bios)["'\s:=]+(\d+(?:\.\d+){1,4})"#).unwrap();
    let mut pairs = vec![];
    let mut index = 0;
    let changed = re
        .replace_all(text, |c: &regex::Captures<'_>| {
            let value = c.get(1).unwrap();
            let token = format!("WSDVERSIONPROTECTED{:06}END", index);
            index += 1;
            pairs.push((token.clone(), value.as_str().to_owned()));
            let whole = c.get(0).unwrap().as_str();
            format!(
                "{}{}",
                &whole[..value.start() - c.get(0).unwrap().start()],
                token
            )
        })
        .into_owned();
    (changed, pairs)
}
fn personal_paths(text: &str) -> String {
    // Analysis-only: do not change the offline AI.zip exporter contract.
    // Keep Windows/system executable paths; remove complete personal/UNC paths.
    let personal = regex::Regex::new(r#"(?im)(?:[a-z]:\\+(?:Users|Documents and Settings)\\+[^\r\n"<>|]+|\\\\[^\r\n"<>|]+|/(?:home|Users)/[^\r\n"<>|]+)"#).unwrap();
    personal.replace_all(text, "[PERSONAL_PATH]").into_owned()
}
pub fn prepare(
    source: Source,
    mut seeds: Vec<String>,
    cancel: &AtomicBool,
) -> Result<Prepared, Error> {
    if cancel.load(Ordering::Acquire) {
        return Err(Error::Cancelled);
    }
    let (raw, path, omissions, encoding, archive_sha256) = match source {
        Source::Zip(path) => {
            let data = crate::ai_export::analysis_zip(&path, cancel).map_err(Error::Source)?;
            (
                data.text,
                path,
                data.omitted,
                "Кодировки материалов определены автоматически".into(),
                Some(data.sha256),
            )
        }
        #[cfg(test)]
        Source::Txt(path) => {
            let mut f = std::fs::File::open(&path)
                .map_err(|_| Error::Source("Не удалось прочитать выбранный TXT".into()))?;
            let before = f
                .metadata()
                .map_err(|_| Error::Source("Недоступны сведения о TXT".into()))?;
            if before.len() > 32 * 1024 * 1024 {
                return Err(Error::Source(
                    "TXT превышает безопасный предел чтения 32 МиБ".into(),
                ));
            }
            let mut b = vec![];
            Read::by_ref(&mut f)
                .take(32 * 1024 * 1024 + 1)
                .read_to_end(&mut b)
                .map_err(|_| Error::Source("Ошибка чтения TXT".into()))?;
            let after = f
                .metadata()
                .map_err(|_| Error::Source("Не удалось проверить источник".into()))?;
            if b.len() > 32 * 1024 * 1024
                || before.len() != after.len()
                || before.modified().ok() != after.modified().ok()
            {
                return Err(Error::Source("Файл изменился во время подготовки".into()));
            }
            let (t, enc) = crate::ai_export::analysis_decode(&b, "report.txt")
                .map_err(|_| Error::Source("Не удалось распознать кодировку TXT".into()))?;
            (t, path, vec![], enc, None)
        }
        #[cfg(test)]
        Source::Session(input) => {
            let path = input
                .zip
                .clone()
                .or(input.directory.clone())
                .ok_or(Error::Source("Нет сохранённого отчёта".into()))?;
            let (t,o)=crate::ai_export::analysis_session(&input, cancel).map_err(|_|Error::Source("Не удалось подготовить материалы сессии; проверь доступность и целостность ZIP".into()))?;
            (
                t,
                path,
                o,
                "Кодировки материалов определены автоматически".into(),
                None,
            )
        }
    };
    if raw.trim().is_empty() {
        return Err(Error::Source("Выбранный отчёт пуст".into()));
    }
    // A previously exported TXT may retain an identifying source ZIP name.
    // Learn the exact stem, without guessing separate client/host fragments.
    if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
        let base = stem
            .strip_suffix(".AI")
            .or_else(|| stem.strip_suffix(".ai"))
            .unwrap_or(stem);
        if base.len() >= 4 {
            seeds.push(base.into());
        }
    }
    let bytes = raw.len();
    let facts = crate::report_facts::Facts::parse(&raw);
    let raw = format!(
        "{}\n========== PRIMARY_MATERIALS ==========\n{}",
        facts.context(),
        raw
    );
    let (protected, versions) = protect_versions(&personal_paths(&raw));
    let mut masked = crate::ai_export::analysis_mask(&protected, &seeds).map_err(|_| {
        Error::Source("Безопасное маскирование не удалось; отправка запрещена".into())
    })?;
    for (token, value) in versions {
        masked = masked.replace(&token, &value);
    }
    if cancel.load(Ordering::Acquire) {
        return Err(Error::Cancelled);
    }
    let (text, omitted_blocks) = if let Some((context, evidence)) =
        masked.split_once("========== PRIMARY_MATERIALS ==========\n")
    {
        let (context, context_omitted) = crate::ai_export::analysis_select(context, 32 * 1024);
        let budget = MAX_INPUT.saturating_sub(context.len() + 64);
        let (evidence, omitted) = crate::ai_export::analysis_select(evidence, budget);
        (
            format!("{context}\n========== PRIMARY_MATERIALS ==========\n{evidence}"),
            omitted + context_omitted,
        )
    } else {
        crate::ai_export::analysis_select(&masked, MAX_INPUT)
    };
    if text.is_empty() || text.len() > MAX_INPUT {
        return Err(Error::Source(
            "Не удалось уложить отчёт в безопасный объём".into(),
        ));
    }
    let digest = crate::content_hash::sha256(text.as_bytes())
        .map_err(|_| Error::Source("Не удалось закрепить отправляемую копию".into()))?;
    Ok(Prepared {
        facts,
        text,
        digest,
        source: path,
        archive_sha256,
        source_bytes: bytes,
        omitted_blocks,
        omissions,
        encoding,
    })
}
