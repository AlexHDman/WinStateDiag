//! A1: local firmware identity and conservative, vendor-specific catalogue comparison.
//! No flashing, driver access, automatic network request or catalogue-as-local-date fallback.
use crate::deep_checks::json::{self, Value};
use regex::Regex;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Identity {
    pub system_maker: String,
    pub system_model: String,
    pub system_sku: String,
    pub board_maker: String,
    pub board_model: String,
    pub board_revision: String,
    pub vendor: String,
    pub version: String,
    pub full_id: String,
    pub date: String,
    pub mobile: bool,
}
impl Identity {
    pub fn from_passport(v: &Value) -> Self {
        Self {
            system_maker: s(v, "system_maker").into(),
            system_model: s(v, "system_model").into(),
            system_sku: s(v, "system_sku").into(),
            board_maker: s(v, "board_maker").into(),
            board_model: s(v, "board").into(),
            board_revision: s(v, "board_revision").into(),
            vendor: s(v, "bios_maker").into(),
            version: s(v, "bios").into(),
            full_id: s(v, "bios_full").into(),
            date: s(v, "bios_date").into(),
            mobile: matches!(v.get("mobile"), Some(Value::Bool(true))),
        }
    }
    pub fn display(&self, public: Option<&str>) -> String {
        let version = public.unwrap_or(self.version.trim());
        format!(
            "{} ({})",
            if version.is_empty() {
                "версия неизвестна"
            } else {
                version
            },
            date_display(&self.date).unwrap_or_else(|| "дата неизвестна".into())
        )
    }
    pub fn json(&self) -> String {
        let fields = [
            ("system_manufacturer", &self.system_maker),
            ("system_model", &self.system_model),
            ("system_sku", &self.system_sku),
            ("board_manufacturer", &self.board_maker),
            ("board_model", &self.board_model),
            ("board_revision", &self.board_revision),
            ("bios_vendor", &self.vendor),
            ("smbios_version_raw", &self.version),
            ("bios_full_id_raw", &self.full_id),
            ("installed_date_raw", &self.date),
        ];
        format!(
            "{{{},\"mobile\":{}}}",
            fields
                .iter()
                .map(|(k, v)| format!("{}:{}", json::string(k), json::string(v)))
                .collect::<Vec<_>>()
                .join(","),
            self.mobile
        )
    }
}
pub(super) fn s<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or("")
}
pub(super) fn array(v: Option<&Value>) -> &[Value] {
    if let Some(Value::Arr(a)) = v { a } else { &[] }
}
pub fn date_display(raw: &str) -> Option<String> {
    let raw = raw.trim();
    let iso = Regex::new(r"^(\d{4})[-/](\d{2})[-/](\d{2})(?:$|[T ])").unwrap();
    let dmtf = Regex::new(r"^(\d{4})(\d{2})(\d{2})\d{6}\.\d{6}[+-]\d{3}$").unwrap();
    let us = Regex::new(r"^(\d{2})/(\d{2})/(\d{4})$").unwrap();
    let (y, m, d) = if let Some(c) = iso.captures(raw).or_else(|| dmtf.captures(raw)) {
        (
            c[1].parse::<u32>().ok()?,
            c[2].parse::<u32>().ok()?,
            c[3].parse::<u32>().ok()?,
        )
    } else {
        let c = us.captures(raw)?;
        (c[3].parse().ok()?, c[1].parse().ok()?, c[2].parse().ok()?)
    };
    let days = match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) => 29,
        2 => 28,
        _ => return None,
    };
    ((1980..=2199).contains(&y) && d > 0 && d <= days).then(|| format!("{d:02}.{m:02}.{y:04}"))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Vendor {
    Msi,
    Asus,
    Gigabyte,
    Asrock,
}
#[derive(Clone, Debug)]
pub struct Profile {
    pub vendor: Vendor,
    pub model: String,
    pub revision: String,
    /// MSI board code or Gigabyte product ID, independently verified against the catalogue.
    pub family: String,
    pub support: String,
}
pub fn norm(s: &str) -> String {
    s.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_uppercase()
}
fn maker(s: &str) -> Option<Vendor> {
    match norm(s).trim_end_matches('.').trim() {
        "MSI" | "MICRO-STAR INTERNATIONAL CO., LTD" => Some(Vendor::Msi),
        "ASUS" | "ASUSTEK COMPUTER INC" => Some(Vendor::Asus),
        "GIGABYTE" | "GIGABYTE TECHNOLOGY CO., LTD" => Some(Vendor::Gigabyte),
        "ASROCK" | "ASROCK INC" => Some(Vendor::Asrock),
        _ => None,
    }
}
fn generic(s: &str) -> bool {
    matches!(
        norm(s).as_str(),
        "" | "SYSTEM PRODUCT NAME"
            | "SYSTEM MANUFACTURER"
            | "TO BE FILLED BY O.E.M."
            | "DEFAULT STRING"
    )
}
/// Identity resolution is not a firmware recommendation. The exact public product
/// and revision must subsequently be verified by the selected provider.
pub fn resolve(id: &Identity) -> Result<Profile, String> {
    if id.mobile {
        return Err(
            "UNSUPPORTED: ноутбук — нужен отдельный каталог производителя компьютера".into(),
        );
    }
    let vendor =
        maker(&id.board_maker).ok_or("UNSUPPORTED: производитель платы пока не поддерживается")?;
    if generic(&id.system_maker) {
        return Err(
            "MODEL_AMBIGUOUS: производитель компьютера не определён; OEM/retail не подтверждено"
                .into(),
        );
    }
    if maker(&id.system_maker) != Some(vendor) {
        return Err("UNSUPPORTED: OEM-компьютер — требуется поддержка производителя системы; розничная прошивка не предлагается".into());
    }
    let mut model = norm(&id.board_model);
    let mut family = String::new();
    if vendor == Vendor::Msi {
        if let Some(c) = Regex::new(r"^(.+) \(MS-([A-Z0-9]{4})\)$")
            .unwrap()
            .captures(&model)
        {
            family = c[2].into();
            model = c[1].into();
        }
        if family.is_empty()
            && let Some(c) = Regex::new(r"^MS-([A-Z0-9]{4})$")
                .unwrap()
                .captures(&norm(&id.system_model))
        {
            family = c[1].into();
        }
    }
    if generic(&model)
        || model.len() > 100
        || model.starts_with("MS-")
        || !model
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || " -_+./()".contains(c))
    {
        return Err("MODEL_AMBIGUOUS: точная модель платы не определена".into());
    }
    if !generic(&id.system_model)
        && norm(&id.system_model) != model
        && norm(&id.system_model) != norm(&id.board_model)
        && !(vendor == Vendor::Msi && norm(&id.system_model) == format!("MS-{family}"))
    {
        return Err(
            "UNSUPPORTED: модель системы отличается от розничной платы; требуется OEM-каталог"
                .into(),
        );
    }
    let revision = norm(&id.board_revision)
        .trim_start_matches("REV.")
        .trim()
        .to_owned();
    if vendor == Vendor::Gigabyte && !Regex::new(r"^\d+\.\d+$").unwrap().is_match(&revision) {
        return Err("MODEL_AMBIGUOUS: Gigabyte — нужна точная аппаратная ревизия платы".into());
    }
    Ok(Profile {
        vendor,
        model,
        revision,
        family,
        support: String::new(),
    })
}
/// Offline aliases proven by package/readme inspection, NOT a device whitelist.
pub fn confirmed_public(id: &Identity) -> Option<String> {
    let p = resolve(id).ok()?;
    let public = match (p.model.as_str(), p.family.as_str(), id.version.trim()) {
        ("PRO H610M-G DDR4", "7D46", "1.R0") => "7D46v1R",
        ("PRO B760M-A DDR4", "7D99", "1.J0") => "7D99v1J",
        ("MAG Z790 TOMAHAWK WIFI", "7D91", "17.I0") => "7D91vHI",
        _ => return None,
    };
    let internal = msi_internal(&p, public)?;
    full_id_agrees(id, &p.family, &internal).then(|| public.into())
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Channel {
    Stable,
    Beta,
    #[default]
    Unconfirmed,
}
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Release {
    pub version: String,
    pub raw_version: String,
    pub branch: String,
    pub date: String,
    pub channel: Channel,
    pub description: String,
    pub notes_raw: String,
    pub prerequisites: String,
    pub package: String,
}
#[derive(Clone, Debug)]
pub struct Catalog {
    pub profile: Profile,
    pub releases: Vec<Release>,
    pub source: String,
    pub proofs: Vec<String>,
    pub retrieved_at: String,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Current,
    Available,
    Uncertain,
}
#[derive(Clone, Debug)]
pub struct Check {
    pub verdict: Verdict,
    pub installed_public: Option<String>,
    pub latest: Option<Release>,
    pub preview: Option<Release>,
    pub reason: String,
    pub source: String,
    pub support: String,
    pub checked_at: String,
    pub catalog: Catalog,
}
pub fn timestamp() -> String {
    let t = crate::ui::sysinfo::local_time();
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        t.year, t.month, t.day, t.hour, t.minute, t.second
    )
}
/// MSI has two observed publication schemes. Never strip a zero blindly:
/// old 1R => internal 1R0; new 1AE0 retains the final revision digit.
fn msi_internal(p: &Profile, public: &str) -> Option<String> {
    let tail = public.strip_prefix(&format!("{}v", p.family))?;
    if !Regex::new(r"^[0-9A-Z]{2,4}$").unwrap().is_match(tail) {
        return None;
    }
    Some(if tail.len() == 2 {
        format!("{tail}0")
    } else {
        tail.into()
    })
}
fn full_id_agrees(id: &Identity, family: &str, internal: &str) -> bool {
    Regex::new(r"E[0-9A-Z]{4}[A-Z]{3}\.[0-9A-Z]{3,4}")
        .unwrap()
        .find_iter(&id.full_id)
        .all(|m| {
            m.as_str().starts_with(&format!("E{family}"))
                && m.as_str().split('.').nth(1) == Some(internal)
        })
}
pub fn normalize_installed(id: &Identity, cat: &Catalog) -> Option<String> {
    let p = &cat.profile;
    if p.vendor != Vendor::Msi {
        let raw = id.version.trim();
        let raw = if p.vendor == Vendor::Asrock {
            raw.strip_prefix('P').unwrap_or(raw)
        } else {
            raw
        };
        return cat
            .releases
            .iter()
            .find(|r| r.version == raw)
            .map(|r| r.version.clone());
    }
    let mut matches = Vec::new();
    let raw_full = Regex::new(r"^E([A-Z0-9]{4})[A-Z]{3}\.([A-Z0-9]{3,4})$")
        .unwrap()
        .captures(id.version.trim());
    for r in &cat.releases {
        let Some(internal) = msi_internal(p, &r.version) else {
            continue;
        };
        if !full_id_agrees(id, &p.family, &internal) {
            continue;
        }
        let raw = id.version.trim();
        let dotted = format!("{}.{}", &internal[..1], &internal[1..]);
        let known_h = p.model == "MAG Z790 TOMAHAWK WIFI"
            && p.family == "7D91"
            && internal.starts_with('H')
            && raw == format!("17.{}", &internal[1..]);
        if raw == r.version
            || raw == dotted
            || known_h
            || raw_full
                .as_ref()
                .is_some_and(|c| c[1] == p.family && c[2] == internal)
        {
            matches.push(r.version.clone());
        }
    }
    (matches.len() == 1).then(|| matches[0].clone())
}
/// Numeric vendor rules. MSI branch is independent of rank; a different branch
/// can never become an update solely because its alphanumeric code is greater.
pub fn rank(p: &Profile, v: &str) -> Option<(String, u32, u32)> {
    match p.vendor {
        Vendor::Msi => {
            let tail = v.strip_prefix(&format!("{}v", p.family))?;
            if !Regex::new(r"^[0-9A-Z]{2,4}$").unwrap().is_match(tail) {
                return None;
            }
            let (branch, main, sub) = if tail.len() == 4 {
                (&tail[..2], &tail[2..3], &tail[3..])
            } else {
                (&tail[..1], &tail[1..2], &tail[2..])
            };
            let sub = if sub.is_empty() || sub == "0" {
                100
            } else {
                sub.parse().ok()?
            };
            Some((branch.into(), u32::from_str_radix(main, 36).ok()?, sub))
        }
        Vendor::Asus => Regex::new(r"^\d{4}$")
            .unwrap()
            .is_match(v)
            .then(|| Some(("main".into(), v.parse().ok()?, 100)))?,
        Vendor::Gigabyte => {
            let c = Regex::new(r"^F(\d{1,3})([a-z]?)$").unwrap().captures(v)?;
            Some((
                "F".into(),
                c[1].parse().ok()?,
                c[2].bytes().next().map_or(100, |b| u32::from(b - b'a' + 1)),
            ))
        }
        Vendor::Asrock => {
            let c = Regex::new(r"^(L?)(\d{1,2})\.(\d{2})$")
                .unwrap()
                .captures(v)?;
            Some((
                "main".into(),
                c[2].parse::<u32>().ok()? * 100 + c[3].parse::<u32>().ok()?,
                if &c[1] == "L" { 0 } else { 100 },
            ))
        }
    }
}
pub fn assess(id: &Identity, catalog: Catalog) -> Check {
    let installed = normalize_installed(id, &catalog);
    let p = &catalog.profile;
    let installed_rank = installed.as_deref().and_then(|v| rank(p, v));
    let compatible = |r: &&Release| {
        installed_rank
            .as_ref()
            .is_none_or(|a| rank(p, &r.version).is_some_and(|b| a.0 == b.0))
    };
    let latest = catalog
        .releases
        .iter()
        .filter(compatible)
        .filter(|r| r.channel == Channel::Stable)
        .max_by_key(|r| rank(p, &r.version))
        .cloned();
    let preview = catalog
        .releases
        .iter()
        .filter(compatible)
        .filter(|r| {
            r.channel != Channel::Stable
                && latest
                    .as_ref()
                    .is_none_or(|l| rank(p, &r.version) > rank(p, &l.version))
        })
        .max_by_key(|r| rank(p, &r.version))
        .cloned();
    let mut check = Check {
        verdict: Verdict::Uncertain,
        installed_public: installed.clone(),
        latest: latest.clone(),
        preview,
        reason: String::new(),
        source: catalog.source.clone(),
        support: p.support.clone(),
        checked_at: catalog.retrieved_at.clone(),
        catalog,
    };
    let Some(current) = installed else {
        check.reason="Установленная версия отсутствует в каталоге или ветка не подтверждена. Она может быть новее каталога; откат не предлагается".into();
        return check;
    };
    let Some(latest) = latest else {
        check.reason = "В совместимой ветке не подтверждена стабильная версия".into();
        return check;
    };
    let p = &check.catalog.profile;
    let (Some(a), Some(b)) = (rank(p, &current), rank(p, &latest.version)) else {
        check.reason = "Правило сравнения этой версии не подтверждено".into();
        return check;
    };
    let found = check
        .catalog
        .releases
        .iter()
        .find(|r| r.version == current)
        .unwrap();
    if check
        .catalog
        .releases
        .iter()
        .any(|r| rank(p, &r.version).is_none())
    {
        check.reason =
            "Каталог содержит неизвестный формат версии; полнота сравнения не подтверждена".into();
    } else if a.0 != b.0 {
        check.reason = "Ветки прошивки различаются; обновление не предлагается".into();
    } else if a > b {
        check.reason =
            "Установленная версия новее стабильного каталога; откат не предлагается".into();
    } else if a == b && found.channel == Channel::Stable {
        check.verdict = Verdict::Current;
        check.reason =
            "Установленная версия совпадает с последней стабильной в полученном каталоге".into();
    } else if a < b && found.channel != Channel::Unconfirmed {
        check.verdict = Verdict::Available;
        check.reason="Доступна более новая совместимая стабильная версия; обновление не является обязательным".into();
    } else {
        check.reason =
            "Установлена предварительная версия; стабильный статус не подтверждён".into();
    }
    check
}
impl Check {
    pub fn code(&self) -> &'static str {
        match self.verdict {
            Verdict::Current => "CURRENT",
            Verdict::Available => "UPDATE_AVAILABLE",
            Verdict::Uncertain => "VERSION_UNCOMPARABLE",
        }
    }
    pub fn label(&self) -> String {
        match self.verdict {
            Verdict::Current => "Актуален".into(),
            Verdict::Available => format!(
                "Доступен: {}",
                self.latest.as_ref().map_or("?", |r| r.version.as_str())
            ),
            Verdict::Uncertain => self.latest.as_ref().map_or_else(
                || "Сопоставление не подтверждено".into(),
                |r| format!("На сайте: {} · сопоставление не подтверждено", r.version),
            ),
        }
    }
    pub fn details(&self) -> String {
        let release = |r: &Release| {
            format!(
                "{} · {} · {:?}\n{}\nУсловия: {}",
                r.version, r.date, r.channel, r.description, r.prerequisites
            )
        };
        format!(
            "{} [{}]\n{}\nСтабильная: {}\nПредварительная: {}\nИсточник: {}\nПоддержка: {}\nПроверено: {}\nПодтверждение: {}",
            self.label(),
            self.code(),
            self.reason,
            self.latest
                .as_ref()
                .map(release)
                .unwrap_or_else(|| "не подтверждена".into()),
            self.preview
                .as_ref()
                .map(release)
                .unwrap_or_else(|| "не найдена".into()),
            self.source,
            self.support,
            self.checked_at,
            self.catalog.proofs.join("; ")
        )
    }
    pub fn json(&self) -> String {
        let q = json::string;
        let releases=self.catalog.releases.iter().map(|r|format!("{{\"raw_version\":{},\"version\":{},\"branch\":{},\"publication_date\":{},\"channel\":{},\"package\":{},\"notes\":{},\"notes_raw\":{},\"prerequisites\":{}}}",q(&r.raw_version),q(&r.version),q(&r.branch),q(&r.date),q(match r.channel {Channel::Stable=>"stable",Channel::Beta=>"beta",Channel::Unconfirmed=>"unknown"}),q(&r.package),q(&r.description),q(&r.notes_raw),q(&r.prerequisites))).collect::<Vec<_>>().join(",");
        format!(
            "{{\"status\":{},\"beta_status\":{},\"installed_public\":{},\"reason\":{},\"source\":{},\"support\":{},\"checked_at_local\":{},\"model\":{},\"revision\":{},\"proofs\":[{}],\"releases\":[{}]}}",
            q(self.code()),
            q(
                if self
                    .preview
                    .as_ref()
                    .is_some_and(|r| r.channel == Channel::Beta)
                {
                    "BETA_AVAILABLE"
                } else {
                    "NOT_CONFIRMED"
                }
            ),
            self.installed_public
                .as_ref()
                .map_or("null".into(), |v| q(v)),
            q(&self.reason),
            q(&self.source),
            q(&self.support),
            q(&self.checked_at),
            q(&self.catalog.profile.model),
            q(&self.catalog.profile.revision),
            self.catalog
                .proofs
                .iter()
                .map(|x| q(x))
                .collect::<Vec<_>>()
                .join(","),
            releases
        )
    }
}
pub fn failure_code(e: &str) -> &'static str {
    if e.starts_with("MODEL_AMBIGUOUS:") {
        "MODEL_AMBIGUOUS"
    } else if e.starts_with("UNSUPPORTED:") {
        "UNSUPPORTED"
    } else {
        "CHECK_FAILED"
    }
}
#[cfg(test)]
#[path = "bios_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "bios_dynamic_tests.rs"]
mod dynamic_tests;
