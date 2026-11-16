//! Official, dynamic discovery. A candidate is never trusted until its exact
//! product identity is verified. No firmware is downloaded by these providers.
use crate::bios::{self, Catalog, Channel, Identity, Profile, Release, Vendor, array, norm, s};
use crate::bios_net::Page;
use crate::deep_checks::json::{self, Value};
use regex::Regex;
pub const GIGABYTE_INDEX: &str = "https://www.gigabyte.com/iisApplicationNuxt/api/proxy/api/v1.0/Support/global/DownloadCenter/2/GetProducts";
pub fn encode(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}
fn parse(body: &str) -> Result<Value, String> {
    if body.len() > crate::bios_net::MAX_RESPONSE {
        return Err("Каталог BIOS превышает предел размера".into());
    }
    json::parse(body.trim_start_matches('\u{feff}'))
        .ok_or_else(|| "Сайт вернул защитную страницу или некорректный каталог BIOS".into())
}
pub fn html_text(s: &str) -> String {
    let s = Regex::new(r"(?s)<[^>]*>")
        .unwrap()
        .replace_all(s, " ")
        .replace("&nbsp;", " ")
        .replace("&amp;", "&")
        .replace("&quot;", "\"")
        .replace("&gt;", ">")
        .replace("&lt;", "<");
    let s = Regex::new(r"&#(x[0-9a-fA-F]+|[0-9]+);")
        .unwrap()
        .replace_all(&s, |c: &regex::Captures<'_>| {
            let n = if let Some(h) = c[1].strip_prefix('x') {
                u32::from_str_radix(h, 16)
            } else {
                c[1].parse()
            };
            n.ok()
                .and_then(char::from_u32)
                .filter(|c| !c.is_control())
                .unwrap_or(' ')
                .to_string()
        });
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn official_download(url: &str, host: &str) -> bool {
    url.starts_with(&format!("https://{host}/"))
        && !url.contains('\\')
        && !url.chars().any(|c| c.is_control() || c.is_whitespace())
}
fn finalize(p: &Profile, source: &str, releases: Vec<Release>) -> Result<Catalog, String> {
    if releases.is_empty() || releases.len() > 512 {
        return Err("Каталог BIOS пуст или имеет неожиданный размер".into());
    }
    let mut seen = std::collections::BTreeSet::new();
    for r in &releases {
        if !seen.insert(&r.version) || bios::date_display(&r.date).is_none() {
            return Err("Каталог BIOS содержит повторные версии или некорректные даты".into());
        }
    }
    Ok(Catalog {
        profile: p.clone(),
        source: source.into(),
        releases,
        proofs: vec![format!(
            "Официальный каталог: {source}; точная модель: {}; ревизия: {}",
            p.model, p.revision
        )],
        retrieved_at: bios::timestamp(),
    })
}
pub fn msi(p: &Profile, source: &str, body: &str) -> Result<Catalog, String> {
    let v = parse(body)?;
    if !matches!(v.get("status").and_then(|s|s.get("code")),Some(Value::Num(n)) if *n==200.0) {
        return Err("MSI: сервер не подтвердил успешное получение каталога".into());
    }
    let result = v.get("result").ok_or("MSI: отсутствует каталог BIOS")?;
    if norm(s(result, "title")) != p.model || s(result, "category") != "mb" {
        return Err(
            "MODEL_AMBIGUOUS: MSI — точная модель/тип продукта в ответе не совпадают с платой"
                .into(),
        );
    }
    let mut p = p.clone();
    let mut releases = Vec::new();
    let pattern = Regex::new(r"^([0-9A-Z]{4})v([0-9A-Z]{2,4})$").unwrap();
    for file in array(result.get("downloads").and_then(|d| d.get("AMI BIOS"))) {
        let raw = s(file, "download_version");
        let version = raw
            .split(|c: char| c.is_whitespace() || c == '(')
            .next()
            .unwrap_or("");
        let c = pattern
            .captures(version)
            .ok_or("MSI: неизвестный формат выпуска BIOS")?;
        if p.family.is_empty() {
            p.family = c[1].into();
        }
        if p.family != c[1] {
            return Err("MODEL_AMBIGUOUS: MSI — код платы противоречит каталогу".into());
        }
        let tail = &c[2];
        // New four-character releases publish xAy0 while the stable archive is xAy.zip.
        // Both observed schemes are accepted only with matching official metadata.
        let package_version = if tail.len() == 4 && tail.ends_with('0') {
            &version[..version.len() - 1]
        } else {
            version
        };
        let expected = format!("https://download.msi.com/bos_exe/mb/{package_version}.zip");
        if s(file, "download_file") != format!("mb/{package_version}.zip")
            || s(file, "download_url") != expected
        {
            return Err("MSI: имя и официальный адрес пакета не согласованы с версией".into());
        }
        let channel = if raw.to_lowercase().contains("beta") {
            Channel::Beta
        } else if tail.len() == 2 || (tail.len() == 4 && tail.ends_with('0')) {
            Channel::Stable
        } else {
            Channel::Unconfirmed
        };
        let description = html_text(s(file, "download_description"));
        releases.push(Release {
            version: version.into(),
            raw_version: raw.into(),
            date: s(file, "download_release").into(),
            channel,
            branch: bios::rank(&p, version).map_or(String::new(), |r| r.0),
            description: description.clone(),
            notes_raw: s(file, "download_description").into(),
            prerequisites: description,
            package: expected,
        });
    }
    let mut cat = finalize(&p, source, releases)?;
    cat.proofs.push(format!(
        "MSI result.title={} category=mb; код семейства={} согласован со всеми пакетами",
        s(result, "title"),
        p.family
    ));
    Ok(cat)
}
pub fn asus(p: &Profile, source: &str, body: &str) -> Result<Catalog, String> {
    let v = parse(body)?;
    let result = v.get("Result").ok_or("ASUS: отсутствует каталог BIOS")?;
    if s(&v, "Status") != "SUCCESS" || norm(s(result, "Model")) != p.model {
        return Err("MODEL_AMBIGUOUS: ASUS — модель каталога не совпадает с платой".into());
    }
    let mut releases = Vec::new();
    let version_rx = Regex::new(r"^\d{4}$").unwrap();
    for group in array(result.get("Obj"))
        .iter()
        .filter(|g| s(g, "Name") == "BIOS")
    {
        for f in array(group.get("Files")) {
            let version = s(f, "Version");
            let expected = format!("{}-ASUS-{version}.zip", p.model.replace(' ', "-"));
            let path = f.get("DownloadUrl").map(|x| s(x, "Global")).unwrap_or("");
            if !version_rx.is_match(version)
                || !path.to_ascii_lowercase().starts_with("/pub/asus/mb/")
                || path.contains("..")
                || !path
                    .rsplit('/')
                    .next()
                    .is_some_and(|name| name.eq_ignore_ascii_case(&expected))
            {
                return Err("ASUS: неизвестный формат версии или пакет другой модели".into());
            }
            let title = format!("{} {}", s(f, "Title"), s(f, "Description")).to_lowercase();
            let channel = if title.contains("beta") {
                Channel::Beta
            } else if s(f, "IsRelease") == "1" {
                Channel::Stable
            } else {
                Channel::Unconfirmed
            };
            let description = html_text(s(f, "Description"));
            releases.push(Release {
                version: version.into(),
                raw_version: version.into(),
                branch: "main".into(),
                date: s(f, "ReleaseDate").into(),
                channel,
                description: description.clone(),
                notes_raw: s(f, "Description").into(),
                prerequisites: format!(
                    "{description}; Reboot={}; AC power={}",
                    s(f, "Reboot"),
                    s(f, "Ac_power")
                ),
                package: format!("https://dlcdnets.asus.com{path}"),
            });
        }
    }
    finalize(p, source, releases)
}
fn revision_matches(revision: &str, allowed: &str) -> bool {
    let allowed = allowed.to_uppercase().replace(' ', "");
    allowed.split('/').any(|v| {
        v == revision
            || (v.ends_with(".X")
                && revision.starts_with(&v[..v.len() - 1])
                && revision[v.len() - 1..].bytes().all(|b| b.is_ascii_digit()))
    })
}
/// The product index binds a public numeric product ID to exact name + revision.
pub fn gigabyte_candidates(p: &Profile, body: &str) -> Result<Vec<Profile>, String> {
    let v = parse(body)?;
    let mut matches = Vec::new();
    if !matches!(v.get("status"),Some(Value::Num(n)) if *n==0.0) {
        return Err("Gigabyte: индекс продуктов недоступен".into());
    }
    let rx = Regex::new(r"(?i)^(.+?)\s*\(rev\.\s*([^)]+)\)$").unwrap();
    for item in array(v.get("data")) {
        let name = norm(s(item, "productName"));
        let Some(c) = rx.captures(&name) else {
            continue;
        };
        if norm(&c[1]) != p.model || !revision_matches(&p.revision, &c[2]) {
            continue;
        }
        let Some(Value::Num(id)) = item.get("productId") else {
            continue;
        };
        if *id <= 0.0 || id.fract() != 0.0 {
            continue;
        }
        let mut matched = p.clone();
        matched.family = id.to_string();
        matched.support = format!(
            "https://www.gigabyte.com/products/product-page.aspx?pid={}",
            matched.family
        );
        matches.push(matched);
    }
    Ok(matches)
}
pub fn gigabyte(p: &Profile, source: &str, body: &str) -> Result<Catalog, String> {
    let v = parse(body)?;
    if !matches!(v.get("status"),Some(Value::Num(n)) if *n==0.0) {
        return Err("Gigabyte: сервер не подтвердил каталог".into());
    }
    let mut releases = Vec::new();
    let version_rx = Regex::new(r"^F\d{1,3}[a-z]?$").unwrap();
    for group in array(v.get("data"))
        .iter()
        .filter(|g| s(g, "key") == "download")
    {
        for category in array(group.get("child"))
            .iter()
            .filter(|c| s(c, "key") == "bios")
        {
            for f in array(category.get("data")) {
                let version = s(f, "fileVersion");
                let name = s(f, "fileName");
                let path = s(f, "filePath");
                if !version_rx.is_match(version)
                    || !name.starts_with("mb_bios_")
                    || !(name.ends_with(&format!("_{}", version.to_ascii_lowercase()))
                        || name.ends_with(&format!("_{}_n", version.to_ascii_lowercase())))
                    || !official_download(path, "download.gigabyte.com")
                    || path.split('?').next()
                        != Some(
                            format!("https://download.gigabyte.com/FileList/BIOS/{name}.zip")
                                .as_str(),
                        )
                {
                    return Err(
                        "Gigabyte: неизвестная ветка BIOS или несогласованные метаданные пакета"
                            .into(),
                    );
                }
                let channel = if s(f, "fileTitle").to_lowercase().contains("beta") {
                    Channel::Beta
                } else if version.ends_with(|c: char| c.is_ascii_digit()) {
                    Channel::Stable
                } else {
                    Channel::Unconfirmed
                };
                let description = html_text(s(f, "fileDescription"));
                releases.push(Release {
                    version: version.into(),
                    raw_version: version.into(),
                    branch: "F".into(),
                    date: s(f, "fileReleaseDate").into(),
                    channel,
                    description: description.clone(),
                    notes_raw: s(f, "fileDescription").into(),
                    prerequisites: description,
                    package: path.into(),
                });
            }
        }
    }
    finalize(p, source, releases)
}
fn title(body: &str) -> Option<String> {
    Regex::new(r"(?is)<title[^>]*>(.*?)</title>")
        .unwrap()
        .captures(body)
        .map(|c| html_text(&c[1]))
}
fn links(body: &str) -> Vec<(String, String)> {
    Regex::new(r#"(?is)<a\b[^>]*href\s*=\s*["']([^"']+)["'][^>]*>(.*?)</a>"#)
        .unwrap()
        .captures_iter(body)
        .map(|c| (c[1].replace("&amp;", "&"), html_text(&c[2])))
        .collect()
}
fn absolute(base: &str, link: &str) -> Option<String> {
    if link.chars().any(char::is_control) || link.contains('\\') {
        return None;
    }
    let url = if link.starts_with("https://") {
        link.into()
    } else if link.starts_with("//") {
        format!("https:{link}")
    } else if !link.contains(':') {
        let h = crate::bios_net::official_host(base)?;
        let path = if link.starts_with('/') {
            link.to_owned()
        } else {
            format!(
                "{}/{}",
                base.strip_prefix(&format!("https://{h}"))?
                    .rsplit_once('/')?
                    .0,
                link
            )
        };
        let mut segments = Vec::new();
        for part in path.split('/') {
            match part {
                "" | "." => {}
                ".." => {
                    segments.pop()?;
                }
                _ => segments.push(part),
            }
        }
        format!("https://{h}/{}", segments.join("/"))
    } else {
        return None;
    };
    let url = url.replace(' ', "%20");
    crate::bios_net::official_host(&url)?;
    Some(url)
}

fn challenge(body: &str) -> bool {
    body.contains("_Incapsula_Resource")
        || body.contains("Request unsuccessful. Incapsula")
        || (body.len() < 4096 && body.contains("Access Denied"))
}
#[derive(Clone, Debug)]
pub struct Candidate {
    pub profile: Profile,
    pub discovery: String,
}
/// Vendor routes below were verified against official public pages/API responses.
/// A deterministic URL is only a candidate, not proof of an exact model.
pub fn find_support_candidates(
    p: &Profile,
    fetch: &mut impl FnMut(&str) -> Result<Page, String>,
) -> Result<Vec<Candidate>, String> {
    let mut p = p.clone();
    match p.vendor {
        Vendor::Msi => {
            let slug = encode(&p.model.replace(' ', "-"));
            p.support = format!("https://www.msi.com/Motherboard/{slug}/support#bios");
            Ok(vec![Candidate {
                profile: p,
                discovery: format!(
                    "https://www.msi.com/api/v1/product/support/panel?product={slug}&type=bios"
                ),
            }])
        }
        Vendor::Asus => {
            p.support = format!(
                "https://www.asus.com/us/supportonly/{}/helpdesk_bios/",
                encode(&p.model.to_lowercase())
            );
            Ok(vec![Candidate {
                discovery: p.support.clone(),
                profile: p,
            }])
        }
        Vendor::Gigabyte => {
            let page = fetch(GIGABYTE_INDEX)?;
            validate_page(GIGABYTE_INDEX, &page)?;
            Ok(gigabyte_candidates(&p, &page.body)?
                .into_iter()
                .map(|profile| Candidate {
                    profile,
                    discovery: GIGABYTE_INDEX.into(),
                })
                .collect())
        }
        Vendor::Asrock => {
            let url = format!(
                "https://www.asrock.com/support/index.us.asp?Model={}",
                encode(&p.model)
            );
            let page = fetch(&url)?;
            validate_page(&url, &page)?;
            let mut found = Vec::new();
            for (link, name) in links(&page.body) {
                if norm(&name) != p.model {
                    continue;
                }
                if let Some(link) = absolute(&page.url, &link) {
                    if !link.contains("/mb/") {
                        continue;
                    }
                    let mut profile = p.clone();
                    profile.support = link;
                    if !found
                        .iter()
                        .any(|c: &Candidate| c.profile.support == profile.support)
                    {
                        found.push(Candidate {
                            profile,
                            discovery: url.clone(),
                        });
                    }
                }
            }
            Ok(found)
        }
    }
}
#[derive(Clone, Debug)]
pub struct VerifiedSupport {
    pub profile: Profile,
    pub proofs: Vec<String>,
    pub inline_catalog: Option<(String, String)>,
}
pub fn validate_page(request: &str, page: &Page) -> Result<(), String> {
    if !crate::bios_net::same_provider(request, &page.url) {
        return Err("Неофициальное перенаправление BIOS отклонено".into());
    }
    if page.body.len() > crate::bios_net::MAX_RESPONSE {
        return Err("Ответ BIOS превышает 4 МиБ".into());
    }
    if challenge(&page.body) {
        return Err(
            "Сайт ограничил автоматический доступ (защитная страница); обход не выполняется".into(),
        );
    }
    Ok(())
}
pub fn verify_support_match(
    c: Candidate,
    fetch: &mut impl FnMut(&str) -> Result<Page, String>,
) -> Result<VerifiedSupport, String> {
    let mut p = c.profile;
    let url = if p.vendor == Vendor::Msi {
        c.discovery.clone()
    } else {
        p.support.clone()
    };
    let page = fetch(&url)?;
    validate_page(&url, &page)?;
    if p.vendor == Vendor::Msi {
        let catalog = msi(&p, &page.url, &page.body)?;
        p.family = catalog.profile.family;
        return Ok(VerifiedSupport {
            profile: p,
            proofs: catalog.proofs,
            inline_catalog: Some((page.url, page.body)),
        });
    }
    let title = title(&page.body)
        .ok_or("Официальная страница не содержит подтверждаемое название модели")?;
    let normalized = norm(&title);
    let matched = match p.vendor {
        Vendor::Asus => normalized == format!("{} - SUPPORT", p.model),
        Vendor::Gigabyte => {
            let rx =
                Regex::new(r"(?i)^(.+?)\s*\(rev\.\s*([^)]+)\)\s+Motherboard\s*-\s*GIGABYTE.*$")
                    .unwrap();
            rx.captures(&title)
                .is_some_and(|c| norm(&c[1]) == p.model && revision_matches(&p.revision, &c[2]))
                && page.url.contains("/Motherboard/")
        }
        Vendor::Asrock => {
            normalized == format!("ASROCK > {}", p.model)
                || normalized == format!("ASROCK | {}", p.model)
                || normalized == format!("ASROCK {}", p.model)
        }
        Vendor::Msi => false,
    };
    if !matched {
        return Err(format!(
            "MODEL_AMBIGUOUS: название/ревизия официальной страницы не совпадают с точной моделью {}",
            p.model
        ));
    }
    p.support = page.url.clone();
    let mut inline_catalog = None;
    if p.vendor == Vendor::Asrock {
        // The product page supplies its catalogue address. Do not guess a slug or
        // synthesize an endpoint when its markup changes.
        if page.body.contains("download.asrock.com") {
            inline_catalog = Some((page.url.clone(), page.body.clone()));
        } else {
            let rx = Regex::new(r#"(?i)["']([^"']*bios\.(?:html|asp)(?:\?[^"']*)?)["']"#).unwrap();
            let mut urls = rx
                .captures_iter(&page.body)
                .filter_map(|x| absolute(&page.url, &x[1]))
                .collect::<Vec<_>>();
            urls.sort();
            urls.dedup();
            if urls.len() != 1 {
                return Err("ASRock: точный адрес каталога BIOS не найден в официальной странице; структура сайта не подтверждена".into());
            }
            let data = fetch(&urls[0])?;
            validate_page(&urls[0], &data)?;
            inline_catalog = Some((data.url, data.body));
        }
    }
    Ok(VerifiedSupport {
        profile: p,
        proofs: vec![format!(
            "Поиск: {}; заголовок: {}; фактическая страница: {}",
            c.discovery, title, page.url
        )],
        inline_catalog,
    })
}
pub fn asrock(p: &Profile, source: &str, body: &str) -> Result<Catalog, String> {
    let mut releases = Vec::new();
    let rows = Regex::new(r"(?is)<tr\b[^>]*>(.*?)</tr>").unwrap();
    let cells = Regex::new(r"(?is)<td\b[^>]*>(.*?)</td>").unwrap();
    let vrx = Regex::new(r"^(?:P)?(L?\d{1,2}\.\d{2})(?:\s*\(?[Bb]eta\)?)?$").unwrap();
    let drx = Regex::new(r"^(\d{4})/(\d{1,2})/(\d{1,2})$").unwrap();
    for row in rows.captures_iter(body) {
        let values = cells
            .captures_iter(&row[1])
            .map(|c| html_text(&c[1]))
            .collect::<Vec<_>>();
        let Some((raw, c)) = values.iter().find_map(|v| vrx.captures(v).map(|c| (v, c))) else {
            if links(&row[1])
                .iter()
                .any(|(url, _)| official_download(url, "download.asrock.com"))
            {
                return Err("ASRock: строка пакета содержит неизвестный формат версии; полнота каталога не подтверждена".into());
            }
            continue;
        };
        let version = c[1].to_string();
        let date = values
            .iter()
            .find_map(|v| drx.captures(v))
            .ok_or("ASRock: дата выпуска отсутствует")?;
        let date = format!(
            "{}-{:02}-{:02}",
            &date[1],
            date[2].parse::<u32>().map_err(|_| "ASRock: дата")?,
            date[3].parse::<u32>().map_err(|_| "ASRock: дата")?
        );
        let package = links(&row[1])
            .into_iter()
            .map(|x| x.0)
            .find(|u| official_download(u, "download.asrock.com"))
            .ok_or("ASRock: официальный пакет не подтверждён")?;
        let description = html_text(&row[1]);
        let channel = if description.to_lowercase().contains("beta") || version.starts_with('L') {
            Channel::Beta
        } else {
            Channel::Stable
        };
        releases.push(Release {
            version,
            raw_version: raw.clone(),
            branch: "main".into(),
            date,
            channel,
            description: description.clone(),
            notes_raw: row[1].into(),
            prerequisites: description,
            package,
        });
    }
    finalize(p, source, releases)
}
pub fn fetch_bios_catalog(
    v: VerifiedSupport,
    fetch: &mut impl FnMut(&str) -> Result<Page, String>,
) -> Result<Catalog, String> {
    let p = v.profile;
    let (url, body) = if let Some(data) = v.inline_catalog {
        data
    } else {
        let url = match p.vendor {
            Vendor::Asus => format!(
                "https://www.asus.com/support/webapi/ProductV2/GetPDBIOS?website=us&model={}&pdhashedid=&pdid=99999&cpu=&siteID=www&sitelang=",
                encode(&p.model)
            ),
            Vendor::Gigabyte => format!(
                "https://www.gigabyte.com/iisApplicationNuxt/api/proxy/api/v1.0/Consumer/global/GetProductTabDataAsync/Support/{}",
                p.family
            ),
            _ => return Err("Официальный каталог не найден".into()),
        };
        let page = fetch(&url)?;
        validate_page(&url, &page)?;
        (page.url, page.body)
    };
    let mut cat = match p.vendor {
        Vendor::Msi => msi(&p, &url, &body),
        Vendor::Asus => asus(&p, &url, &body),
        Vendor::Gigabyte => gigabyte(&p, &url, &body),
        Vendor::Asrock => asrock(&p, &url, &body),
    }?;
    cat.proofs.extend(v.proofs);
    Ok(cat)
}
pub fn check_pages(
    id: &Identity,
    mut fetch: impl FnMut(&str) -> Result<Page, String>,
) -> Result<bios::Check, String> {
    let p = bios::resolve(id)?;
    let mut candidates = find_support_candidates(&p, &mut fetch)?;
    if candidates.len() != 1 {
        return Err("MODEL_AMBIGUOUS: модель требует уточнения — не найдена единственная официальная страница точной модели и ревизии".into());
    }
    let support = verify_support_match(candidates.remove(0), &mut fetch)?;
    Ok(bios::assess(id, fetch_bios_catalog(support, &mut fetch)?))
}
#[cfg(test)]
pub fn check_with(
    id: &Identity,
    mut fetch: impl FnMut(&str) -> Result<String, String>,
) -> Result<bios::Check, String> {
    check_pages(id, |url| {
        fetch(url).map(|body| Page {
            url: url.into(),
            body,
        })
    })
}
