//! v1.1 Hardware Passport 2.0: one scrollable page of compact cards built
//! from the read-only hardware collector's JSON (`Hardware_*.json`).
//!
//! Every value is one of three kinds and is shown as such:
//! * CONFIG      — physical configuration reported by Windows / SMBIOS;
//! * MEASURED    — a current measurement (temperature, charge, wear …);
//! * UNCONFIRMED — Windows did not report a trustworthy value (placeholder
//!   strings such as "Default string" / "To be filled by O.E.M." included).
//!
//! Nothing is invented and there is no universal "OK": a disk shows what
//! Windows reports about it, never a verdict of this page.

use crate::deep_checks::json::{self, Value};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Config,
    Measured,
    Unconfirmed,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Row {
    pub label: String,
    pub value: String,
    pub kind: Kind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CardKind {
    Cpu,
    Ram,
    Board,
    Bios,
    Storage,
    Gpu,
    Network,
    Power,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Card {
    pub kind: CardKind,
    pub title: String,
    pub rows: Vec<Row>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Passport {
    /// «Windows 11 Pro 26300 · MSI · Micro-Star … MS-7E34».
    pub system: String,
    pub cards: Vec<Card>,
    /// Values Windows did not confirm, and collector errors.
    pub unconfirmed: Vec<String>,
    /// `YYYY-MM-DD HH:MM` of the collection.
    pub collected_at: String,
}

/// Texts the page needs (taken from the i18n dictionary by the caller).
pub struct Texts<'a> {
    pub ru: bool,
    pub d: &'a crate::i18n::Dict,
}

fn get<'a>(v: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut cur = v;
    for k in path {
        cur = cur.get(k)?;
    }
    Some(cur)
}

fn text_of(v: Option<&Value>) -> Option<String> {
    match v? {
        Value::Str(s) => Some(s.trim().to_string()),
        Value::Num(n) => Some(num_text(*n)),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn num_of(v: Option<&Value>) -> Option<f64> {
    match v? {
        Value::Num(n) => Some(*n),
        Value::Str(s) => s.trim().parse::<f64>().ok(),
        _ => None,
    }
}

fn num_text(n: f64) -> String {
    if n.fract() == 0.0 && n.abs() < 1e15 {
        format!("{}", n as i64)
    } else {
        format!("{n}")
    }
}

/// An array, a single object / scalar as a one-element list, or nothing.
fn list_of(v: Option<&Value>) -> Vec<&Value> {
    match v {
        Some(Value::Arr(a)) => a.iter().collect(),
        Some(Value::Null) | None => Vec::new(),
        Some(other) => vec![other],
    }
}

/// Placeholder / missing values Windows or a BIOS report instead of data.
pub fn is_unconfirmed(s: &str) -> bool {
    let t = s.trim().trim_matches('.').to_ascii_lowercase();
    t.is_empty()
        || [
            "unavailable",
            "unknown",
            "default string",
            "to be filled by o.e.m",
            "to be filled by oem",
            "system product name",
            "system manufacturer",
            "not applicable",
            "not reported",
            "unable to determine",
            "n/a",
            "none",
            "0",
            "-",
            "—",
        ]
        .contains(&t.as_str())
}

/// `/Date(1782259200000)/` (PowerShell 5.1 DateTime JSON) or an ISO date
/// → `YYYY-MM-DD`.
pub fn date_of(s: &str) -> Option<String> {
    let t = s.trim();
    if let Some(ms) = t
        .strip_prefix("/Date(")
        .and_then(|r| r.split([')', '+', '-']).next())
        .and_then(|n| n.parse::<i64>().ok())
    {
        let days = ms.div_euclid(86_400_000);
        return Some(civil(days));
    }
    let iso = t.get(..10)?;
    (iso.as_bytes().get(4) == Some(&b'-') && iso.as_bytes().get(7) == Some(&b'-'))
        .then(|| iso.to_string())
}

/// Days since 1970-01-01 → `YYYY-MM-DD` (proleptic Gregorian).
fn civil(days: i64) -> String {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    format!("{:04}-{:02}-{:02}", if m <= 2 { y + 1 } else { y }, m, d)
}

fn bytes_text(bytes: f64) -> String {
    let gb = bytes / 1024.0 / 1024.0 / 1024.0;
    if gb >= 1024.0 {
        format!("{:.2} TB", gb / 1024.0)
    } else {
        format!("{gb:.2} GB")
    }
}

struct Builder<'a> {
    t: &'a Texts<'a>,
    unconfirmed: Vec<String>,
}

impl Builder<'_> {
    /// A configuration value, or "не подтверждено" (recorded) when Windows
    /// did not report a trustworthy one.
    fn config(&mut self, card: &str, label: &str, value: Option<String>) -> Row {
        match value.filter(|v| !is_unconfirmed(v)) {
            Some(v) => Row {
                label: label.to_string(),
                value: v,
                kind: Kind::Config,
            },
            None => {
                self.unconfirmed.push(format!("{card}: {label}"));
                Row {
                    label: label.to_string(),
                    value: self.t.d.pp_unconfirmed.to_string(),
                    kind: Kind::Unconfirmed,
                }
            }
        }
    }
}

fn measured(label: &str, value: String) -> Row {
    Row {
        label: label.to_string(),
        value,
        kind: Kind::Measured,
    }
}

fn plain(label: &str, value: String, kind: Kind) -> Row {
    Row {
        label: label.to_string(),
        value,
        kind,
    }
}

/// RAM context notes of the collector, in the UI language.
fn ram_context(note: &str, ru: bool) -> String {
    let n = note.to_ascii_lowercase();
    if !ru {
        return note.to_string();
    }
    if n.starts_with("mixed module capacities") {
        "Модули разного объёма (контекст; не неисправность без ошибок памяти, WHEA или проваленных тестов памяти).".into()
    } else if n.starts_with("mixed declared module speeds") {
        "У модулей разная заявленная скорость (контекст).".into()
    } else if n.starts_with("configured data rate below") {
        "Настроенная скорость ниже заявленной (профиль JEDEC / XMP-EXPO — контекст, не неисправность).".into()
    } else if n.starts_with("on-board (soldered) lpddr") {
        "Память LPDDR распаяна на плате: SMBIOS перечисляет каналы/корпуса, а не съёмные модули."
            .into()
    } else {
        note.to_string()
    }
}

/// Builds the page from the collector JSON. `None` = not a hardware
/// passport document.
pub fn build(text: &str, t: &Texts<'_>) -> Option<Passport> {
    let v = json::parse(text.trim_start_matches('\u{feff}'))?;
    v.get("Cpu")?;
    let d = t.d;
    let ru = t.ru;
    let mut b = Builder {
        t,
        unconfirmed: Vec::new(),
    };
    let mut cards = Vec::new();

    // System line (top).
    let edition = text_of(get(&v, &["System", "WindowsEdition"])).unwrap_or_default();
    let build_no = text_of(get(&v, &["System", "WindowsBuild"])).unwrap_or_default();
    let host = text_of(get(&v, &["System", "Hostname"])).unwrap_or_default();
    let maker = text_of(get(&v, &["System", "Manufacturer"])).unwrap_or_default();
    let model = text_of(get(&v, &["System", "Model"])).unwrap_or_default();
    let device = [maker, model]
        .into_iter()
        .filter(|s| !is_unconfirmed(s))
        .collect::<Vec<_>>()
        .join(" ");
    let system = [
        format!("{edition} {build_no}").trim().to_string(),
        host,
        device,
    ]
    .into_iter()
    .filter(|s| !s.trim().is_empty())
    .collect::<Vec<_>>()
    .join(" · ");

    // Processor.
    let cpu_title = d.pp_cpu;
    let models: Vec<String> = list_of(get(&v, &["Cpu", "Models"]))
        .into_iter()
        .filter_map(|m| text_of(Some(m)))
        .filter(|m| !is_unconfirmed(m))
        .collect();
    let mut rows = vec![b.config(
        cpu_title,
        d.pp_model,
        (!models.is_empty()).then(|| models.join("; ")),
    )];
    let cores = num_of(get(&v, &["Cpu", "PhysicalCores"])).filter(|n| *n > 0.0);
    let threads = num_of(get(&v, &["Cpu", "LogicalProcessors"])).filter(|n| *n > 0.0);
    rows.push(b.config(
        cpu_title,
        d.pp_cores,
        match (cores, threads) {
            (Some(c), Some(t)) => Some(format!("{} / {}", num_text(c), num_text(t))),
            _ => None,
        },
    ));
    rows.push(
        b.config(
            cpu_title,
            d.pp_clock,
            num_of(get(&v, &["Cpu", "MaxClockMHz"]))
                .filter(|n| *n > 0.0)
                .map(|mhz| format!("{:.2} GHz", mhz / 1000.0)),
        ),
    );
    let l2 = num_of(get(&v, &["Cpu", "L2CacheKB"])).filter(|n| *n > 0.0);
    let l3 = num_of(get(&v, &["Cpu", "L3CacheKB"])).filter(|n| *n > 0.0);
    rows.push(b.config(
        cpu_title,
        d.pp_cache,
        match (l2, l3) {
            (Some(a), Some(c)) => Some(format!(
                "{} MB / {} MB",
                num_text(a / 1024.0),
                num_text(c / 1024.0)
            )),
            _ => None,
        },
    ));
    rows.push(b.config(
        cpu_title,
        d.pp_arch,
        text_of(get(&v, &["Cpu", "Architecture"])),
    ));
    if matches!(get(&v, &["Npu", "Detected"]), Some(Value::Bool(true))) {
        let npu: Vec<String> = list_of(get(&v, &["Npu", "Devices"]))
            .into_iter()
            .filter_map(|n| text_of(n.get("Name")))
            .collect();
        if !npu.is_empty() {
            rows.push(plain(d.pp_npu, npu.join("; "), Kind::Config));
        }
    }
    cards.push(Card {
        kind: CardKind::Cpu,
        title: cpu_title.to_string(),
        rows,
    });

    // Memory.
    let ram_title = d.pp_ram;
    let mut rows = vec![
        b.config(
            ram_title,
            d.pp_total,
            num_of(get(&v, &["Ram", "TotalBytes"]))
                .filter(|n| *n > 0.0)
                .map(bytes_text),
        ),
    ];
    let modules = list_of(get(&v, &["Ram", "Modules"]));
    let slots = num_of(get(&v, &["Ram", "DeclaredSlots"])).unwrap_or(0.0);
    let onboard = text_of(get(&v, &["Ram", "Topology"])).as_deref() == Some("ONBOARD_LPDDR");
    rows.push(b.config(
        ram_title,
        d.pp_modules,
        if modules.is_empty() {
            None
        } else if onboard {
            Some(
                d.pp_modules_onboard_fmt
                    .replace("{n}", &modules.len().to_string()),
            )
        } else if slots > 0.0 {
            Some(
                d.pp_modules_fmt
                    .replace("{n}", &modules.len().to_string())
                    .replace("{slots}", &num_text(slots)),
            )
        } else {
            Some(modules.len().to_string())
        },
    ));
    for m in &modules {
        let locator = text_of(m.get("DeviceLocator")).filter(|s| !is_unconfirmed(s));
        let parts: Vec<String> = [
            num_of(m.get("CapacityBytes"))
                .filter(|n| *n > 0.0)
                .map(bytes_text),
            text_of(m.get("Type")).filter(|s| !is_unconfirmed(s)),
            num_of(m.get("ConfiguredSpeedMTs"))
                .or_else(|| num_of(m.get("RatedSpeedMTs")))
                .filter(|n| *n > 0.0)
                .map(|n| format!("{} MT/s", num_text(n))),
            text_of(m.get("Manufacturer")).filter(|s| !is_unconfirmed(s)),
            text_of(m.get("PartNumber")).filter(|s| !is_unconfirmed(s)),
        ]
        .into_iter()
        .flatten()
        .collect();
        let label = locator.unwrap_or_else(|| d.pp_modules.to_string());
        rows.push(if parts.is_empty() {
            b.config(ram_title, &label, None)
        } else {
            plain(&label, parts.join(" · "), Kind::Config)
        });
    }
    // Declared / configured data rates are SMBIOS facts, not measurements.
    let mut speeds: Vec<String> = modules
        .iter()
        .filter_map(|m| {
            num_of(m.get("ConfiguredSpeedMTs"))
                .or_else(|| num_of(m.get("RatedSpeedMTs")))
                .filter(|n| *n > 0.0)
                .map(|n| format!("{} MT/s", num_text(n)))
        })
        .collect();
    speeds.dedup();
    if !speeds.is_empty() {
        rows.insert(2, plain(d.pp_speed, speeds.join(" / "), Kind::Config));
    }
    for note in list_of(get(&v, &["Ram", "Context"])) {
        if let Some(n) = text_of(Some(note)) {
            rows.push(plain("", ram_context(&n, ru), Kind::Config));
        }
    }
    cards.push(Card {
        kind: CardKind::Ram,
        title: ram_title.to_string(),
        rows,
    });

    // Motherboard.
    let board_title = d.pp_board;
    let rows = vec![
        b.config(
            board_title,
            d.pp_manufacturer,
            text_of(get(&v, &["Motherboard", "Manufacturer"])),
        ),
        b.config(
            board_title,
            d.pp_model,
            text_of(get(&v, &["Motherboard", "Product"])),
        ),
        b.config(
            board_title,
            d.pp_version,
            text_of(get(&v, &["Motherboard", "Version"])),
        ),
    ];
    cards.push(Card {
        kind: CardKind::Board,
        title: board_title.to_string(),
        rows,
    });

    // BIOS / UEFI.
    let bios_title = d.pp_bios;
    let secure = text_of(get(&v, &["Bios", "SecureBoot"])).map(|s| match s.as_str() {
        "Enabled" | "True" => (if ru { "Включён" } else { "Enabled" }).to_string(),
        "Disabled" | "False" => (if ru { "Отключён" } else { "Disabled" }).to_string(),
        _ => s,
    });
    let rows = vec![
        b.config(
            bios_title,
            d.pp_version,
            text_of(get(&v, &["Bios", "Version"])),
        ),
        b.config(
            bios_title,
            d.pp_manufacturer,
            text_of(get(&v, &["Bios", "Manufacturer"])),
        ),
        b.config(
            bios_title,
            d.pp_date,
            text_of(get(&v, &["Bios", "ReleaseDate"])).and_then(|s| date_of(&s)),
        ),
        b.config(
            bios_title,
            d.pp_firmware,
            text_of(get(&v, &["Bios", "FirmwareType"])),
        ),
        b.config(bios_title, d.pp_secure_boot, secure),
    ];
    cards.push(Card {
        kind: CardKind::Bios,
        title: bios_title.to_string(),
        rows,
    });

    // Storage.
    let st_title = d.pp_storage;
    let mut rows = Vec::new();
    for disk in list_of(get(&v, &["Storage", "Disks"])) {
        let name = text_of(disk.get("Model"))
            .filter(|s| !is_unconfirmed(s))
            .unwrap_or_else(|| d.pp_unconfirmed.to_string());
        let parts: Vec<String> = [
            num_of(disk.get("CapacityBytes"))
                .filter(|n| *n > 0.0)
                .map(|n| {
                    // Disk capacities in decimal-free binary units like Windows.
                    bytes_text(n)
                }),
            text_of(disk.get("BusType")).filter(|s| !is_unconfirmed(s)),
            text_of(disk.get("MediaType")).filter(|s| !is_unconfirmed(s) && s != "Unspecified"),
        ]
        .into_iter()
        .flatten()
        .collect();
        rows.push(plain(&name, parts.join(" · "), Kind::Config));
        // What Windows REPORTS (not a verdict of this page).
        match text_of(disk.get("HealthStatus")).filter(|s| !is_unconfirmed(s)) {
            Some(h) => rows.push(plain(
                "",
                d.pp_disk_reported_fmt.replace("{state}", &h),
                Kind::Config,
            )),
            None => {
                let r = b.config(st_title, &name, None);
                rows.push(plain("", r.value, Kind::Unconfirmed));
            }
        }
        if let Some(rel) = disk
            .get("Reliability")
            .filter(|r| !matches!(r, Value::Null))
        {
            let mut items = Vec::new();
            if let Some(t) = num_of(rel.get("TemperatureC")).filter(|t| *t > 0.0) {
                items.push(format!("{} {} °C", d.pp_temp, num_text(t)));
            }
            // v1.0 rule: a 0 % wear from the reliability counter is not a
            // trustworthy reading — never shown as a measurement.
            if let Some(w) = num_of(rel.get("WearPercent")).filter(|w| *w > 0.0) {
                items.push(format!("{} {} %", d.pp_wear, num_text(w)));
            }
            if let Some(h) = num_of(rel.get("PowerOnHours")).filter(|h| *h > 0.0) {
                items.push(format!(
                    "{} {} {}",
                    d.pp_hours,
                    num_text(h),
                    if ru { "ч" } else { "h" }
                ));
            }
            if !items.is_empty() {
                rows.push(measured(
                    "",
                    d.pp_disk_counters_fmt
                        .replace("{items}", &items.join(" · ")),
                ));
            }
        }
    }
    if rows.is_empty() {
        rows.push(b.config(st_title, d.pp_storage, None));
    }
    cards.push(Card {
        kind: CardKind::Storage,
        title: st_title.to_string(),
        rows,
    });

    // Graphics.
    let gpu_title = d.pp_gpu;
    let mut rows = Vec::new();
    for g in list_of(get(&v, &["Gpu", "Controllers"])) {
        let name = text_of(g.get("Name"))
            .filter(|s| !is_unconfirmed(s))
            .unwrap_or_else(|| d.pp_unconfirmed.to_string());
        let reliable = matches!(g.get("VRAMReliable"), Some(Value::Bool(true)));
        let kind = text_of(g.get("VRAMKind")).unwrap_or_default();
        let vram = match (reliable, kind.as_str()) {
            (true, "dedicated") => num_of(g.get("DedicatedVideoMemoryBytes"))
                .or_else(|| num_of(g.get("VRAMBytes")))
                .filter(|n| *n > 0.0)
                .map(bytes_text),
            (true, "shared") => Some(d.pp_vram_shared.to_string()),
            _ => None,
        };
        rows.push(plain(&name, String::new(), Kind::Config));
        rows.push(b.config(gpu_title, d.pp_vram, vram));
        rows.push(b.config(gpu_title, d.pp_driver, text_of(g.get("DriverVersion"))));
    }
    if rows.is_empty() {
        rows.push(b.config(gpu_title, d.pp_gpu, None));
    }
    cards.push(Card {
        kind: CardKind::Gpu,
        title: gpu_title.to_string(),
        rows,
    });

    // Network adapters (physical PCI / USB only — the collector filters).
    let net_title = d.pp_network;
    let mut rows = Vec::new();
    for a in list_of(get(&v, &["Network", "Adapters"])) {
        let name = text_of(a.get("Name"))
            .filter(|s| !is_unconfirmed(s))
            .unwrap_or_else(|| d.pp_unconfirmed.to_string());
        let link = match text_of(a.get("LinkState")).as_deref() {
            Some("CONNECTED") => d.pp_link_up,
            Some("DISCONNECTED") => d.pp_link_down,
            _ => d.pp_link_unknown,
        };
        let kind = if link == d.pp_link_unknown {
            Kind::Unconfirmed
        } else {
            Kind::Measured
        };
        rows.push(plain(&name, link.to_string(), kind));
    }
    if rows.is_empty() {
        rows.push(plain(
            d.pp_network,
            d.pp_none_found.to_string(),
            Kind::Config,
        ));
    }
    cards.push(Card {
        kind: CardKind::Network,
        title: net_title.to_string(),
        rows,
    });

    // Power / battery.
    let pw_title = d.pp_power;
    let mut rows = Vec::new();
    let batteries = list_of(get(&v, &["Battery", "Batteries"]));
    if batteries.is_empty() {
        rows.push(plain("", d.pp_no_battery.to_string(), Kind::Config));
    }
    for bat in batteries {
        let name = text_of(bat.get("Name"))
            .filter(|s| !is_unconfirmed(s))
            .unwrap_or_else(|| d.pp_power.to_string());
        rows.push(plain(&name, String::new(), Kind::Config));
        match num_of(bat.get("ChargePercent")) {
            Some(c) => rows.push(measured(d.pp_battery_charge, format!("{} %", num_text(c)))),
            None => rows.push(b.config(pw_title, d.pp_battery_charge, None)),
        }
        match num_of(bat.get("WearPercent")) {
            Some(w) => rows.push(measured(d.pp_battery_wear, format!("{} %", num_text(w)))),
            None => rows.push(b.config(pw_title, d.pp_battery_wear, None)),
        }
        let design = num_of(bat.get("DesignCapacity")).filter(|n| *n > 0.0);
        let full = num_of(bat.get("FullChargeCapacity")).filter(|n| *n > 0.0);
        rows.push(b.config(
            pw_title,
            d.pp_battery_capacity,
            match (design, full) {
                (Some(a), Some(f)) => Some(format!("{} / {} mWh", num_text(a), num_text(f))),
                _ => None,
            },
        ));
        rows.push(b.config(
            pw_title,
            d.pp_battery_cycles,
            num_of(bat.get("CycleCount")).map(num_text),
        ));
    }
    cards.push(Card {
        kind: CardKind::Power,
        title: pw_title.to_string(),
        rows,
    });

    for e in list_of(v.get("CollectionErrors")) {
        if let Some(t) = text_of(Some(e)).filter(|t| !t.is_empty()) {
            b.unconfirmed.push(t);
        }
    }
    let collected_at = text_of(v.get("GeneratedAt"))
        .map(|s| s.replace('T', " ").chars().take(16).collect())
        .unwrap_or_default();
    Some(Passport {
        system,
        cards,
        unconfirmed: b.unconfirmed,
        collected_at,
    })
}

/// Copy / Save summary text (the same model as the page).
pub fn summary_text(p: &Passport, d: &crate::i18n::Dict) -> String {
    let mut out = String::new();
    out.push_str(&format!("{}\r\n", d.pp_title));
    out.push_str(&format!("{}\r\n", p.system));
    out.push_str(&format!(
        "{}\r\n",
        d.pp_collected_fmt.replace("{time}", &p.collected_at)
    ));
    for c in &p.cards {
        out.push_str(&format!("\r\n[{}]\r\n", c.title));
        for r in &c.rows {
            let mark = match r.kind {
                Kind::Config => "",
                Kind::Measured => " *",
                Kind::Unconfirmed => " ?",
            };
            match (r.label.is_empty(), r.value.is_empty()) {
                (true, _) => out.push_str(&format!("  {}{mark}\r\n", r.value)),
                (false, true) => out.push_str(&format!("  {}\r\n", r.label)),
                (false, false) => out.push_str(&format!("  {}: {}{mark}\r\n", r.label, r.value)),
            }
        }
    }
    out.push_str(&format!("\r\n[{}]\r\n", d.pp_unconfirmed_title));
    if p.unconfirmed.is_empty() {
        out.push_str(&format!("  {}\r\n", d.pp_unconfirmed_none));
    }
    for u in &p.unconfirmed {
        out.push_str(&format!("  {u}\r\n"));
    }
    out.push_str(&format!(
        "\r\n* {} · ? {}\r\n",
        d.pp_legend_measured, d.pp_legend_unconfirmed
    ));
    out
}

/// v1.1 QA fixture: sanitized real MSI collector output (serials / MAC
/// replaced) for the `hardware-passport` scene and the tests.
pub(crate) const QA_PASSPORT_JSON: &str = r#"{
  "Tool": "EXPC Hardware Diagnostics", "SchemaVersion": 1,
  "GeneratedAt": "2026-10-13T13:06:12.0075273+03:00", "ReadOnly": true, "OverallState": "OK",
  "System": {"Manufacturer": "Micro-Star International Co., Ltd.", "Model": "MS-7E34", "Hostname": "MSI",
             "SystemType": "x64-based PC", "WindowsEdition": "Microsoft Windows 11 Pro", "WindowsBuild": "26300",
             "WindowsArchitecture": "64-bit", "ProductId": "Default string"},
  "Motherboard": {"Manufacturer": "Micro-Star International Co., Ltd.", "Product": "PRO Z890-P WIFI (MS-7E34)", "Version": "1.0", "Serial": "SERIAL"},
  "Bios": {"Manufacturer": "American Megatrends International, LLC.", "Version": "1.AE0", "ReleaseDate": "/Date(1782259200000)/", "FirmwareType": "UEFI", "SecureBoot": "Enabled"},
  "Cpu": {"Models": ["Intel(R) Core(TM) Ultra 7 270K Plus"], "Manufacturers": ["GenuineIntel"], "PhysicalCores": 24, "LogicalProcessors": 24,
          "MaxClockMHz": 3700, "CurrentClockMHz": 3700, "Sockets": ["U3E1"], "Architecture": "x64", "L2CacheKB": 40960, "L3CacheKB": 36864},
  "Ram": {"State": "OK", "Reasons": [], "Context": [], "TotalBytes": 51539607552, "Total": "48,00 GB", "ModuleCount": 2, "DeclaredSlots": 4, "Topology": "MODULES",
          "Modules": [
            {"Manufacturer": "0x0B92", "PartNumber": "Unavailable", "CapacityBytes": 25769803776, "Type": "DDR5", "RatedSpeedMTs": 7667, "ConfiguredSpeedMTs": 7667, "DeviceLocator": "DIMMA2"},
            {"Manufacturer": "0x0B92", "PartNumber": "Unavailable", "CapacityBytes": 25769803776, "Type": "DDR5", "RatedSpeedMTs": 7667, "ConfiguredSpeedMTs": 7667, "DeviceLocator": "DIMMB2"}]},
  "Storage": {"State": "OK", "Disks": [
      {"Model": "Samsung SSD 9100 PRO 1TB", "CapacityBytes": 1000204886016, "MediaType": "SSD", "BusType": "NVMe", "HealthStatus": "Healthy", "Health": "OK",
       "Reliability": {"TemperatureC": 45, "WearPercent": 0, "PowerOnHours": null}},
      {"Model": "TOSHIBA DT02ABA400", "CapacityBytes": 4000787030016, "MediaType": "HDD", "BusType": "SATA", "HealthStatus": "Healthy", "Health": "OK", "Reliability": null}]},
  "Gpu": {"State": "INFO", "Controllers": [
      {"Name": "NVIDIA GeForce RTX 5060", "DriverVersion": "32.0.16.1692", "VRAMBytes": 8546942976, "VRAMReliable": true, "VRAMKind": "dedicated", "DedicatedVideoMemoryBytes": 8546942976},
      {"Name": "Intel(R) Graphics", "DriverVersion": "32.0.101.6979", "VRAMBytes": null, "VRAMReliable": true, "VRAMKind": "shared"}]},
  "Network": {"State": "INFO", "Adapters": [
      {"Name": "Intel(R) Wi-Fi 7 BE200 320MHz", "Manufacturer": "Intel Corporation", "MAC": "00:00:00:00:00:01", "LinkState": "DISCONNECTED"},
      {"Name": "Realtek PCIe 5GbE Family Controller", "Manufacturer": "Realtek", "MAC": "00:00:00:00:00:02", "LinkState": "CONNECTED"}]},
  "Battery": {"State": "INFO", "Detected": false, "Summary": "Battery: Not present.", "Batteries": []},
  "Npu": {"Detected": true, "Devices": [{"Name": "Intel(R) AI Boost", "Vendor": "Intel Corporation"}]},
  "CollectionErrors": []
}"#;

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn texts(ru: bool) -> Texts<'static> {
        Texts {
            ru,
            d: if ru {
                &crate::i18n::RU
            } else {
                &crate::i18n::EN
            },
        }
    }

    fn card(p: &Passport, k: CardKind) -> &Card {
        p.cards.iter().find(|c| c.kind == k).unwrap()
    }

    #[test]
    fn eight_cards_in_order_with_real_values_and_no_overall_ok() {
        let p = build(QA_PASSPORT_JSON, &texts(true)).expect("passport");
        let kinds: Vec<CardKind> = p.cards.iter().map(|c| c.kind).collect();
        assert_eq!(
            kinds,
            [
                CardKind::Cpu,
                CardKind::Ram,
                CardKind::Board,
                CardKind::Bios,
                CardKind::Storage,
                CardKind::Gpu,
                CardKind::Network,
                CardKind::Power
            ]
        );
        let cpu = card(&p, CardKind::Cpu);
        assert_eq!(cpu.rows[0].value, "Intel(R) Core(TM) Ultra 7 270K Plus");
        assert_eq!(cpu.rows[1].value, "24 / 24");
        assert_eq!(cpu.rows[2].value, "3.70 GHz");
        assert_eq!(cpu.rows[3].value, "40 MB / 36 MB");
        assert!(cpu.rows.iter().any(|r| r.value.contains("AI Boost")));
        let ram = card(&p, CardKind::Ram);
        assert_eq!(ram.rows[0].value, "48.00 GB");
        assert_eq!(ram.rows[1].value, "2 из 4 слотов");
        assert_eq!(ram.rows[2].label, crate::i18n::RU.pp_speed);
        assert_eq!(ram.rows[2].value, "7667 MT/s");
        assert_eq!(ram.rows[3].label, "DIMMA2");
        assert!(ram.rows[3].value.contains("DDR5") && ram.rows[3].value.contains("7667 MT/s"));
        assert!(
            !ram.rows[3].value.contains("Unavailable"),
            "placeholder dropped"
        );
        let bios = card(&p, CardKind::Bios);
        assert!(
            bios.rows.iter().any(|r| r.value == "2026-06-24"),
            "{bios:?}"
        );
        assert!(bios.rows.iter().any(|r| r.value == "Включён"));
        // No universal verdict anywhere on the page.
        let text = summary_text(&p, &crate::i18n::RU);
        assert!(!text.contains("OverallState") && !text.contains("ОБЩИЙ СТАТУС"));
        assert!(!text.lines().any(|l| l.trim() == "OK"), "{text}");
    }

    #[test]
    fn disks_show_what_windows_reports_and_only_real_measurements() {
        let p = build(QA_PASSPORT_JSON, &texts(true)).unwrap();
        let st = card(&p, CardKind::Storage);
        let samsung = st
            .rows
            .iter()
            .position(|r| r.label.starts_with("Samsung"))
            .unwrap();
        assert!(st.rows[samsung].value.contains("NVMe") && st.rows[samsung].value.contains("SSD"));
        assert_eq!(st.rows[samsung + 1].value, "Windows сообщает: Healthy");
        let counters = &st.rows[samsung + 2];
        assert_eq!(counters.kind, Kind::Measured);
        assert!(counters.value.contains("45 °C"));
        assert!(
            !counters.value.contains("износ"),
            "0 % wear is not a reading"
        );
        // A disk without counters gets no invented measurement.
        let toshiba = st
            .rows
            .iter()
            .position(|r| r.label.starts_with("TOSHIBA"))
            .unwrap();
        assert!(
            st.rows
                .get(toshiba + 2)
                .is_none_or(|r| r.kind != Kind::Measured)
        );
    }

    #[test]
    fn graphics_network_power_and_unconfirmed_values() {
        let p = build(QA_PASSPORT_JSON, &texts(false)).unwrap();
        let gpu = card(&p, CardKind::Gpu);
        assert!(gpu.rows.iter().any(|r| r.value == "7.96 GB"));
        assert!(gpu.rows.iter().any(|r| r.value == "shared with RAM"));
        let net = card(&p, CardKind::Network);
        assert_eq!(net.rows[0].value, "Disconnected");
        assert_eq!(net.rows[1].value, "Connected");
        assert_eq!(net.rows[1].kind, Kind::Measured);
        let pw = card(&p, CardKind::Power);
        assert_eq!(pw.rows[0].value, crate::i18n::EN.pp_no_battery);
        // Placeholders become "not confirmed", never shown as data.
        let doc = QA_PASSPORT_JSON.replace(r#""Version": "1.0""#, r#""Version": "Default string""#);
        let p = build(&doc, &texts(true)).unwrap();
        let board = card(&p, CardKind::Board);
        assert_eq!(board.rows[2].kind, Kind::Unconfirmed);
        assert_eq!(board.rows[2].value, crate::i18n::RU.pp_unconfirmed);
        assert!(
            p.unconfirmed
                .iter()
                .any(|u| u.contains(crate::i18n::RU.pp_version))
        );
    }

    #[test]
    fn battery_values_are_measurements_and_missing_ones_unconfirmed() {
        let doc = QA_PASSPORT_JSON.replace(
            r#""Batteries": []"#,
            r#""Batteries": [{"Name": "BAT0", "ChargePercent": 81, "WearPercent": 12.5, "DesignCapacity": 57000, "FullChargeCapacity": 49875, "CycleCount": "Not reported"}]"#,
        );
        let p = build(&doc, &texts(true)).unwrap();
        let pw = card(&p, CardKind::Power);
        assert_eq!(pw.rows[0].label, "BAT0");
        assert_eq!(pw.rows[1].kind, Kind::Measured);
        assert_eq!(pw.rows[1].value, "81 %");
        assert_eq!(pw.rows[2].value, "12.5 %");
        assert_eq!(pw.rows[3].value, "57000 / 49875 mWh");
        assert_eq!(pw.rows[4].kind, Kind::Unconfirmed, "cycles not reported");
    }

    #[test]
    fn dates_and_placeholders() {
        assert_eq!(
            date_of("/Date(1782259200000)/").as_deref(),
            Some("2026-06-24")
        );
        assert_eq!(
            date_of("2025-01-31T00:00:00").as_deref(),
            Some("2025-01-31")
        );
        assert_eq!(date_of("garbage"), None);
        for p in [
            "",
            "Unavailable",
            "Default string",
            "To be filled by O.E.M.",
            "UNKNOWN",
            "Not reported",
        ] {
            assert!(is_unconfirmed(p), "{p}");
        }
        assert!(!is_unconfirmed("MS-7E34"));
        assert!(build("{\"x\": 1}", &texts(true)).is_none());
    }
}
