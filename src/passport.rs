//! v0.4.5 compact "КОМПЬЮТЕР" passport of the Diagnostics page: Windows,
//! CPU, RAM and motherboard only (no disks — those live on the Hardware
//! page). Read-only: one hidden PowerShell CIM query (Win32_OperatingSystem,
//! Win32_Processor, Win32_PhysicalMemory, Win32_BaseBoard) plus the
//! `CurrentVersion` registry values; nothing is changed.

use crate::deep_checks::json;

/// One machine passport. Empty strings mean "not reported".
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Passport {
    pub windows: String,
    pub cpu: String,
    pub ram: String,
    pub board: String,
    /// v1.0: `Win32_BIOS.SMBIOSBIOSVersion` (+ release date when reported).
    pub bios: String,
    /// v1.0 item 34: on-board (soldered) LPDDR — the number of SMBIOS
    /// memory devices (channels/packages), never shown as "N×module".
    pub ram_onboard_devices: Option<usize>,
}

impl Passport {
    /// RAM line with the localised on-board LPDDR topology suffix.
    pub fn ram_text(&self, ru: bool) -> String {
        match (self.ram.is_empty(), self.ram_onboard_devices) {
            (false, Some(n)) if ru => format!("{} · распаянная, SMBIOS: {n} устр.", self.ram),
            (false, Some(n)) => format!("{} · on-board, SMBIOS: {n} devices", self.ram),
            _ => self.ram.clone(),
        }
    }
}

pub const MARKER: &str = "WSD_PASSPORT ";

/// Read-only collector. Emits one `WSD_PASSPORT {json}` line.
pub const COLLECTOR_PS1: &str = r#"
$ErrorActionPreference = 'SilentlyContinue'
$os = Get-CimInstance Win32_OperatingSystem
$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$cpu = @(Get-CimInstance Win32_Processor)
$mem = @(Get-CimInstance Win32_PhysicalMemory)
$bb = Get-CimInstance Win32_BaseBoard
$bios = Get-CimInstance Win32_BIOS | Select-Object -First 1
$biosDate = ''
try { if ($bios.ReleaseDate) { $biosDate = ([datetime]$bios.ReleaseDate).ToString('yyyy-MM-dd') } } catch { }
$mods = New-Object System.Collections.Generic.List[object]
foreach ($m in $mem) {
  $mods.Add([ordered]@{
    cap = [double]$m.Capacity
    type = [int]$m.SMBIOSMemoryType
    speed = [int]$m.ConfiguredClockSpeed
    rated = [int]$m.Speed
  })
}
$o = [ordered]@{
  caption = [string]$os.Caption
  display = [string]$cv.DisplayVersion
  build = [string]$cv.CurrentBuild
  ubr = [int]$cv.UBR
  arch = [string]$os.OSArchitecture
  cpu = [string]($cpu | Select-Object -First 1).Name
  cores = [int](($cpu | Measure-Object NumberOfCores -Sum).Sum)
  threads = [int](($cpu | Measure-Object NumberOfLogicalProcessors -Sum).Sum)
  mem = $mods.ToArray()
  total = [double]$os.TotalVisibleMemorySize
  board_maker = [string]$bb.Manufacturer
  board = [string]$bb.Product
  bios = [string]$bios.SMBIOSBIOSVersion
  bios_date = $biosDate
}
'WSD_PASSPORT ' + ($o | ConvertTo-Json -Compress -Depth 4)
"#;

/// SMBIOS memory type (SMBIOS 3.x table 17) to a display name.
pub fn memory_type_name(code: i64) -> Option<&'static str> {
    Some(match code {
        20 => "DDR",
        21 => "DDR2",
        24 => "DDR3",
        26 => "DDR4",
        27 => "LPDDR",
        28 => "LPDDR2",
        29 => "LPDDR3",
        30 => "LPDDR4",
        34 => "DDR5",
        35 => "LPDDR5",
        _ => return None,
    })
}

fn gib(bytes: f64) -> String {
    let g = bytes / 1024f64.powi(3);
    if (g - g.round()).abs() < 0.05 {
        format!("{:.0} GB", g.round())
    } else {
        format!("{g:.1} GB")
    }
}

/// LPDDR generations (SMBIOS 27..30, 35): soldered on-board memory.
pub fn is_onboard_lpddr(code: i64) -> bool {
    matches!(code, 27..=30 | 35)
}

/// "32 GB DDR5-6000 (2×16 GB)": total, type and configured speed when the
/// modules report them, module layout when there are several.
pub fn format_ram(modules: &[(f64, i64, i64)], visible_kib: f64) -> String {
    let total: f64 = modules.iter().map(|m| m.0).sum();
    let total = if total > 0.0 {
        total
    } else {
        visible_kib * 1024.0
    };
    if total <= 0.0 {
        return String::new();
    }
    let mut s = gib(total);
    let ty = modules.iter().find_map(|m| memory_type_name(m.1));
    let speed = modules.iter().map(|m| m.2).filter(|v| *v > 0).min();
    match (ty, speed) {
        (Some(t), Some(v)) => s.push_str(&format!(" {t}-{v}")),
        (Some(t), None) => s.push_str(&format!(" {t}")),
        (None, Some(v)) => s.push_str(&format!(" · {v} MT/s")),
        (None, None) => {}
    }
    // LPDDR: SMBIOS devices are channels/packages, not modules.
    if modules.len() > 1 && !modules.iter().any(|m| is_onboard_lpddr(m.1)) {
        let first = modules[0].0;
        if modules.iter().all(|m| (m.0 - first).abs() < 1.0) {
            s.push_str(&format!(" ({}×{})", modules.len(), gib(first)));
        } else {
            let parts: Vec<String> = modules
                .iter()
                .map(|m| format!("{:.0}", m.0 / 1024f64.powi(3)))
                .collect();
            s.push_str(&format!(" ({} GB)", parts.join("+")));
        }
    }
    s
}

/// Board vendor names are often long ("Micro-Star International Co., Ltd.");
/// the passport keeps the common short form.
pub fn short_vendor(v: &str) -> String {
    let t = v.trim();
    let l = t.to_ascii_lowercase();
    for (needle, short) in [
        ("micro-star", "MSI"),
        ("asustek", "ASUS"),
        ("gigabyte", "GIGABYTE"),
        ("asrock", "ASRock"),
        ("hewlett", "HP"),
        ("dell", "Dell"),
        ("lenovo", "Lenovo"),
    ] {
        if l.contains(needle) {
            return short.into();
        }
    }
    t.trim_end_matches('.')
        .trim_end_matches(" Ltd")
        .trim_end_matches(',')
        .trim_end_matches(" Co")
        .trim_end_matches(" Inc")
        .trim_end_matches(',')
        .to_string()
}

fn collapse_spaces(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub fn parse_output(stdout: &str) -> Option<Passport> {
    let v = json::parse(crate::ps_exec::marked_line(stdout, MARKER)?)?;
    let s = |k: &str| {
        v.get(k)
            .and_then(|x| x.as_str())
            .map(collapse_spaces)
            .unwrap_or_default()
    };
    let n = |x: Option<&json::Value>| match x {
        Some(json::Value::Num(v)) => *v,
        _ => 0.0,
    };
    // Localised captions: "Microsoft Windows 11 Pro" / "Майкрософт Windows 11 Pro".
    let caption = s("caption");
    let caption = match caption.find("Windows") {
        Some(i) => caption[i..].to_string(),
        None => caption,
    };
    let mut windows = caption;
    let display = s("display");
    if !display.is_empty() {
        windows.push_str(&format!(" {display}"));
    }
    let build = s("build");
    if !build.is_empty() {
        let ubr = n(v.get("ubr")) as u32;
        windows.push_str(&format!(
            " ({})",
            crate::ui::sysinfo::format_full_build(&build, (ubr > 0).then_some(ubr))
        ));
    }
    let mut cpu = s("cpu");
    let cores = n(v.get("cores")) as u32;
    let threads = n(v.get("threads")) as u32;
    if !cpu.is_empty() && cores > 0 {
        cpu.push_str(&format!(" · {cores}C/{threads}T"));
    }
    let modules: Vec<(f64, i64, i64)> = match v.get("mem") {
        Some(json::Value::Arr(items)) => items
            .iter()
            .map(|m| {
                let speed = n(m.get("speed")) as i64;
                let rated = n(m.get("rated")) as i64;
                (
                    n(m.get("cap")),
                    n(m.get("type")) as i64,
                    if speed > 0 { speed } else { rated },
                )
            })
            .collect(),
        Some(m @ json::Value::Obj(_)) => vec![(
            n(m.get("cap")),
            n(m.get("type")) as i64,
            n(m.get("speed")) as i64,
        )],
        _ => Vec::new(),
    };
    let ram = format_ram(&modules, n(v.get("total")));
    let maker = short_vendor(&s("board_maker"));
    let product = s("board");
    let board = match (maker.is_empty(), product.is_empty()) {
        (false, false) if !product.to_lowercase().contains(&maker.to_lowercase()) => {
            format!("{maker} {product}")
        }
        (_, false) => product,
        (false, true) => maker,
        (true, true) => String::new(),
    };
    let ram_onboard_devices = modules
        .iter()
        .any(|m| is_onboard_lpddr(m.1))
        .then_some(modules.len());
    let mut bios = s("bios");
    let bios_date = s("bios_date");
    if !bios.is_empty() && !bios_date.is_empty() {
        bios.push_str(&format!(" ({bios_date})"));
    }
    Some(Passport {
        windows,
        cpu,
        ram,
        board,
        bios,
        ram_onboard_devices,
    })
}

/// Runs the collector (Windows: powershell.exe), 60 s guard.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn collect(host: &str) -> Result<Passport, String> {
    let out =
        crate::ps_exec::run_powershell(host, COLLECTOR_PS1, std::time::Duration::from_secs(60))
            .map_err(|e| e.to_string())?;
    parse_output(&out).ok_or_else(|| "passport collector produced no result".into())
}

/// The "Клиент: X\nКомпьютер: Y" clipboard text of the copy button; only
/// the computer line when no client is entered.
pub fn client_clipboard_text(client: &str, computer: &str, ru: bool) -> String {
    let (cl, co) = if ru {
        ("Клиент", "Компьютер")
    } else {
        ("Client", "Computer")
    };
    let client = client.trim();
    if client.is_empty() {
        format!("{co}: {}", computer.trim())
    } else {
        format!("{cl}: {client}\n{co}: {}", computer.trim())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MSI: &str = r#"noise
WSD_PASSPORT {"caption":"Microsoft Windows 11 Pro","display":"25H2","build":"26200","ubr":6584,"arch":"64-bit","cpu":"Intel(R) Core(TM) i7-14700K   ","cores":20,"threads":28,"mem":[{"cap":17179869184,"type":34,"speed":6000,"rated":6400},{"cap":17179869184,"type":34,"speed":6000,"rated":6400}],"total":33275904,"board_maker":"Micro-Star International Co., Ltd.","board":"PRO Z790-P WIFI (MS-7E06)"}"#;

    #[test]
    fn parses_windows_cpu_ram_and_board_only() {
        let p = parse_output(MSI).expect("parsed");
        assert_eq!(p.windows, "Windows 11 Pro 25H2 (26200.6584)");
        let ru = MSI.replace("Microsoft Windows", "Майкрософт Windows");
        assert_eq!(
            parse_output(&ru).unwrap().windows,
            p.windows,
            "localised prefix"
        );
        assert_eq!(p.cpu, "Intel(R) Core(TM) i7-14700K · 20C/28T");
        assert_eq!(p.ram, "32 GB DDR5-6000 (2×16 GB)");
        assert_eq!(p.board, "MSI PRO Z790-P WIFI (MS-7E06)");
    }

    #[test]
    fn single_module_object_and_unknown_type_degrade_honestly() {
        let out = r#"WSD_PASSPORT {"caption":"Microsoft Windows 10 Home","display":"","build":"19045","ubr":0,"cpu":"AMD Ryzen 5 3600","cores":6,"threads":12,"mem":{"cap":8589934592,"type":0,"speed":0,"rated":0},"total":8300000,"board_maker":"","board":""}"#;
        let p = parse_output(out).unwrap();
        assert_eq!(p.windows, "Windows 10 Home (19045)");
        assert_eq!(p.ram, "8 GB", "no invented memory type/speed");
        assert_eq!(p.board, "", "board not reported stays empty");
        assert_eq!(parse_output("no marker"), None);
    }

    #[test]
    fn ram_type_codes() {
        assert_eq!(memory_type_name(26), Some("DDR4"));
        assert_eq!(memory_type_name(34), Some("DDR5"));
        assert_eq!(memory_type_name(2), None);
        assert_eq!(format_ram(&[], 16_000_000.0), "15.3 GB");
    }

    #[test]
    fn lpddr_onboard_topology_is_not_reported_as_modules() {
        // Real case: laptop with 16 GB LPDDR5 — SMBIOS lists 8 × 2 GB.
        let mem: Vec<String> = (0..8)
            .map(|_| "{\"cap\":2147483648,\"type\":35,\"speed\":6400,\"rated\":6400}".to_string())
            .collect();
        let line = format!(
            "WSD_PASSPORT {{\"caption\":\"Microsoft Windows 11 Home\",\"mem\":[{}],\"total\":16000000,\"bios\":\"N3CET65W (1.40 )\",\"bios_date\":\"2025-05-20\"}}",
            mem.join(",")
        );
        let p = parse_output(&line).expect("parsed");
        assert_eq!(p.ram, "16 GB LPDDR5-6400", "no 8×2 GB module layout");
        assert_eq!(p.ram_onboard_devices, Some(8));
        assert_eq!(
            p.ram_text(true),
            "16 GB LPDDR5-6400 · распаянная, SMBIOS: 8 устр."
        );
        assert!(!p.ram_text(true).contains('×'));
        assert_eq!(p.bios, "N3CET65W (1.40 ) (2025-05-20)");
        // DIMMs keep the module layout; no BIOS → empty (UI says "no data").
        let p = parse_output(
            "WSD_PASSPORT {\"mem\":[{\"cap\":17179869184,\"type\":34,\"speed\":6000},{\"cap\":17179869184,\"type\":34,\"speed\":6000}]}",
        )
        .unwrap();
        assert_eq!(p.ram_text(true), "32 GB DDR5-6000 (2×16 GB)");
        assert_eq!(p.ram_onboard_devices, None);
        assert!(p.bios.is_empty());
    }

    #[test]
    fn collector_is_read_only() {
        let s = COLLECTOR_PS1.to_ascii_lowercase();
        for verb in [
            "set-",
            "remove-",
            "new-item",
            "invoke-cimmethod",
            "stop-",
            "restart-",
        ] {
            assert!(!s.contains(verb), "{verb}");
        }
        assert!(!s.contains("disk"), "the passport lists no disks");
    }

    /// The collector itself runs (real CIM data on Windows; elsewhere it
    /// must still answer with its marker line).
    #[test]
    fn collector_runs() {
        let Some(host) = crate::ps_exec::test_host() else {
            return;
        };
        let p = collect(&host).expect("marker line");
        if cfg!(windows) {
            assert!(p.windows.contains("Windows"), "{p:?}");
            assert!(!p.cpu.is_empty() && !p.ram.is_empty(), "{p:?}");
        }
    }

    #[test]
    fn client_copy_text() {
        assert_eq!(
            client_clipboard_text("Алексей", "MSI", true),
            "Клиент: Алексей\nКомпьютер: MSI"
        );
        assert_eq!(
            client_clipboard_text("  ", "MSI", true),
            "Компьютер: MSI",
            "empty client: computer line only"
        );
        assert_eq!(
            client_clipboard_text("ACME", "PC-1", false),
            "Client: ACME\nComputer: PC-1"
        );
    }
}
