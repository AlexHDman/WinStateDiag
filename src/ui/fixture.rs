//! QA-only fixture reproducing the literal content of the canonical Visual
//! Master (`assets/UI_VISUAL_MASTER.png`). Used exclusively in
//! VISUAL_REFERENCE mode (`--visual-reference`) so the real renderer can be
//! compared with the master. These values are NEVER shown in a normal
//! launch and never touch the diagnostic backend. Every visible word comes
//! from the i18n dictionary of the requested language; only the master's
//! data (names, numbers, raw journal evidence) is literal.

use super::vm::*;
use crate::i18n::{self, Language};

pub const CLIENT_NAME: &str = "AlexHDman";
pub const COMPUTER_NAME: &str = "MSI";
pub const BENCHMARK_PATH: &str = "C:\\";

#[allow(dead_code)] // canonical RU master (scenes use master_vm_in)
pub fn master_vm() -> DashboardVm {
    master_vm_in(Language::Ru)
}

pub fn master_vm_in(lang: Language) -> DashboardVm {
    let d = i18n::t(lang);
    let stages: Vec<StageRow> = d
        .stage_short
        .iter()
        .enumerate()
        .map(|(i, label)| StageRow {
            number: i + 1,
            label: (*label).to_string(),
            full_label: d.stage_description[i].to_string(),
            state: RowState::Done,
            fraction: Some(1.0),
            right_text: "100%".into(),
            active: false,
            finding: None,
            result: Some(if i == 4 {
                crate::details::StageState::Info
            } else {
                crate::details::StageState::Ok
            }),
            result_text: d.expc_state_labels[if i == 4 {
                crate::details::StageState::Info
            } else {
                crate::details::StageState::Ok
            }
            .index()]
            .to_string(),
            short_finding: String::new(),
            duration: format!("00:{:02}", 1 + i % 5),
        })
        .collect();

    // Raw journal evidence exactly as the master shows it (never translated).
    let journal = [
        (
            "17:18:15",
            "Storage: Samsung SSD 9100 PRO 1TB; 931,51 GB; SSD/NVMe; Health: OK",
        ),
        ("17:18:15", "Battery: Battery: Not present."),
        ("17:18:15", "Overall hardware state: OK"),
        ("17:18:17", "Проверка драйверов (только чтение) ..."),
        (
            "17:18:19",
            "Проверка драйверов: Внимание (проблем: 0, предупреждений: 4)",
        ),
    ]
    .iter()
    .map(|(ts, msg)| JournalLine {
        timestamp: (*ts).to_string(),
        message: (*msg).to_string(),
        dim: false,
    })
    .collect();

    let module = |label: &str| ModuleRow {
        label: label.into(),
        state: ModuleState::Done,
        status_text: d.module_status_done.into(),
    };
    let meta = |label: &str, value: &str, tone: Tone, dot: bool| MetaRow {
        label: label.into(),
        value: value.into(),
        value_tone: tone,
        dot,
    };

    DashboardVm {
        lang,
        controls_enabled: true,
        stop_enabled: false,
        crypto: CryptoVm::HashOk,
        crypto_caption: Some(format!("{} · 16:05", d.origin_preflight)),
        crypto_recheck_enabled: true,
        drivers_caption: Some(format!("{} · 16:05", d.origin_preflight)),
        drivers_check_enabled: true,
        computer_name: COMPUTER_NAME.into(),
        stages,
        overall: OverallVm {
            fraction: 1.0,
            percent_text: "100%".into(),
            status_text: d.overall_status_done.into(),
            tone: Tone::Success,
            elapsed: "00:00:30".into(),
            eta: "00:00:00".into(),
            modules: vec![
                module(d.module_name_expc),
                module(d.module_name_hardware),
                module(d.module_name_zip),
            ],
        },
        operation: OperationVm {
            name: d.curop_done_name.into(),
            subtitle: "Reports\\MSI - 28-09-26".into(),
            fraction: Some(1.0),
            percent_text: "100%".into(),
            indeterminate: false,
            tone: Tone::Success,
        },
        ssd: SsdVm::Done {
            status: None,
            note: None,
            tests: [
                Some(TestVm {
                    read: "6943".into(),
                    write: "6029".into(),
                    stability: "STABLE · R 0.4% / W 2.1%".into(),
                    tone: Tone::Success,
                    delta: None,
                }),
                Some(TestVm {
                    read: "7027".into(),
                    write: "5892".into(),
                    stability: "ACCEPT · R 0.3% / W 10.4%".into(),
                    tone: Tone::Warning,
                    delta: Some(
                        d.test_delta_fmt
                            .replace("{r}", "+1.2%")
                            .replace("{w}", "-2.3%"),
                    ),
                }),
            ],
            read_current: "7027".into(),
            read_previous: Some("6943".into()),
            read_delta: Some(1.2),
            write_current: "5892".into(),
            write_previous: Some("6029".into()),
            write_delta: Some(-2.3),
            meta: vec![
                meta(d.ssd_profile_label, "1 MiB  QD4  ×4", Tone::Idle, false),
                meta(d.ssd_passes_label, "4", Tone::Idle, false),
                meta(d.ssd_duration_label, "00:00:01", Tone::Idle, false),
                meta(
                    d.ssd_read_spread_label,
                    "0.30% (STABLE)",
                    Tone::Success,
                    false,
                ),
                meta(
                    d.ssd_write_spread_label,
                    "10.37% (ACCEPT)",
                    Tone::Warning,
                    false,
                ),
                meta(d.ssd_stability_label, "ACCEPT", Tone::Warning, true),
            ],
        },
        ssd_controls_enabled: true,
        ssd_disks: vec![
            DiskEntryVm {
                drive_letter: "C:".into(),
                volume_label: Some("Win11".into()),
                model: "Samsung 9100 PRO 1TB".into(),
                capacity: "1 TB (931 GB)".into(),
                interface: "NVMe".into(),
                serial: Some("S7PZNX0R123456B".into()),
                is_system: true,
                has_target: true,
            },
            DiskEntryVm {
                drive_letter: "E:".into(),
                volume_label: Some("Data".into()),
                model: "Netac NV7000T 1TB".into(),
                capacity: "1 TB".into(),
                interface: "NVMe".into(),
                serial: Some("NT2024081900001".into()),
                is_system: false,
                has_target: true,
            },
            DiskEntryVm {
                drive_letter: "D:".into(),
                volume_label: Some("Soft".into()),
                model: "Kingston KC3000 2TB".into(),
                capacity: "2 TB".into(),
                interface: "NVMe".into(),
                serial: None,
                is_system: false,
                has_target: true,
            },
        ],
        ssd_selected: 0,
        drivers: master_drivers(lang),
        result: ResultVm::Done {
            path_display: "Reports\\MSI - 28-09-26\\MSI - 28-09-26.zip".into(),
            attention: false,
        },
        start: StartVm::NewDiagnostic,
        journal,
        journal_follow_tail: false,
        status_left: d.curop_done_name.into(),
        status_right: vec![
            "Windows 11 Pro".into(),
            "26200".into(),
            "MSI".into(),
            "28.09.2026".into(),
            "17:18".into(),
        ],
        time: 0.0,
        animate: false,
        page: Page::Diagnostics,
        crash: CrashVm {
            headline: d.crash_none.into(),
            tone: Tone::Success,
            counts: d
                .crash_counts_fmt
                .replace("{s}", "0")
                .replace("{b}", "0")
                .replace("{d}", "0"),
            debugger: d.crash_dbg_missing.into(),
            debugger_tone: Tone::Warning,
            debugger_missing: true,
            busy: false,
            can_analyze: false,
            has_details: true,
            rows: vec![InfoRow::new(d.crash_row_bugcheck, "—", Tone::Idle)],
            analysis: None,
            outcome: None,
            install: None,
        },
        sensors: SensorsVm {
            matrix: Vec::new(),
            refs: Vec::new(),
            temps: Vec::new(),
            rails: Vec::new(),
            power_state: d.sensors_no_data.into(),
            power_tone: Tone::Idle,
            power_message: String::new(),
            power: Vec::new(),
            fans: Vec::new(),
            status_line: String::new(),
            busy: false,
            has_data: false,
            read: super::vm::SensorReadVm::Idle,
        },
        gpo: GpoVm {
            status: d.gpo_not_run.into(),
            tone: Tone::Idle,
            rows: vec![InfoRow::new(d.gpo_domain, d.gpo_standalone, Tone::Idle)],
            busy: false,
            has_result: false,
        },
        system_state: SystemStateVm {
            hardware: InfoRow::new(d.hw_state_label, d.state_ok, Tone::Success),
            system: InfoRow::new(d.sys_state_label, d.state_ok, Tone::Success),
            note: d.system_state_note.into(),
        },
        smart: vec![InfoRow::new(
            "Samsung 9100 PRO 1TB",
            "NVMe · OK",
            Tone::Success,
        )],
        passport: vec![
            InfoRow::new(
                d.passport_windows,
                "Windows 11 Pro 25H2 (26200.6584)",
                Tone::Idle,
            ),
            InfoRow::new(
                d.passport_cpu,
                "Intel(R) Core(TM) i7-14700K · 20C/28T",
                Tone::Idle,
            ),
            InfoRow::new(d.passport_ram, "32 GB DDR5-6000 (2×16 GB)", Tone::Idle),
            InfoRow::new(
                d.passport_board,
                "MSI PRO Z790-P WIFI (MS-7E06)",
                Tone::Idle,
            ),
            InfoRow::new(d.passport_bios, "7E06v1A (2025-03-14)", Tone::Idle),
        ],
    }
}

/// Driver card content of the master (QA only; device names are data).
fn master_drivers(lang: Language) -> DriversVm {
    let d = i18n::t(lang);
    let row = |icon, name: &str, version: &str, tone| DriverRow {
        icon,
        name: name.into(),
        version: version.into(),
        tone,
        status_text: if tone == Tone::Warning {
            d.driver_status_warning
        } else {
            d.driver_status_ok
        }
        .into(),
        tooltip: String::new(),
    };
    DriversVm::Done {
        overall: Tone::Warning,
        rows: vec![
            row(
                DeviceIcon::Generic,
                "USB Mobile Monitor Virtual Display",
                "2.0.0.1",
                Tone::Warning,
            ),
            row(
                DeviceIcon::Gpu,
                "Intel Graphics",
                "32.0.101.9030",
                Tone::Success,
            ),
            row(
                DeviceIcon::Chip,
                &format!("{} (Intel)", d.driver_cat_chipset),
                "2.3.20306.4",
                Tone::Warning,
            ),
            row(
                DeviceIcon::Audio,
                &format!("{} (Realtek)", d.driver_cat_audio),
                "6.0.10007.1",
                Tone::Success,
            ),
            row(
                DeviceIcon::Audio,
                "AAF HD Audio Bus Controller",
                "2026.11.10.26",
                Tone::Warning,
            ),
            row(
                DeviceIcon::Storage,
                "Paragon Block Device Monitor",
                "28.3.0.0",
                Tone::Warning,
            ),
        ],
        more: 0,
        alert: Some((
            Tone::Warning,
            d.driver_alert_warning_fmt.replace("{warnings}", "4"),
            d.driver_alert_warning_note.into(),
        )),
        ok_line: String::new(),
    }
}
