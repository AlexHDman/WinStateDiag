//! v1.0 VISUAL QA scenes (`--visual-reference --scene <name>`), QA only.
//!
//! Every scene renders the REAL dashboard / Details code with fixture data
//! (the MSI reference sensors, the client case "C1" 0x139 / RvNetMP60 crash case,
//! a Samsung 9100 UNSTABLE → retest → ACCEPT benchmark). Details windows are
//! embedded into the captured framebuffer. Never active in a normal launch.

use super::*;

/// Scenes that open a Details window (embedded viewports for the capture).
pub(super) fn is_details_scene(scene: &str) -> bool {
    matches!(
        scene,
        "sensor-details" | "stage-details" | "disk-details" | "crash-analyzer" | "windbg-install"
    )
}

impl WinStateDiagApp {
    /// Seeds the app state of one QA scene.
    pub(super) fn seed_qa_scene(&mut self, scene: &str) {
        if scene == "diagnostics" {
            return;
        }
        self.sensors = Some(qa_snapshot());
        self.ata_scan = Some(qa_ata_disks());
        if scene != "disk-details" {
            self.seed_qa_nvme_disks();
        }
        self.driver_audit = DriverAuditState::Done(Box::new(qa_audit()));
        self.crash.inventory = Some(Ok(qa_inventory()));
        if scene == "bsod-running" {
            self.crash.busy = CrashBusy::Analyzing;
            self.crash.progress = Some(AnalysisProgress {
                stage: crash_dump::AnalysisStage::LoadSymbols,
                started: Instant::now()
                    .checked_sub(Duration::from_secs(47))
                    .unwrap_or_else(Instant::now),
                dump_index: 0,
                dump_total: 1,
                dump_name: "100326-9500-01.dmp".into(),
                symbols_downloading: true,
            });
        } else {
            self.crash.analyses = vec![qa_analysis()];
        }
        match scene {
            "sensor-details" => self.sensors_details_open = true,
            "stage-details" => {
                self.state = RunState::Done {
                    zip_path: PathBuf::from("Reports\\MSI - 06-10-26\\MSI - 06-10-26.zip"),
                };
                for s in self.expc_tracker.status.iter_mut() {
                    *s = SubStageStatus::Done;
                }
                self.expc_tracker.durations[4] = Some(Duration::from_secs(3));
                self.expc_checks = vec![crate::deep_checks::ExpcCheck {
                    key: "VSS shadow storage".into(),
                    status: "INFO".into(),
                    detail: "C: Shadow Storage 87% of the user limit; no VSS / Volsnap failures in 7 days".into(),
                }];
                self.event_evidence = Some(Ok((qa_vss_aggregates(), None)));
                self.stage_details = Some(4);
            }
            "disk-details" => self.seed_disk_scene(),
            // v1.0 QA: the redesigned crash analyzer (client 0x139 case).
            "crash-analyzer" => self.crash_details_open = true,
            // v1.0 QA: WinDbg installed by a winget run that reported "no
            // newer package" — independent re-detection says INSTALLED; the
            // mini-journal + collapsed raw output in Details.
            "windbg-install" => {
                self.crash.install = InstallState::Succeeded;
                self.crash.install_log = [
                    "winget install --id Microsoft.WinDbg -e --source winget",
                    "Found WinDbg [Microsoft.WinDbg] Version 1.2506.12002.0",
                    "No newer package versions are available from the configured sources.",
                    "result: No newer package versions are available",
                    "re-detect: INSTALLED",
                ]
                .iter()
                .map(|s| s.to_string())
                .collect();
                self.crash_details_open = true;
            }
            // v1.0 QA: sensor read in progress (spinner READ + real timer).
            "sensor-reading" => {
                let (tx, rx) = std::sync::mpsc::channel();
                std::mem::forget(tx);
                self.sensors_rx = Some(rx);
                self.sensors_started = Instant::now().checked_sub(Duration::from_secs(4));
            }
            _ => {}
        }
    }

    /// v1.0 QA: the three NVMe disks of the reference machine as physical
    /// disks of the SMART block (Kingston not read yet).
    fn seed_qa_nvme_disks(&mut self) {
        let mk =
            |index: u32, model: &str, letter: &str, label: &str| storage_topology::DiskCandidate {
                disk: storage_topology::PhysicalDiskInfo {
                    index,
                    model: model.into(),
                    serial: format!("QA-{index}"),
                    bus_type: "NVMe".into(),
                    size_bytes: 1_000_204_886_016,
                    is_ssd_like: true,
                },
                is_system: index == 3,
                volume: Some(storage_topology::VolumeInfo {
                    mount_point: format!("{letter}:\\"),
                    physical_disk_index: index,
                    writable: true,
                    label: label.into(),
                }),
                label: format!("{letter}: — {model}"),
            };
        self.ssd_candidates = vec![
            mk(3, "Samsung SSD 9100 PRO 1TB", "C", "Win11"),
            mk(4, "Netac NVMe SSD 1TB", "E", "Data"),
            mk(5, "KINGSTON SKC3000D2048G", "D", "Soft"),
        ];
        self.ssd_selected = 0;
        for (i, temp_k) in [(0usize, 319u16), (1, 316)] {
            let disk = self.ssd_candidates[i].disk.clone();
            let identity = storage_topology::physical_disk_identity(&disk);
            let health = nvme_health::NvmeHealth {
                physical_identity: identity.clone(),
                disk_index: disk.index,
                model: disk.model.clone(),
                bus_type: "NVMe".into(),
                captured_at: "2026-10-06T10:57:38".into(),
                source: "QA fixture".into(),
                status: nvme_health::ProbeStatus::Ok,
                status_detail: None,
                smart: Some(nvme_health::SmartHealthLog {
                    critical_warning: 0,
                    composite_temperature_k: temp_k,
                    available_spare_percent: 100,
                    available_spare_threshold_percent: 10,
                    percentage_used: 4,
                    data_units_read: 47_263_352,
                    data_units_written: 72_329_648,
                    host_read_commands: 473_155_973,
                    host_write_commands: 962_649_798,
                    controller_busy_time_minutes: 3584,
                    power_cycles: 88,
                    power_on_hours: 7870,
                    unsafe_shutdowns: 68,
                    media_and_data_integrity_errors: 0,
                    error_information_log_entries: 0,
                    warning_temperature_time_minutes: 0,
                    critical_temperature_time_minutes: 0,
                    temperature_sensors_k: [None; 8],
                }),
                error_log_status: nvme_health::ProbeStatus::Ok,
                error_log_detail: None,
                error_log: Some(Vec::new()),
                reliability: None,
                ata_smart: None,
                temp_warning_c: Some(83.0),
                temp_critical_c: Some(85.0),
            };
            self.nvme_health.insert(identity, health);
        }
    }

    fn seed_disk_scene(&mut self) {
        let disk = storage_topology::PhysicalDiskInfo {
            index: 3,
            model: "Samsung SSD 9100 PRO 1TB".into(),
            serial: "QA-SERIAL".into(),
            bus_type: "NVMe".into(),
            size_bytes: 1_000_204_886_016,
            is_ssd_like: true,
        };
        let identity = storage_topology::physical_disk_identity(&disk);
        self.ssd_candidates = vec![storage_topology::DiskCandidate {
            disk: disk.clone(),
            is_system: true,
            volume: Some(storage_topology::VolumeInfo {
                mount_point: "C:\\".into(),
                physical_disk_index: 3,
                writable: true,
                label: "Win11".into(),
            }),
            label: "C: — Samsung SSD 9100 PRO 1TB".into(),
        }];
        self.ssd_selected = 0;
        let first = qa_summary(11_700.0, 12_230.0, 0.74, 21.7);
        let second = qa_summary(11_546.0, 12_524.0, 2.75, 9.84);
        let mut health = nvme_health::NvmeHealth {
            physical_identity: identity.clone(),
            disk_index: 3,
            model: disk.model.clone(),
            bus_type: "NVMe".into(),
            captured_at: "2026-10-06T10:57:38".into(),
            source: "QA fixture".into(),
            status: nvme_health::ProbeStatus::Ok,
            status_detail: None,
            smart: Some(nvme_health::SmartHealthLog {
                critical_warning: 0,
                composite_temperature_k: 320,
                available_spare_percent: 100,
                available_spare_threshold_percent: 10,
                percentage_used: 4,
                data_units_read: 47_263_352,
                data_units_written: 72_329_648,
                host_read_commands: 473_155_973,
                host_write_commands: 962_649_798,
                controller_busy_time_minutes: 3584,
                power_cycles: 88,
                power_on_hours: 7870,
                unsafe_shutdowns: 68,
                media_and_data_integrity_errors: 0,
                error_information_log_entries: 0,
                warning_temperature_time_minutes: 0,
                critical_temperature_time_minutes: 0,
                temperature_sensors_k: [Some(341), Some(320), None, None, None, None, None, None],
            }),
            error_log_status: nvme_health::ProbeStatus::Ok,
            error_log_detail: None,
            error_log: Some(Vec::new()),
            reliability: None,
            ata_smart: None,
            temp_warning_c: Some(83.0),
            temp_critical_c: Some(85.0),
        };
        health.status_detail = None;
        let inputs = storage_health::StorageHealthInputs {
            physical_identity: identity.clone(),
            disk_index: Some(3),
            benchmark: Some(bench_facts(&first)),
            retest: storage_health::RetestOutcome::Completed(bench_facts(&second)),
            nvme: Some(health.clone()),
            events: storage_health::EventsInput::NotCollected,
            assessed_at: "2026-10-06T10:57:48".into(),
        };
        let classification = storage_health::classify(&inputs);
        self.nvme_health.insert(identity.clone(), health);
        self.assessments.insert(
            identity,
            StorageAssessment {
                disk: Some(disk),
                first: first.clone(),
                first_duration: 0.5,
                first_previous: None,
                second: Some(second.clone()),
                second_duration: Some(0.5),
                retest: storage_health::RetestOutcome::Completed(bench_facts(&second)),
                benchmark_files: Vec::new(),
                health_file: None,
                events: storage_health::EventsInput::NotCollected,
                health_pending: false,
                events_pending: false,
                classification: Some(classification),
                started_at: String::new(),
            },
        );
        self.benchmark_state = BenchmarkUiState::Done {
            result: second,
            duration_seconds: 0.5,
            previous: None,
        };
        self.raw_passes_open = true;
    }

    /// The dashboard view-model of a QA scene: the curated master for the
    /// Diagnostics page, real view-model builders on fixture state for the
    /// Hardware page modules.
    pub(super) fn qa_scene_vm(&mut self, scene: &str) -> DashboardVm {
        let mut vm = fixture::master_vm_in(self.language);
        match scene {
            "diagnostics" => vm,
            "diagnostics-active" | "stage-details" => {
                if scene == "diagnostics-active" {
                    vm.stop_enabled = true;
                    for (i, row) in vm.stages.iter_mut().enumerate() {
                        match i.cmp(&6) {
                            std::cmp::Ordering::Less => {}
                            std::cmp::Ordering::Equal => {
                                row.state = RowState::Running;
                                row.active = true;
                                row.fraction = Some(0.45);
                                row.right_text = "45%".into();
                                row.result = None;
                                row.result_text.clear();
                                row.short_finding.clear();
                                row.duration.clear();
                            }
                            std::cmp::Ordering::Greater => {
                                row.state = RowState::Pending;
                                row.active = false;
                                row.fraction = None;
                                row.right_text = i18n::t(self.language).expc_state_labels
                                    [details::StageState::Waiting.index()]
                                .into();
                                row.result = None;
                                row.result_text.clear();
                                row.short_finding.clear();
                                row.duration.clear();
                            }
                        }
                    }
                }
                // The curated fixture passport stays (no live collector in
                // reference mode).
                vm
            }
            _ => {
                vm.page = Page::Hardware;
                vm.sensors = self.sensors_vm();
                vm.crash = self.crash_vm();
                vm.smart = self.smart_rows();
                vm.system_state = self.system_state_vm();
                vm
            }
        }
    }
}

fn qa_summary(read: f64, write: f64, rspread: f64, wspread: f64) -> StorageDiagnosticSummary {
    StorageDiagnosticSummary {
        profile: crate::storage_benchmark::StorageDiagnosticProfile {
            block_size: 1024 * 1024,
            queue_depth: 4,
            test_file_size: 512 * 1024 * 1024,
            pass_count: 4,
            stable_spread_limit_percent: 5.0,
        },
        preparation_method: "qa",
        preparation_elapsed: Duration::from_secs(0),
        summary_read_mib_s: read,
        summary_write_mib_s: write,
        read_min_mib_s: read * 0.99,
        read_max_mib_s: read * 1.01,
        write_min_mib_s: write * 0.9,
        write_max_mib_s: write * 1.05,
        read_variation_percent: rspread,
        write_variation_percent: wspread,
        stable: rspread <= 5.0 && wspread <= 5.0,
        raw_passes: Vec::new(),
    }
}

fn qa_snapshot() -> sensors::Snapshot {
    sensors::Snapshot {
        captured_at: "2026-10-06T11:00:00".into(),
        samples: 10,
        interval_ms: 1000,
        sensors: sensors::fixture::sample(&sensors::fixture::msi_reference()),
        providers: vec![sensors::ProviderReport {
            provider: sensors::Provider::LhmInternal,
            state: sensors::ProviderState::Partial,
            detail: "PawnIO low-level driver not installed".into(),
        }],
        process_context: Some(sensors::ProcessContext {
            timestamp: "2026-10-06T11:00:03".into(),
            system_cpu_percent: 91.0,
            logical_processors: 24,
            high_load: true,
            top: vec![
                sensors::ProcessSample {
                    name: "MsMpEng".into(),
                    pid: 4120,
                    cpu_percent: 38.5,
                },
                sensors::ProcessSample {
                    name: "chrome".into(),
                    pid: 9932,
                    cpu_percent: 22.1,
                },
                sensors::ProcessSample {
                    name: "powershell".into(),
                    pid: 11804,
                    cpu_percent: 7.4,
                },
            ],
        }),
    }
}

fn qa_ata_disks() -> Vec<AtaDisk> {
    let smart = |temp: u64, hours: u64| crate::ata_smart::AtaSmart {
        state: crate::ata_smart::AtaState::Ok,
        detail: String::new(),
        attributes: vec![
            crate::ata_smart::Attribute {
                id: 5,
                current: 100,
                worst: 100,
                threshold: Some(50),
                raw: 0,
            },
            crate::ata_smart::Attribute {
                id: 9,
                current: 12,
                worst: 12,
                threshold: Some(0),
                raw: hours,
            },
            crate::ata_smart::Attribute {
                id: 194,
                current: 100,
                worst: 100,
                threshold: Some(0),
                raw: temp,
            },
            crate::ata_smart::Attribute {
                id: 197,
                current: 100,
                worst: 100,
                threshold: Some(0),
                raw: 0,
            },
        ],
    };
    vec![
        AtaDisk {
            index: 0,
            model: "TOSHIBA DT02ABA400".into(),
            bus: "SATA".into(),
            smart: smart(28, 35_559),
        },
        AtaDisk {
            index: 1,
            model: "TOSHIBA DT02ABA400".into(),
            bus: "SATA".into(),
            smart: smart(25, 35_574),
        },
        AtaDisk {
            index: 2,
            model: "ST2000VX017-3CV102".into(),
            bus: "SATA".into(),
            smart: smart(32, 10_598),
        },
    ]
}

fn qa_audit() -> AuditReport {
    AuditReport {
        generated: "2026-10-06T10:48:19".into(),
        window_days: 30,
        complete: true,
        devices_scanned: 169,
        overall: Severity::Ok,
        items: Vec::new(),
        unattributed: Vec::new(),
        software_findings: Vec::new(),
        expected_inactive: Vec::new(),
        errors: Vec::new(),
    }
}

pub(super) fn qa_inventory() -> crash_dump::Inventory {
    crash_dump::Inventory {
        bugchecks: vec![crash_dump::BugcheckEvent {
            time: "2026-10-03T00:34:42".into(),
            source: crash_dump::BugcheckSource::Wer1001,
            code: 0x139,
            params: vec![3, 0, 0, 0],
            dump_path: Some("C:\\Windows\\Minidump\\100326-9500-01.dmp".into()),
        }],
        dumps: vec![qa_dump()],
        debugger: crash_dump::DebuggerStatus::Installed {
            cdb: "cdbX64.exe".into(),
        },
        notes: Vec::new(),
        unexpected_shutdowns: 1,
        incidents: Vec::new(),
        live_kernel_reports: Vec::new(),
    }
}

fn qa_dump() -> crash_dump::DumpFile {
    crash_dump::DumpFile {
        path: "C:\\Windows\\Minidump\\100326-9500-01.dmp".into(),
        name: "100326-9500-01.dmp".into(),
        size: 2_621_440,
        modified: "2026-10-03T00:34:41".into(),
        kind: crash_dump::DumpKind::Mini,
    }
}

/// The client case "C1" 0x139 case as the debugger reports it (QA fixture).
pub(super) const CASE_0X139_ANALYZE: &str = r#"
*******************************************************************************
*                                                                             *
*                        Bugcheck Analysis                                    *
*                                                                             *
*******************************************************************************

KERNEL_SECURITY_CHECK_FAILURE (139)
A kernel component has corrupted a critical data structure.
Arguments:
Arg1: 0000000000000003, A LIST_ENTRY has been corrupted (i.e. double remove).
Arg2: ffffd30c7a5e6f10, Address of the trap frame for the exception that caused the BugCheck
Arg3: ffffd30c7a5e6e68, Address of the exception record for the exception that caused the BugCheck
Arg4: 0000000000000000, Reserved

BUGCHECK_CODE:  139

BUGCHECK_P1: 3

PROCESS_NAME:  RvControlSvc.e

STACK_TEXT:
ffffd30c`7a5e6c08 fffff806`2a1c4ea9     : 00000000`00000139 00000000`00000003 : nt!KeBugCheckEx
ffffd30c`7a5e6c10 fffff806`2a1c53b2     : 00000000`00000000 00000000`00000000 : nt!KiBugCheckDispatch+0x69
ffffd30c`7a5e6d50 fffff806`2a1c2f3d     : ffffb808`11d2a1a0 00000000`00000000 : nt!KiFastFailDispatch+0xb2
ffffd30c`7a5e6f30 fffff806`4c7f1a2e     : ffffb808`11d2a1a0 ffffb808`0f4c2000 : nt!KiRaiseSecurityCheckFailure+0x33d
ffffd30c`7a5e70c8 fffff806`4c7f2f11     : 00000000`00000000 00000000`00000000 : RvNetMP60+0x2572
ffffd30c`7a5e70d0 fffff806`4c7f0b12     : 00000000`00000000 00000000`00000000 : RvNetMP60+0x2f11

SYMBOL_NAME:  RvNetMP60+2572

MODULE_NAME: RvNetMP60

IMAGE_NAME:  RvNetMP60.sys

FAILURE_BUCKET_ID:  0x139_3_CORRUPT_LIST_ENTRY_RvNetMP60!unknown_function

Followup:     MachineOwner
---------
"#;

fn qa_analysis() -> crash_dump::DumpAnalysis {
    let bc = qa_inventory().bugchecks.into_iter().next();
    crash_dump::DumpAnalysis::build(
        qa_dump(),
        bc,
        crash_dump::AnalysisStatus::Completed,
        CASE_0X139_ANALYZE.to_string(),
        Some(&qa_audit()),
    )
    .with_module(
        Some(crash_dump::ModuleInfo {
            module: "rvnetmp60".into(),
            image_name: "RvNetMP60.sys".into(),
            image_path: "\\SystemRoot\\System32\\drivers\\RvNetMP60.sys".into(),
            timestamp: "Thu Mar 14 10:21:44 2024".into(),
            file_version: String::new(),
            product_version: String::new(),
            company: String::new(),
            product_name: String::new(),
            file_description: String::new(),
            raw: "start             end                 module name\nfffff806`4c7f0000 fffff806`4c80a000   RvNetMP60   (no symbols)\n    Image path: \\SystemRoot\\System32\\drivers\\RvNetMP60.sys\n    Image name: RvNetMP60.sys\n    Timestamp:        Thu Mar 14 10:21:44 2024".into(),
        }),
        Some(crash_dump::DriverResolution {
            module: "rvnetmp60".into(),
            present: true,
            file: "C:\\Windows\\System32\\drivers\\RvNetMP60.sys".into(),
            file_version: "6.0.0.12".into(),
            company: "Famatech Corp.".into(),
            product: "Radmin VPN".into(),
            signature_status: "Valid".into(),
            signer: "CN=Famatech Corp.".into(),
            service_name: "RvNetMP60".into(),
            service_display: "Virtual network miniport".into(),
            service_state: "Running".into(),
            start_mode: "Manual".into(),
            inf: "oem42.inf".into(),
            provider: "Famatech".into(),
            devices: vec![crash_dump::ResolvedDevice {
                name: "Virtual Network Adapter".into(),
                status: "OK".into(),
                present: true,
                problem_code: None,
            }],
        }),
    )
}

fn qa_vss_aggregates() -> Vec<events::Aggregate> {
    let raw = |p: &str, id: u32, t: &str, m: &str| events::RawEvent {
        log: "System".into(),
        provider: p.into(),
        id,
        time: t.into(),
        message: m.into(),
        data: Vec::new(),
        ..Default::default()
    };
    let mut evs = Vec::new();
    for d in 1..=11 {
        evs.push(raw(
            "volsnap",
            33,
            &format!("2026-10-{:02}T03:00:00", (d % 6) + 1),
            "The oldest shadow copy of volume C: was deleted to keep disk space usage for shadow copies of volume C: below the user defined limit.",
        ));
    }
    for d in 1..=28 {
        evs.push(raw(
            "volsnap",
            33,
            &format!("2026-09-{:02}T03:00:00", (d % 22) + 8),
            "The oldest shadow copy of volume C: was deleted to keep disk space usage for shadow copies of volume C: below the user defined limit.",
        ));
    }
    events::aggregate(&evs, &[], "2026-10-06T10:00:00")
}

#[cfg(test)]
mod case_0x139_regression {
    use super::*;

    /// v1.0 item 44: client case "C1" 0x139 / RvNetMP60 (synthetic fixture of
    /// the real case): the report names the third-party driver, its
    /// service and the corroborating evidence; ntoskrnl is never blamed.
    #[test]
    fn client_0x139_rvnetmp60_report_names_the_driver() {
        let a = qa_analysis();
        assert_eq!(a.bugcheck_code(), Some(0x139));
        assert_eq!(a.third_party_module().as_deref(), Some("rvnetmp60"));
        assert!(
            a.parsed
                .failure_bucket_id
                .as_deref()
                .is_some_and(|b| b.contains("CORRUPT_LIST_ENTRY_RvNetMP60"))
        );
        let inv = qa_inventory();
        let r = crate::crash_report::build(&inv, std::slice::from_ref(&a), true);
        assert_eq!(r.level, crate::crash_report::Level::Problem);
        assert!(
            r.cause[0].contains("RvNetMP60.sys / Radmin VPN"),
            "{:?}",
            r.cause
        );
        assert!(r.cause[0].contains("MEDIUM"), "{:?}", r.cause);
        assert!(
            r.cause.iter().any(|c| c.contains("Служба RvNetMP60")),
            "{:?}",
            r.cause
        );
        assert!(
            r.why.iter().any(|w| w == "SYMBOL_NAME: RvNetMP60+2572"),
            "{:?}",
            r.why
        );
        assert!(
            r.why.iter().any(|w| w == "PROCESS_NAME: RvControlSvc.e"),
            "{:?}",
            r.why
        );
        assert!(
            r.why.iter().any(|w| w.contains("исторический")),
            "{:?}",
            r.why
        );
        assert!(
            r.checks[0].contains("RvNetMP60.sys (Radmin VPN)"),
            "{:?}",
            r.checks
        );
        assert_eq!(r.incidents.len(), 1);
        assert_eq!(r.incidents[0].code, "0x00000139");
        assert_eq!(r.incidents[0].dump, "100326-9500-01.dmp");
        assert!(!r.cause.iter().any(|c| c.contains("ntoskrnl")));
        // Same counters in the card format and the report.
        assert_eq!(
            r.counters,
            crate::crash_report::Counters::of(&inv),
            "one normalized source"
        );
    }
}

/// v1.0 GUI polish (approved references): Disk Details tables, Crash
/// Analyzer sections and the stage-table geometry, rendered from the QA
/// fixtures with the real window code.
#[cfg(test)]
mod polish_tests {
    use super::*;

    fn qa_app(tag: &str) -> WinStateDiagApp {
        let exe = std::env::temp_dir()
            .join(format!("wsd-polish-{tag}-{}", std::process::id()))
            .join("WinStateDiag");
        let _ = std::fs::remove_dir_all(exe.parent().unwrap());
        std::fs::create_dir_all(&exe).unwrap();
        let mut app = WinStateDiagApp::default();
        app.reports_root = exe.join("Reports");
        app.language_pref_dir = exe.clone();
        app.language = Language::Ru;
        app.package = Arc::new(Mutex::new(SessionPackage::new(exe.join("Reports"), None)));
        app
    }

    fn texts(app: &mut WinStateDiagApp, draw: fn(&mut WinStateDiagApp, &egui::Context)) -> String {
        let ctx = egui::Context::default();
        crate::ui::fonts::install(&ctx);
        let mut acc = String::new();
        for _ in 0..6 {
            let mut out = ctx.run_ui(
                egui::RawInput {
                    screen_rect: Some(Rect::from_min_size(egui::Pos2::ZERO, vec2(1400.0, 1200.0))),
                    ..Default::default()
                },
                |ui| draw(app, ui.ctx()),
            );
            out.textures_delta.clear();
            fn walk(shape: &egui::Shape, acc: &mut String) {
                match shape {
                    egui::Shape::Text(t) => {
                        acc.push_str(t.galley.text());
                        acc.push('\n');
                    }
                    egui::Shape::Vec(v) => v.iter().for_each(|s| walk(s, acc)),
                    _ => {}
                }
            }
            acc.clear();
            for c in &out.shapes {
                walk(&c.shape, &mut acc);
            }
        }
        acc
    }

    #[test]
    fn disk_details_show_disk_performance_and_controller_tables() {
        let mut app = qa_app("disk");
        app.seed_qa_scene("disk-details");
        let shown = texts(&mut app, |a, c| a.raw_passes_window(c));
        let d = i18n::t(Language::Ru);
        for t in [
            d.disk_det_identity,
            d.disk_det_subtitle,
            d.disk_det_performance,
            d.nvme_health_title,
            d.journal_viewer_copy,
            d.details_save_as,
            d.journal_viewer_close,
        ] {
            assert!(shown.contains(t), "{t} in {shown}");
        }
        for h in d.disk_det_perf_header {
            assert!(shown.contains(h), "{h}");
        }
        // Real fixture values (Test 1 / Test 2), never invented ones.
        assert!(shown.contains("12268"), "Test 1 read in MB/s: {shown}");
        assert!(
            shown.contains("UNSTABLE") && shown.contains("ACCEPT"),
            "{shown}"
        );
        assert!(shown.contains("PhysicalDrive3"));
        assert!(
            !shown.contains("(пример)") && !shown.contains("S7PNJ0X"),
            "no reference values"
        );
        let rows = app.disk_performance_rows(&qa_summary(1.0, 1.0, 1.0, 1.0));
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1].cells[0], d.test2_title);
    }

    #[test]
    fn crash_analyzer_has_all_sections_and_collapsed_windbg_data() {
        let mut app = qa_app("crash");
        app.seed_qa_scene("crash-analyzer");
        let shown = texts(&mut app, |a, c| a.crash_details_window(c));
        let d = i18n::t(Language::Ru);
        let mut last = 0;
        for t in [
            d.crash_sec_state,
            d.crash_sec_found,
            d.crash_sec_incidents,
            d.crash_sec_cause,
            d.crash_sec_why,
            d.crash_sec_check,
        ] {
            let at = shown.find(t).unwrap_or_else(|| panic!("{t} in {shown}"));
            assert!(at >= last, "section order: {t}");
            last = at;
        }
        // The expandable WinDbg section follows the summary (it may be
        // scrolled out of view with taller system fonts).
        if let Some(at) = shown.find(d.crash_sec_dumps) {
            assert!(at >= last, "WinDbg data after the summary");
        }
        assert!(
            !shown.contains("STACK_TEXT"),
            "WinDbg technical data stays collapsed by default"
        );
        assert!(
            shown.contains("SYMBOL_NAME: RvNetMP60+2572"),
            "why lines shown"
        );
    }

    #[test]
    fn stage_table_columns_leave_room_for_percent_and_finding() {
        let x0 = 0.0;
        let c = crate::ui::pages::stage_table_columns(x0);
        assert!(c.windows(2).all(|w| w[0] < w[1]));
        assert!(c[3] - c[2] >= 110.0, "execution column holds bar + percent");
        assert!(
            c[4] - c[3] <= 90.0,
            "result is a compact indicator (+ header)"
        );
        assert!(c[5] - c[4] >= 160.0, "finding gains the freed width");
        let card_w = crate::ui::tokens::layout::STAGE_TABLE_CARD[2];
        assert!(
            16.0 + c[5] + 70.0 <= card_w - 92.0,
            "time column clear of the Details button"
        );
    }
}
