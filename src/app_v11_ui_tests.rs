//! v1.1 UI contract recovery — regression tests (docs/UI_CONTRACT_V1_1.md):
//! page A/B block order and yellow indices, CryptoPro card ReHash and
//! licence Copy, Group Policy «НЕ ПРИМЕНИМО», journal «Папка» violet,
//! passport identity palette, finished-run verdict colour.

use super::v11::{passport_row_color, passport_value_color};
use super::*;
use crate::ui::dashboard::{block_index_badge, block_index_rects, block_rects};
use crate::ui::tokens::{CANVAS_H, CANVAS_W, layout as l};
use crate::ui::vm::BlockId;

#[test]
fn phase06_driver_card_friendly_name_compatibility_and_incomplete() {
    let mut report = crate::details::tests::report();
    report.items.truncate(1);
    report.items[0].device = "Intel Arc Graphics".into();
    report.items[0].version = "Windows 10 / Windows 11".into();
    report.items[0].status = Severity::Incomplete;
    report.overall = Severity::Incomplete;
    let DriversVm::Done { rows, overall, .. } = drivers_vm(&report, &i18n::RU) else {
        panic!("done")
    };
    assert_eq!(rows[0].name, "Intel Arc Graphics");
    assert_eq!(rows[0].version, i18n::RU.driver_na);
    assert_eq!(rows[0].tone, Tone::Warning);
    assert_eq!(overall, Tone::Warning);
    assert_eq!(report.items[0].version, "Windows 10 / Windows 11");
    report.items[0].pnp_id = r"PCI\VEN_8086&DEV_1234".into();
    report.items[0].device = report.items[0].pnp_id.clone();
    report.items[0].label.clear();
    let DriversVm::Done { rows, .. } = drivers_vm(&report, &i18n::RU) else {
        panic!("done")
    };
    assert!(!rows[0].name.trim().is_empty());
    assert!(!rows[0].name.contains("VEN_8086"));
    assert_eq!(report.items[0].device, report.items[0].pnp_id, "raw kept");
}

#[test]
fn phase06_retest_highlights_frame_without_inventing_countdown() {
    use crate::ui::vm::TestBlockVm;
    let (mut app, exe) = app_in("retest-polish");
    let vm = app.build_vm(0.0, 0.0);
    let frame = Rect::from_min_size(egui::pos2(20.0, 20.0), vec2(600.0, 200.0));
    for (block, busy, caption) in [
        (
            TestBlockVm::Waiting(Some("00:17".into())),
            true,
            Some("00:17"),
        ),
        (
            TestBlockVm::Active {
                read: None,
                write: None,
                elapsed: "00:09".into(),
            },
            true,
            None,
        ),
        (TestBlockVm::Waiting(None), false, None),
    ] {
        let ctx = egui::Context::default();
        crate::ui::fonts::install(&ctx);
        let mut out = ctx.run_ui(egui::RawInput::default(), |ui| {
            crate::ui::pages::draw_test_block_pair(
                ui.painter(),
                frame,
                &vm,
                &[TestBlockVm::Waiting(None), block.clone()],
                true,
            );
        });
        out.textures_delta.clear();
        let highlighted = out.shapes.iter().any(|s| {
            matches!(&s.shape, egui::Shape::Rect(r)
            if r.rect == frame && r.fill == c::YELLOW_WARNING.gamma_multiply(0.12))
        });
        assert_eq!(highlighted, busy);
        let indicator = out.shapes.iter().any(|s| {
            matches!(&s.shape, egui::Shape::Circle(circ)
            if circ.fill == c::YELLOW_WARNING)
        });
        assert_eq!(indicator, busy);
        let shown = out
            .shapes
            .iter()
            .filter_map(|s| {
                if let egui::Shape::Text(t) = &s.shape {
                    Some(t.galley.text().to_string())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        assert_eq!(shown.iter().any(|s| s.contains("00:17")), caption.is_some());
    }
    cleanup(&exe);
}

fn app_in(tag: &str) -> (WinStateDiagApp, PathBuf) {
    let exe = std::env::temp_dir()
        .join(format!("wsd-v11ui-{tag}-{}", std::process::id()))
        .join("WinStateDiag");
    let _ = std::fs::remove_dir_all(exe.parent().unwrap());
    std::fs::create_dir_all(&exe).unwrap();
    let mut app = WinStateDiagApp::default();
    app.reports_root = exe.join("Reports");
    app.language_pref_dir = exe.clone();
    app.language = Language::Ru;
    app.package = Arc::new(Mutex::new(SessionPackage::new(exe.join("Reports"), None)));
    (app, exe)
}

fn cleanup(exe: &Path) {
    let _ = std::fs::remove_dir_all(exe.parent().unwrap());
}

fn texts(ctx: &egui::Context, mut f: impl FnMut(&mut egui::Ui)) -> Vec<String> {
    let input = egui::RawInput {
        screen_rect: Some(Rect::from_min_size(egui::Pos2::ZERO, vec2(1400.0, 1200.0))),
        ..Default::default()
    };
    let mut out = ctx.run_ui(input, |ui| f(ui));
    out.textures_delta.clear();
    fn walk(shape: &egui::Shape, acc: &mut Vec<String>) {
        match shape {
            egui::Shape::Text(t) => acc.push(t.galley.text().to_string()),
            egui::Shape::Vec(v) => v.iter().for_each(|s| walk(s, acc)),
            _ => {}
        }
    }
    let mut acc = Vec::new();
    for c in &out.shapes {
        walk(&c.shape, &mut acc);
    }
    acc
}

/// Text shapes with their rects from one dashboard frame (body origin 0).
fn dashboard_shapes(app: &mut WinStateDiagApp) -> Vec<(String, Rect)> {
    let ctx = egui::Context::default();
    crate::ui::fonts::install(&ctx);
    let vm = app.build_vm(0.0, 0.0);
    let mut actions = Vec::new();
    let (mut client, mut mode, mut deep, mut hw, mut bench) = (
        app.client_name.clone(),
        app.mode,
        app.deep_checks,
        app.include_hardware,
        app.benchmark_path.clone(),
    );
    let input = egui::RawInput {
        screen_rect: Some(Rect::from_min_size(egui::Pos2::ZERO, vec2(1400.0, 1200.0))),
        ..Default::default()
    };
    let out = ctx.run_ui(input, |ui| {
        let mut controls = Controls {
            client_name: &mut client,
            mode: &mut mode,
            deep_checks: &mut deep,
            include_hardware: &mut hw,
            benchmark_path: &mut bench,
        };
        dashboard::draw(ui, egui::Pos2::ZERO, &vm, &mut controls, &mut actions);
    });
    let mut out = out;
    out.textures_delta.clear();
    fn walk(shape: &egui::Shape, acc: &mut Vec<(String, Rect)>) {
        match shape {
            egui::Shape::Text(t) => acc.push((
                t.galley.text().to_string(),
                t.galley.rect.translate(t.pos.to_vec2()),
            )),
            egui::Shape::Vec(v) => v.iter().for_each(|s| walk(s, acc)),
            _ => {}
        }
    }
    let mut acc = Vec::new();
    for c in &out.shapes {
        walk(&c.shape, &mut acc);
    }
    acc
}

// ---------------- 2. pages A / B, order and indices ----------------

#[test]
fn page_a_starts_with_the_passport_and_ends_with_group_policy() {
    let o = crate::ui::dashboard::body_origin(egui::Pos2::ZERO);
    let a = block_rects(o, Page::Diagnostics);
    let ids: Vec<BlockId> = a.iter().map(|b| b.0).collect();
    assert_eq!(
        ids,
        [
            BlockId::Passport,
            BlockId::Client,
            BlockId::CryptoPro,
            BlockId::ExpcMode,
            BlockId::Drivers,
            BlockId::Journal,
            BlockId::GroupPolicy,
            BlockId::Overall,
            BlockId::ExpcStages,
        ]
    );
    let rect = |id: BlockId| a.iter().find(|b| b.0 == id).unwrap().1;
    // The passport is the first (top) block of the left column.
    let left: Vec<&(BlockId, Rect)> = a.iter().filter(|b| b.1.left() < 300.0).collect();
    assert!(
        left.iter()
            .all(|b| rect(BlockId::Passport).top() <= b.1.top())
    );
    // Group Policy is the bottom block of the left column (below the journal).
    assert!(
        left.iter()
            .all(|b| rect(BlockId::GroupPolicy).bottom() >= b.1.bottom())
    );
    assert!(rect(BlockId::GroupPolicy).top() > rect(BlockId::Journal).bottom());
    // Every card size is unchanged (cards are moved, never resized).
    assert_eq!(
        rect(BlockId::Passport).size(),
        vec2(l::PASSPORT_CARD[2], l::PASSPORT_CARD[3])
    );
    assert_eq!(
        rect(BlockId::Journal).size(),
        vec2(l::JOURNAL_COMPACT_CARD[2], l::JOURNAL_COMPACT_CARD[3])
    );
}

#[test]
fn both_pages_fit_the_canvas_without_overlap_and_keep_badge_room() {
    let o = crate::ui::dashboard::body_origin(egui::Pos2::ZERO);
    let canvas = Rect::from_min_size(egui::Pos2::ZERO, vec2(CANVAS_W, CANVAS_H));
    for page in [Page::Diagnostics, Page::Hardware] {
        let blocks = block_rects(o, page);
        for (i, (a, ra)) in blocks.iter().enumerate() {
            assert!(canvas.contains_rect(*ra), "{a:?} leaves the canvas");
            let badge = block_index_badge(*ra);
            assert!(canvas.contains_rect(badge), "{a:?} badge leaves the canvas");
            for (b, rb) in blocks.iter().skip(i + 1) {
                let inter = ra.intersect(*rb);
                assert!(
                    inter.width() <= 0.0 || inter.height() <= 0.0,
                    "{a:?} overlaps {b:?}"
                );
                // A badge never covers another card.
                let bi = badge.intersect(*rb);
                assert!(
                    bi.width() <= 0.0 || bi.height() <= 0.0,
                    "{a:?} badge covers {b:?}"
                );
            }
        }
    }
}

#[test]
fn block_indices_are_a1_to_a9_and_b1_to_b6_in_reading_order() {
    let o = egui::Pos2::ZERO;
    let a: Vec<String> = block_index_rects(o, Page::Diagnostics)
        .into_iter()
        .map(|x| x.0)
        .collect();
    assert_eq!(a, ["A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8", "A9"]);
    let b: Vec<String> = block_index_rects(o, Page::Hardware)
        .into_iter()
        .map(|x| x.0)
        .collect();
    assert_eq!(b, ["B1", "B2", "B3", "B4", "B5", "B6"]);
    let hw = block_rects(o, Page::Hardware);
    assert_eq!(hw[0].0, BlockId::HardwareReport);
    assert_eq!(hw[5].0, BlockId::CrashAnalyzer);
}

#[test]
fn the_dashboard_draws_the_indices_and_the_moved_cards() {
    let (mut app, exe) = app_in("draw");
    app.page = Page::Diagnostics;
    let shapes = dashboard_shapes(&mut app);
    for i in 1..=9 {
        assert!(shapes.iter().any(|s| s.0 == format!("A{i}")), "A{i}");
    }
    assert!(!shapes.iter().any(|s| s.0 == "B1"));
    let y = |needle: &str| {
        shapes
            .iter()
            .find(|s| s.0 == needle)
            .map(|s| s.1.top())
            .unwrap_or_else(|| panic!("{needle} not drawn"))
    };
    let d = &i18n::RU;
    // Passport title above the client label; GPO row label below the journal.
    assert!(y(d.passport_title) < y("Клиент"));
    assert!(y(d.gpo_row_label) > y(d.journal_title));
    app.page = Page::Hardware;
    let shapes = dashboard_shapes(&mut app);
    for i in 1..=6 {
        assert!(shapes.iter().any(|s| s.0 == format!("B{i}")), "B{i}");
    }
    cleanup(&exe);
}

// ---------------- 3. CryptoPro card / Details ----------------

fn crypto_installed(app: &mut WinStateDiagApp, license: cryptopro::LicenseKey) {
    app.crypto_inventory = Some(cryptopro::Inventory {
        product: Some(cryptopro::CspProduct {
            name: "КриптоПро CSP".into(),
            version: "5.0.13800".into(),
            product_code: "{50F91F80-D397-437C-B0C8-62128DE3B55E}".into(),
            license,
            term: cryptopro::LicenseTerm::NotDetermined,
        }),
    });
    app.crypto_detection = cryptopro::Detection::Installed(PathBuf::from(
        "C:\\Program Files (x86)\\Crypto Pro\\CSP\\cpverify.exe",
    ));
}

fn full_key() -> cryptopro::LicenseKey {
    cryptopro::LicenseKey::Installed {
        masked: "5050Z-*****".into(),
        full: cryptopro::SerialKey::new("5050Z-ABCDE-FGHIJ-KLMNO-PQRST"),
    }
}

#[test]
fn crypto_card_shows_csp_hash_and_a_round_rehash_only_for_no_hash() {
    let (mut app, exe) = app_in("cryptocard");
    crypto_installed(&mut app, full_key());
    app.crypto = Some(cryptopro::HashState::HashOk);
    let vm = app.build_vm(0.0, 0.0);
    assert_eq!(vm.crypto_csp, "CSP 5.0.13800");
    assert!(!vm.crypto_rehash_enabled, "HASH OK: nothing to re-hash");
    app.crypto = Some(cryptopro::HashState::NoHash);
    assert!(app.build_vm(0.0, 0.0).crypto_rehash_enabled);
    // Never while a check / ReHash is running.
    let (_tx, rx) = std::sync::mpsc::channel();
    app.crypto_rx = Some(rx);
    assert!(!app.build_vm(0.0, 0.0).crypto_rehash_enabled);
    app.crypto_rx = None;
    // Not installed → «CSP не установлен», no ReHash.
    app.crypto_inventory = Some(cryptopro::Inventory { product: None });
    app.crypto = Some(cryptopro::HashState::NotInstalled);
    let vm = app.build_vm(0.0, 0.0);
    assert_eq!(vm.crypto_csp, i18n::RU.crypto_card_csp_absent);
    assert!(!vm.crypto_rehash_enabled);
    // The card draws «CSP …» and the «#» button.
    crypto_installed(&mut app, full_key());
    app.crypto = Some(cryptopro::HashState::NoHash);
    let shapes = dashboard_shapes(&mut app);
    assert!(shapes.iter().any(|s| s.0 == "CSP 5.0.13800"));
    assert!(shapes.iter().any(|s| s.0 == "#"));
    cleanup(&exe);
}

#[test]
fn card_rehash_explicit_click_no_modal_success_and_failure() {
    let (mut app, exe) = app_in("cryptoflow");
    crypto_installed(&mut app, full_key());
    app.crypto = Some(cryptopro::HashState::NoHash);
    assert!(!app.collector_requests.contains(&"cryptopro_rehash"));
    // Click starts the worker directly; Details and confirmation stay closed.
    app.apply(Action::CryptoRehashRequest);
    assert!(!app.crypto_rehash_confirm);
    assert!(!app.crypto_details_open);
    let ctx = egui::Context::default();
    crate::ui::fonts::install(&ctx);
    let mut shown = Vec::new();
    for _ in 0..3 {
        shown = texts(&ctx, |ui| app.crypto_rehash_confirm_window(ui.ctx()));
    }
    assert!(shown.is_empty(), "no extra confirmation: {shown:?}");
    // Double click must not start a second worker.
    app.apply(Action::CryptoRehashRequest);
    assert_eq!(
        app.collector_requests
            .iter()
            .filter(|r| **r == "cryptopro_rehash")
            .count(),
        1
    );
    assert!(app.collector_requests.contains(&"cryptopro_rehash"));
    assert!(
        app.crypto_rx.is_some(),
        "runs on its worker, not the UI thread"
    );
    // ReHash success / failure are decided by the re-verification (cpverify
    // -rv after -rm) — covered by cryptopro::tests t05 / t06; the card and
    // Details read the same `self.crypto` result.
    app.crypto_rx = None;
    app.crypto = Some(cryptopro::HashState::HashOk);
    let vm = app.build_vm(0.0, 0.0);
    assert_eq!(vm.crypto, CryptoVm::HashOk);
    assert!(
        app.crypto_detail_rows()
            .iter()
            .any(|r| r.value == "HASH OK")
    );
    app.crypto = Some(cryptopro::HashState::CheckError(
        "cpverify -rm: код 1".into(),
    ));
    assert_eq!(app.build_vm(0.0, 0.0).crypto, CryptoVm::CheckError);
    assert!(
        app.crypto_detail_rows()
            .iter()
            .any(|r| r.value.contains("cpverify -rm: код 1"))
    );
    cleanup(&exe);
}

#[test]
fn details_show_the_full_licence_number_with_an_exact_copy() {
    let (mut app, exe) = app_in("licence");
    crypto_installed(&mut app, full_key());
    let rows = app.crypto_detail_rows();
    let lic = rows
        .iter()
        .find(|r| r.label == i18n::RU.crypto_det_license)
        .unwrap();
    assert_eq!(lic.value, "5050Z-ABCDE-FGHIJ-KLMNO-PQRST");
    assert_eq!(lic.copy.as_deref(), Some("5050Z-ABCDE-FGHIJ-KLMNO-PQRST"));
    // The row's own Copy puts exactly the number on the clipboard.
    let ctx = egui::Context::default();
    app.copy_licence_number(&ctx, lic.copy.as_ref().unwrap());
    assert_eq!(
        app.clipboard_out.as_deref(),
        Some("5050Z-ABCDE-FGHIJ-KLMNO-PQRST")
    );
    // The window-wide Copy text and the journal keep the masked form only.
    let all = app.crypto_details_text();
    assert!(
        all.contains("5050Z-*****") && !all.contains("ABCDE"),
        "{all}"
    );
    let journal = app.crypto_inventory.as_ref().unwrap().journal().join("\n");
    assert!(!journal.contains("ABCDE"));
    // The Details window draws the number and the Copy button.
    app.crypto_details_open = true;
    crate::ui::fonts::install(&ctx);
    let mut shown = Vec::new();
    for _ in 0..3 {
        shown = texts(&ctx, |ui| app.crypto_details_window(ui.ctx()));
    }
    assert!(shown.iter().any(|t| t == "5050Z-ABCDE-FGHIJ-KLMNO-PQRST"));
    assert!(
        !shown
            .iter()
            .any(|t| t == i18n::RU.crypto_license_copy || t == "Копировать")
    );
    assert!(!shown.iter().any(|t| t == i18n::RU.crypto_det_errors));
    assert!(!shown.iter().any(|t| t == i18n::RU.crypto_det_term));
    assert!(
        !shown
            .iter()
            .any(|t| t == i18n::RU.crypto_rehash_from_card_note)
    );
    assert!(!shown.iter().any(|t| t == i18n::RU.journal_viewer_close));
    // Term only from a reliable source: never guessed.
    assert!(
        app.crypto_detail_rows()
            .iter()
            .any(|r| r.value == i18n::RU.crypto_det_term_unknown)
    );
    cleanup(&exe);
}

#[test]
fn missing_or_unreadable_licence_is_said_plainly_without_a_copy_button() {
    let (mut app, exe) = app_in("licence2");
    crypto_installed(&mut app, cryptopro::LicenseKey::NotFound);
    let lic = app
        .crypto_detail_rows()
        .into_iter()
        .find(|r| r.label == i18n::RU.crypto_det_license)
        .unwrap();
    assert_eq!(lic.value, i18n::RU.crypto_det_license_none);
    assert_eq!(lic.tone, Tone::Warning);
    assert!(lic.copy.is_none());
    crypto_installed(
        &mut app,
        cryptopro::LicenseKey::Unreadable("доступ к реестру запрещён (код 5)".into()),
    );
    let lic = app
        .crypto_detail_rows()
        .into_iter()
        .find(|r| r.label == i18n::RU.crypto_det_license)
        .unwrap();
    assert!(lic.value.contains("код 5"), "{}", lic.value);
    assert_ne!(
        lic.value,
        i18n::RU.crypto_det_license_none,
        "not 'not found'"
    );
    assert!(lic.copy.is_none());
    cleanup(&exe);
}

// ---------------- 4. Group Policy ----------------

#[test]
fn group_policy_not_applicable_is_amber_and_distinct_from_no_data_and_errors() {
    let (mut app, exe) = app_in("gpo");
    // Not run → NO DATA (neutral).
    assert_eq!(app.build_vm(0.0, 0.0).gpo.tone, Tone::Idle);
    // Standalone PC → «НЕ ПРИМЕНИМО», amber, never green.
    let inputs = gpo_admx::GpoInputs {
        domain_joined: false,
        windows_build: "26200".into(),
        windows_release: "25H2".into(),
        ui_language: "ru-RU".into(),
        ..Default::default()
    };
    let result = gpo_admx::classify(&inputs);
    assert_eq!(result.status, gpo_admx::GpoStatus::NotApplicable);
    app.gpo = Some(Ok((inputs, result)));
    let vm = app.build_vm(0.0, 0.0).gpo;
    assert!(vm.status.starts_with("НЕ ПРИМЕНИМО"), "{}", vm.status);
    assert_eq!(vm.tone, Tone::Warning);
    // Access denied → amber «ДОСТУП ЗАПРЕЩЁН»; any other error → red.
    app.gpo = Some(Err("Get-ChildItem: Access is denied".into()));
    let vm = app.build_vm(0.0, 0.0).gpo;
    assert!(vm.status.starts_with("ДОСТУП ЗАПРЕЩЁН"), "{}", vm.status);
    assert_eq!(vm.tone, Tone::Warning);
    app.gpo = Some(Err("collector timeout".into()));
    let vm = app.build_vm(0.0, 0.0).gpo;
    assert!(vm.status.starts_with("ОШИБКА"), "{}", vm.status);
    assert_eq!(vm.tone, Tone::Error);
    // Export keeps the machine code.
    assert_eq!(gpo_admx::GpoStatus::NotApplicable.code(), "NOT APPLICABLE");
    assert_eq!(gpo_status_tone(gpo_admx::GpoStatus::Ok), Tone::Success);
    cleanup(&exe);
}

// ---------------- 5. journal «Папка» ----------------

#[test]
fn journal_folder_button_uses_the_header_tab_violet_in_every_state() {
    use crate::ui::paint::{ButtonKind, button_colors};
    use crate::ui::tokens::color as c;
    let normal = button_colors(ButtonKind::Nav, true, false, false);
    let hover = button_colors(ButtonKind::Nav, true, true, false);
    let pressed = button_colors(ButtonKind::Nav, true, true, true);
    let disabled = button_colors(ButtonKind::Nav, false, false, false);
    assert_eq!(
        normal,
        (
            egui::Color32::from_rgb(87, 48, 155),
            c::PAGE_TAB_ACTIVE_GLOW,
            c::PAGE_TAB_ACTIVE_TEXT
        )
    );
    assert_eq!(hover.1, c::PAGE_TAB_ACTIVE_GLOW);
    assert_eq!(
        pressed,
        (
            c::PAGE_TAB_ACTIVE_FILL,
            c::PAGE_TAB_ACTIVE_GLOW,
            c::PAGE_TAB_ACTIVE_TEXT
        )
    );
    assert_eq!(
        disabled,
        (normal.0, normal.1, c::BUTTON_DISABLED_TEXT),
        "disabled remains violet but cannot be clicked"
    );
    let src = include_str!("ui/pages.rs").replace("\r\n", "\n");
    let folder = &src[src
        .rfind("\"open_folder\",\n        d.report_row_folder")
        .unwrap()..];
    assert!(folder[..300].contains("ButtonKind::Nav"));
}

// ---------------- 6. passport palette ----------------

#[test]
fn passport_identity_palette_is_separate_from_state_colours() {
    use crate::passport2::{CardKind, Kind};
    use crate::ui::pages::passport_card_value_color;
    use crate::ui::tokens::color as c;
    let d = &i18n::RU;
    assert_eq!(
        passport_card_value_color(d, d.passport_windows, "Windows 11 Pro"),
        c::IDENT_WINDOWS
    );
    assert_eq!(
        passport_card_value_color(d, d.passport_cpu, "Intel(R) Core(TM) i7-14700K"),
        c::IDENT_INTEL
    );
    assert_eq!(
        passport_card_value_color(d, d.passport_cpu, "AMD Ryzen 7 7800X3D"),
        c::IDENT_AMD
    );
    assert_eq!(
        passport_card_value_color(d, d.passport_ram, "32 GB DDR5-6000"),
        c::IDENT_RAM
    );
    assert_eq!(
        passport_card_value_color(d, d.passport_board, "MSI PRO Z790-P"),
        c::IDENT_BOARD
    );
    assert_eq!(
        passport_card_value_color(d, d.passport_bios, "7E06v1A"),
        c::IDENT_BIOS
    );
    // No data / still collecting: muted, never an identity or OK colour.
    for d in [&i18n::RU, &i18n::EN] {
        assert_eq!(
            passport_card_value_color(d, d.passport_bios, d.passport_no_data),
            c::TEXT_MUTED
        );
    }
    assert_eq!(
        passport_card_value_color(d, d.passport_ram, ""),
        c::TEXT_MUTED
    );
    assert_eq!(
        passport_card_value_color(d, d.passport_ram, d.passport_collecting),
        c::TEXT_MUTED
    );
    // An incomplete inventory is a warning, not violet RAM.
    assert_eq!(
        passport_card_value_color(
            d,
            d.passport_ram,
            "≥15.9 GB · SMBIOS: 2× = 8 GB — incomplete module list"
        ),
        c::YELLOW_WARNING
    );
    // Identity colours are not status colours.
    for ident in [c::IDENT_WINDOWS, c::IDENT_AMD, c::IDENT_RAM] {
        assert_ne!(ident, c::GREEN_SUCCESS);
        assert_ne!(ident, c::RED_ERROR);
    }
    // Passport 2.0: a measurement (e.g. 95 % wear) is never healthy green.
    assert_ne!(passport_value_color(Kind::Measured), c::GREEN_SUCCESS);
    assert_eq!(
        passport_row_color(Kind::Measured, CardKind::Storage, "95 %"),
        c::PASSPORT_MEASURED
    );
    assert_eq!(
        passport_row_color(Kind::Config, CardKind::Ram, "2 × 16 GB"),
        c::IDENT_RAM
    );
    assert_eq!(
        passport_row_color(Kind::Config, CardKind::Cpu, "AMD Ryzen 9 9950X"),
        c::IDENT_AMD
    );
    assert_eq!(
        passport_row_color(Kind::Unconfirmed, CardKind::Bios, "?"),
        c::TEXT_MUTED
    );
}

// ---------------- 7. finished-run verdict ----------------

#[test]
fn finished_run_is_green_only_when_the_states_say_ok() {
    let (mut app, exe) = app_in("done");
    let d = &i18n::RU;
    app.include_hardware = false;
    // No crash inventory / no Driver Audit → incomplete, amber.
    assert_eq!(
        app.done_verdict(d),
        (d.overall_status_done_partial, Tone::Warning)
    );
    // Complete clean basis → green.
    app.crash.inventory = Some(Ok(crash_dump::Inventory {
        bugchecks: Vec::new(),
        dumps: Vec::new(),
        debugger: crash_dump::DebuggerStatus::NotInstalled,
        notes: Vec::new(),
        unexpected_shutdowns: 0,
        incidents: Vec::new(),
        live_kernel_reports: Vec::new(),
    }));
    let mut clean = crate::details::tests::report();
    clean.items.retain(|i| i.status == Severity::Ok);
    clean.overall = Severity::Ok;
    app.driver_audit = DriverAuditState::Done(Box::new(clean));
    app.expc_checks = ["SFC", "DISM", "WHEA", "VSS"]
        .into_iter()
        .map(|k| crate::deep_checks::ExpcCheck {
            key: k.into(),
            status: "OK".into(),
            detail: "fixture completed".into(),
        })
        .collect();
    assert_eq!(app.done_verdict(d), (d.overall_status_done, Tone::Success));
    // A system finding → amber «Есть замечания».
    if let Some(Ok(inv)) = &mut app.crash.inventory {
        inv.unexpected_shutdowns = 1;
    }
    assert_eq!(
        app.done_verdict(d),
        (d.overall_status_done_attention, Tone::Warning)
    );
    // The ring of a finished run takes that tone.
    app.state = RunState::Done {
        zip_path: PathBuf::from("Reports\\x.zip"),
    };
    let ring = app.build_vm(0.0, 0.0).overall;
    assert_eq!(ring.tone, Tone::Warning);
    assert_eq!(ring.status_text, d.overall_status_done_attention);
    cleanup(&exe);
}
