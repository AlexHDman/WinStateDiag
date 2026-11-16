use super::*;
fn id(model: &str, version: &str) -> Identity {
    Identity {
        system_maker: "MSI".into(),
        system_model: "MS-7D46".into(),
        board_maker: "Micro-Star International Co., Ltd.".into(),
        board_model: model.into(),
        board_revision: "1.0".into(),
        version: version.into(),
        date: "20260824000000.000000+180".into(),
        ..Default::default()
    }
}
fn msi_catalog(i: &Identity) -> Catalog {
    let p = resolve(i).unwrap();
    crate::bios_sources::msi(
        &p,
        "https://www.msi.com/api/v1/product/support/panel",
        include_str!("../scripts/fixtures/bios/msi-panel.json"),
    )
    .unwrap()
}
#[test]
fn calendar_date_no_timezone_shift() {
    for d in [
        "20260824000000.000000+840",
        "20260824000000.000000-720",
        "2026-08-24",
        "2026-08-24T00:00:00Z",
        "08/24/2026",
    ] {
        assert_eq!(date_display(d).as_deref(), Some("24.08.2026"), "{d}")
    }
}
#[test]
fn invalid_date_is_unknown() {
    for d in [
        "",
        "2026-02-29",
        "2024-02-30",
        "2026-13-01",
        "garbage",
        "/Date(0)/",
    ] {
        assert!(date_display(d).is_none(), "{d}")
    }
    assert_eq!(date_display("2024-02-29").as_deref(), Some("29.02.2024"));
}
#[test]
fn public_msi_alias_needs_exact_model_and_family() {
    let mut i = id("PRO H610M-G DDR4 (MS-7D46)", "1.R0");
    assert_eq!(confirmed_public(&i).as_deref(), Some("7D46v1R"));
    i.full_id = "E7D46IMS.AR0".into();
    assert!(confirmed_public(&i).is_none());
    i.full_id.clear();
    i.board_model = "PRO H610M-G".into();
    assert!(confirmed_public(&i).is_none());
}
#[test]
fn suffixes_oem_and_mobile_never_cross_match() {
    for model in [
        "MS-7D46",
        "PRO H610M-G WIFI DDR4",
        "PRO H610M-G DDR4 MAX",
        "PRO H610M-G DDR4 II",
    ] {
        let i = id(model, "1.R0");
        assert!(
            crate::bios_sources::check_with(&i, |_| Ok(include_str!(
                "../scripts/fixtures/bios/msi-panel.json"
            )
            .into()))
            .is_err()
        );
    }
    let mut i = id("PRO H610M-G DDR4", "1.R0");
    i.system_maker = "Dell Inc.".into();
    assert!(resolve(&i).is_err());
    i.system_maker = "MSI".into();
    i.mobile = true;
    assert!(resolve(&i).is_err());
}
#[test]
fn current_only_after_catalog_and_match() {
    let i = id("PRO H610M-G DDR4", "1.R0");
    let c = assess(&i, msi_catalog(&i));
    assert_eq!(c.verdict, Verdict::Current);
    assert_eq!(
        i.display(c.installed_public.as_deref()),
        "7D46v1R (24.08.2026)"
    );
}
#[test]
fn newer_stable_uses_vendor_order_not_date_or_string() {
    let i = id("PRO H610M-G DDR4", "1.Q0");
    let mut cat = msi_catalog(&i);
    cat.releases.reverse();
    cat.releases
        .iter_mut()
        .find(|r| r.version == "7D46v1Q")
        .unwrap()
        .date = "2099-01-01".into();
    let c = assess(&i, cat);
    assert_eq!(c.verdict, Verdict::Available);
    assert_eq!(c.latest.unwrap().version, "7D46v1R");
}
#[test]
fn missing_newer_or_foreign_installed_never_recommends_downgrade() {
    for v in ["1.Z0", "A.R0", "garbage", "7D99v1R"] {
        let i = id("PRO H610M-G DDR4", v);
        assert_eq!(
            assess(&i, msi_catalog(&i)).verdict,
            Verdict::Uncertain,
            "{v}"
        )
    }
}
#[test]
fn preview_never_replaces_stable() {
    let i = id("PRO H610M-G DDR4", "1.R0");
    let mut c = msi_catalog(&i);
    c.releases.push(Release {
        version: "7D46v1S1".into(),
        date: "2026-11-15".into(),
        channel: Channel::Beta,
        description: String::new(),
        ..Default::default()
    });
    let result = assess(&i, c);
    assert_eq!(result.verdict, Verdict::Current);
    assert_eq!(result.latest.unwrap().version, "7D46v1R");
    assert_eq!(result.preview.unwrap().version, "7D46v1S1");
}
#[test]
fn asus_official_fixture_model_and_versions() {
    let mut i = id("PRIME B760-PLUS D4", "1825");
    i.board_maker = "ASUSTeK COMPUTER INC.".into();
    i.system_maker = "ASUS".into();
    i.system_model = "System Product Name".into();
    let p = resolve(&i).unwrap();
    let raw = include_str!("../scripts/fixtures/bios/asus.json");
    let c = crate::bios_sources::asus(&p, "https://www.asus.com", raw).unwrap();
    assert_eq!(assess(&i, c).verdict, Verdict::Available);
    assert!(
        crate::bios_sources::asus(
            &p,
            "https://www.asus.com",
            &raw.replace("PRIME B760-PLUS D4", "PRIME B760-PLUS")
        )
        .is_err()
    );
}
#[test]
fn gigabyte_revision_and_catalog_identity_required() {
    let mut i = id("B760M DS3H DDR4", "F24");
    i.system_model = i.board_model.clone();
    i.board_maker = "Gigabyte Technology Co., Ltd.".into();
    i.system_maker = "Gigabyte".into();
    let p = resolve(&i).unwrap();
    let candidates = crate::bios_sources::gigabyte_candidates(
        &p,
        include_str!("../scripts/fixtures/bios-dynamic/gigabyte-products.json"),
    )
    .unwrap();
    assert_eq!(candidates.len(), 1);
    let p = candidates[0].clone();
    let c = crate::bios_sources::gigabyte(
        &p,
        "https://www.gigabyte.com",
        include_str!("../scripts/fixtures/bios/gigabyte.json"),
    )
    .unwrap();
    assert_eq!(assess(&i, c).verdict, Verdict::Available);
    for rev in ["", "1.x", "Default string"] {
        i.board_revision = rev.into();
        assert!(resolve(&i).is_err())
    }
}
#[test]
fn official_host_validation() {
    for u in [
        "http://www.msi.com/a",
        "https://www.msi.com.evil.test/a",
        "https://www.msi.com@evil.test/a",
        "https://www.msi.com:444/a",
        "https://www.msi.com\\@evil.test/a",
        "file:///x",
    ] {
        assert!(crate::bios_net::official_host(u).is_none(), "{u}")
    }
}
#[test]
fn unsupported_never_calls_network() {
    let mut i = id("Unknown board", "1.R0");
    i.board_maker = "Unsupported".into();
    let mut called = false;
    assert!(
        crate::bios_sources::check_with(&i, |_| {
            called = true;
            Ok("{}".into())
        })
        .is_err()
    );
    assert!(!called)
}
#[test]
fn invalid_server_body_never_current() {
    let i = id("PRO H610M-G DDR4", "1.R0");
    for raw in ["<html>Access denied</html>", "{}", "[]"] {
        assert!(crate::bios_sources::check_with(&i, |_| Ok(raw.into())).is_err())
    }
}
#[test]
fn update_check_does_not_change_local_date() {
    let i = id("PRO H610M-G DDR4", "1.Q0");
    let before = i.clone();
    let _ = crate::bios_sources::check_with(&i, |_| {
        Ok(include_str!("../scripts/fixtures/bios/msi-panel.json").into())
    })
    .unwrap();
    assert_eq!(i, before)
}
#[test]
fn other_msi_profiles_are_separate() {
    for (model, code, version, public, raw) in [
        (
            "PRO B760M-A DDR4",
            "7D99",
            "1.J0",
            "7D99v1J",
            include_str!("../scripts/fixtures/bios/msi-b760-panel.json"),
        ),
        (
            "MAG Z790 TOMAHAWK WIFI",
            "7D91",
            "17.I0",
            "7D91vHI",
            include_str!("../scripts/fixtures/bios/msi-z790-panel.json"),
        ),
    ] {
        let mut i = id(model, version);
        i.system_model = format!("MS-{code}");
        assert_eq!(confirmed_public(&i).as_deref(), Some(public));
        let p = resolve(&i).unwrap();
        let c = crate::bios_sources::msi(&p, "https://www.msi.com", raw).unwrap();
        assert!(assess(&i, c).installed_public.is_some())
    }
}
#[test]
#[ignore = "explicit real official HTTPS metadata smoke; no firmware download or GUI"]
fn official_https_smoke() {
    let mut cases = Vec::new();
    for (maker, model, version, rev) in [
        ("MSI", "PRO H610M-G DDR4 (MS-7D46)", "1.R0", "1.0"),
        ("MSI", "PRO Z890-P WIFI (MS-7E34)", "1.AE0", "1.0"),
        ("MSI", "B450 TOMAHAWK MAX (MS-7C02)", "3.A0", "1.0"),
        ("ASUS", "TUF GAMING B550-PLUS", "3404", "1.0"),
        ("ASUS", "PRIME B660M-K D4", "2212", "1.0"),
        ("Gigabyte", "B760M DS3H DDR4", "F24", "1.0"),
        ("Gigabyte", "B550 AORUS ELITE V2", "F1", "1.1"),
        ("ASRock", "B550M PRO4", "P3.10", "1.0"),
        ("ASRock", "B650M PG RIPTIDE", "3.10", "1.0"),
    ] {
        cases.push(Identity {
            system_maker: maker.into(),
            system_model: "System Product Name".into(),
            board_maker: maker.into(),
            board_model: model.into(),
            version: version.into(),
            board_revision: rev.into(),
            ..Default::default()
        });
    }
    let mut records = Vec::new();
    let mut errors = Vec::new();
    // Same production transport and provider pipeline; read-only metadata only.
    for i in cases {
        let cancel = std::sync::atomic::AtomicBool::new(false);
        let started = std::time::Instant::now();
        let result = crate::bios_sources::check_pages(&i, |url| {
            let budget = std::time::Duration::from_secs(60)
                .checked_sub(started.elapsed())
                .ok_or("BIOS overall timeout")?;
            crate::bios_net::fetch_page(url, &cancel, budget)
        });
        let q = crate::deep_checks::json::string;
        let outcome = match result {
            Ok(c) => {
                println!("{}: {}", i.board_model, c.label());
                c.json()
            }
            Err(e) => {
                println!("{}: {e}", i.board_model);
                errors.push(format!("{}: {e}", i.board_model));
                format!(
                    "{{\"status\":{},\"reason\":{}}}",
                    q(failure_code(&e)),
                    q(&e)
                )
            }
        };
        records.push(format!(
            "{{\"model\":{},\"result\":{outcome}}}",
            q(&i.board_model)
        ));
    }
    if let Some(path) = std::env::var_os("WSD_BIOS_NETWORK_EVIDENCE") {
        std::fs::write(path, format!("[{}]", records.join(","))).unwrap();
    }
    assert!(errors.is_empty(), "LIVE NETWORK LIMITATIONS: {errors:?}");
}

#[test]
fn public_version_cannot_hide_conflicting_full_id() {
    let mut i = id("PRO H610M-G DDR4", "7D46v1R");
    i.full_id = "E7D99IMS.1R0".into();
    assert_eq!(assess(&i, msi_catalog(&i)).verdict, Verdict::Uncertain)
}
#[test]
fn oversized_and_deep_catalogs_rejected() {
    let i = id("PRO H610M-G DDR4", "1.R0");
    for body in [
        " ".repeat(crate::bios_net::MAX_RESPONSE + 1),
        format!("{}0{}", "[".repeat(100), "]".repeat(100)),
    ] {
        assert!(crate::bios_sources::check_with(&i, |_| Ok(body.clone())).is_err())
    }
}
#[test]
fn duplicate_versions_and_invalid_dates_rejected() {
    let i = id("PRO H610M-G DDR4", "1.R0");
    let raw = include_str!("../scripts/fixtures/bios/msi-panel.json");
    for body in [
        raw.replace("7D46v1Q\"", "7D46v1R\""),
        raw.replace("2026-08-24", "2026-02-30"),
    ] {
        assert!(crate::bios_sources::check_with(&i, |_| Ok(body.clone())).is_err())
    }
}
