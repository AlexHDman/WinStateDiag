use super::*;
use crate::{bios_net::Page, bios_sources as sources};
fn id(maker: &str, model: &str, version: &str, revision: &str) -> Identity {
    Identity {
        system_maker: maker.into(),
        system_model: "System Product Name".into(),
        board_maker: maker.into(),
        board_model: model.into(),
        version: version.into(),
        board_revision: revision.into(),
        date: "20260624000000.000000+180".into(),
        ..Default::default()
    }
}
fn real_reply(i: &Identity, url: &str) -> Result<Page, String> {
    let (body, final_url) = if url.contains("GetProducts") {
        (
            include_str!("../scripts/fixtures/bios-dynamic/gigabyte-products.json"),
            url.to_string(),
        )
    } else if url.contains("product-page.aspx") {
        if url.ends_with("8701") {
            (
                include_str!("../scripts/fixtures/bios-dynamic/gigabyte-legacy.html"),
                "https://www.gigabyte.com/Motherboard/B760M-DS3H-DDR4-rev-1x".into(),
            )
        } else {
            (
                include_str!("../scripts/fixtures/bios-dynamic/gigabyte-b550-page.html"),
                "https://www.gigabyte.com/Motherboard/B550-AORUS-ELITE-V2-rev-10-11".into(),
            )
        }
    } else if url.contains("supportonly") {
        (
            if i.board_model == "TUF GAMING B550-PLUS" {
                include_str!("../scripts/fixtures/bios-dynamic/asus-b550-page.html")
            } else {
                include_str!("../scripts/fixtures/bios-dynamic/asus-b660-page.html")
            },
            url.into(),
        )
    } else {
        (
            match i.board_model.as_str() {
                "PRO Z890-P WIFI (MS-7E34)" => {
                    include_str!("../scripts/fixtures/bios-dynamic/msi-z890.json")
                }
                "B450 TOMAHAWK MAX (MS-7C02)" => {
                    include_str!("../scripts/fixtures/bios-dynamic/msi-b450.json")
                }
                "TUF GAMING B550-PLUS" => {
                    include_str!("../scripts/fixtures/bios-dynamic/asus-b550-api.json")
                }
                "PRIME B660M-K D4" => {
                    include_str!("../scripts/fixtures/bios-dynamic/asus-b660-api.json")
                }
                "B760M DS3H DDR4" => include_str!("../scripts/fixtures/bios/gigabyte.json"),
                "B550 AORUS ELITE V2" => {
                    include_str!("../scripts/fixtures/bios-dynamic/gigabyte-b550.json")
                }
                _ => return Err(format!("Unexpected fixture request: {url}")),
            },
            url.into(),
        )
    };
    Ok(Page {
        url: final_url,
        body: body.into(),
    })
}
#[test]
fn dynamic_real_official_models_outside_old_profiles() {
    let cases = [
        id("MSI", "PRO Z890-P WIFI (MS-7E34)", "1.AE0", "1.0"),
        id("MSI", "B450 TOMAHAWK MAX (MS-7C02)", "3.A0", "1.0"),
        id("ASUS", "TUF GAMING B550-PLUS", "3404", "Rev X.0x"),
        id("ASUS", "PRIME B660M-K D4", "2212", "Rev 1.xx"),
        id("Gigabyte", "B550 AORUS ELITE V2", "F1", "1.1"),
        id("Gigabyte", "B760M DS3H DDR4", "F24", "1.0"),
    ];
    for i in cases {
        let c = sources::check_pages(&i, |u| real_reply(&i, u))
            .unwrap_or_else(|e| panic!("{}: {e}", i.board_model));
        assert_eq!(
            c.verdict,
            Verdict::Available,
            "{}: {}",
            i.board_model,
            c.reason
        );
        assert!(!c.catalog.proofs.is_empty());
        assert!(!c.catalog.releases[0].package.is_empty());
        assert!(crate::deep_checks::json::parse(&c.json()).is_some());
    }
}
#[test]
fn z890_new_msi_format_and_local_date_are_proven_separately() {
    let i = id("MSI", "PRO Z890-P WIFI (MS-7E34)", "1.AE0", "1.0");
    let c = sources::check_pages(&i, |u| real_reply(&i, u)).unwrap();
    assert_eq!(c.installed_public.as_deref(), Some("7E34v1AE0"));
    assert_eq!(c.latest.unwrap().version, "7E34v1AF0");
    assert_eq!(
        i.display(c.installed_public.as_deref()),
        "7E34v1AE0 (24.06.2026)"
    );
    let r = c
        .catalog
        .releases
        .iter()
        .find(|r| r.version == "7E34v1AE0")
        .unwrap();
    assert_eq!(r.date, "2026-07-08");
    assert!(r.package.ends_with("7E34v1AE.zip"));
}
#[test]
fn variants_are_not_trimmed_or_guessed() {
    for variant in [
        "TUF GAMING B550-PLUS WIFI",
        "TUF GAMING B550-PLUS II",
        "TUF GAMING B550-PLUS MAX",
        "TUF GAMING B550-PLUS DDR4",
    ] {
        let i = id("ASUS", variant, "3404", "1.0");
        let error = sources::check_pages(&i, |u| {
            Ok(Page {
                url: u.into(),
                body: include_str!("../scripts/fixtures/bios-dynamic/asus-b550-page.html").into(),
            })
        })
        .unwrap_err();
        assert_eq!(failure_code(&error), "MODEL_AMBIGUOUS", "{error}");
    }
    let i = id("MSI", "PRO Z890-P WIFI (MS-7D46)", "1.AE0", "1.0");
    assert!(
        sources::check_with(&i, |_| Ok(include_str!(
            "../scripts/fixtures/bios-dynamic/msi-z890.json"
        )
        .into()))
        .is_err()
    );
}
#[test]
fn gigabyte_revision_catalogues_never_cross() {
    let raw = include_str!("../scripts/fixtures/bios-dynamic/gigabyte-products.json");
    for (revision, product) in [
        ("1.0", "7500"),
        ("1.1", "7500"),
        ("1.2", "8664"),
        ("1.4", "9008"),
        ("1.5", "9281"),
    ] {
        let p = resolve(&id("Gigabyte", "B550 AORUS ELITE V2", "F1", revision)).unwrap();
        let candidates = sources::gigabyte_candidates(&p, raw).unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].family, product);
    }
    for model in [
        "B550 AORUS ELITE V2 AX",
        "B550 AORUS ELITE V2 WIFI",
        "B550 AORUS ELITE V2 MAX",
    ] {
        assert!(
            sources::gigabyte_candidates(
                &resolve(&id("Gigabyte", model, "F1", "1.0")).unwrap(),
                raw
            )
            .unwrap()
            .is_empty()
        );
    }
    let p = resolve(&id("Gigabyte", "X570 AORUS ELITE", "F3", "1.0")).unwrap();
    let mut p = sources::gigabyte_candidates(&p, raw).unwrap().remove(0);
    assert_eq!(p.family, "6897");
    p.support = "https://www.gigabyte.com/Motherboard/X570-AORUS-ELITE-rev-10".into();
    let cat = sources::gigabyte(
        &p,
        "https://www.gigabyte.com/catalog",
        include_str!("../scripts/fixtures/bios-dynamic/gigabyte-x570.json"),
    )
    .unwrap();
    assert_eq!(
        assess(&id("Gigabyte", "X570 AORUS ELITE", "F3", "1.0"), cat).verdict,
        Verdict::Available
    );
}
#[test]
fn current_requires_exact_catalogue_membership_for_each_comparison_rule() {
    for i in [
        id("MSI", "PRO Z890-P WIFI (MS-7E34)", "1.AF0", "1.0"),
        id("ASUS", "TUF GAMING B550-PLUS", "3645", "1.0"),
        id("Gigabyte", "B550 AORUS ELITE V2", "F1", "1.0"),
    ] {
        let c = sources::check_pages(&i, |u| real_reply(&i, u)).unwrap();
        let mut current = i.clone();
        current.version = c.latest.as_ref().unwrap().version.clone();
        assert_eq!(
            assess(&current, c.catalog.clone()).verdict,
            Verdict::Current
        );
        for version in ["unknown", "9999", "9.ZZ0", "F999"] {
            let mut unknown = i.clone();
            unknown.version = version.into();
            assert_eq!(
                assess(&unknown, c.catalog.clone()).verdict,
                Verdict::Uncertain
            );
        }
    }
}
#[test]
fn oem_laptop_and_unknown_vendor_do_not_use_retail_catalogue() {
    for (maker, mobile) in [("Dell Inc.", false), ("HP", false), ("MSI", true)] {
        let mut i = id("MSI", "PRO Z890-P WIFI (MS-7E34)", "1.AE0", "1.0");
        i.system_maker = maker.into();
        i.mobile = mobile;
        let err = sources::check_pages(&i, |_| {
            panic!("OEM identity must not leak to retail endpoint")
        })
        .unwrap_err();
        assert_eq!(failure_code(&err), "UNSUPPORTED");
    }
}
// ASRock successful markup below is SYNTHETIC CONTRACT COVERAGE, not a real
// catalogue fixture or LIVE acceptance. Actual official responses were blocked.
fn synthetic_asrock(i: &Identity, url: &str) -> Result<Page, String> {
    let body = if url.contains("index.us.asp?") {
        format!(
            r#"<a href="../mb/AMD/Test/index.asp">{}</a><a href="../mb/AMD/Other/index.asp">{} WIFI</a>"#,
            i.board_model, i.board_model
        )
    } else if url.ends_with("index.asp") {
        format!(
            r#"<title>ASRock &gt; {}</title><script>load("BIOS.html")</script>"#,
            i.board_model
        )
    } else {
        r#"<table><tr><td>3.20</td><td>2026/10/12</td><td>Bridge BIOS 3.10 required</td><td><a href="https://download.asrock.com/BIOS/AM5/Test(3.20)ROM.zip">Global</a></td></tr><tr><td>P3.10</td><td>2026/8/1</td><td><a href="https://download.asrock.com/BIOS/AM5/Test(3.10)ROM.zip">Global</a></td></tr><tr><td>4.01 Beta</td><td>2026/11/1</td><td><a href="https://download.asrock.com/BIOS/AM5/Test(4.01)ROM.zip">Global</a></td></tr></table>"#.into()
    };
    Ok(Page {
        url: url.into(),
        body,
    })
}
#[test]
fn asrock_dynamic_contract_preserves_exact_variants_and_prerequisites() {
    for model in ["B550M PRO4", "B760M PRO RS/D4", "B650M PG RIPTIDE"] {
        let i = id("ASRock", model, "P3.10", "1.0");
        let c = sources::check_pages(&i, |u| synthetic_asrock(&i, u)).unwrap();
        assert_eq!(c.verdict, Verdict::Available);
        assert_eq!(c.latest.as_ref().unwrap().version, "3.20");
        assert!(
            c.latest
                .as_ref()
                .unwrap()
                .prerequisites
                .contains("Bridge BIOS 3.10 required")
        );
        assert_eq!(c.preview.as_ref().unwrap().channel, Channel::Beta);
        let mut beta = i.clone();
        beta.version = "4.01".into();
        assert_eq!(assess(&beta, c.catalog.clone()).verdict, Verdict::Uncertain);
        let mut current = i.clone();
        current.version = "P3.20".into();
        assert_eq!(assess(&current, c.catalog).verdict, Verdict::Current);
    }
}
#[test]
fn asrock_real_challenge_and_changed_markup_fail_closed() {
    let i = id("ASRock", "B550M PRO4", "P3.10", "1.0");
    for body in [
        include_str!("../scripts/fixtures/bios-dynamic/asrock-blocked.html"),
        "<html>new schema</html>",
    ] {
        assert!(
            sources::check_pages(&i, |u| Ok(Page {
                url: u.into(),
                body: body.into()
            }))
            .is_err()
        );
    }
    for body in ["<table></table>", "<tr><td>3.20</td><td>2026/1/1</td></tr>"] {
        assert!(
            sources::asrock(
                &resolve(&i).unwrap(),
                "https://www.asrock.com/mb/test",
                body
            )
            .is_err()
        );
    }
}
#[test]
fn network_errors_foreign_redirects_and_empty_responses_never_become_current() {
    let i = id("MSI", "PRO Z890-P WIFI (MS-7E34)", "1.AF0", "1.0");
    for e in [
        "HTTP 403",
        "HTTP 404",
        "HTTP 429",
        "HTTP 500",
        "timeout",
        "TLS certificate rejected",
        "offline",
    ] {
        let error = sources::check_pages(&i, |_| Err(e.into())).unwrap_err();
        assert_eq!(error, e);
        assert_eq!(failure_code(&error), "CHECK_FAILED");
    }
    for url in [
        "http://www.msi.com/x",
        "https://evil.test/x",
        "https://www.asus.com/x",
    ] {
        assert!(
            sources::check_pages(&i, |_| Ok(Page {
                url: url.into(),
                body: include_str!("../scripts/fixtures/bios-dynamic/msi-z890.json").into()
            }))
            .is_err()
        );
    }
    for body in [
        "",
        "{}",
        "[]",
        r#"{"result":{"title":"PRO Z890-P WIFI","category":"mb","downloads":{"AMI BIOS":[]}}}"#,
    ] {
        assert!(
            sources::check_pages(&i, |u| Ok(Page {
                url: u.into(),
                body: body.into()
            }))
            .is_err()
        );
    }
}
#[test]
fn discovery_queries_only_contain_public_model() {
    let mut i = id("MSI", "PRO Z890-P WIFI (MS-7E34)", "1.AE0", "1.0");
    i.system_sku = "PRIVATE-SKU".into();
    i.full_id = "PRIVATE-UUID".into();
    let mut queries = Vec::new();
    let _ = sources::check_pages(&i, |u| {
        queries.push(u.to_owned());
        real_reply(&i, u)
    });
    assert!(!queries.is_empty());
    assert!(queries.iter().all(|q| !q.contains("PRIVATE")));
}

#[test]
fn asrock_unknown_release_row_cannot_disappear_and_report_false_current() {
    let i = id("ASRock", "B550M PRO4", "3.20", "1.0");
    let error = sources::check_pages(&i, |u| {
        let mut page = synthetic_asrock(&i, u)?;
        if u.ends_with("BIOS.html") {
            page.body = page.body.replace("4.01 Beta", "4.01A");
        }
        Ok(page)
    })
    .unwrap_err();
    assert!(error.contains("неизвестный формат версии"));
}
#[test]
fn msi_error_status_cannot_reuse_an_otherwise_valid_catalogue() {
    let i = id("MSI", "PRO Z890-P WIFI (MS-7E34)", "1.AF0", "1.0");
    let raw = include_str!("../scripts/fixtures/bios-dynamic/msi-z890.json");
    let raw = raw
        .replace("\"code\":200", "\"code\":500")
        .replace("\"code\": 200", "\"code\": 500");
    assert!(sources::check_with(&i, |_| Ok(raw.clone())).is_err());
}
