// Embeds the application icon and the Windows manifest (UAC elevation +
// per-monitor DPI awareness) into the compiled .exe. Only runs when the
// target is Windows; harmless no-op on any other host used for `cargo check`.
// The manifest goes into the production bin only (see embed_app_manifest).

const APP_MANIFEST: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity
    version="1.1.0.0"
    processorArchitecture="*"
    name="WinStateDiag"
    type="win32"
  />
  <description>WinStateDiag - Windows State Diagnostics</description>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="requireAdministrator" uiAccess="false" />
      </requestedPrivileges>
    </security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <!-- Windows 10 and 11 (Microsoft has not issued a separate
           supportedOS GUID for Windows 11; the Windows 10 GUID covers
           both). -->
      <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/>
    </application>
  </compatibility>
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true/pm</dpiAware>
      <dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">PerMonitorV2</dpiAwareness>
    </windowsSettings>
  </application>
</assembly>
"#;

/// Embeds the canonical `assets/GRAPHIC_REPORT.md` (the permanent
/// instruction for the graphical customer report) into every session ZIP.
/// When the file does not exist yet, an empty slot is compiled in and the
/// package simply omits it (nothing is invented).
fn embed_graphic_report_template() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=assets");
    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    let source = std::path::Path::new("assets").join("GRAPHIC_REPORT.md");
    let (bytes, state) = match std::fs::read(&source) {
        Ok(bytes) => (bytes, "present"),
        Err(_) => (Vec::new(), "missing"),
    };
    std::fs::write(out_dir.join("GRAPHIC_REPORT.md"), bytes).expect("write template slot");
    // "missing" is a normal, supported state (the package then simply omits
    // the template); it is recorded for the app, not reported as a warning.
    println!("cargo:rustc-env=WSD_GRAPHIC_REPORT_TEMPLATE={state}");
}

/// v0.4.5: bundles the official LibreHardwareMonitorLib (MPL-2.0) and its
/// dependencies when `third_party/LibreHardwareMonitorLib-<ver>/lib/` exists
/// (populated by the audited fetch script; see THIRD-PARTY-NOTICES.md).
/// Without it the generated list is empty and the internal sensor provider
/// reports UNAVAILABLE — nothing is downloaded at build or run time.
fn embed_lhm_bundle() {
    const LHM_VERSION: &str = "0.9.6";
    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    let root = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let tp = root
        .join("third_party")
        .join(format!("LibreHardwareMonitorLib-{LHM_VERSION}"));
    println!("cargo:rerun-if-changed={}", tp.display());
    let mut files: Vec<std::path::PathBuf> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(tp.join("lib")) {
        files.extend(
            rd.filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.extension().is_some_and(|x| x.eq_ignore_ascii_case("dll"))),
        );
    }
    files.sort();
    let mut src = String::from("pub const LHM_VERSION: &str = ");
    src.push_str(&format!(
        "{LHM_VERSION:?};\npub const LHM_FILES: &[(&str, &[u8])] = &[\n"
    ));
    for f in &files {
        println!("cargo:rerun-if-changed={}", f.display());
        let name = f.file_name().unwrap().to_string_lossy().to_string();
        src.push_str(&format!(
            "    ({name:?}, include_bytes!({:?})),\n",
            f.display().to_string()
        ));
    }
    src.push_str("];\n");
    std::fs::write(out_dir.join("lhm_bundle.rs"), src).expect("write lhm bundle list");
}

/// Embeds `APP_MANIFEST` (requireAdministrator + DPI awareness) into the
/// production `win_state_diag` binary ONLY. The `-bin=` scope keeps it out of
/// the library test harness (all tests live in src/lib.rs; the bin has
/// `test = false`, see Cargo.toml) and out of helper bins, so `cargo test`
/// never needs elevation just because the shipped EXE does.
fn embed_app_manifest() {
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() != Ok("msvc") {
        println!("cargo:warning=app manifest is only embedded for MSVC targets");
        return;
    }
    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    let manifest = out_dir.join("WinStateDiag.exe.manifest");
    std::fs::write(&manifest, APP_MANIFEST).expect("write app manifest");
    for arg in [
        "/MANIFEST:EMBED".to_string(),
        format!("/MANIFESTINPUT:{}", manifest.display()),
        // trustInfo comes verbatim from APP_MANIFEST; stop link.exe from
        // adding its own (asInvoker) fragment.
        "/MANIFESTUAC:NO".to_string(),
    ] {
        println!("cargo:rustc-link-arg-bin=win_state_diag={arg}");
    }
}

/// v1.0 version policy: releases are named `major.minor` (v1.0, v1.1, …,
/// v2.0); a patch digit is shown only when it is not zero. Cargo needs a
/// full semver (`1.0.0`), so the display form is derived here once and used
/// by the title, the manifest, the EXE VERSIONINFO strings and the release
/// folder.
fn display_version(semver: &str) -> String {
    let parts: Vec<&str> = semver.split('.').collect();
    match parts.as_slice() {
        [major, minor, "0"] => format!("{major}.{minor}"),
        _ => semver.to_string(),
    }
}

fn main() {
    let display = display_version(&std::env::var("CARGO_PKG_VERSION").expect("version"));
    println!("cargo:rustc-env=WSD_DISPLAY_VERSION={display}");
    embed_graphic_report_template();
    embed_lhm_bundle();
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os != "windows" {
        return;
    }

    embed_app_manifest();

    // Icon + VERSIONINFO only. winresource links its .res with a package-wide
    // `cargo:rustc-link-arg`, i.e. into every linked artifact including the
    // `cargo test` harness EXEs, so the UAC manifest must NOT go through it.
    let mut res = winresource::WindowsResource::new();
    res.set_icon("assets/icon.ico");
    // Explorer / file properties show the release name ("1.0"); the binary
    // VERSIONINFO numbers stay the full 1.0.0.0 from Cargo.
    res.set("FileVersion", &display);
    res.set("ProductVersion", &display);
    if let Err(e) = res.compile() {
        // Do not hard-fail cargo check on non-Windows-resource-capable hosts
        // (e.g. cross-compilation sanity checks); a real Windows release
        // build must not hit this branch.
        println!("cargo:warning=failed to embed Windows resources: {e}");
    }
}
