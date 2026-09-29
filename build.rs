// Embeds the application icon and the Windows manifest (UAC elevation +
// per-monitor DPI awareness) into the compiled .exe. Only runs when the
// target is Windows; harmless no-op on any other host used for `cargo check`.

const APP_MANIFEST: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity
    version="1.0.0.0"
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

fn main() {
    embed_graphic_report_template();
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os != "windows" {
        return;
    }

    let mut res = winresource::WindowsResource::new();
    res.set_icon("assets/icon.ico");
    res.set_manifest(APP_MANIFEST);
    if let Err(e) = res.compile() {
        // Do not hard-fail cargo check on non-Windows-resource-capable hosts
        // (e.g. cross-compilation sanity checks); a real Windows release
        // build must not hit this branch.
        println!("cargo:warning=failed to embed Windows resources: {e}");
    }
}
