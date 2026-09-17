#[derive(Debug)]
struct DiagnosticSession {
    client_name: Option<String>,
    computer_name: String,
}

#[derive(Debug)]
enum ExpcDiagnosticMode {
    SfcDismChkdsk,
    DeepDiagnostic,
    FullAutomaticDiagnostic,
}

#[derive(Debug)]
struct HardwareReport {
    visual_view: bool,
    automatic_json: bool,
}

fn main() {
    let session = DiagnosticSession {
        client_name: None,
        computer_name: std::env::var("COMPUTERNAME").unwrap_or_else(|_| "UNKNOWN-PC".to_string()),
    };

    let diagnostic_mode = ExpcDiagnosticMode::SfcDismChkdsk;

    let hardware = HardwareReport {
        visual_view: true,
        automatic_json: true,
    };

    println!("WinStateDiag");
    println!("Portable Windows State Diagnostic Center");
    println!();
    println!("Session: {session:?}");
    println!("Default diagnostic mode: {diagnostic_mode:?}");
    println!("Hardware Report: {hardware:?}");
    println!();
    println!("Milestone 02 bootstrap: PASS");
}
