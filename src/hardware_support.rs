//! Explicit dependency actions. Detection never installs or starts a driver.
use crate::deep_checks::json;
use std::{
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::mpsc::Sender,
    time::Duration,
};
pub const DETECTION: &str = include_str!("../embedded/HardwareSupport/Detection.ps1");
pub const MANIFEST: &str = include_str!("../embedded/HardwareSupport/manifest.json");
const INSTALL: &str = include_str!("../embedded/HardwareSupport/Install.ps1");
const INSTALLER: &[u8] = include_bytes!("../third_party/PawnIO-2.2.0/PawnIO_setup.exe");
const CONTROL_ZIP: &[u8] =
    include_bytes!("../third_party/LibreHardwareMonitor-0.9.6-standalone/LibreHardwareMonitor.zip");
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Operation {
    Detect,
    Install,
    Control,
}
#[derive(Debug)]
pub enum Event {
    Progress(String),
    Done(Result<Outcome, String>),
}
#[derive(Debug)]
pub struct Outcome {
    pub state: String,
    pub raw: String,
    pub reread: bool,
}
impl Outcome {
    pub fn dependency_state(&self) -> Option<String> {
        if self.state == "REBOOT_REQUIRED" {
            return Some(self.state.clone());
        }
        if matches!(
            self.state.as_str(),
            "ACCESSIBLE"
                | "ABSENT"
                | "INCOMPATIBLE"
                | "ACCESS_DENIED"
                | "BLOCKED_BY_WINDOWS"
                | "INITIALIZATION_ERROR"
        ) {
            return Some(self.state.clone());
        }
        let raw = json::parse(&self.raw)?;
        for key in ["after", "before"] {
            if let Some(v) = raw
                .get(key)
                .and_then(|v| v.get("state"))
                .and_then(json::Value::as_str)
            {
                return Some(v.into());
            }
        }
        None
    }
}
pub fn field(raw: &str, key: &str) -> String {
    json::parse(raw)
        .and_then(|j| j.get(key).and_then(json::Value::as_str).map(str::to_owned))
        .unwrap_or_default()
}
pub fn can_install(state: &str) -> bool {
    matches!(state, "ABSENT" | "INCOMPATIBLE")
}
pub fn label(state: &str) -> &str {
    match state {
        "ACCESSIBLE" => "PawnIO доступен",
        "ABSENT" => "PawnIO не установлен",
        "INCOMPATIBLE" => "Нужна совместимая версия PawnIO",
        "ACCESS_DENIED" => "PawnIO: нет доступа у процесса чтения",
        "BLOCKED_BY_WINDOWS" => "PawnIO заблокирован Windows",
        "CANCELLED" => "Установка отменена пользователем",
        "REBOOT_REQUIRED" => "PawnIO: требуется перезагрузка Windows",
        "INSTALLED_NOT_READY" => "PawnIO установлен; доступ не подтверждён",
        "INSTALLED" | "ALREADY_INSTALLED" => "PawnIO проверен; перечитывание датчиков",
        "CONTROL_CLOSED" => "Контрольный LHM закрыт; перечитывание",
        "INITIALIZATION_ERROR" | "ERROR" => "Ошибка аппаратного источника — подробности в журнале",
        _ => "Проверка аппаратного доступа",
    }
}
pub fn base_script() -> String {
    format!(
        "{}\n$WsdManifest=ConvertFrom-Json -InputObject @'\n{}\n'@\n",
        DETECTION.trim_start_matches('\u{feff}'),
        MANIFEST
    )
}
fn quote(path: &Path) -> String {
    path.to_string_lossy().replace('\'', "''")
}
fn save_new(dir: &Path, name: &str, bytes: &[u8]) -> Result<PathBuf, String> {
    let path = dir.join(name);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|e| e.to_string())?;
    f.write_all(bytes)
        .and_then(|_| f.sync_all())
        .map_err(|e| e.to_string())?;
    Ok(path)
}
pub fn start(op: Operation, base: PathBuf, tx: Sender<Event>) {
    std::thread::spawn(move || {
        let result = run(op, &base, &tx);
        let _ = tx.send(Event::Done(result));
    });
}
pub(crate) fn run(op: Operation, base: &Path, tx: &Sender<Event>) -> Result<Outcome, String> {
    let mut script = base_script();
    if op == Operation::Detect {
        script.push_str("Get-WsdPawnIo | ConvertTo-Json -Depth 12 -Compress");
        let raw = crate::ps_exec::run_powershell_compact(
            "powershell.exe",
            &script,
            Duration::from_secs(25),
        )
        .map_err(|e| e.to_string())?;
        let raw = raw.trim().to_string();
        let state = field(&raw, "state");
        if state.is_empty() {
            return Err("PawnIO detector returned no valid result".into());
        }
        return Ok(Outcome {
            state,
            raw,
            reread: false,
        });
    }
    std::fs::create_dir_all(base).map_err(|e| e.to_string())?;
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_nanos();
    let dir = base.join(format!("hardware-{}-{stamp}", std::process::id()));
    std::fs::create_dir(&dir).map_err(|e| e.to_string())?;
    if op == Operation::Install {
        let installer = save_new(&dir, "PawnIO_setup.exe", INSTALLER)?;
        script.push_str(INSTALL.trim_start_matches('\u{feff}'));
        script.push_str(&format!(
            "\nInvoke-WsdPawnInstall '{}' '{}' $WsdManifest",
            quote(&installer),
            quote(&dir)
        ));
    } else {
        let archive = save_new(&dir, "LibreHardwareMonitor.zip", CONTROL_ZIP)?;
        script.push_str(&format!(r#"
$ErrorActionPreference='Stop'
$owned=$false;$mutex=$null
try {{
 $mutex=[Threading.Mutex]::new($false,'Global\EXPC.HardwareMonitor.Reader')
 try{{$owned=$mutex.WaitOne(0)}}catch [Threading.AbandonedMutexException]{{$owned=$true;Save-WsdHardwareAbort (Get-WsdPawnIo) 'Abandoned reader before comparison';throw 'Previous hardware read was abandoned; comparison refused'}}
 if(-not $owned){{throw 'Hardware polling is busy; close the other monitor first'}}
 if((Get-FileHash -LiteralPath '{archive}' -Algorithm SHA256).Hash -ne '086D9F1B5A99E643EDC2CFAAAC16051685B551E4C5AC0B32A57C58C0E529C001'){{throw 'Official LHM archive hash mismatch'}}
 $gate=Get-WsdPawnIo;if($gate.reader_gate -ne 'READY'){{throw $gate.reader_gate_reason}}
 'WSD_HW_PROGRESS PreparingControl'
 Expand-Archive -LiteralPath '{archive}' -DestinationPath '{dir}\control' -ErrorAction Stop
 $start=[Diagnostics.ProcessStartInfo]::new();$start.FileName='{dir}\control\LibreHardwareMonitor.exe';$start.WorkingDirectory='{dir}\control';$start.UseShellExecute=$true
 if(-not(Get-WsdIsAdmin)){{$start.Verb='runas'}}
 $p=[Diagnostics.Process]::Start($start)
 try{{'WSD_HW_PROGRESS ControlRunning';$p.WaitForExit();$result=@{{state='CONTROL_CLOSED';exit_code=$p.ExitCode;pid=$p.Id;source='Official LHM 0.9.6';comparison='MANUAL; no equivalence claim'}}}}finally{{$p.Dispose()}}
}}catch{{$result=@{{state='ERROR';error=$_.Exception.Message}}}}
finally{{if($owned){{$mutex.ReleaseMutex()}};if($mutex){{$mutex.Dispose()}}}}
$result|ConvertTo-Json -Depth 6|Set-Content -LiteralPath '{dir}\control-result.json' -Encoding UTF8
'WSD_HW_RESULT '+($result|ConvertTo-Json -Depth 6 -Compress)
"#,archive=quote(&archive),dir=quote(&dir)));
    }
    // No kill-on-close Job for installation/control: GUI exit must not interrupt setup.
    let mut cmd = Command::new("powershell.exe");
    cmd.env_remove("PSModulePath")
        .args(["-NoLogo", "-NoProfile", "-NonInteractive", "-Command"])
        .arg(crate::ps_exec::compact_command(&script)?)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000);
    }
    let mut child = cmd.spawn().map_err(|e| e.to_string())?;
    let stderr = child.stderr.take();
    let err_thread = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        if let Some(pipe) = stderr {
            use std::io::Read;
            let _ = pipe.take(65536).read_to_end(&mut bytes);
        }
        String::from_utf8_lossy(&bytes).into_owned()
    });
    let mut raw = None;
    let mut log = std::fs::File::create(dir.join("observer.log")).map_err(|e| e.to_string())?;
    for line in BufReader::new(child.stdout.take().ok_or("Missing operation stdout")?).lines() {
        let line = line.map_err(|e| e.to_string())?;
        let _ = writeln!(log, "{line}");
        if let Some(stage) = line.strip_prefix("WSD_HW_PROGRESS ") {
            let _ = tx.send(Event::Progress(stage.to_string()));
        }
        if let Some(value) = line.strip_prefix("WSD_HW_RESULT ") {
            raw = Some(value.to_string());
        }
    }
    let exit = child.wait().map_err(|e| e.to_string())?;
    let errors = err_thread.join().unwrap_or_default();
    let _ = writeln!(log, "exit={exit}; stderr={errors}");
    let raw = raw.ok_or_else(|| {
        format!(
            "Hardware operation ended without result: {exit}; {errors}; log={}",
            dir.display()
        )
    })?;
    let state = field(&raw, "state");
    let reread = matches!(
        state.as_str(),
        "INSTALLED" | "ALREADY_INSTALLED" | "CONTROL_CLOSED"
    );
    Ok(Outcome { state, raw, reread })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn errors_never_offer_reinstall() {
        for s in [
            "ACCESSIBLE",
            "ACCESS_DENIED",
            "BLOCKED_BY_WINDOWS",
            "INITIALIZATION_ERROR",
            "",
        ] {
            assert!(!can_install(s));
        }
        assert!(can_install("ABSENT"));
        assert!(can_install("INCOMPATIBLE"));
    }
    #[test]
    fn status_json_required() {
        assert_eq!(
            field(r#"{"state":"ACCESS_DENIED"}"#, "state"),
            "ACCESS_DENIED"
        );
        assert_eq!(field("broken", "state"), "");
    }
    #[test]
    fn installation_outcome_keeps_driver_state() {
        for state in ["INSTALLED", "INSTALLED_NOT_READY", "CANCELLED", "ERROR"] {
            let o = Outcome {
                state: state.into(),
                raw: r#"{"before":{"state":"ABSENT"},"after":{"state":"ACCESS_DENIED"}}"#.into(),
                reread: false,
            };
            assert_eq!(o.dependency_state().as_deref(), Some("ACCESS_DENIED"));
            assert!(!can_install(&o.dependency_state().unwrap()));
        }
        let reboot = Outcome {
            state: "REBOOT_REQUIRED".into(),
            raw: r#"{"after":{"state":"ACCESSIBLE"}}"#.into(),
            reread: false,
        };
        assert_eq!(
            reboot.dependency_state().as_deref(),
            Some("REBOOT_REQUIRED")
        );
    }
    #[test]
    fn scripts_fit_command() {
        assert!(crate::ps_exec::compact_command(&(base_script() + INSTALL)).is_ok());
    }
}
