//! Shared helpers to run read-only collectors (PowerShell scripts and
//! command-line tools such as cdb.exe) hidden, inside this WinStateDiag's
//! own process tree, with a hard time limit (v0.4.4).

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::Duration;

/// Why a collector produced no output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunError {
    Spawn(String),
    TimedOut,
    Io(String),
}

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunError::Spawn(e) => write!(f, "could not start: {e}"),
            RunError::TimedOut => write!(f, "timed out"),
            RunError::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

/// `-EncodedCommand` payload: base64 of the UTF-16LE script.
pub fn encoded_command(script: &str) -> String {
    const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(B64[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Runs `cmd` (stdout captured, stdin/stderr closed) and returns its stdout.
/// The process tree is killed when `timeout` expires.
pub fn run_capture(mut cmd: Command, timeout: Duration) -> Result<Vec<u8>, RunError> {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut guard =
        crate::engine::ProcessGuard::spawn(cmd).map_err(|e| RunError::Spawn(e.to_string()))?;
    let Some(mut stdout) = guard.child_mut().stdout.take() else {
        return Err(RunError::Io("no stdout".into()));
    };
    let reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout.read_to_end(&mut buf);
        buf
    });
    let never = std::sync::atomic::AtomicBool::new(false);
    match guard.wait_or_cancel(&never, Some(timeout)) {
        Ok(_) => Ok(reader.join().unwrap_or_default()),
        Err(crate::engine::WaitEnd::TimedOut) => {
            // Whatever was printed before the kill is still useful evidence.
            let _ = reader.join();
            Err(RunError::TimedOut)
        }
        Err(crate::engine::WaitEnd::Cancelled) => Err(RunError::TimedOut),
        Err(crate::engine::WaitEnd::Io(e)) => Err(RunError::Io(e.to_string())),
    }
}

/// v1.0: like [`run_capture`] (hidden, own process tree, hard timeout) but
/// stdout AND stderr are merged and every line is handed to `observer`
/// while the tool is still running — used for real stage feedback of the
/// cdb analysis and the WinDbg installer (no invented percentages). Returns
/// the complete captured text; on a timeout the partial text is returned
/// with `timed_out = true`.
pub fn run_capture_observed(
    mut cmd: Command,
    timeout: Duration,
    mut observer: impl FnMut(&str) + Send + 'static,
) -> Result<(String, bool), RunError> {
    use std::io::BufRead;
    use std::sync::{Arc, Mutex};
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut guard =
        crate::engine::ProcessGuard::spawn(cmd).map_err(|e| RunError::Spawn(e.to_string()))?;
    let stdout = guard.child_mut().stdout.take();
    let stderr = guard.child_mut().stderr.take();
    let text = Arc::new(Mutex::new(String::new()));
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    let mut readers = Vec::new();
    let spawn_reader = |pipe: Box<dyn Read + Send>, tx: std::sync::mpsc::Sender<String>| {
        std::thread::spawn(move || {
            let mut reader = std::io::BufReader::new(pipe);
            let mut buf = Vec::new();
            loop {
                buf.clear();
                match reader.read_until(b'\n', &mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        // winget redraws its progress bar with CR only.
                        for part in String::from_utf8_lossy(&buf).split('\r') {
                            let line = part.trim_end_matches(['\n', '\r']);
                            if !line.trim().is_empty() && tx.send(line.to_string()).is_err() {
                                return;
                            }
                        }
                    }
                }
            }
        })
    };
    if let Some(out) = stdout {
        readers.push(spawn_reader(Box::new(out), tx.clone()));
    }
    if let Some(err) = stderr {
        readers.push(spawn_reader(Box::new(err), tx.clone()));
    }
    drop(tx);
    let collected = Arc::clone(&text);
    let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
    std::thread::spawn(move || {
        for line in rx {
            observer(&line);
            if let Ok(mut t) = collected.lock() {
                t.push_str(&line);
                t.push('\n');
            }
        }
        let _ = done_tx.send(());
    });
    let never = std::sync::atomic::AtomicBool::new(false);
    let end = guard.wait_or_cancel(&never, Some(timeout));
    drop(guard);
    // A grandchild that inherited the pipe must never block us: the drain
    // of the remaining output is bounded.
    let _ = done_rx.recv_timeout(Duration::from_secs(5));
    drop(readers);
    let out = text.lock().map(|t| t.clone()).unwrap_or_default();
    match end {
        Ok(_) => Ok((out, false)),
        Err(crate::engine::WaitEnd::TimedOut) | Err(crate::engine::WaitEnd::Cancelled) => {
            Ok((out, true))
        }
        Err(crate::engine::WaitEnd::Io(e)) => Err(RunError::Io(e.to_string())),
    }
}

/// Prepended to every collector script (see [`run_powershell`]).
pub const PS_PRELUDE: &str = "$ProgressPreference = 'SilentlyContinue'; try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }\n";

/// Runs a read-only PowerShell script with `host` (`powershell.exe` on
/// Windows) and returns its stdout as text.
pub fn run_powershell(host: &str, script: &str, timeout: Duration) -> Result<String, RunError> {
    // v1.0: UTF-8 output (Cyrillic event / title text was decoded lossily
    // from the OEM code page) and no CLIXML progress records in a hidden,
    // console-less host. Every caller passes a plain script body or an
    // `& { … } -Args` call, never a top-level `param()` block.
    let script = format!("{PS_PRELUDE}{script}");
    let mut cmd = Command::new(host);
    // v1.0: started from a PowerShell 7 session, the inherited
    // PSModulePath points Windows PowerShell 5.1 at PS7's own modules
    // (Microsoft.PowerShell.Security fails to load → Get-AuthenticodeSignature
    // silently missing). The child computes its default path instead.
    cmd.env_remove("PSModulePath");
    cmd.args([
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-EncodedCommand",
    ])
    .arg(encoded_command(&script));
    run_capture(cmd, timeout).map(|b| String::from_utf8_lossy(&b).into_owned())
}

/// The line after `marker` in a collector's output (collectors print one
/// `MARKER <json>` line so stray host output never breaks parsing).
pub fn marked_line<'a>(stdout: &'a str, marker: &str) -> Option<&'a str> {
    stdout
        .lines()
        .find_map(|l| l.trim_start_matches('\u{feff}').strip_prefix(marker))
        .map(str::trim)
}

/// PowerShell host for tests: Windows PowerShell on Windows, otherwise
/// `WSD_PWSH` (pwsh) when provided.
#[cfg(test)]
pub fn test_host() -> Option<String> {
    if cfg!(windows) {
        Some("powershell.exe".into())
    } else {
        std::env::var("WSD_PWSH").ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoded_command_is_utf16le_base64() {
        assert_eq!(encoded_command("A"), "QQA=");
        assert_eq!(encoded_command("ab"), "YQBiAA==");
        assert_eq!(encoded_command("abc"), "YQBiAGMA");
    }

    #[test]
    fn observed_capture_streams_every_line_hidden_and_returns_the_text() {
        let Some(host) = test_host() else {
            return;
        };
        let lines = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let seen = std::sync::Arc::clone(&lines);
        let mut cmd = Command::new(host);
        cmd.args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "'one'; [Console]::Error.WriteLine('two'); 'three'",
        ]);
        let (text, timed_out) = run_capture_observed(cmd, Duration::from_secs(60), move |l| {
            seen.lock().unwrap().push(l.to_string());
        })
        .unwrap();
        assert!(!timed_out);
        let got = lines.lock().unwrap().clone();
        for want in ["one", "two", "three"] {
            assert!(got.iter().any(|l| l == want), "{got:?}");
            assert!(text.contains(want));
        }
    }

    #[test]
    fn security_cmdlets_load_even_when_started_from_powershell_7() {
        let Some(host) = test_host() else {
            return;
        };
        let out = run_powershell(
            &host,
            "'WSD_S ' + [string](Get-Command Get-AuthenticodeSignature -ErrorAction SilentlyContinue).Name",
            Duration::from_secs(60),
        )
        .unwrap();
        if cfg!(windows) {
            assert_eq!(
                marked_line(&out, "WSD_S "),
                Some("Get-AuthenticodeSignature")
            );
        }
    }

    #[test]
    fn collector_output_is_utf8_cyrillic_intact() {
        let Some(host) = test_host() else {
            return;
        };
        let out = run_powershell(
            &host,
            "'WSD_T ' + [string][char]0x0416 + 'урнал'",
            Duration::from_secs(60),
        )
        .unwrap();
        assert_eq!(marked_line(&out, "WSD_T "), Some("Журнал"), "{out:?}");
        assert!(!out.contains("CLIXML"));
    }

    #[test]
    fn marked_line_finds_the_payload() {
        let out = "noise\n\u{feff}WSD_X {\"a\":1}\nmore";
        assert_eq!(marked_line(out, "WSD_X "), Some("{\"a\":1}"));
        assert_eq!(marked_line(out, "WSD_Y "), None);
    }
}
