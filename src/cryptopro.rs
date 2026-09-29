//! CryptoPro CSP integrity-hash status (read-only check) and the ONE
//! user-confirmed service action: ReHash.
//!
//! Mechanism (the user's CryptoHash.ps1 + CryptoPro `cpverify`):
//! * A. read-only check: `cpverify.exe -rv` — verifies the registered
//!   reference hashes of the protected files and prints one line per file
//!   ("... ok" / "... has incorrect hash.fail"). It changes nothing.
//! * B. ReHash:          `cpverify.exe -rm` — RECOMPUTES and stores the
//!   reference hashes (mutating). Only after an explicit user confirmation.
//! * C. post-action:     `cpverify.exe -rv` again; only that decides HASH OK.
//!
//! Nothing is inferred heuristically: an output that is not clearly "all
//! ok" or "some fail" is CHECK_ERROR.

use std::path::{Path, PathBuf};

/// Card state. Exactly one is shown at a time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HashState {
    HashOk,
    NoHash,
    NotInstalled,
    /// CryptoPro found, but the state could not be proven (reason).
    CheckError(String),
}

impl HashState {
    /// ReHash is offered only for NO_HASH.
    pub fn rehash_available(&self) -> bool {
        matches!(self, HashState::NoHash)
    }

    /// The single status line of the card.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn label(&self) -> &'static str {
        match self {
            HashState::HashOk => "HASH OK",
            HashState::NoHash => "NO HASH",
            HashState::NotInstalled => "NOT INSTALLED",
            HashState::CheckError(_) => "CHECK ERROR",
        }
    }
}

/// Result of one command run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CmdOutput {
    pub exit_code: Option<i32>,
    pub text: String,
}

/// Runs a program hidden and waits for it (real or fake).
pub trait CommandRunner {
    fn run(&self, exe: &Path, args: &[&str]) -> Result<CmdOutput, String>;
}

/// Where CryptoPro CSP lives on this machine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Detection {
    NotInstalled,
    /// CSP folder exists but `cpverify.exe` is missing.
    NoVerifier(PathBuf),
    Installed(PathBuf),
}

/// Standard install locations: `<ProgramFiles*>\Crypto Pro\CSP\`.
/// `roots` are the Program Files folders to look in (env-derived in
/// production, explicit in tests); spaces/Cyrillic are fine (PathBuf).
pub fn detect(roots: &[PathBuf]) -> Detection {
    let mut csp_dir = None;
    for root in roots {
        let dir = root.join("Crypto Pro").join("CSP");
        let exe = dir.join("cpverify.exe");
        if exe.is_file() {
            return Detection::Installed(exe);
        }
        if dir.is_dir() && csp_dir.is_none() {
            csp_dir = Some(dir);
        }
    }
    match csp_dir {
        Some(dir) => Detection::NoVerifier(dir),
        None => Detection::NotInstalled,
    }
}

/// `%ProgramW6432%`, `%ProgramFiles%`, `%ProgramFiles(x86)%` (deduplicated).
pub fn program_files_roots() -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = Vec::new();
    for var in ["ProgramW6432", "ProgramFiles", "ProgramFiles(x86)"] {
        if let Some(v) = std::env::var_os(var) {
            let p = PathBuf::from(v);
            if !roots.contains(&p) {
                roots.push(p);
            }
        }
    }
    roots
}

/// Interprets `cpverify -rv` output. Only a clear result is accepted.
///
/// Real CryptoPro CSP output (confirmed against CSP 5.0.13800 KC1) reports
/// each file's verdict as a line PREFIX, not a suffix:
///   `ok....C:\...`
///   `fail..C:\...`
/// followed by a summary such as `Verified hash for 112 files` /
/// `Verify hash failed for 12 files` / `Verify hash entries failed`.
/// A recognized fail verdict is a fail regardless of the process exit code
/// (CryptoPro exits non-zero, e.g. 2, on a normal, parseable fail result).
pub fn parse_verify(out: &CmdOutput) -> HashState {
    let mut ok = 0usize;
    let mut fail = 0usize;
    let mut fail_summary = false;
    for line in out.text.lines() {
        let l = line.trim().to_lowercase();
        if l.is_empty() {
            continue;
        }
        if l.starts_with("fail") || l.contains("incorrect hash") {
            fail += 1;
        } else if l.starts_with("ok") {
            ok += 1;
        }
        if l.contains("verify hash failed for") || l.contains("verify hash entries failed") {
            fail_summary = true;
        }
    }
    if fail > 0 || fail_summary {
        return HashState::NoHash;
    }
    match (ok, out.exit_code) {
        (n, Some(0)) if n > 0 => HashState::HashOk,
        (0, code) => HashState::CheckError(format!(
            "cpverify -rv: нет однозначного результата (код {}, вывод: {})",
            code.map(|c| c.to_string()).unwrap_or_else(|| "н/д".into()),
            first_line(&out.text)
        )),
        (_, code) => HashState::CheckError(format!(
            "cpverify -rv завершился с кодом {}",
            code.map(|c| c.to_string()).unwrap_or_else(|| "н/д".into())
        )),
    }
}

fn first_line(text: &str) -> String {
    let l = text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("пусто");
    l.chars().take(160).collect()
}

/// A. Read-only check.
pub fn check(det: &Detection, runner: &dyn CommandRunner) -> HashState {
    match det {
        Detection::NotInstalled => HashState::NotInstalled,
        Detection::NoVerifier(dir) => {
            HashState::CheckError(format!("cpverify.exe не найден в {}", dir.display()))
        }
        Detection::Installed(exe) => match runner.run(exe, &["-rv"]) {
            Ok(out) => parse_verify(&out),
            Err(e) => HashState::CheckError(format!("cpverify -rv не запустился: {e}")),
        },
    }
}

/// Outcome of a confirmed ReHash (B + C).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RehashOutcome {
    pub state: HashState,
    pub journal: Vec<String>,
}

/// B. ReHash (only from NO_HASH, only after user confirmation), then C.
pub fn rehash(det: &Detection, current: &HashState, runner: &dyn CommandRunner) -> RehashOutcome {
    if !current.rehash_available() {
        return RehashOutcome {
            state: current.clone(),
            journal: vec!["[WARN] CryptoPro ReHash недоступен в текущем состоянии.".into()],
        };
    }
    let Detection::Installed(exe) = det else {
        return RehashOutcome {
            state: HashState::CheckError("cpverify.exe не найден".into()),
            journal: vec!["[FAIL] CryptoPro ReHash: cpverify.exe не найден.".into()],
        };
    };
    let mut journal = vec!["[INFO] Запущен CryptoPro ReHash пользователем.".to_string()];
    match runner.run(exe, &["-rm"]) {
        Err(e) => {
            journal.push(format!("[FAIL] CryptoPro ReHash завершился ошибкой: {e}"));
            return RehashOutcome {
                state: HashState::CheckError(format!("ReHash: {e}")),
                journal,
            };
        }
        Ok(out) if out.exit_code != Some(0) => {
            let why = format!(
                "код {}: {}",
                out.exit_code
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "н/д".into()),
                first_line(&out.text)
            );
            journal.push(format!("[FAIL] CryptoPro ReHash завершился ошибкой: {why}"));
            return RehashOutcome {
                state: HashState::CheckError(format!("ReHash {why}")),
                journal,
            };
        }
        Ok(_) => {}
    }
    // C. HASH OK only when the read-only check confirms it.
    let state = check(det, runner);
    match &state {
        HashState::HashOk => {
            journal.push("[PASS] CryptoPro ReHash выполнен, HASH подтверждён.".into())
        }
        HashState::NoHash => journal.push(
            "[WARN] CryptoPro ReHash выполнен, но проверка по-прежнему показывает NO HASH.".into(),
        ),
        HashState::CheckError(e) => {
            journal.push(format!("[WARN] CryptoPro HASH не удалось проверить: {e}"))
        }
        HashState::NotInstalled => {}
    }
    RehashOutcome { state, journal }
}

/// Journal line for a check result.
pub fn journal_for(state: &HashState) -> Vec<String> {
    match state {
        HashState::NotInstalled => vec!["[INFO] CryptoPro не установлен.".into()],
        HashState::HashOk => vec![
            "[INFO] CryptoPro обнаружен.".into(),
            "[PASS] CryptoPro HASH: OK.".into(),
        ],
        HashState::NoHash => vec![
            "[INFO] CryptoPro обнаружен.".into(),
            "[WARN] CryptoPro HASH отсутствует / требуется ReHash.".into(),
        ],
        HashState::CheckError(e) => {
            vec![format!("[WARN] CryptoPro HASH не удалось проверить: {e}")]
        }
    }
}

/// Real runner: hidden process owned by this WinStateDiag (process tree
/// ends with it), output captured, time-limited.
pub struct HiddenRunner {
    pub timeout: std::time::Duration,
}

impl CommandRunner for HiddenRunner {
    fn run(&self, exe: &Path, args: &[&str]) -> Result<CmdOutput, String> {
        use crate::engine::{ProcessGuard, WaitEnd};
        use std::io::Read;
        use std::process::{Command, Stdio};
        let mut cmd = Command::new(exe);
        cmd.args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(dir) = exe.parent() {
            cmd.current_dir(dir);
        }
        let mut guard = ProcessGuard::spawn(cmd).map_err(|e| e.to_string())?;
        let mut out = guard.child_mut().stdout.take();
        let mut err = guard.child_mut().stderr.take();
        let t_out = std::thread::spawn(move || {
            let mut b = Vec::new();
            if let Some(o) = out.as_mut() {
                let _ = o.read_to_end(&mut b);
            }
            b
        });
        let t_err = std::thread::spawn(move || {
            let mut b = Vec::new();
            if let Some(e) = err.as_mut() {
                let _ = e.read_to_end(&mut b);
            }
            b
        });
        let never = std::sync::atomic::AtomicBool::new(false);
        let waited = guard.wait_or_cancel(&never, Some(self.timeout));
        let mut bytes = t_out.join().unwrap_or_default();
        bytes.extend(t_err.join().unwrap_or_default());
        let status = match waited {
            Ok(s) => s,
            Err(WaitEnd::TimedOut) => return Err("превышено время ожидания".into()),
            Err(WaitEnd::Cancelled) => return Err("остановлено".into()),
            Err(WaitEnd::Io(e)) => return Err(e.to_string()),
        };
        Ok(CmdOutput {
            exit_code: status.code(),
            text: decode_console(&bytes),
        })
    }
}

/// cpverify writes in the console code page; the verdict words are ASCII,
/// so a lossy decode is enough (CP866/1251 Cyrillic may show as '?').
fn decode_console(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(s) => s.to_string(),
        Err(_) => bytes
            .iter()
            .map(|&b| if b.is_ascii() { b as char } else { '?' })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// Fake runner: scripted results per argument, records every call.
    struct Fake {
        rv: RefCell<Vec<Result<CmdOutput, String>>>,
        rm: Option<Result<CmdOutput, String>>,
        calls: RefCell<Vec<String>>,
    }

    impl Fake {
        fn new(rv: Vec<Result<CmdOutput, String>>, rm: Option<Result<CmdOutput, String>>) -> Self {
            Self {
                rv: RefCell::new(rv),
                rm,
                calls: RefCell::new(Vec::new()),
            }
        }
        fn calls(&self) -> Vec<String> {
            self.calls.borrow().clone()
        }
    }

    impl CommandRunner for Fake {
        fn run(&self, _exe: &Path, args: &[&str]) -> Result<CmdOutput, String> {
            self.calls.borrow_mut().push(args.join(" "));
            match args {
                ["-rv"] => self.rv.borrow_mut().remove(0),
                ["-rm"] => self.rm.clone().expect("unexpected -rm"),
                _ => Err("unexpected".into()),
            }
        }
    }

    fn out(code: i32, text: &str) -> Result<CmdOutput, String> {
        Ok(CmdOutput {
            exit_code: Some(code),
            text: text.into(),
        })
    }

    const OK_TEXT: &str = "ok....C:\\Windows\\System32\\crypt32.dll\r\nok....C:\\Windows\\System32\\schannel.dll\r\nVerified hash for 2 files\r\n";
    const FAIL_TEXT: &str = "ok....C:\\Windows\\System32\\crypt32.dll\r\nfail..C:\\Windows\\System32\\sspicli.dll\r\nVerify hash failed for 1 files\r\n";

    fn installed() -> Detection {
        Detection::Installed(PathBuf::from(
            r"C:\Program Files\Crypto Pro\CSP\cpverify.exe",
        ))
    }

    #[test]
    fn t01_absent_is_not_installed() {
        let root = std::env::temp_dir().join(format!("wsd-cp-none-{}", std::process::id()));
        assert_eq!(detect(&[root]), Detection::NotInstalled);
        let fake = Fake::new(vec![], None);
        assert_eq!(
            check(&Detection::NotInstalled, &fake),
            HashState::NotInstalled
        );
        assert!(fake.calls().is_empty(), "nothing is run");
    }

    #[test]
    fn detect_finds_cpverify_in_a_cyrillic_path_with_spaces() {
        let root = std::env::temp_dir().join(format!("wsd-cp Программы {}", std::process::id()));
        let dir = root.join("Crypto Pro").join("CSP");
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(detect(&[root.clone()]), Detection::NoVerifier(dir.clone()));
        std::fs::write(dir.join("cpverify.exe"), b"").unwrap();
        assert_eq!(
            detect(&[PathBuf::from("Z:\\nope"), root.clone()]),
            Detection::Installed(dir.join("cpverify.exe"))
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn t02_valid_hash_is_hash_ok_and_check_is_read_only() {
        let fake = Fake::new(vec![out(0, OK_TEXT)], None);
        assert_eq!(check(&installed(), &fake), HashState::HashOk);
        assert_eq!(fake.calls(), vec!["-rv"]);
    }

    #[test]
    fn t03_missing_hash_is_no_hash() {
        let fake = Fake::new(vec![out(1, FAIL_TEXT)], None);
        assert_eq!(check(&installed(), &fake), HashState::NoHash);
    }

    #[test]
    fn t04_failed_or_ambiguous_check_is_check_error() {
        for r in [
            out(0, ""),
            out(2, "Usage: cpverify ..."),
            out(3, OK_TEXT),
            Err("access denied".into()),
        ] {
            let fake = Fake::new(vec![r], None);
            assert!(matches!(
                check(&installed(), &fake),
                HashState::CheckError(_)
            ));
        }
        let no_exe = Detection::NoVerifier(PathBuf::from(r"C:\Program Files\Crypto Pro\CSP"));
        assert!(matches!(
            check(&no_exe, &Fake::new(vec![], None)),
            HashState::CheckError(_)
        ));
    }

    #[test]
    fn t05_rehash_then_verified_is_hash_ok() {
        let fake = Fake::new(vec![out(0, OK_TEXT)], Some(out(0, "done")));
        let r = rehash(&installed(), &HashState::NoHash, &fake);
        assert_eq!(r.state, HashState::HashOk);
        assert_eq!(fake.calls(), vec!["-rm", "-rv"], "verify after ReHash");
        assert!(r.journal.iter().any(|l| l.starts_with("[PASS]")));
    }

    #[test]
    fn t06_failed_rehash_is_check_error() {
        let fake = Fake::new(vec![], Some(out(5, "error")));
        let r = rehash(&installed(), &HashState::NoHash, &fake);
        assert!(matches!(r.state, HashState::CheckError(_)));
        assert!(r.journal.iter().any(|l| l.starts_with("[FAIL]")));
        let fake = Fake::new(vec![], Some(Err("не запустился".into())));
        assert!(matches!(
            rehash(&installed(), &HashState::NoHash, &fake).state,
            HashState::CheckError(_)
        ));
    }

    #[test]
    fn t07_exit_zero_but_still_no_hash_stays_no_hash() {
        let fake = Fake::new(vec![out(1, FAIL_TEXT)], Some(out(0, "")));
        let r = rehash(&installed(), &HashState::NoHash, &fake);
        assert_eq!(
            r.state,
            HashState::NoHash,
            "exit 0 alone never means HASH OK"
        );
        assert!(r.journal.iter().any(|l| l.contains("по-прежнему")));
    }

    /// Real CryptoPro CSP 5.0.13800 KC1 shape: 112 ok / 12 fail, exit code 2.
    /// A recognized fail verdict is NO_HASH even though the exit code is
    /// non-zero — it must never be reported as CHECK_ERROR.
    #[test]
    fn t12_real_confirmed_fail_shape_112_ok_12_fail_exit_2_is_no_hash() {
        let mut text = String::new();
        for i in 0..112 {
            text.push_str(&format!("ok....C:\\Windows\\System32\\file{i}.dll\r\n"));
        }
        for i in 0..12 {
            text.push_str(&format!("fail..C:\\Windows\\System32\\bad{i}.dll\r\n"));
        }
        text.push_str("Verified hash for 112 files\r\n");
        text.push_str("Verify hash failed for 12 files\r\n");
        text.push_str("Verify hash entries failed\r\n");

        let fake = Fake::new(vec![out(2, &text)], None);
        assert_eq!(
            check(&installed(), &fake),
            HashState::NoHash,
            "recognized fail output + non-zero exit code must be NO_HASH, not CHECK_ERROR"
        );
    }

    #[test]
    fn t08_t09_t10_rehash_unavailable_outside_no_hash() {
        for s in [
            HashState::HashOk,
            HashState::NotInstalled,
            HashState::CheckError("x".into()),
        ] {
            assert!(!s.rehash_available());
            let fake = Fake::new(vec![], None);
            let r = rehash(&installed(), &s, &fake);
            assert_eq!(r.state, s);
            assert!(fake.calls().is_empty(), "no mutating command for {s:?}");
        }
        assert!(HashState::NoHash.rehash_available());
    }

    #[test]
    fn t11_one_state_one_label() {
        let all = [
            HashState::HashOk,
            HashState::NoHash,
            HashState::NotInstalled,
            HashState::CheckError(String::new()),
        ];
        for s in &all {
            let l = s.label();
            assert!(!(l.contains("HASH OK") && l.contains("NO HASH")));
        }
        let labels: std::collections::BTreeSet<_> = all.iter().map(|s| s.label()).collect();
        assert_eq!(labels.len(), 4);
    }
}
