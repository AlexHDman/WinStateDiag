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

// ---------------------------------------------------------------------
// v1.0 startup inventory (read-only, registry only)
// ---------------------------------------------------------------------
//
// Launched automatically at startup: presence, version, licence key and
// licence term of CryptoPro CSP, read from the registry only — no process
// is started (no cpverify, no csptest), nothing is written and ReHash is
// never involved. The integrity HASH check stays with the diagnostic.

/// Read-only view of HKLM (64- and 32-bit views); faked in tests.
pub trait RegistryView {
    /// Subkey names of `path` under HKLM (empty when absent).
    fn subkeys(&self, path: &str) -> Vec<String>;
    /// A REG_SZ value of `path` under HKLM.
    fn string(&self, path: &str, name: &str) -> Option<String>;
}

pub const UNINSTALL_ROOTS: [&str; 2] = [
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
    "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
];
const INSTALLER_PRODUCTS: &str =
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Installer\\UserData\\S-1-5-18\\Products";

/// Licence key installed for the CSP product.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LicenseKey {
    /// A serial number is registered; only its first group is kept
    /// (`5050Z-*****`) — the full key never enters journal or evidence.
    Installed {
        masked: String,
    },
    NotFound,
}

/// Licence term. Windows CryptoPro CSP has no documented read-only source
/// for the expiry (the `cpconfig -license -view` CLI exists on Linux
/// only), so it is never guessed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LicenseTerm {
    NotDetermined,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inventory {
    /// `None` = CryptoPro CSP is not installed.
    pub product: Option<CspProduct>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CspProduct {
    pub name: String,
    pub version: String,
    pub product_code: String,
    pub license: LicenseKey,
    pub term: LicenseTerm,
}

impl Inventory {
    pub fn installed(&self) -> bool {
        self.product.is_some()
    }

    /// Startup journal lines (RU).
    pub fn journal(&self) -> Vec<String> {
        let Some(p) = &self.product else {
            return vec![
                "[INFO] CryptoPro CSP: не установлен (проверка реестра, только чтение).".into(),
            ];
        };
        let version = if p.version.is_empty() {
            "версия не указана".to_string()
        } else {
            p.version.clone()
        };
        let license = match &p.license {
            LicenseKey::Installed { masked } => format!("ключ установлен ({masked})"),
            LicenseKey::NotFound => "ключ в реестре не найден".to_string(),
        };
        vec![
            format!("[INFO] CryptoPro CSP обнаружен: {version}."),
            format!("[INFO] CryptoPro CSP: лицензия — {license}."),
            "[INFO] CryptoPro CSP: срок действия лицензии — НЕ ОПРЕДЕЛЁН (нет документированного read-only источника в Windows; см. «Управление лицензиями КриптоПро PKI»)."
                .into(),
            "[INFO] CryptoPro HASH проверяется при запуске диагностики (ReHash автоматически не выполняется).".into(),
        ]
    }
}

/// `{50F91F80-D397-437C-B0C8-62128DE3B55E}` → `08F19F05793DC7340B8C2621D83E5BE5`
/// (the Windows Installer packed product code).
pub fn packed_product_code(guid: &str) -> Option<String> {
    let hex: String = guid.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    let g = guid.trim();
    if hex.len() != 32 || !(g.starts_with('{') && g.ends_with('}')) {
        return None;
    }
    let rev = |s: &str| s.chars().rev().collect::<String>();
    let mut out = String::new();
    out.push_str(&rev(&hex[0..8]));
    out.push_str(&rev(&hex[8..12]));
    out.push_str(&rev(&hex[12..16]));
    for i in (16..32).step_by(2) {
        out.push_str(&rev(&hex[i..i + 2]));
    }
    Some(out.to_ascii_uppercase())
}

/// `5050Z-ABCDE-…` → `5050Z-*****`.
pub fn mask_serial(serial: &str) -> String {
    let s = serial.trim();
    let head: String = s.chars().take_while(|c| *c != '-').take(5).collect();
    format!("{head}-*****")
}

fn is_csp_name(name: &str) -> bool {
    let n = name.trim().to_lowercase();
    (n.starts_with("криптопро csp")
        || n.starts_with("cryptopro csp")
        || n.starts_with("crypto-pro csp"))
        && !n.contains("plug-in")
}

/// Startup inventory from the registry. Read-only.
pub fn inventory(reg: &dyn RegistryView) -> Inventory {
    for root in UNINSTALL_ROOTS {
        for key in reg.subkeys(root) {
            let path = format!("{root}\\{key}");
            let Some(name) = reg.string(&path, "DisplayName") else {
                continue;
            };
            if !is_csp_name(&name) {
                continue;
            }
            let version = reg
                .string(&path, "DisplayVersion")
                .unwrap_or_default()
                .trim()
                .to_string();
            let serial = packed_product_code(&key).and_then(|packed| {
                reg.string(
                    &format!("{INSTALLER_PRODUCTS}\\{packed}\\InstallProperties"),
                    "ProductID",
                )
            });
            let license = match serial.filter(|s| !s.trim().is_empty()) {
                Some(s) => LicenseKey::Installed {
                    masked: mask_serial(&s),
                },
                None => LicenseKey::NotFound,
            };
            return Inventory {
                product: Some(CspProduct {
                    name: name.trim().to_string(),
                    version,
                    product_code: key,
                    license,
                    term: LicenseTerm::NotDetermined,
                }),
            };
        }
    }
    Inventory { product: None }
}

/// The real HKLM view (64-bit and 32-bit registry), read-only access.
pub struct SystemRegistry;

#[cfg(windows)]
mod winreg {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    const HKEY_LOCAL_MACHINE: isize = 0x8000_0002_u32 as i32 as isize;
    const KEY_READ: u32 = 0x2_0019;
    const KEY_WOW64_64KEY: u32 = 0x0100;
    const RRF_RT_REG_SZ: u32 = 0x0000_0002;
    const RRF_SUBKEY_WOW6464KEY: u32 = 0x0001_0000;

    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn RegOpenKeyExW(
            hkey: isize,
            sub_key: *const u16,
            options: u32,
            sam: u32,
            result: *mut isize,
        ) -> i32;
        fn RegEnumKeyExW(
            hkey: isize,
            index: u32,
            name: *mut u16,
            name_len: *mut u32,
            reserved: *mut u32,
            class: *mut u16,
            class_len: *mut u32,
            last_write: *mut u64,
        ) -> i32;
        fn RegCloseKey(hkey: isize) -> i32;
        fn RegGetValueW(
            hkey: isize,
            sub_key: *const u16,
            value: *const u16,
            flags: u32,
            ty: *mut u32,
            data: *mut u16,
            len: *mut u32,
        ) -> i32;
    }

    fn wide(s: &str) -> Vec<u16> {
        OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    pub fn subkeys(path: &str) -> Vec<String> {
        let mut key: isize = 0;
        let p = wide(path);
        let rc = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                p.as_ptr(),
                0,
                KEY_READ | KEY_WOW64_64KEY,
                &mut key,
            )
        };
        if rc != 0 {
            return Vec::new();
        }
        let mut out = Vec::new();
        let mut i = 0u32;
        loop {
            let mut buf = [0u16; 256];
            let mut len = buf.len() as u32;
            let rc = unsafe {
                RegEnumKeyExW(
                    key,
                    i,
                    buf.as_mut_ptr(),
                    &mut len,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            if rc != 0 || i > 10_000 {
                break;
            }
            out.push(String::from_utf16_lossy(&buf[..len as usize]));
            i += 1;
        }
        unsafe { RegCloseKey(key) };
        out
    }

    pub fn string(path: &str, name: &str) -> Option<String> {
        let p = wide(path);
        let n = wide(name);
        let mut buf = vec![0u16; 1024];
        let mut len = (buf.len() * 2) as u32;
        let rc = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                p.as_ptr(),
                n.as_ptr(),
                RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY,
                std::ptr::null_mut(),
                buf.as_mut_ptr(),
                &mut len,
            )
        };
        if rc != 0 {
            return None;
        }
        let chars = (len as usize / 2).saturating_sub(1).min(buf.len());
        Some(String::from_utf16_lossy(&buf[..chars]))
    }
}

impl RegistryView for SystemRegistry {
    fn subkeys(&self, path: &str) -> Vec<String> {
        #[cfg(windows)]
        {
            winreg::subkeys(path)
        }
        #[cfg(not(windows))]
        {
            let _ = path;
            Vec::new()
        }
    }
    fn string(&self, path: &str, name: &str) -> Option<String> {
        #[cfg(windows)]
        {
            winreg::string(path, name)
        }
        #[cfg(not(windows))]
        {
            let _ = (path, name);
            None
        }
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

    /// Fake HKLM: (path, name) → value; subkeys derived from the paths.
    struct FakeReg(Vec<(String, String, String)>);

    impl RegistryView for FakeReg {
        fn subkeys(&self, path: &str) -> Vec<String> {
            let prefix = format!("{path}\\");
            let mut out: Vec<String> = Vec::new();
            for (p, _, _) in &self.0 {
                if let Some(rest) = p.strip_prefix(&prefix) {
                    let k = rest.split('\\').next().unwrap_or(rest).to_string();
                    if !out.contains(&k) {
                        out.push(k);
                    }
                }
            }
            out
        }
        fn string(&self, path: &str, name: &str) -> Option<String> {
            self.0
                .iter()
                .find(|(p, n, _)| p == path && n == name)
                .map(|(_, _, v)| v.clone())
        }
    }

    fn entry(p: &str, n: &str, v: &str) -> (String, String, String) {
        (p.into(), n.into(), v.into())
    }

    /// v1.0: the startup inventory of the real MSI layout — CSP 5.0.13800
    /// under the 64-bit Uninstall key, the browser plug-in next to it, the
    /// licence serial under the packed product code.
    #[test]
    fn startup_inventory_reads_presence_version_and_masked_licence() {
        let u = UNINSTALL_ROOTS[0];
        let csp = "{50F91F80-D397-437C-B0C8-62128DE3B55E}";
        let reg = FakeReg(vec![
            entry(
                &format!("{u}\\{{E12CC7EE-36B7-4AAA-924E-2F5CD75BCECF}}"),
                "DisplayName",
                "КриптоПро ЭЦП Browser plug-in",
            ),
            entry(&format!("{u}\\{csp}"), "DisplayName", "КриптоПро CSP"),
            entry(&format!("{u}\\{csp}"), "DisplayVersion", "5.0.13800"),
            entry(
                &format!(
                    "{INSTALLER_PRODUCTS}\\08F19F05793DC7340B8C2621D83E5BE5\\InstallProperties"
                ),
                "ProductID",
                "5050Z-ABCDE-FGHIJ-KLMNO-PQRST",
            ),
        ]);
        let inv = inventory(&reg);
        let p = inv.product.clone().expect("installed");
        assert_eq!(p.version, "5.0.13800");
        assert_eq!(
            p.license,
            LicenseKey::Installed {
                masked: "5050Z-*****".into()
            }
        );
        assert_eq!(p.term, LicenseTerm::NotDetermined);
        let j = inv.journal().join("\n");
        assert!(j.contains("5.0.13800"), "{j}");
        assert!(j.contains("5050Z-*****"), "{j}");
        assert!(
            !j.contains("ABCDE"),
            "the full serial never leaves the registry"
        );
        assert!(j.contains("НЕ ОПРЕДЕЛЁН"), "expiry never guessed: {j}");
        assert!(j.contains("ReHash автоматически не выполняется"), "{j}");
    }

    #[test]
    fn startup_inventory_absent_or_without_licence() {
        assert_eq!(inventory(&FakeReg(vec![])), Inventory { product: None });
        assert!(inventory(&FakeReg(vec![])).journal()[0].contains("не установлен"));
        // 32-bit registration, no licence key registered.
        let u = UNINSTALL_ROOTS[1];
        let reg = FakeReg(vec![entry(
            &format!("{u}\\{{11111111-2222-3333-4444-555555555555}}"),
            "DisplayName",
            "CryptoPro CSP",
        )]);
        let p = inventory(&reg).product.expect("installed");
        assert_eq!(p.license, LicenseKey::NotFound);
        assert!(p.version.is_empty());
        assert!(inventory(&reg).journal()[0].contains("версия не указана"));
    }

    #[test]
    fn packed_product_code_and_serial_mask() {
        assert_eq!(
            packed_product_code("{50F91F80-D397-437C-B0C8-62128DE3B55E}").as_deref(),
            Some("08F19F05793DC7340B8C2621D83E5BE5")
        );
        assert_eq!(packed_product_code("not-a-guid"), None);
        assert_eq!(mask_serial("5050Z-ABCDE"), "5050Z-*****");
        assert_eq!(mask_serial("ABCDEFGHIJ"), "ABCDE-*****");
    }

    /// The startup inventory is registry-only: no process, no ReHash.
    #[test]
    fn startup_inventory_starts_no_process_and_never_rehashes() {
        let src = include_str!("cryptopro.rs").replace("\r\n", "\n");
        let start = src
            .find("pub fn inventory(reg: &dyn RegistryView)")
            .unwrap();
        let end = start + src[start..].find("\n}\n").unwrap();
        let body = &src[start..end];
        for banned in [
            "Command",
            "run(",
            "rehash",
            "-rm",
            "cpverify",
            "RegSet",
            "RegCreate",
        ] {
            assert!(!body.contains(banned), "{banned} in the inventory");
        }
        let reg_mod = &src[src.find("mod winreg {").unwrap()..];
        let reg_mod = &reg_mod[..reg_mod
            .find("\nimpl RegistryView for SystemRegistry")
            .unwrap()];
        for banned in [
            "RegSetValue",
            "RegCreateKey",
            "RegDelete",
            "KEY_WRITE",
            "KEY_SET_VALUE",
        ] {
            assert!(
                !reg_mod.contains(banned),
                "{banned}: registry access is read-only"
            );
        }
    }

    /// Live read of this machine's registry (never fails: CryptoPro may
    /// be absent); proves the FFI path works.
    #[test]
    fn startup_inventory_live_registry_read_is_consistent() {
        let inv = inventory(&SystemRegistry);
        eprintln!("live CryptoPro inventory: {inv:?}");
        if let Some(p) = &inv.product {
            assert!(is_csp_name(&p.name), "{p:?}");
            if let LicenseKey::Installed { masked } = &p.license {
                assert!(masked.ends_with("-*****"));
            }
        }
    }
}
