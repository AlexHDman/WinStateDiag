//! Safe Graphics Startup: a small supervisor that keeps WinStateDiag
//! reachable when a GPU driver or the graphics stack is broken.
//!
//! Why a separate process: a failing vendor driver can terminate the process
//! from native code (for example the legacy AMD OpenGL driver shows
//! "LoadLibrary failed with error 87" and ends the process with exit code 87;
//! the Intel Vulkan driver `igvk64.dll` crashed with 0xC0000005). Neither can be
//! caught with `catch_unwind`, so the renderer runs in a child process and this
//! module decides, from the child's handshake and exit status, whether to try
//! the safe renderer.
//!
//! Flow (no loops): the bootstrap process (no `--graphics-mode=` argument)
//! starts one NORMAL child. If it fails before its first painted frame, the
//! bootstrap starts one SAFE child. If that also fails, it shows a native
//! message box with the path of the startup log. A child never spawns
//! anything.
//!
//! This module has no dependency on eframe/egui/wgpu; renderer settings live in
//! `graphics_wgpu.rs`.

use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

/// Internal argument that selects the renderer mode of a child process.
pub const ARG_MODE_PREFIX: &str = "--graphics-mode=";
/// Environment variable carrying the handshake file path to a supervised child.
pub const ENV_HANDSHAKE: &str = "WSD_GRAPHICS_HANDSHAKE";
/// File name of the startup log.
pub const LOG_FILE_NAME: &str = "startup_graphics.log";
/// Exit code of a child whose renderer initialisation returned an error.
pub const EXIT_RENDERER_INIT_FAILED: i32 = 3;
/// Exit code of the bootstrap when no renderer could start.
pub const EXIT_NO_RENDERER: i32 = 4;
/// Exit code for an invalid `--graphics-mode=` value.
pub const EXIT_INVALID_MODE: i32 = 2;
/// How long a child may take to paint its first frame.
pub const READY_TIMEOUT: Duration = Duration::from_secs(60);
const LOG_MAX_BYTES: u64 = 512 * 1024;

// ---------------------------------------------------------------------
// Modes and roles (pure)
// ---------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum GraphicsMode {
    /// Direct3D 12 on a hardware adapter (Vulkan and OpenGL are never loaded).
    Normal,
    /// Direct3D 12 on the Microsoft software rasteriser (WARP).
    Safe,
}

impl GraphicsMode {
    pub fn name(self) -> &'static str {
        match self {
            GraphicsMode::Normal => "normal",
            GraphicsMode::Safe => "safe",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "normal" => Some(GraphicsMode::Normal),
            "safe" => Some(GraphicsMode::Safe),
            _ => None,
        }
    }

    pub fn arg(self) -> String {
        format!("{ARG_MODE_PREFIX}{}", self.name())
    }

    pub fn description(self) -> &'static str {
        match self {
            GraphicsMode::Normal => "Direct3D 12, hardware adapter (Vulkan/OpenGL not loaded)",
            GraphicsMode::Safe => "Direct3D 12, Microsoft WARP software adapter",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    /// Supervisor: starts renderer children, never renders itself.
    Bootstrap,
    /// Renderer process. `supervised` = started by the bootstrap (handshake
    /// expected); unsupervised = started by hand with `--graphics-mode=`.
    Renderer {
        mode: GraphicsMode,
        supervised: bool,
    },
}

/// Role of this process from its arguments (without the program name) and
/// the handshake environment variable.
pub fn parse_role(args: &[String], handshake_env: Option<&str>) -> Result<Role, String> {
    let modes: Vec<&str> = args
        .iter()
        .filter_map(|a| a.strip_prefix(ARG_MODE_PREFIX))
        .collect();
    match modes.as_slice() {
        [] => Ok(Role::Bootstrap),
        [value] => match GraphicsMode::parse(value) {
            Some(mode) => Ok(Role::Renderer {
                mode,
                supervised: handshake_env.is_some_and(|p| !p.trim().is_empty()),
            }),
            None => Err(format!(
                "invalid graphics mode '{value}' (expected normal or safe)"
            )),
        },
        _ => Err("graphics mode given more than once".into()),
    }
}

/// Arguments for a child: the user's arguments without any graphics mode,
/// plus the requested mode.
pub fn child_args(user_args: &[String], mode: GraphicsMode) -> Vec<String> {
    let mut out: Vec<String> = user_args
        .iter()
        .filter(|a| !a.starts_with(ARG_MODE_PREFIX))
        .cloned()
        .collect();
    out.push(mode.arg());
    out
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum AttemptOutcome {
    /// The child painted its first frame (handshake file seen).
    Ready,
    /// The child exited before it was ready. `None` = no exit code.
    ExitedBeforeReady { code: Option<i32> },
    /// No handshake within the timeout; the child was terminated.
    TimedOut,
    /// The child process could not be started.
    SpawnFailed(String),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Decision {
    /// Renderer works: keep waiting for the child and exit with its code.
    Supervise,
    /// Stop now with this exit code (clean exit before the first frame).
    Exit(i32),
    /// Try the safe renderer next.
    TrySafe,
    /// No renderer left: show the final native error.
    GiveUp,
}

/// The whole fallback policy. Only a NORMAL failure leads to SAFE; a SAFE
/// failure never leads anywhere but the final error, so there is no loop.
pub fn decide(mode: GraphicsMode, outcome: &AttemptOutcome) -> Decision {
    match outcome {
        AttemptOutcome::Ready => Decision::Supervise,
        AttemptOutcome::ExitedBeforeReady { code: Some(0) } => Decision::Exit(0),
        _ => match mode {
            GraphicsMode::Normal => Decision::TrySafe,
            GraphicsMode::Safe => Decision::GiveUp,
        },
    }
}

/// Human-readable exit code, including the Windows status codes seen in the
/// field.
pub fn describe_exit_code(code: Option<i32>) -> String {
    let Some(code) = code else {
        return "no exit code (terminated)".into();
    };
    let raw = code as u32;
    let note = match raw {
        0 => "success",
        3 => "renderer initialisation failed",
        87 => {
            "ERROR_INVALID_PARAMETER; matches the driver dialog 'LoadLibrary failed with error 87'"
        }
        0xC000_0005 => "access violation (native crash)",
        0xC000_001D => "illegal instruction (native crash)",
        0xC000_0135 => "DLL not found",
        0xC000_0142 => "DLL initialisation failed",
        0xC000_0409 => "fail-fast / Rust panic (abort)",
        0xC000_013A => "terminated (Ctrl+C / close)",
        _ => "",
    };
    let base = if raw >= 0xC000_0000 {
        format!("0x{raw:08X}")
    } else {
        format!("{code} (0x{raw:08X})")
    };
    if note.is_empty() {
        base
    } else {
        format!("{base} — {note}")
    }
}

// ---------------------------------------------------------------------
// Startup log
// ---------------------------------------------------------------------

/// Appends short lines to `startup_graphics.log`. No personal data: only
/// Windows version, session type, modes, adapters and exit codes.
#[derive(Clone, Debug)]
pub struct StartupLog {
    path: PathBuf,
    tag: String,
    /// `<EXE>\Reports`: the log lives in this PC's report folder of today
    /// (`Reports\<Client - Computer - DD-MM-YY>\`), found again for every
    /// line so a later rename of that folder (client added) is followed.
    reports_root: Option<PathBuf>,
}

impl StartupLog {
    /// `Reports\<Client - Computer - DD-MM-YY>\startup_graphics.log` next to
    /// the EXE (the one report folder of this PC and date); if that is not
    /// writable, `%TEMP%\WinStateDiag\startup_graphics.log`.
    pub fn open(tag: &str) -> Self {
        let exe_reports = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join("Reports")));
        if let Some(root) = exe_reports {
            let dir = report_dir_for_today(&root);
            if is_writable_dir(&dir) {
                let mut log = Self::at(&dir, tag);
                log.reports_root = Some(root);
                return log;
            }
        }
        let temp = std::env::temp_dir().join("WinStateDiag");
        let dir = if is_writable_dir(&temp) {
            temp
        } else {
            std::env::temp_dir()
        };
        Self::at(&dir, tag)
    }

    pub fn at(dir: &Path, tag: &str) -> Self {
        let _ = fs::create_dir_all(dir);
        let path = dir.join(LOG_FILE_NAME);
        if fs::metadata(&path)
            .map(|m| m.len() > LOG_MAX_BYTES)
            .unwrap_or(false)
        {
            let _ = fs::rename(&path, dir.join(format!("{LOG_FILE_NAME}.old")));
        }
        Self {
            path,
            tag: tag.to_string(),
            reports_root: None,
        }
    }

    /// Current log file (follows the report folder of this PC and date).
    pub fn path(&self) -> PathBuf {
        match &self.reports_root {
            Some(root) => report_dir_for_today(root).join(LOG_FILE_NAME),
            None => self.path.clone(),
        }
    }

    pub fn line(&self, text: &str) {
        let path = self.path();
        if let Some(dir) = path.parent() {
            let _ = fs::create_dir_all(dir);
        }
        let now = crate::ui::sysinfo::local_time();
        let line = format!(
            "{} {} [{} pid {}] {}\r\n",
            now.date_dmy(),
            now.hms(),
            self.tag,
            std::process::id(),
            text
        );
        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&path) {
            let _ = f.write_all(line.as_bytes());
        }
    }
}

/// Today's report folder of this PC under `root` (the one folder per PC and
/// date, see report_package).
fn report_dir_for_today(root: &Path) -> PathBuf {
    let date = crate::report_package::identity_date(crate::ui::sysinfo::local_time());
    crate::report_package::find_or_new_report_dir(
        root,
        "",
        &crate::report_package::computer_name(),
        &date,
    )
}

fn is_writable_dir(dir: &Path) -> bool {
    if fs::create_dir_all(dir).is_err() {
        return false;
    }
    let probe = dir.join(format!(".wsd-write-probe-{}", std::process::id()));
    let ok = fs::write(&probe, b"").is_ok();
    let _ = fs::remove_file(&probe);
    ok
}

/// One-line environment summary for the log.
pub fn environment_summary() -> String {
    let (edition, build) = crate::ui::sysinfo::windows_edition_and_build();
    format!(
        "WinStateDiag v{}; {} build {}; session: {}",
        env!("CARGO_PKG_VERSION"),
        edition,
        if build.is_empty() { "?" } else { &build },
        session_kind()
    )
}

// ---------------------------------------------------------------------
// Handshake (child side)
// ---------------------------------------------------------------------

/// Called by a supervised child once its first frame has been painted.
pub fn signal_ready(handshake: &Path, detail: &str) {
    let _ = fs::write(handshake, detail.as_bytes());
}

pub fn handshake_path(dir: &Path, mode: GraphicsMode) -> PathBuf {
    dir.join(format!(
        "startup-{}-{}.ready",
        std::process::id(),
        mode.name()
    ))
}

// ---------------------------------------------------------------------
// Bootstrap (supervisor side)
// ---------------------------------------------------------------------

/// Anything that looks like a started child (real process or test double).
pub trait ChildProcess {
    /// `Ok(Some(code))` when exited (`code` = None if no exit code).
    fn poll_exit(&mut self) -> Result<Option<Option<i32>>, String>;
    fn wait_exit(&mut self) -> Option<i32>;
    fn terminate(&mut self);
}

impl ChildProcess for Child {
    fn poll_exit(&mut self) -> Result<Option<Option<i32>>, String> {
        self.try_wait()
            .map(|s| s.map(|st| st.code()))
            .map_err(|e| e.to_string())
    }
    fn wait_exit(&mut self) -> Option<i32> {
        self.wait().ok().and_then(|s| s.code())
    }
    fn terminate(&mut self) {
        let _ = self.kill();
        let _ = self.wait();
    }
}

/// Waits until the child is ready (handshake file exists), exits, or the
/// timeout passes (then the child is terminated).
pub fn wait_for_ready(
    child: &mut dyn ChildProcess,
    handshake: &Path,
    timeout: Duration,
    poll: Duration,
) -> AttemptOutcome {
    let started = Instant::now();
    loop {
        if handshake.exists() {
            return AttemptOutcome::Ready;
        }
        match child.poll_exit() {
            Ok(Some(code)) => {
                // It may have signalled and exited in the same instant.
                if handshake.exists() {
                    return AttemptOutcome::Ready;
                }
                return AttemptOutcome::ExitedBeforeReady { code };
            }
            Ok(None) => {}
            Err(e) => return AttemptOutcome::SpawnFailed(e),
        }
        if started.elapsed() >= timeout {
            child.terminate();
            return AttemptOutcome::TimedOut;
        }
        std::thread::sleep(poll);
    }
}

/// Starts a child in `mode` (production spawner).
fn spawn_renderer(
    user_args: &[String],
    mode: GraphicsMode,
    handshake: &Path,
) -> Result<Child, String> {
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    Command::new(exe)
        .args(child_args(user_args, mode))
        .env(ENV_HANDSHAKE, handshake)
        .spawn()
        .map_err(|e| e.to_string())
}

/// The supervisor loop with an injectable spawner (unit tested).
/// Returns the exit code for this process and the mode that worked.
pub fn run_attempts<S>(
    log: &StartupLog,
    handshake_dir: &Path,
    mut spawn: S,
    timeout: Duration,
    poll: Duration,
) -> (i32, Option<GraphicsMode>)
where
    S: FnMut(GraphicsMode, &Path) -> Result<Box<dyn ChildProcess>, String>,
{
    let mut mode = GraphicsMode::Normal;
    let mut last_code = None;
    loop {
        let handshake = handshake_path(handshake_dir, mode);
        let _ = fs::create_dir_all(handshake_dir);
        let _ = fs::remove_file(&handshake);
        log.line(&format!(
            "attempt: requested renderer = {} ({})",
            mode.name(),
            mode.description()
        ));
        let outcome = match spawn(mode, &handshake) {
            Ok(mut child) => {
                let outcome = wait_for_ready(child.as_mut(), &handshake, timeout, poll);
                match decide(mode, &outcome) {
                    Decision::Supervise => {
                        let detail = fs::read_to_string(&handshake).unwrap_or_default();
                        let _ = fs::remove_file(&handshake);
                        log.line(&format!(
                            "success: {} renderer ready ({})",
                            mode.name(),
                            detail.trim()
                        ));
                        let code = child.wait_exit();
                        log.line(&format!("application exited: {}", describe_exit_code(code)));
                        return (code.unwrap_or(0), Some(mode));
                    }
                    _ => outcome,
                }
            }
            Err(e) => AttemptOutcome::SpawnFailed(e),
        };
        let _ = fs::remove_file(&handshake);
        if let AttemptOutcome::ExitedBeforeReady { code } = &outcome {
            last_code = *code;
        }
        let outcome_text = match &outcome {
            AttemptOutcome::Ready => "ready".to_string(),
            AttemptOutcome::ExitedBeforeReady { code } => {
                format!("exited before first frame: {}", describe_exit_code(*code))
            }
            AttemptOutcome::TimedOut => {
                format!(
                    "no first frame within {} s; child terminated",
                    timeout.as_secs()
                )
            }
            AttemptOutcome::SpawnFailed(e) => format!("could not start: {e}"),
        };
        match decide(mode, &outcome) {
            Decision::Exit(code) => {
                log.line(&format!(
                    "{} renderer: {outcome_text}; exiting",
                    mode.name()
                ));
                return (code, None);
            }
            Decision::TrySafe => {
                log.line(&format!(
                    "failure: normal renderer {outcome_text}; fallback decision: try safe renderer"
                ));
                mode = GraphicsMode::Safe;
            }
            Decision::GiveUp => {
                log.line(&format!(
                    "failure: safe renderer {outcome_text}; no renderer left (last exit code {})",
                    describe_exit_code(last_code)
                ));
                return (EXIT_NO_RENDERER, None);
            }
            Decision::Supervise => unreachable!("handled above"),
        }
    }
}

/// Bootstrap entry point. Returns the process exit code.
pub fn run_bootstrap(user_args: &[String]) -> i32 {
    let log = StartupLog::open("bootstrap");
    log.line(&format!("=== start; {}", environment_summary()));
    let (code, mode) = run_attempts(
        &log,
        &std::env::temp_dir().join("WinStateDiag"),
        |mode, handshake| {
            spawn_renderer(user_args, mode, handshake).map(|c| Box::new(c) as Box<dyn ChildProcess>)
        },
        READY_TIMEOUT,
        Duration::from_millis(50),
    );
    if mode.is_none() && code == EXIT_NO_RENDERER {
        show_native_error(&format!(
            "WinStateDiag не удалось запустить: ни стандартный, ни безопасный графический режим не запустился.\n\n\
             Это похоже на проблему графического драйвера или графической среды (например, RDP).\n\n\
             Подробности записаны в журнал запуска:\n{}",
            log.path().display()
        ));
    }
    code
}

// ---------------------------------------------------------------------
// Windows helpers (no egui involved)
// ---------------------------------------------------------------------

#[cfg(windows)]
mod win {
    #[link(name = "user32")]
    unsafe extern "system" {
        pub fn GetSystemMetrics(index: i32) -> i32;
        pub fn MessageBoxW(hwnd: isize, text: *const u16, caption: *const u16, kind: u32) -> i32;
    }
    pub const SM_REMOTESESSION: i32 = 0x1000;
    pub const MB_OK_ICONERROR: u32 = 0x0000_0010;
    pub const MB_OK_ICONINFORMATION: u32 = 0x0000_0040;
}

/// "RDP" or "local" (SM_REMOTESESSION); "unknown" off Windows.
pub fn session_kind() -> &'static str {
    #[cfg(windows)]
    {
        if unsafe { win::GetSystemMetrics(win::SM_REMOTESESSION) } != 0 {
            "RDP"
        } else {
            "local"
        }
    }
    #[cfg(not(windows))]
    {
        "unknown"
    }
}

fn message_box(text: &str, error: bool) {
    #[cfg(windows)]
    {
        let wide = |s: &str| {
            s.encode_utf16()
                .chain(std::iter::once(0))
                .collect::<Vec<u16>>()
        };
        let text = wide(text);
        let caption = wide("WinStateDiag");
        let kind = if error {
            win::MB_OK_ICONERROR
        } else {
            win::MB_OK_ICONINFORMATION
        };
        unsafe {
            win::MessageBoxW(0, text.as_ptr(), caption.as_ptr(), kind);
        }
    }
    #[cfg(not(windows))]
    {
        let _ = error;
        eprintln!("WinStateDiag: {text}");
    }
}

/// Last-resort native error message (does not depend on any renderer).
pub fn show_native_error(text: &str) {
    message_box(text, true);
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    /// Scripted child: optionally writes the handshake after `ready_after`
    /// polls, and/or exits with `exit` after `exit_after` polls.
    struct FakeChild {
        handshake: PathBuf,
        polls: u32,
        ready_after: Option<u32>,
        exit_after: Option<(u32, Option<i32>)>,
        final_code: Option<i32>,
        terminated: Rc<RefCell<bool>>,
    }

    impl ChildProcess for FakeChild {
        fn poll_exit(&mut self) -> Result<Option<Option<i32>>, String> {
            self.polls += 1;
            if let Some(n) = self.ready_after {
                if self.polls >= n {
                    let _ = fs::write(&self.handshake, "adapter: test");
                }
            }
            match self.exit_after {
                Some((n, code)) if self.polls >= n => Ok(Some(code)),
                _ => Ok(None),
            }
        }
        fn wait_exit(&mut self) -> Option<i32> {
            self.final_code
        }
        fn terminate(&mut self) {
            *self.terminated.borrow_mut() = true;
        }
    }

    #[derive(Clone, Copy)]
    enum Script {
        Ready(i32),
        Exit(Option<i32>),
        Hang,
        SpawnError,
    }

    fn run(scripts: &[Script]) -> (i32, Option<GraphicsMode>, Vec<GraphicsMode>, String, bool) {
        let dir =
            std::env::temp_dir().join(format!("wsd-gs-test-{}-{}", std::process::id(), rand_tag()));
        let log = StartupLog::at(&dir, "test");
        let spawned = Rc::new(RefCell::new(Vec::new()));
        let terminated = Rc::new(RefCell::new(false));
        let scripts = scripts.to_vec();
        let sp = Rc::clone(&spawned);
        let term = Rc::clone(&terminated);
        let (code, mode) = run_attempts(
            &log,
            &dir,
            move |mode, handshake| {
                let idx = sp.borrow().len();
                sp.borrow_mut().push(mode);
                let script = *scripts.get(idx).expect("unexpected extra spawn (loop!)");
                let base = FakeChild {
                    handshake: handshake.to_path_buf(),
                    polls: 0,
                    ready_after: None,
                    exit_after: None,
                    final_code: None,
                    terminated: Rc::clone(&term),
                };
                match script {
                    Script::Ready(code) => Ok(Box::new(FakeChild {
                        ready_after: Some(2),
                        final_code: Some(code),
                        ..base
                    }) as Box<dyn ChildProcess>),
                    Script::Exit(code) => Ok(Box::new(FakeChild {
                        exit_after: Some((2, code)),
                        ..base
                    }) as Box<dyn ChildProcess>),
                    Script::Hang => Ok(Box::new(base) as Box<dyn ChildProcess>),
                    Script::SpawnError => Err("access denied".into()),
                }
            },
            Duration::from_millis(80),
            Duration::from_millis(1),
        );
        let text = fs::read_to_string(log.path()).unwrap_or_default();
        let _ = fs::remove_dir_all(&dir);
        let spawned = spawned.borrow().clone();
        let terminated = *terminated.borrow();
        (code, mode, spawned, text, terminated)
    }

    fn rand_tag() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    }

    #[test]
    fn normal_success_runs_only_the_normal_renderer() {
        let (code, mode, spawned, log, _) = run(&[Script::Ready(0)]);
        assert_eq!(code, 0);
        assert_eq!(mode, Some(GraphicsMode::Normal));
        assert_eq!(spawned, vec![GraphicsMode::Normal]);
        assert!(log.contains("success: normal renderer ready (adapter: test)"));
    }

    #[test]
    fn normal_controlled_failure_tries_safe() {
        let (code, mode, spawned, log, _) = run(&[
            Script::Exit(Some(EXIT_RENDERER_INIT_FAILED)),
            Script::Ready(0),
        ]);
        assert_eq!(spawned, vec![GraphicsMode::Normal, GraphicsMode::Safe]);
        assert_eq!(mode, Some(GraphicsMode::Safe));
        assert_eq!(code, 0);
        assert!(log.contains("fallback decision: try safe renderer"));
        assert!(log.contains("success: safe renderer ready"));
    }

    #[test]
    fn normal_crash_or_driver_exit_87_tries_safe() {
        for code in [0xC000_0005_u32 as i32, 87] {
            let (_, mode, spawned, log, _) = run(&[Script::Exit(Some(code)), Script::Ready(0)]);
            assert_eq!(spawned, vec![GraphicsMode::Normal, GraphicsMode::Safe]);
            assert_eq!(mode, Some(GraphicsMode::Safe));
            assert!(log.contains(&describe_exit_code(Some(code))));
        }
        // Killed without exit code, hang and spawn errors also fall back.
        let (_, mode, _, _, _) = run(&[Script::Exit(None), Script::Ready(0)]);
        assert_eq!(mode, Some(GraphicsMode::Safe));
        let (_, mode, _, _, terminated) = run(&[Script::Hang, Script::Ready(0)]);
        assert_eq!(mode, Some(GraphicsMode::Safe));
        assert!(terminated, "a hung child must be terminated");
        let (_, mode, _, _, _) = run(&[Script::SpawnError, Script::Ready(0)]);
        assert_eq!(mode, Some(GraphicsMode::Safe));
    }

    #[test]
    fn safe_success_propagates_the_application_exit_code() {
        let (code, mode, _, log, _) = run(&[Script::Exit(Some(87)), Script::Ready(5)]);
        assert_eq!(mode, Some(GraphicsMode::Safe));
        assert_eq!(code, 5);
        assert!(log.contains("application exited: 5"));
    }

    #[test]
    fn safe_failure_gives_final_error_without_loop() {
        let (code, mode, spawned, log, _) = run(&[
            Script::Exit(Some(87)),
            Script::Exit(Some(0xC000_0005_u32 as i32)),
        ]);
        assert_eq!(code, EXIT_NO_RENDERER);
        assert_eq!(mode, None);
        // Exactly two attempts; a third spawn would panic in the fake.
        assert_eq!(spawned, vec![GraphicsMode::Normal, GraphicsMode::Safe]);
        assert!(log.contains("no renderer left"));
    }

    #[test]
    fn decision_table_never_leads_back_to_normal() {
        let outcomes = [
            AttemptOutcome::Ready,
            AttemptOutcome::ExitedBeforeReady { code: Some(0) },
            AttemptOutcome::ExitedBeforeReady { code: Some(87) },
            AttemptOutcome::ExitedBeforeReady { code: None },
            AttemptOutcome::TimedOut,
            AttemptOutcome::SpawnFailed("x".into()),
        ];
        for o in &outcomes {
            assert_ne!(decide(GraphicsMode::Safe, o), Decision::TrySafe);
        }
        assert_eq!(
            decide(GraphicsMode::Normal, &AttemptOutcome::TimedOut),
            Decision::TrySafe
        );
        assert_eq!(
            decide(
                GraphicsMode::Normal,
                &AttemptOutcome::ExitedBeforeReady { code: Some(0) }
            ),
            Decision::Exit(0)
        );
        assert_eq!(
            decide(GraphicsMode::Safe, &AttemptOutcome::Ready),
            Decision::Supervise
        );
    }

    #[test]
    fn clean_exit_before_first_frame_is_not_a_graphics_failure() {
        let (code, mode, spawned, _, _) = run(&[Script::Exit(Some(0))]);
        assert_eq!(code, 0);
        assert_eq!(mode, None);
        assert_eq!(spawned, vec![GraphicsMode::Normal]);
    }

    #[test]
    fn roles_and_invalid_mode() {
        assert_eq!(parse_role(&s(&[]), None), Ok(Role::Bootstrap));
        assert_eq!(
            parse_role(&s(&["--visual-reference"]), None),
            Ok(Role::Bootstrap)
        );
        assert_eq!(
            parse_role(&s(&["--graphics-mode=safe"]), Some("C:\\t\\h.ready")),
            Ok(Role::Renderer {
                mode: GraphicsMode::Safe,
                supervised: true
            })
        );
        assert_eq!(
            parse_role(&s(&["--graphics-mode=NORMAL"]), None),
            Ok(Role::Renderer {
                mode: GraphicsMode::Normal,
                supervised: false
            })
        );
        assert!(parse_role(&s(&["--graphics-mode=glow"]), None).is_err());
        assert!(parse_role(&s(&["--graphics-mode="]), None).is_err());
        assert!(
            parse_role(
                &s(&["--graphics-mode=normal", "--graphics-mode=safe"]),
                None
            )
            .is_err()
        );
    }

    #[test]
    fn child_args_never_duplicate_the_mode() {
        let args = child_args(
            &s(&[
                "--visual-reference",
                "--graphics-mode=normal",
                "--capture",
                "a.png",
            ]),
            GraphicsMode::Safe,
        );
        assert_eq!(
            args,
            s(&[
                "--visual-reference",
                "--capture",
                "a.png",
                "--graphics-mode=safe"
            ])
        );
        // A child is always a renderer, so it can never become a bootstrap.
        assert!(matches!(
            parse_role(&args, Some("h")),
            Ok(Role::Renderer {
                supervised: true,
                ..
            })
        ));
    }

    #[test]
    fn startup_log_is_created_and_appended() {
        let dir = std::env::temp_dir().join(format!("wsd-gs-log-{}", std::process::id()));
        let log = StartupLog::at(&dir, "unit");
        log.line("first");
        log.line(&environment_summary());
        let text = fs::read_to_string(log.path()).unwrap();
        assert!(log.path().ends_with(LOG_FILE_NAME));
        assert!(text.contains("[unit pid "));
        assert!(text.contains("first"));
        assert!(text.contains("session:"));
        assert_eq!(text.lines().count(), 2);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn exit_codes_are_described() {
        assert!(describe_exit_code(Some(87)).starts_with("87 (0x00000057)"));
        assert!(describe_exit_code(Some(87)).contains("LoadLibrary failed with error 87"));
        assert!(describe_exit_code(Some(0xC000_0005_u32 as i32)).starts_with("0xC0000005"));
        assert!(describe_exit_code(Some(0xC000_0409_u32 as i32)).contains("panic"));
        assert!(describe_exit_code(None).contains("no exit code"));
        assert!(describe_exit_code(Some(3)).contains("renderer initialisation failed"));
    }

    /// The start-up log lives in today's report folder of this PC, never
    /// loose in `Reports\`.
    #[test]
    fn startup_log_goes_into_the_pc_report_folder() {
        let root = std::env::temp_dir().join(format!("wsd-gs-root-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let dir = report_dir_for_today(&root);
        let mut log = StartupLog::at(&dir, "test");
        log.reports_root = Some(root.clone());
        log.line("hello");
        let path = log.path();
        assert!(path.starts_with(&root));
        assert_ne!(path.parent().unwrap(), root.as_path());
        assert!(fs::read_to_string(&path).unwrap().contains("hello"));
        assert!(!root.join(LOG_FILE_NAME).exists());
        let _ = fs::remove_dir_all(&root);
    }
}
