//! Embedded copy: kill-on-close applies to query workers only. The protected
//! LHM reader uses explicit breakaway, cooperative EOF cleanup and a shared lease.
//! The sampler supervisor.
//!
//! The supervisor owns one sampler child process for the lifetime of a monitoring
//! run. It is deliberately the only place that knows how to start, watch and stop a
//! child, so the GUI can never block on a provider:
//!
//! * the child is created with its standard handles redirected onto three anonymous
//!   pipes — commands, protocol and diagnostics — so the protocol is a private channel
//!   rather than a console, and a noisy child cannot corrupt it with its tracing;
//! * it is created **suspended and detached**, assigned to a [`super::job::JobObject`]
//!   and only then resumed, so there is no window in which it (or a child of its own)
//!   runs outside the job, and no console host is created inside the job;
//! * only the three child ends of the pipes are inheritable, and the inheritance is
//!   restricted to exactly those handles;
//! * a reader thread decodes the protocol with bounded framing and pushes events into a
//!   bounded queue, so a child that floods or stalls the channel can neither block the
//!   UI thread nor grow the supervisor's memory without limit;
//! * **every** failure path terminates the child rather than waiting for it, and a
//!   verdict is only ever built from an exit the process handle has **confirmed**. A
//!   `bye` is the child's own claim: it is recorded and shown, never trusted as proof
//!   that the process exited;
//! * teardown is bounded at every step, including the joins, so no wait in this module
//!   can hold the UI thread for an unbounded time.
//!
//! It never calls `TerminateThread`: only whole processes are ended.

use std::ffi::c_void;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SendError, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use powerlab_core::ipc::{
    self, HostMessage, PROTOCOL_VERSION, ProviderStatus, Sample, SamplerMessage,
};
use powerlab_core::lineio::{LineError, LineReader};

use super::job::JobObject;

// The type names mirror the Windows SDK, so a declaration can be checked against the
// header by eye.
#[allow(clippy::upper_case_acronyms)]
type HANDLE = *mut c_void;
#[allow(clippy::upper_case_acronyms)]
type BOOL = i32;
#[allow(clippy::upper_case_acronyms)]
type DWORD = u32;

const STARTF_USESTDHANDLES: DWORD = 0x0000_0100;
/// `CREATE_SUSPENDED`: the child does not run until `ResumeThread`.
const CREATE_SUSPENDED: DWORD = 0x0000_0004;
/// `DETACHED_PROCESS`: the child gets **no** console.
///
/// `CREATE_NO_WINDOW` (used first) still allocates one, and Windows serves a console
/// with a `conhost.exe` process that is created as a child of the console application
/// and therefore lands **inside this supervisor's job**. That is a measurable defect,
/// not a cosmetic one: `active_processes()` then reports two processes for one child and
/// never falls to one after the child exits, so the very accounting used to prove "no
/// process was left behind" was measuring the console host. The child's standard handles
/// are the pipes, so it needs no console at all.
const CREATE_DETACHED_PROCESS: DWORD = 0x0000_0008;
/// `EXTENDED_STARTUPINFO_PRESENT`: `STARTUPINFOEXW` with an attribute list is passed.
const EXTENDED_STARTUPINFO_PRESENT: DWORD = 0x0008_0000;
/// `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`: the exact set of inheritable handles.
const PROC_THREAD_ATTRIBUTE_HANDLE_LIST: usize = 0x0002_0002;
/// `HANDLE_FLAG_INHERIT`.
const HANDLE_FLAG_INHERIT: DWORD = 0x0000_0001;
/// `WAIT_OBJECT_0`, the only result of `WaitForSingleObject` that means "signalled".
const WAIT_OBJECT_0: DWORD = 0;
/// `WAIT_TIMEOUT`, returned when the wait expired while the object was still unsignalled.
const WAIT_TIMEOUT: DWORD = 0x0000_0102;
/// `PROCESS_QUERY_LIMITED_INFORMATION`: enough to read a process's creation time.
const PROCESS_QUERY_LIMITED_INFORMATION: DWORD = 0x0000_1000;
/// `SYNCHRONIZE`: required to wait on a handle.
///
/// `WaitForSingleObject` fails on a handle opened without it, so an access mask of
/// `PROCESS_QUERY_LIMITED_INFORMATION` alone made every liveness check read "not alive" —
/// which is exactly the silent direction a restart interlock must not fail in.
const SYNCHRONIZE: DWORD = 0x0010_0000;
/// `STILL_ACTIVE`.
///
/// `GetExitCodeProcess` reports this for a process that is **still running**, and a
/// process that really exited with the value 259 is indistinguishable that way. The wait
/// on the process handle is what distinguishes them, so this constant is only used to
/// document the trap: no code path turns it into an exit code.
const STILL_ACTIVE: DWORD = 259;
/// The exit code used when the supervisor has to end the child itself.
const TERMINATION_EXIT_CODE: u32 = 1;

/// How many events may be queued before the reader thread blocks.
///
/// An unbounded queue is memory that a misbehaving child controls. When the queue is
/// full the reader blocks, and the child in turn blocks on its own pipe: that is
/// backpressure, which is bounded, instead of growth.
const EVENT_QUEUE_CAPACITY: usize = 256;

/// How long a forced termination waits for the exit to be confirmed.
///
/// `TerminateJobObject` and `TerminateProcess` are effectively synchronous, so this is a
/// safety cap rather than a typical wait; if it expires the state stays unconfirmed,
/// which is exactly what must not be reported as clean.
const TERMINATION_GRACE: Duration = Duration::from_millis(250);

/// How long a closed protocol stream waits for the process to become signalled.
const STREAM_CLOSE_CONFIRM_BUDGET: Duration = Duration::from_millis(250);

/// How many intervals of headroom the startup budget adds to the handshake budget.
const STARTUP_INTERVALS: u32 = 3;

/// The floor for the cap on the startup budget.
///
/// The startup budget is never longer than the larger of the heartbeat budget and this,
/// so a very long interval cannot make a hung startup wait indefinitely.
const STARTUP_GRACE_CEILING: Duration = Duration::from_secs(30);

/// How long the supervisor waits for the reader's last message after a confirmed exit.
const SETTLE_BUDGET: Duration = Duration::from_millis(200);

/// The same drain, sized for one frame of the non-blocking stop.
///
/// A frame that waits 200 ms is a visible hitch, and the only thing at stake is whether the
/// child's own `bye` had been recorded yet: a stop the supervisor itself asked for is
/// reported as [`StopReason::OperatorStop`] when the claim is missing, which is just as
/// clean. So the frame-sized budget is deliberately small.
#[allow(dead_code)] // Used by the sampler module hosts sharing this file.
const POLL_STOP_SETTLE_BUDGET: Duration = Duration::from_millis(25);

/// How long teardown lets the child leave on its own before it is killed.
///
/// Deliberately much shorter than `stop_grace`: `Drop` runs on the UI thread, and a
/// teardown that waits for a configured stop budget is a teardown that can freeze the
/// interface.
const DROP_POLITE_BUDGET: Duration = Duration::from_millis(150);

/// How long teardown waits for the exit to be confirmed after it has killed the child.
const DROP_EXIT_BUDGET: Duration = Duration::from_millis(250);

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct SecurityAttributes {
    length: DWORD,
    security_descriptor: *mut c_void,
    inherit_handle: BOOL,
}

#[repr(C)]
struct StartupInfoW {
    cb: DWORD,
    reserved: *mut u16,
    desktop: *mut u16,
    title: *mut u16,
    x: DWORD,
    y: DWORD,
    x_size: DWORD,
    y_size: DWORD,
    x_count_chars: DWORD,
    y_count_chars: DWORD,
    fill_attribute: DWORD,
    flags: DWORD,
    show_window: u16,
    reserved2_size: u16,
    reserved2: *mut u8,
    std_input: HANDLE,
    std_output: HANDLE,
    std_error: HANDLE,
}

/// `STARTUPINFOEXW`: `STARTUPINFO` followed by the attribute list pointer.
#[repr(C)]
struct StartupInfoExW {
    startup: StartupInfoW,
    attribute_list: *mut c_void,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct ProcessInformation {
    process: HANDLE,
    thread: HANDLE,
    process_id: DWORD,
    thread_id: DWORD,
}

/// The layout of every Win32 structure in this module is asserted, because a field at the
/// wrong offset is read as a valid value rather than failing: that is how a running
/// process came to look like one that had "exited with code 259".
const _: () = {
    assert!(std::mem::size_of::<SecurityAttributes>() == 24);
    assert!(std::mem::size_of::<StartupInfoW>() == 104);
    assert!(std::mem::size_of::<StartupInfoExW>() == 112);
    assert!(std::mem::size_of::<ProcessInformation>() == 24);
};

#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreatePipe(
        read: *mut HANDLE,
        write: *mut HANDLE,
        attributes: *mut SecurityAttributes,
        size: DWORD,
    ) -> BOOL;
    fn SetHandleInformation(handle: HANDLE, mask: DWORD, flags: DWORD) -> BOOL;
    #[allow(clippy::too_many_arguments)]
    fn CreateProcessW(
        application: *const u16,
        command_line: *mut u16,
        process_attributes: *mut SecurityAttributes,
        thread_attributes: *mut SecurityAttributes,
        inherit_handles: BOOL,
        creation_flags: DWORD,
        environment: *mut c_void,
        current_directory: *const u16,
        startup_info: *mut StartupInfoW,
        process_information: *mut ProcessInformation,
    ) -> BOOL;
    fn ResumeThread(thread: HANDLE) -> DWORD;
    fn InitializeProcThreadAttributeList(
        attribute_list: *mut c_void,
        attribute_count: DWORD,
        flags: DWORD,
        size: *mut usize,
    ) -> BOOL;
    fn UpdateProcThreadAttribute(
        attribute_list: *mut c_void,
        flags: DWORD,
        attribute: usize,
        value: *mut c_void,
        size: usize,
        previous_value: *mut c_void,
        return_size: *mut usize,
    ) -> BOOL;
    fn DeleteProcThreadAttributeList(attribute_list: *mut c_void);
    fn CloseHandle(handle: HANDLE) -> BOOL;
    fn TerminateProcess(process: HANDLE, exit_code: u32) -> BOOL;
    fn WaitForSingleObject(handle: HANDLE, milliseconds: DWORD) -> DWORD;
    fn GetExitCodeProcess(process: HANDLE, code: *mut DWORD) -> BOOL;
    fn OpenProcess(access: DWORD, inherit: BOOL, process_id: DWORD) -> HANDLE;
    fn GetProcessTimes(
        process: HANDLE,
        creation: *mut FileTime,
        exit: *mut FileTime,
        kernel: *mut FileTime,
        user: *mut FileTime,
    ) -> BOOL;
    fn GetLastError() -> DWORD;
}

/// A Win32 `FILETIME`: two `DWORD`s, so the structure is four-byte aligned.
///
/// The same trap as in the sampler's PDH declarations: an `i64` would land on an eight-byte
/// boundary and silently change the layout the API fills.
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct FileTime {
    low: DWORD,
    high: DWORD,
}

impl FileTime {
    fn ticks(self) -> u64 {
        ((self.high as u64) << 32) | self.low as u64
    }
}

fn last_error() -> DWORD {
    unsafe { GetLastError() }
}

/// Why a run ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopReason {
    /// The operator or the duration asked for a stop, and the child exited cleanly.
    Completed,
    /// The child reported a failure of its own.
    ChildFailed(String),
    /// The child stopped sending samples and was terminated.
    HeartbeatTimeout {
        waited_ms: u128,
        /// What the child looked like when it was killed.
        note: String,
    },
    /// The child exited without a `bye`, which means it died rather than finished.
    ChildExited { code: u32 },
    /// The protocol broke down and the child was terminated.
    Protocol(String),
    /// A read or write failure on the pipe.
    Ipc(String),
    /// The operator asked to stop.
    OperatorStop,
    /// Termination was carried out, but the process never **proved** that it exited.
    ///
    /// This is the honest state for "it did not finish in time": not clean, and not
    /// described as an exit either, because no exit code was ever confirmed.
    TerminationPending { note: String },
}

/// The verdict of a run, under the name the acceptance report uses for it.
///
/// A verdict is only ever clean when the process handle has confirmed an exit; see
/// [`StopReason::is_clean`].
#[allow(dead_code)]
pub type RunResult = StopReason;

impl StopReason {
    /// Is this a clean end of the run?
    ///
    /// Clean means the process was **confirmed** to exit, with code 0, after either its
    /// own clean `bye` or a stop the supervisor asked for. A `bye` on its own is not
    /// evidence: a child that says `bye clean=true` and keeps running is `false-bye`
    /// from the acceptance report, and it is terminated as a hung child, not reported as
    /// a completed run.
    pub fn is_clean(&self) -> bool {
        matches!(self, StopReason::Completed | StopReason::OperatorStop)
    }

    pub fn describe(&self) -> String {
        match self {
            StopReason::Completed => "опрос завершён".to_string(),
            StopReason::ChildFailed(reason) => format!("сэмплер сообщил об ошибке: {reason}"),
            StopReason::HeartbeatTimeout { waited_ms, note } => format!(
                "сэмплер не присылал данных {waited_ms} мс и был завершён как зависший ({note})"
            ),
            StopReason::ChildExited { code } => {
                format!("процесс сэмплера завершился сам с кодом {code} без сообщения о завершении")
            }
            StopReason::Protocol(reason) => {
                format!("нарушение протокола IPC: {reason}; процесс сэмплера завершён")
            }
            StopReason::Ipc(reason) => format!("ошибка канала IPC: {reason}"),
            StopReason::OperatorStop => "остановлено оператором".to_string(),
            StopReason::TerminationPending { note } => {
                format!("завершение процесса не подтверждено: {note}")
            }
        }
    }
}

/// What the GUI sees from the supervisor.
#[derive(Debug, Clone)]
pub enum SamplerEvent {
    /// The child announced itself; carries the sampler version and its own token.
    Hello {
        sampler_version: String,
        kind: String,
    },
    /// Providers resolved at startup.
    Providers(Vec<ProviderStatus>),
    /// A measurement cycle.
    Sample(Box<Sample>),
    /// A one-off notice.
    Notice { level: String, text: String },
    /// The run ended. Always the last event.
    Stopped(StopReason),
}

/// What the child said about itself.
///
/// A `bye` and a `fatal` are statements, not evidence: the process handle is the only
/// thing that proves an exit, so neither message ends a run on its own.
#[derive(Debug, Clone, Default)]
struct ChildReport {
    protocol_errors: u64,
    /// The version the child announced in its `hello`.
    ///
    /// Kept here rather than inside `start`, because `start` consumes the `hello` event to
    /// prove the handshake and the window still has to show which sampler answered.
    version: Option<String>,
    bye: Option<ByeClaim>,
    fatal: Option<String>,
}

/// The child's own completion claim.
#[derive(Debug, Clone)]
struct ByeClaim {
    reason: String,
    samples: u32,
    clean: bool,
}

/// The bounded event queue together with the number of events waiting in it.
///
/// `Receiver` has no length, so the backlog the acceptance instrumentation reports is kept
/// by the producer and consumed by [`Supervisor::poll`]. The counter is only a measurement:
/// the bound itself is the channel's capacity.
struct EventQueue {
    tx: SyncSender<SamplerEvent>,
    queued: Arc<AtomicUsize>,
}

impl EventQueue {
    fn send(&self, event: SamplerEvent) -> Result<(), SendError<SamplerEvent>> {
        // Reserve before publication: a consumer may receive before send returns.
        // Includes at most one producer waiting for capacity, in addition to queued events.
        self.queued.fetch_add(1, Ordering::Relaxed);
        let result = self.tx.send(event);
        if result.is_err() {
            self.queued.fetch_sub(1, Ordering::Relaxed);
        }
        result
    }
}

/// The identity of one child process: its id **and** its creation time.
///
/// A process id alone is recycled by Windows, so a remembered id could later name an
/// unrelated process. The creation time distinguishes the child that was started from
/// whatever inherits its id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ChildIdentity {
    pid: u32,
    created: u64,
}

/// Children whose exit was never confirmed, process-wide.
///
/// This is deliberately not per-supervisor: the child that is still alive was started by a
/// supervisor that no longer exists, and the next [`Supervisor::start`] has to see it.
static UNCONFIRMED_CHILDREN: Mutex<Vec<ChildIdentity>> = Mutex::new(Vec::new());

/// Remember a child whose exit could not be confirmed.
fn remember_unconfirmed(identity: ChildIdentity) {
    if let Ok(mut list) = UNCONFIRMED_CHILDREN.lock() {
        if !list.contains(&identity) {
            debug_line(&format!(
                "child pid={} was not confirmed dead; it is remembered so no second sampler runs beside it",
                identity.pid
            ));
            list.push(identity);
        }
    }
}

/// Which remembered children are still alive; the ones that are gone are forgotten.
///
/// Returns every still-running child, so a caller can refuse to start a second sampler
/// while one is known to be alive. The check is non-blocking: it opens a handle and reads
/// the creation time, which cannot wait on the child.
fn unresolved_children() -> Vec<ChildIdentity> {
    let mut unresolved = Vec::new();
    if let Ok(mut list) = UNCONFIRMED_CHILDREN.lock() {
        list.retain(|identity| {
            if process_still_alive(*identity) {
                unresolved.push(*identity);
                true
            } else {
                debug_line(&format!(
                    "remembered child pid={} is gone; the restart interlock is clear",
                    identity.pid
                ));
                false
            }
        });
    }
    unresolved
}

/// Is this exact process — same id, same creation time — still running?
fn process_still_alive(identity: ChildIdentity) -> bool {
    let handle = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
            0,
            identity.pid,
        )
    };
    if handle.is_null() {
        // Only ERROR_INVALID_PARAMETER establishes that this PID no longer exists.
        // Access denied and other observation failures must keep the restart interlock.
        return last_error() != 87;
    }
    let state = unsafe { WaitForSingleObject(handle, 0) };
    let alive = if state == WAIT_TIMEOUT {
        match process_creation_time(handle) {
            Some(created) => identity.created == 0 || created == identity.created,
            // Without a creation time the id is all there is; a live process with that id
            // is treated as the child rather than as a stranger.
            None => true,
        }
    } else {
        state != WAIT_OBJECT_0
    };
    unsafe {
        CloseHandle(handle);
    }
    alive
}

pub(crate) fn current_process_creation_time() -> Option<u64> {
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, std::process::id()) };
    if handle.is_null() {
        return None;
    }
    let result = process_creation_time(handle);
    unsafe {
        CloseHandle(handle);
    }
    result
}

/// The creation time of an open process handle, for identity comparison.
fn process_creation_time(process: HANDLE) -> Option<u64> {
    let mut creation = FileTime::default();
    let mut exit = FileTime::default();
    let mut kernel = FileTime::default();
    let mut user = FileTime::default();
    let ok = unsafe { GetProcessTimes(process, &mut creation, &mut exit, &mut kernel, &mut user) };
    if ok == 0 {
        None
    } else {
        Some(creation.ticks())
    }
}

/// The verdict for a run that ended on its own, from a **confirmed** exit code.
///
/// Kept as a free function of its inputs so the rules it encodes — the rules the
/// acceptance found missing — are covered by unit tests without a child process.
fn verdict_for_confirmed_exit(code: u32, report: &ChildReport, stop_requested: bool) -> StopReason {
    if let Some(fatal) = report.fatal.as_ref() {
        return StopReason::ChildFailed(fatal.clone());
    }
    if code != 0 {
        return StopReason::ChildExited { code };
    }
    match report.bye.as_ref() {
        Some(bye) if bye.clean => StopReason::Completed,
        Some(bye) => StopReason::ChildFailed(format!(
            "сэмплер завершился с кодом 0 после {} замеров, но сообщил, что не освободил все ресурсы: {}",
            bye.samples, bye.reason
        )),
        // A confirmed exit of 0 that the supervisor itself asked for is a clean stop;
        // without a request it is a process that died, whatever the code says.
        None if stop_requested => StopReason::OperatorStop,
        None => StopReason::ChildExited { code },
    }
}

/// The verdict after the supervisor ended the child itself.
///
/// The reason for the termination is only reported once the exit is confirmed. When it
/// is not, the state is [`StopReason::TerminationPending`]: an unconfirmed exit is never
/// clean, and it does not get to borrow the exit code that was never read.
fn verdict_after_termination(
    forced: StopReason,
    exit: Option<u32>,
    waited: Duration,
) -> StopReason {
    match exit {
        Some(_) => forced,
        None => StopReason::TerminationPending {
            note: format!(
                "{}; выход процесса не подтверждён за {} мс",
                forced.describe(),
                waited.as_millis()
            ),
        },
    }
}

/// How the supervisor should behave.
#[derive(Debug, Clone)]
pub struct SupervisorConfig {
    pub program: PathBuf,
    pub provider: Option<String>,
    pub interval: Duration,
    /// Zero means "until stopped".
    pub duration: Duration,
    /// How long to wait for `hello` before giving up.
    pub handshake_timeout: Duration,
    /// How long the child may go without sending anything before it is terminated.
    pub heartbeat_timeout: Duration,
    /// How long the child is given to exit on its own after a stop, before it is
    /// terminated.
    pub stop_grace: Duration,
    /// Optional fault injection, for the acceptance harness.
    pub fault: Option<String>,
    /// Optional startup-hang fixture, for the acceptance harness: `"never-hello"`
    /// makes the child announce nothing and wait for ever.
    pub hang: Option<String>,
}

impl SupervisorConfig {
    /// A configuration with the documented defaults.
    pub fn new(program: impl AsRef<Path>) -> SupervisorConfig {
        SupervisorConfig {
            program: program.as_ref().to_path_buf(),
            provider: None,
            interval: Duration::from_millis(1000),
            duration: Duration::ZERO,
            handshake_timeout: Duration::from_secs(10),
            // The same budget `heartbeat_for_interval` derives for the default 1 s
            // interval: six missed intervals, with a 10 s floor and a 120 s cap. The two
            // used to disagree (15 s here, 10 s from the formula), so a scenario that
            // asked for a derived budget silently got a different one.
            heartbeat_timeout: Duration::from_secs(10),
            stop_grace: Duration::from_secs(3),
            fault: None,
            hang: None,
        }
    }

    /// Derive the heartbeat budget from the interval, so a slow interval is not
    /// mistaken for a hang.
    ///
    /// An explicitly configured budget is a floor rather than something to overwrite:
    /// an acceptance scenario that wants a short heartbeat must get one, otherwise it
    /// would silently be testing the default instead of the path it means to test.
    pub fn heartbeat_for_interval(mut self) -> SupervisorConfig {
        let scaled = self.interval.saturating_mul(6).max(Duration::from_secs(10));
        let scaled = scaled.min(Duration::from_secs(120));
        self.heartbeat_timeout = self.heartbeat_timeout.max(scaled);
        self
    }
}

/// A running sampler.
pub struct Supervisor {
    process: HANDLE,
    job: JobObject,
    events: Receiver<SamplerEvent>,
    child_stdin: Option<std::fs::File>,
    /// The child's exit code, recorded only once the process handle proved the exit.
    exit_code: Option<u32>,
    config: SupervisorConfig,
    /// When the last message of any kind arrived.
    last_heard: Instant,
    /// Set once the run's fate has been decided, so the reason is reported once.
    terminated: Option<StopReason>,
    reader: Option<thread::JoinHandle<()>>,
    /// Drains the child's diagnostic stream so a noisy child cannot block on it.
    stderr_reader: Option<thread::JoinHandle<()>>,
    /// The last of the child's diagnostics, bounded. Shown when a run fails so the
    /// reason is not only "the child stopped talking".
    diagnostics: Arc<Mutex<Vec<String>>>,
    /// How many decoded events are waiting in the queue, for the acceptance
    /// instrumentation. The bound itself is the channel's capacity.
    queued: Arc<AtomicUsize>,
    /// Who this child is, for the restart interlock.
    identity: Option<ChildIdentity>,
    /// A token so a stale sampler from a previous run cannot attach to this one.
    session_token: String,
    /// What the child claimed about itself, filled in by the reader thread.
    report: Arc<Mutex<ChildReport>>,
    /// Set when the supervisor asked the child to stop, so a confirmed exit of 0 can be
    /// read as "it obeyed the stop" rather than "it died".
    stop_requested: bool,
    /// When a non-blocking stop was asked for, so its grace can be measured per frame.
    #[allow(dead_code)] // Used by the sampler module hosts.
    stop_started: Option<Instant>,
    /// Set once the child has announced its providers or produced a sample.
    ///
    /// Until then the child is still starting up: it opens its providers and takes one
    /// **full** interval before its first sample (the sampler deliberately waits out the
    /// remainder of the interval so the first window is complete). Silence during that
    /// phase is not a hang, so it is measured against the startup budget rather than the
    /// heartbeat.
    startup_done: bool,
}

// SAFETY: the handles are only used from the thread that owns the supervisor, and the
// reader thread communicates exclusively through the channel.
unsafe impl Send for Supervisor {}

/// Which end of a pipe the **parent** keeps.
///
/// `CreatePipe` hands back a read end and a write end, and which one the supervisor needs
/// depends on the stream: it writes commands, so it keeps the write end of the command
/// pipe, and it reads the protocol, so it keeps the read end of the protocol pipe. Naming
/// the ends after the parent makes that impossible to get backwards.
#[derive(Clone, Copy, PartialEq, Eq)]
enum End {
    Read,
    Write,
}

/// One anonymous pipe, with its two ends kept apart.
///
/// `CreatePipe` marks **both** ends inheritable in one call, so each end is separated
/// afterwards with `SetHandleInformation`. The parent's end matters most: while the child
/// held a copy of the parent's write end of the command pipe, the child could never see
/// EOF on its commands, and closing the supervisor's copy had no effect. Owning the ends
/// here also means every early return below closes what it opened.
struct Pipe {
    read: HANDLE,
    write: HANDLE,
    /// The end the parent keeps; the other one is the child's.
    parent: End,
}

impl Pipe {
    fn create(what: &str, parent: End) -> Result<Pipe, String> {
        let mut attributes = SecurityAttributes {
            length: std::mem::size_of::<SecurityAttributes>() as DWORD,
            security_descriptor: std::ptr::null_mut(),
            inherit_handle: 1,
        };
        let mut read: HANDLE = std::ptr::null_mut();
        let mut write: HANDLE = std::ptr::null_mut();
        if unsafe { CreatePipe(&mut read, &mut write, &mut attributes, 0) } == 0 {
            return Err(format!(
                "CreatePipe({what}) не выполнена (Win32 {})",
                last_error()
            ));
        }
        let pipe = Pipe {
            read,
            write,
            parent,
        };
        if unsafe { SetHandleInformation(pipe.parent_handle(), HANDLE_FLAG_INHERIT, 0) } == 0 {
            let code = last_error();
            // `pipe` is dropped here, which closes both ends.
            drop(pipe);
            return Err(format!(
                "SetHandleInformation({what}) не выполнена (Win32 {code})"
            ));
        }
        Ok(pipe)
    }

    fn parent_handle(&self) -> HANDLE {
        match self.parent {
            End::Read => self.read,
            End::Write => self.write,
        }
    }

    /// The end the child inherits and receives as one of its standard handles.
    fn child_handle(&self) -> HANDLE {
        match self.parent {
            End::Read => self.write,
            End::Write => self.read,
        }
    }

    /// Hand the child's end over to the child: the parent closes its copy, or the read
    /// end would never see EOF.
    fn close_child(&mut self) {
        let slot = match self.parent {
            End::Read => &mut self.write,
            End::Write => &mut self.read,
        };
        if !slot.is_null() {
            unsafe {
                CloseHandle(*slot);
            }
            *slot = std::ptr::null_mut();
        }
    }

    /// Take the parent's end out of the pipe, as an ordinary `File`.
    fn take_parent(&mut self) -> std::fs::File {
        let slot = match self.parent {
            End::Read => &mut self.read,
            End::Write => &mut self.write,
        };
        let handle = std::mem::replace(slot, std::ptr::null_mut());
        unsafe { std::fs::File::from_raw_handle(handle as _) }
    }
}

impl Drop for Pipe {
    fn drop(&mut self) {
        // Whatever is still owned here is a handle the supervisor no longer needs, and
        // closing the parent's ends is what lets the child see EOF on its streams.
        for handle in [self.read, self.write] {
            if !handle.is_null() {
                unsafe {
                    CloseHandle(handle);
                }
            }
        }
        self.read = std::ptr::null_mut();
        self.write = std::ptr::null_mut();
    }
}

/// A pointer-aligned buffer for a process/thread attribute list.
///
/// The list for a single attribute is a few dozen bytes, so it lives on the stack; the
/// alignment is explicit because the attribute-list API requires a pointer-aligned
/// buffer.
#[repr(C, align(16))]
struct AttributeListBuffer([u8; 1024]);

/// The exact set of handles the child may inherit.
///
/// `bInheritHandles` is all-or-nothing: on its own it duplicates every inheritable handle
/// in this process into the child, including handles this module knows nothing about. The
/// documented handle list restricts the inheritance to the three pipe ends the child
/// actually needs.
struct HandleList {
    /// Owns the memory the list lives in; never read, only kept alive.
    _buffer: Box<AttributeListBuffer>,
    list: *mut c_void,
}

impl HandleList {
    fn create(handles: &[HANDLE]) -> Option<HandleList> {
        let mut buffer = Box::new(AttributeListBuffer([0u8; 1024]));
        let mut size = buffer.0.len();
        let list = buffer.0.as_mut_ptr() as *mut c_void;
        if unsafe { InitializeProcThreadAttributeList(list, 1, 0, &mut size) } == 0 {
            debug_line(&format!(
                "the handle list could not be created (Win32 {}); process startup will be refused",
                last_error()
            ));
            return None;
        }
        let handle_list = HandleList {
            _buffer: buffer,
            list,
        };
        let ok = unsafe {
            UpdateProcThreadAttribute(
                handle_list.list,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                handles.as_ptr() as *mut c_void,
                std::mem::size_of_val(handles),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            debug_line(&format!(
                "the handle list could not be filled (Win32 {}); process startup will be refused",
                last_error()
            ));
            // The partial list is deleted by `Drop`.
            return None;
        }
        Some(handle_list)
    }

    fn pointer(&self) -> *mut c_void {
        self.list
    }
}

impl Drop for HandleList {
    fn drop(&mut self) {
        if !self.list.is_null() {
            unsafe { DeleteProcThreadAttributeList(self.list) };
            self.list = std::ptr::null_mut();
        }
    }
}

impl Supervisor {
    /// Start a sampler and wait for it to announce itself.
    ///
    /// On any failure the child is terminated before returning, so a caller never
    /// receives a half-started supervisor.
    pub fn start(config: SupervisorConfig) -> Result<Supervisor, String> {
        Self::start_cancellable(config, &AtomicBool::new(false))
    }

    pub fn start_cancellable(
        config: SupervisorConfig,
        cancelled: &AtomicBool,
    ) -> Result<Supervisor, String> {
        if cancelled.load(Ordering::Acquire) {
            return Err("запуск отменён пользователем".into());
        }
        // A sampler whose exit was never confirmed must not be joined by a second one: two
        // processes polling the same hardware is the orphan this design exists to prevent.
        // The check only opens a handle and reads a creation time, so the UI thread is never
        // held, and a child that has since died clears it automatically.
        if let Some(child) = unresolved_children().first() {
            return Err(format!(
                "предыдущий процесс сэмплера (PID {}) не подтвердил завершение; запуск нового \
                 остановлен, чтобы не оставить осиротевший опрос оборудования",
                child.pid
            ));
        }
        if !config.program.exists() {
            return Err(format!(
                "исполняемый файл сэмплера не найден: {}",
                config.program.display()
            ));
        }
        let job = JobObject::create_kill_on_close()?;
        let session_token = random_token();

        // Three pipes: the child's commands, its protocol, and its diagnostics. The
        // diagnostics get their **own** pipe because pointing stderr at the stdout pipe
        // mixes the sampler's trace lines into the JSON stream: the reader then sees a
        // "decode error" where a sample should be, and with `POWERLAB_DEBUG=1` the
        // protocol degrades until the child is stopped for talking nonsense.
        //
        // The parent keeps the end it uses: it writes commands and reads protocol and
        // diagnostics, so the child's ends are the other way round.
        let mut command_pipe = Pipe::create("stdin", End::Write)?;
        let mut protocol_pipe = Pipe::create("stdout", End::Read)?;
        let mut diagnostic_pipe = Pipe::create("stderr", End::Read)?;

        let mut args: Vec<String> = vec![
            "--interval-ms".into(),
            config.interval.as_millis().to_string(),
            "--duration-s".into(),
            config.duration.as_secs().to_string(),
            "--session-token".into(),
            session_token.clone(),
        ];
        if let Some(provider) = &config.provider {
            args.push("--provider".into());
            args.push(provider.clone());
        }
        if let Some(fault) = &config.fault {
            args.push("--fault".into());
            args.push(fault.clone());
        }
        if let Some(hang) = &config.hang {
            args.push("--hang".into());
            args.push(hang.clone());
        }

        let mut command_line = build_command_line(&config.program, &args);

        let child_handles = [
            command_pipe.child_handle(),
            protocol_pipe.child_handle(),
            diagnostic_pipe.child_handle(),
        ];
        let handle_list = HandleList::create(&child_handles);
        if handle_list.is_some() {
            debug_line(&format!(
                "inheritance restricted to {} handles",
                child_handles.len()
            ));
        }

        if handle_list.is_none() {
            return Err(
                "Cannot restrict inherited handles; refusing unsafe process startup".into(),
            );
        }
        let mut startup: StartupInfoW = unsafe { std::mem::zeroed() };
        // With `EXTENDED_STARTUPINFO_PRESENT` the size must be that of `STARTUPINFOEXW`,
        // not of the plain structure.
        startup.cb = if handle_list.is_some() {
            std::mem::size_of::<StartupInfoExW>() as DWORD
        } else {
            std::mem::size_of::<StartupInfoW>() as DWORD
        };
        startup.flags = STARTF_USESTDHANDLES;
        startup.std_input = command_pipe.child_handle();
        startup.std_output = protocol_pipe.child_handle();
        startup.std_error = diagnostic_pipe.child_handle();
        let mut startup_ex = StartupInfoExW {
            startup,
            attribute_list: handle_list
                .as_ref()
                .map_or(std::ptr::null_mut(), HandleList::pointer),
        };
        let mut info = ProcessInformation::default();

        // Suspended, so the child cannot run — or start a process of its own — before it
        // is inside the job.
        let flags = CREATE_DETACHED_PROCESS
            | CREATE_SUSPENDED
            | if handle_list.is_some() {
                EXTENDED_STARTUPINFO_PRESENT
            } else {
                0
            };

        let created = unsafe {
            CreateProcessW(
                std::ptr::null(),
                command_line.as_mut_ptr(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                1,
                flags,
                std::ptr::null_mut(),
                std::ptr::null(),
                &mut startup_ex.startup,
                &mut info,
            )
        };
        // `CreateProcessW` copies the attribute list and the handle array it points at,
        // so both must outlive the call. Releasing the list explicitly here — rather than
        // leaving it to the end of the scope — documents that requirement and stops the
        // optimiser from shortening the lifetime.
        drop(handle_list);

        // The child ends of the pipes belong to the child now; the parent must close its
        // copies or the read end would never see EOF.
        command_pipe.close_child();
        protocol_pipe.close_child();
        diagnostic_pipe.close_child();

        if created == 0 {
            let code = last_error();
            return Err(format!("CreateProcessW не выполнена (Win32 {code})"));
        }

        // Assign the child to the job before it is allowed to run, so a failure here
        // still leaves no orphan and no window in which the child is outside the job.
        if let Err(err) = job.assign(info.process) {
            unsafe {
                TerminateProcess(info.process, TERMINATION_EXIT_CODE);
                CloseHandle(info.thread);
                CloseHandle(info.process);
            }
            return Err(format!("не удалось передать сэмплер заданию: {err}"));
        }

        // Only now may the child run.
        if unsafe { ResumeThread(info.thread) } == u32::MAX {
            let code = last_error();
            unsafe {
                TerminateProcess(info.process, TERMINATION_EXIT_CODE);
                CloseHandle(info.thread);
                CloseHandle(info.process);
            }
            return Err(format!("ResumeThread не выполнена (Win32 {code})"));
        }
        unsafe {
            CloseHandle(info.thread);
        }
        debug_line(&format!(
            "child resumed: pid={} creation flags=0x{flags:08X} (the child was in the job before it ran)",
            info.process_id
        ));

        // Wrap the parent ends as standard files so the reader threads and the writer
        // use ordinary Rust IO over the same handles.
        let stdin_file = command_pipe.take_parent();
        let stdout_file = protocol_pipe.take_parent();
        let stderr_file = diagnostic_pipe.take_parent();

        // The diagnostic stream is drained continuously so a noisy child cannot fill
        // the pipe buffer and block on its own logging.
        let diagnostics = Arc::new(Mutex::new(Vec::new()));
        let stderr_reader = spawn_stderr_reader(stderr_file, Arc::clone(&diagnostics));

        // A bounded queue: the child can fill it, but it cannot grow it.
        let (tx, rx) = mpsc::sync_channel(EVENT_QUEUE_CAPACITY);
        let queued = Arc::new(AtomicUsize::new(0));
        let report = Arc::new(Mutex::new(ChildReport::default()));
        let reader = spawn_reader(
            stdout_file,
            EventQueue {
                tx,
                queued: Arc::clone(&queued),
            },
            session_token.clone(),
            Arc::clone(&report),
        );

        // config is moved into the struct, so the values needed below are read
        // before the move.
        let handshake_timeout = config.handshake_timeout;
        let mut supervisor = Supervisor {
            process: info.process,
            job,
            events: rx,
            child_stdin: Some(stdin_file),
            exit_code: None,
            config,
            last_heard: Instant::now(),
            terminated: None,
            reader: Some(reader),
            stderr_reader: Some(stderr_reader),
            diagnostics,
            queued,
            identity: Some(ChildIdentity {
                pid: info.process_id,
                created: process_creation_time(info.process).unwrap_or(0),
            }),
            session_token,
            report,
            stop_requested: false,
            stop_started: None,
            startup_done: false,
        };

        // Send the attach immediately: the sampler refuses to touch hardware until it
        // is confirmed, which is what makes a stale or hijacked pipe inert.
        if let Err(err) = supervisor.send_host(&HostMessage::Attach {
            version: PROTOCOL_VERSION,
            session_token: supervisor.session_token.clone(),
        }) {
            // A failure to send the attach means the channel is unusable, so the
            // child is terminated here rather than left running for nobody.
            supervisor.terminate_with(StopReason::Ipc(err.clone()));
            return Err(err);
        }

        // Wait for `hello` under the handshake deadline.
        let deadline = Instant::now() + handshake_timeout;
        while Instant::now() < deadline {
            if cancelled.load(Ordering::Acquire) {
                let reason = supervisor.terminate_with(StopReason::OperatorStop);
                return Err(if reason == StopReason::OperatorStop {
                    "запуск отменён пользователем".into()
                } else {
                    reason.describe()
                });
            }
            match supervisor.events.recv_timeout(Duration::from_millis(50)) {
                Ok(SamplerEvent::Hello { .. }) => {
                    supervisor.event_received();
                    return Ok(supervisor);
                }
                Ok(other) => {
                    supervisor.event_received();
                    // A well-formed but unexpected first message is a protocol error.
                    supervisor.terminate_with(StopReason::Protocol(format!(
                        "первое сообщение не hello: {other:?}"
                    )));
                    return Err("протокол сэмплера нарушен на старте".to_string());
                }
                Err(RecvTimeoutError::Timeout) => continue,
                Err(RecvTimeoutError::Disconnected) => {
                    // The reader ended before `hello`: either the child died or it closed
                    // the protocol stream. The process handle says which, and until it
                    // says anything the child is terminated rather than described.
                    let reason = match supervisor.await_exit(STREAM_CLOSE_CONFIRM_BUDGET) {
                        Some(code) => StopReason::ChildExited { code },
                        None => supervisor.terminate_with(StopReason::Ipc(
                            "канал протокола закрыт до подтверждения сессии".to_string(),
                        )),
                    };
                    supervisor.terminated_with(reason);
                    return Err("процесс сэмплера завершился до подтверждения сессии".to_string());
                }
            }
        }
        supervisor.terminate_with(StopReason::HeartbeatTimeout {
            waited_ms: handshake_timeout.as_millis(),
            note: "не получено сообщение hello".to_string(),
        });
        Err("сэмплер не подтвердил сессию вовремя".to_string())
    }

    /// The session token, exposed for the acceptance evidence.
    #[allow(dead_code)]
    pub fn session_token(&self) -> &str {
        &self.session_token
    }

    /// The version the child announced in its `hello`, once it has answered.
    ///
    /// The window reports this in its reports: the handshake consumes the `hello` event, so
    /// without this accessor the saved report could only say "unknown".
    pub fn sampler_version(&self) -> Option<String> {
        self.report
            .lock()
            .ok()
            .and_then(|report| report.version.clone())
    }

    /// How many decoded events are waiting to be polled.
    ///
    /// This is the IPC backlog the acceptance asks to instrument: it is what distinguishes
    /// "the child floods faster than the window drains" from "the window is slow".
    pub fn pending_events(&self) -> usize {
        self.queued.load(Ordering::Relaxed)
    }

    /// How many processes are alive in this supervisor's job.
    ///
    /// The child is created detached, so this counts the sampler and anything it started
    /// — not a console host. One live child reads as one; after a confirmed exit it reads
    /// as zero, which is what makes it usable as evidence about orphans.
    pub fn active_processes(&self) -> Result<u32, String> {
        self.job.active_processes()
    }

    /// Called only by the GUI shutdown worker. Keep ownership if either the root
    /// process or its descendant job cannot be confirmed empty; Start remains locked.
    #[allow(dead_code)] // Other hosts share Supervisor but have their own lifecycle checks.
    pub fn confirm_owned_exit(&mut self) -> Result<(), String> {
        if self.await_exit(Duration::ZERO).is_none() {
            return Err("выход сэмплера не подтверждён; повторный запуск заблокирован".into());
        }
        if self.job.active_processes()? != 0 {
            self.job.terminate(TERMINATION_EXIT_CODE)?;
            let deadline = Instant::now() + TERMINATION_GRACE;
            while self.job.active_processes()? != 0 {
                if Instant::now() >= deadline {
                    return Err("в задании остались процессы; повторный запуск заблокирован".into());
                }
                thread::sleep(Duration::from_millis(5));
            }
        }
        Ok(())
    }
    #[cfg(test)]
    #[allow(dead_code)]
    pub fn hold_reader_teardown_for_test(&mut self) -> Arc<AtomicBool> {
        let release = Arc::new(AtomicBool::new(false));
        for reader in [&mut self.reader, &mut self.stderr_reader] {
            let original = reader.take();
            let signal = Arc::clone(&release);
            *reader = Some(thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(5);
                while !signal.load(Ordering::Acquire) && Instant::now() < deadline {
                    thread::sleep(Duration::from_millis(5));
                }
                if let Some(original) = original {
                    let _ = original.join();
                }
            }));
        }
        release
    }

    /// The child's most recent diagnostic lines.
    ///
    /// A forced stop otherwise reads only as "the child stopped talking"; these lines
    /// are what say why.
    #[allow(dead_code)] // Used by the module host; legacy GUI receives warning notices.
    pub fn protocol_errors(&self) -> u64 {
        self.report
            .lock()
            .map(|r| r.protocol_errors)
            .unwrap_or(u64::MAX)
    }

    pub fn diagnostics(&self) -> Vec<String> {
        self.diagnostics
            .lock()
            .map(|lines| lines.clone())
            .unwrap_or_default()
    }

    /// The diagnostics as a single line, for a status field.
    pub fn diagnostics_summary(&self) -> Option<String> {
        let lines = self.diagnostics();
        if lines.is_empty() {
            return None;
        }
        Some(lines.join(" | "))
    }

    /// Is the child still running, as far as this supervisor has observed?
    ///
    /// This reports the last *observed* exit, so it is false both for a child that has
    /// been confirmed exited and for one that has not been checked yet; use
    /// [`Supervisor::poll`] for a verdict.
    #[allow(dead_code)]
    pub fn is_running(&self) -> bool {
        self.exit_code.is_none()
    }

    fn send_host(&mut self, message: &HostMessage) -> Result<(), String> {
        let Some(stdin) = self.child_stdin.as_mut() else {
            return Err("канал команд сэмплера уже закрыт".to_string());
        };
        let line = ipc::encode_host(message);
        writeln!(stdin, "{line}").map_err(|err| format!("ошибка записи команды: {err}"))?;
        stdin
            .flush()
            .map_err(|err| format!("ошибка сброса команды: {err}"))
    }

    /// The child's exit code, recorded only when the process handle has proved the exit.
    ///
    /// `WaitForSingleObject` is the authority: `GetExitCodeProcess` reports
    /// [`STILL_ACTIVE`] for a process that is still running, and a process that really
    /// exited with 259 looks identical through that call alone.
    fn reap(&mut self) -> Option<u32> {
        if self.exit_code.is_some() {
            return self.exit_code;
        }
        if self.process.is_null() {
            return None;
        }
        if unsafe { WaitForSingleObject(self.process, 0) } != WAIT_OBJECT_0 {
            return None;
        }
        let mut code: DWORD = 0;
        if unsafe { GetExitCodeProcess(self.process, &mut code) } != 0 {
            if code == STILL_ACTIVE {
                // Reaching here means the wait above already reported the process as
                // signalled, so this 259 really is its exit code. The value is only
                // ambiguous for a process that is *not* signalled, which is why the wait
                // decides and this call alone never does.
                debug_line("the child's confirmed exit code is 259 (the value of STILL_ACTIVE)");
            }
            self.exit_code = Some(code);
        }
        self.exit_code
    }

    /// The exit code, only if it is already observable.
    fn confirmed_exit(&mut self) -> Option<u32> {
        self.reap()
    }

    /// Wait up to `budget` for the process to exit, then read its exit code.
    ///
    /// The wait is bounded by construction and never runs on a handle that is gone, so a
    /// caller on the UI thread can never be held for longer than it asked for.
    fn await_exit(&mut self, budget: Duration) -> Option<u32> {
        if self.exit_code.is_some() {
            return self.exit_code;
        }
        if !self.process.is_null() {
            let millis = budget.as_millis().min(DWORD::MAX as u128) as DWORD;
            unsafe {
                WaitForSingleObject(self.process, millis);
            }
        }
        self.reap()
    }

    /// The child's own last words.
    fn child_report(&self) -> ChildReport {
        self.report
            .lock()
            .map(|report| report.clone())
            .unwrap_or_default()
    }

    fn event_received(&self) {
        self.queued.fetch_sub(1, Ordering::Relaxed);
    }

    /// Drain events for a bounded moment.
    ///
    /// Used after an exit has been confirmed so the reader's copy of the child's own last
    /// message is recorded before the verdict is built. It never waits for longer than
    /// `budget` and it never turns an unconfirmed exit into a confirmed one.
    fn settle(&mut self, budget: Duration) {
        let deadline = Instant::now() + budget;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return;
            }
            match self
                .events
                .recv_timeout(remaining.min(Duration::from_millis(25)))
            {
                Ok(event) => {
                    self.event_received();
                    if matches!(event, SamplerEvent::Stopped(_)) {
                        return;
                    }
                }
                Err(RecvTimeoutError::Timeout) => continue,
                Err(RecvTimeoutError::Disconnected) => return,
            }
        }
    }

    /// Ask the child to stop, then wait for it to exit.
    ///
    /// If it does not exit within the grace period it is **terminated**, which is the
    /// only way to end a provider stuck inside a driver call. The wait is bounded by
    /// `stop_grace`, and the termination that may follow is bounded by
    /// [`TERMINATION_GRACE`], so the total is the configured budget plus a cap.
    pub fn stop(&mut self) -> StopReason {
        if let Some(reason) = self.terminated.clone() {
            return reason;
        }
        self.stop_requested = true;
        // A write failure here is not fatal: the child may already be gone, and the
        // wait below decides the outcome.
        let _ = self.send_host(&HostMessage::Stop {
            version: PROTOCOL_VERSION,
        });
        // Closing the command channel is a second, independent stop signal: a sampler
        // watching its commands sees EOF even if it missed the message.
        self.child_stdin = None;

        let grace = self.config.stop_grace;
        if let Some(code) = self.await_exit(grace) {
            // Drain the child's own last message so the reason can be the child's. The
            // exit is already confirmed, so this cannot change the evidence.
            self.settle(SETTLE_BUDGET);
            let report = self.child_report();
            let reason = verdict_for_confirmed_exit(code, &report, true);
            return self.terminated_with(reason);
        }
        self.terminate_with(StopReason::HeartbeatTimeout {
            waited_ms: grace.as_millis(),
            note: "не завершился после запроса остановки и был завершён принудительно".to_string(),
        })
    }

    /// Ask the child to stop **without waiting for it**.
    ///
    /// [`Supervisor::stop`] holds its caller for up to `stop_grace` — three seconds by
    /// default. A window that calls it from its frame loop freezes for exactly that long,
    /// and a user reads a frozen window as a hung one. This sends the same two stop signals
    /// and returns at once; [`Supervisor::poll_stop`] then decides the verdict over the
    /// following frames, each call bounded by its own budget.
    #[allow(dead_code)] // GUI shutdown now uses the dedicated worker; hosts still poll.
    pub fn begin_stop(&mut self) {
        if self.stop_requested {
            return;
        }
        self.stop_requested = true;
        self.stop_started = Some(Instant::now());
        // A write failure here is not fatal: the child may already be gone, and the wait
        // that follows decides the outcome.
        let _ = self.send_host(&HostMessage::Stop {
            version: PROTOCOL_VERSION,
        });
        // Closing the command channel is a second, independent stop signal: a sampler
        // watching its commands sees EOF even if it missed the message.
        self.child_stdin = None;
    }

    /// Advance the stop [`Supervisor::begin_stop`] asked for.
    ///
    /// Returns the verdict once the child's fate is known, and `None` while it is still
    /// leaving. Each call waits at most `budget`, so no frame is held longer than that. The
    /// polite part of the wait is bounded by `stop_grace` and the forced part by
    /// [`TERMINATION_GRACE`], exactly as in the blocking path — the difference is only who
    /// waits, the frame loop instead of one blocking call.
    #[allow(dead_code)] // Used by the sampler module hosts.
    pub fn poll_stop(&mut self, budget: Duration) -> Option<StopReason> {
        if let Some(reason) = self.terminated.clone() {
            return Some(reason);
        }
        let started = self.stop_started?;
        if let Some(code) = self.await_exit(budget) {
            // Drain the child's own last message so the reason can be the child's. The exit
            // is already confirmed, so this cannot change the evidence — and the budget is
            // frame-sized, because the caller is a frame loop.
            self.settle(POLL_STOP_SETTLE_BUDGET);
            let report = self.child_report();
            let reason = verdict_for_confirmed_exit(code, &report, true);
            self.terminated_with(reason.clone());
            return Some(reason);
        }
        if started.elapsed() >= self.config.stop_grace {
            return Some(
                self.terminate_with(StopReason::HeartbeatTimeout {
                    waited_ms: self.config.stop_grace.as_millis(),
                    note: "не завершился после запроса остановки и был завершён принудительно"
                        .to_string(),
                }),
            );
        }
        None
    }

    /// Terminate the child and record why.
    ///
    /// The recorded reason is only ever reported when the exit is **confirmed** by the
    /// process handle; otherwise the state is [`StopReason::TerminationPending`]. Both
    /// termination calls are checked, because "we asked it to die" is not the same claim
    /// as "it is dead".
    pub fn terminate_with(&mut self, reason: StopReason) -> StopReason {
        if let Some(decided) = self.terminated.clone() {
            return decided;
        }
        debug_line(&format!("terminating child: {}", reason.describe()));
        // The command pipe is closed here, not only in `Drop`: the child sees EOF on its
        // commands and may leave on its own, which is gentler than being killed — and the
        // exit is awaited below, so either way the outcome is observed.
        self.child_stdin = None;
        // Terminating the whole job also covers any process the sampler started.
        let job_result = self.job.terminate(TERMINATION_EXIT_CODE);
        let process_result = if self.process.is_null() {
            Ok(())
        } else if unsafe { TerminateProcess(self.process, TERMINATION_EXIT_CODE) } == 0 {
            Err(format!(
                "TerminateProcess не выполнена (Win32 {})",
                last_error()
            ))
        } else {
            Ok(())
        };
        let exit = self.await_exit(TERMINATION_GRACE);
        if exit.is_none() {
            // The reasons are recorded in the trace because they are the only available
            // explanation for a termination that could not be confirmed.
            debug_line("the child's exit could not be confirmed after termination");
            if let Err(err) = &job_result {
                debug_line(err);
            }
            if let Err(err) = &process_result {
                debug_line(err);
            }
        }
        let reason = verdict_after_termination(reason, exit, TERMINATION_GRACE);
        self.terminated = Some(reason.clone());
        reason
    }

    fn terminated_with(&mut self, reason: StopReason) -> StopReason {
        if self.terminated.is_none() {
            self.terminated = Some(reason.clone());
        }
        reason
    }

    /// How long the child may take to get from `hello` to its first sample.
    ///
    /// A sampler does not sample the moment it is attached: it opens its providers, warms
    /// them up for one **full** interval (deliberately, so the first window is complete)
    /// and only then announces them and starts its cadence. Measured on this machine with
    /// a 100 ms interval, `hello` is followed by `providers` at about 300 ms and the first
    /// sample at about 400 ms. Holding that against a 300 ms heartbeat killed a perfectly
    /// healthy sampler on startup, which is what the acceptance report saw as "the real
    /// sampler produced zero samples".
    ///
    /// The budget is the handshake budget plus a few intervals of headroom, capped so a
    /// long interval cannot turn the startup phase into an unbounded wait.
    fn startup_grace(&self) -> Duration {
        let budget = self
            .config
            .handshake_timeout
            .saturating_add(self.config.interval.saturating_mul(STARTUP_INTERVALS));
        budget.min(self.config.heartbeat_timeout.max(STARTUP_GRACE_CEILING))
    }

    /// Non-blocking read of the next event, with the heartbeat enforced.
    ///
    /// The GUI calls this every frame. It never blocks for longer than `budget`, so a
    /// silent child cannot freeze the interface, and a child that has gone quiet past
    /// its budget is terminated here rather than waited on. The budget is the startup
    /// budget until the child has announced its providers or produced a sample, and the
    /// heartbeat budget from then on: a sampler that is opening its providers and taking
    /// its first full window is starting up, not hanging.
    pub fn poll(&mut self, budget: Duration) -> Option<SamplerEvent> {
        if let Some(reason) = self.terminated.clone() {
            return Some(SamplerEvent::Stopped(reason));
        }
        match self.events.recv_timeout(budget) {
            Ok(event) => {
                self.event_received();
                self.last_heard = Instant::now();
                if matches!(event, SamplerEvent::Providers(_) | SamplerEvent::Sample(_)) {
                    // The child has proved its cadence: from here on, silence is a
                    // heartbeat problem rather than a startup one.
                    self.startup_done = true;
                }
                if let SamplerEvent::Stopped(cause) = &event {
                    // A verdict from the reader still has to be proven against the
                    // process handle: a broken protocol does not mean the child exited,
                    // and a child that is still running must be ended here rather than
                    // left for teardown.
                    let cause = cause.clone();
                    let reason = self.terminate_with(cause);
                    return Some(SamplerEvent::Stopped(reason));
                }
                Some(event)
            }
            Err(RecvTimeoutError::Timeout) => {
                // The budget the child is being held to, and why.
                let allowance = if self.startup_done {
                    self.config.heartbeat_timeout
                } else {
                    self.startup_grace()
                };
                let quiet = self.last_heard.elapsed();
                if quiet < allowance {
                    return None;
                }
                // A quiet child is never reported as exited until the process handle
                // proves an exit. This is the check that used to turn a live process
                // into `ChildExited(259)`.
                if let Some(code) = self.confirmed_exit() {
                    let report = self.child_report();
                    let reason = verdict_for_confirmed_exit(code, &report, self.stop_requested);
                    self.terminated_with(reason.clone());
                    return Some(SamplerEvent::Stopped(reason));
                }
                let report = self.child_report();
                let cause = match (&report.fatal, &report.bye) {
                    (Some(fatal), _) => StopReason::ChildFailed(format!(
                        "{fatal}; процесс остался жив и был завершён принудительно"
                    )),
                    // The false-`bye` case: the child claimed a clean completion and kept
                    // running. The claim is reported, the verdict is not clean.
                    (None, Some(bye)) if bye.clean => StopReason::HeartbeatTimeout {
                        waited_ms: quiet.as_millis(),
                        note: format!(
                            "сэмплер сообщил о завершении ({}), но процесс остался жив; завершён принудительно",
                            bye.reason
                        ),
                    },
                    _ => StopReason::HeartbeatTimeout {
                        waited_ms: quiet.as_millis(),
                        note: if self.startup_done {
                            format!(
                                "нет сообщений дольше {} мс; процесс завершён принудительно",
                                allowance.as_millis()
                            )
                        } else {
                            format!(
                                "сэмплер не объявил провайдеров и не прислал ни одного замера за {} мс после hello; процесс завершён принудительно",
                                allowance.as_millis()
                            )
                        },
                    },
                };
                let reason = self.terminate_with(cause);
                Some(SamplerEvent::Stopped(reason))
            }
            Err(RecvTimeoutError::Disconnected) => {
                // The child's protocol stream ended. A process that has just closed its
                // pipes is usually in the middle of exiting, so the exit is given a
                // bounded moment to become observable before the closed stream is called
                // a fault.
                if let Some(code) = self.await_exit(STREAM_CLOSE_CONFIRM_BUDGET) {
                    let report = self.child_report();
                    let reason = verdict_for_confirmed_exit(code, &report, self.stop_requested);
                    self.terminated_with(reason.clone());
                    return Some(SamplerEvent::Stopped(reason));
                }
                // The stream is gone while the process is still alive: the run cannot
                // continue, so the child is ended here and the state stays unconfirmed
                // until the handle says otherwise.
                let reason = self.terminate_with(StopReason::Ipc(
                    "сэмплер закрыл поток протокола, не сообщив о завершении".to_string(),
                ));
                Some(SamplerEvent::Stopped(reason))
            }
        }
    }
}

impl Drop for Supervisor {
    fn drop(&mut self) {
        // Dropping the supervisor must never leave a sampler behind, and must never wait
        // on one that will not end. Every step below is bounded: a short polite budget,
        // an immediate job termination, a bounded confirmation, and bounded joins.
        if self.exit_code.is_none() && !self.process.is_null() {
            let _ = self.send_host(&HostMessage::Stop {
                version: PROTOCOL_VERSION,
            });
            self.child_stdin = None;
            let _ = self.await_exit(DROP_POLITE_BUDGET.min(self.config.stop_grace));
            if self.exit_code.is_none() {
                // Closing the job handle would kill it anyway; doing it explicitly makes
                // the intent clear, ends any process the sampler started, and lets the
                // exit be observed before the handle is closed.
                let _ = self.job.terminate(TERMINATION_EXIT_CODE);
                let _ = unsafe { TerminateProcess(self.process, TERMINATION_EXIT_CODE) };
                let _ = self.await_exit(DROP_EXIT_BUDGET);
            }
        }
        // A child that never confirmed its exit is remembered, so the next start refuses to
        // run a second sampler beside it. `TerminateProcess` is asynchronous and a process
        // stuck in kernel I/O can outlive every bounded wait above; promising that it cannot
        // would be a promise this code cannot keep.
        if self.exit_code.is_none() {
            if let Some(identity) = self.identity {
                remember_unconfirmed(identity);
            }
        }
        // The command pipe is closed **unconditionally**, whatever decided the run: a
        // child that is still alive must see EOF on its commands.
        self.child_stdin = None;
        if !self.process.is_null() {
            unsafe {
                CloseHandle(self.process);
            }
            self.process = std::ptr::null_mut();
        }
        // With the child ended and the pipes closed the readers see EOF and finish on
        // their own — but the join is **bounded**, because an unbounded join would make
        // teardown only as reliable as the thread being joined, and a teardown that can
        // hang the GUI is the exact failure this supervisor exists to prevent.
        join_bounded(self.reader.take());
        join_bounded(self.stderr_reader.take());
    }
}

/// Opt-in tracing of the event path.
///
/// Set `POWERLAB_DEBUG=1` to see every message the reader decoded and every reason the
/// supervisor decided to end the child. Off by default so a normal run stays quiet.
fn debug_line(text: &str) {
    if std::env::var_os("POWERLAB_DEBUG").is_some() {
        eprintln!("[powerlab-supervisor] {text}");
    }
}

/// A short name for a message, for the trace.
fn message_kind(message: &SamplerMessage) -> &'static str {
    match message {
        SamplerMessage::Hello { .. } => "hello",
        SamplerMessage::Providers { .. } => "providers",
        SamplerMessage::Sample { .. } => "sample",
        SamplerMessage::Notice { .. } => "notice",
        SamplerMessage::Bye { .. } => "bye",
        SamplerMessage::Fatal { .. } => "fatal",
    }
}

/// Read the child's stderr, keeping only the most recent lines.
///
/// The stream must be drained continuously: a child that writes more than one pipe
/// buffer of diagnostics would otherwise block inside its own logging.
fn spawn_stderr_reader(
    stream: std::fs::File,
    sink: Arc<Mutex<Vec<String>>>,
) -> thread::JoinHandle<()> {
    thread::Builder::new()
        .name("powerlab-sampler-stderr".to_string())
        .spawn(move || {
            // The same bounded framing as the protocol stream: a diagnostic line cannot
            // make the supervisor allocate without limit either.
            let mut reader = LineReader::new(stream);
            loop {
                match reader.next_line() {
                    Ok(line) => {
                        let text = line.trim();
                        if text.is_empty() {
                            continue;
                        }
                        // Bounded twice: the framing caps one line, and only the tail of
                        // the last lines is kept.
                        let text: String = text.chars().take(MAX_DIAGNOSTIC_LINE_CHARS).collect();
                        if let Ok(mut lines) = sink.lock() {
                            if lines.len() >= MAX_DIAGNOSTIC_LINES {
                                lines.remove(0);
                            }
                            lines.push(text);
                        }
                    }
                    Err(_) => return,
                }
            }
        })
        .expect("a stderr reader thread must spawn")
}

/// How many of the child's diagnostic lines are kept.
const MAX_DIAGNOSTIC_LINES: usize = 40;

/// How much of one diagnostic line is kept.
const MAX_DIAGNOSTIC_LINE_CHARS: usize = 512;

/// How long teardown waits for a reader thread before letting it go.
///
/// The readers have already seen EOF by the time this is called, so they finish in
/// microseconds. The bound exists so a thread that somehow does not finish cannot hang
/// the supervisor: past it the thread is detached, which is safe because the pipes it
/// reads from are closed, and the thread ends as soon as the receiver is dropped.
const READER_JOIN_BUDGET: Duration = Duration::from_millis(500);

/// Join a reader thread, giving up after [`READER_JOIN_BUDGET`].
///
/// `std::thread::JoinHandle::join` has no timeout, so the wait is implemented by
/// polling `is_finished` and only joining once the thread has actually finished.
fn join_bounded(handle: Option<thread::JoinHandle<()>>) {
    let Some(handle) = handle else {
        return;
    };
    let deadline = Instant::now() + READER_JOIN_BUDGET;
    while !handle.is_finished() {
        if Instant::now() >= deadline {
            debug_line("a reader thread did not finish within the teardown budget; detaching it");
            return;
        }
        thread::sleep(Duration::from_millis(5));
    }
    let _ = handle.join();
}

/// Read the child's stdout, decode the protocol and forward events.
///
/// The reader never decides that a run is clean. A `bye` is recorded as the child's
/// claim and forwarded as a notice; only the supervisor, with the process handle in
/// hand, turns that into a verdict.
fn spawn_reader(
    stream: std::fs::File,
    queue: EventQueue,
    expected_token: String,
    report: Arc<Mutex<ChildReport>>,
) -> thread::JoinHandle<()> {
    thread::Builder::new()
        .name("powerlab-sampler-reader".to_string())
        .spawn(move || {
            // Framing is bounded **before** a payload is allocated, so a provider that
            // writes a gigabyte without a newline costs one capped line instead of the
            // whole payload. (The previous `read_line` allocated the line first and only
            // then compared its length with the limit.)
            let mut reader = LineReader::new(stream);
            // The trace carries elapsed milliseconds, because "which message arrived when"
            // is exactly what a startup or heartbeat diagnosis needs: a sampler that
            // legitimately spends a provider-warmup interval before its first sample is
            // indistinguishable from a hung one without the timeline.
            let started = Instant::now();
            let mut consecutive_errors = 0u32;
            loop {
                let line = match reader.next_line() {
                    Ok(line) => line,
                    Err(LineError::Eof) => {
                        // The child closed its end. Nothing is sent here: the channel
                        // closing makes `poll` decide from the process handle, and a
                        // process that merely closed its pipes is not an exited one.
                        return;
                    }
                    Err(err) => {
                        consecutive_errors += 1;
                        let total = if let Ok(mut r)=report.lock(){r.protocol_errors=r.protocol_errors.saturating_add(1);r.protocol_errors}else{u64::MAX};
                        if total <= 4 { let _=queue.send(SamplerEvent::Notice {level:"warning".into(),text:format!("IPC rejected frame #{total}: {err}")}); }
                        debug_line(&format!("framing error #{consecutive_errors}: {err}"));
                        if consecutive_errors > ipc::MAX_CONSECUTIVE_PARSE_ERRORS {
                            let _ = queue.send(SamplerEvent::Stopped(StopReason::Protocol(format!(
                                "подряд получено {consecutive_errors} строк, нарушающих протокол: {err}"
                            ))));
                            return;
                        }
                        if matches!(err, LineError::Io(_)) {
                            // A stream error is not a framing slip that the next line
                            // could resynchronise: the reader is done.
                            return;
                        }
                        continue;
                    }
                };
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                match ipc::decode_sampler(trimmed) {
                    Ok(message) => {
                        consecutive_errors = 0;
                        debug_line(&format!(
                            "t+{}ms read {} bytes, kind={}",
                            started.elapsed().as_millis(),
                            trimmed.len(),
                            message_kind(&message)
                        ));
                        let event: Option<SamplerEvent> = match message {
                            SamplerMessage::Hello {
                                sampler_version,
                                session_token,
                                kind,
                                ..
                            } => {
                                // A token mismatch means this pipe's peer is not the
                                // sampler this supervisor started.
                                if session_token != expected_token {
                                    let _ = queue.send(SamplerEvent::Stopped(StopReason::Protocol(
                                        "сэмплер сообщил чужой токен сессии".to_string(),
                                    )));
                                    return;
                                }
                                // The window reports which sampler answered; the version is
                                // recorded here, where the handshake message is decoded.
                                if let Ok(mut report) = report.lock() {
                                    report.version = Some(sampler_version.clone());
                                }
                                Some(SamplerEvent::Hello {
                                    sampler_version,
                                    kind,
                                })
                            }
                            SamplerMessage::Providers { providers, .. } => {
                                Some(SamplerEvent::Providers(providers))
                            }
                            SamplerMessage::Sample { sample, .. } => {
                                Some(SamplerEvent::Sample(Box::new(sample)))
                            }
                            SamplerMessage::Notice { notice, .. } => Some(SamplerEvent::Notice {
                                level: notice.level,
                                text: notice.text,
                            }),
                            SamplerMessage::Bye {
                                reason,
                                samples,
                                clean,
                                ..
                            } => {
                                // The child's own statement, recorded rather than
                                // trusted: a `bye` with `clean: true` from a process that
                                // keeps running is the false completion the acceptance
                                // report found.
                                if let Ok(mut report) = report.lock() {
                                    report.bye = Some(ByeClaim {
                                        reason: reason.clone(),
                                        samples,
                                        clean,
                                    });
                                }
                                Some(SamplerEvent::Notice {
                                    level: "info".to_string(),
                                    text: format!(
                                        "сэмплер завершился: {reason} (замеров: {samples})"
                                    ),
                                })
                            }
                            SamplerMessage::Fatal { reason, .. } => {
                                if let Ok(mut report) = report.lock() {
                                    report.fatal = Some(reason.clone());
                                }
                                Some(SamplerEvent::Notice {
                                    level: "error".to_string(),
                                    text: format!(
                                        "сэмплер сообщил о неустранимой ошибке: {reason}"
                                    ),
                                })
                            }
                        };
                        if let Some(event) = event {
                            // A bounded, blocking send: when the queue is full the reader
                            // waits, and the child waits on its own pipe. That is the
                            // backpressure that replaces unbounded growth.
                            if queue.send(event).is_err() {
                                return;
                            }
                        }
                    }
                    Err(err) => {
                        // A bounded number of malformed lines is tolerated so one
                        // corrupt message does not kill a healthy session; beyond that
                        // the peer is not speaking the protocol and is stopped.
                        consecutive_errors += 1;
                        let total = if let Ok(mut r)=report.lock(){r.protocol_errors=r.protocol_errors.saturating_add(1);r.protocol_errors}else{u64::MAX};
                        if total <= 4 { let _=queue.send(SamplerEvent::Notice {level:"warning".into(),text:format!("IPC rejected frame #{total}: {err}")}); }
                        debug_line(&format!(
                            "decode error #{consecutive_errors} on {} bytes: {err}",
                            trimmed.len()
                        ));
                        if consecutive_errors > ipc::MAX_CONSECUTIVE_PARSE_ERRORS {
                            let _ = queue.send(SamplerEvent::Stopped(StopReason::Protocol(format!(
                                "подряд получено {consecutive_errors} некорректных сообщений: {err}"
                            ))));
                            return;
                        }
                    }
                }
            }
        })
        .expect("a reader thread must spawn")
}

/// Build a Windows command line.
///
/// `CreateProcessW` takes one string, and quoting is the only thing that separates
/// arguments, so every argument is quoted and embedded quotes are escaped by the
/// documented backslash rule.
fn build_command_line(program: &Path, args: &[String]) -> Vec<u16> {
    let mut line = String::new();
    line.push_str(&quote_argument(&program.to_string_lossy()));
    for arg in args {
        line.push(' ');
        line.push_str(&quote_argument(arg));
    }
    let mut wide: Vec<u16> = line.encode_utf16().collect();
    wide.push(0);
    wide
}

/// Quote one argument for `CreateProcessW`.
fn quote_argument(argument: &str) -> String {
    if !argument.is_empty()
        && !argument
            .chars()
            .any(|c| c == ' ' || c == '\t' || c == '"' || c == '\\')
    {
        return argument.to_string();
    }
    let mut out = String::with_capacity(argument.len() + 2);
    out.push('"');
    let mut backslashes = 0usize;
    for ch in argument.chars() {
        match ch {
            '\\' => {
                backslashes += 1;
                out.push('\\');
            }
            '"' => {
                // Backslashes before a quote must be doubled, and the quote escaped.
                for _ in 0..=backslashes {
                    out.push('\\');
                }
                out.push('"');
                backslashes = 0;
            }
            other => {
                backslashes = 0;
                out.push(other);
            }
        }
    }
    // Trailing backslashes must be doubled so they do not escape the closing quote.
    for _ in 0..backslashes {
        out.push('\\');
    }
    out.push('"');
    out
}

/// A session token that a stale process cannot guess.
fn random_token() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id() as u128;
    // Not a cryptographic token: it only has to distinguish this run from a previous
    // one that must not attach to this pipe.
    let mut state = nanos ^ (pid << 64);
    let mut out = String::with_capacity(32);
    for _ in 0..4 {
        // xorshift64*
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        let value = state.wrapping_mul(0x2545_F491_4F6C_DD1D);
        out.push_str(&format!("{:016x}", (value as u64) ^ (nanos as u64)));
    }
    out
}

/// A `File` from a raw Win32 handle.
///
/// The handles here are owned by the supervisor and closed when the `File` drops.
trait FromRawHandle {
    unsafe fn from_raw_handle(handle: *mut c_void) -> std::fs::File;
}

impl FromRawHandle for std::fs::File {
    unsafe fn from_raw_handle(handle: *mut c_void) -> std::fs::File {
        unsafe {
            <std::fs::File as std::os::windows::io::FromRawHandle>::from_raw_handle(
                handle as std::os::windows::raw::HANDLE,
            )
        }
    }
}

/// Blocking variant of the sampler's `Read` usage, kept for the reader thread.
#[allow(dead_code)]
fn read_available(stream: &mut std::fs::File, buffer: &mut [u8]) -> std::io::Result<usize> {
    stream.read(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arguments_are_quoted_by_the_documented_rule() {
        assert_eq!(quote_argument("simple"), "simple");
        assert_eq!(quote_argument("with space"), "\"with space\"");
        assert_eq!(quote_argument(""), "\"\"");
        // A trailing backslash must not escape the closing quote.
        assert_eq!(quote_argument("dir\\"), "\"dir\\\\\"");
        // An embedded quote is escaped, and preceding backslashes are doubled.
        assert_eq!(quote_argument("a\"b"), "\"a\\\"b\"");
        assert_eq!(quote_argument("a\\\"b"), "\"a\\\\\\\"b\"");
    }

    #[test]
    fn the_command_line_is_nul_terminated_utf16() {
        let line = build_command_line(Path::new("C:\\a b\\sampler.exe"), &["--x".into()]);
        assert_eq!(*line.last().unwrap(), 0);
        let text = String::from_utf16(&line[..line.len() - 1]).expect("utf16");
        assert!(text.starts_with("\"C:\\a b\\sampler.exe\""), "{text}");
        assert!(text.ends_with("--x"), "{text}");
    }

    #[test]
    fn a_missing_program_is_refused_before_any_process_is_created() {
        let config = SupervisorConfig::new("C:\\definitely\\not\\here\\sampler.exe");
        let err = match Supervisor::start(config) {
            Ok(_) => panic!("must be refused"),
            Err(err) => err,
        };
        assert!(err.contains("не найден"), "{err}");
    }

    #[test]
    fn session_tokens_differ_between_calls() {
        let first = random_token();
        let second = random_token();
        assert_ne!(first, second);
        assert_eq!(first.len(), 64);
    }

    #[test]
    fn the_heartbeat_scales_with_the_interval_and_stays_bounded() {
        let mut config = SupervisorConfig::new("x");
        config.interval = Duration::from_millis(100);
        let scaled = config.clone().heartbeat_for_interval();
        assert_eq!(scaled.heartbeat_timeout, Duration::from_secs(10));

        config.interval = Duration::from_secs(60);
        let capped = config.heartbeat_for_interval();
        assert_eq!(capped.heartbeat_timeout, Duration::from_secs(120));
    }

    #[test]
    fn the_job_reports_when_no_child_is_running() {
        // A supervisor that has not been started has no job, so this asserts the
        // error path of a refused start instead.
        let config = SupervisorConfig::new("C:\\nope\\sampler.exe");
        assert!(Supervisor::start(config).is_err());
    }

    /// The Win32 structures this module declares must match the SDK exactly.
    ///
    /// The assertions are compile-time, in the module itself, so this test only records
    /// why they are there: a field read at the wrong offset is read as a *valid* value,
    /// which is how a live process came to be reported as `ChildExited(259)`.
    #[test]
    fn the_declared_win32_structures_are_sized_like_the_sdk() {
        assert_eq!(std::mem::size_of::<StartupInfoW>(), 104);
        assert_eq!(std::mem::size_of::<StartupInfoExW>(), 112);
        assert_eq!(std::mem::size_of::<ProcessInformation>(), 24);
        assert_eq!(std::mem::size_of::<SecurityAttributes>(), 24);
    }

    fn bye_report(clean: bool) -> ChildReport {
        ChildReport {
            protocol_errors: 0,
            version: Some("0.1.0-audit".to_string()),
            bye: Some(ByeClaim {
                reason: "done".to_string(),
                samples: 7,
                clean,
            }),
            fatal: None,
        }
    }

    /// A `bye` is a claim, and a claim is not proof.
    ///
    /// The acceptance report found the false `bye` (a child that says `clean=true` and
    /// keeps running) reported as `Completed` / `CLEAN=true`. The verdict functions
    /// cannot do that: without a confirmed exit there is no verdict at all, and a
    /// termination that was never confirmed is `TerminationPending`.
    #[test]
    fn a_clean_claim_without_a_confirmed_exit_is_never_clean() {
        let pending = verdict_after_termination(
            StopReason::HeartbeatTimeout {
                waited_ms: 300,
                note: "quiet".to_string(),
            },
            None,
            TERMINATION_GRACE,
        );
        assert!(!pending.is_clean(), "{pending:?}");
        assert!(
            matches!(pending, StopReason::TerminationPending { .. }),
            "{pending:?}"
        );
        // And a forced termination is reported as such once the exit is confirmed, not
        // as a completion.
        let forced = verdict_after_termination(
            StopReason::Protocol("bad line".to_string()),
            Some(1),
            TERMINATION_GRACE,
        );
        assert!(!forced.is_clean(), "{forced:?}");
        assert!(matches!(forced, StopReason::Protocol(_)), "{forced:?}");
    }

    #[test]
    fn a_clean_verdict_needs_an_exit_of_zero_and_a_clean_bye() {
        assert!(verdict_for_confirmed_exit(0, &bye_report(true), false).is_clean());
        // A `bye` that admits it could not release its resources is a failure.
        let partial = verdict_for_confirmed_exit(0, &bye_report(false), true);
        assert!(!partial.is_clean(), "{partial:?}");
        // A zero exit code from a child that said nothing is only clean when the
        // supervisor itself asked it to stop.
        assert!(!verdict_for_confirmed_exit(0, &ChildReport::default(), false).is_clean());
        assert!(verdict_for_confirmed_exit(0, &ChildReport::default(), true).is_clean());
    }

    #[test]
    fn a_non_zero_exit_code_is_reported_as_an_exit_not_a_completion() {
        let reason = verdict_for_confirmed_exit(9, &ChildReport::default(), false);
        assert_eq!(reason, StopReason::ChildExited { code: 9 });
        assert!(!reason.is_clean());
        // Even a clean `bye` cannot make a crash look clean.
        assert!(!verdict_for_confirmed_exit(9, &bye_report(true), true).is_clean());
    }

    #[test]
    fn a_fatal_message_outranks_a_zero_exit_code() {
        let report = ChildReport {
            protocol_errors: 0,
            version: None,
            bye: None,
            fatal: Some("provider exploded".to_string()),
        };
        let reason = verdict_for_confirmed_exit(0, &report, true);
        assert!(matches!(reason, StopReason::ChildFailed(_)), "{reason:?}");
        assert!(!reason.is_clean());
    }

    /// No verdict may carry `STILL_ACTIVE` as an exit code.
    ///
    /// 259 is what `GetExitCodeProcess` reports for a process that is still running, and
    /// the acceptance report found `ChildExited(259)` reported for a live child. The only
    /// producer of an exit code is [`Supervisor::reap`], which requires the process to be
    /// signalled first; this test records the rule for the verdict layer above it.
    #[test]
    fn a_running_process_is_never_described_as_an_exited_one() {
        let reason = verdict_after_termination(
            StopReason::Ipc("stream closed".to_string()),
            None,
            TERMINATION_GRACE,
        );
        assert!(matches!(reason, StopReason::TerminationPending { .. }));
        assert!(!reason.describe().contains("259"), "{}", reason.describe());
        assert!(!format!("{reason:?}").contains("ChildExited"));
    }

    /// Terminating a stalled child must also release the reader threads.
    ///
    /// This is a regression test for the defect where a reader stayed blocked in a read
    /// and `Drop`'s `join` waited on it for ever, so the GUI hung precisely when the
    /// sampler hung. The bounded reader used by the supervisor is exercised here: closing
    /// the write end must release a reader blocked on it.
    #[test]
    fn closing_the_write_end_releases_a_blocked_reader() {
        let mut inherit = SecurityAttributes {
            length: std::mem::size_of::<SecurityAttributes>() as DWORD,
            security_descriptor: std::ptr::null_mut(),
            inherit_handle: 1,
        };
        let mut read_end: HANDLE = std::ptr::null_mut();
        let mut write_end: HANDLE = std::ptr::null_mut();
        assert_ne!(
            unsafe { CreatePipe(&mut read_end, &mut write_end, &mut inherit, 0) },
            0,
            "CreatePipe failed"
        );
        let reader_file = unsafe { std::fs::File::from_raw_handle(read_end as _) };
        let writer_file = unsafe { std::fs::File::from_raw_handle(write_end as _) };

        let handle = thread::spawn(move || {
            let mut reader = LineReader::new(reader_file);
            // Blocks until the write end closes.
            let _ = reader.next_line();
        });

        // Give the reader time to actually block, then close the write end. Closing it is
        // what teardown does — after terminating the child — and the join below proves
        // the thread is released by that, not by the timeout.
        thread::sleep(Duration::from_millis(150));
        drop(writer_file);

        handle
            .join()
            .expect("the reader must be released by closing the write end");
    }

    /// Serialises the tests that touch the process-wide interlock list.
    ///
    /// The list is shared state by design (a child outlives its supervisor), so a test that
    /// reads or writes it must not race another that does.
    static INTERLOCK_TEST: Mutex<()> = Mutex::new(());

    /// Liveness is decided by process id **and** creation time.
    #[test]
    fn liveness_distinguishes_the_child_from_a_recycled_id() {
        let me = std::process::id();
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, 0, me) };
        assert!(!handle.is_null(), "the test process must be openable");
        let created = process_creation_time(handle).expect("a creation time is available");
        unsafe {
            CloseHandle(handle);
        }
        assert!(
            process_still_alive(ChildIdentity { pid: me, created }),
            "the test process is running and must be recognised as alive"
        );
        // Same id, different creation time: a recycled id is not the child.
        assert!(!process_still_alive(ChildIdentity {
            pid: me,
            created: created ^ 0xFFFF
        }));
        // Pid zero is never a real process.
        assert!(!process_still_alive(ChildIdentity { pid: 0, created: 1 }));
    }

    /// A child that never confirmed its exit must block the next start.
    ///
    /// This is the restart interlock: after an unconfirmed termination the old sampler may
    /// still be polling the hardware, and a second one beside it is exactly the orphan the
    /// acceptance warns about. The test process stands in for that child — the identity has
    /// the same shape the supervisor records — so no extra process is needed.
    #[test]
    fn a_child_that_never_confirmed_its_exit_blocks_the_next_start() {
        let _guard = INTERLOCK_TEST
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Ok(mut list) = UNCONFIRMED_CHILDREN.lock() {
            list.clear();
        }
        let me = std::process::id();
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, 0, me) };
        assert!(!handle.is_null(), "the test process must be openable");
        let created = process_creation_time(handle).expect("a creation time is available");
        unsafe {
            CloseHandle(handle);
        }
        remember_unconfirmed(ChildIdentity { pid: me, created });

        let config = SupervisorConfig::new("C:\\does-not-exist\\powerlab-sampler.exe");
        let message = match Supervisor::start(config) {
            Ok(_) => panic!("the interlock must refuse to start while the child is alive"),
            Err(message) => message,
        };
        assert!(
            message.contains("не подтвердил завершение"),
            "unexpected refusal: {message}"
        );

        // The rest of the suite must not inherit this state.
        if let Ok(mut list) = UNCONFIRMED_CHILDREN.lock() {
            list.clear();
        }
    }

    /// A remembered child that is really gone clears the interlock by itself.
    #[test]
    fn a_remembered_child_that_is_gone_clears_the_interlock() {
        let _guard = INTERLOCK_TEST
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Ok(mut list) = UNCONFIRMED_CHILDREN.lock() {
            list.clear();
        }
        // Pid zero is never a real process, so this identity cannot be alive.
        remember_unconfirmed(ChildIdentity { pid: 0, created: 1 });
        assert!(
            unresolved_children().is_empty(),
            "a child that no longer exists must not block a later start"
        );
    }
}

#[cfg(test)]
mod recovery_tests {
    use super::*;

    #[test]
    fn a_blocked_send_reserves_count_before_publication() {
        let (tx, rx) = mpsc::sync_channel(0);
        let count = Arc::new(AtomicUsize::new(0));
        let queue = EventQueue {
            tx,
            queued: Arc::clone(&count),
        };
        let worker = thread::spawn(move || {
            queue.send(SamplerEvent::Notice {
                level: "info".into(),
                text: "fixture".into(),
            })
        });
        let deadline = Instant::now() + Duration::from_secs(1);
        while count.load(Ordering::Relaxed) == 0 && Instant::now() < deadline {
            thread::yield_now();
        }
        let before_receive = count.load(Ordering::Relaxed);
        rx.recv_timeout(Duration::from_secs(1)).unwrap();
        count.fetch_sub(1, Ordering::Relaxed);
        worker.join().unwrap().unwrap();
        assert_eq!(
            before_receive, 1,
            "reserve must precede blocking publication"
        );
        assert_eq!(count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn failed_send_releases_its_reservation() {
        let (tx, rx) = mpsc::sync_channel(1);
        drop(rx);
        let count = Arc::new(AtomicUsize::new(0));
        let queue = EventQueue {
            tx,
            queued: Arc::clone(&count),
        };
        assert!(
            queue
                .send(SamplerEvent::Notice {
                    level: "info".into(),
                    text: "fixture".into()
                })
                .is_err()
        );
        assert_eq!(count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn cancellation_before_spawn_does_not_create_a_child() {
        let cancelled = AtomicBool::new(true);
        let result =
            Supervisor::start_cancellable(SupervisorConfig::new("missing.exe"), &cancelled);
        assert!(matches!(result, Err(e) if e == "запуск отменён пользователем"));
    }
}

#[cfg(test)]
mod recovery_identity_tests {
    use super::*;
    #[test]
    fn unknown_creation_time_cannot_clear_a_live_pid() {
        assert!(process_still_alive(ChildIdentity {
            pid: std::process::id(),
            created: 0
        }));
    }
    #[test]
    fn mismatched_known_creation_time_is_not_our_child() {
        assert!(!process_still_alive(ChildIdentity {
            pid: std::process::id(),
            created: 1
        }));
    }
}
