//! Explicit UAC for the reader only. The WinDiag UI/session never restarts.
//! Local named pipe, first-instance reservation, random nonce, both peer PIDs checked.
use super::{
    supervisor::{SamplerEvent, StopReason, Supervisor, SupervisorConfig},
    verify_runtime,
};
use powerlab_core::{
    ipc::{self, SamplerMessage},
    lineio::LineReader,
};
use std::{
    ffi::c_void,
    fs::File,
    io::{Read, Write},
    os::windows::io::{AsRawHandle, FromRawHandle},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, SyncSender},
    },
    time::{Duration, Instant},
};
type Handle = *mut c_void;
#[repr(C)]
struct ShellInfo {
    size: u32,
    mask: u32,
    hwnd: Handle,
    verb: *const u16,
    file: *const u16,
    parameters: *const u16,
    directory: *const u16,
    show: i32,
    instance: Handle,
    id_list: Handle,
    class: *const u16,
    class_key: Handle,
    hot_key: u32,
    icon: Handle,
    process: Handle,
}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateNamedPipeW(
        name: *const u16,
        access: u32,
        mode: u32,
        instances: u32,
        out_size: u32,
        in_size: u32,
        timeout: u32,
        security: Handle,
    ) -> Handle;
    fn ConnectNamedPipe(pipe: Handle, overlapped: Handle) -> i32;
    fn SetNamedPipeHandleState(
        pipe: Handle,
        mode: *const u32,
        count: *const u32,
        timeout: *const u32,
    ) -> i32;
    fn GetNamedPipeClientProcessId(pipe: Handle, pid: *mut u32) -> i32;
    fn GetNamedPipeServerProcessId(pipe: Handle, pid: *mut u32) -> i32;
    fn GetProcessId(handle: Handle) -> u32;
    fn WaitForSingleObject(handle: Handle, timeout: u32) -> u32;
    fn CloseHandle(handle: Handle) -> i32;
}
#[link(name = "shell32")]
unsafe extern "system" {
    fn ShellExecuteExW(info: *mut ShellInfo) -> i32;
}
#[link(name = "bcrypt")]
unsafe extern "system" {
    fn BCryptGenRandom(algorithm: Handle, buffer: *mut u8, length: u32, flags: u32) -> i32;
}
static READER_ALIVE: AtomicBool = AtomicBool::new(false);
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}
fn nonce() -> Result<String, String> {
    let mut bytes = [0u8; 32];
    if unsafe { BCryptGenRandom(std::ptr::null_mut(), bytes.as_mut_ptr(), 32, 2) } < 0 {
        return Err("Windows RNG failed".into());
    }
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}
fn valid_token(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}
pub fn available() -> bool {
    !READER_ALIVE.load(Ordering::Acquire)
}
fn launch(name: &str, token: &str, parent: u32) -> Result<(usize, u32), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let file = wide(&exe.to_string_lossy());
    let verb = wide("runas");
    let args = wide(&format!("--powerlab-elevated {name} {token} {parent}"));
    let mut info: ShellInfo = unsafe { std::mem::zeroed() };
    info.size = std::mem::size_of::<ShellInfo>() as u32;
    info.mask = 0x40 | 0x100 | 0x400;
    info.file = file.as_ptr();
    info.verb = verb.as_ptr();
    info.parameters = args.as_ptr();
    info.show = 0;
    if unsafe { ShellExecuteExW(&mut info) } == 0 {
        return Err(format!(
            "Получение прав отменено или недоступно: {}",
            std::io::Error::last_os_error()
        ));
    }
    if info.process.is_null() {
        return Err("Windows не предоставила handle reader".into());
    }
    let pid = unsafe { GetProcessId(info.process) };
    Ok((info.process as usize, pid))
}

#[repr(C)]
struct SecurityAttributes {
    length: u32,
    descriptor: Handle,
    inherit: i32,
}
#[link(name = "advapi32")]
unsafe extern "system" {
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        text: *const u16,
        revision: u32,
        descriptor: *mut Handle,
        size: *mut u32,
    ) -> i32;
}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn LocalFree(memory: Handle) -> Handle;
}
fn caller_sid() -> Result<String, String> {
    let script = "$i=[Security.Principal.WindowsIdentity]::GetCurrent();try{$i.User.Value}finally{$i.Dispose()}";
    let sid =
        crate::ps_exec::run_powershell_compact("powershell.exe", script, Duration::from_secs(10))
            .map_err(|e| e.to_string())?
            .trim()
            .to_owned();
    if !sid.starts_with("S-1-")
        || sid.len() > 184
        || !sid
            .bytes()
            .all(|b| b.is_ascii_digit() || b == b'-' || b == b'S')
    {
        return Err("Caller SID could not be verified".into());
    }
    Ok(sid)
}
fn reserve(name: &str, _direction: u32) -> Result<File, String> {
    let name = wide(&format!(r"\\.\pipe\{name}"));
    let sid = caller_sid()?;
    let sddl = wide(&format!("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;{sid})"));
    let mut descriptor = std::ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let mut security = SecurityAttributes {
        length: std::mem::size_of::<SecurityAttributes>() as u32,
        descriptor,
        inherit: 0,
    };
    // DUPLEX grants FILE_WRITE_ATTRIBUTES for the mode switch. Each reserved pipe
    // is used in only ONE direction, so synchronous ReadFile never locks its writer.
    let h = unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            3 | 0x80000,
            1 | 8,
            1,
            65536,
            65536,
            0,
            &mut security as *mut SecurityAttributes as Handle,
        )
    };
    let error = std::io::Error::last_os_error();
    unsafe {
        LocalFree(descriptor);
    }
    if h as isize == -1 {
        return Err(error.to_string());
    }
    Ok(unsafe { File::from_raw_handle(h) })
}

fn connected(pipe: &File, pid: u32, stop: &AtomicBool, deadline: Instant) -> Result<(), String> {
    let h = pipe.as_raw_handle();
    loop {
        let _ = unsafe { ConnectNamedPipe(h, std::ptr::null_mut()) };
        let mut client = 0;
        if unsafe { GetNamedPipeClientProcessId(h, &mut client) } != 0 {
            if client != pid {
                return Err("Идентичность UAC reader не совпала".into());
            }
            break;
        }
        if stop.load(Ordering::Acquire) || Instant::now() > deadline {
            return Err("Подключение reader не подтверждено".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let mode = 0;
    if unsafe { SetNamedPipeHandleState(h, &mode, std::ptr::null(), std::ptr::null()) } == 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(())
}
fn client_pipe(name: &str, write: bool, deadline: Instant) -> Result<File, String> {
    let path = format!(r"\\.\pipe\{name}");
    loop {
        match std::fs::OpenOptions::new()
            .read(!write)
            .write(write)
            .open(&path)
        {
            Ok(p) => return Ok(p),
            Err(e) => {
                if Instant::now() > deadline {
                    return Err(e.to_string());
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }
}
pub fn run(
    tx: SyncSender<Result<SamplerEvent, String>>,
    stop: Arc<AtomicBool>,
) -> Result<(), String> {
    if READER_ALIVE
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err("Предыдущий расширенный reader ещё не подтвердил завершение".into());
    }
    struct StartupGuard;
    impl Drop for StartupGuard {
        fn drop(&mut self) {
            READER_ALIVE.store(false, Ordering::Release);
        }
    }
    let guard = StartupGuard;
    let token = nonce()?;
    let name = format!("EXPC.WinDiag.PowerLab.{token}");
    let mut pipe = reserve(&name, 1)?;
    let mut control = reserve(&(name.clone() + "-ctl"), 2)?;
    let raw = pipe.as_raw_handle();
    let (launch_tx, launch_rx) = mpsc::channel();
    let n = name.clone();
    let t = token.clone();
    let parent = std::process::id();
    std::mem::forget(guard);
    std::thread::spawn(move || match launch(&n, &t, parent) {
        Ok((handle, pid)) => {
            std::thread::spawn(move || {
                unsafe {
                    WaitForSingleObject(handle as Handle, u32::MAX);
                    CloseHandle(handle as Handle);
                }
                READER_ALIVE.store(false, Ordering::Release);
            });
            let _ = launch_tx.send(Ok(pid));
        }
        Err(e) => {
            READER_ALIVE.store(false, Ordering::Release);
            let _ = launch_tx.send(Err(e));
        }
    });
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut launched = None;
    while launched.is_none() {
        if stop.load(Ordering::Acquire) {
            return Err("Получение прав отменено; текущая сессия WinDiag сохранена".into());
        }
        if Instant::now() > deadline {
            return Err("Истёк срок ожидания UAC".into());
        }
        match launch_rx.try_recv() {
            Ok(Ok(v)) => launched = Some(v),
            Ok(Err(e)) => return Err(e),
            Err(mpsc::TryRecvError::Disconnected) => {
                return Err("UAC launcher завершился без результата".into());
            }
            _ => {}
        }
        // A successful client may connect before ShellExecuteEx returns.
        let _ = unsafe { ConnectNamedPipe(raw, std::ptr::null_mut()) };
        let _ = unsafe { ConnectNamedPipe(control.as_raw_handle(), std::ptr::null_mut()) };
        std::thread::sleep(Duration::from_millis(20));
    }
    let pid = launched.unwrap();
    connected(&pipe, pid, &stop, deadline)?;
    connected(&control, pid, &stop, deadline)?;
    let mut auth = vec![];
    for _ in 0..65 {
        let mut b = [0];
        pipe.read_exact(&mut b).map_err(|e| e.to_string())?;
        if b[0] == b'\n' {
            break;
        }
        auth.push(b[0]);
    }
    if auth != token.as_bytes() {
        return Err("Неверный nonce UAC reader".into());
    }
    let read = pipe.try_clone().map_err(|e| e.to_string())?;
    let (frames, rx) = mpsc::sync_channel(16);
    std::thread::spawn(move || {
        let mut r = LineReader::new(read);
        loop {
            let line = r.next_line().map_err(|e| e.to_string());
            let ended = line.is_err();
            if frames.send(line).is_err() || ended {
                break;
            }
        }
    });
    control.write_all(b"go\n").map_err(|e| e.to_string())?;
    let mut sent_stop = false;
    let mut stopped_at = None;
    let mut heard = Instant::now();
    loop {
        if stop.load(Ordering::Acquire) && !sent_stop {
            let _ = control.write_all(b"stop\n");
            sent_stop = true;
            stopped_at = Some(Instant::now());
        }
        if stopped_at.is_some_and(|t| t.elapsed() > Duration::from_secs(8)) {
            return Err("Расширенный reader завершает операцию; повторный запуск заблокирован до подтверждения выхода".into());
        }
        match rx.recv_timeout(Duration::from_millis(20)) {
            Ok(Ok(line)) => {
                heard = Instant::now();
                let message = ipc::decode_sampler(&line).map_err(|e| e.to_string())?;
                let event = match message {
                    SamplerMessage::Hello {
                        sampler_version,
                        kind,
                        ..
                    } => SamplerEvent::Hello {
                        sampler_version,
                        kind,
                    },
                    SamplerMessage::Providers { providers, .. } => {
                        SamplerEvent::Providers(providers)
                    }
                    SamplerMessage::Sample { sample, .. } => SamplerEvent::Sample(Box::new(sample)),
                    SamplerMessage::Notice { notice, .. } => SamplerEvent::Notice {
                        level: notice.level,
                        text: notice.text,
                    },
                    SamplerMessage::Bye { reason, clean, .. } => {
                        let exit_deadline = Instant::now() + Duration::from_secs(2);
                        while !available() && Instant::now() < exit_deadline {
                            std::thread::sleep(Duration::from_millis(10));
                        }
                        let e = if !available() {
                            StopReason::TerminationPending {
                                note: "UAC reader сообщил bye, но процесс ещё не подтвердил выход"
                                    .into(),
                            }
                        } else if clean {
                            StopReason::OperatorStop
                        } else {
                            StopReason::ChildFailed(reason)
                        };
                        let _ = tx.send(Ok(SamplerEvent::Stopped(e)));
                        return Ok(());
                    }
                    SamplerMessage::Fatal { reason, .. } => return Err(reason),
                };
                if tx.send(Ok(event)).is_err() {
                    let _ = control.write_all(b"stop\n");
                    return Ok(());
                }
            }
            Ok(Err(e)) => return Err(e),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err("Канал UAC reader закрыт".into());
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if heard.elapsed() > Duration::from_secs(20) {
                    let _ = control.write_all(b"stop\n");
                    return Err(
                        "Reader не отвечает; повторное защищённое чтение заблокировано".into(),
                    );
                }
            }
        }
    }
}
pub fn broker(args: &[String]) -> i32 {
    match broker_inner(args) {
        Ok(()) => 0,
        Err(_) => 2,
    }
}
fn broker_inner(args: &[String]) -> Result<(), String> {
    broker_transport(args, None)
}
fn broker_transport(
    args: &[String],
    program_override: Option<std::path::PathBuf>,
) -> Result<(), String> {
    if args.len() != 4
        || !valid_token(&args[2])
        || args[1] != format!("EXPC.WinDiag.PowerLab.{}", args[2])
    {
        return Err("Invalid broker parameters".into());
    }
    let parent: u32 = args[3].parse().map_err(|_| "Invalid parent")?;
    let deadline = Instant::now() + Duration::from_secs(12);
    let mut pipe = client_pipe(&args[1], true, deadline)?;
    let control = client_pipe(&(args[1].clone() + "-ctl"), false, deadline)?;
    let mut server = 0;
    if unsafe { GetNamedPipeServerProcessId(pipe.as_raw_handle(), &mut server) } == 0
        || server != parent
    {
        return Err("Broker parent mismatch".into());
    }
    let mut control_server = 0;
    if unsafe { GetNamedPipeServerProcessId(control.as_raw_handle(), &mut control_server) } == 0
        || control_server != parent
    {
        return Err("Control pipe parent mismatch".into());
    }
    // No hardware initialization until the owner authenticates and grants 'go'.
    writeln!(pipe, "{}", args[2]).map_err(|e| e.to_string())?;
    let read = control;
    let (cmdtx, cmdrx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut reader = LineReader::new(read);
        while let Ok(line) = reader.next_line() {
            if cmdtx.send(line).is_err() {
                break;
            }
        }
    });
    if cmdrx
        .recv_timeout(Duration::from_secs(10))
        .map_err(|_| "No owner authorization")?
        != "go"
    {
        return Err("Owner authorization refused".into());
    }
    let prepared = if program_override.is_none() {
        Some(crate::portable::prepare()?)
    } else {
        None
    };
    let program = match program_override {
        Some(path) => path,
        None => prepared
            .as_ref()
            .unwrap()
            .root
            .join("PowerLab/powerlab-sampler.exe"),
    };
    let _runtime = verify_runtime(&program).map_err(|e| {
        let _ = writeln!(
            pipe,
            "{}",
            ipc::encode_sampler(&SamplerMessage::Fatal {
                version: ipc::PROTOCOL_VERSION,
                reason: e.clone()
            })
        );
        e
    })?;
    let cancel = AtomicBool::new(false);
    let mut s = Supervisor::start_cancellable(SupervisorConfig::new(program), &cancel)?;
    let version = ipc::PROTOCOL_VERSION;
    let mut count = 0;
    let hello = SamplerMessage::Hello {
        version,
        sampler_version: s.sampler_version().unwrap_or_default(),
        session_token: args[2].clone(),
        started_ms: 0,
        interval_ms: 1000,
        kind: "UAC reader".into(),
    };
    writeln!(pipe, "{}", ipc::encode_sampler(&hello)).map_err(|e| e.to_string())?;
    loop {
        match cmdrx.try_recv() {
            Ok(c) if c == "stop" => {
                let reason = s.stop();
                writeln!(
                    pipe,
                    "{}",
                    ipc::encode_sampler(&SamplerMessage::Bye {
                        version,
                        reason: reason.describe(),
                        samples: count,
                        clean: reason.is_clean()
                    })
                )
                .map_err(|e| e.to_string())?;
                return Ok(());
            }
            Err(mpsc::TryRecvError::Disconnected) => {
                let _ = s.stop();
                return Ok(());
            }
            _ => {}
        }
        if let Some(event) = s.poll(Duration::from_millis(20)) {
            let message = match event {
                SamplerEvent::Hello { .. } => continue,
                SamplerEvent::Providers(providers) => {
                    SamplerMessage::Providers { version, providers }
                }
                SamplerEvent::Sample(sample) => {
                    count = sample.index;
                    SamplerMessage::Sample {
                        version,
                        sample: *sample,
                    }
                }
                SamplerEvent::Notice { level, text } => SamplerMessage::Notice {
                    version,
                    notice: ipc::Notice { level, text },
                },
                SamplerEvent::Stopped(reason) => SamplerMessage::Bye {
                    version,
                    reason: reason.describe(),
                    samples: count,
                    clean: reason.is_clean(),
                },
            };
            let end = matches!(message, SamplerMessage::Bye { .. });
            if writeln!(pipe, "{}", ipc::encode_sampler(&message)).is_err() {
                let _ = s.stop();
                return Ok(());
            }
            if end {
                return Ok(());
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn broker_rejects_arbitrary_command_or_path() {
        assert!(
            broker_inner(&[
                "--powerlab-elevated".into(),
                "cmd.exe".into(),
                "x".into(),
                "1".into()
            ])
            .is_err()
        );
        assert!(!valid_token("x"));
        assert!(!valid_token(&"a".repeat(65)));
        assert!(valid_token(&"a".repeat(64)));
    }
}

#[cfg(test)]
mod pipe_tests {
    use super::*;
    #[test]
    #[ignore = "Actual Windows named pipe and sampler, ordinary token; no UAC"]
    fn reader_broker_pipe_roundtrip_without_uac() {
        let token = nonce().unwrap();
        let name = format!("EXPC.WinDiag.PowerLab.{token}");
        let pipe = reserve(&name, 1).unwrap();
        let mut control = reserve(&(name.clone() + "-ctl"), 2).unwrap();
        let args = vec![
            "--powerlab-elevated".into(),
            name,
            token.clone(),
            std::process::id().to_string(),
        ];
        let program = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("third_party/powerlab-runtime/powerlab-sampler.exe");
        let child = std::thread::spawn(move || broker_transport(&args, Some(program)));
        let deadline = Instant::now() + Duration::from_secs(20);
        let stop = AtomicBool::new(false);
        connected(&pipe, std::process::id(), &stop, deadline).unwrap();
        connected(&control, std::process::id(), &stop, deadline).unwrap();
        let mut reader = LineReader::new(pipe.try_clone().unwrap());
        assert_eq!(reader.next_line().unwrap(), token);
        control.write_all(b"go\n").unwrap();
        let mut count = 0;
        loop {
            let message = ipc::decode_sampler(&reader.next_line().unwrap()).unwrap();
            if matches!(message, SamplerMessage::Sample { .. }) {
                count += 1;
                if count == 3 {
                    control.write_all(b"stop\n").unwrap();
                }
            }
            if let SamplerMessage::Bye { clean, .. } = message {
                assert!(clean);
                break;
            }
            assert!(Instant::now() < deadline);
        }
        assert!(count >= 3);
        assert!(child.join().unwrap().is_ok());
    }
}
