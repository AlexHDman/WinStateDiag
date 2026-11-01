//! Explicitly confirmed contextual repair. No startup/diagnostic path invokes this runner.
use crate::deep_checks::{self, CheckResult, DeepCheck, DeepCheckOutcome};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

#[derive(Clone, Debug, PartialEq)]
pub struct Plan {
    pub check: DeepCheck,
    pub drive: String,
    pub before: DeepCheckOutcome,
}
impl Plan {
    pub fn command(&self) -> String {
        self.check.manual_command(&self.drive)
    }
    pub fn verification(&self) -> String {
        match self.check {
            DeepCheck::Sfc => "sfc /verifyonly".into(),
            DeepCheck::Dism => "DISM /Online /Cleanup-Image /ScanHealth".into(),
            DeepCheck::Chkdsk => format!("chkdsk {}", self.drive),
        }
    }
    pub fn warning(&self) -> &'static str {
        match self.check {
            DeepCheck::Sfc => {
                "Будут изменены защищённые системные файлы. Сохрани работу и резервную копию важных данных. После операции будет выполнена проверка /verifyonly."
            }
            DeepCheck::Dism => {
                "Будет изменено хранилище компонентов Windows. Может потребоваться Windows Update, источник восстановления и перезагрузка. После операции будет выполнена /ScanHealth."
            }
            DeepCheck::Chkdsk => {
                "Исправление файловой системы системного NTFS-тома. Принудительное отключение тома запрещено. Если том занят, Windows предложит проверку при следующей перезагрузке; запуск системы может занять длительное время. Перезагрузка не выполняется автоматически. Нужна резервная копия важных данных."
            }
        }
    }
}
pub fn eligible(o: &DeepCheckOutcome) -> bool {
    if o.result != CheckResult::Attention {
        return false;
    }
    let d = o.detail.to_lowercase().replace('ё', "е");
    match o.check {
        DeepCheck::Sfc => {
            (d.contains("verifyonly")
                && d.contains("обнаружил признаки нарушения целостности")
                && !d.contains("не обнаруж"))
                || deep_checks::sfc_semantic_result(&o.detail, false, Some(0))
                    == "INTEGRITY_VIOLATIONS"
                || d.trim() == "integrity_violations"
        }
        DeepCheck::Dism => {
            !d.contains("не подлежит")
                && !d.contains("cannot be repaired")
                && (d.contains("подлежит восстановлению")
                    || d.contains("component store is repairable")
                    || d.trim() == "repairable")
        }
        DeepCheck::Chkdsk => {
            deep_checks::chkdsk_finding(&o.detail)
                == Some(deep_checks::ChkdskFinding::ProblemsFound)
        }
    }
}
pub fn plan(o: &DeepCheckOutcome, drive: &str) -> Option<Plan> {
    let b = drive.as_bytes();
    (eligible(o) && b.len() == 2 && b[0].is_ascii_alphabetic() && b[1] == b':').then(|| Plan {
        check: o.check,
        drive: drive.to_ascii_uppercase(),
        before: o.clone(),
    })
}
/// Constructed only after the UI's explicit command and (for CHKDSK) reboot confirmations.
pub struct Authorized {
    plan: Plan,
}
pub fn authorize(
    plan: Plan,
    confirmed: bool,
    reboot_confirmed: bool,
    elevated: bool,
    busy: bool,
) -> Result<Authorized, String> {
    if !confirmed || (plan.check == DeepCheck::Chkdsk && !reboot_confirmed) {
        return Err("Операция не подтверждена".into());
    }
    if !elevated {
        return Err("Нужны права администратора. Перезапусти EXE и подтверди UAC; при отмене UAC ремонт не запускается.".into());
    }
    if busy {
        return Err("Дождись завершения текущей диагностики или ремонта".into());
    }
    if crate::repair::plan(&plan.before, &plan.drive).as_ref() != Some(&plan) {
        return Err("Недопустимая цель ремонта".into());
    }
    if !eligible(&plan.before) {
        return Err("Подтверждённая исправляемая проблема отсутствует".into());
    }
    Ok(Authorized { plan })
}
#[derive(Clone, Debug, Default)]
pub struct Progress {
    pub phase: String,
    pub percent: Option<f32>,
    pub latest: String,
}
pub type SharedProgress = Arc<Mutex<Progress>>;
#[derive(Clone, Debug)]
pub struct Output {
    pub code: Option<i32>,
    pub text: String,
    pub scheduled: bool,
}
#[derive(Clone, Debug, PartialEq)]
pub enum Failure {
    Cancelled,
    Timeout,
    Error(String),
}
pub trait Runner {
    fn run(
        &mut self,
        plan: &Plan,
        verify: bool,
        cancel: &AtomicBool,
        progress: &SharedProgress,
    ) -> Result<Output, Failure>;
}
#[derive(Clone, Debug)]
pub struct Report {
    pub id: String,
    pub plan: Plan,
    pub status: String,
    pub message: String,
    pub repair: Option<Output>,
    pub verification: Option<Output>,
    pub verified: Option<CheckResult>,
    pub reboot: bool,
}
impl Report {
    pub fn label(&self) -> &'static str {
        match self.status.as_str() {
            "SUCCESS" => "Исправление подтверждено",
            "REBOOT_REQUIRED" => "Требуется перезагрузка",
            "CANCELLED" => "Операция прервана",
            "TIMEOUT" => "Превышено время ожидания",
            "NOT_VERIFIED" => "Исправность не подтверждена",
            _ => "Ошибка выполнения",
        }
    }
    pub fn json(&self) -> String {
        let q = deep_checks::json::string;
        let out = |v: &Option<Output>| {
            v.as_ref()
                .map(|o| {
                    format!(
                        "{{\"exit_code\":{},\"scheduled\":{},\"output\":{}}}",
                        o.code.map(|c| c.to_string()).unwrap_or("null".into()),
                        o.scheduled,
                        q(&o.text)
                    )
                })
                .unwrap_or("null".into())
        };
        format!(
            "{{\"producer_version\":{},\"repair_id\":{},\"check\":{},\"command\":{},\"verification_command\":{},\"original_finding\":{},\"original_status\":{},\"original_source\":{},\"status\":{},\"message\":{},\"reboot_required\":{},\"verified_result\":{},\"repair\":{},\"verification\":{}}}",
            q(crate::APP_VERSION),
            q(&self.id),
            q(self.plan.check.key()),
            q(&self.plan.command()),
            q(&self.plan.verification()),
            q(&self.plan.before.detail),
            q(self.plan.before.result.as_str()),
            q(self.plan.before.source.as_str()),
            q(&self.status),
            q(&self.message),
            self.reboot,
            self.verified
                .map(|v| q(v.as_str()))
                .unwrap_or("null".into()),
            out(&self.repair),
            out(&self.verification)
        )
    }
    pub fn text(&self) -> String {
        format!(
            "WinStateDiag {}\nRepair ID: {}\nПроверка: {}\nКоманда: {}\nПовторная проверка: {}\nИсходная находка: {}\nСтатус: {}\n{}\nПерезагрузка: {}\nRepair exit: {:?}\nVerification exit: {:?}\n\n{}\n\n{}",
            crate::APP_VERSION,
            self.id,
            self.plan.check.key(),
            self.plan.command(),
            self.plan.verification(),
            self.plan.before.detail,
            self.status,
            self.message,
            self.reboot,
            self.repair.as_ref().and_then(|o| o.code),
            self.verification.as_ref().and_then(|o| o.code),
            self.repair.as_ref().map(|o| o.text.as_str()).unwrap_or(""),
            self.verification
                .as_ref()
                .map(|o| o.text.as_str())
                .unwrap_or("")
        )
    }
}
static ACTIVE: AtomicBool = AtomicBool::new(false);
struct Lease;
impl Drop for Lease {
    fn drop(&mut self) {
        ACTIVE.store(false, Ordering::SeqCst);
    }
}
pub fn execute(
    auth: Authorized,
    id: String,
    runner: &mut impl Runner,
    cancel: &AtomicBool,
    progress: &SharedProgress,
) -> Report {
    let mut r = Report {
        id,
        plan: auth.plan,
        status: "ERROR".into(),
        message: String::new(),
        repair: None,
        verification: None,
        verified: None,
        reboot: false,
    };
    if ACTIVE
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        r.message = "Другая операция ремонта уже выполняется".into();
        return r;
    }
    let _lease = Lease;
    let fail = |r: &mut Report, f: Failure| match f {
        Failure::Cancelled => {
            r.status = "CANCELLED".into();
            r.message="Операция прервана; исправность не подтверждена. Проверь журналы и выполни диагностику повторно.".into();
        }
        Failure::Timeout => {
            r.status = "TIMEOUT".into();
            r.message = "Превышено время ожидания; исправность не подтверждена".into();
        }
        Failure::Error(s) => {
            r.status = "ERROR".into();
            r.message = s;
        }
    };
    if cancel.load(Ordering::SeqCst) {
        fail(&mut r, Failure::Cancelled);
        return r;
    }
    *progress.lock().unwrap_or_else(|e| e.into_inner()) = Progress {
        phase: "Исправление".into(),
        ..Default::default()
    };
    match runner.run(&r.plan, false, cancel, progress) {
        Ok(o) => r.repair = Some(o),
        Err(f) => {
            fail(&mut r, f);
            return r;
        }
    }
    let o = r.repair.as_ref().unwrap();
    if cancel.load(Ordering::SeqCst) {
        fail(&mut r, Failure::Cancelled);
        return r;
    }
    if !matches!(o.code, Some(0 | 3010)) {
        r.message = format!(
            "Команда завершилась с ошибкой: {:?}. Исправность не подтверждена.",
            o.code
        );
        return r;
    }
    r.reboot = o.scheduled || o.code == Some(3010) || reboot_text(&o.text);
    if o.scheduled {
        r.status = "REBOOT_REQUIRED".into();
        r.message="Проверка запланирована при следующей перезагрузке. Ремонт ещё не выполнен. После загрузки явно запусти CHKDSK в диагностике; автоматического запуска при открытии программы нет.".into();
        return r;
    }
    *progress.lock().unwrap_or_else(|e| e.into_inner()) = Progress {
        phase: "Повторная проверка (только чтение)".into(),
        ..Default::default()
    };
    match runner.run(&r.plan, true, cancel, progress) {
        Ok(o) => r.verification = Some(o),
        Err(f) => {
            fail(&mut r, f);
            return r;
        }
    }
    if cancel.load(Ordering::SeqCst) {
        fail(&mut r, Failure::Cancelled);
        return r;
    }
    let v = r.verification.as_ref().unwrap();
    let verified = deep_checks::classify_output(r.plan.check, &v.text, v.code);
    r.verified = Some(verified);
    if v.code != Some(0) {
        r.message = format!(
            "Ошибка повторной проверки: {:?}. Исходные доказательства сохранены.",
            v.code
        );
        return r;
    }
    if r.reboot {
        r.status = "REBOOT_REQUIRED".into();
        r.message =
            "Команда требует перезагрузки. После загрузки нужна повторная диагностика.".into();
    } else if verified == CheckResult::Ok {
        r.status = "SUCCESS".into();
        r.message = "Исправление завершено; повторная проверка не обнаружила нарушений.".into();
    } else {
        r.status = "NOT_VERIFIED".into();
        r.message="Команда завершена, но повторная проверка не подтвердила исправность. См. результат и журнал.".into();
    }
    r
}
fn reboot_text(text: &str) -> bool {
    let t = text.to_lowercase();
    [
        "restart required",
        "reboot required",
        "требуется перезагрузка",
        "необходимо перезагрузить",
    ]
    .iter()
    .any(|x| t.contains(x))
}
pub fn percent(text: &str) -> Option<f32> {
    text.rsplit('%').skip(1).find_map(|part| {
        let n: String = part
            .chars()
            .rev()
            .take_while(|c| c.is_ascii_digit() || *c == '.' || *c == ',')
            .collect::<String>()
            .chars()
            .rev()
            .collect();
        n.replace(',', ".")
            .parse::<f32>()
            .ok()
            .filter(|n| n.is_finite() && (0.0..=100.0).contains(n))
    })
}
/// Never answer a dismount/other prompt. Only a recognized boot scheduling question.
pub fn scheduling_answer(text: &str) -> Option<&'static [u8]> {
    let t = text.to_lowercase();
    if t.contains("dismount") || t.contains("размонт") || t.contains("принудительн")
    {
        return None;
    }
    let schedule = (t.contains("schedule") && (t.contains("restart") || t.contains("reboot")))
        || (t.contains("провер")
            && (t.contains("перезагруз") || t.contains("следующ") && t.contains("загруз")));
    if !schedule {
        return None;
    }
    if t.contains("(y/n)") || t.contains("[y/n]") || t.contains("y(да)/n(нет)") {
        Some(b"Y\r\n")
    } else if t.contains("(д/н)") || t.contains("[д/н]") {
        Some(&[0x84, b'\r', b'\n'])
    } else {
        None
    }
}
#[cfg(windows)]
#[link(name = "shell32")]
unsafe extern "system" {
    fn IsUserAnAdmin() -> i32;
}
pub fn elevated() -> bool {
    #[cfg(windows)]
    {
        unsafe { IsUserAnAdmin() != 0 }
    }
    #[cfg(not(windows))]
    {
        false
    }
}
#[cfg(windows)]
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetSystemDirectoryW(buffer: *mut u16, size: u32) -> u32;
    fn GetOEMCP() -> u32;
    fn MultiByteToWideChar(
        cp: u32,
        flags: u32,
        bytes: *const u8,
        len: i32,
        wide: *mut u16,
        size: i32,
    ) -> i32;
    fn GetVolumeInformationW(
        root: *const u16,
        name: *mut u16,
        size: u32,
        serial: *mut u32,
        max: *mut u32,
        flags: *mut u32,
        fs: *mut u16,
        fs_size: u32,
    ) -> i32;
}
pub fn decode(bytes: &[u8]) -> String {
    if bytes.len() > 3
        && (bytes.starts_with(&[255, 254])
            || bytes
                .iter()
                .skip(1)
                .step_by(2)
                .take(100)
                .filter(|b| **b == 0)
                .count()
                > 10)
    {
        let words: Vec<_> = bytes
            .chunks_exact(2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .collect();
        return String::from_utf16_lossy(&words)
            .trim_start_matches('\u{feff}')
            .to_string();
    }
    if let Ok(s) = std::str::from_utf8(bytes) {
        return s.to_string();
    }
    #[cfg(windows)]
    unsafe {
        let n = MultiByteToWideChar(
            GetOEMCP(),
            0,
            bytes.as_ptr(),
            bytes.len() as i32,
            std::ptr::null_mut(),
            0,
        );
        if n > 0 {
            let mut w = vec![0u16; n as usize];
            MultiByteToWideChar(
                GetOEMCP(),
                0,
                bytes.as_ptr(),
                bytes.len() as i32,
                w.as_mut_ptr(),
                n,
            );
            return String::from_utf16_lossy(&w);
        }
    }
    String::from_utf8_lossy(bytes).into_owned()
}
#[cfg(windows)]
#[repr(C)]
struct ProcessEntry {
    size: u32,
    usage: u32,
    pid: u32,
    heap: usize,
    module: u32,
    threads: u32,
    parent: u32,
    priority: i32,
    flags: u32,
    name: [u16; 260],
}
#[cfg(windows)]
#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateMutexW(
        attributes: *const std::ffi::c_void,
        owner: i32,
        name: *const u16,
    ) -> *mut std::ffi::c_void;
    fn WaitForSingleObject(handle: *mut std::ffi::c_void, timeout: u32) -> u32;
    fn ReleaseMutex(handle: *mut std::ffi::c_void) -> i32;
    fn CloseHandle(handle: *mut std::ffi::c_void) -> i32;
    fn CreateToolhelp32Snapshot(flags: u32, pid: u32) -> *mut std::ffi::c_void;
    fn Process32FirstW(handle: *mut std::ffi::c_void, entry: *mut ProcessEntry) -> i32;
    fn Process32NextW(handle: *mut std::ffi::c_void, entry: *mut ProcessEntry) -> i32;
}
struct NativeLease {
    #[cfg(windows)]
    handle: *mut std::ffi::c_void,
}
impl NativeLease {
    fn acquire() -> Result<Self, Failure> {
        #[cfg(windows)]
        unsafe {
            let name: Vec<_> = "Global\\EXPC.WinStateDiag.Servicing\0"
                .encode_utf16()
                .collect();
            let handle = CreateMutexW(std::ptr::null(), 0, name.as_ptr());
            if handle.is_null() {
                return Err(Failure::Error(
                    "Не удалось получить блокировку обслуживания Windows; операция не запущена"
                        .into(),
                ));
            }
            if !matches!(WaitForSingleObject(handle, 0), 0 | 0x80) {
                CloseHandle(handle);
                return Err(Failure::Error(
                    "В другом экземпляре уже выполняется Repair".into(),
                ));
            }
            Ok(Self { handle })
        }
        #[cfg(not(windows))]
        {
            Err(Failure::Error("Нужна Windows".into()))
        }
    }
}
impl Drop for NativeLease {
    fn drop(&mut self) {
        #[cfg(windows)]
        unsafe {
            ReleaseMutex(self.handle);
            CloseHandle(self.handle);
        }
    }
}
fn conflicting_name(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "sfc.exe" | "dism.exe" | "dismhost.exe" | "chkdsk.exe"
    )
}
fn ensure_no_conflicting_process() -> Result<(), Failure> {
    #[cfg(windows)]
    unsafe {
        let h = CreateToolhelp32Snapshot(2, 0);
        if h as isize == -1 {
            return Err(Failure::Error(
                "Не удалось проверить активные процессы обслуживания; ремонт не запущен".into(),
            ));
        }
        let mut entry: ProcessEntry = std::mem::zeroed();
        entry.size = std::mem::size_of::<ProcessEntry>() as u32;
        let mut ok = Process32FirstW(h, &mut entry);
        if ok == 0 {
            CloseHandle(h);
            return Err(Failure::Error("Список процессов недоступен".into()));
        }
        while ok != 0 {
            let name = String::from_utf16_lossy(&entry.name);
            if conflicting_name(name.trim_end_matches('\0')) {
                CloseHandle(h);
                return Err(Failure::Error("Уже выполняется SFC / DISM / CHKDSK. Дождись завершения; чужие процессы не останавливаются.".into()));
            }
            ok = Process32NextW(h, &mut entry);
        }
        CloseHandle(h);
    }
    Ok(())
}

pub struct NativeRunner {
    pub directory: PathBuf,
    _lease: Option<NativeLease>,
}
impl NativeRunner {
    pub fn new(directory: PathBuf) -> Self {
        Self {
            directory,
            _lease: None,
        }
    }
    #[cfg(windows)]
    fn system_dir() -> Result<PathBuf, Failure> {
        unsafe {
            let mut b = [0u16; 1024];
            let n = GetSystemDirectoryW(b.as_mut_ptr(), b.len() as u32) as usize;
            if n == 0 || n >= b.len() {
                return Err(Failure::Error(
                    "Не удалось определить системный каталог".into(),
                ));
            }
            Ok(PathBuf::from(String::from_utf16_lossy(&b[..n])))
        }
    }
    #[cfg(not(windows))]
    fn system_dir() -> Result<PathBuf, Failure> {
        Err(Failure::Error("Нужна Windows".into()))
    }
    fn check_volume(plan: &Plan) -> Result<(), Failure> {
        if plan.check != DeepCheck::Chkdsk {
            return Ok(());
        }
        #[cfg(windows)]
        unsafe {
            let sys = Self::system_dir()?.display().to_string();
            if !sys
                .to_ascii_uppercase()
                .starts_with(&format!("{}\\", plan.drive))
            {
                return Err(Failure::Error(
                    "Разрешён только диагностированный системный том".into(),
                ));
            }
            let root: Vec<_> = format!("{}\\\0", plan.drive).encode_utf16().collect();
            let mut fs = [0u16; 32];
            if GetVolumeInformationW(
                root.as_ptr(),
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                fs.as_mut_ptr(),
                32,
            ) == 0
                || String::from_utf16_lossy(&fs).trim_end_matches('\0') != "NTFS"
            {
                return Err(Failure::Error(
                    "Безопасный сценарий требует доступного системного NTFS-тома; изменений нет"
                        .into(),
                ));
            }
            Ok(())
        }
        #[cfg(not(windows))]
        {
            Err(Failure::Error("Нужна Windows".into()))
        }
    }
}
impl Runner for NativeRunner {
    fn run(
        &mut self,
        plan: &Plan,
        verify: bool,
        cancel: &AtomicBool,
        progress: &SharedProgress,
    ) -> Result<Output, Failure> {
        // Tests must use fake runners; no test can accidentally repair the host.
        if cfg!(test) {
            return Err(Failure::Error(
                "Native repair runner disabled in tests".into(),
            ));
        }
        if !elevated() {
            return Err(Failure::Error(
                "Права администратора отсутствуют; ремонт не запущен".into(),
            ));
        }
        if self._lease.is_none() {
            self._lease = Some(NativeLease::acquire()?);
        }
        ensure_no_conflicting_process()?;
        Self::check_volume(plan)?;
        native_process(
            &Self::system_dir()?,
            &self.directory,
            plan,
            verify,
            cancel,
            progress,
        )
    }
}
fn native_process(
    system: &Path,
    dir: &Path,
    plan: &Plan,
    verify: bool,
    cancel: &AtomicBool,
    progress: &SharedProgress,
) -> Result<Output, Failure> {
    use std::{
        io::{Read, Write},
        process::{Command, Stdio},
        sync::mpsc,
        time::{Duration, Instant},
    };
    let error = |e: std::io::Error| Failure::Error(format!("Ошибка выполнения: {e}"));
    std::fs::create_dir_all(dir).map_err(error)?;
    let phase = if verify { "verify" } else { "repair" };
    let (file, args) = match plan.check {
        DeepCheck::Sfc => (
            "sfc.exe",
            vec![if verify { "/verifyonly" } else { "/scannow" }.to_string()],
        ),
        DeepCheck::Dism => (
            "dism.exe",
            vec![
                "/Online".into(),
                "/Cleanup-Image".into(),
                if verify {
                    "/ScanHealth"
                } else {
                    "/RestoreHealth"
                }
                .into(),
            ],
        ),
        DeepCheck::Chkdsk => (
            "chkdsk.exe",
            if verify {
                vec![plan.drive.clone()]
            } else {
                vec![plan.drive.clone(), "/f".into()]
            },
        ),
    };
    let mut cmd = Command::new(system.join(file));
    cmd.args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut guard = crate::engine::ProcessGuard::spawn(cmd).map_err(error)?;
    let mut stdin = guard.child_mut().stdin.take();
    if plan.check != DeepCheck::Chkdsk || verify {
        stdin = None;
    }
    let (tx, rx) = mpsc::channel();
    let readers: Vec<Box<dyn Read + Send>> = vec![
        Box::new(guard.child_mut().stdout.take().unwrap()),
        Box::new(guard.child_mut().stderr.take().unwrap()),
    ];
    for (index, mut pipe) in readers.into_iter().enumerate() {
        let tx = tx.clone();
        std::thread::spawn(move || {
            let mut bytes = [0u8; 4096];
            loop {
                match pipe.read(&mut bytes) {
                    Ok(0) => break,
                    Ok(n) => {
                        if tx.send((index, Ok(bytes[..n].to_vec()))).is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        let _ = tx.send((index, Err(e.to_string())));
                        break;
                    }
                }
            }
        });
    }
    drop(tx);
    let mut buffers = [Vec::new(), Vec::new()];
    let mut files = [
        std::fs::File::create(dir.join(format!("{phase}-stdout.bin"))).map_err(error)?,
        std::fs::File::create(dir.join(format!("{phase}-stderr.bin"))).map_err(error)?,
    ];
    let started = Instant::now();
    let mut scheduled = false;
    let mut code = None;
    let mut exited = None;
    loop {
        if cancel.load(Ordering::SeqCst) || crate::engine::SHUTDOWN.load(Ordering::SeqCst) {
            guard.kill_tree();
            return Err(Failure::Cancelled);
        }
        if started.elapsed() > Duration::from_secs(3600) {
            guard.kill_tree();
            return Err(Failure::Timeout);
        }
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok((i, chunk)) => {
                let chunk = chunk.map_err(Failure::Error)?;
                files[i].write_all(&chunk).map_err(error)?;
                if buffers[i].len() + chunk.len() > 32 * 1024 * 1024 {
                    return Err(Failure::Error(
                        "Превышен предел вывода; сырые данные сохранены".into(),
                    ));
                }
                buffers[i].extend_from_slice(&chunk);
                let text = decode(&buffers[i]);
                let mut state = progress.lock().unwrap_or_else(|e| e.into_inner());
                state.percent = percent(&text);
                state.latest = text
                    .lines()
                    .rev()
                    .find(|l| !l.trim().is_empty())
                    .unwrap_or("")
                    .to_string();
                drop(state);
                if !verify && plan.check == DeepCheck::Chkdsk && !scheduled {
                    if let Some(answer) = scheduling_answer(&text) {
                        if let Some(mut input) = stdin.take() {
                            input.write_all(answer).map_err(error)?;
                            input.flush().map_err(error)?;
                            scheduled = true;
                        }
                    } else if text.to_lowercase().contains("(y/n)")
                        || text.to_lowercase().contains("[y/n]")
                        || text.to_lowercase().contains("y(да)/n(нет)")
                        || text.to_lowercase().contains("(д/н)")
                    {
                        guard.kill_tree();
                        return Err(Failure::Error("Неожиданный запрос CHKDSK; согласие не отправлено, операция остановлена".into()));
                    }
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                if exited.is_some() {
                    break;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
        if exited.is_none() {
            if let Some(status) = guard.child_mut().try_wait().map_err(error)? {
                code = status.code();
                exited = Some(Instant::now());
            }
        }
        if exited.is_some_and(|t| t.elapsed() > Duration::from_secs(10)) {
            return Err(Failure::Error(
                "Процесс завершён, но поток вывода не закрыт".into(),
            ));
        }
    }
    let text = format!("{}\n{}", decode(&buffers[0]), decode(&buffers[1]));
    std::fs::write(dir.join(format!("{phase}.txt")), &text).map_err(error)?;
    Ok(Output {
        code,
        text,
        scheduled: scheduled && code == Some(0),
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::deep_checks::ResultSource;
    fn outcome(check: DeepCheck, detail: &str) -> DeepCheckOutcome {
        DeepCheckOutcome {
            check,
            result: CheckResult::Attention,
            detail: detail.into(),
            source: ResultSource::ExpcJson,
        }
    }
    fn auth(check: DeepCheck) -> Authorized {
        let d = match check {
            DeepCheck::Sfc => "SFC /verifyonly обнаружил признаки нарушения целостности.",
            DeepCheck::Dism => "REPAIRABLE",
            DeepCheck::Chkdsk => "Windows found problems",
        };
        authorize(
            plan(&outcome(check, d), "C:").unwrap(),
            true,
            true,
            true,
            false,
        )
        .unwrap()
    }
    struct Fake {
        results: std::collections::VecDeque<Result<Output, Failure>>,
        calls: usize,
    }
    impl Runner for Fake {
        fn run(
            &mut self,
            _: &Plan,
            _: bool,
            _: &AtomicBool,
            _: &SharedProgress,
        ) -> Result<Output, Failure> {
            self.calls += 1;
            self.results.pop_front().unwrap()
        }
    }
    fn output(code: i32, text: &str) -> Result<Output, Failure> {
        Ok(Output {
            code: Some(code),
            text: text.into(),
            scheduled: false,
        })
    }
    #[test]
    fn native_is_disabled_in_tests_and_conflicting_tools_are_recognized() {
        assert!(conflicting_name("DISM.exe"));
        assert!(conflicting_name("DismHost.exe"));
        assert!(!conflicting_name("explorer.exe"));
        let mut native =
            NativeRunner::new(std::env::temp_dir().join("never-created-native-repair"));
        let p = auth(DeepCheck::Sfc).plan;
        assert!(matches!(
            native.run(
                &p,
                false,
                &AtomicBool::new(false),
                &Arc::new(Mutex::new(Progress::default()))
            ),
            Err(Failure::Error(_))
        ));
        assert!(!eligible(&outcome(
            DeepCheck::Sfc,
            "SFC /verifyonly: неизвестно, есть ли нарушения целостности"
        )));
    }
    #[test]
    fn real_server_findings_gate_repairs_without_historical_overwrite() {
        let value = deep_checks::json::parse(include_str!(
            "../scripts/fixtures/v1.2.11/server-checks.json"
        ))
        .unwrap();
        for (server, dism_allowed) in [("CASE-A", true), ("CASE-B", false)] {
            let checks = value
                .get(server)
                .unwrap()
                .get("Checks")
                .unwrap()
                .as_arr()
                .unwrap();
            for check in DeepCheck::ALL {
                let raw = checks
                    .iter()
                    .find(|c| c.get("Check").and_then(|v| v.as_str()) == Some(check.key()))
                    .unwrap();
                let outcome = DeepCheckOutcome {
                    check,
                    result: CheckResult::from_status(raw.get("Status").unwrap().as_str().unwrap()),
                    detail: raw.get("Detail").unwrap().as_str().unwrap().into(),
                    source: ResultSource::ExpcJson,
                };
                assert_eq!(
                    eligible(&outcome),
                    match check {
                        DeepCheck::Sfc => true,
                        DeepCheck::Dism => dism_allowed,
                        DeepCheck::Chkdsk => false,
                    },
                    "{server} {check:?}"
                );
            }
        }
        assert_eq!(
            deep_checks::classify_output(
                DeepCheck::Dism,
                "Повреждение хранилища компонентов не обнаружено.",
                Some(0)
            ),
            CheckResult::Ok
        );
    }
    #[test]
    fn eligibility_rejects_ambiguous_and_clean() {
        for check in DeepCheck::ALL {
            for result in [
                CheckResult::Ok,
                CheckResult::Unknown,
                CheckResult::Skipped,
                CheckResult::Error,
            ] {
                let mut o = outcome(check, "REPAIRABLE");
                o.result = result;
                assert!(!eligible(&o));
            }
            assert!(!eligible(&outcome(check, "uncertain")));
        }
        assert!(!eligible(&outcome(
            DeepCheck::Dism,
            "хранилище компонентов не подлежит восстановлению"
        )));
        assert!(eligible(&outcome(
            DeepCheck::Dism,
            "хранилище компонентов повреждено, но подлежит восстановлению"
        )));
        assert!(plan(&outcome(DeepCheck::Chkdsk, "found problems"), "C: & bad").is_none());
    }
    #[test]
    fn confirmation_admin_reboot_and_busy_fail_closed() {
        let p = auth(DeepCheck::Chkdsk).plan;
        for (confirm, reboot, admin, busy) in [
            (false, true, true, false),
            (true, false, true, false),
            (true, true, false, false),
            (true, true, true, true),
        ] {
            assert!(authorize(p.clone(), confirm, reboot, admin, busy).is_err());
        }
    }
    #[test]
    fn fake_success_failure_cancel_timeout_reboot_and_recheck() {
        let progress = Arc::new(Mutex::new(Progress::default()));
        let cancel = AtomicBool::new(false);
        for (results, status, calls) in [
            (
                vec![
                    output(0, "finished"),
                    output(
                        0,
                        "Windows Resource Protection did not find any integrity violations.",
                    ),
                ],
                "SUCCESS",
                2,
            ),
            (vec![output(5, "access denied")], "ERROR", 1),
            (vec![Err(Failure::Cancelled)], "CANCELLED", 1),
            (vec![Err(Failure::Timeout)], "TIMEOUT", 1),
            (
                vec![output(0, "finished"), output(0, "unrecognized")],
                "NOT_VERIFIED",
                2,
            ),
            (
                vec![output(3010, "restart required"), output(0, "unknown")],
                "REBOOT_REQUIRED",
                2,
            ),
            (
                vec![output(0, "finished"), Err(Failure::Cancelled)],
                "CANCELLED",
                2,
            ),
        ] {
            let mut runner = Fake {
                results: results.into(),
                calls: 0,
            };
            let r = execute(
                auth(DeepCheck::Sfc),
                "test".into(),
                &mut runner,
                &cancel,
                &progress,
            );
            assert_eq!(r.status, status);
            assert_eq!(runner.calls, calls);
            assert!(deep_checks::json::parse(&r.json()).is_some());
            assert!(r.json().contains("original_finding"));
        }
        let mut runner = Fake {
            results: vec![Ok(Output {
                code: Some(0),
                text: "scheduled".into(),
                scheduled: true,
            })]
            .into(),
            calls: 0,
        };
        let r = execute(
            auth(DeepCheck::Chkdsk),
            "boot".into(),
            &mut runner,
            &cancel,
            &progress,
        );
        assert_eq!(r.status, "REBOOT_REQUIRED");
        assert_eq!(runner.calls, 1);
        assert!(r.verification.is_none());
    }
    #[test]
    fn native_parser_never_answers_dismount_or_invents_progress() {
        assert_eq!(
            scheduling_answer("Would you like to force a dismount? (Y/N)"),
            None
        );
        assert_eq!(
            scheduling_answer(
                "Would you like to schedule this volume to be checked the next time the system restarts? (Y/N)"
            ),
            Some(&b"Y\r\n"[..])
        );
        assert_eq!(
            scheduling_answer(
                "Выполнить проверку этого тома при следующей перезагрузке системы? [Y(да)/N(нет)]"
            ),
            Some(&b"Y\r\n"[..])
        );
        assert_eq!(
            scheduling_answer("schedule after restart; force a dismount? (Y/N)"),
            None
        );
        assert_eq!(percent("step running"), None);
        assert_eq!(percent("phase 25.5%"), Some(25.5));
        assert_eq!(
            decode(
                &"hello world test"
                    .encode_utf16()
                    .flat_map(u16::to_le_bytes)
                    .collect::<Vec<_>>()
            ),
            "hello world test"
        );
    }
}
