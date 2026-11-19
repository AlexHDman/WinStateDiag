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
    pub source: Option<(String, u32)>,
    pub online_scan: bool,
}
impl Plan {
    pub fn command(&self) -> String {
        if self.check == DeepCheck::Chkdsk {
            format!(
                "chkdsk {} {}",
                self.drive,
                if self.online_scan {
                    "/scan"
                } else {
                    "/spotfix"
                }
            )
        } else if let Some((path, index)) = &self.source {
            format!(
                "DISM /Online /Cleanup-Image /RestoreHealth /Source:wim:\"{path}\":{index} /LimitAccess"
            )
        } else {
            self.check.manual_command(&self.drive)
        }
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
            DeepCheck::Chkdsk if self.online_scan => {
                "Онлайн-проверка /scan может исправлять NTFS. Это изменяющая операция только по подтверждению. Offline repair, отключение тома и планирование перезагрузки не выполняются."
            }
            DeepCheck::Chkdsk => {
                "Исправление файловой системы системного NTFS-тома. Принудительное отключение тома запрещено. Если том занят, Windows предложит проверку при следующей перезагрузке; запуск системы может занять длительное время. Перезагрузка не выполняется автоматически. Нужна резервная копия важных данных."
            }
        }
    }
}
pub fn valid_source(plan: &Plan) -> bool {
    plan.source.as_ref().is_none_or(|(path, index)| {
        plan.check == DeepCheck::Dism
            && *index > 0
            && Path::new(path).is_absolute()
            && path.to_ascii_lowercase().ends_with(".wim")
            && !path.chars().any(|c| c.is_control() || c == '"')
    })
}
pub fn error_advice(text: &str) -> &'static str {
    let s = text.to_ascii_lowercase();
    if ["0x800f081f", "0x800f0906", "0x800f0915"]
        .iter()
        .any(|x| s.contains(x))
    {
        "Источник восстановления недоступен или неполон. Выбери совместимый install.wim и индекс; автоматической подмены ISO нет."
    } else if ["0x80073712", "0x800736cc"].iter().any(|x| s.contains(x)) {
        "Windows сообщает о повреждении хранилища/несовпадении проверки целостности. Сохрани CBS/DISM и проверь совместимый источник; причина повреждения не установлена."
    } else {
        "Проверь исходный вывод и CBS/DISM; успех не подтверждён."
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
        source: None,
        online_scan: false,
    })
}
/// Constructed only after explicit command confirmation, including CHKDSK scheduling consent.
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
    if !confirmed || (plan.check == DeepCheck::Chkdsk && !plan.online_scan && !reboot_confirmed) {
        return Err("Операция не подтверждена".into());
    }
    if !elevated {
        return Err("Нужны права администратора. Перезапусти EXE и подтверди UAC; при отмене UAC ремонт не запускается.".into());
    }
    if busy {
        return Err("Дождись завершения текущей диагностики или ремонта".into());
    }
    let mut canonical = crate::repair::plan(&plan.before, &plan.drive);
    if let Some(p) = &mut canonical {
        p.source = plan.source.clone();
        p.online_scan = plan.online_scan;
    }
    if canonical.as_ref() != Some(&plan)
        || !valid_source(&plan)
        || (plan.online_scan && plan.check != DeepCheck::Chkdsk)
    {
        return Err("Недопустимая цель ремонта".into());
    }
    if !eligible(&plan.before) {
        return Err("Подтверждённая исправляемая проблема отсутствует".into());
    }
    Ok(Authorized { plan })
}
#[derive(Clone, Debug, Default)]
pub struct Progress {
    pub check: Option<DeepCheck>,
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
    Blocked(String),
}
pub trait Runner {
    #[cfg(test)]
    fn set_directory(&mut self, _directory: &Path) {}
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
    pub completed_at: String,
}
impl Report {
    pub fn repair_status(&self) -> &'static str {
        match self.status.as_str() {
            "SUCCESS_VERIFIED" => "REPAIR_SUCCESS",
            "REBOOT_REQUIRED" => "REBOOT_REQUIRED",
            "BLOCKED" => "REPAIR_BLOCKED",
            "VERIFICATION_FAILED" => "VERIFICATION_FAILED",
            "PARTIAL" => "REPAIR_FAILED",
            "FAILED" if self.repair.is_some() => "REPAIR_FAILED",
            "FAILED" => "REPAIR_BLOCKED",
            _ => "RESULT_UNKNOWN",
        }
    }
    pub fn label(&self) -> &'static str {
        match self.status.as_str() {
            "SUCCESS_VERIFIED" => "Исправление подтверждено",
            "VERIFICATION_FAILED" => "Команда завершена · проверка не выполнена",
            "REBOOT_REQUIRED" => "Требуется перезагрузка",
            "CANCELLED" => "Следующие шаги отменены",
            "BLOCKED" => "Запуск заблокирован",
            "PARTIAL" => "Нарушения сохраняются",
            "COMPLETED_UNVERIFIED" => "Исправность не подтверждена",
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
        let result = format!(
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
        );
        format!(
            "{},\"repair_status\":{},\"completed_at\":{}}}",
            &result[..result.len() - 1],
            q(self.repair_status()),
            q(&self.completed_at)
        )
    }
    pub fn text(&self) -> String {
        format!(
            "WinDiag {}\nRepair ID: {}\nПроверка: {}\nКоманда: {}\nПовторная проверка: {}\nИсходная находка: {}\nСтатус: {}\n{}\nПерезагрузка: {}\nRepair exit: {:?}\nVerification exit: {:?}\n\n{}\n\n{}",
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
    runner: &mut (impl Runner + ?Sized),
    cancel: &AtomicBool,
    progress: &SharedProgress,
) -> Report {
    let mut r = Report {
        id,
        plan: auth.plan,
        status: "FAILED".into(),
        message: String::new(),
        repair: None,
        verification: None,
        verified: None,
        reboot: false,
        completed_at: timestamp(),
    };
    if ACTIVE
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        r.status = "BLOCKED".into();
        r.message = "Другая операция ремонта уже выполняется".into();
        r.completed_at = timestamp();
        return r;
    }
    let _lease = Lease;
    let fail = |r: &mut Report, f: Failure| match f {
        Failure::Cancelled => {
            r.status = "CANCELLED".into();
            r.message="Операция прервана; исправность не подтверждена. Проверь журналы и выполни диагностику повторно.".into();
        }
        Failure::Timeout => {
            r.status = "COMPLETED_UNVERIFIED".into();
            r.message = "Превышено время ожидания; исправность не подтверждена".into();
        }
        Failure::Blocked(s) => {
            r.status = "BLOCKED".into();
            r.message = s;
        }
        Failure::Error(s) => {
            r.status = "FAILED".into();
            r.message = s;
        }
    };
    if cancel.load(Ordering::SeqCst) {
        fail(&mut r, Failure::Cancelled);
        r.completed_at = timestamp();
        return r;
    }
    *progress.lock().unwrap_or_else(|e| e.into_inner()) = Progress {
        check: Some(r.plan.check),
        phase: "RUNNING · Проверка условий и запуск".into(),
        ..Default::default()
    };
    match runner.run(&r.plan, false, cancel, progress) {
        Ok(o) => r.repair = Some(o),
        Err(f) => {
            fail(&mut r, f);
            r.completed_at = timestamp();
            return r;
        }
    }
    let o = r.repair.as_ref().unwrap();
    if cancel.load(Ordering::SeqCst) {
        fail(&mut r, Failure::Cancelled);
        r.completed_at = timestamp();
        return r;
    }
    if !matches!(o.code, Some(0 | 3010))
        && !(r.plan.check == DeepCheck::Chkdsk && o.code == Some(1))
    {
        r.message = format!(
            "Команда завершилась с ошибкой: {:?}. Исправность не подтверждена.",
            o.code
        );
        r.message.push(' ');
        r.message.push_str(error_advice(&format!(
            "{} 0x{:08x}",
            o.text,
            o.code.unwrap_or(0) as u32
        )));
        r.completed_at = timestamp();
        return r;
    }
    r.reboot = o.scheduled || o.code == Some(3010) || reboot_text(&o.text);
    if r.reboot {
        r.status = "REBOOT_REQUIRED".into();
        r.message=if o.scheduled {"Проверка запланирована при следующей перезагрузке. Ремонт ещё не выполнен. После загрузки явно запусти CHKDSK в диагностике; автоматического запуска при открытии программы нет."}else{"Windows требует перезагрузку для завершения обслуживания. Следующие команды не запускаются. После ручной перезагрузки в согласованное окно повтори диагностику."}.into();
        r.completed_at = timestamp();
        return r;
    }
    *progress.lock().unwrap_or_else(|e| e.into_inner()) = Progress {
        check: Some(r.plan.check),
        phase: "RUNNING · Повторная проверка (только чтение)".into(),
        ..Default::default()
    };
    match runner.run(&r.plan, true, cancel, progress) {
        Ok(o) => r.verification = Some(o),
        Err(f) => {
            fail(&mut r, f);
            if r.status != "CANCELLED" {
                r.status = "VERIFICATION_FAILED".into();
            }
            r.message = format!(
                "Команда восстановления завершилась; контрольная проверка не выполнена: {}",
                r.message
            );
            r.completed_at = timestamp();
            return r;
        }
    }
    if cancel.load(Ordering::SeqCst) {
        fail(&mut r, Failure::Cancelled);
        r.completed_at = timestamp();
        return r;
    }
    let v = r.verification.as_ref().unwrap();
    let verified = deep_checks::classify_output(r.plan.check, &v.text, v.code);
    r.verified = Some(verified);
    if v.code != Some(0) {
        r.status = "VERIFICATION_FAILED".into();
        r.message = format!(
            "Ошибка повторной проверки: {:?}. Исходные доказательства сохранены.",
            v.code
        );
        r.completed_at = timestamp();
        return r;
    }
    if r.reboot {
        r.status = "REBOOT_REQUIRED".into();
        r.message =
            "Команда требует перезагрузки. После загрузки нужна повторная диагностика.".into();
    } else if r
        .repair
        .as_ref()
        .is_some_and(|o| o.text.contains("WSD_LOG_COVERAGE_INCOMPLETE"))
        || v.text.contains("WSD_LOG_COVERAGE_INCOMPLETE")
    {
        r.status = "PARTIAL".into();
        r.message = "Повторная проверка выполнена, но часть журналов обслуживания недоступна; см. log-ranges.json. Полнота доказательств не подтверждена.".into();
    } else if verified == CheckResult::Ok {
        r.status = "SUCCESS_VERIFIED".into();
        r.message = "Исправление завершено; повторная проверка не обнаружила нарушений.".into();
    } else {
        r.status = if verified == CheckResult::Attention {
            "PARTIAL"
        } else {
            "COMPLETED_UNVERIFIED"
        }
        .into();
        r.message="Команда завершена, но повторная проверка не подтвердила исправность. См. результат и журнал.".into();
    }
    r.completed_at = timestamp();
    r
}
fn reboot_text(text: &str) -> bool {
    let t = text
        .to_lowercase()
        .replace("no reboot required", "")
        .replace("no restart required", "")
        .replace("перезагрузка не требуется", "");
    [
        "restart required",
        "reboot required",
        "требуется перезагрузка",
        "необходимо перезагрузить",
    ]
    .iter()
    .any(|x| t.contains(x))
}
pub fn operation_id() -> String {
    static SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!(
        "WSD-repair-{}-{nanos:x}-{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    )
}
#[cfg(test)]
pub(crate) static TEST_REPAIR_LOCK: Mutex<()> = Mutex::new(());
pub fn timestamp() -> String {
    let t = crate::ui::sysinfo::local_time();
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        t.year, t.month, t.day, t.hour, t.minute, t.second
    )
}
pub fn execute_sequence(
    first: Authorized,
    next: Option<Authorized>,
    id: String,
    runner: &mut (impl Runner + ?Sized),
    cancel: &AtomicBool,
    progress: &SharedProgress,
) -> Vec<Report> {
    let r = execute(first, format!("{id}-1"), runner, cancel, progress);
    let proceed = r.status == "SUCCESS_VERIFIED" && !r.reboot && !cancel.load(Ordering::SeqCst);
    let mut reports = vec![r];
    if let Some(next) = next {
        if proceed {
            reports.push(execute(next, format!("{id}-2"), runner, cancel, progress));
        } else {
            reports.push(Report {
                id: format!("{id}-2"),
                plan: next.plan,
                status: "BLOCKED".into(),
                message:
                    "Зависимый SFC не запускался: DISM не подтверждён или отменены следующие шаги"
                        .into(),
                repair: None,
                verification: None,
                verified: None,
                reboot: false,
                completed_at: timestamp(),
            });
        }
    }
    reports
}
pub fn percent(text: &str) -> Option<f32> {
    text.rsplit('%').skip(1).find_map(|part| {
        let n: String = part
            .trim_end()
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
pub(crate) struct NativeLease {
    #[cfg(windows)]
    handle: *mut std::ffi::c_void,
}
impl NativeLease {
    pub(crate) fn acquire() -> Result<Self, Failure> {
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
        "sfc.exe" | "dism.exe" | "dismhost.exe" | "chkdsk.exe" | "tiworker.exe"
    )
}
fn repair_conflict(name: &str, include_hosts: bool) -> bool {
    conflicting_name(name)
        && (include_hosts
            || !matches!(
                name.to_ascii_lowercase().as_str(),
                "tiworker.exe" | "dismhost.exe"
            ))
}
pub(crate) fn ensure_no_conflicting_process() -> Result<(), Failure> {
    scan_conflicting_process(true)
}
fn scan_conflicting_process(include_hosts: bool) -> Result<(), Failure> {
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
            if repair_conflict(name.trim_end_matches('\0'), include_hosts) {
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
        scan_conflicting_process(plan.check == DeepCheck::Chkdsk)?;
        Self::check_volume(plan)?;
        let phase_dir = self.directory.join(plan.check.key());
        std::fs::create_dir_all(&phase_dir).map_err(|e| Failure::Error(e.to_string()))?;
        if !verify {
            let (source, index) = plan.source.clone().unwrap_or_default();
            let script = format!(
                "{}\nGet-RepairPreflight -SourcePath '{}' -SourceIndex {} -Check '{}' | ConvertTo-Json -Depth 6 -Compress",
                include_str!("../embedded/WinStateDiag/RepairPreflight.ps1"),
                source.replace('\'', "''"),
                index.max(1),
                plan.check.key()
            );
            let pre = crate::ps_exec::run_powershell(
                "powershell.exe",
                &script,
                std::time::Duration::from_secs(120),
            )
            .map_err(|e| Failure::Error(format!("Preflight недоступен: {e}; изменений нет")))?;
            std::fs::write(phase_dir.join("preflight.json"), &pre)
                .map_err(|e| Failure::Error(e.to_string()))?;
            let v = deep_checks::json::parse(pre.trim().trim_start_matches('\u{feff}'))
                .ok_or_else(|| {
                    Failure::Error("Не удалось разобрать preflight; ремонт заблокирован".into())
                })?;
            if v.get("Allowed") != Some(&deep_checks::json::Value::Bool(true)) {
                return Err(Failure::Blocked(
                    v.get("Reason")
                        .and_then(|x| x.as_str())
                        .unwrap_or("Preflight UNKNOWN")
                        .into(),
                ));
            }
        }
        if cancel.load(Ordering::SeqCst) {
            return Err(Failure::Cancelled);
        }
        let system = Self::system_dir()?;
        let windows = system
            .parent()
            .ok_or_else(|| Failure::Error("Windows root UNKNOWN".into()))?;
        let sources = [
            windows.join("Logs/CBS/CBS.log"),
            windows.join("Logs/DISM/dism.log"),
        ];
        let offsets = sources
            .iter()
            .map(|p| std::fs::metadata(p).map(|m| m.len()).ok())
            .collect::<Vec<_>>();
        let mut result = native_process(&system, &phase_dir, plan, verify, cancel, progress);
        if plan.check != DeepCheck::Chkdsk {
            let mut records = Vec::new();
            let mut incomplete = false;
            for (source, offset) in sources.iter().zip(offsets) {
                use std::io::{Seek, SeekFrom};
                let name = source.file_name().unwrap().to_string_lossy();
                let capture = (|| -> Result<u64, String> {
                    let start = offset.ok_or("Initial log offset unavailable")?;
                    let mut input = std::fs::File::open(source).map_err(|e| e.to_string())?;
                    let end = input.metadata().map_err(|e| e.to_string())?.len();
                    if end < start {
                        return Err("Log rotated; appended range unavailable, no whole-history substitution".into());
                    }
                    input
                        .seek(SeekFrom::Start(start))
                        .map_err(|e| e.to_string())?;
                    let mut output = std::fs::File::create(phase_dir.join(format!(
                        "{}-{name}",
                        if verify { "verify" } else { "repair" }
                    )))
                    .map_err(|e| e.to_string())?;
                    std::io::copy(&mut std::io::Read::take(input, end - start), &mut output)
                        .map_err(|e| e.to_string())
                })();
                incomplete |= capture.is_err();
                records.push(format!(
                    "{{\"source\":{},\"start_byte\":{},\"result\":{}}}",
                    deep_checks::json::string(&source.display().to_string()),
                    offset.map(|x| x.to_string()).unwrap_or("null".into()),
                    deep_checks::json::string(&format!("{capture:?}"))
                ));
            }
            std::fs::write(
                phase_dir.join(format!(
                    "{}-log-ranges.json",
                    if verify { "verify" } else { "repair" }
                )),
                format!("[{}]", records.join(",")),
            )
            .map_err(|e| {
                Failure::Error(format!(
                    "Результат servicing получен, но доказательства недоступны: {e}"
                ))
            })?;
            if incomplete && let Ok(output) = &mut result {
                output.text.push_str(
                    "\nWSD_LOG_COVERAGE_INCOMPLETE: часть журналов недоступна; см. log-ranges.json",
                );
            }
        }
        result
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
    native_process_with(
        system,
        dir,
        plan,
        verify,
        cancel,
        progress,
        |target, args| {
            let mut cmd = std::process::Command::new(target);
            cmd.args(args);
            cmd
        },
    )
}
pub(crate) fn native_process_with(
    system: &Path,
    dir: &Path,
    plan: &Plan,
    verify: bool,
    cancel: &AtomicBool,
    progress: &SharedProgress,
    command: impl FnOnce(&Path, &[String]) -> std::process::Command,
) -> Result<Output, Failure> {
    use std::{
        io::{Read, Write},
        process::Stdio,
        sync::mpsc,
        time::{Duration, Instant},
    };
    let error = |e: std::io::Error| Failure::Error(format!("Ошибка выполнения: {e}"));
    std::fs::create_dir_all(dir).map_err(error)?;
    let phase = if verify { "verify" } else { "repair" };
    let (file, mut args) = match plan.check {
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
                vec![
                    plan.drive.clone(),
                    if plan.online_scan {
                        "/scan"
                    } else {
                        "/spotfix"
                    }
                    .into(),
                ]
            },
        ),
    };
    if !verify && let Some((path, index)) = &plan.source {
        args.push(format!("/Source:wim:{path}:{index}"));
        args.push("/LimitAccess".into());
    }
    let started_at = timestamp();
    std::fs::write(
        dir.join(format!("{phase}-command.json")),
        format!(
            "{{\"command\":{},\"started_at\":{},\"mode\":{},\"effective_admin\":{}}}",
            deep_checks::json::string(&format!("{file} {}", args.join(" "))),
            deep_checks::json::string(&started_at),
            deep_checks::json::string(phase),
            elevated()
        ),
    )
    .map_err(error)?;
    let mut files = [
        std::fs::File::create(dir.join(format!("{phase}-stdout.bin"))).map_err(error)?,
        std::fs::File::create(dir.join(format!("{phase}-stderr.bin"))).map_err(error)?,
    ];
    let mut capture_error: Option<String> = None;
    let mut cmd = command(&system.join(file), &args);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut guard = if verify {
        crate::engine::ProcessGuard::spawn(cmd)
    } else {
        crate::engine::ProcessGuard::spawn_servicing(cmd)
    }
    .map_err(error)?;
    let mut stdin = guard.child_mut().stdin.take();
    if plan.check != DeepCheck::Chkdsk || verify || plan.online_scan {
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

    let started = Instant::now();
    let mut scheduled = false;
    let mut code = None;
    let mut exited = None;
    loop {
        if cancel.load(Ordering::SeqCst) || crate::engine::SHUTDOWN.load(Ordering::SeqCst) {
            if verify {
                guard.kill_tree();
                return Err(Failure::Cancelled);
            }
            progress.lock().unwrap_or_else(|e| e.into_inner()).phase =
                "Отмена следующих шагов: ожидается безопасное завершение текущего обслуживания"
                    .into();
        }
        if started.elapsed() > Duration::from_secs(3600) {
            if verify {
                guard.kill_tree();
                return Err(Failure::Timeout);
            }
            progress.lock().unwrap_or_else(|e| e.into_inner()).phase =
                "Превышено ожидаемое время; Windows продолжает обслуживание, принудительная остановка запрещена".into();
        }
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok((i, chunk)) => {
                let chunk = match chunk {
                    Ok(c) => c,
                    Err(e) => {
                        capture_error = Some(e);
                        continue;
                    }
                };
                if let Err(e) = files[i].write_all(&chunk) {
                    capture_error = Some(format!("Запись raw output: {e}"));
                }
                if buffers[i].len() + chunk.len() > 32 * 1024 * 1024 {
                    capture_error=Some("Превышен предел вывода в памяти; сырые файлы сохранены, автоматическая верификация запрещена".into());
                    let excess = (buffers[i].len() + chunk.len())
                        .saturating_sub(32 * 1024 * 1024)
                        .min(buffers[i].len());
                    buffers[i].drain(..excess);
                }
                buffers[i].extend_from_slice(&chunk);
                let text = decode(&buffers[i]);
                let mut state = progress.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(p) = percent(&text) {
                    state.percent = Some(p);
                }
                state.latest = text
                    .lines()
                    .rev()
                    .find(|l| !l.trim().is_empty())
                    .unwrap_or("")
                    .to_string();
                drop(state);
                if !verify && plan.check == DeepCheck::Chkdsk && !plan.online_scan && !scheduled {
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
                        // Refuse a dismount request through stdin, never kill a servicing process.
                        if let Some(mut input) = stdin.take() {
                            let _ = input.write_all(b"N\r\n");
                        }
                        progress.lock().unwrap_or_else(|e| e.into_inner()).latest =
                            "Неподтверждённый запрос отключения тома отклонён".into();
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
    std::fs::write(
        dir.join(format!("{phase}-completion.json")),
        format!(
            "{{\"ended_at\":{},\"elapsed_ms\":{},\"exit_code\":{}}}",
            deep_checks::json::string(&timestamp()),
            started.elapsed().as_millis(),
            code.map(|x| x.to_string()).unwrap_or("null".into())
        ),
    )
    .map_err(error)?;
    let text = format!("{}\n{}", decode(&buffers[0]), decode(&buffers[1]));
    std::fs::write(dir.join(format!("{phase}.txt")), &text).map_err(error)?;
    if let Some(e) = capture_error {
        return Err(Failure::Error(e));
    }
    if scheduled && code == Some(0) {
        let t = text.to_lowercase();
        if ![
            "will be checked the next time",
            "has been scheduled",
            "будет проверен при следующ",
            "проверка запланирована",
        ]
        .iter()
        .any(|x| t.contains(x))
        {
            return Err(Failure::Error("Согласие на планирование передано, но подтверждение Windows не распознано. Результат UNKNOWN; проверь журнал вручную.".into()));
        }
    }
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
        assert!(!repair_conflict("TiWorker.exe", false));
        assert!(!repair_conflict("DismHost.exe", false));
        assert!(repair_conflict("TiWorker.exe", true));
        assert!(repair_conflict("sfc.exe", false));
        assert!(repair_conflict("dism.exe", false));
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
    fn synthetic_server_findings_gate_repairs_without_historical_overwrite() {
        let value = deep_checks::json::parse(include_str!(
            "../scripts/fixtures/repair-synthetic/server-checks.json"
        ))
        .unwrap();
        for (server, dism_allowed) in [("SYNTHETIC-A", true), ("SYNTHETIC-B", false)] {
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
        let _serial = TEST_REPAIR_LOCK.lock().unwrap_or_else(|e| e.into_inner());
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
                "SUCCESS_VERIFIED",
                2,
            ),
            (vec![output(5, "access denied")], "FAILED", 1),
            (vec![Err(Failure::Cancelled)], "CANCELLED", 1),
            (
                vec![Err(Failure::Blocked("pending servicing".into()))],
                "BLOCKED",
                1,
            ),
            (vec![Err(Failure::Timeout)], "COMPLETED_UNVERIFIED", 1),
            (
                vec![output(0, "finished"), output(0, "unrecognized")],
                "COMPLETED_UNVERIFIED",
                2,
            ),
            (vec![output(3010, "restart required")], "REBOOT_REQUIRED", 1),
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
        // Full dependency chain is exercised only through the fake runner.
        for (clean, expected, calls) in [(true, "SUCCESS_VERIFIED", 4), (false, "BLOCKED", 2)] {
            let mut runner = Fake {
                results: vec![
                    output(0, "done"),
                    output(
                        0,
                        if clean {
                            "No component store corruption detected."
                        } else {
                            "The component store is repairable."
                        },
                    ),
                    output(0, "done"),
                    output(
                        0,
                        "Windows Resource Protection did not find any integrity violations.",
                    ),
                ]
                .into(),
                calls: 0,
            };
            let reports = execute_sequence(
                auth(DeepCheck::Dism),
                Some(auth(DeepCheck::Sfc)),
                "chain".into(),
                &mut runner,
                &cancel,
                &progress,
            );
            assert_eq!(reports.len(), 2);
            assert_eq!(reports[1].status, expected);
            assert_eq!(runner.calls, calls);
        }
        let mut runner = Fake {
            results: vec![output(0x800f081fu32 as i32, "")].into(),
            calls: 0,
        };
        let r = execute(
            auth(DeepCheck::Dism),
            "source".into(),
            &mut runner,
            &cancel,
            &progress,
        );
        assert_eq!(r.status, "FAILED");
        assert!(r.message.contains("install.wim"));
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

#[cfg(test)]
mod v1212_progress_tests {
    #[test]
    fn v1212_progress_spaces_and_latest_value() {
        assert_eq!(
            super::percent("Verification 10 % complete.\rVerification 25,5 % complete."),
            Some(25.5)
        );
        assert_eq!(super::percent("No progress supplied"), None);
        assert_eq!(super::percent("wrong 101%"), None);
    }
}

#[cfg(test)]
mod v13_contracts {
    use super::*;
    #[test]
    fn explicit_online_scan_and_offline_consent_are_distinct() {
        let o = DeepCheckOutcome {
            check: DeepCheck::Chkdsk,
            result: CheckResult::Attention,
            detail: "Windows found problems".into(),
            source: deep_checks::ResultSource::ExpcJson,
        };
        let mut p = plan(&o, "C:").unwrap();
        assert!(authorize(p.clone(), true, false, true, false).is_err());
        p.online_scan = true;
        assert_eq!(p.command(), "chkdsk C: /scan");
        assert_eq!(p.verification(), "chkdsk C:");
        assert!(authorize(p.clone(), false, false, true, false).is_err());
        assert!(authorize(p, true, false, true, false).is_ok());
    }
    #[test]
    fn reboot_negation_and_source_validation() {
        assert!(!reboot_text(
            "No reboot required. Перезагрузка не требуется."
        ));
        assert!(reboot_text("restart required"));
        let o = DeepCheckOutcome {
            check: DeepCheck::Dism,
            result: CheckResult::Attention,
            detail: "REPAIRABLE".into(),
            source: deep_checks::ResultSource::ExpcJson,
        };
        let mut p = plan(&o, "C:").unwrap();
        for path in ["relative.wim", r"C:\invalid.iso", "C:/bad\n.wim"] {
            p.source = Some((path.into(), 1));
            assert!(!valid_source(&p));
        }
    }
}

#[path = "repair_elevation.rs"]
mod elevation;
#[cfg(not(test))]
pub use elevation::elevate_sequence;
pub use elevation::elevated_worker;
#[cfg(test)]
pub use elevation::not_started_report;
