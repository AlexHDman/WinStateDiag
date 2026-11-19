//! UAC bridge for a non-elevated GUI. Only the same signed/unsigned EXE is launched;
//! the helper accepts eligible SFC/DISM plans, never arbitrary commands.
use super::*;
use crate::deep_checks::json::{self, Value};
use std::{fs, time::Duration};
fn text<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or("")
}
fn rows(v: &Value) -> Result<&[Value], String> {
    match v {
        Value::Arr(a) => Ok(a),
        _ => Err("Некорректный ответ elevated worker".into()),
    }
}
pub fn not_started_report(auth: Authorized, id: String, error: String) -> Report {
    Report {
        id,
        plan: auth.plan,
        status: if error.contains("1223") {
            "CANCELLED"
        } else {
            "FAILED"
        }
        .into(),
        message: error,
        repair: None,
        verification: None,
        verified: None,
        reboot: false,
        completed_at: timestamp(),
    }
}
fn output(v: Option<&Value>) -> Option<Output> {
    let v = v?;
    let code = match v.get("exit_code") {
        Some(Value::Num(n)) => Some(*n as i32),
        _ => None,
    };
    v.get("output")?;
    Some(Output {
        code,
        text: text(v, "output").into(),
        scheduled: v.get("scheduled") == Some(&Value::Bool(true)),
    })
}
fn decode_report(v: &Value, p: Plan, id: &str) -> Result<Report, String> {
    if text(v, "repair_id") != id || text(v, "check") != p.check.key() {
        return Err("Ответ elevated worker не соответствует запросу".into());
    }
    let verification = output(v.get("verification"));
    let verified = v
        .get("verified_result")
        .and_then(Value::as_str)
        .map(CheckResult::from_status);
    if text(v, "status") == "SUCCESS_VERIFIED"
        && !verification.as_ref().is_some_and(|o| {
            o.code == Some(0)
                && deep_checks::classify_output(p.check, &o.text, o.code) == CheckResult::Ok
        })
    {
        return Err("Неподтверждённый SUCCESS elevated worker отклонён".into());
    }
    Ok(Report {
        id: id.into(),
        plan: p,
        status: text(v, "status").into(),
        message: text(v, "message").into(),
        repair: output(v.get("repair")),
        verification,
        verified,
        reboot: v.get("reboot_required") == Some(&Value::Bool(true)),
        completed_at: text(v, "completed_at").into(),
    })
}
pub fn elevate_sequence(
    auth: Authorized,
    next: Option<Authorized>,
    id: String,
    dir: PathBuf,
    cancel: &AtomicBool,
    progress: &SharedProgress,
) -> Vec<Report> {
    let plans: Vec<_> = std::iter::once(auth.plan.clone())
        .chain(next.as_ref().map(|n| n.plan.clone()))
        .collect();
    let result = (|| -> Result<Vec<Report>, String> {
        if cfg!(test) {
            return Err("Native UAC disabled in tests".into());
        }
        let request = plans
            .iter()
            .map(|p| {
                format!(
                    "{{\"check\":{},\"drive\":{},\"finding\":{}}}",
                    json::string(p.check.key()),
                    json::string(&p.drive),
                    json::string(&p.before.detail)
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        fs::write(dir.join("elevation-request.json"), format!("[{request}]"))
            .map_err(|e| e.to_string())?;
        progress.lock().unwrap_or_else(|e| e.into_inner()).phase =
            "RUNNING · Ожидание штатного UAC Windows".into();
        launch(&dir, &id, cancel, progress)?;
        let v = json::parse(
            &fs::read_to_string(dir.join("elevation-result.json"))
                .map_err(|e| format!("Повышенный процесс не передал результат: {e}"))?,
        )
        .ok_or("Некорректный результат UAC worker")?;
        let result = rows(&v)?;
        if result.len() != plans.len() {
            return Err("Неполный результат elevated worker".into());
        }
        result
            .iter()
            .zip(plans)
            .enumerate()
            .map(|(i, (v, p))| decode_report(v, p, &format!("{id}-{}", i + 1)))
            .collect()
    })();
    result.unwrap_or_else(|e| vec![not_started_report(auth, id, e)])
}
fn helper_directory(path: &Path, id: &str) -> bool {
    if id.is_empty()
        || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        || path.file_name().and_then(|s| s.to_str()) != Some(id)
    {
        return false;
    }
    crate::repair_history::roots().iter().any(|root| {
        match (path.canonicalize(), root.canonicalize()) {
            (Ok(p), Ok(r)) => p.parent() == Some(r.as_path()),
            _ => false,
        }
    })
}
pub fn elevated_worker(args: &[String]) -> i32 {
    if cfg!(test) || !elevated() || args.len() != 3 {
        return 5;
    }
    let dir = PathBuf::from(&args[1]);
    let id = &args[2];
    if !helper_directory(&dir, id) {
        return 5;
    }
    let result = (|| -> Result<(), String> {
        let v = json::parse(
            &fs::read_to_string(dir.join("elevation-request.json")).map_err(|e| e.to_string())?,
        )
        .ok_or("Invalid request")?;
        let items = rows(&v)?;
        if items.is_empty() || items.len() > 2 {
            return Err("Invalid plan count".into());
        }
        let mut auth = Vec::new();
        for (i, v) in items.iter().enumerate() {
            let check = match text(v, "check") {
                "SFC" => DeepCheck::Sfc,
                "DISM" => DeepCheck::Dism,
                _ => return Err("Only SFC/DISM allowed".into()),
            };
            if items.len() == 2
                && check
                    != if i == 0 {
                        DeepCheck::Dism
                    } else {
                        DeepCheck::Sfc
                    }
            {
                return Err("Invalid dependency order".into());
            }
            let before = DeepCheckOutcome {
                check,
                result: CheckResult::Attention,
                detail: text(v, "finding").into(),
                source: deep_checks::ResultSource::ExpcJson,
            };
            auth.push(authorize(
                plan(&before, text(v, "drive")).ok_or("Finding not eligible")?,
                true,
                false,
                true,
                false,
            )?);
        }
        let first = auth.remove(0);
        let next = auth.pop();
        let progress = Arc::new(Mutex::new(Progress::default()));
        let cancel = Arc::new(AtomicBool::new(false));
        let done = Arc::new(AtomicBool::new(false));
        let writer = {
            let progress = Arc::clone(&progress);
            let cancel = Arc::clone(&cancel);
            let done = Arc::clone(&done);
            let dir = dir.clone();
            std::thread::spawn(move || {
                while !done.load(Ordering::SeqCst) {
                    if dir.join("elevation-cancel.request").exists() {
                        cancel.store(true, Ordering::SeqCst);
                    }
                    let p = progress.lock().unwrap_or_else(|e| e.into_inner()).clone();
                    let wire = format!(
                        "{{\"check\":{},\"phase\":{},\"percent\":{},\"latest\":{}}}",
                        json::string(p.check.map(|c| c.key()).unwrap_or("")),
                        json::string(&p.phase),
                        p.percent.map(|p| p.to_string()).unwrap_or("null".into()),
                        json::string(&p.latest)
                    );
                    let _ = fs::write(dir.join("elevation-progress.json"), wire);
                    std::thread::sleep(Duration::from_millis(200));
                }
            })
        };
        let mut runner = NativeRunner::new(dir.clone());
        let mut reports =
            execute_sequence(first, next, id.clone(), &mut runner, &cancel, &progress);
        crate::repair_history::finish(&dir, &mut reports);
        done.store(true, Ordering::SeqCst);
        let _ = writer.join();
        fs::write(
            dir.join("elevation-result.json"),
            format!(
                "[{}]",
                reports
                    .iter()
                    .map(Report::json)
                    .collect::<Vec<_>>()
                    .join(",")
            ),
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    })();
    match result {
        Ok(()) => 0,
        Err(e) => {
            let _ = fs::write(dir.join("elevation-error.txt"), e);
            1
        }
    }
}
#[cfg(windows)]
fn launch(
    dir: &Path,
    id: &str,
    cancel: &AtomicBool,
    progress: &SharedProgress,
) -> Result<(), String> {
    use std::ffi::c_void;
    #[repr(C)]
    struct ShellInfo {
        size: u32,
        mask: u32,
        hwnd: *mut c_void,
        verb: *const u16,
        file: *const u16,
        parameters: *const u16,
        directory: *const u16,
        show: i32,
        instance: *mut c_void,
        id_list: *mut c_void,
        class: *const u16,
        class_key: *mut c_void,
        hot_key: u32,
        icon: *mut c_void,
        process: *mut c_void,
    }
    #[link(name = "shell32")]
    unsafe extern "system" {
        fn ShellExecuteExW(info: *mut ShellInfo) -> i32;
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn WaitForSingleObject(h: *mut c_void, ms: u32) -> u32;
        fn GetExitCodeProcess(h: *mut c_void, code: *mut u32) -> i32;
        fn CloseHandle(h: *mut c_void) -> i32;
    }
    let wide = |s: &str| s.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let path = dir.to_str().ok_or("Некорректный каталог журнала")?;
    if path.contains('"') {
        return Err("Некорректный каталог журнала".into());
    }
    let verb = wide("runas");
    let file = wide(&exe.to_string_lossy());
    let params = wide(&format!("--repair-elevated \"{path}\" {id}"));
    let mut info: ShellInfo = unsafe { std::mem::zeroed() };
    info.size = std::mem::size_of::<ShellInfo>() as u32;
    info.mask = 0x40 | 0x100 | 0x400;
    info.verb = verb.as_ptr();
    info.file = file.as_ptr();
    info.parameters = params.as_ptr();
    info.show = 0;
    if unsafe { ShellExecuteExW(&mut info) } == 0 {
        return Err(format!(
            "UAC: {}. Исправление не запущено",
            std::io::Error::last_os_error()
        ));
    }
    if info.process.is_null() {
        return Err("UAC: Windows не предоставила handle процесса".into());
    }
    struct Handle(*mut c_void);
    impl Drop for Handle {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
    let handle = Handle(info.process);
    loop {
        if cancel.load(Ordering::SeqCst) {
            let _ = fs::write(
                dir.join("elevation-cancel.request"),
                b"cancel subsequent steps",
            );
        }
        if let Ok(text) = fs::read_to_string(dir.join("elevation-progress.json"))
            && let Some(v) = json::parse(&text)
        {
            *progress.lock().unwrap_or_else(|e| e.into_inner()) = Progress {
                check: match text_field(&v, "check") {
                    "SFC" => Some(DeepCheck::Sfc),
                    "DISM" => Some(DeepCheck::Dism),
                    _ => None,
                },
                phase: text_field(&v, "phase").into(),
                percent: match v.get("percent") {
                    Some(Value::Num(n)) => Some(*n as f32),
                    _ => None,
                },
                latest: text_field(&v, "latest").into(),
            };
        }
        match unsafe { WaitForSingleObject(handle.0, 200) } {
            0 => break,
            258 => {}
            _ => {
                return Err(
                    "Ошибка ожидания повышенного процесса; он не остановлен принудительно".into(),
                );
            }
        }
    }
    let mut code = 0;
    if unsafe { GetExitCodeProcess(handle.0, &mut code) } == 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    if code != 0 {
        return Err(format!(
            "Повышенный процесс завершился с кодом {code}: {}",
            fs::read_to_string(dir.join("elevation-error.txt")).unwrap_or_else(|_| {
                "Проверь права и пользователя, от имени которого выполнен UAC".into()
            })
        ));
    }
    Ok(())
}
fn text_field<'a>(v: &'a Value, k: &str) -> &'a str {
    text(v, k)
}
#[cfg(not(windows))]
fn launch(_: &Path, _: &str, _: &AtomicBool, _: &SharedProgress) -> Result<(), String> {
    Err("UAC requires Windows".into())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wire_rejects_unverified_success_and_preserves_failures() {
        let before = DeepCheckOutcome {
            check: DeepCheck::Sfc,
            result: CheckResult::Attention,
            detail: "INTEGRITY_VIOLATIONS".into(),
            source: deep_checks::ResultSource::ExpcJson,
        };
        let p = plan(&before, "C:").unwrap();
        let auth = authorize(p.clone(), true, false, true, false).unwrap();
        let report = not_started_report(auth, "test-1".into(), "UAC 1223".into());
        let parsed = json::parse(&report.json()).unwrap();
        assert_eq!(
            decode_report(&parsed, p.clone(), "test-1").unwrap().status,
            "CANCELLED"
        );
        assert!(decode_report(&parsed, p.clone(), "wrong-id").is_err());
        let invalid = json::parse(&report.json().replace("CANCELLED", "SUCCESS_VERIFIED")).unwrap();
        assert!(decode_report(&invalid, p.clone(), "test-1").is_err());
        let mut report = report;
        report.status = "SUCCESS_VERIFIED".into();
        report.verified = Some(CheckResult::Ok);
        report.verification = Some(Output {
            code: Some(0),
            scheduled: false,
            text: "Windows Resource Protection did not find any integrity violations.".into(),
        });
        let parsed = json::parse(&report.json()).unwrap();
        assert_eq!(
            decode_report(&parsed, p, "test-1").unwrap().verified,
            Some(CheckResult::Ok)
        );
    }
    #[test]
    fn uac_test_gate_never_launches_native_helper() {
        let before = DeepCheckOutcome {
            check: DeepCheck::Dism,
            result: CheckResult::Attention,
            detail: "REPAIRABLE".into(),
            source: deep_checks::ResultSource::ExpcJson,
        };
        let auth = authorize(plan(&before, "C:").unwrap(), true, false, true, false).unwrap();
        let progress = Arc::new(Mutex::new(Progress::default()));
        let reports = elevate_sequence(
            auth,
            None,
            "test".into(),
            PathBuf::from("never-created"),
            &AtomicBool::new(false),
            &progress,
        );
        assert_eq!(reports[0].status, "FAILED");
        assert!(reports[0].message.contains("disabled in tests"));
    }
    #[test]
    fn helper_rejects_arbitrary_path_and_never_runs_in_tests() {
        assert!(!helper_directory(Path::new("C:/Windows"), "Windows"));
        assert_eq!(elevated_worker(&[]), 5);
    }
}
