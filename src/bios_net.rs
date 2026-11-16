//! Bounded HTTPS reader in an owned, hidden child process; no downloaded code is run.
use crate::bios::s;
use std::{
    io::Read,
    process::{Command, Stdio},
    sync::atomic::AtomicBool,
    time::Duration,
};
#[derive(Clone, Debug)]
pub struct Page {
    pub url: String,
    pub body: String,
}
pub const MAX_RESPONSE: usize = 4 * 1024 * 1024;
pub fn official_host(url: &str) -> Option<&str> {
    let rest = url.strip_prefix("https://")?;
    let host = rest.split('/').next()?;
    if url.len() > 2048
        || url
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || c == '\\')
    {
        return None;
    }
    matches!(
        host,
        "www.msi.com" | "www.asus.com" | "www.gigabyte.com" | "www.asrock.com" | "pg.asrock.com"
    )
    .then_some(host)
}
pub fn same_provider(a: &str, b: &str) -> bool {
    match (official_host(a), official_host(b)) {
        (Some(x), Some(y)) => {
            x == y
                || (["www.asrock.com", "pg.asrock.com"].contains(&x)
                    && ["www.asrock.com", "pg.asrock.com"].contains(&y))
        }
        _ => false,
    }
}
#[cfg(test)]
pub fn fetch(url: &str, cancel: &AtomicBool, timeout: Duration) -> Result<String, String> {
    fetch_page(url, cancel, timeout).map(|p| p.body)
}
pub fn fetch_page(url: &str, cancel: &AtomicBool, timeout: Duration) -> Result<Page, String> {
    let host = official_host(url).ok_or("Отклонён неофициальный/небезопасный адрес BIOS")?;
    if cancel.load(std::sync::atomic::Ordering::SeqCst) {
        return Err("Проверка BIOS отменена".into());
    }
    let script = format!(
        "{}\n$url='{}'\n$allowedHost='{}'\n{}\n{}",
        crate::ps_exec::PS_PRELUDE,
        url.replace('\'', "''"),
        host,
        RETRY_POLICY,
        HTTP_SCRIPT
    );
    fetch_script(&script, host, cancel, timeout)
}
fn fetch_script(
    script: &str,
    host: &str,
    cancel: &AtomicBool,
    timeout: Duration,
) -> Result<Page, String> {
    let mut cmd = Command::new("powershell.exe");
    cmd.env_remove("PSModulePath")
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-EncodedCommand",
        ])
        .arg(crate::ps_exec::encoded_command(script));
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut guard = crate::engine::ProcessGuard::spawn(cmd)
        .map_err(|e| format!("Не удалось запустить проверку BIOS: {e}"))?;
    let stdout = guard
        .child_mut()
        .stdout
        .take()
        .ok_or("Нет канала ответа BIOS")?;
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = stdout.take(12 * 1024 * 1024 + 1).read_to_end(&mut bytes);
        (bytes, result)
    });
    let end = guard.wait_or_cancel(cancel, Some(timeout));
    drop(guard);
    let (bytes, read) = reader.join().map_err(|_| "Прервано чтение каталога BIOS")?;
    match end {
        Err(crate::engine::WaitEnd::Cancelled) => return Err("Проверка BIOS отменена".into()),
        Err(crate::engine::WaitEnd::TimedOut) => {
            return Err("Сайт BIOS не ответил за отведённое время".into());
        }
        Err(crate::engine::WaitEnd::Io(e)) => {
            return Err(format!("Ошибка процесса проверки BIOS: {e}"));
        }
        _ => {}
    }
    read.map_err(|_| "Не удалось прочитать ответ сайта BIOS")?;
    if bytes.len() > 12 * 1024 * 1024 {
        return Err("Ответ BIOS превышает предел размера".into());
    }
    let text = String::from_utf8(bytes).map_err(|_| "Некорректная кодировка ответа BIOS")?;
    let v = crate::ps_exec::marked_line(&text, "WSD_BIOS_HTTP ")
        .and_then(crate::deep_checks::json::parse)
        .ok_or("Процесс проверки BIOS не вернул корректный ответ")?;
    if !matches!(
        v.get("ok"),
        Some(crate::deep_checks::json::Value::Bool(true))
    ) {
        return Err(format!(
            "Не удалось получить каталог BIOS: {}",
            s(&v, "error")
        ));
    }
    if !same_provider(&format!("https://{host}/"), s(&v, "url")) {
        return Err("Сайт BIOS перенаправил запрос за пределы официального источника".into());
    }
    let body = s(&v, "body");
    if body.len() > MAX_RESPONSE {
        return Err("Каталог BIOS превышает 4 МиБ".into());
    }
    Ok(Page {
        url: s(&v, "url").into(),
        body: body.into(),
    })
}
const RETRY_POLICY: &str = r#"
function Get-BiosRetryPolicy([int]$Code,[string]$RetryAfter,[int]$Attempt) {
    $retry=($Code -eq 429 -or $Code -in @(500,502,503,504)) -and $Attempt -lt 2
    $delay=1+$Attempt
    if ($RetryAfter) {
        $seconds=0; $when=[DateTimeOffset]::MinValue
        if ([int]::TryParse($RetryAfter,[ref]$seconds)) { $delay=[Math]::Max($delay,$seconds) }
        elseif ([DateTimeOffset]::TryParse($RetryAfter,[ref]$when)) { $delay=[Math]::Max($delay,[Math]::Ceiling(($when-[DateTimeOffset]::UtcNow).TotalSeconds)) }
        else { $retry=$false }
        # Never retry earlier than requested. Longer waits belong to the next user check.
        if ($delay -gt 5) { $retry=$false }
    }
    [pscustomobject]@{Retry=$retry;Delay=$delay}
}
"#;
const HTTP_SCRIPT: &str = r#"
$ErrorActionPreference='Stop'
[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
$allowedHosts=@($allowedHost)
if ($allowedHost -in @('www.asrock.com','pg.asrock.com')) { $allowedHosts=@('www.asrock.com','pg.asrock.com') }
$originalUrl=$url
for ($attempt=0;$attempt -lt 3;$attempt++) {
    $url=$originalUrl
    $retry=$false; $delay=1+$attempt
    try {
        for ($redirect=0;$redirect -le 3;$redirect++) {
            $u=[Uri]$url
            if ($u.Scheme -ne 'https' -or $u.DnsSafeHost -notin $allowedHosts -or $u.Port -ne 443 -or $u.UserInfo) { throw 'Неофициальное перенаправление' }
            $req=[Net.HttpWebRequest]::Create($u)
            $req.AllowAutoRedirect=$false; $req.UseDefaultCredentials=$false
            # Use the standard Windows proxy; do not import browser cookies or credentials.
            $req.Proxy=[Net.WebRequest]::DefaultWebProxy
            $req.Timeout=10000; $req.ReadWriteTimeout=10000
            $req.UserAgent='WinDiag/1.4 (BIOS metadata check)'
            # No automatic decompression: both wire and decoded metadata are capped.
            $req.AutomaticDecompression=[Net.DecompressionMethods]::None
            $res=$null; $stream=$null; $mem=$null
            try {
                $res=$req.GetResponse()
                $status=[int]$res.StatusCode
                if ($status -ge 300 -and $status -lt 400) {
                    if (!$res.Headers['Location'] -or $redirect -eq 3) { throw 'Слишком много перенаправлений' }
                    $url=([Uri]::new($u,$res.Headers['Location'])).AbsoluteUri
                    continue
                }
                if ($status -ne 200) { throw ('HTTP '+$status) }
                if ($res.ContentLength -gt 4194304) { throw 'Ответ превышает 4 МиБ' }
                if ($res.ContentEncoding -and $res.ContentEncoding -ne 'identity') { throw 'Неподдерживаемое сжатие ответа BIOS' }
                $stream=$res.GetResponseStream(); $mem=New-Object IO.MemoryStream
                $buf=New-Object byte[] 16384
                while (($n=$stream.Read($buf,0,$buf.Length)) -gt 0) {
                    if ($mem.Length+$n -gt 4194304) { throw 'Ответ превышает 4 МиБ' }
                    $mem.Write($buf,0,$n)
                }
                $utf8=New-Object Text.UTF8Encoding($false,$true)
                $body=$utf8.GetString($mem.ToArray()).TrimStart([char]0xFEFF)
                'WSD_BIOS_HTTP '+(@{ok=$true;url=$url;body=$body}|ConvertTo-Json -Compress -Depth 3)
                exit 0
            } finally { if($stream){$stream.Dispose()};if($mem){$mem.Dispose()};if($res){$res.Dispose()} }
        }
        throw 'Не получен каталог BIOS'
    } catch {
        $message='Сеть/TLS недоступны или сайт отклонил запрос'
        $cause=$_.Exception
        while ($cause.InnerException) { $cause=$cause.InnerException }
        if ($cause -is [Net.WebException] -and $cause.Response) {
            $code=[int]$cause.Response.StatusCode
            $message='HTTP '+$code
            $policy=Get-BiosRetryPolicy $code $cause.Response.Headers['Retry-After'] $attempt
            $retry=$policy.Retry; $delay=$policy.Delay
            if ($delay -gt 5) { $message+='; повторить позднее (Retry-After)' }
            if ($code -eq 403) { $message+=': сайт запретил автоматический доступ' }
            if ($code -eq 429) { $message+=': превышен лимит запросов' }
            $cause.Response.Close()
        } elseif ($cause -is [Net.WebException]) {
            $message='Сеть/TLS: '+$cause.Status
            $retry=($cause.Status -in @([Net.WebExceptionStatus]::Timeout,[Net.WebExceptionStatus]::ConnectFailure,[Net.WebExceptionStatus]::ConnectionClosed))
        } elseif ($_.Exception.Message -match '4 МиБ|перенаправлен|сжатие') { $message=$_.Exception.Message }
        if ($retry -and $attempt -lt 2) { Start-Sleep -Seconds $delay; continue }
        'WSD_BIOS_HTTP '+(@{ok=$false;error=$message}|ConvertTo-Json -Compress)
        exit 1
    }
}
"#;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn owned_https_process_timeout_and_cancellation() {
        if crate::ps_exec::test_host().is_none() {
            return;
        }
        for cancelled in [false, true] {
            let stop = std::sync::Arc::new(AtomicBool::new(false));
            let c = stop.clone();
            let thread = std::thread::spawn(move || {
                if cancelled {
                    std::thread::sleep(Duration::from_millis(150));
                    c.store(true, std::sync::atomic::Ordering::SeqCst)
                }
            });
            let start = std::time::Instant::now();
            let r = fetch_script(
                "Start-Sleep -Seconds 30",
                "www.msi.com",
                &stop,
                Duration::from_millis(300),
            );
            thread.join().unwrap();
            assert!(r.unwrap_err().contains(if cancelled {
                "отменена"
            } else {
                "время"
            }));
            assert!(start.elapsed() < Duration::from_secs(5));
        }
    }
    #[test]
    fn cancelled_before_start_does_not_request_network() {
        assert!(
            fetch(
                "https://www.msi.com/x",
                &AtomicBool::new(true),
                Duration::from_secs(1)
            )
            .unwrap_err()
            .contains("отменена")
        );
    }
    #[test]
    fn redirect_validation_is_per_hop_and_certificates_remain_enabled() {
        assert!(HTTP_SCRIPT.contains("$req.AllowAutoRedirect=$false"));
        assert!(HTTP_SCRIPT.contains("$u.DnsSafeHost -notin $allowedHosts"));
        assert!(!HTTP_SCRIPT.contains("ServerCertificateValidationCallback"));
    }
    #[test]
    fn production_retry_policy_respects_status_attempt_limit_and_retry_after() {
        let Some(host) = crate::ps_exec::test_host() else {
            return;
        };
        let script = format!(
            "{RETRY_POLICY}\n{}",
            r#"
$cases=@(@(403,'',0),@(404,'',0),@(429,'2',0),@(429,'120',0),@(503,'',1),@(500,'',2),@(429,'invalid',0))
foreach($c in $cases) { $r=Get-BiosRetryPolicy $c[0] $c[1] $c[2]; 'RESULT '+(@{retry=$r.Retry;delay=$r.Delay}|ConvertTo-Json -Compress) }
$future=[DateTimeOffset]::UtcNow.AddSeconds(120).ToString('r');$r=Get-BiosRetryPolicy 429 $future 0
'FUTURE '+$r.Retry
"#
        );
        let text = crate::ps_exec::run_powershell(&host, &script, Duration::from_secs(10)).unwrap();
        let rows = text
            .lines()
            .filter_map(|l| l.strip_prefix("RESULT "))
            .map(|s| crate::deep_checks::json::parse(s).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(rows.len(), 7);
        for (row, expected) in rows
            .iter()
            .zip([false, false, true, false, true, false, false])
        {
            assert!(
                matches!(row.get("retry"),Some(crate::deep_checks::json::Value::Bool(v)) if *v==expected)
            );
        }
        assert!(
            matches!(rows[2].get("delay"),Some(crate::deep_checks::json::Value::Num(n)) if *n==2.0)
        );
        assert!(text.contains("FUTURE False"));
    }
}
