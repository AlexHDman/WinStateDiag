//! One POST, fixed HTTPS origin, standard certificate checks, no redirect/retry.
use super::*;
use std::{
    ffi::c_void,
    io::{self, BufRead, BufReader},
    process::{ChildStdin, Command, Stdio},
    ptr,
    sync::{Arc, atomic::AtomicU8, mpsc},
};
type Handle = *mut c_void;
#[link(name = "winhttp")]
unsafe extern "system" {
    fn WinHttpOpen(
        agent: *const u16,
        access: u32,
        proxy: *const u16,
        bypass: *const u16,
        flags: u32,
    ) -> Handle;
    fn WinHttpConnect(session: Handle, server: *const u16, port: u16, reserved: u32) -> Handle;
    fn WinHttpOpenRequest(
        connect: Handle,
        verb: *const u16,
        path: *const u16,
        version: *const u16,
        referer: *const u16,
        accept: *const *const u16,
        flags: u32,
    ) -> Handle;
    fn WinHttpSetTimeouts(
        handle: Handle,
        resolve: i32,
        connect: i32,
        send: i32,
        receive: i32,
    ) -> i32;
    fn WinHttpSetOption(handle: Handle, option: u32, buffer: *const c_void, len: u32) -> i32;
    fn WinHttpSendRequest(
        request: Handle,
        headers: *const u16,
        headers_len: u32,
        body: *const c_void,
        body_len: u32,
        total: u32,
        context: usize,
    ) -> i32;
    fn WinHttpReceiveResponse(request: Handle, reserved: *mut c_void) -> i32;
    fn WinHttpQueryHeaders(
        request: Handle,
        level: u32,
        name: *const u16,
        buffer: *mut c_void,
        len: *mut u32,
        index: *mut u32,
    ) -> i32;
    fn WinHttpReadData(request: Handle, buffer: *mut c_void, len: u32, read: *mut u32) -> i32;
    fn WinHttpCloseHandle(handle: Handle) -> i32;
}
struct Http(Handle);
impl Drop for Http {
    fn drop(&mut self) {
        unsafe {
            WinHttpCloseHandle(self.0);
        }
    }
}
fn handle(p: Handle) -> Result<Http, Error> {
    if p.is_null() {
        Err(native_error())
    } else {
        Ok(Http(p))
    }
}
fn w(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}
fn native_error() -> Error {
    if std::io::Error::last_os_error().raw_os_error() == Some(12002) {
        Error::Timeout
    } else {
        Error::Network
    }
}
const MAX_REQUEST: usize = MAX_INPUT * 6 + 16_384;
const MAX_IPC_RESPONSE: usize = MAX_RESPONSE * 6 + 8192;
const SEND_EVENT: &[u8] = b"WIN_DIAG_OPENAI_SENDING\n";
const WAIT_EVENT: &[u8] = b"WIN_DIAG_OPENAI_WAITING\n";

pub(crate) enum KeyChoice {
    Stored,
    Session(credentials::Secret),
}

#[derive(Copy, Clone)]
pub(crate) enum Phase {
    Preparing,
    Sending,
    Waiting,
}

#[derive(Default)]
pub(crate) struct Progress(AtomicU8);
impl Progress {
    pub fn phase(&self) -> Phase {
        match self.0.load(Ordering::Acquire) {
            1 => Phase::Sending,
            2 => Phase::Waiting,
            _ => Phase::Preparing,
        }
    }
}

pub(crate) struct SendRequest {
    pub body: String,
    pub model: String,
    pub key: KeyChoice,
    pub cancel: Arc<AtomicBool>,
    pub progress: Arc<Progress>,
}

// A private child pipe carries the selected key and JSON in separate frames.
// Zero length is an explicit request to use the current-user saved credential.
fn write_request(mut output: impl Write, body: &str, key: KeyChoice) -> io::Result<()> {
    let token = match &key {
        KeyChoice::Stored => &[][..],
        KeyChoice::Session(secret) => secret.bytes(),
    };
    output.write_all(&(token.len() as u32).to_le_bytes())?;
    output.write_all(token)?;
    output.write_all(body.as_bytes())
}

fn read_request(mut input: impl Read) -> Result<(String, KeyChoice), Error> {
    let mut length = [0u8; 4];
    input.read_exact(&mut length).map_err(|_| Error::Worker)?;
    let length = u32::from_le_bytes(length) as usize;
    if length > credentials::MAX_KEY_BYTES {
        return Err(Error::InvalidKey);
    }
    let key = if length == 0 {
        KeyChoice::Stored
    } else {
        let mut bytes = vec![0; length];
        if input.read_exact(&mut bytes).is_err() {
            credentials::wipe_bytes(&mut bytes);
            return Err(Error::Worker);
        }
        KeyChoice::Session(credentials::Secret::from_bytes(bytes)?)
    };
    let mut body = String::new();
    input
        .take((MAX_REQUEST + 1) as u64)
        .read_to_string(&mut body)
        .map_err(|_| Error::InvalidResponse)?;
    if body.len() > MAX_REQUEST {
        return Err(Error::InvalidResponse);
    }
    Ok((body, key))
}

fn request_id(req: &Http) -> String {
    const WINHTTP_QUERY_CUSTOM: u32 = 65535;
    let mut buffer = [0u16; 100];
    let mut bytes = std::mem::size_of_val(&buffer) as u32;
    if unsafe {
        WinHttpQueryHeaders(
            req.0,
            WINHTTP_QUERY_CUSTOM,
            w("x-request-id").as_ptr(),
            buffer.as_mut_ptr().cast(),
            &mut bytes,
            ptr::null_mut(),
        )
    } == 0
    {
        return String::new();
    }
    String::from_utf16_lossy(&buffer[..((bytes / 2) as usize).min(buffer.len())])
        .trim_end_matches('\0')
        .to_owned()
}

struct Reply {
    body: String,
    request_id: String,
}
fn post(
    body: &str,
    key: &credentials::Secret,
    mut emit: impl FnMut(&[u8]) -> io::Result<()>,
) -> Result<Reply, Error> {
    let session = handle(unsafe {
        WinHttpOpen(
            w(concat!("EXPC WinDiag/", env!("CARGO_PKG_VERSION"))).as_ptr(),
            4,
            ptr::null(),
            ptr::null(),
            0,
        )
    })?;
    if unsafe { WinHttpSetTimeouts(session.0, 8000, 10000, 15000, 110000) } == 0 {
        return Err(native_error());
    }
    let connect =
        handle(unsafe { WinHttpConnect(session.0, w("api.openai.com").as_ptr(), 443, 0) })?;
    let req = handle(unsafe {
        WinHttpOpenRequest(
            connect.0,
            w("POST").as_ptr(),
            w("/v1/responses").as_ptr(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            0x00800000,
        )
    })?;
    let never: u32 = 0;
    if unsafe { WinHttpSetOption(req.0, 88, (&never as *const u32).cast(), 4) } == 0 {
        return Err(native_error());
    }
    emit(SEND_EVENT).map_err(|_| Error::Worker)?;
    // Header memory is wiped after the synchronous send; it never enters argv/logs.
    let token = std::str::from_utf8(key.bytes()).map_err(|_| Error::NoKey)?;
    if !token.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(Error::NoKey);
    }
    let mut header = format!(
        "Content-Type: application/json; charset=utf-8\r\nAuthorization: Bearer {token}\r\n"
    );
    let mut wide = w(&header);
    let sent = unsafe {
        WinHttpSendRequest(
            req.0,
            wide.as_ptr(),
            (wide.len() - 1) as u32,
            body.as_ptr().cast(),
            body.len() as u32,
            body.len() as u32,
            0,
        )
    };
    credentials::wipe(&mut header);
    for c in &mut wide {
        unsafe { ptr::write_volatile(c, 0) }
    }
    if sent == 0 {
        return Err(native_error());
    }
    emit(WAIT_EVENT).map_err(|_| Error::Worker)?;
    if unsafe { WinHttpReceiveResponse(req.0, ptr::null_mut()) } == 0 {
        return Err(native_error());
    }
    let mut status = 0u32;
    let mut len = 4;
    if unsafe {
        WinHttpQueryHeaders(
            req.0,
            19 | 0x20000000,
            ptr::null(),
            (&mut status as *mut u32).cast(),
            &mut len,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(Error::InvalidResponse);
    }
    let request_id = request_id(&req);
    let mut bytes = vec![];
    loop {
        let mut chunk = [0u8; 8192];
        let mut n = 0;
        if unsafe { WinHttpReadData(req.0, chunk.as_mut_ptr().cast(), chunk.len() as u32, &mut n) }
            == 0
        {
            let problem = if native_error() == Error::Timeout {
                HttpProblem::ReadTimeout
            } else {
                HttpProblem::ReadError
            };
            return Err(Error::Http(HttpFailure::new(status, &request_id, problem)));
        }
        if n == 0 {
            break;
        }
        if bytes.len() + n as usize > MAX_RESPONSE {
            return Err(Error::Http(HttpFailure::new(
                status,
                &request_id,
                HttpProblem::InvalidResponse,
            )));
        }
        bytes.extend_from_slice(&chunk[..n as usize]);
    }
    let text = String::from_utf8(bytes).map_err(|_| {
        Error::Http(HttpFailure::new(
            status,
            &request_id,
            HttpProblem::InvalidResponse,
        ))
    })?;
    if status != 200 {
        return Err(classify_http(status, &text, &request_id));
    }
    Ok(Reply {
        body: text,
        request_id,
    })
}
pub fn worker() -> i32 {
    let mut stdout = std::io::stdout().lock();
    let result = (|| {
        let (body, choice) = read_request(std::io::stdin().lock())?;
        let j = Json::parse(&body).map_err(|_| Error::InvalidResponse)?;
        if !valid_model(string(&j, "model"))
            || string(&j, "instructions") != INSTRUCTIONS
            || string(&j, "input").len() > MAX_INPUT
            || j.get("store") != Some(&Json::Bool(false))
            || !array(&j, "tools").is_empty()
            || string(&j, "tool_choice") != "none"
        {
            return Err(Error::InvalidResponse);
        }
        let key = match choice {
            KeyChoice::Stored => credentials::load()?,
            KeyChoice::Session(key) => key,
        };
        post(&body, &key, |event| {
            stdout.write_all(event)?;
            stdout.flush()
        })
    })();
    let output = encode_reply(result).render();
    if stdout
        .write_all(output.as_bytes())
        .and_then(|_| stdout.flush())
        .is_err()
    {
        1
    } else {
        0
    }
}

fn encode_reply(reply: Result<Reply, Error>) -> Json {
    match reply {
        Ok(reply) => object(vec![
            ("ok", Json::Bool(true)),
            ("body", Json::str(&reply.body)),
            (
                "request_id",
                Json::str(&safe_request_id(&reply.request_id).unwrap_or_default()),
            ),
        ]),
        Err(Error::Http(e)) => {
            let issue = match e.problem {
                HttpProblem::Authentication => "auth",
                HttpProblem::Access => "access",
                HttpProblem::Region => "region",
                HttpProblem::Model => "model",
                HttpProblem::Quota => "quota",
                HttpProblem::RateLimit => "rate",
                HttpProblem::Server => "server",
                HttpProblem::Rejected => "rejected",
                HttpProblem::ReadError => "read_error",
                HttpProblem::ReadTimeout => "read_timeout",
                HttpProblem::InvalidResponse => "invalid_response",
            };
            object(vec![
                ("ok", Json::Bool(false)),
                ("error", Json::str("http")),
                ("issue", Json::str(issue)),
                ("status", Json::Int(i64::from(e.status))),
                ("code", Json::str(e.code.as_deref().unwrap_or_default())),
                (
                    "type",
                    Json::str(e.error_type.as_deref().unwrap_or_default()),
                ),
                (
                    "request_id",
                    Json::str(e.request_id.as_deref().unwrap_or_default()),
                ),
            ])
        }
        Err(e) => {
            let (code, number) = match e {
                Error::NoKey => ("no_key", 0),
                Error::InvalidKey => ("invalid_key", 0),
                Error::Credential(n) => ("credential", n),
                Error::Network => ("network", 0),
                Error::Timeout => ("timeout", 0),
                Error::Worker => ("worker", 0),
                _ => ("invalid", 0),
            };
            object(vec![
                ("ok", Json::Bool(false)),
                ("error", Json::str(code)),
                ("status", Json::Int(i64::from(number))),
            ])
        }
    }
}

fn parse_reply(output: &str, model: &str) -> Result<Analysis, Error> {
    let json = Json::parse(output).map_err(|_| Error::InvalidResponse)?;
    let id = string(&json, "request_id");
    if json.get("ok") == Some(&Json::Bool(true)) {
        return parse_response(string(&json, "body"), model)
            .map_err(|_| Error::Http(HttpFailure::new(200, id, HttpProblem::InvalidResponse)));
    }
    let status = json
        .get("status")
        .and_then(Json::as_int)
        .and_then(|n| u32::try_from(n).ok())
        .unwrap_or(0);
    let error = match string(&json, "error") {
        "no_key" => Error::NoKey,
        "invalid_key" => Error::InvalidKey,
        "credential" => Error::Credential(status),
        "network" => Error::Network,
        "timeout" => Error::Timeout,
        "worker" => Error::Worker,
        "http" if (100..=599).contains(&status) => {
            let problem = match string(&json, "issue") {
                "auth" => HttpProblem::Authentication,
                "access" => HttpProblem::Access,
                "region" => HttpProblem::Region,
                "model" => HttpProblem::Model,
                "quota" => HttpProblem::Quota,
                "rate" => HttpProblem::RateLimit,
                "server" => HttpProblem::Server,
                "read_error" => HttpProblem::ReadError,
                "read_timeout" => HttpProblem::ReadTimeout,
                "invalid_response" => HttpProblem::InvalidResponse,
                _ => HttpProblem::Rejected,
            };
            let mut failure = HttpFailure::new(status, id, problem);
            failure.code = safe_diagnostic_field(string(&json, "code"));
            failure.error_type = safe_diagnostic_field(string(&json, "type"));
            Error::Http(failure)
        }
        _ => Error::InvalidResponse,
    };
    Err(error)
}

fn read_output(source: impl Read, progress: Option<&Progress>) -> io::Result<Vec<u8>> {
    let mut input = BufReader::new(source.take((MAX_IPC_RESPONSE + 1) as u64));
    let mut output = Vec::new();
    if let Some(progress) = progress {
        loop {
            if input.read_until(b'\n', &mut output)? == 0 {
                return Ok(output);
            }
            match output.as_slice() {
                SEND_EVENT => progress.0.store(1, Ordering::Release),
                WAIT_EVENT => progress.0.store(2, Ordering::Release),
                _ => break,
            }
            output.clear();
        }
    }
    input.read_to_end(&mut output)?;
    Ok(output)
}
fn process(
    program: &Path,
    args: &[&str],
    write_input: impl FnOnce(&mut ChildStdin) -> io::Result<()>,
    cancel: &AtomicBool,
    timeout: Duration,
    progress: Option<Arc<Progress>>,
) -> Result<String, Error> {
    if cancel.load(Ordering::Acquire) {
        return Err(Error::Cancelled);
    }
    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut guard = crate::engine::ProcessGuard::spawn(cmd).map_err(|_| Error::Worker)?;
    let mut input = guard.child_mut().stdin.take().ok_or(Error::Worker)?;
    write_input(&mut input).map_err(|_| Error::Worker)?;
    drop(input);
    let stdout = guard.child_mut().stdout.take().ok_or(Error::Worker)?;
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(read_output(stdout, progress.as_deref()));
    });
    let status = guard
        .wait_or_cancel(cancel, Some(timeout))
        .map_err(|e| match e {
            crate::engine::WaitEnd::Cancelled => Error::Cancelled,
            _ => Error::Timeout,
        })?;
    if !status.success() {
        return Err(Error::Worker);
    }
    let bytes = rx
        .recv_timeout(Duration::from_secs(3))
        .map_err(|_| Error::Worker)?
        .map_err(|_| Error::Worker)?;
    if bytes.len() > MAX_IPC_RESPONSE {
        return Err(Error::InvalidResponse);
    }
    String::from_utf8(bytes).map_err(|_| Error::InvalidResponse)
}
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn execute(request: SendRequest) -> Result<Analysis, Error> {
    let SendRequest {
        body,
        model,
        key,
        cancel,
        progress,
    } = request;
    let exe = std::env::current_exe().map_err(|_| Error::Worker)?;
    let output = process(
        &exe,
        &["--ai-analysis-worker"],
        |pipe| write_request(pipe, &body, key),
        &cancel,
        Duration::from_secs(135),
        Some(progress),
    )?;
    if cancel.load(Ordering::Acquire) {
        return Err(Error::Cancelled);
    }
    parse_reply(&output, &model)
}
#[cfg(test)]
pub(super) fn mock_process(
    program: &Path,
    args: &[&str],
    body: String,
    cancel: &AtomicBool,
    timeout: Duration,
) -> Result<String, Error> {
    process(
        program,
        args,
        |pipe| pipe.write_all(body.as_bytes()),
        cancel,
        timeout,
        None,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipe_has_only_the_selected_input_key_and_separate_json() {
        let fixture = "mock-session-token-9876";
        let key = credentials::Secret::from_input(&format!(" \r\n{fixture} \t")).unwrap();
        let mut pipe = Vec::new();
        write_request(&mut pipe, "{}", KeyChoice::Session(key)).unwrap();
        let (report, key) = read_request(pipe.as_slice()).unwrap();
        assert_eq!(report, "{}");
        let KeyChoice::Session(key) = key else {
            panic!("session key fell back to saved")
        };
        assert!(key.bytes() == fixture.as_bytes());
        assert!(!report.contains(fixture));
        credentials::wipe_bytes(&mut pipe);
    }

    #[test]
    fn no_argument_or_error_body_with_a_key_is_reflected() {
        let raw = r#"{"error":{"code":"invalid_api_key","type":"invalid_request_error","message":"Authorization: Bearer mock-private-secret--!"}}"#;
        let err = classify_http(401, raw, "req_Controlled401");
        let wire = encode_reply(Err(err.clone())).render();
        assert!(!wire.contains("mock-private-secret"));
        assert!(!wire.contains("Authorization"));
        assert!(matches!(parse_reply(&wire,"gpt-4.1-mini"), Err(e) if e==err));
    }

    #[test]
    fn worker_progress_is_separate_from_the_result() {
        let progress = Progress::default();
        assert!(matches!(progress.phase(), Phase::Preparing));
        let input = [SEND_EVENT, WAIT_EVENT, b"{}"].concat();
        let output = read_output(input.as_slice(), Some(&progress)).unwrap();
        assert_eq!(output, b"{}");
        assert!(matches!(progress.phase(), Phase::Waiting));
    }
}
