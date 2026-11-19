//! Current-user generic credential. No configuration/environment/command-line key fallback.
use super::Error;
use std::{ffi::c_void, ptr};
pub(crate) const MAX_KEY_BYTES: usize = 4096;
const TARGET: &str = "EXPC/WinDiag/OpenAI";
#[repr(C)]
struct Credential {
    flags: u32,
    kind: u32,
    target: *mut u16,
    comment: *mut u16,
    last_written: [u32; 2],
    blob_len: u32,
    blob: *mut u8,
    persist: u32,
    attr_count: u32,
    attrs: *mut c_void,
    alias: *mut u16,
    user: *mut u16,
}
#[link(name = "advapi32")]
unsafe extern "system" {
    fn CredReadW(target: *const u16, kind: u32, flags: u32, out: *mut *mut Credential) -> i32;
    fn CredWriteW(credential: *const Credential, flags: u32) -> i32;
    fn CredDeleteW(target: *const u16, kind: u32, flags: u32) -> i32;
    fn CredFree(p: *mut c_void);
}
pub struct Secret(Vec<u8>);
impl Secret {
    pub fn from_input(value: &str) -> Result<Self, Error> {
        let value = value.trim();
        if value.is_empty() {
            return Err(Error::NoKey);
        }
        if !is_valid(value.as_bytes()) {
            return Err(Error::InvalidKey);
        }
        Ok(Self(value.as_bytes().to_vec()))
    }
    pub(super) fn from_bytes(mut bytes: Vec<u8>) -> Result<Self, Error> {
        if !is_valid(&bytes) {
            wipe_bytes(&mut bytes);
            return Err(Error::InvalidKey);
        }
        Ok(Self(bytes))
    }
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }
}
impl Drop for Secret {
    fn drop(&mut self) {
        wipe_bytes(&mut self.0);
    }
}
fn is_valid(key: &[u8]) -> bool {
    (16..=MAX_KEY_BYTES).contains(&key.len()) && key.iter().all(u8::is_ascii_graphic)
}
pub(super) fn wipe_bytes(bytes: &mut [u8]) {
    for b in bytes {
        unsafe { ptr::write_volatile(b, 0) }
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}
fn error() -> Error {
    Error::Credential(std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32)
}
pub fn load() -> Result<Secret, Error> {
    let target = wide(TARGET);
    let mut p = ptr::null_mut();
    if unsafe { CredReadW(target.as_ptr(), 1, 0, &mut p) } == 0 {
        return Err(
            if std::io::Error::last_os_error().raw_os_error() == Some(1168) {
                Error::NoKey
            } else {
                error()
            },
        );
    }
    if p.is_null() {
        return Err(Error::Credential(87));
    }
    let c = unsafe { &mut *p };
    let result = if c.blob_len > 0 && c.blob_len as usize <= MAX_KEY_BYTES && !c.blob.is_null() {
        let bytes = unsafe { std::slice::from_raw_parts_mut(c.blob, c.blob_len as usize) };
        let copy = Secret::from_bytes(bytes.to_vec());
        wipe_bytes(bytes);
        copy
    } else {
        Err(Error::Credential(87))
    };
    unsafe { CredFree(p.cast()) };
    result
}
#[cfg_attr(test, allow(dead_code))]
pub fn present() -> Result<bool, Error> {
    match load() {
        Ok(_) => Ok(true),
        Err(Error::NoKey) => Ok(false),
        Err(e) => Err(e),
    }
}
pub fn save(key: &str) -> Result<(), Error> {
    let key = Secret::from_input(key)?;
    let target = wide(TARGET);
    let user = wide("WinDiag");
    let credential = Credential {
        flags: 0,
        kind: 1,
        target: target.as_ptr() as *mut _,
        comment: ptr::null_mut(),
        last_written: [0; 2],
        blob_len: key.bytes().len() as u32,
        blob: key.bytes().as_ptr() as *mut _,
        persist: 2,
        attr_count: 0,
        attrs: ptr::null_mut(),
        alias: ptr::null_mut(),
        user: user.as_ptr() as *mut _,
    };
    if unsafe { CredWriteW(&credential, 0) } == 0 {
        Err(error())
    } else {
        Ok(())
    }
}
pub fn delete() -> Result<(), Error> {
    let target = wide(TARGET);
    if unsafe { CredDeleteW(target.as_ptr(), 1, 0) } == 0
        && std::io::Error::last_os_error().raw_os_error() != Some(1168)
    {
        Err(error())
    } else {
        Ok(())
    }
}
pub fn wipe(value: &mut String) {
    unsafe { wipe_bytes(value.as_mut_vec()) };
    value.clear();
}
