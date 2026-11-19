//! Streaming SHA256 through the Windows CNG provider; no external hashing process.
use std::io::{self, Read};
type Handle = *mut std::ffi::c_void;
#[link(name = "bcrypt")]
unsafe extern "system" {
    fn BCryptOpenAlgorithmProvider(
        out: *mut Handle,
        name: *const u16,
        implementation: *const u16,
        flags: u32,
    ) -> i32;
    fn BCryptCloseAlgorithmProvider(handle: Handle, flags: u32) -> i32;
    fn BCryptCreateHash(
        alg: Handle,
        out: *mut Handle,
        object: *mut u8,
        object_len: u32,
        secret: *mut u8,
        secret_len: u32,
        flags: u32,
    ) -> i32;
    fn BCryptHashData(handle: Handle, data: *const u8, len: u32, flags: u32) -> i32;
    fn BCryptFinishHash(handle: Handle, out: *mut u8, len: u32, flags: u32) -> i32;
    fn BCryptDestroyHash(handle: Handle) -> i32;
}
fn checked(status: i32) -> io::Result<()> {
    if status < 0 {
        Err(io::Error::other(format!(
            "CNG status 0x{:08x}",
            status as u32
        )))
    } else {
        Ok(())
    }
}
pub fn sha256(mut input: impl Read) -> io::Result<String> {
    let mut alg = std::ptr::null_mut();
    let mut hash = std::ptr::null_mut();
    let name: Vec<u16> = "SHA256\0".encode_utf16().collect();
    // SAFETY: valid out-pointers; CNG-owned hash object is destroyed before its provider.
    unsafe {
        checked(BCryptOpenAlgorithmProvider(
            &mut alg,
            name.as_ptr(),
            std::ptr::null(),
            0,
        ))?;
    }
    let result = (|| {
        unsafe {
            checked(BCryptCreateHash(
                alg,
                &mut hash,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                0,
                0,
            ))?;
        }
        let mut buffer = [0u8; 65536];
        loop {
            let n = input.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            unsafe {
                checked(BCryptHashData(hash, buffer.as_ptr(), n as u32, 0))?;
            }
        }
        let mut digest = [0u8; 32];
        unsafe {
            checked(BCryptFinishHash(hash, digest.as_mut_ptr(), 32, 0))?;
        }
        Ok(digest.iter().map(|b| format!("{b:02X}")).collect())
    })();
    unsafe {
        if !hash.is_null() {
            BCryptDestroyHash(hash);
        }
        BCryptCloseAlgorithmProvider(alg, 0);
    }
    result
}
#[cfg(test)]
mod tests {
    #[test]
    fn standard_vectors() {
        assert_eq!(
            super::sha256(&b"abc"[..]).unwrap(),
            "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"
        );
        assert_eq!(
            super::sha256(&b""[..]).unwrap(),
            "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
        );
    }
}
