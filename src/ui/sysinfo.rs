//! Read-only status-bar facts: Windows edition/build (registry, read-only)
//! and local wall-clock time. UI-level helpers only — no diagnostic logic.

#[derive(Clone, Copy, Debug, Default)]
pub struct LocalTime {
    pub year: u16,
    pub month: u16,
    pub day: u16,
    pub hour: u16,
    pub minute: u16,
    pub second: u16,
}

impl LocalTime {
    pub fn hms(&self) -> String {
        format!("{:02}:{:02}:{:02}", self.hour, self.minute, self.second)
    }
    pub fn date_dmy(&self) -> String {
        format!("{:02}.{:02}.{:04}", self.day, self.month, self.year)
    }
    pub fn hm(&self) -> String {
        format!("{:02}:{:02}", self.hour, self.minute)
    }
}

#[cfg(windows)]
mod imp {
    use super::LocalTime;
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    #[repr(C)]
    #[derive(Default)]
    struct SystemTime {
        year: u16,
        month: u16,
        day_of_week: u16,
        day: u16,
        hour: u16,
        minute: u16,
        second: u16,
        milliseconds: u16,
    }

    const HKEY_LOCAL_MACHINE: isize = 0x8000_0002_u32 as i32 as isize;
    const RRF_RT_REG_SZ: u32 = 0x0000_0002;
    const RRF_RT_REG_DWORD: u32 = 0x0000_0010;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetLocalTime(st: *mut SystemTime);
    }

    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn RegGetValueW(
            hkey: isize,
            sub_key: *const u16,
            value: *const u16,
            flags: u32,
            ty: *mut u32,
            data: *mut u16,
            len: *mut u32,
        ) -> i32;
    }

    fn wide(s: &str) -> Vec<u16> {
        OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    pub fn local_time() -> LocalTime {
        let mut st = SystemTime::default();
        unsafe { GetLocalTime(&mut st) };
        LocalTime {
            year: st.year,
            month: st.month,
            day: st.day,
            hour: st.hour,
            minute: st.minute,
            second: st.second,
        }
    }

    pub fn current_version_value(name: &str) -> Option<String> {
        let key = wide("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");
        let val = wide(name);
        let mut buf = vec![0u16; 256];
        let mut len = (buf.len() * 2) as u32;
        let rc = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                key.as_ptr(),
                val.as_ptr(),
                RRF_RT_REG_SZ,
                std::ptr::null_mut(),
                buf.as_mut_ptr(),
                &mut len,
            )
        };
        if rc != 0 {
            return None;
        }
        let chars = (len as usize / 2).saturating_sub(1).min(buf.len());
        Some(String::from_utf16_lossy(&buf[..chars]).trim().to_string())
    }

    /// REG_DWORD value of the same key (read-only).
    pub fn current_version_dword(name: &str) -> Option<u32> {
        let key = wide("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");
        let val = wide(name);
        let mut data: u32 = 0;
        let mut len: u32 = 4;
        let rc = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                key.as_ptr(),
                val.as_ptr(),
                RRF_RT_REG_DWORD,
                std::ptr::null_mut(),
                (&mut data as *mut u32).cast::<u16>(),
                &mut len,
            )
        };
        (rc == 0 && len == 4).then_some(data)
    }
}

#[cfg(not(windows))]
mod imp {
    use super::LocalTime;
    pub fn local_time() -> LocalTime {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let day_secs = secs % 86_400;
        LocalTime {
            year: 1970,
            month: 1,
            day: 1,
            hour: (day_secs / 3600) as u16,
            minute: ((day_secs / 60) % 60) as u16,
            second: (day_secs % 60) as u16,
        }
    }
    pub fn current_version_value(_name: &str) -> Option<String> {
        None
    }
    pub fn current_version_dword(_name: &str) -> Option<u32> {
        None
    }
}

pub fn local_time() -> LocalTime {
    imp::local_time()
}

/// ("Windows 11 Pro", "26200") — Windows 11 still reports "Windows 10" in
/// ProductName, so the build number decides the marketing major version.
pub fn windows_edition_and_build() -> (String, String) {
    let build = imp::current_version_value("CurrentBuildNumber").unwrap_or_default();
    let mut product = imp::current_version_value("ProductName").unwrap_or_else(|| "Windows".into());
    if build.parse::<u32>().map(|b| b >= 22000).unwrap_or(false) {
        product = product.replace("Windows 10", "Windows 11");
    }
    (product, build)
}

/// `26200.7462` from `CurrentBuildNumber` + `UBR` (update build revision);
/// just the build when the revision is not available.
pub fn format_full_build(build: &str, ubr: Option<u32>) -> String {
    let build = build.trim();
    match ubr {
        Some(rev) if !build.is_empty() && build.chars().all(|c| c.is_ascii_digit()) => {
            format!("{build}.{rev}")
        }
        _ => build.to_string(),
    }
}

/// v0.4.0 footer / manifest: ("Windows 11 Pro", "26200.7462"). The plain
/// build of `windows_edition_and_build` stays unchanged for its other users.
pub fn windows_edition_and_full_build() -> (String, String) {
    let (product, build) = windows_edition_and_build();
    let full = format_full_build(&build, imp::current_version_dword("UBR"));
    (product, full)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_build_joins_build_and_update_revision() {
        assert_eq!(format_full_build("26200", Some(7462)), "26200.7462");
        assert_eq!(format_full_build(" 19045 ", Some(0)), "19045.0");
        // No revision / no build / unexpected build text: unchanged.
        assert_eq!(format_full_build("26200", None), "26200");
        assert_eq!(format_full_build("", Some(7462)), "");
        assert_eq!(format_full_build("26200.1", Some(5)), "26200.1");
    }
}
