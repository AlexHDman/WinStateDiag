//! v1.0 standard Windows "Save As" dialog for the Details windows
//! (`GetSaveFileNameW`, comdlg32). Saves only what the caller passes — the
//! current module's text — never the global journal.

use std::path::{Path, PathBuf};

/// Result of one Save As interaction.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(any(not(windows), test), allow(dead_code))]
pub enum SavePick {
    /// The user chose this file.
    Path(PathBuf),
    /// The user closed the dialog without choosing.
    Cancelled,
    /// The dialog could not be shown (no Windows dialog available).
    Unavailable,
}

/// Shows the modal Save As dialog: initial folder `dir`, proposed
/// `file_name`, filter "Text (*.txt)". Blocks the calling (UI) thread while
/// open, exactly like any native modal dialog.
pub fn save_as(dir: &Path, file_name: &str, title: &str) -> SavePick {
    #[cfg(all(windows, not(test)))]
    {
        imp::save_as(dir, file_name, title)
    }
    #[cfg(any(not(windows), test))]
    {
        let _ = (dir, file_name, title);
        SavePick::Unavailable
    }
}

#[cfg(all(windows, not(test)))]
mod imp {
    use super::SavePick;
    use std::os::windows::ffi::OsStrExt;
    use std::path::{Path, PathBuf};

    #[repr(C)]
    #[allow(non_snake_case)]
    struct OpenFileNameW {
        lStructSize: u32,
        hwndOwner: isize,
        hInstance: isize,
        lpstrFilter: *const u16,
        lpstrCustomFilter: *mut u16,
        nMaxCustFilter: u32,
        nFilterIndex: u32,
        lpstrFile: *mut u16,
        nMaxFile: u32,
        lpstrFileTitle: *mut u16,
        nMaxFileTitle: u32,
        lpstrInitialDir: *const u16,
        lpstrTitle: *const u16,
        Flags: u32,
        nFileOffset: u16,
        nFileExtension: u16,
        lpstrDefExt: *const u16,
        lCustData: isize,
        lpfnHook: *const std::ffi::c_void,
        lpTemplateName: *const u16,
        pvReserved: *const std::ffi::c_void,
        dwReserved: u32,
        FlagsEx: u32,
    }

    const OFN_OVERWRITEPROMPT: u32 = 0x0000_0002;
    const OFN_HIDEREADONLY: u32 = 0x0000_0004;
    const OFN_NOCHANGEDIR: u32 = 0x0000_0008;
    const OFN_PATHMUSTEXIST: u32 = 0x0000_0800;
    const OFN_EXPLORER: u32 = 0x0008_0000;

    #[link(name = "comdlg32")]
    unsafe extern "system" {
        fn GetSaveFileNameW(ofn: *mut OpenFileNameW) -> i32;
        fn CommDlgExtendedError() -> u32;
    }
    #[link(name = "user32")]
    unsafe extern "system" {
        fn GetActiveWindow() -> isize;
    }

    fn wide(s: &str) -> Vec<u16> {
        std::ffi::OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    pub fn save_as(dir: &Path, file_name: &str, title: &str) -> SavePick {
        let _ = std::fs::create_dir_all(dir);
        let mut buf = vec![0u16; 1024];
        for (i, c) in file_name.encode_utf16().take(1000).enumerate() {
            buf[i] = c;
        }
        // "Text (*.txt)\0*.txt\0All files (*.*)\0*.*\0\0"
        let filter: Vec<u16> = "Text (*.txt)\0*.txt\0All files (*.*)\0*.*\0\0"
            .encode_utf16()
            .collect();
        let initial: Vec<u16> = dir
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let title_w = wide(title);
        let ext = wide("txt");
        let mut ofn = OpenFileNameW {
            lStructSize: std::mem::size_of::<OpenFileNameW>() as u32,
            hwndOwner: unsafe { GetActiveWindow() },
            hInstance: 0,
            lpstrFilter: filter.as_ptr(),
            lpstrCustomFilter: std::ptr::null_mut(),
            nMaxCustFilter: 0,
            nFilterIndex: 1,
            lpstrFile: buf.as_mut_ptr(),
            nMaxFile: buf.len() as u32,
            lpstrFileTitle: std::ptr::null_mut(),
            nMaxFileTitle: 0,
            lpstrInitialDir: initial.as_ptr(),
            lpstrTitle: title_w.as_ptr(),
            Flags: OFN_OVERWRITEPROMPT
                | OFN_HIDEREADONLY
                | OFN_NOCHANGEDIR
                | OFN_PATHMUSTEXIST
                | OFN_EXPLORER,
            nFileOffset: 0,
            nFileExtension: 0,
            lpstrDefExt: ext.as_ptr(),
            lCustData: 0,
            lpfnHook: std::ptr::null(),
            lpTemplateName: std::ptr::null(),
            pvReserved: std::ptr::null(),
            dwReserved: 0,
            FlagsEx: 0,
        };
        // SAFETY: every pointer refers to a live, NUL-terminated buffer
        // owned by this frame for the whole (modal) call.
        let ok = unsafe { GetSaveFileNameW(&mut ofn) };
        if ok != 0 {
            let len = buf.iter().position(|c| *c == 0).unwrap_or(buf.len());
            return SavePick::Path(PathBuf::from(String::from_utf16_lossy(&buf[..len])));
        }
        if unsafe { CommDlgExtendedError() } == 0 {
            SavePick::Cancelled
        } else {
            SavePick::Unavailable
        }
    }
}

/// Writes `text` as UTF-8 with BOM (Notepad-friendly) to `path`.
pub fn write_text(path: &Path, text: &str) -> Result<PathBuf, String> {
    let mut bytes = vec![0xEF, 0xBB, 0xBF];
    bytes.extend_from_slice(text.replace("\r\n", "\n").replace('\n', "\r\n").as_bytes());
    std::fs::write(path, bytes)
        .map(|_| path.to_path_buf())
        .map_err(|e| format!("{e} — {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tests_never_open_a_modal_dialog_and_write_text_is_utf8_bom_crlf() {
        assert_eq!(
            save_as(Path::new("C:\\"), "x.txt", "t"),
            SavePick::Unavailable
        );
        let dir = std::env::temp_dir().join(format!("wsd_dlg_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("a.txt");
        write_text(&p, "Строка 1\nline 2").unwrap();
        let b = std::fs::read(&p).unwrap();
        assert!(b.starts_with(&[0xEF, 0xBB, 0xBF]));
        assert!(String::from_utf8(b[3..].to_vec()).unwrap() == "Строка 1\r\nline 2");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
