//! Print the exact pages shown in the light A4 preview.
use crate::poster::Poster;

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Printed,
    Cancelled,
}

fn after_dialog<T>(
    selection: Option<T>,
    spool: impl FnOnce(T) -> Result<(), String>,
) -> Result<Outcome, String> {
    match selection {
        Some(selection) => {
            spool(selection)?;
            Ok(Outcome::Printed)
        }
        None => Ok(Outcome::Cancelled),
    }
}

fn page_rectangle(w: i32, h: i32, dpi_x: i32, dpi_y: i32) -> Option<[i32; 4]> {
    if w <= 0 || h <= 0 || dpi_x <= 0 || dpi_y <= 0 {
        return None;
    }
    // Fit the whole sheet into printable space. Physical margins reported by
    // GDI are outside this coordinate system, and the page retains its own inset.
    let ratio = (210.0 * f64::from(dpi_x)) / (297.0 * f64::from(dpi_y));
    let (width, height) = if f64::from(w) / f64::from(h) > ratio {
        ((f64::from(h) * ratio).floor() as i32, h)
    } else {
        (w, (f64::from(w) / ratio).floor() as i32)
    };
    (width > 0 && height > 0).then_some([(w - width) / 2, (h - height) / 2, width, height])
}

#[cfg(not(test))]
pub fn print(pages: &[Poster]) -> Result<Outcome, String> {
    let selection = native::select(pages.len())?;
    after_dialog(selection, |printer| native::spool(&printer, pages))
}

#[cfg(test)]
pub fn print(_pages: &[Poster]) -> Result<Outcome, String> {
    after_dialog::<()>(None, |_| panic!("host printing in a test"))
}

#[cfg(not(test))]
mod native {
    use super::*;
    use std::mem::size_of;
    use windows_sys::Win32::{
        Foundation::GlobalFree,
        Graphics::Gdi::*,
        Storage::Xps::{AbortDoc, DOCINFOW, EndDoc, EndPage, StartDocW, StartPage},
        System::Memory::{GlobalLock, GlobalSize, GlobalUnlock},
        UI::{Controls::Dialogs::*, Input::KeyboardAndMouse::GetActiveWindow},
    };

    pub(super) struct Printer(PRINTDLGW);
    impl Drop for Printer {
        fn drop(&mut self) {
            unsafe {
                if !self.0.hDC.is_null() {
                    DeleteDC(self.0.hDC);
                }
                if !self.0.hDevMode.is_null() {
                    GlobalFree(self.0.hDevMode);
                }
                if !self.0.hDevNames.is_null() {
                    GlobalFree(self.0.hDevNames);
                }
            }
        }
    }
    pub(super) fn select(pages: usize) -> Result<Option<Printer>, String> {
        if pages == 0 {
            return Err("Нет страниц для печати".into());
        }
        let owner = unsafe { GetActiveWindow() };
        if owner.is_null() {
            return Err("Активируй окно предпросмотра перед печатью".into());
        }
        let mut default = Printer(PRINTDLGW {
            lStructSize: size_of::<PRINTDLGW>() as u32,
            Flags: PD_RETURNDEFAULT,
            ..Default::default()
        });
        if unsafe { PrintDlgW(&mut default.0) } != 0 {
            unsafe {
                let handle = default.0.hDevMode;
                if !handle.is_null() && GlobalSize(handle) >= size_of::<DEVMODEW>() {
                    let mode = GlobalLock(handle).cast::<DEVMODEW>();
                    if !mode.is_null() {
                        let devmode = &mut *mode;
                        devmode.dmFields &= !(DM_PAPERWIDTH | DM_PAPERLENGTH);
                        devmode.dmFields |= DM_ORIENTATION | DM_PAPERSIZE;
                        devmode.Anonymous1.Anonymous1.dmOrientation = DMORIENT_PORTRAIT as i16;
                        devmode.Anonymous1.Anonymous1.dmPaperSize = DMPAPER_A4 as i16;
                        GlobalUnlock(handle);
                    }
                }
            }
        }
        let mut dialog = Printer(PRINTDLGW {
            lStructSize: size_of::<PRINTDLGW>() as u32,
            hwndOwner: owner,
            hDevMode: std::mem::take(&mut default.0.hDevMode),
            hDevNames: std::mem::take(&mut default.0.hDevNames),
            Flags: PD_RETURNDC | PD_NOPAGENUMS | PD_NOSELECTION | PD_USEDEVMODECOPIESANDCOLLATE,
            nMinPage: 1,
            nMaxPage: pages as u16,
            nCopies: 1,
            ..Default::default()
        });
        if unsafe { PrintDlgW(&mut dialog.0) } == 0 {
            let error = unsafe { CommDlgExtendedError() };
            return if error == 0 {
                Ok(None)
            } else {
                Err(format!("Диалог принтера завершился с ошибкой ({error:#X})"))
            };
        }
        if dialog.0.hDC.is_null() {
            return Err("Драйвер не предоставил контекст печати".into());
        }
        Ok(Some(dialog))
    }

    pub(super) fn spool(printer: &Printer, pages: &[Poster]) -> Result<(), String> {
        let dc = printer.0.hDC;
        let [x, y, w, h] = unsafe {
            page_rectangle(
                GetDeviceCaps(dc, HORZRES as i32),
                GetDeviceCaps(dc, VERTRES as i32),
                GetDeviceCaps(dc, LOGPIXELSX as i32),
                GetDeviceCaps(dc, LOGPIXELSY as i32),
            )
        }
        .ok_or("Принтер не сообщил доступную область печати")?;
        let title: Vec<u16> = "EXPC WinDiag".encode_utf16().chain(Some(0)).collect();
        let info = DOCINFOW {
            cbSize: size_of::<DOCINFOW>() as i32,
            lpszDocName: title.as_ptr(),
            ..Default::default()
        };
        if unsafe { StartDocW(dc, &info) } <= 0 {
            return Err("Принтер не начал печать".into());
        }
        let result = (|| {
            for page in pages {
                if unsafe { StartPage(dc) } <= 0 {
                    return Err("Принтер не принял страницу".into());
                }
                let mut bgra = page.rgba.clone();
                for px in bgra.as_chunks_mut::<4>().0 {
                    px.swap(0, 2);
                }
                let paper = BITMAPINFO {
                    bmiHeader: BITMAPINFOHEADER {
                        biSize: size_of::<BITMAPINFOHEADER>() as u32,
                        biWidth: page.width as i32,
                        biHeight: -(page.height as i32),
                        biPlanes: 1,
                        biBitCount: 32,
                        biCompression: BI_RGB,
                        ..Default::default()
                    },
                    ..Default::default()
                };
                unsafe {
                    SetStretchBltMode(dc, HALFTONE);
                    SetBrushOrgEx(dc, 0, 0, std::ptr::null_mut());
                    let copied = StretchDIBits(
                        dc,
                        x,
                        y,
                        w,
                        h,
                        0,
                        0,
                        page.width as i32,
                        page.height as i32,
                        bgra.as_ptr().cast(),
                        &paper,
                        DIB_RGB_COLORS,
                        SRCCOPY,
                    );
                    if copied == 0 || copied == -1 || EndPage(dc) <= 0 {
                        return Err("Драйвер не завершил страницу".into());
                    }
                }
            }
            if unsafe { EndDoc(dc) } <= 0 {
                return Err("Драйвер не завершил задание".into());
            }
            Ok(())
        })();
        if result.is_err() {
            unsafe {
                AbortDoc(dc);
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cancelling_dialog_never_invokes_spooler() {
        assert_eq!(
            after_dialog::<()>(None, |_| panic!("cancel must not spool")),
            Ok(Outcome::Cancelled)
        );
        let mut seen = false;
        assert_eq!(
            after_dialog(Some(()), |_| {
                seen = true;
                Ok(())
            }),
            Ok(Outcome::Printed)
        );
        assert!(seen);
    }
    #[test]
    fn printable_area_preserves_a4_with_different_device_dpi() {
        for (w, h, dx, dy) in [
            (2350, 3410, 300, 300),
            (1100, 3500, 150, 300),
            (5000, 1900, 600, 300),
        ] {
            let [x, y, width, height] = page_rectangle(w, h, dx, dy).unwrap();
            assert!(x >= 0 && y >= 0 && width + x <= w && height + y <= h);
            assert!(
                ((f64::from(width) / f64::from(dx)) / (f64::from(height) / f64::from(dy))
                    - 210. / 297.)
                    .abs()
                    < 0.002
            );
        }
        assert!(page_rectangle(0, 3500, 300, 300).is_none());
    }
}
