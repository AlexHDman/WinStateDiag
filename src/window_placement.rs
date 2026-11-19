//! First-launch placement in physical coordinates of the window's own monitor.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Area {
    pub left: i32,
    pub top: i32,
    pub width: i32,
    pub height: i32,
}
pub(crate) fn initial_position(work: Area, width: i32, height: i32) -> (i32, i32) {
    let axis = |origin: i32, extent: i32, size: i32| {
        let space = (extent - size).max(0);
        origin + ((space as f64 / 2.0 - extent as f64 * 0.1).round() as i32).clamp(0, space)
    };
    (
        axis(work.left, work.width, width),
        axis(work.top, work.height, height),
    )
}
#[cfg(all(windows, not(test)))]
pub(crate) fn place_own_active_window() -> bool {
    #[repr(C)]
    #[derive(Default)]
    struct Rect {
        left: i32,
        top: i32,
        right: i32,
        bottom: i32,
    }
    #[repr(C)]
    struct Info {
        size: u32,
        monitor: Rect,
        work: Rect,
        flags: u32,
    }
    #[link(name = "user32")]
    unsafe extern "system" {
        fn GetActiveWindow() -> isize;
        fn GetWindowThreadProcessId(w: isize, p: *mut u32) -> u32;
        fn GetWindowRect(w: isize, r: *mut Rect) -> i32;
        fn MonitorFromWindow(w: isize, f: u32) -> isize;
        fn GetMonitorInfoW(m: isize, i: *mut Info) -> i32;
        fn IsZoomed(w: isize) -> i32;
        fn IsIconic(w: isize) -> i32;
        fn SetWindowPos(
            w: isize,
            after: isize,
            x: i32,
            y: i32,
            cx: i32,
            cy: i32,
            flags: u32,
        ) -> i32;
    }
    // The UI thread owns the handle; never reposition another process or steal focus.
    unsafe {
        let w = GetActiveWindow();
        let mut pid = 0;
        if w == 0 {
            return false;
        }
        GetWindowThreadProcessId(w, &mut pid);
        if pid != std::process::id() {
            return false;
        }
        if IsZoomed(w) != 0 || IsIconic(w) != 0 {
            return true;
        }
        let mut rect = Rect::default();
        let mut info = Info {
            size: std::mem::size_of::<Info>() as u32,
            monitor: Rect::default(),
            work: Rect::default(),
            flags: 0,
        };
        if GetWindowRect(w, &mut rect) == 0
            || GetMonitorInfoW(MonitorFromWindow(w, 2), &mut info) == 0
        {
            return false;
        }
        let (x, y) = initial_position(
            Area {
                left: info.work.left,
                top: info.work.top,
                width: info.work.right - info.work.left,
                height: info.work.bottom - info.work.top,
            },
            rect.right - rect.left,
            rect.bottom - rect.top,
        );
        SetWindowPos(w, 0, x, y, 0, 0, 0x0001 | 0x0004 | 0x0010) != 0
    }
}
#[cfg(any(not(windows), test))]
pub(crate) fn place_own_active_window() -> bool {
    true
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn v1214_work_area_dpi_multimonitor_and_taskbar() {
        for scale in [1.0, 1.25, 1.5, 2.0] {
            for (left, top, w, h) in [
                (0, 0, 1920, 1040),
                (-2560, 0, 2560, 1400),
                (1920, -1080, 1920, 1040),
                (0, 40, 1280, 680),
            ] {
                let width = (800.0 * scale) as i32;
                let height = (500.0 * scale) as i32;
                let work = Area {
                    left,
                    top,
                    width: w,
                    height: h,
                };
                let (x, y) = initial_position(work, width, height);
                assert!(x >= left && y >= top);
                if width <= w {
                    assert!(x + width <= left + w)
                }
                if height <= h {
                    assert!(y + height <= top + h)
                }
            }
        }
        assert_eq!(
            initial_position(
                Area {
                    left: 0,
                    top: 0,
                    width: 1920,
                    height: 1040
                },
                800,
                500
            ),
            (368, 166)
        );
    }
}
