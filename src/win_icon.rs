//! v1.0 crisp application icon on every WinStateDiag window.
//!
//! eframe/winit accept a single RGBA image for the window icon, which
//! Windows then shrinks from 256 px to the 16/20/24 px titlebar size (tiny
//! and blurry ruler/pencil). The EXE already carries the approved
//! multi-frame `assets\icon.ico` as icon resource 1 (winresource), with
//! purpose-made 16/24/32/48 px frames. This module loads that resource at
//! the system small/large icon sizes (`LoadImageW` picks the best frame) and
//! sets it with `WM_SETICON` on every top-level window of the UI thread —
//! the main window and each Details viewport (titlebar, taskbar, Alt+Tab).
//!
//! Read-only with respect to the system: only this process' own windows.

/// Icon resource id written by winresource (`set_icon`, id "1").
pub const ICON_RESOURCE_ID: u16 = 1;

#[cfg(windows)]
mod imp {
    use std::collections::HashSet;

    type Hwnd = isize;
    type Handle = isize;

    const IMAGE_ICON: u32 = 1;
    const LR_DEFAULTCOLOR: u32 = 0;
    const WM_SETICON: u32 = 0x0080;
    const ICON_SMALL: usize = 0;
    const ICON_BIG: usize = 1;
    const SM_CXICON: i32 = 11;
    const SM_CYICON: i32 = 12;
    const SM_CXSMICON: i32 = 49;
    const SM_CYSMICON: i32 = 50;
    const GWL_STYLE: i32 = -16;
    const WS_CAPTION: isize = 0x00C0_0000;

    #[link(name = "user32")]
    unsafe extern "system" {
        fn LoadImageW(
            hinst: Handle,
            name: *const u16,
            kind: u32,
            cx: i32,
            cy: i32,
            flags: u32,
        ) -> Handle;
        fn GetSystemMetrics(index: i32) -> i32;
        fn SendMessageW(hwnd: Hwnd, msg: u32, wparam: usize, lparam: isize) -> isize;
        fn EnumThreadWindows(
            thread: u32,
            cb: unsafe extern "system" fn(Hwnd, isize) -> i32,
            lparam: isize,
        ) -> i32;
        fn GetWindowLongPtrW(hwnd: Hwnd, index: i32) -> isize;
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetModuleHandleW(name: *const u16) -> Handle;
        fn GetCurrentThreadId() -> u32;
    }

    /// Small + big icon handles of the EXE resource (loaded once; owned for
    /// the process lifetime, never destroyed while windows use them).
    struct Icons {
        small: Handle,
        big: Handle,
    }

    fn icons() -> Option<&'static Icons> {
        static ICONS: std::sync::OnceLock<Option<Icons>> = std::sync::OnceLock::new();
        ICONS
            .get_or_init(|| unsafe {
                let module = GetModuleHandleW(std::ptr::null());
                // MAKEINTRESOURCEW(id): the integer id in the pointer value.
                let name = super::ICON_RESOURCE_ID as usize as *const u16;
                let load = |cx: i32, cy: i32| {
                    LoadImageW(
                        module,
                        name,
                        IMAGE_ICON,
                        GetSystemMetrics(cx),
                        GetSystemMetrics(cy),
                        LR_DEFAULTCOLOR,
                    )
                };
                let small = load(SM_CXSMICON, SM_CYSMICON);
                let big = load(SM_CXICON, SM_CYICON);
                (small != 0 && big != 0).then_some(Icons { small, big })
            })
            .as_ref()
    }

    unsafe extern "system" fn collect(hwnd: Hwnd, lparam: isize) -> i32 {
        // SAFETY: lparam is the &mut Vec passed by `thread_windows`.
        let list = unsafe { &mut *(lparam as *mut Vec<Hwnd>) };
        if unsafe { GetWindowLongPtrW(hwnd, GWL_STYLE) } & WS_CAPTION != 0 {
            list.push(hwnd);
        }
        1
    }

    fn thread_windows() -> Vec<Hwnd> {
        let mut list: Vec<Hwnd> = Vec::new();
        unsafe {
            EnumThreadWindows(
                GetCurrentThreadId(),
                collect,
                &mut list as *mut Vec<Hwnd> as isize,
            );
        }
        list
    }

    /// Applies the resource icon to every captioned window of the calling
    /// (UI) thread not handled yet. Cheap; call once per frame or less.
    pub fn apply(done: &mut HashSet<isize>) {
        let Some(icons) = icons() else {
            return;
        };
        for hwnd in thread_windows() {
            if done.insert(hwnd) {
                unsafe {
                    SendMessageW(hwnd, WM_SETICON, ICON_SMALL, icons.small);
                    SendMessageW(hwnd, WM_SETICON, ICON_BIG, icons.big);
                }
            }
        }
    }
}

/// Tracks which native windows already received the resource icon.
#[derive(Default)]
pub struct WindowIcons {
    #[cfg_attr(not(windows), allow(dead_code))]
    done: std::collections::HashSet<isize>,
    #[cfg_attr(not(windows), allow(dead_code))]
    last_viewports: usize,
    #[cfg_attr(not(windows), allow(dead_code))]
    frames: u32,
}

impl WindowIcons {
    /// Called from the app's frame logic. Re-scans the thread's windows on
    /// the first frames and whenever the number of viewports changes (a
    /// Details window opened), so new windows get the crisp icon at once.
    pub fn update(&mut self, viewports: usize) {
        #[cfg(windows)]
        if !cfg!(test) && (self.frames < 3 || viewports != self.last_viewports) {
            imp::apply(&mut self.done);
        }
        self.frames = self.frames.saturating_add(1);
        self.last_viewports = viewports;
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_resource_icon_is_the_approved_multi_frame_icon_ico() {
        // build.rs embeds assets\icon.ico as resource 1 (winresource
        // default id), which LoadImageW reads at the system icon sizes.
        let build = include_str!("../build.rs");
        assert!(build.contains("res.set_icon(\"assets/icon.ico\")"));
        assert_eq!(super::ICON_RESOURCE_ID, 1);
        // The small-icon frames that Windows picks exist and fill their
        // area (no tiny artwork with wide transparent padding).
        let ico: &[u8] = include_bytes!("../assets/icon.ico");
        let count = u16::from_le_bytes([ico[4], ico[5]]) as usize;
        let sizes: Vec<u32> = (0..count)
            .map(|i| {
                let w = ico[6 + 16 * i];
                if w == 0 { 256 } else { u32::from(w) }
            })
            .collect();
        for want in [16, 24, 32, 48, 256] {
            assert!(sizes.contains(&want), "icon.ico lacks {want}px: {sizes:?}");
        }
        let lib = include_str!("lib.rs");
        assert!(lib.contains("mod win_icon;"));
        let app = include_str!("app.rs");
        assert!(app.contains("self.window_icons.update("));
    }
}
