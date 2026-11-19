//! WinDiag-owned viewport geometry. Values are UI points with the capture scale.
use std::path::PathBuf;
#[derive(Clone, Copy, Debug)]
pub struct Geometry {
    pub x: f32,
    pub y: f32,
    pub w: f32,
    pub h: f32,
    pub scale: f32,
    pub maximized: bool,
}
impl Geometry {
    pub fn parse(s: &str) -> Option<Self> {
        let values = s
            .split_whitespace()
            .map(str::parse::<f32>)
            .collect::<Result<Vec<_>, _>>()
            .ok()?;
        if values.len() != 6 {
            return None;
        }
        let g = Self {
            x: values[0],
            y: values[1],
            w: values[2],
            h: values[3],
            scale: values[4],
            maximized: values[5] != 0.0,
        };
        (values.iter().all(|v| v.is_finite())
            && g.x.abs() < 100000.0
            && g.y.abs() < 100000.0
            && g.w >= 640.0
            && g.w <= 10000.0
            && g.h >= 480.0
            && g.h <= 10000.0
            && g.scale >= 0.25
            && g.scale <= 8.0)
            .then_some(g)
    }
    fn encode(self) -> String {
        format!(
            "{} {} {} {} {} {}",
            self.x,
            self.y,
            self.w,
            self.h,
            self.scale,
            if self.maximized { 1 } else { 0 }
        )
    }
}
fn path() -> PathBuf {
    let exe = std::env::current_exe().unwrap_or_default();
    crate::app_paths::data_root(exe.parent().unwrap_or_else(|| std::path::Path::new(".")))
        .join("PowerLab.window")
}
pub fn load() -> Option<Geometry> {
    let p = path();
    if std::fs::metadata(&p).ok()?.len() > 256 {
        return None;
    }
    Geometry::parse(&std::fs::read_to_string(p).ok()?)
}
pub fn save(g: Geometry) {
    #[cfg(not(test))]
    {
        let p = path();
        if let Some(parent) = p.parent()
            && std::fs::create_dir_all(parent).is_ok()
        {
            let _ = std::fs::write(p, g.encode());
        }
    }
    #[cfg(test)]
    {
        let _ = g;
    }
}
#[repr(C)]
struct Rect {
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
}
#[link(name = "user32")]
unsafe extern "system" {
    fn MonitorFromRect(rect: *const Rect, flags: u32) -> isize;
}
pub fn visible(g: Geometry) -> bool {
    let r = Rect {
        left: (g.x * g.scale) as i32,
        top: (g.y * g.scale) as i32,
        right: ((g.x + g.w.min(160.0)) * g.scale) as i32,
        bottom: ((g.y + 32.0) * g.scale) as i32,
    };
    unsafe { MonitorFromRect(&r, 0) != 0 }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_corrupt_placement_and_preserves_user_geometry() {
        assert!(Geometry::parse("NaN 0 800 600 1 0").is_none());
        assert!(Geometry::parse("0 0 80 60 1 0").is_none());
        let g = Geometry::parse("-1200 40 1180 880 1.25 0").unwrap();
        let h = Geometry::parse(&g.encode()).unwrap();
        assert_eq!(h.x, -1200.0);
        assert_eq!(h.w, 1180.0);
        assert!(!h.maximized);
    }
}
