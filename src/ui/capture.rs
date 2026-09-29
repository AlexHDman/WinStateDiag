//! VISUAL_REFERENCE mode (developer/QA only): renders the dashboard at one
//! deterministic logical size with pixels_per_point forced to 1.0, captures
//! the real framebuffer through egui's own screenshot command and writes a
//! PNG + metadata next to it. Enabled only by the `--visual-reference`
//! command-line flag; never active in a normal launch.

use super::tokens::{CANVAS_H, CANVAS_W};
use std::path::PathBuf;

pub struct ReferenceMode {
    pub capture_path: Option<PathBuf>,
    frames: u32,
    stable_frames: u32,
    requested: bool,
    pub finished: bool,
    size_sent: bool,
}

impl ReferenceMode {
    /// Parses `--visual-reference [--capture <path.png>]`.
    pub fn from_args() -> Option<Self> {
        let args: Vec<String> = std::env::args().collect();
        if !args.iter().any(|a| a == "--visual-reference") {
            return None;
        }
        let capture_path = args
            .iter()
            .position(|a| a == "--capture")
            .and_then(|i| args.get(i + 1))
            .map(PathBuf::from);
        Some(Self {
            capture_path,
            frames: 0,
            stable_frames: 0,
            requested: false,
            finished: false,
            size_sent: false,
        })
    }

    /// Call once per frame (before painting). Forces ppp = 1.0 and a
    /// physical client size of CANVAS_W x CANVAS_H, then requests the
    /// screenshot after the geometry has been stable for a few frames.
    pub fn drive(&mut self, ctx: &egui::Context) {
        self.frames += 1;
        let native = ctx.native_pixels_per_point().unwrap_or(1.0);
        let zoom = 1.0 / native;
        if (ctx.zoom_factor() - zoom).abs() > 1e-4 {
            ctx.set_zoom_factor(zoom);
        }
        if !self.size_sent {
            ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(egui::vec2(
                CANVAS_W / native,
                CANVAS_H / native,
            )));
            ctx.send_viewport_cmd(egui::ViewportCommand::Resizable(false));
            self.size_sent = true;
        }
        let rect = ctx.content_rect();
        let ok = (ctx.pixels_per_point() - 1.0).abs() < 1e-3
            && (rect.width() - CANVAS_W).abs() < 0.5
            && (rect.height() - CANVAS_H).abs() < 0.5;
        self.stable_frames = if ok { self.stable_frames + 1 } else { 0 };
        let give_up = self.frames > 120;
        if self.capture_path.is_some() && !self.requested && (self.stable_frames >= 4 || give_up) {
            ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot(egui::UserData::default()));
            self.requested = true;
        }
        if self.requested && !self.finished {
            let shot = ctx.input(|i| {
                i.events.iter().find_map(|e| match e {
                    egui::Event::Screenshot { image, .. } => Some(image.clone()),
                    _ => None,
                })
            });
            if let Some(image) = shot {
                if let Some(path) = &self.capture_path {
                    let [w, h] = image.size;
                    let mut rgba = Vec::with_capacity(w * h * 4);
                    for px in &image.pixels {
                        rgba.extend_from_slice(&[px.r(), px.g(), px.b(), 255]);
                    }
                    let _ = std::fs::write(path, encode_png(w as u32, h as u32, &rgba));
                    let meta = format!(
                        "{{\n  \"image_px\": [{w}, {h}],\n  \"canvas_points\": [{CANVAS_W}, {CANVAS_H}],\n  \"content_rect_points\": [{:.2}, {:.2}],\n  \"native_pixels_per_point\": {native:.4},\n  \"egui_zoom_factor\": {:.4},\n  \"pixels_per_point\": {:.4},\n  \"frames_until_capture\": {}\n}}\n",
                        rect.width(),
                        rect.height(),
                        ctx.zoom_factor(),
                        ctx.pixels_per_point(),
                        self.frames
                    );
                    let _ = std::fs::write(path.with_extension("json"), meta);
                }
                self.finished = true;
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
        }
        ctx.request_repaint();
    }
}

// ---------------------------------------------------------------------------
// Minimal dependency-free PNG encoder (RGBA8, stored deflate blocks).
// ---------------------------------------------------------------------------

fn crc32(data: &[u8]) -> u32 {
    let mut table = [0u32; 256];
    for (i, slot) in table.iter_mut().enumerate() {
        let mut c = i as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
        }
        *slot = c;
    }
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc = table[((crc ^ b as u32) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc ^ 0xFFFF_FFFF
}

fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for &x in data {
        a = (a + x as u32) % 65_521;
        b = (b + a) % 65_521;
    }
    (b << 16) | a
}

fn chunk(out: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    let mut body = Vec::with_capacity(4 + data.len());
    body.extend_from_slice(kind);
    body.extend_from_slice(data);
    out.extend_from_slice(&body);
    out.extend_from_slice(&crc32(&body).to_be_bytes());
}

pub fn encode_png(width: u32, height: u32, rgba: &[u8]) -> Vec<u8> {
    let stride = width as usize * 4;
    let mut raw = Vec::with_capacity((stride + 1) * height as usize);
    for row in rgba.chunks(stride).take(height as usize) {
        raw.push(0); // filter: none
        raw.extend_from_slice(row);
    }
    let mut z = vec![0x78, 0x01];
    let mut blocks = raw.chunks(65_535).peekable();
    while let Some(block) = blocks.next() {
        let last = blocks.peek().is_none();
        z.push(if last { 1 } else { 0 });
        let len = block.len() as u16;
        z.extend_from_slice(&len.to_le_bytes());
        z.extend_from_slice(&(!len).to_le_bytes());
        z.extend_from_slice(block);
    }
    z.extend_from_slice(&adler32(&raw).to_be_bytes());

    let mut out = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&width.to_be_bytes());
    ihdr.extend_from_slice(&height.to_be_bytes());
    ihdr.extend_from_slice(&[8, 6, 0, 0, 0]); // 8-bit RGBA
    chunk(&mut out, b"IHDR", &ihdr);
    chunk(&mut out, b"IDAT", &z);
    chunk(&mut out, b"IEND", &[]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn png_has_signature_and_iend() {
        let png = encode_png(2, 2, &[255u8; 16]);
        assert_eq!(&png[..8], &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]);
        assert_eq!(&png[png.len() - 8..png.len() - 4], b"IEND");
    }

    #[test]
    fn crc32_matches_known_vector() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }
}
