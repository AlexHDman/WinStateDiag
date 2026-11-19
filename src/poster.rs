//! Local memory-DC renderer; never opens a desktop window or calls an AI service.
use crate::report_facts::Facts;
use std::{
    ffi::c_void,
    io::Write,
    path::{Path, PathBuf},
    ptr,
};
#[derive(Clone)]
pub struct Poster {
    pub path: PathBuf,
    pub width: u32,
    pub height: u32,
    pub rgba: Vec<u8>,
}
#[repr(C)]
struct BitmapInfo {
    size: u32,
    width: i32,
    height: i32,
    planes: u16,
    bits: u16,
    compression: u32,
    image_size: u32,
    xppm: i32,
    yppm: i32,
    colors: u32,
    important: u32,
}
#[repr(C)]
struct Rect {
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
}
#[repr(C)]
struct Point {
    x: i32,
    y: i32,
}
fn line_height(size: i32) -> i32 {
    (size * 14 + 9) / 10
}

#[link(name = "gdi32")]
unsafe extern "system" {
    fn CreateCompatibleDC(h: isize) -> isize;
    fn DeleteDC(h: isize) -> i32;
    fn CreateDIBSection(
        h: isize,
        info: *const BitmapInfo,
        usage: u32,
        bits: *mut *mut c_void,
        section: isize,
        offset: u32,
    ) -> isize;
    fn SelectObject(h: isize, obj: isize) -> isize;
    fn DeleteObject(h: isize) -> i32;
    fn CreateFontW(
        height: i32,
        width: i32,
        esc: i32,
        orientation: i32,
        weight: i32,
        italic: u32,
        underline: u32,
        strike: u32,
        charset: u32,
        out_precision: u32,
        clip: u32,
        quality: u32,
        family: u32,
        face: *const u16,
    ) -> isize;
    fn SetTextColor(h: isize, color: u32) -> u32;
    fn SetBkMode(h: isize, mode: i32) -> i32;
    fn GdiFlush() -> i32;
    fn GetTextExtentPoint32W(h: isize, text: *const u16, len: i32, size: *mut Point) -> i32;
    fn CreatePen(style: i32, width: i32, color: u32) -> isize;
    fn Polyline(h: isize, points: *const Point, count: i32) -> i32;
}
#[link(name = "user32")]
unsafe extern "system" {
    fn DrawTextW(h: isize, text: *const u16, count: i32, rect: *mut Rect, format: u32) -> i32;
}
mod layout;
use layout::{Report, render_dark, render_light};

struct Canvas {
    dc: isize,
    bitmap: isize,
    old: isize,
    bits: *mut u8,
    w: usize,
    h: usize,
    scale: i32,
    fonts: std::collections::BTreeMap<(i32, bool), isize>,
}
impl Drop for Canvas {
    fn drop(&mut self) {
        unsafe {
            SelectObject(self.dc, self.old);
            DeleteObject(self.bitmap);
            for font in self.fonts.values() {
                DeleteObject(*font);
            }
            DeleteDC(self.dc);
        }
    }
}
fn rgb(c: u32) -> u32 {
    ((c >> 16) & 255) | (c & 0xff00) | ((c & 255) << 16)
}
impl Canvas {
    fn new(width: i32, height: i32, scale: i32, background: u32) -> Result<Self, String> {
        let (w, h) = ((width * scale) as usize, (height * scale) as usize);
        unsafe {
            let dc = CreateCompatibleDC(0);
            if dc == 0 {
                return Err("Не удалось подготовить PNG".into());
            }
            let info = BitmapInfo {
                size: 40,
                width: w as i32,
                height: -(h as i32),
                planes: 1,
                bits: 32,
                compression: 0,
                image_size: (w * h * 4) as u32,
                xppm: 3780,
                yppm: 3780,
                colors: 0,
                important: 0,
            };
            let mut bits = ptr::null_mut();
            let bitmap = CreateDIBSection(dc, &info, 0, &mut bits, 0, 0);
            if bitmap == 0 || bits.is_null() {
                DeleteDC(dc);
                return Err("Недостаточно памяти для PNG".into());
            }
            let old = SelectObject(dc, bitmap);
            let mut c = Self {
                dc,
                bitmap,
                old,
                bits: bits.cast(),
                w,
                h,
                scale,
                fonts: Default::default(),
            };
            c.fill(0, 0, width, height, background);
            Ok(c)
        }
    }
    fn fill(&mut self, x: i32, y: i32, w: i32, h: i32, color: u32) {
        let scale = self.scale as usize;
        let x0 = x.max(0) as usize * scale;
        let y0 = y.max(0) as usize * scale;
        let x1 = ((x + w).max(0) as usize * scale).min(self.w);
        let y1 = ((y + h).max(0) as usize * scale).min(self.h);
        if x1 <= x0 || y1 <= y0 {
            return;
        }
        unsafe {
            GdiFlush();
        }
        let bgra = color | 0xff00_0000;
        for yy in y0..y1 {
            unsafe {
                std::slice::from_raw_parts_mut(
                    self.bits.cast::<u32>().add(yy * self.w + x0),
                    x1 - x0,
                )
                .fill(bgra);
            }
        }
    }
    fn panel(&mut self, [x, y, w, h]: [i32; 4], border: u32, fill: u32) {
        self.fill(x, y, w, h, border);
        self.fill(x + 1, y + 1, w - 2, h - 2, fill);
    }
    fn panel_edges(&mut self, [x, y, w, h]: [i32; 4], color: u32) {
        self.stroke(
            &[
                [x + 11, y],
                [x + w - 11, y],
                [x + w, y + 11],
                [x + w, y + h - 11],
                [x + w - 11, y + h],
                [x + 11, y + h],
                [x, y + h - 11],
                [x, y + 11],
                [x + 11, y],
            ],
            1,
            color,
        );
    }
    fn stroke(&mut self, points: &[[i32; 2]], width: i32, color: u32) {
        if points.len() < 2 {
            return;
        }
        let scaled: Vec<_> = points
            .iter()
            .map(|[x, y]| Point {
                x: x * self.scale,
                y: y * self.scale,
            })
            .collect();
        unsafe {
            let pen = CreatePen(0, width * self.scale, rgb(color));
            if pen == 0 {
                return;
            }
            let prior = SelectObject(self.dc, pen);
            Polyline(self.dc, scaled.as_ptr(), scaled.len() as i32);
            SelectObject(self.dc, prior);
            DeleteObject(pen);
        }
    }
    fn logo(&mut self, x: i32, y: i32, width: i32) {
        use crate::ui::dashboard::{EXPC_HEADER_LOGO_DIM, EXPC_HEADER_LOGO_RGBA};
        let [sw, sh] = EXPC_HEADER_LOGO_DIM;
        let width = (width * self.scale) as usize;
        let height = width * sh / sw;
        let (x, y) = ((x * self.scale) as usize, (y * self.scale) as usize);
        unsafe {
            GdiFlush();
        }
        for yy in 0..height.min(self.h.saturating_sub(y)) {
            for xx in 0..width.min(self.w.saturating_sub(x)) {
                let i = (yy * sh / height * sw + xx * sw / width) * 4;
                let alpha = u32::from(EXPC_HEADER_LOGO_RGBA[i + 3]);
                if alpha == 0 {
                    continue;
                }
                unsafe {
                    let pixel = self.bits.add(((yy + y) * self.w + xx + x) * 4);
                    for (target, source) in [2, 1, 0].into_iter().enumerate() {
                        let background = u32::from(*pixel.add(target));
                        let foreground = u32::from(EXPC_HEADER_LOGO_RGBA[i + source]);
                        *pixel.add(target) =
                            ((foreground * alpha + background * (255 - alpha) + 127) / 255) as u8;
                    }
                }
            }
        }
    }
    fn select_font(&mut self, size: i32, bold: bool) -> isize {
        let font = *self.fonts.entry((size, bold)).or_insert_with(|| {
            let face: Vec<u16> = "Segoe UI\0".encode_utf16().collect();
            unsafe {
                CreateFontW(
                    -size * self.scale,
                    0,
                    0,
                    0,
                    if bold { 700 } else { 400 },
                    0,
                    0,
                    0,
                    1,
                    0,
                    0,
                    4,
                    0,
                    face.as_ptr(),
                )
            }
        });
        unsafe { SelectObject(self.dc, font) }
    }
    fn lines(&mut self, text: &str, width: i32, size: i32, bold: bool) -> Vec<String> {
        let prior = self.select_font(size, bold);
        let fits = |str: &str| unsafe {
            let utf16: Vec<u16> = str.encode_utf16().collect();
            let mut measured = Point { x: 0, y: 0 };
            GetTextExtentPoint32W(self.dc, utf16.as_ptr(), utf16.len() as i32, &mut measured);
            measured.x <= width * self.scale
        };
        let mut lines = Vec::new();
        for paragraph in text.lines() {
            let mut line = String::new();
            for word in paragraph.split_whitespace() {
                let candidate = if line.is_empty() {
                    word.to_owned()
                } else {
                    format!("{line} {word}")
                };
                if fits(&candidate) {
                    line = candidate;
                    continue;
                }
                if !line.is_empty() {
                    lines.push(std::mem::take(&mut line));
                }
                if fits(word) {
                    line.push_str(word);
                } else {
                    for ch in word.chars() {
                        line.push(ch);
                        if !fits(&line) && line.chars().count() > 1 {
                            line.pop();
                            lines.push(std::mem::take(&mut line));
                            line.push(ch);
                        }
                    }
                }
            }
            lines.push(line);
        }
        unsafe {
            SelectObject(self.dc, prior);
        }
        lines
    }
    fn text(&mut self, text: &str, rect: [i32; 4], size: i32, color: u32, bold: bool) {
        let [x, y, w, h] = rect.map(|v| v * self.scale);
        let prior = self.select_font(size, bold);
        let chars: Vec<u16> = text.encode_utf16().collect();
        let mut rect = Rect {
            left: x,
            top: y,
            right: x + w,
            bottom: y + h,
        };
        unsafe {
            SetTextColor(self.dc, rgb(color));
            SetBkMode(self.dc, 1);
            DrawTextW(
                self.dc,
                chars.as_ptr(),
                chars.len() as i32,
                &mut rect,
                0x20 | 0x800,
            );
            SelectObject(self.dc, prior);
        }
    }
    fn draw_lines(
        &mut self,
        lines: &[String],
        [x, y, w]: [i32; 3],
        size: i32,
        color: u32,
        bold: bool,
    ) -> i32 {
        let step = line_height(size);
        for (i, line) in lines.iter().enumerate() {
            self.text(line, [x, y + step * i as i32, w, step], size, color, bold);
        }
        step * lines.len() as i32
    }
    fn finish(self) -> Vec<u8> {
        unsafe {
            GdiFlush();
        }
        let mut rgba = vec![0u8; self.w * self.h * 4];
        for (i, p) in rgba.as_chunks_mut::<4>().0.iter_mut().enumerate() {
            unsafe {
                let src = self.bits.add(i * 4);
                p.copy_from_slice(&[*src.add(2), *src.add(1), *src, 255]);
            }
        }
        rgba
    }
}
fn safe(s: &str) -> String {
    let user = std::env::var("USERNAME").unwrap_or_default();
    crate::ai_export::analysis_mask(s, &[user]).unwrap_or_else(|_| "[Сведения скрыты]".into())
}
fn display(s: &str) -> String {
    if s.trim().is_empty() {
        "Нет данных".into()
    } else {
        safe(s)
    }
}
fn crc(bytes: &[u8]) -> u32 {
    let mut c = !0u32;
    for b in bytes {
        c ^= u32::from(*b);
        for _ in 0..8 {
            c = (c >> 1) ^ if c & 1 != 0 { 0xedb88320 } else { 0 };
        }
    }
    !c
}
fn png(w: u32, h: u32, rgba: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = b"\x89PNG\r\n\x1a\n".to_vec();
    fn chunk(out: &mut Vec<u8>, kind: &[u8; 4], b: &[u8]) {
        out.extend_from_slice(&(b.len() as u32).to_be_bytes());
        out.extend_from_slice(kind);
        out.extend_from_slice(b);
        let mut all = kind.to_vec();
        all.extend_from_slice(b);
        out.extend_from_slice(&crc(&all).to_be_bytes());
    }
    let mut header = w.to_be_bytes().to_vec();
    header.extend_from_slice(&h.to_be_bytes());
    header.extend_from_slice(&[8, 6, 0, 0, 0]);
    chunk(&mut out, b"IHDR", &header);
    let mut z = flate2::write::ZlibEncoder::new(vec![], flate2::Compression::default());
    for row in rgba.chunks_exact(w as usize * 4) {
        z.write_all(&[0])
            .and_then(|_| z.write_all(row))
            .map_err(|_| "Ошибка кодирования PNG")?;
    }
    chunk(&mut out, b"IDAT", &z.finish().map_err(|_| "Ошибка PNG")?);
    chunk(&mut out, b"IEND", &[]);
    Ok(out)
}
fn unique_write(dir: &Path, stem: &str, ext: &str, bytes: &[u8]) -> Result<PathBuf, String> {
    for i in 0..10000 {
        let suffix = if i == 0 {
            String::new()
        } else {
            format!(" ({i})")
        };
        let path = dir.join(format!("{stem}{suffix}.{ext}"));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut f) => {
                f.write_all(bytes)
                    .and_then(|_| f.sync_all())
                    .map_err(|_| "Не удалось записать PNG; частичный файл сохранён")?;
                return Ok(path);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err("Не удалось сохранить PNG рядом с отчётом".into()),
        }
    }
    Err("Не найдено свободное имя PNG".into())
}
pub struct PosterDocument {
    pub dark: Poster,
    pub light: Vec<Poster>,
}

impl Poster {
    pub fn image(&self) -> egui::ColorImage {
        egui::ColorImage::from_rgba_unmultiplied(
            [self.width as usize, self.height as usize],
            &self.rgba,
        )
    }
    pub fn preview_image(&self, max_side: usize) -> egui::ColorImage {
        let [w, h] = [self.width as usize, self.height as usize];
        let max_side = max_side.max(1);
        let longest = w.max(h);
        if longest <= max_side {
            return self.image();
        }
        let [dw, dh] = [
            (w * max_side / longest).max(1),
            (h * max_side / longest).max(1),
        ];
        let mut pixels = Vec::with_capacity(dw * dh * 4);
        for y in 0..dh {
            for x in 0..dw {
                let pixel = (y * h / dh * w + x * w / dw) * 4;
                pixels.extend_from_slice(&self.rgba[pixel..pixel + 4]);
            }
        }
        egui::ColorImage::from_rgba_unmultiplied([dw, dh], &pixels)
    }
}

pub fn from_zip(
    source: &Path,
    cached: Option<crate::ai_analysis::Analysis>,
    ru: bool,
) -> Result<PosterDocument, String> {
    let report = read_zip(source, cached, ru)?;
    write_document(&report, source)
}

fn read_zip(
    source: &Path,
    cached: Option<crate::ai_analysis::Analysis>,
    ru: bool,
) -> Result<Report, String> {
    let archive =
        crate::ai_export::analysis_zip(source, &std::sync::atomic::AtomicBool::new(false))?;
    let analysis = cached
        .filter(|a| a.archive_sha256.as_deref() == Some(archive.sha256.as_str()))
        .or_else(|| crate::ai_analysis::saved_for_archive(source, &archive.sha256).map(|(a, _)| a));
    let facts = Facts::parse(&archive.text);
    Ok(Report::new(
        &facts,
        &archive.text,
        analysis.as_ref().map(|a| a.sections[4].as_str()),
        analysis.as_ref().map(|a| a.sections[3].as_str()),
        ru,
    ))
}
fn write_document(report: &Report, target: &Path) -> Result<PosterDocument, String> {
    let dir = target.parent().ok_or("Каталог отчёта недоступен")?;
    let stem = target
        .file_stem()
        .ok_or("Имя отчёта недоступно")?
        .to_string_lossy();
    let dark_canvas = render_dark(report)?;
    let light_pages = render_light(report)?;
    let dark = write_canvas(dark_canvas, dir, &format!("{stem}.Poster.Dark"))?;
    let light = light_pages
        .into_iter()
        .enumerate()
        .map(|(i, canvas)| {
            let name = if i == 0 {
                format!("{stem}.Poster.Light")
            } else {
                format!("{stem}.Poster.Light-{}", i + 1)
            };
            write_canvas(canvas, dir, &name)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(PosterDocument { dark, light })
}

fn write_canvas(c: Canvas, dir: &Path, name: &str) -> Result<Poster, String> {
    let (width, height) = (c.w as u32, c.h as u32);
    let rgba = c.finish();
    let bytes = png(width, height, &rgba)?;
    let path = unique_write(dir, name, "png", &bytes)?;
    Ok(Poster {
        path,
        width,
        height,
        rgba,
    })
}

#[cfg(test)]
pub fn sample_from_zip(source: &Path, evidence: &Path) -> Result<PosterDocument, String> {
    let report = read_zip(source, None, true)?;
    write_document(&report, &evidence.join("WinDiag-1.12.zip"))
}

#[cfg(test)]
pub fn create(
    facts: &Facts,
    conclusion: Option<&str>,
    source: &Path,
    ru: bool,
) -> Result<Poster, String> {
    let report = Report::new(facts, "", conclusion, None, ru);
    let dir = source.parent().ok_or("Каталог отчёта недоступен")?;
    let name = source.file_stem().unwrap_or_default().to_string_lossy();
    write_canvas(render_dark(&report)?, dir, &format!("{name}.Poster"))
}

#[repr(C)]
struct Guid(u32, u16, u16, [u8; 8]);
#[link(name = "shell32")]
unsafe extern "system" {
    fn SHGetKnownFolderPath(id: *const Guid, flags: u32, token: isize, path: *mut *mut u16) -> i32;
}
#[link(name = "ole32")]
unsafe extern "system" {
    fn CoTaskMemFree(p: *mut c_void);
}
pub fn save_desktop(p: &Poster) -> Result<PathBuf, String> {
    unsafe {
        let id = Guid(
            0xb4bfcc3a,
            0xdb2c,
            0x424c,
            [0xb0, 0x29, 0x7f, 0xe9, 0x9a, 0x87, 0xc6, 0x41],
        );
        let mut ptr = ptr::null_mut();
        if SHGetKnownFolderPath(&id, 0, 0, &mut ptr) < 0 || ptr.is_null() {
            return Err("Рабочий стол недоступен".into());
        }
        let mut len = 0;
        while len < 32768 && *ptr.add(len) != 0 {
            len += 1;
        }
        let text = String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len));
        CoTaskMemFree(ptr.cast());
        let dir = PathBuf::from(text);
        let bytes = png(p.width, p.height, &p.rgba)?;
        unique_write(
            &dir,
            &p.path.file_stem().unwrap_or_default().to_string_lossy(),
            "png",
            &bytes,
        )
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn poster_without_api_is_valid_unique_png_and_preserves_source() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target/poster-tests")
            .join(format!(
                "{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
        std::fs::create_dir_all(&dir).unwrap();
        let source = dir.join("Контроль.txt");
        std::fs::write(&source, "unchanged").unwrap();
        let f = Facts {
            computer: "ТЕСТОВЫЙ ПК".into(),
            cpu: "Intel Core i5-12600".into(),
            date: "2026-11-19".into(),
            version: "1.11".into(),
            ..Default::default()
        };
        let p = create(&f, None, &source, true).unwrap();
        let p2 = create(&f, None, &source, true).unwrap();
        assert_ne!(p.path, p2.path);
        assert_eq!(&std::fs::read(&p.path).unwrap()[..8], b"\x89PNG\r\n\x1a\n");
        assert_eq!(std::fs::read_to_string(source).unwrap(), "unchanged");
        assert_eq!(p.rgba.len(), p.width as usize * p.height as usize * 4);
        let preview = p.preview_image(512);
        assert_eq!(preview.size.iter().max(), Some(&512));
        assert!(preview.size[0] < p.width as usize);
        assert_eq!(p.image().size, [p.width as usize, p.height as usize]);
    }
}
