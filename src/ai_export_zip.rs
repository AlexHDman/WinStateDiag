//! Single-entry Deflate ZIP for the existing AI text generator. No report-sized buffers.
use super::*;
use std::io::{self, BufReader};

/// Only paths created with create_new by this export are ever cleaned up.
struct Pending {
    path: PathBuf,
    file: Option<File>,
    cleanup: bool,
}
impl Pending {
    fn new(directory: &Path, kind: &str) -> Result<Self, String> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        for _ in 0..100 {
            let path = directory.join(format!(
                ".wsd-ai-{}-{stamp}-{}-{kind}.partial",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(file) => {
                    return Ok(Self {
                        path,
                        file: Some(file),
                        cleanup: true,
                    });
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => {
                    return Err(bad(format!("временный файл {}: {e}", path.display())));
                }
            }
        }
        Err(bad("не удалось создать уникальный временный файл"))
    }
    fn file(&mut self) -> &mut File {
        self.file.as_mut().expect("owned pending file")
    }
}
impl Drop for Pending {
    fn drop(&mut self) {
        drop(self.file.take());
        // No globbing, directory cleanup, or deletion of a user-visible TXT/ZIP.
        if self.cleanup {
            let _ = fs::remove_file(&self.path);
        }
    }
}
fn number32(n: u64) -> io::Result<u32> {
    u32::try_from(n).map_err(|_| io::Error::other("AI ZIP exceeds ZIP32 limits"))
}
fn word(out: &mut impl Write, n: u16) -> io::Result<()> {
    out.write_all(&n.to_le_bytes())
}
fn dword(out: &mut impl Write, n: u32) -> io::Result<()> {
    out.write_all(&n.to_le_bytes())
}

/// Finishes the Deflate stream, patches the local header, then writes the central
/// directory and EOCD. The caller flushes/closes/verifies before publication.
fn write_zip(text: &mut impl Read, zip: &mut (impl Write + Seek), name: &str) -> io::Result<()> {
    let nl = u16::try_from(name.len()).map_err(io::Error::other)?;
    dword(zip, 0x04034b50)?;
    for n in [20, 0x800, 8, 0, 33] {
        word(zip, n)?;
    } // UTF-8, Deflate, 1980-01-01
    for _ in 0..3 {
        dword(zip, 0)?;
    }
    word(zip, nl)?;
    word(zip, 0)?;
    zip.write_all(name.as_bytes())?;
    let data_start = zip.stream_position()?;
    let mut crc = flate2::Crc::new();
    let mut size = 0u64;
    {
        let mut deflate =
            flate2::write::DeflateEncoder::new(&mut *zip, flate2::Compression::default());
        let mut buf = [0u8; 64 * 1024];
        loop {
            let n = text.read(&mut buf)?;
            if n == 0 {
                break;
            }
            size += n as u64;
            number32(size)?;
            crc.update(&buf[..n]);
            deflate.write_all(&buf[..n])?;
        }
        deflate.finish()?;
    }
    let cd_offset = zip.stream_position()?;
    let compressed = number32(cd_offset - data_start)?;
    let size = number32(size)?;
    zip.seek(SeekFrom::Start(14))?;
    for n in [crc.sum(), compressed, size] {
        dword(zip, n)?;
    }
    zip.seek(SeekFrom::Start(cd_offset))?;
    dword(zip, 0x02014b50)?;
    for n in [20, 20, 0x800, 8, 0, 33] {
        word(zip, n)?;
    }
    for n in [crc.sum(), compressed, size] {
        dword(zip, n)?;
    }
    for n in [nl, 0, 0, 0, 0] {
        word(zip, n)?;
    }
    dword(zip, 0)?;
    dword(zip, 0)?;
    zip.write_all(name.as_bytes())?;
    let cd_size = number32(zip.stream_position()? - cd_offset)?;
    dword(zip, 0x06054b50)?;
    for n in [0, 0, 1, 1] {
        word(zip, n)?;
    }
    dword(zip, cd_size)?;
    dword(zip, number32(cd_offset)?)?;
    word(zip, 0)?;
    zip.flush()
}

/// Read back the closed archive, check its directory/CRC/Deflate boundaries,
/// and compare every decompressed byte with the generator's UTF-8 file.
fn verify(zip_path: &Path, expected: &mut File, name: &str) -> Result<(), String> {
    let mut zip = File::open(zip_path).map_err(bad)?;
    let entries = zip_index(&mut zip)?;
    let e = entries.first().ok_or_else(|| bad("пустой AI ZIP"))?;
    if entries.len() != 1
        || e.name != name
        || e.method != 8
        || e.skip.is_some()
        || e.size != expected.metadata().map_err(bad)?.len()
    {
        return Err(bad("проверка состава AI ZIP не пройдена"));
    }
    zip.seek(SeekFrom::Start(0)).map_err(bad)?;
    let mut local = [0u8; 30];
    zip.read_exact(&mut local).map_err(bad)?;
    if u16b(&local, 6)? != 0x800
        || u32b(&local, 14)? != e.crc
        || u32b(&local, 18)? as u64 != e.compressed
        || u32b(&local, 22)? as u64 != e.size
    {
        return Err(bad("AI ZIP: несовпадение локального заголовка"));
    }
    zip.seek(SeekFrom::Start(e.offset)).map_err(bad)?;
    expected.rewind().map_err(bad)?;
    let mut decoder = flate2::bufread::DeflateDecoder::new(BufReader::new(zip.take(e.compressed)));
    let mut actual = [0u8; 64 * 1024];
    let mut reference = [0u8; 64 * 1024];
    let mut crc = flate2::Crc::new();
    let mut count = 0u64;
    loop {
        let n = decoder.read(&mut actual).map_err(bad)?;
        if n == 0 {
            break;
        }
        count += n as u64;
        if count > e.size {
            return Err(bad("AI ZIP: лишние распакованные данные"));
        }
        expected.read_exact(&mut reference[..n]).map_err(bad)?;
        if actual[..n] != reference[..n] {
            return Err(bad("AI ZIP: TXT не совпал с генератором"));
        }
        crc.update(&actual[..n]);
    }
    if count != e.size || crc.sum() != e.crc || decoder.total_in() != e.compressed {
        return Err(bad("AI ZIP: не совпали CRC, размер или конец Deflate"));
    }
    Ok(())
}

pub(super) fn export(input: &Input, destination: &Path) -> Result<Outcome, String> {
    let base: String = input
        .base
        .chars()
        .map(|c| {
            if c.is_control() || "<>:\"/\\|?*".contains(c) {
                '_'
            } else {
                c
            }
        })
        .take(160)
        .collect();
    let base = base.trim_matches([' ', '.', '-', '_']);
    if base.is_empty() {
        return Err(bad("невозможно определить имя исходного отчёта"));
    }
    let materials = prepare(input)?;
    fs::create_dir_all(destination).map_err(bad)?;
    let mut body = Pending::new(destination, "body")?;
    let mut text = Pending::new(destination, "text")?;
    let stats = generate_text(materials, body.file(), text.file())?;
    text.file().sync_all().map_err(bad)?;
    let text_bytes = text.file().metadata().map_err(bad)?.len();
    drop(body);
    for index in 1..10000 {
        let suffix = if index == 1 {
            String::new()
        } else {
            format!(" ({index})")
        };
        let stem = format!("{base}{suffix}.AI");
        let path = destination.join(format!("{stem}.zip"));
        if path.try_exists().map_err(bad)? {
            continue;
        }
        let name = format!("{stem}.txt");
        let mut pending = Pending::new(destination, "zip")?;
        text.file().rewind().map_err(bad)?;
        write_zip(text.file(), pending.file(), &name)
            .map_err(|e| bad(format!("сжатие/закрытие ZIP: {e}")))?;
        pending.file().sync_all().map_err(bad)?;
        let zip_bytes = pending.file().metadata().map_err(bad)?.len();
        drop(pending.file.take());
        verify(&pending.path, text.file(), &name)?;
        match crate::report_package::rename_archive(&pending.path, &path, false) {
            Ok(()) => {
                pending.cleanup = false;
                return Ok(Outcome {
                    path,
                    included: stats.included,
                    omitted: stats.omitted,
                    limited: stats.limited,
                    masked: stats.masked,
                    incomplete: stats.incomplete,
                    text_bytes,
                    zip_bytes,
                });
            }
            Err(e)
                if e.kind() == io::ErrorKind::AlreadyExists
                    || path.try_exists().unwrap_or(false) =>
            {
                continue;
            }
            Err(e) => return Err(bad(format!("публикация {}: {e}", path.display()))),
        }
    }
    Err(bad("слишком много повторных экспортов"))
}

#[cfg(test)]
#[path = "ai_export_zip_tests.rs"]
mod tests;
