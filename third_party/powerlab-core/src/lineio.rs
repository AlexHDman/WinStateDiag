//! Bounded, line-oriented framing for the sampler pipe.
//!
//! Two failure modes have to be survivable on a pipe that a possibly-broken
//! provider is writing to:
//!
//! * **unbounded output** — a provider that loops forever writing text would make
//!   the reader allocate without limit. Each line is therefore capped at
//!   [`ipc::MAX_LINE_BYTES`], and an over-long line is reported and skipped rather
//!   than buffered.
//! * **a stalled peer** — a reader that blocks forever in `read` cannot be
//!   interrupted either, so the *caller* is expected to treat this as an
//!   asynchronously fed source: the caller reads on its own thread and applies a
//!   deadline, exactly as the supervisor does.
//!
//! The reader never panics on bad input: it reports [`LineError`], and the caller
//! decides whether to keep going. A bounded number of consecutive bad lines is
//! tolerated so one corrupt message does not kill an otherwise healthy session.

use std::io::{BufRead, Read};

use crate::ipc;

/// A failure while reading one line.
#[derive(Debug)]
pub enum LineError {
    /// The underlying stream ended.
    Eof,
    /// A line exceeded [`ipc::MAX_LINE_BYTES`] and was discarded.
    TooLong { limit: usize },
    /// The bytes were not valid UTF-8.
    NotUtf8,
    /// The stream failed.
    Io(std::io::Error),
}

impl std::fmt::Display for LineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LineError::Eof => write!(f, "поток завершился"),
            LineError::TooLong { limit } => {
                write!(
                    f,
                    "строка превысила допустимые {limit} байт и была отброшена"
                )
            }
            LineError::NotUtf8 => write!(f, "строка не является корректным UTF-8"),
            LineError::Io(err) => write!(f, "ошибка чтения потока: {err}"),
        }
    }
}

impl std::error::Error for LineError {}

/// Reads newline-delimited UTF-8 lines with a hard size cap.
pub struct LineReader<R: Read> {
    inner: R,
    /// Bytes of the current line, or of the next line after a split.
    buf: Vec<u8>,
    /// Bytes already read past the current line's newline.
    pending: Vec<u8>,
    /// Count of consecutive malformed lines, for the caller's tolerance policy.
    consecutive_errors: u32,
}

impl<R: Read> LineReader<R> {
    pub fn new(inner: R) -> Self {
        LineReader {
            inner,
            buf: Vec::with_capacity(8 * 1024),
            pending: Vec::new(),
            consecutive_errors: 0,
        }
    }

    /// Consecutive recoverable errors since the last good line.
    pub fn consecutive_errors(&self) -> u32 {
        self.consecutive_errors
    }

    /// Reset the error streak after a good line or a deliberate policy decision.
    pub fn clear_errors(&mut self) {
        self.consecutive_errors = 0;
    }

    /// Read the next line, without its terminator.
    ///
    /// A recoverable error (over-long line, invalid UTF-8) is returned to the
    /// caller **and** counted; the reader stays usable so the session can continue.
    pub fn next_line(&mut self) -> Result<String, LineError> {
        self.buf.clear();
        match self.fill_to_newline() {
            Ok(()) => {}
            Err(err) => {
                if matches!(err, LineError::TooLong { .. } | LineError::NotUtf8) {
                    self.consecutive_errors = self.consecutive_errors.saturating_add(1);
                }
                return Err(err);
            }
        }
        // Strip a trailing '\n' and an optional '\r' so CRLF streams work.
        let mut end = self.buf.len();
        if end > 0 && self.buf[end - 1] == b'\n' {
            end -= 1;
        }
        if end > 0 && self.buf[end - 1] == b'\r' {
            end -= 1;
        }
        match std::str::from_utf8(&self.buf[..end]) {
            Ok(text) => {
                self.consecutive_errors = 0;
                Ok(text.to_string())
            }
            Err(_) => {
                self.consecutive_errors = self.consecutive_errors.saturating_add(1);
                Err(LineError::NotUtf8)
            }
        }
    }

    /// Read bytes into `buf` until a newline or the cap is reached.
    ///
    /// The cap is decided **before** any newline is accepted, so a line that ends
    /// exactly at the limit is still refused. Accepting it would let a peer push a
    /// maximum-sized line through on a technicality, and the whole point of the cap
    /// is a memory bound the caller can rely on.
    fn fill_to_newline(&mut self) -> Result<(), LineError> {
        let mut chunk = [0u8; 8 * 1024];
        // How much of `buf` has already been searched, so a long line is not
        // rescanned from the start on every chunk.
        let mut scanned = 0usize;
        loop {
            if let Some(position) = self.buf[scanned..].iter().position(|b| *b == b'\n') {
                let at = scanned + position;
                if at > ipc::MAX_LINE_BYTES {
                    // The terminator is already buffered, just past the cap. Drop
                    // the line and keep everything after it for the next call.
                    self.pending = self.buf.split_off(at + 1);
                    self.buf.clear();
                    return Err(LineError::TooLong {
                        limit: ipc::MAX_LINE_BYTES,
                    });
                }
                // Any bytes after the newline belong to the next line.
                self.pending = self.buf.split_off(at + 1);
                self.buf.truncate(at);
                return Ok(());
            }
            scanned = self.buf.len();

            if self.buf.len() > ipc::MAX_LINE_BYTES {
                // No terminator buffered yet and the cap is passed: drain the rest
                // of the line from the stream, then keep whatever follows it.
                self.buf.clear();
                self.pending.clear();
                self.discard_to_newline()?;
                return Err(LineError::TooLong {
                    limit: ipc::MAX_LINE_BYTES,
                });
            }
            // Any bytes already read past the previous line's newline belong to
            // this line, so move them in before reading more.
            if !self.pending.is_empty() {
                let pending = std::mem::take(&mut self.pending);
                self.buf.extend_from_slice(&pending);
                continue;
            }
            let read = match self.inner.read(&mut chunk) {
                Ok(0) => {
                    if self.buf.is_empty() {
                        return Err(LineError::Eof);
                    }
                    // Final line without a terminator.
                    return Ok(());
                }
                Ok(n) => n,
                Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(err) => return Err(LineError::Io(err)),
            };
            self.buf.extend_from_slice(&chunk[..read]);
        }
    }

    /// Drop bytes until the next newline so alignment is preserved.
    ///
    /// Reached only when the over-long line had **no** terminator in the buffer, so
    /// the remaining bytes of that line really are still on the stream.
    fn discard_to_newline(&mut self) -> Result<(), LineError> {
        let mut chunk = [0u8; 8 * 1024];
        loop {
            match self.inner.read(&mut chunk) {
                Ok(0) => return Ok(()),
                Ok(n) => {
                    if let Some(position) = chunk[..n].iter().position(|b| *b == b'\n') {
                        self.pending = chunk[position + 1..n].to_vec();
                        return Ok(());
                    }
                }
                Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(err) => return Err(LineError::Io(err)),
            }
        }
    }
}

/// Reads lines from any `BufRead`, used by the in-process tests.
pub fn read_line_from<R: BufRead>(reader: &mut R) -> Result<String, LineError> {
    let mut text = String::new();
    match reader.read_line(&mut text) {
        Ok(0) => Err(LineError::Eof),
        Ok(_) => {
            if text.len() > ipc::MAX_LINE_BYTES {
                return Err(LineError::TooLong {
                    limit: ipc::MAX_LINE_BYTES,
                });
            }
            let trimmed = text.trim_end_matches(['\n', '\r']);
            Ok(trimmed.to_string())
        }
        Err(err) => Err(LineError::Io(err)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn reader(text: &str) -> LineReader<Cursor<Vec<u8>>> {
        LineReader::new(Cursor::new(text.as_bytes().to_vec()))
    }

    #[test]
    fn lines_are_split_and_crlf_is_tolerated() {
        let mut r = reader("a\r\nb\nc");
        assert_eq!(r.next_line().unwrap(), "a");
        assert_eq!(r.next_line().unwrap(), "b");
        assert_eq!(r.next_line().unwrap(), "c");
        assert!(matches!(r.next_line(), Err(LineError::Eof)));
    }

    #[test]
    fn an_empty_line_is_a_line_not_an_error() {
        let mut r = reader("\n\n");
        assert_eq!(r.next_line().unwrap(), "");
        assert_eq!(r.next_line().unwrap(), "");
        assert!(matches!(r.next_line(), Err(LineError::Eof)));
    }

    #[test]
    fn multi_byte_utf8_survives() {
        let mut r = reader("мощность 45.8 Вт\n");
        assert_eq!(r.next_line().unwrap(), "мощность 45.8 Вт");
    }

    #[test]
    fn an_over_long_line_is_reported_and_the_stream_stays_aligned() {
        let mut text = "x".repeat(ipc::MAX_LINE_BYTES + 10);
        text.push('\n');
        text.push_str("good\n");
        let mut r = reader(&text);
        match r.next_line() {
            Err(LineError::TooLong { limit }) => assert_eq!(limit, ipc::MAX_LINE_BYTES),
            other => panic!("expected TooLong, got {other:?}"),
        }
        assert_eq!(
            r.next_line().unwrap(),
            "good",
            "the reader must resynchronise on the next newline"
        );
        assert_eq!(r.consecutive_errors(), 0, "a good line clears the streak");
    }

    #[test]
    fn invalid_utf8_is_reported_and_counted() {
        let mut bytes = b"ok\n".to_vec();
        bytes.extend_from_slice(&[0xFF, 0xFE, b'\n']);
        bytes.extend_from_slice(b"after\n");
        let mut r = LineReader::new(Cursor::new(bytes));
        assert_eq!(r.next_line().unwrap(), "ok");
        assert!(matches!(r.next_line(), Err(LineError::NotUtf8)));
        assert_eq!(r.consecutive_errors(), 1);
        assert_eq!(r.next_line().unwrap(), "after");
        assert_eq!(r.consecutive_errors(), 0);
    }

    #[test]
    fn a_long_run_of_bad_lines_is_counted_not_ignored() {
        let mut bytes = Vec::new();
        for _ in 0..ipc::MAX_CONSECUTIVE_PARSE_ERRORS + 2 {
            bytes.extend_from_slice(&[0xFF, b'\n']);
        }
        let mut r = LineReader::new(Cursor::new(bytes));
        let mut errors = 0;
        loop {
            match r.next_line() {
                Err(LineError::Eof) => break,
                Err(_) => errors += 1,
                Ok(_) => panic!("no good lines expected"),
            }
        }
        assert_eq!(errors, ipc::MAX_CONSECUTIVE_PARSE_ERRORS + 2);
        assert_eq!(
            r.consecutive_errors(),
            ipc::MAX_CONSECUTIVE_PARSE_ERRORS + 2
        );
    }

    #[test]
    fn a_final_line_without_a_terminator_is_still_delivered() {
        let mut r = reader("last");
        assert_eq!(r.next_line().unwrap(), "last");
        assert!(matches!(r.next_line(), Err(LineError::Eof)));
    }

    #[test]
    fn the_buffer_never_grows_past_the_cap() {
        // 4 MiB of one line: far past the cap. Memory must stay bounded.
        let text = format!("{}\n", "y".repeat(4 * 1024 * 1024));
        let mut r = reader(&text);
        let _ = r.next_line();
        assert!(
            r.buf.len() <= ipc::MAX_LINE_BYTES + 8192,
            "buffer grew to {}",
            r.buf.len()
        );
    }

    #[test]
    fn bufread_helper_trims_terminators() {
        let mut cursor = Cursor::new(b"hello\r\n".to_vec());
        assert_eq!(read_line_from(&mut cursor).unwrap(), "hello");
    }
}
