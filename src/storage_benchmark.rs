//! Compact, dependency-free Windows storage benchmark engine.
//!
//! Only a dedicated temporary file is accessed. The implementation uses
//! synchronous unbuffered Win32 I/O for QD1 and IOCP-backed OVERLAPPED I/O
//! for deeper queues.

use std::collections::HashMap;
use std::ffi::{OsStr, c_void};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr::null_mut;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

type Handle = *mut c_void;
type Bool = i32;
type Dword = u32;

const INVALID_HANDLE_VALUE: Handle = -1_isize as Handle;
const GENERIC_READ: Dword = 0x8000_0000;
const GENERIC_WRITE: Dword = 0x4000_0000;
const FILE_SHARE_READ: Dword = 0x0000_0001;
const FILE_SHARE_WRITE: Dword = 0x0000_0002;
const FILE_SHARE_DELETE: Dword = 0x0000_0004;
const CREATE_NEW: Dword = 1;
const FILE_ATTRIBUTE_TEMPORARY: Dword = 0x0000_0100;
const FILE_FLAG_WRITE_THROUGH: Dword = 0x8000_0000;
const FILE_FLAG_NO_BUFFERING: Dword = 0x2000_0000;
const FILE_FLAG_DELETE_ON_CLOSE: Dword = 0x0400_0000;
const FILE_FLAG_OVERLAPPED: Dword = 0x4000_0000;
const FILE_BEGIN: Dword = 0;
const ERROR_IO_PENDING: i32 = 997;
const WAIT_TIMEOUT: i32 = 258;
const MEM_COMMIT: Dword = 0x0000_1000;
const MEM_RESERVE: Dword = 0x0000_2000;
const MEM_RELEASE: Dword = 0x0000_8000;
const PAGE_READWRITE: Dword = 0x04;

pub const DEFAULT_TEST_FILE_SIZE: u64 = 512 * 1024 * 1024;
pub const DIAGNOSTIC_BLOCK_SIZE: usize = 1024 * 1024;
pub const DIAGNOSTIC_QUEUE_DEPTH: u32 = 4;
pub const DIAGNOSTIC_PASSES: u32 = 4;
pub const STABLE_SPREAD_LIMIT_PERCENT: f64 = 10.0;
pub const DEFAULT_BLOCK_SIZES: [usize; 6] = [
    4 * 1024,
    16 * 1024,
    64 * 1024,
    256 * 1024,
    1024 * 1024,
    4 * 1024 * 1024,
];

unsafe extern "system" {
    fn CreateFileW(
        file_name: *const u16,
        desired_access: Dword,
        share_mode: Dword,
        security_attributes: *mut c_void,
        creation_disposition: Dword,
        flags_and_attributes: Dword,
        template_file: Handle,
    ) -> Handle;
    fn ReadFile(
        file: Handle,
        buffer: *mut c_void,
        bytes_to_read: Dword,
        bytes_read: *mut Dword,
        overlapped: *mut c_void,
    ) -> Bool;
    fn WriteFile(
        file: Handle,
        buffer: *const c_void,
        bytes_to_write: Dword,
        bytes_written: *mut Dword,
        overlapped: *mut c_void,
    ) -> Bool;
    fn SetFilePointerEx(file: Handle, distance: i64, new_position: *mut i64, method: Dword)
    -> Bool;
    fn FlushFileBuffers(file: Handle) -> Bool;
    fn CloseHandle(handle: Handle) -> Bool;
    fn DeleteFileW(file_name: *const u16) -> Bool;
    fn GetDiskFreeSpaceW(
        root: *const u16,
        sectors_per_cluster: *mut Dword,
        bytes_per_sector: *mut Dword,
        free_clusters: *mut Dword,
        total_clusters: *mut Dword,
    ) -> Bool;
    fn GetDiskFreeSpaceExW(
        directory: *const u16,
        free_for_caller: *mut u64,
        total_bytes: *mut u64,
        total_free: *mut u64,
    ) -> Bool;
    fn VirtualAlloc(
        address: *mut c_void,
        size: usize,
        allocation_type: Dword,
        protect: Dword,
    ) -> *mut c_void;
    fn VirtualFree(address: *mut c_void, size: usize, free_type: Dword) -> Bool;
    fn CreateIoCompletionPort(
        file_handle: Handle,
        existing_port: Handle,
        completion_key: usize,
        concurrent_threads: Dword,
    ) -> Handle;
    fn GetQueuedCompletionStatus(
        completion_port: Handle,
        bytes_transferred: *mut Dword,
        completion_key: *mut usize,
        overlapped: *mut *mut Overlapped,
        milliseconds: Dword,
    ) -> Bool;
    fn CancelIoEx(file: Handle, overlapped: *mut Overlapped) -> Bool;
}

#[repr(C)]
#[derive(Debug, Default)]
struct Overlapped {
    internal: usize,
    internal_high: usize,
    offset: Dword,
    offset_high: Dword,
    event: Handle,
}

#[derive(Debug, Clone)]
pub struct StorageBenchmarkConfig {
    pub directory: PathBuf,
    pub test_file_size: u64,
    pub block_sizes: Vec<usize>,
    pub queue_depth: u32,
}

impl StorageBenchmarkConfig {
    pub fn standard(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
            test_file_size: DEFAULT_TEST_FILE_SIZE,
            block_sizes: DEFAULT_BLOCK_SIZES.to_vec(),
            queue_depth: 1,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DriveInfo {
    pub test_directory: PathBuf,
    pub bytes_per_sector: u32,
    pub alignment: usize,
    pub available_bytes: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct IoMeasurement {
    pub bytes: u64,
    pub operations: u64,
    pub elapsed: Duration,
    pub mb_per_second: f64,
    pub iops: f64,
    pub average_latency: Duration,
}

#[derive(Debug, Clone)]
pub struct BenchmarkRun {
    pub block_size: usize,
    pub read: IoMeasurement,
    pub write: IoMeasurement,
}

#[derive(Debug, Clone)]
pub enum BenchmarkStatus {
    Completed,
    Cancelled,
}

#[derive(Debug, Clone)]
pub struct StorageBenchmarkResult {
    pub drive: DriveInfo,
    pub test_file_size: u64,
    pub queue_depth: u32,
    pub status: BenchmarkStatus,
    pub runs: Vec<BenchmarkRun>,
}

#[derive(Debug, Clone)]
pub struct StorageDiagnosticProfile {
    pub block_size: usize,
    pub queue_depth: u32,
    pub test_file_size: u64,
    pub pass_count: u32,
    pub stable_spread_limit_percent: f64,
}

#[derive(Debug, Clone)]
pub struct DiagnosticPass {
    pub pass_number: u32,
    pub run: BenchmarkRun,
}

#[derive(Debug, Clone)]
pub struct StorageDiagnosticSummary {
    pub profile: StorageDiagnosticProfile,
    pub preparation_method: &'static str,
    pub preparation_elapsed: Duration,
    pub summary_read_mib_s: f64,
    pub summary_write_mib_s: f64,
    pub read_min_mib_s: f64,
    pub read_max_mib_s: f64,
    pub write_min_mib_s: f64,
    pub write_max_mib_s: f64,
    pub read_variation_percent: f64,
    pub write_variation_percent: f64,
    pub stable: bool,
    pub raw_passes: Vec<DiagnosticPass>,
}

#[derive(Debug, Clone, Copy)]
pub enum DiagnosticProgress {
    Preparation,
    PassWrite { pass: u32, total: u32 },
    PassRead { pass: u32, total: u32 },
    Complete,
}

pub fn run_diagnostic_summary(
    directory: impl Into<PathBuf>,
) -> io::Result<StorageDiagnosticSummary> {
    run_diagnostic_summary_with_cancel(directory, &AtomicBool::new(false))
}

pub fn run_diagnostic_summary_with_cancel(
    directory: impl Into<PathBuf>,
    cancel: &AtomicBool,
) -> io::Result<StorageDiagnosticSummary> {
    run_diagnostic_summary_with_progress(directory, cancel, |_| {})
}

pub fn run_diagnostic_summary_with_progress<F>(
    directory: impl Into<PathBuf>,
    cancel: &AtomicBool,
    mut progress: F,
) -> io::Result<StorageDiagnosticSummary>
where
    F: FnMut(DiagnosticProgress),
{
    let profile = StorageDiagnosticProfile {
        block_size: DIAGNOSTIC_BLOCK_SIZE,
        queue_depth: DIAGNOSTIC_QUEUE_DEPTH,
        test_file_size: DEFAULT_TEST_FILE_SIZE,
        pass_count: DIAGNOSTIC_PASSES,
        stable_spread_limit_percent: STABLE_SPREAD_LIMIT_PERCENT,
    };
    let directory = directory.into();
    let config = StorageBenchmarkConfig {
        directory: directory.clone(),
        test_file_size: profile.test_file_size,
        block_sizes: vec![profile.block_size],
        queue_depth: profile.queue_depth,
    };
    validate_config(&config)?;
    let drive = inspect_drive(&directory)?;
    if drive.available_bytes < profile.test_file_size.saturating_add(128 * 1024 * 1024) {
        return Err(io::Error::other(format!(
            "insufficient free space: {} bytes available, {} bytes plus 128 MiB reserve required",
            drive.available_bytes, profile.test_file_size
        )));
    }
    if profile.block_size % drive.alignment != 0
        || profile.test_file_size % profile.block_size as u64 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "diagnostic block size {} is incompatible with alignment {} or file size",
                profile.block_size, drive.alignment
            ),
        ));
    }

    let path = unique_test_path(&directory);
    let wide_path = wide(&path);
    let mut cleanup = TempFileGuard {
        path: wide_path.clone(),
    };
    let handle = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null_mut(),
            CREATE_NEW,
            FILE_ATTRIBUTE_TEMPORARY
                | FILE_FLAG_NO_BUFFERING
                | FILE_FLAG_WRITE_THROUGH
                | FILE_FLAG_DELETE_ON_CLOSE
                | FILE_FLAG_OVERLAPPED,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let file = HandleGuard(handle);
    let completion_port = unsafe { CreateIoCompletionPort(file.0, null_mut(), 0, 1) };
    if completion_port.is_null() {
        return Err(io::Error::last_os_error());
    }
    let completion_port = HandleGuard(completion_port);

    progress(DiagnosticProgress::Preparation);
    let preparation_started = Instant::now();
    measure_io_async(
        file.0,
        completion_port.0,
        profile.block_size,
        profile.test_file_size,
        profile.queue_depth,
        false,
        cancel,
    )?;
    if unsafe { FlushFileBuffers(file.0) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let preparation_elapsed = preparation_started.elapsed();

    let mut raw_passes = Vec::with_capacity(profile.pass_count as usize);
    for pass_number in 1..=profile.pass_count {
        if cancel.load(Ordering::Relaxed) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "diagnostic summary cancelled",
            ));
        }
        progress(DiagnosticProgress::PassWrite {
            pass: pass_number,
            total: profile.pass_count,
        });
        let write = measure_io_async(
            file.0,
            completion_port.0,
            profile.block_size,
            profile.test_file_size,
            profile.queue_depth,
            false,
            cancel,
        )?;
        if unsafe { FlushFileBuffers(file.0) } == 0 {
            return Err(io::Error::last_os_error());
        }
        progress(DiagnosticProgress::PassRead {
            pass: pass_number,
            total: profile.pass_count,
        });
        let read = measure_io_async(
            file.0,
            completion_port.0,
            profile.block_size,
            profile.test_file_size,
            profile.queue_depth,
            true,
            cancel,
        )?;
        let run = BenchmarkRun {
            block_size: profile.block_size,
            read,
            write,
        };
        raw_passes.push(DiagnosticPass { pass_number, run });
    }
    drop(completion_port);
    drop(file);
    cleanup.delete_now();
    let summary = aggregate_diagnostic_passes(profile, preparation_elapsed, raw_passes)?;
    progress(DiagnosticProgress::Complete);
    Ok(summary)
}

fn aggregate_diagnostic_passes(
    profile: StorageDiagnosticProfile,
    preparation_elapsed: Duration,
    raw_passes: Vec<DiagnosticPass>,
) -> io::Result<StorageDiagnosticSummary> {
    if raw_passes.len() != profile.pass_count as usize || raw_passes.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "diagnostic summary requires exactly the configured pass count",
        ));
    }
    let count = raw_passes.len() as f64;
    let summary_read_mib_s = raw_passes
        .iter()
        .map(|pass| pass.run.read.mb_per_second)
        .sum::<f64>()
        / count;
    let summary_write_mib_s = raw_passes
        .iter()
        .map(|pass| pass.run.write.mb_per_second)
        .sum::<f64>()
        / count;
    let read_min_mib_s = raw_passes
        .iter()
        .map(|pass| pass.run.read.mb_per_second)
        .fold(f64::INFINITY, f64::min);
    let read_max_mib_s = raw_passes
        .iter()
        .map(|pass| pass.run.read.mb_per_second)
        .fold(f64::NEG_INFINITY, f64::max);
    let write_min_mib_s = raw_passes
        .iter()
        .map(|pass| pass.run.write.mb_per_second)
        .fold(f64::INFINITY, f64::min);
    let write_max_mib_s = raw_passes
        .iter()
        .map(|pass| pass.run.write.mb_per_second)
        .fold(f64::NEG_INFINITY, f64::max);
    let read_variation_percent = spread_percent(read_min_mib_s, read_max_mib_s, summary_read_mib_s);
    let write_variation_percent =
        spread_percent(write_min_mib_s, write_max_mib_s, summary_write_mib_s);
    let stable = read_variation_percent <= profile.stable_spread_limit_percent
        && write_variation_percent <= profile.stable_spread_limit_percent;
    Ok(StorageDiagnosticSummary {
        profile,
        preparation_method: "one unmeasured 512 MiB QD4 OVERLAPPED write plus FlushFileBuffers",
        preparation_elapsed,
        summary_read_mib_s,
        summary_write_mib_s,
        read_min_mib_s,
        read_max_mib_s,
        write_min_mib_s,
        write_max_mib_s,
        read_variation_percent,
        write_variation_percent,
        stable,
        raw_passes,
    })
}

fn spread_percent(minimum: f64, maximum: f64, mean: f64) -> f64 {
    if mean > 0.0 {
        (maximum - minimum) / mean * 100.0
    } else if maximum == minimum {
        0.0
    } else {
        f64::INFINITY
    }
}

pub fn run(config: &StorageBenchmarkConfig) -> io::Result<StorageBenchmarkResult> {
    run_with_cancel(config, &AtomicBool::new(false))
}

pub fn run_with_cancel(
    config: &StorageBenchmarkConfig,
    cancel: &AtomicBool,
) -> io::Result<StorageBenchmarkResult> {
    validate_config(config)?;
    let drive = inspect_drive(&config.directory)?;
    if drive.available_bytes < config.test_file_size.saturating_add(128 * 1024 * 1024) {
        return Err(io::Error::other(format!(
            "insufficient free space: {} bytes available, {} bytes plus 128 MiB reserve required",
            drive.available_bytes, config.test_file_size
        )));
    }
    for &block in &config.block_sizes {
        if block % drive.alignment != 0 || config.test_file_size % block as u64 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "block size {block} is incompatible with alignment {} or file size",
                    drive.alignment
                ),
            ));
        }
    }

    let path = unique_test_path(&config.directory);
    let wide_path = wide(&path);
    let mut cleanup = TempFileGuard {
        path: wide_path.clone(),
    };
    let handle = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null_mut(),
            CREATE_NEW,
            FILE_ATTRIBUTE_TEMPORARY
                | FILE_FLAG_NO_BUFFERING
                | FILE_FLAG_WRITE_THROUGH
                | FILE_FLAG_DELETE_ON_CLOSE
                | if config.queue_depth > 1 {
                    FILE_FLAG_OVERLAPPED
                } else {
                    0
                },
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let file = HandleGuard(handle);
    let mut sync_buffer = if config.queue_depth == 1 {
        let max_block = *config
            .block_sizes
            .iter()
            .max()
            .expect("validated non-empty");
        let mut buffer = AlignedBuffer::new(max_block)?;
        buffer.fill_pattern();
        Some(buffer)
    } else {
        None
    };
    let completion_port = if config.queue_depth > 1 {
        let port = unsafe { CreateIoCompletionPort(file.0, null_mut(), 0, 1) };
        if port.is_null() {
            return Err(io::Error::last_os_error());
        }
        Some(HandleGuard(port))
    } else {
        None
    };
    let mut runs = Vec::with_capacity(config.block_sizes.len());

    for &block_size in &config.block_sizes {
        if cancel.load(Ordering::Relaxed) {
            drop(file);
            cleanup.delete_now();
            return Ok(StorageBenchmarkResult {
                drive,
                test_file_size: config.test_file_size,
                queue_depth: config.queue_depth,
                status: BenchmarkStatus::Cancelled,
                runs,
            });
        }
        let write = if let Some(buffer) = sync_buffer.as_mut() {
            seek_start(file.0)?;
            measure_io_sync(
                file.0,
                buffer.ptr,
                block_size,
                config.test_file_size,
                false,
                cancel,
            )?
        } else {
            measure_io_async(
                file.0,
                completion_port.as_ref().expect("IOCP created").0,
                block_size,
                config.test_file_size,
                config.queue_depth,
                false,
                cancel,
            )?
        };
        if unsafe { FlushFileBuffers(file.0) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let read = if let Some(buffer) = sync_buffer.as_mut() {
            seek_start(file.0)?;
            measure_io_sync(
                file.0,
                buffer.ptr,
                block_size,
                config.test_file_size,
                true,
                cancel,
            )?
        } else {
            measure_io_async(
                file.0,
                completion_port.as_ref().expect("IOCP created").0,
                block_size,
                config.test_file_size,
                config.queue_depth,
                true,
                cancel,
            )?
        };
        runs.push(BenchmarkRun {
            block_size,
            read,
            write,
        });
    }

    drop(file);
    cleanup.delete_now();
    Ok(StorageBenchmarkResult {
        drive,
        test_file_size: config.test_file_size,
        queue_depth: config.queue_depth,
        status: BenchmarkStatus::Completed,
        runs,
    })
}

fn validate_config(config: &StorageBenchmarkConfig) -> io::Result<()> {
    if !config.directory.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "benchmark directory does not exist",
        ));
    }
    if config.test_file_size == 0 || config.block_sizes.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "file size and block list must be non-zero",
        ));
    }
    if !matches!(config.queue_depth, 1 | 4 | 8) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "queue depth must be 1, 4, or 8",
        ));
    }
    if config
        .block_sizes
        .iter()
        .any(|&b| b == 0 || b > u32::MAX as usize)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid block size",
        ));
    }
    Ok(())
}

fn inspect_drive(directory: &Path) -> io::Result<DriveInfo> {
    let canonical = directory.canonicalize()?;
    let text = canonical.to_string_lossy();
    let root = if text.starts_with(r"\\") {
        let mut parts = text.trim_start_matches(r"\\").split('\\');
        format!(
            r"\\{}\{}\",
            parts.next().unwrap_or(""),
            parts.next().unwrap_or("")
        )
    } else {
        format!(
            "{}\\",
            text.get(..2)
                .ok_or_else(|| io::Error::other("cannot determine volume root"))?
        )
    };
    let root_w = wide(OsStr::new(&root));
    let dir_w = wide(&canonical);
    let mut sectors_per_cluster = 0;
    let mut bytes_per_sector = 0;
    let mut free_clusters = 0;
    let mut total_clusters = 0;
    if unsafe {
        GetDiskFreeSpaceW(
            root_w.as_ptr(),
            &mut sectors_per_cluster,
            &mut bytes_per_sector,
            &mut free_clusters,
            &mut total_clusters,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut available_bytes = 0_u64;
    if unsafe { GetDiskFreeSpaceExW(dir_w.as_ptr(), &mut available_bytes, null_mut(), null_mut()) }
        == 0
    {
        return Err(io::Error::last_os_error());
    }
    let alignment = (bytes_per_sector as usize).max(4096);
    if !alignment.is_power_of_two() {
        return Err(io::Error::other(format!(
            "unsupported non-power-of-two alignment: {alignment}"
        )));
    }
    Ok(DriveInfo {
        test_directory: canonical,
        bytes_per_sector,
        alignment,
        available_bytes,
    })
}

fn measure_io_sync(
    handle: Handle,
    buffer: *mut u8,
    block_size: usize,
    total_bytes: u64,
    reading: bool,
    cancel: &AtomicBool,
) -> io::Result<IoMeasurement> {
    let operations = total_bytes / block_size as u64;
    let start = Instant::now();
    for _ in 0..operations {
        if cancel.load(Ordering::Relaxed) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "benchmark cancelled",
            ));
        }
        let mut transferred = 0_u32;
        let ok = unsafe {
            if reading {
                ReadFile(
                    handle,
                    buffer.cast(),
                    block_size as u32,
                    &mut transferred,
                    null_mut(),
                )
            } else {
                WriteFile(
                    handle,
                    buffer.cast(),
                    block_size as u32,
                    &mut transferred,
                    null_mut(),
                )
            }
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        if transferred as usize != block_size {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "short unbuffered I/O operation",
            ));
        }
    }
    let elapsed = start.elapsed();
    let seconds = elapsed.as_secs_f64();
    if seconds <= 0.0 {
        return Err(io::Error::other(
            "timer resolution produced zero elapsed time",
        ));
    }
    Ok(IoMeasurement {
        bytes: total_bytes,
        operations,
        elapsed,
        mb_per_second: total_bytes as f64 / 1_048_576.0 / seconds,
        iops: operations as f64 / seconds,
        average_latency: Duration::from_secs_f64(seconds / operations as f64),
    })
}

struct AsyncSlot {
    buffer: AlignedBuffer,
    overlapped: Box<Overlapped>,
    submitted_at: Option<Instant>,
}

fn measure_io_async(
    handle: Handle,
    completion_port: Handle,
    block_size: usize,
    total_bytes: u64,
    queue_depth: u32,
    reading: bool,
    cancel: &AtomicBool,
) -> io::Result<IoMeasurement> {
    let operations = total_bytes / block_size as u64;
    let slot_count = usize::try_from(queue_depth)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid queue depth"))?;
    let mut slots = Vec::with_capacity(slot_count);
    for slot_index in 0..slot_count {
        let mut buffer = AlignedBuffer::new(block_size)?;
        if !reading {
            buffer.fill_pattern_with_seed(slot_index as u32 + 1);
        }
        slots.push(AsyncSlot {
            buffer,
            overlapped: Box::new(Overlapped::default()),
            submitted_at: None,
        });
    }
    let mut slot_by_overlapped = HashMap::with_capacity(slot_count);
    for (index, slot) in slots.iter_mut().enumerate() {
        slot_by_overlapped.insert((&mut *slot.overlapped) as *mut Overlapped as usize, index);
    }

    let started = Instant::now();
    let mut next_operation = 0_u64;
    let mut outstanding = 0_u64;
    let mut completed = 0_u64;
    let mut latency_seconds = 0.0_f64;
    let mut terminal_error: Option<io::Error> = None;

    for index in 0..slot_count {
        if next_operation >= operations {
            break;
        }
        if let Err(error) = submit_async(
            handle,
            &mut slots[index],
            next_operation * block_size as u64,
            block_size,
            reading,
        ) {
            terminal_error = Some(error);
            break;
        }
        next_operation += 1;
        outstanding += 1;
    }
    if terminal_error.is_some() && outstanding > 0 {
        unsafe {
            CancelIoEx(handle, null_mut());
        }
    }

    while outstanding > 0 {
        if cancel.load(Ordering::Relaxed) && terminal_error.is_none() {
            terminal_error = Some(io::Error::new(
                io::ErrorKind::Interrupted,
                "benchmark cancelled",
            ));
            unsafe {
                CancelIoEx(handle, null_mut());
            }
        }

        let mut transferred = 0_u32;
        let mut completion_key = 0_usize;
        let mut completed_overlapped: *mut Overlapped = null_mut();
        let ok = unsafe {
            GetQueuedCompletionStatus(
                completion_port,
                &mut transferred,
                &mut completion_key,
                &mut completed_overlapped,
                100,
            )
        };
        if completed_overlapped.is_null() {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(WAIT_TIMEOUT) {
                continue;
            }
            if terminal_error.is_none() {
                terminal_error = Some(error);
                unsafe {
                    CancelIoEx(handle, null_mut());
                }
            }
            continue;
        }

        outstanding -= 1;
        let Some(&slot_index) = slot_by_overlapped.get(&(completed_overlapped as usize)) else {
            if terminal_error.is_none() {
                terminal_error = Some(io::Error::other("IOCP returned an unknown OVERLAPPED"));
                unsafe {
                    CancelIoEx(handle, null_mut());
                }
            }
            continue;
        };
        let slot = &mut slots[slot_index];
        if let Some(submitted_at) = slot.submitted_at.take() {
            latency_seconds += submitted_at.elapsed().as_secs_f64();
        }

        if ok == 0 {
            if terminal_error.is_none() {
                terminal_error = Some(io::Error::last_os_error());
                unsafe {
                    CancelIoEx(handle, null_mut());
                }
            }
            continue;
        }
        if transferred as usize != block_size {
            if terminal_error.is_none() {
                terminal_error = Some(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!("partial OVERLAPPED completion: {transferred} of {block_size} bytes"),
                ));
                unsafe {
                    CancelIoEx(handle, null_mut());
                }
            }
            continue;
        }
        completed += 1;

        if terminal_error.is_none() && next_operation < operations {
            match submit_async(
                handle,
                slot,
                next_operation * block_size as u64,
                block_size,
                reading,
            ) {
                Ok(()) => {
                    next_operation += 1;
                    outstanding += 1;
                }
                Err(error) => {
                    terminal_error = Some(error);
                    unsafe {
                        CancelIoEx(handle, null_mut());
                    }
                }
            }
        }
    }

    if let Some(error) = terminal_error {
        return Err(error);
    }
    if completed != operations {
        return Err(io::Error::other(format!(
            "completed {completed} of {operations} operations"
        )));
    }
    let elapsed = started.elapsed();
    let seconds = elapsed.as_secs_f64();
    if seconds <= 0.0 {
        return Err(io::Error::other(
            "timer resolution produced zero elapsed time",
        ));
    }
    Ok(IoMeasurement {
        bytes: total_bytes,
        operations,
        elapsed,
        mb_per_second: total_bytes as f64 / 1_048_576.0 / seconds,
        iops: operations as f64 / seconds,
        average_latency: Duration::from_secs_f64(latency_seconds / operations as f64),
    })
}

fn submit_async(
    handle: Handle,
    slot: &mut AsyncSlot,
    offset: u64,
    block_size: usize,
    reading: bool,
) -> io::Result<()> {
    *slot.overlapped = Overlapped {
        offset: offset as u32,
        offset_high: (offset >> 32) as u32,
        ..Overlapped::default()
    };
    slot.submitted_at = Some(Instant::now());
    let ok = unsafe {
        if reading {
            ReadFile(
                handle,
                slot.buffer.ptr.cast(),
                block_size as u32,
                null_mut(),
                (&mut *slot.overlapped) as *mut Overlapped as *mut c_void,
            )
        } else {
            WriteFile(
                handle,
                slot.buffer.ptr.cast(),
                block_size as u32,
                null_mut(),
                (&mut *slot.overlapped) as *mut Overlapped as *mut c_void,
            )
        }
    };
    if ok == 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_IO_PENDING) {
            slot.submitted_at = None;
            return Err(error);
        }
    }
    Ok(())
}

fn seek_start(handle: Handle) -> io::Result<()> {
    if unsafe { SetFilePointerEx(handle, 0, null_mut(), FILE_BEGIN) } == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn unique_test_path(directory: &Path) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    directory.join(format!(
        ".WinStateDiag-benchmark-{}-{nonce}.tmp",
        std::process::id()
    ))
}

fn wide(value: impl AsRef<OsStr>) -> Vec<u16> {
    value.as_ref().encode_wide().chain(Some(0)).collect()
}

struct HandleGuard(Handle);
impl Drop for HandleGuard {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

struct TempFileGuard {
    path: Vec<u16>,
}
impl TempFileGuard {
    fn delete_now(&mut self) {
        unsafe {
            DeleteFileW(self.path.as_ptr());
        }
    }
}
impl Drop for TempFileGuard {
    fn drop(&mut self) {
        self.delete_now();
    }
}

struct AlignedBuffer {
    ptr: *mut u8,
    size: usize,
}
impl AlignedBuffer {
    fn new(size: usize) -> io::Result<Self> {
        let ptr =
            unsafe { VirtualAlloc(null_mut(), size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) }
                .cast::<u8>();
        if ptr.is_null() {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self { ptr, size })
        }
    }
    fn fill_pattern(&mut self) {
        self.fill_pattern_with_seed(0x9E37_79B9);
    }
    fn fill_pattern_with_seed(&mut self, seed: u32) {
        let bytes = unsafe { std::slice::from_raw_parts_mut(self.ptr, self.size) };
        let mut state = seed.max(1);
        for byte in bytes {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            *byte = state as u8;
        }
    }
}
impl Drop for AlignedBuffer {
    fn drop(&mut self) {
        unsafe {
            VirtualFree(self.ptr.cast(), 0, MEM_RELEASE);
        }
    }
}
