//! Multi-SSD/NVMe physical-disk topology (v0.3.6).
//!
//! Windows exposes storage in two disconnected layers: physical disks
//! (`\\.\PhysicalDriveN`, with a real model/serial/bus type) and logical
//! volumes (drive letters). A single physical SSD can carry several
//! volumes, and a drive letter can be reassigned — so this module treats
//! the PHYSICAL DISK as the unit of identity everywhere (selection,
//! history, benchmark target), never the drive letter alone.
//!
//! All Windows-specific enumeration/mapping lives behind the
//! [`TopologySource`] trait (see the `windows_source` module) so the
//! selection/target/identity logic above it — the part that actually
//! decides what happens — is plain, deterministic Rust that this file's
//! tests exercise with synthetic inventories, with no Windows runtime
//! required to verify it.

use std::path::PathBuf;

/// One physical storage device, as Windows reports it. Read-only facts;
/// never guessed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhysicalDiskInfo {
    /// `\\.\PhysicalDriveN`'s N.
    pub index: u32,
    pub model: String,
    /// Empty when Windows does not expose one for this device.
    pub serial: String,
    /// e.g. "NVMe", "SATA", "USB", "SCSI", "Unknown" — from the OS, not guessed.
    pub bus_type: String,
    pub size_bytes: u64,
    /// True for NVMe/SSD-reported media; false for a spinning HDD. The
    /// selector only ever lists SSD/NVMe candidates (never an HDD), matching
    /// the existing benchmark's SSD/NVMe-only scope.
    pub is_ssd_like: bool,
}

/// One writable volume (drive letter) and the physical disk backing it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeInfo {
    /// e.g. `"C:\\"`.
    pub mount_point: String,
    pub physical_disk_index: u32,
    /// Best-effort probe result (e.g. a real temp-file write attempt).
    /// `false` means this volume cannot be used as a benchmark target.
    pub writable: bool,
    /// The volume's own Windows label (e.g. "Win11", "Data"), read from
    /// this exact mapped volume; empty when the volume has no label. Pure
    /// display data — never used for identity (see
    /// [`physical_disk_identity`]).
    pub label: String,
}

/// SSD/HDD decision for one physical disk (pure, tested): NVMe is always
/// solid-state; anything else (SATA, USB, RAID, …) counts as SSD only when
/// Windows explicitly reports NO seek penalty. A rotating HDD — or a device
/// that cannot tell — never takes an SSD slot.
pub fn is_ssd_media(bus_type: &str, seek_penalty: Option<bool>) -> bool {
    bus_type == "NVMe" || seek_penalty == Some(false)
}

/// A stable identity for history/report comparisons — physical disk model
/// + serial when both are known, never the drive letter alone (a letter can
/// be reassigned; two different SSDs must never be compared as "the same
/// disk", e.g. a Samsung vs. a Netac).
pub fn physical_disk_identity(disk: &PhysicalDiskInfo) -> String {
    let model = disk.model.trim();
    let serial = disk.serial.trim();
    match (model.is_empty(), serial.is_empty()) {
        (false, false) => format!("PHYS#{model}#{serial}"),
        (false, true) => format!("PHYS#{model}#IDX{}", disk.index),
        (true, _) => format!("PHYS#UNKNOWN#IDX{}", disk.index),
    }
}

/// One selectable entry in the SSD/NVMe card's disk selector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiskCandidate {
    pub disk: PhysicalDiskInfo,
    /// True when this physical disk backs `SystemDrive` (the default
    /// selection) — determined by real volume→physical-disk mapping, never
    /// by assuming the letter is `C:`.
    pub is_system: bool,
    /// A writable volume on this physical disk, chosen deterministically
    /// (lowest mount point letter) when more than one exists. `None` means
    /// this SSD currently has no writable volume WinStateDiag can use.
    pub volume: Option<VolumeInfo>,
    /// A stable label for the UI, e.g. "C: — Samsung 9100 PRO 1 TB".
    pub label: String,
}

/// Capacity string for display (e.g. "1 TB"), reusing the same rounding as
/// the candidate label (v0.3.6 UI finalization).
pub fn capacity_text(disk: &PhysicalDiskInfo) -> String {
    if disk.size_bytes == 0 {
        // Size unknown (the query failed): say so, never "0 GB".
        "—".to_string()
    } else {
        format_size(disk.size_bytes)
    }
}

/// Interface/bus text exactly as Windows reports it — never a guessed PCIe
/// generation (spec: "if we only know BusType = NVMe, display NVMe").
pub fn interface_text(disk: &PhysicalDiskInfo) -> String {
    let bus = disk.bus_type.trim();
    if bus.is_empty() {
        "—".to_string()
    } else {
        bus.to_string()
    }
}

/// Drive-letter text for a disk card: `"C:"`, or `"—"` when this physical
/// disk currently has no writable volume.
pub fn drive_letter_text(candidate: &DiskCandidate) -> String {
    match &candidate.volume {
        Some(v) => v.mount_point.trim_end_matches('\\').to_string(),
        None => "—".to_string(),
    }
}

/// The real volume label of the candidate's mapped volume, for the disk
/// card ("C:  Win11"): `None` when there is no volume or it has no label —
/// never a fabricated "Windows"/"System"/"Local Disk".
pub fn volume_label_text(candidate: &DiskCandidate) -> Option<String> {
    candidate
        .volume
        .as_ref()
        .map(|v| v.label.trim().to_string())
        .filter(|l| !l.is_empty())
}

/// Serial text for display: `None` when Windows did not report one — the
/// caller decides whether to show "Не сообщается" or omit the row entirely.
pub fn serial_text(disk: &PhysicalDiskInfo) -> Option<String> {
    let s = disk.serial.trim();
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

fn format_size(bytes: u64) -> String {
    const GB: f64 = 1_000_000_000.0;
    const TB: f64 = 1_000_000_000_000.0;
    let b = bytes as f64;
    if b >= TB * 0.9 {
        format!("{:.0} TB", (b / TB).round())
    } else {
        format!("{:.0} GB", (b / GB).round())
    }
}

fn candidate_label(disk: &PhysicalDiskInfo, volume: Option<&VolumeInfo>) -> String {
    let model = if disk.model.trim().is_empty() {
        format!("PhysicalDrive{}", disk.index)
    } else {
        disk.model.trim().to_string()
    };
    let size = format_size(disk.size_bytes);
    match volume {
        Some(v) => {
            let letter = v.mount_point.trim_end_matches('\\');
            format!("{letter} — {model} {size}")
        }
        None => format!("{model} {size} (no writable volume)"),
    }
}

/// Builds the selector's candidate list: physical SSD/NVMe disks only (an
/// HDD is never listed here — the existing benchmark is SSD/NVMe-scoped),
/// each paired with its chosen writable volume when one exists. Stable,
/// deterministic order: the reliably identified system SSD first, then the
/// others by physical disk index (never by drive letter, so C/D/E need not
/// be contiguous).
pub fn build_candidates(
    disks: &[PhysicalDiskInfo],
    volumes: &[VolumeInfo],
    system_drive_physical_index: Option<u32>,
) -> Vec<DiskCandidate> {
    let mut candidates: Vec<DiskCandidate> = disks
        .iter()
        .filter(|d| d.is_ssd_like)
        .map(|disk| {
            let volume = volumes
                .iter()
                .filter(|v| v.physical_disk_index == disk.index && v.writable)
                .min_by(|a, b| a.mount_point.cmp(&b.mount_point))
                .cloned();
            let is_system = system_drive_physical_index == Some(disk.index);
            let label = candidate_label(disk, volume.as_ref());
            DiskCandidate {
                disk: disk.clone(),
                is_system,
                volume,
                label,
            }
        })
        .collect();
    candidates.sort_by_key(|c| (!c.is_system, c.disk.index));
    candidates
}

/// The default selection: the physical disk backing `SystemDrive`, or
/// (only if that disk was not itself SSD/NVMe, or somehow absent) the
/// first candidate. `None` when there are no SSD/NVMe candidates at all.
pub fn default_candidate_index(candidates: &[DiskCandidate]) -> Option<usize> {
    candidates
        .iter()
        .position(|c| c.is_system)
        .or(if candidates.is_empty() { None } else { Some(0) })
}

/// Resolves the real directory the benchmark must write its test file into.
/// Never falls back to `C:` (or anywhere else) silently: a candidate with no
/// writable volume is a clear, explicit error, not a silent redirect.
pub fn benchmark_target_dir(candidate: &DiskCandidate) -> Result<PathBuf, String> {
    match &candidate.volume {
        Some(v) if v.writable => Ok(PathBuf::from(&v.mount_point)),
        Some(_) => Err(format!(
            "{}: выбранный том недоступен для записи.",
            candidate.label
        )),
        None => Err(format!(
            "{}: нет доступного для записи тома на этом накопителе.",
            candidate.label
        )),
    }
}

/// Real, read-only enumeration of physical disks and writable volumes.
/// Kept behind a trait so the selection logic above never depends on
/// Windows being present; a `Fake` implementation drives the unit tests.
pub trait TopologySource {
    fn physical_disks(&self) -> Vec<PhysicalDiskInfo>;
    fn volumes(&self) -> Vec<VolumeInfo>;
    /// The physical disk index backing `SystemDrive`, if it could be
    /// determined.
    fn system_drive_physical_index(&self) -> Option<u32>;
}

/// Convenience: build the full candidate list from any [`TopologySource`].
pub fn candidates_from(source: &dyn TopologySource) -> Vec<DiskCandidate> {
    build_candidates(
        &source.physical_disks(),
        &source.volumes(),
        source.system_drive_physical_index(),
    )
}

#[cfg(windows)]
pub mod windows_source {
    //! Real Windows enumeration: `\\.\PhysicalDriveN` +
    //! `IOCTL_STORAGE_QUERY_PROPERTY` for model/serial/bus type,
    //! `\\.\<letter>:` + `IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS` to map a
    //! drive letter to its physical disk, and a real temp-file write/delete
    //! to probe writability. Read-only apart from that probe file, which is
    //! always deleted. This module cannot be exercised without a Windows
    //! host, so it is kept as small and literal as possible — the actual
    //! decision logic it feeds is in the parent module, fully tested above.
    use super::{PhysicalDiskInfo, TopologySource, VolumeInfo};
    use std::ffi::{OsStr, c_void};
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use std::ptr::null_mut;

    type Handle = *mut c_void;
    type Bool = i32;
    type Dword = u32;

    const INVALID_HANDLE_VALUE: Handle = -1_isize as Handle;
    const GENERIC_READ: Dword = 0x8000_0000;
    const FILE_SHARE_READ: Dword = 0x0000_0001;
    const FILE_SHARE_WRITE: Dword = 0x0000_0002;
    const OPEN_EXISTING: Dword = 3;
    const IOCTL_STORAGE_QUERY_PROPERTY: Dword = 0x2D_1400;
    const IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS: Dword = 0x56_0000;
    const IOCTL_DISK_GET_LENGTH_INFO: Dword = 0x0007_405C;
    const STORAGE_PROPERTY_ID_DEVICE: Dword = 0;
    /// StorageDeviceSeekPenaltyProperty: a rotating HDD "incurs a seek
    /// penalty", an SSD does not — the reliable HDD/SSD discriminator.
    const STORAGE_PROPERTY_ID_SEEK_PENALTY: Dword = 7;
    const PROPERTY_STANDARD_QUERY: Dword = 0;

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
        fn CloseHandle(handle: Handle) -> Bool;
        fn DeviceIoControl(
            device: Handle,
            io_control_code: Dword,
            in_buffer: *mut c_void,
            in_buffer_size: Dword,
            out_buffer: *mut c_void,
            out_buffer_size: Dword,
            bytes_returned: *mut Dword,
            overlapped: *mut c_void,
        ) -> Bool;
        fn GetLogicalDrives() -> Dword;
        fn GetDriveTypeW(root_path: *const u16) -> Dword;
        fn GetVolumeInformationW(
            root_path_name: *const u16,
            volume_name_buffer: *mut u16,
            volume_name_size: Dword,
            volume_serial_number: *mut Dword,
            maximum_component_length: *mut Dword,
            file_system_flags: *mut Dword,
            file_system_name_buffer: *mut u16,
            file_system_name_size: Dword,
        ) -> Bool;
    }

    #[repr(C)]
    struct DeviceSeekPenaltyDescriptor {
        version: Dword,
        size: Dword,
        incurs_seek_penalty: u8,
    }

    const DRIVE_FIXED: Dword = 3;

    #[repr(C)]
    struct StoragePropertyQuery {
        property_id: Dword,
        query_type: Dword,
        additional_parameters: [u8; 1],
    }

    #[repr(C)]
    struct StorageDeviceDescriptorHeader {
        version: Dword,
        size: Dword,
        device_type: u8,
        device_type_modifier: u8,
        removable_media: u8,
        command_queueing: u8,
        vendor_id_offset: i32,
        product_id_offset: i32,
        product_revision_offset: i32,
        serial_number_offset: i32,
        bus_type: u32,
        raw_properties_length: Dword,
        // raw bytes follow; read manually.
    }

    #[repr(C)]
    struct DiskExtent {
        disk_number: Dword,
        _starting_offset: i64,
        _extent_length: i64,
    }

    #[repr(C)]
    struct VolumeDiskExtents {
        number_of_disk_extents: Dword,
        extents: [DiskExtent; 1],
    }

    fn wide(s: &str) -> Vec<u16> {
        OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    fn bus_type_name(code: u32) -> &'static str {
        // STORAGE_BUS_TYPE (winioctl.h); only the codes worth naming.
        match code {
            1 => "SCSI",
            3 => "ATA",
            7 => "USB",
            8 => "RAID",
            10 => "SATA",
            11 => "SD",
            17 => "NVMe",
            _ => "Unknown",
        }
    }

    fn read_cstr_at(buf: &[u8], offset: i32) -> String {
        if offset <= 0 || offset as usize >= buf.len() {
            return String::new();
        }
        let start = offset as usize;
        let end = buf[start..]
            .iter()
            .position(|&b| b == 0)
            .map(|p| start + p)
            .unwrap_or(buf.len());
        String::from_utf8_lossy(&buf[start..end]).trim().to_string()
    }

    fn query_physical_disk(index: u32) -> Option<PhysicalDiskInfo> {
        let path = wide(&format!("\\\\.\\PhysicalDrive{index}"));
        let handle = unsafe {
            CreateFileW(
                path.as_ptr(),
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                null_mut(),
                OPEN_EXISTING,
                0,
                null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return None;
        }
        let query = StoragePropertyQuery {
            property_id: STORAGE_PROPERTY_ID_DEVICE,
            query_type: PROPERTY_STANDARD_QUERY,
            additional_parameters: [0],
        };
        let mut buf = vec![0u8; 4096];
        let mut returned: Dword = 0;
        let ok = unsafe {
            DeviceIoControl(
                handle,
                IOCTL_STORAGE_QUERY_PROPERTY,
                &query as *const _ as *mut c_void,
                std::mem::size_of::<StoragePropertyQuery>() as Dword,
                buf.as_mut_ptr() as *mut c_void,
                buf.len() as Dword,
                &mut returned,
                null_mut(),
            )
        };
        let mut model = String::new();
        let mut serial = String::new();
        let mut bus_type = String::from("Unknown");
        if ok != 0 && returned as usize >= std::mem::size_of::<StorageDeviceDescriptorHeader>() {
            let header = unsafe { &*(buf.as_ptr() as *const StorageDeviceDescriptorHeader) };
            let vendor = read_cstr_at(&buf, header.vendor_id_offset);
            let product = read_cstr_at(&buf, header.product_id_offset);
            model = [vendor, product]
                .into_iter()
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .join(" ");
            serial = read_cstr_at(&buf, header.serial_number_offset);
            bus_type = bus_type_name(header.bus_type).to_string();
        }
        let seek_penalty = query_seek_penalty(handle);
        unsafe { CloseHandle(handle) };
        let is_ssd_like = super::is_ssd_media(&bus_type, seek_penalty);
        Some(PhysicalDiskInfo {
            index,
            model,
            serial,
            bus_type,
            // 0 = unknown (displayed as "—", never "0 GB").
            size_bytes: query_length(index).unwrap_or(0),
            is_ssd_like,
        })
    }

    /// `Some(true)` = rotating media (HDD), `Some(false)` = no seek penalty
    /// (SSD), `None` = the device did not answer.
    fn query_seek_penalty(handle: Handle) -> Option<bool> {
        let query = StoragePropertyQuery {
            property_id: STORAGE_PROPERTY_ID_SEEK_PENALTY,
            query_type: PROPERTY_STANDARD_QUERY,
            additional_parameters: [0],
        };
        let mut desc = DeviceSeekPenaltyDescriptor {
            version: 0,
            size: 0,
            incurs_seek_penalty: 0,
        };
        let mut returned: Dword = 0;
        let ok = unsafe {
            DeviceIoControl(
                handle,
                IOCTL_STORAGE_QUERY_PROPERTY,
                &query as *const _ as *mut c_void,
                std::mem::size_of::<StoragePropertyQuery>() as Dword,
                &mut desc as *mut _ as *mut c_void,
                std::mem::size_of::<DeviceSeekPenaltyDescriptor>() as Dword,
                &mut returned,
                null_mut(),
            )
        };
        if ok != 0 && returned as usize >= std::mem::size_of::<DeviceSeekPenaltyDescriptor>() {
            Some(desc.incurs_seek_penalty != 0)
        } else {
            None
        }
    }

    /// Physical disk size in bytes (read-only `IOCTL_DISK_GET_LENGTH_INFO`,
    /// which needs a read-access handle; the app already runs elevated).
    fn query_length(index: u32) -> Option<u64> {
        let path = wide(&format!("\\\\.\\PhysicalDrive{index}"));
        let handle = unsafe {
            CreateFileW(
                path.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                null_mut(),
                OPEN_EXISTING,
                0,
                null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return None;
        }
        let mut length: i64 = 0;
        let mut returned: Dword = 0;
        let ok = unsafe {
            DeviceIoControl(
                handle,
                IOCTL_DISK_GET_LENGTH_INFO,
                null_mut(),
                0,
                &mut length as *mut _ as *mut c_void,
                std::mem::size_of::<i64>() as Dword,
                &mut returned,
                null_mut(),
            )
        };
        unsafe { CloseHandle(handle) };
        (ok != 0 && length > 0).then_some(length as u64)
    }

    /// The volume's own label (empty when it has none or cannot be read).
    fn volume_label(mount_point: &str) -> String {
        let root = wide(mount_point);
        let mut name = [0u16; 261];
        let ok = unsafe {
            GetVolumeInformationW(
                root.as_ptr(),
                name.as_mut_ptr(),
                name.len() as Dword,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                0,
            )
        };
        if ok == 0 {
            return String::new();
        }
        let end = name.iter().position(|&c| c == 0).unwrap_or(name.len());
        String::from_utf16_lossy(&name[..end]).trim().to_string()
    }

    fn physical_index_for_volume(mount_point: &str) -> Option<u32> {
        let letter = mount_point.trim_end_matches('\\').trim_end_matches(':');
        let path = wide(&format!("\\\\.\\{letter}:"));
        let handle = unsafe {
            CreateFileW(
                path.as_ptr(),
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                null_mut(),
                OPEN_EXISTING,
                0,
                null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return None;
        }
        let mut extents = VolumeDiskExtents {
            number_of_disk_extents: 0,
            extents: [DiskExtent {
                disk_number: 0,
                _starting_offset: 0,
                _extent_length: 0,
            }],
        };
        let mut returned: Dword = 0;
        let ok = unsafe {
            DeviceIoControl(
                handle,
                IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
                null_mut(),
                0,
                &mut extents as *mut _ as *mut c_void,
                std::mem::size_of::<VolumeDiskExtents>() as Dword,
                &mut returned,
                null_mut(),
            )
        };
        unsafe { CloseHandle(handle) };
        if ok != 0 && extents.number_of_disk_extents > 0 {
            Some(extents.extents[0].disk_number)
        } else {
            None
        }
    }

    fn probe_writable(mount_point: &str) -> bool {
        let probe = Path::new(mount_point).join(".wsd_write_probe.tmp");
        match std::fs::write(&probe, b"wsd") {
            Ok(()) => {
                let _ = std::fs::remove_file(&probe);
                true
            }
            Err(_) => false,
        }
    }

    /// The real, live `TopologySource` used outside tests.
    pub struct WindowsTopologySource;

    impl TopologySource for WindowsTopologySource {
        fn physical_disks(&self) -> Vec<PhysicalDiskInfo> {
            // A generous, bounded scan; stops once several consecutive
            // indices fail to open (no fixed hardcoded disk count assumed).
            let mut disks = Vec::new();
            let mut consecutive_misses = 0u32;
            for index in 0..32 {
                match query_physical_disk(index) {
                    Some(d) => {
                        consecutive_misses = 0;
                        disks.push(d);
                    }
                    None => {
                        consecutive_misses += 1;
                        if consecutive_misses >= 3 && !disks.is_empty() {
                            break;
                        }
                    }
                }
            }
            disks
        }

        fn volumes(&self) -> Vec<VolumeInfo> {
            let mask = unsafe { GetLogicalDrives() };
            let mut volumes = Vec::new();
            for i in 0..26u32 {
                if mask & (1 << i) == 0 {
                    continue;
                }
                let letter = (b'A' + i as u8) as char;
                let mount_point = format!("{letter}:\\");
                let root_wide = wide(&mount_point);
                if unsafe { GetDriveTypeW(root_wide.as_ptr()) } != DRIVE_FIXED {
                    continue;
                }
                if let Some(physical_disk_index) = physical_index_for_volume(&mount_point) {
                    volumes.push(VolumeInfo {
                        mount_point: mount_point.clone(),
                        physical_disk_index,
                        writable: probe_writable(&mount_point),
                        label: volume_label(&mount_point),
                    });
                }
            }
            volumes
        }

        fn system_drive_physical_index(&self) -> Option<u32> {
            let system_drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
            let mount_point = format!("{}\\", system_drive.trim_end_matches('\\'));
            physical_index_for_volume(&mount_point)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn disk(index: u32, model: &str, serial: &str, bus: &str, ssd: bool) -> PhysicalDiskInfo {
        PhysicalDiskInfo {
            index,
            model: model.into(),
            serial: serial.into(),
            bus_type: bus.into(),
            size_bytes: 1_000_000_000_000,
            is_ssd_like: ssd,
        }
    }

    fn vol(mount: &str, phys: u32, writable: bool) -> VolumeInfo {
        VolumeInfo {
            mount_point: mount.into(),
            physical_disk_index: phys,
            writable,
            label: String::new(),
        }
    }

    #[test]
    fn hdd_or_unknown_media_never_counts_as_ssd() {
        assert!(is_ssd_media("NVMe", None));
        assert!(is_ssd_media("NVMe", Some(true)));
        assert!(is_ssd_media("SATA", Some(false)));
        assert!(is_ssd_media("USB", Some(false)));
        assert!(
            !is_ssd_media("SATA", Some(true)),
            "a SATA HDD is never an SSD"
        );
        assert!(
            !is_ssd_media("SATA", None),
            "unknown media never takes a slot"
        );
        assert!(!is_ssd_media("USB", Some(true)));
    }

    #[test]
    fn system_ssd_is_listed_first_then_by_physical_index() {
        // The Windows SSD is physical disk 2 here; letters are not contiguous.
        let disks = [
            disk(0, "Netac NV7000T 1TB", "N1", "NVMe", true),
            disk(1, "WD Blue HDD 4TB", "H1", "SATA", false),
            disk(2, "Samsung 9100 PRO 1TB", "S1", "NVMe", true),
            disk(3, "Kingston KC3000 2TB", "K1", "NVMe", true),
        ];
        let vols = [
            vol("E:\\", 0, true),
            vol("D:\\", 1, true),
            vol("C:\\", 2, true),
            vol("G:\\", 3, true),
        ];
        let c = build_candidates(&disks, &vols, Some(2));
        let models: Vec<&str> = c.iter().map(|x| x.disk.model.as_str()).collect();
        assert_eq!(
            models,
            [
                "Samsung 9100 PRO 1TB",
                "Netac NV7000T 1TB",
                "Kingston KC3000 2TB"
            ]
        );
        assert!(c[0].is_system);
        assert_eq!(default_candidate_index(&c), Some(0));
        // Deterministic: same input, same order.
        assert_eq!(build_candidates(&disks, &vols, Some(2)), c);
    }

    #[test]
    fn volume_label_is_the_mapped_volumes_own_label_or_none() {
        let mut v = vol("C:\\", 0, true);
        v.label = "Win11".into();
        let c = build_candidates(
            &[disk(0, "Samsung 9100 PRO 1TB", "S1", "NVMe", true)],
            &[v],
            Some(0),
        );
        assert_eq!(volume_label_text(&c[0]).as_deref(), Some("Win11"));
        // Blank label -> only the letter is shown; never "Local Disk".
        let mut blank = vol("E:\\", 1, true);
        blank.label = "   ".into();
        let c = build_candidates(
            &[disk(1, "Netac NV7000T 1TB", "N1", "NVMe", true)],
            &[blank],
            None,
        );
        assert_eq!(volume_label_text(&c[0]), None);
        assert_eq!(drive_letter_text(&c[0]), "E:");
        // No volume at all -> no label.
        let c = build_candidates(
            &[disk(2, "Kingston KC3000 2TB", "K1", "NVMe", true)],
            &[],
            None,
        );
        assert_eq!(volume_label_text(&c[0]), None);
        // The label never influences the physical identity.
        let mut a = vol("C:\\", 0, true);
        a.label = "Win11".into();
        let mut b = vol("C:\\", 0, true);
        b.label = "Renamed".into();
        let d = disk(0, "Samsung 9100 PRO 1TB", "S1", "NVMe", true);
        let ca = build_candidates(std::slice::from_ref(&d), &[a], Some(0));
        let cb = build_candidates(std::slice::from_ref(&d), &[b], Some(0));
        assert_eq!(
            physical_disk_identity(&ca[0].disk),
            physical_disk_identity(&cb[0].disk)
        );
    }

    #[test]
    fn unknown_capacity_is_a_dash_never_zero_gb() {
        let mut d = disk(0, "Samsung 9100 PRO 1TB", "S1", "NVMe", true);
        d.size_bytes = 0;
        assert_eq!(capacity_text(&d), "—");
    }

    #[test]
    fn identity_uses_model_and_serial_not_the_drive_letter() {
        let samsung = disk(0, "Samsung 9100 PRO 1TB", "S1", "NVMe", true);
        let netac = disk(1, "Netac NV7000T 1TB", "S2", "NVMe", true);
        assert_ne!(
            physical_disk_identity(&samsung),
            physical_disk_identity(&netac)
        );
        // Same disk, letter changed: identity is unchanged (it never uses
        // the drive letter at all).
        let samsung_after_letter_change = samsung.clone();
        assert_eq!(
            physical_disk_identity(&samsung),
            physical_disk_identity(&samsung_after_letter_change)
        );
    }

    #[test]
    fn identity_falls_back_gracefully_without_serial() {
        let d = disk(2, "Generic SSD", "", "SATA", true);
        let id = physical_disk_identity(&d);
        assert!(id.contains("Generic SSD"));
        assert!(id.contains("IDX2"));
    }

    #[test]
    fn one_ssd_is_the_only_and_default_candidate() {
        let disks = vec![disk(0, "Samsung 9100 PRO 1TB", "S1", "NVMe", true)];
        let volumes = vec![vol("C:\\", 0, true)];
        let candidates = build_candidates(&disks, &volumes, Some(0));
        assert_eq!(candidates.len(), 1);
        assert_eq!(default_candidate_index(&candidates), Some(0));
        assert!(candidates[0].is_system);
        assert_eq!(candidates[0].label, "C: — Samsung 9100 PRO 1TB 1 TB");
    }

    #[test]
    fn two_ssds_are_both_listed_windows_disk_is_default() {
        let disks = vec![
            disk(0, "Samsung 9100 PRO 1TB", "S1", "NVMe", true),
            disk(1, "Netac NV7000T 1TB", "S2", "NVMe", true),
        ];
        let volumes = vec![vol("C:\\", 0, true), vol("D:\\", 1, true)];
        let candidates = build_candidates(&disks, &volumes, Some(0));
        assert_eq!(candidates.len(), 2);
        let default = default_candidate_index(&candidates).unwrap();
        assert!(candidates[default].is_system);
        assert_eq!(candidates[default].disk.index, 0);
        // The second SSD is present and independently selectable.
        assert!(candidates.iter().any(|c| c.disk.index == 1 && !c.is_system));
    }

    #[test]
    fn hdd_is_never_listed_even_when_present() {
        let disks = vec![
            disk(0, "Samsung 9100 PRO 1TB", "S1", "NVMe", true),
            disk(1, "WD Blue HDD 2TB", "H1", "SATA", false),
        ];
        let volumes = vec![vol("C:\\", 0, true), vol("D:\\", 1, true)];
        let candidates = build_candidates(&disks, &volumes, Some(0));
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].disk.index, 0);
    }

    #[test]
    fn a_physical_disk_with_multiple_volumes_is_one_ssd_with_one_chosen_volume() {
        let disks = vec![disk(0, "Samsung 9100 PRO 1TB", "S1", "NVMe", true)];
        // Two volumes on the SAME physical disk (e.g. a recovery + data
        // partition): still one SSD, and the selector picks a deterministic
        // writable volume (lowest letter), not "each volume is its own SSD".
        let volumes = vec![vol("E:\\", 0, true), vol("C:\\", 0, true)];
        let candidates = build_candidates(&disks, &volumes, Some(0));
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].volume.as_ref().unwrap().mount_point, "C:\\");
    }

    #[test]
    fn no_writable_volume_never_falls_back_to_c_silently() {
        let disks = vec![disk(0, "Samsung 9100 PRO 1TB", "S1", "NVMe", true)];
        // Its only volume cannot be written to.
        let volumes = vec![vol("C:\\", 0, false)];
        let candidates = build_candidates(&disks, &volumes, Some(0));
        assert_eq!(candidates[0].volume, None);
        let err = benchmark_target_dir(&candidates[0]).unwrap_err();
        assert!(err.contains("нет доступного"), "{err}");
    }

    #[test]
    fn benchmark_target_is_on_the_selected_disk_not_always_c() {
        let disks = vec![
            disk(0, "Samsung 9100 PRO 1TB", "S1", "NVMe", true),
            disk(1, "Netac NV7000T 1TB", "S2", "NVMe", true),
        ];
        let volumes = vec![vol("C:\\", 0, true), vol("D:\\", 1, true)];
        let candidates = build_candidates(&disks, &volumes, Some(0));
        let second = candidates.iter().find(|c| c.disk.index == 1).unwrap();
        let target = benchmark_target_dir(second).unwrap();
        assert_eq!(target, PathBuf::from("D:\\"));
    }

    #[test]
    fn no_ssd_candidates_means_no_default_and_no_crash() {
        let disks = vec![disk(0, "WD Blue HDD 2TB", "H1", "SATA", false)];
        let volumes = vec![vol("C:\\", 0, true)];
        let candidates = build_candidates(&disks, &volumes, Some(0));
        assert!(candidates.is_empty());
        assert_eq!(default_candidate_index(&candidates), None);
    }

    #[test]
    fn system_drive_on_a_non_ssd_falls_back_to_first_listed_ssd() {
        // SystemDrive is on disk 1, which is an HDD and therefore never
        // listed; the default falls back to the first (only) SSD candidate
        // rather than defaulting to nothing.
        let disks = vec![
            disk(0, "Samsung 9100 PRO 1TB", "S1", "NVMe", true),
            disk(1, "WD Blue HDD 2TB", "H1", "SATA", false),
        ];
        let volumes = vec![vol("C:\\", 1, true), vol("D:\\", 0, true)];
        let candidates = build_candidates(&disks, &volumes, Some(1));
        assert_eq!(candidates.len(), 1);
        assert_eq!(default_candidate_index(&candidates), Some(0));
        assert!(!candidates[0].is_system);
    }

    struct Fake {
        disks: Vec<PhysicalDiskInfo>,
        volumes: Vec<VolumeInfo>,
        system_index: Option<u32>,
    }
    impl TopologySource for Fake {
        fn physical_disks(&self) -> Vec<PhysicalDiskInfo> {
            self.disks.clone()
        }
        fn volumes(&self) -> Vec<VolumeInfo> {
            self.volumes.clone()
        }
        fn system_drive_physical_index(&self) -> Option<u32> {
            self.system_index
        }
    }

    #[test]
    fn candidates_from_a_topology_source_matches_build_candidates() {
        let fake = Fake {
            disks: vec![disk(0, "Samsung 9100 PRO 1TB", "S1", "NVMe", true)],
            volumes: vec![vol("C:\\", 0, true)],
            system_index: Some(0),
        };
        let candidates = candidates_from(&fake);
        assert_eq!(candidates.len(), 1);
        assert!(candidates[0].is_system);
    }

    #[test]
    fn interface_text_is_reported_verbatim_never_a_guessed_pcie_generation() {
        let d = disk(0, "Samsung 9100 PRO 1TB", "S1", "NVMe", true);
        assert_eq!(interface_text(&d), "NVMe");
        // No PCIe generation invented from the model string.
        assert!(!interface_text(&d).contains("PCIe"));
        let unknown = disk(1, "Some Drive", "", "", true);
        assert_eq!(interface_text(&unknown), "—");
    }

    #[test]
    fn serial_text_is_none_when_windows_reports_nothing() {
        let with_serial = disk(0, "Samsung 9100 PRO 1TB", "S1", "NVMe", true);
        assert_eq!(serial_text(&with_serial).as_deref(), Some("S1"));
        let without = disk(1, "Netac NV7000T 1TB", "", "NVMe", true);
        assert_eq!(serial_text(&without), None);
    }

    #[test]
    fn drive_letter_text_falls_back_to_dash_without_a_volume() {
        let candidates = build_candidates(
            &[disk(0, "Samsung 9100 PRO 1TB", "S1", "NVMe", true)],
            &[],
            None,
        );
        assert_eq!(drive_letter_text(&candidates[0]), "—");
        let with_vol = build_candidates(
            &[disk(0, "Samsung 9100 PRO 1TB", "S1", "NVMe", true)],
            &[vol("C:\\", 0, true)],
            None,
        );
        assert_eq!(drive_letter_text(&with_vol[0]), "C:");
    }

    #[test]
    fn capacity_text_matches_the_label_rounding() {
        let d = disk(0, "Samsung 9100 PRO 1TB", "S1", "NVMe", true);
        assert_eq!(capacity_text(&d), "1 TB");
    }
}
