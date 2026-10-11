//! v1.0 ATA / SATA SMART reader — STRICTLY READ-ONLY.
//!
//! Only two SMART commands are ever sent, through the documented Windows
//! disk IOCTLs:
//!   * `SMART_GET_VERSION` — does the driver path support SMART at all;
//!   * `SMART_RCV_DRIVE_DATA` with SMART READ DATA (0xB0 / feature 0xD0)
//!     and SMART READ THRESHOLDS (0xB0 / feature 0xD1).
//!
//! No SMART enable/disable, no attribute autosave, no self-test, no
//! RETURN STATUS / send command, no pass-through, no vendor commands, no
//! data written. Windows defines `SMART_RCV_DRIVE_DATA` with read+write
//! *handle* access, so the handle is first opened GENERIC_READ and, only if
//! the IOCTL is refused for access, re-opened read+write — the command set
//! stays the two read commands above (asserted by a source test).
//!
//! A controller / USB bridge / RAID (RST) path that blocks SMART yields
//! UNSUPPORTED / INSUFFICIENT DATA — never a disk failure, never invented
//! attributes.

// The Windows reader is not compiled for tests (no real devices).
#![cfg_attr(any(test, not(windows)), allow(dead_code))]

use crate::deep_checks::json;

/// SMART READ DATA / READ THRESHOLDS feature codes (the only ones used).
pub const SMART_READ_DATA: u8 = 0xD0;
pub const SMART_READ_THRESHOLDS: u8 = 0xD1;
pub const SMART_CMD: u8 = 0xB0;

/// One SMART attribute with its threshold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute {
    pub id: u8,
    pub current: u8,
    pub worst: u8,
    pub threshold: Option<u8>,
    /// 48-bit raw value (vendor encoding; meaningful for the standard ids).
    pub raw: u64,
}

impl Attribute {
    /// Normalised value at or below a non-zero threshold: the drive's own
    /// "threshold exceeded" condition.
    pub fn failing(&self) -> bool {
        matches!(self.threshold, Some(t) if t > 0 && self.current <= t)
    }
}

/// Standard attribute names (only well-known, vendor-independent ids).
pub fn attribute_name(id: u8) -> &'static str {
    match id {
        1 => "Raw Read Error Rate",
        5 => "Reallocated Sectors Count",
        9 => "Power-On Hours",
        10 => "Spin Retry Count",
        12 => "Power Cycle Count",
        177 => "Wear Leveling Count (vendor)",
        184 => "End-to-End Error",
        187 => "Reported Uncorrectable Errors",
        188 => "Command Timeout",
        190 => "Airflow Temperature",
        194 => "Temperature",
        196 => "Reallocation Event Count",
        197 => "Current Pending Sector Count",
        198 => "Offline Uncorrectable Sector Count",
        199 => "UDMA CRC Error Count",
        202 => "Percent Lifetime Remaining (vendor)",
        231 => "SSD Life Left (vendor)",
        233 => "Media Wearout Indicator (vendor)",
        241 => "Total LBAs Written",
        _ => "",
    }
}

/// Result state of one ATA SMART read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtaState {
    /// Attributes read.
    Ok,
    /// The driver / bridge / RAID path does not pass SMART through.
    Unsupported,
    /// Device could not be opened (access, missing).
    InsufficientData,
}

impl AtaState {
    pub fn code(self) -> &'static str {
        match self {
            AtaState::Ok => "OK",
            AtaState::Unsupported => "UNSUPPORTED",
            AtaState::InsufficientData => "INSUFFICIENT DATA",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtaSmart {
    pub state: AtaState,
    pub detail: String,
    pub attributes: Vec<Attribute>,
}

impl AtaSmart {
    pub fn unsupported(detail: impl Into<String>) -> Self {
        Self {
            state: AtaState::Unsupported,
            detail: detail.into(),
            attributes: Vec::new(),
        }
    }

    fn get(&self, id: u8) -> Option<&Attribute> {
        self.attributes.iter().find(|a| a.id == id)
    }

    /// Raw counter of a standard "count" attribute (low 32 bits; vendors
    /// use the upper bytes for other data).
    pub fn count(&self, id: u8) -> Option<u64> {
        self.get(id).map(|a| a.raw & 0xFFFF_FFFF)
    }

    /// Temperature °C (attribute 194, else 190; low byte of the raw value).
    pub fn temperature_c(&self) -> Option<u8> {
        self.get(194)
            .or_else(|| self.get(190))
            .map(|a| (a.raw & 0xFF) as u8)
            .filter(|t| (1..=100).contains(t))
    }

    pub fn power_on_hours(&self) -> Option<u64> {
        self.get(9).map(|a| a.raw & 0xFFFF_FFFF)
    }

    /// Vendor wear indicator (normalised current value of 177 / 202 / 231 /
    /// 233, whichever exists) — a vendor value, labelled as such.
    pub fn wear_indicator(&self) -> Option<(u8, u8)> {
        [231u8, 233, 202, 177]
            .iter()
            .find_map(|id| self.get(*id).map(|a| (*id, a.current)))
    }

    /// The drive's own SMART threshold verdict: any attribute at or below
    /// its non-zero threshold.
    pub fn threshold_exceeded(&self) -> Vec<u8> {
        self.attributes
            .iter()
            .filter(|a| a.failing())
            .map(|a| a.id)
            .collect()
    }

    /// Conservative health text (facts, not a verdict): threshold exceeded
    /// → "SMART: THRESHOLD EXCEEDED"; non-zero reallocated / pending /
    /// uncorrectable counters → "SMART: ATTENTION (sector counters)";
    /// otherwise "SMART: OK". Not read → the state code.
    pub fn health(&self) -> &'static str {
        if self.state != AtaState::Ok {
            return match self.state {
                AtaState::Unsupported => "SMART: UNSUPPORTED",
                _ => "SMART: INSUFFICIENT DATA",
            };
        }
        if !self.threshold_exceeded().is_empty() {
            "SMART: THRESHOLD EXCEEDED"
        } else if [5u8, 197, 198, 187]
            .iter()
            .any(|id| self.count(*id).is_some_and(|c| c > 0))
        {
            "SMART: ATTENTION (sector counters)"
        } else {
            "SMART: OK"
        }
    }

    /// Fact lines for Details / SMART card.
    pub fn fact_lines(&self) -> Vec<(String, String)> {
        let mut out = vec![("ATA SMART".to_string(), self.health().to_string())];
        if self.state != AtaState::Ok {
            if !self.detail.is_empty() {
                out.push((String::new(), self.detail.clone()));
            }
            return out;
        }
        let mut push = |k: &str, v: Option<String>| {
            if let Some(v) = v {
                out.push((k.to_string(), v));
            }
        };
        push(
            "Temperature",
            self.temperature_c().map(|t| format!("{t} °C")),
        );
        push(
            "Power-On Hours",
            self.power_on_hours().map(|h| h.to_string()),
        );
        for id in [5u8, 197, 198, 187, 199, 12] {
            push(attribute_name(id), self.count(id).map(|c| c.to_string()));
        }
        push(
            "Wear (vendor, normalised)",
            self.wear_indicator()
                .map(|(id, v)| format!("{v} (attr {id}, vendor-specific)")),
        );
        let exceeded = self.threshold_exceeded();
        if !exceeded.is_empty() {
            push(
                "Threshold exceeded",
                Some(
                    exceeded
                        .iter()
                        .map(|id| format!("{id} {}", attribute_name(*id)))
                        .collect::<Vec<_>>()
                        .join(", "),
                ),
            );
        }
        out
    }
}

/// Parses SMART READ DATA (512 bytes) + SMART READ THRESHOLDS (512 bytes).
/// Thirty 12-byte entries from offset 2; id 0 = empty slot.
pub fn parse(data: &[u8], thresholds: Option<&[u8]>) -> Result<Vec<Attribute>, String> {
    if data.len() < 362 {
        return Err(format!("SMART data too short ({} bytes)", data.len()));
    }
    let mut out = Vec::new();
    for i in 0..30 {
        let o = 2 + i * 12;
        let id = data[o];
        if id == 0 {
            continue;
        }
        let mut raw = 0u64;
        for (k, b) in data[o + 5..o + 11].iter().enumerate() {
            raw |= u64::from(*b) << (8 * k);
        }
        let threshold = thresholds.and_then(|t| {
            (0..30).find_map(|j| {
                let p = 2 + j * 12;
                (t.len() > p + 1 && t[p] == id).then_some(t[p + 1])
            })
        });
        out.push(Attribute {
            id,
            current: data[o + 3],
            worst: data[o + 4],
            threshold,
            raw,
        });
    }
    Ok(out)
}

pub fn to_json(s: &AtaSmart) -> String {
    let attrs: Vec<String> = s
        .attributes
        .iter()
        .map(|a| {
            format!(
                "{{\"id\": {}, \"name\": {}, \"current\": {}, \"worst\": {}, \"threshold\": {}, \"raw\": {}, \"threshold_exceeded\": {}}}",
                a.id,
                json::string(attribute_name(a.id)),
                a.current,
                a.worst,
                a.threshold
                    .map(|t| t.to_string())
                    .unwrap_or_else(|| "null".into()),
                a.raw,
                a.failing()
            )
        })
        .collect();
    format!(
        "{{\"source\": \"SMART_RCV_DRIVE_DATA (READ DATA 0xD0 + READ THRESHOLDS 0xD1), read-only\", \"state\": {}, \"health\": {}, \"detail\": {}, \"temperature_c\": {}, \"power_on_hours\": {}, \"reallocated_sectors\": {}, \"pending_sectors\": {}, \"offline_uncorrectable\": {}, \"reported_uncorrectable\": {}, \"udma_crc_errors\": {}, \"attributes\": [{}]}}",
        json::string(s.state.code()),
        json::string(s.health()),
        json::string(&s.detail),
        opt(s.temperature_c().map(u64::from)),
        opt(s.power_on_hours()),
        opt(s.count(5)),
        opt(s.count(197)),
        opt(s.count(198)),
        opt(s.count(187)),
        opt(s.count(199)),
        attrs.join(", ")
    )
}

fn opt(v: Option<u64>) -> String {
    v.map(|x| x.to_string()).unwrap_or_else(|| "null".into())
}

/// Reads ATA SMART of `\\.\PhysicalDrive<index>` (Windows only).
pub fn read(index: u32) -> AtaSmart {
    #[cfg(all(windows, not(test)))]
    {
        windows_reader::read(index)
    }
    #[cfg(any(not(windows), test))]
    {
        let _ = index;
        AtaSmart::unsupported("SMART reader not available on this host")
    }
}

#[cfg(all(windows, not(test)))]
mod windows_reader {
    use super::{AtaSmart, AtaState, SMART_CMD, SMART_READ_DATA, SMART_READ_THRESHOLDS};
    use std::ffi::c_void;
    use std::ptr::null_mut;

    type Handle = *mut c_void;
    const INVALID_HANDLE_VALUE: Handle = -1_isize as Handle;
    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_READ_AND_HANDLE_WRITE: u32 = 0x8000_0000 | 0x4000_0000;
    const FILE_SHARE_READ: u32 = 1;
    const FILE_SHARE_WRITE: u32 = 2;
    const OPEN_EXISTING: u32 = 3;
    const SMART_GET_VERSION: u32 = 0x0007_4080;
    const SMART_RCV_DRIVE_DATA: u32 = 0x0007_C088;
    const ERROR_ACCESS_DENIED: u32 = 5;

    unsafe extern "system" {
        fn CreateFileW(
            name: *const u16,
            access: u32,
            share: u32,
            sa: *mut c_void,
            disposition: u32,
            flags: u32,
            template: Handle,
        ) -> Handle;
        fn CloseHandle(h: Handle) -> i32;
        fn DeviceIoControl(
            h: Handle,
            code: u32,
            inb: *mut c_void,
            inlen: u32,
            outb: *mut c_void,
            outlen: u32,
            ret: *mut u32,
            ov: *mut c_void,
        ) -> i32;
        fn GetLastError() -> u32;
    }

    struct Owned(Handle);
    impl Drop for Owned {
        fn drop(&mut self) {
            // SAFETY: valid handle from CreateFileW, closed once.
            unsafe {
                CloseHandle(self.0);
            }
        }
    }

    fn open(index: u32, access: u32) -> Result<Owned, u32> {
        let path: Vec<u16> = format!(r"\\.\PhysicalDrive{index}")
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        // SAFETY: NUL-terminated path, null optional pointers.
        let h = unsafe {
            CreateFileW(
                path.as_ptr(),
                access,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                null_mut(),
                OPEN_EXISTING,
                0,
                null_mut(),
            )
        };
        if h == INVALID_HANDLE_VALUE || h.is_null() {
            Err(unsafe { GetLastError() })
        } else {
            Ok(Owned(h))
        }
    }

    /// GETVERSIONINPARAMS → (IDE device map, capabilities).
    fn version(h: &Owned) -> Option<(u8, u32)> {
        let mut out = [0u8; 24];
        let mut ret = 0u32;
        // SAFETY: fixed-size output buffer owned by this frame.
        let ok = unsafe {
            DeviceIoControl(
                h.0,
                SMART_GET_VERSION,
                null_mut(),
                0,
                out.as_mut_ptr().cast(),
                out.len() as u32,
                &mut ret,
                null_mut(),
            )
        };
        (ok != 0).then(|| (out[3], u32::from_le_bytes([out[4], out[5], out[6], out[7]])))
    }

    /// One SMART READ (feature `feature` ∈ {0xD0, 0xD1}) of drive `drive`.
    fn smart_read(h: &Owned, drive: u8, feature: u8) -> Result<Vec<u8>, u32> {
        debug_assert!(feature == SMART_READ_DATA || feature == SMART_READ_THRESHOLDS);
        // SENDCMDINPARAMS (packed, 33 bytes incl. the 1-byte buffer).
        let mut inp = [0u8; 33];
        inp[0..4].copy_from_slice(&512u32.to_le_bytes());
        inp[4] = feature; // bFeaturesReg
        inp[5] = 1; // bSectorCountReg
        inp[6] = 1; // bSectorNumberReg
        inp[7] = 0x4F; // bCylLowReg (SMART signature)
        inp[8] = 0xC2; // bCylHighReg
        inp[9] = 0xA0 | ((drive & 1) << 4); // bDriveHeadReg
        inp[10] = SMART_CMD; // bCommandReg
        inp[12] = drive; // bDriveNumber
        // SENDCMDOUTPARAMS: cBufferSize(4) + DRIVERSTATUS(12) + 512.
        let mut out = vec![0u8; 16 + 512];
        let mut ret = 0u32;
        // SAFETY: both buffers are owned and sized as declared.
        let ok = unsafe {
            DeviceIoControl(
                h.0,
                SMART_RCV_DRIVE_DATA,
                inp.as_mut_ptr().cast(),
                inp.len() as u32,
                out.as_mut_ptr().cast(),
                out.len() as u32,
                &mut ret,
                null_mut(),
            )
        };
        if ok == 0 {
            return Err(unsafe { GetLastError() });
        }
        if out[4] != 0 {
            // DRIVERSTATUS.bDriverError
            return Err(u32::from(out[4]) | 0x1000_0000);
        }
        Ok(out[16..].to_vec())
    }

    pub fn read(index: u32) -> AtaSmart {
        let mut last_err = 0u32;
        for access in [GENERIC_READ, GENERIC_READ_AND_HANDLE_WRITE] {
            let h = match open(index, access) {
                Ok(h) => h,
                Err(e) => {
                    last_err = e;
                    continue;
                }
            };
            let Some((_map, caps)) = version(&h) else {
                return AtaSmart::unsupported(
                    "SMART_GET_VERSION not supported by this driver path (USB bridge / RAID / RST / NVMe)",
                );
            };
            if caps & 0x4 == 0 {
                return AtaSmart::unsupported("driver reports no SMART command capability");
            }
            let drive = (index & 1) as u8;
            match smart_read(&h, drive, SMART_READ_DATA) {
                Ok(data) => {
                    let th = smart_read(&h, drive, SMART_READ_THRESHOLDS).ok();
                    return match super::parse(&data, th.as_deref()) {
                        Ok(attributes) if !attributes.is_empty() => AtaSmart {
                            state: AtaState::Ok,
                            detail: if th.is_some() {
                                String::new()
                            } else {
                                "thresholds not readable; values shown without threshold".into()
                            },
                            attributes,
                        },
                        Ok(_) => AtaSmart::unsupported("SMART data page empty"),
                        Err(e) => AtaSmart::unsupported(e),
                    };
                }
                Err(e) if e == ERROR_ACCESS_DENIED && access == GENERIC_READ => {
                    last_err = e;
                    continue;
                }
                Err(e) => {
                    return AtaSmart::unsupported(format!(
                        "SMART READ DATA refused by the driver path (code {e})"
                    ));
                }
            }
        }
        AtaSmart {
            state: AtaState::InsufficientData,
            detail: format!("device could not be opened (code {last_err})"),
            attributes: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page(entries: &[(u8, u8, u8, u64)]) -> Vec<u8> {
        let mut b = vec![0u8; 512];
        for (i, (id, cur, worst, raw)) in entries.iter().enumerate() {
            let o = 2 + i * 12;
            b[o] = *id;
            b[o + 3] = *cur;
            b[o + 4] = *worst;
            for k in 0..6 {
                b[o + 5 + k] = (raw >> (8 * k)) as u8;
            }
        }
        b
    }

    fn thresholds(entries: &[(u8, u8)]) -> Vec<u8> {
        let mut b = vec![0u8; 512];
        for (i, (id, t)) in entries.iter().enumerate() {
            let o = 2 + i * 12;
            b[o] = *id;
            b[o + 1] = *t;
        }
        b
    }

    #[test]
    fn healthy_hdd_attributes_parse_with_thresholds() {
        let data = page(&[
            (5, 100, 100, 0),
            (9, 98, 98, 12_345),
            (12, 100, 100, 880),
            (194, 125, 110, 0x0000_0012_0016_001E),
            (197, 100, 100, 0),
            (198, 100, 100, 0),
        ]);
        let th = thresholds(&[(5, 36), (9, 0), (194, 0), (197, 0)]);
        let attrs = parse(&data, Some(&th)).unwrap();
        let s = AtaSmart {
            state: AtaState::Ok,
            detail: String::new(),
            attributes: attrs,
        };
        assert_eq!(s.temperature_c(), Some(30));
        assert_eq!(s.power_on_hours(), Some(12_345));
        assert_eq!(s.count(5), Some(0));
        assert_eq!(s.health(), "SMART: OK");
        assert!(s.threshold_exceeded().is_empty());
        let js = to_json(&s);
        assert!(crate::deep_checks::json::parse(&js).is_some(), "{js}");
        assert!(js.contains("\"pending_sectors\": 0"));
    }

    #[test]
    fn sector_counters_are_attention_and_threshold_is_the_drive_verdict() {
        let data = page(&[(5, 90, 90, 16), (197, 100, 100, 2)]);
        let th = thresholds(&[(5, 36)]);
        let s = AtaSmart {
            state: AtaState::Ok,
            detail: String::new(),
            attributes: parse(&data, Some(&th)).unwrap(),
        };
        assert_eq!(s.health(), "SMART: ATTENTION (sector counters)");
        let failing = AtaSmart {
            state: AtaState::Ok,
            detail: String::new(),
            attributes: parse(&page(&[(5, 30, 30, 900)]), Some(&th)).unwrap(),
        };
        assert_eq!(failing.health(), "SMART: THRESHOLD EXCEEDED");
        assert_eq!(failing.threshold_exceeded(), vec![5]);
    }

    #[test]
    fn unsupported_path_is_honest_never_a_failure_and_never_fakes_values() {
        let s = AtaSmart::unsupported("USB bridge");
        assert_eq!(s.health(), "SMART: UNSUPPORTED");
        assert!(s.attributes.is_empty());
        assert_eq!(s.temperature_c(), None);
        assert!(parse(&[0u8; 10], None).is_err(), "truncated data rejected");
        // Tests never touch real devices.
        assert_eq!(read(0).state, AtaState::Unsupported);
    }

    #[test]
    fn reader_is_strictly_read_only() {
        let src = include_str!("ata_smart.rs");
        let code = &src[..src.find("#[cfg(test)]\nmod tests").unwrap()];
        for forbidden in [
            "SMART_SEND_DRIVE_COMMAND",
            "IOCTL_ATA_PASS_THROUGH",
            "IOCTL_SCSI_PASS_THROUGH",
            "WriteFile",
            "0xD8", // ENABLE OPERATIONS
            "0xD9", // DISABLE OPERATIONS
            "0xD4", // EXECUTE OFF-LINE IMMEDIATE (self-test)
            "0xD3", // ATTRIBUTE AUTOSAVE
            "0xD6", // WRITE LOG
            "0xDA", // RETURN STATUS (send command)
        ] {
            assert!(!code.contains(forbidden), "{forbidden} in ata_smart.rs");
        }
        let ioctls: Vec<&str> = code
            .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .filter(|w| {
                w.starts_with("SMART_") && w.chars().all(|c| c.is_ascii_uppercase() || c == '_')
            })
            .collect();
        for w in ioctls {
            assert!(
                matches!(
                    w,
                    "SMART_GET_VERSION"
                        | "SMART_RCV_DRIVE_DATA"
                        | "SMART_READ_DATA"
                        | "SMART_READ_THRESHOLDS"
                        | "SMART_CMD"
                        | "SMART_"
                ),
                "unexpected {w}"
            );
        }
        assert!(code.contains("pub const SMART_READ_DATA: u8 = 0xD0;"));
        assert!(code.contains("pub const SMART_READ_THRESHOLDS: u8 = 0xD1;"));
    }
}
