//! One read-only inventory, not another sensor poll. Join only exact unique serials.
use super::*;
#[derive(Clone, Debug)]
pub(super) struct Identity {
    pub hardware: String,
    pub model: String,
}
const QUERY: &str = r#"$ErrorActionPreference='Stop';$p=@(Get-CimInstance -Namespace root/Microsoft/Windows/Storage -ClassName MSFT_PhysicalDisk -ErrorAction Stop|Select-Object -First 128 DeviceId,SerialNumber,FriendlyName);$d=@(Get-CimInstance -ClassName Win32_DiskDrive -ErrorAction Stop|Select-Object -First 128 Index,SerialNumber,Model);@{Physical=$p;Disks=$d}|ConvertTo-Json -Depth 4 -Compress"#;
pub(super) fn start() -> Receiver<Result<BTreeMap<String, Identity>, String>> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let result =
            crate::ps_exec::run_powershell("powershell.exe", QUERY, Duration::from_secs(5))
                .map_err(|e| e.to_string())
                .and_then(|s| decode(&s));
        let _ = tx.send(result);
    });
    rx
}
fn decode(raw: &str) -> Result<BTreeMap<String, Identity>, String> {
    use crate::deep_checks::json;
    let data = json::parse(raw.trim_start_matches('\u{feff}'))
        .ok_or("Некорректный результат инвентаризации")?;
    let mut result = BTreeMap::new();
    let physical = crate::repair_center::rows(&data, "Physical");
    let disks = crate::repair_center::rows(&data, "Disks");
    let serial = |v: &json::Value| {
        crate::repair_center::field(v, "SerialNumber")
            .trim()
            .to_ascii_uppercase()
    };
    for p in physical {
        let key = serial(p);
        let first = key.chars().next().unwrap_or('\0');
        if matches!(
            key.as_str(),
            "UNKNOWN" | "NONE" | "NOT SPECIFIED" | "TO BE FILLED BY O.E.M."
        ) || key.chars().all(|c| c == first)
            || key.len() < 4
            || key.chars().all(|c| c == '0' || c.is_whitespace())
            || physical.iter().filter(|p| serial(p) == key).count() != 1
        {
            continue;
        }
        let matches: Vec<_> = disks.iter().filter(|d| serial(d) == key).collect();
        if matches.len() != 1 {
            continue;
        }
        let d = matches[0];
        let model = crate::repair_center::field(d, "Model");
        let index = match d.get("Index") {
            Some(json::Value::Num(n)) if *n >= 0. && *n <= 127. && n.fract() == 0. => *n as u32,
            _ => continue,
        };
        let id = crate::repair_center::field(p, "DeviceId");
        if id.is_empty() || !id.chars().all(|c| c.is_ascii_digit()) || model.is_empty() {
            continue;
        }
        result.insert(
            format!("storage.{id}"),
            Identity {
                hardware: format!("disk/{index}"),
                model: model.into(),
            },
        );
    }
    Ok(result)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn join_requires_exact_unique_identity_not_similar_model_or_equal_index() {
        let raw = r#"{"Physical":[{"DeviceId":"7","SerialNumber":"SYNTHETIC-ABC","FriendlyName":"Same model"}],"Disks":[{"Index":2,"SerialNumber":"synthetic-abc","Model":"Synthetic Disk"}]}"#;
        let m = decode(raw).unwrap();
        assert_eq!(m["storage.7"].hardware, "disk/2");
        assert!(
            decode(&raw.replace("synthetic-abc", "DIFFERENT"))
                .unwrap()
                .is_empty()
        );
        let duplicate = raw.replace("\"Index\":2", "\"Index\":3").replace(
            "}]}",
            "},{\"Index\":2,\"SerialNumber\":\"SYNTHETIC-ABC\",\"Model\":\"Synthetic Disk\"}]}",
        );
        assert!(decode(&duplicate).unwrap().is_empty());
    }
}
