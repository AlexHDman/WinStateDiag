//! Group Policy / ADMX Health (v0.4.4) — READ-ONLY diagnostics.
//!
//! Inspects the local `%SystemRoot%\PolicyDefinitions` store and, on a
//! domain-joined machine with a reachable SYSVOL, the domain Central Store
//! (`\\<domain>\SYSVOL\<domain>\Policies\PolicyDefinitions`). Nothing is
//! copied, repaired, downloaded or changed; `gpupdate` is never run.
//!
//! Template generation evidence (never file names or timestamps): the
//! `supportedOn` references inside the ADMX files (`SUPPORTED_Windows_11_0_
//! 25H2`, …) and, when the administrator placed it next to WinStateDiag,
//! Microsoft's official Group Policy Settings Reference spreadsheet for the
//! installed release. Reference for Windows 11 26H2:
//! <https://aka.ms/Windows11/26H2/GPsettings> (download "Group Policy
//! Settings Reference Spreadsheet for Windows 11 2026 Update (26H2)").
//! 25H2 and 26H2 are kept separate; a release whose generation cannot be
//! proven is INSUFFICIENT DATA, never MISMATCH.

#![cfg_attr(not(windows), allow(dead_code))]

use crate::deep_checks::json;

pub const EVIDENCE_PREFIX: &str = "GroupPolicy_ADMX_Health_";
pub const MS_26H2_REFERENCE: &str = "https://aka.ms/Windows11/26H2/GPsettings";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpoStatus {
    Ok,
    Outdated,
    Mismatch,
    CentralStoreNotFound,
    NotApplicable,
    Unreachable,
    InsufficientData,
    /// v1.0: harmless local ADMX/ADML differences on a standalone PC
    /// (e.g. windowssandbox.admx without ru-RU ADML) — information only.
    Info,
}

impl GpoStatus {
    pub fn code(self) -> &'static str {
        match self {
            GpoStatus::Ok => "OK",
            GpoStatus::Outdated => "OUTDATED",
            GpoStatus::Mismatch => "MISMATCH",
            GpoStatus::CentralStoreNotFound => "CENTRAL STORE NOT FOUND",
            GpoStatus::NotApplicable => "NOT APPLICABLE",
            GpoStatus::Unreachable => "UNREACHABLE",
            GpoStatus::InsufficientData => "INSUFFICIENT DATA",
            GpoStatus::Info => "INFO",
        }
    }
    pub fn text(self, ru: bool) -> &'static str {
        if !ru {
            return self.code();
        }
        match self {
            GpoStatus::Ok => "OK",
            GpoStatus::Outdated => "УСТАРЕЛИ",
            GpoStatus::Mismatch => "НЕСООТВЕТСТВИЕ",
            GpoStatus::CentralStoreNotFound => "ЦЕНТРАЛЬНОЕ ХРАНИЛИЩЕ НЕ НАЙДЕНО",
            GpoStatus::NotApplicable => "НЕ ПРИМЕНИМО",
            GpoStatus::Unreachable => "НЕДОСТУПНО",
            GpoStatus::InsufficientData => "НЕДОСТАТОЧНО ДАННЫХ",
            GpoStatus::Info => "ИНФО",
        }
    }
}

/// `25H2` → (25, 2) for ordering; anything else → None.
pub fn release_key(r: &str) -> Option<(u32, u32)> {
    let r = r.trim().to_ascii_uppercase();
    let (y, h) = r.split_once('H')?;
    Some((y.parse().ok()?, h.parse().ok()?))
}

/// One ADMX/ADML store (local or central).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Store {
    pub path: String,
    pub exists: bool,
    /// ADMX file name (lower-case) → revision attribute.
    pub admx: Vec<(String, String)>,
    /// language → ADML file names (lower-case).
    pub adml: Vec<(String, Vec<String>)>,
    /// `SUPPORTED_*` definitions found (normally in windows.admx).
    pub supported_defined: Vec<String>,
    /// `windows:SUPPORTED_*` references used by policies.
    pub supported_referenced: Vec<String>,
    /// Newest Windows 11 release named by supportedOn references.
    pub newest_release: Option<String>,
}

impl Store {
    pub fn admx_names(&self) -> Vec<&str> {
        self.admx.iter().map(|(n, _)| n.as_str()).collect()
    }
    /// ADMX files without an ADML for `lang`.
    pub fn missing_adml(&self, lang: &str) -> Vec<String> {
        let Some((_, list)) = self.adml.iter().find(|(l, _)| l.eq_ignore_ascii_case(lang)) else {
            return self.admx.iter().map(|(n, _)| n.clone()).collect();
        };
        self.admx
            .iter()
            .filter(|(n, _)| {
                let adml = n.trim_end_matches(".admx").to_string() + ".adml";
                !list.contains(&adml)
            })
            .map(|(n, _)| n.clone())
            .collect()
    }
    pub fn adml_count(&self) -> usize {
        self.adml.iter().map(|(_, l)| l.len()).sum()
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct GpoInputs {
    pub domain_joined: bool,
    pub domain: String,
    /// SYSVOL `\\<domain>\SYSVOL\<domain>\Policies` reachable.
    pub sysvol_reachable: bool,
    pub windows_build: String,
    /// `DisplayVersion` (e.g. 25H2 / 26H2), empty when unknown.
    pub windows_release: String,
    pub ui_language: String,
    pub local: Store,
    pub central: Option<Store>,
    /// ADMX files documented by Microsoft's reference spreadsheet for the
    /// installed release (empty = reference not available).
    pub reference_release: String,
    pub reference_admx: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GpoResult {
    /// Central Store / domain verdict (NOT APPLICABLE on a standalone PC).
    pub status: GpoStatus,
    /// v1.0: health of the LOCAL `%SystemRoot%\PolicyDefinitions`, always
    /// evaluated separately — also on a standalone machine.
    pub local_status: GpoStatus,
    pub local_findings: Vec<String>,
    pub missing_adml: Vec<String>,
    pub version_findings: Vec<String>,
    pub mismatch_findings: Vec<String>,
    pub info: Vec<String>,
}

fn undefined_refs(store: &Store) -> Vec<String> {
    if store.supported_defined.is_empty() {
        return Vec::new();
    }
    let mut v: Vec<String> = store
        .supported_referenced
        .iter()
        .filter(|r| {
            !store
                .supported_defined
                .iter()
                .any(|d| d.eq_ignore_ascii_case(r))
        })
        .cloned()
        .collect();
    v.sort();
    v.dedup();
    v
}

/// Generation verdict for one store against the installed release.
/// `Some(true)` = proven outdated, `Some(false)` = proven current,
/// `None` = cannot be proven.
fn generation(store: &Store, inputs: &GpoInputs, findings: &mut Vec<String>) -> Option<bool> {
    let installed = release_key(&inputs.windows_release)?;
    // Official reference (only for the SAME release as installed).
    if !inputs.reference_admx.is_empty()
        && release_key(&inputs.reference_release) == Some(installed)
    {
        let names = store.admx_names();
        let missing: Vec<&String> = inputs
            .reference_admx
            .iter()
            .filter(|r| !names.contains(&r.to_ascii_lowercase().as_str()))
            .collect();
        if !missing.is_empty() {
            findings.push(format!(
                "{} ADMX file(s) documented by the Microsoft {} reference are absent: {}",
                missing.len(),
                inputs.reference_release,
                missing
                    .iter()
                    .take(10)
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
            return Some(true);
        }
        return Some(false);
    }
    let newest = store.newest_release.as_deref().and_then(release_key)?;
    if newest >= installed {
        Some(false)
    } else {
        findings.push(format!(
            "newest Windows release named by supportedOn: {}; installed: {}",
            store.newest_release.as_deref().unwrap_or("?"),
            inputs.windows_release
        ));
        Some(true)
    }
}

/// v1.0 local PolicyDefinitions health (independent of the domain):
/// store absent → INSUFFICIENT DATA; ADMX without an ADML of the UI
/// language or undefined supportedOn references → MISMATCH; template
/// generation older than the installed release → OUTDATED; proven current
/// → OK; generation not provable → INSUFFICIENT DATA.
pub fn classify_local(i: &GpoInputs) -> (GpoStatus, Vec<String>) {
    let mut findings = Vec::new();
    if !i.local.exists || i.local.admx.is_empty() {
        findings.push("local PolicyDefinitions store not found or empty".into());
        return (GpoStatus::InsufficientData, findings);
    }
    let lang = if i.ui_language.is_empty() {
        "en-US"
    } else {
        &i.ui_language
    };
    let missing = i.local.missing_adml(lang);
    let undefined = undefined_refs(&i.local);
    if !missing.is_empty() {
        findings.push(format!(
            "{} local ADMX without a {lang} ADML: {}",
            missing.len(),
            missing
                .iter()
                .take(8)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if !undefined.is_empty() {
        findings.push(format!(
            "supportedOn references without a definition in the local store: {}",
            undefined
                .iter()
                .take(8)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if !findings.is_empty() {
        return (GpoStatus::Mismatch, findings);
    }
    let status = match generation(&i.local, i, &mut findings) {
        Some(true) => GpoStatus::Outdated,
        Some(false) => GpoStatus::Ok,
        None => GpoStatus::InsufficientData,
    };
    (status, findings)
}

pub fn classify(i: &GpoInputs) -> GpoResult {
    let (local_status, local_findings) = classify_local(i);
    let mut r = GpoResult {
        local_status,
        local_findings,
        status: GpoStatus::Ok,
        missing_adml: Vec::new(),
        version_findings: Vec::new(),
        mismatch_findings: Vec::new(),
        info: Vec::new(),
    };
    let lang = if i.ui_language.is_empty() {
        "en-US"
    } else {
        &i.ui_language
    };
    // Local store facts are always collected (informational when a Central
    // Store is in use).
    let local_missing = i.local.missing_adml(lang);
    if !i.domain_joined {
        // v1.0: on a standalone PC local ADMX/ADML inconsistencies are
        // harmless (no domain editors depend on them): INFO, not MISMATCH.
        if r.local_status == GpoStatus::Mismatch {
            r.local_status = GpoStatus::Info;
        }
        r.status = GpoStatus::NotApplicable;
        r.missing_adml = local_missing;
        r.info
            .push("standalone machine: no domain Central Store".into());
        return r;
    }
    if !i.sysvol_reachable {
        r.status = GpoStatus::Unreachable;
        r.info.push(
            "domain controller / SYSVOL not reachable now; Central Store not evaluated".into(),
        );
        return r;
    }
    let Some(central) = i.central.as_ref().filter(|c| c.exists) else {
        r.status = GpoStatus::CentralStoreNotFound;
        r.info.push("SYSVOL Policies reachable, PolicyDefinitions absent: editors fall back to each admin's local store".into());
        return r;
    };
    // Central Store: what domain Group Policy editors actually use.
    r.missing_adml = central.missing_adml(lang);
    let undefined = undefined_refs(central);
    if !undefined.is_empty() {
        r.mismatch_findings.push(format!(
            "supportedOn references without a definition in the Central Store (mixed template generations): {}",
            undefined.iter().take(8).cloned().collect::<Vec<_>>().join(", ")
        ));
    }
    if !r.missing_adml.is_empty() {
        r.mismatch_findings.push(format!(
            "{} ADMX without a {lang} ADML in the Central Store",
            r.missing_adml.len()
        ));
    }
    // Local vs central: informational divergence only.
    let local_names = i.local.admx_names();
    let central_names = central.admx_names();
    let only_local = local_names
        .iter()
        .filter(|n| !central_names.contains(n))
        .count();
    let only_central = central_names
        .iter()
        .filter(|n| !local_names.contains(n))
        .count();
    let revision_diff: Vec<String> = i
        .local
        .admx
        .iter()
        .filter_map(|(n, rev)| {
            central
                .admx
                .iter()
                .find(|(c, _)| c == n)
                .filter(|(_, crev)| !crev.is_empty() && !rev.is_empty() && crev != rev)
                .map(|(_, crev)| format!("{n}: local {rev} / central {crev}"))
        })
        .collect();
    if only_local + only_central > 0 || !revision_diff.is_empty() {
        r.info.push(format!(
            "local vs Central Store: {only_local} only local, {only_central} only central, {} revision differences (informational — editors use the Central Store)",
            revision_diff.len()
        ));
        r.version_findings
            .extend(revision_diff.into_iter().take(10));
    }
    let verdict = generation(central, i, &mut r.version_findings);
    r.status = if !r.mismatch_findings.is_empty() {
        GpoStatus::Mismatch
    } else {
        match verdict {
            Some(true) => GpoStatus::Outdated,
            Some(false) => GpoStatus::Ok,
            None => GpoStatus::InsufficientData,
        }
    };
    r
}

// ---------------------------------------------------------------------
// Collector
// ---------------------------------------------------------------------

/// Read-only collector. Prints one `WSD_GPO <json>` line. The SYSVOL probe
/// runs in a background job with a 15 s limit (an unreachable DC never
/// hangs the diagnostics). The optional Microsoft reference spreadsheet is
/// read (never downloaded) from `<EXE dir>\Reference\`.
pub const COLLECTOR_PS1: &str = r#"param([string]$ReferenceDir = '')
$ErrorActionPreference = 'Continue'
function Read-Store([string]$path, [string[]]$langs) {
    $st = [ordered]@{ path = $path; exists = $false; admx = @(); adml = @(); defined = @(); referenced = @() }
    if (-not $path -or -not (Test-Path -LiteralPath $path)) { return $st }
    $st.exists = $true
    $refs = New-Object System.Collections.Generic.HashSet[string]
    $defs = New-Object System.Collections.Generic.HashSet[string]
    foreach ($f in @(Get-ChildItem -LiteralPath $path -Filter *.admx -File -ErrorAction SilentlyContinue)) {
        $rev = ''
        try {
            $text = [IO.File]::ReadAllText($f.FullName)
            $m = [regex]::Match($text, '<policyDefinitions[^>]*\srevision="([^"]+)"')
            if ($m.Success) { $rev = $m.Groups[1].Value }
            foreach ($x in [regex]::Matches($text, 'ref="(?:[A-Za-z]+:)?(SUPPORTED_[A-Za-z0-9_]+)"')) { [void]$refs.Add($x.Groups[1].Value) }
            foreach ($x in [regex]::Matches($text, '<definition\s+name="(SUPPORTED_[A-Za-z0-9_]+)"')) { [void]$defs.Add($x.Groups[1].Value) }
        } catch { }
        $st.admx += [PSCustomObject]@{ n = $f.Name.ToLowerInvariant(); r = $rev }
    }
    foreach ($l in $langs) {
        $dir = Join-Path $path $l
        $names = @()
        if (Test-Path -LiteralPath $dir) { $names = @(Get-ChildItem -LiteralPath $dir -Filter *.adml -File -ErrorAction SilentlyContinue | ForEach-Object { $_.Name.ToLowerInvariant() }) }
        $st.adml += [PSCustomObject]@{ lang = $l; files = @($names) }
    }
    $st.defined = @($defs)
    $st.referenced = @($refs)
    return $st
}
$cs = $null
try { $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop } catch { }
$joined = [bool]($cs -and $cs.PartOfDomain)
$domain = ''
if ($joined) { $domain = [string]$cs.Domain }
$cv = $null
try { $cv = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop } catch { }
$build = ''
$release = ''
if ($cv) { $build = ('{0}.{1}' -f $cv.CurrentBuild, $cv.UBR); $release = [string]$cv.DisplayVersion }
$ui = (Get-Culture).Name
$langs = @('en-US')
if ($ui -and $ui -ne 'en-US') { $langs += $ui }
$localPath = ''
if ($env:SystemRoot) { $localPath = Join-Path $env:SystemRoot 'PolicyDefinitions' }
$local = Read-Store $localPath $langs
$reachable = $false
$central = $null
if ($joined -and $domain) {
    $policies = "\\$domain\SYSVOL\$domain\Policies"
    $job = Start-Job -ScriptBlock { param($p) Test-Path -LiteralPath $p } -ArgumentList $policies
    if (Wait-Job $job -Timeout 15) { $reachable = [bool](Receive-Job $job) }
    Remove-Job $job -Force -ErrorAction SilentlyContinue
    if ($reachable) { $central = Read-Store (Join-Path $policies 'PolicyDefinitions') $langs }
}
$refRelease = ''
$refAdmx = @()
if ($release -and $ReferenceDir -and (Test-Path -LiteralPath $ReferenceDir)) {
    $x = Get-ChildItem -LiteralPath $ReferenceDir -Filter ("*{0}*.xlsx" -f $release) -File -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($x) {
        try {
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            $zip = [IO.Compression.ZipFile]::OpenRead($x.FullName)
            try {
                $sst = @()
                $e = $zip.GetEntry('xl/sharedStrings.xml')
                if ($e) { $r = New-Object IO.StreamReader($e.Open()); [xml]$sx = $r.ReadToEnd(); $r.Dispose(); $sst = @($sx.sst.si | ForEach-Object { $_.InnerText }) }
                $names = New-Object System.Collections.Generic.HashSet[string]
                foreach ($s in $sst) { if ($s -match '^[A-Za-z0-9_.-]+\.admx$') { [void]$names.Add($s.ToLowerInvariant()) } }
                $refAdmx = @($names)
                $refRelease = $release
            } finally { $zip.Dispose() }
        } catch { }
    }
}
$out = [PSCustomObject]@{ joined = $joined; domain = $domain; reachable = $reachable; build = $build; release = $release; ui = $ui; local = $local; central = $central; ref_release = $refRelease; ref_admx = $refAdmx }
Write-Output ('WSD_GPO ' + (ConvertTo-Json -InputObject $out -Depth 6 -Compress))
"#;

fn strs(v: Option<&json::Value>) -> Vec<String> {
    match v {
        Some(json::Value::Arr(a)) => a
            .iter()
            .filter_map(|x| x.as_str().map(str::to_string))
            .collect(),
        Some(json::Value::Str(s)) => vec![s.clone()],
        _ => Vec::new(),
    }
}

fn objs(v: Option<&json::Value>) -> Vec<json::Value> {
    match v {
        Some(json::Value::Arr(a)) => a.clone(),
        Some(o @ json::Value::Obj(_)) => vec![o.clone()],
        _ => Vec::new(),
    }
}

/// Newest `Windows_11_0_xxHy` release named by supportedOn identifiers.
pub fn newest_release(ids: &[String]) -> Option<String> {
    let mut best: Option<((u32, u32), String)> = None;
    for id in ids {
        let up = id.to_ascii_uppercase();
        let Some(pos) = up.find("WINDOWS_11_0") else {
            continue;
        };
        for part in up[pos..].split('_') {
            if let Some(k) = release_key(part) {
                if part.len() == 4 && best.as_ref().is_none_or(|(b, _)| k > *b) {
                    best = Some((k, part.to_string()));
                }
            }
        }
    }
    best.map(|(_, s)| s)
}

fn store(v: &json::Value) -> Store {
    let admx: Vec<(String, String)> = objs(v.get("admx"))
        .iter()
        .filter_map(|a| {
            Some((
                a.get("n")?.as_str()?.to_string(),
                a.get("r")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string(),
            ))
        })
        .collect();
    let adml = objs(v.get("adml"))
        .iter()
        .filter_map(|a| Some((a.get("lang")?.as_str()?.to_string(), strs(a.get("files")))))
        .collect();
    let referenced = strs(v.get("referenced"));
    Store {
        path: v
            .get("path")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string(),
        exists: matches!(v.get("exists"), Some(json::Value::Bool(true))),
        admx,
        adml,
        supported_defined: strs(v.get("defined")),
        newest_release: newest_release(&referenced),
        supported_referenced: referenced,
    }
}

pub fn parse_output(stdout: &str) -> Option<GpoInputs> {
    let v = json::parse(crate::ps_exec::marked_line(stdout, "WSD_GPO ")?)?;
    let s = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
    Some(GpoInputs {
        domain_joined: matches!(v.get("joined"), Some(json::Value::Bool(true))),
        domain: s("domain"),
        sysvol_reachable: matches!(v.get("reachable"), Some(json::Value::Bool(true))),
        windows_build: s("build"),
        windows_release: s("release"),
        ui_language: s("ui"),
        local: v.get("local").map(store).unwrap_or_default(),
        central: v
            .get("central")
            .filter(|c| !matches!(c, json::Value::Null))
            .map(store),
        reference_release: s("ref_release"),
        reference_admx: strs(v.get("ref_admx")),
    })
}

/// Runs the collector (Windows: powershell.exe). The script is passed with
/// its reference-folder argument appended as a parameter block call.
pub fn collect(host: &str, reference_dir: &std::path::Path) -> Result<GpoInputs, String> {
    let script = format!(
        "& {{\n{COLLECTOR_PS1}\n}} -ReferenceDir '{}'",
        reference_dir.display().to_string().replace('\'', "''")
    );
    let out = crate::ps_exec::run_powershell(host, &script, std::time::Duration::from_secs(120))
        .map_err(|e| e.to_string())?;
    parse_output(&out).ok_or_else(|| "Group Policy collector produced no result".into())
}

// ---------------------------------------------------------------------
// Evidence
// ---------------------------------------------------------------------

pub fn evidence_name(stamp: &str, ext: &str) -> String {
    format!("{EVIDENCE_PREFIX}{stamp}.{ext}")
}

fn list(v: &[String]) -> String {
    if v.is_empty() {
        "[]".into()
    } else {
        format!(
            "[{}]",
            v.iter()
                .map(|s| json::string(s))
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

fn store_json(s: Option<&Store>, lang: &str) -> String {
    match s {
        None => "null".into(),
        Some(s) => format!(
            "{{\"exists\": {}, \"admx_count\": {}, \"adml_count\": {}, \"missing_adml_count\": {}, \"newest_supported_release\": {}}}",
            s.exists,
            s.admx.len(),
            s.adml_count(),
            if s.exists {
                s.missing_adml(lang).len()
            } else {
                0
            },
            s.newest_release
                .as_deref()
                .map(json::string)
                .unwrap_or_else(|| "null".into())
        ),
    }
}

/// Evidence JSON. The domain DNS name is recorded (needed to interpret the
/// result); no credentials, user names or SYSVOL contents are included.
pub fn to_json(i: &GpoInputs, r: &GpoResult) -> String {
    let lang = if i.ui_language.is_empty() {
        "en-US"
    } else {
        &i.ui_language
    };
    let admx_store = i.central.as_ref().filter(|c| c.exists).unwrap_or(&i.local);
    format!(
        "{{\n  \"format\": \"winstatediag.group_policy_admx/1\",\n  \"status\": {},\n  \"central_store_status\": {},\n  \"local_store_status\": {},\n  \"local_store_findings\": {},\n  \"machine_mode\": {},\n  \"domain_name\": {},\n  \"domain_reachable\": {},\n  \"local_store\": {},\n  \"central_store\": {},\n  \"windows_build\": {},\n  \"windows_release\": {},\n  \"admx_count\": {},\n  \"adml_count\": {},\n  \"missing_adml\": {},\n  \"version_findings\": {},\n  \"mismatch_findings\": {},\n  \"info\": {},\n  \"reference\": {{\"release\": {}, \"admx_documented\": {}, \"source\": {}}}\n}}\n",
        json::string(r.status.code()),
        json::string(r.status.code()),
        json::string(r.local_status.code()),
        list(&r.local_findings),
        json::string(if i.domain_joined {
            "domain_joined"
        } else {
            "standalone"
        }),
        if i.domain.is_empty() {
            "null".into()
        } else {
            json::string(&i.domain)
        },
        if i.domain_joined {
            i.sysvol_reachable.to_string()
        } else {
            "null".into()
        },
        store_json(Some(&i.local), lang),
        store_json(i.central.as_ref(), lang),
        json::string(&i.windows_build),
        json::string(&i.windows_release),
        admx_store.admx.len(),
        admx_store.adml_count(),
        list(&r.missing_adml),
        list(&r.version_findings),
        list(&r.mismatch_findings),
        list(&r.info),
        if i.reference_release.is_empty() {
            "null".into()
        } else {
            json::string(&i.reference_release)
        },
        i.reference_admx.len(),
        json::string(MS_26H2_REFERENCE)
    )
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn st(
        admx: &[(&str, &str)],
        adml: &[&str],
        defined: &[&str],
        refs: &[&str],
    ) -> Store {
        let referenced: Vec<String> = refs.iter().map(|s| s.to_string()).collect();
        Store {
            path: "x".into(),
            exists: true,
            admx: admx
                .iter()
                .map(|(n, r)| (n.to_string(), r.to_string()))
                .collect(),
            adml: vec![("en-US".into(), adml.iter().map(|s| s.to_string()).collect())],
            supported_defined: defined.iter().map(|s| s.to_string()).collect(),
            newest_release: newest_release(&referenced),
            supported_referenced: referenced,
        }
    }

    fn good_store(newest: &str) -> Store {
        let r = format!("SUPPORTED_Windows_11_0_{newest}");
        st(
            &[("windows.admx", "1.0"), ("bits.admx", "1.0")],
            &["windows.adml", "bits.adml"],
            &[&r, "SUPPORTED_Windows7"],
            &[&r, "SUPPORTED_Windows7"],
        )
    }

    fn domain(central: Option<Store>, release: &str) -> GpoInputs {
        GpoInputs {
            domain_joined: true,
            domain: "contoso.local".into(),
            sysvol_reachable: true,
            windows_build: "26200.7000".into(),
            windows_release: release.into(),
            ui_language: "en-US".into(),
            local: good_store("25H2"),
            central,
            ..Default::default()
        }
    }

    #[test]
    fn standalone_is_not_applicable() {
        let i = GpoInputs {
            domain_joined: false,
            windows_release: "25H2".into(),
            local: good_store("25H2"),
            ..Default::default()
        };
        assert_eq!(classify(&i).status, GpoStatus::NotApplicable);
    }

    #[test]
    fn domain_central_store_ok_missing_and_unreachable() {
        assert_eq!(
            classify(&domain(Some(good_store("25H2")), "25H2")).status,
            GpoStatus::Ok
        );
        assert_eq!(
            classify(&domain(None, "25H2")).status,
            GpoStatus::CentralStoreNotFound
        );
        let mut missing = good_store("25H2");
        missing.exists = false;
        assert_eq!(
            classify(&domain(Some(missing), "25H2")).status,
            GpoStatus::CentralStoreNotFound
        );
        let mut i = domain(None, "25H2");
        i.sysvol_reachable = false;
        let r = classify(&i);
        assert_eq!(
            r.status,
            GpoStatus::Unreachable,
            "never 'not found' when unreachable"
        );
    }

    #[test]
    fn missing_adml_and_true_mismatch() {
        let mut c = good_store("25H2");
        c.adml[0].1.pop();
        let r = classify(&domain(Some(c), "25H2"));
        assert_eq!(r.status, GpoStatus::Mismatch);
        assert_eq!(r.missing_adml, ["bits.admx"]);
        // A policy referencing a 26H2 definition that windows.admx lacks:
        // mixed generations.
        let c = st(
            &[("windows.admx", "1.0"), ("new.admx", "1.0")],
            &["windows.adml", "new.adml"],
            &["SUPPORTED_Windows_11_0_25H2"],
            &["SUPPORTED_Windows_11_0_25H2", "SUPPORTED_Windows_11_0_26H2"],
        );
        let r = classify(&domain(Some(c), "26H2"));
        assert_eq!(r.status, GpoStatus::Mismatch);
        assert!(r.mismatch_findings[0].contains("SUPPORTED_Windows_11_0_26H2"));
    }

    #[test]
    fn outdated_only_with_reliable_evidence_and_releases_kept_separate() {
        // 25H2 templates on a 26H2 machine: supportedOn proves it.
        let r = classify(&domain(Some(good_store("25H2")), "26H2"));
        assert_eq!(r.status, GpoStatus::Outdated);
        // No release token anywhere: INSUFFICIENT DATA, not MISMATCH.
        let c = st(
            &[("windows.admx", "1.0")],
            &["windows.adml"],
            &["SUPPORTED_Windows7"],
            &["SUPPORTED_Windows7"],
        );
        assert_eq!(
            classify(&domain(Some(c), "26H2")).status,
            GpoStatus::InsufficientData
        );
        // Unknown installed release: insufficient data.
        assert_eq!(
            classify(&domain(Some(good_store("25H2")), "")).status,
            GpoStatus::InsufficientData
        );
        // Microsoft 26H2 reference: documented ADMX absent → OUTDATED; a
        // 25H2 reference is never applied to a 26H2 machine.
        let mut i = domain(Some(good_store("26H2")), "26H2");
        i.reference_release = "26H2".into();
        i.reference_admx = vec!["windows.admx".into(), "copilot.admx".into()];
        let r = classify(&i);
        assert_eq!(r.status, GpoStatus::Outdated);
        assert!(r.version_findings[0].contains("copilot.admx"));
        i.reference_release = "25H2".into();
        assert_eq!(
            classify(&i).status,
            GpoStatus::Ok,
            "25H2 reference ignored for 26H2"
        );
    }

    #[test]
    fn local_vs_central_divergence_is_informational() {
        let mut central = good_store("25H2");
        central.admx.push(("extra.admx".into(), "1.0".into()));
        central.adml[0].1.push("extra.adml".into());
        central.admx[1].1 = "1.1".into();
        let r = classify(&domain(Some(central), "25H2"));
        assert_eq!(r.status, GpoStatus::Ok);
        assert!(r.info.iter().any(|x| x.contains("informational")));
        assert!(r.version_findings.iter().any(|x| x.contains("bits.admx")));
    }

    #[test]
    fn timestamps_never_drive_severity_and_json_is_valid() {
        // The model has no timestamp input at all: only content evidence.
        let i = domain(Some(good_store("25H2")), "25H2");
        let r = classify(&i);
        let js = to_json(&i, &r);
        let v = json::parse(&js).expect("valid JSON");
        for k in [
            "machine_mode",
            "domain_name",
            "domain_reachable",
            "local_store",
            "central_store",
            "windows_build",
            "windows_release",
            "admx_count",
            "adml_count",
            "missing_adml",
            "version_findings",
            "mismatch_findings",
            "status",
        ] {
            assert!(v.get(k).is_some(), "{k}");
        }
        assert!(js.contains(MS_26H2_REFERENCE));
        assert_eq!(
            newest_release(&[
                "SUPPORTED_Windows_11_0_NOSERVER_24H2".into(),
                "SUPPORTED_Windows_11_0_25H2".into()
            ])
            .as_deref(),
            Some("25H2")
        );
        assert_eq!(
            evidence_name("04.10.26_10-00", "json"),
            "GroupPolicy_ADMX_Health_04.10.26_10-00.json"
        );
    }

    #[test]
    fn collector_is_read_only_and_runs() {
        for forbidden in [
            "Copy-Item",
            "Remove-Item",
            "Set-Item",
            "New-Item",
            "gpupdate",
            "Invoke-WebRequest",
            "Start-BitsTransfer",
            "Out-File",
            "Set-Content",
        ] {
            assert!(!COLLECTOR_PS1.contains(forbidden), "{forbidden}");
        }
        let Some(host) = crate::ps_exec::test_host() else {
            return;
        };
        let dir = std::env::temp_dir();
        let i = collect(&host, &dir).expect("collector answers");
        if !cfg!(windows) {
            assert!(!i.domain_joined);
            assert_eq!(classify(&i).status, GpoStatus::NotApplicable);
        }
    }
}
