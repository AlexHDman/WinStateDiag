# WinStateDiag - populate third_party\LibreHardwareMonitorLib-<ver>\ from
# the OFFICIAL nuget.org packages (LibreHardwareMonitorLib + its .NET
# Framework dependencies), then verify every file against the pinned
# hashes in scripts\release\lhm_bundle.sha256.
#
# build.rs embeds third_party\...\lib\*.dll into the EXE; those binaries are
# git-ignored, so this script + the lock file make the bundle reproducible.
# Installs nothing (no driver, no service; PawnIO is NOT installed).
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File scripts\release\fetch_lhm.ps1            # fetch + verify
#   powershell -ExecutionPolicy Bypass -File scripts\release\fetch_lhm.ps1 -VerifyOnly # verify only
param([string]$Version = '0.9.6', [switch]$VerifyOnly)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$tp = Join-Path $root "third_party\LibreHardwareMonitorLib-$Version"
$pk = Join-Path $tp 'packages'
$lib = Join-Path $tp 'lib'
$lock = Join-Path $PSScriptRoot 'lhm_bundle.sha256'

function Verify-Bundle {
    $expected = @{}
    Get-Content -LiteralPath $lock | Where-Object { $_ -and -not $_.StartsWith('#') } | ForEach-Object {
        if ($_ -notmatch '^([0-9A-F]{64})  (\S+)$') { throw "bad lock line: $_" }
        $expected[$Matches[2]] = $Matches[1]
    }
    $bad = 0
    $script:unexpected = 0
    foreach ($rel in ($expected.Keys | Sort-Object)) {
        if ($rel -like 'packages/*' -and -not (Test-Path -LiteralPath $pk)) { continue }
        $p = Join-Path $tp $rel
        if (-not (Test-Path -LiteralPath $p)) { Write-Host "LHM_MISSING $rel"; $bad++; continue }
        $h = (Get-FileHash -Algorithm SHA256 -LiteralPath $p).Hash
        if ($h -ne $expected[$rel]) { Write-Host "LHM_HASH_MISMATCH $rel $h"; $bad++ } else { Write-Host "LHM_OK $rel" }
    }
    # Exact set: no extra DLL may be embedded.
    Get-ChildItem -LiteralPath $lib -Filter *.dll -ErrorAction SilentlyContinue | ForEach-Object {
        if (-not $expected.ContainsKey("lib/$($_.Name)")) { Write-Host "LHM_UNEXPECTED lib/$($_.Name)"; $script:unexpected++ }
    }
    $bad += $script:unexpected
    if ($bad) { Write-Host "LHM_BUNDLE=FAIL ($bad)" } else { Write-Host "LHM_BUNDLE=PASS" }
    return $bad
}

if (-not $VerifyOnly) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    New-Item -ItemType Directory -Force -Path $pk, $lib | Out-Null
    # Recursive fetch: .NET Framework 4.7.2 dependency group, lowest allowed version.
    $fwOrder = 'net472', 'net471', 'net47', 'net462', 'net461', 'net46', 'net452', 'net451', 'net45', 'netstandard2.0'
    $seen = @{}
    function Fetch([string]$id, [string]$ver) {
        $key = $id.ToLowerInvariant()
        if ($seen.ContainsKey($key)) { return }
        $seen[$key] = $ver
        $lv = $ver.ToLowerInvariant()
        $url = "https://api.nuget.org/v3-flatcontainer/$key/$lv/$key.$lv.nupkg"
        $file = Join-Path $pk "$key.$lv.nupkg"
        if (-not (Test-Path $file)) { Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $file }
        Write-Host "PKG $id $ver"
        $z = [IO.Compression.ZipFile]::OpenRead($file)
        try {
            $nuspec = $z.Entries | Where-Object { $_.FullName -notmatch '/' -and $_.Name -like '*.nuspec' } | Select-Object -First 1
            $sr = New-Object IO.StreamReader($nuspec.Open()); [xml]$x = $sr.ReadToEnd(); $sr.Close()
            $picked = $null
            foreach ($fw in $fwOrder) {
                # LibreHardwareMonitorLib ships its assemblies under runtimes/win-x64/lib/<tfm>/.
                $ents = @($z.Entries | Where-Object { $_.FullName -like "runtimes/win-x64/lib/$fw/*" -and $_.Name })
                if (-not $ents.Count) { $ents = @($z.Entries | Where-Object { $_.FullName -like "lib/$fw/*" -and $_.Name }) }
                if ($ents.Count) {
                    $picked = $fw
                    foreach ($e in $ents) {
                        if ($e.Name -like '*.dll') { [IO.Compression.ZipFileExtensions]::ExtractToFile($e, (Join-Path $lib $e.Name), $true) }
                    }
                    break
                }
            }
            if (-not $picked -and $key -eq 'librehardwaremonitorlib') { throw 'LibreHardwareMonitorLib: no usable assembly folder in the package' }
            foreach ($e in $z.Entries) {
                if ($e.Name -match '^(LICENSE|license|THIRD-PARTY|NOTICE)') { [IO.Compression.ZipFileExtensions]::ExtractToFile($e, (Join-Path $tp "$key.$($e.Name)"), $true) }
            }
            $groups = @($x.package.metadata.dependencies.group)
            $grp = $null
            foreach ($tf in '.NETFramework4.7.2', 'net472', '.NETFramework4.6.2', 'net462', '.NETFramework4.6.1', '.NETStandard2.0', 'netstandard2.0') {
                $grp = $groups | Where-Object { $_.targetFramework -eq $tf } | Select-Object -First 1
                if ($grp) { break }
            }
            if ($grp) {
                foreach ($d in @($grp.dependency)) {
                    if ($d) { Fetch $d.id (($d.version -replace '[\[\]\(\) ]', '').Split(',')[0]) }
                }
            }
        } finally { $z.Dispose() }
    }
    Fetch 'LibreHardwareMonitorLib' $Version
}

if ((Verify-Bundle) -eq 0) { exit 0 } else { exit 1 }
