# WinStateDiag - versioned PORTABLE release (the only way to produce a
# user-testable EXE).
#
# Rule: target\ is internal build output only. Users test ONLY
#       dist\WinStateDiag-vX.Y.Z\WinStateDiag.exe produced by this script.
#
# Steps:
#   1. version from Cargo.toml ([package] version)
#   2. cargo fmt --check / check / test
#   3. forced fresh cargo build --release (the package is cleaned first, so
#      the EXE is guaranteed to come from THIS run)
#   4. EXE version metadata must equal the Cargo version
#   5. copy to dist\WinStateDiag-vX.Y.Z\WinStateDiag.exe (never overwrites an
#      existing release unless -Force)
#   6. SHA256(dist EXE) must equal SHA256(target\release\win_state_diag.exe)
#   7. lists older dist entries as obsolete (does NOT delete anything)
#   8. writes docs\releases\vX.Y.Z.txt (release manifest)
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File C:\AI\WinStateDiag\scripts\make_release.ps1 [-Force]

param([switch]$Force)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$started = Get-Date

function Fail([string]$msg) {
    Write-Host "RELEASE FAIL: $msg" -ForegroundColor Red
    exit 1
}

function Run([string]$name, [scriptblock]$cmd) {
    Write-Host "== $name" -ForegroundColor Cyan
    & $cmd
    if ($LASTEXITCODE -ne 0) { Fail "$name (exit $LASTEXITCODE)" }
    Write-Host "   PASS" -ForegroundColor Green
}

# 1. version
$cargo = Get-Content (Join-Path $root 'Cargo.toml') -Raw
if ($cargo -notmatch '(?ms)^\[package\].*?^version\s*=\s*"(\d+\.\d+\.\d+)"') { Fail 'version not found in Cargo.toml' }
$version = $Matches[1]
Write-Host "WinStateDiag release v$version" -ForegroundColor Yellow

# 2-3. quality gate + fresh build
Run 'cargo fmt --check' { cargo fmt --check }
Run 'cargo check' { cargo check --color never }
Run 'cargo test' { cargo test --color never }
Run 'cargo clean -p win_state_diag --release' { cargo clean -p win_state_diag --release }
Run 'cargo build --release' { cargo build --release --color never }

$buildExe = Join-Path $root 'target\release\win_state_diag.exe'
if (-not (Test-Path $buildExe)) { Fail "build output missing: $buildExe" }
$buildItem = Get-Item $buildExe
if ($buildItem.LastWriteTime -lt $started) { Fail "target EXE is older than this run ($($buildItem.LastWriteTime))" }

# 4. version metadata
$fileVersion = $buildItem.VersionInfo.FileVersion
$productVersion = $buildItem.VersionInfo.ProductVersion
if (-not ("$fileVersion" -like "$version*" -or "$productVersion" -like "$version*")) {
    Fail "EXE version metadata ($fileVersion / $productVersion) does not match Cargo version $version"
}

# 5. copy into the versioned portable folder
$dist = Join-Path $root 'dist'
$releaseDir = Join-Path $dist "WinStateDiag-v$version"
$releaseExe = Join-Path $releaseDir 'WinStateDiag.exe'
if ((Test-Path $releaseExe) -and -not $Force) {
    Fail "$releaseExe already exists (use -Force to replace this version's EXE)"
}
New-Item -ItemType Directory -Force -Path $releaseDir | Out-Null
Copy-Item -LiteralPath $buildExe -Destination $releaseExe -Force

# 6. verification
$distItem = Get-Item $releaseExe
$shaBuild = (Get-FileHash -Algorithm SHA256 -LiteralPath $buildExe).Hash
$shaDist = (Get-FileHash -Algorithm SHA256 -LiteralPath $releaseExe).Hash
$match = ($shaBuild -eq $shaDist) -and ($distItem.Length -eq $buildItem.Length)

# 7. older releases (reported, never deleted)
$obsolete = @(Get-ChildItem -LiteralPath $dist -Force | Where-Object {
    $_.Name -ne "WinStateDiag-v$version" -and $_.Name -ne '.gitkeep'
} | ForEach-Object { $_.Name })

$lines = @(
    "VERSION=$version",
    "PORTABLE_PATH=$releaseExe",
    "EXE_LAST_WRITE=$($distItem.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))",
    "EXE_SIZE=$($distItem.Length)",
    "EXE_SHA256=$shaDist",
    "BUILD_EXE=$buildExe",
    "BUILD_EXE_LAST_WRITE=$($buildItem.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))",
    "BUILD_EXE_SIZE=$($buildItem.Length)",
    "BUILD_EXE_SHA256=$shaBuild",
    "SHA_MATCH=$(if ($match) { 'YES' } else { 'NO' })",
    "FILE_VERSION=$fileVersion",
    "PRODUCT_VERSION=$productVersion",
    "CURRENT_RELEASE=dist\WinStateDiag-v$version\WinStateDiag.exe",
    "OBSOLETE_RELEASES=$(if ($obsolete.Count) { $obsolete -join '; ' } else { 'none' })",
    "BUILT_AT=$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))"
)

# 8. manifest (kept outside the portable folder: the distribution unit is the EXE)
$manifestDir = Join-Path $root 'docs\releases'
New-Item -ItemType Directory -Force -Path $manifestDir | Out-Null
$lines | Out-File (Join-Path $manifestDir "v$version.txt") -Encoding utf8

Write-Host ''
$lines | ForEach-Object { Write-Host $_ }
if (-not $match) { Fail 'SHA256 of the dist EXE does not match the fresh build' }
Write-Host "`nRELEASE PASS: test ONLY $releaseExe" -ForegroundColor Green
exit 0
