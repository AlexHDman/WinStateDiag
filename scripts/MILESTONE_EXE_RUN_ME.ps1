<#
    WinStateDiag - Functional EXE Milestone
    One-time local run: cargo checks/tests/release build, dist packaging,
    and (only if everything above passed) commit + push.

    Claude could not compile or run this code in its own session (no shell
    access to this computer was available), so this script is the actual
    "one controlled build" gate the task calls for. Run it once from the
    project folder:

        powershell -ExecutionPolicy Bypass -File MILESTONE_EXE_RUN_ME.ps1

    It stops at the first failure (nothing after that runs), and pauses
    before commit/push so you can read the `git status` staged-content
    audit first.

    IMPORTANT: $ErrorActionPreference = 'Stop' does NOT make PowerShell
    treat a nonzero exit code from an external/native command (cargo.exe,
    git.exe, ...) as an error - it only catches PowerShell-level
    terminating errors. So every cargo step below is followed by an
    explicit $LASTEXITCODE check that throws (and therefore stops the
    whole script) on failure. Without this, a failed build can be
    silently skipped over and a stale dist\WinStateDiag.exe left in place
    looking like a successful deliverable.
#>

$ErrorActionPreference = 'Stop'
$ProjectRoot = 'C:\AI\WinStateDiag'
Set-Location -Path $ProjectRoot

function Assert-LastExitCode {
    param(
        [Parameter(Mandatory = $true)][string]$StepName
    )
    if ($LASTEXITCODE -ne 0) {
        throw "$StepName failed with exit code $LASTEXITCODE. STOPPING - nothing after this step ran."
    }
}

# ── PORTABLE BUILD: static CRT linking ──────────────────────────────
# Without +crt-static, MSVC Rust builds link VCRUNTIME140.dll and
# Universal CRT (api-ms-win-crt-*.dll) DYNAMICALLY. Those DLLs are
# absent on machines without the Visual C++ Redistributable installed,
# which causes the EXE to fail to launch on a clean Windows PC.
# This env var tells rustc to link the CRT statically into the EXE.
$env:RUSTFLAGS = '-C target-feature=+crt-static'
Write-Host "RUSTFLAGS = $env:RUSTFLAGS (static CRT for portable EXE)" -ForegroundColor Magenta

# Also ensure .cargo/config.toml exists for IDE / manual cargo builds.
$cargoConfigDir = Join-Path $ProjectRoot '.cargo'
$cargoConfigFile = Join-Path $cargoConfigDir 'config.toml'
if (-not (Test-Path -LiteralPath $cargoConfigFile)) {
    Write-Host "Creating .cargo/config.toml for static CRT..." -ForegroundColor Yellow
    if (-not (Test-Path -LiteralPath $cargoConfigDir)) {
        New-Item -ItemType Directory -Path $cargoConfigDir -Force | Out-Null
    }
    @'
# Static CRT linking — ensures WinStateDiag.exe is truly portable.
# Without this, Rust dynamically links VCRUNTIME140.dll + Universal CRT,
# which are absent on machines without the VC++ Redistributable installed.
[target.x86_64-pc-windows-msvc]
rustflags = ["-C", "target-feature=+crt-static"]
'@ | Set-Content -Path $cargoConfigFile -Encoding UTF8
}

Write-Host "== 1. cargo fmt --check ==" -ForegroundColor Cyan
cargo fmt --check
Assert-LastExitCode -StepName "cargo fmt --check"

Write-Host "== 2. cargo check ==" -ForegroundColor Cyan
cargo check
Assert-LastExitCode -StepName "cargo check"

Write-Host "== 3. cargo test ==" -ForegroundColor Cyan
cargo test
Assert-LastExitCode -StepName "cargo test"

Write-Host "== 4. Remove stale dist\WinStateDiag.exe (if any) before building ==" -ForegroundColor Cyan
$distDir = Join-Path $ProjectRoot 'dist'
$distExe = Join-Path $distDir 'WinStateDiag.exe'
if (Test-Path -LiteralPath $distExe) {
    Remove-Item -LiteralPath $distExe -Force
    Write-Host "Removed old $distExe" -ForegroundColor Yellow
}
else {
    Write-Host "No existing $distExe to remove." -ForegroundColor Yellow
}

Write-Host "== 5. cargo build --release ==" -ForegroundColor Cyan
cargo build --release
Assert-LastExitCode -StepName "cargo build --release"

Write-Host "== 6. Package dist\WinStateDiag.exe ==" -ForegroundColor Cyan
$builtExe = Join-Path $ProjectRoot 'target\release\win_state_diag.exe'
if (-not (Test-Path -LiteralPath $builtExe)) {
    throw "Release build did not produce $builtExe"
}
if (-not (Test-Path -LiteralPath $distDir)) {
    New-Item -ItemType Directory -Path $distDir -Force | Out-Null
}
Copy-Item -LiteralPath $builtExe -Destination $distExe -Force
$size = (Get-Item -LiteralPath $distExe).Length
if ($size -le 0) {
    throw "$distExe is empty."
}

# Sanity check: the exe we just copied must be freshly built by THIS run,
# not a leftover from an earlier build. If step 4 removed an old copy and
# this one exists again, it can only be because step 5/6 just recreated it,
# but we double-check the timestamp anyway so a future refactor of this
# script can't quietly reintroduce the "stale exe" bug.
$builtTime = (Get-Item -LiteralPath $builtExe).LastWriteTimeUtc
if ($builtTime -lt (Get-Date).ToUniversalTime().AddMinutes(-10)) {
    throw "target\release\win_state_diag.exe looks stale (last written $builtTime UTC); refusing to package it as a fresh build."
}

# ── PORTABILITY VERIFICATION ─────────────────────────────────────────
Write-Host "== 6b. Verify EXE portability (no CRT DLL dependencies) ==" -ForegroundColor Cyan
$dumpbin = Get-Command dumpbin.exe -ErrorAction SilentlyContinue
if ($dumpbin) {
    $imports = & dumpbin.exe /IMPORTS $distExe 2>&1 | Select-String -Pattern '\.dll' -SimpleMatch
    $crtDlls = $imports | Where-Object { $_ -match '(?i)(VCRUNTIME|api-ms-win-crt|ucrtbase|msvcp)' }
    if ($crtDlls) {
        Write-Host "WARNING: EXE still has CRT DLL dependencies:" -ForegroundColor Red
        $crtDlls | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
        throw "Static CRT linking failed — EXE is NOT portable."
    }
    else {
        Write-Host "PASS: No CRT DLL imports detected — EXE is portable." -ForegroundColor Green
    }
}
else {
    # dumpbin not on PATH — fall back to a simple binary string search
    $bytes = [IO.File]::ReadAllBytes($distExe)
    $text  = [Text.Encoding]::ASCII.GetString($bytes)
    if ($text -match 'VCRUNTIME140\.dll') {
        Write-Host "WARNING: VCRUNTIME140.dll found in EXE binary — static CRT may not have applied." -ForegroundColor Red
        throw "Static CRT linking verification failed."
    }
    else {
        Write-Host "PASS: VCRUNTIME140.dll not found in binary — static CRT appears applied." -ForegroundColor Green
    }
}

Write-Host ("dist\WinStateDiag.exe ready ({0:n1} KB)" -f ($size / 1KB)) -ForegroundColor Green

Write-Host "== 7. SHA256 of portable EXE ==" -ForegroundColor Cyan
$hash = (Get-FileHash -LiteralPath $distExe -Algorithm SHA256).Hash
Write-Host "SHA256: $hash" -ForegroundColor White

Write-Host "== 8. Git status / diff (review before staging) ==" -ForegroundColor Cyan
git status
git diff --stat

Write-Host "== 9. Stage source only (never dist\, target\, Reports\) ==" -ForegroundColor Cyan
git add Cargo.toml Cargo.lock build.rs src desktop.ini README.md CHANGELOG.md docs .gitignore .cargo 2>$null

Write-Host "== 10. Review staged content before commit (audit) ==" -ForegroundColor Yellow
git status

Write-Host ""
Write-Host "Build succeeded and dist\WinStateDiag.exe was freshly rebuilt with STATIC CRT." -ForegroundColor Green
Write-Host "Check the list above: no dist\WinStateDiag.exe, no Reports\, no *.zip, no target\, no secrets/tokens." -ForegroundColor Yellow
Write-Host "Press Enter to commit and push, or Ctrl+C to abort." -ForegroundColor Yellow
Read-Host | Out-Null

git commit -m "feat: portable EXE with static CRT linking"
Assert-LastExitCode -StepName "git commit"

git push -u origin main
Assert-LastExitCode -StepName "git push"

Write-Host "== Done. ==" -ForegroundColor Green
git status
git log -1 --oneline
