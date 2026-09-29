# WinStateDiag - quality gate + VISUAL_REFERENCE capture (developer/QA only).
#
# Runs, in order, from the repository root:
#   cargo fmt --check ; cargo check ; cargo test ; cargo build --release
# then launches the REAL release EXE in visual-reference mode, which renders
# the dashboard at the reference canvas (1372x1106 px, pixels_per_point 1.0),
# captures its own framebuffer and exits.
#
# Outputs (all under docs\visual\):
#   qa_run.log              full console output of every step + exit codes
#   actual_reference.png    captured framebuffer of the real EXE
#   actual_reference.json   viewport / DPI metadata of that capture
#
# Usage (PowerShell, from anywhere):
#   powershell -ExecutionPolicy Bypass -File C:\AI\WinStateDiag\scripts\visual_qa.ps1

$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$outDir = Join-Path $root 'docs\visual'
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$log = Join-Path $outDir 'qa_run.log'
"WinStateDiag visual QA run  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" | Out-File $log -Encoding utf8
"rustc: $(rustc --version)" | Out-File $log -Append -Encoding utf8

function Step($name, [scriptblock]$cmd) {
    "`n===== $name =====" | Out-File $log -Append -Encoding utf8
    Write-Host "== $name" -ForegroundColor Cyan
    $out = & $cmd 2>&1
    $code = $LASTEXITCODE
    $out | ForEach-Object { "$_" } | Out-File $log -Append -Encoding utf8
    "EXIT_CODE[$name]=$code" | Out-File $log -Append -Encoding utf8
    if ($code -eq 0) { Write-Host "   PASS" -ForegroundColor Green } else { Write-Host "   FAIL ($code)" -ForegroundColor Red }
    return $code
}

$fmt   = Step 'cargo fmt --check'     { cargo fmt --check }
$check = Step 'cargo check'           { cargo check --color never }
$test  = Step 'cargo test'            { cargo test --color never }
$build = Step 'cargo build --release' { cargo build --release --color never }

$png = Join-Path $outDir 'actual_reference.png'
Remove-Item $png, ([IO.Path]::ChangeExtension($png, 'json')) -ErrorAction SilentlyContinue
$exe = Join-Path $root 'target\release\win_state_diag.exe'
if ($build -eq 0 -and (Test-Path $exe)) {
    "`n===== launch visual reference =====" | Out-File $log -Append -Encoding utf8
    Write-Host "== launch real EXE (visual reference capture)" -ForegroundColor Cyan
    $p = Start-Process -FilePath $exe -ArgumentList @('--visual-reference', '--capture', "`"$png`"") -PassThru
    if (-not $p.WaitForExit(60000)) { $p.Kill(); "EXE did not exit within 60 s (killed)" | Out-File $log -Append -Encoding utf8 }
    "EXE exit code: $($p.ExitCode)" | Out-File $log -Append -Encoding utf8
    if (Test-Path $png) {
        "CAPTURE_OK $png" | Out-File $log -Append -Encoding utf8
        Get-Content ([IO.Path]::ChangeExtension($png, 'json')) | Out-File $log -Append -Encoding utf8
        Write-Host "   capture written: $png" -ForegroundColor Green
    } else {
        "CAPTURE_MISSING" | Out-File $log -Append -Encoding utf8
        Write-Host "   capture missing" -ForegroundColor Red
    }
} else {
    "launch skipped (build failed or EXE missing)" | Out-File $log -Append -Encoding utf8
}

# Display / DPI facts for the report.
Add-Type -AssemblyName System.Windows.Forms
$s = [System.Windows.Forms.Screen]::PrimaryScreen
"`nPrimary screen bounds: $($s.Bounds.Width)x$($s.Bounds.Height)" | Out-File $log -Append -Encoding utf8
try {
    $dpi = (Get-ItemProperty 'HKCU:\Control Panel\Desktop\WindowMetrics' -Name AppliedDPI -ErrorAction Stop).AppliedDPI
    "AppliedDPI: $dpi (scale $([math]::Round($dpi / 96 * 100))%)" | Out-File $log -Append -Encoding utf8
} catch { "AppliedDPI: n/a" | Out-File $log -Append -Encoding utf8 }

Write-Host "`nLog: $log"
