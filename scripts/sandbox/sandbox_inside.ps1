# WinStateDiag sandbox test runner — runs INSIDE Windows Sandbox only.
# Pushed by Invoke-WsdSandboxTests.ps1 together with WinStateDiag.exe and
# started with `winapp target exec sandbox -- powershell ... -File <this>`.
# Read-only probes and offscreen QA renders; every step has a timeout, the
# process tree of a hung step is ended, and results go to one ZIP that the
# host pulls. Never run on the host (refuses unless the sandbox user).
param(
    [string]$Root = 'C:\wsdtest',
    [int]$StepTimeoutSec = 240
)
$ErrorActionPreference = 'Continue'
$out = Join-Path $Root 'out'
New-Item -ItemType Directory -Force -Path $out | Out-Null
$log = Join-Path $out 'inside.log'
function L([string]$m) { Add-Content -Encoding UTF8 -LiteralPath $log -Value ((Get-Date -Format 'HH:mm:ss') + ' ' + $m) }
$results = New-Object System.Collections.Generic.List[object]
function Result([string]$id, [string]$status, [string]$detail, $exit, [double]$sec) {
    $results.Add([ordered]@{ id = $id; status = $status; exit_code = $exit; seconds = [math]::Round($sec, 1); detail = $detail })
    L "RESULT $id=$status exit=$exit ($detail)"
}

# Guard: refuse on the host. The host has the project at C:\AI\WinStateDiag;
# a fresh Windows Sandbox never does (its user is normally WDAGUtilityAccount).
if (Test-Path -LiteralPath 'C:\AI\WinStateDiag') {
    L "REFUSED: C:\AI\WinStateDiag exists - this is not a fresh Windows Sandbox (user $env:USERNAME)"
    Result 'guard' 'BLOCKED' "host detected (user $env:USERNAME)" $null 0
    ConvertTo-Json -InputObject @($results) -Depth 4 | Set-Content -Encoding UTF8 (Join-Path $out 'inside_results.json')
    exit 3
}
$exe = Join-Path $Root 'WinStateDiag.exe'
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
L "START user=$env:USERNAME elevated=$admin exe=$exe exists=$(Test-Path -LiteralPath $exe)"
$os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
L ("OS " + $os.Caption + ' ' + $os.BuildNumber)

function Run-Step([string]$id, [string[]]$argv, [string]$expectFile) {
    $t0 = Get-Date
    try {
        $p = Start-Process -FilePath $exe -ArgumentList $argv -PassThru -WindowStyle Hidden -ErrorAction Stop
    } catch {
        Result $id 'FAIL' ('start failed: ' + $_.Exception.Message) $null 0
        return
    }
    $null = $p.Handle
    if (-not $p.WaitForExit($StepTimeoutSec * 1000)) {
        $null = cmd /c "taskkill /F /T /PID $($p.Id) 2>&1"
        Result $id 'TIMEOUT' "no exit within ${StepTimeoutSec}s (UAC or hang); process tree ended" $null ((Get-Date) - $t0).TotalSeconds
        return
    }
    $p.WaitForExit()
    $sec = ((Get-Date) - $t0).TotalSeconds
    $have = (-not $expectFile) -or (Test-Path -LiteralPath $expectFile)
    $status = if ($p.ExitCode -eq 0 -and $have) { 'PASS' } elseif ($have) { 'FAIL' } else { 'FAIL' }
    $detail = if ($have) { 'output present' } else { "missing output $expectFile" }
    Result $id $status $detail $p.ExitCode $sec
}

# 0. P0 STARTUP STABILITY (first): the normal GUI launch with no user
#    action, observed for >= 60 s, repeated, plus non-admin and a portable
#    path with spaces / Cyrillic and a foreign working directory. Records
#    PID, lifetime, exit code, window state, startup_graphics.log, WER
#    events and dumps. Nothing is restarted automatically.
$startup = New-Object System.Collections.Generic.List[object]
$sdir = Join-Path $out 'startup'
New-Item -ItemType Directory -Force -Path $sdir | Out-Null
# WER LocalDumps for our EXE — sandbox registry only (disposable VM).
$ld = 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\WinStateDiag.exe'
try {
    New-Item -Path $ld -Force -ErrorAction Stop | Out-Null
    New-ItemProperty -Path $ld -Name DumpFolder -Value (Join-Path $sdir 'dumps') -PropertyType ExpandString -Force | Out-Null
    New-ItemProperty -Path $ld -Name DumpType -Value 2 -PropertyType DWord -Force | Out-Null
    New-Item -ItemType Directory -Force -Path (Join-Path $sdir 'dumps') | Out-Null
    L 'LocalDumps enabled (sandbox only)'
} catch { L ('LocalDumps not enabled: ' + $_.Exception.Message) }

function Watch-Launch([string]$id, [string]$exePath, [string]$workDir, [bool]$asInvoker, [int]$watchSec) {
    $t0 = Get-Date
    $old = $env:__COMPAT_LAYER
    if ($asInvoker) { $env:__COMPAT_LAYER = 'RunAsInvoker' }
    try {
        $p = Start-Process -FilePath $exePath -WorkingDirectory $workDir -PassThru -ErrorAction Stop
    } catch {
        $env:__COMPAT_LAYER = $old
        $startup.Add([ordered]@{ id = $id; status = 'START_FAILED'; detail = $_.Exception.Message })
        Result $id 'FAIL' ('start failed: ' + $_.Exception.Message) $null 0
        return
    }
    $env:__COMPAT_LAYER = $old
    $null = $p.Handle
    $samples = New-Object System.Collections.Generic.List[object]
    $exited = $false
    while (((Get-Date) - $t0).TotalSeconds -lt $watchSec) {
        Start-Sleep -Seconds 2
        $procs = @(Get-CimInstance Win32_Process -Filter "Name='WinStateDiag.exe'" -ErrorAction SilentlyContinue)
        $win = @(Get-Process -Name WinStateDiag -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowHandle -ne 0 } | ForEach-Object { "$($_.Id):$($_.MainWindowTitle):responding=$($_.Responding)" })
        $samples.Add([ordered]@{ t = [math]::Round(((Get-Date) - $t0).TotalSeconds, 1); processes = @($procs | ForEach-Object { "$($_.ProcessId)<-$($_.ParentProcessId)" }); windows = $win })
        if ($p.HasExited) { $exited = $true; break }
    }
    $life = [math]::Round(((Get-Date) - $t0).TotalSeconds, 1)
    $code = $null
    if ($exited) { $p.WaitForExit(); $code = $p.ExitCode }
    # Our test ends here: the launch is stopped by the harness (after the
    # observation window) — recorded as such, never as a crash.
    if (-not $exited) { $null = cmd /c "taskkill /F /T /PID $($p.Id) 2>&1" }
    Start-Sleep -Seconds 2
    $logs = @((Join-Path (Split-Path -Parent $exePath) 'Reports\Logs\startup_graphics.log'), (Join-Path $env:TEMP 'WinStateDiag\startup_graphics.log'))
    foreach ($lg in $logs) { if (Test-Path -LiteralPath $lg) { Copy-Item -LiteralPath $lg -Destination (Join-Path $sdir "$id.startup_graphics.log") -Force } }
    $status = if ($exited) { 'EXITED_ON_ITS_OWN' } else { 'STABLE' }
    $rec = [ordered]@{ id = $id; exe = $exePath; workdir = $workDir; as_invoker = $asInvoker; pid = $p.Id; status = $status; lifetime_s = $life; exit_code = $code; exit_hex = $(if ($code -ne $null) { '0x{0:X8}' -f ([uint32]([int64]$code -band 0xFFFFFFFF)) } else { $null }); samples = $samples }
    $startup.Add($rec)
    $st = if ($exited) { 'FAIL' } else { 'PASS' }
    Result $id $st ("$status after ${life}s; exit=$code") $code $life
}

$watch = 70
for ($i = 1; $i -le 3; $i++) { Watch-Launch "startup_admin_$i" $exe $Root $false $watch }
Watch-Launch 'startup_nonadmin' $exe $Root $true $watch
$odd = 'C:\wsd тест\папка с пробелами'
New-Item -ItemType Directory -Force -Path $odd | Out-Null
Copy-Item -LiteralPath $exe -Destination (Join-Path $odd 'WinStateDiag.exe') -Force
Watch-Launch 'startup_portable_path' (Join-Path $odd 'WinStateDiag.exe') 'C:\Windows\System32' $false $watch
# WER / Application Error / .NET Runtime events of this sandbox session.
try {
    Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'Application Error', 'Windows Error Reporting', '.NET Runtime', 'Application Hang' } -MaxEvents 200 -ErrorAction Stop |
        Where-Object { $_.Message -match 'WinStateDiag' } |
        Select-Object TimeCreated, ProviderName, Id, Message |
        Format-List | Out-String -Width 400 | Set-Content -Encoding UTF8 (Join-Path $sdir 'wer_events.txt')
} catch { Set-Content -Encoding UTF8 (Join-Path $sdir 'wer_events.txt') ('no matching events: ' + $_.Exception.Message) }
Get-ChildItem -LiteralPath (Join-Path $sdir 'dumps') -ErrorAction SilentlyContinue | Select-Object Name, Length | Format-Table | Out-String | Set-Content -Encoding UTF8 (Join-Path $sdir 'dumps.txt')
ConvertTo-Json -InputObject @($startup) -Depth 6 | Set-Content -Encoding UTF8 (Join-Path $sdir 'startup_runs.json')

# 1. Functional: read-only CLI probes (no GUI).
Run-Step 'probe_consistency' @('--consistency-probe', "`"$out\consistency.txt`"") "$out\consistency.txt"
Run-Step 'probe_incident' @('--incident-probe', "`"$out\incidents.json`"") "$out\incidents.json"
New-Item -ItemType Directory -Force -Path "$out\events" | Out-Null
Run-Step 'probe_evidence' @('--evidence-probe', "`"$out\events`"") $null

# 2. UI: offscreen QA renders of the v1.1 UI contract scenes (the app
#    captures its own framebuffer and exits; nothing is clicked).
$scenes = @('diagnostics', 'hardware', 'crypto-details', 'crypto-rehash-confirm', 'hardware-passport', 'driver-details')
foreach ($s in $scenes) {
    foreach ($lang in @('ru', 'en')) {
        $png = Join-Path $out ("render_{0}_{1}.png" -f $s, $lang)
        Run-Step ("render_{0}_{1}" -f $s, $lang) @('--visual-reference', '--qa-offscreen', '--lang', $lang, '--scene', $s, '--capture', "`"$png`"") $png
    }
}
# 3. DPI: the main scene at 125 % / 150 % QA scale.
foreach ($scale in @('1.25', '1.5')) {
    $png = Join-Path $out ("render_diagnostics_ru_{0}.png" -f $scale)
    Run-Step ("render_diagnostics_scale_$scale") @('--visual-reference', '--qa-offscreen', '--lang', 'ru', '--qa-scale', $scale, '--scene', 'diagnostics', '--capture', "`"$png`"") $png
}

ConvertTo-Json -InputObject @($results) -Depth 4 | Set-Content -Encoding UTF8 (Join-Path $out 'inside_results.json')
# Sandbox-side leftovers of our processes only.
Get-Process -Name 'WinStateDiag', 'win_state_diag' -ErrorAction SilentlyContinue | ForEach-Object { $null = cmd /c "taskkill /F /T /PID $($_.Id) 2>&1" }
$zip = Join-Path $Root 'wsd_sandbox_out.zip'
if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force }
Compress-Archive -Path (Join-Path $out '*') -DestinationPath $zip -Force
L "DONE zip=$zip"
exit 0
