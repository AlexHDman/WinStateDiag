# WinStateDiag — minimal startup-crash diagnostics for a remote PC. READ-ONLY.
#
# Collects only: WinStateDiag startup logs, Windows Error Reporting /
# Application Error / Application Hang events that name WinStateDiag (last
# 14 days), WER report texts (Report.wer) of WinStateDiag, and a short
# system summary (Windows build, session type, GPU + driver, RAM, display).
# Changes nothing, needs no administrator rights, sends nothing anywhere.
# Result: WinStateDiag_StartupDiag_<computer>_<time>.zip on the Desktop.
#
# Usage (PowerShell, in the folder with WinStateDiag.exe or with -ExeDir):
#   powershell -ExecutionPolicy Bypass -File Collect-WsdStartupDiagnostics.ps1 -ExeDir "D:\Tools\WinStateDiag"
param([string]$ExeDir = (Get-Location).Path, [int]$Days = 14)
$ErrorActionPreference = 'Continue'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$work = Join-Path $env:TEMP "WsdStartupDiag_$stamp"
New-Item -ItemType Directory -Force -Path $work | Out-Null
function Save([string]$name, $content) { $content | Out-String -Width 400 | Set-Content -Encoding UTF8 -LiteralPath (Join-Path $work $name) }

# 1. Startup logs (bootstrap / renderer stages, panics, slow frames, exit codes).
$logs = @(
    (Join-Path $ExeDir 'Reports\Logs\startup_graphics.log'),
    (Join-Path $ExeDir 'Reports\Logs\startup_graphics.log.old'),
    (Join-Path $env:TEMP 'WinStateDiag\startup_graphics.log'),
    (Join-Path $env:TEMP 'WinStateDiag\startup_graphics.log.old'),
    (Join-Path $env:TEMP 'startup_graphics.log'))
$i = 0
foreach ($l in $logs) {
    if (Test-Path -LiteralPath $l) { $i++; Copy-Item -LiteralPath $l -Destination (Join-Path $work ("startup_graphics_{0}.log" -f $i)) }
}
Save 'logs_found.txt' ($logs | ForEach-Object { "$_ : $(Test-Path -LiteralPath $_)" })

# 2. Events naming WinStateDiag.
$since = (Get-Date).AddDays(-$Days)
try {
    $ev = Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'Application Error', 'Windows Error Reporting', 'Application Hang', '.NET Runtime'; StartTime = $since } -ErrorAction Stop |
        Where-Object { $_.Message -match 'WinStateDiag|win_state_diag' }
    Save 'events_application.txt' ($ev | Select-Object TimeCreated, ProviderName, Id, LevelDisplayName, Message | Format-List)
} catch { Save 'events_application.txt' ('no events / not readable: ' + $_.Exception.Message) }
try {
    $sys = Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Display', 'nvlddmkm', 'amdkmdag', 'igfx', 'Microsoft-Windows-Resource-Exhaustion-Detector'; StartTime = $since } -MaxEvents 100 -ErrorAction Stop
    Save 'events_system_gpu_memory.txt' ($sys | Select-Object TimeCreated, ProviderName, Id, LevelDisplayName, Message | Format-List)
} catch { Save 'events_system_gpu_memory.txt' ('no events / not readable: ' + $_.Exception.Message) }

# 3. WER report texts of WinStateDiag (no dumps copied).
$werRoots = @("$env:ProgramData\Microsoft\Windows\WER\ReportArchive", "$env:ProgramData\Microsoft\Windows\WER\ReportQueue", "$env:LOCALAPPDATA\Microsoft\Windows\WER\ReportArchive", "$env:LOCALAPPDATA\Microsoft\Windows\WER\ReportQueue")
$n = 0
foreach ($r in $werRoots) {
    Get-ChildItem -LiteralPath $r -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'WinStateDiag|win_state_diag' } | ForEach-Object {
        $wer = Join-Path $_.FullName 'Report.wer'
        if (Test-Path -LiteralPath $wer) { $n++; Copy-Item -LiteralPath $wer -Destination (Join-Path $work ("Report_{0}_{1}.wer" -f $n, $_.Name)) }
    }
}
$dumps = @(Get-ChildItem -LiteralPath "$env:LOCALAPPDATA\CrashDumps" -Filter 'WinStateDiag*.dmp' -ErrorAction SilentlyContinue | Select-Object Name, Length, LastWriteTime)
Save 'crashdumps_list.txt' $dumps

# 4. System summary (no user data).
$os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
$cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
$gpu = Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue | Select-Object Name, DriverVersion, DriverDate, Status, CurrentHorizontalResolution, CurrentVerticalResolution, AdapterRAM
Save 'system_summary.txt' @(
    "OS: $($os.Caption) $($os.Version) build $($os.BuildNumber)",
    "Session: $env:SESSIONNAME (RDP sessions are named RDP-Tcp#N)",
    "RAM total MB: $([math]::Round($cs.TotalPhysicalMemory / 1MB)); free MB: $([math]::Round($os.FreePhysicalMemory / 1KB))",
    "Model: $($cs.Manufacturer) $($cs.Model)",
    "Elevated now: $(([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))",
    "ExeDir: $ExeDir; EXE present: $(Test-Path -LiteralPath (Join-Path $ExeDir 'WinStateDiag.exe'))",
    '', 'GPU:', ($gpu | Format-List | Out-String))
$exe = Join-Path $ExeDir 'WinStateDiag.exe'
if (Test-Path -LiteralPath $exe) {
    Save 'exe_info.txt' @("SHA256: $((Get-FileHash -Algorithm SHA256 -LiteralPath $exe).Hash)", "Size: $((Get-Item -LiteralPath $exe).Length)", "Version: $((Get-Item -LiteralPath $exe).VersionInfo.FileVersion)")
}

$zip = Join-Path ([Environment]::GetFolderPath('Desktop')) ("WinStateDiag_StartupDiag_{0}_{1}.zip" -f $env:COMPUTERNAME, $stamp)
Compress-Archive -Path (Join-Path $work '*') -DestinationPath $zip -Force
Write-Output "Done: $zip"
