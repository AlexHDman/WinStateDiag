# Guest-only minimum idle test. Never changes Windows configuration.
param([Parameter(Mandatory = $true)][string]$Root, [ValidateSet('Start','Observe','Finish')][string]$Mode)
$ErrorActionPreference = 'Stop'
if ($env:USERNAME -ne 'WDAGUtilityAccount' -or (Test-Path 'C:\AI\WinStateDiag')) { throw 'Refusing non-Sandbox environment' }
$out = Join-Path $Root 'out'
$marker = Join-Path $out 'owner.json'
$exe = Join-Path $Root 'WinStateDiag.exe'
New-Item -ItemType Directory -Force -Path $out | Out-Null
if ($Mode -eq 'Start') {
    if (Test-Path $marker) { throw 'Launch already recorded' }
    $p = Start-Process -FilePath $exe -WorkingDirectory $Root -PassThru
    @{ pid = $p.Id; start = $p.StartTime.ToUniversalTime().ToString('o'); exe = $exe } | ConvertTo-Json | Set-Content $marker -Encoding UTF8
    # Keep target exec alive while observing; detached child lifetime is not
    # guaranteed after its guest execution job closes.
    $Mode = 'Observe'
}
$owner = Get-Content $marker -Raw | ConvertFrom-Json
function Owned-Process {
    $p = Get-Process -Id $owner.pid -ErrorAction SilentlyContinue
    if ($p -and ($p.StartTime.ToUniversalTime().ToString('o') -ne $owner.start -or $p.Path -ne $owner.exe)) { throw 'PID identity changed: refuse to touch it' }
    return $p
}
if ($Mode -eq 'Observe') {
    $samples = New-Object System.Collections.Generic.List[object]
    $observeStart = Get-Date
    $until = (Get-Date).AddSeconds(70)
    $ok = $true
    do {
        $p = Owned-Process
        if (-not $p) { $ok = $false; break }
        $children = @(Get-CimInstance Win32_Process -Filter "ParentProcessId=$($p.Id)" | Where-Object { $_.ExecutablePath -eq $exe })
        $windows = @(@($p) + @($children | ForEach-Object { Get-Process -Id $_.ProcessId -ErrorAction SilentlyContinue }) | Where-Object { $_.MainWindowHandle -ne 0 })
        $samples.Add(@{ pid = $p.Id; windows = @($windows | Select-Object Id,MainWindowTitle,Responding); at = (Get-Date -Format o) })
        if (((Get-Date) - [datetime]$owner.start).TotalSeconds -gt 10 -and ($windows.Count -eq 0 -or @($windows | Where-Object { -not $_.Responding }).Count)) { $ok = $false }
        Start-Sleep -Seconds 2
    } while ((Get-Date) -lt $until)
    @{ result = $(if ($ok) { 'PASS' } else { 'FAIL' }); owner = $owner; observed_seconds = ((Get-Date) - $observeStart).TotalSeconds; samples = @($samples.ToArray()); spontaneous_exit_code = $null; exit_note = 'PID disappearance is failure; see exit.json for controlled close.' } | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $out 'result.json') -Encoding UTF8
    $Mode = 'Finish'
}
if ($Mode -eq 'Finish') {
    $p = Owned-Process
    $termination = 'already exited; exit code unavailable'
    if ($p) {
        $null = $p.Handle
        $children = @(Get-CimInstance Win32_Process -Filter "ParentProcessId=$($p.Id)" | Where-Object { $_.ExecutablePath -eq $exe })
        foreach ($child in $children) { $cp = Get-Process -Id $child.ProcessId -ErrorAction SilentlyContinue; if ($cp) { $null = $cp.CloseMainWindow() } }
        $null = $p.CloseMainWindow()
        if (-not $p.WaitForExit(10000)) { & taskkill.exe /F /T /PID $p.Id | Out-Null; $p.WaitForExit(); $termination = 'forced own process tree after close timeout' }
        else { $termination = 'normal window close' }
        @{ method = $termination; exit_code = $p.ExitCode; pid = $p.Id } | ConvertTo-Json | Set-Content (Join-Path $out 'exit.json') -Encoding UTF8
    }
    foreach ($path in @((Join-Path $Root 'Reports\Logs'), (Join-Path $env:TEMP 'WinStateDiag'))) {
        if (Test-Path $path) { Copy-Item -LiteralPath $path -Destination (Join-Path $out ([IO.Path]::GetFileName($path))) -Recurse -Force }
    }
    try {
        @(Get-WinEvent -FilterHashtable @{LogName='Application'; StartTime=[datetime]$owner.start} -ErrorAction Stop | Where-Object { $_.ProviderName -in @('Application Error','Windows Error Reporting','Application Hang') -and $_.Message -match 'WinStateDiag' } | Select-Object TimeCreated,Id,ProviderName,Message) | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $out 'wer.json') -Encoding UTF8
    } catch { $_.Exception.Message | Set-Content (Join-Path $out 'wer-unavailable.txt') -Encoding UTF8 }
}
if ($null -ne $ok -and -not $ok) { exit 1 }
