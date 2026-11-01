# Host controller. No host GUI launch, no host input automation.
param(
    [Parameter(Mandatory = $true)][string]$Exe,
    [Parameter(Mandatory = $true)][string]$Artifacts,
    [int]$BootTimeoutSec = 180
)
$ErrorActionPreference = 'Stop'
if (Test-Path -LiteralPath $Artifacts) {
    if (@(Get-ChildItem -LiteralPath $Artifacts -Force).Count -gt 0) { throw 'Artifacts must be a new or empty directory; prior evidence will not be overwritten.' }
}
New-Item -ItemType Directory -Force -Path $Artifacts | Out-Null
$Artifacts = (Resolve-Path -LiteralPath $Artifacts).Path
$steps = New-Object System.Collections.Generic.List[object]
$summary = [ordered]@{ result = 'BLOCKED'; started = (Get-Date -Format o); phase = 'minimum-smoke'; cleanup = 'No Sandbox stopped: ownership must be independently proven.' }
$script:boundTarget = $null
$script:observationStarted = $false
function Assert-SandboxBinding($Expected, $Current) {
    if (-not $Current.running -or -not $Current.attached -or
        [string]::IsNullOrWhiteSpace($Expected.executionTarget.epoch) -or
        $Current.executionTarget.epoch -ne $Expected.executionTarget.epoch -or
        $Current.desktop.processId -ne $Expected.desktop.processId -or
        $Current.workRoot -ne $Expected.workRoot) {
        throw 'BLOCKED: Sandbox identity changed or became unavailable; no reconnect, cleanup or default-target action is allowed.'
    }
}
function Assert-NoConcurrentTargetCommand([scriptblock]$During) {
    # The observed exec/UI overlap changed the default guest. Until a pinned
    # transport is validated, refuse this route BEFORE starting either command.
    if ($During) { throw 'BLOCKED: concurrent default-target execution/capture is quarantined; stable-ID transport requires separate validation.' }
}
function Run([string]$Name, [string]$Command, [int]$Seconds = 60, [scriptblock]$During, [switch]$IdentityProbe) {
    Assert-NoConcurrentTargetCommand $During
    if ($script:boundTarget -and -not $IdentityProbe) {
        $current = (Run ($Name + '-identity-before') 'winapp target snapshot sandbox --json' 30 -IdentityProbe) | ConvertFrom-Json
        Assert-SandboxBinding $script:boundTarget $current
    }
    $stdout = Join-Path $Artifacts ($Name + '.stdout.txt')
    $stderr = Join-Path $Artifacts ($Name + '.stderr.txt')
    $p = Start-Process -FilePath 'cmd.exe' -ArgumentList @('/d', '/c', $Command) -WindowStyle Hidden -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    $null = $p.Handle
    if ($Name -eq 'start-observe') { $script:observationStarted = $true }
    if (-not $p.WaitForExit($Seconds * 1000)) {
        & taskkill.exe /F /T /PID $p.Id | Out-Null
        $steps.Add(@{ name = $Name; exit = $null; timeout = $true })
        throw "$Name timed out after $Seconds seconds"
    }
    $p.WaitForExit()
    $steps.Add(@{ name = $Name; exit = $p.ExitCode; timeout = $false })
    if ($p.ExitCode -ne 0) { throw "$Name exit=$($p.ExitCode); see $stderr" }
    if ($script:boundTarget -and -not $IdentityProbe) {
        $current = (Run ($Name + '-identity-after') 'winapp target snapshot sandbox --json' 30 -IdentityProbe) | ConvertFrom-Json
        Assert-SandboxBinding $script:boundTarget $current
    }
    return (Get-Content -LiteralPath $stdout -Raw)
}
$captureDuringObservation = {
    Start-Sleep -Seconds 10
    $null = Run 'windows' 'winapp ui list-windows --on sandbox'
    $null = Run 'inspect' 'winapp ui inspect --on sandbox -a WinStateDiag'
    $shot = Join-Path $Artifacts 'main.png'
    $null = Run 'screenshot' "winapp ui screenshot --on sandbox -a WinStateDiag -o `"$shot`""
}
try {
    # Fail before deployment, not after creating another VM, while this
    # observation plan still requires the known-unsafe concurrent route.
    Assert-NoConcurrentTargetCommand $captureDuringObservation
    if (-not (Test-Path -LiteralPath $Exe -PathType Leaf)) { throw 'EXE missing' }
    $summary.exe = (Resolve-Path -LiteralPath $Exe).Path
    $summary.sha256 = (Get-FileHash -LiteralPath $Exe -Algorithm SHA256).Hash
    $summary.host_pids_before = @(Get-Process WinStateDiag -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id)
    $summary.explorer_before = @(Get-Process explorer -ErrorAction SilentlyContinue | ForEach-Object { "$($_.Id):$($_.StartTime.ToUniversalTime().Ticks)" })
    $null = Run 'version' 'winapp --version'
    $before = (Run 'sandbox-before' 'wsb list --raw') | ConvertFrom-Json
    if ($null -eq $before.PSObject.Properties['WindowsSandboxEnvironments']) { throw 'Unrecognized Sandbox inventory; refuse deployment' }
    if (@($before.WindowsSandboxEnvironments).Count -ne 0) { throw 'Existing Sandbox: refuse to use or stop it' }
    $scope = 'wsd-smoke-' + [guid]::NewGuid().ToString('N')
    $summary.scope = $scope
    $runner = Join-Path $PSScriptRoot 'sandbox_smoke.ps1'
    $null = Run 'push-exe' "winapp target push sandbox `"$Exe`" `"$scope/WinStateDiag.exe`"" $BootTimeoutSec
    $snap = (Run 'snapshot' 'winapp target snapshot sandbox --json') | ConvertFrom-Json
    Assert-SandboxBinding $snap $snap
    $script:boundTarget = $snap
    $summary.bound_epoch = $snap.executionTarget.epoch
    $null = Run 'push-runner' "winapp target push sandbox `"$runner`" `"$scope/sandbox_smoke.ps1`"" $BootTimeoutSec
    # Resolve only a reported workRoot. Never guess an absolute guest path.
    function Find-WorkRoot($Object) {
        if ($null -eq $Object -or $Object -is [string]) { return }
        foreach ($prop in $Object.PSObject.Properties) {
            if ($prop.Name -eq 'workRoot' -and $prop.Value -is [string]) { $prop.Value }
            elseif ($prop.Value -is [pscustomobject]) { Find-WorkRoot $prop.Value }
        }
    }
    $roots = @(Find-WorkRoot $snap | Sort-Object -Unique)
    if ($roots.Count -ne 1 -or $roots[0] -notmatch '^[A-Za-z]:\\') { throw 'Snapshot did not provide one absolute guest workRoot' }
    $guest = Join-Path $roots[0] $scope
    $summary.guest_root = $guest
    $summary.result = 'FAIL'
    $null = Run 'start-observe' "winapp target exec sandbox -- powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$guest\sandbox_smoke.ps1`" -Root `"$guest`" -Mode Start" 120 $captureDuringObservation
    $shot = Join-Path $Artifacts 'main.png'
    $null = Run 'pull' "winapp target pull sandbox `"$scope/out`" `"$Artifacts\guest`"" 60
    $result = Get-Content (Join-Path $Artifacts 'guest/result.json') -Raw | ConvertFrom-Json
    $summary.guest = $result
    $exitResult = Get-Content (Join-Path $Artifacts 'guest/exit.json') -Raw | ConvertFrom-Json
    $summary.guest_exit = $exitResult
    if ($result.result -ne 'PASS' -or $result.observed_seconds -lt 70 -or $exitResult.method -ne 'normal window close' -or $exitResult.exit_code -ne 0 -or $summary.capture_error -or -not (Test-Path -LiteralPath $shot)) { throw 'Smoke evidence did not pass' }
    $summary.result = 'PASS'
} catch {
    $summary.reason = $_.Exception.Message
    if ($summary.reason -like 'BLOCKED:*') { $summary.result = 'BLOCKED' }
} finally {
    if ($guest -and $script:observationStarted) {
        try { $null = Run 'finish' "winapp target exec sandbox -- powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$guest\sandbox_smoke.ps1`" -Root `"$guest`" -Mode Finish" } catch { $summary.cleanup_error = $_.Exception.Message; $summary.result = 'BLOCKED' }
        try { $null = Run 'pull-final' "winapp target pull sandbox `"$scope/out`" `"$Artifacts\guest`"" } catch { $summary.export_error = $_.Exception.Message; $summary.result = 'BLOCKED' }
    }
    $summary.host_pids_after = @(Get-Process WinStateDiag -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id)
    $summary.explorer_after = @(Get-Process explorer -ErrorAction SilentlyContinue | ForEach-Object { "$($_.Id):$($_.StartTime.ToUniversalTime().Ticks)" })
    if ($summary.result -eq 'PASS' -and (($summary.explorer_before -join ',') -ne ($summary.explorer_after -join ',') -or @($summary.host_pids_after | Where-Object { $summary.host_pids_before -notcontains $_ }).Count)) { $summary.result = 'FAIL'; $summary.reason = 'Host process inventory changed during test' }
    $summary.finished = Get-Date -Format o
    $summary.steps = @($steps.ToArray())
    $summary | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $Artifacts 'summary.json') -Encoding UTF8
}
Write-Output ('SANDBOX_RESULT=' + $summary.result)
if ($summary.result -eq 'PASS') { exit 0 }
exit 3
