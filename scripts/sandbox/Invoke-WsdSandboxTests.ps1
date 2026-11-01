# WinStateDiag — Windows Sandbox test harness (host side).
#
# Every WinStateDiag run that could touch Explorer, the GUI or the system
# state happens INSIDE Windows Sandbox, driven only by the official WinApp
# CLI commands:
#   winapp target push sandbox <src> <dst>      winapp target exec sandbox -- <cmd>
#   winapp target pull sandbox <src> <dst>      winapp run <path> --on sandbox --detach
#   winapp ui list-windows --on sandbox         winapp ui inspect --on sandbox -a <app>
#   winapp ui screenshot --on sandbox -a <app> -o <path>
# plus `wsb list` / `wsb stop --id <id>` for the session this harness started.
#
# No host mouse / keyboard automation. Nothing is installed. The host's own
# WinStateDiag is never started; Explorer is snapshotted before / after.
# Each external command has a timeout and its process tree is ended on
# expiry. A sandbox that was already running before the harness (the
# user's) is never used or stopped: the run is BLOCKED instead.
# Results: <Artifacts>\summary.json, harness.log, cmd\*.txt (stdout / stderr
# / exit code of every command), sandbox\* (pulled ZIP content), live\*.

param(
    [Parameter(Mandatory = $true)][string]$Exe,
    [Parameter(Mandatory = $true)][string]$Artifacts,
    [string]$SandboxRoot = 'wsdtest',
    [int]$BootTimeoutSec = 600,
    [int]$InsideTimeoutSec = 2400,
    [int]$UiTimeoutSec = 180,
    [int]$LiveSettleSec = 25,
    [switch]$SkipLive,
    [switch]$SmokeOnly
)

$ErrorActionPreference = 'Continue'
if ($SmokeOnly) {
    & (Join-Path $PSScriptRoot 'Invoke-WsdSandboxSmoke.ps1') -Exe $Exe -Artifacts $Artifacts -BootTimeoutSec $BootTimeoutSec
    exit $LASTEXITCODE
}
# Expanded legacy runner is not an acceptance gate until its ownership,
# token and cleanup semantics have been independently validated.
Write-Error 'Expanded harness disabled: run -SmokeOnly first. Legacy matrix requires a separate safety review.'
exit 3
New-Item -ItemType Directory -Force -Path $Artifacts | Out-Null
$cmdDir = Join-Path $Artifacts 'cmd'
New-Item -ItemType Directory -Force -Path $cmdDir | Out-Null
$log = Join-Path $Artifacts 'harness.log'
Set-Content -Encoding UTF8 -LiteralPath $log -Value ('START ' + (Get-Date -Format s))
function L([string]$m) { Add-Content -Encoding UTF8 -LiteralPath $log -Value ((Get-Date -Format 'HH:mm:ss') + ' ' + $m) }

$steps = New-Object System.Collections.Generic.List[object]
$script:n = 0

# Runs one external command through cmd.exe (works for .exe / .cmd shims),
# hidden, stdout / stderr to files, with a timeout that ends the whole tree.
function Invoke-Cmd([string]$id, [string]$commandLine, [int]$timeoutSec) {
    $script:n++
    $tag = '{0:D2}_{1}' -f $script:n, $id
    $so = Join-Path $cmdDir "$tag.out.txt"
    $se = Join-Path $cmdDir "$tag.err.txt"
    L "RUN $tag : $commandLine (timeout ${timeoutSec}s)"
    $t0 = Get-Date
    $exit = $null; $state = 'DONE'
    try {
        $p = Start-Process -FilePath 'cmd.exe' -ArgumentList @('/d', '/c', $commandLine) -PassThru `
            -WindowStyle Hidden -RedirectStandardOutput $so -RedirectStandardError $se -ErrorAction Stop
        $null = $p.Handle
        if (-not $p.WaitForExit($timeoutSec * 1000)) {
            $null = cmd /c "taskkill /F /T /PID $($p.Id) 2>&1"
            $state = 'TIMEOUT'
        } else {
            $p.WaitForExit()
            $exit = $p.ExitCode
        }
    } catch {
        $state = 'START_FAILED'
        Set-Content -Encoding UTF8 -LiteralPath $se -Value $_.Exception.Message
    }
    $sec = [math]::Round(((Get-Date) - $t0).TotalSeconds, 1)
    $text = ''
    foreach ($f in @($so, $se)) { if (Test-Path -LiteralPath $f) { $text += (Get-Content -Raw -LiteralPath $f) } }
    $rec = [ordered]@{ id = $tag; command = $commandLine; state = $state; exit_code = $exit; seconds = $sec; stdout = $so; stderr = $se }
    $steps.Add($rec)
    L "END $tag state=$state exit=$exit ${sec}s"
    return [pscustomobject]@{ ok = ($state -eq 'DONE' -and $exit -eq 0); exit = $exit; state = $state; text = $text }
}

function Sandbox-Ids([string]$text) {
    @([regex]::Matches($text, '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}') |
        ForEach-Object { $_.Value.ToLowerInvariant() } | Sort-Object -Unique)
}
function Host-Snapshot {
    [ordered]@{
        explorer = @(Get-Process -Name explorer -ErrorAction SilentlyContinue |
            ForEach-Object { '{0}@{1}' -f $_.Id, ($(try { $_.StartTime.ToString('s') } catch { '?' })) } | Sort-Object)
        winstatediag = @(Get-Process -Name 'WinStateDiag', 'win_state_diag' -ErrorAction SilentlyContinue |
            ForEach-Object { $_.Id } | Sort-Object)
    }
}

$summary = [ordered]@{
    harness = 'WinStateDiag Windows Sandbox harness v1'
    started = (Get-Date -Format s)
    exe = $Exe
    exe_sha256 = $(if (Test-Path -LiteralPath $Exe) { (Get-FileHash -Algorithm SHA256 -LiteralPath $Exe).Hash } else { $null })
    sandbox_root = $SandboxRoot
    result = 'FAIL'
    limitations = @(
        'Sandbox window z-order is not changed (no host window automation); it may appear in front of other windows while it boots.',
        'Elevation inside the sandbox depends on the sandbox account; a UAC prompt there ends the step as TIMEOUT.',
        'GPU: the sandbox renders with its virtual adapter / WARP; visuals are checked for layout, not colour fidelity of the real GPU.',
        'Hardware probes inside the sandbox see virtual hardware only (no SMART, sensors, real drivers).'
    )
}

# ------------------------------------------------------------- 0. tools
$winapp = Get-Command winapp -ErrorAction SilentlyContinue
$wsb = Get-Command wsb -ErrorAction SilentlyContinue
$summary.winapp = $(if ($winapp) { $winapp.Source } else { $null })
$summary.wsb = $(if ($wsb) { $wsb.Source } else { $null })
if (-not $winapp) {
    $summary.result = 'BLOCKED'
    $summary.reason = 'winapp CLI not found on PATH'
} elseif (-not (Test-Path -LiteralPath $Exe)) {
    $summary.result = 'BLOCKED'
    $summary.reason = "EXE not found: $Exe"
} else {
    [void](Invoke-Cmd 'winapp_version' 'winapp --version' 60)
    foreach ($h in @('run', 'ui list-windows', 'ui inspect', 'ui screenshot', 'target exec', 'target push', 'target pull')) {
        [void](Invoke-Cmd ('help_' + ($h -replace ' ', '_')) "winapp $h --help" 60)
    }
    # ----------------------------------------------- 1. host + sandbox before
    $before = Host-Snapshot
    $summary.host_before = $before
    $preIds = @()
    if ($wsb) {
        $r = Invoke-Cmd 'wsb_list_before' 'wsb list' 120
        $preIds = Sandbox-Ids $r.text
    }
    $summary.sandboxes_before = $preIds
    if ($preIds.Count -gt 0) {
        $summary.result = 'BLOCKED'
        $summary.reason = 'A Windows Sandbox is already running (not started by this harness); it is not used or stopped.'
    } else {
        # ------------------------------------------- 2. deploy (push)
        $inside = Join-Path $PSScriptRoot 'sandbox_inside.ps1'
        $push1 = Invoke-Cmd 'push_exe' ("winapp target push sandbox `"$Exe`" `"$SandboxRoot\WinStateDiag.exe`"") $BootTimeoutSec
        $push2 = Invoke-Cmd 'push_runner' ("winapp target push sandbox `"$inside`" `"$SandboxRoot\sandbox_inside.ps1`"") $UiTimeoutSec
        $summary.deploy = [ordered]@{ exe = $push1.state + '/' + $push1.exit; runner = $push2.state + '/' + $push2.exit }
        if ($wsb) {
            $r = Invoke-Cmd 'wsb_list_started' 'wsb list' 120
            $summary.sandboxes_started = @(Sandbox-Ids $r.text | Where-Object { $preIds -notcontains $_ })
        }
        if ($push1.ok -and $push2.ok) {
            # --------------------------------------- 3. functional + render tests inside
            $ex = Invoke-Cmd 'exec_inside' ("winapp target exec sandbox -- powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File `"$SandboxRoot\sandbox_inside.ps1`" -Root `"$SandboxRoot`"") $InsideTimeoutSec
            $summary.inside_exec = $ex.state + '/' + $ex.exit
            $zip = Join-Path $Artifacts 'sandbox_out.zip'
            $pl = Invoke-Cmd 'pull_results' ("winapp target pull sandbox `"$SandboxRoot\wsd_sandbox_out.zip`" `"$zip`"") $UiTimeoutSec
            if (Test-Path -LiteralPath $zip) {
                $dst = Join-Path $Artifacts 'sandbox'
                Expand-Archive -LiteralPath $zip -DestinationPath $dst -Force
                $ir = Join-Path $dst 'inside_results.json'
                if (Test-Path -LiteralPath $ir) {
                    # PS 5.1 emits a JSON array as ONE object: assign, then enumerate.
                    $parsed = Get-Content -Raw -LiteralPath $ir | ConvertFrom-Json
                    $summary.inside_results = @($parsed | ForEach-Object { $_ })
                }
            }
            $summary.pull = $pl.state + '/' + $pl.exit
            # --------------------------------------- 4. live GUI inside the sandbox
            if (-not $SkipLive) {
                $live = Join-Path $Artifacts 'live'
                New-Item -ItemType Directory -Force -Path $live | Out-Null
                $run = Invoke-Cmd 'run_detach' ("winapp run `"$Exe`" --on sandbox --detach") $UiTimeoutSec
                $deploy = 'winapp run'
                if (-not $run.ok) {
                    # Unpackaged EXE not supported by `winapp run`: start the
                    # pushed copy inside the sandbox instead (no wait).
                    $deploy = 'target exec (start)'
                    $run = Invoke-Cmd 'run_exec_start' ("winapp target exec sandbox -- cmd.exe /c start `"`" `"$SandboxRoot\WinStateDiag.exe`"") $UiTimeoutSec
                }
                $summary.live_deploy = "$deploy : " + $run.state + '/' + $run.exit
                Start-Sleep -Seconds $LiveSettleSec
                $lw = Invoke-Cmd 'ui_list_windows' 'winapp ui list-windows --on sandbox' $UiTimeoutSec
                Copy-Item -LiteralPath $steps[$steps.Count - 1].stdout -Destination (Join-Path $live 'list-windows.txt') -ErrorAction SilentlyContinue
                $app = 'WinStateDiag'
                $ins = Invoke-Cmd 'ui_inspect' "winapp ui inspect --on sandbox -a $app" $UiTimeoutSec
                Copy-Item -LiteralPath $steps[$steps.Count - 1].stdout -Destination (Join-Path $live 'inspect.txt') -ErrorAction SilentlyContinue
                $shot = Join-Path $live 'live_main.png'
                $sc = Invoke-Cmd 'ui_screenshot' ("winapp ui screenshot --on sandbox -a $app -o `"$shot`"") $UiTimeoutSec
                $summary.live = [ordered]@{
                    list_windows = $lw.state + '/' + $lw.exit
                    window_listed = [bool]($lw.text -match 'WinStateDiag')
                    inspect = $ins.state + '/' + $ins.exit
                    screenshot = $sc.state + '/' + $sc.exit
                    screenshot_file = $(if (Test-Path -LiteralPath $shot) { $shot } else { $null })
                }
                # End our app inside the sandbox only.
                [void](Invoke-Cmd 'live_stop' 'winapp target exec sandbox -- taskkill.exe /F /T /IM WinStateDiag.exe' $UiTimeoutSec)
            }
        }
        # ------------------------------------------- 5. stop OUR sandbox only (after export)
        if ($wsb) {
            $r = Invoke-Cmd 'wsb_list_end' 'wsb list' 120
            $ours = @(Sandbox-Ids $r.text | Where-Object { $preIds -notcontains $_ })
            $summary.sandboxes_ours = $ours
            foreach ($id in $ours) { [void](Invoke-Cmd 'wsb_stop' "wsb stop --id $id" 180) }
            $r = Invoke-Cmd 'wsb_list_after_stop' 'wsb list' 120
            $summary.sandboxes_left = @(Sandbox-Ids $r.text)
        } else {
            $summary.sandboxes_ours = 'wsb CLI not available: the sandbox was not stopped by the harness'
        }
    }
    # ----------------------------------------------- 6. host untouched?
    $after = Host-Snapshot
    $summary.host_after = $after
    $summary.explorer_untouched = (($before.explorer -join '|') -eq ($after.explorer -join '|'))
    $summary.host_winstatediag_started = @($after.winstatediag | Where-Object { $before.winstatediag -notcontains $_ }).Count -gt 0
    # ----------------------------------------------- 7. verdict
    if ($summary.result -ne 'BLOCKED') {
        $inside = @($summary.inside_results)
        $pass = @($inside | Where-Object { $_.status -eq 'PASS' }).Count
        $summary.inside_pass = $pass
        $summary.inside_total = $inside.Count
        $hostOk = $summary.explorer_untouched -and -not $summary.host_winstatediag_started
        if ($inside.Count -gt 0 -and $pass -eq $inside.Count -and $hostOk) { $summary.result = 'PASS' }
        elseif ($pass -gt 0 -and $hostOk) { $summary.result = 'PARTIAL' }
        else { $summary.result = 'FAIL' }
    }
}
$summary.steps = $steps
$summary.finished = (Get-Date -Format s)
$summary | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 -LiteralPath (Join-Path $Artifacts 'summary.json')
L ("RESULT " + $summary.result)
Write-Output ("SANDBOX_RESULT=" + $summary.result)
if ($summary.result -eq 'PASS') { exit 0 }
exit 1
