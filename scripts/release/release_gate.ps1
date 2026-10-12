# WinStateDiag release gate (versioned in Git: scripts/release/).
#
# Proves a release EXE for ONE exact, clean, committed HEAD. FAILS CLOSED:
# any error, exception or failed check ends with GATE_RESULT=FAIL, and
# GATE_RESULT=PASS is written only after the final dist EXE has been built
# by make_release.ps1, hashed and verified, and after HEAD / worktree were
# re-checked at the end.
#
# Provenance (checked first, before anything is built):
#   * -ExpectedHead (full 40-hex SHA) is mandatory and must equal HEAD;
#   * the worktree is clean (no modified, staged or untracked files);
#   * this script, its helpers and make_release.ps1 are tracked by Git and
#     the script runs from <repo>\scripts\release (not a copy elsewhere).
#
# Evidence: release-evidence\v<version>\gate_<stamp>_<sha12>\ (git-ignored)
#   gate.log, release_manifest.txt (PRODUCER_COMMIT), probe outputs,
#   gate_summary.txt. Superseded EXEs of the same version are backed up to
#   release-evidence\v<version>\superseded\ before being replaced.
# Older dist\ releases are hashed before / after and must be unchanged.
# Only one gate runs at a time (release-evidence\gate.lock); every step's
# exit code is logged, and each app probe / render has a timeout (FAIL).
#
# Usage (elevated; the .cmd wrapper requests elevation):
#   scripts\release\release_gate.cmd <expected-head-sha>
#
# -TestFault build|missing_exe is ONLY for testing the gate itself: it
# skips fmt/check/test, injects the fault, and the result can never be PASS.

param(
    [Parameter(Mandatory = $true)][string]$ExpectedHead,
    [ValidateSet('', 'build', 'missing_exe')][string]$TestFault = ''
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Set-Location $root
$started = Get-Date
$stamp = $started.ToString('yyyyMMdd-HHmmss')
$script:Failed = $null
$script:Log = $null
$script:LogBuffer = New-Object System.Collections.Generic.List[string]

# Appends one line, sharing the file and retrying for ~10 s: a scanner or
# log viewer holding gate.log for a moment must not kill the gate (a plain
# Add-Content sharing violation did, with no FAIL recorded).
function Append-Line([string]$path, [string]$line) {
    $bytes = [Text.Encoding]::UTF8.GetBytes($line + "`r`n")
    for ($i = 1; ; $i++) {
        try {
            $fs = [IO.File]::Open($path, [IO.FileMode]::Append, [IO.FileAccess]::Write,
                [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
            try { $fs.Write($bytes, 0, $bytes.Length) } finally { $fs.Dispose() }
            return
        } catch [IO.IOException] {
            if ($i -ge 50) { throw }
            Start-Sleep -Milliseconds 200
        }
    }
}
# Never throws: a line that cannot reach gate.log goes to gate.log.unwritten.
function Log([string]$line) {
    if ($line.StartsWith('== ')) { $line += "  [$((Get-Date).ToString('HH:mm:ss'))]" }
    Write-Host $line
    if (-not $script:Log) { $script:LogBuffer.Add($line); return }
    try { Append-Line $script:Log $line }
    catch {
        try { Append-Line ($script:Log + '.unwritten') "$line   <<< gate.log write failed: $_" }
        catch { Write-Host "LOG WRITE FAILED: $_" -ForegroundColor Red }
    }
}
function Fail([string]$step, [string]$why) {
    throw "GATE_STEP_FAILED|$step|$why"
}
# Native tools run through cmd.exe: Windows PowerShell 5.1 would turn
# their stderr (cargo progress, git warnings) into terminating errors.
function Native([string]$line) {
    $ErrorActionPreference = 'Continue'
    cmd /c $line | Out-Host
    return $LASTEXITCODE
}
function Native-Log([string]$line, [string]$step) {
    $rc = Native ($line + ' >> "' + $script:Log + '" 2>&1')
    Log "EXIT $step=$rc"
    if ($rc -ne 0) { Fail $step "exit $rc" }
}
function Git([string]$a) {
    $ErrorActionPreference = 'Continue'
    $out = @(cmd /c "git $a 2>&1")
    if ($LASTEXITCODE -ne 0) { Fail 'GIT' ("git $a failed: " + ($out -join ' ')) }
    return $out
}
# Runs one app probe / render with a timeout; on timeout its process tree is
# ended and the step FAILS. The exit code of every run is logged.
function Run-Exe([string]$exe, [string[]]$a, [string]$step, [int]$timeoutSec, [switch]$Hidden) {
    $t0 = Get-Date
    $style = if ($Hidden) { 'Hidden' } else { 'Normal' }
    $p = Start-Process -FilePath $exe -ArgumentList $a -PassThru -WindowStyle $style
    $null = $p.Handle  # keeps ExitCode readable after exit (PowerShell 5.1)
    if (-not $p.WaitForExit($timeoutSec * 1000)) {
        $null = cmd /c "taskkill /F /T /PID $($p.Id) 2>&1"
        Log "EXIT $step=TIMEOUT after ${timeoutSec}s (process tree $($p.Id) ended)"
        Fail "${step}_TIMEOUT" "$($a[0]) did not exit within ${timeoutSec}s"
    }
    $p.WaitForExit()
    Log "EXIT $step=$($p.ExitCode) ($([int]((Get-Date) - $t0).TotalSeconds)s)"
    return $p.ExitCode
}
function Sha([string]$path) { (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash }
function Dist-Hashes([string]$exclude) {
    Get-ChildItem -LiteralPath (Join-Path $root 'dist') -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { -not $_.FullName.StartsWith($exclude, [StringComparison]::OrdinalIgnoreCase) } |
        ForEach-Object { $_.FullName.Substring($root.Length + 1) + '=' + (Sha $_.FullName) } |
        Sort-Object
}
function Driver-Service-Names {
    @((Get-CimInstance Win32_SystemDriver | ForEach-Object Name) +
      (Get-CimInstance Win32_Service | ForEach-Object Name)) | Sort-Object -Unique
}

$servicesBefore = $null
$evidence = $null
try {
    # ---------------------------------------------------------------- 1
    Log "== 1. PROVENANCE"
    # One gate at a time: the lock is held (exclusive handle) until exit.
    $lockPath = Join-Path $root 'release-evidence\gate.lock'
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $lockPath) | Out-Null
    try { $script:Lock = [IO.File]::Open($lockPath, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None) }
    catch { Fail '0_GATE_ALREADY_RUNNING' "another release gate holds $lockPath" }
    Log "GATE_LOCK=$lockPath (PID $PID)"
    if ($ExpectedHead -notmatch '^[0-9a-f]{40}$') { Fail '1_PROVENANCE' 'ExpectedHead must be a full 40-hex lowercase SHA' }
    $head = ((Git 'rev-parse HEAD') -join '').Trim()
    $short = $head.Substring(0, 12)

    $cargo = Get-Content -Raw (Join-Path $root 'Cargo.toml')
    if ($cargo -notmatch '(?ms)^\[package\].*?^version\s*=\s*"(\d+)\.(\d+)\.(\d+)"') { Fail '1_PROVENANCE' 'version not found in Cargo.toml' }
    $version = if ($Matches[3] -eq '0') { "$($Matches[1]).$($Matches[2])" } else { "$($Matches[1]).$($Matches[2]).$($Matches[3])" }

    $evidence = Join-Path $root "release-evidence\v$version\gate_${stamp}_$short"
    New-Item -ItemType Directory -Force -Path $evidence | Out-Null
    $script:Log = Join-Path $evidence 'gate.log'
    $script:LogBuffer | ForEach-Object { Append-Line $script:Log $_ }

    Log "GATE_STARTED=$($started.ToString('yyyy-MM-dd HH:mm:ss'))"
    Log "GATE_SCRIPT=$PSCommandPath"
    Log "EXPECTED_HEAD=$ExpectedHead"
    Log "HEAD=$head"
    Log "BRANCH=$(((Git 'rev-parse --abbrev-ref HEAD') -join '').Trim())"
    Log "VERSION=$version"
    if ($TestFault) { Log "TEST_FAULT=$TestFault (gate self-test: result is forced to FAIL)" }
    if ($head -ne $ExpectedHead) { Fail '1_PROVENANCE_HEAD' "HEAD $head != expected $ExpectedHead" }

    $dirty = @(Git 'status --porcelain --untracked-files=all' | Where-Object { $_ })
    Log "WORKTREE_CHANGES=$($dirty.Count)"
    $dirty | Select-Object -First 20 | ForEach-Object { Log "  DIRTY $_" }
    if ($dirty.Count) { Fail '1_PROVENANCE_DIRTY' 'worktree is not clean' }

    $expectedScript = Join-Path $root 'scripts\release\release_gate.ps1'
    if ($PSCommandPath -ne $expectedScript) { Fail '1_PROVENANCE_SCRIPT' "gate must run from $expectedScript" }
    foreach ($f in @('scripts/release/release_gate.ps1', 'scripts/release/release_gate.cmd',
                     'scripts/release/check_manifest.ps1', 'scripts/make_release.ps1',
                     'scripts/release/fetch_lhm.ps1', 'scripts/release/lhm_bundle.sha256', '.cargo/config.toml',
                     'Cargo.toml', 'Cargo.lock', 'build.rs', '.gitignore')) {
        if ((Native "git ls-files --error-unmatch -- $f >nul 2>&1") -ne 0) { Fail '1_PROVENANCE_TRACKED' "$f is not tracked by Git" }
        Log "TRACKED $f @ $(((Git "log -1 --format=%h -- $f") -join '').Trim())"
    }
    Log "RUSTC=$((cmd /c 'rustc --version 2>&1') -join ' ')"
    Log "CARGO=$((cmd /c 'cargo --version 2>&1') -join ' ')"
    # Embedded third-party binaries (git-ignored) must match the pinned lock.
    Native-Log ('powershell -NoProfile -ExecutionPolicy Bypass -File "' + (Join-Path $PSScriptRoot 'fetch_lhm.ps1') + '" -VerifyOnly') '1_LHM_BUNDLE'
    Log "LHM_BUNDLE=PASS"
    Log "PROVENANCE=PASS"

    # ---------------------------------------------------------------- 2
    Log "== 2. DIST BEFORE"
    $releaseDir = Join-Path $root "dist\WinStateDiag-v$version"
    $distExe = Join-Path $releaseDir 'WinStateDiag.exe'
    $oldBefore = @(Dist-Hashes $releaseDir)
    $oldBefore | ForEach-Object { Log "BEFORE $_" }
    $oldBefore | Out-File -Encoding utf8 (Join-Path $evidence 'old_dist_before.txt')
    if (Test-Path -LiteralPath $distExe) {
        $prevSha = Sha $distExe
        $sup = Join-Path $root "release-evidence\v$version\superseded"
        New-Item -ItemType Directory -Force -Path $sup | Out-Null
        $backup = Join-Path $sup ("WinStateDiag_" + $prevSha.Substring(0, 16) + ".exe")
        if (-not (Test-Path -LiteralPath $backup)) { Copy-Item -LiteralPath $distExe -Destination $backup }
        if ((Sha $backup) -ne $prevSha) { Fail '2_BACKUP' 'backup of the superseded EXE does not match' }
        Log "SUPERSEDED_EXE_SHA256=$prevSha"
        Log "SUPERSEDED_BACKUP=$backup"
    }

    # ---------------------------------------------------------------- 3
    Log "== 3. MONITOR TOOLS CLOSED"
    $mon = @(Get-Process | Where-Object { $_.ProcessName -match 'hwinfo|aida' } | ForEach-Object ProcessName)
    Log "MONITOR_PROCESSES=$($mon -join ',')"
    if ($mon.Count) { Fail '3_MONITOR_TOOLS_RUNNING' ($mon -join ',') }

    # ---------------------------------------------------------------- 4
    $testOutput = Join-Path $evidence 'test_output.txt'
    if ($TestFault) {
        Log "== 4. QUALITY SKIPPED (TEST_FAULT)"
    } else {
        Log "== 4. FMT / CHECK / TEST"
        Native-Log 'cargo fmt --check' '4_FMT'
        Log "FMT=PASS"
        Native-Log 'cargo check --all-targets --color never' '4_CHECK'
        Log "CHECK=PASS"
        $testExit = Native ('cargo test --color never > "' + $testOutput + '" 2>&1')
        Log "EXIT 4_TEST=$testExit"
        $results = @(Select-String -LiteralPath $testOutput -Pattern '^test result' | ForEach-Object { $_.Line })
        $results | ForEach-Object { Log $_ }
        $passed = 0; $failedTests = 0
        foreach ($r in $results) {
            if ($r -match '(\d+) passed; (\d+) failed') { $passed += [int]$Matches[1]; $failedTests += [int]$Matches[2] }
        }
        Log "TESTS_PASSED=$passed TESTS_FAILED=$failedTests"
        if ($testExit -ne 0 -or $failedTests -ne 0 -or $passed -lt 1) { Fail '4_TEST' "exit $testExit, failed $failedTests" }
        Log "TEST=PASS"
    }

    # ---------------------------------------------------------------- 5
    Log "== 5. BUILD"
    $build = 'cargo build --release --color never'
    if ($TestFault -eq 'build') { $build += ' --features gate_test_fault_nonexistent_feature' }
    Native-Log $build '5_BUILD'
    $exe = Join-Path $root 'target\release\win_state_diag.exe'
    if ($TestFault -eq 'missing_exe') { $exe = Join-Path $root 'target\release\gate_test_fault_missing.exe' }
    if (-not (Test-Path -LiteralPath $exe)) { Fail '5_BUILD_EXE_MISSING' $exe }
    Log "BUILD=PASS"
    if ($TestFault) { Fail '5_TEST_FAULT' 'gate self-test never passes' }

    # ---------------------------------------------------------------- 6
    Log "== 6. ELEVATION"
    $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    Log "ELEVATED=$admin"
    if (-not $admin) { Fail '6_NOT_ELEVATED' 'the live probes need administrator rights' }
    $servicesBefore = @(Driver-Service-Names)
    $d = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction SilentlyContinue
    Log "HVCI_RUNNING=$([bool](@($d.SecurityServicesRunning) -contains 2))"

    # ---------------------------------------------------------------- 7
    Log "== 7. SENSOR PROBE"
    $sensors = Join-Path $evidence 'sensors.json'
    if ((Run-Exe $exe @('--sensor-probe', "`"$sensors`"") '7_SENSOR_PROBE' 300 -Hidden) -ne 0) { Fail '7_SENSOR_PROBE' 'exit code' }
    $j = Get-Content -Raw -LiteralPath $sensors | ConvertFrom-Json
    Log "SENSOR_STATUS=$($j.status) SENSOR_COUNT=$($j.sensor_count)"
    $j.providers | ForEach-Object { Log "PROVIDER $($_.provider) = $($_.status) | $($_.detail)" }
    $bad = @($j.sensors | Where-Object { -not $_.PSObject.Properties['threshold_source'] -or -not $_.provider -or -not $_.timestamp }).Count
    Log "SENSOR_METADATA_MISSING=$bad"
    if ($bad -gt 0 -or $j.sensor_count -lt 1) { Fail '7_SENSOR_METADATA' "missing=$bad count=$($j.sensor_count)" }

    # ---------------------------------------------------------------- 8
    Log "== 8. INCIDENT + EVENT PROBE"
    $inc = Join-Path $evidence 'incidents.json'
    if ((Run-Exe $exe @('--incident-probe', "`"$inc`"") '8_INCIDENT_PROBE' 900 -Hidden) -ne 0) { Fail '8_INCIDENT_PROBE' 'exit code' }
    $incTxt = Join-Path $evidence 'incidents.txt'
    Get-Content -LiteralPath $incTxt | ForEach-Object { Log $_ }
    $evDir = Join-Path $evidence 'events'
    if ((Run-Exe $exe @('--evidence-probe', "`"$evDir`"") '8_EVENT_PROBE' 900 -Hidden) -ne 0) { Fail '8_EVENT_PROBE' 'exit code' }
    Get-Content -LiteralPath (Join-Path $evDir 'evidence_probe.txt') -TotalCount 40 -ErrorAction SilentlyContinue | ForEach-Object { Log $_ }
    $ev = Get-Content -Raw -LiteralPath (Join-Path $evDir 'Event_Evidence_probe.json') | ConvertFrom-Json
    Log "EVENT_SCOPE=$([bool]$ev.scope) ACTIONABLE_GROUPS=$(@($ev.actionable_groups).Count) COLLECTED_AT=$($ev.collected_at)"
    if (-not $ev.scope) { Fail '8_EVENT_SCOPE' 'no scope' }
    if ($ev.collected_at -notmatch '^\d{4}-\d{2}-\d{2}T') { Fail '8_EVENT_COLLECTED_AT' "$($ev.collected_at)" }

    # ---------------------------------------------------------------- 9
    Log "== 9. SMART PROBE"
    $smart = Join-Path $evidence 'smart.json'
    $smartExit = Run-Exe $exe @('--smart-probe', "`"$smart`"") '9_SMART_PROBE' 600 -Hidden
    Get-Content -LiteralPath (Join-Path $evidence 'smart.txt') -ErrorAction SilentlyContinue | ForEach-Object { Log $_ }
    if ($smartExit -ne 0) { Fail '9_SMART_CONSISTENCY' "exit $smartExit" }

    # ---------------------------------------------------------------- 10
    Log "== 10. WINDBG DETECTION"
    $pkg = Get-AppxPackage -Name 'Microsoft.WinDbg' -ErrorAction SilentlyContinue | Select-Object -First 1
    Log "PACKAGE=$(if ($pkg) { $pkg.Version } else { 'none' })"
    $line = (Select-String -LiteralPath $incTxt -Pattern '^DEBUGGER=' | Select-Object -First 1).Line
    Log "APP_$line"
    if (-not $line) { Fail '10_WINDBG_DETECTION' 'no DEBUGGER line' }
    if ($pkg -and $line -match 'NOT INSTALLED') { Fail '10_WINDBG_DETECTION' 'package present, app says not installed' }

    # ---------------------------------------------------------------- 11
    Log "== 11. CONSISTENCY (target)"
    $ct = Join-Path $evidence 'consistency_target.txt'
    $ctExit = Run-Exe $exe @('--consistency-probe', "`"$ct`"") '11_CONSISTENCY' 600 -Hidden
    Get-Content -LiteralPath $ct -ErrorAction SilentlyContinue | ForEach-Object { Log $_ }
    if ($ctExit -ne 0) { Fail '11_CONSISTENCY' "exit $ctExit" }

    # ---------------------------------------------------------------- 12
    Log "== 12. MAKE_RELEASE (fresh build into dist)"
    Native-Log ('powershell -NoProfile -ExecutionPolicy Bypass -File "' + (Join-Path $root 'scripts\make_release.ps1') + '" -Force -ManifestDir "' + $evidence + '"') '12_MAKE_RELEASE'

    # ---------------------------------------------------------------- 13
    Log "== 13. DIST VERIFICATION"
    if (-not (Test-Path -LiteralPath $distExe)) { Fail '13_DIST_MISSING' $distExe }
    $manifestPath = Join-Path $evidence 'release_manifest.txt'
    if (-not (Test-Path -LiteralPath $manifestPath)) { Fail '13_MANIFEST_MISSING' $manifestPath }
    $m = @{}
    Get-Content -LiteralPath $manifestPath | ForEach-Object { if ($_ -match '^([A-Z_0-9]+)=(.*)$') { $m[$Matches[1]] = $Matches[2] } }
    $distSha = Sha $distExe
    $targetSha = Sha $exe
    Log "DIST_SHA256=$distSha"
    Log "TARGET_SHA256=$targetSha"
    Log "MANIFEST_EXE_SHA256=$($m['EXE_SHA256'])"
    Log "MANIFEST_PRODUCER_COMMIT=$($m['PRODUCER_COMMIT'])"
    if ($distSha -ne $targetSha -or $distSha -ne $m['EXE_SHA256']) { Fail '13_DIST_SHA' 'dist / target / manifest hashes differ' }
    if ($m['PRODUCER_COMMIT'] -ne $head) { Fail '13_PRODUCER_COMMIT' "manifest commit $($m['PRODUCER_COMMIT']) != $head" }
    if ($m['WORKTREE_CLEAN'] -ne 'YES') { Fail '13_MANIFEST_WORKTREE' 'make_release saw a dirty worktree' }
    if ((Get-Item -LiteralPath $distExe).LastWriteTime -lt $started) { Fail '13_DIST_STALE' 'dist EXE older than this gate run' }

    # ---------------------------------------------------------------- 14
    Log "== 14. VERSION / TITLE / PRODUCER_VERSION"
    $vi = (Get-Item -LiteralPath $distExe).VersionInfo
    Log "FILE_VERSION=$($vi.FileVersion) PRODUCT_VERSION=$($vi.ProductVersion)"
    if ($vi.FileVersion -ne $version -or $vi.ProductVersion -ne $version) { Fail '14_FILE_VERSION' "$($vi.FileVersion)/$($vi.ProductVersion)" }
    $cd = Join-Path $evidence 'consistency_dist.txt'
    $cdExit = Run-Exe $distExe @('--consistency-probe', "`"$cd`"") '14_DIST_CONSISTENCY' 600 -Hidden
    $cdText = Get-Content -Raw -Encoding UTF8 -LiteralPath $cd
    Get-Content -LiteralPath $cd | ForEach-Object { Log $_ }
    if ($cdExit -ne 0) { Fail '14_DIST_CONSISTENCY' "exit $cdExit" }
    if ($cdText -notmatch ('PRODUCER_VERSION=' + [regex]::Escape($version) + '\b')) { Fail '14_PRODUCER_VERSION' 'mismatch' }
    if ($cdText -notmatch ('TITLE=WinStateDiag ' + [char]0x2014 + ' v' + [regex]::Escape($version))) { Fail '14_TITLE' 'mismatch' }
    Log "TITLE=PASS"

    # ---------------------------------------------------------------- 15
    Log "== 15. MANIFEST / ELEVATION LEVELS"
    $mc = Join-Path $evidence 'manifest_check.txt'
    $mcExit = Native ('powershell -NoProfile -ExecutionPolicy Bypass -File "' + (Join-Path $PSScriptRoot 'check_manifest.ps1') + '" -Root "' + $root + '" -TestOutput "' + $testOutput + '" -Dist "' + $distExe + '" > "' + $mc + '" 2>&1')
    Log "EXIT 15_CHECK_MANIFEST=$mcExit"
    Get-Content -LiteralPath $mc | ForEach-Object { Log $_ }
    if (-not (Select-String -LiteralPath $mc -SimpleMatch 'DIST_EXECUTION_LEVEL=requireAdministrator' -Quiet)) { Fail '15_DIST_MANIFEST' 'dist is not requireAdministrator' }
    if ($mcExit -ne 0) { Fail '15_TEST_ELEVATION' "exit $mcExit" }

    # ---------------------------------------------------------------- 16
    Log "== 16. OLD RELEASES UNCHANGED"
    $oldAfter = @(Dist-Hashes $releaseDir)
    $oldAfter | ForEach-Object { Log "AFTER $_" }
    if (($oldBefore -join '|') -ne ($oldAfter -join '|')) { Fail '16_OLD_RELEASES_CHANGED' 'dist hashes differ' }
    if ($backup -and (Sha $backup) -ne $prevSha) { Fail '16_BACKUP_CHANGED' $backup }
    Log "OLD_RELEASES_UNCHANGED=YES ($($oldAfter.Count) files)"

    # ---------------------------------------------------------------- 17
    Log "== 17. QA RENDERS"
    New-Item -ItemType Directory -Force -Path (Join-Path $root 'docs\visual') | Out-Null
    $scenes = [ordered]@{ 'diagnostics' = 'DIAGNOSTICS'; 'hardware' = 'HARDWARE'; 'sensor-reading' = 'SENSOR_READING';
        'sensor-details' = 'SENSOR_DETAILS'; 'crash-analyzer' = 'CRASH_ANALYZER'; 'windbg-install' = 'WINDBG_INSTALL'; 'disk-details' = 'DISK_DETAILS' }
    foreach ($s in $scenes.Keys) {
        $png = Join-Path $root "docs\visual\v${version}_$($scenes[$s]).png"
        if (Test-Path -LiteralPath $png) { Remove-Item -LiteralPath $png -Force }
        [void](Run-Exe $distExe @('--visual-reference', '--scene', $s, '--capture', "`"$png`"") "17_RENDER_$($scenes[$s])" 180)
        if (-not (Test-Path -LiteralPath $png)) { Fail '17_RENDER' $scenes[$s] }
        Log "RENDER $($scenes[$s])=OK"
    }

    # ---------------------------------------------------------------- 18
    Log "== 18. FINAL PROVENANCE RE-CHECK"
    $headAfter = ((Git 'rev-parse HEAD') -join '').Trim()
    $dirtyAfter = @(Git 'status --porcelain --untracked-files=all' | Where-Object { $_ })
    Log "HEAD_AFTER=$headAfter WORKTREE_CHANGES_AFTER=$($dirtyAfter.Count)"
    $dirtyAfter | Select-Object -First 20 | ForEach-Object { Log "  DIRTY $_" }
    if ($headAfter -ne $head) { Fail '18_HEAD_CHANGED' $headAfter }
    if ($dirtyAfter.Count) { Fail '18_WORKTREE_DIRTY_AFTER' 'the gate run changed tracked files' }
    $servicesAfter = @(Driver-Service-Names)
    $new = @(Compare-Object $servicesBefore $servicesAfter | Where-Object SideIndicator -eq '=>' | ForEach-Object InputObject)
    Log "NEW_DRIVERS_OR_SERVICES=$($new -join ',')"
    if ($new.Count) { Fail '18_NEW_DRIVERS_OR_SERVICES' ($new -join ',') }

    @("GATE_COMMIT=$head", "VERSION=$version", "DIST=$distExe", "DIST_SHA256=$distSha",
      "DIST_SIZE=$((Get-Item -LiteralPath $distExe).Length)", "EVIDENCE=$evidence",
      "FINISHED=$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))", "GATE_RESULT=PASS") |
        Out-File -Encoding utf8 (Join-Path $evidence 'gate_summary.txt')
    Log "GATE_COMMIT=$head"
    Log "DIST=$distExe"
    Log "DIST_SHA256=$distSha"
    Log "GATE_RESULT=PASS"
    exit 0
}
catch {
    $msg = "$_"
    if ($msg -match '^GATE_STEP_FAILED\|([^|]+)\|(.*)$') { $script:Failed = $Matches[1]; $why = $Matches[2] }
    else { $script:Failed = 'UNEXPECTED_ERROR'; $why = "$msg @ line $($_.InvocationInfo.ScriptLineNumber)" }
    if (-not $script:Log) {
        try {
            $fallback = Join-Path $root "release-evidence\gate_${stamp}_preflight"
            New-Item -ItemType Directory -Force -Path $fallback | Out-Null
            $script:Log = Join-Path $fallback 'gate.log'
            $script:LogBuffer | ForEach-Object { Append-Line $script:Log $_ }
        } catch { Write-Host "PREFLIGHT LOG FAILED: $_" -ForegroundColor Red }
    }
    Log "FAILED_STEP=$($script:Failed)"
    Log "FAILED_REASON=$why"
    Log "GATE_RESULT=FAIL"
    if ($script:Log) {
        try {
            @("GATE_COMMIT=$head", "FAILED_STEP=$($script:Failed)", "FAILED_REASON=$why",
              "FINISHED=$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))", "GATE_RESULT=FAIL") |
                Out-File -Encoding utf8 (Join-Path (Split-Path -Parent $script:Log) 'gate_summary.txt')
        } catch { Write-Host "SUMMARY WRITE FAILED: $_" -ForegroundColor Red }
    }
    Write-Host "GATE FAILED at $($script:Failed). Log: $($script:Log)" -ForegroundColor Red
    exit 1
}
