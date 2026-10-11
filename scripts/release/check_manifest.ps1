# WinStateDiag release gate helper: reads the EMBEDDED application manifest
# (RT_MANIFEST #1) with the Windows SDK mt.exe - never a byte search, so
# string literals inside test binaries cannot cause a false result.
# Usage: check_manifest.ps1 -Root C:\AI\WinStateDiag -TestOutput <test_output.txt> -Dist <dist exe>
param([string]$Root, [string]$TestOutput, [string]$Dist)
$ErrorActionPreference = 'Continue'
$mt = Get-ChildItem 'C:\Program Files (x86)\Windows Kits\10\bin' -Recurse -Filter mt.exe -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -like '*\x64\mt.exe' } | Sort-Object FullName -Descending | Select-Object -First 1
if (-not $mt) { 'MT_EXE=NOT FOUND'; exit 2 }
'MT_EXE=' + $mt.FullName
function Get-Level([string]$exe) {
    $tmp = Join-Path $env:TEMP ('wsd_manifest_' + [IO.Path]::GetFileNameWithoutExtension($exe) + '.xml')
    if (Test-Path $tmp) { Remove-Item $tmp -Force }
    & $mt.FullName -nologo "-inputresource:$exe;#1" "-out:$tmp" 2>&1 | Out-Null
    if (-not (Test-Path $tmp)) { return 'NO_MANIFEST (asInvoker)' }
    $x = Get-Content -Raw $tmp
    if ($x -match 'requestedExecutionLevel[^>]*level="([^"]+)"') { return $Matches[1] }
    return 'MANIFEST_WITHOUT_LEVEL (asInvoker)'
}
$fail = 0
if (-not [IO.Path]::IsPathRooted($Dist)) { $Dist = Join-Path $Root $Dist }
$d = Get-Level (Resolve-Path $Dist).Path
'DIST_EXECUTION_LEVEL=' + $d
if ($d -ne 'requireAdministrator') { $fail++ }
$tests = @(Select-String -Path $TestOutput -Pattern 'Running unittests .*\((target\\debug\\deps\\[^)]+\.exe)\)' |
    ForEach-Object { $_.Matches[0].Groups[1].Value } | Select-Object -Unique)
$tests += 'target\release\storage_benchmark.exe'
if ($tests.Count -lt 2) { 'TEST_EXES=NOT FOUND'; exit 1 }
foreach ($t in $tests) {
    $p = Join-Path $Root $t
    if (-not (Test-Path $p)) { 'TEST_EXE ' + $t + ' MISSING'; continue }
    $l = Get-Level $p
    'TEST_EXE ' + $t + ' EXECUTION_LEVEL=' + $l
    if ($l -eq 'requireAdministrator' -or $l -eq 'highestAvailable') { $fail++ }
}
if ($fail) { exit 1 } else { exit 0 }
