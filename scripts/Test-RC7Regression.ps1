# Read-only regression/replay. No SFC, DISM scans, service or device changes.
param([string]$FieldRoot='', [switch]$NativeProbe)
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$env:TEMP=Join-Path $root 'target\rc7-temp'; $env:TMP=$env:TEMP
[void][IO.Directory]::CreateDirectory($env:TEMP)
function Load-Functions([string]$Path,[string[]]$Names) {
 $tokens=$null; $errors=$null
 $ast=[Management.Automation.Language.Parser]::ParseFile($Path,[ref]$tokens,[ref]$errors)
 if ($errors.Count) { throw ($errors | Out-String) }
 foreach ($name in $Names) {
  $fn=$ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst]},$true) | Where-Object Name -eq $name | Select-Object -First 1
  if (-not $fn) { throw "Missing $name" }
  # Define functions in the caller's script scope, never execute top-level actions.
  . ([scriptblock]::Create($fn.Extent.Text.Replace("function $name", "function script:$name")))
 }
}
function Assert($Condition,[string]$Message) { if (-not $Condition) { throw $Message }; Write-Output "PASS $Message" }
Load-Functions (Join-Path $root 'embedded\EXPC-Diagnostic\EXPC-Diagnostic.ps1') @('Get-SfcSemanticResult')
foreach ($text in @('Программа защиты ресурсов Windows обнаружила нарушения целостности.','Защита ресурсов Windows обнаружила нарушения целостности.','Windows Resource Protection found integrity violations.')) {
 Assert ((Get-SfcSemanticResult $text $false $true 0) -eq 'INTEGRITY_VIOLATIONS') 'SFC violations despite exit0'
}
Assert ((Get-SfcSemanticResult 'Проверка 100% завершена.' $false $true 0) -eq 'UNKNOWN') 'SFC progress and exit0 do not prove CLEAN'
Assert ((Get-SfcSemanticResult 'Защита ресурсов Windows не обнаружила нарушений целостности.' $false $true 0) -eq 'CLEAN') 'SFC clean semantics'
Assert ((Get-SfcSemanticResult 'Windows Resource Protection did not find any integrity violations.' $true $true 0) -eq 'INTEGRITY_VIOLATIONS') 'fresh CBS violation takes priority'
if ($FieldRoot) {
 foreach ($machine in @('CASE-E','CASE-B','CASE-F')) {
  $file=Get-ChildItem -LiteralPath (Join-Path $FieldRoot $machine) -Filter '*Result.json' | Select-Object -First 1
  $check=(Get-Content -LiteralPath $file.FullName -Raw -Encoding UTF8 | ConvertFrom-Json).checks | Where-Object check -eq 'SFC'
  $actual=Get-SfcSemanticResult $check.output_text $false $check.exit_code_known $check.exit_code
  $expected=if ($machine -eq 'CASE-F') {'CLEAN'} else {'INTEGRITY_VIOLATIONS'}
  Assert ($actual -eq $expected) "FIELD $machine SFC $($check.result) -> $actual (same raw text)"
 }
}
Load-Functions (Join-Path $root 'embedded\WinStateDiag\DriverAudit.ps1') @('S','Emit','Resolve-PnpCode','Get-CmPnpFacts')
foreach ($code in @(0,22,28,43)) {
 $r=Resolve-PnpCode ([pscustomobject]@{ConfigManagerErrorCode=$code}) 'PCI\TEST\1'
 Assert ($r.Code -eq [string]$code) "PnP exact numeric $code"
}
# Windows native POC uses a real current device and a nonexistent test ID.
if ($NativeProbe) {
 $e=Get-CimInstance Win32_PnPEntity -ErrorAction Stop | Where-Object {$_.ConfigManagerErrorCode -eq 0 -and $_.PNPDeviceID -like 'PCI\*'} | Select-Object -First 1
 Assert ($null -ne $e) 'LIVE native probe has a current PCI node'
 $r=Get-CmPnpFacts $e.PNPDeviceID
 Assert ($r.Source -eq 'CfgMgr32.CM_Get_DevNode_Status' -and $r.Code -eq '0') 'LIVE independent native problem code'
 $r=Get-CmPnpFacts 'ROOT\WSD_RC7_NONEXISTENT_PROBE\0000'
 Assert ($r.Source -eq 'CfgMgr32.NOT_PRESENT' -and $r.Code -eq '') 'LIVE nonexistent node is NOT_PRESENT, never code0'
}
# Inject only the read-only boundary result: no Windows device is changed.
function script:Get-CmPnpFacts($id) { [pscustomobject]@{Code='';Source='CfgMgr32.NOT_PRESENT';Error='NORMAL=13; PHANTOM=0'} }
$script:PrinterQueues=@()
foreach ($id in @('SWD\REMOTEDISPLAYENUM\1','SWD\MMDEVAPI\1','SWD\SCDEVICEENUM\1','SWD\PRINTENUM\1','TERMINPUT_BUS\UMB\1','DISPLAY\DEFAULT_MONITOR\1')) {
 $r=Resolve-PnpCode $null $id
 Assert ($r.Source -eq 'CfgMgr32.NOT_PRESENT' -and $r.Code -eq '') "MOCK native absence $id"
}
$script:PrinterQueues=@([pscustomobject]@{Name='\\printserver\Queue';PNPDeviceID=$null})
Assert ((Resolve-PnpCode $null '\\printserver\Queue').Source -eq 'Win32_Printer.PRINT_QUEUE_NOT_PNP') 'UNC print queue exact identity'
function script:Get-CmPnpFacts($id) { [pscustomobject]@{Code='';Source='UNAVAILABLE';Error='ACCESS_DENIED'} }
function script:Get-PnpDeviceProperty { throw 'READ_ERROR' }
$r=Resolve-PnpCode $null 'PCI\TEST\1'
Assert ($r.Source -eq 'UNAVAILABLE' -and $r.Code -eq '' -and $r.Error -match 'ACCESS_DENIED.*READ_ERROR') 'collection errors retained without fake zero'
Emit @('TEST', $null, '', 0, $false, 'tail')
