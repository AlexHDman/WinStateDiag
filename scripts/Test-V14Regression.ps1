# AST-isolated synthetic checks; no servicing or registry mutation.
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$n=0
function Eq($a,$b,$label){if($a -ne $b){throw "$label actual=$a expected=$b"};$script:n++}
$t=$null;$e=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'embedded/EXPC-Diagnostic/EXPC-Diagnostic.ps1'),[ref]$t,[ref]$e)
Eq $e.Count 0 'syntax'
foreach($name in @('Get-DismRepairIntelligence','Get-SfcSemanticResult','Get-SfcClassification','Get-SfcCbsViolations','Get-LocalizedTextDecodeScore','Convert-BytesToTextAuto','Read-BytesShared','Read-TextFileAuto','Get-LatestPercentFromText','Invoke-NativeWithProgress')){
 $f=$ast.Find({param($a)$a -is [Management.Automation.Language.FunctionDefinitionAst] -and $a.Name -eq $name},$true)
 . ([scriptblock]::Create($f.Extent.Text))
}
$clean='Windows Resource Protection did not find any integrity violations.'
$ru='Защита ресурсов Windows не обнаружила нарушений целостности.'
foreach($text in @($clean,$ru,[Text.Encoding]::Unicode.GetString([Text.Encoding]::Unicode.GetBytes($ru)),[Text.Encoding]::GetEncoding(866).GetString([Text.Encoding]::GetEncoding(866).GetBytes($ru)))){Eq (Get-SfcSemanticResult $text $false $true 0) CLEAN 'clean RU EN UTF16 OEM'}
Eq (Get-SfcSemanticResult $clean $true $true 0) UNKNOWN 'CBS cannot override clean'
Eq (Get-SfcSemanticResult 'Windows Resource Protection found integrity violations.' $false $true 0) INTEGRITY_VIOLATIONS 'positive result'
Eq (Get-SfcSemanticResult 'Verification 100% complete.' $false $true 0) UNKNOWN 'percentage not final'
Eq (Get-SfcSemanticResult $clean $false $true 5) ERROR 'nonzero exit'
Eq (Get-SfcSemanticResult '2026-11-01 10:00:00 CBS There is a system repair pending which requires reboot to complete.' $false $true 0) UNKNOWN 'historical pending ignored'
Eq (Get-SfcSemanticResult 'There is a system repair pending which requires reboot to complete.' $false $true 0) REBOOT_PENDING 'native pending retained'
Eq (Get-SfcClassification CLEAN $false) INCOMPLETE 'interrupted'
Eq (Get-SfcClassification ERROR) EXECUTION_FAILED 'execution'
Eq (Get-SfcClassification CLEAN) PASS 'public result'
Eq (Get-SfcClassification INTEGRITY_VIOLATIONS) ATTENTION 'public finding'
$lines=@('2026-11-01 10:00:00 CBS [SR] Cannot repair old.dll','2026-11-07 10:00:01 CSI Store corruption check completed','2026-11-07 10:00:02 CSI Payload Corrupt (n) synthetic.dll') -join "`n"
$bad=@(Get-SfcCbsViolations $lines ([datetime]'2026-11-07T10:00:00') ([datetime]'2026-11-07T10:02:00'))
Eq $bad.Count 1 'only current concrete corruption'
$now=[datetime]'2026-11-07T22:00:00'
foreach($counter in @('Count of times corruption detected','Total Detected Corruption','CSI Payload Corruption','CSI Manifest Corruption','CBS Manifest Corruption')) {
 Eq (Get-DismRepairIntelligence 'No component store corruption detected.' @("2026-11-07 21:27:58 CBS ${counter}: 0") $now).Verdict CLEAN "zero $counter"
 Eq (Get-DismRepairIntelligence 'No component store corruption detected.' @("2026-11-07 21:27:58 CBS ${counter}: 15") $now).Verdict HISTORICAL_ONLY "positive $counter"
}
Eq (Get-DismRepairIntelligence 'Повреждение хранилища компонентов не обнаружено.' @() $now).Current CLEAN 'native RU singular'
Eq (Get-DismRepairIntelligence 'Повреждений хранилища компонентов не обнаружено.' @() $now).Current CLEAN 'native RU plural'
Eq (Get-DismRepairIntelligence $clean @('corruption detected') $now).LastCorruption $null 'undated cannot prove history'
Eq (Get-DismRepairIntelligence 'No component store corruption detected.' @('2026-11-07 22:01:00 CBS corruption detected') $now).Verdict CLEAN 'current not historical'
$h=@('2026-11-07 20:00:00 CBS corruption detected','2026-11-07 21:00:00 DISM The restore operation completed successfully.')
$r=Get-DismRepairIntelligence 'The component store is repairable.' $h $now
Eq $r.Verdict CURRENT_CORRUPTION 'same file recurrence not inferred from global repair'
Eq $r.Status ATTENTION 'real current defect retained'
# Actual byte decoder and harmless redirected process, before preflight mocks.
$oldCulture=[Threading.Thread]::CurrentThread.CurrentCulture
try {
 [Threading.Thread]::CurrentThread.CurrentCulture=[Globalization.CultureInfo]::GetCultureInfo('ru-RU')
 foreach($cp in @(65001,1200,866,1251)) {
  $decoded=Convert-BytesToTextAuto ([Text.Encoding]::GetEncoding($cp).GetBytes($ru))
  Eq (Get-SfcSemanticResult $decoded $false $true 0) CLEAN "actual decoder $cp"
 }
} finally {[Threading.Thread]::CurrentThread.CurrentCulture=$oldCulture}
Eq (Get-SfcSemanticResult 'Защита ресурсов Windows обнаружила нарушения целостности.' $false $true 0) INTEGRITY_VIOLATIONS 'RU violation'
Eq (Get-SfcSemanticResult 'Windows Resource Protection did not find any' $false $true 0) UNKNOWN 'truncated final'
function Show-LiveProgress {param($Label,$Percent,$Elapsed,[switch]$Complete)}
function Write-Log {param($Message) if($Message -like '[[]ERROR[]]*'){throw $Message}}
$ReportDirectory=Join-Path $root ('target\v14-native-capture\'+[guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($ReportDirectory)
$env:TEMP=$ReportDirectory
$ReportBaseName='SYNTHETIC'
$payload="[Console]::WriteLine('Windows Resource Protection did not find any integrity violations.');[Console]::Error.WriteLine('synthetic stderr');exit 0"
$encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payload))
$r=Invoke-NativeWithProgress -FilePath (Join-Path $PSHOME 'powershell.exe') -Arguments ("-NoProfile -NonInteractive -EncodedCommand "+$encoded) -Label 'SFC synthetic'
Eq ($r.Text -like '*did not find*') $true 'mock process output'
Eq @(Get-ChildItem -LiteralPath $ReportDirectory -Filter '*_stdout.bin').Count 1 'stdout persisted'
Eq @(Get-ChildItem -LiteralPath $ReportDirectory -Filter '*_stderr.bin').Count 1 'stderr persisted'
Eq @(Get-ChildItem -LiteralPath $ReportDirectory -Filter '*_Native_*.json').Count 1 'metadata persisted'
Eq ($null -eq (Get-Process -Id $r.ProcessId -ErrorAction SilentlyContinue)) $true 'own mock exited'
. (Join-Path $root 'embedded/WinStateDiag/RepairPreflight.ps1')
$script:cbs=$true;$script:wu=$false;$script:pending=$false
function Get-CimInstance {param($Class,$ErrorAction) [pscustomobject]@{ProductType=1;Version='10.0.26200'}}
function Test-Path {param($LiteralPath,$ErrorAction) if($LiteralPath -like '*RebootPending'){$script:cbs}elseif($LiteralPath -like '*RebootRequired'){$script:wu}else{$false}}
function Get-WindowsPackage {param([switch]$Online,$ErrorAction) if($script:pending){[pscustomobject]@{PackageState='InstallPending'}}}
Eq (Get-RepairPreflight -Check SFC).Allowed $true 'single CBS does not block SFC'
Eq (Get-RepairPreflight -Check DISM).Allowed $true 'single CBS does not block DISM'
Eq (Get-RepairPreflight -Check SFC).RebootRecommended $true 'advisory retained'
$script:wu=$true
Eq (Get-RepairPreflight -Check SFC).Allowed $true 'SFC native decides WU advisory'
Eq (Get-RepairPreflight -Check DISM).Allowed $false 'DISM WU explicit blocker'
$script:pending=$true
Eq (Get-RepairPreflight -Check SFC).Allowed $false 'active pending package blocks'
Write-Host "V1.4 SYNTHETIC: $n PASS; REAL REPAIR NOT RUN"
