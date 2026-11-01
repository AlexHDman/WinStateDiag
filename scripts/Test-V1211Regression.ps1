$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'Test-V1210Regression.ps1')
Load-Functions (Join-Path $root 'embedded/EXPC-Diagnostic/EXPC-Diagnostic.ps1') @('Get-PnpIssueClass')
foreach($machine in @('CASE-A','CASE-B')){
 $raw=Get-Content -LiteralPath (Join-Path $PSScriptRoot "fixtures/v1.2.11/$machine-writers.txt") -Raw -Encoding UTF8
 $r=ConvertFrom-VssWriters $raw 0
 if($machine -eq 'CASE-A'){Eq $r.Count 11 'CaseA synthetic count';Eq $r.Stable 11 'CaseA stable';Eq $r.Status OK 'CaseA parsed'}
 else {Eq $r.Count 10 'CaseB synthetic count';Eq $r.Waiting 2 'CaseB System and WMI waiting';Eq $r.Failed 0 'waiting not failed';Eq $r.Status WAITING 'CaseB parsed';Eq @($r.Writers|Where-Object {$_.Name -eq 'System Writer' -and $_.StateCode -eq 5 -and $_.State -eq 'WAITING'}).Count 1 'System Writer state 5'}
 Eq $r.Coverage COMPLETE "$machine complete records"
 Eq @($r.Writers|Where-Object {!$_.WriterId -or !$_.InstanceId}).Count 0 "$machine GUIDs retained"
 $en=$raw.Replace('Имя компонента записи','Writer name').Replace('Id экземпляра компонента записи','Writer Instance Id').Replace('Id компонента записи','Writer Id').Replace('Состояние','State').Replace('Последняя ошибка','Last error').Replace('Нет ошибок','No error')
 Eq (ConvertFrom-VssWriters $en 0).Status $r.Status "$machine EN numeric state parity"
 $broken=$raw -replace '(?im)^.*Id экземпляра.*$',''
 Eq (ConvertFrom-VssWriters $broken 0).Coverage LIMITED 'missing GUID is limited'
}
Eq (Get-PnpIssueClass 22 'PCI\VEN_1002') DISABLED 'Radeon Code22 not malfunction'
foreach($code in @(10,28,31,43)){Eq (Get-PnpIssueClass $code 'PCI\VEN_FAKE') PROBLEM "Code $code retained"}
Eq (Get-PnpIssueClass $null 'PCI\VEN_FAKE') UNKNOWN 'missing PnP code not OK'
Eq (Get-PnpIssueClass 24 'ACPI\PNP0303\0') LEGACY_CONTEXT 'legacy PS2'
Eq (Get-PnpIssueClass 45 'USB\MISSING') NOT_PRESENT 'Code45 absent'


# Execute the real Stage 03 action with mocked collection only.
$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'embedded/EXPC-Diagnostic/EXPC-Diagnostic.ps1'),[ref]$tokens,[ref]$errors)
$command=$ast.FindAll({param($a)$a -is [Management.Automation.Language.CommandAst] -and $a.GetCommandName() -eq 'Invoke-Step'},$true)|Where-Object {$_.CommandElements[2].Extent.Text -eq '3'}|Select-Object -First 1
$action=($command.CommandElements|Where-Object {$_ -is [Management.Automation.Language.ScriptBlockExpressionAst]}).ScriptBlock.GetScriptBlock()
function Get-PnpDevice {param([switch]$PresentOnly,$ErrorAction) if($script:PnpFail){throw 'access denied fixture'}; $script:NativeFixture}
function Get-CompatInstance {param($Class,$ErrorAction) if($script:PnpFail){throw 'access denied fixture'}; $script:PnpFixture}
function Write-Log {}
function Write-ObjectLog {}
function Add-Attention {}
function Set-CheckStatus {param($Key,$Status,$Detail) $script:PnpChecks[$Key]=[pscustomobject]@{Status=$Status;Detail=$Detail}}
foreach($code in @(0,22,10,28,31,43,$null)){
 $script:PnpFail=$false;$script:PnpChecks=@{}
 $script:NativeFixture=@([pscustomobject]@{FriendlyName='AMD Radeon HD 7450';Class='DISPLAY';InstanceId='PCI\VEN_1002';Status='Error'})
 $script:PnpFixture=@([pscustomobject]@{Name='AMD Radeon HD 7450';Present=$true;PNPDeviceID='PCI\VEN_1002';ConfigManagerErrorCode=$code})
 & $action
 $expected=if($null -eq $code){'UNKNOWN'}elseif($code -eq 0){'OK'}elseif($code -eq 22){'INFO'}else{'ATTENTION'}
 Eq $script:PnpChecks['PnP devices'].Status $expected "actual Stage03 code $code"
}
$script:PnpFail=$true;$script:PnpChecks=@{};& $action
Eq $script:PnpChecks['PnP devices'].Status UNKNOWN 'Stage03 denied not OK'
Eq $script:PnpChecks['PnP collection'].Status ERROR 'Stage03 execution failure retained'
Write-Output "V1211_ASSERTIONS_PASS=$n"
