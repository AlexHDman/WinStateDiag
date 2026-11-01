$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$t=$null;$e=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'embedded\EXPC-Diagnostic\EXPC-Diagnostic.ps1'),[ref]$t,[ref]$e)
if($e.Count){throw ($e|Out-String)}
foreach($name in @('Get-VssEventClassification','Test-HypervisorLaunchEvent','Set-CheckStatus')){
 $f=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true)
 . ([scriptblock]::Create($f.Extent.Text))
}
function Write-Log {param($m)}
function Write-ObjectLog {param($Object,$Format)}
function Add-Attention {param($m)}
function Short-Message {param($m,$n) return $m}
$script:Checks=[ordered]@{}
function Get-VssWriters {[pscustomobject]@{Status='OK';Count=1;Raw='stable fixture'}}
function Get-VssShadowStorageInfo {[pscustomobject]@{Success=$true;Rows=@();Error='';NearLimitCount=0}}
function Get-VssEventEvidence {[pscustomobject]@{Events=@($script:Events);Errors=@($script:Errors)}}
function Get-WinEvent {param($FilterHashtable,$ErrorAction) $script:Events}
function Event([string]$provider,[int]$id,[datetime]$time,[string]$message){[pscustomobject]@{ProviderName=$provider;Id=$id;TimeCreated=$time;Message=$message;Properties=@([pscustomobject]@{Value=0})}}
$commands=$ast.FindAll({param($n)$n -is [Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Invoke-Step'},$true)
$c=$commands|Where-Object {$_.CommandElements[2].Extent.Text -eq '5'}|Select-Object -First 1
$action=($c.CommandElements|Where-Object {$_ -is [Management.Automation.Language.ScriptBlockExpressionAst]}).ScriptBlock.GetScriptBlock()
foreach($case in @('EMPTY','DENIED','VSS','VOLSNAP36')){
 $script:Events=@();$script:Errors=@();$script:Status=''
 if($case -eq 'DENIED'){$script:Errors=@('Access denied fixture')}
 if($case -eq 'VSS'){$script:Events=@(Event VSS 8193 (Get-Date) 'Operation failed')}
 if($case -eq 'VOLSNAP36'){$script:Events=@(Event volsnap 36 (Get-Date) 'The shadow copies were aborted due to a user imposed limit')}
 & $action
 $script:Status=$script:Checks['VSS Shadow Storage'].Status;$script:Detail=$script:Checks['VSS Shadow Storage'].Detail
 $expected=if($case -in @('EMPTY','DENIED')){'UNKNOWN'}else{'ATTENTION'}
 if($script:Status -ne $expected){throw "VSS $case $script:Status expected $expected"}
 if($case -in @('VSS','VOLSNAP36') -and $script:Detail -notmatch 'недавних=1'){throw 'Failure count lost'}
 if($case -eq 'DENIED' -and $script:Checks['VSS collection'].Status -ne 'ERROR'){throw 'VSS query error hidden from execution status'}
 Write-Output "VSS_STAGE_${case}=PASS"
}
$c=$commands|Where-Object {$_.CommandElements[2].Extent.Text -eq '7'}|Select-Object -First 1
$action=($c.CommandElements|Where-Object {$_ -is [Management.Automation.Language.ScriptBlockExpressionAst]}).ScriptBlock.GetScriptBlock()
$oldRoot=$env:SystemRoot;$env:SystemRoot=Join-Path $root 'target\rc9-temp\mock-windows-empty'
try{
 foreach($days in @(2,25)){
  $script:Events=@((Event 'Microsoft-Windows-Kernel-Power' 41 ((Get-Date).AddDays(-$days)) 'Unexpected shutdown'),(Event EventLog 6008 ((Get-Date).AddDays(-$days)) 'Unexpected shutdown'))
  & $action
  $script:Status=$script:Checks['Stability / BSOD'].Status
  $expected=if($days -lt 7){'ATTENTION'}else{'HISTORICAL'}
  if($script:Status -ne $expected){throw "STABILITY age=$days status=$script:Status expected=$expected"}
  Write-Output "STABILITY_AGE_${days}=PASS"
 }
}finally{$env:SystemRoot=$oldRoot}