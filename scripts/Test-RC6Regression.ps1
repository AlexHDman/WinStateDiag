#requires -Version 5.1
# Headless fixtures only. No real SFC, DISM, repair or event-log modification.
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$source=Join-Path $root 'embedded\EXPC-Diagnostic\EXPC-Diagnostic.ps1'
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors | Out-String)}
function Write-Log {param($Message)}
function Write-ObjectLog {param($Object,$Format)}
function Add-Attention {param($Message)}
function Short-Message {param($Message,$Length) return $Message}
function Set-CheckStatus {param($Key,$Status,$Detail) $script:Status=$Status; $script:Detail=$Detail}
$functionAst=$ast.FindAll({param($a) $a -is [Management.Automation.Language.FunctionDefinitionAst] -and $a.Name -in @('Get-WheaCperInfo','Convert-PcieCorrectableStatusToText','Test-HypervisorLaunchEvent')},$true)
foreach($f in $functionAst){Invoke-Expression $f.Extent.Text}
function Get-WinEvent {
 [CmdletBinding()]param($FilterHashtable)
 if($script:QueryMode -eq 'DENIED'){throw 'Access denied fixture'}
 if($script:QueryMode -eq 'EMPTY'){
  $e=New-Object Management.Automation.ErrorRecord ([Exception]::new('No matching events')),'NoMatchingEventsFound',([Management.Automation.ErrorCategory]::ObjectNotFound),$null
  $PSCmdlet.ThrowTerminatingError($e)
 }
 return $script:Events
}
function Event([string]$Provider,[int]$Id,[string]$Raw='') {
 $o=[PSCustomObject]@{ProviderName=$Provider;Id=$Id;TimeCreated=(Get-Date);Message='fixture';LevelDisplayName='Warning';Properties=@([PSCustomObject]@{Value=0});Raw=$Raw}
 $o | Add-Member ScriptMethod ToXml {return ('<Event><EventData><Data Name="RawData">'+$this.Raw+'</Data></EventData></Event>')}
 return $o
}
$commands=$ast.FindAll({param($a) $a -is [Management.Automation.Language.CommandAst] -and $a.GetCommandName() -eq 'Invoke-Step'},$true)
$oldRoot=$env:SystemRoot
$env:SystemRoot=Join-Path $root 'target\rc6-temp\event-fixture-windows'
try {
 foreach($number in 6,7){
  $command=$commands | Where-Object {$_.CommandElements[2].Extent.Text -eq [string]$number} | Select-Object -First 1
  $action=($command.CommandElements | Where-Object {$_ -is [Management.Automation.Language.ScriptBlockExpressionAst]}).ScriptBlock.GetScriptBlock()
  foreach($mode in 'DENIED','EMPTY'){
   $script:QueryMode=$mode; $script:Status=$null
   & $action
   $expected=if($mode -eq 'DENIED'){'UNKNOWN'}else{'OK'}
   if($script:Status -ne $expected){throw "Step $number $mode expected $expected got $script:Status"}
   Write-Output "STEP_${number}_${mode}=PASS"
  }
  if($number -eq 7){
   $script:QueryMode='EVENTS'
   foreach($case in 'UNEXPECTED','BUGCHECK','OTHER_WER'){
    $script:Events=@((Event 'Microsoft-Windows-Kernel-Power' 41),(Event 'EventLog' 6008))
    if($case -eq 'BUGCHECK'){$script:Events+=Event 'Microsoft-Windows-WER-SystemErrorReporting' 1001}
    if($case -eq 'OTHER_WER'){$script:Events+=Event 'Vendor-WER-Other' 1001}
    & $action
    if($script:Status -ne 'ATTENTION'){throw "Unexpected shutdown lost: $case"}
    if($case -ne 'BUGCHECK' -and $script:Detail -notlike '*BSOD*'){throw "Unconfirmed BSOD lost: $case"}
    if($case -eq 'BUGCHECK' -and $script:Detail -notlike '*BugCheck=1*'){throw 'BugCheck not counted'}
    Write-Output "STABILITY_${case}=PASS"
   }
  }
 }
 foreach($code in 0,1,2,3,99){
  $bytes=New-Object byte[] 128
  [Array]::Copy([Text.Encoding]::ASCII.GetBytes('CPER'),0,$bytes,0,4)
  [Array]::Copy([BitConverter]::GetBytes([uint32]$code),0,$bytes,12,4)
  [Array]::Copy([BitConverter]::GetBytes([uint32]128),0,$bytes,20,4)
  $hex=[BitConverter]::ToString($bytes).Replace('-','')
  $info=Get-WheaCperInfo (Event 'Microsoft-Windows-WHEA-Logger' 18 $hex)
  $expected=@{0='Recoverable';1='Fatal';2='Corrected';3='Informational';99='Unknown'}[$code]
  if($info.Severity -ne $expected){throw "CPER severity $code"}
  Write-Output "WHEA_${expected}=PASS"
 }
 if((Get-WheaCperInfo (Event 'Microsoft-Windows-WHEA-Logger' 18 'broken')).Severity -ne 'Unknown'){throw 'Malformed CPER invented severity'}
 if((Get-WheaCperInfo (Event 'Microsoft-Windows-WHEA-Logger' 17)).Severity -ne 'Corrected'){throw 'WHEA17 lost'}
 Write-Output 'RC6_EVENT_REGRESSION=PASS'
} finally {$env:SystemRoot=$oldRoot}
