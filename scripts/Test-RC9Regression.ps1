# RC9 headless regression: AST-extracted pure functions, mocked providers only.
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
function Import-Functions([string]$file,[string[]]$names){
 $t=$null;$e=$null;$a=[Management.Automation.Language.Parser]::ParseFile($file,[ref]$t,[ref]$e)
 if($e.Count){throw ($e|Out-String)}
 foreach($name in $names){
  $f=$a.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true)
  if(!$f){throw "Missing $name"}
  . ([scriptblock]::Create($f.Extent.Text.Replace('function '+$name, 'function global:'+$name)))
 }
}
$script:n=0
function Eq($actual,$expected,[string]$name){if($actual -ne $expected){throw "$name expected=$expected actual=$actual"};$script:n++;Write-Output "PASS $name"}
Import-Functions (Join-Path $root 'embedded\EXPC-Diagnostic\EXPC-Diagnostic.ps1') @('Get-SfcSemanticResult','Get-DismRepairIntelligence','Get-VssEventClassification','Get-VssEventEvidence','Get-ScmServiceName')
foreach($c in @(
 @('Windows Resource Protection did not find any integrity violations.','CLEAN'),
 @('Защита ресурсов Windows не обнаружила нарушений целостности.','CLEAN'),
 @('Windows Resource Protection found integrity violations.','INTEGRITY_VIOLATIONS'),
 @('Защита ресурсов Windows обнаружила поврежденные файлы.','INTEGRITY_VIOLATIONS'),
 @('There is a system repair pending which requires reboot to complete.','REBOOT_PENDING'),
 @('Требуется перезагрузка для завершения восстановления','REBOOT_PENDING'),
 @('Windows Resource Protection could not start the repair service.','SERVICE_ERROR'),
 @('Не удалось запустить службу восстановления','SERVICE_ERROR'),
 @('Windows Resource Protection could not perform the requested operation.','ERROR'),
 @('Защита ресурсов Windows не может выполнить запрошенную операцию.','ERROR'),
 @('Verification 100% complete.','UNKNOWN'))){Eq (Get-SfcSemanticResult $c[0] $false $true 0) $c[1] ('SFC '+$c[1])}
Eq (Get-SfcSemanticResult 'No recognized output' $true $true 0) 'INTEGRITY_VIOLATIONS' 'CSI evidence without SR'
Eq (Get-SfcSemanticResult 'Windows Resource Protection did not find any integrity violations.' $false $true 5) 'ERROR' 'Nonzero prevents clean'
$noise=@('2026-10-20 10:00:00, CBS Signaling IdleScavenge and/or repair complete')
Eq (Get-DismRepairIntelligence 'The component store is repairable.' $noise).Verdict 'CURRENT_CORRUPTION' 'IdleScavenge not repair'
Eq (Get-DismRepairIntelligence 'No component store corruption detected.' $noise).Verdict 'CLEAN' 'IdleScavenge clean'
$history=@('2026-10-20 09:00:00, corruption detected','2026-10-20 10:00:00, The restore operation completed successfully.')
Eq (Get-DismRepairIntelligence 'The component store is repairable.' $history).Verdict 'RECURRENT_CORRUPTION' 'Confirmed restore recurrence'
$history+= '2026-10-20 11:00:00, corruption detected'
Eq (Get-DismRepairIntelligence 'The component store is repairable.' $history).Verdict 'CURRENT_CORRUPTION' 'Later corruption not hidden'
Eq (Get-VssEventClassification volsnap 33 'Oldest copy deleted') 'ROTATION' 'Volsnap33'
Eq (Get-VssEventClassification volsnap 36 'The shadow copies were aborted because of a user imposed limit') 'QUOTA_INTERRUPTION' 'Volsnap36 failure'
Eq (Get-VssEventClassification volsnap 36 '') 'UNKNOWN' 'Volsnap36 absent message'
Eq (Get-VssEventClassification volsnap 95 'oldest shadow copy deleted; later copies marked for delete') 'DELETE_DEPENDENCY_CONTEXT' 'Volsnap95 not quota'
Eq (Get-VssEventClassification volsnap 95 '') 'UNKNOWN' 'Volsnap95 no invented meaning'
Eq (Get-VssEventClassification VSS 8193 '0x8007045b') 'SERVICE_CONTEXT' 'Shutdown HRESULT not power cause'
function global:Get-WinEvent {throw 'Access denied fixture'}
$x=Get-VssEventEvidence;Eq $x.Events.Count 0 'No fabricated events';Eq $x.Errors.Count 2 'Both query errors retained'
foreach($name in @('TermService','ScDeviceEnum')){
 $hex=[BitConverter]::ToString([Text.Encoding]::Unicode.GetBytes($name+[char]0)).Replace('-','')
 $event=[pscustomobject]@{Id=7031;Message='Service terminated';Xml="<Event><EventData><Data Name='param1'>Localized display name</Data><Binary>$hex</Binary></EventData></Event>"}
 $event|Add-Member ScriptMethod ToXml {$this.Xml}
 Eq (Get-ScmServiceName $event) $name ('SCM Binary '+$name)
}
# Deliberate Add-Type denial before defining the mock type: no cfgmgr32 calls.
Import-Functions (Join-Path $root 'embedded\WinStateDiag\DriverAudit.ps1') @('Get-CmPnpFacts')
function global:Add-Type {throw 'CLM/AppLocker fixture denial'}
$x=Get-CmPnpFacts 'MOCK';Eq $x.Source 'UNAVAILABLE' 'Add-Type failure coverage';Eq ($x.Error -match 'CLM/AppLocker.*denial') $true 'Add-Type reason retained'
Microsoft.PowerShell.Utility\Add-Type -TypeDefinition 'public static class WsdPnp { public static uint Phantom=13; public static uint CM_Locate_DevNodeW(out uint node,string id,uint flags){node=0;return flags==1?Phantom:13;} public static uint CM_Get_DevNode_Status(out uint status,out uint problem,uint node,uint flags){status=0;problem=0;return 0;} }'
$x=Get-CmPnpFacts 'MOCK';Eq $x.Source 'UNAVAILABLE' 'PHANTOM13 not absent'
[WsdPnp]::Phantom=0;$x=Get-CmPnpFacts 'MOCK';Eq $x.Source 'CfgMgr32.NOT_PRESENT' 'PHANTOM0 confirmed absent'
Write-Output "RC9_ASSERTIONS_PASS=$script:n"
