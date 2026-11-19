# Fixture-only: no Windows repair, installer, service or actual user cache access.
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$fixture=Join-Path $root ('target/repair-center-tests/'+[guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($fixture)
$text=[IO.File]::ReadAllText((Join-Path $root 'embedded/WinStateDiag/RepairCenter.ps1'))
$text=$text.Replace('__THUMBNAIL_B64__',[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes([IO.File]::ReadAllText((Join-Path $root 'embedded/WinStateDiag/ThumbnailCleanup.cs')))))
$text=$text.Replace('Global\EXPC.WinStateDiag.Servicing',('Local\EXPC.FixtureRepair.'+[guid]::NewGuid().ToString('N')))
$t=$null;$e=$null;$ast=[Management.Automation.Language.Parser]::ParseInput($text,[ref]$t,[ref]$e)
if($e.Count){throw 'syntax errors'}
$n=1
function Assert($ok,$label){if(!$ok){throw $label};$script:n++}
$code='{12345678-1234-1234-1234-123456789ABC}'
function Run-Fixture($operation,$target,$exitCode=0,$busy=$false,$admin=$true,$installedAfter=$true){
 $script:Calls=New-Object Collections.Generic.List[object]
 $script:InventoryCall=0;$script:ExitCode=$exitCode;$script:Busy=$busy;$script:Admin=$admin;$script:InstalledAfter=$installedAfter
 $body=$text
 $replacements=@{
  'Inspect-Installer'='function Inspect-Installer([string]$Path){if($script:BadSignature){throw "Synthetic invalid signature"};[pscustomobject]@{Path=$Path;Hash=("A"*64);ProductCode="{12345678-1234-1234-1234-123456789ABC}";Name="Synthetic MSI";Publisher="Fixture";Version="1.0";SignaturePublisher="Synthetic certificate"}}'
  'Native'='function Native([string]$Name,[string[]]$Arguments){$script:Calls.Add([pscustomobject]@{Name=$Name;Arguments=$Arguments});[pscustomobject]@{ExitCode=$script:ExitCode;Output="SYNTHETIC native result";RebootRequired=($script:ExitCode -eq 3010)}}'
  'Inventory-Programs'='function Inventory-Programs {$script:InventoryCall++;if($script:InventoryCall -eq 1 -or $script:InstalledAfter){[pscustomobject]@{Name="Synthetic MSI";Publisher="Fixture";Version="1.0";Context="Machine64";ProductCode="{12345678-1234-1234-1234-123456789ABC}"}}}'
  'Assert-ServicingIdle'='function Assert-ServicingIdle {if($script:Busy){throw "Synthetic servicing busy"}}'
  'Test-RepairAdministrator'='function Test-RepairAdministrator {$script:Admin}'
 }
 $functions=$ast.FindAll({param($a)$a -is [Management.Automation.Language.FunctionDefinitionAst]},$true)
 foreach($f in $functions | Sort-Object {$_.Extent.StartOffset} -Descending){if($replacements.ContainsKey($f.Name)){$body=$body.Remove($f.Extent.StartOffset,$f.Extent.EndOffset-$f.Extent.StartOffset).Insert($f.Extent.StartOffset,$replacements[$f.Name])}}
 $Evidence=Join-Path $fixture ([guid]::NewGuid().ToString('N'));[void][IO.Directory]::CreateDirectory($Evidence)
 $Operation=$operation;$Target=$target;$ExpectedJSON=$script:ExpectedValue
 $output=& ([scriptblock]::Create($body))
 $line=@($output | Where-Object {$_ -is [string] -and $_.StartsWith('WSD_REPAIR_CENTER ')})[-1]
 if(!$line){throw 'No result'}
 $line.Substring(17) | ConvertFrom-Json
}
$r=Run-Fixture 'MsiRemove' $code 0 $false $true $false
Assert ($r.Status -eq 'REMOVAL_VERIFIED') 'remove independently verified'
Assert ($script:Calls.Count -eq 1) 'one native call'
Assert ($script:Calls[0].Name -eq 'msiexec.exe') 'system MSI executable'
Assert ($script:Calls[0].Arguments -contains '/x') 'MSI selected uninstall'
Assert ($script:Calls[0].Arguments -contains $code) 'exact product GUID'
Assert ($script:Calls[0].Arguments -contains '/norestart') 'no reboot'
$r=Run-Fixture 'MsiRepair' $code
Assert ($r.Status -eq 'COMPLETED_UNVERIFIED') 'repair not invented from registration'
Assert ($script:Calls[0].Arguments -contains '/fomus') 'repair arguments'
foreach($exitCode in @(1603,1618,3010)){$r=Run-Fixture 'MsiRepair' $code $exitCode;Assert ($r.Status -eq $(if($exitCode -eq 3010){'REBOOT_REQUIRED'}else{'FAILED'})) ('exit '+$exitCode)}
$r=Run-Fixture 'MsiRemove' $code 0 $true
Assert ($r.Status -eq 'FAILED' -and $script:Calls.Count -eq 0) 'servicing conflict before launch'
$r=Run-Fixture 'MsiRemove' $code 0 $false $false
Assert ($r.Status -eq 'FAILED' -and $script:Calls.Count -eq 0) 'admin refusal before launch'
$r=Run-Fixture 'MsiRemove' '{evil; command}'
Assert ($r.Status -eq 'FAILED' -and $script:Calls.Count -eq 0) 'injection rejected'
$r=Run-Fixture 'ComponentAnalysis' ''
Assert ($script:Calls[0].Arguments -contains '/AnalyzeComponentStore') 'WinSxS read-only'
$r=Run-Fixture 'ComponentCleanup' ''
Assert ($script:Calls[0].Arguments -contains '/StartComponentCleanup') 'servicing selected'
Assert (!($script:Calls[0].Arguments -contains '/ResetBase')) 'no ResetBase'
Assert (!$text.Contains('Win32_Product')) 'no MSI inventory repairs'

function Get-CimInstance { [pscustomobject]@{DeviceID='C:';DriveType=3;FileSystem='NTFS';VolumeSerialNumber='SYNTHETIC-VOLUME'} }
$r=Run-Fixture 'CheckVolume' 'C:'
Assert ($script:Calls[0].Arguments.Count -eq 1 -and $script:Calls[0].Arguments[0] -eq 'C:') 'read-only CHKDSK'
$r=Run-Fixture 'RepairVolume' 'C:'
Assert ($script:Calls.Count -eq 2) 'repair then verify'
Assert ($script:Calls[0].Arguments -contains '/spotfix') 'spotfix selected'
Assert (!($script:Calls[0].Arguments -contains '/x') -and !($script:Calls[0].Arguments -contains '/r')) 'no dismount or surface scan'
$r=Run-Fixture 'RepairVolume' 'C:' 3
Assert ($script:Calls.Count -eq 1) 'no blind continuation after repair error'
function Get-WinEvent { [pscustomobject]@{TimeCreated=[datetime]'2026-11-16';Id=20;Message='Synthetic update error'} }
function Get-Service {
 param([Parameter(Position=0,ValueFromRemainingArguments=$true)]$Name)
 foreach($nameItem in $Name){foreach($n in @($nameItem)){
  $obj=[pscustomobject]@{Name=$n;Status=$script:States[$n]}
  $obj | Add-Member -MemberType ScriptMethod -Name WaitForStatus -Value {param($state,$timeout)if($script:States[$this.Name] -ne $state){throw 'Synthetic service wait failed'}}
  $obj
 }}
}
function Stop-Service {param($Name)$script:States[$Name]='Stopped';$script:Stops++}
function Start-Service {param($Name)$script:States[$Name]='Running';$script:Starts++}
$savedWindir=$env:windir
try {
 $env:windir=Join-Path $fixture 'SyntheticWindows'
 $download=Join-Path $env:windir 'SoftwareDistribution/Download'
 [void][IO.Directory]::CreateDirectory($download)
 [IO.File]::WriteAllText((Join-Path $download 'original.bin'),'SYNTHETIC CACHE')
 $script:States=@{wuauserv='Running';bits='Stopped'};$script:Stops=0;$script:Starts=0
 $r=Run-Fixture 'UpdateCache' ''
 Assert ($r.Status -eq 'COMPLETED_UNVERIFIED') 'cache action not invented as repair'
 Assert ($script:States.wuauserv -eq 'Running' -and $script:States.bits -eq 'Stopped') 'original states restored'
 Assert ($script:Stops -eq 1 -and $script:Starts -eq 1) 'only previously running service changed'
 Assert ([IO.File]::ReadAllText((Join-Path $r.PreservedCache 'original.bin')) -eq 'SYNTHETIC CACHE') 'cache preserved, not deleted'
 # Missing source must restore the service even when rename cannot happen.
 $script:Stops=0;$script:Starts=0
 $r=Run-Fixture 'UpdateCache' ''
 Assert ($r.Status -eq 'FAILED') 'cache failure reported'
 Assert ($script:States.wuauserv -eq 'Running' -and $script:Starts -eq 1) 'service restored after failure'
} finally {$env:windir=$savedWindir}

$script:ExpectedValue='{"Name":"Synthetic MSI","Version":"2.0","Publisher":"Fixture","Context":"Machine64"}'
$r=Run-Fixture 'MsiRemove' $code
Assert ($r.Status -eq 'FAILED' -and $script:Calls.Count -eq 0) 'changed product blocked before execution'
$script:ExpectedValue='{"VolumeSerialNumber":"REPLACED"}'
$r=Run-Fixture 'RepairVolume' 'C:'
Assert ($r.Status -eq 'FAILED' -and $script:Calls.Count -eq 0) 'changed volume blocked before execution'
$script:ExpectedValue=$null

$package=Join-Path $fixture 'Тестовый пакет.msi';[IO.File]::WriteAllText($package,'SYNTHETIC: never execute this as MSI')
$r=Run-Fixture 'AnalyzeInstaller' $package
Assert ($r.Status -eq 'INSTALLER_ANALYZED' -and $script:Calls.Count -eq 0) 'MSI inspection never installs'
$script:ExpectedValue=@{Hash=('A'*64);ProductCode=$code;Name='Synthetic MSI';Publisher='Fixture';Version='1.0'}|ConvertTo-Json -Compress
$r=Run-Fixture 'MsiInstall' $package
Assert ($r.Status -eq 'COMPLETED_UNVERIFIED') 'installation not invented as app health'
Assert ($script:Calls[0].Arguments -contains '/i') 'install command'
Assert ($script:Calls[0].Arguments -contains ('"'+$package+'"')) 'Unicode installer path remains one quoted argument'
Assert ($script:Calls[0].Arguments -contains '/norestart') 'installation never reboots'
$script:BadSignature=$true
$r=Run-Fixture 'MsiInstall' $package
Assert ($r.Status -eq 'FAILED' -and $script:Calls.Count -eq 0) 'invalid signature never launches MSI'
$script:BadSignature=$false
$script:ExpectedValue=@{Hash=('B'*64);ProductCode=$code;Name='Synthetic MSI';Publisher='Fixture';Version='1.0'}|ConvertTo-Json -Compress
$r=Run-Fixture 'MsiInstall' $package
Assert ($r.Status -eq 'FAILED' -and $script:Calls.Count -eq 0) 'modified installer never launches MSI'
$script:ExpectedValue=$null
'PASS RepairCenter fixture assertions: '+$n+'; REAL WINDOWS REPAIR NOT RUN'

function Get-WinEvent {
 [pscustomobject]@{TimeCreated=[datetime]'2026-11-17';Id=11708;LevelDisplayName='Error';Message='Failure {12345678-1234-1234-1234-123456789ABC}';Properties=@()}
 [pscustomobject]@{TimeCreated=[datetime]'2026-11-17';Id=11708;LevelDisplayName='Error';Message='Other {87654321-4321-4321-4321-CBA987654321}';Properties=@()}
}
$r=Run-Fixture 'AnalyzeProduct' $code
Assert ($r.Status -eq 'PRODUCT_ANALYZED' -and @($r.Events).Count -eq 1) 'exact product event isolation'
Assert ($script:Calls.Count -eq 0) 'product analysis never executes native repair'
$r=Run-Fixture 'AnalyzeProduct' 'invalid'
Assert ($r.Status -eq 'FAILED') 'invalid ProductCode rejected'
function Get-WinEvent {throw 'Synthetic event access denied'}
$r=Run-Fixture 'AnalyzeProduct' $code
Assert ($r.Status -eq 'PARTIAL' -and $r.EventReadError.Contains('access denied')) 'event failure is partial rather than healthy'
'PASS RepairCenter including selected product events: '+$n
