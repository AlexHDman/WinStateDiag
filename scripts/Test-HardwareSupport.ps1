[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$Evidence)
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
. (Join-Path $root 'embedded\HardwareSupport\Detection.ps1')
. (Join-Path $root 'embedded\HardwareSupport\Install.ps1')
$m=Get-Content -LiteralPath (Join-Path $root 'embedded\HardwareSupport\manifest.json') -Raw | ConvertFrom-Json
[IO.Directory]::CreateDirectory($Evidence)|Out-Null
$script:passed=0
function Check($Value,[string]$Name){if(-not $Value){throw "FAIL: $Name"};$script:passed++;"PASS $Name"}
$cases=@(
 @($false,$true,2,0,'','ABSENT'),
 @($false,$false,2,0,'','INITIALIZATION_ERROR'),
 @($true,$true,2,0,'2.2.0','INITIALIZATION_ERROR'),
 @($true,$true,5,0,'2.2.0','ACCESS_DENIED'),
 @($false,$false,5,0,'','ACCESS_DENIED'),
 @($true,$true,577,0,'2.2.0','BLOCKED_BY_WINDOWS'),
 @($true,$true,2,1275,'2.2.0','BLOCKED_BY_WINDOWS'),
 @($true,$true,0,0,'2.2.0.0','ACCESSIBLE'),
 @($true,$true,0,0,'2.1.0','INCOMPATIBLE'),
 @($true,$true,0,0,'unknown','INITIALIZATION_ERROR'),
 @($false,$true,-1,0,'','INITIALIZATION_ERROR')
)
foreach($c in $cases){Check ((Resolve-WsdPawnState $c[0] $c[1] $c[2] $c[3] $c[4]) -eq $c[5]) ('classification '+$c[5]+' / '+$c[2])}
Check ((Resolve-WsdInstallExit 0)-eq 'INSTALLED') 'installer exit zero'
Check ((Resolve-WsdInstallExit 3010)-eq 'REBOOT_REQUIRED') 'reboot required, never auto reboot'
Check ((Resolve-WsdInstallExit 1223)-eq 'CANCELLED') 'UAC cancellation'
Check ((Resolve-WsdInstallExit 5)-eq 'INSTALLER_ERROR') 'installer denied'
$installer=Join-Path $root 'third_party\PawnIO-2.2.0\PawnIO_setup.exe'
$verified=Test-WsdInstaller $installer $m.installer
Check ($verified.signature -eq 'Valid') 'real offline installer SHA256 / Authenticode / publisher'
$bad=Join-Path $Evidence ('tampered-'+[guid]::NewGuid().ToString('N')+'.exe')
[IO.File]::WriteAllBytes($bad,[byte[]](0,1,2,3))
$rejected=$false
try{Test-WsdInstaller $bad $m.installer|Out-Null}catch{$rejected=$true}
Check $rejected 'tampered installer refused'
$wrong=$m.installer|ConvertTo-Json|ConvertFrom-Json;$wrong.thumbprint='0000000000000000000000000000000000000000'
$rejected=$false
try{Test-WsdInstaller $installer $wrong|Out-Null}catch{$rejected=$true}
Check $rejected 'wrong publisher certificate refused'
$dll=Join-Path $root 'third_party\LibreHardwareMonitorLib-0.9.6\lib\LibreHardwareMonitorLib.dll'
Check ((Get-FileHash -LiteralPath $dll -Algorithm SHA256).Hash -eq $m.lhm_sha256) 'actual consumer DLL pinned'
$asm=[Reflection.Assembly]::LoadFrom($dll)
$modules=Test-WsdLhmModules $asm $m
Check ($modules.Count -eq 12) '12 exact official module matches'
$modules|ConvertTo-Json -Depth 6|Set-Content -LiteralPath (Join-Path $Evidence 'module-verification.json') -Encoding UTF8
$actual=Get-WsdPawnIo
$actual|ConvertTo-Json -Depth 10|Set-Content -LiteralPath (Join-Path $Evidence 'actual-pawnio.json') -Encoding UTF8
Check ($actual.state -in @('ACCESSIBLE','ACCESS_DENIED','ABSENT','INCOMPATIBLE','BLOCKED_BY_WINDOWS','INITIALIZATION_ERROR')) 'actual detector has explicit state'
Get-WsdHardwareIdentity | ConvertTo-Json -Depth 10|Set-Content -LiteralPath (Join-Path $Evidence 'identity.json') -Encoding UTF8
# Negative entry-point tests: no test below can start an installer.
function Get-WsdPawnIo { [ordered]@{state=$script:fixtureState;open_message='fixture';boot_id='fixture';reader_gate='READY'} }
$script:fixtureState='ACCESSIBLE'
$out=Invoke-WsdPawnInstall 'must-not-exist.exe' (Join-Path $Evidence 'already-present') $m
$result=($out|Where-Object {$_ -like 'WSD_HW_RESULT *'}|Select-Object -Last 1).Substring(14)|ConvertFrom-Json
Check ($result.state -eq 'ALREADY_INSTALLED') 'entry point skips installed driver even with absent setup'
$script:fixtureState='ACCESS_DENIED'
$out=Invoke-WsdPawnInstall 'must-not-exist.exe' (Join-Path $Evidence 'denied') $m
$result=($out|Where-Object {$_ -like 'WSD_HW_RESULT *'}|Select-Object -Last 1).Substring(14)|ConvertFrom-Json
Check ($result.state -eq 'ERROR' -and $null -eq $result.exit_code) 'entry point never reinstalls on access denied'
$script:fixtureState='ABSENT'
$out=Invoke-WsdPawnInstall $bad (Join-Path $Evidence 'tampered-entry') $m
$result=($out|Where-Object {$_ -like 'WSD_HW_RESULT *'}|Select-Object -Last 1).Substring(14)|ConvertFrom-Json
Check ($result.state -eq 'ERROR' -and $null -eq $result.exit_code) 'entry point refuses corrupted setup before execution'
$fixture=[pscustomobject]@{reader_gate='READY';boot_id='fixture';lease_path=(Join-Path $Evidence ('lease-'+[guid]::NewGuid().ToString('N')+'.json'))}
$lease=Open-WsdHardwareLease $fixture
$rejected=$false;try{Open-WsdHardwareLease $fixture|Out-Null}catch{$rejected=$true}
Check $rejected 'exclusive protected lease prevents replacement'
Close-WsdHardwareLease $lease $true
Check (-not(Test-Path -LiteralPath $fixture.lease_path)) 'successful cleanup removes only own lease'
$lease=Open-WsdHardwareLease $fixture
Close-WsdHardwareLease $lease $false
Check (Test-Path -LiteralPath $fixture.lease_path) 'uncertain cleanup preserves blocking evidence'
$summary=[ordered]@{status='PASS';tests=$script:passed;windows_powershell=$PSVersionTable.PSVersion.ToString();actual_state=$actual.state;installer_execution='NOT RUN';uac='NOT RUN';protected_sensor_live='NOT RUN'}
$summary|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $Evidence 'summary.json') -Encoding UTF8
$summary|ConvertTo-Json
