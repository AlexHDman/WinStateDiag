param([switch]$NativeProbe)
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
function Load-Functions($Path,$Names){
 $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($Path,[ref]$tokens,[ref]$errors)
 if($errors.Count){throw ($errors|Out-String)}
 foreach($name in $Names){$f=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true); if(!$f){throw "Missing $name"};. ([scriptblock]::Create($f.Extent.Text.Replace("function $name", "function global:$name")))}
}
Load-Functions (Join-Path $root 'embedded\EXPC-Diagnostic\EXPC-Diagnostic.ps1') @('ConvertFrom-VssWriterBytes','ConvertFrom-VssWriters','Get-VssWriters','Test-CheckExecutionError','Get-ExecutionStatus','Get-CoverageStatus','Get-FindingsStatus')
Load-Functions (Join-Path $root 'embedded\WinStateDiag\DriverAudit.ps1') @('Get-DriverPackageFailure')
$n=0
function Eq($Actual,$Expected,$Name){if($Actual -ne $Expected){throw "$Name : $Actual != $Expected"};$script:n++;Write-Output "PASS $Name"}
$ru="Имя модуля записи: 'Writer один'`r`nWriter Id: {11111111-1111-1111-1111-111111111111}`nWriter Instance Id: {22222222-2222-2222-2222-222222222222}`nСостояние: [1] Стабильное`r`nПоследняя ошибка: Без ошибок`r`n"
$en="Writer name: 'Writer two'`nWriter Id: {11111111-1111-1111-1111-111111111111}`nWriter Instance Id: {22222222-2222-2222-2222-222222222222}`nState: [1] Stable`nLast error: No error`n"
foreach($cp in @(65001,1200,1201,866,1251)){
 $bytes=[Text.Encoding]::GetEncoding($cp).GetBytes($ru)
 $decoded=ConvertFrom-VssWriterBytes $bytes
 Eq $decoded.Text $ru "RU exact decode $cp"
 $r=ConvertFrom-VssWriters $decoded.Text 0
 Eq $r.Status 'OK' "RU stable $cp"
 Eq $r.Count 1 "RU count $cp"
}
$errorRu="Ошибка: У вас отсутствует разрешение на запуск этой команды. Запустите эту команду с правами администратора."
foreach($cp in @(65001,1200,1201,866,1251)){
 Eq (ConvertFrom-VssWriterBytes ([Text.Encoding]::GetEncoding($cp).GetBytes($errorRu))).Text $errorRu "RU native error decode $cp"
}
$r=ConvertFrom-VssWriters ($ru+$en) 0
Eq $r.Count 2 'writers count by headers';Eq $r.Stable 2 'two stable writers';Eq $r.Coverage COMPLETE 'full records'
$r=ConvertFrom-VssWriters ($ru+"Writer name: 'missing state'`n") 0
Eq $r.Count 2 'missing state still counted';Eq $r.Unknown 1 'missing state unknown';Eq $r.Status UNKNOWN 'partial cannot be OK'
$r=ConvertFrom-VssWriters ($ru+$en.Replace('[1] Stable','[9] Failed').Replace('No error','Timed out')) 0
Eq $r.Failed 1 'failed writer';Eq $r.Status ATTENTION 'failure not hidden'
Eq (ConvertFrom-VssWriters $ru 5).Status UNKNOWN 'exit failure with partial output'
Eq (ConvertFrom-VssWriters $en.Replace('[1]','[99]') 0).Status UNKNOWN 'future state not failed'
Eq (ConvertFrom-VssWriters '' 0).Count $null 'empty not zero writers'
Eq (ConvertFrom-VssWriters 'State: [1] Stable' 0).Status UNKNOWN 'headerless incomplete'
$err=[Management.Automation.ErrorRecord]::new([Runtime.InteropServices.COMException]::new('Failure 0xc0040009',-1073479671),'DismError',[Management.Automation.ErrorCategory]::NotSpecified,$null)
$detail=Get-DriverPackageFailure $err 'C:\user\run\dism.log'
Eq ($detail -match 'category=DISMAPI_E_LOGGING_DISABLED') $true 'CASE-F known HRESULT'
Eq ($detail -match 'scope=DRIVER_PACKAGE_COLLECTION') $true 'package scope separate'
Eq ($detail -match 'original=Failure 0xc0040009') $true 'original retained'
$steps=@([pscustomobject]@{execution_status='COMPLETED'})
$checks=@([pscustomobject]@{Check='SFC';Status='UNKNOWN';Detail='не распознано'})
Eq (Get-ExecutionStatus $steps $checks) COMPLETED 'unknown is coverage, not execution failure'
Eq (Get-CoverageStatus $steps $checks) LIMITED 'unknown coverage explicit'
$checks=@([pscustomobject]@{Check='DISM';Status='ERROR';Detail='NOT_REPAIRABLE'})
Eq (Get-ExecutionStatus $steps $checks) COMPLETED 'corruption is finding, not execution error'
Eq (Get-FindingsStatus $checks) ATTENTION 'corruption retained'
$checks=@([pscustomobject]@{Check='Step 07';Status='ERROR';Detail='exception'})
Eq (Get-ExecutionStatus $steps $checks) COMPLETED_WITH_ERRORS 'real execution failure visible'
Eq (Get-CoverageStatus $steps $checks) LIMITED 'failed coverage limited'
$checks=@([pscustomobject]@{Check='VSS collection';Status='ERROR';Detail='access denied'})
Eq (Get-ExecutionStatus $steps $checks) COMPLETED_WITH_ERRORS 'VSS collection failure separate from writer health'
Eq (Get-ExecutionStatus @([pscustomobject]@{execution_status='CANCELLED'}) $checks) CANCELLED 'cancel priority'
$tokens=$null;$errors=$null;$driverAst=[Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'embedded\WinStateDiag\DriverAudit.ps1'),[ref]$tokens,[ref]$errors)
$commands=@($driverAst.FindAll({param($a)$a -is [Management.Automation.Language.CommandAst]},$true)|ForEach-Object {$_.GetCommandName()})
Eq @($commands|Where-Object {$_ -match '^(dism(\.exe)?|pnputil(\.exe)?|Set-|Remove-|Enable-|Disable-|Start-Process|Invoke-Expression)'}).Count 0 'read-only command AST'
$pkg=$driverAst.Find({param($a)$a -is [Management.Automation.Language.TryStatementAst] -and $a.Body.Extent.Text -match 'Get-WindowsDriver -Online'},$true)
$script:Rows=New-Object Collections.ArrayList
function Emit($row){[void]$script:Rows.Add(($row -join "`t"))}
function Get-WindowsDriver {param([switch]$Online,$LogPath,$ErrorAction)
 $script:ObservedLog=$LogPath
 if($script:FailPackage){throw [Runtime.InteropServices.COMException]::new('Failure 0xc0040009',-1073479671)}
 [pscustomobject]@{Driver='oem1.inf';OriginalFileName='C:\Windows\INF\vendor.inf';ProviderName='Vendor';ClassName='Net';Version='1.0';Date=[datetime]'2026-01-01'}
}
$script:FixtureRoot=$root
$script:FailPackage=$false;. ([scriptblock]::Create($pkg.Extent.Text.Replace('$PSScriptRoot','$script:FixtureRoot')))
Eq ($script:ObservedLog -like '*Dism-DriverPackages-*.log') $true 'private log passed to actual package block'
Eq @($script:Rows|Where-Object {$_ -like 'PKG*'}).Count 1 'package successful path retained'
$script:FailPackage=$true;. ([scriptblock]::Create($pkg.Extent.Text.Replace('$PSScriptRoot','$script:FixtureRoot')))
Eq @($script:Rows|Where-Object {$_ -like 'ERR*Get-WindowsDriver*0xC0040009*'}).Count 1 'package failure evidence retained'
if($NativeProbe){
 $result=@(Get-VssWriters)
 Eq $result.Count 1 'native reader returns exactly one object'
 Eq ($result[0].Status -in @('OK','ATTENTION','UNKNOWN')) $true 'native state contract'
 if($result[0].ExitCode -ne 0){Eq $result[0].Coverage LIMITED 'native nonzero exit limits coverage'}
}
Write-Output "V1210_ASSERTIONS_PASS=$n"
