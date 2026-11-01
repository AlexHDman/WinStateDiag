$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$t=$null;$e=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'embedded\EXPC-Diagnostic\EXPC-Diagnostic.ps1'),[ref]$t,[ref]$e)
if($e.Count){throw ($e|Out-String)}
foreach($name in @('Set-CheckStatus','Write-DiagResult','Invoke-Step','Test-CheckExecutionError','Get-ExecutionStatus','ConvertFrom-VssWriters','Test-ApplicationContextOnly')){
 $f=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true)
 . ([scriptblock]::Create($f.Extent.Text))
}
$n=0
function Eq($actual,$expected,$label){if($actual -ne $expected){throw "$label : $actual != $expected"};$script:n++;Write-Output "PASS $label"}
function Write-Log {param($Text)}
function Write-Section {param($Text)}
function Short-Message {param($Text,$Max) $Text}
function Add-Attention {param($Text)}
function Get-StepDecision {param($Title,[switch]$Long,$DeepKey) 'Run'}
$script:Checks=[ordered]@{};$script:StepRuns=New-Object Collections.ArrayList
$null=Invoke-Step -Number 7 -Title 'Historical actual contract' -Action {Set-CheckStatus -Key 'Stability / BSOD' -Status HISTORICAL -Detail 'Kernel-Power 41 and 6008, 25 days ago'}
Eq $script:Checks['Stability / BSOD'].Status 'HISTORICAL' 'real ValidateSet admits historical'
Eq $script:StepRuns[0].execution_status 'COMPLETED' 'historical stage completed'
Eq (Get-ExecutionStatus @($script:StepRuns) @($script:Checks.Values)) 'COMPLETED' 'historical is context'
$null=Invoke-Step -Number 8 -Title 'Injected failure' -Action {throw 'injected stage failure'}
Eq $script:Checks['Step 08'].Status 'ERROR' 'stage exception recorded in checks'
Eq $script:StepRuns[1].execution_status 'ERROR' 'stage exception recorded in runs'
Eq (Get-ExecutionStatus @($script:StepRuns) @($script:Checks.Values)) 'COMPLETED_WITH_ERRORS' 'completed other steps cannot hide failure'
Eq (Get-ExecutionStatus @([pscustomobject]@{execution_status='ERROR'}) @()) 'ERROR' 'total failure'
Eq (Get-ExecutionStatus @([pscustomobject]@{execution_status='CANCELLED'}) @()) 'CANCELLED' 'cancelled contract'
Eq (Get-ExecutionStatus @([pscustomobject]@{execution_status='COMPLETED'}) @([pscustomobject]@{Status='ATTENTION'})) 'COMPLETED' 'findings do not change execution'
Eq (ConvertFrom-VssWriters "Writer name: Test`nWriter Id: {11111111-1111-1111-1111-111111111111}`nWriter Instance Id: {22222222-2222-2222-2222-222222222222}`nState: [1] Stable`nLast error: No error" 0).Status 'OK' 'writers EN stable'
Eq (ConvertFrom-VssWriters "Имя модуля записи: Тест`nWriter Id: {11111111-1111-1111-1111-111111111111}`nWriter Instance Id: {22222222-2222-2222-2222-222222222222}`nСостояние: [1] Стабильно`nПоследняя ошибка: Ошибок нет" 0).Status 'OK' 'writers RU stable'
Eq (ConvertFrom-VssWriters "Writer name: Failed`nWriter Id: {11111111-1111-1111-1111-111111111111}`nWriter Instance Id: {22222222-2222-2222-2222-222222222222}`nState: [9] Failed`nLast error: Failed" 0).Status 'ATTENTION' 'writers real failure'
Eq (ConvertFrom-VssWriters 'Access denied' 5).Status 'UNKNOWN' 'writers access denied not OK'
Eq (Test-ApplicationContextOnly 'C:\MSI\LEDKeeper2.exe') $true 'LEDKeeper exact noise'
Eq (Test-ApplicationContextOnly 'gui_audit.exe') $true 'GUI test-tool context'
Eq (Test-ApplicationContextOnly 'powershell.exe') $false 'PowerShell crashes retained'
Eq (Test-ApplicationContextOnly 'adb.exe') $false 'ADB crashes retained'
# Execute the real final Applications decision: known noise cannot mask a separate component failure.
$decision=$ast.Find({param($node) $node -is [Management.Automation.Language.IfStatementAst] -and $node.Clauses[0].Item1.Extent.Text -eq '$activeCrashGroups.Count -gt 0'},$true)
if(!$decision){throw 'Applications decision not found'}
$activeCrashGroups=@();$crashEvents=@([pscustomobject]@{Application='LEDKeeper2.exe'});$componentEvents=@([pscustomobject]@{Id=33});$componentGroups=@('SideBySide')
. ([scriptblock]::Create($decision.Extent.Text))
Eq $script:Checks['Applications'].Status 'ATTENTION' 'known noise does not hide component failure'
$componentEvents=@()
. ([scriptblock]::Create($decision.Extent.Text))
Eq $script:Checks['Applications'].Status 'INFO' 'known noise alone is context'
Write-Output "RC10_ASSERTIONS_PASS=$n"
