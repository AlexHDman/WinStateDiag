# Deterministic host-only tests. Never starts a guest or application.
$ErrorActionPreference = 'Stop'
$count = 0
function Assert($value, $message) { if (-not $value) { throw $message }; $script:count++ }
$asts = @{}
foreach ($name in @('Invoke-WsdSandboxTests.ps1','Invoke-WsdSandboxSmoke.ps1','sandbox_smoke.ps1')) {
    $tokens = $null; $errors = $null
    $asts[$name] = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot $name), [ref]$tokens, [ref]$errors)
    Assert ($errors.Count -eq 0) "parse: $name"
}
$hostText = $asts['Invoke-WsdSandboxSmoke.ps1'].Extent.Text
$guestText = $asts['sandbox_smoke.ps1'].Extent.Text
Assert ($hostText -notmatch 'wsb stop') 'No unproven Sandbox shutdown'
Assert ($hostText -notmatch '/IM\s') 'No process-name kill'
Assert ($guestText -notmatch '/IM\s|New-ItemProperty|Set-ItemProperty|RunAsInvoker') 'No broad kill, registry mutation, or fake non-admin test'
Assert ($hostText -match 'WindowsSandboxEnvironments.*Count -ne 0') 'Existing Sandbox fails closed'
Assert ($hostText -match 'exit 3' -and $hostText -match "result -eq 'PASS'.*exit 0") 'Nonzero on failure'
foreach ($line in ($hostText -split "`n" | Where-Object { $_ -match 'winapp ui ' })) {
    Assert ($line -match '--on sandbox') 'Explicit guest UI target'
}
$fn = $asts['Invoke-WsdSandboxSmoke.ps1'].Find({ param($a) $a -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $a.Name -eq 'Find-WorkRoot' }, $true)
. ([scriptblock]::Create($fn.Extent.Text))
Assert (@(Find-WorkRoot ([pscustomobject]@{ workRoot = 'C:\WinApp\work' })).Count -eq 1) 'Direct workRoot'
Assert (@(Find-WorkRoot ([pscustomobject]@{ nested = [pscustomobject]@{ workRoot = 'C:\test' } })).Count -eq 1) 'Nested workRoot'
Assert (@(Find-WorkRoot ([pscustomobject]@{ running = $false })).Count -eq 0) 'Missing workRoot'
Assert (@(Find-WorkRoot ([pscustomobject]@{ a=[pscustomobject]@{workRoot='C:\a'}; b=[pscustomobject]@{workRoot='C:\b'} })).Count -eq 2) 'Ambiguous roots preserved for rejection'
$owner = [pscustomobject]@{ pid=7; start='2026-10-19T00:00:00.0000000Z'; exe='C:\test.exe' }
$fn = $asts['sandbox_smoke.ps1'].Find({ param($a) $a -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $a.Name -eq 'Owned-Process' }, $true)
. ([scriptblock]::Create($fn.Extent.Text))
function Get-Process { param($Id, $ErrorAction) return $script:fakeProcess }
$script:fakeProcess = $null
Assert ($null -eq (Owned-Process)) 'Missing PID safe'
$script:fakeProcess = [pscustomobject]@{ StartTime=[datetime]::Parse($owner.start).ToUniversalTime(); Path=$owner.exe }
Assert ($null -ne (Owned-Process)) 'Matching PID identity'
$script:fakeProcess.Path='C:\foreign.exe'
$rejected=$false; try { Owned-Process | Out-Null } catch { $rejected=$true }
Assert $rejected 'Foreign path rejected'
$script:fakeProcess.Path=$owner.exe; $script:fakeProcess.StartTime=$script:fakeProcess.StartTime.AddSeconds(1)
$rejected=$false; try { Owned-Process | Out-Null } catch { $rejected=$true }
Assert $rejected 'Reused PID rejected'
foreach ($name in @('Assert-SandboxBinding','Assert-NoConcurrentTargetCommand')) {
    $fn = $asts['Invoke-WsdSandboxSmoke.ps1'].Find({ param($a) $a -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $a.Name -eq $name }, $true)
    . ([scriptblock]::Create($fn.Extent.Text))
}
$bound = [pscustomobject]@{running=$true;attached=$true;executionTarget=[pscustomobject]@{epoch='original:boot'};desktop=[pscustomobject]@{processId=123};workRoot='C:\WinApp\work'}
Assert-SandboxBinding $bound $bound
Assert $true 'Same epoch/client/root accepted'
foreach ($mutation in @('epoch','pid','root','running','attached')) {
    $changed = $bound | ConvertTo-Json -Depth 4 | ConvertFrom-Json
    switch ($mutation) {
        'epoch' { $changed.executionTarget.epoch='replacement:boot' }
        'pid' { $changed.desktop.processId=456 }
        'root' { $changed.workRoot='C:\other' }
        'running' { $changed.running=$false }
        'attached' { $changed.attached=$false }
    }
    $rejected=$false; try { Assert-SandboxBinding $bound $changed } catch { $rejected=$true }
    Assert $rejected "Changed $mutation rejected"
}
Assert-NoConcurrentTargetCommand $null
Assert $true 'Serial command permitted'
$script:callbackRan=$false
$rejected=$false; try { Assert-NoConcurrentTargetCommand { $script:callbackRan=$true } } catch { $rejected=$true }
Assert ($rejected -and -not $script:callbackRan) 'Concurrent callback rejected before execution'
Assert ($hostText -match 'if \(\$guest -and \$script:observationStarted\)') 'No guest cleanup for a blocked launch'
Write-Output "SANDBOX_SAFETY_TESTS=$count PASS"
