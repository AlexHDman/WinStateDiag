$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$t=$null;$e=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'embedded\EXPC-Diagnostic\EXPC-Diagnostic.ps1'),[ref]$t,[ref]$e)
if($e.Count){throw ($e|Out-String)}
$f=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Export-ServicingEvidence'},$true)
. ([scriptblock]::Create($f.Extent.Text))
function Write-Log {param($m)}
function Assert($yes,$label){if(!$yes){throw "FAIL: $label"};Write-Output "PASS: $label"}
$base=Join-Path $root ('target\rc9-temp\servicing-fixture-'+[guid]::NewGuid().ToString('N'))
$windows=Join-Path $base 'Windows'
foreach($area in @('CBS','DISM')){[void][IO.Directory]::CreateDirectory((Join-Path $windows ('Logs\'+$area)))}
$utf=New-Object Text.UTF8Encoding($false)
$cbs=Join-Path $windows 'Logs\CBS\CBS.log'
[IO.File]::WriteAllText($cbs,"2026-10-20 10:00:00, ordinary context`n2026-10-20 10:00:01, CSI Payload Corrupt fixture`n continuation-one`n continuation-two`n2026-10-27 12:00:00, CURRENT SESSION SENTINEL`n continuation-current`n",$utf)
[IO.File]::WriteAllText((Join-Path $windows 'Logs\DISM\dism.log'),"2026-10-20 10:00:00, normal`n",$utf)
[IO.File]::WriteAllText((Join-Path $windows 'Logs\CBS\CbsPersist_fixture.log'),"2026-10-27 12:00:01, ROTATED SESSION SENTINEL`n rotated-continuation`n",$utf)
$check=[pscustomobject]@{check='SFC';result='INTEGRITY_VIOLATIONS';exit_code_known=$true;exit_code=0;started_at='2026-10-27T12:00:00';ended_at='2026-10-27T12:00:02'}
function OutDir($name){$d=Join-Path $base $name;[void][IO.Directory]::CreateDirectory($d);return $d}
$out=OutDir 'compact'
Export-ServicingEvidence -Checks @($check) -Directory $out -WindowsRoot $windows -CollectedAt ([datetime]'2026-10-27T12:00:02') -BudgetBytes 1
$m=Get-Content (Get-ChildItem $out -Filter '*Result.json').FullName -Raw|ConvertFrom-Json
$text=(Get-ChildItem $out -Filter '*.log'|ForEach-Object{[IO.File]::ReadAllText($_.FullName)}) -join "`n"
Assert ($m.budget_exceeded -and $m.status -eq 'COMPLETE') 'soft budget may exceed without losing evidence'
Assert ($text.Contains("CSI Payload Corrupt fixture`n continuation-one`n continuation-two`n")) 'multiline key record survives tiny budget'
Assert ($text.Contains('CURRENT SESSION SENTINEL') -and $text.Contains('continuation-current')) 'non-key current session survives budget'
Assert ($text.Contains('ROTATED SESSION SENTINEL') -and $text.Contains('rotated-continuation')) 'current session found in rotated CbsPersist'
$clean=OutDir 'clean';$check.result='CLEAN'
Export-ServicingEvidence -Checks @($check) -Directory $clean -WindowsRoot $windows
Assert (@(Get-ChildItem $clean).Count -eq 0) 'clean check creates no servicing evidence'
$check.result='UNKNOWN'
$missing=OutDir 'missing'
Export-ServicingEvidence -Checks @($check) -Directory $missing -WindowsRoot (Join-Path $base 'unavailable')
$m=Get-Content (Get-ChildItem $missing -Filter '*Result.json').FullName -Raw|ConvertFrom-Json
Assert ($m.status -eq 'PARTIAL' -and $m.errors.Count -ge 2) 'missing or rotated active logs report incomplete coverage'
$full=OutDir 'full'
Export-ServicingEvidence -Checks @($check) -Directory $full -WindowsRoot $windows -FullLogs
$m=Get-Content (Get-ChildItem $full -Filter '*Result.json').FullName -Raw|ConvertFrom-Json
Assert ($m.mode -eq 'FULL_EXPLICIT' -and @($m.files|Where-Object {$_.source_sha256 -ne $_.sha256}).Count -eq 0) 'explicit full mode byte exact'
Write-Output 'RC9_SERVICING_ASSERTIONS_PASS=7'
