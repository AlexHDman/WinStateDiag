# Real process plumbing test; executable is a self-created, harmless fixture.
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$Evidence=Join-Path $root ('target/repair-native-mock/'+[guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($Evidence)
$exe=Join-Path $Evidence 'native-fixture.exe'
$code='using System; using System.Text; class Fixture {static int Main(){Console.OutputEncoding=new UTF8Encoding(false);Console.WriteLine("stdout доказательство");Console.Error.WriteLine("stderr fixture");return 7;}}'
Add-Type -TypeDefinition $code -OutputAssembly $exe -OutputType ConsoleApplication
$t=$null;$e=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'embedded/WinStateDiag/RepairCenter.ps1'),[ref]$t,[ref]$e)
foreach($name in @('Decode-NativeBytes','Native')){
 $f=$ast.Find({param($a)$a -is [Management.Automation.Language.FunctionDefinitionAst] -and $a.Name -eq $name},$true)
 $source=$f.Extent.Text.Replace("Join-Path ([Environment]::GetFolderPath('System')) `$Name",'$Name')
 . ([scriptblock]::Create($source))
}
$r=Native $exe @()
if($r.ExitCode -ne 7 -or !$r.Output.Contains('stdout доказательство') -or !$r.Output.Contains('stderr fixture')){throw 'Native mock result mismatch'}
$logs=@(Get-ChildItem -LiteralPath $Evidence -Filter '*.log' -File)
if($logs.Count -ne 2){throw 'Raw stdout/stderr not retained'}
if((Decode-NativeBytes ([Text.Encoding]::Unicode.GetBytes('Стабильный результат'))) -ne 'Стабильный результат'){throw 'UTF16 decode'}
$ru='Защита ресурсов Windows';if((Decode-NativeBytes ([Text.Encoding]::GetEncoding(866).GetBytes($ru))) -ne $ru){throw 'OEM decode'}
'PASS native process fixture: launch, exit7, UTF8/UTF16/OEM, stdout+stderr durable logs; real repair NOT RUN'
