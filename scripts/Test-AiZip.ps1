param([string]$EvidenceRoot = (Join-Path $PSScriptRoot '..\release-evidence\v1.4\ai-zip-20261116'))
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath($EvidenceRoot)
$rows = @()
foreach ($case in 'small','large') {
    $dir = Join-Path (Join-Path $root 'Сравнение AI с пробелами') $case
    $oracle = Join-Path $dir 'Клиент-ПК-16.11.26-20.00.AI.txt'
    $source = Join-Path $dir 'Клиент-ПК-16.11.26-20.00.zip'
    $before = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
    $archives = @(Get-ChildItem -LiteralPath $dir -Filter '*.AI.zip' -File)
    if (-not $archives.Count) { throw "NOT RUN: missing generated fixture in $dir" }
    foreach ($archive in $archives) {
    $zip = $archive.FullName
    $expectedName = [IO.Path]::GetFileNameWithoutExtension($zip) + '.txt'
    $unpack = Join-Path $dir ('windows-expand-' + [Guid]::NewGuid().ToString('N'))
    # Standard Windows PowerShell 5.1 ZIP support; no third-party extractor.
    Expand-Archive -LiteralPath $zip -DestinationPath $unpack
    $files = @(Get-ChildItem -LiteralPath $unpack -File)
    if ($files.Count -ne 1 -or $files[0].Name -ne $expectedName) { throw 'Wrong archive inventory' }
    $actual = (Get-FileHash -LiteralPath $files[0].FullName -Algorithm SHA256).Hash
    $expected = (Get-FileHash -LiteralPath $oracle -Algorithm SHA256).Hash
    if ($actual -ne $expected) { throw "TXT content changed: $case" }
    $stream = [IO.File]::OpenRead($files[0].FullName)
    try { $bom = @($stream.ReadByte(), $stream.ReadByte(), $stream.ReadByte()) } finally { $stream.Dispose() }
    if (($bom -join ',') -ne '239,187,191') { throw 'UTF-8 BOM missing' }
    if ((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash -ne $before) { throw 'Source was changed' }
    if (@(Get-ChildItem -LiteralPath $dir -Force -File | Where-Object Name -like '.wsd-ai-*').Count) { throw 'Owned temporary file left behind' }
    $rows += [ordered]@{ case=$case; archive=$archive.Name; result='PASS'; powershell=$PSVersionTable.PSVersion.ToString(); txt_bytes=$files[0].Length; zip_bytes=(Get-Item -LiteralPath $zip).Length; txt_sha256=$actual; zip_sha256=(Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash; source_unchanged=$true; expanded=$files[0].FullName }
    Write-Host "PASS: Windows Expand-Archive / $case / $($archive.Name) / exact SHA256" -ForegroundColor Green
    }
}
$rows | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $root 'windows-zip-results.json') -Encoding UTF8
