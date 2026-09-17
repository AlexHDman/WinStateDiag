<#
.SYNOPSIS
    Re-applies the WinStateDiag project folder icon (desktop.ini + Windows attributes).

.DESCRIPTION
    Git does not preserve Windows file/folder attributes (Hidden/System/Read-only).
    After a fresh clone or checkout, Explorer will not show the custom folder icon
    until this script is run once.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\Set-FolderIcon.ps1
#>

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$ini  = Join-Path $root 'desktop.ini'

if (-not (Test-Path $ini)) {
    throw "desktop.ini not found at $ini"
}

attrib +s +h $ini
attrib +r $root

Write-Host "Folder icon attributes applied to $root" -ForegroundColor Green
Write-Host "If Explorer does not refresh immediately, restart explorer.exe or reopen the folder." -ForegroundColor DarkGray
