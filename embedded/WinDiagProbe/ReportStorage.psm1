Set-StrictMode -Version 2.0

function Get-WinDiagReportDirectory {
    [CmdletBinding()]
    param([switch]$Ensure)
    $reportsRoot = Join-Path $PSScriptRoot 'Reports'
    $dayName = (Get-Date).ToString('dd-MM-yy',[Globalization.CultureInfo]::InvariantCulture)
    $directory = Join-Path $reportsRoot $dayName
    if ($Ensure -and -not (Test-Path -LiteralPath $directory)) {
        [void](New-Item -ItemType Directory -Path $directory -Force -ErrorAction Stop)
    }
    return $directory
}

function New-WinDiagReportBaseName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][ValidateSet('EXPC','Hardware','WinDiagProbe')][string]$Prefix,
        [Parameter(Mandatory=$true)][datetime]$RunStartedAt
    )
    return '{0}_{1}' -f $Prefix,$RunStartedAt.ToLocalTime().ToString('dd.MM.yy_HH-mm',[Globalization.CultureInfo]::InvariantCulture)
}

function Get-UniqueWinDiagReportBaseName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][ValidateSet('EXPC','Hardware','WinDiagProbe')][string]$Prefix,
        [Parameter(Mandatory=$true)][datetime]$RunStartedAt,
        [Parameter(Mandatory=$true)][string]$Directory,
        [Parameter(Mandatory=$true)][string[]]$Extensions
    )
    $baseName = New-WinDiagReportBaseName -Prefix $Prefix -RunStartedAt $RunStartedAt
    $sequence = 1
    while ($true) {
        $candidate = if($sequence -eq 1){$baseName}else{'{0}_{1:D2}' -f $baseName,$sequence}
        $exists = @($Extensions | Where-Object { Test-Path -LiteralPath (Join-Path $Directory ($candidate + $_)) }).Count -gt 0
        if (-not $exists) {
            return [PSCustomObject]@{ BaseName=$candidate; Timestamp=$RunStartedAt; Directory=$Directory; Sequence=$sequence }
        }
        $sequence++
    }
}

function Initialize-WinDiagSession {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$SessionId,
        [string]$Directory = (Get-WinDiagReportDirectory -Ensure)
    )
    $sessionsRoot = Join-Path $Directory '.sessions'
    $sessionDir = Join-Path $sessionsRoot $SessionId
    if (-not (Test-Path -LiteralPath $sessionDir)) {
        [void](New-Item -ItemType Directory -Path $sessionDir -Force -ErrorAction Stop)
    }
    try { (Get-Item -LiteralPath $sessionsRoot -Force).Attributes = ((Get-Item -LiteralPath $sessionsRoot -Force).Attributes -bor [IO.FileAttributes]::Hidden) } catch {}
    $marker = Join-Path $sessionDir '.started'
    if (-not (Test-Path -LiteralPath $marker)) { [IO.File]::WriteAllText($marker,[DateTime]::Now.ToString('o')) }
    return [PSCustomObject]@{ Directory=$Directory; SessionDirectory=$sessionDir; Marker=$marker }
}

function Update-WinDiagSessionZip {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$SessionId,
        [string]$Directory = (Get-WinDiagReportDirectory -Ensure)
    )

    $session = Initialize-WinDiagSession -SessionId $SessionId -Directory $Directory
    $sessionDir = $session.SessionDirectory
    $markerTime = (Get-Item -LiteralPath $session.Marker -Force).LastWriteTime

    # Collect only reports produced during this launcher session.  Move them to
    # hidden staging so the visible day folder contains ready-to-send ZIPs only.
    $loose = @(Get-ChildItem -LiteralPath $Directory -File -ErrorAction Stop | Where-Object {
        $_.Extension -ne '.zip' -and $_.LastWriteTime -ge $markerTime.AddSeconds(-2)
    })
    foreach($file in $loose) {
        Move-Item -LiteralPath $file.FullName -Destination (Join-Path $sessionDir $file.Name) -Force -ErrorAction Stop
    }

    $files = @(Get-ChildItem -LiteralPath $sessionDir -File -ErrorAction Stop | Where-Object { $_.Name -ne '.started' })
    $zipName = 'EXPC_Diagnostics_{0}.zip' -f $SessionId
    $zipPath = Join-Path $Directory $zipName
    $tempZip = Join-Path (Split-Path -Parent $Directory) ('.{0}.{1}.tmp.zip' -f $SessionId,[Guid]::NewGuid().ToString('N'))

    if ($files.Count -eq 0) {
        return [PSCustomObject]@{ Status='NO_REPORTS'; Directory=$Directory; ZipPath=$zipPath; FileCount=0 }
    }

    try {
        Compress-Archive -LiteralPath @($files.FullName) -DestinationPath $tempZip -CompressionLevel Optimal -Force -ErrorAction Stop
        if (-not (Test-Path -LiteralPath $tempZip -PathType Leaf)) { throw 'Temporary ZIP was not created.' }
        if ((Get-Item -LiteralPath $tempZip).Length -le 0) { throw 'Temporary ZIP is empty.' }
        Move-Item -LiteralPath $tempZip -Destination $zipPath -Force -ErrorAction Stop
        return [PSCustomObject]@{ Status='OK'; Directory=$Directory; ZipPath=$zipPath; FileCount=$files.Count; SessionDirectory=$sessionDir }
    }
    catch {
        Remove-Item -LiteralPath $tempZip -Force -ErrorAction SilentlyContinue
        throw
    }
}

Export-ModuleMember -Function Get-WinDiagReportDirectory,New-WinDiagReportBaseName,Get-UniqueWinDiagReportBaseName,Initialize-WinDiagSession,Update-WinDiagSessionZip
