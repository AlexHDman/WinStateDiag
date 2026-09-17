#requires -Version 5.0
<#
EXPC Diagnostic v1.5
Read-only diagnostic collector for Windows 10/11.

Release v1.5 — consolidated stable baseline:
- Reports use the project-wide EXPC_DD.MM.YY_HH-mm-ss TXT/JSON naming convention.
- Pending Reboot is split into CBS, Windows Update and PendingFileRenameOperations; PFRO source->target pairs are shown.
- Print Spooler V4Dirs + active RDP redirected printers are recognized as PRINT/RDP CONTEXT instead of an automatic reboot fault.
- Legacy ACPI PS/2 Code 24 placeholders (PNP0303 / PNP0F03) are INFO and no longer raise PnP ATTENTION by themselves.
- Smart Card / CCID log storms are grouped as a peripheral context (count/first/last/example) instead of flooding the System fault list.
- VSS rows map volume GUIDs to drive letters when possible and include shadow-copy count / oldest / newest timestamps.
- Application crash grouping now includes faulting application/module/exception signature instead of grouping only by provider/event ID.
- Microsoft Remote Display Adapter is excluded from the primary GPU and driver inventory tables.
- DISM log evidence is scoped to lines appended during the current ScanHealth run; old historical lines no longer pollute the report.
- CHKDSK key output filters progress lines from the TXT report while the live console progress remains unchanged.
- Deep-check console results print [ OK ] / [ ATTENTION ] / [ ERROR ] with semantic status colors.
- BIOS/driver age flags are REVIEW/INFO, not an automatic system ATTENTION; latest still requires external OEM/WU verification.
- Adds BIOS service-safety context: firmware mode, Secure Boot, TPM and BitLocker state (no recovery keys/secrets are collected).
- Keeps the v1.4.7.1 native-process progress completion hotfix.
- Deep checks remain OFF by default. No repair commands were added.

The script does NOT run repair commands such as:
SFC /scannow
DISM /RestoreHealth
CHKDSK /f
Windows Update reset
TRIM / cleanup / registry changes
#>

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

$ScriptVersion = '1.5'
$ComputerName  = $env:COMPUTERNAME
$CompanyName   = ''
$StationName   = $ComputerName
$ScriptLaunchTime = Get-Date
Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) 'Compatibility.psm1') -Force
Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) 'ReportStorage.psm1') -Force
$RuntimeInfo = Get-CompatRuntimeInfo
$ReportDirectory = Get-WinDiagReportDirectory

# Resolve the CURRENT user's real Desktop directory.
# Universal for different Windows user names and redirected/OneDrive Desktop locations.
$Desktop = [Environment]::GetFolderPath([Environment+SpecialFolder]::DesktopDirectory)
if ([string]::IsNullOrWhiteSpace($Desktop)) {
    $Desktop = Join-Path $env:USERPROFILE 'Desktop'
}

# LogPath and StartTime are assigned only after the operator identifies the client/station.
$LogPath   = $null
$StartTime = $null

# Source file must be saved as UTF-8 with BOM for Windows PowerShell 5.1.
# Report is also always written as UTF-8 with BOM.
$script:Utf8Bom = New-Object System.Text.UTF8Encoding($true)
$script:Attention = New-Object System.Collections.Generic.List[string]
$script:Checks = [ordered]@{}
$script:IsAdmin = $false
$script:Mode = 1
$script:DeepChecks = @{
    SFC    = $false
    DISM   = $false
    CHKDSK = $false
}
$script:LastProgressLength = 0
$script:ProgressLineActive = $false

function Test-IsAdmin {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

function Write-Log {
    param([AllowEmptyString()][string]$Text = '')
    [System.IO.File]::AppendAllText(
        $LogPath,
        $Text + [Environment]::NewLine,
        $script:Utf8Bom
    )
}

function Write-Section {
    param([string]$Title)
    Write-Log ''
    Write-Log ('=' * 96)
    Write-Log $Title
    Write-Log ('=' * 96)
}

function Write-ObjectLog {
    param(
        [Parameter(Mandatory=$false)]$InputObject,
        [ValidateSet('List','Table')][string]$Format = 'List'
    )

    if ($null -eq $InputObject) {
        Write-Log '(нет данных)'
        return
    }

    try {
        if ($Format -eq 'Table') {
            $text = ($InputObject | Format-Table -AutoSize | Out-String -Width 500).TrimEnd()
        } else {
            $text = ($InputObject | Format-List | Out-String -Width 500).TrimEnd()
        }

        if ([string]::IsNullOrWhiteSpace($text)) {
            $text = '(нет данных)'
        }
        Write-Log $text
    } catch {
        Write-Log ("Ошибка форматирования: {0}" -f $_.Exception.Message)
    }
}

function Add-Attention {
    param([string]$Text)
    if (-not [string]::IsNullOrWhiteSpace($Text)) {
        [void]$script:Attention.Add($Text)
    }
}

function Set-CheckStatus {
    param(
        [Parameter(Mandatory=$true)][string]$Key,
        [Parameter(Mandatory=$true)]
        [ValidateSet('OK','ATTENTION','ERROR','INFO','REVIEW','SKIPPED','NOT TESTED','UNKNOWN')]
        [string]$Status,
        [string]$Detail = ''
    )

    $script:Checks[$Key] = [PSCustomObject]@{
        Check  = $Key
        Status = $Status
        Detail = $Detail
    }
}

function Write-DiagResult {
    param(
        [ValidateSet('OK','ATTENTION','ERROR','INFO','REVIEW','UNKNOWN')]
        [string]$Status,
        [string]$Message
    )

    $color = switch ($Status) {
        'OK'        { 'Green' }
        'ATTENTION' { 'DarkYellow' }
        'ERROR'     { 'Red' }
        'INFO'      { 'Cyan' }
        'REVIEW'    { 'Yellow' }
        default     { 'Gray' }
    }

    Write-Host ("[ {0} ] " -f $Status) -ForegroundColor $color -NoNewline
    Write-Host $Message
}

function Short-Message {
    param([string]$Text, [int]$Max = 1800)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return ''
    }

    $t = (($Text -replace '\r?\n', ' ') -replace '\s+', ' ').Trim()
    if ($t.Length -gt $Max) {
        return $t.Substring(0, $Max) + ' ...'
    }
    return $t
}

function ConvertTo-SafeFileToken {
    param(
        [AllowEmptyString()][string]$Text,
        [string]$Fallback = ''
    )

    $value = [string]$Text
    if ([string]::IsNullOrWhiteSpace($value)) {
        $value = [string]$Fallback
    }

    $value = $value.Trim()
    $value = $value -replace '[\\/:*?"<>|]', '_'
    $value = $value -replace '\s+', '_'
    $value = $value -replace '_{2,}', '_'
    $value = $value -replace '^_+|_+$', ''
    $value = $value.Trim().TrimEnd('.')

    if ($value -match '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?$') {
        $value = '_' + $value
    }

    return $value
}

function New-ExpcDiagnosticReportBaseName {
    param(
        [AllowEmptyString()][string]$Client,
        [Parameter(Mandatory=$true)][string]$Computer,
        [Parameter(Mandatory=$true)][datetime]$RunStartedAt
    )

    return New-WinDiagReportBaseName -Prefix EXPC -RunStartedAt $RunStartedAt
}

function Read-YesNoDefaultNo {
    param([string]$Prompt)

    $a = Read-Host ("{0} [y/N]" -f $Prompt)
    return ($a.Trim().ToLowerInvariant() -in @('y','yes','д','да'))
}

function Get-FileLengthSafe {
    param([string]$Path)
    try {
        if (Test-Path -LiteralPath $Path) {
            return (Get-Item -LiteralPath $Path -ErrorAction Stop).Length
        }
    } catch {}
    return 0L
}

function Read-BytesShared {
    param(
        [string]$Path,
        [long]$Offset = 0
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return [byte[]]@()
    }

    $fs = $null
    try {
        $fs = New-Object System.IO.FileStream(
            $Path,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::ReadWrite
        )

        if ($Offset -lt 0 -or $Offset -gt $fs.Length) {
            $Offset = 0
        }

        [void]$fs.Seek($Offset, [System.IO.SeekOrigin]::Begin)
        $remaining = [int][Math]::Min(($fs.Length - $Offset), [int]::MaxValue)
        if ($remaining -le 0) {
            return [byte[]]@()
        }

        $buffer = New-Object byte[] $remaining
        $read = $fs.Read($buffer, 0, $remaining)

        if ($read -eq $buffer.Length) {
            return $buffer
        }

        if ($read -le 0) {
            return [byte[]]@()
        }

        $trimmed = New-Object byte[] $read
        [Array]::Copy($buffer, $trimmed, $read)
        return $trimmed
    } catch {
        return [byte[]]@()
    } finally {
        if ($null -ne $fs) {
            $fs.Dispose()
        }
    }
}

function Get-LocalizedTextDecodeScore {
    param([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return -100000
    }

    $score = 0
    $score += ([regex]::Matches($Text, '[А-Яа-яЁё]').Count * 3)
    $score += ([regex]::Matches($Text, '[A-Za-z0-9]').Count)
    $score -= ([regex]::Matches($Text, '[\u2500-\u257F]').Count * 8)
    $score -= ([regex]::Matches($Text, [char]0xFFFD).Count * 20)

    $patterns = @(
        'Windows', 'провер', 'ошиб', 'файл', 'систем', 'диск', 'сектор',
        'заверш', 'ресурс', 'защит', 'компонент', 'повреж', 'наруш'
    )

    foreach ($p in $patterns) {
        if ($Text -match $p) {
            $score += 25
        }
    }

    return $score
}

function Convert-BytesToTextAuto {
    param([byte[]]$Bytes)

    if ($null -eq $Bytes -or $Bytes.Length -eq 0) {
        return ''
    }

    if ($Bytes.Length -ge 3 -and
        $Bytes[0] -eq 0xEF -and $Bytes[1] -eq 0xBB -and $Bytes[2] -eq 0xBF) {
        return (New-Object System.Text.UTF8Encoding($false)).GetString($Bytes, 3, $Bytes.Length - 3)
    }

    if ($Bytes.Length -ge 2 -and $Bytes[0] -eq 0xFF -and $Bytes[1] -eq 0xFE) {
        return [System.Text.Encoding]::Unicode.GetString($Bytes, 2, $Bytes.Length - 2)
    }

    if ($Bytes.Length -ge 2 -and $Bytes[0] -eq 0xFE -and $Bytes[1] -eq 0xFF) {
        return [System.Text.Encoding]::BigEndianUnicode.GetString($Bytes, 2, $Bytes.Length - 2)
    }

    # Redirected SFC often produces UTF-16 without a BOM.
    $sample = [Math]::Min($Bytes.Length, 4096)
    $evenNulls = 0
    $oddNulls = 0
    $pairs = [Math]::Floor($sample / 2)

    if ($pairs -gt 0) {
        for ($i = 0; $i -lt ($pairs * 2); $i += 2) {
            if ($Bytes[$i] -eq 0) { $evenNulls++ }
            if ($Bytes[$i + 1] -eq 0) { $oddNulls++ }
        }

        if (($oddNulls / $pairs) -gt 0.20 -and ($evenNulls / $pairs) -lt 0.10) {
            return [System.Text.Encoding]::Unicode.GetString($Bytes)
        }
        if (($evenNulls / $pairs) -gt 0.20 -and ($oddNulls / $pairs) -lt 0.10) {
            return [System.Text.Encoding]::BigEndianUnicode.GetString($Bytes)
        }
    }

    try {
        $strictUtf8 = New-Object System.Text.UTF8Encoding($false, $true)
        return $strictUtf8.GetString($Bytes)
    } catch {}

    # Russian Windows tools are inconsistent under redirection. On tested PCs
    # CHKDSK produced ANSI/1251 while other console output may use OEM/866.
    # Decode both and select the version that looks like readable localized text.
    $ansiText = ''
    $oemText = ''

    try {
        $ansiCp = [System.Globalization.CultureInfo]::CurrentCulture.TextInfo.ANSICodePage
        $ansiText = [System.Text.Encoding]::GetEncoding($ansiCp).GetString($Bytes)
    } catch {}

    try {
        $oemCp = [System.Globalization.CultureInfo]::CurrentCulture.TextInfo.OEMCodePage
        $oemText = [System.Text.Encoding]::GetEncoding($oemCp).GetString($Bytes)
    } catch {}

    if (-not [string]::IsNullOrWhiteSpace($ansiText) -and
        -not [string]::IsNullOrWhiteSpace($oemText)) {
        $ansiScore = Get-LocalizedTextDecodeScore -Text $ansiText
        $oemScore = Get-LocalizedTextDecodeScore -Text $oemText
        if ($ansiScore -ge $oemScore) { return $ansiText }
        return $oemText
    }

    if (-not [string]::IsNullOrWhiteSpace($ansiText)) { return $ansiText }
    if (-not [string]::IsNullOrWhiteSpace($oemText)) { return $oemText }

    try { return [System.Text.Encoding]::Default.GetString($Bytes) } catch { return '' }
}

function Read-TextFileAuto {
    param(
        [string]$Path,
        [long]$Offset = 0
    )

    $bytes = Read-BytesShared -Path $Path -Offset $Offset
    return Convert-BytesToTextAuto -Bytes $bytes
}

function Get-LatestPercentFromText {
    param([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return $null
    }

    $matches = [regex]::Matches($Text, '(?<!\d)(\d{1,3}(?:[\.,]\d+)?)\s*%')
    if ($matches.Count -eq 0) {
        return $null
    }

    for ($i = $matches.Count - 1; $i -ge 0; $i--) {
        $raw = $matches[$i].Groups[1].Value -replace ',', '.'
        $value = 0.0
        if ([double]::TryParse(
            $raw,
            [System.Globalization.NumberStyles]::Float,
            [System.Globalization.CultureInfo]::InvariantCulture,
            [ref]$value
        )) {
            if ($value -ge 0 -and $value -le 100) {
                return $value
            }
        }
    }

    return $null
}

function Format-ProgressTrack {
    param(
        [double]$Percent,
        [int]$Width = 40
    )

    if ($Percent -lt 0) { $Percent = 0 }
    if ($Percent -gt 100) { $Percent = 100 }

    $fill = [int][Math]::Round(($Percent / 100.0) * $Width)
    $chars = New-Object char[] $Width

    for ($i = 0; $i -lt $Width; $i++) {
        $chars[$i] = if ($i -lt $fill) { '=' } else { ' ' }
    }

    return ('[' + (-join $chars) + ']')
}

function Format-LiveProgressLine {
    param(
        [string]$Label,
        $Percent,
        [TimeSpan]$Elapsed
    )

    $trackPercent = 0.0
    $percentText = '  --.-%'
    if ($null -ne $Percent) {
        $trackPercent = [Math]::Max(0.0, [Math]::Min(100.0, [double]$Percent))
        $percentText = ("{0,6:0.0}%" -f $trackPercent)
    }

    $track = Format-ProgressTrack -Percent $trackPercent
    $elapsedMinutes = [int][Math]::Floor($Elapsed.TotalMinutes)
    $elapsedText = "{0:00}:{1:00}" -f $elapsedMinutes, $Elapsed.Seconds
    return ("{0}  {1}  {2}  {3}" -f $track, $percentText, $elapsedText, $Label)
}

function Get-InteractiveProgressConsoleWidth {
    try {
        if ($Host.Name -ne 'ConsoleHost') { return 0 }
        if ([Console]::IsOutputRedirected) { return 0 }
        $width = [int][Console]::BufferWidth
        if ($width -lt 20) { return 0 }
        return $width
    } catch {
        return 0
    }
}

function Show-LiveProgress {
    param(
        [string]$Label,
        $Percent,
        [TimeSpan]$Elapsed,
        [switch]$Complete
    )

    $line = Format-LiveProgressLine -Label $Label -Percent $Percent -Elapsed $Elapsed
    $consoleWidth = Get-InteractiveProgressConsoleWidth

    # A carriage return can only repaint the current physical console row. If the
    # line would wrap, or output is redirected/non-interactive, suppress periodic
    # frames and emit one compact completion line instead.
    if ($consoleWidth -le 0 -or $line.Length -ge $consoleWidth) {
        if ($script:ProgressLineActive) {
            try { [Console]::WriteLine() } catch {}
        }
        $script:ProgressLineActive = $false
        $script:LastProgressLength = 0

        if ($Complete) {
            $elapsedMinutes = [int][Math]::Floor($Elapsed.TotalMinutes)
            $elapsedText = "{0:00}:{1:00}" -f $elapsedMinutes, $Elapsed.Seconds
            Write-Host ("Completed  {0}  {1}" -f $elapsedText, $Label) -ForegroundColor Cyan
        }
        return
    }

    # Erase any characters left by a longer previous line.
    $pad = ''
    if ($script:LastProgressLength -gt $line.Length) {
        $pad = ' ' * ($script:LastProgressLength - $line.Length)
    }
    $script:LastProgressLength = $line.Length

    try {
        [Console]::Write(("`r{0}{1}" -f $line, $pad))
        $script:ProgressLineActive = $true

        if ($Complete) {
            [Console]::WriteLine()
            $script:LastProgressLength = 0
            $script:ProgressLineActive = $false
        }
    } catch {
        $script:LastProgressLength = 0
        $script:ProgressLineActive = $false
        if ($Complete) {
            $elapsedMinutes = [int][Math]::Floor($Elapsed.TotalMinutes)
            $elapsedText = "{0:00}:{1:00}" -f $elapsedMinutes, $Elapsed.Seconds
            Write-Host ("Completed  {0}  {1}" -f $elapsedText, $Label) -ForegroundColor Cyan
        }
    }
}

function Invoke-NativeWithProgress {
    param(
        [Parameter(Mandatory=$true)][string]$FilePath,
        [Parameter(Mandatory=$true)][string]$Arguments,
        [Parameter(Mandatory=$true)][string]$Label
    )

    $tempRoot = Join-Path $env:TEMP 'EXPC-Diagnostic'
    if (-not (Test-Path -LiteralPath $tempRoot)) {
        New-Item -Path $tempRoot -ItemType Directory -Force | Out-Null
    }

    $id = [Guid]::NewGuid().ToString('N')
    $stdoutPath = Join-Path $tempRoot ($id + '.out')
    $stderrPath = Join-Path $tempRoot ($id + '.err')

    $proc = $null
    $processId = $null
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $lastPercent = $null

    try {
        Write-Host ''

        $proc = Start-Process `
            -FilePath $FilePath `
            -ArgumentList $Arguments `
            -RedirectStandardOutput $stdoutPath `
            -RedirectStandardError $stderrPath `
            -WindowStyle Hidden `
            -PassThru

        $processId = [int]$proc.Id

        # Follow the actual OS PID. On Windows PowerShell 5.1 the Process object
        # returned by Start-Process can remain stale after some native tools exit.
        while ($true) {
            Start-Sleep -Milliseconds 350

            $textNow = Read-TextFileAuto -Path $stdoutPath
            $pct = Get-LatestPercentFromText -Text $textNow
            if ($null -ne $pct) { $lastPercent = [double]$pct }

            Show-LiveProgress -Label $Label -Percent $lastPercent -Elapsed $sw.Elapsed

            $alive = $false
            try {
                $alive = ($null -ne (Get-Process -Id $processId -ErrorAction SilentlyContinue))
            } catch {
                $alive = $false
            }

            if (-not $alive) { break }
        }

        # Never block indefinitely after the native process disappeared.
        $waitCompleted = $false
        try { $waitCompleted = $proc.WaitForExit(5000) } catch {}
        try { $proc.Refresh() } catch {}

        $exitCode = $null
        $exitCodeKnown = $false
        try {
            if ($proc.HasExited) {
                $exitCode = [int]$proc.ExitCode
                $exitCodeKnown = $true
            }
        } catch {}

        # Give redirected output a short settling window.
        $lastSize = -1L
        for ($i = 0; $i -lt 10; $i++) {
            $currentSize = 0L
            try {
                if (Test-Path -LiteralPath $stdoutPath) {
                    $currentSize += (Get-Item -LiteralPath $stdoutPath -ErrorAction SilentlyContinue).Length
                }
                if (Test-Path -LiteralPath $stderrPath) {
                    $currentSize += (Get-Item -LiteralPath $stderrPath -ErrorAction SilentlyContinue).Length
                }
            } catch {}

            if ($currentSize -eq $lastSize) { break }
            $lastSize = $currentSize
            Start-Sleep -Milliseconds 150
        }

        $sw.Stop()

        $finalOut = Read-TextFileAuto -Path $stdoutPath
        $finalErr = Read-TextFileAuto -Path $stderrPath
        $combined = $finalOut

        if (-not [string]::IsNullOrWhiteSpace($finalErr)) {
            if (-not [string]::IsNullOrWhiteSpace($combined)) {
                $combined += [Environment]::NewLine
            }
            $combined += $finalErr
        }

        # The native process has already disappeared from the OS process table,
        # so execution is complete. Some tools (especially CHKDSK /scan) leave a
        # stale percentage in redirected output (for example 13%) even though the
        # command finished normally. Do not let that stale parser value freeze the UI.
        #
        # 100% here means "process execution completed" only. Diagnostic health is
        # still determined independently by semantic output + ExitCode below.
        $finalPercent = 100.0

        Show-LiveProgress -Label $Label -Percent $finalPercent -Elapsed $sw.Elapsed -Complete

        return [PSCustomObject]@{
            ProcessId     = $processId
            ExitCode      = $exitCode
            ExitCodeKnown = $exitCodeKnown
            WaitCompleted = $waitCompleted
            Text          = $combined
            Duration      = $sw.Elapsed
        }
    } catch {
        if ($sw.IsRunning) { $sw.Stop() }
        Show-LiveProgress -Label $Label -Percent $lastPercent -Elapsed $sw.Elapsed -Complete
        throw
    } finally {
        foreach ($f in @($stdoutPath, $stderrPath)) {
            try {
                if (Test-Path -LiteralPath $f) {
                    Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue
                }
            } catch {}
        }
    }
}

function Get-MeaningfulNativeLines {
    param(
        [string]$Text,
        [int]$MaxLines = 20
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return @()
    }

    $lines = @($Text -split '\r?\n' | ForEach-Object { $_.TrimEnd() } | Where-Object {
        -not [string]::IsNullOrWhiteSpace($_) -and
        $_ -notmatch '^\s*\[[=\s]*\d{1,3}(?:[\.,]\d+)?%[=\s]*\]\s*$' -and
        $_ -notmatch '^\s*Progress:\s' -and
        $_ -notmatch '^\s*Ход выполнения:' -and
        $_ -notmatch '^\s*Progress completed:'
    })

    if ($lines.Count -le $MaxLines) {
        return $lines
    }

    return @($lines | Select-Object -Last $MaxLines)
}

function Get-PendingRebootState {
    $cbs = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
    $wu  = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'

    $pfroRaw = @()
    try {
        $p = Get-ItemProperty `
            'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' `
            -Name PendingFileRenameOperations `
            -ErrorAction Stop
        $pfroRaw = @($p.PendingFileRenameOperations)
    } catch {}

    $pairs = @()
    if ($pfroRaw.Count -gt 0) {
        for ($i = 0; $i -lt $pfroRaw.Count; $i += 2) {
            $src = [string]$pfroRaw[$i]
            $dst = if (($i + 1) -lt $pfroRaw.Count) { [string]$pfroRaw[$i + 1] } else { '' }
            $pairs += [PSCustomObject]@{
                Source = $src
                Target = $dst
            }
        }
    }

    $v4Pairs = @(
        $pairs | Where-Object {
            ([string]$_.Source -match '(?i)\\Windows\\System32\\spool\\V4Dirs\\') -or
            ([string]$_.Target -match '(?i)\\Windows\\System32\\spool\\V4Dirs\\')
        }
    )

    $v4Guids = @(
        foreach ($pair in $v4Pairs) {
            foreach ($path in @([string]$pair.Source, [string]$pair.Target)) {
                $m = [regex]::Match($path, '(?i)\\V4Dirs\\\{?([0-9A-Fa-f-]{36})\}?\\')
                if ($m.Success) { $m.Groups[1].Value.ToUpperInvariant() }
            }
        }
    ) | Sort-Object -Unique

    $rdpPrinters = @()
    try {
        $rdpPrinters = @(
            Get-CompatInstance Win32_Printer -ErrorAction Stop |
            Where-Object {
                ([string]$_.PortName -match '^(?i)TS\d+') -or
                ([string]$_.Name -match '(?i)перенаправлено|redirected')
            } |
            Select-Object Name, PortName, DriverName
        )
    } catch {}

    $reasons = @()
    if ($cbs) { $reasons += 'CBS RebootPending' }
    if ($wu)  { $reasons += 'Windows Update RebootRequired' }
    if ($pairs.Count -gt 0) { $reasons += 'PendingFileRenameOperations' }

    $onlyPrintRdp = (
        -not $cbs -and -not $wu -and
        $pairs.Count -gt 0 -and
        $v4Pairs.Count -eq $pairs.Count -and
        $rdpPrinters.Count -gt 0
    )

    $classification = if ($onlyPrintRdp) {
        'PRINT/RDP CONTEXT'
    } elseif ($pairs.Count -gt 0 -and $v4Pairs.Count -eq $pairs.Count) {
        'PRINT SPOOLER / V4 DRIVER CONTEXT'
    } elseif ($cbs -or $wu) {
        'SERVICING REBOOT'
    } elseif ($pairs.Count -gt 0) {
        'FILE RENAME PENDING'
    } else {
        'NONE'
    }

    return [PSCustomObject]@{
        Pending                    = ($reasons.Count -gt 0)
        Reasons                    = ($reasons -join '; ')
        CBSRebootPending           = [bool]$cbs
        WindowsUpdateRebootRequired= [bool]$wu
        PendingFileRenameCount     = $pairs.Count
        PendingFileRenamePairs     = $pairs
        PrintV4PairCount           = $v4Pairs.Count
        PrintV4Guids               = $v4Guids
        RdpPrinterCount            = $rdpPrinters.Count
        RdpPrinters                = $rdpPrinters
        OnlyPrintRdpContext        = [bool]$onlyPrintRdp
        Classification             = $classification
    }
}

function Test-SmartCardPeripheralEvent {
    param($Event)
    if ($null -eq $Event) { return $false }
    $provider = [string]$Event.ProviderName
    $id = [int]$Event.Id
    if ($provider -match '(?i)WudfUsbccidDriver|Smartcard-Server|SmartCard') { return $true }
    if ($provider -match '(?i)Microsoft-Windows-Smartcard-Server' -and $id -in @(205,610)) { return $true }
    return $false
}

function Get-SystemEventMessageSignature {
    param($Event)
    $message = Short-Message ([string]$Event.Message) 1000
    if ([string]::IsNullOrWhiteSpace($message)) { return '' }
    $message = $message -replace '\b0x[0-9A-Fa-f]+\b', '0x#'
    $message = $message -replace '\b\d{4,}\b', '#'
    return $message
}

function Test-ServiceSignificantSystemEvent {
    param($Event)

    if ($null -eq $Event) {
        return $false
    }

    $provider = [string]$Event.ProviderName
    $id = [int]$Event.Id

    # Smart Card / CCID storms are peripheral context, not generic hardware/system faults.
    if (Test-SmartCardPeripheralEvent -Event $Event) { return $false }

    # Volsnap 36 is interpreted only by the dedicated VSS Shadow Storage check.
    if ($provider -match '^volsnap$' -and $id -eq 36) {
        return $false
    }

    if ($provider -match 'WHEA|Disk|Ntfs|storahci|stornvme|storsvc|volmgr|volsnap|partmgr|spaceport|Kernel-Power|BugCheck') {
        return $true
    }

    if ($id -in @(7,11,15,41,51,55,57,98,129,140,153,154,157,161,6008)) {
        return $true
    }

    if ($id -eq 1001 -and $provider -match 'BugCheck|WER|ErrorReporting') {
        return $true
    }

    return $false
}

function Get-ApplicationEventCategory {
    param($Event)

    if ($null -eq $Event) {
        return ''
    }

    $provider = [string]$Event.ProviderName
    $id = [int]$Event.Id

    # Real application failure categories. Provider + Event ID are both checked
    # so unrelated Event ID 1000/1001 records (for example Perflib) are not
    # incorrectly called application crashes.
    if (
        ($provider -match '^Application Error$' -and $id -eq 1000) -or
        ($provider -match '^Application Hang$' -and $id -eq 1002) -or
        ($provider -match '^Windows Error Reporting$' -and $id -eq 1001) -or
        ($provider -match '^\.NET Runtime$' -and $id -eq 1026)
    ) {
        return 'CrashHang'
    }

    # SideBySide is a software-component/dependency problem, not automatically
    # an application crash.
    if ($provider -match '^SideBySide$' -and $id -in @(33,59)) {
        return 'SoftwareComponent'
    }

    return ''
}

function Test-SignificantApplicationEvent {
    param($Event)
    return (-not [string]::IsNullOrWhiteSpace((Get-ApplicationEventCategory -Event $Event)))
}

function Get-ApplicationIssueSignature {
    param($Event)

    if ($null -eq $Event) { return '' }

    $provider = [string]$Event.ProviderName
    $id = [int]$Event.Id
    $category = Get-ApplicationEventCategory -Event $Event
    $message = Short-Message ([string]$Event.Message) 3500

    if ($category -eq 'SoftwareComponent') {
        $assembly = ''
        $m = [regex]::Match($message, '(?i)(?:Dependent Assembly|зависимая сборка)\s+"([^"]+)"')
        if ($m.Success) { $assembly = $m.Groups[1].Value.Trim() }
        if (-not [string]::IsNullOrWhiteSpace($assembly)) {
            return ("{0}|{1}|{2}|{3}" -f $category, $provider, $id, $assembly)
        }
    }

    $appName = ''
    $moduleName = ''
    $exception = ''

    $m = [regex]::Match($message, '(?i)(?:Faulting application name|Имя сбойного приложения):\s*([^,]+)')
    if ($m.Success) { $appName = $m.Groups[1].Value.Trim() }

    $m = [regex]::Match($message, '(?i)(?:Faulting module name|Имя сбойного модуля):\s*([^,]+)')
    if ($m.Success) { $moduleName = $m.Groups[1].Value.Trim() }

    $m = [regex]::Match($message, '(?i)(?:Exception code|Код исключения):\s*(0x[0-9a-f]+)')
    if ($m.Success) { $exception = $m.Groups[1].Value.ToLowerInvariant() }

    if ($provider -match '^\.NET Runtime$') {
        if ([string]::IsNullOrWhiteSpace($appName)) {
            $m = [regex]::Match($message, '(?i)(?:Application|Приложение):\s*([^\s]+)')
            if ($m.Success) { $appName = $m.Groups[1].Value.Trim() }
        }
        $m = [regex]::Match($message, '(?i)(?:Exception Info|Сведения об исключении):\s*([^\s]+)')
        if ($m.Success) { $exception = $m.Groups[1].Value.Trim() }
    }

    if ([string]::IsNullOrWhiteSpace($appName)) { $appName = '-' }
    if ([string]::IsNullOrWhiteSpace($moduleName)) { $moduleName = '-' }
    if ([string]::IsNullOrWhiteSpace($exception)) { $exception = '-' }

    return ("{0}|{1}|{2}|{3}|{4}|{5}" -f $category, $provider, $id, $appName, $moduleName, $exception)
}

function Convert-PcieCorrectableStatusToText {
    param($StatusValue)

    if ($null -eq $StatusValue) { return '' }

    try {
        $value = [uint32]$StatusValue
    } catch {
        return ''
    }

    if ($value -eq 0) { return 'None' }

    $names = New-Object System.Collections.Generic.List[string]
    $knownMask = [uint32]0

    $map = @(
        @{ Mask = [uint32]0x00000001; Name = 'Receiver Error' },
        @{ Mask = [uint32]0x00000040; Name = 'Bad TLP' },
        @{ Mask = [uint32]0x00000080; Name = 'Bad DLLP' },
        @{ Mask = [uint32]0x00000100; Name = 'Replay Num Rollover' },
        @{ Mask = [uint32]0x00001000; Name = 'Replay Timer Timeout' },
        @{ Mask = [uint32]0x00002000; Name = 'Advisory Non-Fatal Error' },
        @{ Mask = [uint32]0x00004000; Name = 'Corrected Internal Error' },
        @{ Mask = [uint32]0x00008000; Name = 'Header Log Overflow' }
    )

    foreach ($item in $map) {
        $knownMask = $knownMask -bor $item.Mask
        if (($value -band $item.Mask) -ne 0) {
            [void]$names.Add($item.Name)
        }
    }

    $unknownBits = $value -band (-bnot $knownMask)
    if ($unknownBits -ne 0) {
        [void]$names.Add(('Unknown bits 0x{0:X}' -f $unknownBits))
    }

    return ($names -join ' + ')
}

function Get-WheaCperInfo {
    param([Parameter(Mandatory=$true)]$Record)

    $message = Short-Message $Record.Message 1800
    $eventId = [int]$Record.Id

    if ($eventId -eq 17) {
        $bdf = ''
        $pciHardwareId = ''
        $vendorId = ''
        $deviceId = ''
        $sourceType = ''
        $component = ''
        $correctableStatus = $null
        $uncorrectableStatus = $null
        $correctableStatusHex = ''
        $uncorrectableStatusHex = ''
        $aerCorrectable = ''

        if ($message -match 'Advanced Error Reporting|AER') { $sourceType = 'PCIe AER' }
        if ($message -match 'PCI Express Root Port') { $component = 'PCI Express Root Port' }

        # Event ID 17 exposes structured PCIe/AER fields in EventData. Prefer them over localized message parsing.
        try {
            [xml]$eventXml17 = $Record.ToXml()
            $data = @{}
            foreach ($node in @($eventXml17.Event.EventData.Data)) {
                $name = [string]$node.Name
                if (-not [string]::IsNullOrWhiteSpace($name)) {
                    $data[$name] = [string]$node.'#text'
                }
            }

            if ($data.ContainsKey('Bus') -and $data.ContainsKey('Device') -and $data.ContainsKey('Function')) {
                $bus = [Convert]::ToUInt32(($data['Bus'] -replace '^0x',''), 16)
                $dev = [Convert]::ToUInt32(($data['Device'] -replace '^0x',''), 16)
                $fun = [Convert]::ToUInt32(($data['Function'] -replace '^0x',''), 16)
                $bdf = ('{0:X}:{1:X}:{2:X}' -f $bus, $dev, $fun)
            }

            if ($data.ContainsKey('VendorID')) {
                $vendorId = ('{0:X4}' -f [Convert]::ToUInt32(($data['VendorID'] -replace '^0x',''), 16))
            }
            if ($data.ContainsKey('DeviceID')) {
                $deviceId = ('{0:X4}' -f [Convert]::ToUInt32(($data['DeviceID'] -replace '^0x',''), 16))
            }
            if ($data.ContainsKey('PrimaryDeviceName')) {
                $pciHardwareId = [string]$data['PrimaryDeviceName']
            }
            if ($data.ContainsKey('CorrectableErrorStatus')) {
                $correctableStatus = [Convert]::ToUInt32(($data['CorrectableErrorStatus'] -replace '^0x',''), 16)
                $correctableStatusHex = ('0x{0:X}' -f $correctableStatus)
                $aerCorrectable = Convert-PcieCorrectableStatusToText -StatusValue $correctableStatus
            }
            if ($data.ContainsKey('UncorrectableErrorStatus')) {
                $uncorrectableStatus = [Convert]::ToUInt32(($data['UncorrectableErrorStatus'] -replace '^0x',''), 16)
                $uncorrectableStatusHex = ('0x{0:X}' -f $uncorrectableStatus)
            }
        } catch {}

        # Fallback for systems/locales where EventData is incomplete.
        if ([string]::IsNullOrWhiteSpace($bdf)) {
            $bdfMatch = [regex]::Match($message, '0x([0-9A-Fa-f]+):0x([0-9A-Fa-f]+):0x([0-9A-Fa-f]+)')
            if ($bdfMatch.Success) {
                $bdf = "{0}:{1}:{2}" -f `
                    $bdfMatch.Groups[1].Value.ToUpperInvariant(), `
                    $bdfMatch.Groups[2].Value.ToUpperInvariant(), `
                    $bdfMatch.Groups[3].Value.ToUpperInvariant()
            }
        }

        if ([string]::IsNullOrWhiteSpace($vendorId) -or [string]::IsNullOrWhiteSpace($deviceId)) {
            $pciMatch = [regex]::Match($message, 'PCI\\VEN_([0-9A-Fa-f]{4})&DEV_([0-9A-Fa-f]{4})[^ \r\n]*')
            if ($pciMatch.Success) {
                $vendorId = $pciMatch.Groups[1].Value.ToUpperInvariant()
                $deviceId = $pciMatch.Groups[2].Value.ToUpperInvariant()
                if ([string]::IsNullOrWhiteSpace($pciHardwareId)) { $pciHardwareId = $pciMatch.Value }
            }
        }

        return [PSCustomObject]@{
            TimeCreated             = $Record.TimeCreated
            EventId                 = $eventId
            Level                   = $Record.LevelDisplayName
            Signature               = 'WHEA17'
            SeverityCode            = 2
            Severity                = 'Corrected'
            SectionCount            = $null
            RecordLength            = $null
            SourceType              = $sourceType
            Component               = $component
            BDF                     = $bdf
            VendorId                = $vendorId
            DeviceId                = $deviceId
            PCIHardwareId           = $pciHardwareId
            CorrectableErrorStatus  = $correctableStatusHex
            UncorrectableErrorStatus= $uncorrectableStatusHex
            AERCorrectable          = $aerCorrectable
            Message                 = $message
        }
    }

    $rawHex = ''
    try {
        [xml]$eventXml = $Record.ToXml()
        $rawNode = $eventXml.SelectSingleNode("/*[local-name()='Event']/*[local-name()='EventData']/*[local-name()='Data' and @Name='RawData']")
        if ($null -ne $rawNode) { $rawHex = ([string]$rawNode.InnerText).Trim() }
    } catch {}

    $signature = ''
    $sectionCount = $null
    $severityCode = $null
    $recordLength = $null

    if (-not [string]::IsNullOrWhiteSpace($rawHex) -and $rawHex.Length -ge 48 -and
        ($rawHex.Length % 2) -eq 0 -and $rawHex -match '^[0-9A-Fa-f]+$') {
        try {
            $bytes = New-Object byte[] ($rawHex.Length / 2)
            for ($i = 0; $i -lt $bytes.Length; $i++) {
                $bytes[$i] = [Convert]::ToByte($rawHex.Substring($i * 2, 2), 16)
            }
            if ($bytes.Length -ge 24) {
                $signature = [System.Text.Encoding]::ASCII.GetString($bytes, 0, 4)
                if ($signature -eq 'CPER') {
                    $sectionCount = [BitConverter]::ToUInt16($bytes, 10)
                    $severityCode = [BitConverter]::ToUInt32($bytes, 12)
                    $recordLength = [BitConverter]::ToUInt32($bytes, 20)
                }
            }
        } catch {}
    }

    $severityName = switch ($severityCode) {
        0 { 'Recoverable' }
        1 { 'Fatal' }
        2 { 'Corrected' }
        3 { 'Informational' }
        default { 'Unknown' }
    }

    [PSCustomObject]@{
        TimeCreated              = $Record.TimeCreated
        EventId                  = $eventId
        Level                    = $Record.LevelDisplayName
        Signature                = $signature
        SeverityCode             = $severityCode
        Severity                 = $severityName
        SectionCount             = $sectionCount
        RecordLength             = $recordLength
        SourceType               = ''
        Component                = ''
        BDF                      = ''
        VendorId                 = ''
        DeviceId                 = ''
        PCIHardwareId            = ''
        CorrectableErrorStatus   = ''
        UncorrectableErrorStatus = ''
        AERCorrectable           = ''
        Message                  = $message
    }
}
function Normalize-VolumeDeviceId {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return '' }
    $t = $Text.Trim().Trim('"')
    $m = [regex]::Match($t, '(?i)(\\\\\?\\Volume\{[0-9A-Fa-f-]+\}\\?)')
    if ($m.Success) { $t = $m.Groups[1].Value }
    if (-not $t.EndsWith('\')) { $t += '\' }
    return $t.ToUpperInvariant()
}

function Get-VssVolumeMap {
    $map = @{}
    try {
        foreach ($v in @(Get-CompatInstance Win32_Volume -ErrorAction Stop)) {
            $key = Normalize-VolumeDeviceId -Text ([string]$v.DeviceID)
            if (-not [string]::IsNullOrWhiteSpace($key)) {
                $label = if (-not [string]::IsNullOrWhiteSpace([string]$v.DriveLetter)) {
                    [string]$v.DriveLetter
                } else {
                    [string]$v.DeviceID
                }
                $map[$key] = $label
            }
        }
    } catch {}
    return $map
}

function Get-VssVolumeText {
    param($Value, [hashtable]$VolumeMap)

    if ($null -eq $Value) { return '' }

    $raw = ''
    try {
        if ($null -ne $Value.PSObject.Properties['DriveLetter']) {
            $dl = [string]$Value.DriveLetter
            if (-not [string]::IsNullOrWhiteSpace($dl)) { return $dl }
        }
    } catch {}

    try {
        if ($null -ne $Value.PSObject.Properties['DeviceID']) {
            $raw = [string]$Value.DeviceID
        }
    } catch {}

    if ([string]::IsNullOrWhiteSpace($raw)) {
        try { $raw = [string]$Value } catch { $raw = '' }
    }

    $key = Normalize-VolumeDeviceId -Text $raw
    if ($null -ne $VolumeMap -and $VolumeMap.ContainsKey($key)) {
        return $VolumeMap[$key]
    }
    return $raw
}

function Get-VssShadowStorageInfo {
    $rows = @()
    $volumeMap = Get-VssVolumeMap
    $shadows = @()
    try { $shadows = @(Get-CompatInstance Win32_ShadowCopy -ErrorAction Stop) } catch {}

    try {
        $stores = @(Get-CompatInstance -Namespace 'root\cimv2' -ClassName 'Win32_ShadowStorage' -ErrorAction Stop)
    } catch {
        return [PSCustomObject]@{ Success=$false; Error=$_.Exception.Message; Rows=@(); NearLimitCount=0 }
    }

    foreach ($s in $stores) {
        $used = 0.0; $allocated = 0.0; $max = 0.0
        try { if ($null -ne $s.UsedSpace) { $used = [double]([uint64]$s.UsedSpace) } } catch {}
        try { if ($null -ne $s.AllocatedSpace) { $allocated = [double]([uint64]$s.AllocatedSpace) } } catch {}
        try { if ($null -ne $s.MaxSpace) { $max = [double]([uint64]$s.MaxSpace) } } catch {}

        $isUnlimited = ($max -ge 9.0e18)
        $limitPct = $null
        if (-not $isUnlimited -and $max -gt 0) { $limitPct = [Math]::Round(($used / $max) * 100.0, 1) }
        $nearLimit = ($null -ne $limitPct -and [double]$limitPct -ge 85.0)

        $volumeRaw = ''
        try {
            if ($null -ne $s.Volume.PSObject.Properties['DeviceID']) { $volumeRaw = [string]$s.Volume.DeviceID }
            else { $volumeRaw = [string]$s.Volume }
        } catch { $volumeRaw = [string]$s.Volume }
        $volumeKey = Normalize-VolumeDeviceId -Text $volumeRaw

        $volumeShadows = @(
            $shadows | Where-Object {
                (Normalize-VolumeDeviceId -Text ([string]$_.VolumeName)) -eq $volumeKey
            }
        )
        $dates = @($volumeShadows | ForEach-Object { $_.InstallDate } | Where-Object { $null -ne $_ } | Sort-Object)

        $rows += [PSCustomObject]@{
            Volume        = Get-VssVolumeText -Value $s.Volume -VolumeMap $volumeMap
            StorageVolume = Get-VssVolumeText -Value $s.DiffVolume -VolumeMap $volumeMap
            UsedGB        = [Math]::Round($used / 1GB, 2)
            AllocatedGB   = [Math]::Round($allocated / 1GB, 2)
            MaximumGB     = $(if ($isUnlimited) { 'UNLIMITED' } else { [Math]::Round($max / 1GB, 2) })
            LimitUsagePct = $(if ($null -eq $limitPct) { '-' } else { $limitPct })
            NearLimit     = [bool]$nearLimit
            Shadows       = $volumeShadows.Count
            Oldest        = $(if ($dates.Count -gt 0) { $dates[0] } else { '' })
            Newest        = $(if ($dates.Count -gt 0) { $dates[-1] } else { '' })
        }
    }

    $nearCount = @($rows | Where-Object { $_.NearLimit -eq $true }).Count
    return [PSCustomObject]@{ Success=$true; Error=''; Rows=$rows; NearLimitCount=$nearCount }
}

function Get-BiosSafetyContext {
    $firmwareMode = 'UNKNOWN'
    try {
        $pe = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control' -Name PEFirmwareType -ErrorAction Stop).PEFirmwareType
        $firmwareMode = switch ([int]$pe) { 1 { 'Legacy BIOS' } 2 { 'UEFI' } default { 'UNKNOWN' } }
    } catch {}

    $secureBoot = 'UNKNOWN'
    if (Get-Command Confirm-SecureBootUEFI -ErrorAction SilentlyContinue) {
        try { $secureBoot = [string][bool](Confirm-SecureBootUEFI -ErrorAction Stop) } catch { $secureBoot = 'Unsupported/UNKNOWN' }
    }

    $tpmPresent = 'UNKNOWN'; $tpmReady = 'UNKNOWN'; $tpmEnabled = 'UNKNOWN'
    if (Get-Command Get-Tpm -ErrorAction SilentlyContinue) {
        try {
            $tpm = Get-Tpm -ErrorAction Stop
            $tpmPresent = [string]$tpm.TpmPresent
            $tpmReady   = [string]$tpm.TpmReady
            $tpmEnabled = [string]$tpm.TpmEnabled
        } catch {}
    }

    $bitLocker = 'UNKNOWN'
    if (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) {
        try {
            $bl = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop | Select-Object -First 1
            if ($null -ne $bl) {
                $bitLocker = "VolumeStatus={0}; Protection={1}; Encryption={2}%" -f $bl.VolumeStatus, $bl.ProtectionStatus, $bl.EncryptionPercentage
            }
        } catch { $bitLocker = 'Unavailable' }
    }

    return [PSCustomObject]@{
        FirmwareMode = $firmwareMode
        SecureBoot   = $secureBoot
        TpmPresent   = $tpmPresent
        TpmReady     = $tpmReady
        TpmEnabled   = $tpmEnabled
        BitLockerC   = $bitLocker
    }
}

function Get-StepDecision {
    param(
        [string]$Title,
        [switch]$Long,
        [string]$DeepKey = ''
    )

    # Mode 1: base diagnostics only; deep checks OFF.
    if ($script:Mode -eq 1) {
        if ($Long) { return 'Skip' }
        return 'Run'
    }

    # Mode 2: base diagnostics + deep checks chosen once at startup.
    if ($script:Mode -eq 2) {
        if ($Long) {
            if (-not [string]::IsNullOrWhiteSpace($DeepKey) -and $script:DeepChecks[$DeepKey]) {
                return 'Run'
            }
            return 'Skip'
        }
        return 'Run'
    }

    # Mode 3: full automatic.
    if ($script:Mode -eq 3) {
        return 'Run'
    }

    # Mode 4: step-by-step.
    while ($true) {
        Write-Host ''
        Write-Host ("Шаг: {0}" -f $Title) -ForegroundColor Cyan
        if ($Long) {
            Write-Host 'Это глубокая проверка и может занять несколько минут.' -ForegroundColor DarkYellow
        }

        $a = Read-Host '[Enter/1] Выполнить   [2] Пропустить   [3] Завершить диагностику'
        switch ($a.Trim().ToLowerInvariant()) {
            ''  { return 'Run' }
            '1' { return 'Run' }
            '2' { return 'Skip' }
            '3' { return 'Exit' }
            default {
                Write-Host 'Введите 1, 2 или 3.' -ForegroundColor Yellow
            }
        }
    }
}

function Invoke-Step {
    param(
        [int]$Number,
        [string]$Title,
        [scriptblock]$Action,
        [switch]$Long,
        [string]$DeepKey = ''
    )

    $decision = Get-StepDecision -Title $Title -Long:$Long -DeepKey $DeepKey

    if ($decision -eq 'Exit') {
        Write-Section ("ДИАГНОСТИКА ОСТАНОВЛЕНА ПОЛЬЗОВАТЕЛЕМ НА ШАГЕ {0}" -f $Number)
        return $false
    }

    if ($decision -eq 'Skip') {
        Write-Section ("[{0:00}] {1}" -f $Number, $Title)
        Write-Log 'ПРОПУЩЕНО: глубокая проверка не выбрана / выбран основной режим.'
        Write-Host ("Пропущено: {0}" -f $Title) -ForegroundColor DarkGray

        if (-not [string]::IsNullOrWhiteSpace($DeepKey)) {
            Set-CheckStatus -Key $DeepKey -Status 'SKIPPED' -Detail 'Не выбрано при запуске.'
        }
        return $true
    }

    Write-Host ''
    Write-Host ("Выполняется: {0}" -f $Title) -ForegroundColor Green
    Write-Section ("[{0:00}] {1}" -f $Number, $Title)

    $sw = [Diagnostics.Stopwatch]::StartNew()
    try {
        & $Action
        $sw.Stop()
        Write-Log ("Время шага: {0:n1} сек." -f $sw.Elapsed.TotalSeconds)
        Write-Host ("Готово ({0:n1} сек.)" -f $sw.Elapsed.TotalSeconds) -ForegroundColor Green
    } catch {
        $sw.Stop()
        $msg = $_.Exception.Message
        $exceptionType = $_.Exception.GetType().FullName
        $scriptLine = $_.InvocationInfo.ScriptLineNumber
        $position = $_.InvocationInfo.PositionMessage

        Write-Log ("ОШИБКА ШАГА: {0}" -f $msg)
        Write-Log ("Exception type : {0}" -f $exceptionType)
        Write-Log ("Script line    : {0}" -f $scriptLine)
        if (-not [string]::IsNullOrWhiteSpace($position)) {
            Write-Log ("Position       : {0}" -f (Short-Message $position 1200))
        }

        Add-Attention ("Шаг {0} '{1}' завершился ошибкой: {2} (line {3})" -f $Number, $Title, $msg, $scriptLine)
        Write-Host ("Ошибка: {0} (строка {1})" -f $msg, $scriptLine) -ForegroundColor Red

        if (-not [string]::IsNullOrWhiteSpace($DeepKey)) {
            Set-CheckStatus -Key $DeepKey -Status 'ERROR' -Detail ("{0} (line {1})" -f $msg, $scriptLine)
        } else {
            Set-CheckStatus -Key ("Step {0:00}" -f $Number) -Status 'ERROR' -Detail ("{0}: {1} (line {2})" -f $Title, $msg, $scriptLine)
        }
    }

    return $true
}

Clear-Host
Write-Host '============================================================' -ForegroundColor Blue
Write-Host (" EXPC Diagnostic v{0}" -f $ScriptVersion) -ForegroundColor Cyan
Write-Host ' Диагностика Windows 7/8.1/10/11 — только чтение' -ForegroundColor White
Write-Host (" Runtime: {0} | Compatibility: {1}" -f $RuntimeInfo.DisplayName,$RuntimeInfo.Compatibility) -ForegroundColor Gray
Write-Host '============================================================' -ForegroundColor Blue
Write-Host ''
Write-Host 'Основная диагностика выполняется автоматически.' -ForegroundColor Gray
Write-Host 'SFC / DISM / CHKDSK — глубокие проверки, по умолчанию ВЫКЛЮЧЕНЫ.' -ForegroundColor Gray
Write-Host 'Ремонтные команды этот скрипт не запускает.' -ForegroundColor Gray
Write-Host ''

$script:IsAdmin = Test-IsAdmin

if (-not $script:IsAdmin) {
    Write-Host 'Для полной диагностики нужны права администратора.' -ForegroundColor Yellow
    Write-Host '[1] Перезапустить этот скрипт от имени администратора'
    Write-Host '[2] Продолжить без повышения прав'
    Write-Host '[3] Выход'

    $elev = Read-Host 'Выбор'
    if ($elev -eq '1') {
        try {
            $arg = "-NoLogo -NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
            Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $arg
            exit
        } catch {
            Write-Host ("Не удалось повысить права: {0}" -f $_.Exception.Message) -ForegroundColor Red
        }
    } elseif ($elev -eq '3') {
        exit
    }
}

Write-Host ''
Write-Host 'Идентификация отчёта:' -ForegroundColor Cyan
$CompanyName = (Read-Host 'Название фирмы / клиента (можно оставить пустым)').Trim()

$stationInput = Read-Host ("Название компьютера / станции [{0}]" -f $ComputerName)
if ([string]::IsNullOrWhiteSpace($stationInput)) {
    $StationName = $ComputerName
} else {
    $StationName = $stationInput.Trim()
}

try {
    if (-not (Test-Path -LiteralPath $ReportDirectory)) {
        [void](New-Item -ItemType Directory -Path $ReportDirectory -Force -ErrorAction Stop)
    }
} catch {
    Write-Host ("Не удалось создать {0}: {1}" -f $ReportDirectory, $_.Exception.Message) -ForegroundColor Yellow
    Write-Host 'Будет использован Рабочий стол как аварийный путь.' -ForegroundColor Yellow
    $ReportDirectory = $Desktop
}

Write-Host ("Фирма / клиент : {0}" -f $(if ([string]::IsNullOrWhiteSpace($CompanyName)) { '(не указана)' } else { $CompanyName })) -ForegroundColor Gray
Write-Host ("Станция         : {0}" -f $StationName) -ForegroundColor Gray
Write-Host ("Windows PC      : {0}" -f $ComputerName) -ForegroundColor Gray

Write-Host ''
Write-Host 'Режим:' -ForegroundColor Cyan
Write-Host '[1] Основной — автоматическая диагностика, SFC / DISM / CHKDSK выключены (рекомендуется)'
Write-Host '[2] Основной + выбрать глубокие проверки один раз'
Write-Host '[3] Полный — автоматически выполнить всё, включая SFC / DISM / CHKDSK'
Write-Host '[4] Пошаговый — спрашивать перед каждым этапом'
Write-Host '[5] Выход'

while ($true) {
    $m = Read-Host 'Выбор [1]'
    if ([string]::IsNullOrWhiteSpace($m)) {
        $m = '1'
    }

    if ($m -in @('1','2','3','4','5')) {
        break
    }
}

if ($m -eq '5') {
    exit
}

$script:Mode = [int]$m

if ($script:Mode -eq 2) {
    Write-Host ''
    Write-Host 'Выберите глубокие проверки. По умолчанию ответ Нет.' -ForegroundColor Cyan
    $script:DeepChecks.SFC    = Read-YesNoDefaultNo 'SFC /verifyonly'
    $script:DeepChecks.DISM   = Read-YesNoDefaultNo 'DISM /ScanHealth'
    $script:DeepChecks.CHKDSK = Read-YesNoDefaultNo ("CHKDSK {0} /scan" -f $env:SystemDrive)
} elseif ($script:Mode -eq 3) {
    $script:DeepChecks.SFC    = $true
    $script:DeepChecks.DISM   = $true
    $script:DeepChecks.CHKDSK = $true
}

# Diagnostics timing begins after operator identification and mode selection.
$StartTime = Get-Date
$allocation = Get-UniqueWinDiagReportBaseName -Prefix EXPC -RunStartedAt $ScriptLaunchTime -Directory $ReportDirectory -Extensions @('.txt','.json')
$ReportBaseName = $allocation.BaseName
$LogPath = Join-Path $ReportDirectory ($ReportBaseName + '.txt')
$JsonPath = Join-Path $ReportDirectory ($ReportBaseName + '.json')
Write-Host ("Файл отчёта     : {0}" -f $LogPath) -ForegroundColor Green

# Create a fresh report and write BOM immediately.
$logStream = [IO.File]::Open($LogPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
try {
    $preamble = $script:Utf8Bom.GetPreamble()
    $logStream.Write($preamble,0,$preamble.Length)
} finally { $logStream.Dispose() }

Write-Log 'Tool: EXPC Diagnostic'
Write-Log 'EXPC DIAGNOSTIC REPORT'
Write-Log ("Version          : {0}" -f $ScriptVersion)
Write-Log ("Company / Client : {0}" -f $(if ([string]::IsNullOrWhiteSpace($CompanyName)) { '(not specified)' } else { $CompanyName }))
Write-Log ("Station          : {0}" -f $StationName)
Write-Log ("Windows Computer : {0}" -f $ComputerName)
Write-Log ("Started          : {0:yyyy-MM-dd HH:mm:ss}" -f $StartTime)
Write-Log ("Administrator    : {0}" -f $script:IsAdmin)
Write-Log ("PowerShell       : {0}" -f $PSVersionTable.PSVersion)
Write-Log ("Mode             : {0}" -f $script:Mode)
Write-Log ("System drive     : {0}" -f $env:SystemDrive)
Write-Log 'NOTE: CPU/GPU temperatures are not collected because standard Windows PowerShell has no reliable universal sensor interface.'

:Diagnostics while ($true) {

$continue = Invoke-Step -Number 1 -Title 'Сведения о системе, железе, Windows и аптайме' -Action {
    $os   = Get-CompatInstance Win32_OperatingSystem
    $cs   = Get-CompatInstance Win32_ComputerSystem
    $cpu  = Get-CompatInstance Win32_Processor
    $bios = Get-CompatInstance Win32_BIOS
    $bb   = Get-CompatInstance Win32_BaseBoard
    $gpu  = @(Get-CompatInstance Win32_VideoController | Where-Object { $_.Name -notmatch '^Microsoft Remote Display Adapter$' })

    Write-ObjectLog ([PSCustomObject]@{
        ComputerName = $env:COMPUTERNAME
        Manufacturer = $cs.Manufacturer
        Model        = $cs.Model
        Windows      = $os.Caption
        Version      = $os.Version
        Build        = $os.BuildNumber
        Architecture = $os.OSArchitecture
        LastBoot     = $os.LastBootUpTime
        UptimeDays   = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalDays, 2)
        RAM_GB       = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
        BIOS         = (($bios.Manufacturer + ' ' + $bios.SMBIOSBIOSVersion).Trim())
        BIOS_Date    = $bios.ReleaseDate
        Motherboard  = (($bb.Manufacturer + ' ' + $bb.Product).Trim())
        BoardVersion = $bb.Version
        BoardSerial  = $bb.SerialNumber
    })

    Write-Log ''
    Write-Log 'CPU:'
    Write-ObjectLog (
        $cpu | Select-Object Name, Manufacturer, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed
    ) -Format Table

    Write-Log ''
    Write-Log 'GPU:'
    Write-ObjectLog (
        $gpu | Select-Object Name, DriverVersion, DriverDate, AdapterRAM
    ) -Format Table

    $pending = Get-PendingRebootState
    Write-Log ''
    Write-Log ("Pending reboot: {0}" -f $pending.Pending)
    Write-Log ("CBS RebootPending          : {0}" -f $pending.CBSRebootPending)
    Write-Log ("WU RebootRequired          : {0}" -f $pending.WindowsUpdateRebootRequired)
    Write-Log ("PendingFileRename pairs    : {0}" -f $pending.PendingFileRenameCount)
    Write-Log ("Classification             : {0}" -f $pending.Classification)

    if ($pending.PendingFileRenameCount -gt 0) {
        Write-Log 'PendingFileRenameOperations (source -> target):'
        Write-ObjectLog ($pending.PendingFileRenamePairs | Select-Object -First 30 Source, Target) -Format Table
    }
    if ($pending.PrintV4PairCount -gt 0) {
        Write-Log ("Print Spooler / V4Dirs pairs: {0}" -f $pending.PrintV4PairCount)
        if (@($pending.PrintV4Guids).Count -gt 0) { Write-Log ("V4 driver GUIDs: {0}" -f ($pending.PrintV4Guids -join ', ')) }
    }
    if ($pending.RdpPrinterCount -gt 0) {
        Write-Log ("Active RDP redirected printers: {0}" -f $pending.RdpPrinterCount)
        Write-ObjectLog $pending.RdpPrinters -Format Table
    }

    if ($pending.OnlyPrintRdpContext) {
        $detail = "PFRO относится к Print Spooler/V4Dirs при активной RDP-печати; обычная системная перезагрузка не подтверждена как необходимая."
        Set-CheckStatus -Key 'System / Pending reboot' -Status 'INFO' -Detail $detail
    } elseif ($pending.Pending) {
        Write-Log ("Reasons: {0}" -f $pending.Reasons)
        Add-Attention ("Есть признаки ожидающей перезагрузки: {0}" -f $pending.Reasons)
        Set-CheckStatus -Key 'System / Pending reboot' -Status 'ATTENTION' -Detail $pending.Reasons
    } else {
        Set-CheckStatus -Key 'System / Pending reboot' -Status 'OK' -Detail 'Ожидающая перезагрузка не обнаружена.'
    }

    Write-Log ''
    Write-Log 'Последние установленные обновления:'
    try {
        Write-ObjectLog (
            Get-HotFix |
            ForEach-Object {
                # Get-HotFix may expose InstalledOn as a throwing script property.
                $installedOn = $null
                try { $installedOn = $_.InstalledOn } catch {}
                [PSCustomObject]@{
                    HotFixID = $_.HotFixID
                    Description = $_.Description
                    InstalledOn = $installedOn
                }
            } |
            Sort-Object -Property {
                $date = [datetime]::MinValue
                if ($_.InstalledOn -is [datetime]) {
                    $_.InstalledOn.Ticks
                } elseif ([datetime]::TryParse([string]$_.InstalledOn, [ref]$date)) {
                    $date.Ticks
                } else {
                    -1L
                }
            } -Descending |
            Select-Object -First 12 HotFixID, Description, InstalledOn
        ) -Format Table
    } catch {
        Write-Log ("Get-HotFix недоступен: {0}" -f $_.Exception.Message)
    }
}
if (-not $continue) { break Diagnostics }

$continue = Invoke-Step -Number 2 -Title 'Накопители, свободное место и показатели надёжности' -Action {
    $storageAttention = New-Object System.Collections.Generic.List[string]

    Write-Log 'Логические диски:'
    $logical = Get-CompatInstance Win32_LogicalDisk -Filter "DriveType=3" | ForEach-Object {
        $sizeGB = if ($_.Size) { [math]::Round($_.Size / 1GB, 1) } else { 0 }
        $freeGB = if ($_.FreeSpace) { [math]::Round($_.FreeSpace / 1GB, 1) } else { 0 }
        $freePct = if ($_.Size) { [math]::Round(100 * $_.FreeSpace / $_.Size, 1) } else { 0 }

        # Warning only if:
        # 1) critically low absolute free space (<20 GB), OR
        # 2) both low percentage (<10%) AND less than 100 GB free.
        $lowSpace = ($freeGB -lt 20) -or (($freePct -lt 10) -and ($freeGB -lt 100))
        if ($_.Size -and $lowSpace) {
            $msg = "Мало свободного места на {0}: {1} GB ({2}%)" -f $_.DeviceID, $freeGB, $freePct
            [void]$storageAttention.Add($msg)
            Add-Attention $msg
        }

        [PSCustomObject]@{
            Drive       = $_.DeviceID
            Volume      = $_.VolumeName
            FileSystem  = $_.FileSystem
            SizeGB      = $sizeGB
            FreeGB      = $freeGB
            FreePercent = $freePct
        }
    }

    Write-ObjectLog $logical -Format Table
    Write-Log ''
    Write-Log 'Физические диски:'

    if (Get-Command Get-PhysicalDisk -ErrorAction SilentlyContinue) {
        $pdisks = @(Get-PhysicalDisk)

        Write-ObjectLog (
            $pdisks |
            Select-Object FriendlyName, MediaType, BusType, HealthStatus, OperationalStatus,
                @{N='SizeGB';E={[math]::Round($_.Size / 1GB, 0)}}
        ) -Format Table

        foreach ($d in $pdisks) {
            $operational = @($d.OperationalStatus | ForEach-Object { [string]$_ })
            $healthyOperational = ($operational -contains 'OK') -or ($operational -contains 'Online')

            if (($d.HealthStatus -and $d.HealthStatus -ne 'Healthy') -or -not $healthyOperational) {
                $msg = "Накопитель '{0}' сообщает Health={1}, Operational={2}" -f `
                    $d.FriendlyName, $d.HealthStatus, ($operational -join ',')

                [void]$storageAttention.Add($msg)
                Add-Attention $msg
            }
        }

        if (Get-Command Get-StorageReliabilityCounter -ErrorAction SilentlyContinue) {
            Write-Log ''
            Write-Log 'Storage Reliability Counters (пустые поля допустимы, если контроллер их не отдаёт):'

            foreach ($d in $pdisks) {
                try {
                    Write-Log ("--- {0} ---" -f $d.FriendlyName)
                    $r = $d | Get-StorageReliabilityCounter -ErrorAction Stop
                    Write-ObjectLog (
                        $r | Select-Object Temperature, TemperatureMax, Wear, PowerOnHours,
                            ReadErrorsTotal, ReadErrorsCorrected, WriteErrorsTotal, WriteErrorsCorrected
                    ) -Format List
                    if ($null -ne $r.PowerOnHours -and [double]$r.PowerOnHours -ge 50000) {
                        Write-Log ("Lifecycle INFO: высокая наработка {0:n0} ч.; сама по себе не является признаком отказа без SMART/IO ошибок." -f [double]$r.PowerOnHours)
                    }
                } catch {
                    Write-Log ("Счётчики недоступны: {0}" -f $_.Exception.Message)
                }
            }
        }
    } else {
        Write-Log 'Storage module / Get-PhysicalDisk недоступен.'
    }

    if ($storageAttention.Count -gt 0) {
        Set-CheckStatus -Key 'Storage' -Status 'ATTENTION' -Detail ($storageAttention -join ' | ')
    } else {
        Set-CheckStatus -Key 'Storage' -Status 'OK' -Detail 'Критических автоматических маркеров накопителей не обнаружено.'
    }
}
if (-not $continue) { break Diagnostics }

$continue = Invoke-Step -Number 3 -Title 'Проблемные устройства Plug and Play — только присутствующие сейчас' -Action {
    $bad = @()

    if (Get-Command Get-PnpDevice -ErrorAction SilentlyContinue) {
        try {
            $present = @(Get-PnpDevice -PresentOnly -ErrorAction Stop)
            $cimPresent = @(Get-CompatInstance Win32_PnPEntity -ErrorAction SilentlyContinue | Where-Object { $_.Present -eq $true })
            $cimById = @{}
            foreach ($c in $cimPresent) {
                if (-not [string]::IsNullOrWhiteSpace($c.PNPDeviceID)) { $cimById[$c.PNPDeviceID] = $c }
            }
            foreach ($d in $present) {
                $c = $null
                if ($cimById.ContainsKey($d.InstanceId)) { $c = $cimById[$d.InstanceId] }
                $problemCode = if ($null -ne $c) { [int]$c.ConfigManagerErrorCode } else { 0 }
                if ($problemCode -ne 0 -and $problemCode -ne 45) {
                    $bad += [PSCustomObject]@{
                        Name=$d.FriendlyName; PNPClass=$d.Class; Status=$d.Status
                        ConfigManagerErrorCode=$problemCode; InstanceId=$d.InstanceId
                    }
                }
            }
        } catch { Write-Log ("Get-PnpDevice -PresentOnly недоступен: {0}" -f $_.Exception.Message) }
    }

    if ($bad.Count -eq 0) {
        $bad = @(Get-CompatInstance Win32_PnPEntity -ErrorAction SilentlyContinue | Where-Object {
            $_.Present -eq $true -and $_.ConfigManagerErrorCode -ne 0 -and $_.ConfigManagerErrorCode -ne 45
        } | Select-Object Name, PNPClass, Status, ConfigManagerErrorCode, @{N='InstanceId';E={$_.PNPDeviceID}})
    }

    $legacyPs2 = @($bad | Where-Object {
        [int]$_.ConfigManagerErrorCode -eq 24 -and [string]$_.InstanceId -match '^ACPI\\(PNP0303|PNP0F03)\\'
    })
    $realBad = @($bad | Where-Object {
        -not ([int]$_.ConfigManagerErrorCode -eq 24 -and [string]$_.InstanceId -match '^ACPI\\(PNP0303|PNP0F03)\\')
    })

    if ($realBad.Count -gt 0) {
        Write-Log 'Реальные присутствующие PnP-ошибки:'
        Write-ObjectLog $realBad -Format Table
        $msg = "Обнаружены присутствующие PnP-устройства с кодом ошибки: {0}" -f $realBad.Count
        Add-Attention $msg
        Set-CheckStatus -Key 'PnP devices' -Status 'ATTENTION' -Detail $msg
    } else {
        Write-Log 'Реальных присутствующих PnP-ошибок не обнаружено.'
        $detail = 'Активных PnP-ошибок не обнаружено.'
        if ($legacyPs2.Count -gt 0) { $detail += " Legacy PS/2 Code 24 placeholders ignored: $($legacyPs2.Count)." }
        Set-CheckStatus -Key 'PnP devices' -Status 'OK' -Detail $detail
    }

    if ($legacyPs2.Count -gt 0) {
        Write-Log ''
        Write-Log 'Legacy PS/2 placeholders (INFO, не неисправность без дополнительных симптомов):'
        Write-ObjectLog $legacyPs2 -Format Table
    }
}
if (-not $continue) { break Diagnostics }

$continue = Invoke-Step -Number 4 -Title 'Критические и ошибочные события System за 14 дней' -Action {
    $start = (Get-Date).AddDays(-14)
    $events = @(Get-WinEvent -FilterHashtable @{ LogName='System'; Level=1,2; StartTime=$start } -ErrorAction SilentlyContinue)
    $smartCard = @($events | Where-Object { Test-SmartCardPeripheralEvent $_ })
    $significant = @($events | Where-Object { (Test-ServiceSignificantSystemEvent $_) -and -not (Test-SmartCardPeripheralEvent $_) })

    Write-Log ("Всего Critical/Error: {0}" -f $events.Count)
    Write-Log ("Сервисно-значимых системных по фильтру EXPC: {0}" -f $significant.Count)
    Write-Log ("Smart Card / CCID peripheral events: {0}" -f $smartCard.Count)

    if ($events.Count -gt 0) {
        Write-Log ''
        Write-Log 'Наиболее частые Provider + Event ID (контекст, не все требуют ремонта):'
        Write-ObjectLog ($events | Group-Object ProviderName, Id | Sort-Object Count -Descending | Select-Object -First 15 Count, Name) -Format Table
    }

    if ($smartCard.Count -gt 0) {
        Write-Log ''
        Write-Log 'Smart Card / CCID — сгруппированный периферийный контекст:'
        $groups = @(
            $smartCard | Group-Object { "{0}|{1}|{2}" -f $_.ProviderName, $_.Id, (Get-SystemEventMessageSignature $_) } |
            Sort-Object Count -Descending
        )
        $rows = @(
            foreach ($g in $groups | Select-Object -First 12) {
                $sorted = @($g.Group | Sort-Object TimeCreated)
                [PSCustomObject]@{
                    Count    = $g.Count
                    Provider = $sorted[0].ProviderName
                    EventID  = $sorted[0].Id
                    First    = $sorted[0].TimeCreated
                    Last     = $sorted[-1].TimeCreated
                    Example  = Short-Message $sorted[-1].Message 700
                }
            }
        )
        Write-ObjectLog $rows -Format Table
        Set-CheckStatus -Key 'Smart Card / CCID' -Status 'INFO' -Detail ("Периферийные CCID/SmartCard события сгруппированы: {0}; системная неисправность автоматически не подтверждается." -f $smartCard.Count)
    }

    if ($significant.Count -gt 0) {
        Write-Log ''
        Write-Log 'Сервисно-значимые системные события (сгруппировано):'
        $sigGroups = @($significant | Group-Object ProviderName, Id | Sort-Object Count -Descending)
        $sigRows = @(
            foreach ($g in $sigGroups | Select-Object -First 15) {
                $sorted = @($g.Group | Sort-Object TimeCreated)
                [PSCustomObject]@{
                    Count=$g.Count; Provider=$sorted[0].ProviderName; EventID=$sorted[0].Id
                    First=$sorted[0].TimeCreated; Last=$sorted[-1].TimeCreated
                    Example=Short-Message $sorted[-1].Message 900
                }
            }
        )
        Write-ObjectLog $sigRows -Format Table
        $msg = "Сервисно-значимые System-события за 14 дней: {0}" -f $significant.Count
        Add-Attention $msg
        Set-CheckStatus -Key 'System event log' -Status 'ATTENTION' -Detail $msg
    } else {
        Write-Log 'Сервисно-значимых аппаратных/дисковых/аварийных System-событий по фильтру не обнаружено.'
        Set-CheckStatus -Key 'System event log' -Status 'OK' -Detail 'Значимых аппаратных/дисковых/аварийных событий по фильтру не обнаружено.'
    }
}
if (-not $continue) { break Diagnostics }

$continue = Invoke-Step -Number 5 -Title 'VSS Shadow Storage и события Volsnap' -Action {
    $vss = Get-VssShadowStorageInfo

    if (-not $vss.Success) {
        Write-Log ("Не удалось прочитать Win32_ShadowStorage: {0}" -f $vss.Error)
        Set-CheckStatus -Key 'VSS Shadow Storage' -Status 'UNKNOWN' -Detail 'Win32_ShadowStorage недоступен.'
    } elseif (@($vss.Rows).Count -eq 0) {
        Write-Log 'Win32_ShadowStorage не вернул настроенных областей хранения теневых копий.'
        Set-CheckStatus -Key 'VSS Shadow Storage' -Status 'OK' -Detail 'Настроенные области Shadow Storage не обнаружены; автоматический маркер проблемы не сработал.'
    } else {
        Write-Log 'Текущее состояние Shadow Storage:'
        Write-ObjectLog $vss.Rows -Format Table

        if ($vss.NearLimitCount -gt 0) {
            $msg = "VSS Shadow Storage близко к установленному максимуму: областей с использованием >= 85% — {0}." -f $vss.NearLimitCount
            Add-Attention $msg
            Set-CheckStatus -Key 'VSS Shadow Storage' -Status 'ATTENTION' -Detail $msg
        } else {
            Set-CheckStatus -Key 'VSS Shadow Storage' -Status 'OK' -Detail 'Областей Shadow Storage с использованием >= 85% лимита не обнаружено.'
        }
    }

    Write-Log ''
    Write-Log 'Volsnap Event ID 36 за 30 дней:'

    $volsnap36 = @(
        Get-WinEvent -FilterHashtable @{
            LogName      = 'System'
            ProviderName = 'volsnap'
            Id           = 36
            StartTime    = (Get-Date).AddDays(-30)
        } -ErrorAction SilentlyContinue
    )

    Write-Log ("Количество: {0}" -f $volsnap36.Count)

    if ($volsnap36.Count -gt 0) {
        Write-ObjectLog (
            $volsnap36 |
            Select-Object -First 10 TimeCreated, Id, ProviderName,
                @{N='Message';E={Short-Message $_.Message 1800}}
        ) -Format List

        if ($vss.Success -and $vss.NearLimitCount -eq 0) {
            Write-Log 'Примечание: исторические Volsnap 36 есть, но текущая конфигурация Shadow Storage не находится у порога 85%.'
        }
    }
}
if (-not $continue) { break Diagnostics }

$continue = Invoke-Step -Number 6 -Title 'WHEA / CPER за 30 дней — классификация Severity' -Action {
    $start = (Get-Date).AddDays(-30)
    $whea = @(
        Get-WinEvent -FilterHashtable @{
            LogName      = 'System'
            ProviderName = 'Microsoft-Windows-WHEA-Logger'
            StartTime    = $start
        } -ErrorAction SilentlyContinue
    )

    Write-Log ("WHEA events total: {0}" -f $whea.Count)

    $wheaBootTime = $null
    try {
        $wheaBootTime = (Get-CompatInstance Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime
    } catch {}

    if ($null -ne $wheaBootTime) {
        $wheaSinceBootRaw = @($whea | Where-Object { $_.TimeCreated -ge $wheaBootTime })
        Write-Log ("WHEA events since last boot ({0}): {1}" -f ([datetime]$wheaBootTime).ToString('yyyy-MM-dd HH:mm:ss'), $wheaSinceBootRaw.Count)
    }

    if ($whea.Count -eq 0) {
        Write-Log 'WHEA-события за 30 дней не обнаружены.'
        Set-CheckStatus -Key 'WHEA' -Status 'OK' -Detail '0 событий за 30 дней.'
    } else {
        $parsed = @(
            foreach ($event in $whea) {
                Get-WheaCperInfo -Record $event
            }
        )

        $infoCount        = @($parsed | Where-Object { $_.Severity -eq 'Informational' }).Count
        $correctedCount   = @($parsed | Where-Object { $_.Severity -eq 'Corrected' }).Count
        $recoverableCount = @($parsed | Where-Object { $_.Severity -eq 'Recoverable' }).Count
        $fatalCount       = @($parsed | Where-Object { $_.Severity -eq 'Fatal' }).Count
        $unknownCount     = @($parsed | Where-Object { $_.Severity -eq 'Unknown' }).Count
        $faultCount       = $correctedCount + $recoverableCount + $fatalCount

        Write-Log ("Informational records : {0}" -f $infoCount)
        Write-Log ("Corrected records     : {0}" -f $correctedCount)
        Write-Log ("Recoverable records   : {0}" -f $recoverableCount)
        Write-Log ("Fatal records         : {0}" -f $fatalCount)
        Write-Log ("Unknown/unparsed      : {0}" -f $unknownCount)
        Write-Log ("Hardware fault records: {0}" -f $faultCount)

        $correctedSinceBoot = @()
        $faultSinceBoot = @()
        if ($null -ne $wheaBootTime) {
            $correctedSinceBoot = @($parsed | Where-Object { $_.TimeCreated -ge $wheaBootTime -and $_.Severity -eq 'Corrected' })
            $faultSinceBoot = @($parsed | Where-Object { $_.TimeCreated -ge $wheaBootTime -and $_.Severity -in @('Corrected','Recoverable','Fatal') })
            Write-Log ("Corrected records since boot : {0}" -f $correctedSinceBoot.Count)
            Write-Log ("Hardware faults since boot   : {0}" -f $faultSinceBoot.Count)
        }

        $pcieCorrected = @(
            $parsed | Where-Object { $_.EventId -eq 17 -and $_.Severity -eq 'Corrected' }
        )
        Write-Log ("Corrected PCIe/AER records: {0}" -f $pcieCorrected.Count)
        if ($null -ne $wheaBootTime) {
            $pcieSinceBootCount = @($pcieCorrected | Where-Object { $_.TimeCreated -ge $wheaBootTime }).Count
            Write-Log ("Corrected PCIe/AER since boot: {0}" -f $pcieSinceBootCount)
        }

        if ($pcieCorrected.Count -gt 0) {
            $pcieGroups = @(
                $pcieCorrected | Group-Object BDF, VendorId, DeviceId | Sort-Object Count -Descending
            )
            Write-Log ("Affected PCIe groups      : {0}" -f $pcieGroups.Count)
            Write-Log ''
            Write-Log 'Сгруппированные corrected PCIe/AER ошибки:'

            $presentPnp = @()
            try { $presentPnp = @(Get-PnpDevice -PresentOnly -ErrorAction Stop) } catch {}

            function Resolve-PcieRootPortChildLocal {
                param(
                    [string]$VendorId,
                    [string]$DeviceId
                )

                if ($presentPnp.Count -eq 0 -or [string]::IsNullOrWhiteSpace($VendorId) -or [string]::IsNullOrWhiteSpace($DeviceId)) {
                    return ''
                }

                $rootPattern = ('^PCI\\VEN_{0}&DEV_{1}&' -f [regex]::Escape($VendorId), [regex]::Escape($DeviceId))
                $roots = @($presentPnp | Where-Object { $_.InstanceId -match $rootPattern })
                if ($roots.Count -eq 0) { return '' }

                $children = New-Object System.Collections.Generic.List[string]
                foreach ($dev in $presentPnp) {
                    $parent = $null
                    try {
                        $parent = Get-PnpDeviceProperty -InstanceId $dev.InstanceId -KeyName 'DEVPKEY_Device_Parent' -ErrorAction Stop
                    } catch {
                        continue
                    }

                    foreach ($root in $roots) {
                        if ([string]$parent.Data -eq [string]$root.InstanceId) {
                            $name = [string]$dev.FriendlyName
                            if ([string]::IsNullOrWhiteSpace($name)) { $name = [string]$dev.InstanceId }
                            if (-not [string]::IsNullOrWhiteSpace($name) -and -not $children.Contains($name)) {
                                [void]$children.Add($name)
                            }
                        }
                    }
                }

                return ($children -join '; ')
            }

            $groupRows = @(
                foreach ($g in $pcieGroups) {
                    $sample = $g.Group | Select-Object -First 1
                    $statusMasks = @($g.Group | ForEach-Object { $_.CorrectableErrorStatus } | Where-Object { $_ } | Select-Object -Unique)
                    $errorTypes = @($g.Group | ForEach-Object { $_.AERCorrectable } | Where-Object { $_ } | Select-Object -Unique)
                    $child = Resolve-PcieRootPortChildLocal -VendorId $sample.VendorId -DeviceId $sample.DeviceId

                    $sinceBootGroup = ''
                    if ($null -ne $wheaBootTime) {
                        $sinceBootGroup = @($g.Group | Where-Object { $_.TimeCreated -ge $wheaBootTime }).Count
                    }

                    [PSCustomObject]@{
                        Count       = $g.Count
                        SinceBoot   = $sinceBootGroup
                        BDF         = $sample.BDF
                        VendorId    = $sample.VendorId
                        DeviceId    = $sample.DeviceId
                        ChildDevice = $child
                        StatusMask  = ($statusMasks -join ', ')
                        AERType     = ($errorTypes -join ' | ')
                    }
                }
            )
            Write-ObjectLog $groupRows -Format Table
        }

        Write-Log ''
        Write-Log 'Распознанные WHEA записи:'

        Write-ObjectLog (
            $parsed |
            Select-Object -First 30 TimeCreated, EventId, Level, Signature,
                SeverityCode, Severity, SourceType, BDF, VendorId, DeviceId, CorrectableErrorStatus, AERCorrectable, Message
        ) -Format Table

        if ($fatalCount -gt 0) {
            $msg = "WHEA: обнаружены Fatal CPER записи: {0}." -f $fatalCount
            Add-Attention $msg
            Set-CheckStatus -Key 'WHEA' -Status 'ERROR' -Detail $msg
        } elseif ($recoverableCount -gt 0) {
            $msg = "WHEA: обнаружены Recoverable CPER записи: {0}." -f $recoverableCount
            Add-Attention $msg
            Set-CheckStatus -Key 'WHEA' -Status 'ATTENTION' -Detail $msg
        } elseif ($correctedCount -gt 0) {
            $msg = "WHEA: обнаружены Corrected аппаратные записи: {0}." -f $correctedCount
            Add-Attention $msg
            Set-CheckStatus -Key 'WHEA' -Status 'ATTENTION' -Detail $msg
        } elseif ($unknownCount -gt 0) {
            $msg = "WHEA: {0} записей не удалось классифицировать по CPER Severity; нужен инженерный разбор." -f $unknownCount
            Add-Attention $msg
            Set-CheckStatus -Key 'WHEA' -Status 'UNKNOWN' -Detail $msg
        } else {
            $detail = "Только Informational CPER: {0}; hardware fault records: 0." -f $infoCount
            Write-Log ("Result: OK — {0}" -f $detail)
            Set-CheckStatus -Key 'WHEA' -Status 'OK' -Detail $detail
        }
    }
}
if (-not $continue) { break Diagnostics }

$continue = Invoke-Step -Number 7 -Title 'Неожиданные выключения, Kernel-Power и BSOD за 30 дней' -Action {
    $start = (Get-Date).AddDays(-30)

    $ev = @(
        Get-WinEvent -FilterHashtable @{
            LogName   = 'System'
            Id        = 41,6008,1001
            StartTime = $start
        } -ErrorAction SilentlyContinue
    )

    $kp41 = @($ev | Where-Object { $_.Id -eq 41 })
    $ev6008 = @($ev | Where-Object { $_.Id -eq 6008 })
    $bugchecks = @(
        $ev | Where-Object {
            $_.Id -eq 1001 -and
            $_.ProviderName -match 'BugCheck|WER|ErrorReporting'
        }
    )

    # One unexpected shutdown normally creates both Kernel-Power 41 and EventLog
    # 6008. Count the pair as one incident. A standalone 6008 is counted only if
    # no Kernel-Power 41 exists within +/- 15 minutes.
    $incidentTimes = @()

    foreach ($e in $kp41) {
        $incidentTimes += $e.TimeCreated
    }

    foreach ($e in $ev6008) {
        $paired = $false

        foreach ($k in $kp41) {
            $deltaMinutes = [Math]::Abs(($e.TimeCreated - $k.TimeCreated).TotalMinutes)
            if ($deltaMinutes -le 15.0) {
                $paired = $true
                break
            }
        }

        if (-not $paired) {
            $incidentTimes += $e.TimeCreated
        }
    }

    $incidentTimes = @($incidentTimes | Sort-Object -Unique)
    $incidentCount = $incidentTimes.Count
    $lastIncident = $null

    if ($incidentCount -gt 0) {
        $lastIncident = $incidentTimes | Sort-Object -Descending | Select-Object -First 1
    }

    $dumps = @(
        Get-ChildItem (Join-Path $env:SystemRoot 'Minidump\*.dmp') -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 10 Name, Length, LastWriteTime
    )

    Write-Log ("Kernel-Power 41 events        : {0}" -f $kp41.Count)
    Write-Log ("EventLog 6008 events          : {0}" -f $ev6008.Count)
    Write-Log ("Unexpected shutdown incidents : {0}" -f $incidentCount)
    Write-Log ("Confirmed BugCheck events     : {0}" -f $bugchecks.Count)
    Write-Log ("Minidump files                : {0}" -f $dumps.Count)

    if ($null -ne $lastIncident) {
        Write-Log ("Last unexpected shutdown      : {0:yyyy-MM-dd HH:mm:ss}" -f $lastIncident)
    }

    $relevant = @($kp41 + $ev6008 + $bugchecks | Sort-Object TimeCreated -Descending)
    if ($relevant.Count -gt 0) {
        Write-Log ''
        Write-Log 'События для контекста:'
        Write-ObjectLog (
            $relevant |
            Select-Object -First 30 TimeCreated, Id, ProviderName,
                @{N='Message';E={Short-Message $_.Message 2500}}
        ) -Format List
    }

    Write-Log ''
    Write-Log 'Minidump-файлы:'
    if ($dumps.Count -gt 0) {
        Write-ObjectLog $dumps -Format Table
    } else {
        Write-Log 'Minidump-файлы не найдены.'
    }

    if ($bugchecks.Count -gt 0 -or $dumps.Count -gt 0) {
        $msg = "Подтверждённые признаки BSOD: BugCheck={0}, minidump={1}; неожиданных выключений={2}." -f $bugchecks.Count, $dumps.Count, $incidentCount
        Add-Attention $msg
        Set-CheckStatus -Key 'Stability / BSOD' -Status 'ATTENTION' -Detail $msg
    } elseif ($incidentCount -gt 0) {
        $lastText = if ($null -ne $lastIncident) { "{0:yyyy-MM-dd}" -f $lastIncident } else { 'unknown' }
        $msg = "Неожиданных выключений за 30 дней: {0}; BSOD не подтверждён; последнее: {1}." -f $incidentCount, $lastText
        Add-Attention $msg
        Set-CheckStatus -Key 'Stability / BSOD' -Status 'ATTENTION' -Detail $msg
    } else {
        Write-Log 'За 30 дней неожиданных выключений / подтверждённых BugCheck не обнаружено.'
        Set-CheckStatus -Key 'Stability / BSOD' -Status 'OK' -Detail 'Unexpected shutdown incidents=0; BugCheck=0; minidump=0.'
    }
}
if (-not $continue) { break Diagnostics }

$continue = Invoke-Step -Number 8 -Title 'Ошибки приложений за 14 дней' -Action {
    $start = (Get-Date).AddDays(-14)

    $app = @(
        Get-WinEvent -FilterHashtable @{
            LogName   = 'Application'
            Level     = 1,2
            StartTime = $start
        } -ErrorAction SilentlyContinue
    )

    $classified = @(
        foreach ($event in $app) {
            $category = Get-ApplicationEventCategory -Event $event
            if (-not [string]::IsNullOrWhiteSpace($category)) {
                [PSCustomObject]@{
                    Category     = $category
                    Signature    = Get-ApplicationIssueSignature -Event $event
                    TimeCreated  = $event.TimeCreated
                    Id           = $event.Id
                    ProviderName = $event.ProviderName
                    Message      = Short-Message $event.Message
                }
            }
        }
    )

    $crashEvents = @($classified | Where-Object { $_.Category -eq 'CrashHang' })
    $componentEvents = @($classified | Where-Object { $_.Category -eq 'SoftwareComponent' })

    $crashGroups = @(
        $crashEvents |
        Group-Object Signature |
        Sort-Object Count -Descending
    )

    $componentGroups = @(
        $componentEvents |
        Group-Object Signature |
        Sort-Object Count -Descending
    )

    Write-Log ("Application Critical/Error total       : {0}" -f $app.Count)
    Write-Log ("Crash/Hang/.NET/WER incidents           : {0}" -f $crashEvents.Count)
    Write-Log ("Unique crash/hang issue groups          : {0}" -f $crashGroups.Count)
    Write-Log ("SideBySide software-component events    : {0}" -f $componentEvents.Count)
    Write-Log ("Unique software-component issue groups  : {0}" -f $componentGroups.Count)

    if ($app.Count -gt 0) {
        Write-Log ''
        Write-Log 'Наиболее частые Provider + Event ID (контекст):'
        Write-ObjectLog (
            $app |
            Group-Object ProviderName, Id |
            Sort-Object Count -Descending |
            Select-Object -First 12 Count, Name
        ) -Format Table
    }

    if ($crashEvents.Count -gt 0) {
        Write-Log ''
        Write-Log 'Реальные crash/hang/.NET/WER события:'
        Write-ObjectLog (
            $crashEvents |
            Sort-Object TimeCreated -Descending |
            Select-Object -First 20 TimeCreated, Id, ProviderName, Message
        ) -Format List
    }

    if ($componentEvents.Count -gt 0) {
        Write-Log ''
        Write-Log 'SideBySide / software-component события:'
        Write-ObjectLog (
            $componentEvents |
            Sort-Object TimeCreated -Descending |
            Select-Object -First 15 TimeCreated, Id, ProviderName, Message
        ) -Format List

        Write-Log ''
        Write-Log 'Сгруппированные software-component проблемы:'
        Write-ObjectLog (
            $componentGroups |
            Select-Object -First 10 Count, Name
        ) -Format Table
    }

    if ($crashEvents.Count -gt 0) {
        $msg = "Crash/Hang/.NET/WER за 14 дней: {0}; уникальных групп: {1}." -f $crashEvents.Count, $crashGroups.Count
        Add-Attention $msg
        Set-CheckStatus -Key 'Applications' -Status 'ATTENTION' -Detail $msg
    } elseif ($componentEvents.Count -gt 0) {
        $msg = "Реальных crash/hang не найдено; SideBySide software-component events: {0}; уникальных проблем: {1}." -f $componentEvents.Count, $componentGroups.Count
        Add-Attention $msg
        Set-CheckStatus -Key 'Applications' -Status 'ATTENTION' -Detail $msg
    } else {
        Write-Log 'Реальных crash/hang/.NET/WER и SideBySide проблем по фильтру не обнаружено.'
        Set-CheckStatus -Key 'Applications' -Status 'OK' -Detail 'Crash/hang и software-component issues по фильтру не обнаружены.'
    }
}
if (-not $continue) { break Diagnostics }

$continue = Invoke-Step -Number 9 -Title 'Результаты Windows Memory Diagnostic' -Action {
    $mem = @(
        Get-WinEvent -FilterHashtable @{
            LogName      = 'System'
            ProviderName = 'Microsoft-Windows-MemoryDiagnostics-Results'
        } -MaxEvents 8 -ErrorAction SilentlyContinue
    )

    if ($mem.Count -gt 0) {
        Write-ObjectLog (
            $mem |
            Select-Object TimeCreated, Id, LevelDisplayName,
                @{N='Message';E={Short-Message $_.Message 3000}}
        ) -Format List

        $badText = ($mem | ForEach-Object { $_.Message }) -join ' '
        if ($badText -match '(hardware problems|errors were detected|обнаружены ошибки|неполадк)') {
            $msg = 'В журнале Windows Memory Diagnostic есть признаки обнаруженных проблем памяти.'
            Add-Attention $msg
            Set-CheckStatus -Key 'Memory Diagnostic' -Status 'ATTENTION' -Detail $msg
        } else {
            Set-CheckStatus -Key 'Memory Diagnostic' -Status 'OK' -Detail 'Последний найденный Memory Diagnostic не содержит автоматического маркера ошибки.'
        }
    } else {
        Write-Log 'Результаты Windows Memory Diagnostic не найдены (тест мог не запускаться).'
        Set-CheckStatus -Key 'Memory Diagnostic' -Status 'NOT TESTED' -Detail 'В журнале нет результатов теста.'
    }
}
if (-not $continue) { break Diagnostics }

$continue = Invoke-Step -Number 10 -Title 'Антивирус и состояние Microsoft Defender' -Action {
    Write-Log 'Зарегистрированные антивирусные продукты:'
    try {
        $av = Get-CompatInstance `
            -Namespace 'root\SecurityCenter2' `
            -ClassName AntiVirusProduct `
            -ErrorAction Stop |
            Select-Object displayName, productState

        Write-ObjectLog $av -Format Table
    } catch {
        Write-Log ("SecurityCenter2 недоступен: {0}" -f $_.Exception.Message)
    }

    Write-Log ''
    Write-Log 'Microsoft Defender:'

    if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
        try {
            $mp = Get-MpComputerStatus

            Write-ObjectLog (
                $mp | Select-Object AntivirusEnabled, AMServiceEnabled, RealTimeProtectionEnabled,
                    BehaviorMonitorEnabled, IoavProtectionEnabled, AntivirusSignatureLastUpdated,
                    QuickScanAge, FullScanAge
            ) -Format List

            if (-not $mp.AntivirusEnabled -or -not $mp.AMServiceEnabled -or -not $mp.RealTimeProtectionEnabled) {
                $msg = 'Microsoft Defender сообщает об отключённом Antivirus/AMService/RealTimeProtection.'
                Add-Attention $msg
                Set-CheckStatus -Key 'Defender' -Status 'ATTENTION' -Detail $msg
            } else {
                Set-CheckStatus -Key 'Defender' -Status 'OK' -Detail 'Antivirus, AMService и RealTimeProtection включены.'
            }
        } catch {
            Write-Log ("Get-MpComputerStatus: {0}" -f $_.Exception.Message)
            Set-CheckStatus -Key 'Defender' -Status 'UNKNOWN' -Detail 'Не удалось получить Get-MpComputerStatus.'
        }

        Write-Log ''
        Write-Log 'Активные угрозы Defender:'
        try {
            $activeThreats = @(
                Get-MpThreat -ErrorAction Stop |
                Where-Object { $_.IsActive -eq $true }
            )

            if ($activeThreats.Count -gt 0) {
                Write-ObjectLog (
                    $activeThreats |
                    Select-Object ThreatID, ThreatName, SeverityID, CategoryID, IsActive, DidThreatExecute
                ) -Format List

                $msg = "Defender сообщает активные угрозы: {0}" -f $activeThreats.Count
                Add-Attention $msg
                Set-CheckStatus -Key 'Defender' -Status 'ATTENTION' -Detail $msg
            } else {
                Write-Log 'Активных угроз не обнаружено.'
            }
        } catch {
            Write-Log ("Get-MpThreat недоступен/нет данных: {0}" -f $_.Exception.Message)
        }

        Write-Log ''
        Write-Log 'История обнаружений Defender (до 10; история НЕ равна активной угрозе):'
        try {
            $history = @(
                Get-MpThreatDetection -ErrorAction Stop |
                Sort-Object InitialDetectionTime -Descending |
                Select-Object -First 10 InitialDetectionTime, ThreatID, ActionSuccess, Resources
            )

            if ($history.Count -gt 0) {
                Write-ObjectLog $history -Format List
            } else {
                Write-Log 'История обнаружений не найдена.'
            }
        } catch {
            Write-Log ("Get-MpThreatDetection недоступен/нет данных: {0}" -f $_.Exception.Message)
        }
    } else {
        Write-Log 'Команды Microsoft Defender отсутствуют (возможен сторонний антивирус / другая редакция Windows).'
        Set-CheckStatus -Key 'Defender' -Status 'NOT TESTED' -Detail 'Команды Defender отсутствуют.'
    }
}
if (-not $continue) { break Diagnostics }

$continue = Invoke-Step `
    -Number 11 `
    -Title 'SFC — проверка целостности системных файлов (/verifyonly)' `
    -Long `
    -DeepKey 'SFC' `
    -Action {

    if (-not $script:IsAdmin) {
        Write-Log 'ПРОПУСК: для SFC /verifyonly нужны права администратора.'
        Add-Attention 'SFC /verifyonly не выполнен из-за отсутствия административных прав.'
        Set-CheckStatus -Key 'SFC' -Status 'SKIPPED' -Detail 'Нет административных прав.'
        return
    }

    $cbs = Join-Path $env:windir 'Logs\CBS\CBS.log'
    $cbsOffset = Get-FileLengthSafe -Path $cbs

    Write-Log 'Команда: sfc.exe /verifyonly'
    Write-Log 'Прогресс показывался оператору и намеренно не записан в TXT.'

    $r = Invoke-NativeWithProgress `
        -FilePath (Join-Path $env:SystemRoot 'System32\sfc.exe') `
        -Arguments '/verifyonly' `
        -Label 'SFC /verifyonly'

    if ($r.ExitCodeKnown) {
        Write-Log ("ExitCode: {0}" -f $r.ExitCode)
    } else {
        Write-Log 'ExitCode: UNKNOWN (process already ended; semantic result will be used)'
    }
    Write-Log ("Duration: {0:n1} sec" -f $r.Duration.TotalSeconds)

    $text = [string]$r.Text
    $newCbs = Read-TextFileAuto -Path $cbs -Offset $cbsOffset

    $badSfcText = (
        $text -match 'Windows Resource Protection found integrity violations|Защита ресурсов Windows обнаружила нарушения целостности'
    )

    $badCbs = @(
        $newCbs -split '\r?\n' |
        Where-Object {
            $_ -match '\[SR\]' -and
            $_ -match 'Cannot repair|Repair failed|Hashes for file member.*do not match|corrupt|не удается восстановить|не удалось восстановить'
        }
    )

    $healthySfcText = (
        $text -match 'Windows Resource Protection did not find any integrity violations|Защита ресурсов Windows не обнаружила нарушений целостности'
    )

    if ($badSfcText -or $badCbs.Count -gt 0) {
        $detail = 'SFC /verifyonly обнаружил признаки нарушения целостности.'
        Write-Log ("Result: ATTENTION — {0}" -f $detail)
        Add-Attention $detail
        Set-CheckStatus -Key 'SFC' -Status 'ATTENTION' -Detail $detail
        Write-DiagResult -Status 'ATTENTION' -Message $detail

        if ($badCbs.Count -gt 0) {
            Write-Log ''
            Write-Log 'Значимые новые строки [SR] из CBS.log:'
            Write-Log (($badCbs | Select-Object -Last 40) -join [Environment]::NewLine)
        }
    } elseif ($healthySfcText) {
        $detail = 'Признаков нарушений целостности по текущему запуску не обнаружено.'
        Write-Log ("Result: OK — {0}" -f $detail)
        Set-CheckStatus -Key 'SFC' -Status 'OK' -Detail $detail
        Write-DiagResult -Status 'OK' -Message $detail
    } elseif ($r.ExitCodeKnown -and $r.ExitCode -eq 0) {
        $detail = 'SFC завершился успешно; явных признаков нарушения целостности не обнаружено.'
        Write-Log ("Result: OK — {0}" -f $detail)
        Set-CheckStatus -Key 'SFC' -Status 'OK' -Detail $detail
        Write-DiagResult -Status 'OK' -Message $detail
    } elseif ($r.ExitCodeKnown -and $r.ExitCode -ne 0) {
        $detail = "SFC завершился с ExitCode {0}; итоговая строка не распознана." -f $r.ExitCode
        Write-Log ("Result: ERROR/UNKNOWN — {0}" -f $detail)
        Add-Attention $detail
        Set-CheckStatus -Key 'SFC' -Status 'ERROR' -Detail $detail
        Write-DiagResult -Status 'ERROR' -Message $detail
    } else {
        $detail = 'Не удалось однозначно распознать итог SFC; требуется инженерная проверка CBS.log.'
        Write-Log ("Result: UNKNOWN — {0}" -f $detail)
        Add-Attention $detail
        Set-CheckStatus -Key 'SFC' -Status 'UNKNOWN' -Detail $detail
        Write-DiagResult -Status 'ATTENTION' -Message $detail
    }
}
if (-not $continue) { break Diagnostics }

$continue = Invoke-Step `
    -Number 12 `
    -Title 'DISM — диагностика хранилища компонентов (/ScanHealth)' `
    -Long `
    -DeepKey 'DISM' `
    -Action {

    if (-not $script:IsAdmin) {
        Write-Log 'ПРОПУСК: для DISM /ScanHealth нужны права администратора.'
        Add-Attention 'DISM /ScanHealth не выполнен из-за отсутствия административных прав.'
        Set-CheckStatus -Key 'DISM' -Status 'SKIPPED' -Detail 'Нет административных прав.'
        return
    }

    $dismLog = Join-Path $env:windir 'Logs\DISM\dism.log'
    $dismOffset = Get-FileLengthSafe -Path $dismLog

    Write-Log 'Команда: DISM.exe /Online /Cleanup-Image /ScanHealth /NoRestart /English'
    Write-Log 'Прогресс показывался оператору и намеренно не записан в TXT.'

    $r = Invoke-NativeWithProgress `
        -FilePath (Join-Path $env:SystemRoot 'System32\DISM.exe') `
        -Arguments '/Online /Cleanup-Image /ScanHealth /NoRestart /English' `
        -Label 'DISM /ScanHealth'

    if ($r.ExitCodeKnown) {
        Write-Log ("ExitCode: {0}" -f $r.ExitCode)
    } else {
        Write-Log 'ExitCode: UNKNOWN (process already ended; semantic result will be used)'
    }
    Write-Log ("Duration: {0:n1} sec" -f $r.Duration.TotalSeconds)

    $text = [string]$r.Text
    $meaningful = @(
        $text -split '\r?\n' |
        Where-Object {
            $_ -match 'No component store corruption detected|component store is repairable|component store cannot be repaired|Error:|operation completed successfully'
        } |
        Select-Object -Last 20
    )

    if ($meaningful.Count -gt 0) {
        Write-Log ''
        Write-Log 'Ключевые строки DISM:'
        Write-Log ($meaningful -join [Environment]::NewLine)
    }

    if ($text -match 'component store cannot be repaired') {
        $detail = 'DISM сообщает: хранилище компонентов не может быть восстановлено обычным способом.'
        Write-Log ("Result: ERROR — {0}" -f $detail)
        Add-Attention $detail
        Set-CheckStatus -Key 'DISM' -Status 'ERROR' -Detail $detail
        Write-DiagResult -Status 'ERROR' -Message $detail
    } elseif ($text -match 'component store is repairable') {
        $detail = 'DISM сообщает: хранилище компонентов повреждено, но подлежит восстановлению.'
        Write-Log ("Result: ATTENTION — {0}" -f $detail)
        Add-Attention $detail
        Set-CheckStatus -Key 'DISM' -Status 'ATTENTION' -Detail $detail
        Write-DiagResult -Status 'ATTENTION' -Message $detail
    } elseif ($text -match 'No component store corruption detected') {
        $detail = 'Повреждение хранилища компонентов не обнаружено.'
        Write-Log ("Result: OK — {0}" -f $detail)
        Set-CheckStatus -Key 'DISM' -Status 'OK' -Detail $detail
        Write-DiagResult -Status 'OK' -Message $detail
    } elseif ($r.ExitCodeKnown -and $r.ExitCode -ne 0) {
        $detail = "DISM /ScanHealth завершился с ExitCode {0}; итоговая строка не распознана." -f $r.ExitCode
        Write-Log ("Result: ERROR — {0}" -f $detail)
        Add-Attention $detail
        Set-CheckStatus -Key 'DISM' -Status 'ERROR' -Detail $detail
        Write-DiagResult -Status 'ERROR' -Message $detail
    } else {
        $detail = 'Итоговая строка DISM не распознана; требуется инженерная проверка вывода.'
        Write-Log ("Result: UNKNOWN — {0}" -f $detail)
        Add-Attention $detail
        Set-CheckStatus -Key 'DISM' -Status 'UNKNOWN' -Detail $detail
        Write-DiagResult -Status 'ATTENTION' -Message $detail
    }

    if (Test-Path -LiteralPath $dismLog) {
        $newDismLog = Read-TextFileAuto -Path $dismLog -Offset $dismOffset
        $err = @(
            $newDismLog -split '\r?\n' |
            Where-Object {
                $_ -match 'Error|Failed|Corrupt|0x800f0915|repair content|Falling back to WU|Unable to repair' -and
                $_ -notmatch 'Failed to archive the log file'
            } |
            Select-Object -Last 30
        )
        if ($err.Count -gt 0) {
            Write-Log ''
            Write-Log 'DISM.log — строки, добавленные текущим ScanHealth (scoped evidence):'
            Write-Log ($err -join [Environment]::NewLine)
        }
    }
}
if (-not $continue) { break Diagnostics }

$continue = Invoke-Step `
    -Number 13 `
    -Title ("CHKDSK — онлайн-проверка {0} (/scan)" -f $env:SystemDrive) `
    -Long `
    -DeepKey 'CHKDSK' `
    -Action {

    if (-not $script:IsAdmin) {
        Write-Log 'ПРОПУСК: для CHKDSK /scan нужны права администратора.'
        Add-Attention 'CHKDSK /scan не выполнен из-за отсутствия административных прав.'
        Set-CheckStatus -Key 'CHKDSK' -Status 'SKIPPED' -Detail 'Нет административных прав.'
        return
    }

    Write-Log ("Команда: chkdsk.exe {0} /scan" -f $env:SystemDrive)
    Write-Log 'Прогресс показывался оператору и намеренно не записан в TXT.'

    $r = Invoke-NativeWithProgress `
        -FilePath (Join-Path $env:SystemRoot 'System32\chkdsk.exe') `
        -Arguments ("{0} /scan" -f $env:SystemDrive) `
        -Label ("CHKDSK {0} /scan" -f $env:SystemDrive)

    if ($r.ExitCodeKnown) {
        Write-Log ("ExitCode: {0}" -f $r.ExitCode)
    } else {
        Write-Log 'ExitCode: UNKNOWN (process already ended; semantic result will be used)'
    }
    Write-Log ("Duration: {0:n1} sec" -f $r.Duration.TotalSeconds)

    $text = [string]$r.Text
    $meaningful = Get-MeaningfulNativeLines -Text $text -MaxLines 18

    if ($meaningful.Count -gt 0) {
        Write-Log ''
        Write-Log 'Ключевой итог CHKDSK:'
        Write-Log ($meaningful -join [Environment]::NewLine)
    }

    $healthy = (
        $text -match 'Windows has scanned the file system and found no problems|не обнаружила проблем|не обнаружено проблем'
    )

    $problem = (
        $text -match 'found problems|found errors|Windows has made corrections|обнаружила неполадки|обнаружены ошибки|внесла исправления'
    )

    if ($problem) {
        $detail = 'CHKDSK сообщил о проблемах/исправлениях файловой системы.'
        Write-Log ("Result: ATTENTION — {0}" -f $detail)
        Add-Attention $detail
        Set-CheckStatus -Key 'CHKDSK' -Status 'ATTENTION' -Detail $detail
        Write-DiagResult -Status 'ATTENTION' -Message $detail
    } elseif ($healthy) {
        $detail = 'Windows проверила файловую систему и не обнаружила проблем.'
        Write-Log ("Result: OK — {0}" -f $detail)
        Set-CheckStatus -Key 'CHKDSK' -Status 'OK' -Detail $detail
        Write-DiagResult -Status 'OK' -Message $detail
    } elseif ($r.ExitCodeKnown -and $r.ExitCode -eq 0) {
        $detail = 'CHKDSK завершился успешно; автоматических маркеров ошибки файловой системы не обнаружено.'
        Write-Log ("Result: OK — {0}" -f $detail)
        Set-CheckStatus -Key 'CHKDSK' -Status 'OK' -Detail $detail
        Write-DiagResult -Status 'OK' -Message $detail
    } elseif ($r.ExitCodeKnown -and $r.ExitCode -ne 0) {
        $detail = "CHKDSK завершился с ExitCode {0}; итоговый текст не распознан." -f $r.ExitCode
        Write-Log ("Result: ATTENTION — {0}" -f $detail)
        Add-Attention $detail
        Set-CheckStatus -Key 'CHKDSK' -Status 'ATTENTION' -Detail $detail
        Write-DiagResult -Status 'ATTENTION' -Message $detail
    } else {
        $detail = 'Не удалось однозначно распознать итог CHKDSK.'
        Write-Log ("Result: UNKNOWN — {0}" -f $detail)
        Add-Attention $detail
        Set-CheckStatus -Key 'CHKDSK' -Status 'UNKNOWN' -Detail $detail
        Write-DiagResult -Status 'ATTENTION' -Message $detail
    }
}

if (-not $continue) { break Diagnostics }

$continue = Invoke-Step -Number 14 -Title 'BIOS, основные драйверы и firmware — контроль версий' -Action {
    Write-Log 'Назначение: дать компактный инвентарный срез ключевых версий и отметить компоненты, которые стоит проверить на обновление.'
    Write-Log 'ВАЖНО: локальный скрипт не может достоверно доказать, что версия является последней у OEM без внешнего источника.'
    Write-Log 'Статусы CHECK / REVIEW означают необходимость проверки, а не автоматическое требование обновления.'
    Write-Log ''
    Write-Log 'Контекст безопасности перед BIOS/UEFI обслуживанием (без ключей восстановления):'
    Write-ObjectLog (Get-BiosSafetyContext) -Format List
    Write-Log ''

    $now = Get-Date
    $inventory = New-Object System.Collections.Generic.List[object]

    function Get-AgeMonthsLocal {
        param($DateValue)
        if ($null -eq $DateValue) { return $null }
        try {
            $d = [datetime]$DateValue
            if ($d.Year -lt 2009) { return $null }
            return [int][math]::Floor(($now - $d).TotalDays / 30.4375)
        } catch {
            return $null
        }
    }

    function Get-DriverReviewLocal {
        param(
            [string]$Provider,
            $DriverDate
        )

        $age = Get-AgeMonthsLocal $DriverDate

        if ($Provider -match 'Microsoft') {
            return 'WINDOWS/WU'
        }

        if ($null -eq $age) {
            return 'CHECK'
        }

        if ($age -ge 36) {
            return 'REVIEW OLD'
        }

        if ($age -ge 24) {
            return 'CHECK'
        }

        return 'NO AGE FLAG'
    }

    function Add-DriverRowsLocal {
        param(
            [string]$Component,
            [object[]]$Drivers
        )

        foreach ($d in @($Drivers)) {
            if ($null -eq $d) { continue }

            $age = Get-AgeMonthsLocal $d.DriverDate
            $dateText = ''
            $driverDateObj = $null
            try {
                if ($null -ne $d.DriverDate) {
                    $driverDateObj = [datetime]$d.DriverDate
                    if ($driverDateObj.Year -lt 2009) {
                        $dateText = 'SYSTEM/INF'
                    } else {
                        $dateText = $driverDateObj.ToString('yyyy-MM-dd')
                    }
                }
            } catch {}

            $review = Get-DriverReviewLocal -Provider ([string]$d.DriverProviderName) -DriverDate $d.DriverDate
            if ($null -ne $driverDateObj -and $driverDateObj.Year -lt 2009 -and ([string]$d.DriverProviderName) -notmatch 'Microsoft') {
                $review = 'OEM/WU'
            }

            [void]$inventory.Add([PSCustomObject]@{
                Component = $Component
                Device    = [string]$d.DeviceName
                Version   = [string]$d.DriverVersion
                Date_FW   = $dateText
                Provider  = [string]$d.DriverProviderName
                AgeMonths = $(if ($null -eq $age) { '' } else { $age })
                Update    = $review
            })
        }
    }

    # Present devices only, to avoid stale driver packages from removed hardware.
    $presentIds = @{}
    try {
        Get-PnpDevice -PresentOnly -ErrorAction Stop | ForEach-Object {
            if (-not [string]::IsNullOrWhiteSpace($_.InstanceId)) {
                $presentIds[$_.InstanceId.ToUpperInvariant()] = $true
            }
        }
    } catch {}

    $signedDrivers = @()
    try {
        $signedDrivers = @(
            Get-CompatInstance Win32_PnPSignedDriver -ErrorAction Stop |
            Where-Object {
                if ([string]::IsNullOrWhiteSpace($_.DeviceID)) {
                    return $false
                }

                if ($presentIds.Count -eq 0) {
                    return $true
                }

                return $presentIds.ContainsKey($_.DeviceID.ToUpperInvariant())
            }
        )
    } catch {
        Write-Log ("Win32_PnPSignedDriver недоступен: {0}" -f $_.Exception.Message)
    }

    # BIOS / motherboard
    try {
        $bios = Get-CompatInstance Win32_BIOS -ErrorAction Stop
        $bb   = Get-CompatInstance Win32_BaseBoard -ErrorAction Stop

        $biosAge = Get-AgeMonthsLocal $bios.ReleaseDate
        $biosUpdate = 'OEM CHECK'
        if ($null -ne $biosAge -and $biosAge -ge 36) {
            $biosUpdate = 'REVIEW OEM'
        }

        [void]$inventory.Add([PSCustomObject]@{
            Component = 'BIOS / UEFI'
            Device    = ("{0} {1} rev {2}" -f $bb.Manufacturer, $bb.Product, $bb.Version).Trim()
            Version   = [string]$bios.SMBIOSBIOSVersion
            Date_FW   = $(try { ([datetime]$bios.ReleaseDate).ToString('yyyy-MM-dd') } catch { '' })
            Provider  = [string]$bios.Manufacturer
            AgeMonths = $(if ($null -eq $biosAge) { '' } else { $biosAge })
            Update    = $biosUpdate
        })
    } catch {
        [void]$inventory.Add([PSCustomObject]@{
            Component='BIOS / UEFI'; Device='Не удалось получить BIOS/BaseBoard'; Version=''; Date_FW=''; Provider=''; AgeMonths=''; Update='UNKNOWN'
        })
    }

    # CPU: there is no meaningful separate OEM "CPU driver" to compare like GPU/LAN.
    # Microcode/platform fixes normally arrive through BIOS/UEFI and Windows Update.
    try {
        $cpu = Get-CompatInstance Win32_Processor -ErrorAction Stop | Select-Object -First 1
        [void]$inventory.Add([PSCustomObject]@{
            Component = 'CPU / microcode'
            Device    = [string]$cpu.Name
            Version   = 'platform-managed'
            Date_FW   = ''
            Provider  = [string]$cpu.Manufacturer
            AgeMonths = ''
            Update    = 'BIOS/WU'
        })
    } catch {}

    # Chipset / Management Engine / AMD PSP representative platform drivers.
    $platform = @(
        $signedDrivers | Where-Object {
            $_.DeviceClass -match '^SYSTEM$' -and
            $_.DeviceName -match 'Management Engine|SMBus|Chipset|Platform Security Processor|PSP'
        } | Sort-Object DeviceName -Unique
    )
    if ($platform.Count -gt 0) {
        Add-DriverRowsLocal -Component 'Chipset / ME' -Drivers $platform
    }

    # Display
    $video = @(
        $signedDrivers | Where-Object {
            $_.DeviceClass -match '^DISPLAY$' -and $_.DeviceName -notmatch '^Microsoft Remote Display Adapter$'
        } | Sort-Object DeviceName -Unique
    )
    if ($video.Count -gt 0) {
        Add-DriverRowsLocal -Component 'Video' -Drivers $video
    }

    # Audio: prefer real MEDIA devices; skip common software/virtual filters where possible.
    $audio = @(
        $signedDrivers | Where-Object {
            $_.DeviceClass -match '^MEDIA$' -and
            $_.DeviceName -notmatch 'Virtual|Streaming|Capture|Sonic|Nahimic|Voicemeeter'
        } | Sort-Object DeviceName -Unique
    )
    if ($audio.Count -gt 0) {
        Add-DriverRowsLocal -Component 'Audio' -Drivers $audio
    }

    # Physical network adapters; ignore WAN/Bluetooth virtual entries.
    $network = @(
        $signedDrivers | Where-Object {
            $_.DeviceClass -match '^NET$' -and
            $_.DeviceName -notmatch 'WAN Miniport|Bluetooth|Virtual|TAP|VPN|Loopback|Kernel Debug|Debug Network'
        } | Sort-Object DeviceName -Unique
    )
    if ($network.Count -gt 0) {
        Add-DriverRowsLocal -Component 'Network' -Drivers $network
    }

    # Storage controllers: show controllers relevant to the buses of installed physical disks.
    $physical = @()
    try { $physical = @(Get-PhysicalDisk -ErrorAction Stop) } catch {}
    $busTypes = @($physical | ForEach-Object { [string]$_.BusType } | Where-Object { $_ } | Select-Object -Unique)

    $storageDrivers = @(
        $signedDrivers | Where-Object {
            if ($_.DeviceClass -notmatch '^(SCSIADAPTER|HDC)$') { return $false }
            if ($_.DeviceName -match 'Storage Spaces Controller') { return $false }

            $name = [string]$_.DeviceName
            if ($busTypes -contains 'NVMe' -and $name -match 'NVM|NVMe') { return $true }
            if (($busTypes -contains 'SATA' -or $busTypes -contains 'RAID') -and $name -match 'AHCI|SATA|RAID') { return $true }
            if ($busTypes.Count -eq 0 -and $name -match 'NVM|NVMe|AHCI|SATA|RAID|SCSI') { return $true }
            return $false
        } | Sort-Object DeviceName -Unique
    )
    if ($storageDrivers.Count -gt 0) {
        Add-DriverRowsLocal -Component 'Storage driver' -Drivers $storageDrivers
    }

    # Physical disk firmware.
    try {
        if ($physical.Count -eq 0) { $physical = @(Get-PhysicalDisk -ErrorAction Stop) }
        foreach ($disk in $physical) {
            [void]$inventory.Add([PSCustomObject]@{
                Component = 'Disk firmware'
                Device    = [string]$disk.FriendlyName
                Version   = [string]$disk.FirmwareVersion
                Date_FW   = ''
                Provider  = $(if ([string]::IsNullOrWhiteSpace([string]$disk.Manufacturer)) { 'OEM' } else { [string]$disk.Manufacturer })
                AgeMonths = ''
                Update    = 'OEM CHECK'
            })
        }
    } catch {
        Write-Log ("Get-PhysicalDisk firmware inventory недоступен: {0}" -f $_.Exception.Message)
    }

    if ($inventory.Count -eq 0) {
        Write-Log 'Не удалось сформировать инвентарь BIOS/основных драйверов.'
        Set-CheckStatus -Key 'BIOS / Drivers' -Status 'UNKNOWN' -Detail 'Инвентарь ключевых версий не получен.'
        return
    }

    Write-Log 'Краткая таблица:'
    Write-ObjectLog $inventory -Format Table

    Write-Log ''
    Write-Log 'Легенда Update:'
    Write-Log '  NO AGE FLAG = по возрасту драйвера нет автоматического повода для проверки; это НЕ подтверждение latest.'
    Write-Log '  CHECK       = версию разумно сверить с Windows Update / OEM.'
    Write-Log '  REVIEW OLD  = драйвер старше ~36 месяцев; приоритетная ручная сверка.'
    Write-Log '  WINDOWS/WU  = системный Microsoft-драйвер; обновляется вместе с Windows / Windows Update.'
    Write-Log '  OEM/WU      = служебная/синтетическая дата INF; проверять через OEM / Windows Update, возраст не оценивается.'
    Write-Log '  OEM CHECK   = сверить BIOS/firmware с официальным источником производителя.'
    Write-Log '  REVIEW OEM  = BIOS старше ~36 месяцев; приоритетно сверить с официальной страницей платы.'
    Write-Log '  BIOS/WU     = CPU microcode / platform fixes обычно приходят через BIOS и Windows Update.'

    $reviewRows = @(
        $inventory | Where-Object {
            $_.Update -in @('REVIEW OLD','REVIEW OEM')
        }
    )

    $checkRows = @(
        $inventory | Where-Object {
            $_.Update -eq 'CHECK'
        }
    )

    $oemCheckRows = @(
        $inventory | Where-Object {
            $_.Update -in @('OEM CHECK','OEM/WU')
        }
    )

    if ($reviewRows.Count -gt 0) {
        $detail = "Версии собраны; REVIEW по возрасту: {0}; CHECK: {1}; OEM/WU verification: {2}. Возраст сам по себе не означает неисправность." -f $reviewRows.Count, $checkRows.Count, $oemCheckRows.Count
        Set-CheckStatus -Key 'BIOS / Drivers' -Status 'REVIEW' -Detail $detail
    } elseif ($checkRows.Count -gt 0) {
        $detail = "Версии собраны; CHECK: {0}; OEM/WU verification: {1}. Latest требует внешней сверки." -f $checkRows.Count, $oemCheckRows.Count
        Set-CheckStatus -Key 'BIOS / Drivers' -Status 'REVIEW' -Detail $detail
    } else {
        $detail = "Версии собраны; возрастных CHECK/REVIEW флагов нет; OEM/WU verification: {0}. Latest требует внешней сверки." -f $oemCheckRows.Count
        Set-CheckStatus -Key 'BIOS / Drivers' -Status 'INFO' -Detail $detail
    }
}
if (-not $continue) { break Diagnostics }

break Diagnostics
}

$EndTime = Get-Date

Write-Section 'EXPC DIAGNOSTIC SUMMARY'

if ($script:Checks.Count -gt 0) {
    $summary = @(
        foreach ($entry in $script:Checks.GetEnumerator()) {
            [PSCustomObject]@{
                Check  = $entry.Value.Check
                Status = $entry.Value.Status
                Detail = $entry.Value.Detail
            }
        }
    )
    Write-ObjectLog $summary -Format Table
} else {
    Write-Log '(нет данных summary)'
}

Write-Section 'ИТОГОВЫЕ МАРКЕРЫ ДЛЯ ИНЖЕНЕРНОГО РАЗБОРА'
Write-Log 'Принцип EXPC: цель — надёжное рабочее состояние; REVIEW/INFO и остаточные маркеры без практического влияния не требуют ремонта ради идеального отчёта.'
Write-Log ''

if ($script:Attention.Count -gt 0) {
    $i = 1
    foreach ($item in $script:Attention) {
        Write-Log ("{0}. {1}" -f $i, $item)
        $i++
    }
} else {
    Write-Log 'Автоматические маркеры внимания не сработали.'
    Write-Log 'Это НЕ означает, что система гарантированно исправна: требуется инженерная интерпретация отчёта.'
}

Write-Section 'ЗАВЕРШЕНИЕ'
Write-Log ("Finished         : {0:yyyy-MM-dd HH:mm:ss}" -f $EndTime)
Write-Log ("Duration         : {0:n1} minutes" -f (($EndTime - $StartTime).TotalMinutes))
Write-Log ("Log              : {0}" -f $LogPath)
Write-Log ("JSON             : {0}" -f $JsonPath)
Write-Log 'Recommendation   : передайте этот TXT для инженерного анализа. Не выполняйте ремонтные команды только по автоматическому маркеру.'

$jsonReport = [PSCustomObject][ordered]@{
    Tool='EXPC Diagnostic'; Version=$ScriptVersion; GeneratedAt=$EndTime.ToString('o'); StartedAt=$StartTime.ToString('o')
    ReadOnly=$true; Company=$CompanyName; Station=$StationName; Computer=$ComputerName; Mode=$script:Mode
    Checks=@($script:Checks.GetEnumerator() | ForEach-Object { $_.Value }); Attention=@($script:Attention); TxtPath=$LogPath; JsonPath=$JsonPath
}
$jsonStream = [IO.File]::Open($JsonPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
$jsonWriter = New-Object IO.StreamWriter($jsonStream,$script:Utf8Bom)
try { $jsonWriter.Write(($jsonReport | ConvertTo-Json -Depth 8)) } finally { $jsonWriter.Dispose() }

Write-Host ''
Write-Host '============================================================' -ForegroundColor Blue
Write-Host ' EXPC Diagnostic завершён.' -ForegroundColor Green
Write-Host '============================================================' -ForegroundColor Blue
Write-Host 'Лог создан:' -ForegroundColor White
Write-Host $LogPath -ForegroundColor Cyan
Write-Host $JsonPath -ForegroundColor Cyan
Write-Host ''
Write-Host 'Передайте этот TXT для инженерного разбора EXPC.' -ForegroundColor Yellow
Write-Host ''
Read-Host 'Нажмите Enter для выхода'
