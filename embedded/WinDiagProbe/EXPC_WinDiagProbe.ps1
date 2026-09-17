#requires -Version 5.0
[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ScriptLaunchTime = Get-Date
Import-Module (Join-Path $PSScriptRoot 'Compatibility.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'ReportStorage.psm1') -Force
$RuntimeInfo = Get-CompatRuntimeInfo
$OutputDirectory = Get-WinDiagReportDirectory -Ensure

function New-ModuleResult {
    param([string]$Status = 'UNKNOWN', [object]$Data = $null, [string[]]$Errors = @())
    [PSCustomObject]@{ Status = $Status; Data = $Data; Errors = @($Errors) }
}

function Convert-CimDate {
    param([object]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return $Value.ToString('o') }
    try { return ([Management.ManagementDateTimeConverter]::ToDateTime([string]$Value)).ToString('o') } catch { return [string]$Value }
}

function ConvertTo-SafeFileToken {
    param(
        [AllowEmptyString()][string]$Text,
        [string]$Fallback = ''
    )

    $value = [string]$Text
    if ([string]::IsNullOrWhiteSpace($value)) { $value = [string]$Fallback }
    $value = $value.Trim()
    $value = $value -replace '[\\/:*?"<>|]', '_'
    $value = $value -replace '\s+', '_'
    $value = $value -replace '_{2,}', '_'
    $value = $value -replace '^_+|_+$', ''
    $value = $value.Trim().TrimEnd('.')
    if ($value -match '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?$') { $value = '_' + $value }
    return $value
}

function New-WinDiagProbeReportBaseName {
    param(
        [Parameter(Mandatory = $true)][string]$Computer,
        [Parameter(Mandatory = $true)][datetime]$RunStartedAt
    )

    return New-WinDiagReportBaseName -Prefix WinDiagProbe -RunStartedAt $RunStartedAt
}

function Get-SystemSnapshot {
    try {
        $errors = @()
        $os = $null
        $cs = $null
        $cpu = @()
        try { $os = Get-CompatInstance Win32_OperatingSystem } catch { $errors += "Win32_OperatingSystem: $($_.Exception.Message)" }
        try { $cs = Get-CompatInstance Win32_ComputerSystem } catch { $errors += "Win32_ComputerSystem: $($_.Exception.Message)" }
        try { $cpu = @(Get-CompatInstance Win32_Processor) } catch { $errors += "Win32_Processor: $($_.Exception.Message)" }
        $driveId = if ($env:SystemDrive) { $env:SystemDrive } else { 'C:' }
        try { $drive = Get-CompatInstance Win32_LogicalDisk -Filter "DeviceID='$driveId'" } catch { $drive = $null; $errors += "Win32_LogicalDisk: $($_.Exception.Message)" }
        try { $pageSettings = @(Get-CompatInstance Win32_PageFileSetting) } catch { $pageSettings = @(); $errors += $_.Exception.Message }
        try { $pageUsage = @(Get-CompatInstance Win32_PageFileUsage) } catch { $pageUsage = @(); $errors += $_.Exception.Message }
        try { $windowsInfo = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' } catch { $windowsInfo = $null; $errors += "Windows registry metadata: $($_.Exception.Message)" }
        $lastBoot = if ($os -and $os.LastBootUpTime) { [datetime]$os.LastBootUpTime } else { $null }
        $edition = if ($os) { $os.Caption } elseif ($windowsInfo.ProductName) { $windowsInfo.ProductName } else { 'Unavailable' }
        $displayVersion = if ($os) { $os.Version } elseif ($windowsInfo.DisplayVersion) { $windowsInfo.DisplayVersion } else { [Environment]::OSVersion.Version.ToString() }
        $build = if ($os) { $os.BuildNumber } elseif ($windowsInfo.CurrentBuildNumber) { $windowsInfo.CurrentBuildNumber } else { [Environment]::OSVersion.Version.Build }
        $cpuName = if ($cpu.Count -gt 0) { (($cpu | ForEach-Object Name) -join '; ') } elseif ($env:PROCESSOR_IDENTIFIER) { $env:PROCESSOR_IDENTIFIER } else { 'Unavailable' }
        $totalRam = if ($cs) { [uint64]$cs.TotalPhysicalMemory } else { $null }
        $availableRam = if ($os) { [uint64]$os.FreePhysicalMemory * 1KB } else { $null }
        $automaticPageFile = if ($cs -and $null -ne $cs.AutomaticManagedPagefile) { [bool]$cs.AutomaticManagedPagefile } else { $null }
        $pageFileMode = if ($automaticPageFile -eq $true) { 'SYSTEM_MANAGED' } elseif ($automaticPageFile -eq $false) { 'CUSTOM' } else { 'UNKNOWN' }
        $data = [PSCustomObject]@{
            ComputerName = $env:COMPUTERNAME
            WindowsEdition = $edition
            WindowsVersion = $displayVersion
            WindowsBuild = $build
            InstallationDate = if ($os) { Convert-CimDate $os.InstallDate } elseif ($windowsInfo.InstallDate) { ([datetime]'1970-01-01Z').AddSeconds([double]$windowsInfo.InstallDate).ToLocalTime().ToString('o') } else { $null }
            LastBoot = if ($lastBoot) { $lastBoot.ToString('o') } else { $null }
            UptimeSeconds = if ($lastBoot) { [math]::Round(((Get-Date) - $lastBoot).TotalSeconds) } else { $null }
            CPU = [PSCustomObject]@{
                Name = $cpuName
                PhysicalCores = if ($cpu.Count -gt 0) { [int](($cpu | Measure-Object NumberOfCores -Sum).Sum) } else { $null }
                LogicalProcessors = if ($cpu.Count -gt 0) { [int](($cpu | Measure-Object NumberOfLogicalProcessors -Sum).Sum) } else { [Environment]::ProcessorCount }
            }
            RAM = [PSCustomObject]@{
                TotalBytes = $totalRam
                AvailableBytes = $availableRam
            }
            SystemDrive = [PSCustomObject]@{
                DeviceID = $driveId
                SizeBytes = if ($drive) { [uint64]$drive.Size } else { $null }
                FreeBytes = if ($drive) { [uint64]$drive.FreeSpace } else { $null }
            }
            PageFileConfiguration = @($pageSettings | ForEach-Object {
                [PSCustomObject]@{ Name = $_.Name; InitialSizeMB = $_.InitialSize; MaximumSizeMB = $_.MaximumSize; SystemManaged = ($automaticPageFile -eq $true) }
            })
            PageFileUsage = @($pageUsage | ForEach-Object {
                [PSCustomObject]@{ Name = $_.Name; AllocatedBaseSizeMB = $_.AllocatedBaseSize; CurrentUsageMB = $_.CurrentUsage; PeakUsageMB = $_.PeakUsage }
            })
            PageFile = [PSCustomObject]@{
                ManagementMode = $pageFileMode
                AutomaticManaged = $automaticPageFile
                Configuration = @($pageSettings | ForEach-Object { [PSCustomObject]@{ Name = $_.Name; InitialSizeMB = $_.InitialSize; MaximumSizeMB = $_.MaximumSize } })
                Usage = @($pageUsage | ForEach-Object { [PSCustomObject]@{ Name = $_.Name; AllocatedBaseSizeMB = $_.AllocatedBaseSize; CurrentUsageMB = $_.CurrentUsage; PeakUsageMB = $_.PeakUsage } })
            }
        }
        New-ModuleResult -Status $(if ($os -or $windowsInfo) { 'OK' } else { 'UNKNOWN' }) -Data $data -Errors $errors
    } catch {
        New-ModuleResult -Errors @($_.Exception.Message)
    }
}

function Get-CpuSample {
    try {
        $errors = @()
        $samples = @()
        $sampleCount = 3
        $intervalMilliseconds = 500
        for ($index = 0; $index -lt $sampleCount; $index++) {
            try {
                $counter = Get-CompatInstance Win32_PerfFormattedData_PerfOS_Processor -Filter "Name='_Total'"
                if ($null -ne $counter.PercentProcessorTime) {
                    $samples += [PSCustomObject]@{ Timestamp = (Get-Date).ToString('o'); ProcessorTimePercent = [double]$counter.PercentProcessorTime }
                }
            } catch { $errors += $_.Exception.Message; break }
            if ($index -lt ($sampleCount - 1)) { Start-Sleep -Milliseconds $intervalMilliseconds }
        }
        $values = @($samples | ForEach-Object ProcessorTimePercent)
        if ($values.Count -gt 0) {
            $measure = $values | Measure-Object -Average -Minimum -Maximum
            $data = [PSCustomObject]@{
                DurationMilliseconds = ($sampleCount - 1) * $intervalMilliseconds
                SampleCount = $values.Count
                AveragePercent = [math]::Round([double]$measure.Average, 2)
                MinimumPercent = [math]::Round([double]$measure.Minimum, 2)
                MaximumPercent = [math]::Round([double]$measure.Maximum, 2)
                Samples = $samples
            }
            New-ModuleResult -Status 'OK' -Data $data -Errors $errors
        } else {
            New-ModuleResult -Status 'UNKNOWN' -Data ([PSCustomObject]@{ DurationMilliseconds = ($sampleCount - 1) * $intervalMilliseconds; SampleCount = 0; AveragePercent = $null; MinimumPercent = $null; MaximumPercent = $null; Samples = @() }) -Errors $errors
        }
    } catch {
        New-ModuleResult -Errors @($_.Exception.Message)
    }
}

function Get-MemoryHealth {
    try {
        $errors = @()
        $os = Get-CompatInstance Win32_OperatingSystem
        $total = [double]$os.TotalVisibleMemorySize * 1KB
        $available = [double]$os.FreePhysicalMemory * 1KB
        $availablePct = if ($total -gt 0) { [math]::Round(($available / $total) * 100, 2) } else { $null }
        $perf = $null
        try { $perf = Get-CompatInstance Win32_PerfFormattedData_PerfOS_Memory } catch { $errors += $_.Exception.Message }

        $committed = if ($perf) { [double]$perf.CommittedBytes } else { $null }
        $commitLimit = if ($perf) { [double]$perf.CommitLimit } else { $null }
        $commitPct = if ($null -ne $committed -and $commitLimit -gt 0) { [math]::Round(($committed / $commitLimit) * 100, 2) } else { $null }
        $status = if (($null -ne $availablePct -and $availablePct -lt 10) -or ($null -ne $commitPct -and $commitPct -gt 85)) { 'ATTENTION' } elseif ($null -eq $availablePct) { 'UNKNOWN' } else { 'OK' }
        $data = [PSCustomObject]@{
            PhysicalTotalBytes = [uint64]$total
            AvailableBytes = [uint64]$available
            AvailablePercent = $availablePct
            CommitUsedBytes = if ($null -ne $committed) { [uint64]$committed } else { $null }
            CommitLimitBytes = if ($null -ne $commitLimit) { [uint64]$commitLimit } else { $null }
            CommitPercent = $commitPct
            PagedPoolBytes = if ($perf) { [uint64]$perf.PoolPagedBytes } else { $null }
            NonpagedPoolBytes = if ($perf) { [uint64]$perf.PoolNonpagedBytes } else { $null }
            PagesPerSec = if ($perf) { [double]$perf.PagesPersec } else { $null }
            PageReadsPerSec = if ($perf) { [double]$perf.PageReadsPersec } else { $null }
            PageWritesPerSec = if ($perf) { [double]$perf.PageWritesPersec } else { $null }
            Signals = @(
                if ($null -ne $availablePct -and $availablePct -lt 10) { 'Available RAM is below 10%.' }
                if ($null -ne $commitPct -and $commitPct -gt 85) { 'Commit usage is above 85%.' }
            )
        }
        New-ModuleResult -Status $status -Data $data -Errors $errors
    } catch {
        New-ModuleResult -Errors @($_.Exception.Message)
    }
}

function Convert-TerminalSessionState {
    param([string]$RawState, [bool]$IsCurrent = $false)
    if ($IsCurrent) { return 'ACTIVE' }
    if ([string]::IsNullOrWhiteSpace($RawState)) { return 'OTHER' }

    $stateKey = $RawState.Trim().ToUpperInvariant()
    if ($stateKey -eq 'ACTIVE') { return 'ACTIVE' }
    if ($stateKey -eq 'DISC' -or $stateKey -eq 'DISCONNECTED') { return 'DISCONNECTED' }

    # Keep the script ASCII-safe for Windows PowerShell 5.1 while recognizing
    # Russian quser states: Active, Disc, and Disconnected.
    $russianActive = -join ([char[]](0x0410, 0x041A, 0x0422, 0x0418, 0x0412, 0x041D, 0x041E))
    $russianDisc = -join ([char[]](0x0414, 0x0418, 0x0421, 0x041A))
    $russianDisconnected = -join ([char[]](0x041E, 0x0422, 0x041A, 0x041B, 0x042E, 0x0427, 0x0415, 0x041D, 0x041E))
    if ($stateKey -eq $russianActive) { return 'ACTIVE' }
    if ($stateKey -eq $russianDisc -or $stateKey -eq $russianDisconnected) { return 'DISCONNECTED' }
    return 'OTHER'
}

function Get-MultiUserRdpState {
    try {
        $errors = @()
        try {
            $termService = Get-CompatInstance Win32_Service -Filter "Name='TermService'"
            $termServiceState = if ($termService) { [string]$termService.State } else { 'NOT_FOUND' }
        } catch { $termService = $null; $termServiceState = 'UNKNOWN'; $errors += "TermService: $($_.Exception.Message)" }
        try {
            $terminalServerConfig = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
            $rdpEnabled = [int]$terminalServerConfig.fDenyTSConnections -eq 0
        } catch { $rdpEnabled = $null; $errors += "RDP configuration: $($_.Exception.Message)" }

        $sessions = @()
        try {
            $quserOutput = @(& "$env:SystemRoot\System32\quser.exe" 2>&1 | ForEach-Object { [string]$_ })
            if ($LASTEXITCODE -eq 0) {
                foreach ($line in @($quserOutput | Select-Object -Skip 1)) {
                    if ($line -match '^\s*(?<current>>?)(?<prefix>.*?)\s+(?<id>\d+)\s+(?<state>\S+)(?:\s+.*)?$') {
                        $capturedPrefix = $Matches.prefix
                        $capturedSessionId = [int]$Matches.id
                        $capturedState = $Matches.state
                        $capturedCurrent = $Matches.current
                        $prefixParts = @($capturedPrefix.Trim() -split '\s+' | Where-Object { $_ })
                        $userName = if ($prefixParts.Count -gt 0) { $prefixParts[0] } else { $null }
                        $sessionName = if ($prefixParts.Count -gt 1) { $prefixParts[1] } else { $null }
                        $rawState = $capturedState
                        $normalizedState = Convert-TerminalSessionState -RawState $rawState -IsCurrent ($capturedCurrent -eq '>')
                        $sessions += [PSCustomObject]@{
                            UserName = $userName
                            SessionName = $sessionName
                            SessionId = $capturedSessionId
                            State = $normalizedState
                            RawState = $rawState
                            IsCurrent = ($capturedCurrent -eq '>')
                        }
                    }
                }
            } elseif (($quserOutput -join ' ') -notmatch '(?i)no user exists') {
                $errors += "quser exit code $LASTEXITCODE`: $(($quserOutput -join ' ').Trim())"
            }
        } catch { $errors += "quser: $($_.Exception.Message)" }

        $wrapperPaths = @(
            (Join-Path $env:ProgramFiles 'RDP Wrapper\rdpwrap.dll'),
            (Join-Path $env:ProgramFiles 'RDP Wrapper\rdpwrap.ini')
        )
        if (${env:ProgramFiles(x86)}) {
            $wrapperPaths += Join-Path ${env:ProgramFiles(x86)} 'RDP Wrapper\rdpwrap.dll'
            $wrapperPaths += Join-Path ${env:ProgramFiles(x86)} 'RDP Wrapper\rdpwrap.ini'
        }
        $detectedFiles = @($wrapperPaths | Where-Object { Test-Path -LiteralPath $_ } | ForEach-Object {
            $item = Get-Item -LiteralPath $_
            [PSCustomObject]@{ Path = $item.FullName; Version = if ($item.Extension -eq '.dll') { $item.VersionInfo.FileVersion } else { $null } }
        })
        try {
            $termServiceParameters = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\TermService\Parameters'
            $serviceDll = [string]$termServiceParameters.ServiceDll
        } catch { $serviceDll = $null; $errors += "TermService ServiceDll: $($_.Exception.Message)" }
        try {
            $wrapperServices = @(Get-CompatInstance Win32_Service | Where-Object { ($_.Name + ' ' + $_.DisplayName + ' ' + $_.PathName) -match '(?i)rdpwrap|rdp wrapper' } | ForEach-Object {
                [PSCustomObject]@{ Name = $_.Name; State = $_.State; PathName = $_.PathName }
            })
        } catch { $wrapperServices = @(); $errors += "RDP Wrapper services: $($_.Exception.Message)" }
        $wrapperPresent = $detectedFiles.Count -gt 0 -or $wrapperServices.Count -gt 0 -or $serviceDll -match '(?i)rdpwrap'
        $wrapperStatus = if ($wrapperPresent) { 'PRESENT' } elseif (@($errors | Where-Object { $_ -match 'ServiceDll|Wrapper services' }).Count -ge 2) { 'UNKNOWN' } else { 'NOT_DETECTED' }
        $activeCount = @($sessions | Where-Object State -eq 'ACTIVE').Count
        $disconnectedCount = @($sessions | Where-Object State -eq 'DISCONNECTED').Count
        $data = [PSCustomObject]@{
            TermServiceState = $termServiceState.ToUpperInvariant()
            RDPEnabled = $rdpEnabled
            SessionCount = $sessions.Count
            ActiveSessionCount = $activeCount
            DisconnectedSessionCount = $disconnectedCount
            Sessions = $sessions
            RDPWrapper = [PSCustomObject]@{
                Status = $wrapperStatus
                Present = if ($wrapperStatus -eq 'PRESENT') { $true } elseif ($wrapperStatus -eq 'NOT_DETECTED') { $false } else { $null }
                DetectedFiles = $detectedFiles
                Services = $wrapperServices
                TermServiceServiceDll = $serviceDll
            }
        }
        New-ModuleResult -Status 'INFO' -Data $data -Errors $errors
    } catch { New-ModuleResult -Status 'INFO' -Data $null -Errors @($_.Exception.Message) }
}

function Get-TopProcesses {
    param([object[]]$Sessions = @())
    try {
        $errors = @()
        $sessionUsers = @{}
        foreach ($session in @($Sessions)) {
            if ($null -ne $session.SessionId -and -not [string]::IsNullOrWhiteSpace([string]$session.UserName)) { $sessionUsers[[string]$session.SessionId] = [string]$session.UserName }
        }
        $items = foreach ($process in @(Get-Process -ErrorAction SilentlyContinue)) {
            try {
                $sessionId = try { [int]$process.SessionId } catch { $null }
                [PSCustomObject]@{
                    ProcessName = $process.ProcessName
                    PID = $process.Id
                    SessionId = $sessionId
                    UserName = if ($null -ne $sessionId -and $sessionUsers.ContainsKey([string]$sessionId)) { $sessionUsers[[string]$sessionId] } else { $null }
                    WorkingSetMB = [math]::Round($process.WorkingSet64 / 1MB, 2)
                    PrivateMB = [math]::Round($process.PrivateMemorySize64 / 1MB, 2)
                    Handles = $process.HandleCount
                    Threads = @($process.Threads).Count
                    CPUSeconds = if ($null -ne $process.CPU) { [math]::Round($process.CPU, 2) } else { $null }
                }
            } catch { $errors += "PID $($process.Id): $($_.Exception.Message)" }
        }
        $data = [PSCustomObject]@{
            ByWorkingSet = @($items | Sort-Object WorkingSetMB -Descending | Select-Object -First 10)
            ByPrivateMemory = @($items | Sort-Object PrivateMB -Descending | Select-Object -First 10)
            ByHandles = @($items | Sort-Object Handles -Descending | Select-Object -First 10)
            ByThreads = @($items | Sort-Object Threads -Descending | Select-Object -First 10)
            ByCPUTime = @($items | Sort-Object CPUSeconds -Descending | Select-Object -First 10)
        }
        New-ModuleResult -Status 'OK' -Data $data -Errors $errors
    } catch {
        New-ModuleResult -Errors @($_.Exception.Message)
    }
}

function Get-DriverState {
    try {
        $errors = @()
        $drivers = @()
        try { $drivers = @(Get-CompatInstance Win32_PnPSignedDriver) } catch { $errors += $_.Exception.Message }
        $driverRows = @($drivers | ForEach-Object {
            $problemCodeProperty = $_.PSObject.Properties['ProblemCode']
            if ($null -eq $problemCodeProperty) { $problemCodeProperty = $_.PSObject.Properties['ConfigManagerErrorCode'] }
            $problemCode = if ($null -ne $problemCodeProperty) { $problemCodeProperty.Value } else { $null }
            [PSCustomObject]@{
                DeviceName = $_.DeviceName
                Manufacturer = $_.Manufacturer
                IsSigned = $_.IsSigned
                ProblemCode = $problemCode
                DriverDate = Convert-CimDate $_.DriverDate
                DriverVersion = $_.DriverVersion
            }
        })
        $unsigned = @($driverRows | Where-Object { $_.IsSigned -eq $false })
        $problematic = @($driverRows | Where-Object { $null -ne $_.ProblemCode -and [int]$_.ProblemCode -ne 0 })
        $verifierState = 'UNKNOWN'
        $verifierOutput = @()
        try {
            $verifierOutput = @(& "$env:SystemRoot\System32\verifier.exe" /querysettings 2>&1 | ForEach-Object { [string]$_ })
            $verifierFlags = $null
            foreach ($verifierLine in $verifierOutput) {
                $flagsMatch = [regex]::Match($verifierLine, '^\s*[^:\r\n]+:\s*(0x[0-9A-Fa-f]+)\s*$')
                if ($flagsMatch.Success) {
                    $verifierFlags = [Convert]::ToUInt64($flagsMatch.Groups[1].Value.Substring(2), 16)
                    break
                }
            }
            if ($null -ne $verifierFlags) {
                $verifierState = if ($verifierFlags -eq 0) { 'DISABLED' } else { 'ENABLED' }
            }
        } catch { $errors += $_.Exception.Message }
        $data = [PSCustomObject]@{
            InstalledSignedDriversCount = @($driverRows | Where-Object IsSigned -eq $true).Count
            InstalledDriversCount = $drivers.Count
            UnsignedDrivers = $unsigned
            UnknownSignatureDrivers = @($driverRows | Where-Object { $null -eq $_.IsSigned })
            ProblematicDrivers = $problematic
            DriverInventory = $driverRows
            DriverVerifier = [PSCustomObject]@{ State = $verifierState; QueryOutput = $verifierOutput }
        }
        $status = if ($drivers.Count -eq 0) { 'UNKNOWN' } elseif (($unsigned.Count + $problematic.Count) -gt 0) { 'ATTENTION' } else { 'OK' }
        New-ModuleResult -Status $status -Data $data -Errors $errors
    } catch {
        New-ModuleResult -Errors @($_.Exception.Message)
    }
}

function Get-EventAggregate {
    param([string]$LogName, [int[]]$Ids, [string[]]$Providers, [datetime]$StartTime, [switch]$IncludeApplication)
    $events = @(Get-WinEvent -FilterHashtable @{ LogName = $LogName; Id = $Ids; StartTime = $StartTime } -ErrorAction Stop |
        Where-Object { $Providers -contains $_.ProviderName })
    $normalized = foreach ($event in $events) {
        $application = $null
        if ($IncludeApplication -and ($event.Id -eq 1000 -or $event.Id -eq 1002) -and $event.Properties.Count -gt 0) {
            $candidate = [string]$event.Properties[0].Value
            if (-not [string]::IsNullOrWhiteSpace($candidate)) { $application = $candidate }
        }
        [PSCustomObject]@{ Source = $event.ProviderName; EventId = $event.Id; Application = $application; TimeCreated = $event.TimeCreated }
    }
    @($normalized | Group-Object Source,EventId,Application | ForEach-Object {
        $latest = $_.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1
        [PSCustomObject]@{ Source = $latest.Source; EventId = $latest.EventId; Application = $latest.Application; Count = $_.Count; LastOccurrence = $latest.TimeCreated.ToString('o') }
    } | Sort-Object Count -Descending)
}

function Get-CrashHangSummary {
    try {
        $errors = @()
        $start = (Get-Date).AddDays(-7)
        try { $application = @(Get-EventAggregate -LogName Application -Ids 1000,1001,1002 -Providers 'Application Error','Application Hang','Windows Error Reporting' -StartTime $start -IncludeApplication) } catch { $application = @(); if ($_.FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound') { $errors += "Application log: $($_.Exception.Message)" } }
        try { $system = @(Get-EventAggregate -LogName System -Ids 41,1001 -Providers 'Microsoft-Windows-Kernel-Power','Microsoft-Windows-WER-SystemErrorReporting','BugCheck' -StartTime $start) } catch { $system = @(); if ($_.FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound') { $errors += "System log: $($_.Exception.Message)" } }
        try {
            $wheaEvents = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; StartTime = $start; ProviderName = 'Microsoft-Windows-WHEA-Logger' } -ErrorAction Stop)
            $whea = @($wheaEvents | Group-Object ProviderName,Id | ForEach-Object {
                $latest = $_.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1
                [PSCustomObject]@{ Source = $latest.ProviderName; EventId = $latest.Id; Application = $null; Count = $_.Count; LastOccurrence = $latest.TimeCreated.ToString('o') }
            })
        } catch { $whea = @(); if ($_.FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound') { $errors += "WHEA events: $($_.Exception.Message)" } }
        # WER 1001 is contextual telemetry and does not alone confirm a crash/hang.
        # Application Error 1000 and Application Hang 1002 remain actionable.
        $actionableApplication = @(
            $application | Where-Object {
                -not ($_.Source -eq 'Windows Error Reporting' -and $_.EventId -eq 1001)
            }
        )

        $data = [PSCustomObject]@{ WindowDays = 7; StartTime = $start.ToString('o'); Application = $application; System = @($system + $whea) }
        $status = if (($actionableApplication.Count + $system.Count + $whea.Count) -gt 0) {
            'ATTENTION'
        } elseif ($errors.Count -gt 0) {
            'UNKNOWN'
        } else {
            'OK'
        }
        New-ModuleResult -Status $status -Data $data -Errors $errors
    } catch {
        New-ModuleResult -Errors @($_.Exception.Message)
    }
}

function Get-PowerState {
    try {
        $errors = @()
        $activeScheme = $null
        try { $activeScheme = ((& "$env:SystemRoot\System32\powercfg.exe" /getactivescheme 2>&1) -join ' ').Trim() } catch { $errors += $_.Exception.Message }
        try { $batteries = @(Get-CompatInstance Win32_Battery) } catch { $batteries = @(); $errors += $_.Exception.Message }
        $data = [PSCustomObject]@{
            ActiveScheme = $activeScheme
            BatteryPresent = ($batteries.Count -gt 0)
            Battery = @($batteries | ForEach-Object {
                [PSCustomObject]@{ Name = $_.Name; EstimatedChargeRemainingPercent = $_.EstimatedChargeRemaining; BatteryStatus = $_.BatteryStatus; EstimatedRunTimeMinutes = $_.EstimatedRunTime }
            })
        }
        New-ModuleResult -Status $(if ($activeScheme) { 'OK' } else { 'UNKNOWN' }) -Data $data -Errors $errors
    } catch {
        New-ModuleResult -Errors @($_.Exception.Message)
    }
}

function Get-ThermalFanCapability {
    try {
        $errors = @()
        $expectedMptfPath = Join-Path $env:SystemRoot 'System32\drivers\MPTFPowerTrackerCore.sys'
        $mptfFilePresent = Test-Path -LiteralPath $expectedMptfPath

        try {
            $platformDrivers = @(Get-CompatInstance Win32_SystemDriver | Where-Object {
                $_.Name -match '(?i)MPTF|^ipf_' -or $_.PathName -match '(?i)MPTF|\\ipf[_a-z0-9-]*\.sys'
            })
        } catch { $platformDrivers = @(); $errors += "Platform drivers: $($_.Exception.Message)" }
        try {
            $platformDevices = @(Get-CompatInstance Win32_PnPEntity | Where-Object {
                ($_.Name + ' ' + $_.DeviceID + ' ' + $_.Service + ' ' + $_.Manufacturer) -match '(?i)MPTF|IPF|Innovation Platform Framework|Dynamic Platform|Dynamic Tuning|Intel.*Thermal'
            } | ForEach-Object {
                [PSCustomObject]@{ Name = $_.Name; Manufacturer = $_.Manufacturer; Status = $_.Status; Service = $_.Service; DeviceID = $_.DeviceID; ProblemCode = $_.ConfigManagerErrorCode }
            })
        } catch { $platformDevices = @(); $errors += "Platform devices: $($_.Exception.Message)" }

        $providerNames = @(
            'Microsoft-Windows-Kernel-Power',
            'Microsoft-Windows-Kernel-Acpi',
            'Microsoft-Windows-MPTF-MPTFPowerTrackerCore'
        )
        $providerInventory = foreach ($providerName in $providerNames) {
            try {
                $providerOutput = @(& "$env:SystemRoot\System32\logman.exe" query providers $providerName 2>&1 | ForEach-Object { [string]$_ })
                $providerExitCode = $LASTEXITCODE
                [PSCustomObject]@{ Name = $providerName; Registered = ($providerExitCode -eq 0); ExitCode = $providerExitCode }
            } catch {
                $errors += "ETW provider $providerName`: $($_.Exception.Message)"
                [PSCustomObject]@{ Name = $providerName; Registered = $null; ExitCode = $null }
            }
        }
        $kernelPowerProvider = $providerInventory | Where-Object Name -eq 'Microsoft-Windows-Kernel-Power' | Select-Object -First 1
        $kernelAcpiProvider = $providerInventory | Where-Object Name -eq 'Microsoft-Windows-Kernel-Acpi' | Select-Object -First 1
        $mptfProvider = $providerInventory | Where-Object Name -eq 'Microsoft-Windows-MPTF-MPTFPowerTrackerCore' | Select-Object -First 1

        $thermalZones = @()
        try {
            $thermalZones = @(Get-CompatInstance Win32_PerfFormattedData_Counters_ThermalZoneInformation | ForEach-Object {
                $temperatureC = if ($null -ne $_.HighPrecisionTemperature -and [double]$_.HighPrecisionTemperature -gt 0) {
                    [math]::Round(([double]$_.HighPrecisionTemperature / 10) - 273.15, 1)
                } elseif ($null -ne $_.Temperature -and [double]$_.Temperature -gt 0) {
                    [math]::Round([double]$_.Temperature - 273.15, 1)
                } else { $null }
                [PSCustomObject]@{
                    ZoneName = $_.Name
                    TemperatureC = $temperatureC
                    HighPrecisionTemperature = $_.HighPrecisionTemperature
                    PercentPassiveLimit = $_.PercentPassiveLimit
                    ThrottleReasons = $_.ThrottleReasons
                    Source = 'Win32_PerfFormattedData_Counters_ThermalZoneInformation'
                }
            })
        } catch { $errors += "ThermalZoneInformation: $($_.Exception.Message)" }
        if ($thermalZones.Count -eq 0) {
            try {
                $thermalZones = @(Get-CompatInstance -Namespace root/wmi -ClassName MSAcpi_ThermalZoneTemperature | ForEach-Object {
                    [PSCustomObject]@{
                        ZoneName = $_.InstanceName
                        TemperatureC = if ($null -ne $_.CurrentTemperature -and [double]$_.CurrentTemperature -gt 0) { [math]::Round(([double]$_.CurrentTemperature / 10) - 273.15, 1) } else { $null }
                        HighPrecisionTemperature = $_.CurrentTemperature
                        PercentPassiveLimit = $null
                        ThrottleReasons = $null
                        Source = 'MSAcpi_ThermalZoneTemperature'
                    }
                })
            } catch { $errors += "MSAcpi_ThermalZoneTemperature: $($_.Exception.Message)" }
        }
        $validThermalZones = @($thermalZones | Where-Object { $null -ne $_.TemperatureC })
        $thermalStatus = if ($validThermalZones.Count -gt 0) { 'AVAILABLE' } elseif ($thermalZones.Count -gt 0) { 'PARTIAL' } elseif (@($errors | Where-Object { $_ -match 'ThermalZone' }).Count -gt 0) { 'INFO' } else { 'UNAVAILABLE' }

        try {
            $standardFans = @(Get-CompatInstance Win32_Fan | ForEach-Object {
                [PSCustomObject]@{ Name = $_.Name; Status = $_.Status; DesiredSpeed = $_.DesiredSpeed; ActiveCooling = $_.ActiveCooling; Availability = $_.Availability; DeviceID = $_.DeviceID }
            })
        } catch { $standardFans = @(); $errors += "Win32_Fan: $($_.Exception.Message)" }
        $fanParticipants = @($platformDevices | Where-Object { ($_.Name + ' ' + $_.DeviceID) -match '(?i)Fan Participant|ACPI\\INTC[0-9A-F]+\\TFN' })
        $rpmValues = @($standardFans | Where-Object { $null -ne $_.DesiredSpeed -and [uint64]$_.DesiredSpeed -gt 0 } | ForEach-Object { [uint64]$_.DesiredSpeed })
        $rpmAvailable = $rpmValues.Count -gt 0
        $fanParticipantPresent = $fanParticipants.Count -gt 0
        $standardFanApiAvailable = $standardFans.Count -gt 0
        $fanStatus = if ($rpmAvailable) { 'AVAILABLE' } elseif ($fanParticipantPresent -or $standardFanApiAvailable) { 'PARTIAL' } elseif (@($errors | Where-Object { $_ -match 'Win32_Fan' }).Count -gt 0) { 'INFO' } else { 'UNAVAILABLE' }

        $mptfDriverPresent = $mptfFilePresent -or @($platformDrivers | Where-Object { $_.Name -match '(?i)MPTFPowerTrackerCore' -or $_.PathName -match '(?i)MPTFPowerTrackerCore' }).Count -gt 0
        $mptfDevicePresent = @($platformDevices | Where-Object { ($_.Name + ' ' + $_.DeviceID + ' ' + $_.Service) -match '(?i)MPTF' }).Count -gt 0
        $intelIpfPresent = @($platformDrivers | Where-Object { $_.Name -match '(?i)^ipf_' -or $_.PathName -match '(?i)\\ipf[_a-z0-9-]*\.sys' }).Count -gt 0 -or @($platformDevices | Where-Object { ($_.Name + ' ' + $_.DeviceID) -match '(?i)IPF|Innovation Platform Framework' }).Count -gt 0
        $mptfRegistered = if ($mptfProvider) { $mptfProvider.Registered } else { $null }
        $data = [PSCustomObject]@{
            Platform = [PSCustomObject]@{
                IntelIPFPresent = $intelIpfPresent
                MPTFPresent = ($mptfDriverPresent -or $mptfDevicePresent -or $mptfRegistered -eq $true)
                MPTFDriverPresent = $mptfDriverPresent
                IntelMptfIpfDeviceCount = $platformDevices.Count
            }
            Thermal = [PSCustomObject]@{
                Status = $thermalStatus
                StandardTelemetryAvailable = ($validThermalZones.Count -gt 0)
                ThermalZones = $thermalZones
            }
            Fan = [PSCustomObject]@{
                Status = $fanStatus
                FanParticipantStatus = if ($fanParticipantPresent) { 'AVAILABLE' } else { 'UNAVAILABLE' }
                FanParticipantPresent = $fanParticipantPresent
                FanParticipantDevices = $fanParticipants
                StandardFanApiAvailable = $standardFanApiAvailable
                RPMStatus = if ($rpmAvailable) { 'AVAILABLE' } else { 'UNAVAILABLE' }
                RPMAvailable = $rpmAvailable
                RPM = if ($rpmAvailable) { $rpmValues[0] } else { $null }
                RPMSource = if ($rpmAvailable) { 'Win32_Fan.DesiredSpeed' } else { 'UNAVAILABLE_STANDARD_API' }
            }
            ETWCapabilities = [PSCustomObject]@{
                KernelPowerRegistered = if ($kernelPowerProvider) { $kernelPowerProvider.Registered } else { $null }
                KernelAcpiRegistered = if ($kernelAcpiProvider) { $kernelAcpiProvider.Registered } else { $null }
                MptfPowerTrackerRegistered = $mptfRegistered
            }
        }
        New-ModuleResult -Status 'INFO' -Data $data -Errors $errors
    } catch {
        $emptyData = [PSCustomObject]@{
            Platform = [PSCustomObject]@{ IntelIPFPresent = $false; MPTFPresent = $false; MPTFDriverPresent = $false; IntelMptfIpfDeviceCount = 0 }
            Thermal = [PSCustomObject]@{ Status = 'INFO'; StandardTelemetryAvailable = $false; ThermalZones = @() }
            Fan = [PSCustomObject]@{ Status = 'INFO'; FanParticipantStatus = 'UNAVAILABLE'; FanParticipantPresent = $false; FanParticipantDevices = @(); StandardFanApiAvailable = $false; RPMStatus = 'UNAVAILABLE'; RPMAvailable = $false; RPM = $null; RPMSource = 'UNAVAILABLE_STANDARD_API' }
            ETWCapabilities = [PSCustomObject]@{ KernelPowerRegistered = $null; KernelAcpiRegistered = $null; MptfPowerTrackerRegistered = $null }
        }
        New-ModuleResult -Status 'INFO' -Data $emptyData -Errors @($_.Exception.Message)
    }
}

function Format-Bytes {
    param([object]$Bytes)
    if ($null -eq $Bytes) { return 'Unavailable' }
    if ([double]$Bytes -ge 1GB) { return ('{0:N2} GB' -f ([double]$Bytes / 1GB)) }
    return ('{0:N2} MB' -f ([double]$Bytes / 1MB))
}

function Export-WinDiagReport {
    param(
        [Parameter(Mandatory = $true)][object]$Snapshot,
        [Parameter(Mandatory = $true)][string]$Directory,
        [Parameter(Mandatory = $true)][datetime]$RunStartedAt
    )
    try {
        if (-not (Test-Path -LiteralPath $Directory)) { New-Item -ItemType Directory -Path $Directory -Force | Out-Null }
        $allocation = Get-UniqueWinDiagReportBaseName -Prefix WinDiagProbe -RunStartedAt $RunStartedAt -Directory $Directory -Extensions @('.txt','.json')
        $baseName = $allocation.BaseName
        $txtPath = Join-Path $Directory ($baseName + '.txt')
        $jsonPath = Join-Path $Directory ($baseName + '.json')
        $lines = New-Object System.Collections.Generic.List[string]
        $lines.Add('EXPC WinDiagProbe 0.2')
        $lines.Add("Generated: $($Snapshot.generated_at)")
        $lines.Add("Overall status: $($Snapshot.OverallStatus)")
        $lines.Add("Computer: $($Snapshot.system.Data.ComputerName)")
        $lines.Add("Windows: $($Snapshot.system.Data.WindowsEdition) $($Snapshot.system.Data.WindowsVersion) (Build $($Snapshot.system.Data.WindowsBuild))")
        $lines.Add('')
        $lines.Add('[SYSTEM]')
        $lines.Add("Status: $($Snapshot.system.Status)")
        $lines.Add("Last boot: $($Snapshot.system.Data.LastBoot)")
        $lines.Add("CPU: $($Snapshot.system.Data.CPU.Name); cores $($Snapshot.system.Data.CPU.PhysicalCores), logical $($Snapshot.system.Data.CPU.LogicalProcessors)")
        $lines.Add("CPU sample: avg $($Snapshot.cpu_sample.Data.AveragePercent)%; min $($Snapshot.cpu_sample.Data.MinimumPercent)%; max $($Snapshot.cpu_sample.Data.MaximumPercent)%; samples $($Snapshot.cpu_sample.Data.SampleCount) over $($Snapshot.cpu_sample.Data.DurationMilliseconds) ms")
        $lines.Add("RAM: $(Format-Bytes $Snapshot.system.Data.RAM.TotalBytes); available $(Format-Bytes $Snapshot.system.Data.RAM.AvailableBytes)")
        $lines.Add("System drive: $($Snapshot.system.Data.SystemDrive.DeviceID) $(Format-Bytes $Snapshot.system.Data.SystemDrive.FreeBytes) free of $(Format-Bytes $Snapshot.system.Data.SystemDrive.SizeBytes)")
        $lines.Add("Pagefile: $($Snapshot.system.Data.PageFile.ManagementMode)")
        foreach ($page in @($Snapshot.system.Data.PageFile.Usage)) { $lines.Add("Pagefile usage: $($page.Name); allocated $($page.AllocatedBaseSizeMB) MB; current $($page.CurrentUsageMB) MB; peak $($page.PeakUsageMB) MB") }
        $lines.Add('')
        $lines.Add('[MEMORY HEALTH]')
        $lines.Add("Status: $($Snapshot.memory_health.Status)")
        $lines.Add("Available: $(Format-Bytes $Snapshot.memory_health.Data.AvailableBytes) ($($Snapshot.memory_health.Data.AvailablePercent)%)")
        $lines.Add("Commit: $(Format-Bytes $Snapshot.memory_health.Data.CommitUsedBytes) / $(Format-Bytes $Snapshot.memory_health.Data.CommitLimitBytes) ($($Snapshot.memory_health.Data.CommitPercent)%)")
        $lines.Add("Paged pool: $(Format-Bytes $Snapshot.memory_health.Data.PagedPoolBytes); nonpaged pool: $(Format-Bytes $Snapshot.memory_health.Data.NonpagedPoolBytes)")
        $lines.Add("Pages/sec: $($Snapshot.memory_health.Data.PagesPerSec); reads/sec: $($Snapshot.memory_health.Data.PageReadsPerSec); writes/sec: $($Snapshot.memory_health.Data.PageWritesPerSec)")
        $lines.Add('')
        foreach ($ranking in 'ByWorkingSet','ByPrivateMemory','ByHandles','ByThreads','ByCPUTime') {
            $lines.Add("[TOP PROCESSES - $ranking]")
            $lines.Add('ProcessName | PID | SessionId | UserName | WorkingSetMB | PrivateMB | Handles | Threads | CPUSeconds')
            foreach ($p in @($Snapshot.top_processes.Data.$ranking)) { $lines.Add("$($p.ProcessName) | $($p.PID) | $($p.SessionId) | $($p.UserName) | $($p.WorkingSetMB) | $($p.PrivateMB) | $($p.Handles) | $($p.Threads) | $($p.CPUSeconds)") }
            $lines.Add('')
        }
        $lines.Add('[DRIVER / KERNEL STATE]')
        $lines.Add("Status: $($Snapshot.driver_state.Status)")
        $lines.Add("Drivers: $($Snapshot.driver_state.Data.InstalledDriversCount); signed: $($Snapshot.driver_state.Data.InstalledSignedDriversCount); unsigned: $(@($Snapshot.driver_state.Data.UnsignedDrivers).Count); signature unknown: $(@($Snapshot.driver_state.Data.UnknownSignatureDrivers).Count); problematic: $(@($Snapshot.driver_state.Data.ProblematicDrivers).Count)")
        $lines.Add("Driver Verifier: $($Snapshot.driver_state.Data.DriverVerifier.State)")
        $lines.Add('')
        $lines.Add('[CRASH / HANG SIGNALS - LAST 7 DAYS]')
        $lines.Add("Status: $($Snapshot.crash_hang_summary.Status)")
        $lines.Add('Source | Event ID | Application | Count | Last occurrence')
        foreach ($e in @($Snapshot.crash_hang_summary.Data.Application) + @($Snapshot.crash_hang_summary.Data.System)) { $lines.Add("$($e.Source) | $($e.EventId) | $($e.Application) | $($e.Count) | $($e.LastOccurrence)") }
        $lines.Add('')
        $lines.Add('[POWER]')
        $lines.Add("Status: $($Snapshot.power_state.Status)")
        $lines.Add("Active scheme: $($Snapshot.power_state.Data.ActiveScheme)")
        $lines.Add($(if ($Snapshot.power_state.Data.BatteryPresent) { "Battery: Present; charge $($Snapshot.power_state.Data.Battery[0].EstimatedChargeRemainingPercent)%" } else { 'Battery: Not present' }))
        $lines.Add('')
        $lines.Add('[MULTI-USER / RDP]')
        $lines.Add("RDP service       : $($Snapshot.multi_user_rdp.Data.TermServiceState)")
        $lines.Add("RDP enabled       : $(if ($Snapshot.multi_user_rdp.Data.RDPEnabled -eq $true) { 'YES' } elseif ($Snapshot.multi_user_rdp.Data.RDPEnabled -eq $false) { 'NO' } else { 'UNKNOWN' })")
        $lines.Add("Sessions          : $($Snapshot.multi_user_rdp.Data.SessionCount)")
        $lines.Add("Active            : $($Snapshot.multi_user_rdp.Data.ActiveSessionCount)")
        $lines.Add("Disconnected      : $($Snapshot.multi_user_rdp.Data.DisconnectedSessionCount)")
        $lines.Add("RDP Wrapper       : $($Snapshot.multi_user_rdp.Data.RDPWrapper.Status)")
        $lines.Add('UserName | SessionId | SessionName | State')
        foreach ($session in @($Snapshot.multi_user_rdp.Data.Sessions)) { $lines.Add("$($session.UserName) | $($session.SessionId) | $($session.SessionName) | $($session.State)") }
        $lines.Add('')
        $lines.Add('[THERMAL / FAN]')
        $lines.Add("ACPI thermal telemetry : $($Snapshot.thermal_fan_capability.Data.Thermal.Status)")
        $lines.Add("Thermal zones          : $(@($Snapshot.thermal_fan_capability.Data.Thermal.ThermalZones).Count)")
        $lines.Add("Intel IPF              : $(if ($Snapshot.thermal_fan_capability.Data.Platform.IntelIPFPresent) { 'PRESENT' } else { 'NOT PRESENT' })")
        $lines.Add("Fan participant        : $(if ($Snapshot.thermal_fan_capability.Data.Fan.FanParticipantPresent) { 'PRESENT' } else { 'NOT PRESENT' })")
        $lines.Add("Fan RPM                : $($Snapshot.thermal_fan_capability.Data.Fan.RPMStatus)")
        $lines.Add("Kernel-Power ETW       : $(if ($Snapshot.thermal_fan_capability.Data.ETWCapabilities.KernelPowerRegistered -eq $true) { 'REGISTERED' } elseif ($Snapshot.thermal_fan_capability.Data.ETWCapabilities.KernelPowerRegistered -eq $false) { 'NOT REGISTERED' } else { 'INFO' })")
        $lines.Add("Kernel-ACPI ETW        : $(if ($Snapshot.thermal_fan_capability.Data.ETWCapabilities.KernelAcpiRegistered -eq $true) { 'REGISTERED' } elseif ($Snapshot.thermal_fan_capability.Data.ETWCapabilities.KernelAcpiRegistered -eq $false) { 'NOT REGISTERED' } else { 'INFO' })")
        $lines.Add("MPTF ETW               : $(if ($Snapshot.thermal_fan_capability.Data.ETWCapabilities.MptfPowerTrackerRegistered -eq $true) { 'REGISTERED' } elseif ($Snapshot.thermal_fan_capability.Data.ETWCapabilities.MptfPowerTrackerRegistered -eq $false) { 'NOT REGISTERED' } else { 'INFO' })")
        foreach ($zone in @($Snapshot.thermal_fan_capability.Data.Thermal.ThermalZones)) { $lines.Add("ACPI Thermal Zone $($zone.ZoneName): $($zone.TemperatureC) C") }
        $lines.Add('')
        $lines.Add('[COLLECTION ERRORS / UNAVAILABLE DATA]')
        foreach ($moduleName in 'system','cpu_sample','memory_health','top_processes','driver_state','crash_hang_summary','power_state','multi_user_rdp','thermal_fan_capability') {
            foreach ($message in @($Snapshot.$moduleName.Errors)) { $lines.Add("$moduleName`: $message") }
        }
        $utf8 = New-Object System.Text.UTF8Encoding($false)
        [IO.File]::WriteAllLines($txtPath, $lines, $utf8)
        [IO.File]::WriteAllText($jsonPath, ($Snapshot | ConvertTo-Json -Depth 10), $utf8)
        [PSCustomObject]@{ TxtPath = $txtPath; JsonPath = $jsonPath }
    } catch { throw "Report export failed: $($_.Exception.Message)" }
}

function Write-ProbeStatus {
    param([string]$Status, [string]$Label)
    $color = switch ($Status) { 'OK' { 'Green' } 'ATTENTION' { 'Yellow' } 'ERROR' { 'Red' } default { 'Cyan' } }
    Write-Host ('[ {0} ] {1}' -f $Status, $Label) -ForegroundColor $color
}

Write-Host 'EXPC WinDiagProbe 0.2' -ForegroundColor Cyan
$system = Get-SystemSnapshot
$cpuSample = Get-CpuSample
$memory = Get-MemoryHealth
$multiUser = Get-MultiUserRdpState
$processes = Get-TopProcesses -Sessions $(if ($null -ne $multiUser.Data) { @($multiUser.Data.Sessions) } else { @() })
$drivers = Get-DriverState
$events = Get-CrashHangSummary
$power = Get-PowerState
$thermalFan = Get-ThermalFanCapability

# Preserve a stable report shape even when an entire Windows provider is denied.
if ($null -eq $system.Data) {
    $system.Data = [PSCustomObject]@{ ComputerName = $env:COMPUTERNAME; WindowsEdition = 'Unavailable'; WindowsVersion = [Environment]::OSVersion.Version.ToString(); WindowsBuild = [Environment]::OSVersion.Version.Build; InstallationDate = $null; LastBoot = $null; UptimeSeconds = $null; CPU = [PSCustomObject]@{ Name = $env:PROCESSOR_IDENTIFIER; PhysicalCores = $null; LogicalProcessors = [Environment]::ProcessorCount }; RAM = [PSCustomObject]@{ TotalBytes = $null; AvailableBytes = $null }; SystemDrive = [PSCustomObject]@{ DeviceID = $env:SystemDrive; SizeBytes = $null; FreeBytes = $null }; PageFileConfiguration = @(); PageFileUsage = @(); PageFile = [PSCustomObject]@{ ManagementMode = 'UNKNOWN'; AutomaticManaged = $null; Configuration = @(); Usage = @() } }
}
if ($null -eq $cpuSample.Data) { $cpuSample.Data = [PSCustomObject]@{ DurationMilliseconds = 1000; SampleCount = 0; AveragePercent = $null; MinimumPercent = $null; MaximumPercent = $null; Samples = @() } }
if ($null -eq $memory.Data) { $memory.Data = [PSCustomObject]@{ PhysicalTotalBytes = $null; AvailableBytes = $null; AvailablePercent = $null; CommitUsedBytes = $null; CommitLimitBytes = $null; CommitPercent = $null; PagedPoolBytes = $null; NonpagedPoolBytes = $null; PagesPerSec = $null; PageReadsPerSec = $null; PageWritesPerSec = $null; Signals = @() } }
if ($null -eq $processes.Data) { $processes.Data = [PSCustomObject]@{ ByWorkingSet = @(); ByPrivateMemory = @(); ByHandles = @(); ByThreads = @(); ByCPUTime = @() } }
if ($null -eq $drivers.Data) { $drivers.Data = [PSCustomObject]@{ InstalledSignedDriversCount = 0; InstalledDriversCount = 0; UnsignedDrivers = @(); UnknownSignatureDrivers = @(); ProblematicDrivers = @(); DriverInventory = @(); DriverVerifier = [PSCustomObject]@{ State = 'UNKNOWN'; QueryOutput = @() } } }
if ($null -eq $events.Data) { $events.Data = [PSCustomObject]@{ WindowDays = 7; StartTime = (Get-Date).AddDays(-7).ToString('o'); Application = @(); System = @() } }
if ($null -eq $power.Data) { $power.Data = [PSCustomObject]@{ ActiveScheme = $null; BatteryPresent = $false; Battery = @() } }
if ($null -eq $multiUser.Data) { $multiUser.Data = [PSCustomObject]@{ TermServiceState = 'UNKNOWN'; RDPEnabled = $null; SessionCount = 0; ActiveSessionCount = 0; DisconnectedSessionCount = 0; Sessions = @(); RDPWrapper = [PSCustomObject]@{ Status = 'UNKNOWN'; Present = $null; DetectedFiles = @(); Services = @(); TermServiceServiceDll = $null } } }
if ($null -eq $thermalFan.Data) {
    $thermalFan.Data = [PSCustomObject]@{
        Platform = [PSCustomObject]@{ IntelIPFPresent = $false; MPTFPresent = $false; MPTFDriverPresent = $false; IntelMptfIpfDeviceCount = 0 }
        Thermal = [PSCustomObject]@{ Status = 'INFO'; StandardTelemetryAvailable = $false; ThermalZones = @() }
        Fan = [PSCustomObject]@{ Status = 'INFO'; FanParticipantStatus = 'UNAVAILABLE'; FanParticipantPresent = $false; FanParticipantDevices = @(); StandardFanApiAvailable = $false; RPMStatus = 'UNAVAILABLE'; RPMAvailable = $false; RPM = $null; RPMSource = 'UNAVAILABLE_STANDARD_API' }
        ETWCapabilities = [PSCustomObject]@{ KernelPowerRegistered = $null; KernelAcpiRegistered = $null; MptfPowerTrackerRegistered = $null }
    }
}

$healthStatuses = @($system.Status, $memory.Status, $drivers.Status, $events.Status)
$overallStatus = if ($healthStatuses -contains 'ERROR') { 'ERROR' } elseif ($healthStatuses -contains 'ATTENTION') { 'ATTENTION' } elseif ($healthStatuses -contains 'UNKNOWN') { 'UNKNOWN' } else { 'OK' }

$snapshot = [PSCustomObject][ordered]@{
    tool = 'EXPC WinDiagProbe'
    version = '0.2'
    schema_version = 2
    generated_at = (Get-Date).ToString('o')
    read_only = $true
    etw_session_created = $false
    OverallStatus = $overallStatus
    system = $system
    cpu_sample = $cpuSample
    memory_health = $memory
    top_processes = $processes
    driver_state = $drivers
    crash_hang_summary = $events
    power_state = $power
    multi_user_rdp = $multiUser
    thermal_fan_capability = $thermalFan
}

Write-Host "Runtime: $($RuntimeInfo.DisplayName)"
Write-Host "Compatibility: $($RuntimeInfo.Compatibility)"
Write-Host "Computer: $($system.Data.ComputerName)"
Write-Host "Windows: $($system.Data.WindowsEdition) $($system.Data.WindowsVersion)"
Write-Host ''
Write-ProbeStatus $system.Status 'System'
Write-ProbeStatus $cpuSample.Status "CPU sample: $($cpuSample.Data.AveragePercent)% average"
Write-ProbeStatus $memory.Status 'Memory'
$crashCount = 0
foreach ($eventRow in @($events.Data.Application | Where-Object Source -eq 'Application Error')) { $crashCount += [int]$eventRow.Count }
Write-ProbeStatus $(if ($crashCount -gt 0) { 'ATTENTION' } elseif ($events.Status -eq 'UNKNOWN') { 'UNKNOWN' } else { 'OK' }) "Application crashes: $crashCount"

$werCount = 0
foreach ($eventRow in @($events.Data.Application | Where-Object Source -eq 'Windows Error Reporting')) { $werCount += [int]$eventRow.Count }
Write-ProbeStatus $(if ($werCount -gt 0) { 'INFO' } else { 'OK' }) "WER reports: $werCount"

$hangCount = 0
foreach ($eventRow in @($events.Data.Application | Where-Object Source -eq 'Application Hang')) { $hangCount += [int]$eventRow.Count }
Write-ProbeStatus $(if ($hangCount -gt 0) { 'ATTENTION' } elseif ($events.Status -eq 'UNKNOWN') { 'UNKNOWN' } else { 'OK' }) "Application hangs: $hangCount"
$kernelCount = 0
foreach ($eventRow in @($events.Data.System)) { $kernelCount += [int]$eventRow.Count }
Write-ProbeStatus $(if ($kernelCount -gt 0) { 'ATTENTION' } elseif ($events.Status -eq 'UNKNOWN') { 'UNKNOWN' } else { 'OK' }) "Kernel/WHEA signals: $kernelCount"
Write-ProbeStatus $(if ($drivers.Data.DriverVerifier.State -eq 'UNKNOWN') { 'INFO' } else { 'OK' }) "Driver Verifier: $($drivers.Data.DriverVerifier.State)"
Write-Host ''
Write-Host '[MULTI-USER / RDP]' -ForegroundColor Cyan
Write-Host ("RDP service       : {0}" -f $multiUser.Data.TermServiceState)
Write-Host ("RDP enabled       : {0}" -f $(if ($multiUser.Data.RDPEnabled -eq $true) { 'YES' } elseif ($multiUser.Data.RDPEnabled -eq $false) { 'NO' } else { 'UNKNOWN' }))
Write-Host ("Sessions          : {0}" -f $multiUser.Data.SessionCount)
Write-Host ("Active            : {0}" -f $multiUser.Data.ActiveSessionCount)
Write-Host ("Disconnected      : {0}" -f $multiUser.Data.DisconnectedSessionCount)
Write-Host ("RDP Wrapper       : {0}" -f $multiUser.Data.RDPWrapper.Status)
Write-Host ''
Write-Host '[THERMAL / FAN]' -ForegroundColor Cyan
Write-Host ("ACPI thermal telemetry : {0}" -f $thermalFan.Data.Thermal.Status)
Write-Host ("Thermal zones          : {0}" -f @($thermalFan.Data.Thermal.ThermalZones).Count)
Write-Host ("Intel IPF              : {0}" -f $(if ($thermalFan.Data.Platform.IntelIPFPresent) { 'PRESENT' } else { 'NOT PRESENT' }))
Write-Host ("Fan participant        : {0}" -f $(if ($thermalFan.Data.Fan.FanParticipantPresent) { 'PRESENT' } else { 'NOT PRESENT' }))
Write-Host ("Fan RPM                : {0}" -f $thermalFan.Data.Fan.RPMStatus)
Write-Host ("Kernel-Power ETW       : {0}" -f $(if ($thermalFan.Data.ETWCapabilities.KernelPowerRegistered -eq $true) { 'REGISTERED' } elseif ($thermalFan.Data.ETWCapabilities.KernelPowerRegistered -eq $false) { 'NOT REGISTERED' } else { 'INFO' }))
Write-Host ("Kernel-ACPI ETW        : {0}" -f $(if ($thermalFan.Data.ETWCapabilities.KernelAcpiRegistered -eq $true) { 'REGISTERED' } elseif ($thermalFan.Data.ETWCapabilities.KernelAcpiRegistered -eq $false) { 'NOT REGISTERED' } else { 'INFO' }))
Write-Host ("MPTF ETW               : {0}" -f $(if ($thermalFan.Data.ETWCapabilities.MptfPowerTrackerRegistered -eq $true) { 'REGISTERED' } elseif ($thermalFan.Data.ETWCapabilities.MptfPowerTrackerRegistered -eq $false) { 'NOT REGISTERED' } else { 'INFO' }))
foreach ($zone in @($thermalFan.Data.Thermal.ThermalZones)) { Write-Host ("ACPI Thermal Zone {0}: {1} C" -f $zone.ZoneName, $zone.TemperatureC) }
Write-Host ''
Write-ProbeStatus $overallStatus 'Overall status'

try {
    $report = Export-WinDiagReport -Snapshot $snapshot -Directory $OutputDirectory -RunStartedAt $ScriptLaunchTime
    Write-Host ''
    Write-Host 'Reports:' -ForegroundColor Cyan
    Write-Host ($OutputDirectory.TrimEnd('\') + '\')
    Write-Host $report.TxtPath
    Write-Host $report.JsonPath
} catch {
    Write-ProbeStatus 'ERROR' $_.Exception.Message
    exit 1
}
