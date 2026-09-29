#requires -Version 5.0
# WinStateDiag Driver Audit collector -- READ-ONLY.
#
# Uses only read-only queries: Get-CimInstance (Win32_PnPEntity,
# Win32_PnPSignedDriver, Win32_SystemDriver) and Get-WinEvent. It changes
# nothing on the system and writes no files. It prints tab-separated records
# (UTF-8) to stdout. The Rust side (src/driver_audit.rs) classifies them.
#
# Record formats (tabs and newlines inside values are replaced by spaces):
#   META <key> <value>
#   DEV  <class> <name> <manufacturer> <provider> <version> <date yyyy-MM-dd>
#        <inf> <pnp error code> <is signed> <pnp device id> <service>
#   SYS  <name> <display name> <path> <state> <start mode> <service type>
#   EVT  <tag> <event id> <time yyyy-MM-ddTHH:mm:ss> <provider>
#        <properties joined by ' | '> <message, first 400 chars> <level>
#   DRVFILE <service name> <resolved image path> <exists True/False>
#        <Authenticode status> <signer subject> <company> <file version>
#        (only for drivers named in SCM 7026 events)
#   ERR  <source> <message>

param([int]$Days = 30)

$ErrorActionPreference = 'SilentlyContinue'
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch {}

function S($v) {
    if ($null -eq $v) { return '' }
    return (([string]$v) -replace "[`t`r`n]+", ' ').Trim()
}
function Emit([object[]]$fields) {
    [Console]::Out.WriteLine((($fields | ForEach-Object { S $_ }) -join "`t"))
}
function IsoTime($t) {
    if ($t) { return ([datetime]$t).ToString('yyyy-MM-ddTHH:mm:ss') }
    return ''
}

$since = (Get-Date).AddDays(-$Days)
Emit @('META', 'version', '1')
Emit @('META', 'generated', (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss'))
Emit @('META', 'window_days', $Days)

# ---------------------------------------------------------------- devices
$entities = @{}
try {
    foreach ($e in @(Get-CimInstance -ClassName Win32_PnPEntity -ErrorAction Stop)) {
        if ($e.PNPDeviceID) { $entities[[string]$e.PNPDeviceID] = $e }
    }
} catch { Emit @('ERR', 'Win32_PnPEntity', $_.Exception.Message) }

$seen = @{}
try {
    foreach ($d in @(Get-CimInstance -ClassName Win32_PnPSignedDriver -ErrorAction Stop)) {
        if (-not $d.DeviceID) { continue }
        $id = [string]$d.DeviceID
        $e = $entities[$id]
        $code = ''; $svc = ''
        if ($e) { $code = $e.ConfigManagerErrorCode; $svc = $e.Service }
        $cls = $d.DeviceClass
        if (-not $cls -and $e) { $cls = $e.PNPClass }
        $date = ''
        if ($d.DriverDate) { try { $date = ([datetime]$d.DriverDate).ToString('yyyy-MM-dd') } catch {} }
        Emit @('DEV', $cls, $d.DeviceName, $d.Manufacturer, $d.DriverProviderName, $d.DriverVersion,
               $date, $d.InfName, $code, $d.IsSigned, $id, $svc)
        $seen[$id] = $true
    }
} catch { Emit @('ERR', 'Win32_PnPSignedDriver', $_.Exception.Message) }

# Devices with a PnP error but no signed-driver record (e.g. code 28).
foreach ($id in @($entities.Keys)) {
    if ($seen[$id]) { continue }
    $e = $entities[$id]
    if ($e.ConfigManagerErrorCode -and [int]$e.ConfigManagerErrorCode -ne 0) {
        Emit @('DEV', $e.PNPClass, $e.Name, $e.Manufacturer, '', '', '', '',
               $e.ConfigManagerErrorCode, '', $id, $e.Service)
    }
}

# ---------------------------------------------------- kernel/system drivers
$sysDrivers = @{}
try {
    foreach ($s in @(Get-CimInstance -ClassName Win32_SystemDriver -ErrorAction Stop)) {
        Emit @('SYS', $s.Name, $s.DisplayName, $s.PathName, $s.State, $s.StartMode, $s.ServiceType)
        $sysDrivers[[string]$s.Name] = $s
    }
} catch { Emit @('ERR', 'Win32_SystemDriver', $_.Exception.Message) }

# ------------------------------------------------------------------ events
function Emit-Events([hashtable]$filter, [string]$tag) {
    $events = @()
    try {
        $events = @(Get-WinEvent -FilterHashtable $filter -MaxEvents 400 -ErrorAction Stop)
    } catch {
        if ([string]$_.FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound') {
            Emit @('ERR', $tag, $_.Exception.Message)
        }
        return
    }
    foreach ($ev in $events) {
        $props = @()
        foreach ($p in @($ev.Properties)) {
            $v = $p.Value
            if ($v -is [int] -or $v -is [uint32] -or $v -is [long]) {
                $v = '0x' + ('{0:x8}' -f $v)
            }
            $props += (S $v)
        }
        $msg = S $ev.Message
        if ($msg.Length -gt 400) { $msg = $msg.Substring(0, 400) }
        Emit @('EVT', $tag, $ev.Id, (IsoTime $ev.TimeCreated), $ev.ProviderName, ($props -join ' | '), $msg, $ev.Level)
    }
}

# Application crashes (faulting module may be a driver component).
Emit-Events @{ LogName = 'Application'; ProviderName = 'Application Error'; Id = 1000; StartTime = $since } 'APPCRASH'
# Boot/system-start drivers that failed to load; services that failed to start.
Emit-Events @{ LogName = 'System'; ProviderName = 'Service Control Manager'; Id = 7026; StartTime = $since } 'SCM7026'
Emit-Events @{ LogName = 'System'; ProviderName = 'Service Control Manager'; Id = 7000; StartTime = $since } 'SCM7000'
# Other service start failures (dependency failed, start timeout): context only.
Emit-Events @{ LogName = 'System'; ProviderName = 'Service Control Manager'; Id = 7001, 7009; StartTime = $since } 'SCMERR'
# Driver failed to load for a device.
Emit-Events @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-PnP'; Id = 219; StartTime = $since } 'KPNP219'
# Display driver stopped responding and was recovered (TDR).
Emit-Events @{ LogName = 'System'; ProviderName = 'Display'; Id = 4101; StartTime = $since } 'TDR4101'
# Code Integrity: unsigned / invalid image / signing level / policy blocks.
Emit-Events @{ LogName = 'Microsoft-Windows-CodeIntegrity/Operational'; Id = 3001, 3002, 3004, 3033, 3063, 3077; StartTime = $since } 'CI'

# ------------------------------------------ image files of 7026 drivers
# Read-only facts (existence, Authenticode signature, version info) for the
# drivers named in SCM 7026, so an inactive but intact Microsoft driver can
# be told apart from a damaged one.
function Resolve-DriverImage([string]$raw) {
    if (-not $raw) { return '' }
    $p = $raw.Trim().Trim('"')
    if ($p.StartsWith('\??\')) { $p = $p.Substring(4) }
    if ($p -match '^\\SystemRoot\\(.*)$') { $p = Join-Path $env:SystemRoot $Matches[1] }
    elseif ($p -match '^(?i)system32\\') { $p = Join-Path $env:SystemRoot $p }
    return $p
}
$names7026 = @{}
try {
    foreach ($ev in @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Service Control Manager'; Id = 7026; StartTime = $since } -MaxEvents 400 -ErrorAction Stop)) {
        foreach ($p in @($ev.Properties)) {
            foreach ($n in ([string]$p.Value -split '[\s,]+')) { if ($n) { $names7026[$n.ToLowerInvariant()] = $n } }
        }
    }
} catch {}
foreach ($key in @($names7026.Keys)) {
    $svc = $sysDrivers[$names7026[$key]]
    if (-not $svc) { foreach ($k in $sysDrivers.Keys) { if ($k.ToLowerInvariant() -eq $key) { $svc = $sysDrivers[$k] } } }
    if (-not $svc) { continue }
    $path = Resolve-DriverImage $svc.PathName
    $exists = $false; $status = ''; $signer = ''; $company = ''; $version = ''
    if ($path -and (Test-Path -LiteralPath $path -PathType Leaf)) {
        $exists = $true
        try {
            $sig = Get-AuthenticodeSignature -LiteralPath $path -ErrorAction Stop
            $status = [string]$sig.Status
            if ($sig.SignerCertificate) { $signer = $sig.SignerCertificate.Subject }
        } catch { $status = 'Error' }
        try {
            $vi = (Get-Item -LiteralPath $path -ErrorAction Stop).VersionInfo
            $company = $vi.CompanyName; $version = $vi.FileVersion
        } catch {}
    }
    Emit @('DRVFILE', $svc.Name, $path, $exists, $status, $signer, $company, $version)
}

Emit @('META', 'done', '1')
