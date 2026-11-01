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
#   SIGCHK <pnp device id> <image path> <image Authenticode status>
#        <image signer> <inf Authenticode status> <inf signer>
#        (v1.0: second, independent verification for every device whose
#        Win32_PnPSignedDriver.IsSigned is False — WMI alone is not proof)
#   PKG  <published name> <original name> <provider> <class> <version>
#        <date yyyy-MM-dd>  (v1.0: authoritative driver-package identity,
#        read-only package inventory Get-WindowsDriver -Online)
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

# Independent Configuration Manager query. Get-PnpDeviceProperty uses the
# same Win32_PnPEntity provider and cannot resolve its coverage gaps.
function Get-CmPnpFacts([string]$id) {
    try {
        if (-not ('WsdPnp' -as [type])) {
            Add-Type -ErrorAction Stop -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class WsdPnp {
 [DllImport("cfgmgr32.dll", CharSet=CharSet.Unicode, ExactSpelling=true)]
 public static extern uint CM_Locate_DevNodeW(out uint node, string id, uint flags);
 [DllImport("cfgmgr32.dll", ExactSpelling=true)]
 public static extern uint CM_Get_DevNode_Status(out uint status, out uint problem, uint node, uint flags);
}
"@
        }
        $node=[uint32]0; $status=[uint32]0; $problem=[uint32]0
        $located=[WsdPnp]::CM_Locate_DevNodeW([ref]$node,$id,0)
        if ($located -eq 13) {
            # CR_NO_SUCH_DEVNODE: no currently present node. Never code 0.
            $phantom=[WsdPnp]::CM_Locate_DevNodeW([ref]$node,$id,1)
            if ($phantom -eq 0) {
                return [PSCustomObject]@{Code=''; Source='CfgMgr32.NOT_PRESENT'; Error="CM_Locate_DevNode NORMAL=13; PHANTOM=$phantom; inventory record, current device health NOT TESTED"}
            }
            throw "CM_Locate_DevNode NORMAL=$located; PHANTOM=$phantom"
        }
        if ($located -ne 0) { throw "CM_Locate_DevNode NORMAL=$located" }
        $result=[WsdPnp]::CM_Get_DevNode_Status([ref]$status,[ref]$problem,$node,0)
        if ($result -ne 0) { throw "CM_Get_DevNode_Status=$result" }
        return [PSCustomObject]@{Code=[string]$problem; Source='CfgMgr32.CM_Get_DevNode_Status'; Error=''}
    } catch {
        return [PSCustomObject]@{Code=''; Source='UNAVAILABLE'; Error=('Configuration Manager / Add-Type unavailable; LanguageMode=' + $ExecutionContext.SessionState.LanguageMode + '; ' + $_.Exception.Message)}
    }
}

# Numeric problem codes are language independent. Null/empty is never zero.
function Resolve-PnpCode($entity, [string]$id) {
    $number = [uint32]0
    $raw = if ($null -ne $entity) { $entity.ConfigManagerErrorCode } else { $null }
    if ($null -ne $raw -and [uint32]::TryParse([string]$raw, [ref]$number)) {
        return [PSCustomObject]@{ Code=[string]$number; Source='Win32_PnPEntity.ConfigManagerErrorCode'; Error='' }
    }
    # Win32_PnPSignedDriver also returns print-queue records keyed by queue
    # name rather than a PnP InstanceId. Confirm with Win32_Printer; do not
    # invent a devnode/code 0 for a software queue.
    if ($null -eq $entity) {
        try {
            if ($null -eq $script:PrinterQueues) {
                $script:PrinterQueues = @(Get-CimInstance -ClassName Win32_Printer -ErrorAction Stop)
            }
            $queue = $script:PrinterQueues | Where-Object { $_.Name -eq $id } | Select-Object -First 1
            if ($queue -and [string]::IsNullOrWhiteSpace([string]$queue.PNPDeviceID)) {
                return [PSCustomObject]@{Code=''; Source='Win32_Printer.PRINT_QUEUE_NOT_PNP'; Error='PnP code not applicable to a confirmed print queue; queue operational health not tested'}
            }
            if ($queue -and $queue.PNPDeviceID) { $id=[string]$queue.PNPDeviceID }
        } catch { }
    }
    $native = Get-CmPnpFacts $id
    if ($native.Source -ne 'UNAVAILABLE') { return $native }
    try {
        $property = Get-PnpDeviceProperty -InstanceId $id -KeyName 'DEVPKEY_Device_ProblemCode' -ErrorAction Stop
        if ($null -ne $property.Data -and [uint32]::TryParse([string]$property.Data, [ref]$number)) {
            return [PSCustomObject]@{ Code=[string]$number; Source='Get-PnpDeviceProperty.DEVPKEY_Device_ProblemCode'; Error='' }
        }
        throw 'ProblemCode property is null or invalid'
    } catch {
        return [PSCustomObject]@{ Code=''; Source='UNAVAILABLE'; Error=($native.Error + '; PnpDeviceProperty: ' + $_.Exception.Message) }
    }
}

$script:AuditClock=[Diagnostics.Stopwatch]::StartNew()
function Audit-Progress([string]$phase,[int]$done=0,[int]$total=0) {
    Emit @('PROGRESS',$phase,$done,$total,[math]::Round($script:AuditClock.Elapsed.TotalSeconds,1))
    [Console]::Out.Flush()
}
$since = (Get-Date).AddDays(-$Days)
Audit-Progress 'PnP inventory'
Emit @('META', 'version', '1')
Emit @('META', 'generated', (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss'))
Emit @('META', 'window_days', $Days)

# ---------------------------------------------------------------- devices
$entities = @{}
try {
    foreach ($e in @(Get-CimInstance -ClassName Win32_PnPEntity -ErrorAction Stop)) {
        foreach ($key in @($e.PNPDeviceID,$e.DeviceID)) { if ($key) { $entities[([string]$key).Trim()] = $e } }
    }
} catch {
    try {
        foreach ($e in @(Get-WmiObject -Class Win32_PnPEntity -ErrorAction Stop)) {
            foreach ($key in @($e.PNPDeviceID,$e.DeviceID)) { if ($key) { $entities[([string]$key).Trim()] = $e } }
        }
    } catch { Emit @('ERR', 'Win32_PnPEntity CIM/WMI', $_.Exception.Message) }
}

$seen = @{}
$unsignedDev = @()
try {
    Audit-Progress 'Signed driver inventory'
    $signed=@(Get-CimInstance -ClassName Win32_PnPSignedDriver -ErrorAction Stop)
    $dates=@{};$dateErrors=@()
    Audit-Progress 'Native driver dates (batch)'
    try {
        $ids=@($signed|Where-Object DeviceID|ForEach-Object {[string]$_.DeviceID})
        if($ids.Count){
            # Bounded batches avoid the provider query quota for hundreds of IDs.
            for($offset=0;$offset -lt $ids.Count;$offset+=16){
                $last=[math]::Min($offset+15,$ids.Count-1)
                $batchErrors=@()
                Get-PnpDeviceProperty -InstanceId $ids[$offset..$last] -KeyName 'DEVPKEY_Device_DriverDate' -ErrorAction SilentlyContinue -ErrorVariable batchErrors | ForEach-Object {
                    if($_.InstanceId -and $null -ne $_.Data){$dates[[string]$_.InstanceId]=$_.Data}
                }
                $dateErrors+= $batchErrors
                Audit-Progress 'Native driver dates (batch)' ($last+1) $ids.Count
            }
        }
    } catch {$dateErrors+= $_}
    # A missing/problematic ID can suppress neighbours in a batch; recover every
    # absent result independently. No reduction in date coverage is accepted.
    $missingDates=@($signed|Where-Object {$_.DeviceID -and !$dates.ContainsKey([string]$_.DeviceID)})
    $recovered=0
    foreach($device in $missingDates){
        try {$prop=Get-PnpDeviceProperty -InstanceId ([string]$device.DeviceID) -KeyName 'DEVPKEY_Device_DriverDate' -ErrorAction Stop
            if($null -ne $prop.Data){$dates[[string]$device.DeviceID]=$prop.Data}
        }catch{$dateErrors+=$_}
        $recovered++;Audit-Progress 'Native date fallback' $recovered $missingDates.Count
    }
    $processed=0
    foreach ($d in $signed) {
        if (-not $d.DeviceID) { continue }
        $id = ([string]$d.DeviceID).Trim()
        $e = $entities[$id]
        $code = ''; $svc = ''
        $pnp = Resolve-PnpCode $e $id
        $code = $pnp.Code
        if ($e) { $svc = $e.Service }
        $cls = $d.DeviceClass
        if (-not $cls -and $e) { $cls = $e.PNPClass }
        $date = ''
        if ($d.DriverDate) { try { $date = ([datetime]$d.DriverDate).ToString('yyyy-MM-dd') } catch {} }
        $dateRaw=[string]$d.DriverDate
        $dateSource='Win32_PnPSignedDriver.DriverDate (fallback; native date unavailable)'
        try {
            if($dates.ContainsKey($id)) {
                $date=([datetime]$dates[$id]).ToString('yyyy-MM-dd',[Globalization.CultureInfo]::InvariantCulture)
                $dateSource='DEVPKEY_Device_DriverDate'
            } else {$dateSource+='; batch result absent; query errors='+$dateErrors.Count}
        } catch {$dateSource+='; '+$_.Exception.Message}
        $processed++
        if($processed % 25 -eq 0 -or $processed -eq $signed.Count){Audit-Progress 'Device metadata' $processed $signed.Count}
        $friendlyName = [string]$e.Name
        if ([string]::IsNullOrWhiteSpace($friendlyName)) { $friendlyName = [string]$d.DeviceName }
        if ([string]::IsNullOrWhiteSpace($friendlyName)) { $friendlyName = $id }
        Emit @('DEV', $cls, $friendlyName, $d.Manufacturer, $d.DriverProviderName, $d.DriverVersion,
               $date, $d.InfName, $code, $d.IsSigned, $id, $svc, $pnp.Source, $pnp.Error, $dateSource, $dateRaw)
        $seen[$id] = $true
        if ($e) { foreach ($key in @($e.PNPDeviceID,$e.DeviceID)) { if ($key) { $seen[([string]$key).Trim()]=$true } } }
        if ($d.IsSigned -eq $false) { $unsignedDev += [PSCustomObject]@{ Id = $id; Svc = [string]$svc; Inf = [string]$d.InfName } }
    }
} catch { Emit @('ERR', 'Win32_PnPSignedDriver', $_.Exception.Message) }

Audit-Progress 'Remaining PnP nodes'
# Include every remaining devnode, including code 0 without a signed-driver record.
foreach ($id in @($entities.Keys)) {
    if ($seen[$id]) { continue }
    $e = $entities[$id]
    if ($e.PNPDeviceID -and $id -ne ([string]$e.PNPDeviceID).Trim()) { continue }
    $pnp = Resolve-PnpCode $e $id
    Emit @('DEV', $e.PNPClass, $e.Name, $e.Manufacturer, '', '', '', '',
           $pnp.Code, '', $id, $e.Service, $pnp.Source, $pnp.Error)
}

# ---------------------------------------------------- kernel/system drivers
Audit-Progress 'System drivers / signatures'
$sysDrivers = @{}
try {
    foreach ($s in @(Get-CimInstance -ClassName Win32_SystemDriver -ErrorAction Stop)) {
        Emit @('SYS', $s.Name, $s.DisplayName, $s.PathName, $s.State, $s.StartMode, $s.ServiceType)
        $sysDrivers[[string]$s.Name] = $s
    }
} catch { Emit @('ERR', 'Win32_SystemDriver', $_.Exception.Message) }

# ------------------------------------- v1.0 independent signature check
function Get-SigFacts([string]$path) {
    if (-not $path -or -not (Test-Path -LiteralPath $path -PathType Leaf)) { return @('NotFound', '') }
    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $path -ErrorAction Stop
        $signer = ''
        if ($sig.SignerCertificate) { $signer = $sig.SignerCertificate.Subject }
        return @([string]$sig.Status, $signer)
    } catch { return @('Error', '') }
}
function Resolve-ImagePath([string]$raw) {
    if (-not $raw) { return '' }
    $p = $raw.Trim().Trim('"')
    if ($p.StartsWith('\??\')) { $p = $p.Substring(4) }
    if ($p -match '^\\SystemRoot\\(.*)$') { $p = Join-Path $env:SystemRoot $Matches[1] }
    elseif ($p -match '^(?i)system32\\') { $p = Join-Path $env:SystemRoot $p }
    return $p
}
foreach ($u in $unsignedDev) {
    $img = ''
    if ($u.Svc -and $sysDrivers[$u.Svc]) { $img = Resolve-ImagePath ([string]$sysDrivers[$u.Svc].PathName) }
    $is = Get-SigFacts $img
    $infPath = ''
    if ($u.Inf) { $infPath = Join-Path (Join-Path $env:SystemRoot 'INF') $u.Inf }
    $fs = Get-SigFacts $infPath
    Emit @('SIGCHK', $u.Id, $img, $is[0], $is[1], $fs[0], $fs[1])
}

function Get-DriverPackageFailure($Record,[string]$LogPath) {
    $original=[string]$Record.Exception.Message
    $hr=[int64]$Record.Exception.HResult -band 0xffffffffL
    $code='0x{0:X8}' -f $hr
    if(($Record|Out-String) -match '(?i)0xC0040009'){$code='0xC0040009'}
    $kind=if($code -eq '0xC0040009'){'DISMAPI_E_LOGGING_DISABLED'}else{'PACKAGE_QUERY_FAILED'}
    $description=if($code -eq '0xC0040009'){'DISM не получил доступ к журналу; список пакетов недоступен'}else{'Не удалось получить список пакетов драйверов'}
    return "$description; code=$code; category=$kind; scope=DRIVER_PACKAGE_COLLECTION; log=$LogPath; original=$original; not evidence of PnP failure or component-store corruption"
}

Audit-Progress 'Driver packages'
# ------------------------------------------- v1.0 driver package identity
try {
    # Private per-run log: do not rely on access to the Windows DISM log.
    $packageLogRoot=if($env:WSD_A5_LOG_DIR -and [IO.Directory]::Exists($env:WSD_A5_LOG_DIR)){$env:WSD_A5_LOG_DIR}else{$PSScriptRoot}
    $packageLog=Join-Path $packageLogRoot ('Dism-DriverPackages-'+[guid]::NewGuid().ToString('N')+'.log')
    foreach ($p in @(Get-WindowsDriver -Online -LogPath $packageLog -ErrorAction Stop)) {
        $pd = ''
        if ($p.Date) { try { $pd = ([datetime]$p.Date).ToString('yyyy-MM-dd') } catch {} }
        Emit @('PKG', $p.Driver, (Split-Path -Leaf ([string]$p.OriginalFileName)), $p.ProviderName, $p.ClassName, $p.Version, $pd)
    }
} catch {
    Emit @('ERR', 'Get-WindowsDriver', ((Get-DriverPackageFailure $_ $packageLog) + '; PS=' + $PSVersionTable.PSVersion + '; 64bit=' + [Environment]::Is64BitProcess))
}

Audit-Progress 'Event evidence'
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

Audit-Progress 'Completed'
Emit @('META', 'done', '1')
