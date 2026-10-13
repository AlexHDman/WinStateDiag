<#
WinStateDiag - Power Telemetry research probe (v1.0 research, NOT production)

READ-ONLY. Separate from the production sensor backend; nothing here is
linked into WinStateDiag.exe.

What it does:
  * reads Windows-native telemetry (performance counters via CIM, ACPI
    thermal zones, CIM probe classes, SMBIOS processor data);
  * queries the NVIDIA driver through nvidia-smi (query only) if present;
  * DETECTS (never starts, never installs) HWiNFO / AIDA64 shared memory,
    LibreHardwareMonitor / OpenHardwareMonitor WMI, PawnIO, Intel PMT and
    OEM WMI providers; reads HWiNFO / AIDA64 shared memory read-only ONLY
    if the user already runs them with shared memory enabled;
  * lists already-loaded third-party ring-0 I/O drivers as a SECURITY
    observation (it does not touch them).

It never: loads a driver, writes the registry, writes EC / Super-I/O /
SMBus, changes Memory Integrity, starts or installs HWiNFO / AIDA64 /
PawnIO / LHM, or calls any fan / clock control.

Every value row: parameter, sensor identity, value, unit, source,
timestamp, confidence, note.

Usage:  powershell -NoProfile -ExecutionPolicy Bypass -File Power-Telemetry-Probe.ps1 -OutDir <dir>
#>
param(
    [string]$OutDir = (Join-Path $PSScriptRoot '..\logs'),
    [int]$Samples = 3,
    [int]$IntervalMs = 1000
)

$ErrorActionPreference = 'Continue'
$null = New-Item -ItemType Directory -Force -Path $OutDir
$rows = New-Object System.Collections.Generic.List[object]
$presence = New-Object System.Collections.Generic.List[object]
$security = New-Object System.Collections.Generic.List[object]

function Now-Iso { (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss.fffzzz') }

function Add-Value {
    param([string]$Parameter, [string]$Identity, $Value, [string]$Unit,
          [string]$Source, [string]$Confidence, [string]$Note = '')
    $rows.Add([PSCustomObject]@{
        parameter = $Parameter; sensor_identity = $Identity
        value = $Value; unit = $Unit; source = $Source
        timestamp = (Now-Iso); confidence = $Confidence; note = $Note
    })
}

function Add-Presence {
    param([string]$Provider, [string]$State, [string]$Detail = '')
    $presence.Add([PSCustomObject]@{ provider = $Provider; state = $State; detail = $Detail; timestamp = (Now-Iso) })
}

$elevated = $false
try {
    $elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch { }

# ---------------------------------------------------------------- machine
$machine = [ordered]@{}
try {
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    $bb = Get-CimInstance Win32_BaseBoard -ErrorAction Stop
    $cpu = @(Get-CimInstance Win32_Processor -ErrorAction Stop)[0]
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $machine.system = ('{0} {1}' -f $cs.Manufacturer, $cs.Model).Trim()
    $machine.board = ('{0} {1}' -f $bb.Manufacturer, $bb.Product).Trim()
    $machine.cpu = ([string]$cpu.Name).Trim()
    $machine.cpu_vendor = [string]$cpu.Manufacturer
    $machine.arch = [string]$env:PROCESSOR_ARCHITECTURE
    $machine.os = ('{0} {1}' -f $os.Caption, $os.BuildNumber)
    $machine.gpus = @(Get-CimInstance Win32_VideoController | ForEach-Object { [string]$_.Name })
    $machine.pc_system_type = [int]$cs.PCSystemType   # 1 desktop, 2 mobile
} catch { $machine.error = $_.Exception.Message }
$machine.elevated = $elevated
try {
    $dg = Get-CimInstance -Namespace root/Microsoft/Windows/DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction Stop
    $machine.hvci_running = (@($dg.SecurityServicesRunning) -contains 2)
} catch { $machine.hvci_running = $null }

# ------------------------------------------------- 1. Windows native (CIM)
for ($s = 0; $s -lt [math]::Max(1, $Samples); $s++) {
    if ($s -gt 0) { Start-Sleep -Milliseconds $IntervalMs }
    $tag = "sample $($s + 1)"

    # CPU load: Processor Information(_Total) % Processor Utility (the
    # Task Manager definition on Windows 10/11).
    try {
        $pi = Get-CimInstance Win32_PerfFormattedData_Counters_ProcessorInformation -Filter "Name='_Total'" -ErrorAction Stop
        Add-Value 'CPU_LOAD' 'Processor Information(_Total)' ([double]$pi.PercentProcessorUtility) '%' 'Windows PDH (CIM Win32_PerfFormattedData_Counters_ProcessorInformation.PercentProcessorUtility)' 'HIGH' $tag
    } catch { }

    # GPU load: max over engine types of the per-engine-type sum, per
    # adapter LUID (Task Manager style).
    try {
        $eng = @(Get-CimInstance Win32_PerfFormattedData_GPUPerformanceCounters_GPUEngine -ErrorAction Stop)
        $byLuid = @{}
        foreach ($e in $eng) {
            if ($e.Name -match '^pid_\d+_luid_(0x[0-9A-Fa-f]+_0x[0-9A-Fa-f]+)_phys_\d+_eng_\d+_engtype_(.+)$') {
                $luid = $Matches[1]; $type = $Matches[2]
                if (-not $byLuid.ContainsKey($luid)) { $byLuid[$luid] = @{} }
                if (-not $byLuid[$luid].ContainsKey($type)) { $byLuid[$luid][$type] = 0.0 }
                $byLuid[$luid][$type] += [double]$e.UtilizationPercentage
            }
        }
        foreach ($luid in $byLuid.Keys) {
            $max = ($byLuid[$luid].Values | Measure-Object -Maximum).Maximum
            Add-Value 'GPU_LOAD' "GPU Engine luid_$luid" ([math]::Min(100, [double]$max)) '%' 'Windows PDH (CIM GPUPerformanceCounters_GPUEngine, max engine type)' 'MEDIUM' "$tag; adapter by LUID, not by name"
        }
    } catch { }
}

# ACPI thermal zones via PDH (Thermal Zone Information): HighPrecision
# is tenths of Kelvin.
try {
    foreach ($z in @(Get-CimInstance Win32_PerfFormattedData_Counters_ThermalZoneInformation -ErrorAction Stop)) {
        $k = if ($z.HighPrecisionTemperature) { [double]$z.HighPrecisionTemperature / 10.0 } else { [double]$z.Temperature }
        if ($k -gt 0) {
            Add-Value 'ACPI_THERMAL_ZONE' ([string]$z.Name) ([math]::Round($k - 273.15, 1)) 'C' 'Windows PDH Thermal Zone Information' 'LOW' 'ACPI zone (firmware-defined, often static / not CPU package)'
        }
    }
} catch { }
try {
    foreach ($z in @(Get-CimInstance -Namespace root/wmi -ClassName MSAcpi_ThermalZoneTemperature -ErrorAction Stop)) {
        Add-Value 'ACPI_THERMAL_ZONE' ([string]$z.InstanceName) ([math]::Round(([double]$z.CurrentTemperature / 10.0) - 273.15, 1)) 'C' 'WMI root/wmi MSAcpi_ThermalZoneTemperature' 'LOW' 'ACPI zone'
    }
} catch { Add-Presence 'MSAcpi_ThermalZoneTemperature' 'NO DATA' $_.Exception.Message }

# Energy Meter (EMI) / Power Meter counters: native Windows power
# telemetry where the platform exposes an EMI device (RAPL on some Intel
# systems, Snapdragon PMIC, battery). Units: Power = mW, Energy = pJ.
foreach ($cls in 'Win32_PerfFormattedData_PowerMeterCounter_EnergyMeter', 'Win32_PerfFormattedData_PowerMeterCounter_PowerMeter') {
    try {
        $inst = @(Get-CimInstance $cls -ErrorAction Stop)
        if ($inst.Count -eq 0) { Add-Presence $cls 'NO INSTANCES' 'class registered, no EMI device exposed' }
        foreach ($m in $inst) {
            $p = $null
            foreach ($prop in 'Power', 'PowerBudget') { if ($null -ne $m.$prop -and $null -eq $p) { $p = [double]$m.$prop } }
            # The RAPL domain is the LAST name part (RAPL_Package0_PKG):
            # 'Package0' is the socket, not the domain.
            $domain = ([string]$m.Name).Split('_')[-1].ToUpperInvariant()
            $param = switch ($domain) {
                'PKG' { 'CPU_PACKAGE_POWER' }
                'PP0' { 'CPU_CORES_POWER' }
                'PP1' { 'IGPU_POWER' }
                'DRAM' { 'DRAM_POWER' }
                'PSYS' { 'PLATFORM_POWER' }
                default { 'EMI_CHANNEL_POWER' }
            }
            if ($m.Name -eq '_Total') { continue }
            if ($null -ne $p) {
                $w = [math]::Round($p / 1000.0, 3)
                if ($w -le 0 -and $domain -eq 'DRAM') {
                    Add-Value $param ("$cls/" + [string]$m.Name) $null 'W' "Windows EMI ($cls)" 'NONE' 'channel exposed but reports 0 (DRAM RAPL not supported on this platform) -> NO DATA'
                } else {
                    Add-Value $param ("$cls/" + [string]$m.Name) $w 'W' "Windows EMI ($cls), Power in mW / 1000" 'HIGH' 'RAPL energy counter published by the platform EMI provider; CPU/SoC power, never PSU output power'
                }
            }
        }
    } catch { Add-Presence $cls 'NOT REGISTERED' $_.Exception.Message }
}

# CIM probe classes (SMBIOS / vendor): usually empty on desktops.
foreach ($c in @(
        @{ cls = 'Win32_Fan'; param = 'FAN_RPM'; prop = 'DesiredSpeed'; unit = 'RPM' },
        @{ cls = 'Win32_VoltageProbe'; param = 'VOLTAGE_PROBE'; prop = 'CurrentReading'; unit = 'mV' },
        @{ cls = 'Win32_TemperatureProbe'; param = 'TEMPERATURE_PROBE'; prop = 'CurrentReading'; unit = 'dC' },
        @{ cls = 'Win32_CurrentProbe'; param = 'CURRENT_PROBE'; prop = 'CurrentReading'; unit = 'mA' })) {
    try {
        $inst = @(Get-CimInstance $c.cls -ErrorAction Stop)
        if ($inst.Count -eq 0) { Add-Presence $c.cls 'NO INSTANCES' '' }
        foreach ($i in $inst) {
            $v = $i.($c.prop)
            Add-Value $c.param ("$($c.cls)/" + [string]$i.DeviceID + ' ' + [string]$i.Description) $v $c.unit "CIM $($c.cls)" 'LOW' $(if ($null -eq $v) { 'instance without a live reading (SMBIOS descriptor only)' } else { 'SMBIOS probe; often static' })
        }
    } catch { Add-Presence $c.cls 'ERROR' $_.Exception.Message }
}

# SMBIOS processor voltage: a static descriptor, NOT live Vcore / VID.
try {
    foreach ($p in @(Get-CimInstance Win32_Processor -ErrorAction Stop)) {
        if ($p.CurrentVoltage) {
            Add-Value 'CPU_VOLTAGE_SMBIOS' ([string]$p.DeviceID) ([double]$p.CurrentVoltage / 10.0) 'V' 'CIM Win32_Processor.CurrentVoltage (SMBIOS type 4)' 'LOW' 'static SMBIOS value, not live Vcore / VID'
        }
    }
} catch { }

# ------------------------------------------------- 2. GPU vendor (read-only)
$smi = $null
foreach ($cand in @((Get-Command nvidia-smi.exe -ErrorAction SilentlyContinue).Source, "$env:SystemRoot\System32\nvidia-smi.exe", "$env:ProgramFiles\NVIDIA Corporation\NVSMI\nvidia-smi.exe")) {
    if ($cand -and (Test-Path -LiteralPath $cand)) { $smi = $cand; break }
}
if ($smi) {
    try {
        $q = 'name,uuid,power.draw,power.limit,temperature.gpu,utilization.gpu,fan.speed,clocks.gr'
        $lines = @(& $smi "--query-gpu=$q" '--format=csv,noheader,nounits' 2>$null)
        foreach ($l in $lines) {
            $f = @($l.Split(',') | ForEach-Object { $_.Trim() })
            if ($f.Count -lt 8) { continue }
            $id = "$($f[0]) [$($f[1])]"
            $num = { param($x) $d = 0.0; if ([double]::TryParse($x, [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$d)) { $d } else { $null } }
            Add-Value 'GPU_POWER' $id (& $num $f[2]) 'W' 'NVIDIA NVML via nvidia-smi (query only)' 'HIGH' ("board power draw; limit {0} W" -f $f[3])
            Add-Value 'GPU_TEMP' $id (& $num $f[4]) 'C' 'NVIDIA NVML via nvidia-smi (query only)' 'HIGH' ''
            Add-Value 'GPU_LOAD' $id (& $num $f[5]) '%' 'NVIDIA NVML via nvidia-smi (query only)' 'HIGH' ''
            Add-Value 'GPU_FAN' $id (& $num $f[6]) '%' 'NVIDIA NVML via nvidia-smi (query only)' 'HIGH' 'percent of max, not RPM; 0 = zero-RPM mode'
        }
        Add-Presence 'nvidia-smi' 'PRESENT' $smi
    } catch { Add-Presence 'nvidia-smi' 'ERROR' $_.Exception.Message }
} else { Add-Presence 'nvidia-smi' 'ABSENT' '' }

# ------------------------------------------------- 3. Optional providers (detect / read-only)
function Read-SharedMemoryHeader {
    param([string[]]$Names, [int]$Bytes)
    foreach ($n in $Names) {
        try {
            $mmf = [IO.MemoryMappedFiles.MemoryMappedFile]::OpenExisting($n, [IO.MemoryMappedFiles.MemoryMappedFileRights]::Read)
            try {
                $view = $mmf.CreateViewAccessor(0, $Bytes, [IO.MemoryMappedFiles.MemoryMappedFileAccess]::Read)
                $buf = New-Object byte[] $Bytes
                $null = $view.ReadArray(0, $buf, 0, $Bytes)
                $view.Dispose()
                return @{ name = $n; bytes = $buf }
            } finally { $mmf.Dispose() }
        } catch { }
    }
    return $null
}

# HWiNFO Shared Memory (only when the user runs HWiNFO with SM enabled).
$hw = Read-SharedMemoryHeader @('Global\HWiNFO_SENS_SM2', 'HWiNFO_SENS_SM2') 44
if ($hw) {
    $b = $hw.bytes
    $sig = [Text.Encoding]::ASCII.GetString($b, 0, 4)
    Add-Presence 'HWiNFO Shared Memory' 'PRESENT (read-only)' ("{0}; signature {1}; version {2}.{3}; sensors {4}; readings {5}" -f $hw.name, $sig, [BitConverter]::ToUInt32($b, 4), [BitConverter]::ToUInt32($b, 8), [BitConverter]::ToUInt32($b, 28), [BitConverter]::ToUInt32($b, 40))
} else {
    $running = [bool](Get-Process -Name 'HWiNFO*' -ErrorAction SilentlyContinue)
    Add-Presence 'HWiNFO Shared Memory' $(if ($running) { 'RUNNING, SHARED MEMORY OFF' } else { 'NOT RUNNING' }) 'never started by the probe'
}

# AIDA64 shared memory (reference only).
$ai = Read-SharedMemoryHeader @('AIDA64_SensorValues') 16
if ($ai) { Add-Presence 'AIDA64 Shared Memory' 'PRESENT (reference only)' $ai.name }
else {
    $running = [bool](Get-Process -Name 'aida64*' -ErrorAction SilentlyContinue)
    Add-Presence 'AIDA64 Shared Memory' $(if ($running) { 'RUNNING, SHARED MEMORY OFF' } else { 'NOT RUNNING' }) 'never started by the probe'
}

# LHM / OHM WMI (only when that app runs with WMI publishing).
foreach ($ns in 'root/LibreHardwareMonitor', 'root/OpenHardwareMonitor') {
    try {
        $s = @(Get-CimInstance -Namespace $ns -ClassName Sensor -ErrorAction Stop)
        Add-Presence "$ns WMI" 'PRESENT' ("{0} sensors" -f $s.Count)
        foreach ($x in $s) {
            Add-Value ("LHM_" + [string]$x.SensorType).ToUpperInvariant() ([string]$x.Identifier) $x.Value ([string]$x.SensorType) "$ns WMI (running app)" 'MEDIUM' ([string]$x.Name)
        }
    } catch { Add-Presence "$ns WMI" 'ABSENT' '' }
}

# PawnIO (detect only; security research).
$pawn = @(Get-CimInstance Win32_SystemDriver -Filter "Name='PawnIO'" -ErrorAction SilentlyContinue)
Add-Presence 'PawnIO driver' $(if ($pawn.Count) { 'PRESENT (' + $pawn[0].State + ')' } else { 'ABSENT' }) 'detect only; never installed'

# Intel PMT (Platform Monitoring Technology) PnP device.
$pmt = @(Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue | Where-Object { $_.FriendlyName -match 'Platform Monitoring|PMT|Telemetry Aggregator' })
Add-Presence 'Intel PMT device' $(if ($pmt.Count) { 'PRESENT' } else { 'ABSENT' }) (($pmt | ForEach-Object { "$($_.FriendlyName) [$($_.Status)]" }) -join '; ')

# Intel / AMD vendor SDK footprints (detect only).
Add-Presence 'AMD Ryzen Master Monitoring SDK' $(if (Test-Path "$env:ProgramFiles\AMD\RyzenMasterMonitoringSDK") { 'PRESENT' } else { 'ABSENT' }) 'SDK requires AMD CPU + AMD-signed driver from the Ryzen Master install'
Add-Presence 'Intel ME WMI (root/Intel_ME)' $(if (Get-CimInstance -Namespace root -ClassName __Namespace -Filter "Name='Intel_ME'" -ErrorAction SilentlyContinue) { 'PRESENT' } else { 'ABSENT' }) 'management engine info; no sensor telemetry'

# OEM WMI namespaces / classes (read-only class listing).
$oem = @()
foreach ($ns in 'root/WMI', 'root/HP/InstrumentedBIOS', 'root/dcim/sysman', 'root/Lenovo', 'root/ASUS', 'root/MSI') {
    try {
        $cls = @(Get-CimClass -Namespace $ns -ErrorAction Stop | Where-Object { $_.CimClassName -cmatch '^(MSI_|Lenovo_|HP_|HPBIOS_|DCIM_|ASUS|AsusAtk|Acer|Dell|Gigabyte|GB_|ASRock)' } | Select-Object -ExpandProperty CimClassName)
        if ($cls.Count) { $oem += "$ns : " + (($cls | Select-Object -First 25) -join ', ') }
    } catch { }
}
Add-Presence 'OEM WMI providers' $(if ($oem.Count) { 'PRESENT' } else { 'ABSENT' }) ($oem -join ' | ')
$oemSw = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '(?i)MSI.?Center|MSI_Central|DragonCenter|Armoury|LenovoVantage|HPSystemEventUtility|DellOptimizer|GCC' } | Select-Object -ExpandProperty Name -Unique)
Add-Presence 'OEM monitoring software running' $(if ($oemSw.Count) { 'PRESENT' } else { 'ABSENT' }) ($oemSw -join ', ')

# ------------------------------------------------- 4. Security observation
$risky = 'WinRing0|WinRing0x64|MsIo|NTIOLib|RTCore|AsIO|inpout|GLCKIO|Phymem|EneIo|HwRw|AsrDrv|BS_|PawnIO'
foreach ($d in @(Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue | Where-Object { $_.Name -match $risky -or $_.PathName -match $risky })) {
    $sig = $null
    $file = ([string]$d.PathName) -replace '^\\\?\?\\', ''
    try { $a = Get-AuthenticodeSignature -LiteralPath $file -ErrorAction Stop; $sig = ('{0}; {1}' -f $a.Status, $(if ($a.SignerCertificate) { $a.SignerCertificate.Subject } else { 'no embedded signer (catalog-signed or unsigned)' })) } catch { }
    $security.Add([PSCustomObject]@{ driver = [string]$d.Name; state = [string]$d.State; path = $file; signer = $sig; note = 'third-party ring-0 port/MSR I/O driver already present; NOT used by WinStateDiag' })
}

# ------------------------------------------------- output
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$out = [ordered]@{
    format = 'winstatediag.power_probe/1'
    produced_at = (Now-Iso)
    read_only = $true
    machine = $machine
    values = $rows
    providers = $presence
    security_observations = $security
}
$json = Join-Path $OutDir "power_probe_$stamp.json"
$out | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $json -Encoding UTF8
Write-Output "WSD_POWER_PROBE $json"
