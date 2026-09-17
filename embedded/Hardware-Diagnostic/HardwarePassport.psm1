Set-StrictMode -Version 2.0
Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) 'Compatibility.psm1')

function Get-HardwareValue {
    param([AllowNull()][object]$Object, [string]$Name, [AllowNull()][object]$Default = $null)
    if ($null -eq $Object) { return $Default }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value) { return $Default }
    return $property.Value
}

function ConvertTo-HardwareText {
    param([AllowNull()][object]$Value, [string]$Default = 'Unavailable')
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $Default }
    return ([string]$Value).Trim()
}

function ConvertTo-HardwareSize {
    param([AllowNull()][object]$Bytes)
    if ($null -eq $Bytes) { return 'Unavailable' }
    if ([double]$Bytes -ge 1TB) { return ('{0:N2} TB' -f ([double]$Bytes / 1TB)) }
    if ([double]$Bytes -ge 1GB) { return ('{0:N2} GB' -f ([double]$Bytes / 1GB)) }
    return ('{0:N2} MB' -f ([double]$Bytes / 1MB))
}

function Get-HardwareMemoryType {
    param([AllowNull()][object]$Code)
    switch ([int]$Code) { 20 { 'DDR' } 21 { 'DDR2' } 24 { 'DDR3' } 26 { 'DDR4' } 30 { 'LPDDR4' } 34 { 'DDR5' } 35 { 'LPDDR5' } default { 'Unknown' } }
}

function Get-HardwareOverallState {
    param([object[]]$States)
    $values = @($States | Where-Object { $_ -in @('OK','WARNING','CRITICAL','UNKNOWN') })
    if ($values -contains 'CRITICAL') { return 'CRITICAL' }
    if ($values -contains 'WARNING') { return 'WARNING' }
    if ($values -contains 'UNKNOWN') { return 'UNKNOWN' }
    if ($values -contains 'OK') { return 'OK' }
    return 'UNKNOWN'
}

function Get-HardwareSource {
    param([switch]$DisableModernStorage,[switch]$DisableFirmwareProbe,[scriptblock]$InstanceReader)
    $errors = New-Object System.Collections.Generic.List[string]
    function Read-CimLocal {
        param([string]$ClassName)
        try {
            if($InstanceReader){return @(& $InstanceReader $ClassName)}
            return @(Get-CompatInstance -ClassName $ClassName)
        }
        catch { $errors.Add("${ClassName}: $($_.Exception.Message)"); return @() }
    }

    $physicalDisks = @()
    $reliability = @()
    if (-not $DisableModernStorage -and (Get-Command Get-PhysicalDisk -ErrorAction SilentlyContinue)) {
        try {
            $physicalDisks = @(Get-PhysicalDisk -ErrorAction Stop)
            if (Get-Command Get-StorageReliabilityCounter -ErrorAction SilentlyContinue) {
                foreach ($disk in $physicalDisks) {
                    try {
                        $counter = $disk | Get-StorageReliabilityCounter -ErrorAction Stop
                        if ($counter) {
                            $reliability += [PSCustomObject]@{ DeviceId=$disk.DeviceId; Temperature=$counter.Temperature; Wear=$counter.Wear; PowerOnHours=$counter.PowerOnHours; ReadErrorsTotal=$counter.ReadErrorsTotal; WriteErrorsTotal=$counter.WriteErrorsTotal }
                        }
                    } catch { $errors.Add("StorageReliability[$($disk.DeviceId)]: $($_.Exception.Message)") }
                }
            }
        } catch { $errors.Add("Get-PhysicalDisk: $($_.Exception.Message)") }
    }

    $firmwareType = 'UNKNOWN'
    if (-not $DisableFirmwareProbe) { try {
        if (-not ('ExpcHardwareFirmwareNative' -as [type])) {
            Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class ExpcHardwareFirmwareNative {
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool GetFirmwareType(out UInt32 firmwareType);
}
'@
        }
        [uint32]$nativeFirmwareType = 0
        if ([ExpcHardwareFirmwareNative]::GetFirmwareType([ref]$nativeFirmwareType)) {
            $firmwareType = switch ($nativeFirmwareType) { 1 { 'Legacy BIOS' } 2 { 'UEFI' } default { 'UNKNOWN' } }
        } else { $errors.Add("GetFirmwareType: Win32 error $([Runtime.InteropServices.Marshal]::GetLastWin32Error())") }
    } catch { $errors.Add("FirmwareType: $($_.Exception.Message)") } }

    [PSCustomObject]@{
        System = @(Read-CimLocal Win32_ComputerSystem | Select-Object -First 1)
        OperatingSystem = @(Read-CimLocal Win32_OperatingSystem | Select-Object -First 1)
        Product = @(Read-CimLocal Win32_ComputerSystemProduct | Select-Object -First 1)
        BaseBoard = @(Read-CimLocal Win32_BaseBoard | Select-Object -First 1)
        Bios = @(Read-CimLocal Win32_BIOS | Select-Object -First 1)
        Processors = @(Read-CimLocal Win32_Processor)
        MemoryModules = @(Read-CimLocal Win32_PhysicalMemory)
        MemoryArrays = @(Read-CimLocal Win32_PhysicalMemoryArray)
        VideoControllers = @(Read-CimLocal Win32_VideoController)
        Disks = @(Read-CimLocal Win32_DiskDrive)
        PhysicalDisks = $physicalDisks
        Reliability = $reliability
        NetworkAdapters = @(Read-CimLocal Win32_NetworkAdapter)
        NetworkConfigurations = @(Read-CimLocal Win32_NetworkAdapterConfiguration)
        Batteries = @(Read-CimLocal Win32_Battery)
        FirmwareType = $firmwareType
        Errors = @($errors)
    }
}

function New-HardwarePassport {
    [CmdletBinding()]
    param([AllowNull()][object]$Source)
    if ($null -eq $Source) { $Source = Get-HardwareSource }

    $system = @($Source.System | Select-Object -First 1)[0]
    $operatingSystem = @($Source.OperatingSystem | Select-Object -First 1)[0]
    $product = @($Source.Product | Select-Object -First 1)[0]
    $board = @($Source.BaseBoard | Select-Object -First 1)[0]
    $bios = @($Source.Bios | Select-Object -First 1)[0]
    $processors = @($Source.Processors)
    $memory = @($Source.MemoryModules)
    $arrays = @($Source.MemoryArrays)
    $physical = @($Source.PhysicalDisks)
    $wmiDisks = @($Source.Disks)
    $reliability = @($Source.Reliability)

    $ramRows = @($memory | ForEach-Object {
        $speed = Get-HardwareValue $_ 'Speed'
        $configured = Get-HardwareValue $_ 'ConfiguredClockSpeed'
        [PSCustomObject]@{
            Manufacturer = ConvertTo-HardwareText (Get-HardwareValue $_ 'Manufacturer')
            PartNumber = ConvertTo-HardwareText (Get-HardwareValue $_ 'PartNumber')
            CapacityBytes = Get-HardwareValue $_ 'Capacity'
            Capacity = ConvertTo-HardwareSize (Get-HardwareValue $_ 'Capacity')
            Type = Get-HardwareMemoryType (Get-HardwareValue $_ 'SMBIOSMemoryType' 0)
            RatedSpeedMHz = $speed
            ConfiguredClockMHz = $configured
            DeviceLocator = ConvertTo-HardwareText (Get-HardwareValue $_ 'DeviceLocator')
            BankLabel = ConvertTo-HardwareText (Get-HardwareValue $_ 'BankLabel')
            Serial = ConvertTo-HardwareText (Get-HardwareValue $_ 'SerialNumber')
            State = $(if($speed -and $configured -and [int]$configured -lt [int]$speed){'WARNING'}elseif(-not (Get-HardwareValue $_ 'DeviceLocator')){'INFO'}else{'OK'})
        }
    })
    $ramReasons = @()
    $capacities = @($ramRows | Where-Object CapacityBytes | ForEach-Object CapacityBytes | Sort-Object -Unique)
    $speeds = @($ramRows | Where-Object RatedSpeedMHz | ForEach-Object RatedSpeedMHz | Sort-Object -Unique)
    if ($capacities.Count -gt 1) { $ramReasons += 'Mixed module capacities.' }
    if ($speeds.Count -gt 1) { $ramReasons += 'Mixed declared module speeds.' }
    if (@($ramRows | Where-Object { $_.RatedSpeedMHz -and $_.ConfiguredClockMHz -and [int]$_.ConfiguredClockMHz -lt [int]$_.RatedSpeedMHz }).Count) { $ramReasons += 'One or more modules run below their declared speed.' }
    $declaredSlots = [int](($arrays | Measure-Object MemoryDevices -Sum).Sum)
    $ramState = if (-not $ramRows.Count) { 'UNKNOWN' } elseif ($ramReasons.Count) { 'WARNING' } elseif ($declaredSlots -le 0 -or @($ramRows | Where-Object DeviceLocator -eq 'Unavailable').Count) { 'INFO' } else { 'OK' }

    $diskRows = @()
    if ($physical.Count) {
        $diskRows = @($physical | ForEach-Object {
            $disk = $_
            $health = ConvertTo-HardwareText (Get-HardwareValue $disk 'HealthStatus') 'UNKNOWN'
            $operational = @((Get-HardwareValue $disk 'OperationalStatus' @()) | ForEach-Object { [string]$_ })
            $state = if ($health -match 'Unhealthy|Critical|Failed' -or $operational -match 'Lost Communication|Failed') { 'CRITICAL' }
                elseif ($health -match 'Warning|Degraded' -or $operational -match 'Degraded|Predictive Failure') { 'WARNING' }
                elseif ($health -eq 'Healthy' -or $operational -contains 'OK') { 'OK' } else { 'UNKNOWN' }
            $counter = @($reliability | Where-Object { [string]$_.DeviceId -eq [string]$disk.DeviceId } | Select-Object -First 1)[0]
            [PSCustomObject]@{
                Model=ConvertTo-HardwareText (Get-HardwareValue $disk 'FriendlyName'); Serial=ConvertTo-HardwareText (Get-HardwareValue $disk 'SerialNumber')
                CapacityBytes=Get-HardwareValue $disk 'Size'; Capacity=ConvertTo-HardwareSize (Get-HardwareValue $disk 'Size')
                MediaType=ConvertTo-HardwareText (Get-HardwareValue $disk 'MediaType') 'Unspecified'; BusType=ConvertTo-HardwareText (Get-HardwareValue $disk 'BusType')
                Firmware=ConvertTo-HardwareText (Get-HardwareValue $disk 'FirmwareVersion'); HealthStatus=$health; OperationalStatus=$operational
                Health=$state; HealthReason=$(if ($state -eq 'UNKNOWN') { 'Windows storage health data unavailable.' } else { "Windows reports $health / $($operational -join ', ')." })
                Reliability=$(if ($counter) { [PSCustomObject]@{ TemperatureC=$counter.Temperature; WearPercent=$counter.Wear; PowerOnHours=$counter.PowerOnHours; ReadErrorsTotal=$counter.ReadErrorsTotal; WriteErrorsTotal=$counter.WriteErrorsTotal } } else { $null })
            }
        })
    } else {
        $diskRows = @($wmiDisks | ForEach-Object {
            $status = ConvertTo-HardwareText (Get-HardwareValue $_ 'Status') 'UNKNOWN'
            [PSCustomObject]@{ Model=ConvertTo-HardwareText $_.Model; Serial=ConvertTo-HardwareText $_.SerialNumber; CapacityBytes=$_.Size; Capacity=ConvertTo-HardwareSize $_.Size
                MediaType=ConvertTo-HardwareText $_.MediaType 'Unspecified'; BusType=ConvertTo-HardwareText $_.InterfaceType; Firmware=ConvertTo-HardwareText $_.FirmwareRevision
                HealthStatus=$status; OperationalStatus=@($status); Health='UNKNOWN'; HealthReason='Windows does not expose trustworthy storage health data on this platform.'; Reliability=$null }
        })
    }

    $gpus = @($Source.VideoControllers | Where-Object { $_.Name -notmatch '(?i)Remote Display Adapter|Virtual Display|Microsoft Basic Display' } | ForEach-Object {
        $vram = Get-HardwareValue $_ 'AdapterRAM'
        [PSCustomObject]@{ Name=ConvertTo-HardwareText $_.Name; DriverVersion=ConvertTo-HardwareText $_.DriverVersion; VRAMBytes=$vram; VRAM=$(if ($vram) { ConvertTo-HardwareSize $vram } else { 'Unavailable' }); PnpId=ConvertTo-HardwareText $_.PNPDeviceID }
    })
    $networkConfigurations=@(Get-HardwareValue $Source 'NetworkConfigurations' @())
    $networks = @($Source.NetworkAdapters | Where-Object {
        $pnp=[string](Get-HardwareValue $_ 'PNPDeviceID' '')
        $physical=Get-HardwareValue $_ 'PhysicalAdapter'
        $name=[string](Get-HardwareValue $_ 'Name' '')
        ($physical -eq $true -or $pnp -match '^(?i:PCI|USB)\\') -and $pnp -match '^(?i:PCI|USB)\\' -and $name -notmatch '(?i)Bluetooth.*Personal Area Network|Virtual|Loopback|WAN Miniport'
    } | ForEach-Object {
        $adapter=$_;$index=Get-HardwareValue $adapter 'Index';$configuration=@($networkConfigurations|Where-Object{(Get-HardwareValue $_ 'Index') -eq $index}|Select-Object -First 1)[0]
        $mac=Get-HardwareValue $adapter 'MACAddress' (Get-HardwareValue $configuration 'MACAddress')
        $enabled=Get-HardwareValue $adapter 'NetEnabled' (Get-HardwareValue $configuration 'IPEnabled')
        [PSCustomObject]@{ Name=ConvertTo-HardwareText (Get-HardwareValue $adapter 'Name'); Manufacturer=ConvertTo-HardwareText (Get-HardwareValue $adapter 'Manufacturer'); MAC=[string]$mac; LinkState=$(if ($enabled -eq $true) { 'CONNECTED' } elseif ($enabled -eq $false) { 'DISCONNECTED' } else { 'UNKNOWN' }); AdapterType=ConvertTo-HardwareText (Get-HardwareValue $adapter 'AdapterType'); PnpId=ConvertTo-HardwareText (Get-HardwareValue $adapter 'PNPDeviceID') }
    })
    $batteries = @($Source.Batteries | ForEach-Object {
        [PSCustomObject]@{ Name=ConvertTo-HardwareText $_.Name; StatusCode=Get-HardwareValue $_ 'BatteryStatus'; ChargePercent=Get-HardwareValue $_ 'EstimatedChargeRemaining'; DesignCapacity=Get-HardwareValue $_ 'DesignCapacity'; FullChargeCapacity=Get-HardwareValue $_ 'FullChargeCapacity' }
    })
    $batteryState = if (-not $batteries.Count) { 'INFO' } elseif (@($batteries | Where-Object { $null -ne $_.ChargePercent -and [int]$_.ChargePercent -lt 10 }).Count) { 'WARNING' } else { 'INFO' }
    $storageState = Get-HardwareOverallState @($diskRows | ForEach-Object Health)
    $overall = Get-HardwareOverallState @($ramState, $storageState, $batteryState)

    [PSCustomObject][ordered]@{
        Tool='EXPC Hardware Diagnostics'; SchemaVersion=1; GeneratedAt=(Get-Date).ToString('o'); ReadOnly=$true; OverallState=$overall
        System=[PSCustomObject]@{ Manufacturer=ConvertTo-HardwareText (Get-HardwareValue $system 'Manufacturer'); Model=ConvertTo-HardwareText (Get-HardwareValue $system 'Model'); Hostname=$(if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { ConvertTo-HardwareText (Get-HardwareValue $system 'Name') }); SystemType=ConvertTo-HardwareText (Get-HardwareValue $system 'SystemType'); WindowsEdition=ConvertTo-HardwareText (Get-HardwareValue $operatingSystem 'Caption'); WindowsBuild=ConvertTo-HardwareText (Get-HardwareValue $operatingSystem 'BuildNumber'); WindowsArchitecture=ConvertTo-HardwareText (Get-HardwareValue $operatingSystem 'OSArchitecture' $env:PROCESSOR_ARCHITECTURE); ProductId=ConvertTo-HardwareText (Get-HardwareValue $product 'IdentifyingNumber') }
        Motherboard=[PSCustomObject]@{ Manufacturer=ConvertTo-HardwareText (Get-HardwareValue $board 'Manufacturer'); Product=ConvertTo-HardwareText (Get-HardwareValue $board 'Product'); Version=ConvertTo-HardwareText (Get-HardwareValue $board 'Version'); Serial=ConvertTo-HardwareText (Get-HardwareValue $board 'SerialNumber') }
        Bios=[PSCustomObject]@{ Manufacturer=ConvertTo-HardwareText (Get-HardwareValue $bios 'Manufacturer'); Version=ConvertTo-HardwareText (Get-HardwareValue $bios 'SMBIOSBIOSVersion' (Get-HardwareValue $bios 'Version')); ReleaseDate=Get-HardwareValue $bios 'ReleaseDate'; FirmwareType=ConvertTo-HardwareText $Source.FirmwareType 'UNKNOWN' }
        Cpu=[PSCustomObject]@{ Models=@($processors | ForEach-Object { ConvertTo-HardwareText $_.Name }); Manufacturers=@($processors | ForEach-Object { ConvertTo-HardwareText $_.Manufacturer }|Sort-Object -Unique); PhysicalCores=[int](($processors | Measure-Object NumberOfCores -Sum).Sum); LogicalProcessors=[int](($processors | Measure-Object NumberOfLogicalProcessors -Sum).Sum); MaxClockMHz=$(($processors | Measure-Object MaxClockSpeed -Maximum).Maximum); CurrentClockMHz=$(($processors | Measure-Object CurrentClockSpeed -Maximum).Maximum); Sockets=@($processors | ForEach-Object SocketDesignation | Where-Object { $_ }); Architecture=$(switch([int](Get-HardwareValue ($processors|Select-Object -First 1) 'Architecture' -1)){0{'x86'}5{'ARM'}9{'x64'}12{'ARM64'}default{'Unknown'}}); L2CacheKB=[int](($processors|Measure-Object L2CacheSize -Sum).Sum); L3CacheKB=[int](($processors|Measure-Object L3CacheSize -Sum).Sum) }
        Ram=[PSCustomObject]@{ State=$ramState; Reasons=$ramReasons; TotalBytes=[uint64](($memory | Measure-Object Capacity -Sum).Sum); Total=ConvertTo-HardwareSize (($memory | Measure-Object Capacity -Sum).Sum); ModuleCount=$ramRows.Count; DeclaredSlots=$declaredSlots; Modules=$ramRows }
        Storage=[PSCustomObject]@{ State=$storageState; Disks=$diskRows }
        Gpu=[PSCustomObject]@{ State=$(if ($gpus.Count) { 'INFO' } else { 'UNKNOWN' }); Controllers=$gpus }
        Network=[PSCustomObject]@{ State=$(if ($networks.Count) { 'INFO' } else { 'UNKNOWN' }); Adapters=$networks }
        Battery=[PSCustomObject]@{ State=$batteryState; Detected=($batteries.Count -gt 0); Summary=$(if ($batteries.Count) { 'Battery detected.' } else { 'Not applicable / not detected.' }); Batteries=$batteries }
        CollectionErrors=@($Source.Errors)
    }
}

Export-ModuleMember -Function New-HardwarePassport,Get-HardwareOverallState,ConvertTo-HardwareSize
