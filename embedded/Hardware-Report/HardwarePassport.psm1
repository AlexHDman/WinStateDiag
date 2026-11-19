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
    switch ([int]$Code) { 20 { 'DDR' } 21 { 'DDR2' } 24 { 'DDR3' } 26 { 'DDR4' } 27 { 'LPDDR' } 28 { 'LPDDR2' } 29 { 'LPDDR3' } 30 { 'LPDDR4' } 34 { 'DDR5' } 35 { 'LPDDR5' } default { 'Unknown' } }
}

# v0.4.2: SMBIOS memory speeds (Win32_PhysicalMemory.Speed /
# ConfiguredClockSpeed) are data rates in MT/s for DDR memory (SMBIOS 3.1+),
# not a measured clock in MHz. Shown as reported, never as a measurement;
# an inferred value is marked approximate.
function Format-HardwareMemoryRate {
    param([AllowNull()][object]$Value, [switch]$Approximate)
    if ($null -eq $Value) { return 'Unavailable' }
    $rate = 0
    if (-not [int]::TryParse(([string]$Value).Trim(), [ref]$rate) -or $rate -le 0) { return 'Unavailable' }
    if ($Approximate) { return ('~{0} MT/s' -f $rate) }
    return ('{0} MT/s' -f $rate)
}

# v0.4.2: GPU memory with documented precedence; never a capped/guessed
# value presented as authoritative, never derived from the GPU name.
#   1. Display class key HardwareInformation.qwMemorySize (64-bit, written
#      by the display driver) - used when > 0.
#   2. Win32_VideoController.AdapterRAM / HardwareInformation.MemorySize
#      (32-bit) - used only when below the 32-bit ceiling (0xFFF00000);
#      at/above it the value is a saturated field (e.g. "4.00 GB" for an
#      8 GB card) and is NOT shown as VRAM.
#   3. Otherwise: not reliably determined.
# Raw source values are kept for evidence.
function Resolve-HardwareGpuMemory {
    param([AllowNull()][object]$AdapterRam, [AllowNull()][object]$RegistryQword, [AllowNull()][object]$RegistryDword)
    $toUInt64 = {
        param($v)
        if ($null -eq $v) { return $null }
        if ($v -is [byte[]]) {
            if ($v.Length -ge 8) { return [BitConverter]::ToUInt64($v, 0) }
            if ($v.Length -ge 4) { return [uint64][BitConverter]::ToUInt32($v, 0) }
            return $null
        }
        $n = [uint64]0
        if ([uint64]::TryParse(([string]$v).Trim(), [ref]$n)) { return $n }
        $i = [int64]0
        if ([int64]::TryParse(([string]$v).Trim(), [ref]$i)) { return [uint64]($i -band [int64]4294967295) }
        return $null
    }
    $ceiling = [uint64]4293918720
    $wmi = & $toUInt64 $AdapterRam
    $qw = & $toUInt64 $RegistryQword
    $dw = & $toUInt64 $RegistryDword
    $bytes = $null; $source = 'none'; $note = ''
    if ($null -ne $qw -and $qw -gt 0) {
        $bytes = $qw; $source = 'registry:HardwareInformation.qwMemorySize'
        if ($null -ne $wmi -and $wmi -gt 0 -and $wmi -lt $ceiling -and [math]::Abs([double]$wmi - [double]$qw) -gt 1MB) {
            $note = 'WMI AdapterRAM differs (32-bit field); the 64-bit driver value is used.'
        }
    } elseif ($null -ne $wmi -and $wmi -gt 0 -and $wmi -lt $ceiling) {
        $bytes = $wmi; $source = 'wmi:Win32_VideoController.AdapterRAM'
        if ($null -ne $dw -and $dw -gt 0 -and $dw -lt $ceiling -and [math]::Abs([double]$wmi - [double]$dw) -gt 1MB) {
            $bytes = $null; $source = 'conflict'
            $note = 'WMI AdapterRAM and registry MemorySize disagree; not reliably determined.'
        }
    } elseif ($null -ne $dw -and $dw -gt 0 -and $dw -lt $ceiling) {
        $bytes = $dw; $source = 'registry:HardwareInformation.MemorySize'
    } elseif (($null -ne $wmi -and $wmi -ge $ceiling) -or ($null -ne $dw -and $dw -ge $ceiling)) {
        $note = 'Only a saturated 32-bit value (about 4 GB) is available; the real size is larger or unknown.'
    }
    [PSCustomObject]@{
        Bytes = $bytes
        Reliable = ($null -ne $bytes)
        Display = $(if ($null -ne $bytes) { ConvertTo-HardwareSize $bytes } else { 'Not reliably determined' })
        Source = $source
        Note = $note
        RawAdapterRam = $wmi
        RawRegistryQword = $qw
        RawRegistryDword = $dw
    }
}

# v0.4.2 (real iGPU case): what KIND of graphics memory a value is. An
# integrated GPU's driver can report a very large value (e.g. ~28 GB) that
# is shared/system graphics memory, not dedicated VRAM. Evidence used, in
# order (never the GPU name):
#   1. The DirectX adapter record (HKLM\SOFTWARE\Microsoft\DirectX\<id>,
#      written by Windows for each adapter): DedicatedVideoMemory and
#      SharedSystemMemory, matched by PCI vendor/device id (unique match only).
#      A driver value far above DedicatedVideoMemory is not dedicated VRAM.
#   2. Without that record: an adapter on PCI bus 0 (the root complex, i.e.
#      an integrated adapter) is never labelled dedicated VRAM.
#   3. Otherwise the 64-bit/32-bit driver value keeps its v0.4.2 meaning.
function Resolve-HardwareGpuMemoryKind {
    param([object]$Memory, [AllowNull()][object]$DirectX, [AllowNull()][string]$LocationInfo)
    $mb = [uint64]1048576
    $dedicatedDx = $null; $sharedDx = $null
    if ($null -ne $DirectX) {
        try { if ($null -ne $DirectX.DedicatedVideoMemory) { $dedicatedDx = [uint64]$DirectX.DedicatedVideoMemory } } catch { }
        try { if ($null -ne $DirectX.SharedSystemMemory) { $sharedDx = [uint64]$DirectX.SharedSystemMemory } } catch { }
    }
    $driver = $null
    if ($null -ne $Memory -and $Memory.Reliable) { $driver = [uint64]$Memory.Bytes }
    $integratedBus = ([string]$LocationInfo) -match '^\s*PCI bus 0\s*,'
    $kind = 'unknown'; $dedicated = $null; $reported = $driver; $why = ''
    if ($null -ne $dedicatedDx -and $dedicatedDx -gt 0) {
        $tolerance = [math]::Max([double](64 * $mb), [double]$dedicatedDx * 0.05)
        if ($null -eq $driver -or [math]::Abs([double]$driver - [double]$dedicatedDx) -le $tolerance) {
            $kind = 'dedicated'; $dedicated = $(if ($null -ne $driver) { $driver } else { $dedicatedDx })
            $why = 'DirectX DedicatedVideoMemory confirms the driver value.'
            if ($null -eq $driver) { $why = 'DirectX DedicatedVideoMemory.' }
        } elseif ($driver -gt $dedicatedDx) {
            $kind = 'shared'; $dedicated = $dedicatedDx
            $why = 'Driver value exceeds DirectX DedicatedVideoMemory: it includes shared/system graphics memory.'
        } else {
            $kind = 'driver_reported'
            $why = 'Driver value and DirectX DedicatedVideoMemory disagree.'
        }
    } elseif ($null -ne $driver) {
        if ($integratedBus) {
            $kind = 'driver_reported'
            $why = 'Integrated adapter (PCI bus 0) without a DirectX dedicated-memory record: not classified as dedicated VRAM.'
        } else {
            $kind = 'dedicated'; $dedicated = $driver
            $why = 'Driver-reported dedicated memory.'
        }
    }
    $display = switch ($kind) {
        'dedicated' { ConvertTo-HardwareSize $dedicated }
        'shared' {
            $parts = @('Dedicated video memory ' + (ConvertTo-HardwareSize $dedicated))
            if ($null -ne $sharedDx -and $sharedDx -gt 0) { $parts += 'shared system graphics memory ' + (ConvertTo-HardwareSize $sharedDx) }
            $parts += 'driver-reported graphics memory ' + (ConvertTo-HardwareSize $driver) + ' (not dedicated VRAM)'
            $parts -join '; '
        }
        'driver_reported' { 'Graphics memory reported by driver ' + (ConvertTo-HardwareSize $driver) + ' (dedicated VRAM not confirmed)' }
        default { if ($null -ne $Memory) { $Memory.Display } else { 'Not reliably determined' } }
    }
    [PSCustomObject]@{
        Kind = $kind
        DedicatedBytes = $dedicated
        SharedBytes = $sharedDx
        DriverReportedBytes = $reported
        DirectXDedicatedBytes = $dedicatedDx
        Display = $display
        Reason = $why
    }
}

# Read-only: the DirectX adapter records (one per adapter Windows started).
function Get-HardwareGpuDirectXMemory {
    $rows = @()
    try {
        foreach ($key in @(Get-ChildItem -LiteralPath 'HKLM:\SOFTWARE\Microsoft\DirectX' -ErrorAction Stop)) {
            try {
                $v = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction Stop
                if ($null -eq $v.PSObject.Properties['VendorId'] -or $null -eq $v.PSObject.Properties['DeviceId']) { continue }
                $rows += [PSCustomObject]@{
                    VendorId = [uint32]$v.VendorId; DeviceId = [uint32]$v.DeviceId
                    DedicatedVideoMemory = $(if ($v.PSObject.Properties['DedicatedVideoMemory']) { $v.DedicatedVideoMemory } else { $null })
                    SharedSystemMemory = $(if ($v.PSObject.Properties['SharedSystemMemory']) { $v.SharedSystemMemory } else { $null })
                }
            } catch { }
        }
    } catch { }
    return $rows
}

# The DirectX record of one PnP device: matched by PCI VEN/DEV; only a
# unique match is used (two identical adapters stay unresolved).
function Select-HardwareGpuDirectX {
    param([AllowNull()][object[]]$Rows, [string]$PnpDeviceId)
    if ([string]$PnpDeviceId -notmatch '(?i)VEN_([0-9A-F]{4})&DEV_([0-9A-F]{4})') { return $null }
    $ven = [Convert]::ToUInt32($Matches[1], 16); $dev = [Convert]::ToUInt32($Matches[2], 16)
    $hits = @(@($Rows) | Where-Object { $null -ne $_ -and [uint32]$_.VendorId -eq $ven -and [uint32]$_.DeviceId -eq $dev })
    if ($hits.Count -eq 1) { return $hits[0] }
    return $null
}

# Read-only: the display driver's memory values for one PnP device
# (Enum\<PnP id>\Driver -> Control\Class\<driver key>) and its bus location.
function Get-HardwareGpuRegistryMemory {
    param([string]$PnpDeviceId)
    $result = [PSCustomObject]@{ Qword = $null; Dword = $null; Location = $null }
    if ([string]::IsNullOrWhiteSpace($PnpDeviceId)) { return $result }
    try {
        $enum = Get-ItemProperty -LiteralPath ("HKLM:\SYSTEM\CurrentControlSet\Enum\" + $PnpDeviceId) -ErrorAction Stop
        if ($enum.PSObject.Properties['LocationInformation']) { $result.Location = [string]$enum.LocationInformation }
        $class = Get-ItemProperty -LiteralPath ("HKLM:\SYSTEM\CurrentControlSet\Control\Class\" + $enum.Driver) -ErrorAction Stop
        $q = $class.PSObject.Properties['HardwareInformation.qwMemorySize']
        $d = $class.PSObject.Properties['HardwareInformation.MemorySize']
        if ($q) { $result.Qword = $q.Value }
        if ($d) { $result.Dword = $d.Value }
    } catch { }
    return $result
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

    # Единый механизм Firmware/Secure Boot (v0.3.6): Compatibility.psm1's
    # Get-CompatFirmwareState, the same one EXPC-Diagnostic uses, so the two
    # modules can never disagree about UEFI/Legacy/Secure Boot again.
    $firmwareType = 'UNKNOWN'
    $secureBootState = 'Unable to determine'
    if (-not $DisableFirmwareProbe) {
        try {
            $firmwareState = Get-CompatFirmwareState
            $firmwareType = switch ($firmwareState.Firmware) { 'UEFI' { 'UEFI' } 'Legacy' { 'Legacy BIOS' } default { 'UNKNOWN' } }
            $secureBootState = $firmwareState.SecureBoot
        } catch { $errors.Add("FirmwareType: $($_.Exception.Message)") }
    }

    # Battery detail (root\wmi, ACPI-vendor-dependent): each class is
    # independently optional. Any missing/unsupported class degrades to
    # "not reported", never an error and never a guess.
    function Read-WmiLocal {
        param([string]$ClassName)
        try {
            if ($InstanceReader) { return @(& $InstanceReader $ClassName 'root\wmi' '') }
            return @(Get-CompatInstance -ClassName $ClassName -Namespace 'root\wmi')
        } catch { return @() }
    }
    $batteryStatic = @(Read-WmiLocal 'BatteryStaticData')
    $batteryFullCharge = @(Read-WmiLocal 'BatteryFullChargedCapacity')
    $batteryCycleCount = @(Read-WmiLocal 'BatteryCycleCount')
    $batteryStatus = @(Read-WmiLocal 'BatteryStatus')

    $videoControllers = @(Read-CimLocal Win32_VideoController)
    $gpuRegistry = @()
    $gpuDirectX = @()
    if (-not $InstanceReader) {
        $gpuRegistry = @($videoControllers | ForEach-Object {
            $pnp = [string](Get-HardwareValue $_ 'PNPDeviceID' '')
            $mem = Get-HardwareGpuRegistryMemory -PnpDeviceId $pnp
            [PSCustomObject]@{ PnpId = $pnp; Qword = $mem.Qword; Dword = $mem.Dword; Location = $mem.Location }
        })
        $gpuDirectX = @(Get-HardwareGpuDirectXMemory)
    }

    [PSCustomObject]@{
        System = @(Read-CimLocal Win32_ComputerSystem | Select-Object -First 1)
        OperatingSystem = @(Read-CimLocal Win32_OperatingSystem | Select-Object -First 1)
        Product = @(Read-CimLocal Win32_ComputerSystemProduct | Select-Object -First 1)
        BaseBoard = @(Read-CimLocal Win32_BaseBoard | Select-Object -First 1)
        Bios = @(Read-CimLocal Win32_BIOS | Select-Object -First 1)
        Processors = @(Read-CimLocal Win32_Processor)
        MemoryModules = @(Read-CimLocal Win32_PhysicalMemory)
        MemoryArrays = @(Read-CimLocal Win32_PhysicalMemoryArray)
        VideoControllers = $videoControllers
        GpuRegistryMemory = $gpuRegistry
        GpuDirectXMemory = $gpuDirectX
        Disks = @(Read-CimLocal Win32_DiskDrive)
        PhysicalDisks = $physicalDisks
        Reliability = $reliability
        NetworkAdapters = @(Read-CimLocal Win32_NetworkAdapter)
        NetworkConfigurations = @(Read-CimLocal Win32_NetworkAdapterConfiguration)
        Batteries = @(Read-CimLocal Win32_Battery)
        BatteryStatic = $batteryStatic
        BatteryFullCharge = $batteryFullCharge
        BatteryCycleCount = $batteryCycleCount
        BatteryStatus = $batteryStatus
        SignedDrivers = @(Read-CimLocal Win32_PnPSignedDriver)
        FirmwareType = $firmwareType
        SecureBootState = $secureBootState
        Errors = @($errors)
    }
}


# SPD files are operator-provided snapshots; no hardware driver or SMBus access.
function Read-HardwareSpd {
 param([byte[]]$Bytes)
 if($Bytes.Length -ne 512 -or $Bytes[2] -ne 12 -or $Bytes[17] -ne 0){throw 'Unsupported SPD: only DDR4 / 512 bytes / standard timebase'}
 $crc=0;foreach($b in $Bytes[0..125]){$crc=$crc -bxor ([int]$b -shl 8);for($i=0;$i -lt 8;$i++){if($crc -band 32768){$crc=(($crc -shl 1) -bxor 0x1021) -band 65535}else{$crc=($crc -shl 1) -band 65535}}}
 if($crc -ne ([int]$Bytes[126]+256*[int]$Bytes[127])){throw 'SPD base CRC mismatch'}
 $rate={param($a,$b) $fine=if($b -ge 128){[int]$b-256}else{[int]$b};$ps=125*[int]$a+$fine;if($ps -le 0){return $null};$n=2000000.0/$ps;if($n -lt 800 -or $n -gt 8000){return $null};$known=@(1600,1866,2133,2400,2666,2800,2933,3000,3200,3333,3466,3600,3733,3800,4000,4133,4266,4400,4600,4800,5000,5333);$near=$known|Sort-Object {[Math]::Abs($_-$n)}|Select-Object -First 1;if([Math]::Abs($near-$n)/$n -lt 0.005){[int]$near}else{[int][Math]::Round($n)}}
 $profiles=@();if($Bytes[384] -eq 12 -and $Bytes[385] -eq 74 -and $Bytes[387] -eq 32){foreach($i in 0..1){if($Bytes[386] -band (1 -shl $i)){$n=& $rate $Bytes[(396+47*$i)] $Bytes[(431+47*$i)];if($n){$profiles+=$n}}}}
 $sha=[Security.Cryptography.SHA256]::Create();try{$hash=[BitConverter]::ToString($sha.ComputeHash($Bytes)).Replace('-','')}finally{$sha.Dispose()}
 [pscustomobject]@{Serial=([BitConverter]::ToString($Bytes[325..328]).Replace('-',''));PartNumber=[Text.Encoding]::ASCII.GetString($Bytes[329..348]).Trim([char]0,' ');JedecMTs=(& $rate $Bytes[18] $Bytes[125]);Profiles=@($profiles);Source='OPERATOR_SPD_DUMP_DDR4';SHA256=$hash;RawBase64=[Convert]::ToBase64String($Bytes)}
}
function Get-HardwareRamIntelligence {
 param($Passport,[object[]]$Spd=@(),$Previous=$null)
 $mods=@($Passport.Ram.Modules);$rates=@($mods|ForEach-Object ConfiguredSpeedMTs|Where-Object {$_ -gt 0}|Sort-Object -Unique)
 $current=if($rates.Count -eq 1 -and @($mods|Where-Object {$_.ConfiguredSpeedMTs -gt 0}).Count -eq $mods.Count){[int]$rates[0]}else{$null}
 $cpu=@($Passport.Cpu.Models)-join ' ';$type=@($mods|ForEach-Object Type|Sort-Object -Unique)-join '/';$limit=$null;$boardLimit=$null
 $sources=@('Win32_PhysicalMemory / SMBIOS: reported MT/s, not measured')
 if($cpu -match '(?i)\bi5-14600K(F)?\b'){$limit=if($type -eq 'DDR4'){3200}elseif($type -eq 'DDR5'){5600}else{$null};$sources+='https://www.intel.com/content/www/us/en/products/sku/236778/intel-core-i5-processor-14600kf-24m-cache-up-to-5-30-ghz/specifications.html'}
 if($Passport.Motherboard.Manufacturer -match '(?i)Gigabyte' -and $Passport.Motherboard.Product -eq 'B760 GAMING X DDR4 GEN5' -and $type -eq 'DDR4'){$boardLimit=3200;$sources+='https://www.gigabyte.com/pt/Motherboard/B760-GAMING-X-DDR4-GEN5/sp'}
 $bound=@();$common=$null
 foreach($m in $mods){$matches=@($Spd|Where-Object {$_.Serial -eq $m.Serial -and $_.Serial -notmatch '^(0+|F+|)$' -and $_.PartNumber -eq $m.PartNumber});if($matches.Count -ne 1){$common=@();continue};$bound+=$matches[0];if($null -eq $common){$common=@($matches[0].Profiles)}else{$profiles=$matches[0].Profiles;$common=@($common|Where-Object {$profiles -contains $_})}}
 if($bound.Count -ne $mods.Count){$common=@()};$target=if(@($common).Count){($common|Measure-Object -Maximum).Maximum}else{$null}
 $status='UNKNOWN';$color='GRAY';$notes=@();$action='Целевой профиль не определён: проверь SPD/XMP в BIOS или предоставь SPD-дамп. Автоматических изменений нет.'
 if($target -and $current){if($current -lt $target-2){$status='ATTENTION';$color='ORANGE';$notes+='Скорость ниже подтверждённого профиля DIMM.';$action='Проверь настройки памяти/XMP в BIOS с учётом лимита CPU; после изменения проверь стабильность.'}elseif([Math]::Abs($current-$target) -le 2){$status='CONFIGURATION_MATCH';$color='GREEN';$action='Скорость соответствует профилю DIMM; активность XMP и стабильность этим не доказаны.'}else{$status='ATTENTION';$color='ORANGE';$notes+='Скорость выше подтверждённого профиля; стабильность не проверялась.'}}
 if($current -and $limit -and $boardLimit -and $current -lt [Math]::Min($limit,$boardLimit)-2){$status='ATTENTION';$color='ORANGE';$notes+='Скорость ниже официальной возможности CPU и этой платы; возможности DIMM требуют проверки.';$action='Проверь профили DIMM и настройки памяти в BIOS. XMP не определён; не включай разгон без проверки.'}
 if($current -and $limit -and $current -gt $limit+2){$status='ATTENTION';$color='ORANGE';$notes+='Скорость выше официального лимита CPU; требуется проверка стабильности. Не является доказательством неисправности.'}
 if(@($mods|ForEach-Object PartNumber|Sort-Object -Unique).Count -gt 1 -or @($mods|ForEach-Object CapacityBytes|Sort-Object -Unique).Count -gt 1){$notes+='Различающиеся DIMM: проверь совместимость и расположение.';if($color -eq 'GREEN'){$color='ORANGE';$status='ATTENTION'}}
 if($mods.Count -eq 1){$notes+='Один DIMM: проверь конфигурацию каналов по руководству платы. Активный режим каналов не измерен.'}
 if($color -eq 'GREEN' -and (-not $limit -or -not $boardLimit)){$color='GRAY';$status='PROFILE_MATCH_PLATFORM_UNKNOWN';$notes+='Скорость совпадает с DIMM-профилем, но официальные ограничения CPU/платы не установлены.'}
 $previousRate=$null;$change=$null
 if($Previous -and $Previous.Identity -and $Previous.Identity -eq $Passport.Ram.Identity -and $Previous.GeneratedAt -lt $Passport.GeneratedAt){$previousRate=$Previous.CurrentMTs;if($current -and $previousRate -gt 0){$change=[Math]::Round(100.0*($current-$previousRate)/$previousRate,1);if($current -lt $previousRate-2){$status='ATTENTION';$color='ORANGE';$notes+='Скорость ниже предыдущей сессии той же конфигурации.'}}}
 [pscustomobject]@{Status=$status;Color=$color;CurrentMTs=$current;JedecMTs=@($bound|ForEach-Object JedecMTs|Sort-Object -Unique);ProfileMTs=$target;AvailableProfiles=@($common);XmpActive='UNKNOWN';SpdAvailability=$(if($bound.Count -eq $mods.Count -and $mods.Count){'IMPORTED'}else{'UNAVAILABLE'});CpuOfficialMTs=$limit;BoardOfficialMTs=$boardLimit;PreviousMTs=$previousRate;TransferRateChangePercent=$change;PerformanceChange='NOT_MEASURED';Stability='NOT_TESTED';Channels='UNKNOWN';Notes=$notes;Recommendation=$action;Sources=$sources;SpdEvidence=$bound;HistoryStatus='NOT_LOADED'}
}
function Update-HardwareRamHistory {
 param($Passport,[string]$Directory)
 $spd=@();$issues=@();$history=Join-Path $Directory 'MemoryHistory';$identity=[string]$Passport.Ram.Identity;$prev=$null
 try{if(Test-Path -LiteralPath (Join-Path $Directory 'SPD')){foreach($f in @(Get-ChildItem -LiteralPath (Join-Path $Directory 'SPD') -Filter '*.bin' -File -ErrorAction Stop|Select-Object -First 16)){try{if($f.Length -ne 512){throw 'Unsupported SPD size'};$spd+=Read-HardwareSpd ([IO.File]::ReadAllBytes($f.FullName))}catch{$issues+=$_.Exception.Message}}}}catch{$issues+=$_.Exception.Message}
 try{if($identity -and (Test-Path -LiteralPath $history)){$prev=@(Get-ChildItem -LiteralPath $history -Filter ($identity+'-*.json') -File|Sort-Object Name -Descending|Select-Object -First 100|ForEach-Object {try{[IO.File]::ReadAllText($_.FullName)|ConvertFrom-Json}catch{$issues+='History unreadable'}}|Where-Object {$_.GeneratedAt -lt $Passport.GeneratedAt}|Sort-Object GeneratedAt -Descending|Select-Object -First 1)[0]}}catch{$issues+=$_.Exception.Message}
 $Passport.Ram.Intelligence=Get-HardwareRamIntelligence $Passport $spd $prev
 try{if($identity){[void][IO.Directory]::CreateDirectory($history);$record=[ordered]@{Identity=$identity;GeneratedAt=$Passport.GeneratedAt;CurrentMTs=$Passport.Ram.Intelligence.CurrentMTs;Bios=$Passport.Bios.Version};$file=Join-Path $history ($identity+'-'+(Get-Date -Format yyyyMMddHHmmssffff)+'-'+[guid]::NewGuid().ToString('N')+'.json');[IO.File]::WriteAllText($file,($record|ConvertTo-Json),[Text.UTF8Encoding]::new($false));$Passport.Ram.Intelligence.HistoryStatus='SAVED'}else{$Passport.Ram.Intelligence.HistoryStatus='IDENTITY_UNKNOWN'}}catch{$issues+=$_.Exception.Message;$Passport.Ram.Intelligence.HistoryStatus='ERROR'}
 $Passport.Ram.Intelligence.Notes+=@($issues|ForEach-Object {'Источник RAM недоступен: '+$_})
 $Passport.Ram.Context+=@($Passport.Ram.Intelligence.Notes)+@($Passport.Ram.Intelligence.Recommendation)
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
            # Kept for parser compatibility: these SMBIOS values are data
            # rates in MT/s despite the historical "MHz" field names.
            RatedSpeedMHz = $speed
            ConfiguredClockMHz = $configured
            RatedSpeedMTs = $speed
            ConfiguredSpeedMTs = $configured
            RatedSpeed = Format-HardwareMemoryRate $speed
            ConfiguredSpeed = Format-HardwareMemoryRate $configured
            SpeedSource = 'SMBIOS/WMI (reported, not measured)'
            DeviceLocator = ConvertTo-HardwareText (Get-HardwareValue $_ 'DeviceLocator')
            BankLabel = ConvertTo-HardwareText (Get-HardwareValue $_ 'BankLabel')
            Serial = ConvertTo-HardwareText (Get-HardwareValue $_ 'SerialNumber')
            State = $(if($speed -and $configured -and [int]$configured -lt [int]$speed){'INFO'}elseif(-not (Get-HardwareValue $_ 'DeviceLocator')){'INFO'}else{'OK'})
        }
    })
    # v1.0: module mix and configured-vs-rated speed are CONTEXT (INFO),
    # never a hardware WARNING by themselves: a mixed-capacity kit that runs
    # normally, with clean WHEA and no memory-test errors, is not a fault.
    # JEDEC / configured rate / XMP-EXPO profile stay separate facts.
    $ramReasons = @()
    $ramContext = @()
    $capacities = @($ramRows | Where-Object CapacityBytes | ForEach-Object CapacityBytes | Sort-Object -Unique)
    $speeds = @($ramRows | Where-Object RatedSpeedMHz | ForEach-Object RatedSpeedMHz | Sort-Object -Unique)
    if ($capacities.Count -gt 1) { $ramContext += 'Mixed module capacities (context; not a fault without memory errors, WHEA or failed memory tests).' }
    if ($speeds.Count -gt 1) { $ramContext += 'Mixed declared module speeds (context).' }
    if (@($ramRows | Where-Object { $_.RatedSpeedMHz -and $_.ConfiguredClockMHz -and [int]$_.ConfiguredClockMHz -lt [int]$_.RatedSpeedMHz }).Count) { $ramContext += 'Configured data rate below the declared rate (JEDEC / XMP-EXPO profile context, not a fault).' }
    $declaredSlots = [int](($arrays | Measure-Object MemoryDevices -Sum).Sum)
    # v1.1 RC (KNOWN_BUGS X79G): an independent installed total. When Windows
    # reports materially more memory than the SMBIOS module list adds up to,
    # the module list is incomplete (firmware); no module is invented and it
    # is never a memory fault (state at most INFO).
    $enumBytes = [uint64](($memory | Measure-Object Capacity -Sum).Sum)
    $visibleBytes = [uint64]0
    if ($system -and $system.TotalPhysicalMemory) { try { $visibleBytes = [uint64]$system.TotalPhysicalMemory } catch { } }
    $inventoryComplete = -not ($enumBytes -gt 0 -and $visibleBytes -gt ($enumBytes * 1.05))
    $installedBytes = if ($inventoryComplete -and $enumBytes -gt 0) { $enumBytes } else { $visibleBytes }
    $installedSource = if ($inventoryComplete -and $enumBytes -gt 0) { 'SUM(Win32_PhysicalMemory.Capacity)' } else { 'Win32_ComputerSystem.TotalPhysicalMemory (usable, lower bound)' }
    $inventoryNote = if ($inventoryComplete) { '' } else { ('DIMM inventory incomplete: firmware/SMBIOS lists {0} module(s) = {1}; Windows reports {2} (lower bound). Not a memory fault.' -f @($ramRows).Count, (ConvertTo-HardwareSize $enumBytes), (ConvertTo-HardwareSize $visibleBytes)) }
    # v1.0 item 34: LPDDR is soldered on-board memory. SMBIOS lists one
    # memory device per channel/package (e.g. 8 x 2 GB) - these are not
    # removable modules; slot / dual-channel / mixed-kit rules do not apply.
    $lpddr = @($ramRows | Where-Object { [string]$_.Type -like 'LPDDR*' }).Count -gt 0
    $ramTopology = if ($lpddr) { 'ONBOARD_LPDDR' } elseif ($ramRows.Count) { 'MODULES' } else { 'UNKNOWN' }
    if ($lpddr) {
        $ramContext = @($ramContext | Where-Object { $_ -notlike 'Mixed module capacities*' })
        $ramContext += ('On-board (soldered) LPDDR memory: SMBIOS lists {0} memory devices (channels/packages), not removable modules.' -f $ramRows.Count)
    }
    if ($inventoryNote) { $ramContext += $inventoryNote }
    $ramState = if (-not $ramRows.Count) { 'UNKNOWN' } elseif ($ramReasons.Count) { 'WARNING' } elseif ($ramContext.Count -or $declaredSlots -le 0 -or @($ramRows | Where-Object DeviceLocator -eq 'Unavailable').Count) { 'INFO' } else { 'OK' }

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
        $pnp = [string](Get-HardwareValue $_ 'PNPDeviceID' '')
        $reg = @(@(Get-HardwareValue $Source 'GpuRegistryMemory' @()) | Where-Object { [string]$_.PnpId -eq $pnp } | Select-Object -First 1)[0]
        $mem = Resolve-HardwareGpuMemory -AdapterRam (Get-HardwareValue $_ 'AdapterRAM') -RegistryQword (Get-HardwareValue $reg 'Qword') -RegistryDword (Get-HardwareValue $reg 'Dword')
        $dx = Select-HardwareGpuDirectX -Rows @(Get-HardwareValue $Source 'GpuDirectXMemory' @()) -PnpDeviceId $pnp
        $kind = Resolve-HardwareGpuMemoryKind -Memory $mem -DirectX $dx -LocationInfo ([string](Get-HardwareValue $reg 'Location' ''))
        # VRAM* keeps its meaning: dedicated video memory only.
        $mem.Display = $kind.Display
        $mem.Bytes = $kind.DedicatedBytes
        $mem.Reliable = ($kind.Kind -in @('dedicated','shared'))
        [PSCustomObject]@{ Name=ConvertTo-HardwareText $_.Name; DriverVersion=ConvertTo-HardwareText $_.DriverVersion; VRAMBytes=$mem.Bytes; VRAM=$mem.Display; VRAMReliable=$mem.Reliable; VRAMSource=$mem.Source; VRAMNote=$mem.Note; VRAMKind=$kind.Kind; VRAMKindReason=$kind.Reason; DedicatedVideoMemoryBytes=$kind.DedicatedBytes; SharedSystemMemoryBytes=$kind.SharedBytes; DriverReportedMemoryBytes=$kind.DriverReportedBytes; VRAMRawAdapterRAM=$mem.RawAdapterRam; VRAMRawRegistryQword=$mem.RawRegistryQword; VRAMRawRegistryDword=$mem.RawRegistryDword; PnpId=ConvertTo-HardwareText $_.PNPDeviceID }
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
    # Battery Health (v0.3.6): Win32_Battery gives charge/design/full-charge
    # capacity; root\wmi ACPI classes (independently optional, per device)
    # add Manufacturer/Model/Serial/Cycle Count where the platform reports
    # them. A desktop with no battery is normal, not a warning; a missing
    # Cycle Count is "Not reported", never an error.
    function ConvertTo-BatteryText {
        # BatteryStaticData exposes ManufactureName/SerialNumber as a UInt16
        # array of UTF-16 code units (the ACPI _BIF string form). Any shape
        # mismatch degrades to $null (-> "Not reported"), never a guess.
        param([AllowNull()][object]$Codes)
        if ($null -eq $Codes) { return $null }
        try {
            $chars = @($Codes) | ForEach-Object { [char][int]$_ }
            $text = (-join $chars).Trim([char]0).Trim()
            if ([string]::IsNullOrWhiteSpace($text)) { return $null }
            return $text
        } catch { return $null }
    }
    $batteries = @($Source.Batteries | ForEach-Object {
        $wmiBattery = $_
        $instanceKey = [string](Get-HardwareValue $wmiBattery 'PNPDeviceID' '')
        $static = @($Source.BatteryStatic | Where-Object { [string](Get-HardwareValue $_ 'InstanceName' '') -match [regex]::Escape($instanceKey) -or $instanceKey -eq '' } | Select-Object -First 1)[0]
        $fullChargeRow = @($Source.BatteryFullCharge | Select-Object -First 1)[0]
        $cycleRow = @($Source.BatteryCycleCount | Select-Object -First 1)[0]

        $designCapacity = Get-HardwareValue $wmiBattery 'DesignCapacity' (Get-HardwareValue $static 'DesignedCapacity')
        $fullChargeCapacity = Get-HardwareValue $wmiBattery 'FullChargeCapacity' (Get-HardwareValue $fullChargeRow 'FullChargedCapacity')
        $wearPercent = $null
        if ($null -ne $designCapacity -and $null -ne $fullChargeCapacity -and [double]$designCapacity -gt 0) {
            $wearPercent = [Math]::Round(100.0 - ([double]$fullChargeCapacity / [double]$designCapacity * 100.0), 1)
            if ($wearPercent -lt 0) { $wearPercent = 0.0 }
        }
        $cycleCount = Get-HardwareValue $cycleRow 'CycleCount'

        [PSCustomObject]@{
            Name = ConvertTo-HardwareText $wmiBattery.Name
            Manufacturer = ConvertTo-HardwareText (ConvertTo-BatteryText (Get-HardwareValue $static 'ManufactureName')) 'Not reported'
            Model = ConvertTo-HardwareText $wmiBattery.Name 'Not reported'
            Serial = ConvertTo-HardwareText (ConvertTo-BatteryText (Get-HardwareValue $static 'SerialNumber')) 'Not reported'
            StatusCode = Get-HardwareValue $wmiBattery 'BatteryStatus'
            ChargePercent = Get-HardwareValue $wmiBattery 'EstimatedChargeRemaining'
            DesignCapacity = $designCapacity
            FullChargeCapacity = $fullChargeCapacity
            WearPercent = $(if ($null -eq $wearPercent) { 'N/A' } else { $wearPercent })
            CycleCount = $(if ($null -eq $cycleCount) { 'Not reported' } else { [int]$cycleCount })
        }
    })
    $batteryState = if (-not $batteries.Count) { 'INFO' } elseif (@($batteries | Where-Object { $null -ne $_.ChargePercent -and [int]$_.ChargePercent -lt 10 }).Count) { 'WARNING' } else { 'INFO' }

    # NPU (v0.3.6): a name-signature match against real, Windows-reported PnP
    # driver entries — never a guessed spec/TOPS table. Absence is normal.
    $npus = @($Source.SignedDrivers | Where-Object {
        [string](Get-HardwareValue $_ 'DeviceName' '') -match '(?i)\bNPU\b|Neural Processing Unit|\bXDNA\b|AI Boost|Intel\(R\) AI Boost|AI Engine'
    } | ForEach-Object {
        [PSCustomObject]@{
            Name = ConvertTo-HardwareText (Get-HardwareValue $_ 'DeviceName')
            Vendor = ConvertTo-HardwareText (Get-HardwareValue $_ 'Manufacturer')
            DriverVersion = ConvertTo-HardwareText (Get-HardwareValue $_ 'DriverVersion')
            DriverDate = Get-HardwareValue $_ 'DriverDate'
            DeviceStatus = ConvertTo-HardwareText (Get-HardwareValue $_ 'Status') 'UNKNOWN'
            InstanceId = ConvertTo-HardwareText (Get-HardwareValue $_ 'DeviceID')
        }
    })

    $storageState = Get-HardwareOverallState @($diskRows | ForEach-Object Health)
    $overall = Get-HardwareOverallState @($ramState, $storageState, $batteryState)

    $passport = [PSCustomObject][ordered]@{
        Tool='EXPC Hardware Diagnostics'; Version=$(if($env:WSD_APP_VERSION){$env:WSD_APP_VERSION}else{'1.3'}); SchemaVersion=1; GeneratedAt=(Get-Date).ToString('o'); ReadOnly=$true; AssessmentScope='Inventory and reported metadata; memory/stress test NOT_TESTED'; OverallState=$(if($overall -eq 'OK'){'CONFIGURATION_DETECTED'}else{$overall})
        System=[PSCustomObject]@{ Manufacturer=ConvertTo-HardwareText (Get-HardwareValue $system 'Manufacturer'); Model=ConvertTo-HardwareText (Get-HardwareValue $system 'Model'); Hostname=$(if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { ConvertTo-HardwareText (Get-HardwareValue $system 'Name') }); SystemType=ConvertTo-HardwareText (Get-HardwareValue $system 'SystemType'); WindowsEdition=ConvertTo-HardwareText (Get-HardwareValue $operatingSystem 'Caption'); WindowsBuild=ConvertTo-HardwareText (Get-HardwareValue $operatingSystem 'BuildNumber'); WindowsArchitecture=ConvertTo-HardwareText (Get-HardwareValue $operatingSystem 'OSArchitecture' $env:PROCESSOR_ARCHITECTURE); ProductId=ConvertTo-HardwareText (Get-HardwareValue $product 'IdentifyingNumber') }
        Motherboard=[PSCustomObject]@{ Manufacturer=ConvertTo-HardwareText (Get-HardwareValue $board 'Manufacturer'); Product=ConvertTo-HardwareText (Get-HardwareValue $board 'Product'); Version=ConvertTo-HardwareText (Get-HardwareValue $board 'Version'); Serial=ConvertTo-HardwareText (Get-HardwareValue $board 'SerialNumber') }
        Bios=[PSCustomObject]@{ Manufacturer=ConvertTo-HardwareText (Get-HardwareValue $bios 'Manufacturer'); Version=ConvertTo-HardwareText (Get-HardwareValue $bios 'SMBIOSBIOSVersion' (Get-HardwareValue $bios 'Version')); ReleaseDate=Get-HardwareValue $bios 'ReleaseDate'; FirmwareType=ConvertTo-HardwareText $Source.FirmwareType 'UNKNOWN'; SecureBoot=ConvertTo-HardwareText (Get-HardwareValue $Source 'SecureBootState') 'Unable to determine' }
        Cpu=[PSCustomObject]@{ Models=@($processors | ForEach-Object { ConvertTo-HardwareText $_.Name }); Manufacturers=@($processors | ForEach-Object { ConvertTo-HardwareText $_.Manufacturer }|Sort-Object -Unique); PhysicalCores=[int](($processors | Measure-Object NumberOfCores -Sum).Sum); LogicalProcessors=[int](($processors | Measure-Object NumberOfLogicalProcessors -Sum).Sum); MaxClockMHz=$(($processors | Measure-Object MaxClockSpeed -Maximum).Maximum); CurrentClockMHz=$null; CurrentClockSource='NOT_MEASURED'; WindowsReportedCurrentClockMHz=$(($processors | Measure-Object CurrentClockSpeed -Maximum).Maximum); ClockSource='Win32_Processor / SMBIOS (reported, not measured)'; Sockets=@($processors | ForEach-Object SocketDesignation | Where-Object { $_ }); Architecture=$(switch([int](Get-HardwareValue ($processors|Select-Object -First 1) 'Architecture' -1)){0{'x86'}5{'ARM'}9{'x64'}12{'ARM64'}default{'Unknown'}}); L2CacheKB=[int](($processors|Measure-Object L2CacheSize -Sum).Sum); L3CacheKB=[int](($processors|Measure-Object L3CacheSize -Sum).Sum) }
        Ram=[PSCustomObject]@{ State=$(if($ramState -eq 'OK'){'CONFIGURATION_DETECTED'}else{$ramState}); MemoryTest='NOT_TESTED'; Reasons=$ramReasons; Context=$ramContext; TotalBytes=$installedBytes; Total=$(if($inventoryComplete){ConvertTo-HardwareSize $installedBytes}else{'>= ' + (ConvertTo-HardwareSize $installedBytes) + ' (DIMM inventory incomplete)'}); InstalledSource=$installedSource; EnumeratedBytes=$enumBytes; InventoryComplete=[bool]$inventoryComplete; InventoryNote=$inventoryNote; ModuleCount=$ramRows.Count; DeclaredSlots=$declaredSlots; Topology=$ramTopology; Modules=$ramRows }
        Storage=[PSCustomObject]@{ State=$storageState; Disks=$diskRows }
        Gpu=[PSCustomObject]@{ State=$(if ($gpus.Count) { 'INFO' } else { 'UNKNOWN' }); Controllers=$gpus }
        Network=[PSCustomObject]@{ State=$(if ($networks.Count) { 'INFO' } else { 'UNKNOWN' }); Adapters=$networks }
        Battery=[PSCustomObject]@{ State=$batteryState; Detected=($batteries.Count -gt 0); Summary=$(if ($batteries.Count) { 'Battery detected.' } else { 'Battery: Not present.' }); Batteries=$batteries }
        Npu=[PSCustomObject]@{ Detected=($npus.Count -gt 0); Devices=$npus }
        CollectionErrors=@($Source.Errors)
    }
    $identity='';$uuid=[string](Get-HardwareValue $product 'UUID' '')
    if($uuid -match '^[0-9a-fA-F-]{36}$' -and $uuid -notmatch '^(0|-)+$|^(F|-)+$' -and $ramRows.Count -and @($ramRows|Where-Object {$_.Serial -match '^(0+|F+|Unavailable|Unknown|)$'}).Count -eq 0){
        $parts=@($ramRows|ForEach-Object {"$($_.Serial)|$($_.PartNumber)|$($_.CapacityBytes)|$($_.DeviceLocator)"}|Sort-Object)
        $key=$uuid+'|'+$passport.Motherboard.Product+'|'+$passport.Bios.Version+'|'+($passport.Cpu.Models -join ',')+'|'+($parts -join ';')
        $sha=[Security.Cryptography.SHA256]::Create();try{$identity=[BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($key))).Replace('-','')}finally{$sha.Dispose()}
    }
    $passport.Ram|Add-Member NoteProperty Identity $identity
    $passport.Ram|Add-Member NoteProperty Intelligence (Get-HardwareRamIntelligence $passport)
    return $passport

}

Export-ModuleMember -Function Read-HardwareSpd,Get-HardwareRamIntelligence,Update-HardwareRamHistory,New-HardwarePassport,Get-HardwareOverallState,ConvertTo-HardwareSize,Format-HardwareMemoryRate,Resolve-HardwareGpuMemory,Resolve-HardwareGpuMemoryKind,Select-HardwareGpuDirectX
