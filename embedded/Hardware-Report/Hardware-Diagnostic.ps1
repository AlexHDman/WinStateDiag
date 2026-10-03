#requires -Version 5.0
[CmdletBinding()]
param([switch]$NoGui, [switch]$ExportAll, [switch]$GuiSmoke, [string]$GuiScreenshotPath='', [switch]$WsdViewer, [string]$ReportFolder='')

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$runStarted = Get-Date
Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) 'Compatibility.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'HardwarePassport.psm1') -Force
Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) 'ReportStorage.psm1') -Force
$RuntimeInfo = Get-CompatRuntimeInfo
$OutputDirectory = Get-WinDiagReportDirectory -Ensure

function Format-HardwareLine {
    param([string]$Label, [AllowNull()][object]$Value)
    return ('{0,-20}: {1}' -f $Label, $(if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { 'Unavailable' } else { $Value }))
}

function ConvertTo-HardwareFileToken {
    param([string]$Text)
    $value = ([string]$Text).Trim() -replace '[\/:*?"<>|]', '_'
    $value = $value -replace '\s+', '_' -replace '_{2,}', '_'
    $value = $value.Trim('_').TrimEnd('.')
    if ([string]::IsNullOrWhiteSpace($value)) { $value = 'UNKNOWN' }
    if ($value -match '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$') { $value = '_' + $value }
    return $value
}

function New-HardwareReportLines {
    param([Parameter(Mandatory=$true)][object]$Passport)
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('EXPC HARDWARE DIAGNOSTICS')
    $lines.Add((Format-HardwareLine 'Generated' $Passport.GeneratedAt))
    $lines.Add((Format-HardwareLine 'Read-only' $Passport.ReadOnly))
    $lines.Add((Format-HardwareLine 'Overall state' $Passport.OverallState))
    $lines.Add('')
    $lines.Add('[HARDWARE SUMMARY]')
    $lines.Add((Format-HardwareLine 'Device' ("$($Passport.System.Manufacturer) $($Passport.System.Model)")))
    $lines.Add((Format-HardwareLine 'CPU' (($Passport.Cpu.Models | Where-Object { $_ -ne 'Unavailable' }) -join '; ')))
    $lines.Add((Format-HardwareLine 'CPU topology' ("$($Passport.Cpu.PhysicalCores)C / $($Passport.Cpu.LogicalProcessors)T")))
    $lines.Add((Format-HardwareLine 'RAM' ("$($Passport.Ram.Total), $($Passport.Ram.ModuleCount) module(s), $($Passport.Ram.State)")))
    $lines.Add((Format-HardwareLine 'GPU' (($Passport.Gpu.Controllers | ForEach-Object Name) -join '; ')))
    $lines.Add((Format-HardwareLine 'Storage' (($Passport.Storage.Disks | ForEach-Object { "$($_.Model) $($_.Capacity) [$($_.Health)]" }) -join '; ')))
    $lines.Add((Format-HardwareLine 'Motherboard' ("$($Passport.Motherboard.Manufacturer) $($Passport.Motherboard.Product)")))
    $lines.Add((Format-HardwareLine 'BIOS' ("$($Passport.Bios.Version), $($Passport.Bios.FirmwareType)")))
    $lines.Add('')
    $lines.Add('[SYSTEM]')
    $lines.Add((Format-HardwareLine 'Manufacturer' $Passport.System.Manufacturer))
    $lines.Add((Format-HardwareLine 'Model' $Passport.System.Model))
    $lines.Add((Format-HardwareLine 'Hostname' $Passport.System.Hostname))
    $lines.Add((Format-HardwareLine 'System type' $Passport.System.SystemType))
    $lines.Add((Format-HardwareLine 'Architecture' $Passport.System.WindowsArchitecture))
    $lines.Add('')
    $lines.Add('[MOTHERBOARD]')
    $lines.Add((Format-HardwareLine 'Manufacturer' $Passport.Motherboard.Manufacturer))
    $lines.Add((Format-HardwareLine 'Product' $Passport.Motherboard.Product))
    $lines.Add((Format-HardwareLine 'Version' $Passport.Motherboard.Version))
    $lines.Add((Format-HardwareLine 'Serial' $Passport.Motherboard.Serial))
    $lines.Add('')
    $lines.Add('[BIOS / UEFI]')
    $lines.Add((Format-HardwareLine 'Manufacturer' $Passport.Bios.Manufacturer))
    $lines.Add((Format-HardwareLine 'Version' $Passport.Bios.Version))
    $lines.Add((Format-HardwareLine 'Release date' $Passport.Bios.ReleaseDate))
    $lines.Add((Format-HardwareLine 'Firmware mode' $Passport.Bios.FirmwareType))
    $lines.Add((Format-HardwareLine 'Secure Boot' $Passport.Bios.SecureBoot))
    $lines.Add('')
    $lines.Add('[CPU]')
    $lines.Add((Format-HardwareLine 'Model' ($Passport.Cpu.Models -join '; ')))
    $lines.Add((Format-HardwareLine 'Cores / threads' ("$($Passport.Cpu.PhysicalCores) / $($Passport.Cpu.LogicalProcessors)")))
    $lines.Add((Format-HardwareLine 'Base clock (Windows-reported nominal)' ("$($Passport.Cpu.MaxClockMHz) MHz")))
    $lines.Add((Format-HardwareLine 'Current clock' ("$($Passport.Cpu.CurrentClockMHz) MHz")))
    $lines.Add((Format-HardwareLine 'Max Boost' 'Not reliably reported by Windows'))
    $lines.Add((Format-HardwareLine 'Socket' ($Passport.Cpu.Sockets -join '; ')))
    $lines.Add('')
    $lines.Add('[RAM]')
    $lines.Add((Format-HardwareLine 'State' $Passport.Ram.State))
    $lines.Add((Format-HardwareLine 'Total / detected modules' ("$($Passport.Ram.Total) / $($Passport.Ram.ModuleCount)")))
    $lines.Add((Format-HardwareLine 'SMBIOS declared memory devices/slots' $Passport.Ram.DeclaredSlots))
    if ($Passport.Ram.ModuleCount -lt $Passport.Ram.DeclaredSlots) {
        $lines.Add('Note: SMBIOS may not reflect full physical topology (soldered/onboard RAM, incomplete SMBIOS). An unpopulated physical slot is not confirmed.')
    }
    foreach ($reason in @($Passport.Ram.Reasons)) { $lines.Add("Reason: $reason") }
    foreach ($module in @($Passport.Ram.Modules)) { $lines.Add("- $($module.DeviceLocator): $($module.Manufacturer) $($module.PartNumber), $($module.Capacity) $($module.Type), rated $(Format-HardwareMemoryRate $module.RatedSpeedMHz), configured $(Format-HardwareMemoryRate $module.ConfiguredClockMHz) (SMBIOS-reported data rate, not measured)") }
    $lines.Add('')
    $lines.Add('[STORAGE]')
    $lines.Add((Format-HardwareLine 'State' $Passport.Storage.State))
    foreach ($disk in @($Passport.Storage.Disks)) {
        $lines.Add("- $($disk.Model), $($disk.Capacity), $($disk.MediaType) / $($disk.BusType)")
        $lines.Add("  Serial: $($disk.Serial); firmware: $($disk.Firmware); health: $($disk.Health)")
        $lines.Add("  Reason: $($disk.HealthReason)")
        if ($disk.Reliability) { $lines.Add("  Reliability: temperature $($disk.Reliability.TemperatureC) C; wear $($disk.Reliability.WearPercent)%; power-on $($disk.Reliability.PowerOnHours) h; read/write errors $($disk.Reliability.ReadErrorsTotal)/$($disk.Reliability.WriteErrorsTotal)") }
    }
    $lines.Add('')
    $lines.Add('[GPU]')
    foreach ($gpu in @($Passport.Gpu.Controllers)) { $memLabel = $(if ($gpu.PSObject.Properties['VRAMKind'] -and $gpu.VRAMKind -ne 'dedicated') { 'graphics memory' } else { 'VRAM' }); $lines.Add("- $($gpu.Name); driver $($gpu.DriverVersion); $memLabel $($gpu.VRAM); PNP $($gpu.PnpId)"); if ($gpu.PSObject.Properties['VRAMKindReason'] -and $gpu.VRAMKindReason) { $lines.Add("  Memory kind: $($gpu.VRAMKind) - $($gpu.VRAMKindReason)") }; if ($gpu.PSObject.Properties['VRAMNote'] -and $gpu.VRAMNote) { $lines.Add("  VRAM note: $($gpu.VRAMNote)") }; if ($gpu.PSObject.Properties['VRAMSource']) { $lines.Add("  VRAM source: $($gpu.VRAMSource); raw AdapterRAM: $($gpu.VRAMRawAdapterRAM); raw qwMemorySize: $($gpu.VRAMRawRegistryQword)") } }
    $lines.Add('')
    $lines.Add('[NETWORK]')
    foreach ($adapter in @($Passport.Network.Adapters)) { $lines.Add("- $($adapter.Name); $($adapter.Manufacturer); $($adapter.MAC); $($adapter.LinkState)") }
    $lines.Add('')
    $lines.Add('[BATTERY]')
    $lines.Add((Format-HardwareLine 'Battery' $Passport.Battery.Summary))
    foreach ($battery in @($Passport.Battery.Batteries)) {
        $lines.Add("- $($battery.Name); Manufacturer: $($battery.Manufacturer); Model: $($battery.Model); Serial: $($battery.Serial)")
        $wearText = if ($battery.WearPercent -eq 'N/A') { 'N/A' } else { "$($battery.WearPercent)%" }
        $lines.Add("  Charge: $($battery.ChargePercent)%; Status code: $($battery.StatusCode); Design capacity: $($battery.DesignCapacity); Full charge capacity: $($battery.FullChargeCapacity); Wear: $wearText; Cycle count: $($battery.CycleCount)")
    }
    $lines.Add('')
    $lines.Add('[NPU]')
    if ($Passport.Npu.Detected) {
        foreach ($npu in @($Passport.Npu.Devices)) {
            $lines.Add("- $($npu.Name); Vendor: $($npu.Vendor); Driver: $($npu.DriverVersion) ($($npu.DriverDate)); Status: $($npu.DeviceStatus)")
        }
    } else {
        $lines.Add((Format-HardwareLine 'NPU' 'Not detected (normal on platforms without an NPU).'))
    }
    if (@($Passport.CollectionErrors).Count) {
        $lines.Add(''); $lines.Add('[UNAVAILABLE DATA]')
        foreach ($message in @($Passport.CollectionErrors)) { $lines.Add("- $message") }
    }
    return $lines
}

function Write-NewHardwareTextFile {
    param([string]$Path,[string]$Text)
    if (Test-Path -LiteralPath $Path) { return $Path }
    $stream=[IO.File]::Open($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
    $writer=New-Object IO.StreamWriter($stream,(New-Object Text.UTF8Encoding($false)))
    try { $writer.Write($Text) } finally { $writer.Dispose() }
    return $Path
}

function Save-HardwareReport {
    param([object]$Passport,[string]$BaseName,[string]$Directory,[ValidateSet('TXT','JSON','HTML')][string]$Format)
    $extension='.'+$Format.ToLowerInvariant()
    $path=Join-Path $Directory ($BaseName+$extension)
    if (Test-Path -LiteralPath $path) { return $path }
    switch ($Format) {
        'TXT' { $content=(@(New-HardwareReportLines $Passport) -join [Environment]::NewLine)+[Environment]::NewLine }
        'JSON' { $content=$Passport | ConvertTo-Json -Depth 10 }
        'HTML' {
            $encoded=[Net.WebUtility]::HtmlEncode((@(New-HardwareReportLines $Passport) -join [Environment]::NewLine))
            $content='<!doctype html><html><head><meta charset="utf-8"><title>EXPC Hardware Diagnostics</title><style>body{font-family:Segoe UI,Arial;background:#f5f7fa;color:#172033;margin:32px}main{max-width:1100px;margin:auto;background:white;padding:28px;border-radius:12px;box-shadow:0 3px 18px #ccd2dc}pre{white-space:pre-wrap;font:14px/1.5 Consolas,monospace}</style></head><body><main><h1>Hardware Diagnostics</h1><pre>'+$encoded+'</pre></main></body></html>'
        }
    }
    return Write-NewHardwareTextFile -Path $path -Text $content
}

function New-HardwareReadOnlyBox {
    param([bool]$Multiline=$false)
    $box=New-Object Windows.Forms.TextBox
    $box.ReadOnly=$true;$box.BorderStyle='FixedSingle';$box.BackColor=[Drawing.Color]::White;$box.ShortcutsEnabled=$true
    if($Multiline){$box.Multiline=$true;$box.ScrollBars='Both';$box.WordWrap=$false;$box.Font=New-Object Drawing.Font('Consolas',10)}
    return $box
}

function New-HardwarePropertyPage {
    param([string]$Title,[object[]]$Fields)
    $page=New-Object Windows.Forms.Panel;$page.Size=New-Object Drawing.Size(1100,650);$page.Dock='Fill';$page.BackColor=[Drawing.Color]::FromArgb(244,247,251);$page.AutoScroll=$true
    $heading=New-Object Windows.Forms.Label;$heading.Text=$Title;$heading.Font=New-Object Drawing.Font('Segoe UI Semibold',20);$heading.ForeColor=[Drawing.Color]::FromArgb(24,36,51);$heading.AutoSize=$true;$heading.Location=New-Object Drawing.Point(24,20);$page.Controls.Add($heading)
    $table=New-Object Windows.Forms.TableLayoutPanel;$table.Location=New-Object Drawing.Point(24,70);$table.Width=950;$table.AutoSize=$true;$table.ColumnCount=2;$table.RowCount=$Fields.Count;$table.Anchor='Top,Left,Right'
    [void]$table.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle('Absolute',220)))
    [void]$table.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle('Percent',100)))
    $values=@{};$row=0
    foreach($field in $Fields){
        $label=New-Object Windows.Forms.Label;$label.Text=$field.Label;$label.Font=New-Object Drawing.Font('Segoe UI',10);$label.ForeColor=[Drawing.Color]::FromArgb(70,82,98);$label.Dock='Fill';$label.TextAlign='MiddleLeft';$label.Margin=New-Object Windows.Forms.Padding(0,6,8,6)
        $box=New-HardwareReadOnlyBox;$box.Dock='Fill';$box.Font=New-Object Drawing.Font('Segoe UI',10);$box.Margin=New-Object Windows.Forms.Padding(0,5,0,5)
        $table.Controls.Add($label,0,$row);$table.Controls.Add($box,1,$row);$values[$field.Key]=$box;$row++
    }
    $page.Controls.Add($table)
    return [PSCustomObject]@{Panel=$page;Values=$values;Table=$table}
}

function New-HardwareGridPage {
    param([string]$Title,[object[]]$Columns)
    $page=New-Object Windows.Forms.Panel;$page.Size=New-Object Drawing.Size(1100,650);$page.Dock='Fill';$page.BackColor=[Drawing.Color]::FromArgb(244,247,251)
    $heading=New-Object Windows.Forms.Label;$heading.Text=$Title;$heading.Font=New-Object Drawing.Font('Segoe UI Semibold',20);$heading.ForeColor=[Drawing.Color]::FromArgb(24,36,51);$heading.AutoSize=$true;$heading.Location=New-Object Drawing.Point(24,20);$page.Controls.Add($heading)
    $grid=New-Object Windows.Forms.DataGridView;$grid.Location=New-Object Drawing.Point(24,70);$grid.Size=New-Object Drawing.Size(1020,490);$grid.Anchor='Top,Bottom,Left,Right';$grid.ReadOnly=$true;$grid.AllowUserToAddRows=$false;$grid.AllowUserToDeleteRows=$false;$grid.AllowUserToResizeRows=$false;$grid.RowHeadersVisible=$false;$grid.SelectionMode='CellSelect';$grid.MultiSelect=$true;$grid.ClipboardCopyMode='EnableAlwaysIncludeHeaderText';$grid.AutoSizeColumnsMode='DisplayedCells';$grid.BackgroundColor=[Drawing.Color]::White;$grid.BorderStyle='FixedSingle'
    foreach($column in $Columns){[void]$grid.Columns.Add($column.Key,$column.Label)}
    $footer=New-HardwareReadOnlyBox;$footer.Multiline=$true;$footer.Location=New-Object Drawing.Point(24,570);$footer.Size=New-Object Drawing.Size(1020,65);$footer.Anchor='Bottom,Left,Right';$footer.ScrollBars='Vertical';$footer.WordWrap=$true;$footer.Font=New-Object Drawing.Font('Segoe UI',9)
    $page.Controls.Add($grid);$page.Controls.Add($footer)
    return [PSCustomObject]@{Panel=$page;Grid=$grid;Footer=$footer}
}

function Set-HardwareGridRows {
    param([Windows.Forms.DataGridView]$Grid,[object[]]$Rows)
    $Grid.Rows.Clear()
    foreach($row in @($Rows)){[void]$Grid.Rows.Add([object[]]$row)}
}

function New-HardwareOverviewPage {
    $page=New-Object Windows.Forms.Panel;$page.Size=New-Object Drawing.Size(1100,650);$page.Dock='Fill';$page.BackColor=[Drawing.Color]::FromArgb(244,247,251);$page.AutoScroll=$true
    $heading=New-Object Windows.Forms.Label;$heading.Text='HARDWARE PASSPORT';$heading.Font=New-Object Drawing.Font('Segoe UI Semibold',20);$heading.ForeColor=[Drawing.Color]::FromArgb(24,36,51);$heading.AutoSize=$true;$heading.Location=New-Object Drawing.Point(24,16);$page.Controls.Add($heading)
    $subtitle=New-Object Windows.Forms.Label;$subtitle.Text='Краткая конфигурация компьютера';$subtitle.Font=New-Object Drawing.Font('Segoe UI',9);$subtitle.ForeColor=[Drawing.Color]::FromArgb(92,105,122);$subtitle.AutoSize=$true;$subtitle.Location=New-Object Drawing.Point(27,51);$page.Controls.Add($subtitle)
    $layout=New-Object Windows.Forms.TableLayoutPanel;$layout.Location=New-Object Drawing.Point(24,78);$layout.Size=New-Object Drawing.Size(1020,548);$layout.Anchor='Top,Bottom,Left,Right';$layout.ColumnCount=2;$layout.RowCount=5;$layout.BackColor=$page.BackColor
    [void]$layout.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle('Percent',50)));[void]$layout.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle('Percent',50)))
    foreach($height in @(96,104,112,168,58)){[void]$layout.RowStyles.Add((New-Object Windows.Forms.RowStyle('Absolute',$height)))}
    $values=@{};$cards=@{}
    $specs=@(
        [PSCustomObject]@{Key='Device';Title='Устройство';Column=0;Row=0;Span=1},[PSCustomObject]@{Key='System';Title='Система';Column=1;Row=0;Span=1},
        [PSCustomObject]@{Key='Cpu';Title='Процессор';Column=0;Row=1;Span=1},[PSCustomObject]@{Key='Ram';Title='Память';Column=1;Row=1;Span=1},
        [PSCustomObject]@{Key='Gpu';Title='Графика';Column=0;Row=2;Span=1},[PSCustomObject]@{Key='Board';Title='Материнская плата';Column=1;Row=2;Span=1},
        [PSCustomObject]@{Key='Storage';Title='Накопители';Column=0;Row=3;Span=1},[PSCustomObject]@{Key='Bios';Title='BIOS / UEFI';Column=1;Row=3;Span=1},
        [PSCustomObject]@{Key='Overall';Title='ОБЩИЙ СТАТУС';Column=0;Row=4;Span=2}
    )
    foreach($spec in $specs){
        $card=New-Object Windows.Forms.Panel;$card.Dock='Fill';$card.Margin=New-Object Windows.Forms.Padding(0,0,12,12);$card.BackColor=[Drawing.Color]::White;$card.BorderStyle='FixedSingle'
        if($spec.Column -eq 1){$card.Margin=New-Object Windows.Forms.Padding(0,0,0,12)}
        if($spec.Span -eq 2){$card.Margin=New-Object Windows.Forms.Padding(0,0,0,0)}
        $cardLayout=New-Object Windows.Forms.TableLayoutPanel;$cardLayout.Dock='Fill';$cardLayout.ColumnCount=1;$cardLayout.RowCount=2;$cardLayout.Padding=New-Object Windows.Forms.Padding(12,6,12,7)
        [void]$cardLayout.RowStyles.Add((New-Object Windows.Forms.RowStyle('Absolute',25)));[void]$cardLayout.RowStyles.Add((New-Object Windows.Forms.RowStyle('Percent',100)))
        $label=New-Object Windows.Forms.Label;$label.Text=$spec.Title;$label.Dock='Fill';$label.Font=New-Object Drawing.Font('Segoe UI Semibold',9);$label.ForeColor=[Drawing.Color]::FromArgb(31,119,210);$label.TextAlign='MiddleLeft'
        $box=New-HardwareReadOnlyBox $true;$box.Dock='Fill';$box.BorderStyle='None';$box.BackColor=[Drawing.Color]::White;$box.Font=New-Object Drawing.Font('Segoe UI',10);$box.WordWrap=$true;$box.ScrollBars=$(if($spec.Key -in @('Gpu','Storage')){'Vertical'}else{'None'});$box.AccessibleName=$spec.Title
        $cardLayout.Controls.Add($label,0,0);$cardLayout.Controls.Add($box,0,1);$card.Controls.Add($cardLayout);$layout.Controls.Add($card,$spec.Column,$spec.Row)
        if($spec.Span -gt 1){$layout.SetColumnSpan($card,$spec.Span)}
        $values[$spec.Key]=$box;$cards[$spec.Key]=$card
    }
    $page.Controls.Add($layout)
    return [PSCustomObject]@{Panel=$page;Values=$values;Cards=$cards;Layout=$layout}
}

function Get-HardwareOverviewValues {
    param([object]$Passport)
    $types=@($Passport.Ram.Modules|ForEach-Object Type|Where-Object{$_ -and $_ -ne 'Unavailable'}|Sort-Object -Unique)
    $speeds=@($Passport.Ram.Modules|ForEach-Object ConfiguredClockMHz|Where-Object{$_}|Sort-Object -Unique)
    $ramType=$(if($types.Count){$types -join '/'}else{'Type unavailable'})
    $ramSpeed=$(if($speeds.Count){($speeds -join '/')+' MT/s'}else{'speed unavailable'})
    $gpus=@($Passport.Gpu.Controllers|ForEach-Object Name|Where-Object{$_})
    $disks=@($Passport.Storage.Disks|ForEach-Object{"$($_.Model) — $($_.Capacity) — $($_.MediaType)/$($_.BusType) — $($_.Health)"})
    return [ordered]@{
        Device="$($Passport.System.Manufacturer) $($Passport.System.Model)`r`nИмя компьютера: $($Passport.System.Hostname)"
        System="$($Passport.System.WindowsEdition) $($Passport.System.WindowsArchitecture)`r`nBuild $($Passport.System.WindowsBuild)"
        Cpu="$($Passport.Cpu.Models -join '; ')`r`n$($Passport.Cpu.PhysicalCores) ядер / $($Passport.Cpu.LogicalProcessors) потоков"
        Ram="$($Passport.Ram.Total) $ramType — $ramSpeed`r`n$($Passport.Ram.ModuleCount) модулей"
        Gpu=$(if($gpus.Count){$gpus -join [Environment]::NewLine}else{'Unavailable'})
        Board="$($Passport.Motherboard.Manufacturer) $($Passport.Motherboard.Product)"
        Storage=$(if($disks.Count){$disks -join [Environment]::NewLine}else{'Unavailable'})
        Bios="$($Passport.Bios.Version)`r`n$($Passport.Bios.FirmwareType) — $($Passport.Bios.ReleaseDate)"
        Overall=[string]$Passport.OverallState
    }
}

function New-HardwareOverviewSummary {
    param([object]$Passport)
    $values=Get-HardwareOverviewValues $Passport
    $labels=[ordered]@{Device='Устройство';Cpu='Процессор';Ram='Память';Gpu='Графика';Storage='Накопители';Board='Материнская плата';Bios='BIOS / UEFI';System='Система';Overall='ОБЩИЙ СТАТУС'}
    $lines=New-Object Collections.Generic.List[string];$lines.Add('HARDWARE PASSPORT')
    foreach($key in $labels.Keys){$lines.Add('');$lines.Add($labels[$key]);$lines.Add([string]$values[$key])}
    return $lines -join [Environment]::NewLine
}

function Update-HardwareGui {
    param([object]$State)
    $p=$State.Passport
    $overview=Get-HardwareOverviewValues $p
    foreach($key in $overview.Keys){$State.OverviewValues[$key].Text=[string]$overview[$key]}
    $State.OverviewValues.Overall.Font=New-Object Drawing.Font('Segoe UI Semibold',13)
    $State.OverviewValues.Overall.ForeColor=$(switch($p.OverallState){'OK'{[Drawing.Color]::FromArgb(44,155,94)}'WARNING'{[Drawing.Color]::FromArgb(205,132,25)}'CRITICAL'{[Drawing.Color]::FromArgb(205,55,55)}default{[Drawing.Color]::FromArgb(92,105,122)}})
    $cpu=@{Model=$p.Cpu.Models-join '; ';Manufacturer=$p.Cpu.Manufacturers-join '; ';Cores=$p.Cpu.PhysicalCores;Logical=$p.Cpu.LogicalProcessors;Socket=$p.Cpu.Sockets-join '; ';MaxClock="$($p.Cpu.MaxClockMHz) MHz";CurrentClock="$($p.Cpu.CurrentClockMHz) MHz";MaxBoost='Not reliably reported by Windows';Architecture=$p.Cpu.Architecture;Cache="L2 $($p.Cpu.L2CacheKB) KB; L3 $($p.Cpu.L3CacheKB) KB"}
    foreach($key in $cpu.Keys){$State.CpuValues[$key].Text=[string]$cpu[$key]}
    Set-HardwareGridRows $State.RamGrid @($p.Ram.Modules|ForEach-Object{,@($_.DeviceLocator,$_.Manufacturer,$_.PartNumber,$_.Capacity,(Format-HardwareMemoryRate $_.RatedSpeedMHz),(Format-HardwareMemoryRate $_.ConfiguredClockMHz),$_.Serial,$_.State)})
    $State.RamFooter.Text="Total installed: $($p.Ram.Total) | Type: $(@($p.Ram.Modules|ForEach-Object Type|Sort-Object -Unique)-join '/') | Declared slots: $($p.Ram.DeclaredSlots) | Detected: $($p.Ram.ModuleCount) | State: $($p.Ram.State)`r`n$($p.Ram.Reasons -join '; ')"
    Set-HardwareGridRows $State.StorageGrid @($p.Storage.Disks|ForEach-Object{,@($_.Model,$_.MediaType,$_.Capacity,$_.BusType,$_.Health,($_.OperationalStatus-join ', '),$_.Firmware,$_.Serial)})
    $State.StorageFooter.Text="Overall storage state: $($p.Storage.State). UNKNOWN means Windows did not expose trustworthy health data."
    Set-HardwareGridRows $State.GpuGrid @($p.Gpu.Controllers|ForEach-Object{,@($_.Name,$_.VRAM,$_.DriverVersion,$_.PnpId,$p.Gpu.State)})
    $State.GpuFooter.Text='Windows does not expose a universal trustworthy GPU hardware-health value.'
    Set-HardwareGridRows $State.NetworkGrid @($p.Network.Adapters|ForEach-Object{,@($_.Name,$_.AdapterType,$_.Manufacturer,$_.MAC,$_.LinkState)})
    $State.NetworkFooter.Text="Physical Ethernet / Wi-Fi adapters: $(@($p.Network.Adapters).Count)."
    $bios=@{BoardManufacturer=$p.Motherboard.Manufacturer;BoardProduct=$p.Motherboard.Product;BoardVersion=$p.Motherboard.Version;BoardSerial=$p.Motherboard.Serial;BiosManufacturer=$p.Bios.Manufacturer;BiosVersion=$p.Bios.Version;ReleaseDate=$p.Bios.ReleaseDate;FirmwareType=$p.Bios.FirmwareType;SecureBoot=$p.Bios.SecureBoot}
    foreach($key in $bios.Keys){$State.BiosValues[$key].Text=[string]$bios[$key]}
    $battery=@($p.Battery.Batteries|Select-Object -First 1)
    $b=if($battery.Count){$battery[0]}else{$null}
    $batteryValues=@{Detected=$p.Battery.Detected;Summary=$p.Battery.Summary;Charge=$(if($b){"$($b.ChargePercent)%"}else{'Not applicable'});Status=$(if($b){$b.StatusCode}else{'Not applicable'});Design=$(if($b){$b.DesignCapacity}else{'Unavailable'});Full=$(if($b){$b.FullChargeCapacity}else{'Unavailable'})}
    foreach($key in $batteryValues.Keys){$State.BatteryValues[$key].Text=[string]$batteryValues[$key]}
    $State.RawJson.Text=$p|ConvertTo-Json -Depth 10
    $State.StatusLabel.Text=$p.OverallState;$State.StatusLabel.ForeColor=$(switch($p.OverallState){'OK'{[Drawing.Color]::FromArgb(61,180,112)}'WARNING'{[Drawing.Color]::FromArgb(240,175,60)}'CRITICAL'{[Drawing.Color]::FromArgb(220,70,70)}default{[Drawing.Color]::Silver}})
    $generated=[datetime]$p.GeneratedAt;$State.FooterLabel.Text=('Дата: {0:dd.MM.yy}    Время: {0:HH:mm}    Last refresh: {1:HH:mm}    EXPC WinDiagProbe    Design by EXPC' -f $generated,(Get-Date))
    if($State.WsdViewer){$State.PathLabel.Text="Папка отчёта: $($State.ReportFolder)"}else{$State.PathLabel.Text="Reports: $($State.Directory) | Current basename: $($State.BaseName)"}
}

function Show-HardwareDiagnosticsGui {
    param([object]$Passport,[string]$BaseName,[string]$Directory,[switch]$SmokeTest,[string]$ScreenshotPath='',[switch]$WsdViewer,[string]$ReportFolder='')
    Add-Type -AssemblyName System.Windows.Forms;Add-Type -AssemblyName System.Drawing
    [Windows.Forms.Application]::EnableVisualStyles()
    $form=New-Object Windows.Forms.Form;$form.Text='EXPC WinDiagProbe — Hardware Diagnostics';$form.Size=New-Object Drawing.Size(1350,850);$form.MinimumSize=New-Object Drawing.Size(1100,700);$form.StartPosition='CenterScreen';$form.BackColor=[Drawing.Color]::FromArgb(244,247,251);$form.KeyPreview=$true
    $nav=New-Object Windows.Forms.Panel;$nav.Dock='Left';$nav.Width=245;$nav.BackColor=[Drawing.Color]::FromArgb(24,36,51)
    $brand=New-Object Windows.Forms.Label;$brand.Text="EXPC`r`nWinDiagProbe`r`nHardware Diagnostics";$brand.Font=New-Object Drawing.Font('Segoe UI Semibold',14);$brand.ForeColor=[Drawing.Color]::White;$brand.SetBounds(20,20,220,82);$nav.Controls.Add($brand)
    $statusPanel=New-Object Windows.Forms.Panel;$statusPanel.Dock='Bottom';$statusPanel.Height=90
    $statusTitle=New-Object Windows.Forms.Label;$statusTitle.Text='Общий статус';$statusTitle.ForeColor=[Drawing.Color]::LightGray;$statusTitle.SetBounds(20,12,200,22)
    $status=New-Object Windows.Forms.Label;$status.Font=New-Object Drawing.Font('Segoe UI Semibold',16);$status.SetBounds(20,38,200,35);$statusPanel.Controls.Add($statusTitle);$statusPanel.Controls.Add($status);$nav.Controls.Add($statusPanel)
    $workspace=New-Object Windows.Forms.Panel;$workspace.Dock='Fill';$workspace.BackColor=[Drawing.Color]::FromArgb(244,247,251)
    $header=New-Object Windows.Forms.Panel;$header.Dock='Top';$header.Height=58;$header.BackColor=[Drawing.Color]::White
    $headerText=New-Object Windows.Forms.Label;$headerText.Text='Hardware Passport';$headerText.Font=New-Object Drawing.Font('Segoe UI Semibold',17);$headerText.ForeColor=[Drawing.Color]::FromArgb(24,36,51);$headerText.AutoSize=$true;$headerText.Location=New-Object Drawing.Point(22,14);$header.Controls.Add($headerText)
    $actions=New-Object Windows.Forms.Panel;$actions.Dock='Bottom';$actions.Height=70;$actions.BackColor=[Drawing.Color]::White;$actions.AutoScroll=$true
    $footer=New-Object Windows.Forms.Label;$footer.Dock='Bottom';$footer.Height=24;$footer.TextAlign='MiddleLeft';$footer.ForeColor=[Drawing.Color]::DimGray;$footer.Padding=New-Object Windows.Forms.Padding(12,0,0,0)
    $content=New-Object Windows.Forms.Panel;$content.Dock='Fill';$content.Padding=New-Object Windows.Forms.Padding(0)
    $workspace.Controls.Add($content);$workspace.Controls.Add($footer);$workspace.Controls.Add($actions);$workspace.Controls.Add($header);$form.Controls.Add($workspace);$form.Controls.Add($nav)

    $overview=New-HardwareOverviewPage
    $cpu=New-HardwarePropertyPage 'Процессор' @([PSCustomObject]@{Key='Model';Label='Model'},[PSCustomObject]@{Key='Manufacturer';Label='Manufacturer'},[PSCustomObject]@{Key='Cores';Label='Cores'},[PSCustomObject]@{Key='Logical';Label='Logical processors'},[PSCustomObject]@{Key='Socket';Label='Socket'},[PSCustomObject]@{Key='MaxClock';Label='Base clock (Windows-reported nominal)'},[PSCustomObject]@{Key='CurrentClock';Label='Current clock'},[PSCustomObject]@{Key='MaxBoost';Label='Max Boost'},[PSCustomObject]@{Key='Architecture';Label='Architecture'},[PSCustomObject]@{Key='Cache';Label='Cache'})
    $ram=New-HardwareGridPage 'Память (RAM)' @([PSCustomObject]@{Key='Slot';Label='Slot'},[PSCustomObject]@{Key='Manufacturer';Label='Manufacturer'},[PSCustomObject]@{Key='PartNumber';Label='Part Number'},[PSCustomObject]@{Key='Capacity';Label='Capacity'},[PSCustomObject]@{Key='Speed';Label='Rated speed (SMBIOS)'},[PSCustomObject]@{Key='Clock';Label='Configured speed (SMBIOS)'},[PSCustomObject]@{Key='Serial';Label='Serial'},[PSCustomObject]@{Key='State';Label='State'})
    $storage=New-HardwareGridPage 'Накопители' @([PSCustomObject]@{Key='Model';Label='Model'},[PSCustomObject]@{Key='Type';Label='Type'},[PSCustomObject]@{Key='Capacity';Label='Capacity'},[PSCustomObject]@{Key='Bus';Label='Bus / Interface'},[PSCustomObject]@{Key='Health';Label='Health'},[PSCustomObject]@{Key='Operational';Label='Operational State'},[PSCustomObject]@{Key='Firmware';Label='Firmware'},[PSCustomObject]@{Key='Serial';Label='Serial'})
    $gpu=New-HardwareGridPage 'Видеоадаптеры' @([PSCustomObject]@{Key='Name';Label='Name'},[PSCustomObject]@{Key='VRAM';Label='Video memory'},[PSCustomObject]@{Key='Driver';Label='Driver version'},[PSCustomObject]@{Key='Pnp';Label='PNP identifier'},[PSCustomObject]@{Key='State';Label='State'})
    $network=New-HardwareGridPage 'Сеть' @([PSCustomObject]@{Key='Adapter';Label='Adapter'},[PSCustomObject]@{Key='Type';Label='Type'},[PSCustomObject]@{Key='Manufacturer';Label='Manufacturer'},[PSCustomObject]@{Key='MAC';Label='MAC'},[PSCustomObject]@{Key='State';Label='Connection state'})
    $bios=New-HardwarePropertyPage 'BIOS / Плата' @([PSCustomObject]@{Key='BoardManufacturer';Label='Board manufacturer'},[PSCustomObject]@{Key='BoardProduct';Label='Board product'},[PSCustomObject]@{Key='BoardVersion';Label='Board version'},[PSCustomObject]@{Key='BoardSerial';Label='Board serial'},[PSCustomObject]@{Key='BiosManufacturer';Label='BIOS manufacturer'},[PSCustomObject]@{Key='BiosVersion';Label='BIOS version'},[PSCustomObject]@{Key='ReleaseDate';Label='Release date'},[PSCustomObject]@{Key='FirmwareType';Label='UEFI / Legacy'},[PSCustomObject]@{Key='SecureBoot';Label='Secure Boot'})
    $battery=New-HardwarePropertyPage 'Батарея' @([PSCustomObject]@{Key='Detected';Label='Battery detected'},[PSCustomObject]@{Key='Summary';Label='Summary'},[PSCustomObject]@{Key='Charge';Label='Charge'},[PSCustomObject]@{Key='Status';Label='Status'},[PSCustomObject]@{Key='Design';Label='Design capacity'},[PSCustomObject]@{Key='Full';Label='Full charge capacity'})
    $rawPage=New-Object Windows.Forms.Panel;$rawPage.Size=New-Object Drawing.Size(1100,650);$rawPage.Dock='Fill';$rawPage.BackColor=[Drawing.Color]::FromArgb(244,247,251)
    $rawHeading=New-Object Windows.Forms.Label;$rawHeading.Text='Raw JSON';$rawHeading.Font=New-Object Drawing.Font('Segoe UI Semibold',20);$rawHeading.AutoSize=$true;$rawHeading.Location=New-Object Drawing.Point(24,20)
    $raw=New-HardwareReadOnlyBox $true;$raw.Location=New-Object Drawing.Point(24,70);$raw.Size=New-Object Drawing.Size(1020,565);$raw.Anchor='Top,Bottom,Left,Right';$rawPage.Controls.Add($rawHeading);$rawPage.Controls.Add($raw)
    $pages=[ordered]@{Overview=$overview.Panel;Cpu=$cpu.Panel;Ram=$ram.Panel;Storage=$storage.Panel;Gpu=$gpu.Panel;Network=$network.Panel;Bios=$bios.Panel;Battery=$battery.Panel;Raw=$rawPage}
    foreach($page in $pages.Values){$page.Visible=$false;$content.Controls.Add($page)}
    $navButtons=@{};$navItems=@([PSCustomObject]@{Key='Overview';Label='Обзор'},[PSCustomObject]@{Key='Cpu';Label='Процессор'},[PSCustomObject]@{Key='Ram';Label='Память (RAM)'},[PSCustomObject]@{Key='Storage';Label='Накопители'},[PSCustomObject]@{Key='Gpu';Label='Видеоадаптеры'},[PSCustomObject]@{Key='Network';Label='Сеть'},[PSCustomObject]@{Key='Bios';Label='BIOS / Плата'},[PSCustomObject]@{Key='Battery';Label='Батарея'},[PSCustomObject]@{Key='Raw';Label='Raw JSON'})
    $top=118
    foreach($item in $navItems){$key=$item.Key;$button=New-Object Windows.Forms.Button;$button.Text=$item.Label;$button.FlatStyle='Flat';$button.FlatAppearance.BorderSize=0;$button.TextAlign='MiddleLeft';$button.Padding=New-Object Windows.Forms.Padding(14,0,0,0);$button.Font=New-Object Drawing.Font('Segoe UI',10);$button.ForeColor=[Drawing.Color]::White;$button.BackColor=$nav.BackColor;$button.SetBounds(0,$top,245,43);$nav.Controls.Add($button);$navButtons[$key]=$button;$top+=44}
    $state=[PSCustomObject]@{Passport=$Passport;BaseName=$BaseName;Directory=$Directory;Pages=$pages;NavButtons=$navButtons;OverviewValues=$overview.Values;CpuValues=$cpu.Values;RamGrid=$ram.Grid;RamFooter=$ram.Footer;StorageGrid=$storage.Grid;StorageFooter=$storage.Footer;GpuGrid=$gpu.Grid;GpuFooter=$gpu.Footer;NetworkGrid=$network.Grid;NetworkFooter=$network.Footer;BiosValues=$bios.Values;BatteryValues=$battery.Values;RawJson=$raw;StatusLabel=$status;FooterLabel=$footer;PathLabel=$null;CurrentPage='Overview';WsdViewer=[bool]$WsdViewer;ReportFolder=$ReportFolder}
    $showPage={param($key)foreach($name in $state.Pages.Keys){$state.Pages[$name].Visible=($name -eq $key);$state.NavButtons[$name].BackColor=$(if($name -eq $key){[Drawing.Color]::FromArgb(31,119,210)}else{[Drawing.Color]::FromArgb(24,36,51)})};$state.Pages[$key].BringToFront();$state.CurrentPage=$key}.GetNewClosure()
    foreach($key in @($navButtons.Keys)){$localKey=$key;$navButtons[$key].Add_Click(({&$showPage $localKey}.GetNewClosure()))}
    if($WsdViewer){$buttonSpecs=@([PSCustomObject]@{Text='Обновить (F5)';Width=125},[PSCustomObject]@{Text='Копировать сводку';Width=145},[PSCustomObject]@{Text='Открыть папку отчёта';Width=170},[PSCustomObject]@{Text='Закрыть';Width=100})}else{$buttonSpecs=@([PSCustomObject]@{Text='Обновить (F5)';Width=125},[PSCustomObject]@{Text='Копировать сводку';Width=145},[PSCustomObject]@{Text='Копировать всё';Width=125},[PSCustomObject]@{Text='Сохранить TXT';Width=120},[PSCustomObject]@{Text='Сохранить JSON';Width=125},[PSCustomObject]@{Text='Экспорт HTML';Width=120},[PSCustomObject]@{Text='Открыть папку отчётов';Width=175})};$actionButtons=@();$left=12
    foreach($spec in $buttonSpecs){$b=New-Object Windows.Forms.Button;$b.Text=$spec.Text;$b.Width=$spec.Width;$b.Height=34;$b.Left=$left;$b.Top=8;$b.FlatStyle='Flat';$b.BackColor=[Drawing.Color]::FromArgb(31,119,210);$b.ForeColor=[Drawing.Color]::White;$b.FlatAppearance.BorderSize=0;$actions.Controls.Add($b);$actionButtons+=$b;$left+=$b.Width+8}
    $pathLabel=New-Object Windows.Forms.Label;$pathLabel.SetBounds(14,45,1050,20);$pathLabel.AutoEllipsis=$true;$pathLabel.Anchor='Bottom,Left,Right';$actions.Controls.Add($pathLabel);$state.PathLabel=$pathLabel
    $refresh={try{$form.Cursor='WaitCursor';$pathLabel.Text='Collecting hardware passport...';[Windows.Forms.Application]::DoEvents();$state.Passport=New-HardwarePassport;$allocation=Get-UniqueWinDiagReportBaseName Hardware (Get-Date) $state.Directory @('.txt','.json','.html');$state.BaseName=$allocation.BaseName;Update-HardwareGui $state}catch{$pathLabel.Text='Error: '+$_.Exception.Message}finally{$form.Cursor='Default'}}.GetNewClosure()
    $copySummary={try{[Windows.Forms.Clipboard]::SetText((New-HardwareOverviewSummary $state.Passport));$pathLabel.Text='Copied: overview summary'}catch{$pathLabel.Text='Clipboard error: '+$_.Exception.Message}}.GetNewClosure()
    $copyAll={try{[Windows.Forms.Clipboard]::SetText((@(New-HardwareReportLines $state.Passport)-join [Environment]::NewLine));$pathLabel.Text='Copied: full hardware report'}catch{$pathLabel.Text='Clipboard error: '+$_.Exception.Message}}.GetNewClosure()
    $saveTxt={try{$pathLabel.Text='Saved: '+(Save-HardwareReport $state.Passport $state.BaseName $state.Directory TXT)}catch{$pathLabel.Text='Error: '+$_.Exception.Message}}.GetNewClosure()
    $saveJson={try{$pathLabel.Text='Saved: '+(Save-HardwareReport $state.Passport $state.BaseName $state.Directory JSON)}catch{$pathLabel.Text='Error: '+$_.Exception.Message}}.GetNewClosure()
    $saveHtml={try{$pathLabel.Text='Saved: '+(Save-HardwareReport $state.Passport $state.BaseName $state.Directory HTML)}catch{$pathLabel.Text='Error: '+$_.Exception.Message}}.GetNewClosure()
    $openReports={try{Start-Process -FilePath explorer.exe -ArgumentList @($state.Directory);$pathLabel.Text='Opened: '+$state.Directory}catch{$pathLabel.Text='Error: '+$_.Exception.Message}}.GetNewClosure()
    # WinStateDiag viewer: evidence is persisted automatically by WinStateDiag (no manual save buttons); a refresh writes a new set and announces it.
    $refreshWsd={try{$form.Cursor='WaitCursor';$pathLabel.Text='Collecting hardware passport...';[Windows.Forms.Application]::DoEvents();$state.Passport=New-HardwarePassport;$allocation=Get-UniqueWinDiagReportBaseName Hardware (Get-Date) $state.Directory @('.txt','.json','.html');$state.BaseName=$allocation.BaseName;foreach($format in @('TXT','JSON','HTML')){[void](Save-HardwareReport $state.Passport $state.BaseName $state.Directory $format)};[Console]::Out.WriteLine('WSD_HW_SAVED|'+$state.BaseName);[Console]::Out.Flush();Update-HardwareGui $state}catch{$pathLabel.Text='Error: '+$_.Exception.Message}finally{$form.Cursor='Default'}}.GetNewClosure()
    $openReportFolder={try{if(-not (Test-Path -LiteralPath $state.ReportFolder -PathType Container)){throw ('Папка отчёта не найдена: '+$state.ReportFolder)};Invoke-Item -LiteralPath $state.ReportFolder;$pathLabel.Text='Открыто: '+$state.ReportFolder}catch{$pathLabel.Text='Error: '+$_.Exception.Message}}.GetNewClosure()
    $closeViewer={$form.Close()}.GetNewClosure()
    if($WsdViewer){$handlers=@($refreshWsd,$copySummary,$openReportFolder,$closeViewer);$refreshAction=$refreshWsd}else{$handlers=@($refresh,$copySummary,$copyAll,$saveTxt,$saveJson,$saveHtml,$openReports);$refreshAction=$refresh};for($i=0;$i -lt $actionButtons.Count;$i++){$actionButtons[$i].Add_Click($handlers[$i])}
    $form.Add_KeyDown(({if($_.KeyCode -eq [Windows.Forms.Keys]::F5){&$refreshAction;$_.Handled=$true}}.GetNewClosure()))
    if($WsdViewer){$form.Add_Shown(({$form.TopMost=$true;$form.Activate();$form.TopMost=$false}.GetNewClosure()))}
    Update-HardwareGui $state;&$showPage 'Overview'
    if($SmokeTest){
        $originalClipboard=$null
        try{$originalClipboard=[Windows.Forms.Clipboard]::GetDataObject()}catch{}
        try{
            $form.Show();[Windows.Forms.Application]::DoEvents()
            $actionButtons[1].PerformClick();$summaryText=[Windows.Forms.Clipboard]::GetText();$summaryCopied=($summaryText -match 'HARDWARE PASSPORT' -and $summaryText -match 'Процессор' -and $summaryText -match 'ОБЩИЙ СТАТУС')
            $actionButtons[2].PerformClick();$allCopied=([Windows.Forms.Clipboard]::GetText() -match '\[STORAGE\]')
            $previousGeneration=$state.Passport.GeneratedAt
            $keyArgs=New-Object Windows.Forms.KeyEventArgs([Windows.Forms.Keys]::F5)
            $onKeyDown=$form.GetType().GetMethod('OnKeyDown',[Reflection.BindingFlags]'Instance,NonPublic')
            [void]$onKeyDown.Invoke($form,[object[]]@($keyArgs.PSObject.BaseObject));[Windows.Forms.Application]::DoEvents()
            $refreshWorked=($keyArgs.Handled -and $state.Passport.GeneratedAt -ne $previousGeneration -and -not [string]::IsNullOrWhiteSpace($state.RawJson.Text))
            $actionButtons[3].PerformClick();$txtPath=Join-Path $state.Directory ($state.BaseName+'.txt')
            $actionButtons[4].PerformClick();$jsonPath=Join-Path $state.Directory ($state.BaseName+'.json')
            $actionButtons[5].PerformClick();$htmlPath=Join-Path $state.Directory ($state.BaseName+'.html')
            $actionButtons[6].PerformClick();$folderOpened=$pathLabel.Text -eq ('Opened: '+$state.Directory)
            if(-not [string]::IsNullOrWhiteSpace($ScreenshotPath)){$form.Show();[Windows.Forms.Application]::DoEvents();$bitmap=New-Object Drawing.Bitmap($form.Width,$form.Height);try{$form.DrawToBitmap($bitmap,(New-Object Drawing.Rectangle(0,0,$bitmap.Width,$bitmap.Height)));$bitmap.Save($ScreenshotPath,[Drawing.Imaging.ImageFormat]::Png)}finally{$bitmap.Dispose();$form.Hide()}}
            $overviewKeys=@('Device','Cpu','Ram','Gpu','Storage','Board','Bios','System','Overall')
            $overviewPopulated=@($overviewKeys|Where-Object{[string]::IsNullOrWhiteSpace($overview.Values[$_].Text)}).Count -eq 0
            $overviewAllCopyable=@($overviewKeys|Where-Object{-not ($overview.Values[$_] -is [Windows.Forms.TextBox]) -or -not $overview.Values[$_].ReadOnly}).Count -eq 0
            $result=[PSCustomObject]@{Title=$form.Text;Size="$($form.Width)x$($form.Height)";Pages=@($pages.Keys);Buttons=@($actionButtons|ForEach-Object Text);ReportDirectory=$Directory;BaseName=$state.BaseName;OverviewCopyable=$overviewAllCopyable;OverviewPopulated=$overviewPopulated;CpuPopulated=(-not [string]::IsNullOrWhiteSpace($cpu.Values.Model.Text));RamGrid=($ram.Grid -is [Windows.Forms.DataGridView]);RamRows=$ram.Grid.Rows.Count;StorageGrid=($storage.Grid -is [Windows.Forms.DataGridView]);StorageRows=$storage.Grid.Rows.Count;GpuRows=$gpu.Grid.Rows.Count;NetworkRows=$network.Grid.Rows.Count;BiosPopulated=(-not [string]::IsNullOrWhiteSpace($bios.Values.BiosVersion.Text));BatterySafe=(-not [string]::IsNullOrWhiteSpace($battery.Values.Summary.Text));GridsCopyable=($ram.Grid.ClipboardCopyMode -eq 'EnableAlwaysIncludeHeaderText' -and $storage.Grid.ClipboardCopyMode -eq 'EnableAlwaysIncludeHeaderText');RawJsonReadOnly=$raw.ReadOnly;RawJsonPopulated=(-not [string]::IsNullOrWhiteSpace($raw.Text));SummaryCopied=$summaryCopied;AllCopied=$allCopied;RefreshWorked=$refreshWorked;TxtPath=$txtPath;JsonPath=$jsonPath;HtmlPath=$htmlPath;ExportsExist=((Test-Path $txtPath) -and (Test-Path $jsonPath) -and (Test-Path $htmlPath));OpenFolderReady=((Test-Path $state.Directory) -and $actionButtons[6].Text -eq 'Открыть папку отчётов');OpenFolderWorked=$folderOpened;ScreenshotPath=$ScreenshotPath;ScreenshotExists=([string]::IsNullOrWhiteSpace($ScreenshotPath) -or (Test-Path $ScreenshotPath))}
        } finally {if($null -ne $originalClipboard){try{[Windows.Forms.Clipboard]::SetDataObject($originalClipboard,$true)}catch{}};$form.Hide();$form.Dispose()}
        return $result
    }
    [void]$form.ShowDialog()
}

Write-Host 'EXPC Hardware Diagnostics' -ForegroundColor Cyan
Write-Host 'Read-only hardware passport for Windows 7/8.1/10/11' -ForegroundColor Gray
Write-Host ("Runtime: {0}" -f $RuntimeInfo.DisplayName) -ForegroundColor Gray
Write-Host ("Compatibility: {0}" -f $RuntimeInfo.Compatibility) -ForegroundColor Gray
Write-Host ''

try {
    $passport = New-HardwarePassport
    if (-not (Test-Path -LiteralPath $OutputDirectory)) { [void](New-Item -ItemType Directory -Path $OutputDirectory -Force) }
    $allocation=Get-UniqueWinDiagReportBaseName -Prefix Hardware -RunStartedAt $runStarted -Directory $OutputDirectory -Extensions @('.txt','.json','.html')
    $baseName=$allocation.BaseName

    Write-Host ("Device: {0} {1}" -f $passport.System.Manufacturer,$passport.System.Model)
    Write-Host ("CPU: {0} ({1}C / {2}T)" -f ($passport.Cpu.Models -join '; '),$passport.Cpu.PhysicalCores,$passport.Cpu.LogicalProcessors)
    Write-Host ("RAM: {0}; {1} module(s); {2}" -f $passport.Ram.Total,$passport.Ram.ModuleCount,$passport.Ram.State)
    foreach ($gpu in @($passport.Gpu.Controllers)) { Write-Host ("GPU: {0}" -f $gpu.Name) }
    foreach ($disk in @($passport.Storage.Disks)) { Write-Host ("Storage: {0}; {1}; {2}/{3}; Health: {4}" -f $disk.Model,$disk.Capacity,$disk.MediaType,$disk.BusType,$disk.Health) }
    Write-Host ("Battery: {0}" -f $passport.Battery.Summary)
    Write-Host ''
    Write-Host ("Overall hardware state: {0}" -f $passport.OverallState) -ForegroundColor $(switch ($passport.OverallState) { 'OK' {'Green'} 'WARNING' {'Yellow'} 'CRITICAL' {'Red'} default {'Cyan'} })
    Write-Host 'Reports:' -ForegroundColor Cyan
    Write-Host $OutputDirectory
    if($GuiSmoke){
        $smoke=Show-HardwareDiagnosticsGui -Passport $passport -BaseName $baseName -Directory $OutputDirectory -SmokeTest -ScreenshotPath $GuiScreenshotPath
        $required=$smoke.Pages.Count -eq 9 -and $smoke.Buttons.Count -eq 7 -and $smoke.OverviewCopyable -and $smoke.OverviewPopulated -and $smoke.CpuPopulated -and $smoke.RamGrid -and $smoke.RamRows -gt 0 -and $smoke.StorageGrid -and $smoke.StorageRows -gt 0 -and $smoke.GpuRows -gt 0 -and $smoke.NetworkRows -gt 0 -and $smoke.BiosPopulated -and $smoke.BatterySafe -and $smoke.GridsCopyable -and $smoke.RawJsonReadOnly -and $smoke.RawJsonPopulated -and $smoke.SummaryCopied -and $smoke.AllCopied -and $smoke.RefreshWorked -and $smoke.ExportsExist -and $smoke.OpenFolderReady -and $smoke.OpenFolderWorked -and $smoke.ScreenshotExists
        if(-not $required){
            $failed=@($smoke.PSObject.Properties|Where-Object{$_.Value -is [bool] -and -not $_.Value}|ForEach-Object Name)
            throw ('Hardware GUI interaction smoke did not satisfy all required controls/actions: '+($failed -join ', '))
        }
        Write-Output ('HARDWARE_GUI_SMOKE_PASS: pages={0}; buttons={1}; copy={2}/{3}; refresh={4}; exports={5}; basename={6}; reports={7}' -f $smoke.Pages.Count,$smoke.Buttons.Count,$smoke.SummaryCopied,$smoke.AllCopied,$smoke.RefreshWorked,$smoke.ExportsExist,$smoke.BaseName,$smoke.ReportDirectory)
    } elseif ($WsdViewer) {
        # WinStateDiag "Смотреть": save first, let WinStateDiag persist the
        # evidence into the session report, then show the viewer.
        [Console]::Out.WriteLine('WSD_HW_PHASE|report');[Console]::Out.Flush()
        foreach($format in @('TXT','JSON','HTML')) { [void](Save-HardwareReport -Passport $passport -BaseName $baseName -Directory $OutputDirectory -Format $format) }
        [Console]::Out.WriteLine('WSD_HW_SAVED|'+$baseName);[Console]::Out.Flush()
        $reply=[string][Console]::In.ReadLine()
        if($reply.Trim() -eq 'SHOW'){ Show-HardwareDiagnosticsGui -Passport $passport -BaseName $baseName -Directory $OutputDirectory -WsdViewer -ReportFolder $ReportFolder }
    } elseif ($ExportAll -or $NoGui) {
        if ($ExportAll) {
            foreach($format in @('TXT','JSON','HTML')) { Write-Host (Save-HardwareReport -Passport $passport -BaseName $baseName -Directory $OutputDirectory -Format $format) }
        }
    } else {
        try { Show-HardwareDiagnosticsGui -Passport $passport -BaseName $baseName -Directory $OutputDirectory }
        catch {
            Write-Host ("[WARNING] GUI unavailable: {0}" -f $_.Exception.Message) -ForegroundColor Yellow
            foreach($format in @('TXT','JSON','HTML')) { Write-Host (Save-HardwareReport -Passport $passport -BaseName $baseName -Directory $OutputDirectory -Format $format) }
        }
    }
} catch {
    Write-Host ("[ERROR] Hardware diagnostics failed: {0}" -f $_.Exception.Message) -ForegroundColor Red
    exit 1
}
