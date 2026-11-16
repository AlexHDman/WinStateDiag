#requires -Version 5.0
[CmdletBinding()]
param(
    [string]$ReportsDirectory = '',
    [switch]$NoOpen,
    [switch]$PassThru
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'ReportStorage.psm1') -Force
if ([string]::IsNullOrWhiteSpace($ReportsDirectory)) {
    $ReportsDirectory = Get-WinDiagReportDirectory -Ensure
} elseif (-not (Test-Path -LiteralPath $ReportsDirectory)) {
    [void](New-Item -ItemType Directory -Path $ReportsDirectory -Force -ErrorAction Stop)
}
$ReportsDirectory = [IO.Path]::GetFullPath($ReportsDirectory)

function ConvertTo-HtmlText {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return '' }
    return [Net.WebUtility]::HtmlEncode([string]$Value)
}

function Get-ReportProperty {
    param([AllowNull()][object]$Object,[string]$Name,[AllowNull()][object]$Default=$null)
    if ($null -eq $Object) { return $Default }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value) { return $Default }
    return $property.Value
}

function ConvertTo-CanonicalState {
    param([AllowNull()][object]$Value)
    switch -Regex (([string]$Value).ToUpperInvariant()) {
        'CRITICAL|ERROR|FAILED|FAIL' { return 'CRITICAL' }
        'WARNING|ATTENTION|REVIEW' { return 'WARNING' }
        '^OK$|AVAILABLE|HEALTHY' { return 'OK' }
        default { return 'UNKNOWN' }
    }
}

function Get-StateRank {
    param([string]$State)
    switch ($State) { 'CRITICAL' {3} 'WARNING' {2} 'OK' {1} default {0} }
}

function Format-SourceTime {
    param([AllowNull()][object]$Value,[datetime]$Fallback)
    $parsed=[datetime]::MinValue
    if ($null -ne $Value -and [datetime]::TryParse([string]$Value,[ref]$parsed)) { return $parsed.ToLocalTime().ToString('dd.MM.yy HH:mm') }
    return $Fallback.ToLocalTime().ToString('dd.MM.yy HH:mm')
}

function Format-ByteSize {
    param([AllowNull()][object]$Bytes)
    $number=0.0
    if ($null -eq $Bytes -or -not [double]::TryParse([string]$Bytes,[ref]$number)) { return '' }
    if ($number -ge 1TB) { return ('{0:N2} TB' -f ($number/1TB)) }
    if ($number -ge 1GB) { return ('{0:N2} GB' -f ($number/1GB)) }
    if ($number -ge 1MB) { return ('{0:N1} MB' -f ($number/1MB)) }
    return ('{0:N0} B' -f $number)
}

function Get-LatestJsonReport {
    param([string]$Prefix)
    $file=Get-ChildItem -LiteralPath $ReportsDirectory -Filter ($Prefix+'_*.json') -File -Recurse -Force -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTimeUtc,Name -Descending | Select-Object -First 1
    if ($null -eq $file) {
        return [PSCustomObject]@{Kind=$Prefix;File=$null;Data=$null;Valid=$false;Missing=$true;Error=$null;SourceTime=$null}
    }
    try {
        $jsonText=[IO.File]::ReadAllText($file.FullName,(New-Object Text.UTF8Encoding($false)))
        $data=$jsonText | ConvertFrom-Json -ErrorAction Stop
        $generated=Get-ReportProperty $data 'GeneratedAt' (Get-ReportProperty $data 'generated_at' $null)
        return [PSCustomObject]@{Kind=$Prefix;File=$file;Data=$data;Valid=$true;Missing=$false;Error=$null;SourceTime=(Format-SourceTime $generated $file.LastWriteTime)}
    } catch {
        return [PSCustomObject]@{Kind=$Prefix;File=$file;Data=$null;Valid=$false;Missing=$false;Error=$_.Exception.Message;SourceTime=(Format-SourceTime $null $file.LastWriteTime)}
    }
}

function Add-SourceNotice {
    param([Collections.Generic.List[string]]$Html,[object]$Report,[string]$Title)
    $Html.Add('<section class="section">')
    $Html.Add('<div class="section-head"><div><h2>'+(ConvertTo-HtmlText $Title)+'</h2>')
    if ($Report.File) {$Html.Add('<div class="source">Source: '+(ConvertTo-HtmlText $Report.File.Name)+' · '+(ConvertTo-HtmlText $Report.SourceTime)+'</div>')}
    $Html.Add('</div></div>')
    if ($Report.Missing) {$Html.Add('<div class="empty">No report available</div>');$Html.Add('</section>');return $false}
    if (-not $Report.Valid) {$Html.Add('<div class="error-card"><strong>Invalid JSON</strong><br>'+(ConvertTo-HtmlText $Report.Error)+'</div>');$Html.Add('</section>');return $false}
    return $true
}

function New-CardHtml {
    param([string]$Title,[AllowNull()][object]$Value,[string]$Class='')
    $text=if([string]::IsNullOrWhiteSpace([string]$Value)){'No report available'}else{ConvertTo-HtmlText $Value}
    return '<article class="card '+$Class+'"><div class="card-title">'+(ConvertTo-HtmlText $Title)+'</div><div class="card-value">'+($text -replace "(`r`n|`n|`r)",'<br>')+'</div></article>'
}

function New-ObjectTableHtml {
    param([object[]]$Rows,[object[]]$Columns)
    if (-not @($Rows).Count) { return '<div class="empty">No report available</div>' }
    $html=New-Object Collections.Generic.List[string];$html.Add('<div class="table-wrap"><table><thead><tr>')
    foreach($column in $Columns){$html.Add('<th>'+(ConvertTo-HtmlText $column.Label)+'</th>')};$html.Add('</tr></thead><tbody>')
    foreach($row in @($Rows)){$html.Add('<tr>');foreach($column in $Columns){$value=Get-ReportProperty $row $column.Key '';if($value -is [array]){$value=$value -join ', '};$html.Add('<td>'+(ConvertTo-HtmlText $value)+'</td>')};$html.Add('</tr>')}
    $html.Add('</tbody></table></div>');return $html -join ''
}

function Add-HardwareReportHtml {
    param([Collections.Generic.List[string]]$Html,[object]$Report)
    if (-not (Add-SourceNotice $Html $Report 'Hardware Passport')) { return }
    $p=$Report.Data;$system=Get-ReportProperty $p 'System';$cpu=Get-ReportProperty $p 'Cpu';$ram=Get-ReportProperty $p 'Ram';$gpu=Get-ReportProperty $p 'Gpu';$storage=Get-ReportProperty $p 'Storage';$board=Get-ReportProperty $p 'Motherboard';$bios=Get-ReportProperty $p 'Bios'
    $modules=@(Get-ReportProperty $ram 'Modules' @());$types=@($modules|ForEach-Object{Get-ReportProperty $_ 'Type'}|Where-Object{$_}|Sort-Object -Unique);$speeds=@($modules|ForEach-Object{Get-ReportProperty $_ 'ConfiguredClockMHz'}|Where-Object{$_}|Sort-Object -Unique)
    $controllers=@(Get-ReportProperty $gpu 'Controllers' @());$disks=@(Get-ReportProperty $storage 'Disks' @())
    $gpuText=@($controllers|ForEach-Object{Get-ReportProperty $_ 'Name'}|Where-Object{$_}) -join "`n"
    $diskText=@($disks|ForEach-Object{('{0} — {1} — {2}/{3} — {4}' -f (Get-ReportProperty $_ 'Model'),(Get-ReportProperty $_ 'Capacity'),(Get-ReportProperty $_ 'MediaType'),(Get-ReportProperty $_ 'BusType'),(Get-ReportProperty $_ 'Health'))}) -join "`n"
    $Html.Add('<div class="cards">')
    $Html.Add((New-CardHtml 'DEVICE' (("{0} {1}`n{2}" -f (Get-ReportProperty $system 'Manufacturer'),(Get-ReportProperty $system 'Model'),(Get-ReportProperty $system 'Hostname')))))
    $Html.Add((New-CardHtml 'WINDOWS' (("{0} {1}`nBuild {2}" -f (Get-ReportProperty $system 'WindowsEdition'),(Get-ReportProperty $system 'WindowsArchitecture'),(Get-ReportProperty $system 'WindowsBuild')))))
    $Html.Add((New-CardHtml 'CPU' (("{0}`n{1} cores / {2} threads" -f (@(Get-ReportProperty $cpu 'Models' @()) -join '; '),(Get-ReportProperty $cpu 'PhysicalCores'),(Get-ReportProperty $cpu 'LogicalProcessors')))))
    $Html.Add((New-CardHtml 'RAM' (("{0} {1} — {2} MHz`n{3} modules" -f (Get-ReportProperty $ram 'Total'),($types -join '/'),($speeds -join '/'),(Get-ReportProperty $ram 'ModuleCount')))))
    $Html.Add((New-CardHtml 'GPU' $gpuText));$Html.Add((New-CardHtml 'MOTHERBOARD' (('{0} {1}' -f (Get-ReportProperty $board 'Manufacturer'),(Get-ReportProperty $board 'Product')))))
    $Html.Add((New-CardHtml 'STORAGE' $diskText 'wide'));$Html.Add((New-CardHtml 'BIOS / UEFI' (("{0}`n{1} · {2}" -f (Get-ReportProperty $bios 'Version'),(Get-ReportProperty $bios 'FirmwareType'),(Get-ReportProperty $bios 'ReleaseDate')))))
    $Html.Add('</div>')
    $Html.Add('<h3>CPU</h3><div class="key-grid">'+(New-CardHtml 'Model' (@(Get-ReportProperty $cpu 'Models' @()) -join '; '))+(New-CardHtml 'Topology' (('{0} cores / {1} threads' -f (Get-ReportProperty $cpu 'PhysicalCores'),(Get-ReportProperty $cpu 'LogicalProcessors'))))+(New-CardHtml 'Clock' (('Current {0} MHz · Max {1} MHz' -f (Get-ReportProperty $cpu 'CurrentClockMHz'),(Get-ReportProperty $cpu 'MaxClockMHz'))))+'</div>')
    $Html.Add('<h3>RAM</h3>');$Html.Add((New-ObjectTableHtml $modules @([PSCustomObject]@{Key='DeviceLocator';Label='Slot'},[PSCustomObject]@{Key='Manufacturer';Label='Manufacturer'},[PSCustomObject]@{Key='PartNumber';Label='Part number'},[PSCustomObject]@{Key='Capacity';Label='Capacity'},[PSCustomObject]@{Key='ConfiguredClockMHz';Label='Configured MHz'},[PSCustomObject]@{Key='State';Label='State'})))
    $Html.Add('<h3>Storage</h3>');$Html.Add((New-ObjectTableHtml $disks @([PSCustomObject]@{Key='Model';Label='Model'},[PSCustomObject]@{Key='MediaType';Label='Type'},[PSCustomObject]@{Key='Capacity';Label='Capacity'},[PSCustomObject]@{Key='BusType';Label='Bus'},[PSCustomObject]@{Key='Health';Label='Health'},[PSCustomObject]@{Key='OperationalStatus';Label='Operational'})))
    $Html.Add('<h3>GPU</h3>');$Html.Add((New-ObjectTableHtml $controllers @([PSCustomObject]@{Key='Name';Label='Name'},[PSCustomObject]@{Key='VRAM';Label='VRAM'},[PSCustomObject]@{Key='DriverVersion';Label='Driver'})))
    $network=Get-ReportProperty $p 'Network';$Html.Add('<h3>Network</h3>');$Html.Add((New-ObjectTableHtml @(Get-ReportProperty $network 'Adapters' @()) @([PSCustomObject]@{Key='Name';Label='Adapter'},[PSCustomObject]@{Key='AdapterType';Label='Type'},[PSCustomObject]@{Key='Manufacturer';Label='Manufacturer'},[PSCustomObject]@{Key='LinkState';Label='State'})))
    $Html.Add('<h3>BIOS / Motherboard</h3><div class="key-grid">'+(New-CardHtml 'Motherboard' (('{0} {1} {2}' -f (Get-ReportProperty $board 'Manufacturer'),(Get-ReportProperty $board 'Product'),(Get-ReportProperty $board 'Version'))))+(New-CardHtml 'BIOS / UEFI' (('{0} · {1} · {2}' -f (Get-ReportProperty $bios 'Version'),(Get-ReportProperty $bios 'FirmwareType'),(Get-ReportProperty $bios 'ReleaseDate'))))+'</div>')
    $battery=Get-ReportProperty $p 'Battery';$Html.Add('<h3>Battery</h3>');$Html.Add((New-CardHtml 'Battery' (Get-ReportProperty $battery 'Summary')))
    $Html.Add('</section>')
}

function Get-WinDiagDetail {
    param([string]$Name,[object]$Data)
    switch($Name){
        'system' { return ('{0}; build {1}; RAM {2}' -f (Get-ReportProperty $Data 'WindowsEdition'),(Get-ReportProperty $Data 'WindowsBuild'),(Format-ByteSize (Get-ReportProperty (Get-ReportProperty $Data 'RAM') 'TotalBytes'))) }
        'cpu_sample' { return ('Average {0}% · Max {1}% · {2} samples' -f (Get-ReportProperty $Data 'AveragePercent'),(Get-ReportProperty $Data 'MaximumPercent'),(Get-ReportProperty $Data 'SampleCount')) }
        'memory_health' { return ('Available {0}% · Commit {1}%' -f (Get-ReportProperty $Data 'AvailablePercent'),(Get-ReportProperty $Data 'CommitPercent')) }
        'driver_state' { return ('Unsigned {0} · Problematic {1} · Verifier {2}' -f @((Get-ReportProperty $Data 'UnsignedDrivers' @())).Count,@((Get-ReportProperty $Data 'ProblematicDrivers' @())).Count,(Get-ReportProperty (Get-ReportProperty $Data 'DriverVerifier') 'State')) }
        'crash_hang_summary' { return ('Application events {0} · System events {1}' -f @((Get-ReportProperty $Data 'Application' @())).Count,@((Get-ReportProperty $Data 'System' @())).Count) }
        'power_state' { return ('Battery present: {0} · {1}' -f (Get-ReportProperty $Data 'BatteryPresent'),(Get-ReportProperty $Data 'ActiveScheme')) }
        'multi_user_rdp' { return ('RDP enabled: {0} · Sessions {1} · Active {2} · Disconnected {3}' -f (Get-ReportProperty $Data 'RDPEnabled'),(Get-ReportProperty $Data 'SessionCount'),(Get-ReportProperty $Data 'ActiveSessionCount'),(Get-ReportProperty $Data 'DisconnectedSessionCount')) }
        'thermal_fan_capability' {$thermal=Get-ReportProperty $Data 'Thermal';$fan=Get-ReportProperty $Data 'Fan';return ('Thermal {0} · Fan participant {1} · RPM {2}' -f (Get-ReportProperty $thermal 'Status'),(Get-ReportProperty $fan 'FanParticipantStatus'),(Get-ReportProperty $fan 'RPMStatus'))}
        default { return '' }
    }
}

function Add-WinDiagReportHtml {
    param([Collections.Generic.List[string]]$Html,[object]$Report)
    if (-not (Add-SourceNotice $Html $Report 'WinDiagProbe findings')) { return }
    $labels=[ordered]@{system='System';cpu_sample='CPU sample';memory_health='Memory';top_processes='Top processes';driver_state='Drivers';crash_hang_summary='Crash / Hang';power_state='Power';multi_user_rdp='Multi-user / RDP';thermal_fan_capability='Thermal / Fan capability'}
    $Html.Add('<div class="table-wrap"><table><thead><tr><th>Area</th><th>Status</th><th>Important findings</th></tr></thead><tbody>')
    foreach($name in $labels.Keys){$section=Get-ReportProperty $Report.Data $name;if($null -eq $section){continue};$status=[string](Get-ReportProperty $section 'Status' 'UNKNOWN');$detail=Get-WinDiagDetail $name (Get-ReportProperty $section 'Data');$Html.Add('<tr><td>'+(ConvertTo-HtmlText $labels[$name])+'</td><td><span class="badge '+(ConvertTo-CanonicalState $status).ToLowerInvariant()+'">'+(ConvertTo-HtmlText $status)+'</span></td><td>'+(ConvertTo-HtmlText $detail)+'</td></tr>')}
    $Html.Add('</tbody></table></div></section>')
}

function Add-ExpcReportHtml {
    param([Collections.Generic.List[string]]$Html,[object]$Report)
    if (-not (Add-SourceNotice $Html $Report 'EXPC-Diagnostic findings')) { return }
    $checks=@(Get-ReportProperty $Report.Data 'Checks' @());$attention=@(Get-ReportProperty $Report.Data 'Attention' @())
    if($checks.Count){$Html.Add((New-ObjectTableHtml $checks @([PSCustomObject]@{Key='Check';Label='Check'},[PSCustomObject]@{Key='Status';Label='Status'},[PSCustomObject]@{Key='Detail';Label='Finding'})))}else{$Html.Add('<div class="empty">No report available</div>')}
    if($attention.Count){$Html.Add('<h3>Attention</h3><ul class="findings">');foreach($item in $attention){$Html.Add('<li>'+(ConvertTo-HtmlText $item)+'</li>')};$Html.Add('</ul>')}
    $Html.Add('</section>')
}

function Get-ViewerIdentity {
    param([object]$Hardware,[object]$WinDiag,[object]$Expc)
    if($Hardware.Valid){$s=Get-ReportProperty $Hardware.Data 'System';return [PSCustomObject]@{Computer=Get-ReportProperty $s 'Hostname';Device=(('{0} {1}' -f (Get-ReportProperty $s 'Manufacturer'),(Get-ReportProperty $s 'Model')).Trim())}}
    if($WinDiag.Valid){$s=Get-ReportProperty (Get-ReportProperty $WinDiag.Data 'system') 'Data';return [PSCustomObject]@{Computer=Get-ReportProperty $s 'ComputerName';Device=''}}
    if($Expc.Valid){return [PSCustomObject]@{Computer=Get-ReportProperty $Expc.Data 'Computer';Device=(('{0} {1}' -f (Get-ReportProperty $Expc.Data 'Company'),(Get-ReportProperty $Expc.Data 'Station')).Trim())}}
    return [PSCustomObject]@{Computer=$env:COMPUTERNAME;Device=''}
}

function Get-ViewerOverallState {
    param([object]$Hardware,[object]$WinDiag,[object]$Expc)
    $states=New-Object Collections.Generic.List[string]
    if($Hardware.Valid){$states.Add((ConvertTo-CanonicalState (Get-ReportProperty $Hardware.Data 'OverallState')))}
    if($WinDiag.Valid){$states.Add((ConvertTo-CanonicalState (Get-ReportProperty $WinDiag.Data 'OverallStatus')))}
    if($Expc.Valid){$checks=@(Get-ReportProperty $Expc.Data 'Checks' @());$attention=@(Get-ReportProperty $Expc.Data 'Attention' @());if(@($checks|Where-Object{(ConvertTo-CanonicalState (Get-ReportProperty $_ 'Status')) -eq 'CRITICAL'}).Count){$states.Add('CRITICAL')}elseif($attention.Count -or @($checks|Where-Object{(ConvertTo-CanonicalState (Get-ReportProperty $_ 'Status')) -eq 'WARNING'}).Count){$states.Add('WARNING')}else{$states.Add('OK')}}
    if(-not $states.Count){return 'UNKNOWN'}
    return $states|Sort-Object @{Expression={Get-StateRank $_};Descending=$true}|Select-Object -First 1
}

function Get-NewSummaryPath {
    param([datetime]$Now)
    $base='Summary_'+$Now.ToLocalTime().ToString('dd.MM.yy_HH-mm',[Globalization.CultureInfo]::InvariantCulture);$sequence=1
    while($true){$name=if($sequence -eq 1){$base+'.html'}else{'{0}_{1:D2}.html' -f $base,$sequence};$path=Join-Path $ReportsDirectory $name;if(-not(Test-Path -LiteralPath $path)){return $path};$sequence++}
}

$hardware=Get-LatestJsonReport 'Hardware';$winDiag=Get-LatestJsonReport 'WinDiagProbe';$expc=Get-LatestJsonReport 'EXPC'
$identity=Get-ViewerIdentity $hardware $winDiag $expc;$overall=Get-ViewerOverallState $hardware $winDiag $expc;$now=Get-Date;$outputPath=Get-NewSummaryPath $now
$computerLabel=@([string]$identity.Computer,[string]$identity.Device)|Where-Object{-not [string]::IsNullOrWhiteSpace($_)}
$computerLabel=$computerLabel -join ' · '
$html=New-Object Collections.Generic.List[string]
$html.Add('<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>EXPC WinDiagProbe — Diagnostic Report</title>')
$html.Add(@'
<style>
:root{--navy:#182433;--blue:#1f77d0;--bg:#f4f7fb;--text:#182433;--muted:#66758a;--line:#dce3ec;--ok:#2c9b5e;--warning:#cd8419;--critical:#cd3737;--unknown:#68778a}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.45 "Segoe UI",Arial,sans-serif}.hero{background:var(--navy);color:#fff;padding:28px 36px}.hero-inner,.main{max-width:1220px;margin:auto}.brand{font-size:14px;color:#a9c7e8;letter-spacing:.08em;text-transform:uppercase}.hero h1{font-size:30px;margin:4px 0 18px}.meta{display:grid;grid-template-columns:2fr 1fr 1fr 1fr;gap:12px}.meta-item{background:#223449;border-left:3px solid var(--blue);padding:10px 12px;border-radius:4px}.meta-label,.card-title{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:#71829a}.meta-value{font-size:15px;margin-top:3px}.state{font-weight:700}.state.ok{color:#65d493}.state.warning{color:#ffc05a}.state.critical{color:#ff7777}.state.unknown{color:#c1c9d3}.main{padding:26px 24px 48px}.section{background:#fff;border:1px solid var(--line);border-radius:8px;padding:22px;margin-bottom:22px;box-shadow:0 2px 8px rgba(24,36,51,.05)}.section-head{display:flex;justify-content:space-between;align-items:flex-end;border-bottom:2px solid var(--blue);padding-bottom:10px;margin-bottom:16px}.section h2{margin:0;font-size:21px}.source{color:var(--muted);font-size:12px;margin-top:4px}.cards,.key-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px;margin:14px 0 22px}.key-grid{grid-template-columns:repeat(3,minmax(0,1fr))}.card{border:1px solid var(--line);border-left:3px solid var(--blue);border-radius:5px;padding:12px 14px;background:#fff;min-height:76px}.card.wide{min-height:110px}.card-value{font-size:14px;margin-top:6px;overflow-wrap:anywhere}.section h3{font-size:15px;margin:24px 0 9px}.table-wrap{overflow:auto;border:1px solid var(--line);border-radius:5px}table{width:100%;border-collapse:collapse;font-size:13px}th{background:#edf4fb;color:#42536a;text-align:left;font-weight:600}th,td{padding:9px 11px;border-bottom:1px solid var(--line);vertical-align:top}tr:last-child td{border-bottom:0}.badge{display:inline-block;padding:2px 8px;border-radius:10px;background:#eef1f4;color:var(--unknown);font-weight:600;font-size:11px}.badge.ok{background:#e2f4e9;color:#207b48}.badge.warning{background:#fff1d9;color:#9c610d}.badge.critical{background:#fde5e5;color:#a92323}.error-card{background:#fff0f0;border-left:4px solid var(--critical);padding:14px;color:#8f2525}.empty{padding:18px;border:1px dashed #bcc7d4;border-radius:5px;color:var(--muted);background:#fafbfd}.findings{margin:0;padding-left:20px}.findings li{margin:6px 0}.footer{text-align:center;color:var(--muted);padding:10px}@media(max-width:800px){.meta,.cards,.key-grid{grid-template-columns:1fr}.hero{padding:24px}.main{padding:18px 12px}}@media print{body{background:#fff}.hero{-webkit-print-color-adjust:exact;print-color-adjust:exact}.section{box-shadow:none;break-inside:avoid}.main{padding:18px 0}}
</style></head><body>
'@)
$html.Add('<header class="hero"><div class="hero-inner"><div class="brand">EXPC WinDiagProbe</div><h1>Diagnostic Report</h1><div class="meta">')
$html.Add('<div class="meta-item"><div class="meta-label">Computer</div><div class="meta-value">'+(ConvertTo-HtmlText $computerLabel)+'</div></div>')
$html.Add('<div class="meta-item"><div class="meta-label">Date</div><div class="meta-value">'+$now.ToString('dd.MM.yy')+'</div></div><div class="meta-item"><div class="meta-label">Time</div><div class="meta-value">'+$now.ToString('HH:mm')+'</div></div>')
$html.Add('<div class="meta-item"><div class="meta-label">Overall state</div><div class="meta-value state '+$overall.ToLowerInvariant()+'">'+$overall+'</div></div></div></div></header><main class="main">')
Add-HardwareReportHtml $html $hardware;Add-WinDiagReportHtml $html $winDiag;Add-ExpcReportHtml $html $expc
$html.Add('<div class="footer">Design by EXPC</div></main></body></html>')
$stream=[IO.File]::Open($outputPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
$writer=New-Object IO.StreamWriter($stream,(New-Object Text.UTF8Encoding($false)))
try{$writer.Write(($html -join [Environment]::NewLine))}finally{$writer.Dispose()}

if(-not $NoOpen){Start-Process -FilePath $outputPath}
Write-Host ('Report viewer: {0}' -f $outputPath) -ForegroundColor Green
if($PassThru){
    [PSCustomObject]@{OutputPath=$outputPath;OverallState=$overall;Hardware=$hardware;WinDiagProbe=$winDiag;EXPC=$expc;Opened=(-not $NoOpen)}
}
