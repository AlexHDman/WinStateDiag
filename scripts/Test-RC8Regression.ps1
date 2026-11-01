# RC8 headless regressions. Executes definitions only; no scans, repairs or GUI.
param([string]$FieldRoot='')
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
function Load-Definitions([string]$Path) {
 $tokens=$null; $errors=$null
 $ast=[Management.Automation.Language.Parser]::ParseFile($Path,[ref]$tokens,[ref]$errors)
 if($errors.Count){throw ($errors|Out-String)}
 foreach($f in $ast.EndBlock.Statements | Where-Object {$_ -is [Management.Automation.Language.FunctionDefinitionAst]}) {
  . ([scriptblock]::Create($f.Extent.Text.Replace(('function '+$f.Name),('function script:'+$f.Name))))
 }
}
function Assert($value,[string]$message) { if(-not $value){throw $message}; Write-Output "PASS $message" }
Load-Definitions (Join-Path $root 'embedded\Hardware-Report\HardwarePassport.psm1')
Load-Definitions (Join-Path $root 'embedded\Hardware-Report\Hardware-Diagnostic.ps1')
$src=@{}
foreach($k in @('System','OperatingSystem','Product','BaseBoard','Bios','Processors','MemoryModules','MemoryArrays','PhysicalDisks','Disks','Reliability','VideoControllers','NetworkAdapters','Batteries','BatteryStatic','BatteryFullCharge','BatteryCycleCount','SignedDrivers','Errors')) {$src[$k]=@()}
$src.System=@([pscustomobject]@{TotalPhysicalMemory=0})
$src.FirmwareType='UEFI'; $src.SecureBootState='Unknown'
$src.Processors=@([pscustomobject]@{Name='Fixture CPU';Manufacturer='Fixture';NumberOfCores=24;NumberOfLogicalProcessors=24;MaxClockSpeed=3700;CurrentClockSpeed=3700;SocketDesignation='U3E1';Architecture=9;L2CacheSize=40960;L3CacheSize=36864})
$p=New-HardwarePassport -Source ([pscustomobject]$src)
Assert ($p.Cpu.MaxClockMHz -eq 3700) 'CPU reported nominal retained'
Assert ($null -eq $p.Cpu.CurrentClockMHz -and $p.Cpu.CurrentClockSource -eq 'NOT_MEASURED') 'CPU current is null without measurement'
Assert ($p.Cpu.WindowsReportedCurrentClockMHz -eq 3700) 'Original SMBIOS current value retained as reported evidence'
$txt=(New-HardwareReportLines -Passport $p) -join "`n"
Assert ($txt -match 'Current clock\s*: Not measured' -and $txt -notmatch 'Current clock\s*: 3700') 'TXT does not call nominal current'
$json=$p | ConvertTo-Json -Depth 15
Assert ($json -match '"CurrentClockMHz":\s*null') 'JSON current is null'
# Test the exact production date expression (and its actual typed CIM contract).
$driverText=Get-Content (Join-Path $root 'embedded\WinStateDiag\DriverAudit.ps1') -Raw -Encoding UTF8
Assert ($driverText.Contains("([datetime]`$d.DriverDate).ToString('yyyy-MM-dd')")) 'A5 date conversion unchanged'
$prior=[Threading.Thread]::CurrentThread.CurrentCulture
try {
 foreach($culture in @('ru-RU','en-US')) {
  [Threading.Thread]::CurrentThread.CurrentCulture=[cultureinfo]$culture
  $d=[pscustomobject]@{DriverDate=[datetime]::new(2026,12,9)}
  Assert (([datetime]$d.DriverDate).ToString('yyyy-MM-dd') -eq '2026-12-09') "CIM typed future date preserved under $culture"
 }
} finally { [Threading.Thread]::CurrentThread.CurrentCulture=$prior }
$dmtf=[Management.ManagementDateTimeConverter]::ToDateTime('20261209000000.000000+000')
Assert ($dmtf.Month -eq 12 -and $dmtf.Day -eq 9) 'DMTF order is yyyyMMdd, not localized'
if($FieldRoot) {
 $a=Get-ChildItem $FieldRoot -Filter 'DriverAudit*.json' | Select-Object -First 1
 $a=Get-Content $a.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
 Assert ($a.devices_scanned -eq 289 -and $a.collection_complete -and $a.coverage_gaps.Count -eq 0) 'RC7 MSI A5 archive has 289 devices and complete coverage'
 $u=$a.items | Where-Object device -eq 'UGREEN Camera Audio'
 Assert ($u.driver_date -eq '2026-12-09' -and $u.status -eq 'OK') 'MSI date is retained independently of PnP health'
}
