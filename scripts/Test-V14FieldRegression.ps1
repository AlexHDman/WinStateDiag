# Synthetic RAM/SPD/history regression. No hardware access or Windows repair.
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$moduleRoot=Join-Path $root ('target/field-ram-modules/'+[guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory((Join-Path $moduleRoot 'Hardware'))
Copy-Item -LiteralPath (Join-Path $root 'embedded/Hardware-Report/HardwarePassport.psm1') -Destination (Join-Path $moduleRoot 'Hardware/HardwarePassport.psm1')
Copy-Item -LiteralPath (Join-Path $root 'embedded/WinStateDiag/Compatibility.psm1') -Destination (Join-Path $moduleRoot 'Compatibility.psm1')
Import-Module (Join-Path $moduleRoot 'Hardware/HardwarePassport.psm1') -Force
$n=0
function Eq($actual,$expected,$label){if($actual -ne $expected){throw "$label actual=$actual expected=$expected"};$script:n++}
function Passport([int]$rate=2666,[string]$type='DDR4',[string]$cpu='Intel Core i5-14600KF',[string]$board='B760 GAMING X DDR4 GEN5') {
 [pscustomobject]@{GeneratedAt='2026-11-09T12:00:00';Cpu=[pscustomobject]@{Models=@($cpu)};Motherboard=[pscustomobject]@{Manufacturer='Gigabyte';Product=$board};Bios=[pscustomobject]@{Version='SYNTHETIC'};Ram=[pscustomobject]@{Identity='SYNTHETIC-HARDWARE-A';Context=@();Intelligence=$null;Modules=@([pscustomobject]@{ConfiguredSpeedMTs=$rate;Type=$type;Serial='01020304';PartNumber='SYNTHETIC-DIMM';CapacityBytes=8GB},[pscustomobject]@{ConfiguredSpeedMTs=$rate;Type=$type;Serial='05060708';PartNumber='SYNTHETIC-DIMM';CapacityBytes=8GB})}}
}
function Spd([int]$serial=1,[int]$period=556) {
 $b=New-Object byte[] 512;$b[2]=12;$b[18]=6
 $b[325]=$serial;$b[326]=$serial+1;$b[327]=$serial+2;$b[328]=$serial+3
 [Text.Encoding]::ASCII.GetBytes('SYNTHETIC-DIMM').CopyTo($b,329)
 $b[384]=12;$b[385]=74;$b[386]=1;$b[387]=32;$b[396]=[math]::Floor($period/125);$b[431]=$period%125
 $crc=0;foreach($v in $b[0..125]){$crc=$crc -bxor ([int]$v -shl 8);for($i=0;$i -lt 8;$i++){if($crc -band 32768){$crc=(($crc -shl 1) -bxor 0x1021) -band 65535}else{$crc=($crc -shl 1) -band 65535}}};$b[126]=$crc -band 255;$b[127]=$crc -shr 8
 return ,$b
}
$a=Read-HardwareSpd (Spd);$b=Read-HardwareSpd (Spd 5)
Eq $a.JedecMTs 2666 'JEDEC timing'
Eq $a.Profiles[0] 3600 'XMP timing'
Eq $a.Serial '01020304' 'serial binding'
$bad=Spd;$bad[18]=7;$rejected=$false;try{Read-HardwareSpd $bad}catch{$rejected=$true};Eq $rejected $true 'base CRC fails closed'
$bad=Spd;$bad[2]=18;$rejected=$false;try{Read-HardwareSpd $bad}catch{$rejected=$true};Eq $rejected $true 'DDR5 not decoded as DDR4'
$p=Passport
$r=Get-HardwareRamIntelligence $p
Eq $r.Color ORANGE '2666 target platform hint without SPD'
Eq $r.ProfileMTs $null 'no invented XMP'
Eq $r.XmpActive UNKNOWN 'no invented active XMP'
Eq $r.SpdAvailability UNAVAILABLE 'SPD absent'
$r=Get-HardwareRamIntelligence $p @($a,$b)
Eq $r.ProfileMTs 3600 'two bound DIMMs'
Eq $r.Color ORANGE 'below confirmed profile'
Eq (Get-HardwareRamIntelligence $p @($a)).ProfileMTs $null 'partial SPD not whole kit profile'
$p=Passport 3600;$r=Get-HardwareRamIntelligence $p @($a,$b)
Eq $r.Color ORANGE 'above CPU official is caution'
Eq $r.Stability NOT_TESTED 'no stress claim'
$p=Passport 3200;$c=Read-HardwareSpd (Spd 1 625);$d=Read-HardwareSpd (Spd 5 625)
Eq (Get-HardwareRamIntelligence $p @($c,$d)).Color GREEN '3200 profile matches'
$p=Passport 3600 'DDR4' 'AMD Ryzen 5 5600' 'OTHER BOARD'
Eq (Get-HardwareRamIntelligence $p @($a,$b)).Color GRAY 'known DIMM profile on unlisted CPU'
Eq (Get-HardwareRamIntelligence $p @($a,$b)).CpuOfficialMTs $null 'AMD limit not guessed'
foreach($cpu in @('AMD Ryzen 7 7800X3D','Intel Core i5-10400','Intel Core i7-14700')) {
 foreach($type in @('DDR4','DDR5')) {$r=Get-HardwareRamIntelligence (Passport 2666 $type $cpu 'OTHER');Eq $r.Color GRAY 'unlisted profile unknown';Eq $r.ProfileMTs $null 'DDR5 XMP EXPO not invented'}
}
$p=Passport 4000;$r=Get-HardwareRamIntelligence $p @($a,$b);Eq $r.Color ORANGE 'higher than profile'
$p=Passport 3200;$p.Ram.Modules[1].PartNumber='DIFFERENT';$r=Get-HardwareRamIntelligence $p @($c,$d);Eq $r.ProfileMTs $null 'mismatched kit cannot bind';Eq ($r.Notes -join ' ' -like '*DIMM*') $true 'mixed DIMM note'
$p=Passport 3600;$old=[pscustomobject]@{Identity=$p.Ram.Identity;GeneratedAt='2026-11-09T11:00:00';CurrentMTs=2666}
$r=Get-HardwareRamIntelligence $p @() $old;Eq $r.PreviousMTs 2666 'same machine history';Eq $r.TransferRateChangePercent 35.0 'rate increase';Eq $r.PerformanceChange NOT_MEASURED 'not performance improvement'
$old.Identity='OTHER';Eq (Get-HardwareRamIntelligence $p @() $old).PreviousMTs $null 'other machine excluded'
$old.Identity=$p.Ram.Identity;$old.GeneratedAt='2026-11-10T12:00:00';Eq (Get-HardwareRamIntelligence $p @() $old).PreviousMTs $null 'future history excluded'
$dir=Join-Path $root ('target/field-ram-tests/'+[guid]::NewGuid().ToString('N'))
$p=Passport 2666;$p.GeneratedAt='2026-11-08T12:00:00';Update-HardwareRamHistory $p $dir;Eq $p.Ram.Intelligence.HistoryStatus SAVED 'history saved'
$p=Passport 3600;Update-HardwareRamHistory $p $dir;Eq $p.Ram.Intelligence.PreviousMTs 2666 'history survives fresh object'
$p=Passport 2666;$p.Ram.Identity='OTHER-BIOS-CPU-DIMM';Update-HardwareRamHistory $p $dir;Eq $p.Ram.Intelligence.PreviousMTs $null 'identity change excludes history'
[void][IO.Directory]::CreateDirectory((Join-Path $dir 'SPD'));[IO.File]::WriteAllBytes((Join-Path $dir 'SPD/a.bin'),(Spd));[IO.File]::WriteAllBytes((Join-Path $dir 'SPD/b.bin'),(Spd 5))
$p=Passport 2666;Update-HardwareRamHistory $p $dir;Eq $p.Ram.Intelligence.ProfileMTs 3600 'actual file import end to end';Eq $p.Ram.Intelligence.SpdAvailability IMPORTED 'source explicit'
$p=Passport 2666;$p.Ram.Identity='';Update-HardwareRamHistory $p $dir;Eq $p.Ram.Intelligence.HistoryStatus IDENTITY_UNKNOWN 'unknown identity does not contaminate history'
Write-Output "PASS RAM/SPD/history: $n assertions; LIVE Windows EEPROM/HVCI NOT TESTED"

if($env:WSD_FIELD_ZIP){
 Add-Type -AssemblyName System.IO.Compression.FileSystem
 $zip=[IO.Compression.ZipFile]::OpenRead($env:WSD_FIELD_ZIP)
 try {
  $entry=@($zip.Entries|Where-Object {$_.Name -like 'Hardware_*.json' -and $_.Name -notlike '*Sensors*'})[0]
  $reader=[IO.StreamReader]::new($entry.Open());try{$passport=$reader.ReadToEnd()|ConvertFrom-Json}finally{$reader.Dispose()}
  $r=Get-HardwareRamIntelligence $passport
  Eq $r.CurrentMTs 3600 'private replay configured rate'
  Eq $r.CpuOfficialMTs 3200 'private replay exact CPU'
  Eq $r.BoardOfficialMTs 3200 'private replay exact board'
  Eq $r.Color ORANGE 'private replay over CPU limit'
  Eq $r.ProfileMTs $null 'private replay WMI is not XMP'
  Write-Output "PASS private field replay: 5 assertions; original ZIP read-only"
 } finally {$zip.Dispose()}
}
