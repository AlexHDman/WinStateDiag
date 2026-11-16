# Only the compiled operation allowlist is executable. Inventory reads registration without invoking the Installer provider.
$ErrorActionPreference='Stop'
function Initialize-ThumbnailCleaner {
 if(!('WinDiagThumbnailCleanup' -as [type])){Add-Type -TypeDefinition ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('__THUMBNAIL_B64__'))) -ErrorAction Stop}
}
function Thumbnail-Root {Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Microsoft\Windows\Explorer'}
function Inspect-Installer([string]$Path) {
 if(![IO.Path]::IsPathRooted($Path) -or [IO.Path]::GetExtension($Path) -ne '.msi' -or $Path.Contains('"')){throw 'Нужен полный путь к MSI-пакету'}
 $signature=Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
 if($signature.Status -ne 'Valid'){throw 'Подпись MSI недействительна или отсутствует; запуск запрещён'}
 $hash=(Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash
 $installer=New-Object -ComObject WindowsInstaller.Installer
 $db=$null
 try {
  $db=$installer.OpenDatabase($Path,0)
  $result=@{Path=$Path;Hash=$hash;SignaturePublisher=$signature.SignerCertificate.Subject}
  foreach($property in @('ProductName','Manufacturer','ProductVersion','ProductCode')){
   $view=$null;$record=$null
   try {
    $bt=[char]96;$quote=[char]39
    $query='SELECT '+$bt+'Value'+$bt+' FROM '+$bt+'Property'+$bt+' WHERE '+$bt+'Property'+$bt+' = '+$quote+$property+$quote
    $view=$db.OpenView($query);$view.Execute();$record=$view.Fetch()
    $result[$property]=if($record){$record.StringData(1)}else{''}
   }finally{if($record){[void][Runtime.InteropServices.Marshal]::ReleaseComObject($record)};if($view){$view.Close();[void][Runtime.InteropServices.Marshal]::ReleaseComObject($view)}}
  }
  [pscustomobject]@{Path=$Path;Hash=$hash;ProductCode=$result.ProductCode;Name=$result.ProductName;Publisher=$result.Manufacturer;Version=$result.ProductVersion;SignaturePublisher=$result.SignaturePublisher}
 }finally{if($db){[void][Runtime.InteropServices.Marshal]::ReleaseComObject($db)};[void][Runtime.InteropServices.Marshal]::ReleaseComObject($installer)}
}
function Inventory-Programs {
 $list=New-Object Collections.Generic.List[object]
 foreach($context in @(@('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','Machine64'),@('HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall','Machine32'),@('HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','CurrentUser'))) {
  if(!(Test-Path -LiteralPath $context[0])){continue}
  foreach($key in Get-ChildItem -LiteralPath $context[0] -ErrorAction Stop){
   $v=Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction Stop
   if(!$v.DisplayName){continue}
   $guid=if($key.PSChildName -match '^\{[A-Fa-f0-9-]{36}\}$' -and $v.WindowsInstaller -eq 1){$key.PSChildName}else{''}
   $list.Add([pscustomobject]@{Name=[string]$v.DisplayName;Publisher=[string]$v.Publisher;Version=[string]$v.DisplayVersion;Context=$context[1];ProductCode=$guid;Key=$key.PSPath})
  }
 }
 @($list.ToArray())
}
function Test-RepairAdministrator { ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
function Assert-ServicingIdle {
 if(Get-Process -Name msiexec,TiWorker,dism,sfc,MoUsoCoreWorker -ErrorAction SilentlyContinue){throw 'Установщик или обслуживание Windows уже выполняется'}
 foreach($p in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')){if(Test-Path -LiteralPath $p){throw 'Windows ожидает перезагрузку: сначала заверши её вручную'}}
}
function Decode-NativeBytes([byte[]]$Bytes){
 if($Bytes.Length -ge 2 -and $Bytes[0] -eq 255 -and $Bytes[1] -eq 254){return [Text.Encoding]::Unicode.GetString($Bytes).TrimStart([char]0xFEFF)}
 if($Bytes.Length -ge 2 -and $Bytes[0] -eq 254 -and $Bytes[1] -eq 255){return [Text.Encoding]::BigEndianUnicode.GetString($Bytes).TrimStart([char]0xFEFF)}
 $sample=[Math]::Min($Bytes.Length,512);$odd=0
 for($i=1;$i -lt $sample;$i+=2){if($Bytes[$i] -le 4){$odd++}}
 if($sample -gt 16 -and $odd -gt $sample/4){return [Text.Encoding]::Unicode.GetString($Bytes)}
 try{$utf8=New-Object Text.UTF8Encoding($false,$true);return $utf8.GetString($Bytes).TrimStart([char]0xFEFF)}catch{return [Text.Encoding]::GetEncoding((Get-Culture).TextInfo.OEMCodePage).GetString($Bytes)}
}
function Native([string]$Name,[string[]]$Arguments){
 $p=New-Object Diagnostics.Process
 $p.StartInfo.FileName=Join-Path ([Environment]::GetFolderPath('System')) $Name
 $p.StartInfo.Arguments=$Arguments -join ' '
 $p.StartInfo.UseShellExecute=$false;$p.StartInfo.CreateNoWindow=$true
 $p.StartInfo.RedirectStandardOutput=$true;$p.StartInfo.RedirectStandardError=$true;$p.StartInfo.RedirectStandardInput=$true
 $stage=[IO.Path]::GetFileNameWithoutExtension($Name)+'-'+[guid]::NewGuid().ToString('N')
 $outPath=Join-Path $Evidence ($stage+'-stdout.log');$errPath=Join-Path $Evidence ($stage+'-stderr.log')
 $outFile=[IO.File]::Open($outPath,'CreateNew','Write','Read');$errFile=$null
 try {
  $errFile=[IO.File]::Open($errPath,'CreateNew','Write','Read')
  if(!$p.Start()){throw 'Процесс не запущен'}
  $p.StandardInput.Close()
  $outTask=$p.StandardOutput.BaseStream.CopyToAsync($outFile);$errTask=$p.StandardError.BaseStream.CopyToAsync($errFile)
  $p.WaitForExit();[Threading.Tasks.Task]::WaitAll(@($outTask,$errTask))
  $outFile.Flush($true);$errFile.Flush($true);$code=$p.ExitCode
 } finally {$outFile.Dispose();if($errFile){$errFile.Dispose()};$p.Dispose()}
 # Raw streams are durable evidence. The UI/JSON receives a bounded readable excerpt.
 $text=''
 foreach($file in @($outPath,$errPath)){
  $stream=[IO.File]::Open($file,'Open','Read','ReadWrite')
  try {
   $length=[int][Math]::Min(1048576,$stream.Length);$bytes=New-Object byte[] $length
   if($stream.Length -le 1048576){[void]$stream.Read($bytes,0,$length)}else{
    [void]$stream.Read($bytes,0,524288);[void]$stream.Seek(-524288,'End');[void]$stream.Read($bytes,524288,524288)
   }
   $text+=(Decode-NativeBytes $bytes)+"`n"
  }finally{$stream.Dispose()}
 }

 [pscustomobject]@{ExitCode=$code;Output=$text;RebootRequired=($code -in @(3010,1641))}
}
try {
 if($Operation -notin @('Analyze','AnalyzeInstaller','MsiInstall','UpdateCache','CheckVolume','RepairVolume','MsiRepair','MsiRemove','ComponentAnalysis','ComponentCleanup','ThumbnailCleanup')){throw 'Неизвестная операция'}
 $mutating=$Operation -in @('MsiInstall','UpdateCache','RepairVolume','MsiRepair','MsiRemove','ComponentCleanup','ThumbnailCleanup')
 $lease=New-Object Threading.Mutex($false,'Global\EXPC.WinStateDiag.Servicing')
 if(!$lease.WaitOne(0)){throw 'Другой исполнитель Repair уже работает'}
 try {
  if($mutating){
   if(!(Test-RepairAdministrator)){throw 'Нужен запуск WinDiag с правами администратора через штатный UAC'}
   Assert-ServicingIdle
  }
  $expected=if($ExpectedJSON){$ExpectedJSON|ConvertFrom-Json}else{$null}
  $result=$null
  switch($Operation){
   'AnalyzeInstaller' {
    Initialize-ThumbnailCleaner;$held=[WinDiagThumbnailCleanup]::HoldPackage($Target)
    try{$file=Inspect-Installer $Target;$result=@{Status='INSTALLER_ANALYZED';Installer=$file;Notice='MSI открыт только для чтения. Установка не запускалась.'}}finally{$held.Dispose()}
   }
   'MsiInstall' {
    if(!$expected.Hash){throw 'Нет подтверждённого отпечатка пакета'}
    Initialize-ThumbnailCleaner;$held=[WinDiagThumbnailCleanup]::HoldPackage($Target)
    try {
     $file=Inspect-Installer $Target
     foreach($key in @('Hash','ProductCode','Name','Publisher','Version')){if([string]$file.$key -ne [string]$expected.$key){throw 'MSI-пакет изменился после анализа'}}
     $file | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $Evidence 'selected-installer.json') -Encoding UTF8
     $log=Join-Path $Evidence 'msi.log'
     $r=Native 'msiexec.exe' @('/i',('"'+$Target+'"'),'/qn','/norestart','/L*v',('"'+$log+'"'))
     $after=@(Inventory-Programs | Where-Object {$_.ProductCode -eq $file.ProductCode})
     $result=@{Status=if($r.ExitCode -eq 3010){'REBOOT_REQUIRED'}elseif($r.ExitCode -ne 0){'FAILED'}else{'COMPLETED_UNVERIFIED'};Installer=$file;Execution=$r;After=$after;Notice='Регистрация после установки сохранена. Работоспособность программы требует отдельной проверки.'}
    } finally {$held.Dispose()}
   }
   'Analyze' {
    $errors=New-Object Collections.Generic.List[string]
    $programs=@();$volumes=@();$updates=@();$services=@();$cleanup=@()
    try{$programs=@(Inventory-Programs)}catch{$errors.Add('Программы: '+$_.Exception.Message)}
    try{$volumes=@(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction Stop | ForEach-Object {[pscustomobject]@{Drive=$_.DeviceID;FileSystem=$_.FileSystem;Size=[string]$_.Size;Free=[string]$_.FreeSpace;Label=$_.VolumeName;VolumeSerialNumber=[string]$_.VolumeSerialNumber}})}catch{$errors.Add('Тома: '+$_.Exception.Message)}
    try{$updates=@(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WindowsUpdateClient/Operational';Level=2;StartTime=(Get-Date).AddDays(-30)} -MaxEvents 50 -ErrorAction Stop | Select-Object TimeCreated,Id,Message)}catch{if($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*'){$errors.Add('Windows Update: '+$_.Exception.Message)}}
    try{$services=@(Get-Service -Name wuauserv,bits,cryptsvc,msiserver -ErrorAction Stop | Select-Object Name,@{n='State';e={$_.Status.ToString()}})}catch{$errors.Add('Службы: '+$_.Exception.Message)}
    foreach($category in @(@('Временные файлы пользователя',$env:TEMP,'SAFE'),@('Временные файлы Windows',(Join-Path $env:windir 'Temp'),'ADVANCED'),@('WER',(Join-Path $env:ProgramData 'Microsoft\Windows\WER'),'ADVANCED'),@('Windows.old',(Join-Path $env:SystemDrive 'Windows.old'),'EXPERT'),@('Кэш приложений Direct3D',(Join-Path $env:LOCALAPPDATA 'D3DSCache'),'SAFE'),@('Кэш браузера Chrome (Default)',(Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data\Default\Cache\Cache_Data'),'ADVANCED'),@('Кэш браузера Edge (Default)',(Join-Path $env:LOCALAPPDATA 'Microsoft\Edge\User Data\Default\Cache\Cache_Data'),'ADVANCED'),@('Кэш разработчика pip',(Join-Path $env:LOCALAPPDATA 'pip\Cache'),'ADVANCED'),@('Кэш разработчика npm',(Join-Path $env:LOCALAPPDATA 'npm-cache\_cacache'),'ADVANCED'),@('Дампы Windows',(Join-Path $env:windir 'Minidump'),'EXPERT'),@('Корзина текущего пользователя',(Join-Path $env:SystemDrive ('$Recycle.Bin\'+[Security.Principal.WindowsIdentity]::GetCurrent().User.Value)),'ADVANCED'))){
     $bytes=[long]0;$count=0;$skipped=0;$root=$category[1];$seen=0;$present=$false
     if(Test-Path -LiteralPath $root){
      $present=$true
      $pending=New-Object Collections.Generic.Queue[string];$pending.Enqueue($root)
      while($pending.Count -and $seen -lt 10000){
       $folder=$pending.Dequeue();$seen++
       try{
        $a=Get-Item -LiteralPath $folder -Force -ErrorAction Stop
        if($a.Attributes -band [IO.FileAttributes]::ReparsePoint){$skipped++;continue}
        foreach($f in Get-ChildItem -LiteralPath $folder -Force -ErrorAction Stop){
         $seen++;if($seen -gt 10000){$skipped++;break}
         if($f.Attributes -band [IO.FileAttributes]::ReparsePoint){$skipped++;continue}
         if($f.PSIsContainer){$pending.Enqueue($f.FullName)}else{$bytes+=$f.Length;$count++}
        }
       }catch{$skipped++}
      }
      if($pending.Count){$skipped+=$pending.Count}
     }
     $cleanup+= [pscustomobject]@{Category=$category[0];Root=$root;Risk=$category[2];Status=if(!$present){'NOT_PRESENT'}elseif($skipped){'PARTIAL'}else{'ANALYZED'};Bytes=if(!$present){''}else{[string]$bytes};Objects=$count;Skipped=$skipped;DeletionSupported=$false;Reason='Анализ не разрешает удаление. Для этой категории требуется проверенный пообъектный план; пользовательские документы и текущие доказательства защищены.'}
    }
    $cacheFiles=@();$cacheSkipped=0
    try {
     Initialize-ThumbnailCleaner;$thumbRoot=Thumbnail-Root
     if(Test-Path -LiteralPath $thumbRoot){foreach($file in @(Get-ChildItem -LiteralPath $thumbRoot -Filter 'thumbcache_*.db' -File -ErrorAction Stop | Select-Object -First 128)){
      try{$cacheFiles+=[WinDiagThumbnailCleanup]::Inspect($thumbRoot,$file.FullName,'','',$false)}catch{$cacheSkipped++}
     }}
    }catch{$errors.Add('Эскизы: '+$_.Exception.Message)}
    $result=@{CacheFiles=$cacheFiles;CacheSkipped=$cacheSkipped;Status=if($errors.Count -or $cacheSkipped -gt 0 -or @($cleanup|Where-Object {$_.Skipped -gt 0}).Count){'PARTIAL'}else{'ANALYZED'};Programs=$programs;Volumes=$volumes;UpdateErrors=$updates;Services=$services;Cleanup=$cleanup;Errors=@($errors.ToArray());Computer=$env:COMPUTERNAME;CollectedAt=(Get-Date).ToString('o')}
   }
   {$_ -in @('CheckVolume','RepairVolume')} {
    if($Target -notmatch '^[A-Z]:$'){throw 'Некорректный том'}
    $v=Get-CimInstance Win32_LogicalDisk -Filter ("DeviceID='"+$Target+"'") -ErrorAction Stop
    if(!$v -or $v.DriveType -ne 3 -or $v.FileSystem -ne 'NTFS'){throw 'Нужен доступный локальный NTFS-том'}
    if($expected -and $expected.VolumeSerialNumber -and [string]$expected.VolumeSerialNumber -ne [string]$v.VolumeSerialNumber){throw 'Том заменён после анализа; план устарел'}
    $args=@($Target);if($Operation -eq 'RepairVolume'){$args+= '/spotfix'}
    $r=Native 'chkdsk.exe' $args
    $verify=if($Operation -eq 'RepairVolume' -and $r.ExitCode -in @(0,1)){Native 'chkdsk.exe' @($Target)}else{$null}
    $result=@{Status=if($r.ExitCode -notin @(0,1)){'FAILED'}elseif($Operation -eq 'CheckVolume'){'CHECK_COMPLETED'}else{'COMPLETED_UNVERIFIED'};Before=$v | Select-Object DeviceID,VolumeSerialNumber,FileSystem;Repair=$r;Verification=$verify;Notice='Результат и коды требуют оценки вывода. Автоматического согласия на перезагрузку/отключение тома нет.'}
   }
   {$_ -in @('MsiRepair','MsiRemove')} {
    if($Target -notmatch '^\{[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}\}$'){throw 'Некорректный ProductCode'}
    $matches=@(Inventory-Programs | Where-Object {$_.ProductCode -eq $Target})
    if($matches.Count -ne 1){throw 'Продукт не определён однозначно; нужен новый анализ'}
    $before=$matches[0]
    if($expected){foreach($field in @('Name','Version','Publisher','Context')){if([string]$expected.$field -ne [string]$before.$field){throw 'Продукт изменился после анализа; план устарел'}}}
    $before | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $Evidence 'before-product.json') -Encoding UTF8
    $flag=if($Operation -eq 'MsiRemove'){'/x'}else{'/fomus'}
    $log=Join-Path $Evidence 'msi.log'
    $r=Native 'msiexec.exe' @($flag,$Target,'/qn','/norestart','/L*v',('"'+$log+'"'))
    $after=@(Inventory-Programs | Where-Object {$_.ProductCode -eq $Target})
    $status=if($r.ExitCode -eq 3010){'REBOOT_REQUIRED'}elseif($r.ExitCode -ne 0){'FAILED'}elseif($Operation -eq 'MsiRemove' -and $after.Count -eq 0){'REMOVAL_VERIFIED'}else{'COMPLETED_UNVERIFIED'}
    $result=@{Status=$status;Before=$before;After=$after;Execution=$r;Notice='Регистрация продукта не доказывает исправность его файлов. Intel определяется выбранным ProductCode; DriverStore не затрагивается.'}
   }
   'ThumbnailCleanup' {
    Initialize-ThumbnailCleaner;$thumbRoot=Thumbnail-Root
    $selected=@($expected)
    if(!$selected.Count -or $selected.Count -gt 128){throw 'Недопустимое количество объектов'}
    $selected | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $Evidence 'selected-files.json') -Encoding UTF8
    $drive=New-Object IO.DriveInfo([IO.Path]::GetPathRoot($thumbRoot));$freeBefore=$drive.AvailableFreeSpace
    $deleted=[long]0;$done=0;$skipped=New-Object Collections.Generic.List[string]
    foreach($file in $selected){try{
      $item=[WinDiagThumbnailCleanup]::Inspect($thumbRoot,[string]$file.Path,[string]$file.Hash,[string]$file.Identity,$true)
      if($item.Deleted){$deleted+=$item.Bytes;$done++}
     }catch{$skipped.Add([string]$file.Path+': '+$_.Exception.Message)}}
    $freeAfter=(New-Object IO.DriveInfo([IO.Path]::GetPathRoot($thumbRoot))).AvailableFreeSpace
    $result=@{Status=if($skipped.Count){'PARTIAL'}else{'CLEANUP_COMPLETED'};Selected=$selected.Count;Deleted=$done;ProcessedBytes=[string]$deleted;FreeSpaceDelta=[string]($freeAfter-$freeBefore);Skipped=@($skipped.ToArray());Notice='Обработанные размеры и изменение свободного места независимы; параллельные записи Windows влияют на свободное место.'}
   }
   'UpdateCache' {
    $events=@(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WindowsUpdateClient/Operational';Level=2;StartTime=(Get-Date).AddDays(-30)} -MaxEvents 50 -ErrorAction Stop)
    if(!$events.Count){throw 'Нет доступных диагностических доказательств ошибок Windows Update'}
    $events | Select-Object TimeCreated,Id,Message | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $Evidence 'before-update-errors.json') -Encoding UTF8
    $states=@(Get-Service wuauserv,bits -ErrorAction Stop | Select-Object Name,Status)
    if($states | Where-Object {$_.Status -notin @('Running','Stopped')}){throw 'Служба в переходном состоянии'}
    $path=Join-Path $env:windir 'SoftwareDistribution\Download';$old=$path+'.WinDiag-'+[guid]::NewGuid().ToString('N')
    $restore=New-Object Collections.Generic.List[string]
    try {
     foreach($s in $states | Where-Object {$_.Status -eq 'Running'}){Stop-Service -Name $s.Name -ErrorAction Stop;(Get-Service $s.Name).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30))}
     foreach($part in @($env:windir,(Split-Path $path),$path)){
      $i=Get-Item -LiteralPath $part -Force -ErrorAction Stop
      if($i.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Подмена пути: reparse point; операция запрещена'}
     }
     Move-Item -LiteralPath $path -Destination $old -ErrorAction Stop
    } finally {
     foreach($s in $states | Where-Object {$_.Status -eq 'Running'}){try{Start-Service $s.Name -ErrorAction Stop;(Get-Service $s.Name).WaitForStatus('Running',[TimeSpan]::FromSeconds(30))}catch{$restore.Add($s.Name+': '+$_.Exception.Message)}}
    }
    $result=@{Status=if($restore.Count){'PARTIAL'}else{'COMPLETED_UNVERIFIED'};PreservedCache=$old;BeforeServices=$states;AfterServices=@(Get-Service wuauserv,bits | Select-Object Name,@{n='State';e={$_.Status.ToString()}});RestoreErrors=@($restore.ToArray());Notice='Старый кэш сохранён. Успешность следующего обновления требует отдельной проверки; политики/ACL не сбрасывались.'}
   }
   {$_ -in @('ComponentAnalysis','ComponentCleanup')} {
    $arg=if($Operation -eq 'ComponentAnalysis'){'/AnalyzeComponentStore'}else{'/StartComponentCleanup'}
    $r=Native 'dism.exe' @('/Online','/Cleanup-Image',$arg)
    $verify=if($Operation -eq 'ComponentCleanup' -and $r.ExitCode -eq 0){Native 'dism.exe' @('/Online','/Cleanup-Image','/AnalyzeComponentStore')}else{$null}
    $result=@{Status=if($r.RebootRequired){'REBOOT_REQUIRED'}elseif($r.ExitCode -eq 0){'COMPLETED_UNVERIFIED'}else{'FAILED'};Execution=$r;Verification=$verify}
   }
  }
  'WSD_REPAIR_CENTER '+($result | ConvertTo-Json -Depth 10 -Compress)
 }finally{try{$lease.ReleaseMutex()}catch{};$lease.Dispose()}
}catch{
 'WSD_REPAIR_CENTER '+(@{Status='FAILED';Error=$_.Exception.Message}|ConvertTo-Json -Compress)
}
