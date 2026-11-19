# Explicit UI-confirmed quota increase only. Functions have no startup side effects.
function Get-VssControlFacts {
    $ErrorActionPreference='Stop'
    $volumes=@(Get-CimInstance Win32_Volume -ErrorAction Stop)
    $copies=@(Get-CimInstance Win32_ShadowCopy -ErrorAction Stop)
    $stores=@(Get-CimInstance Win32_ShadowStorage -ErrorAction Stop)
    $rows=@()
    foreach($s in $stores){
        $source=$volumes|Where-Object {$_.DeviceID -eq $s.Volume.DeviceID}|Select-Object -First 1
        $dest=$volumes|Where-Object {$_.DeviceID -eq $s.DiffVolume.DeviceID}|Select-Object -First 1
        $shadows=@($copies|Where-Object {$_.VolumeName -eq $source.DeviceID})
        $rows+=[pscustomobject]@{For=[string]$source.DriveLetter;On=[string]$dest.DriveLetter;Maximum=[string]$s.MaxSpace;Used=[string]$s.UsedSpace;Allocated=[string]$s.AllocatedSpace;Free=[string]$dest.FreeSpace;Capacity=[string]$dest.Capacity;Copies=$shadows.Count;CopyIds=@($shadows|ForEach-Object {[string]$_.ID});Oldest=@($shadows|Sort-Object InstallDate|Select-Object -First 1|ForEach-Object {[string]$_.InstallDate})}
    }
    $backup=@();$backupError=$null
    try{$backup=@(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Backup';StartTime=(Get-Date).AddDays(-7)} -MaxEvents 100 -ErrorAction Stop | ForEach-Object {[pscustomobject]@{Time=$_.TimeCreated.ToString('o');Id=$_.Id;Message=$_.Message}})}catch{$backupError=$_.Exception.Message}
    [pscustomobject]@{Status='AVAILABLE';Rows=$rows;CapturedAt=(Get-Date).ToString('o');SnapshotCreation='NOT_TESTED';BackupSuccess='UNKNOWN';BackupEvents=$backup;BackupQueryError=$backupError;BackupWindowDays=7;BackupPossiblyTruncated=($backup.Count -ge 100);Correlation='Compare backup and VSS timestamps; temporal proximity alone is not causation'}
}
function Invoke-VssResizeNative {
    param([string]$For,[string]$On,[uint64]$ProposedBytes)
    $output=(& (Join-Path $env:SystemRoot 'System32\vssadmin.exe') resize shadowstorage "/For=$For" "/On=$On" "/MaxSize=$ProposedBytes" 2>&1|Out-String)
    [pscustomobject]@{ExitCode=$LASTEXITCODE;Output=$output}
}
function Invoke-VssQuotaIncrease {
    param([string]$For,[string]$On,[uint64]$ExpectedMaximum,[uint64]$ProposedBytes,[bool]$Confirmed=$false)
    $ErrorActionPreference='Stop'
    if(!$Confirmed){throw 'Изменение не подтверждено'}
    if($For -notmatch '^[A-Z]:$' -or $On -notmatch '^[A-Z]:$'){throw 'Нужны локальные тома с буквами дисков'}
    $before=Get-VssControlFacts
    $row=@($before.Rows|Where-Object {$_.For -eq $For -and $_.On -eq $On})
    if($row.Count -ne 1){throw 'Ассоциация VSS не подтверждена однозначно'}
    if([uint64]$row[0].Maximum -ne $ExpectedMaximum){throw 'Квота изменилась; повтори анализ и подтверждение'}
    if($ProposedBytes -le $ExpectedMaximum -or $ProposedBytes -ge [uint64]::MaxValue){throw 'Разрешено только конечное увеличение квоты'}
    $growth=$ProposedBytes-$ExpectedMaximum
    if([uint64]$row[0].Free -lt $growth+2GB){throw 'Недостаточно свободного места с резервом 2 ГБ'}
    $command="vssadmin resize shadowstorage /For=$For /On=$On /MaxSize=$ProposedBytes"
    $started=(Get-Date).ToString('o')
    $native=Invoke-VssResizeNative -For $For -On $On -ProposedBytes $ProposedBytes
    $output=$native.Output;$exit=$native.ExitCode
    $afterError=$null
    try{$after=Get-VssControlFacts}catch{$afterError=$_.Exception.Message;$after=[pscustomobject]@{Rows=@();Status='UNKNOWN';Error=$afterError}}
    $new=@($after.Rows|Where-Object {$_.For -eq $For -and $_.On -eq $On})
    $lost=@($row[0].CopyIds|Where-Object {$_ -notin @($new|ForEach-Object {$_.CopyIds})})
    $verified=$exit -eq 0 -and $new.Count -eq 1 -and [uint64]$new[0].Maximum -ge $ProposedBytes -and $lost.Count -eq 0
    [pscustomobject]@{Status=$(if($verified){'SUCCESS_VERIFIED'}elseif($exit -ne 0){'FAILED'}else{'COMPLETED_UNVERIFIED'});Command=$command;StartedAt=$started;EndedAt=(Get-Date).ToString('o');ExitCode=$exit;Output=$output;VerificationError=$afterError;Before=$before;After=$after;MissingCopyIds=$lost;Rollback='Автоматический откат снижением квоты запрещён: он может удалить снимки';BackupSuccess='UNKNOWN'}
}
