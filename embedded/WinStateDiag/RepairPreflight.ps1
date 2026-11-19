# Read-only preflight. No servicing command is launched by this script.
function Get-RepairPreflight {
    param([string]$SourcePath='', [int]$SourceIndex=1, [ValidateSet('SFC','DISM','CHKDSK')][string]$Check='DISM')
    $ErrorActionPreference='Stop'
    $r=[ordered]@{Allowed=$false;Reason='UNKNOWN';Server=$null;Source=$SourcePath;Index=$SourceIndex;CheckedAt=(Get-Date).ToString('o')}
    try {
        $os=Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $r.Server=([int]$os.ProductType -ne 1)
        $r.WindowsVersion=[string]$os.Version
        $cbs=Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending' -ErrorAction Stop
        $wu=Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired' -ErrorAction Stop
        $pendingXml=Test-Path -LiteralPath (Join-Path $env:SystemRoot 'WinSxS\pending.xml') -ErrorAction Stop
        $packages=@(Get-WindowsPackage -Online -ErrorAction Stop | Where-Object {$_.PackageState -match 'Pending'})
        $r.Check=$Check;$r.Evidence=[ordered]@{CBS_RebootPending=$cbs;WU_RebootRequired=$wu;PendingXml=$pendingXml;PendingPackages=$packages.Count}
        $r.RebootRecommended=($cbs -or $wu -or $pendingXml);$r.Action='Не требуется'
        if($packages.Count){$r.Action='Дождаться окончания обслуживания; затем перезагрузить Windows вручную и повторить проверку';throw 'Get-WindowsPackage: обнаружены пакеты с состоянием Pending; запуск отложен.'}
        if($Check -ne 'SFC' -and $wu){$r.Action='Перезагрузить Windows вручную и повторить проверку';throw 'Windows Update RebootRequired: ожидается завершение установки обновлений; DISM/CHKDSK отложен.'}
        # A lone CBS key is advisory; only the native SFC result can confirm that SFC cannot run.
        if($r.RebootRecommended){$r.Action='Рекомендуется предварительная ручная перезагрузка; результат команды будет проверен'}
        if($SourcePath){
            if($SourceIndex -lt 1 -or [IO.Path]::GetExtension($SourcePath) -ine '.wim'){throw 'Выбери локальный install.wim и положительный индекс образа. Автоматическое монтирование ISO не выполняется.'}
            if(!(Test-Path -LiteralPath $SourcePath -PathType Leaf)){throw 'Выбранный источник отсутствует или недоступен.'}
            $image=Get-WindowsImage -ImagePath $SourcePath -Index $SourceIndex -ErrorAction Stop
            $current=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
            $version=[version]$image.Version; $target=[version]$os.Version
            if($version.Major -ne $target.Major -or $version.Minor -ne $target.Minor -or $version.Build -ne $target.Build -or $version.Revision -lt [int]$current.UBR){throw 'Версия/build источника не совпадает с Windows либо источник старее установленного cumulative update.'}
            if([string]$image.EditionId -ine [string]$current.EditionID){throw 'Редакция выбранного WIM не совпадает с установленной Windows.'}
            if([string]$image.Architecture -notin @('9','x64','amd64')){throw 'Нужен подтверждённый x64 образ для текущего x64 приложения.'}
            $languages=@($image.Languages|ForEach-Object {[string]$_})
            foreach($lang in @($os.MUILanguages)){if($lang -notin $languages){throw 'Языковой состав WIM не подтверждён для установленной Windows.'}}
            $r.ImageVersion=[string]$image.Version;$r.ImageEdition=[string]$image.EditionId;$r.ImageLanguages=$languages
        }
        $r.Allowed=$true;$r.Reason='READY'
    } catch {$r.Reason=$_.Exception.Message}
    [pscustomobject]$r
}
