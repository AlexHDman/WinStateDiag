# Functions only: the caller invokes Install after an explicit user click.
function Test-WsdInstaller([string]$Path, $Expected) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw 'Offline PawnIO installer is missing from the package' }
    $hash=(Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash
    if ($hash -ne $Expected.sha256) { throw 'PawnIO SHA256 does not match the pinned official release; execution refused' }
    $signature=Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -ne $Expected.thumbprint -or $signature.SignerCertificate.Subject -ne $Expected.publisher) { throw ('PawnIO Authenticode verification failed: '+$signature.Status+'; '+$signature.StatusMessage) }
    return [ordered]@{sha256=$hash;signature=[string]$signature.Status;publisher=$signature.SignerCertificate.Subject;thumbprint=$signature.SignerCertificate.Thumbprint;path=$Path}
}
function Resolve-WsdInstallExit([int]$Code) {
    switch ($Code) { 0 {'INSTALLED'} 3010 {'REBOOT_REQUIRED'} 1223 {'CANCELLED'} default {'INSTALLER_ERROR'} }
}
function Invoke-WsdPawnInstall([string]$Installer, [string]$LogDirectory, $Manifest) {
    $ErrorActionPreference='Stop'
    [IO.Directory]::CreateDirectory($LogDirectory) | Out-Null
    $record=[ordered]@{operation='PawnIO explicit install';started=(Get-Date).ToUniversalTime().ToString('o');state='INITIALIZATION_ERROR';exit_code=$null;reboot_required=$false;verification=$null;before=$null;after=$null;error=$null;installer_stdout='The official elevated installer does not expose redirected output; exit and driver verification are recorded.'}
    $mutex=$null; $owned=$false; $lock=$null
    function Stage([string]$Name) { 'WSD_HW_PROGRESS '+(@{stage=$Name}|ConvertTo-Json -Compress) }
    try {
        Stage 'Checking'
        $mutex=[Threading.Mutex]::new($false,'Global\EXPC.HardwareMonitor.Reader')
        try {$owned=$mutex.WaitOne(0)} catch [Threading.AbandonedMutexException] { $owned=$true;Save-WsdHardwareAbort (Get-WsdPawnIo) 'Abandoned reader before install'; throw 'Previous hardware reader exited without releasing ownership; restart verification is required' }
        if (-not $owned) { throw 'Another hardware read or installation is still active; no second operation started' }
        $record.before=Get-WsdPawnIo
        if ($record.before.state -eq 'ACCESSIBLE') { $record.state='ALREADY_INSTALLED';$record.after=$record.before }
        elseif ($record.before.state -notin @('ABSENT','INCOMPATIBLE')) { throw ('Installation not applicable: '+$record.before.state+' / '+$record.before.open_message) }
        else {
            Stage 'Preparing'
            # Keep the exact verified file locked against replacement through process exit.
            $lock=[IO.File]::Open($Installer,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
            Stage 'VerifyingFile'
            $record.verification=Test-WsdInstaller $Installer $Manifest.installer
            Stage 'Installing'
            $start=[Diagnostics.ProcessStartInfo]::new()
            $start.FileName=$Installer; $start.Arguments='-install -silent'; $start.UseShellExecute=$true
            if (-not (Get-WsdIsAdmin)) { $start.Verb='runas' }
            # Windows owns the UAC prompt. No hidden consent and no automatic reboot.
            $process=[Diagnostics.Process]::Start($start)
            if ($null -eq $process) { throw 'Installer did not return a process handle' }
            try {
                $record['installer_pid']=$process.Id
                # Never forcibly kill an installation halfway through. This observer runs off UI.
                $process.WaitForExit()
                $record.exit_code=$process.ExitCode
                $record.state=Resolve-WsdInstallExit $process.ExitCode
            } finally { $process.Dispose() }
            $record.reboot_required=$record.state -eq 'REBOOT_REQUIRED'
            if ($record.state -eq 'INSTALLED') {
                Stage 'VerifyingDriver'
                $record.after=Get-WsdPawnIo
                if ($record.after.state -ne 'ACCESSIBLE') { $record.state='INSTALLED_NOT_READY';$record.error='Installer completed but device is not accessible: '+$record.after.state }
            }
        }
    } catch {
        $ex=$_.Exception
        while ($ex.InnerException) { $ex=$ex.InnerException }
        if (($ex -is [ComponentModel.Win32Exception] -and $ex.NativeErrorCode -eq 1223) -or $ex.HResult -eq -2147023673) { $record.state='CANCELLED';$record.exit_code=1223 }
        else { $record.state='ERROR' }
        $record.error=$ex.Message
    } finally {
        if($lock){$lock.Dispose()}
        if($owned){$mutex.ReleaseMutex()};if($mutex){$mutex.Dispose()}
        $record['finished']=(Get-Date).ToUniversalTime().ToString('o')
        $json=$record|ConvertTo-Json -Depth 12
        $path=Join-Path $LogDirectory 'PawnIO-install.json'
        [IO.File]::WriteAllText($path,$json,[Text.UTF8Encoding]::new($false))
    }
    'WSD_HW_RESULT '+($record|ConvertTo-Json -Depth 12 -Compress)
}
