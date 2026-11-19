# Shared WinDiag/PowerLab dependency detection. No driver install/start or module execution.
function Get-WsdIsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try { ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
    finally { $identity.Dispose() }
}
function Initialize-WsdPawnNative {
    if ('WsdPawnNative' -as [type]) { return }
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class WsdPawnNative {

 static readonly System.Collections.Generic.Dictionary<string,string> AssemblyFiles = new System.Collections.Generic.Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);
 static readonly System.Collections.Generic.HashSet<string> Loading = new System.Collections.Generic.HashSet<string>(StringComparer.OrdinalIgnoreCase);
 static readonly System.Collections.Generic.Dictionary<string,int> Attempts = new System.Collections.Generic.Dictionary<string,int>(StringComparer.OrdinalIgnoreCase);
 public static void RegisterLhm(string folder){
  foreach(string file in System.IO.Directory.GetFiles(folder,"*.dll"))AssemblyFiles[System.IO.Path.GetFileNameWithoutExtension(file)]=file;
  AppDomain.CurrentDomain.AssemblyResolve+=ResolveLhm;
 }
 static System.Reflection.Assembly ResolveLhm(object sender,ResolveEventArgs args){
  string name=new System.Reflection.AssemblyName(args.Name).Name;string file;
  lock(AssemblyFiles){
   if(!AssemblyFiles.TryGetValue(name,out file))return null;
   int attempts;Attempts.TryGetValue(name,out attempts);Attempts[name]=attempts+1;
   if(attempts>4 || !Loading.Add(name))throw new System.IO.FileLoadException("Recursive LHM dependency resolution refused: "+args.Name);
   try{
    if(Environment.GetEnvironmentVariable("WSD_HW_TRACE")=="1")Console.WriteLine("WSD_HW_RESOLVE "+args.Name);
    return System.Reflection.Assembly.LoadFrom(file);
   }finally{Loading.Remove(name);}
  }
 }
 public static volatile bool Stop;
 public static void WatchParent(){System.Threading.Tasks.Task.Run(()=>{try{Console.ReadLine();}finally{Stop=true;}});}
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
 static extern SafeFileHandle CreateFile(string name,uint access,uint share,IntPtr security,uint disposition,uint flags,IntPtr template);
 public static int OpenExisting(){using(var h=CreateFile(@"\\?\GLOBALROOT\Device\PawnIO",3,3,IntPtr.Zero,3,128,IntPtr.Zero)){int e=Marshal.GetLastWin32Error();return h.IsInvalid?e:0;}}
}
"@ -ErrorAction Stop
}
function Resolve-WsdPawnState([bool]$Installed, [bool]$DiscoveryComplete, [int]$OpenError, [int]$ServiceError, [string]$Version) {
    if ($OpenError -eq 0) {
        $v=$null
        if (-not [version]::TryParse($Version,[ref]$v)) { return 'INITIALIZATION_ERROR' }
        if ($v -lt [version]'2.2.0') { return 'INCOMPATIBLE' }
        return 'ACCESSIBLE'
    }
    if ($OpenError -in @(577,1275,1260,4551) -or $ServiceError -in @(577,1275,1260,4551)) { return 'BLOCKED_BY_WINDOWS' }
    if ($OpenError -eq 5) { return 'ACCESS_DENIED' }
    if ($OpenError -in @(2,3) -and -not $Installed -and $DiscoveryComplete) { return 'ABSENT' }
    return 'INITIALIZATION_ERROR'
}
function Get-WsdAbortPath { Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'EXPC\HardwareMonitor\uncertain-reader.json' }
function Save-WsdHardwareAbort($Snapshot,[string]$Reason) {
    $path=Get-WsdAbortPath
    [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($path))|Out-Null
    [IO.File]::WriteAllText($path,(@{boot_id=$Snapshot.boot_id;reason=$Reason;timestamp=(Get-Date).ToUniversalTime().ToString('o')}|ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))
}
function Get-WsdLeasePath([string]$Boot) {
    $key=$Boot -replace '[^0-9A-Za-z]',''
    if(-not $key){$key='UNKNOWN'}
    Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) ('EXPC\HardwareMonitor\reader-'+$key+'.json')
}
function Open-WsdHardwareLease($Snapshot) {
    if($Snapshot.reader_gate -ne 'READY' -or $Snapshot.boot_id -eq 'UNKNOWN'){throw 'Protected reader safety gate is not ready'}
    $path=$Snapshot.lease_path
    [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($path))|Out-Null
    $stream=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,[IO.FileShare]::Read)
    $id=[guid]::NewGuid().ToString('N')
    $bytes=[Text.Encoding]::UTF8.GetBytes((@{id=$id;pid=$PID;boot_id=$Snapshot.boot_id;state='PROTECTED_READING'}|ConvertTo-Json -Compress))
    $stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)
    return @{path=$path;stream=$stream;id=$id}
}
function Close-WsdHardwareLease($Lease,[bool]$Clean) {
    if($null -eq $Lease){return}
    $Lease.stream.Dispose()
    if($Clean){
        $record=Get-Content -LiteralPath $Lease.path -Raw -ErrorAction Stop|ConvertFrom-Json -ErrorAction Stop
        if($record.id -ne $Lease.id){throw 'Hardware lease identity changed; cleanup record preserved'}
        # Only this successful operation's exclusively-created lease is removed.
        [IO.File]::Delete($Lease.path)
    }
}
function Get-WsdPawnIo {
    $errors=[Collections.Generic.List[string]]::new(); $version=''; $installed=$false; $complete=$true
    foreach ($view in @([Microsoft.Win32.RegistryView]::Registry64,[Microsoft.Win32.RegistryView]::Registry32)) {
        $base=$null; $key=$null; $service=$null
        try {
            $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$view)
            $key=$base.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\PawnIO')
            $service=$base.OpenSubKey('SYSTEM\CurrentControlSet\Services\PawnIO')
            if ($key) { $installed=$true; if (-not $version) { $version=[string]$key.GetValue('DisplayVersion') } }
            if ($service) { $installed=$true }
        } catch { $complete=$false; $errors.Add('registry: '+$_.Exception.Message) }
        finally { if($service){$service.Dispose()};if($key){$key.Dispose()};if($base){$base.Dispose()} }
    }
    $serviceState='UNKNOWN'; $serviceError=0
    try {
        $service=Get-CimInstance Win32_SystemDriver -Filter "Name='PawnIO'" -OperationTimeoutSec 5 -ErrorAction Stop
        if ($service) { $installed=$true; $serviceState=[string]$service.State; $serviceError=[int]$service.ExitCode }
        else { $serviceState='ABSENT' }
    } catch { $complete=$false; $errors.Add('service query: '+$_.Exception.Message) }
    $openError=-1
    try { Initialize-WsdPawnNative; $openError=[WsdPawnNative]::OpenExisting() }
    catch { $errors.Add('device probe: '+$_.Exception.Message) }
    $boot='UNKNOWN'
    try{$boot=(Get-CimInstance Win32_OperatingSystem -OperationTimeoutSec 5 -ErrorAction Stop).LastBootUpTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm'Z'")}catch{$errors.Add('boot identity: '+$_.Exception.Message)}
    $gate='READY';$gateReason=''
    $abortPath=Get-WsdAbortPath
    if(Test-Path -LiteralPath $abortPath){
        try {
            $prior=Get-Content -LiteralPath $abortPath -Raw -ErrorAction Stop|ConvertFrom-Json -ErrorAction Stop
            if($boot -eq 'UNKNOWN' -or -not $prior.boot_id -or $prior.boot_id -eq $boot){
                $gate='BLOCKED_UNCERTAIN_CLEANUP';$gateReason='Previous reader did not complete hardware cleanup; protected polling stays disabled until a confirmed Windows restart: '+$prior.reason
            }
        } catch {$gate='BLOCKED_UNCERTAIN_CLEANUP';$gateReason='Previous reader cleanup record cannot be verified'}
    }
    $leasePath=Get-WsdLeasePath $boot
    if($boot -eq 'UNKNOWN'){$gate='BLOCKED_UNKNOWN_BOOT';$gateReason='Windows boot identity unavailable; safe crash recovery cannot be confirmed'}
    elseif(Test-Path -LiteralPath $leasePath){$gate='BLOCKED_UNCERTAIN_CLEANUP';$gateReason='A protected reader is active or did not complete cleanup in this Windows boot; no overlapping/replacement protected polling'}
    $state=Resolve-WsdPawnState $installed $complete $openError $serviceError $version
    $openMessage=if ($openError -ge 0) { ([ComponentModel.Win32Exception]::new($openError)).Message } else { 'Device probe not completed' }
    [ordered]@{state=$state;lease_path=$leasePath;reader_gate=$gate;reader_gate_reason=$gateReason;boot_id=$boot;version=$version;installed_evidence=$installed;discovery_complete=$complete;service_state=$serviceState;service_error=$serviceError;open_win32=$openError;open_message=$openMessage;reader_admin=(Get-WsdIsAdmin);reader_pid=$PID;timestamp=(Get-Date).ToUniversalTime().ToString('o');errors=@($errors.ToArray())}
}
function Test-WsdLhmModules($Assembly, $Manifest) {
    $results=[Collections.Generic.List[object]]::new()
    $names=@($Assembly.GetManifestResourceNames() | Where-Object { $_ -like '*.PawnIo.*.bin' })
    if ($names.Count -ne $Manifest.modules.Count) { throw 'Unexpected PawnIO resource count' }
    foreach ($module in $Manifest.modules) {
        $stream=$Assembly.GetManifestResourceStream($module.name)
        if ($null -eq $stream) { throw ('Missing signed module resource: '+$module.name) }
        $hash=[Security.Cryptography.SHA256]::Create()
        try { $actual=([BitConverter]::ToString($hash.ComputeHash($stream))).Replace('-','') }
        finally { $hash.Dispose();$stream.Dispose() }
        if ($actual -ne $module.sha256) { throw ('Unverified PawnIO module: '+$module.name) }
        $results.Add([ordered]@{name=$module.name;sha256=$actual;official_release=$Manifest.modules_version;provenance='EXACT_MATCH';runtime='NOT_YET_READ'})
    }
    return ,$results.ToArray()
}
function Get-WsdHardwareIdentity {
    $out=[ordered]@{}
    foreach ($item in @(@('board','Win32_BaseBoard',@('Manufacturer','Product','Version')),@('bios','Win32_BIOS',@('Manufacturer','SMBIOSBIOSVersion','ReleaseDate')),@('cpu','Win32_Processor',@('Name','Manufacturer','NumberOfCores','NumberOfLogicalProcessors')),@('gpu','Win32_VideoController',@('Name','DriverVersion')))) {
        try { $data=@(Get-CimInstance -ClassName $item[1] -OperationTimeoutSec 5 -ErrorAction Stop | Select-Object -Property $item[2]); $out[$item[0]]=[ordered]@{state=$(if($data.Count){'AVAILABLE'}else{'UNKNOWN'});devices=$data;reason=$(if($data.Count){''}else{'WMI returned no identity'})} }
        catch { $out[$item[0]]=[ordered]@{state='UNKNOWN';devices=@();reason=$_.Exception.Message} }
    }
    return $out
}
