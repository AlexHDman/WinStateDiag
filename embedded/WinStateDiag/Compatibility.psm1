Set-StrictMode -Version 2.0

function Test-CompatCommand {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Name)
    return $null -ne (Get-Command -Name $Name -ErrorAction SilentlyContinue)
}

function Test-CompatPowerShellVersion {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][version]$Version)
    return $Version.Major -ge 5
}

function Get-CompatRuntimeInfo {
    [CmdletBinding()]
    param(
        [version]$PowerShellVersion=$PSVersionTable.PSVersion,
        [version]$OsVersion=[Environment]::OSVersion.Version,
        [AllowNull()][string]$Edition=$null
    )
    if([string]::IsNullOrWhiteSpace($Edition)){
        $editionVariable=Get-Variable -Name PSEdition -ErrorAction SilentlyContinue
        $Edition=if($editionVariable){[string]$editionVariable.Value}else{'Desktop'}
    }
    $family=if($Edition -eq 'Core'){'PowerShell'}else{'Windows PowerShell'}
    [PSCustomObject]@{
        Supported=Test-CompatPowerShellVersion $PowerShellVersion
        Version=$PowerShellVersion
        Edition=$Edition
        DisplayName=('{0} {1}.{2}' -f $family,$PowerShellVersion.Major,$PowerShellVersion.Minor)
        Compatibility=$(if($OsVersion.Major -ge 10){'MODERN'}else{'LEGACY'})
    }
}

function Get-CompatInstance {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,Position=0)][string]$ClassName,
        [string]$Namespace='root\cimv2',
        [string]$Filter='',
        [switch]$ForceWmi,
        [scriptblock]$CimInvoker,
        [scriptblock]$WmiInvoker
    )
    $cimError=$null
    if(-not $ForceWmi -and ($CimInvoker -or (Test-CompatCommand 'Get-CimInstance'))){
        try {
            if($CimInvoker){return @(& $CimInvoker $ClassName $Namespace $Filter)}
            $parameters=@{ClassName=$ClassName;Namespace=$Namespace;ErrorAction='Stop'}
            if(-not [string]::IsNullOrWhiteSpace($Filter)){$parameters.Filter=$Filter}
            return @(Get-CimInstance @parameters)
        } catch { $cimError=$_.Exception }
    }
    try {
        if($WmiInvoker){return @(& $WmiInvoker $ClassName $Namespace $Filter)}
        if(Test-CompatCommand 'Get-WmiObject'){
            $parameters=@{Class=$ClassName;Namespace=$Namespace;ErrorAction='Stop'}
            if(-not [string]::IsNullOrWhiteSpace($Filter)){$parameters.Filter=$Filter}
            return @(Get-WmiObject @parameters)
        }
    } catch {
        if($cimError){throw (New-Object InvalidOperationException ("CIM and WMI queries failed for {0}. CIM: {1}; WMI: {2}" -f $ClassName,$cimError.Message,$_.Exception.Message),$_.Exception)}
        throw
    }
    if($cimError){throw $cimError}
    throw (New-Object PlatformNotSupportedException 'Neither Get-CimInstance nor Get-WmiObject is available.')
}

function Get-CompatFirmwareState {
    [CmdletBinding()]
    param()
    # Single shared mechanism (v0.3.6) for Firmware/Secure Boot, so every
    # caller agrees: one module previously read a WinPE-only registry value
    # (HKLM:\SYSTEM\CurrentControlSet\Control!PEFirmwareType, normally
    # absent -> silently UNKNOWN) while another used the reliable Win32
    # GetFirmwareType API and correctly reported UEFI. That divergence is
    # what this function removes: everyone now calls this, and only this.
    $firmware = 'Unable to determine'
    try {
        if (-not ('ExpcCompatFirmwareNative' -as [type])) {
            Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class ExpcCompatFirmwareNative {
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool GetFirmwareType(out UInt32 firmwareType);
}
'@
        }
        [uint32]$native = 0
        if ([ExpcCompatFirmwareNative]::GetFirmwareType([ref]$native)) {
            $firmware = switch ($native) { 1 { 'Legacy' } 2 { 'UEFI' } default { 'Unable to determine' } }
        }
    } catch { $firmware = 'Unable to determine' }

    # Secure Boot only means anything on UEFI; on Legacy/unknown firmware
    # the state is "Unable to determine", never a guessed Disabled/False.
    $secureBoot = 'Unable to determine'
    if ($firmware -eq 'UEFI') {
        try {
            $state = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' -Name UEFISecureBootEnabled -ErrorAction Stop
            $secureBoot = if ([int]$state.UEFISecureBootEnabled -eq 1) { 'Enabled' } else { 'Disabled' }
        } catch {
            if (Test-CompatCommand 'Confirm-SecureBootUEFI') {
                try { $secureBoot = if (Confirm-SecureBootUEFI -ErrorAction Stop) { 'Enabled' } else { 'Disabled' } }
                catch { $secureBoot = 'Unable to determine' }
            }
        }
    }

    [PSCustomObject]@{ Firmware = $firmware; SecureBoot = $secureBoot }
}

Export-ModuleMember -Function Test-CompatCommand,Test-CompatPowerShellVersion,Get-CompatRuntimeInfo,Get-CompatInstance,Get-CompatFirmwareState
