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

Export-ModuleMember -Function Test-CompatCommand,Test-CompatPowerShellVersion,Get-CompatRuntimeInfo,Get-CompatInstance
