param(
    [string]$Project = 'C:\AI\WinStateDiag'
)

$ErrorActionPreference = 'Stop'

$AuditDir = Join-Path $Project 'docs\AUDIT'

$WinStateFile = Join-Path $Project 'embedded\WinStateDiag\EXPC_WinDiagProbe.ps1'
$ExpcFile     = Join-Path $Project 'embedded\EXPC-Diagnostic\EXPC-Diagnostic.ps1'
$HardwareFile = Join-Path $Project 'embedded\Hardware-Report\Hardware-Diagnostic.ps1'
$PassportFile = Join-Path $Project 'embedded\Hardware-Report\HardwarePassport.psm1'

Write-Host ""
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host " WinStateDiag - Milestone 03 Functional Audit" -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan

# ------------------------------------------------------------
# 1. SAFETY
# ------------------------------------------------------------

$Required = @(
    $WinStateFile,
    $ExpcFile,
    $HardwareFile,
    $PassportFile
)

foreach ($File in $Required) {
    if (-not (Test-Path $File)) {
        throw "Required file not found: $File"
    }
}

New-Item -ItemType Directory -Force -Path $AuditDir | Out-Null

Write-Host "[PASS] Required baseline files found." -ForegroundColor Green

# ------------------------------------------------------------
# 2. HELPERS
# ------------------------------------------------------------

function Get-InterestingLines {
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string[]]$Patterns
    )

    $Lines = Get-Content -LiteralPath $Path

    $Results = for ($i = 0; $i -lt $Lines.Count; $i++) {

        $Line = $Lines[$i]

        foreach ($Pattern in $Patterns) {
            if ($Line -match $Pattern) {
                [PSCustomObject]@{
                    Line = $i + 1
                    Text = $Line.Trim()
                }
                break
            }
        }
    }

    return @($Results)
}


function Get-FunctionInventory {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $Tokens = $null
    $Errors = $null

    $Ast = [System.Management.Automation.Language.Parser]::ParseFile(
        $Path,
        [ref]$Tokens,
        [ref]$Errors
    )

    $Functions = $Ast.FindAll(
        {
            param($Node)
            $Node -is [System.Management.Automation.Language.FunctionDefinitionAst]
        },
        $true
    )

    $Result = foreach ($Function in $Functions) {
        [PSCustomObject]@{
            Name      = $Function.Name
            StartLine = $Function.Extent.StartLineNumber
            EndLine   = $Function.Extent.EndLineNumber
        }
    }

    [PSCustomObject]@{
        Functions   = @($Result)
        ParseErrors = @(
            $Errors | ForEach-Object {
                [PSCustomObject]@{
                    Line    = $_.Extent.StartLineNumber
                    Message = $_.Message
                }
            }
        )
    }
}


function Get-CommandInventory {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $Tokens = $null
    $Errors = $null

    $Ast = [System.Management.Automation.Language.Parser]::ParseFile(
        $Path,
        [ref]$Tokens,
        [ref]$Errors
    )

    $Commands = $Ast.FindAll(
        {
            param($Node)
            $Node -is [System.Management.Automation.Language.CommandAst]
        },
        $true
    )

    $Names = foreach ($Command in $Commands) {
        $Name = $Command.GetCommandName()

        if ($Name) {
            $Name
        }
    }

    return @(
        $Names |
            Sort-Object -Unique
    )
}


function Write-Section {
    param(
        [System.Collections.Generic.List[string]]$Buffer,
        [string]$Title
    )

    $Buffer.Add('')
    $Buffer.Add('============================================================')
    $Buffer.Add($Title)
    $Buffer.Add('============================================================')
}


function Add-LineResults {
    param(
        [System.Collections.Generic.List[string]]$Buffer,
        [object[]]$Results
    )

    if (-not $Results -or $Results.Count -eq 0) {
        $Buffer.Add('(none found)')
        return
    }

    foreach ($Item in $Results) {
        $Buffer.Add(
            ('L{0}: {1}' -f $Item.Line, $Item.Text)
        )
    }
}


# ------------------------------------------------------------
# 3. AST PARSE CONTROL
# ------------------------------------------------------------

$Files = @(
    [PSCustomObject]@{
        Name = 'WinStateDiag baseline'
        Path = $WinStateFile
    },
    [PSCustomObject]@{
        Name = 'EXPC Diagnostic'
        Path = $ExpcFile
    },
    [PSCustomObject]@{
        Name = 'Hardware Report'
        Path = $HardwareFile
    },
    [PSCustomObject]@{
        Name = 'Hardware Passport module'
        Path = $PassportFile
    }
)

$ParseSummary = @()

foreach ($Item in $Files) {

    $Inventory = Get-FunctionInventory -Path $Item.Path

    $ParseSummary += [PSCustomObject]@{
        Component   = $Item.Name
        File        = $Item.Path
        Functions   = $Inventory.Functions.Count
        ParseErrors = $Inventory.ParseErrors.Count
    }

    if ($Inventory.ParseErrors.Count -gt 0) {

        Write-Host "[WARN] Parse issues: $($Item.Name)" -ForegroundColor Yellow

        $Inventory.ParseErrors |
            Format-Table Line, Message -AutoSize
    }
    else {
        Write-Host "[PASS] Parsed: $($Item.Name)" -ForegroundColor Green
    }
}

# ------------------------------------------------------------
# 4. EXPC DIAGNOSTIC MENU / MODES
# ------------------------------------------------------------

$ExpcMenuPatterns = @(
    'Read-Host',
    'switch\s*\(',
    'switch\s*\(',
    'Select',
    'choice',
    'menu',
    'режим',
    'провер',
    'автомат',
    'глуб',
    'пошаг',
    '\[1\]',
    '\[2\]',
    '\[3\]',
    '\[4\]',
    '\[5\]',
    "'1'",
    "'2'",
    "'3'",
    "'4'",
    '"1"',
    '"2"',
    '"3"',
    '"4"'
)

$ExpcMenuLines = Get-InterestingLines `
    -Path $ExpcFile `
    -Patterns $ExpcMenuPatterns


# ------------------------------------------------------------
# 5. EXPC DIAGNOSTIC COMMANDS
# ------------------------------------------------------------

$DiagnosticPatterns = @(
    '\bsfc(\.exe)?\b',
    'verifyonly',
    'scannow',
    '\bdism(\.exe)?\b',
    'ScanHealth',
    'CheckHealth',
    'RestoreHealth',
    '\bchkdsk(\.exe)?\b',
    'Get-WinEvent',
    'Get-CimInstance',
    'Get-WmiObject',
    'Get-PhysicalDisk',
    'Get-Disk',
    'Get-Volume',
    'Get-Storage',
    'Get-PnpDevice',
    'Get-HotFix',
    'Get-MpComputerStatus',
    'Get-NetAdapter',
    'Get-Counter',
    'Win32_',
    'WHEA',
    'BugCheck',
    'SMART',
    'Defender',
    'EventLog',
    'Reliability',
    'Battery',
    'BIOS'
)

$ExpcDiagnosticLines = Get-InterestingLines `
    -Path $ExpcFile `
    -Patterns $DiagnosticPatterns


# ------------------------------------------------------------
# 6. OUTPUT / REPORT BEHAVIOR
# ------------------------------------------------------------

$OutputPatterns = @(
    'ConvertTo-Json',
    'Export-Csv',
    'Out-File',
    'Set-Content',
    'Add-Content',
    'Export-Clixml',
    'ConvertTo-Html',
    'Compress-Archive',
    '\.json',
    '\.txt',
    '\.html',
    '\.csv',
    '\.zip',
    'OutputDir',
    'Report',
    'Save',
    'Path'
)

$ExpcOutputLines = Get-InterestingLines `
    -Path $ExpcFile `
    -Patterns $OutputPatterns

$HardwareOutputLines = Get-InterestingLines `
    -Path $HardwareFile `
    -Patterns $OutputPatterns

$PassportOutputLines = Get-InterestingLines `
    -Path $PassportFile `
    -Patterns $OutputPatterns


# ------------------------------------------------------------
# 7. HARDWARE DATA INVENTORY
# ------------------------------------------------------------

$HardwarePatterns = @(
    'Win32_ComputerSystem',
    'Win32_BaseBoard',
    'Win32_BIOS',
    'Win32_Processor',
    'Win32_PhysicalMemory',
    'Win32_PhysicalMemoryArray',
    'Win32_MemoryDevice',
    'Win32_DiskDrive',
    'Win32_DiskPartition',
    'Win32_LogicalDisk',
    'Win32_VideoController',
    'Win32_NetworkAdapter',
    'Win32_NetworkAdapterConfiguration',
    'Win32_Battery',
    'MSFT_PhysicalDisk',
    'Get-PhysicalDisk',
    'Get-Disk',
    'Get-Partition',
    'Get-Volume',
    'Get-NetAdapter',
    'Get-CimInstance',
    'Get-WmiObject',
    'Manufacturer',
    'Model',
    'PartNumber',
    'SerialNumber',
    'Capacity',
    'Speed',
    'ConfiguredClockSpeed',
    'DeviceLocator',
    'BankLabel',
    'SMBIOS',
    'BIOS',
    'UEFI',
    'Memory',
    'Motherboard',
    'GPU',
    'Video',
    'Storage',
    'Battery'
)

$HardwareLines = Get-InterestingLines `
    -Path $HardwareFile `
    -Patterns $HardwarePatterns

$PassportLines = Get-InterestingLines `
    -Path $PassportFile `
    -Patterns $HardwarePatterns


# ------------------------------------------------------------
# 8. FUNCTION INVENTORY
# ------------------------------------------------------------

$WinStateFunctions = Get-FunctionInventory -Path $WinStateFile
$ExpcFunctions     = Get-FunctionInventory -Path $ExpcFile
$HardwareFunctions = Get-FunctionInventory -Path $HardwareFile
$PassportFunctions = Get-FunctionInventory -Path $PassportFile

$WinStateCommands = Get-CommandInventory -Path $WinStateFile
$ExpcCommands     = Get-CommandInventory -Path $ExpcFile
$HardwareCommands = Get-CommandInventory -Path $HardwareFile
$PassportCommands = Get-CommandInventory -Path $PassportFile


# ------------------------------------------------------------
# 9. POSSIBLE OVERLAP
# ------------------------------------------------------------

$WinStateCommandSet = @($WinStateCommands)
$ExpcCommandSet     = @($ExpcCommands)

$CommonCommands = @(
    $WinStateCommandSet |
        Where-Object { $_ -in $ExpcCommandSet } |
        Sort-Object -Unique
)

$InterestingCommonCommands = @(
    $CommonCommands |
        Where-Object {
            $_ -match '^(Get-|Test-|Repair-|Invoke-|Start-|Stop-|sfc|dism|chkdsk)'
        }
)


# ------------------------------------------------------------
# 10. BUILD HUMAN-READABLE AUDIT
# ------------------------------------------------------------

$Report = [System.Collections.Generic.List[string]]::new()

$Report.Add('WinStateDiag - Milestone 03 Functional Audit')
$Report.Add(('Generated: {0}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')))
$Report.Add(('Project: {0}' -f $Project))
$Report.Add('')
$Report.Add('IMPORTANT:')
$Report.Add('This report is a static audit.')
$Report.Add('No diagnostic command was intentionally executed by this audit.')

Write-Section $Report '1. PARSE SUMMARY'

foreach ($Item in $ParseSummary) {
    $Report.Add(
        ('{0}: Functions={1}; ParseErrors={2}' -f `
            $Item.Component, `
            $Item.Functions, `
            $Item.ParseErrors)
    )
}


Write-Section $Report '2. EXPC DIAGNOSTIC - MENU / MODE CANDIDATES'
Add-LineResults $Report $ExpcMenuLines


Write-Section $Report '3. EXPC DIAGNOSTIC - DIAGNOSTIC COMMAND CANDIDATES'
Add-LineResults $Report $ExpcDiagnosticLines


Write-Section $Report '4. EXPC DIAGNOSTIC - OUTPUT / REPORT CANDIDATES'
Add-LineResults $Report $ExpcOutputLines


Write-Section $Report '5. EXPC DIAGNOSTIC - FUNCTIONS'

foreach ($Function in $ExpcFunctions.Functions) {
    $Report.Add(
        ('{0} [L{1}-L{2}]' -f `
            $Function.Name, `
            $Function.StartLine, `
            $Function.EndLine)
    )
}


Write-Section $Report '6. EXPC DIAGNOSTIC - COMMAND INVENTORY'

foreach ($Command in $ExpcCommands) {
    $Report.Add($Command)
}


Write-Section $Report '7. HARDWARE REPORT - DATA CANDIDATES'
Add-LineResults $Report $HardwareLines


Write-Section $Report '8. HARDWARE PASSPORT MODULE - DATA CANDIDATES'
Add-LineResults $Report $PassportLines


Write-Section $Report '9. HARDWARE REPORT - OUTPUT CANDIDATES'
Add-LineResults $Report $HardwareOutputLines


Write-Section $Report '10. HARDWARE PASSPORT - OUTPUT CANDIDATES'
Add-LineResults $Report $PassportOutputLines


Write-Section $Report '11. HARDWARE REPORT - FUNCTIONS'

foreach ($Function in $HardwareFunctions.Functions) {
    $Report.Add(
        ('{0} [L{1}-L{2}]' -f `
            $Function.Name, `
            $Function.StartLine, `
            $Function.EndLine)
    )
}


Write-Section $Report '12. HARDWARE PASSPORT MODULE - FUNCTIONS'

foreach ($Function in $PassportFunctions.Functions) {
    $Report.Add(
        ('{0} [L{1}-L{2}]' -f `
            $Function.Name, `
            $Function.StartLine, `
            $Function.EndLine)
    )
}


Write-Section $Report '13. WINSTATEDIAG BASELINE - FUNCTIONS'

foreach ($Function in $WinStateFunctions.Functions) {
    $Report.Add(
        ('{0} [L{1}-L{2}]' -f `
            $Function.Name, `
            $Function.StartLine, `
            $Function.EndLine)
    )
}


Write-Section $Report '14. WINSTATEDIAG BASELINE - COMMAND INVENTORY'

foreach ($Command in $WinStateCommands) {
    $Report.Add($Command)
}


Write-Section $Report '15. WINSTATEDIAG / EXPC POSSIBLE COMMAND OVERLAP'

if ($InterestingCommonCommands.Count -eq 0) {
    $Report.Add('(no interesting common commands detected)')
}
else {
    foreach ($Command in $InterestingCommonCommands) {
        $Report.Add($Command)
    }
}


Write-Section $Report '16. HARDWARE COMMAND INVENTORY'

foreach ($Command in $HardwareCommands) {
    $Report.Add($Command)
}


Write-Section $Report '17. HARDWARE PASSPORT COMMAND INVENTORY'

foreach ($Command in $PassportCommands) {
    $Report.Add($Command)
}


# ------------------------------------------------------------
# 11. SAVE TXT
# ------------------------------------------------------------

$AuditTxt = Join-Path $AuditDir 'MILESTONE_03_FUNCTIONAL_AUDIT.txt'

$Report |
    Set-Content `
        -LiteralPath $AuditTxt `
        -Encoding utf8


# ------------------------------------------------------------
# 12. SAVE MACHINE-READABLE JSON
# ------------------------------------------------------------

$AuditObject = [ordered]@{

    GeneratedAt = (Get-Date).ToString('o')

    Project = $Project

    Files = [ordered]@{
        WinStateDiag       = $WinStateFile
        EXPCDiagnostic     = $ExpcFile
        HardwareReport     = $HardwareFile
        HardwarePassport   = $PassportFile
    }

    ParseSummary = $ParseSummary

    EXPCDiagnostic = [ordered]@{
        Functions        = $ExpcFunctions.Functions
        Commands         = $ExpcCommands
        MenuCandidates   = $ExpcMenuLines
        DiagnosticLines  = $ExpcDiagnosticLines
        OutputLines      = $ExpcOutputLines
    }

    HardwareReport = [ordered]@{
        Functions       = $HardwareFunctions.Functions
        Commands        = $HardwareCommands
        DataLines       = $HardwareLines
        OutputLines     = $HardwareOutputLines
    }

    HardwarePassport = [ordered]@{
        Functions       = $PassportFunctions.Functions
        Commands        = $PassportCommands
        DataLines       = $PassportLines
        OutputLines     = $PassportOutputLines
    }

    WinStateDiagBaseline = [ordered]@{
        Functions       = $WinStateFunctions.Functions
        Commands        = $WinStateCommands
    }

    PossibleOverlap = [ordered]@{
        CommonInterestingCommands = $InterestingCommonCommands
    }
}

$AuditJson = Join-Path $AuditDir 'MILESTONE_03_FUNCTIONAL_AUDIT.json'

$AuditObject |
    ConvertTo-Json -Depth 12 |
    Set-Content `
        -LiteralPath $AuditJson `
        -Encoding utf8


# ------------------------------------------------------------
# 13. CONTROL
# ------------------------------------------------------------

if (-not (Test-Path $AuditTxt)) {
    throw "TXT audit was not created."
}

if (-not (Test-Path $AuditJson)) {
    throw "JSON audit was not created."
}

$TxtSize  = (Get-Item $AuditTxt).Length
$JsonSize = (Get-Item $AuditJson).Length

$TxtHash  = (Get-FileHash $AuditTxt -Algorithm SHA256).Hash
$JsonHash = (Get-FileHash $AuditJson -Algorithm SHA256).Hash


Write-Host ""
Write-Host "=== PARSE SUMMARY ===" -ForegroundColor Cyan

$ParseSummary |
    Format-Table Component, Functions, ParseErrors -AutoSize


Write-Host ""
Write-Host "=== QUICK INVENTORY ===" -ForegroundColor Cyan

Write-Host "EXPC functions            : $($ExpcFunctions.Functions.Count)"
Write-Host "EXPC commands             : $($ExpcCommands.Count)"
Write-Host "EXPC menu candidates      : $($ExpcMenuLines.Count)"
Write-Host "EXPC diagnostic candidates: $($ExpcDiagnosticLines.Count)"
Write-Host ""
Write-Host "Hardware functions        : $($HardwareFunctions.Functions.Count)"
Write-Host "Passport functions        : $($PassportFunctions.Functions.Count)"
Write-Host "Hardware data candidates  : $($HardwareLines.Count)"
Write-Host "Passport data candidates  : $($PassportLines.Count)"
Write-Host ""
Write-Host "Possible shared commands  : $($InterestingCommonCommands.Count)"


Write-Host ""
Write-Host "====================================================" -ForegroundColor Green
Write-Host " WINSTATEDIAG MILESTONE 03 AUDIT: PASS" -ForegroundColor Green
Write-Host "====================================================" -ForegroundColor Green

Write-Host ""
Write-Host "TXT : $AuditTxt"
Write-Host "Size: $TxtSize bytes"
Write-Host "SHA : $TxtHash"

Write-Host ""
Write-Host "JSON: $AuditJson"
Write-Host "Size: $JsonSize bytes"
Write-Host "SHA : $JsonHash"

Write-Host ""
Write-Host "No diagnostic operation was intentionally executed." -ForegroundColor Green
