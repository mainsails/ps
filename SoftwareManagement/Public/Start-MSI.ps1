Function Start-MSI {
    <#
    .SYNOPSIS
        Executes msiexec.exe to perform the following actions for MSI & MSP files and MSI product codes: install, uninstall, patch, repair
    .DESCRIPTION
        Executes msiexec.exe to perform the following actions for MSI & MSP files and MSI product codes: install, uninstall, patch, repair
        If the -Action parameter is set to "Install" and the MSI is already installed, the function will exit
        Uses default switches for msiexec, preferring a silent install with no console output
        Automatically generates an msi log file in $env:WinDir\Temp\SoftwarePSM
    .PARAMETER Action
        The action to perform. Options: Install, Uninstall, Patch, Repair
    .PARAMETER Path
        The path to the MSI/MSP file or the product code of the installed MSI
    .PARAMETER Transform
        The name of the transform file(s) to be applied to the MSI. The transform file is expected to be in the same directory as the MSI file
    .PARAMETER $CustomParameters
        Adds to the default parameters. Install default is: "REBOOT=ReallySuppress /QN". Uninstall default is: "REBOOT=ReallySuppress /QN"
    .PARAMETER PassThru
        Returns ExitCode, STDOut, and STDErr output from the process
    .PARAMETER ContinueOnError
        Continue if an exit code is returned by msiexec that is not recognized. Default is: $false
    .EXAMPLE
        Start-MSI -Action Install -Path 'C:\Path\To\File\7z1604-x64.msi'
        Installs an MSI
    .EXAMPLE
        Start-MSI -Action Install -Path 'Adobe_Acrobat_DC_x64_EN.msi' -Transform 'Adobe_Acrobat_DC_x64_EN_01.mst'
        Installs an MSI and applies a transform
    .EXAMPLE
        Start-MSI -Action Uninstall -Path '{23170F69-40C1-2702-1604-000001000000}'
        Uninstalls an MSI using a product code
    .EXAMPLE
        Start-MSI -Action Patch -Path 'Adobe_Acrobat_DC_x64_EN.msp'
        Installs an MSP
    .LINK
        Remove-MSI
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false)]
        [ValidateSet('Install','Uninstall','Patch','Repair')]
        [string]$Action = 'Install',
        [Parameter(Mandatory=$true,Position=0)]
        [ValidateScript({ ($_ -match $MSIProductCodeRegExPattern) -or ('.msi','.msp' -contains [IO.Path]::GetExtension($_)) })]
        [Alias('ProductCode')]
        [string]$Path,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [string]$Transform,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [string]$CustomParameters,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [switch]$PassThru = $false,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [boolean]$ContinueOnError = $false
    )

    Begin {
        # Verbose Logging
        [string]$CmdletName  = $MyInvocation.MyCommand.Name
        [string]$CmdletParam = $PSBoundParameters | Format-Table -Property @{ Label = 'Parameter'; Expression = { "[-$($_.Key)]" } }, @{ Label = 'Value'; Expression = { $_.Value }; Alignment = 'Left' } -AutoSize -Wrap | Out-String
        Write-Verbose -Message "##### Calling : [$CmdletName]"

        # Set Default Switches
        $msiInstallDefaultParams   = 'REBOOT=ReallySuppress /QN'
        $msiUninstallDefaultParams = 'REBOOT=ReallySuppress /QN'
        $msiFile                   = [IO.Path]::GetFileNameWithoutExtension($Path)
        $msiLogPath                = "$env:WinDir\Temp\SoftwarePSM"
        $msiLoggingOptions         = '/L*v'
        $exeMsiexec                = 'msiexec.exe'

        ## Create log folder if it doesn't already exist
        If (-not (Test-Path -LiteralPath $msiLogPath -PathType 'Container')) {
            New-Item -Path $msiLogPath -ItemType 'Directory' -Force -ErrorAction 'Stop' | Out-Null
        }

        # ProductCode RegEx Pattern
        [string]$MSIProductCodeRegExPattern = '^(\{{0,1}([0-9a-fA-F]){8}-([0-9a-fA-F]){4}-([0-9a-fA-F]){4}-([0-9a-fA-F]){4}-([0-9a-fA-F]){12}\}{0,1})$'

        # Invalid File Name Characters
        [char[]]$InvalidFileNameChars = [IO.Path]::GetInvalidFileNameChars()
    }
    Process {
        # Log Initialisation
        Write-Verbose -Message "Calling : $($MyInvocation.MyCommand.Name) [$Action]"
        Write-Verbose -Message "MSI : $Path"

        If ($Transform) {
            Write-Verbose -Message "Transform : $Transform"
        }
        Else {
            Write-Verbose -Message "Transform : No Transform(s) Specified"
        }

        # Build Log File Name
        If ($Path -match $MSIProductCodeRegExPattern) {
            [boolean]$PathIsProductCode = $true
            Write-Verbose -Message 'Resolving product code to a publisher, application name, and version'
            [psobject]$ProductCodeNameVersion = Get-InstalledApplication -ProductCode $Path | Select-Object -Property 'Publisher', 'DisplayName', 'DisplayVersion' -First 1 -ErrorAction 'SilentlyContinue'
            If ($ProductCodeNameVersion.Publisher) {
                $LogName = ($ProductCodeNameVersion.Publisher + '_' + $ProductCodeNameVersion.DisplayName + '_' + $ProductCodeNameVersion.DisplayVersion) -replace "[$InvalidFileNameChars]",'' -replace ' ',''
            }
            Else {
                $LogName = ($ProductCodeNameVersion.DisplayName + '_' + $ProductCodeNameVersion.DisplayVersion) -replace "[$InvalidFileNameChars]",'' -replace ' ',''
            }
        }
        Else {
            [boolean]$PathIsProductCode = $false
            $LogName = $msiFile
        }

        # Get DateTime for MSI Log FileName
        $DateTime = Get-Date -Format "yyyy-MM-dd-HHmm"
        # Build the MSI Parameters
        Switch ($Action) {
            'Install'   { $Option = '/i';      [string]$msiLogFile = $msiLogPath + '\' + $Action + '-' + $DateTime + '-' + $LogName + '.log'; $msiDefaultParams = $msiInstallDefaultParams }
            'Uninstall' { $Option = '/x';      [string]$msiLogFile = $msiLogPath + '\' + $Action + '-' + $DateTime + '-' + $LogName + '.log'; $msiDefaultParams = $msiUninstallDefaultParams }
            'Patch'     { $Option = '/update'; [string]$msiLogFile = $msiLogPath + '\' + $Action + '-' + $DateTime + '-' + $LogName + '.log'; $msiDefaultParams = $msiInstallDefaultParams }
            'Repair'    { $Option = '/f';      [string]$msiLogFile = $msiLogPath + '\' + $Action + '-' + $DateTime + '-' + $LogName + '.log'; $msiDefaultParams = $msiInstallDefaultParams }
        }

        # Enclose MSI LogFile path in quotes (quirk)
        [string]$msiLogFile = "`"$msiLogFile`""

        # Set the full path to the MSI
        If (Test-Path -LiteralPath $Path -ErrorAction 'SilentlyContinue') {
            [string]$msiFile = (Get-Item -LiteralPath $Path).FullName
        }
        ElseIf ($PathIsProductCode) {
            [string]$msiFile = $Path
        }
        Else {
            Throw "Execution : Failed to find [$Path]"
        }

        # Enumerate all transforms
        If ($Transform) {
            [string[]]$Transforms = $Transform -split ','
            0..($Transforms.Length - 1) | ForEach-Object {
                $Transforms[$_] = Join-Path -Path (Split-Path -Path $msiFile -Parent) -ChildPath $Transforms[$_].Replace('.\','')
            }
            [string]$mstFile = "`"$($Transforms -join ';')`""
        }

        # Enumerate all patches
        If ($Patch) {
            [string[]]$Patches = $Patch -split ','
            0..($Patches.Length - 1) | ForEach-Object {
                $Patches[$_] = Join-Path -Path (Split-Path -Path $msiFile -Parent) -ChildPath $Patches[$_].Replace('.\','')
            }
            [string]$mspFile = "`"$($Patches -join ';')`""
        }

        # Get the ProductCode of the MSI
        If ($PathIsProductCode) {
            [string]$MSIProductCode = $Path
        }
        ElseIf ([IO.Path]::GetExtension($msiFile) -eq '.msi') {
            Try {
                [hashtable]$GetMsiTablePropertySplat = @{ Path = $msiFile; Table = 'Property' }
                If ($Transforms) { $GetMsiTablePropertySplat.Add( 'TransformPath', $Transforms ) }
                [string]$MSIProductCode = Get-MsiTableProperty @GetMsiTablePropertySplat | Select-Object -ExpandProperty 'ProductCode' -ErrorAction 'Stop'
            }
            Catch {
                Write-Warning -Message "Failed to get the ProductCode from the MSI file. Continuing with requested action [$Action]"
            }
        }

        # Enclose the MSI file in quotes (quirk)
        [string]$msiFile = "`"$msiFile`""

        # Start building the MsiExec command line
        [string]$argsMSI = "$Option $msiFile $msiDefaultParams $msiLoggingOptions $msiLogFile"
        If ($Transform)        { $argsMSI = "$argsMSI TRANSFORMS=$mstFile TRANSFORMSSECURE=1" }
        If ($Patch)            { $argsMSI = "$argsMSI PATCH=$mspFile" }
        If ($CustomParameters) { $argsMSI = $CustomParameters }

        # Build the hashtable with the options that will be passed to Start-EXE using splatting
        [hashtable]$ExecuteProcessSplat = @{
            Path       = $exeMsiexec
            Parameters = $argsMSI
        }
        If ($PassThru) { $ExecuteProcessSplat.Add('PassThru', $PassThru) }
        If ($ContinueOnError) { $ExecuteProcessSplat.Add( 'ContinueOnError', $ContinueOnError) }

        # Log Pre-Action
        If ($MSIProductCode) { Write-Verbose -Message "MSI ProductCode : $MSIProductCode" }
        Write-Verbose -Message "MSI Switches : $argsMSI"

        # Check if the MSI is already installed
        If ($MSIProductCode) {
            [psobject]$MsiInstalled = Get-InstalledApplication -ProductCode $MSIProductCode
            If ($MsiInstalled) { [boolean]$IsMsiInstalled = $true } Else { [boolean]$IsMsiInstalled = $false }
        }
        Else {
            If ($Action -eq 'Install') { [boolean]$IsMsiInstalled = $false } Else { [boolean]$IsMsiInstalled = $true }
        }

        # Execute Process
        If (($IsMsiInstalled) -and ($Action -eq 'Install')) {
            Write-Warning -Message "The MSI is already installed on this system. Skipping action [$Action]"
        }
        ElseIf (((-not $IsMsiInstalled) -and ($Action -eq 'Install')) -or ($IsMsiInstalled)) {
            Write-Verbose -Message "Starting : $Action"
            If ($PassThru) {
                [psobject]$ExecuteResults = Start-EXE @ExecuteProcessSplat
            }
            Else {
                Start-EXE @ExecuteProcessSplat
            }
            # Refresh the Windows Explorer Shell
            Update-Desktop
        }
        Else {
            Write-Warning -Message "The MSI is not installed on this system. Skipping action [$Action]"
        }
    }
    End {
        If ($PassThru) { Write-Output -InputObject $ExecuteResults }
        # Verbose Logging
        Write-Verbose -Message "##### Ending : [$CmdletName]"
    }
}