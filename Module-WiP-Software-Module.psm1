#Requires -Version 4.0
#Requires -RunAsAdministrator

Function Get-InstalledApplication {
    <#
    .SYNOPSIS
        Retrieves information on installed applications
    .DESCRIPTION
        Retrieves information about installed applications by querying the registry. You can specify an application's name, a product code, or both
        Returns information about application's publisher, name & version, product code, uninstall string, install source, location, date, and application architecture
    .PARAMETER Name
        The name of the application to retrieve information on. Performs a regex match on the application display name by default
    .PARAMETER Exact
        Specifies that the named application must be matched using the exact name
    .PARAMETER ProductCode
        The product code of the application to retrieve information for
    .PARAMETER IncludeUpdatesAndHotfixes
        Include matches against updates and hotfixes in results
    .EXAMPLE
        Get-InstalledApplication -Name '7-Zip'
    .EXAMPLE
        Get-InstalledApplication -ProductCode '{23170F69-40C1-2702-1604-000001000000}'
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [string[]]$Name,
        [Parameter(Mandatory=$false)]
        [switch]$Exact = $false,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [string[]]$ProductCode,
        [Parameter(Mandatory=$false)]
        [switch]$IncludeUpdatesAndHotfixes
    )

    Begin {
        # Verbose Logging
        [string]$CmdletName  = $MyInvocation.MyCommand.Name
        [string]$CmdletParam = $PSBoundParameters | Format-Table -Property @{ Label = 'Parameter'; Expression = { "[-$($_.Key)]" } }, @{ Label = 'Value'; Expression = { $_.Value }; Alignment = 'Left' } -AutoSize -Wrap | Out-String
        Write-Verbose -Message "##### Calling : [$CmdletName]"

        # RegEx Pattern
        [string]$MSIProductCodeRegExPattern = '^(\{{0,1}([0-9a-fA-F]){8}-([0-9a-fA-F]){4}-([0-9a-fA-F]){4}-([0-9a-fA-F]){4}-([0-9a-fA-F]){12}\}{0,1})$'
    }
    Process {
        # Enumerate installed applications from the registry for applications that have a "DisplayName" property
        $RegKeyApplication  = @()
        $RegKeyApplications = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall')
        ForEach ($RegKey in $RegKeyApplications) {
            If (Test-Path -LiteralPath $RegKey -ErrorAction 'SilentlyContinue') {
                $InstalledApps = Get-ChildItem -LiteralPath $RegKey -ErrorAction 'SilentlyContinue'
                ForEach ($InstalledApp in $InstalledApps) {
                    Try {
                        $RegKeyApplicationProps = Get-ItemProperty -LiteralPath $InstalledApp.PSPath -ErrorAction 'Stop'
                        If ($RegKeyApplicationProps.DisplayName) {
                            $RegKeyApplication += $RegKeyApplicationProps
                        }
                    }
                    Catch {
                        Continue
                    }
                }
            }
        }

        # Create a sanitised object with the desired properties for the installed applications
        $InstalledApplication = @()
        ForEach ($RegKeyApp in $RegKeyApplication) {
            # Bypass Updates
            If (-not $IncludeUpdatesAndHotfixes) {
                If ($RegKeyApp.DisplayName -match '(?i)kb\d+')         { Continue }
                If ($RegKeyApp.DisplayName -match 'Cumulative Update') { Continue }
                If ($RegKeyApp.DisplayName -match 'Security Update')   { Continue }
                If ($RegKeyApp.DisplayName -match 'Hotfix')            { Continue }
            }

            # Remove problematic characters
            [string]$AppDisplayName    = $RegKeyApp.DisplayName    -replace '[^\u001F-\u007F]',''
            [string]$AppDisplayVersion = $RegKeyApp.DisplayVersion -replace '[^\u001F-\u007F]',''
            [string]$AppPublisher      = $RegKeyApp.Publisher      -replace '[^\u001F-\u007F]',''

            ## Determine if application is a 64-bit application
            [boolean]$Is64BitApp = If (([Environment]::Is64BitOperatingSystem -eq $true) -and ($RegKeyApp.PSPath -notmatch '^Microsoft\.PowerShell\.Core\\Registry::HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node')) { $true } Else { $false }

            # Verify that there is a match with the product code passed to the script
            If ($ProductCode) {
                ForEach ($Application in $ProductCode) {
                    If ($RegKeyApp.PSChildName -match [regex]::Escape($Application)) {
                        Write-Verbose -Message "Found installed application [$AppDisplayName] version [$AppDisplayVersion] matching product code [$Application]"
                        $InstalledApplication += New-Object -TypeName 'PSObject' -Property @{
                            UninstallSubkey    = $RegKeyApp.PSChildName
                            ProductCode        = If ($RegKeyApp.PSChildName -match $MSIProductCodeRegExPattern) { $RegKeyApp.PSChildName } Else { [string]::Empty }
                            DisplayName        = $AppDisplayName
                            DisplayVersion     = $AppDisplayVersion
                            UninstallString    = $RegKeyApp.UninstallString
                            InstallSource      = $RegKeyApp.InstallSource
                            InstallLocation    = $RegKeyApp.InstallLocation
                            InstallDate        = $RegKeyApp.InstallDate
                            Publisher          = $AppPublisher
                            Is64BitApplication = $Is64BitApp
                        }
                    }
                }
            }

            # Verify that there is a match with the application name(s) passed to the script
            If ($Name) {
                ForEach ($Application in $Name) {
                    $ApplicationMatched = $false
                    If ($Exact) {
                        # Check for an exact application name match
                        If ($RegKeyApp.DisplayName -eq $Application) {
                            $ApplicationMatched = $true
                            Write-Verbose -Message "Found installed application [$AppDisplayName] version [$AppDisplayVersion] using exact name matching for search term [$Application]"
                        }
                    }
                    # Check for a regex application name match
                    ElseIf ($RegKeyApp.DisplayName -match [regex]::Escape($Application)) {
                        $ApplicationMatched = $true
                        Write-Verbose -Message "Found installed application [$AppDisplayName] version [$AppDisplayVersion] using regex matching for search term [$Application]"
                    }

                    If ($ApplicationMatched) {
                        $InstalledApplication += New-Object -TypeName 'PSObject' -Property @{
                            UninstallSubkey    = $RegKeyApp.PSChildName
                            ProductCode        = If ($RegKeyApp.PSChildName -match $MSIProductCodeRegExPattern) { $RegKeyApp.PSChildName } Else { [string]::Empty }
                            DisplayName        = $AppDisplayName
                            DisplayVersion     = $AppDisplayVersion
                            UninstallString    = $RegKeyApp.UninstallString
                            InstallSource      = $RegKeyApp.InstallSource
                            InstallLocation    = $RegKeyApp.InstallLocation
                            InstallDate        = $RegKeyApp.InstallDate
                            Publisher          = $AppPublisher
                            Is64BitApplication = $Is64BitApp
                        }
                    }
                }
            }

            # Verify that a full search is requested
            If ((-not $Name) -and (-not $ProductCode) -and (-not $Exact)) {
                $InstalledApplication += New-Object -TypeName 'PSObject' -Property @{
                    UninstallSubkey    = $RegKeyApp.PSChildName
                    ProductCode        = If ($RegKeyApp.PSChildName -match $MSIProductCodeRegExPattern) { $RegKeyApp.PSChildName } Else { [string]::Empty }
                    DisplayName        = $AppDisplayName
                    DisplayVersion     = $AppDisplayVersion
                    UninstallString    = $RegKeyApp.UninstallString
                    InstallSource      = $RegKeyApp.InstallSource
                    InstallLocation    = $RegKeyApp.InstallLocation
                    InstallDate        = $RegKeyApp.InstallDate
                    Publisher          = $AppPublisher
                    Is64BitApplication = $Is64BitApp
                }
            }
        }

        # Output Object
        Write-Output -InputObject $InstalledApplication
    }
    End {
        # Verbose Logging
        Write-Verbose -Message "##### Ending : [$CmdletName]"
    }
}


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
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false)]
        [ValidateSet('Install','Uninstall','Patch','Repair')]
        [string]$Action = 'Install',
        [Parameter(Mandatory=$true)]
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
            Write-Verbose -Message 'Resolve product code to a publisher, application name, and version'
            [psobject]$ProductCodeNameVersion = Get-InstalledApplication -ProductCode $path | Select-Object -Property 'Publisher', 'DisplayName', 'DisplayVersion' -First 1 -ErrorAction 'SilentlyContinue'
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
            [string]$MSIProductCode = $path
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


Function Start-MSP {
    <#
    .SYNOPSIS
        Execute MSP Patch on applicable systems
    .DESCRIPTION
        Reads SummaryInfo targeted product codes in MSP file and determines if the MSP file applies to any installed products
        If a valid installed product is found, the Start-MSI function is triggered to patch the installation
    .PARAMETER Path
        The path to the MSP file
    .PARAMETER PassThru
        Returns ExitCode, STDOut, and STDErr output from the process
    .PARAMETER ContinueOnError
        Continue if an exit code is returned by msiexec that is not recognized. Default is: $true
    .EXAMPLE
        Start-MSP -Path 'C:\Path\To\File\Adobe_Acrobat_DC_x64_EN.msp'
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateScript({ ('.msp' -contains [IO.Path]::GetExtension($_))} )]
        [string]$Path,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [switch]$PassThru = $false,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [boolean]$ContinueOnError = $true
    )

    Begin {
        # Verbose Logging
        [string]$CmdletName  = $MyInvocation.MyCommand.Name
        [string]$CmdletParam = $PSBoundParameters | Format-Table -Property @{ Label = 'Parameter'; Expression = { "[-$($_.Key)]" } }, @{ Label = 'Value'; Expression = { $_.Value }; Alignment = 'Left' } -AutoSize -Wrap | Out-String
        Write-Verbose -Message "##### Calling : [$CmdletName]"
    }
    Process {
        # Set the full path to the MSP
        If (Test-Path -LiteralPath $Path -ErrorAction 'SilentlyContinue') {
            [string]$mspFile = (Get-Item -LiteralPath $Path).FullName
        }
        Else {
            Throw "Failed to find MSP file [$Path]"
        }

        # Check MSP is applicable to the system
        Write-Verbose -Message 'Checking MSP file for valid product codes'
        [boolean]$IsMSPNeeded = $false
        $Installer = New-Object -ComObject WindowsInstaller.Installer
        $Database = $Installer.GetType().InvokeMember(“OpenDatabase”, “InvokeMethod”, $Null, $Installer, $($mspFile,([int32]32)))
        [__comobject]$SummaryInformation = Get-ObjectProperty -InputObject $Database -PropertyName 'SummaryInformation'
        [hashtable]$SummaryInfoProperty = @{}
        $InstallerProperties = (Get-ObjectProperty -InputObject $SummaryInformation -PropertyName 'Property' -ArgumentList @(7)).Split(";")
        Write-Verbose -Message 'Checking System for MSP product codes'
        ForEach ($FormattedProductCode in $InstallerProperties) {
            [psobject]$MSIInstalled = Get-InstalledApplication -ProductCode $FormattedProductCode -Verbose:$False
            If ($MSIInstalled) {
                Write-Verbose -Message "Found Applicable Product : [$($MSIInstalled.ProductCode)] - [$($MSIInstalled.DisplayName)]"
                [boolean]$IsMSPNeeded = $true
            }
        }
        Try { $null = [Runtime.Interopservices.Marshal]::ReleaseComObject($SummaryInformation) } Catch {}
        Try { $null = [Runtime.Interopservices.Marshal]::ReleaseComObject($DataBase) } Catch {}
        Try { $null = [Runtime.Interopservices.Marshal]::ReleaseComObject($Installer) } Catch {}

        # Install MSP if required
        If ($IsMSPNeeded) {
            Start-MSI -Action Patch -Path $Path -PassThru $PassThru -ContinueOnError $ContinueOnError
        }
        Else {
            If ($ContinueOnError) {
                Write-Warning -Message "MSP is not applicable to this System : [$(Split-Path -Path $Path -Leaf)]"
            }
            Else {
                Throw "MSP is not applicable to this System : [$(Split-Path -Path $Path -Leaf)]"
            }
        }
    }
    End {
        # Verbose Logging
        Write-Verbose -Message "##### Ending : [$CmdletName]"
    }
}


Function Start-EXE {
    <#
    .SYNOPSIS
        Execute a process with optional arguments
    .DESCRIPTION
        Executes a process with optional arguments
    .PARAMETER Path
        Full path to the file to be executed
    .PARAMETER Parameters
        Arguments to be passed to the executable
    .PARAMETER IgnoreExitCodes
        List of exit codes to ignore
    .PARAMETER PassThru
        Returns ExitCode, STDOut, and STDErr output from the process
    .PARAMETER ContinueOnError
        Continue if an exit code is returned by msiexec that is not recognized. Default is: $false
    .EXAMPLE
        Start-EXE -Path 'C:\Path\To\File\7z1604-x64.exe' -Parameters "/S"
    .EXAMPLE
        Start-EXE -Path 'C:\Path\To\File\7z1604-x64.exe' -Parameters "/S" -IgnoreExitCodes '1,2'
    .EXAMPLE
        Start-EXE -Path 'C:\Path\To\File\setup.exe' -Parameters "/s /v`"ALLUSERS=1 /qn /L* \`"$LogDir\$LogName.log`"`""
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [string]$Path,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [string[]]$Parameters,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [string]$IgnoreExitCodes,
        [Parameter(Mandatory=$false)]
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

        # Set Time to wait for msiexec to finish
        [timespan]$MsiExecWaitTime = $(New-TimeSpan -Seconds 600)
    }
    Process {
        Try {
            $private:ReturnCode = $null

            # Validate and find the fully qualified path for the $Path variable
            If (([IO.Path]::IsPathRooted($Path)) -and ([IO.Path]::HasExtension($Path))) {
                If (-not (Test-Path -LiteralPath $Path -PathType 'Leaf' -ErrorAction 'Stop')) {
                    Throw "File [$Path] not found"
                }
                Write-Verbose -Message "[$Path] is a valid fully qualified path"
            }
            Else {
                # Add current location to PATH environmental variable
                [string]$CurrentFolder = (Get-Location -PSProvider 'FileSystem').Path
                $env:PATH = $CurrentFolder + ';' + $env:PATH
                # Get the fully qualified path from and revert PATH environmental variable
                [string]$FullyQualifiedPath = Get-Command -Name $Path -CommandType 'Application' -TotalCount 1 -Syntax -ErrorAction 'Stop'
                $env:PATH = $env:PATH -replace [regex]::Escape($CurrentFolder + ';'), ''
                If ($FullyQualifiedPath) {
                    Write-Verbose -Message "[$Path] successfully resolved to fully qualified path [$FullyQualifiedPath]"
                    $Path = $FullyQualifiedPath
                }
                Else {
                    Throw "[$Path] contains an invalid path or file name"
                }
            }

            # Set the working directory
            $WorkingDirectory = Split-Path -Path $Path -Parent -ErrorAction 'Stop'

            # If MSI install, check to see if the MSI installer service is available
            If ($Path -match 'msiexec') {
                [boolean]$MsiExecAvailable = Test-IsMutexAvailable -MutexName 'Global\_MSIExecute' -MutexWaitTimeInMilliseconds $MsiExecWaitTime.TotalMilliseconds
                Start-Sleep -Seconds 1
                If (-not $MsiExecAvailable) {
                    # Default MSI exit code for install already in progress
                    [int32]$returnCode = 1618
                    Throw 'Please complete in progress MSI installation before proceeding with this install'
                }
            }

            Try {
                # Disable Zone checking to prevent warnings when running executables
                $env:SEE_MASK_NOZONECHECKS = 1

                # Allow capture of exceptions from .NET methods
                $private:previousErrorActionPreference = $ErrorActionPreference
                $ErrorActionPreference = 'Stop'

                # Define process
                $ProcessStartInfo = New-Object -TypeName 'System.Diagnostics.ProcessStartInfo' -ErrorAction 'Stop'
                $ProcessStartInfo.FileName = $Path
                $ProcessStartInfo.WorkingDirectory = $WorkingDirectory
                $ProcessStartInfo.UseShellExecute = $false
                $ProcessStartInfo.ErrorDialog = $false
                $ProcessStartInfo.RedirectStandardOutput = $true
                $ProcessStartInfo.RedirectStandardError = $true
                $ProcessStartInfo.CreateNoWindow = $false
                $ProcessStartInfo.WindowStyle = 'Hidden'
                If ($Parameters)  { $ProcessStartInfo.Arguments = $Parameters }
                $Process = New-Object -TypeName 'System.Diagnostics.Process' -ErrorAction 'Stop'
                $Process.StartInfo = $ProcessStartInfo

                # Add event handler to capture process's standard output redirection
                [scriptblock]$ProcessEventHandler = { If (-not [string]::IsNullOrEmpty($EventArgs.Data)) { $Event.MessageData.AppendLine($EventArgs.Data) } }
                $stdOutBuilder = New-Object -TypeName 'System.Text.StringBuilder' -ArgumentList ''
                $stdOutEvent   = Register-ObjectEvent -InputObject $Process -Action $ProcessEventHandler -EventName 'OutputDataReceived' -MessageData $stdOutBuilder -ErrorAction 'Stop'

                # Log Initialisation
                Write-Verbose -Message "Working Directory : $WorkingDirectory"
                If ($Parameters) {
                    If ($Parameters -match '-Command \&') {
                        Write-Verbose -Message "Executing : $Path [PowerShell ScriptBlock]"
                    }
                    Else {
                        Write-Verbose -Message "Executing : $Path $Parameters"
                    }
                }
                Else {
                    Write-Verbose -Message "Executing : $Path"
                }
                # Start Process
                [boolean]$ProcessStarted = $Process.Start()
                $Process.BeginOutputReadLine()
                $stdErr = $($Process.StandardError.ReadToEnd()).ToString() -replace $null,''

                # Wait for the process to exit
                $Process.WaitForExit()
                While (-not ($Process.HasExited)) {
                    $Process.Refresh(); Start-Sleep -Seconds 1
                }

                # Get the exit code for the process
                Try {
                    [int32]$ReturnCode = $Process.ExitCode
                }
                Catch [System.Management.Automation.PSInvalidCastException] {
                    # Catch exit codes that are out of int32 range
                    [int32]$ReturnCode = 60013
                }

                # Unregister standard output event and retrieve process output
                If ($stdOutEvent) {
                    Unregister-Event -SourceIdentifier $stdOutEvent.Name -ErrorAction 'Stop'; $stdOutEvent = $null
                }
                $stdOut = $stdOutBuilder.ToString() -replace $null,''

                If ($stdErr.Length -gt 0) {
                    Write-Warning -Message "Error : $stdErr"
                }
            }
            Finally {
                ## Make sure the standard output event is unregistered
                If ($stdOutEvent) { Unregister-Event -SourceIdentifier $stdOutEvent.Name -ErrorAction 'Stop'}

                ## Free resources associated with the process
                If ($Process) { $Process.Close() }

                ## Enable Zone checking
                Remove-Item -LiteralPath 'env:SEE_MASK_NOZONECHECKS' -ErrorAction 'SilentlyContinue'

                If ($private:PreviousErrorActionPreference) {
                    $ErrorActionPreference = $private:PreviousErrorActionPreference
                }
            }

            # Check to see if exit codes should be ignored
            $ignoreExitCodeMatch = $false
            If ($ignoreExitCodes) {
                # Split the processes on a comma
                [int32[]]$ignoreExitCodesArray = $ignoreExitCodes -split ','
                ForEach ($ignoreCode in $ignoreExitCodesArray) {
                    If ($returnCode -eq $ignoreCode) { $ignoreExitCodeMatch = $true }
                }
            }
            If ($ContinueOnError) {
                $ignoreExitCodeMatch = $true
            }

            If ($PassThru) {
                Write-Verbose -Message "Execution completed with exit code [$returnCode]"
                [psobject]$ExecutionResults = New-Object -TypeName 'PSObject' -Property @{ ExitCode = $ReturnCode; StdOut = $stdOut; StdErr = $stdErr }
                Write-Output -InputObject $ExecutionResults
            }
            ElseIf ($ignoreExitCodeMatch) {
                Write-Verbose -Message "Execution complete and the exit code [$returncode] is being ignored"
            }
            ElseIf (($ReturnCode -eq 3010) -or ($ReturnCode -eq 1641)) {
                Write-Verbose -Message "Execution : Completed successfully with exit code [$ReturnCode]. A reboot is required"
                Set-Variable -Name 'msiRebootDetected' -Value $true -Scope 'Script'
            }
            ElseIf (($ReturnCode -eq 1605) -and ($Path -match 'msiexec')) {
                Write-Warning -Message "Execution : Failed with exit code [$ReturnCode] because the product is not currently installed"
            }
            ElseIf (($ReturnCode -eq -2145124329) -and ($Path -match 'wusa')) {
                Write-Warning -Message "Execution : Failed with exit code [$ReturnCode] because the Windows Update is not applicable to this system"
            }
            ElseIf (($ReturnCode -eq 17025) -and ($Path -match 'fullfile')) {
                Write-Warning -Message "Execution : Failed with exit code [$ReturnCode] because the Office Update is not applicable to this system"
            }
            ElseIf ($ReturnCode -eq 0) {
                Write-Verbose -Message "Execution : Completed successfully with exit code [$ReturnCode]"
            }
            Else {
                Write-Warning -Message "Execution : Failed with exit code [$ReturnCode]"
            }
        }
        Catch {
            Write-Warning -Message "Execution : Completed with exit code [$ReturnCode] - Function failed"
            If ($PassThru) {
                [psobject]$ExecutionResults = New-Object -TypeName 'PSObject' -Property @{ ExitCode = $returnCode; StdOut = If ($stdOut) { $stdOut } Else { '' }; StdErr = If ($stdErr) { $stdErr } Else { '' } }
                Write-Output -InputObject $ExecutionResults
            }
        }
    }
    End {
        # Verbose Logging
        Write-Verbose -Message "##### Ending : [$CmdletName]"
    }
}


Function Remove-MSIApplication {
    <#
    .SYNOPSIS
        Removes all MSI applications matching the specified application name
    .DESCRIPTION
        Removes all MSI applications matching the specified application name
        Enumerates the registry for installed applications matching the specified application name and uninstalls that application using the product code, provided the uninstall string matches "msiexec"
    .PARAMETER Name
        The name of the application to uninstall. Performs a regex match on the application display name by default
    .PARAMETER Exact
        Specifies that the named application must be matched using the exact name
    .PARAMETER CustomParameters
        Overrides the default uninstall parameters. Uninstall default parameters are : "REBOOT=ReallySuppress /QN"
    .PARAMETER FilterApplication
        Two-dimensional array that contains one or more (property, value, match-type) sets that should be used to filter the list of results returned by Get-InstalledApplication to only those that should be uninstalled
        Properties that can be filtered upon: ProductCode, DisplayName, DisplayVersion, UninstallString, InstallSource, InstallLocation, InstallDate, Publisher, Is64BitApplication
    .PARAMETER ExcludeFromUninstall
        Two-dimensional array that contains one or more (property, value, match-type) sets that should be excluded from uninstall if found
        Properties that can be excluded: ProductCode, DisplayName, DisplayVersion, UninstallString, InstallSource, InstallLocation, InstallDate, Publisher, Is64BitApplication
    .PARAMETER PassThru
        Returns ExitCode, STDOut, and STDErr output from the process
    .PARAMETER ContinueOnError
        Continue if an exit code is returned by msiexec that is not recognized. Default is: $true
    .EXAMPLE
        Remove-MSIApplication -Name 'Adobe Flash'
        Removes all versions of software that match the name "Adobe Flash"
    .EXAMPLE
        Remove-MSIApplication -Name 'Adobe'
        Removes all versions of software that match the name "Adobe"
    .EXAMPLE
        Remove-MSIApplications -Name 'Java 8' -FilterApplication ('Is64BitApplication', $false, 'Exact'),('Publisher', 'Oracle Corporation', 'Exact')
        Removes all versions of software that match the name "Java 8" where the software is 32-bits and the publisher is "Oracle Corporation"
    .EXAMPLE
        Remove-MSIApplications -Name 'Java 8' -FilterApplication (,('Publisher', 'Oracle Corporation', 'Exact')) -ExcludeFromUninstall (,('DisplayName', 'Java 8 Update 45', 'RegEx'))
        Removes all versions of software that match the name "Java 8" and also have "Oracle Corporation" as the Publisher; however, it will not uninstall "Java 8 Update 45"
        NOTE: if only specifying a single row in the two-dimensional arrays, the array must have the extra parentheses and leading comma as per the example
    .EXAMPLE
        Remove-MSIApplications -Name 'Java 8' -ExcludeFromUninstall (,('DisplayName', 'Java 8 Update 45', 'RegEx'))
        Removes all versions of software that match the name "Java 8"; however, it does not uninstall "Java 8 Update 45" of the software.
        NOTE: if only specifying a single row in the two-dimensional array, the array must have the extra parentheses and leading comma as in this example
    .EXAMPLE
        Remove-MSIApplications -Name 'Java 8 Update' -ExcludeFromUninstall
            ('Is64BitApplication', $true, 'Exact'),
            ('DisplayName', 'Java 8 Update 45', 'Exact'),
            ('DisplayName', 'Java 8 Update 4*', 'WildCard'),
            ('DisplayName', 'Java 8 Update 45', 'RegEx')
        Removes all versions of software that match the name "Java 8 Update"; however, it does not uninstall 64-bit versions of the software, Update 45 of the software, or any Update that starts with 4.
    .NOTES
        Information on -FilterApplication or -ExcludeFromUninstall parameters: http://blogs.msdn.com/b/powershell/archive/2007/01/23/array-literals-in-powershell.aspx
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [string]$Name,
        [Parameter(Mandatory=$false)]
        [switch]$Exact = $false,
        [Parameter(Mandatory=$false)]
        [Alias('Arguments')]
        [ValidateNotNullorEmpty()]
        [string]$CustomParameters,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [array]$FilterApplication = @(@()),
        [Parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [array]$ExcludeFromUninstall = @(@()),
        [Parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [switch]$PassThru = $false,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [boolean]$ContinueOnError = $true
    )

    Begin {
        # Verbose Logging
        [string]$CmdletName  = $MyInvocation.MyCommand.Name
        [string]$CmdletParam = $PSBoundParameters | Format-Table -Property @{ Label = 'Parameter'; Expression = { "[-$($_.Key)]" } }, @{ Label = 'Value'; Expression = { $_.Value }; Alignment = 'Left' } -AutoSize -Wrap | Out-String
        Write-Verbose -Message "##### Calling : [$CmdletName]"
    }
    Process {
        # Build the hashtable with the options that will be passed to Get-InstalledApplication using splatting
        [hashtable]$GetInstalledApplicationSplat = @{ Name = $Name }
        If ($Exact) { $GetInstalledApplicationSplat.Add( 'Exact', $Exact) }
        [psobject[]]$InstalledApplications = Get-InstalledApplication @GetInstalledApplicationSplat
        Write-Verbose -Message "Found [$($InstalledApplications.Count)] application(s) that matched the specified criteria [$Name]"

        # Filter the results from Get-InstalledApplication
        [Collections.ArrayList]$RemoveMSIApplications = New-Object -TypeName 'System.Collections.ArrayList'
        If (($null -ne $InstalledApplications) -and ($InstalledApplications.Count)) {
            ForEach ($InstalledApplication in $InstalledApplications) {
                If ($InstalledApplication.UninstallString -notmatch 'msiexec') {
                    Write-Warning -Message "Skipping removal of application [$($InstalledApplication.DisplayName)] because uninstall string [$($InstalledApplication.UninstallString)] does not match `"msiexec`""
                    Continue
                }
                If ([string]::IsNullOrEmpty($InstalledApplication.ProductCode)) {
                    Write-Warning -Message "Skipping removal of application [$($InstalledApplication.DisplayName)] because unable to discover MSI ProductCode from application's registry Uninstall subkey [$($InstalledApplication.UninstallSubkey)]"
                    Continue
                }

                # Filter the results from Get-InstalledApplication to only those that should be uninstalled
                If (($null -ne $FilterApplication) -and ($FilterApplication.Count)) {
                    Write-Verbose -Message "Filter the results to only those that should be uninstalled as specified in parameter [-FilterApplication]"
                    [boolean]$AddAppToRemoveList = $false
                    ForEach ($Filter in $FilterApplication) {
                        If ($Filter[2] -eq 'RegEx') {
                            If ($installedApplication.($Filter[0]) -match [regex]::Escape($Filter[1])) {
                                [boolean]$AddAppToRemoveList = $true
                                Write-Verbose -Message "Preserve removal of application [$($InstalledApplication.DisplayName) $($InstalledApplication.Version)] because of regex match against [-FilterApplication] criteria"
                            }
                        }
                        ElseIf ($Filter[2] -eq 'WildCard') {
                            If ($installedApplication.($Filter[0]) -like $Filter[1]) {
                                [boolean]$AddAppToRemoveList = $true
                                Write-Verbose -Message "Preserve removal of application [$($InstalledApplication.DisplayName) $($InstalledApplication.Version)] because of wildcard match against [-FilterApplication] criteria"
                            }
                        }
                        ElseIf ($Filter[2] -eq 'Exact') {
                            If ($installedApplication.($Filter[0]) -eq $Filter[1]) {
                                [boolean]$AddAppToRemoveList = $true
                                Write-Verbose -Message "Preserve removal of application [$($InstalledApplication.DisplayName) $($InstalledApplication.Version)] because of exact match against [-FilterApplication] criteria"
                            }
                        }
                    }
                }
                Else {
                    [boolean]$AddAppToRemoveList = $true
                }

                # Filter the results from Get-InstalledApplication to remove those that should never be uninstalled
                If (($null -ne $ExcludeFromUninstall) -and ($ExcludeFromUninstall.Count)) {
                    Write-Verbose -Message "Filter the results to only those that should be uninstalled as specified in parameter [-ExcludeFromUninstall]"
                    ForEach ($Exclude in $ExcludeFromUninstall) {
                        If ($Exclude[2] -eq 'RegEx') {
                            If ($installedApplication.($Exclude[0]) -match [regex]::Escape($Exclude[1])) {
                                [boolean]$AddAppToRemoveList = $false
                                Write-Verbose -Message "Skipping removal of application [$($InstalledApplication.DisplayName) $($InstalledApplication.Version)] because of regex match against [-ExcludeFromUninstall] criteria"
                            }
                        }
                        ElseIf ($Exclude[2] -eq 'WildCard') {
                            If ($installedApplication.($Exclude[0]) -like $Exclude[1]) {
                                [boolean]$AddAppToRemoveList = $false
                                Write-Verbose -Message "Skipping removal of application [$($InstalledApplication.DisplayName) $($InstalledApplication.Version)] because of wildcard match against [-ExcludeFromUninstall] criteria"
                            }
                        }
                        ElseIf ($Exclude[2] -eq 'Exact') {
                            If ($installedApplication.($Exclude[0]) -eq $Exclude[1]) {
                                [boolean]$AddAppToRemoveList = $false
                                Write-Verbose -Message "Skipping removal of application [$($InstalledApplication.DisplayName) $($InstalledApplication.Version)] because of exact match against [-ExcludeFromUninstall] criteria"
                            }
                        }
                    }
                }

                If ($AddAppToRemoveList) {
                    Write-Verbose -Message "Adding application to list for removal: [$($InstalledApplication.DisplayName) $($InstalledApplication.Version)]"
                    $RemoveMSIApplications.Add($InstalledApplication) | Out-Null
                }
            }
        }

        # Build the hashtable with the options that will be passed to Start-MSI using splatting
        [hashtable]$ExecuteMSISplat =  @{ Action = 'Uninstall'; Path = '' }
        If ($CustomParameters) { $ExecuteMSISplat.Add( 'CustomParameters', $CustomParameters) }
        If ($PassThru) { $ExecuteMSISplat.Add( 'PassThru', $PassThru) }
        If ($ContinueOnError) { $ExecuteMSISplat.Add( 'ContinueOnError', $ContinueOnError) }

        # Remove the MSI Applications
        If (($null -ne $RemoveMSIApplications) -and ($RemoveMSIApplications.Count)) {
            ForEach ($RemoveMSIApplication in $RemoveMSIApplications) {
                Write-Verbose -Message "Remove application [$($RemoveMSIApplication.DisplayName) $($RemoveMSIApplication.Version)]"
                $ExecuteMSISplat.Path = $RemoveMSIApplication.ProductCode
                If ($PassThru) {
                    [psobject[]]$ExecuteResults += Start-MSI @ExecuteMSISplat
                }
                Else {
                    Start-MSI @ExecuteMSISplat
                }
            }
        }
        Else {
            Write-Verbose -Message 'No applications found for removal'
        }
    }
    End {
        If ($PassThru) { Write-Output -InputObject $ExecuteResults }
        # Verbose Logging
        Write-Verbose -Message "##### Ending : [$CmdletName]"
    }
}


Function Invoke-ObjectMethod {
    <#
    .SYNOPSIS
        Invoke method on an object
    .DESCRIPTION
        Invoke method on an object with or without named parameters
    .PARAMETER InputObject
        Specifies an object which has methods that can be invoked
    .PARAMETER MethodName
        Specifies the name of a method to invoke
    .PARAMETER ArgumentList
        Argument to pass to the method being executed. Allows execution of method without specifying named parameters
    .PARAMETER Parameter
        Argument to pass to the method being executed. Allows execution of method by using named parameters
    .EXAMPLE
        $ShellApp = New-Object -ComObject 'Shell.Application'
        $null = Invoke-ObjectMethod -InputObject $ShellApp -MethodName 'MinimizeAll'
        Minimizes all windows
    .EXAMPLE
        $ShellApp = New-Object -ComObject 'Shell.Application'
        $null = Invoke-ObjectMethod -InputObject $ShellApp -MethodName 'Explore' -Parameter @{'vDir'='C:\Windows'}
        Opens the "C:\Windows" folder in a Windows Explorer window
    #>

    [CmdletBinding(DefaultParameterSetName='Positional')]
    Param (
        [Parameter(Mandatory=$true,Position=0)]
        [ValidateNotNull()]
        [object]$InputObject,
        [Parameter(Mandatory=$true,Position=1)]
        [ValidateNotNullorEmpty()]
        [string]$MethodName,
        [Parameter(Mandatory=$false,Position=2,ParameterSetName='Positional')]
        [object[]]$ArgumentList,
        [Parameter(Mandatory=$true,Position=2,ParameterSetName='Named')]
        [ValidateNotNull()]
        [hashtable]$Parameter
    )

    Begin {}
    Process {
        If ($PSCmdlet.ParameterSetName -eq 'Named') {
            # Invoke method by using parameter names
            Write-Output -InputObject $InputObject.GetType().InvokeMember($MethodName, [Reflection.BindingFlags]::InvokeMethod, $null, $InputObject, ([object[]]($Parameter.Values)), $null, $null, ([string[]]($Parameter.Keys)))
        }
        Else {
            # Invoke method without using parameter names
            Write-Output -InputObject $InputObject.GetType().InvokeMember($MethodName, [Reflection.BindingFlags]::InvokeMethod, $null, $InputObject, $ArgumentList, $null, $null, $null)
        }
    }
    End {}
}


Function Get-ObjectProperty {
    <#
    .SYNOPSIS
        Get a property from an object
    .DESCRIPTION
        Get a property from an object
    .PARAMETER InputObject
        Specifies an object which has properties that can be retrieved
    .PARAMETER PropertyName
        Specifies the name of a property to retrieve
    .PARAMETER ArgumentList
        Argument to pass to the property being retrieved
    .EXAMPLE
        Get-ObjectProperty -InputObject $Record -PropertyName 'StringData' -ArgumentList @(1)
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true,Position=0)]
        [ValidateNotNull()]
        [object]$InputObject,
        [Parameter(Mandatory=$true,Position=1)]
        [ValidateNotNullorEmpty()]
        [string]$PropertyName,
        [Parameter(Mandatory=$false,Position=2)]
        [object[]]$ArgumentList
    )

    Begin {}
    Process {
        ## Get Object property
        Write-Output -InputObject $InputObject.GetType().InvokeMember($PropertyName, [Reflection.BindingFlags]::GetProperty, $null, $InputObject, $ArgumentList, $null, $null, $null)
    }
    End {}
}


Function Test-IsMutexAvailable {
    <#
    .SYNOPSIS
        Wait, up to a timeout value, to check if current thread is able to acquire an exclusive lock on a system mutex
    .DESCRIPTION
        A mutex can be used to serialize applications and prevent multiple instances from being opened at the same time
        Wait, up to a timeout (default is 1 millisecond), for the mutex to become available for an exclusive lock
    .PARAMETER MutexName
        The name of the system mutex
    .PARAMETER MutexWaitTime
        The number of milliseconds the current thread should wait to acquire an exclusive lock of a named mutex. Default is: 1 millisecond
        A wait time of -1 milliseconds means to wait indefinitely. A wait time of zero does not acquire an exclusive lock but instead tests the state of the wait handle and returns immediately.
    .EXAMPLE
        Test-IsMutexAvailable -MutexName 'Global\_MSIExecute'
    .EXAMPLE
        Test-IsMutexAvailable -MutexName 'Global\_MSIExecute' -MutexWaitTimeInMilliseconds (New-TimeSpan -Seconds 60).TotalMilliseconds
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateLength(1,260)]
        [string]$MutexName,
        [Parameter(Mandatory=$false)]
        [ValidateScript({ ($_ -ge -1) -and ($_ -le [int32]::MaxValue) })]
        [int32]$MutexWaitTimeInMilliseconds = 1
    )

    Begin {
        # Verbose Logging
        [string]$CmdletName  = $MyInvocation.MyCommand.Name
        [string]$CmdletParam = $PSBoundParameters | Format-Table -Property @{ Label = 'Parameter'; Expression = { "[-$($_.Key)]" } }, @{ Label = 'Value'; Expression = { $_.Value }; Alignment = 'Left' } -AutoSize -Wrap | Out-String
        Write-Verbose -Message "##### Calling : [$CmdletName]"

        # Initialise Variables
        [timespan]$MutexWaitTime = [timespan]::FromMilliseconds($MutexWaitTimeInMilliseconds)
        If ($MutexWaitTime.TotalMinutes -ge 1) {
            [string]$WaitLogMsg = "$($MutexWaitTime.TotalMinutes) minute(s)"
        }
        ElseIf ($MutexWaitTime.TotalSeconds -ge 1) {
            [string]$WaitLogMsg = "$($MutexWaitTime.TotalSeconds) second(s)"
        }
        Else {
            [string]$WaitLogMsg = "$($MutexWaitTime.Milliseconds) millisecond(s)"
        }
        [boolean]$IsUnhandledException      = $false
        [boolean]$IsMutexFree               = $false
        [Threading.Mutex]$OpenExistingMutex = $null
    }
    Process {
        Write-Verbose -Message "Check to see if mutex [$MutexName] is available. Wait up to [$WaitLogMsg] for the mutex to become available."
        Try {
            # Allow capture of exceptions from .NET methods
            $private:PreviousErrorActionPreference = $ErrorActionPreference
            $ErrorActionPreference = 'Stop'

            # Open the specified named mutex, if it already exists, without acquiring an exclusive lock on it.
            [Threading.Mutex]$OpenExistingMutex = [Threading.Mutex]::OpenExisting($MutexName)
            # Attempt to acquire an exclusive lock on the mutex for specified timespan.
            $IsMutexFree = $OpenExistingMutex.WaitOne($MutexWaitTime, $false)
        }
        Catch [Threading.WaitHandleCannotBeOpenedException] {
            # The mutex does not exist
            $IsMutexFree = $true
        }
        Catch [ObjectDisposedException] {
            # Mutex was disposed between opening it and attempting to wait on it
            $IsMutexFree = $true
        }
        Catch [UnauthorizedAccessException] {
            # The named mutex exists, but the user does not have the security access required to use it
            $IsMutexFree = $false
        }
        Catch [Threading.AbandonedMutexException] {
            # The wait completed because a thread exited without releasing a mutex
            $IsMutexFree = $true
        }
        Catch {
            $IsUnhandledException = $true
            # Return $true, to signify that mutex is available, because function was unable to successfully complete a check due to an unhandled exception. Default is to err on the side of the mutex being available on a hard failure
            Write-Verbose -Message "Unable to check if mutex [$MutexName] is available due to an unhandled exception. Will default to return value of [$true]"
            $IsMutexFree = $true
        }
        Finally {
            If ($IsMutexFree) {
                If (-not $IsUnhandledException) {
                    Write-Verbose -Message "Mutex [$MutexName] is available for an exclusive lock."
                }
            }
            Else {
                If ($MutexName -eq 'Global\_MSIExecute') {
                    # Get the command line for the MSI installation in progress
                    Try {
                        [string]$msiInProgressCmdLine = Get-WmiObject -Class 'Win32_Process' -Filter "name = 'msiexec.exe'" -ErrorAction 'Stop' | Where-Object { $_.CommandLine } | Select-Object -ExpandProperty 'CommandLine' | Where-Object { $_ -match '\.msi' } | ForEach-Object { $_.Trim() }
                    }
                    Catch {}
                    Write-Verbose -Message "Mutex [$MutexName] is not available for an exclusive lock because the following MSI installation is in progress [$msiInProgressCmdLine]"
                }
                Else {
                    Write-Verbose -Message "Mutex [$MutexName] is not available because another thread already has an exclusive lock on it."
                }
            }
            If (($null -ne $OpenExistingMutex) -and ($IsMutexFree)) {
                # Release exclusive lock on the mutex
                $null = $OpenExistingMutex.ReleaseMutex()
                $OpenExistingMutex.Close()
            }
            If ($private:PreviousErrorActionPreference) { $ErrorActionPreference = $private:PreviousErrorActionPreference }
        }
    }
    End {
        Write-Output -InputObject $IsMutexFree

        # Verbose Logging
        Write-Verbose -Message "##### Ending : [$CmdletName]"
    }
}


Function Get-MsiTableProperty {
    <#
    .SYNOPSIS
        Get all of the properties from a Windows Installer database table or the Summary Information stream and return as a custom object
    .DESCRIPTION
        Use the Windows Installer object to read all of the properties from a Windows Installer database table or the Summary Information stream
    .PARAMETER Path
        The fully qualified path to a database file. Supports .msi and .msp files
    .PARAMETER TransformPath
        The fully qualified path to a list of MST file(s) which should be applied to the MSI file
    .PARAMETER Table
        The name of the the MSI table from which all of the properties must be retrieved. Default is: 'Property'
    .PARAMETER TablePropertyNameColumnNum
        Specify the table column number which contains the name of the properties. Default is: 1 for MSIs and 2 for MSPs
    .PARAMETER TablePropertyValueColumnNum
        Specify the table column number which contains the value of the properties. Default is: 2 for MSIs and 3 for MSPs
    .EXAMPLE
        Get-MsiTableProperty -Path 'C:\Path\To\File\7z1604-x64.msi' -TransformPath 'C:\Path\To\File\7z1604-x64.mst'
        Retrieve all of the properties from the default 'Property' table
    .EXAMPLE
        Get-MsiTableProperty -Path 'C:\Path\To\File\7z1604-x64.msi' -TransformPath 'C:\Path\To\File\7z1604-x64.mst' -Table 'Property' | Select-Object -ExpandProperty ProductCode
        Retrieve all of the properties from the 'Property' table and then pipe to Select-Object to select the ProductCode property
    #>

    [CmdletBinding(DefaultParameterSetName='TableInfo')]
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateScript({ Test-Path -LiteralPath $_ -PathType 'Leaf' })]
        [string]$Path,
        [Parameter(Mandatory=$false)]
        [ValidateScript({ Test-Path -LiteralPath $_ -PathType 'Leaf' })]
        [string[]]$TransformPath,
        [Parameter(Mandatory=$false,ParameterSetName='TableInfo')]
        [ValidateNotNullOrEmpty()]
        [string]$Table = $(If ([IO.Path]::GetExtension($Path) -eq '.msi') { 'Property' } Else { 'MsiPatchMetadata' }),
        [Parameter(Mandatory=$false,ParameterSetName='TableInfo')]
        [ValidateNotNullorEmpty()]
        [int32]$TablePropertyNameColumnNum = $(If ([IO.Path]::GetExtension($Path) -eq '.msi') { 1 } Else { 2 }),
        [Parameter(Mandatory=$false,ParameterSetName='TableInfo')]
        [ValidateNotNullorEmpty()]
        [int32]$TablePropertyValueColumnNum = $(If ([IO.Path]::GetExtension($Path) -eq '.msi') { 2 } Else { 3 })
    )

    Begin {
        # Verbose Logging
        [string]$CmdletName  = $MyInvocation.MyCommand.Name
        [string]$CmdletParam = $PSBoundParameters | Format-Table -Property @{ Label = 'Parameter'; Expression = { "[-$($_.Key)]" } }, @{ Label = 'Value'; Expression = { $_.Value }; Alignment = 'Left' } -AutoSize -Wrap | Out-String
        Write-Verbose -Message "##### Calling : [$CmdletName]"
    }
    Process {
        Try {
            # Create a Windows Installer object
            [__comobject]$Installer = New-Object -ComObject 'WindowsInstaller.Installer' -ErrorAction 'Stop'
            # Determine if the database file is a patch (.msp) or not
            If ([IO.Path]::GetExtension($Path) -eq '.msp') { [boolean]$IsMspFile = $true }
            # Define properties for how the MSI database is opened
            [int32]$msiOpenDatabaseModeReadOnly = 0
            [int32]$msiSuppressApplyTransformErrors = 63
            [int32]$msiOpenDatabaseMode = $msiOpenDatabaseModeReadOnly
            [int32]$msiOpenDatabaseModePatchFile = 32
            If ($IsMspFile) { [int32]$msiOpenDatabaseMode = $msiOpenDatabaseModePatchFile }
            # Open database in read only mode
            [__comobject]$Database = Invoke-ObjectMethod -InputObject $Installer -MethodName 'OpenDatabase' -ArgumentList @($Path, $msiOpenDatabaseMode)
            # Apply a list of transform(s) to the database
            If (($TransformPath) -and (-not $IsMspFile)) {
                ForEach ($Transform in $TransformPath) {
                    $null = Invoke-ObjectMethod -InputObject $Database -MethodName 'ApplyTransform' -ArgumentList @($Transform, $msiSuppressApplyTransformErrors)
                }
            }

            # Get either the requested windows database table information or summary information
            If ($PSCmdlet.ParameterSetName -eq 'TableInfo') {
                # Open the requested table view from the database
                [__comobject]$View = Invoke-ObjectMethod -InputObject $Database -MethodName 'OpenView' -ArgumentList @("SELECT * FROM $Table")
                $null = Invoke-ObjectMethod -InputObject $View -MethodName 'Execute'

                # Create an empty object to store properties in
                [psobject]$TableProperties = New-Object -TypeName 'PSObject'

                # Retrieve the first row from the requested table. If the first row was successfully retrieved, then save data and loop through the entire table.
                # https://msdn.microsoft.com/en-us/library/windows/desktop/aa371136(v=vs.85).aspx
                [__comobject]$Record = Invoke-ObjectMethod -InputObject $View -MethodName 'Fetch'
                While ($Record) {
                    # Read string data from record and add property/value pair to custom object
                    $TableProperties | Add-Member -MemberType 'NoteProperty' -Name (Get-ObjectProperty -InputObject $Record -PropertyName 'StringData' -ArgumentList @($TablePropertyNameColumnNum)) -Value (Get-ObjectProperty -InputObject $Record -PropertyName 'StringData' -ArgumentList @($TablePropertyValueColumnNum)) -Force
                    # Retrieve the next row in the table
                    [__comobject]$Record = Invoke-ObjectMethod -InputObject $View -MethodName 'Fetch'
                }
                Write-Output -InputObject $TableProperties
            }
            Else {
                # Get the SummaryInformation from the windows installer database
                [__comobject]$SummaryInformation = Get-ObjectProperty -InputObject $Database -PropertyName 'SummaryInformation'
                [hashtable]$SummaryInfoProperty  = @{}
                # Summary property descriptions: https://msdn.microsoft.com/en-us/library/aa372049(v=vs.85).aspx
                $SummaryInfoProperty.Add('CodePage',            (Get-ObjectProperty -InputObject $SummaryInformation -PropertyName 'Property' -ArgumentList @(1)))
                $SummaryInfoProperty.Add('Title',               (Get-ObjectProperty -InputObject $SummaryInformation -PropertyName 'Property' -ArgumentList @(2)))
                $SummaryInfoProperty.Add('Subject',             (Get-ObjectProperty -InputObject $SummaryInformation -PropertyName 'Property' -ArgumentList @(3)))
                $SummaryInfoProperty.Add('Author',              (Get-ObjectProperty -InputObject $SummaryInformation -PropertyName 'Property' -ArgumentList @(4)))
                $SummaryInfoProperty.Add('Keywords',            (Get-ObjectProperty -InputObject $SummaryInformation -PropertyName 'Property' -ArgumentList @(5)))
                $SummaryInfoProperty.Add('Comments',            (Get-ObjectProperty -InputObject $SummaryInformation -PropertyName 'Property' -ArgumentList @(6)))
                $SummaryInfoProperty.Add('Template',            (Get-ObjectProperty -InputObject $SummaryInformation -PropertyName 'Property' -ArgumentList @(7)))
                $SummaryInfoProperty.Add('LastSavedBy',         (Get-ObjectProperty -InputObject $SummaryInformation -PropertyName 'Property' -ArgumentList @(8)))
                $SummaryInfoProperty.Add('RevisionNumber',      (Get-ObjectProperty -InputObject $SummaryInformation -PropertyName 'Property' -ArgumentList @(9)))
                $SummaryInfoProperty.Add('LastPrinted',         (Get-ObjectProperty -InputObject $SummaryInformation -PropertyName 'Property' -ArgumentList @(11)))
                $SummaryInfoProperty.Add('CreateTimeDate',      (Get-ObjectProperty -InputObject $SummaryInformation -PropertyName 'Property' -ArgumentList @(12)))
                $SummaryInfoProperty.Add('LastSaveTimeDate',    (Get-ObjectProperty -InputObject $SummaryInformation -PropertyName 'Property' -ArgumentList @(13)))
                $SummaryInfoProperty.Add('PageCount',           (Get-ObjectProperty -InputObject $SummaryInformation -PropertyName 'Property' -ArgumentList @(14)))
                $SummaryInfoProperty.Add('WordCount',           (Get-ObjectProperty -InputObject $SummaryInformation -PropertyName 'Property' -ArgumentList @(15)))
                $SummaryInfoProperty.Add('CharacterCount',      (Get-ObjectProperty -InputObject $SummaryInformation -PropertyName 'Property' -ArgumentList @(16)))
                $SummaryInfoProperty.Add('CreatingApplication', (Get-ObjectProperty -InputObject $SummaryInformation -PropertyName 'Property' -ArgumentList @(18)))
                $SummaryInfoProperty.Add('Security',            (Get-ObjectProperty -InputObject $SummaryInformation -PropertyName 'Property' -ArgumentList @(19)))
                [psobject]$SummaryInfoProperties = New-Object -TypeName 'PSObject' -Property $SummaryInfoProperty
                Write-Output -InputObject $SummaryInfoProperties
            }
        }
        Catch {
            Write-Warning -Message "Failed to get the MSI table [$Table]"
        }
        Finally {
            Try {
                If ($View) {
                    $null = Invoke-ObjectMethod -InputObject $View -MethodName 'Close' -ArgumentList @()
                    Try { $null = [Runtime.InteropServices.Marshal]::ReleaseComObject($View) } Catch {}
                }
                ElseIf ($SummaryInformation) {
                    Try { $null = [Runtime.InteropServices.Marshal]::ReleaseComObject($SummaryInformation) } Catch {}
                }
            }
            Catch {}
            Try { $null = [Runtime.InteropServices.Marshal]::ReleaseComObject($DataBase)  } Catch {}
            Try { $null = [Runtime.InteropServices.Marshal]::ReleaseComObject($Installer) } Catch {}
        }
    }
    End {
        # Verbose Logging
        Write-Verbose -Message "##### Ending : [$CmdletName]"
    }
}


Function Get-FreeDiskSpace {
    <#
    .SYNOPSIS
        Retrieves the free disk space in MB on a particular drive (defaults to system drive)
    .DESCRIPTION
        Retrieves the free disk space in MB on a particular drive (defaults to system drive)
    .PARAMETER Drive
        Drive to check free disk space on
    .PARAMETER ContinueOnError
        Continue if an error is encountered. Default is: $true
    .EXAMPLE
        Get-FreeDiskSpace -Drive 'C:'
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [string]$Drive = $env:SystemDrive,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [boolean]$ContinueOnError = $true
    )

    Begin {
        # Verbose Logging
        [string]$CmdletName  = $MyInvocation.MyCommand.Name
        [string]$CmdletParam = $PSBoundParameters | Format-Table -Property @{ Label = 'Parameter'; Expression = { "[-$($_.Key)]" } }, @{ Label = 'Value'; Expression = { $_.Value }; Alignment = 'Left' } -AutoSize -Wrap | Out-String
        Write-Verbose -Message "##### Calling : [$CmdletName]"
    }
    Process {
        Try {
            Write-Verbose -Message "Retrieve free disk space for drive [$Drive]"
            $Disk = Get-WmiObject -Class 'Win32_LogicalDisk' -Filter "DeviceID='$Drive'" -ErrorAction 'Stop'
            [double]$FreeDiskSpace = [math]::Round($Disk.FreeSpace / 1MB)

            Write-Verbose -Message "Free disk space for drive [$Drive]: [$FreeDiskSpace MB]"
            Write-Output -InputObject $FreeDiskSpace
        }
        Catch {
            Write-Warning -Message "Failed to retrieve free disk space for drive [$Drive]"
            If (-not $ContinueOnError) {
                Throw "Failed to retrieve free disk space for drive [$Drive]: $($_.Exception.Message)"
            }
        }
    }
    End {
        # Verbose Logging
        Write-Verbose -Message "##### Ending : [$CmdletName]"
    }
}


Function Get-MSIErrorCodeMessage {
    <#
    .SYNOPSIS
        Get message for MSI error code
    .DESCRIPTION
        Get message for MSI error code
    .PARAMETER MSIErrorCode
        MSI error code
    .EXAMPLE
        Get-MSIErrorCodeMessage -MSIErrorCode 3010
    #>

    [CmdletBinding()]
    Param (
    [Parameter(Mandatory=$true)]
    [ValidateNotNullorEmpty()]
    [int32]$MSIErrorCode
    )

    Begin {
        # Verbose Logging
        [string]$CmdletName  = $MyInvocation.MyCommand.Name
        [string]$CmdletParam = $PSBoundParameters | Format-Table -Property @{ Label = 'Parameter'; Expression = { "[-$($_.Key)]" } }, @{ Label = 'Value'; Expression = { $_.Value }; Alignment = 'Left' } -AutoSize -Wrap | Out-String
        Write-Verbose -Message "##### Calling : [$CmdletName]"

        $MSIErrorCodeData = @{
            0    = 'ERROR_SUCCESS', 'The action completed successfully.'
            13   = 'ERROR_INVALID_DATA', 'The data is invalid.'
            87   = 'ERROR_INVALID_PARAMETER', 'One of the parameters was invalid.'
            120  = 'ERROR_CALL_NOT_IMPLEMENTED', 'This value is returned when a custom action attempts to call a function that cannot be called from custom actions. The function returns the value ERROR_CALL_NOT_IMPLEMENTED. Available beginning with Windows Installer version 3.0.'
            1259 = 'ERROR_APPHELP_BLOCK', 'If Windows Installer determines a product may be incompatible with the current operating system, it displays a dialog box informing the user and asking whether to try to install anyway. This error code is returned if the user chooses not to try the installation.'
            1601 = 'ERROR_INSTALL_SERVICE_FAILURE', 'The Windows Installer service could not be accessed. Contact your support personnel to verify that the Windows Installer service is properly registered.'
            1602 = 'ERROR_INSTALL_USEREXIT', 'The user cancels installation.'
            1603 = 'ERROR_INSTALL_FAILURE', 'A fatal error occurred during installation.'
            1604 = 'ERROR_INSTALL_SUSPEND', 'Installation suspended, incomplete.'
            1605 = 'ERROR_UNKNOWN_PRODUCT', 'This action is only valid for products that are currently installed.'
            1606 = 'ERROR_UNKNOWN_FEATURE', 'The feature identifier is not registered.'
            1607 = 'ERROR_UNKNOWN_COMPONENT', 'The component identifier is not registered.'
            1608 = 'ERROR_UNKNOWN_PROPERTY', 'This is an unknown property.'
            1609 = 'ERROR_INVALID_HANDLE_STATE', 'The handle is in an invalid state.'
            1610 = 'ERROR_BAD_CONFIGURATION', 'The configuration data for this product is corrupt. Contact your support personnel.'
            1611 = 'ERROR_INDEX_ABSENT', 'The component qualifier not present.'
            1612 = 'ERROR_INSTALL_SOURCE_ABSENT', 'The installation source for this product is not available. Verify that the source exists and that you can access it.'
            1613 = 'ERROR_INSTALL_PACKAGE_VERSION', 'This installation package cannot be installed by the Windows Installer service. You must install a Windows service pack that contains a newer version of the Windows Installer service.'
            1614 = 'ERROR_PRODUCT_UNINSTALLED', 'The product is uninstalled.'
            1615 = 'ERROR_BAD_QUERY_SYNTAX', 'The SQL query syntax is invalid or unsupported.'
            1616 = 'ERROR_INVALID_FIELD', 'The record field does not exist.'
            1618 = 'ERROR_INSTALL_ALREADY_RUNNING', 'Another installation is already in progress. Complete that installation before proceeding with this install.'
            1619 = 'ERROR_INSTALL_PACKAGE_OPEN_FAILED', 'This installation package could not be opened. Verify that the package exists and is accessible, or contact the application vendor to verify that this is a valid Windows Installer package.'
            1620 = 'ERROR_INSTALL_PACKAGE_INVALID', 'This installation package could not be opened. Contact the application vendor to verify that this is a valid Windows Installer package.'
            1621 = 'ERROR_INSTALL_UI_FAILURE', 'There was an error starting the Windows Installer service user interface. Contact your support personnel.'
            1622 = 'ERROR_INSTALL_LOG_FAILURE', 'There was an error opening installation log file. Verify that the specified log file location exists and is writable.'
            1623 = 'ERROR_INSTALL_LANGUAGE_UNSUPPORTED', 'This language of this installation package is not supported by your system.'
            1624 = 'ERROR_INSTALL_TRANSFORM_FAILURE', 'There was an error applying transforms. Verify that the specified transform paths are valid.'
            1625 = 'ERROR_INSTALL_PACKAGE_REJECTED', 'This installation is forbidden by system policy. Contact your system administrator.'
            1626 = 'ERROR_FUNCTION_NOT_CALLED', 'The function could not be executed.'
            1627 = 'ERROR_FUNCTION_FAILED', 'The function failed during execution.'
            1628 = 'ERROR_INVALID_TABLE', 'An invalid or unknown table was specified.'
            1629 = 'ERROR_DATATYPE_MISMATCH', 'The data supplied is the wrong type.'
            1630 = 'ERROR_UNSUPPORTED_TYPE', 'Data of this type is not supported.'
            1631 = 'ERROR_CREATE_FAILED', 'The Windows Installer service failed to start. Contact your support personnel.'
            1632 = 'ERROR_INSTALL_TEMP_UNWRITABLE', 'The Temp folder is either full or inaccessible. Verify that the Temp folder exists and that you can write to it.'
            1633 = 'ERROR_INSTALL_PLATFORM_UNSUPPORTED', 'This installation package is not supported on this platform. Contact your application vendor.'
            1634 = 'ERROR_INSTALL_NOTUSED', 'Component is not used on this machine.'
            1635 = 'ERROR_PATCH_PACKAGE_OPEN_FAILED', 'This patch package could not be opened. Verify that the patch package exists and is accessible, or contact the application vendor to verify that this is a valid Windows Installer patch package.'
            1636 = 'ERROR_PATCH_PACKAGE_INVALID', 'This patch package could not be opened. Contact the application vendor to verify that this is a valid Windows Installer patch package.'
            1637 = 'ERROR_PATCH_PACKAGE_UNSUPPORTED', 'This patch package cannot be processed by the Windows Installer service. You must install a Windows service pack that contains a newer version of the Windows Installer service.'
            1638 = 'ERROR_PRODUCT_VERSION', 'Another version of this product is already installed. Installation of this version cannot continue. To configure or remove the existing version of this product, use Add/Remove Programs in Control Panel.'
            1639 = 'ERROR_INVALID_COMMAND_LINE', 'Invalid command line argument. Consult the Windows Installer SDK for detailed command-line help.'
            1640 = 'ERROR_INSTALL_REMOTE_DISALLOWED', 'The current user is not permitted to perform installations from a client session of a server running the Terminal Server role service.'
            1641 = 'ERROR_SUCCESS_REBOOT_INITIATED', 'The installer has initiated a restart. This message is indicative of a success.'
            1642 = 'ERROR_PATCH_TARGET_NOT_FOUND', 'The installer cannot install the upgrade patch because the program being upgraded may be missing or the upgrade patch updates a different version of the program. Verify that the program to be upgraded exists on your computer and that you have the correct upgrade patch.'
            1643 = 'ERROR_PATCH_PACKAGE_REJECTED', 'The patch package is not permitted by system policy.'
            1644 = 'ERROR_INSTALL_TRANSFORM_REJECTED', 'One or more customizations are not permitted by system policy.'
            1645 = 'ERROR_INSTALL_REMOTE_PROHIBITED', 'Windows Installer does not permit installation from a Remote Desktop Connection.'
            1646 = 'ERROR_PATCH_REMOVAL_UNSUPPORTED', 'The patch package is not a removable patch package. Available beginning with Windows Installer version 3.0.'
            1647 = 'ERROR_UNKNOWN_PATCH', 'The patch is not applied to this product. Available beginning with Windows Installer version 3.0.'
            1648 = 'ERROR_PATCH_NO_SEQUENCE', 'No valid sequence could be found for the set of patches. Available beginning with Windows Installer version 3.0.'
            1649 = 'ERROR_PATCH_REMOVAL_DISALLOWED', 'Patch removal was disallowed by policy. Available beginning with Windows Installer version 3.0.'
            1650 = 'ERROR_INVALID_PATCH_XML', 'The XML patch data is invalid. Available beginning with Windows Installer version 3.0.'
            1651 = 'ERROR_PATCH_MANAGED_ADVERTISED_PRODUCT', 'Administrative user failed to apply patch for a per-user managed or a per-machine application that is in advertise state. Available beginning with Windows Installer version 3.0.'
            1652 = 'ERROR_INSTALL_SERVICE_SAFEBOOT', 'Windows Installer is not accessible when the computer is in Safe Mode. Exit Safe Mode and try again or try using System Restore to return your computer to a previous state. Available beginning with Windows Installer version 4.0.'
            1653 = 'ERROR_ROLLBACK_DISABLED', 'Could not perform a multiple-package transaction because rollback has been disabled. Multiple-Package Installations cannot run if rollback is disabled. Available beginning with Windows Installer version 4.5.'
            1654 = 'ERROR_INSTALL_REJECTED', 'The app that you are trying to run is not supported on this version of Windows. A Windows Installer package, patch, or transform that has not been signed by Microsoft cannot be installed on an ARM computer.'
            3010 = 'ERROR_SUCCESS_REBOOT_REQUIRED', 'A restart is required to complete the install. This message is indicative of a success. This does not include installs where the ForceReboot action is run.  '
        }
    }
    Process {
        Try {
            Write-Verbose -Message "Get message for exit code [$MSIErrorCode]"
            $MSIErrorCodeMessage = $MSIErrorCodeData.Get_Item($MSIErrorCode)
            Write-Output -InputObject $MSIErrorCodeMessage
        }
        Catch {
            Write-Warning -Message "Failed to get message for exit code [$MSIErrorCode]"
        }
    }
    End {
        # Verbose Logging
        Write-Verbose -Message "##### Ending : [$CmdletName]"
    }
}


Function Get-FileVersion {
    <#
    .SYNOPSIS
        Gets the version of the specified file
    .DESCRIPTION
        Gets the version of the specified file
    .PARAMETER File
        Path of the file
    .EXAMPLE
        Get-FileVersion -File 'C:\Path\To\File\7z1604-x64.exe'
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [string]$File
    )

    Begin {
        # Verbose Logging
        [string]$CmdletName  = $MyInvocation.MyCommand.Name
        [string]$CmdletParam = $PSBoundParameters | Format-Table -Property @{ Label = 'Parameter'; Expression = { "[-$($_.Key)]" } }, @{ Label = 'Value'; Expression = { $_.Value }; Alignment = 'Left' } -AutoSize -Wrap | Out-String
        Write-Verbose -Message "##### Calling : [$CmdletName]"
    }
    Process {
        Try {
            Write-Verbose -Message "Get file version information for file [$File]"
            If (Test-Path -LiteralPath $File -PathType 'Leaf') {
                # Get file version
                $FileVersion = (Get-Command -Name $File -ErrorAction 'Stop').FileVersionInfo.FileVersion
                If ($FileVersion) {
                    # Remove product information
                    $FileVersion = ($FileVersion -split ' ' | Select-Object -First 1)
                    Write-Verbose -Message "File version is [$FileVersion]"
                    Write-Output -InputObject $FileVersion
                }
                Else {
                    Write-Verbose -Message 'No file version information found'
                }
            }
        }
        Catch {
            Write-Warning -Message 'Failed to get file version info'
        }
    }
    End {
        # Verbose Logging
        Write-Verbose -Message "##### Ending : [$CmdletName]"
    }
}


Function New-Shortcut {
    <#
    .SYNOPSIS
        Creates a new .lnk or .url shortcut
    .DESCRIPTION
        Creates a new .lnk or .url shortcut
    .PARAMETER Path
        Path to save the shortcut
    .PARAMETER TargetPath
        Target path or URL that the shortcut launches
    .PARAMETER Arguments
        Arguments to be passed
    .PARAMETER IconLocation
        Location of the icon used for the shortcut
    .PARAMETER IconIndex
        Executables, DLLs and ICO files with multiple icons need the index to be specified
    .PARAMETER Description
        Description of the shortcut (Comment)
    .PARAMETER WorkingDirectory
        Working Directory to be used for the shortcut
    .PARAMETER WindowStyle
        Window style of the application. Options: Normal, Maximized, Minimized. Default is: Normal
    .PARAMETER RunAsAdmin
        Set shortcut to run program as administrator. This option will prompt user to elevate when executing shortcut
    .PARAMETER ContinueOnError
        Continue if an exit code is returned by msiexec that is not recognized. Default is: $true
    .EXAMPLE
        New-Shortcut -Path "C:\Path\To\File\TestProgram.lnk" -TargetPath "$env:windir\System32\notepad.exe" -IconLocation "$env:windir\system32\notepad.exe" -Description 'Notepad Shortcut'
    .EXAMPLE
        New-Shortcut -Path "C:\Path\To\File\TestURL.url" -TargetPath "www.google.co.uk"
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [string]$Path,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [string]$TargetPath,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$Arguments,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [string]$IconLocation,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [string]$IconIndex,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$Description,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$WorkingDirectory,
        [Parameter(Mandatory=$false)]
        [ValidateSet('Normal','Maximized','Minimized')]
        [string]$WindowStyle,
        [Parameter(Mandatory=$false)]
        [switch]$RunAsAdmin,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [boolean]$ContinueOnError = $true
    )

    Begin {
        # Verbose Logging
        [string]$CmdletName  = $MyInvocation.MyCommand.Name
        [string]$CmdletParam = $PSBoundParameters | Format-Table -Property @{ Label = 'Parameter'; Expression = { "[-$($_.Key)]" } }, @{ Label = 'Value'; Expression = { $_.Value }; Alignment = 'Left' } -AutoSize -Wrap | Out-String
        Write-Verbose -Message "##### Calling : [$CmdletName]"

        If (-not $Shell) { [__comobject]$Shell = New-Object -ComObject 'WScript.Shell' -ErrorAction 'Stop' }
    }
    Process {
        Try {
            # Create path to shortcut
            Try {
                [IO.FileInfo]$Path = [IO.FileInfo]$Path
                [string]$PathDirectory = $Path.DirectoryName
                If (-not (Test-Path -LiteralPath $PathDirectory -PathType 'Container' -ErrorAction 'Stop')) {
                    Write-Verbose -Message "Create shortcut directory [$PathDirectory]"
                    $null = New-Item -Path $PathDirectory -ItemType 'Directory' -Force -ErrorAction 'Stop'
                }
            }
            Catch {
                Write-Warning -Message "Failed to create shortcut directory [$PathDirectory]"
                Throw
            }

            Write-Verbose -Message "Create shortcut [$($Path.FullName)]"
            # Create URL shortcut
            If (($Path.FullName).EndsWith('.url')) {
                [string[]]$URLFile = '[InternetShortcut]'
                $URLFile += "URL=$TargetPath"
                If ($IconIndex)    { $URLFile += "IconIndex=$IconIndex" }
                If ($IconLocation) { $URLFile += "IconFile=$IconLocation" }
                $URLFile | Out-File -FilePath $Path.FullName -Force -Encoding 'default' -ErrorAction 'Stop'
            }
            # Create LNK shortcut
            ElseIf (($Path.FullName).EndsWith('.lnk')) {
                If (($IconLocation -and $IconIndex) -and (-not ($IconLocation.Contains(',')))) {
                    $IconLocation = $IconLocation + ",$IconIndex"
                }
                Switch ($WindowStyle) {
                    'Normal'    { $WindowStyleInt = 1 }
                    'Maximized' { $WindowStyleInt = 3 }
                    'Minimized' { $WindowStyleInt = 7 }
                    Default     { $windowStyleInt = 1 }
                }
                $Shortcut = $Shell.CreateShortcut($Path.FullName)
                $Shortcut.TargetPath       = $TargetPath
                $Shortcut.Arguments        = $Arguments
                $Shortcut.Description      = $Description
                $Shortcut.WorkingDirectory = $WorkingDirectory
                $Shortcut.WindowStyle      = $WindowStyleInt
                If ($IconLocation) { $Shortcut.IconLocation = $IconLocation }
                $Shortcut.Save()

                # Set shortcut to run as administrator
                If ($RunAsAdmin) {
                    Write-Verbose -Message 'Set shortcut to run program as administrator'
                    $TempFileName = [IO.Path]::GetRandomFileName()
                    $TempFile     = [IO.FileInfo][IO.Path]::Combine($Path.Directory, $TempFileName)
                    $Writer       = New-Object -TypeName 'System.IO.FileStream' -ArgumentList ($TempFile, ([IO.FileMode]::Create)) -ErrorAction 'Stop'
                    $Reader       = $Path.OpenRead()
                    While ($Reader.Position -lt $Reader.Length) {
                        $Byte = $Reader.ReadByte()
                        If ($Reader.Position -eq 22) { $Byte = 34 }
                        $Writer.WriteByte($Byte)
                    }
                    $Reader.Close()
                    $Writer.Close()
                    $Path.Delete()
                    $null = Rename-Item -LiteralPath $TempFile -NewName $Path.Name -Force -ErrorAction 'Stop'
                }
            }
        }
        Catch {
            Write-Warning -Message "Failed to create shortcut [$($Path.FullName)]"
            If (-not $ContinueOnError) {
                Throw "Failed to create shortcut [$($Path.FullName)]: $($_.Exception.Message)"
            }
        }
    }
    End {
        # Verbose Logging
        Write-Verbose -Message "##### Ending : [$CmdletName]"
    }
}


Function Get-LoggedOnUser {
    <#
    .SYNOPSIS
        Get session details for all local and RDP logged on users
    .DESCRIPTION
        Get session details for all local and RDP logged on users using Win32 APIs
    .EXAMPLE
        Get-LoggedOnUser
    .EXAMPLE
        Get-LoggedOnUser -ComputerName 'Computer1'
    .NOTES
        Description of the ConnectState property :
        Value         Description
        -----         -----------
        Active        A user is logged on to the session.
        ConnectQuery  The session is in the process of connecting to a client
        Connected	    A client is connected to the session
        Disconnected  The session is active, but the client has disconnected from it
        Down          The session is down due to an error
        Idle          The session is waiting for a client to connect
        Initializing  The session is initializing
        Listening     The session is listening for connections
        Reset         The session is being reset
        Shadowing     This session is shadowing another session

        Description of IsActiveUserSession property :
        If a console user exists, then that will be the active user session
        If no console user exists but users are logged in, then the first logged-in non-console user that is either 'Active' or 'Connected' is the active user

        Description of IsRdpSession property :
        Boolean value indicating whether the user is associated with an RDP client session
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false)]
        [string[]]$ComputerName = $env:ComputerName
    )

    Begin {
        # Verbose Logging
        [string]$CmdletName  = $MyInvocation.MyCommand.Name
        [string]$CmdletParam = $PSBoundParameters | Format-Table -Property @{ Label = 'Parameter'; Expression = { "[-$($_.Key)]" } }, @{ Label = 'Value'; Expression = { $_.Value }; Alignment = 'Left' } -AutoSize -Wrap | Out-String
        Write-Verbose -Message "##### Calling : [$CmdletName]"

        # Load C# Namespace if required
        If (-not ([Management.Automation.PSTypeName]'PSSM.QueryUser').Type) {
            $ReferencedAssemblies = ( "System.DirectoryServices, Version=2.0.0.0, Culture=neutral, PublicKeyToken=B03F5F7F11D50A3A" )

            $CSSourceCode = @"
using System;
using System.Collections;
using System.ComponentModel;
using System.DirectoryServices;
using System.Security.Principal;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using FILETIME = System.Runtime.InteropServices.ComTypes.FILETIME;

namespace PSSM
{
    public class QueryUser
  {
    [DllImport("wtsapi32.dll", CharSet = CharSet.Auto, SetLastError = false)]
    public static extern IntPtr WTSOpenServer(string pServerName);

    [DllImport("wtsapi32.dll", CharSet = CharSet.Auto, SetLastError = false)]
    public static extern void WTSCloseServer(IntPtr hServer);

    [DllImport("wtsapi32.dll", CharSet = CharSet.Ansi, SetLastError = false)]
    public static extern bool WTSQuerySessionInformation(IntPtr hServer, int sessionId, WTS_INFO_CLASS wtsInfoClass, out IntPtr pBuffer, out int pBytesReturned);

    [DllImport("wtsapi32.dll", CharSet = CharSet.Ansi, SetLastError = false)]
    public static extern int WTSEnumerateSessions(IntPtr hServer, int Reserved, int Version, out IntPtr pSessionInfo, out int pCount);

    [DllImport("wtsapi32.dll", CharSet = CharSet.Auto, SetLastError = false)]
    public static extern void WTSFreeMemory(IntPtr pMemory);

    [DllImport("winsta.dll", CharSet = CharSet.Auto, SetLastError = false)]
    public static extern int WinStationQueryInformation(IntPtr hServer, int sessionId, int information, ref WINSTATIONINFORMATIONW pBuffer, int bufferLength, ref int returnedLength);

    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = false)]
    public static extern int GetCurrentProcessId();

    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = false)]
    public static extern bool ProcessIdToSessionId(int processId, ref int pSessionId);

    public class TerminalSessionData
    {
      public int SessionId;
      public string ConnectionState;
      public string SessionName;
      public bool IsUserSession;
      public TerminalSessionData(int sessionId, string connState, string sessionName, bool isUserSession)
      {
        SessionId = sessionId;
        ConnectionState = connState;
        SessionName = sessionName;
        IsUserSession = isUserSession;
      }
    }

    public class TerminalSessionInfo
    {
      public string NTAccount;
      public string SID;
      public string UserName;
      public string DomainName;
      public int SessionId;
      public string SessionName;
      public string ConnectState;
      public bool IsCurrentSession;
      public bool IsConsoleSession;
      public bool IsActiveUserSession;
      public bool IsUserSession;
      public bool IsRdpSession;
      public bool IsLocalAdmin;
      public DateTime? LogonTime;
      public TimeSpan? IdleTime;
      public DateTime? DisconnectTime;
      public string ClientName;
      public string ClientProtocolType;
      public string ClientDirectory;
      public int ClientBuildNumber;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WTS_SESSION_INFO
    {
      public Int32 SessionId;
      [MarshalAs(UnmanagedType.LPStr)]
      public string SessionName;
      public WTS_CONNECTSTATE_CLASS State;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WINSTATIONINFORMATIONW
    {
      [MarshalAs(UnmanagedType.ByValArray, SizeConst = 70)]
      private byte[] Reserved1;
      public int SessionId;
      [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
      private byte[] Reserved2;
      public FILETIME ConnectTime;
      public FILETIME DisconnectTime;
      public FILETIME LastInputTime;
      public FILETIME LoginTime;
      [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1096)]
      private byte[] Reserved3;
      public FILETIME CurrentTime;
    }

    public enum WINSTATIONINFOCLASS
    {
      WinStationInformation = 8
    }

    public enum WTS_CONNECTSTATE_CLASS
    {
      Active,
      Connected,
      ConnectQuery,
      Shadow,
      Disconnected,
      Idle,
      Listen,
      Reset,
      Down,
      Init
    }

    public enum WTS_INFO_CLASS
    {
      SessionId=4,
      UserName,
      SessionName,
      DomainName,
      ConnectState,
      ClientBuildNumber,
      ClientName,
      ClientDirectory,
      ClientProtocolType=16
    }

    private static IntPtr OpenServer(string Name)
    {
      IntPtr server = WTSOpenServer(Name);
      return server;
    }

    private static void CloseServer(IntPtr ServerHandle)
    {
      WTSCloseServer(ServerHandle);
    }

    private static IList<T> PtrToStructureList<T>(IntPtr ppList, int count) where T : struct
    {
      List<T> result = new List<T>();
      long pointer = ppList.ToInt64();
      int sizeOf = Marshal.SizeOf(typeof(T));

      for (int index = 0; index < count; index++)
      {
        T item = (T) Marshal.PtrToStructure(new IntPtr(pointer), typeof(T));
        result.Add(item);
        pointer += sizeOf;
      }
      return result;
    }

    public static DateTime? FileTimeToDateTime(FILETIME ft)
    {
      if (ft.dwHighDateTime == 0 && ft.dwLowDateTime == 0)
      {
        return null;
      }
      long hFT = (((long) ft.dwHighDateTime) << 32) + ft.dwLowDateTime;
      return DateTime.FromFileTime(hFT);
    }

    public static WINSTATIONINFORMATIONW GetWinStationInformation(IntPtr server, int sessionId)
    {
      int retLen = 0;
      WINSTATIONINFORMATIONW wsInfo = new WINSTATIONINFORMATIONW();
      WinStationQueryInformation(server, sessionId, (int) WINSTATIONINFOCLASS.WinStationInformation, ref wsInfo, Marshal.SizeOf(typeof(WINSTATIONINFORMATIONW)), ref retLen);
      return wsInfo;
    }

    public static TerminalSessionData[] ListSessions(string ServerName)
    {
      IntPtr server = IntPtr.Zero;
      if (ServerName == "localhost" || ServerName == String.Empty)
      {
        ServerName = Environment.MachineName;
      }

      List<TerminalSessionData> results = new List<TerminalSessionData>();

      try
      {
        server = OpenServer(ServerName);
        IntPtr ppSessionInfo = IntPtr.Zero;
        int count;
        bool _isUserSession = false;
        IList<WTS_SESSION_INFO> sessionsInfo;

        if (WTSEnumerateSessions(server, 0, 1, out ppSessionInfo, out count) == 0)
        {
          throw new Win32Exception();
        }

        try
        {
          sessionsInfo = PtrToStructureList<WTS_SESSION_INFO>(ppSessionInfo, count);
        }
        finally
        {
          WTSFreeMemory(ppSessionInfo);
        }

        foreach (WTS_SESSION_INFO sessionInfo in sessionsInfo)
        {
          if (sessionInfo.SessionName != "Services" && sessionInfo.SessionName != "RDP-Tcp")
          {
            _isUserSession = true;
          }
          results.Add(new TerminalSessionData(sessionInfo.SessionId, sessionInfo.State.ToString(), sessionInfo.SessionName, _isUserSession));
          _isUserSession = false;
        }
      }
      finally
      {
        CloseServer(server);
      }

      TerminalSessionData[] returnData = results.ToArray();
      return returnData;
    }

    public static TerminalSessionInfo GetSessionInfo(string ServerName, int SessionId)
    {
      IntPtr server = IntPtr.Zero;
      IntPtr buffer = IntPtr.Zero;
      int bytesReturned;
      TerminalSessionInfo data = new TerminalSessionInfo();
      bool _IsCurrentSessionId = false;
      bool _IsConsoleSession = false;
      bool _IsUserSession = false;
      int currentSessionID = 0;
      string _NTAccount = String.Empty;
      if (ServerName == "localhost" || ServerName == String.Empty)
      {
        ServerName = Environment.MachineName;
      }
      if (ProcessIdToSessionId(GetCurrentProcessId(), ref currentSessionID) == false)
      {
        currentSessionID = -1;
      }

      bool _IsLocalAdminCheckSuccess = false;
      List<string> localAdminGroupSidsList = new List<string>();
      try
      {
        DirectoryEntry localMachine = new DirectoryEntry("WinNT://" + ServerName + ",Computer");
        string localAdminGroupName = new SecurityIdentifier("S-1-5-32-544").Translate(typeof(NTAccount)).Value.Split('\\')[1];
        DirectoryEntry admGroup = localMachine.Children.Find(localAdminGroupName, "group");
        object members = admGroup.Invoke("members", null);
        foreach (object groupMember in (IEnumerable)members)
        {
          DirectoryEntry member = new DirectoryEntry(groupMember);
          if (member.Name != String.Empty)
          {
            localAdminGroupSidsList.Add((new NTAccount(member.Name)).Translate(typeof(SecurityIdentifier)).Value);
          }
        }
        _IsLocalAdminCheckSuccess = true;
      }
      catch { }

      try
      {
        server = OpenServer(ServerName);

        if (WTSQuerySessionInformation(server, SessionId, WTS_INFO_CLASS.ClientBuildNumber, out buffer, out bytesReturned) == false)
        {
          return data;
        }
        int lData = Marshal.ReadInt32(buffer);
        data.ClientBuildNumber = lData;

        if (WTSQuerySessionInformation(server, SessionId, WTS_INFO_CLASS.ClientDirectory, out buffer, out bytesReturned) == false)
        {
          return data;
        }
        string strData = Marshal.PtrToStringAnsi(buffer);
        data.ClientDirectory = strData;

        if (WTSQuerySessionInformation(server, SessionId, WTS_INFO_CLASS.ClientName, out buffer, out bytesReturned) == false)
        {
          return data;
        }
        strData = Marshal.PtrToStringAnsi(buffer);
        data.ClientName = strData;

        if (WTSQuerySessionInformation(server, SessionId, WTS_INFO_CLASS.ClientProtocolType, out buffer, out bytesReturned) == false)
        {
          return data;
        }
        Int16 intData = Marshal.ReadInt16(buffer);
        if (intData == 2)
        {
          strData = "RDP";
          data.IsRdpSession = true;
        }
        else
        {
          strData = "";
          data.IsRdpSession = false;
        }
        data.ClientProtocolType = strData;

        if (WTSQuerySessionInformation(server, SessionId, WTS_INFO_CLASS.ConnectState, out buffer, out bytesReturned) == false)
        {
          return data;
        }
        lData = Marshal.ReadInt32(buffer);
        data.ConnectState = ((WTS_CONNECTSTATE_CLASS) lData).ToString();

        if (WTSQuerySessionInformation(server, SessionId, WTS_INFO_CLASS.SessionId, out buffer, out bytesReturned) == false)
        {
          return data;
        }
        lData = Marshal.ReadInt32(buffer);
        data.SessionId = lData;

        if (WTSQuerySessionInformation(server, SessionId, WTS_INFO_CLASS.DomainName, out buffer, out bytesReturned) == false)
        {
          return data;
        }
        strData = Marshal.PtrToStringAnsi(buffer).ToUpper();
        data.DomainName = strData;
        if (strData != String.Empty)
        {
          _NTAccount = strData;
        }

        if (WTSQuerySessionInformation(server, SessionId, WTS_INFO_CLASS.UserName, out buffer, out bytesReturned) == false)
        {
          return data;
        }
        strData = Marshal.PtrToStringAnsi(buffer);
        data.UserName = strData;
        if (strData != String.Empty)
        {
          data.NTAccount = _NTAccount + "\\" + strData;
          string _Sid = (new NTAccount(_NTAccount + "\\" + strData)).Translate(typeof(SecurityIdentifier)).Value;
          data.SID = _Sid;
          if (_IsLocalAdminCheckSuccess == true)
          {
            foreach (string localAdminGroupSid in localAdminGroupSidsList)
            {
              if (localAdminGroupSid == _Sid)
              {
                data.IsLocalAdmin = true;
                break;
              }
              else
              {
                data.IsLocalAdmin = false;
              }
            }
          }
        }

        if (WTSQuerySessionInformation(server, SessionId, WTS_INFO_CLASS.SessionName, out buffer, out bytesReturned) == false)
        {
          return data;
        }
        strData = Marshal.PtrToStringAnsi(buffer);
        data.SessionName = strData;
        if (strData != "Services" && strData != "RDP-Tcp" && data.UserName != String.Empty)
        {
          _IsUserSession = true;
        }
        data.IsUserSession = _IsUserSession;
        if (strData == "Console")
        {
          _IsConsoleSession = true;
        }
        data.IsConsoleSession = _IsConsoleSession;

        WINSTATIONINFORMATIONW wsInfo = GetWinStationInformation(server, SessionId);
        DateTime? _loginTime = FileTimeToDateTime(wsInfo.LoginTime);
        DateTime? _lastInputTime = FileTimeToDateTime(wsInfo.LastInputTime);
        DateTime? _disconnectTime = FileTimeToDateTime(wsInfo.DisconnectTime);
        DateTime? _currentTime = FileTimeToDateTime(wsInfo.CurrentTime);
        TimeSpan? _idleTime = (_currentTime != null && _lastInputTime != null) ? _currentTime.Value - _lastInputTime.Value : TimeSpan.Zero;
        data.LogonTime = _loginTime;
        data.IdleTime = _idleTime;
        data.DisconnectTime = _disconnectTime;

        if (currentSessionID == SessionId)
        {
          _IsCurrentSessionId = true;
        }
        data.IsCurrentSession = _IsCurrentSessionId;
      }
      finally
      {
        WTSFreeMemory(buffer);
        buffer = IntPtr.Zero;
        CloseServer(server);
      }
      return data;
    }

    public static TerminalSessionInfo[] GetUserSessionInfo(string ServerName)
    {
      if (ServerName == "localhost" || ServerName == String.Empty)
      {
        ServerName = Environment.MachineName;
      }

      TerminalSessionData[] sessions = ListSessions(ServerName);
      TerminalSessionInfo sessionInfo = new TerminalSessionInfo();
      List<TerminalSessionInfo> userSessionsInfo = new List<TerminalSessionInfo>();
      string firstActiveUserNTAccount = String.Empty;
      bool IsActiveUserSessionSet = false;
      foreach (TerminalSessionData session in sessions)
      {
        if (session.IsUserSession == true)
        {
          sessionInfo = GetSessionInfo(ServerName, session.SessionId);
          if (sessionInfo.IsUserSession == true)
          {
            if ((firstActiveUserNTAccount == String.Empty) && (sessionInfo.ConnectState == "Active" || sessionInfo.ConnectState == "Connected"))
            {
              firstActiveUserNTAccount = sessionInfo.NTAccount;
            }

            if (sessionInfo.IsConsoleSession == true)
            {
              sessionInfo.IsActiveUserSession = true;
              IsActiveUserSessionSet = true;
            }
            else
            {
              sessionInfo.IsActiveUserSession = false;
            }

            userSessionsInfo.Add(sessionInfo);
          }
        }
      }

      TerminalSessionInfo[] userSessions = userSessionsInfo.ToArray();
      if (IsActiveUserSessionSet == false)
      {
        foreach (TerminalSessionInfo userSession in userSessions)
        {
          if (userSession.NTAccount == firstActiveUserNTAccount)
          {
            userSession.IsActiveUserSession = true;
            break;
          }
        }
      }

      return userSessions;
    }
  }
}
"@

            Write-Verbose -Message 'Loading C# Namespace'
            Add-Type -ReferencedAssemblies $ReferencedAssemblies -TypeDefinition $CSSourceCode -Language CSharp
        }
    }
    Process {
        Try {
            Write-Verbose -Message "Get session information for all logged on users on [$ComputerName]"
            Write-Output -InputObject ([PSSM.QueryUser]::GetUserSessionInfo("$ComputerName"))
        }
        Catch {
            Write-Warning -Message "Failed to get session information for logged on users on [$ComputerName]"
        }
    }
    End {
        # Verbose Logging
        Write-Verbose -Message "##### Ending : [$CmdletName]"
    }
}


Function ConvertTo-NTAccountOrSID {
    <#
    .SYNOPSIS
        Convert between NT Account names and their security identifiers (SIDs)
    .DESCRIPTION
        Specify either the NT Account name or the SID and get the other. Can also convert WellKnownSidType
    .PARAMETER AccountName
        The Windows NT Account name specified in <domain>\<username> format
    .PARAMETER SID
        The Windows NT Account SID
    .PARAMETER WellKnownSIDName
        Specify the Well Known SID name to translate to the actual SID (e.g. LocalServiceSid).
        To enumerate all well known SIDs available on system: [enum]::GetNames([Security.Principal.WellKnownSidType])
    .PARAMETER WellKnownToNTAccount
        Convert the Well Known SID to an NTAccount name
    .EXAMPLE
        ConvertTo-NTAccountOrSID -AccountName '<domain>\UserName'
        Converts a Windows NT Account name to the corresponding SID
    .EXAMPLE
        ConvertTo-NTAccountOrSID -SID 'S-1-5-21-1220945662-2111687655-725345543-14012660'
        Converts a Windows NT Account SID to the corresponding NT Account Name
    .EXAMPLE
        ConvertTo-NTAccountOrSID -WellKnownSIDName 'NetworkServiceSid'
        Converts a Well Known SID name to a SID
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true,ParameterSetName='NTAccountToSID',ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$AccountName,
        [Parameter(Mandatory=$true,ParameterSetName='SIDToNTAccount',ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$SID,
        [Parameter(Mandatory=$true,ParameterSetName='WellKnownName',ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$WellKnownSIDName,
        [Parameter(Mandatory=$false,ParameterSetName='WellKnownName')]
        [ValidateNotNullOrEmpty()]
        [switch]$WellKnownToNTAccount
    )

    Begin {}
    Process {
        Try {
            Switch ($PSCmdlet.ParameterSetName) {
                'SIDToNTAccount' {
                    $NTAccountSID = New-Object -TypeName 'System.Security.Principal.SecurityIdentifier' -ArgumentList $SID
                    $NTAccount = $NTAccountSID.Translate([Security.Principal.NTAccount])
                    Write-Output -InputObject $NTAccount
                }
                'NTAccountToSID' {
                    $NTAccount = New-Object -TypeName 'System.Security.Principal.NTAccount' -ArgumentList $AccountName
                    $NTAccountSID = $NTAccount.Translate([Security.Principal.SecurityIdentifier])
                    Write-Output -InputObject $NTAccountSID
                }
                'WellKnownName' {
                    If ($WellKnownToNTAccount) {
                        [string]$ConversionType = 'NTAccount'
                    }
                    Else {
                        [string]$ConversionType = 'SID'
                    }
                    # Get the SID for the root domain
                    Try {
                        $MachineRootDomain = (Get-WmiObject -Class 'Win32_ComputerSystem' -ErrorAction 'Stop').Domain.ToLower()
                        $ADDomainObj = New-Object -TypeName 'System.DirectoryServices.DirectoryEntry' -ArgumentList "LDAP://$MachineRootDomain"
                        $DomainSidInBinary = $ADDomainObj.ObjectSid
                        $DomainSid = New-Object -TypeName 'System.Security.Principal.SecurityIdentifier' -ArgumentList ($DomainSidInBinary[0], 0)
                    }
                    Catch {
                        Write-Warning -Message 'Unable to get Domain SID from Active Directory. Setting Domain SID to $null'
                        $DomainSid = $null
                    }

                    # Get the SID for the well known SID name
                    $WellKnownSidType = [Security.Principal.WellKnownSidType]::$WellKnownSIDName
                    $NTAccountSID = New-Object -TypeName 'System.Security.Principal.SecurityIdentifier' -ArgumentList ($WellKnownSidType, $DomainSid)

                    If ($WellKnownToNTAccount) {
                        $NTAccount = $NTAccountSID.Translate([Security.Principal.NTAccount])
                        Write-Output -InputObject $NTAccount
                    }
                    Else {
                        Write-Output -InputObject $NTAccountSID
                    }
                }
            }
        }
        Catch {
            Write-Warning -Message "Failed to convert $Message. It may not be a valid account anymore or there is some other problem"
        }
    }
    End {}
}


Function Get-UserProfiles {
    <#
    .SYNOPSIS
        Get the User Profile Path, User Account SID, and the User Account Name for all users that log onto the machine (including the Default User)
    .DESCRIPTION
        Get the User Profile Path, User Account SID, and the User Account Name for all users that log onto the machine (including the Default User)
    .PARAMETER ExcludeNTAccount
        Specify NT account names in <domain>\<username> format to exclude from the list of user profiles
    .PARAMETER ExcludeSystemProfiles
        Exclude system profiles: SYSTEM, LOCAL SERVICE, NETWORK SERVICE. Default is: $true
    .PARAMETER ExcludeDefaultUser
        Exclude the Default User. Default is: $false
    .EXAMPLE
        Get-UserProfiles
        Returns the following properties for each user profile on the system: NTAccount, SID, ProfilePath
    .EXAMPLE
        Get-UserProfiles -ExcludeNTAccount '<domain>\UserName','<domain>\AnotherUserName'
    .EXAMPLE
        [string[]]$ProfilePaths = Get-UserProfiles | Select-Object -ExpandProperty 'ProfilePath'
        Returns the user profile path for each user on the system. This information can then be used to make modifications under the user profile on the filesystem
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string[]]$ExcludeNTAccount,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [boolean]$ExcludeSystemProfiles = $true,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [switch]$ExcludeDefaultUser = $false
    )

    Begin {
        # Verbose Logging
        [string]$CmdletName  = $MyInvocation.MyCommand.Name
        [string]$CmdletParam = $PSBoundParameters | Format-Table -Property @{ Label = 'Parameter'; Expression = { "[-$($_.Key)]" } }, @{ Label = 'Value'; Expression = { $_.Value }; Alignment = 'Left' } -AutoSize -Wrap | Out-String
        Write-Verbose -Message "##### Calling : [$CmdletName]"
    }
    Process {
        Try {
            Write-Verbose -Message 'Get the User Profile Path, User Account SID, and the User Account Name for all users that log onto the machine'

            # Get the User Profile Path, User Account SID and the User Account Name for all users that log onto the machine
            [string]$UserProfileListRegKey = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
            [psobject[]]$UserProfiles = Get-ChildItem -LiteralPath $UserProfileListRegKey -ErrorAction 'Stop' |
            ForEach-Object {
                Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction 'Stop' | Where-Object { ($_.ProfileImagePath) } |
                Select-Object @{ Label = 'NTAccount'; Expression = { $(ConvertTo-NTAccountOrSID -SID $_.PSChildName).Value } }, @{ Label = 'SID'; Expression = { $_.PSChildName } }, @{ Label = 'ProfilePath'; Expression = { $_.ProfileImagePath } }
            }
            If ($ExcludeSystemProfiles) {
                [string[]]$SystemProfiles = 'S-1-5-18', 'S-1-5-19', 'S-1-5-20'
                [psobject[]]$UserProfiles = $UserProfiles | Where-Object { $SystemProfiles -notcontains $_.SID }
            }
            If ($ExcludeNTAccount) {
                [psobject[]]$UserProfiles = $UserProfiles | Where-Object { $ExcludeNTAccount -notcontains $_.NTAccount }
            }

            # Find the path to the Default User profile
            If (-not $ExcludeDefaultUser) {
                [string]$UserProfilesDirectory = Get-ItemProperty -LiteralPath $UserProfileListRegKey -Name 'ProfilesDirectory' -ErrorAction 'Stop' | Select-Object -ExpandProperty 'ProfilesDirectory'

                If ([Environment]::OSVersion.Version.Major -gt 5) {
                    # Path to Default User Profile directory on Windows Vista or higher: By default, C:\Users\Default
                    [string]$DefaultUserProfileDirectory = Get-ItemProperty -LiteralPath $UserProfileListRegKey -Name 'Default' -ErrorAction 'Stop' | Select-Object -ExpandProperty 'Default'
                }

                # Create a custom object for the Default User profile since it is not an actual account
                [psobject]$DefaultUserProfile = New-Object -TypeName 'PSObject' -Property @{
                    NTAccount = 'Default User'
                    SID = 'S-1-5-21-Default-User'
                    ProfilePath = $DefaultUserProfileDirectory
                }

                # Add the Default User custom object to the User Profile list
                $UserProfiles += $DefaultUserProfile
            }

            Write-Output -InputObject $UserProfiles
        }
        Catch {
            Write-Warning -Message 'Failed to create a custom object representing all user profiles on the machine'
        }
    }
    End {
        # Verbose Logging
        Write-Verbose -Message "##### Ending : [$CmdletName]"
    }
}


Function Start-EXEAsUser {
    <#
    .SYNOPSIS
        Execute a process with a logged in user account, by using a scheduled task, to provide interaction with user in the SYSTEM context
    .DESCRIPTION
        Execute a process with a logged in user account, by using a scheduled task, to provide interaction with user in the SYSTEM context
    .PARAMETER UserName
        Logged in Username under which to run the process from. Default is: The active console user
    .PARAMETER Path
        Path to the file being executed
    .PARAMETER Parameters
        Arguments to be passed to the file being executed
    .PARAMETER RunLevel
        Specifies the level of user rights that Task Scheduler uses to run the task. The acceptable values for this parameter are:
        - HighestAvailable: Tasks run by using the highest available privileges (Admin privileges for Administrators). Default Value
        - LeastPrivilege: Tasks run by using the least-privileged user account (LUA) privileges
    .PARAMETER Wait
        Wait for the process, launched by the scheduled task, to complete execution before accepting more input. Default is $false
    .PARAMETER PassThru
        Returns ExitCode, STDOut, and STDErr output from the process
    .PARAMETER ContinueOnError
        Continue if an exit code is returned by msiexec that is not recognized. Default is: $true
    .EXAMPLE
        Start-EXEAsUser -UserName 'DOMAIN\User' -Path "$PSHOME\powershell.exe" -Parameters "-Command & { & `"C:\TestScript.ps1`"; Exit `$LastExitCode }" -Wait
        Execute process under a user account by specifying a username under which to execute it.
    .EXAMPLE
        Start-EXEAsUser -Path "$PSHOME\powershell.exe" -Parameters "-Command & { & `"C:\TestScript.ps1`"; Exit `$LastExitCode }" -Wait
        Execute process under a user account by using the default active logged in user that was detected when the function was launched
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [string]$UserName = (Get-LoggedOnUser | Select-Object -ExpandProperty NTAccount -First 1),
        [Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [string]$Path,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [string]$Parameters = '',
        [Parameter(Mandatory=$false)]
        [ValidateSet('HighestAvailable','LeastPrivilege')]
        [string]$RunLevel = 'HighestAvailable',
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [switch]$Wait = $false,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [switch]$PassThru = $false,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [boolean]$ContinueOnError = $true
    )

    Begin {
        # Verbose Logging
        [string]$CmdletName  = $MyInvocation.MyCommand.Name
        [string]$CmdletParam = $PSBoundParameters | Format-Table -Property @{ Label = 'Parameter'; Expression = { "[-$($_.Key)]" } }, @{ Label = 'Value'; Expression = { $_.Value }; Alignment = 'Left' } -AutoSize -Wrap | Out-String
        Write-Verbose -Message "##### Calling : [$CmdletName]"

        [string]$exeSchTasks = "$env:WinDir\System32\schtasks.exe"
    }
    Process {
        # Initialize exit code variable
        [int32]$executeProcessAsUserExitCode = 0

        # Confirm that the username field is not empty
        If (-not $UserName) {
            [int32]$executeProcessAsUserExitCode = 60009
            Write-Warning -Message "This function has a -UserName parameter that has an empty default value because no logged in users were detected"
            If (-not $ContinueOnError) {
                Throw "The function [$CmdletName] has a -UserName parameter that has an empty default value because no logged in users were detected"
            }
            Else {
                Return
            }
        }

        # Confirm if the function is running with administrator privileges
        If (($RunLevel -eq 'HighestAvailable') -and (-not [boolean](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match 'S-1-5-32-544'))) {
            [int32]$executeProcessAsUserExitCode = 60003
            Write-Warning -Message "This function requires Administrator privileges if the [-RunLevel] parameter is set to 'HighestAvailable'"
            If (-not $ContinueOnError) {
                Throw "The function [$CmdletName] requires Administrator privileges if the [-RunLevel] parameter is set to 'HighestAvailable'"
            }
            Else {
                Return
            }
        }

        ## Build the scheduled task XML name
        [string]$schTaskName = "SoftwarePSM-ExecuteAsUser"

        $tempDir = $(Get-UserProfiles | Where-Object -Property NTAccount -EQ $UserName | Select-Object -ExpandProperty ProfilePath) + "\AppData\Local\Temp"
        If (-not (Test-Path -LiteralPath $tempDir)) {
            Write-Warning -Message "Error finding User Profile [$UserName]"
            Return
        }

        ## If PowerShell.exe is being launched, then create a VBScript to launch PowerShell so that we can suppress the console window that flashes otherwise
        If ((Split-Path -Path $Path -Leaf) -eq 'PowerShell.exe') {
            [string]$executeProcessAsUserParametersVBS = 'chr(34) & ' + "`"$($Path)`"" + ' & chr(34) & ' + '" ' + ($Parameters -replace '"', "`" & chr(34) & `"" -replace ' & chr\(34\) & "$','') + '"'
            [string[]]$executeProcessAsUserScript = "strCommand = $executeProcessAsUserParametersVBS"
            $executeProcessAsUserScript += 'set oWShell = CreateObject("WScript.Shell")'
            $executeProcessAsUserScript += 'intReturn = oWShell.Run(strCommand, 0, true)'
            $executeProcessAsUserScript += 'WScript.Quit intReturn'
            $executeProcessAsUserScript | Out-File -FilePath "$tempDir\$($schTaskName).vbs" -Force -Encoding 'default' -ErrorAction 'SilentlyContinue'
            $Path = 'wscript.exe'
            $Parameters = "`"$tempDir\$($schTaskName).vbs`""
        }

        ## Specify the scheduled task configuration in XML format
        [string]$xmlSchTask = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo />
  <Triggers />
  <Settings>
  <MultipleInstancesPolicy>StopExisting</MultipleInstancesPolicy>
  <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
  <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
  <AllowHardTerminate>true</AllowHardTerminate>
  <StartWhenAvailable>false</StartWhenAvailable>
  <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
  <IdleSettings>
    <StopOnIdleEnd>false</StopOnIdleEnd>
    <RestartOnIdle>false</RestartOnIdle>
  </IdleSettings>
  <AllowStartOnDemand>true</AllowStartOnDemand>
  <Enabled>true</Enabled>
  <Hidden>false</Hidden>
  <RunOnlyIfIdle>false</RunOnlyIfIdle>
  <WakeToRun>false</WakeToRun>
  <ExecutionTimeLimit>PT72H</ExecutionTimeLimit>
  <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
  <Exec>
    <Command>$Path</Command>
    <Arguments>$Parameters</Arguments>
  </Exec>
  </Actions>
  <Principals>
  <Principal id="Author">
    <UserId>$UserName</UserId>
    <LogonType>InteractiveToken</LogonType>
    <RunLevel>$RunLevel</RunLevel>
  </Principal>
  </Principals>
</Task>
"@
        ## Export the XML to file
        Try {
            # Specify the filename to export the XML to
            [string]$xmlSchTaskFilePath = "$tempDir\$schTaskName.xml"
            [string]$xmlSchTask | Out-File -FilePath $xmlSchTaskFilePath -Force -ErrorAction 'Stop'
        }
        Catch {
            [int32]$executeProcessAsUserExitCode = 60007
            Write-Warning -Message "Failed to export the scheduled task XML file [$xmlSchTaskFilePath]"
            If (-not $ContinueOnError) {
                Throw "Failed to export the scheduled task XML file [$xmlSchTaskFilePath]: $($_.Exception.Message)"
            }
            Else {
                Return
            }
        }

        ## Create Scheduled Task to run the process with a logged-on user account
        Write-Verbose -Message "Create scheduled task to run the process [$Path] with parameters [$Parameters] as the logged-on user [$UserName]"
        [psobject]$schTaskResult = Start-EXE -Path $exeSchTasks -Parameters "/create /f /tn $schTaskName /xml `"$xmlSchTaskFilePath`"" -PassThru
        If ($schTaskResult.ExitCode -ne 0) {
            [int32]$executeProcessAsUserExitCode = $schTaskResult.ExitCode
            Write-Warning -Message "Failed to create the scheduled task by importing the scheduled task XML file [$xmlSchTaskFilePath]"
            If (-not $ContinueOnError) {
                Throw "Failed to create the scheduled task by importing the scheduled task XML file [$xmlSchTaskFilePath]"
            }
            Else {
                Return
            }
        }

        ## Trigger the Scheduled Task
        Write-Verbose -Message "Trigger execution of scheduled task with command [$Path] using parameters [$Parameters] as the logged-on user [$UserName]"
        [psobject]$schTaskResult = Start-EXE -Path $exeSchTasks -Parameters "/run /i /tn $schTaskName" -PassThru
        If ($schTaskResult.ExitCode -ne 0) {
            [int32]$executeProcessAsUserExitCode = $schTaskResult.ExitCode
            Write-Warning -Message "Failed to trigger scheduled task [$schTaskName]"
            # Delete Scheduled Task
            Write-Verbose -Message 'Delete the scheduled task which did not trigger'
            $schTaskRemoval = Start-EXE -Path $exeSchTasks -Parameters "/delete /tn $schTaskName /f" -ContinueOnError $true
            If (-not $ContinueOnError) {
                Throw "Failed to trigger scheduled task [$schTaskName]."
            }
            Else {
                Return
            }
        }

        ## Wait for the process launched by the scheduled task to complete execution
        If ($Wait) {
            Write-Verbose -Message "Waiting for the process launched by the scheduled task [$schTaskName] to complete execution (this may take some time)"
            Start-Sleep -Seconds 1
            While ((($exeSchTasksResult = & $exeSchTasks /query /TN $schTaskName /V /FO CSV) | ConvertFrom-CSV | Select-Object -ExpandProperty 'Status' | Select-Object -First 1) -eq 'Running') {
                Start-Sleep -Seconds 5
            }
            # Get the exit code from the process launched by the scheduled task
            [int32]$executeProcessAsUserExitCode = ($exeSchTasksResult = & $exeSchTasks /query /TN $schTaskName /V /FO CSV) | ConvertFrom-CSV | Select-Object -ExpandProperty 'Last Result' | Select-Object -First 1
            Write-Verbose -Message "Exit code from process launched by scheduled task [$executeProcessAsUserExitCode]"
        }

        ## Delete scheduled task
        Try {
            Write-Verbose -Message "Delete scheduled task [$schTaskName]"
            $schTaskRemoval = Start-EXE -Path $exeSchTasks -Parameters "/delete /tn $schTaskName /f" -ErrorAction 'Stop' -PassThru
        }
        Catch {
            Write-Warning -Message "Failed to delete scheduled task [$schTaskName]"
        }
    }
    End {
        If ($PassThru) { Write-Output -InputObject $executeProcessAsUserExitCode }
        # Verbose Logging
        Write-Verbose -Message "##### Ending : [$CmdletName]"
    }
}


Function Get-PendingReboot {
    <#
    .SYNOPSIS
        Get the pending reboot status on a local computer.
    .DESCRIPTION
        Check WMI and the registry to determine if the system has a pending reboot operation from any of the following:
        a) Component Based Servicing
        b) Windows Update / Auto Update
        c) SCCM 2012 Clients (DetermineIfRebootPending WMI method)
        d) Pending File Rename Operations
    .EXAMPLE
        Get-PendingReboot

        Returns custom object with following properties:
        ComputerName, LastBootUpTime, IsSystemRebootPending, IsCBServicingRebootPending, IsWindowsUpdateRebootPending, IsSCCMClientRebootPending, IsFileRenameRebootPending, PendingFileRenameOperations, ErrorMsg

        *Notes: ErrorMsg only contains something if an error occurred
    .EXAMPLE
        (Get-PendingReboot).IsSystemRebootPending
        Returns boolean value determining whether or not there is a pending reboot operation.
    #>

    [CmdletBinding()]
    Param ()

    Begin {
        # Verbose Logging
        [string]$CmdletName  = $MyInvocation.MyCommand.Name
        [string]$CmdletParam = $PSBoundParameters | Format-Table -Property @{ Label = 'Parameter'; Expression = { "[-$($_.Key)]" } }, @{ Label = 'Value'; Expression = { $_.Value }; Alignment = 'Left' } -AutoSize -Wrap | Out-String
        Write-Verbose -Message "##### Calling : [$CmdletName]"

        ## Initialize variables
        [string]$ComputerName = ([Net.Dns]::GetHostEntry('')).HostName
        $PendRebootErrorMsg = $null
    }
    Process {
        Write-Verbose -Message "Get the pending reboot status on the local computer [$ComputerName]"

        ## Get the date/time that the system last booted up
        Try {
            [nullable[datetime]]$LastBootUpTime = (Get-Date -ErrorAction 'Stop') - ([timespan]::FromMilliseconds([math]::Abs([Environment]::TickCount)))
        }
        Catch {
            [nullable[datetime]]$LastBootUpTime = $null
            [string[]]$PendRebootErrorMsg += "Failed to get LastBootUpTime: $($_.Exception.Message)"
            Write-Warning -Message 'Failed to get LastBootUpTime'
        }

        ## Determine if the machine has a pending reboot from a Component Based Servicing (CBS) operation
        Try {
            If ([Environment]::OSVersion.Version.Major -ge 5) {
                If (Test-Path -LiteralPath 'HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending' -ErrorAction 'Stop') {
                    [nullable[boolean]]$IsCBServicingRebootPending = $true
                }
                Else {
                    [nullable[boolean]]$IsCBServicingRebootPending = $false
                }
            }
        }
        Catch {
            [nullable[boolean]]$IsCBServicingRebootPending = $null
            [string[]]$PendRebootErrorMsg += "Failed to get IsCBServicingRebootPending: $($_.Exception.Message)"
            Write-Warning -Message 'Failed to get IsCBServicingRebootPending'
        }

        ## Determine if there is a pending reboot from a Windows Update
        Try {
            If (Test-Path -LiteralPath 'HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired' -ErrorAction 'Stop') {
                [nullable[boolean]]$IsWindowsUpdateRebootPending = $true
            }
            Else {
                [nullable[boolean]]$IsWindowsUpdateRebootPending = $false
            }
        }
        Catch {
            [nullable[boolean]]$IsWindowsUpdateRebootPending = $null
            [string[]]$PendRebootErrorMsg += "Failed to get IsWindowsUpdateRebootPending: $($_.Exception.Message)"
            Write-Warning -Message 'Failed to get IsWindowsUpdateRebootPending'
        }

        ## Determine if there is a pending reboot from a pending file rename operation
        [boolean]$IsFileRenameRebootPending = $false
        $PendingFileRenameOperations = $null
        If (Get-ItemProperty -LiteralPath 'HKLM:SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'PendingFileRenameOperations' -ErrorAction SilentlyContinue) {
            # If PendingFileRenameOperations value exists, set $IsFileRenameRebootPending variable to $true
            [boolean]$IsFileRenameRebootPending = $true
            # Get the value of PendingFileRenameOperations
            Try {
                [string[]]$PendingFileRenameOperations = Get-ItemProperty -LiteralPath 'HKLM:SYSTEM\CurrentControlSet\Control\Session Manager' -ErrorAction 'Stop' | Select-Object -ExpandProperty 'PendingFileRenameOperations' -ErrorAction 'Stop'
            }
            Catch {
                [string[]]$PendRebootErrorMsg += "Failed to get PendingFileRenameOperations: $($_.Exception.Message)"
                Write-Warning -Message 'Failed to get PendingFileRenameOperations'
            }
        }

        ## Determine SCCM 2012 Client reboot pending status
        Try {
            Try {
                [boolean]$IsSccmClientNamespaceExists = [boolean](Get-WmiObject -Namespace 'ROOT\CCM\ClientSDK' -List -ErrorAction 'Stop' | Where-Object { $_.Name -eq 'CCM_ClientUtilities' })
            }
            Catch [System.Management.ManagementException] {
                $CmdException = $_
                If ($CmdException.FullyQualifiedErrorId -eq 'INVALID_NAMESPACE_IDENTIFIER,Microsoft.PowerShell.Commands.GetWmiObjectCommand') {
                    [boolean]$IsSccmClientNamespaceExists = $false
                }
            }

            If ($IsSccmClientNamespaceExists) {
                [psobject]$SCCMClientRebootStatus = Invoke-WmiMethod -ComputerName $ComputerName -NameSpace 'ROOT\CCM\ClientSDK' -Class 'CCM_ClientUtilities' -Name 'DetermineIfRebootPending' -ErrorAction 'Stop'
                If ($SCCMClientRebootStatus.ReturnValue -ne 0) {
                    Throw "'DetermineIfRebootPending' method of 'ROOT\CCM\ClientSDK\CCM_ClientUtilities' class returned error code [$($SCCMClientRebootStatus.ReturnValue)]"
                }
                Else {
                    [nullable[boolean]]$IsSCCMClientRebootPending = $false
                    If ($SCCMClientRebootStatus.IsHardRebootPending -or $SCCMClientRebootStatus.RebootPending) {
                        [nullable[boolean]]$IsSCCMClientRebootPending = $true
                    }
                }
            }
            Else {
                [nullable[boolean]]$IsSCCMClientRebootPending = $null
            }
        }
        Catch {
            [nullable[boolean]]$IsSCCMClientRebootPending = $null
            [string[]]$PendRebootErrorMsg += "Failed to get IsSCCMClientRebootPending: $($_.Exception.Message)"
            Write-Warning -Message 'Failed to get IsSCCMClientRebootPending'
        }

        ## Determine if there is a pending reboot for the system
        [boolean]$IsSystemRebootPending = $false
        If ($IsCBServicingRebootPending -or $IsWindowsUpdateRebootPending -or $IsSCCMClientRebootPending -or $IsFileRenameRebootPending) {
            [boolean]$IsSystemRebootPending = $true
        }

        ## Create a custom object containing pending reboot information for the system
        [psobject]$PendingRebootInfo = New-Object -TypeName 'PSObject' -Property @{
            ComputerName                 = $ComputerName
            LastBootUpTime               = $LastBootUpTime
            IsSystemRebootPending        = $IsSystemRebootPending
            IsCBServicingRebootPending   = $IsCBServicingRebootPending
            IsWindowsUpdateRebootPending = $IsWindowsUpdateRebootPending
            IsSCCMClientRebootPending    = $IsSCCMClientRebootPending
            IsFileRenameRebootPending    = $IsFileRenameRebootPending
            PendingFileRenameOperations  = $PendingFileRenameOperations
            ErrorMsg                     = $PendRebootErrorMsg
        }
    }
    End {
        Write-Output -InputObject ($PendingRebootInfo | Select-Object -Property 'ComputerName','LastBootUpTime','IsSystemRebootPending','IsCBServicingRebootPending','IsWindowsUpdateRebootPending','IsSCCMClientRebootPending','IsFileRenameRebootPending','PendingFileRenameOperations','ErrorMsg')

        # Verbose Logging
        Write-Verbose -Message "##### Ending : [$CmdletName]"
    }
}


Function Get-ScheduledTasks {
    <#
    .SYNOPSIS
        Retrieve all details for scheduled tasks on the local computer
    .DESCRIPTION
        Retrieve all details for scheduled tasks on the local computer using schtasks.exe. All property names have spaces and colons removed
    .PARAMETER TaskName
        Specify the name of the scheduled task to retrieve details for. Uses regex match to find scheduled task
    .PARAMETER ContinueOnError
        Continue if an error is encountered. Default: $true.
    .EXAMPLE
        Get-ScheduledTasks
        To display a list of all scheduled task properties
    .EXAMPLE
        Get-ScheduledTasks | Out-GridView
        To display a grid view of all scheduled task properties.
    .EXAMPLE
        Get-ScheduledTasks | Select-Object -Property TaskName
        To display a list of all scheduled task names
    .NOTES
        'Get-ScheduledTasks' can be replaced with the built-in cmdlet 'Get-ScheduledTask' in Windows 8.1+
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$TaskName,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [boolean]$ContinueOnError = $true
    )

    Begin {
        # Verbose Logging
        [string]$CmdletName  = $MyInvocation.MyCommand.Name
        [string]$CmdletParam = $PSBoundParameters | Format-Table -Property @{ Label = 'Parameter'; Expression = { "[-$($_.Key)]" } }, @{ Label = 'Value'; Expression = { $_.Value }; Alignment = 'Left' } -AutoSize -Wrap | Out-String
        Write-Verbose -Message "##### Calling : [$CmdletName]"

        [string]$exeSchTasks = "$env:WINDIR\system32\schtasks.exe"
        [psobject[]]$ScheduledTasks = @()
    }
    Process {
        Try {
            Write-Verbose 'Retrieve Scheduled Tasks...'
            [string[]]$exeSchtasksResults = & $exeSchTasks /Query /V /FO CSV
            If ($Global:LastExitCode -ne 0) {
                Throw "Failed to retrieve scheduled tasks using [$exeSchTasks]"
            }
            [psobject[]]$SchtasksResults = $exeSchtasksResults | ConvertFrom-CSV -Header 'HostName', 'TaskName', 'Next Run Time', 'Status', 'Logon Mode', 'Last Run Time', 'Last Result', 'Author', 'Task To Run', 'Start In', 'Comment', 'Scheduled Task State', 'Idle Time', 'Power Management', 'Run As User', 'Delete Task If Not Rescheduled', 'Stop Task If Runs X Hours and X Mins', 'Schedule', 'Schedule Type', 'Start Time', 'Start Date', 'End Date', 'Days', 'Months', 'Repeat: Every', 'Repeat: Until: Time', 'Repeat: Until: Duration', 'Repeat: Stop If Still Running' -ErrorAction 'Stop'

            If ($SchtasksResults) {
                ForEach ($SchtasksResult in $SchtasksResults) {
                    If ($SchtasksResult.TaskName -match $TaskName) {
                        $SchtasksResult | Get-Member -MemberType 'Properties' |
                        ForEach -Begin {
                            [hashtable]$Task = @{}
                        } -Process {
                            # Remove spaces and colons in property names. Do not set property value if line being processed is a column header
                            ($Task.($($_.Name).Replace(' ','').Replace(':',''))) = If ($_.Name -ne $SchtasksResult.($_.Name)) { $SchtasksResult.($_.Name) }
                        } -End {
                            ## Only add task to the custom object if all property values are not empty
                            If (($Task.Values | Select-Object -Unique | Measure-Object).Count) {
                                $ScheduledTasks += New-Object -TypeName 'PSObject' -Property $Task
                            }
                        }
                    }
                }
            }
        }
        Catch {
            Write-Warning -Message 'Failed to retrieve scheduled tasks'
            If (-not $ContinueOnError) {
                Throw "Failed to retrieve scheduled tasks: $($_.Exception.Message)"
            }
        }
    }
    End {
        Write-Output -InputObject $ScheduledTasks

        # Verbose Logging
        Write-Verbose -Message "##### Ending : [$CmdletName]"
    }
}


Function Update-Desktop {
    <#
    .SYNOPSIS
        Refresh the Windows Explorer Shell
    .DESCRIPTION
        Refresh the Windows Explorer Shell, causing the desktop icons and the environment variables to be reloaded
    .EXAMPLE
        Update-Desktop
    #>

    [CmdletBinding()]
    Param ()

    Begin {
        # Verbose Logging
        [string]$CmdletName  = $MyInvocation.MyCommand.Name
        [string]$CmdletParam = $PSBoundParameters | Format-Table -Property @{ Label = 'Parameter'; Expression = { "[-$($_.Key)]" } }, @{ Label = 'Value'; Expression = { $_.Value }; Alignment = 'Left' } -AutoSize -Wrap | Out-String
        Write-Verbose -Message "##### Calling : [$CmdletName]"

        # Load C# Namespace if required
        If (-not ([Management.Automation.PSTypeName]'PSSM.Explorer').Type) {
            $CSSourceCode = @"
using System;
using System.Runtime.InteropServices;

namespace PSSM
{
  public class Explorer
  {
    private static readonly IntPtr HWND_BROADCAST = new IntPtr(0xffff);
    private const int WM_SETTINGCHANGE = 0x1a;
    private const int SMTO_ABORTIFHUNG = 0x0002;

    [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = false)]
    static extern bool SendNotifyMessage(IntPtr hWnd, int Msg, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = false)]
    private static extern IntPtr SendMessageTimeout(IntPtr hWnd, int Msg, IntPtr wParam, string lParam, int fuFlags, int uTimeout, IntPtr lpdwResult);

    [DllImport("shell32.dll", CharSet = CharSet.Auto, SetLastError = false)]
    private static extern int SHChangeNotify(int eventId, int flags, IntPtr item1, IntPtr item2);

    public static void RefreshDesktopAndEnvironmentVariables()
    {
      // Update desktop icons
      SHChangeNotify(0x8000000, 0x1000, IntPtr.Zero, IntPtr.Zero);
      SendMessageTimeout(HWND_BROADCAST, WM_SETTINGCHANGE, IntPtr.Zero, null, SMTO_ABORTIFHUNG, 100, IntPtr.Zero);
      // Update environment variables
      SendMessageTimeout(HWND_BROADCAST, WM_SETTINGCHANGE, IntPtr.Zero, "Environment", SMTO_ABORTIFHUNG, 100, IntPtr.Zero);
    }
  }
}
"@

            Write-Verbose -Message 'Loading C# Namespace'
            Add-Type -TypeDefinition $CSSourceCode -Language CSharp
        }
    }
    Process {
        Try {
            Write-Verbose -Message 'Refresh the Desktop and the Windows Explorer environment process block'
            [PSSM.Explorer]::RefreshDesktopAndEnvironmentVariables()
        }
        Catch {
            Write-Warning -Message 'Failed to refresh the Desktop and the Windows Explorer environment process block'
        }
    }
    End {
        # Verbose Logging
        Write-Verbose -Message "##### Ending : [$CmdletName]"
    }
}


Function Block-AppExecution {
    <#
    .SYNOPSIS
        Block the execution of an application(s)
    .DESCRIPTION
        Block the execution of an application(s) by :
        1. Checks for an existing scheduled task from a previous failed installation attempt where apps were blocked and if found, calls the Unblock-AppExecution function to restore the original IFEO registry keys
           This is to prevent the function from overriding the backup of the original IFEO options
        2. Creates a scheduled task to restore the IFEO registry key values in case the script is terminated uncleanly by calling a local temporary copy of the Unblock-AppExecution function
        3. Modifies the "Image File Execution Options" registry key for the specified process(s)
    .PARAMETER ProcessName
        Name of the process or processes separated by commas
    .EXAMPLE
        Block-AppExecution -ProcessName 'winword'
    .EXAMPLE
        Block-AppExecution -ProcessName 'excel','winword'
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [string[]]$ProcessName
    )

    Begin {
        # Verbose Logging
        [string]$CmdletName  = $MyInvocation.MyCommand.Name
        [string]$CmdletParam = $PSBoundParameters | Format-Table -Property @{ Label = 'Parameter'; Expression = { "[-$($_.Key)]" } }, @{ Label = 'Value'; Expression = { $_.Value }; Alignment = 'Left' } -AutoSize -Wrap | Out-String
        Write-Verbose -Message "##### Calling : [$CmdletName]"

        # Use built-in 'Get-ScheduledTask' function if available
        If (Get-Command -Name Get-ScheduledTask -CommandType Function -ErrorAction SilentlyContinue) {
            $GetSchTaskFunc = 'Get-ScheduledTask'
        }
        # Use 'Get-ScheduledTasks' function if not
        Else {
            $GetSchTaskFunc = 'Get-ScheduledTasks'
        }

        # IFEO Registry Location
        [string]$regKeyAppExecution = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
        # Task Scheduler Executable
        [string]$exeSchTasks = "$env:windir\System32\schtasks.exe"

        # Create Temporary Script Folder
        $AppBlockScript = "$env:WinDir\Temp\SoftwarePSM\AppBlock"
        If (-not (Test-Path -LiteralPath $AppBlockScript -PathType 'Container')) {
            New-Item -Path $AppBlockScript -ItemType 'Directory' -Force -ErrorAction 'Stop' | Out-Null
        }
        # Write unblock script to machine (rework)
        #$UnBlockScript = (Get-Command -CommandType Function Unblock-AppExecution).Definition
        #Out-File -InputObject $UnBlockScript -FilePath "$AppBlockScript\Unblock-AppExecutionScript.ps1" -Force -Encoding 'default' -ErrorAction 'SilentlyContinue'
        $GetSchTaskScript = 'Function Get-ScheduledTasks' + '{' + (Get-Command -CommandType Function Get-ScheduledTasks).Definition + '}'
        $UnBlockScript    = 'Function Unblock-AppExecution' + '{' + (Get-Command -CommandType Function Unblock-AppExecution).Definition + '}' + 'Unblock-AppExecution'
        Out-File -InputObject $GetSchTaskScript,$UnBlockScript -FilePath "$AppBlockScript\Unblock-AppExecutionScript.ps1" -Force -Encoding 'default' -ErrorAction 'SilentlyContinue'

        [string]$schTaskUnblockAppsCommand += "-ExecutionPolicy Bypass -NoProfile -NoLogo -WindowStyle Hidden -File `"$AppBlockScript\Unblock-AppExecutionScript.ps1`""
        # Specify the scheduled task configuration in XML format
        [string]$xmlUnblockAppsSchTask = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo></RegistrationInfo>
  <Triggers>
    <BootTrigger>
      <Enabled>true</Enabled>
    </BootTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT1H</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>$schTaskUnblockAppsCommand</Arguments>
    </Exec>
  </Actions>
</Task>
"@
    }
    Process {
        [string]$schTaskBlockedAppsName = "SoftwarePSM-BlockedApps"

        # Set the debugger block value
        [string]$debuggerBlockValue = 'PSSM_BlockAppExecution'

        # Create a scheduled task to run on startup to call this script and clean up blocked applications in case the installation is interrupted, e.g. user shuts down during installation"
        Write-Verbose -Message 'Create scheduled task to cleanup blocked applications in case installation is interrupted'
        If (& $GetSchTaskFunc | Select-Object -Property 'TaskName' | Where-Object { $_.TaskName -eq "$schTaskBlockedAppsName" }) {
            Write-Verbose -Message "Scheduled task [$schTaskBlockedAppsName] already exists"
        }
        Else {
            # Export the scheduled task XML to file
            Try {
                # Specify the filename to export the XML to
                [string]$xmlSchTaskFilePath = "$AppBlockScript\SchTaskUnBlockApps.xml"
                [string]$xmlUnblockAppsSchTask | Out-File -FilePath $xmlSchTaskFilePath -Force -ErrorAction 'Stop'
            }
            Catch {
                Write-Warning -Message "Failed to export the scheduled task XML file [$xmlSchTaskFilePath]"
                Return
            }

            # Import the Scheduled Task XML file to create the Scheduled Task
            [psobject]$schTaskResult = Start-EXE -Path $exeSchTasks -Parameters "/create /f /tn $schTaskBlockedAppsName /xml `"$xmlSchTaskFilePath`"" -PassThru
            If ($schTaskResult.ExitCode -ne 0) {
                Write-Warning -Message "Failed to create the scheduled task [$schTaskBlockedAppsName] by importing the scheduled task XML file [$xmlSchTaskFilePath]"
                Return
            }
        }

        [string[]]$blockProcessName = $processName
        # Append .exe to match registry keys
        [string[]]$blockProcessName = $blockProcessName | ForEach-Object { $_ + '.exe' } -ErrorAction 'SilentlyContinue'

        # Enumerate each process and set the debugger value to block application execution
        ForEach ($blockProcess in $blockProcessName) {
            # Create/Set/Update Registry keys and values
            Write-Verbose -Message "Set the Image File Execution Option registry key to block execution of [$blockProcess]"
            Set-RegistryKey -Key (Join-Path -Path $regKeyAppExecution -ChildPath $blockProcess) -Name 'Debugger' -Value $debuggerBlockValue
        }
    }
    End {
        # Verbose Logging
        Write-Verbose -Message "##### Ending : [$CmdletName]"
    }
}


Function Unblock-AppExecution {
    <#
    .SYNOPSIS
        Unblocks the execution of applications performed by the Block-AppExecution function
    .DESCRIPTION
        Unblocks the execution of applications performed by the Block-AppExecution function
    .EXAMPLE
        Unblock-AppExecution
    #>

    [CmdletBinding()]
    Param ()

    Begin {
        # Verbose Logging
        [string]$CmdletName  = $MyInvocation.MyCommand.Name
        [string]$CmdletParam = $PSBoundParameters | Format-Table -Property @{ Label = 'Parameter'; Expression = { "[-$($_.Key)]" } }, @{ Label = 'Value'; Expression = { $_.Value }; Alignment = 'Left' } -AutoSize -Wrap | Out-String
        Write-Verbose -Message "##### Calling : [$CmdletName]"

        # Use built-in 'Get-ScheduledTask' function if available
        If (Get-Command -Name Get-ScheduledTask -CommandType Function -ErrorAction SilentlyContinue) {
            $GetSchTaskFunc = 'Get-ScheduledTask'
        }
        # Use 'Get-ScheduledTasks' function if not
        Else {
            $GetSchTaskFunc = 'Get-ScheduledTasks'
        }

        # IFEO Registry Location
        [string]$regKeyAppExecution = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
        # Task Scheduler Executable
        [string]$exeSchTasks = "$env:windir\System32\schtasks.exe"
    }
    Process {
        # Remove IEFO Debugger values to unblock processes
        [psobject[]]$unblockProcesses = $null
        [psobject[]]$unblockProcesses += (Get-ChildItem -LiteralPath $regKeyAppExecution -Recurse -ErrorAction 'SilentlyContinue' | ForEach-Object { Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction 'SilentlyContinue' })
        ForEach ($unblockProcess in ($unblockProcesses | Where-Object { $_.Debugger -like '*PSSM_BlockAppExecution*' })) {
            Write-Verbose -Message "Remove the Image File Execution Options registry key to unblock execution of [$($unblockProcess.PSChildName)]."
            $unblockProcess | Remove-ItemProperty -Name 'Debugger' -ErrorAction 'SilentlyContinue'
        }

        # Remove the scheduled task if it exists
        [string]$schTaskBlockedAppsName = "SoftwarePSM-BlockedApps"
        If (& $GetSchTaskFunc | Select-Object -Property 'TaskName' | Where-Object { $_.TaskName -eq "$schTaskBlockedAppsName" }) {
            Write-Verbose -Message "Delete Scheduled Task [$schTaskBlockedAppsName]"
            Start-Process -FilePath $exeSchTasks -ArgumentList "/Delete /TN $schTaskBlockedAppsName /F" -NoNewWindow -Wait
        }
    }
    End {
        # Verbose Logging
        Write-Verbose -Message "##### Ending : [$CmdletName]"
    }
}


Function Convert-RegistryPath {
    <#
    .SYNOPSIS
        Converts the specified registry key path to a format that is compatible with built-in PowerShell cmdlets
    .DESCRIPTION
        Converts the specified registry key path to a format that is compatible with built-in PowerShell cmdlets
        Converts registry key hives to their full paths. Example: HKLM is converted to "Registry::HKEY_LOCAL_MACHINE"
    .PARAMETER Key
        Path to the registry key to convert (can be a registry hive or fully qualified path)
    .EXAMPLE
        Convert-RegistryPath -Key 'HKEY_LOCAL_MACHINE\SOFTWARE\Test'
    .EXAMPLE
        Convert-RegistryPath -Key 'HKLM:SOFTWARE\Test'
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [string]$Key
    )

    Begin {}
    Process {
        # Convert the registry key hive to the full path, only match if at the beginning of the line
        If ($Key -match '^HKLM:\\|^HKCU:\\|^HKCR:\\|^HKU:\\|^HKCC:\\|^HKPD:\\') {
            # Converts registry paths that start with, e.g.: HKLM:\
            $Key = $Key -replace '^HKLM:\\', 'HKEY_LOCAL_MACHINE\'
            $Key = $Key -replace '^HKCR:\\', 'HKEY_CLASSES_ROOT\'
            $Key = $Key -replace '^HKCU:\\', 'HKEY_CURRENT_USER\'
            $Key = $Key -replace '^HKU:\\',  'HKEY_USERS\'
            $Key = $Key -replace '^HKCC:\\', 'HKEY_CURRENT_CONFIG\'
            $Key = $Key -replace '^HKPD:\\', 'HKEY_PERFORMANCE_DATA\'
        }
        ElseIf ($Key -match '^HKLM:|^HKCU:|^HKCR:|^HKU:|^HKCC:|^HKPD:') {
            # Converts registry paths that start with, e.g.: HKLM:
            $Key = $Key -replace '^HKLM:', 'HKEY_LOCAL_MACHINE\'
            $Key = $Key -replace '^HKCR:', 'HKEY_CLASSES_ROOT\'
            $Key = $Key -replace '^HKCU:', 'HKEY_CURRENT_USER\'
            $Key = $Key -replace '^HKU:',  'HKEY_USERS\'
            $Key = $Key -replace '^HKCC:', 'HKEY_CURRENT_CONFIG\'
            $Key = $Key -replace '^HKPD:', 'HKEY_PERFORMANCE_DATA\'
        }
        ElseIf ($Key -match '^HKLM\\|^HKCU\\|^HKCR\\|^HKU\\|^HKCC\\|^HKPD\\') {
            # Converts registry paths that start with, e.g.: HKLM\
            $Key = $Key -replace '^HKLM\\', 'HKEY_LOCAL_MACHINE\'
            $Key = $Key -replace '^HKCR\\', 'HKEY_CLASSES_ROOT\'
            $Key = $Key -replace '^HKCU\\', 'HKEY_CURRENT_USER\'
            $Key = $Key -replace '^HKU\\',  'HKEY_USERS\'
            $Key = $Key -replace '^HKCC\\', 'HKEY_CURRENT_CONFIG\'
            $Key = $Key -replace '^HKPD\\', 'HKEY_PERFORMANCE_DATA\'
        }

        # Append the PowerShell drive to the registry key path
        If ($Key -notmatch '^Registry::') { [string]$Key = "Registry::$Key" }

        If ($Key -match '^Registry::HKEY_LOCAL_MACHINE|^Registry::HKEY_CLASSES_ROOT|^Registry::HKEY_CURRENT_USER|^Registry::HKEY_USERS|^Registry::HKEY_CURRENT_CONFIG|^Registry::HKEY_PERFORMANCE_DATA') {
            Write-Output -InputObject $Key
        }
        Else {
            # If key string is not properly formatted, throw an error
            Throw "Unable to detect target registry hive in string [$Key]."
        }
    }
    End {}
}


Function Set-RegistryKey {
    <#
    .SYNOPSIS
        Creates a registry key name, value, and value data
    .DESCRIPTION
        Creates a registry key name, value, and value data, updating if it already exists
    .PARAMETER Key
        The registry key path
    .PARAMETER Name
        The value name
    .PARAMETER Value
        The value data
    .PARAMETER Type
        The type of registry value to create or set. Options: 'Binary','DWord','ExpandString','MultiString','None','QWord','String','Unknown'. Default: String
    .PARAMETER ContinueOnError
        Continue if an exit code is returned by msiexec that is not recognized. Default is: $true
    .EXAMPLE
        Set-RegistryKey -Key 'HKEY_LOCAL_MACHINE\SOFTWARE\Test' -Name 'TestName' -Value 'TestValue' -Type String
    .EXAMPLE
        Set-RegistryKey -Key 'HKLM:SOFTWARE\Test'
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateScript({ Convert-RegistryPath -Key $_ })]
        [string]$Key,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,
        [Parameter(Mandatory=$false)]
        $Value,
        [Parameter(Mandatory=$false)]
        [ValidateSet('Binary','DWord','ExpandString','MultiString','None','QWord','String','Unknown')]
        [Microsoft.Win32.RegistryValueKind]$Type = 'String',
        [Parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [boolean]$ContinueOnError = $true
    )

    Begin {
        # Verbose Logging
        [string]$CmdletName  = $MyInvocation.MyCommand.Name
        [string]$CmdletParam = $PSBoundParameters | Format-Table -Property @{ Label = 'Parameter'; Expression = { "[-$($_.Key)]" } }, @{ Label = 'Value'; Expression = { $_.Value }; Alignment = 'Left' } -AutoSize -Wrap | Out-String
        Write-Verbose -Message "##### Calling : [$CmdletName]"
    }
    Process {
        Try {
            # Convert registry key hive to its full path
            $Key = Convert-RegistryPath -Key $Key
            # Create registry key if it doesn't exist
            If (-not (Test-Path -LiteralPath $Key -ErrorAction 'Stop')) {
                Try {
                    Write-Verbose -Message "Create registry key [$Key]"
                    $null = New-Item -Path $Key -ItemType 'Registry' -Force -ErrorAction 'Stop'
                }
                Catch {
                    Throw
                }
            }

            If ($Name) {
                # Set registry value if it doesn't exist
                If (-not (Get-ItemProperty -LiteralPath $Key -Name $Name -ErrorAction 'SilentlyContinue')) {
                    Write-Verbose -Message "Set registry key value: [$Key] [$Name = $Value]"
                    $null = New-ItemProperty -LiteralPath $Key -Name $Name -Value $Value -PropertyType $Type -ErrorAction 'Stop'
                }
                # Update registry value if it does exist
                Else {
                    [string]$RegistryValueWriteAction = 'update'
                    Write-Verbose -Message "Update registry key value: [$Key] [$Name = $Value]"
                    $null = Set-ItemProperty -LiteralPath $Key -Name $Name -Value $Value -ErrorAction 'Stop'
                }
            }
        }
        Catch {
            If ($Name) {
                Write-Warning -Message "Failed to $RegistryValueWriteAction value [$Value] for registry key [$Key] [$Name]"
                If (-not $ContinueOnError) {
                    Throw "Failed to $RegistryValueWriteAction value [$Value] for registry key [$Key] [$Name]: $($_.Exception.Message)"
                }
            }
            Else {
                Write-Warning -Message "Failed to set registry key [$Key]"
                If (-not $ContinueOnError) {
                    Throw "Failed to set registry key [$Key]: $($_.Exception.Message)"
                }
            }
        }
    }
    End {
        # Verbose Logging
        Write-Verbose -Message "##### Ending : [$CmdletName]"
    }
}


Function Remove-RegistryKey {
    <#
    .SYNOPSIS
        Deletes the specified registry key or value
    .DESCRIPTION
        Deletes the specified registry key or value
    .PARAMETER Key
        Path of the registry key to delete
    .PARAMETER Name
        Name of the registry value to delete
    .PARAMETER Recurse
        Delete registry key recursively
    .PARAMETER ContinueOnError
        Continue if an exit code is returned by msiexec that is not recognized. Default is: $true
    .EXAMPLE
        Remove-RegistryKey -Key 'HKEY_LOCAL_MACHINE\SOFTWARE\Test' -Recurse
    .EXAMPLE
        Remove-RegistryKey -Key 'HKLM:SOFTWARE\Test' -Name 'TestName'
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateScript({ Convert-RegistryPath -Key $_ })]
        [string]$Key,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,
        [Parameter(Mandatory=$false)]
        [switch]$Recurse,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [boolean]$ContinueOnError = $true
    )

    Begin {
        # Verbose Logging
        [string]$CmdletName  = $MyInvocation.MyCommand.Name
        [string]$CmdletParam = $PSBoundParameters | Format-Table -Property @{ Label = 'Parameter'; Expression = { "[-$($_.Key)]" } }, @{ Label = 'Value'; Expression = { $_.Value }; Alignment = 'Left' } -AutoSize -Wrap | Out-String
        Write-Verbose -Message "##### Calling : [$CmdletName]"
    }
    Process {
        Try {
            # Convert registry key hive to its full path
            $Key = Convert-RegistryPath -Key $Key
            If (-not ($Name)) {
                If (Test-Path -LiteralPath $Key -ErrorAction 'Stop') {
                    If ($Recurse) {
                        Write-Verbose -Message "Delete registry key recursively [$Key]"
                        $null = Remove-Item -LiteralPath $Key -Force -Recurse -ErrorAction 'Stop'
                    }
                    Else {
                        # Use Get-ChildItem to workaround non-existant subkey quirk of Remove-Item
                        If ($null -eq (Get-ChildItem -LiteralPath $Key -ErrorAction 'Stop')) {
                            Write-Verbose -Message "Delete registry key [$Key]"
                            $null = Remove-Item -LiteralPath $Key -Force -ErrorAction 'Stop'
                        }
                        Else {
                            Throw "Unable to delete child key(s) of [$Key] without [-Recurse] switch"
                        }
                    }
                }
                Else {
                    Write-Warning -Message "Unable to delete registry key [$Key] because it does not exist"
                }
            }
            Else {
                If (Get-ItemProperty -Path $Key -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $Name) {
                    Write-Verbose -Message "Delete registry value [$Key] [$Name]"
                    $null = Remove-ItemProperty -LiteralPath $Key -Name $Name -Force -ErrorAction 'Stop'
                }
                Else {
                    Write-Warning -Message "Unable to delete registry value [$Key] [$Name] because registry key does not exist"
                }
            }
        }
        Catch [System.Management.Automation.PSArgumentException] {
            Write-Warning -Message "Unable to delete registry value [$Key] [$Name] because it does not exist"
        }
        Catch {
            If (-not ($Name)) {
                Write-Warning -Message "Failed to delete registry key [$Key]"
                If (-not $ContinueOnError) {
                    Throw "Failed to delete registry key [$Key]: $($_.Exception.Message)"
                }
            }
            Else {
                Write-Warning -Message "Failed to delete registry value [$Key] [$Name]"
                If (-not $ContinueOnError) {
                    Throw "Failed to delete registry value [$Key] [$Name]: $($_.Exception.Message)"
                }
            }
        }
    }
    End {
        # Verbose Logging
        Write-Verbose -Message "##### Ending : [$CmdletName]"
    }
}


Function Update-GroupPolicy {
    <#
    .SYNOPSIS
        Performs a gpupdate command to refresh Group Policies on the local machine
    .DESCRIPTION
        Performs a gpupdate command to refresh Group Policies on the local machine
    .EXAMPLE
        Update-GroupPolicy
    #>

    [CmdletBinding()]
    Param ()

    Begin {
        # Verbose Logging
        [string]$CmdletName  = $MyInvocation.MyCommand.Name
        [string]$CmdletParam = $PSBoundParameters | Format-Table -Property @{ Label = 'Parameter'; Expression = { "[-$($_.Key)]" } }, @{ Label = 'Value'; Expression = { $_.Value }; Alignment = 'Left' } -AutoSize -Wrap | Out-String
        Write-Verbose -Message "##### Calling : [$CmdletName]"
    }
    Process {
        [string[]]$GPUpdateCmds = '/C echo N | gpupdate.exe /Target:Computer /Force', '/C echo N | gpupdate.exe /Target:User /Force'
        [int32]$InstallCount = 0
        ForEach ($GPUpdateCmd in $GPUpdateCmds) {
            Try {
                If ($InstallCount -eq 0) {
                    [string]$InstallMsg = 'Update Group Policies for the Machine'
                    Write-Verbose -Message "$($InstallMsg)..."
                }
                Else {
                    [string]$InstallMsg = 'Update Group Policies for the User'
                    Write-Verbose -Message "$($InstallMsg)..."
                }
                [psobject]$ExecuteResult = Start-EXE -Path "$env:windir\system32\cmd.exe" -Parameters $GPUpdateCmd -PassThru

                If ($ExecuteResult.ExitCode -ne 0) {
                    If ($ExecuteResult.ExitCode -eq 60002) {
                        Throw "Start-EXE function failed with exit code [$($ExecuteResult.ExitCode)]"
                    }
                    Else {
                        Throw "gpupdate.exe failed with exit code [$($ExecuteResult.ExitCode)]"
                    }
                }
                $InstallCount++
            }
            Catch {
                Write-Warning -Message "Failed to $($InstallMsg)"
                Continue
            }
        }
    }
    End {
        # Verbose Logging
        Write-Verbose -Message "##### Ending : [$CmdletName]"
    }
}


Function Get-PowerSupply {
    <#
    .SYNOPSIS
        Retrieve Power Supply information from the local machine
    .DESCRIPTION
        Retrieve Power Supply information from the local machine
    .EXAMPLE
        Get-PowerSupply
    .EXAMPLE
        (Get-PowerSupply).IsLaptop
        Determines if the current system is a laptop or not
    .EXAMPLE
        (Get-PowerSupply).IsUsingACPower
        Determines if the current system is a laptop or not
    .NOTES
        IsLaptop - [Boolean]
        IsUsingACPower - [Boolean]
        ACPowerLineStatusBatteryChargeStatus :
                [Offline] : The system is not using AC power
                [Online]  : The system is using AC power
                [Unknown] : The power status of the system is unknown
        BatteryLifePercent - Get the approximate amount of full battery charge remaining
        BatteryLifeRemaining - Approximate number of seconds of battery life remaining
        BatteryFullLifetime - Reported number of seconds of battery life available when the battery is fully charged
    #>

    [CmdletBinding()]
    Param ()

    Begin {
        # Verbose Logging
        [string]$CmdletName  = $MyInvocation.MyCommand.Name
        [string]$CmdletParam = $PSBoundParameters | Format-Table -Property @{ Label = 'Parameter'; Expression = { "[-$($_.Key)]" } }, @{ Label = 'Value'; Expression = { $_.Value }; Alignment = 'Left' } -AutoSize -Wrap | Out-String
        Write-Verbose -Message "##### Calling : [$CmdletName]"

        # Add assembly for more reliable PowerStatus class in cases where the battery is failing
        Add-Type -Assembly 'System.Windows.Forms' -ErrorAction 'SilentlyContinue'

        # Initialize a hashtable to store information about system type and power status
        [hashtable]$SystemTypePowerStatus = @{}
    }
    Process {
        Write-Verbose -Message 'Check if system is using AC power or if it is running on battery...'

        [Windows.Forms.PowerStatus]$PowerStatus = [Windows.Forms.SystemInformation]::PowerStatus

        ## Get the system power status. Indicates whether the system is using AC power or if the status is unknown. Possible values:
        #  Offline : The system is not using AC power
        #  Online  : The system is using AC power
        #  Unknown : The power status of the system is unknown
        [string]$PowerLineStatus = $PowerStatus.PowerLineStatus
        $SystemTypePowerStatus.Add('ACPowerLineStatus', $PowerStatus.PowerLineStatus)

        # Get the current battery charge status. Possible values: High, Low, Critical, Charging, NoSystemBattery, Unknown
        [string]$BatteryChargeStatus = $PowerStatus.BatteryChargeStatus
        $SystemTypePowerStatus.Add('BatteryChargeStatus', $PowerStatus.BatteryChargeStatus)

        ## Get the approximate amount, from 0.00 to 1.0, of full battery charge remaining
        #  This property can report 1.0 when the battery is damaged and Windows can't detect a battery
        #  Therefore, this property is only indicative of battery charge remaining if 'BatteryChargeStatus' property is not reporting 'NoSystemBattery' or 'Unknown'
        [single]$BatteryLifePercent = $PowerStatus.BatteryLifePercent
        If (($BatteryChargeStatus -eq 'NoSystemBattery') -or ($BatteryChargeStatus -eq 'Unknown')) {
            [single]$BatteryLifePercent = 0.0
        }
        $SystemTypePowerStatus.Add('BatteryLifePercent', $($BatteryLifePercent.tostring("P")))

        # The reported approximate number of seconds of battery life remaining. It will report –1 if the remaining life is unknown because the system is on AC power
        [int32]$BatteryLifeRemaining = $PowerStatus.BatteryLifeRemaining
        $SystemTypePowerStatus.Add('BatteryLifeRemaining', $PowerStatus.BatteryLifeRemaining)

        ## Get the manufacturer reported full charge lifetime of the primary battery power source in seconds
        #  The reported number of seconds of battery life available when the battery is fully charged, or -1 if it is unknown
        #  This will only be reported if the battery supports reporting this information. You will most likely get -1, indicating unknown
        [int32]$BatteryFullLifetime = $PowerStatus.BatteryFullLifetime
        $SystemTypePowerStatus.Add('BatteryFullLifetime', $PowerStatus.BatteryFullLifetime)

        # Determine if the system is using AC power
        [boolean]$OnACPower = $false
        If ($PowerLineStatus -eq 'Online') {
            Write-Verbose -Message 'System is using AC power'
            $OnACPower = $true
        }
        ElseIf ($PowerLineStatus -eq 'Offline') {
            Write-Verbose -Message 'System is using battery power'
        }
        ElseIf ($PowerLineStatus -eq 'Unknown') {
            If (($BatteryChargeStatus -eq 'NoSystemBattery') -or ($BatteryChargeStatus -eq 'Unknown')) {
                Write-Verbose -Message  "System power status is [$PowerLineStatus] and battery charge status is [$BatteryChargeStatus]. This is likely due to a damaged battery - Reporting as using AC power"
                $OnACPower = $true
            }
            Else {
                Write-Verbose -Message "System power status is [$PowerLineStatus] and battery charge status is [$BatteryChargeStatus]. Reporting as using battery power"
            }
        }
        $SystemTypePowerStatus.Add('IsUsingACPower', $OnACPower)

        # Determine if the system is a laptop
        [boolean]$IsLaptop = $false
        If (($BatteryChargeStatus -eq 'NoSystemBattery') -or ($BatteryChargeStatus -eq 'Unknown')) {
            $IsLaptop = $false
        }
        Else {
            $IsLaptop = $true
        }
        # Chassis Types (https://msdn.microsoft.com/en-us/library/aa394474(v=vs.85).aspx)
        [int32[]]$ChassisTypes = Get-WmiObject -Class 'Win32_SystemEnclosure' | Where-Object { $_.ChassisTypes } | Select-Object -ExpandProperty 'ChassisTypes'
        Write-Verbose -Message "The following system chassis types were detected [$($ChassisTypes -join ',')]"
        ForEach ($ChassisType in $ChassisTypes) {
            Switch ($ChassisType) {
                { $_ -eq 9 -or $_ -eq 10 -or $_ -eq 14 } { $IsLaptop = $true } # 9=Laptop, 10=Notebook, 14=Sub Notebook
                { $_ -eq 3 } { $IsLaptop = $false } # 3=Desktop
            }
        }
        # Add IsLaptop property to hashtable
        $SystemTypePowerStatus.Add('IsLaptop', $IsLaptop)

        # Write Output
        Write-Output -InputObject $SystemTypePowerStatus
    }
    End {
        # Verbose Logging
        Write-Verbose -Message "##### Ending : [$CmdletName]"
    }
}


# Start-MSI -Action Install   -Path "C:\Path\To\File\7z1604-x64.msi" -Verbose
# Start-MSI -Action Uninstall -Path "C:\Path\To\File\7z1604-x64.msi" -Verbose
# Start-MSI -Action Uninstall -Path "{23170F69-40C1-2702-1604-000001000000}" -Verbose
# Start-MSP -Path 'C:\Path\To\File\Adobe_Acrobat_DC_x64_EN.msp' -Verbose
# Start-EXE -Path "C:\Path\To\File\7z1604-x64.exe" -Parameters "/S" -Verbose
# Get-MsiTableProperty -Path "C:\Path\To\File\7z1604-x64.msi"
# Get-InstalledApplication -Name "7-Zip"
# Get-InstalledApplication -ProductCode "{23170F69-40C1-2702-1604-000001000000}"
# Get-FreeDiskSpace -Drive 'C:'
# Get-MSIErrorCodeMessage -MSIErrorCode 3010
# Get-FileVersion -File "C:\Path\To\File\7z1604-x64.exe"
# New-Shortcut -Path "C:\Path\To\File\TestProgram.lnk" -TargetPath "$env:windir\System32\notepad.exe" -IconLocation "$env:windir\system32\notepad.exe" -Description 'Notepad Shortcut'
# Get-LoggedOnUser
# Get-UserProfiles
# Update-Desktop
# Update-GroupPolicy
# Get-PowerSupply
# (Get-PowerSupply).IsLaptop
# Remove-MSIApplication -Name 'Java' -Verbose
# Remove-MSIApplication -Name 'Java' -Verbose -ExcludeFromUninstall (,('DisplayName', 'Java(TM) 6 Update 31', 'RegEx'))
# Start-EXEAsUser -UserName 'Domain\UserName' -Path "C:\Path\To\File\7zFM.exe" -verbose -wait
# Start-EXEAsUser -UserName 'Domain\UserName' -Path "powershell.exe" -Parameters '-Command C:\Path\To\File\Script.ps1'
# Get-PendingReboot
# (Get-PendingReboot).LastBootUpTime
# Block-AppExecution -ProcessName 'excel','winword' -Verbose
# Unblock-AppExecution -Verbose
# Convert-RegistryPath -Key 'HKEY_LOCAL_MACHINE\SOFTWARE\Test'
# Set-RegistryKey -Key 'HKLM:SOFTWARE\Test' -Verbose
# Set-RegistryKey -Key 'HKEY_LOCAL_MACHINE\SOFTWARE\Test' -Name 'TestName' -Value 'TestValue' -Type String -Verbose
# Remove-RegistryKey -Key 'HKEY_LOCAL_MACHINE\SOFTWARE\Test' -Recurse -Verbose
# Remove-RegistryKey -Key 'HKLM:SOFTWARE\Test' -Name 'TestName' -Verbose