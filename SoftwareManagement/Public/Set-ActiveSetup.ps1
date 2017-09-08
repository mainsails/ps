Function Set-ActiveSetup {
    <#
    .SYNOPSIS
        Creates an Active Setup entry in the registry to execute a file for each user upon login
    .DESCRIPTION
        Active Setup allows handling of per-user changes registry/file changes upon login
        A registry key is created in the HKLM registry hive which gets replicated to the HKCU hive when a user logs in
        If the "Version" value of the Active Setup entry in HKLM is higher than the version value in HKCU, the file referenced in "StubPath" is executed
        This Function:
        - Creates the registry entries in HKLM:SOFTWARE\Microsoft\Active Setup\Installed Components\[guid]
        - Creates StubPath value depending on the file extension of the $StubEXEPath parameter
        - Handles Version value with YYYYMMDDHHMM granularity to permit re-installs on the same day and still trigger Active Setup after Version increase
        - Executes the StubPath file for the current user as long as not in Session 0 (no need to logout/login to trigger Active Setup)
    .PARAMETER StubEXEPath
        Full destination path to the file that will be executed for each user that logs in
    .PARAMETER Arguments
        Arguments to pass to the file being executed
    .PARAMETER Description
        Description for the Active Setup. Users will see "Setting up personalized settings for: $Description" at logon
    .PARAMETER Key
        Name of the registry key for the Active Setup entry
    .PARAMETER Version
        Specify version for Active setup entry. Note : Active Setup is not triggered if Version value has more than 8 consecutive digits
    .PARAMETER PurgeActiveSetupKey
        Remove Active Setup entry from HKLM and all HKCU registry hives
    .PARAMETER DisableActiveSetup
        Disables the Active Setup entry so that the StubPath file will not be executed
    .PARAMETER ContinueOnError
        Continue if an error is encountered. Default is: $true
    .EXAMPLE
        Set-ActiveSetup -StubEXEPath '"C:\Path\To\File\PerUserScript.vbs' -Arguments '/Silent' -Description 'PerUser Script' -Key 'PerUser_Script'
        Run "PerUserScript.vbs" with the argument '/Silent' for all future logons
    .EXAMPLE
        Set-ActiveSetup -StubEXEPath "$env:WinDir\regedit.exe" -Arguments "/S `"C:\Path\To\File\HKCURegistryChange.reg`"" -Description 'HKCU Registry Change' -Key 'HKCU_Registry_Change' -Verbose
        Launch a registry edit from a .reg file for all future logons
    .EXAMPLE
        Set-ActiveSetup -Key 'HKCU_Registry_Change' -PurgeActiveSetupKey
        Deletes "HKCU_Registry_Change" Active Setup entry from all registry hives
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true,ParameterSetName='Create')]
        [ValidateNotNullorEmpty()]
        [string]$StubEXEPath,
        [Parameter(Mandatory=$false,ParameterSetName='Create')]
        [ValidateNotNullorEmpty()]
        [string]$Arguments,
        [Parameter(Mandatory=$false,ParameterSetName='Create')]
        [ValidateNotNullorEmpty()]
        [string]$Description = [System.IO.Path]::GetFileNameWithoutExtension($StubEXEPath),
        [Parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [string]$Key = [guid]::NewGuid(),
        [Parameter(Mandatory=$false,ParameterSetName='Create')]
        [ValidateNotNullorEmpty()]
        [string]$Version = ((Get-Date -Format 'yyyy,MM,dd,HHmm').ToString()),
        [Parameter(Mandatory=$false,ParameterSetName='Create')]
        [ValidateNotNullorEmpty()]
        [switch]$DisableActiveSetup = $false,
        [Parameter(Mandatory=$true,ParameterSetName='Purge')]
        [switch]$PurgeActiveSetupKey,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [boolean]$ContinueOnError = $true
    )

    Begin {
        # Verbose Logging
        [string]$CmdletName  = $MyInvocation.MyCommand.Name
        [string]$CmdletParam = $PSBoundParameters | Format-Table -Property @{ Label = 'Parameter'; Expression = { "[-$($_.Key)]" } }, @{ Label = 'Value'; Expression = { $_.Value }; Alignment = 'Left' } -AutoSize -Wrap | Out-String
        Write-Verbose -Message "##### Calling : [$CmdletName]"

        # Check if running in session zero
        [Security.Principal.WindowsIdentity]$CurrentProcessToken  = [Security.Principal.WindowsIdentity]::GetCurrent()
        [Security.Principal.SecurityIdentifier]$CurrentProcessSID = $CurrentProcessToken.User
        [boolean]$IsLocalSystemAccount                            = $CurrentProcessSID.IsWellKnown([Security.Principal.WellKnownSidType]'LocalSystemSid')
        [boolean]$IsLocalServiceAccount                           = $CurrentProcessSID.IsWellKnown([Security.Principal.WellKnownSidType]'LocalServiceSid')
        [boolean]$IsNetworkServiceAccount                         = $CurrentProcessSID.IsWellKnown([Security.Principal.WellKnownSidType]'NetworkServiceSid')
        [boolean]$IsServiceAccount                                = [boolean]($CurrentProcessToken.Groups -contains [Security.Principal.SecurityIdentifier]'S-1-5-6')
        If ($IsLocalSystemAccount -or $IsLocalServiceAccount -or $IsNetworkServiceAccount -or $IsServiceAccount) {
            $SessionZero = $true
        }
        Else {
            $SessionZero = $false
        }
    }
    Process {
        Try {
            [string]$ActiveSetupKey     = "HKLM:SOFTWARE\Microsoft\Active Setup\Installed Components\$Key"
            [string]$HKCUActiveSetupKey = "HKCU:Software\Microsoft\Active Setup\Installed Components\$Key"

            # Delete Active Setup registry entry from the HKLM hive and for all logon user registry hives on the system
            If ($PurgeActiveSetupKey) {
                Write-Verbose -Message "Remove Active Setup entry [$ActiveSetupKey]"
                Remove-RegistryKey -Key $ActiveSetupKey -Recurse

                Write-Verbose -Message "Remove Active Setup entry [$HKCUActiveSetupKey] for all log on user registry hives on the system"
                [scriptblock]$RemoveHKCUActiveSetupKey = {
                    Remove-RegistryKey -Key $HKCUActiveSetupKey -SID $UserProfile.SID -Recurse
                }
                Invoke-HKCURegistrySettingsForAllUsers -RegistrySettings $RemoveHKCUActiveSetupKey -UserProfiles (Get-UserProfiles -ExcludeDefaultUser)
                Return
            }

            # Verify a file with a supported file extension was specified in $StubEXEPath
            [string[]]$StubEXEPathFileExtensions = '.exe', '.vbs', '.cmd', '.ps1', '.js'
            [string]$StubExeExt                  = [IO.Path]::GetExtension($StubEXEPath)
            If ($StubEXEPathFileExtensions -notcontains $StubExeExt) {
                Throw "Unsupported Active Setup StubPath file extension [$StubExeExt]"
            }
            [string]$StubEXEPath         = [Environment]::ExpandEnvironmentVariables($StubEXEPath)
            [string]$ActiveSetupFileName = [IO.Path]::GetFileName($StubEXEPath)

            # Check if the $StubEXEPath file exists
            If (-not (Test-Path -LiteralPath $StubEXEPath -PathType 'Leaf')) {
                Throw "Active Setup StubPath file [$ActiveSetupFileName] is missing"
            }

            # Define Active Setup StubPath according to file extension of $StubEXEPath
            Switch ($StubExeExt) {
                '.exe' {
                    [string]$CUStubEXEPath = $StubEXEPath
                    [string]$CUArguments   = $Arguments
                    [string]$StubPath      = $CUStubEXEPath
                }
                { '.vbs','.js' -contains $StubExeExt } {
                    [string]$CUStubEXEPath = "$env:windir\System32\cscript.exe"
                    [string]$CUArguments   = "//nologo `"$StubEXEPath`""
                    [string]$StubPath      = "$CUStubEXEPath $CUArguments"
                }
                '.cmd' {
                    [string]$CUStubEXEPath = "$env:windir\System32\cmd.exe"
                    [string]$CUArguments   = "/C `"$StubEXEPath`""
                    [string]$StubPath      = "$CUStubEXEPath $CUArguments"
                }
                '.ps1' {
                    [string]$CUStubEXEPath = "$PSHOME\powershell.exe"
                    [string]$CUArguments   = "-ExecutionPolicy Bypass -NoProfile -NoLogo -WindowStyle Hidden -Command & { & `\`"$StubEXEPath`\`"}"
                    [string]$StubPath      = "$CUStubEXEPath $CUArguments"
                }
            }
            If ($Arguments) {
                [string]$StubPath = "$StubPath $Arguments"
                If ($StubExeExt -ne '.exe') {
                    [string]$CUArguments = "$CUArguments $Arguments"
                }
            }

            # Create the Active Setup entry in the registry
            [scriptblock]$SetActiveSetupRegKeys = {
                Param (
                    [Parameter(Mandatory=$true)]
                    [ValidateNotNullorEmpty()]
                    [string]$ActiveSetupRegKey
                )
                Set-RegistryKey -Key $ActiveSetupRegKey -Name '(Default)' -Value $Description -ContinueOnError $false
                Set-RegistryKey -Key $ActiveSetupRegKey -Name 'StubPath' -Value $StubPath -Type 'String' -ContinueOnError $false
                Set-RegistryKey -Key $ActiveSetupRegKey -Name 'Version' -Value $Version -ContinueOnError $false
                If ($DisableActiveSetup) {
                    Set-RegistryKey -Key $ActiveSetupRegKey -Name 'IsInstalled' -Value 0 -Type 'DWord' -ContinueOnError $false
                }
                Else {
                    Set-RegistryKey -Key $ActiveSetupRegKey -Name 'IsInstalled' -Value 1 -Type 'DWord' -ContinueOnError $false
                }
            }
            & $SetActiveSetupRegKeys -ActiveSetupRegKey $ActiveSetupKey

            # Execute the StubPath file for the current user as long as not in Session 0
            If ($SessionZero) {
                Write-Verbose -Message 'Session 0 detected: No logged in users detected. Active Setup StubPath file will execute when users first log into their account'
            }
            Else {
                Write-Verbose -Message 'Execute Active Setup StubPath file for the current user'
                If ($CUArguments) {
                    $ExecuteResults = Start-EXE -Path $CUStubEXEPath -Parameters $CUArguments -PassThru
                }
                Else {
                    $ExecuteResults = Start-EXE -Path $CUStubEXEPath -PassThru
                }
                & $SetActiveSetupRegKeys -ActiveSetupRegKey $HKCUActiveSetupKey
            }
        }
        Catch {
            Write-Warning -Message "Failed to set Active Setup registry entry"
            If (-not $ContinueOnError) {
                Throw "Failed to set Active Setup registry entry: $($_.Exception.Message)"
            }
        }
    }
    End {
        # Verbose Logging
        Write-Verbose -Message "##### Ending : [$CmdletName]"
    }
}