Function Invoke-HKCURegistrySettingsForAllUsers {
    <#
    .SYNOPSIS
        Set current user registry settings for all current users and any new users in the future
    .DESCRIPTION
        Set HKCU registry settings for all current and future users by loading their NTUSER.dat registry hive file, and making the modifications
        This function will modify HKCU settings for all users even when executed under the SYSTEM account
        To ensure new users in the future get the registry edits, the Default User registry hive used to provision the registry for new users is modified
        This function can be used as an alternative to using ActiveSetup for registry settings
        The advantage of using this function over ActiveSetup is that a user does not have to log off and log back on before the changes take effect
    .PARAMETER RegistrySettings
        Script block which contains HKCU registry settings which should be modified for all users on the system. Must specify the -SID parameter for all HKCU settings
    .PARAMETER UserProfiles
        Specify the user profiles to modify HKCU registry settings for. Default is all user profiles except for system profiles
    .EXAMPLE
        [scriptblock]$HKCURegistrySettings = {
            Set-RegistryKey -Key 'HKCU\SOFTWARE\Test' -Name 'TestName'    -Value 'TestValue'    -Type String -SID $UserProfile.SID
            Set-RegistryKey -Key 'HKCU\SOFTWARE\Test' -Name 'TestNameTwo' -Value 'TestValueTwo' -Type String -SID $UserProfile.SID
        }
        Invoke-HKCURegistrySettingsForAllUsers -RegistrySettings $HKCURegistrySettings
    .EXAMPLE
        [scriptblock]$HKCURegistrySettings = {
            Remove-RegistryKey -Key 'HKCU\SOFTWARE\Test' -Name 'TestName'    -SID $UserProfile.SID
            Remove-RegistryKey -Key 'HKCU\SOFTWARE\Test' -Name 'TestNameTwo' -SID $UserProfile.SID
        }
        Invoke-HKCURegistrySettingsForAllUsers -RegistrySettings $HKCURegistrySettings
    .LINK
        Set-RegistryKey
    .LINK
        Remove-RegistryKey
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [scriptblock]$RegistrySettings,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [psobject[]]$UserProfiles = (Get-UserProfiles)
    )

    Begin {
        # Verbose Logging
        [string]$CmdletName  = $MyInvocation.MyCommand.Name
        [string]$CmdletParam = $PSBoundParameters | Format-Table -Property @{ Label = 'Parameter'; Expression = { "[-$($_.Key)]" } }, @{ Label = 'Value'; Expression = { $_.Value }; Alignment = 'Left' } -AutoSize -Wrap | Out-String
        Write-Verbose -Message "##### Calling : [$CmdletName]"
    }
    Process {
        ForEach ($UserProfile in $UserProfiles) {
            Try {
                # Set the path to the user's registry hive when it is loaded
                [string]$UserRegistryPath = "Registry::HKEY_USERS\$($UserProfile.SID)"

                # Set the path to the user's registry hive file
                [string]$UserRegistryHiveFile = Join-Path -Path $UserProfile.ProfilePath -ChildPath 'NTUSER.DAT'

                # Load the User profile registry hive if it is not already loaded because the User is logged in
                [boolean]$ManuallyLoadedRegHive = $false
                If (-not (Test-Path -LiteralPath $UserRegistryPath)) {
                    # Load the User registry hive if the registry hive file exists
                    If (Test-Path -LiteralPath $UserRegistryHiveFile -PathType 'Leaf') {
                        Write-Verbose -Message "Load the User [$($UserProfile.NTAccount)] registry hive in path [HKEY_USERS\$($UserProfile.SID)]"
                        [string]$HiveLoadResult = & reg.exe load "`"HKEY_USERS\$($UserProfile.SID)`"" "`"$UserRegistryHiveFile`"" 2>&1

                        If ($global:LastExitCode -ne 0) {
                            Throw "Failed to load the registry hive for User [$($UserProfile.NTAccount)] with SID [$($UserProfile.SID)]. Failure message [$HiveLoadResult]. Continue..."
                        }

                        [boolean]$ManuallyLoadedRegHive = $true
                    }
                    Else {
                        Throw "Failed to find the registry hive file [$UserRegistryHiveFile] for User [$($UserProfile.NTAccount)] with SID [$($UserProfile.SID)]. Continue..."
                    }
                }
                Else {
                    Write-Verbose -Message "The User [$($UserProfile.NTAccount)] registry hive is already loaded in path [HKEY_USERS\$($UserProfile.SID)]"
                }

                # Execute ScriptBlock which contains code to manipulate HKCU registry
                # Make sure read/write calls to the HKCU registry hive specify the -SID parameter (-SID $UserProfile.SID) or settings will not be changed for all users
                Write-Verbose -Message 'Execute ScriptBlock to modify HKCU registry settings for all users'
                & $RegistrySettings
            }
            Catch {
                Write-Warning -Message "Failed to modify the registry hive for User [$($UserProfile.NTAccount)] with SID [$($UserProfile.SID)]"
            }
            Finally {
                If ($ManuallyLoadedRegHive) {
                    Try {
                        Write-Verbose -Message "Unload the User [$($UserProfile.NTAccount)] registry hive in path [HKEY_USERS\$($UserProfile.SID)]"
                        [string]$HiveLoadResult = & reg.exe unload "`"HKEY_USERS\$($UserProfile.SID)`"" 2>&1

                        If ($global:LastExitCode -ne 0) {
                            Write-Warning -Message "REG.exe failed to unload the registry hive and exited with exit code [$($global:LastExitCode)]. Performing manual garbage collection to ensure successful unloading of registry hive"
                            [GC]::Collect()
                            [GC]::WaitForPendingFinalizers()
                            Start-Sleep -Seconds 5

                            Write-Verbose -Message "Unload the User [$($UserProfile.NTAccount)] registry hive in path [HKEY_USERS\$($UserProfile.SID)]"
                            [string]$HiveLoadResult = & reg.exe unload "`"HKEY_USERS\$($UserProfile.SID)`"" 2>&1
                            If ($global:LastExitCode -ne 0) {
                                Throw "reg.exe failed with exit code [$($global:LastExitCode)] and result [$HiveLoadResult]"
                            }
                        }
                    }
                    Catch {
                        Write-Warning -Message "Failed to unload the registry hive for User [$($UserProfile.NTAccount)] with SID [$($UserProfile.SID)]"
                    }
                }
            }
        }
    }
    End {
        # Verbose Logging
        Write-Verbose -Message "##### Ending : [$CmdletName]"
    }
}