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
    .PARAMETER SID
        The security identifier (SID) for a user. Specifying this parameter will convert a HKEY_CURRENT_USER registry key to the HKEY_USERS\$SID format
        Specify this parameter from the Invoke-HKCURegistrySettingsForAllUsers function to read/edit HKCU registry settings for all users on the system
    .PARAMETER ContinueOnError
        Continue if an exit code is returned by msiexec that is not recognized. Default is: $true
    .EXAMPLE
        Set-RegistryKey -Key 'HKEY_LOCAL_MACHINE\SOFTWARE\Test' -Name 'TestName' -Value 'TestValue' -Type String
    .EXAMPLE
        Set-RegistryKey -Key 'HKLM:SOFTWARE\Test'
    .LINK
        Remove-RegistryKey
    .LINK
        Invoke-HKCURegistrySettingsForAllUsers
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
        [string]$SID,
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
            If ($PSBoundParameters.ContainsKey('SID')) {
                [string]$Key = Convert-RegistryPath -Key $Key -SID $SID
            }
            Else {
                [string]$Key = Convert-RegistryPath -Key $Key
            }

            # Replace forward slash character to allow forward slash in name of the registry key
            $Key = $Key.Replace('/',"$([char]0x2215)")

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