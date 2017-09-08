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
    .PARAMETER SID
        The security identifier (SID) for a user. Specifying this parameter will convert a HKEY_CURRENT_USER registry key to the HKEY_USERS\$SID format
        Specify this parameter from the Invoke-HKCURegistrySettingsForAllUsers function to read/edit HKCU registry settings for all users on the system
    .PARAMETER ContinueOnError
        Continue if an exit code is returned by msiexec that is not recognized. Default is: $true
    .EXAMPLE
        Remove-RegistryKey -Key 'HKEY_LOCAL_MACHINE\SOFTWARE\Test' -Recurse
    .EXAMPLE
        Remove-RegistryKey -Key 'HKLM:SOFTWARE\Test' -Name 'TestName'
    .LINK
        Set-RegistryKey
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
        [switch]$Recurse,
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
            If (-not ($Name)) {
                If (Test-Path -LiteralPath $Key -ErrorAction 'Stop') {
                    If ($Recurse) {
                        Write-Verbose -Message "Delete registry key recursively [$Key]"
                        $null = Remove-Item -LiteralPath $Key -Force -Recurse -ErrorAction 'Stop'
                    }
                    Else {
                        # Use Get-ChildItem to workaround "non-existant subkey" quirk of Remove-Item
                        If ($null -eq (Get-ChildItem -LiteralPath $Key -ErrorAction 'Stop')) {
                            Write-Verbose -Message "Delete registry key [$Key]"
                            $null = Remove-Item -LiteralPath $Key -Force -ErrorAction 'Stop'
                        }
                        Else {
                            Write-Warning -Message "Unable to delete child key(s) of [$Key] without [-Recurse] switch"
                            Throw
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