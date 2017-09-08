Function Convert-RegistryPath {
    <#
    .SYNOPSIS
        Converts the specified registry key path to a format that is compatible with built-in PowerShell cmdlets
    .DESCRIPTION
        Converts the specified registry key path to a format that is compatible with built-in PowerShell cmdlets
        Converts registry key hives to their full paths. Example: HKLM is converted to "Registry::HKEY_LOCAL_MACHINE"
    .PARAMETER Key
        Path to the registry key to convert (can be a registry hive or fully qualified path)
    .PARAMETER SID
        The security identifier (SID) for a user. Specifying this parameter will convert a HKEY_CURRENT_USER registry key to the HKEY_USERS\$SID format
        Specify this parameter from the Invoke-HKCURegistrySettingsForAllUsers function to read/edit HKCU registry settings for all users on the system
    .EXAMPLE
        Convert-RegistryPath -Key 'HKEY_LOCAL_MACHINE\SOFTWARE\Test'
    .EXAMPLE
        Convert-RegistryPath -Key 'HKLM:SOFTWARE\Test'
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [string]$Key,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [string]$SID
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

        # If the SID variable is specified, then convert all HKEY_CURRENT_USER key's to HKEY_USERS\$SID
        If ($PSBoundParameters.ContainsKey('SID')) {
            If ($Key -match '^HKEY_CURRENT_USER\\') {
                $Key = $Key -replace '^HKEY_CURRENT_USER\\', "HKEY_USERS\$SID\"
            }
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