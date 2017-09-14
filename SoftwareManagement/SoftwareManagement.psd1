@{

# Script module or binary module file associated with this manifest.
RootModule = 'SoftwareManagement.psm1'

# Version number of this module.
ModuleVersion = '0.1.0'

# ID used to uniquely identify this module
GUID = 'f6ef9d27-d00c-452f-8853-5da0f85f330b'

# Author of this module
Author = 'Sam Shaw'

# Copyright statement for this module
Copyright = '(c) 2017 Sam Shaw. All rights reserved.'

# Description of the functionality provided by this module
Description = 'Module to assist with common application deployment tasks'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '4.0'

# Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
FunctionsToExport = @('Block-AppExecution',
                      'ConvertTo-NTAccountOrSID',
                      'Copy-File',
                      'Get-FileVersion',
                      'Get-FreeDiskSpace',
                      'Get-InstalledApplication',
                      'Get-LoggedOnUser',
                      'Get-MSIErrorCodeMessage',
                      'Get-MsiTableProperty',
                      'Get-PendingReboot',
                      'Get-PowerSupply',
                      'Get-ScheduledTasks',
                      'Invoke-HKCURegistrySettingsForAllUsers',
                      'Invoke-RegisterOrUnregisterDLL',
                      'New-Folder',
                      'New-Shortcut',
                      'Remove-File',
                      'Remove-Folder',
                      'Remove-MSI',
                      'Remove-RegistryKey',
                      'Set-ActiveSetup',
                      'Set-RegistryKey',
                      'Start-EXE',
                      'Start-EXEAsUser',
                      'Start-MSI',
                      'Start-MSP',
                      'Unblock-AppExecution',
                      'Update-Desktop',
                      'Update-GroupPolicy')

# Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
PrivateData = @{

    PSData = @{

        # Tags applied to this module. These help with module discovery in online galleries.
        Tags = @('Software','Applications','Deployment','Configuration')

        # A URL to the main website for this project.
        ProjectUri = 'https://github.com/mainsails/ps/SoftwareManagement'

    } # End of PSData hashtable

} # End of PrivateData hashtable

# HelpInfo URI of this module
# HelpInfoURI = ''

}

