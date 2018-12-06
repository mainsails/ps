@{

# Script module or binary module file associated with this manifest.
RootModule = 'IPCalculator.psm1'

# Version number of this module.
ModuleVersion = '0.1.0'

# ID used to uniquely identify this module
GUID = 'c1c0af88-5254-4598-b55c-2a79a1e277d9'

# Author of this module
Author = 'Sam Shaw'

# Copyright statement for this module
Copyright = '(c) 2018 Sam Shaw. All rights reserved.'

# Description of the functionality provided by this module
Description = 'Module to assist with common IP Address administration tasks'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '4.0'

# Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
FunctionsToExport = @('Get-IPv4Calculation',
                      'Convert-SubnetMask',
                      'ConvertTo-Binary',
                      'ConvertTo-DottedDecimal',
                      'ConvertTo-InverseBinary',
                      'Test-IPv4Address')

# Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
PrivateData = @{

    PSData = @{

        # Tags applied to this module. These help with module discovery in online galleries.
        Tags = @('IP','Subnet','CIDR')

        # A URL to the main website for this project.
        ProjectUri = 'https://github.com/mainsails/IPCalculator'

    } # End of PSData hashtable

} # End of PrivateData hashtable

# HelpInfo URI of this module
# HelpInfoURI = ''

}

