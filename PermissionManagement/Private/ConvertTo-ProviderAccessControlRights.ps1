Function ConvertTo-ProviderAccessControlRights {
    <#
    .SYNOPSIS
        Converts strings into the appropriate access control rights for a PowerShell provider (e.g. FileSystemRights or RegistryRights)
    .DESCRIPTION
        Converts strings into the appropriate access control rights for a PowerShell provider (e.g. FileSystemRights or RegistryRights)
    .PARAMETER ProviderName
        The provider name
    .PARAMETER InputObject
        The values to convert
    .EXAMPLE
        ConvertTo-ProviderAccessControlRights -ProviderName 'FileSystem' -InputObject 'Read','Write'
        Demonstrates how to convert 'Read' and 'Write' into a 'System.Security.AccessControl.FileSystemRights' value
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [ValidateSet('FileSystem','Registry','CryptoKey')]
        [string]$ProviderName,
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
        [string[]]$InputObject
    )

    Begin {
        $Rights = 0
        $RightTypeName = 'Security.AccessControl.{0}Rights' -f $ProviderName
        $FoundInvalidRight = $false
    }
    Process {
        $InputObject | ForEach-Object {
            $Right = ($_ -as $RightTypeName)
            If (-not $Right) {
                $AllowedValues = [Enum]::GetNames($RightTypeName)
                Write-Error ("System.Security.AccessControl.{0}Rights value '{1}' not found.  Must be one of: {2}." -f $ProviderName,$_,($AllowedValues -join ' '))
                $FoundInvalidRight = $true
                return
            }
            $Rights = $Rights -bor $Right
        }
    }
    End {
        If ($FoundInvalidRight) {
            return $null
        }
        Else {
            $Rights
        }
    }
}