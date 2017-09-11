Function Test-Identity {
    <#
    .SYNOPSIS
        Tests that a name is a valid Windows local or domain user/group
    .DESCRIPTION
        Uses the Windows 'LookupAccountName' Function to find an identity
        If it can't be found, returns '$false'.  Otherwise, it returns '$true'
        Use the 'PassThru' switch to return a 'PSPM.Identity' object (instead of '$true' if the identity exists)
    .PARAMETER Name
        The name of the identity to test
    .PARAMETER PassThru
        Returns a 'PSPM.Identity' object if the identity exists
    .EXAMPLE
        Test-Identity -Name 'Administrators'
        Tests that a user or group called 'Administrators' exists on the local computer
    .EXAMPLE
        Test-Identity -Name 'DOMAIN\UserGroup'
        Tests that a group called 'UserGroup' exists in the 'DOMAIN' domain
    .EXAMPLE
        Test-Identity -Name 'Test' -PassThru
        Tests that a user or group named 'Test' exists and returns a 'System.Security.Principal.SecurityIdentifier' object if it does
    .LINK
        Resolve-Identity
    .LINK
        Resolve-IdentityName
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Name,
        [switch]$PassThru
    )

    $Identity = [PSPM.Identity]::FindByName($Name)
    If (-not $Identity) {
        return $false
    }

    If ($PassThru) {
        return $Identity
    }
    return $true
}