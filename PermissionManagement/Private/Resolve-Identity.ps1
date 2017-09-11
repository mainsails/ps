Function Resolve-Identity {
    <#
    .SYNOPSIS
        Gets domain, name, type, and SID information about a user or group
    .DESCRIPTION
        The 'Resolve-Identity' Function takes an identity name or security identifier (SID) and gets its canonical representation
        It returns a 'PSPM.Identity' object which contains the following information about the identity :
            * Domain   - The domain the user was found in
            * FullName - The users full name, e.g. Domain\Name
            * Name     - The user's username or the group's name
            * Type     - The SID type
            * SID      - The account's security identifier as a 'System.Security.Principal.SecurityIdentifier' object

        The common name for an account is not always the canonical name used by the operating system
        For example, the local Administrators group is actually called 'BUILTIN\Administrators'. This Function uses the 'LookupAccountName' and 'LookupAccountSid' Windows Functions to resolve an account name or security identifier into its domain, name, full name, SID, and SID type

        You may pass a 'System.Security.Principal.SecurityIdentifer', a SID in SDDL form (as a string), or a SID in binary form (a byte array) as the value to the 'SID' parameter. You'll get an error and nothing returned if the SDDL or byte array SID are invalid

        If the name or security identifier doesn't represent an actual user or group, an error is written and nothing is returned
    .PARAMETER Name
        The name of the identity to return
    .PARAMETER SID
        The SID of the identity to return
        Accepts a SID in SDDL form as a 'string', a 'System.Security.Principal.SecurityIdentifier' object, or a SID in binary form as an array of bytes
    .EXAMPLE
        Resolve-Identity -Name 'Administrators'
        Returns an object representing the 'Administrators' group
    .EXAMPLE
        Resolve-Identity -SID 'S-1-5-32-544'
        Demonstrates how to use a SID in SDDL form to convert a SID into an identity
    .EXAMPLE
        Resolve-Identity -SID (New-Object 'Security.Principal.SecurityIdentifier' 'S-1-5-32-544')
        Demonstrates that you can pass a 'SecurityIdentifier' object as the value of the SID parameter
    .EXAMPLE
        Resolve-Identity -SID $SIDBytes
        Demonstrates that you can use a byte array that represents a SID as the value of the 'SID' parameter
    .OUTPUTS
        PSPM.Identity
    .LINK
        Test-Identity
    .LINK
        Resolve-IdentityName
    .LINK
        ConvertTo-SecurityIdentifier
    .LINK
        Resolve-IdentityName
    .LINK
        Test-Identity
    .LINK
        http://msdn.microsoft.com/en-us/library/system.security.principal.securityidentifier.aspx
    .LINK
        http://msdn.microsoft.com/en-us/library/windows/desktop/aa379601.aspx
    #>

    [CmdletBinding(DefaultParameterSetName='ByName')]
    [OutputType([PSPM.Identity])]
    Param(
        [Parameter(Mandatory=$true,ParameterSetName='ByName',Position=0)]
        [string]$Name,
        [Parameter(Mandatory=$true,ParameterSetName='BySid')]
        $SID
    )

    If ($PSCmdlet.ParameterSetName -eq 'BySid') {
        $SID = ConvertTo-SecurityIdentifier -SID $SID
        If (-not $SID) {
            return
        }

        $ID = [PSPM.Identity]::FindBySid($SID)
        If (-not $ID) {
            Write-Error ('Identity ''{0}'' not found.' -f $SID) -ErrorAction $ErrorActionPreference
        }
        return $ID
    }

    If (-not (Test-Identity -Name $Name)) {
        Write-Error ('Identity ''{0}'' not found.' -f $Name) -ErrorAction $ErrorActionPreference
        return
    }

    return [PSPM.Identity]::FindByName($Name)
}