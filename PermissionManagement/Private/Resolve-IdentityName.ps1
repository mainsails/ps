Function Resolve-IdentityName {
    <#
    .SYNOPSIS
        Determines the full, NT identity name for a user or group
    .DESCRIPTION
        'Resolve-IdentityName' resolves a user/group name into its full, canonical name, used by the operating system
        For example, the local Administrators group is actually called 'BUILTIN\Administrators'
        With a canonical username, you can unambiguously compare principals on objects that contain user/group information

        If unable to resolve a name into an identity, 'Resolve-IdentityName' returns nothing

        You can also resolve a SID into its identity name
        The 'SID' parameter accepts a SID in SDDL form as a 'string', a 'System.Security.Principal.SecurityIdentifier' object, or a SID in binary form as an array of bytes
        If the SID no longer maps to an active account, you'll get the original SID in SDDL form (as a string) returned to you

        If you want to get full identity information (domain, type, sid, etc.), use 'Resolve-Identity'
    .PARAMETER Name
        The name of the identity to return
    .PARAMETER SID
        Get an identity's name from its SID. Accepts a SID in SDDL form as a 'string', a 'System.Security.Principal.SecurityIdentifier' object, or a SID in binary form as an array of bytes
    .EXAMPLE
        Resolve-IdentityName -Name 'Administrators'
        Returns 'BUILTIN\Administrators', the canonical name for the local Administrators group
    .OUTPUTS
        string
    .LINK
        ConvertTo-SecurityIdentifier
    .LINK
        Resolve-Identity
    .LINK
        Test-Identity
    .LINK
        http://msdn.microsoft.com/en-us/library/system.security.principal.securityidentifier.aspx
    .LINK
        http://msdn.microsoft.com/en-us/library/windows/desktop/aa379601.aspx
    #>

    [CmdletBinding(DefaultParameterSetName='ByName')]
    [OutputType([string])]
    Param(
        [Parameter(Mandatory=$true,ParameterSetName='ByName',Position=0)]
        [string]$Name,
        [Parameter(Mandatory=$true,ParameterSetName='BySid')]
        $SID
    )

    If ($PSCmdlet.ParameterSetName -eq 'ByName') {
        return Resolve-Identity -Name $Name -ErrorAction Ignore | Select-Object -ExpandProperty 'FullName'
    }
    ElseIf ($PSCmdlet.ParameterSetName -eq 'BySid') {
        $SID = ConvertTo-SecurityIdentifier -SID $SID
        If (-not $SID) {
            return
        }

        $ID = [PSPM.Identity]::FindBySid($SID)
        If ($ID) {
            return $ID.FullName
        }
        Else {
            return $SID.ToString()
        }
    }
}