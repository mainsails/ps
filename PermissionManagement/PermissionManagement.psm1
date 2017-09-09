
Function ConvertTo-ContainerInheritanceFlags {
    <#
    .SYNOPSIS
        Converts a combination of InheritanceFlags Propagation Flags into a 'PSPM.Security.ContainerInheritanceFlags' enumeration value
    .DESCRIPTION
        'Grant-Permission', 'Test-Permission', and 'Get-Permission' all take an 'ApplyTo' parameter, which is a 'PSPM.Security.ContainerInheritanceFlags' enumeration value. This enumeration is then converted to the appropriate 'System.Security.AccessControl.InheritanceFlags' and 'System.Security.AccessControl.PropagationFlags' values for getting/granting/testing permissions
        If you prefer to speak in terms of 'InheritanceFlags' and 'PropagationFlags', use this Function to convert them to a 'ContainerInheritanceFlags' value
        If your combination doesn't result in a valid combination, '$null' is returned
        For detailed description of inheritance and propagation flags, see the help for 'Grant-Permission'
    .PARAMETER InheritanceFlags
        The inheritance flags to convert
    .PARAMETER PropagationFlags
        The propagation flags to convert
    .EXAMPLE
        ConvertTo-ContainerInheritanceFlags -InheritanceFlags 'ContainerInherit' -PropagationFlags 'None'
        Demonstrates how to convert 'InheritanceFlags' and 'PropagationFlags' enumeration values into a 'ContainerInheritanceFlags'
        In this case, '[PSPM.Security.ContainerInheritanceFlags]::ContainerAndSubContainers' is returned
    .OUTPUTS
        PSPM.Security.ContainerInheritanceFlags
    .LINK
        Grant-Permission
    .LINK
        Test-Permission
    #>

    [CmdletBinding()]
    [OutputType([PSPM.Security.ContainerInheritanceFlags])]
    Param(
        [Parameter(Mandatory=$true,Position=0)]
        [Security.AccessControl.InheritanceFlags]$InheritanceFlags,
        [Parameter(Mandatory=$true,Position=1)]
        [Security.AccessControl.PropagationFlags]$PropagationFlags
   )

    $PropFlagsNone = $PropagationFlags -eq [Security.AccessControl.PropagationFlags]::None
    $PropFlagsInheritOnly = $PropagationFlags -eq [Security.AccessControl.PropagationFlags]::InheritOnly
    $PropFlagsInheritOnlyNoPropagate = $PropagationFlags -eq ([Security.AccessControl.PropagationFlags]::InheritOnly -bor [Security.AccessControl.PropagationFlags]::NoPropagateInherit)
    $PropFlagsNoPropagate = $PropagationFlags -eq [Security.AccessControl.PropagationFlags]::NoPropagateInherit

    If ($InheritanceFlags -eq [Security.AccessControl.InheritanceFlags]::None) {
        return [PSPM.Security.ContainerInheritanceFlags]::Container
    }
    ElseIf ($InheritanceFlags -eq [Security.AccessControl.InheritanceFlags]::ContainerInherit) {
        If ($PropFlagsInheritOnly) {
            return [PSPM.Security.ContainerInheritanceFlags]::SubContainers
        }
        ElseIf ($PropFlagsInheritOnlyNoPropagate) {
            return [PSPM.Security.ContainerInheritanceFlags]::ChildContainers
        }
        ElseIf ($PropFlagsNone) {
            return [PSPM.Security.ContainerInheritanceFlags]::ContainerAndSubContainers
        }
        ElseIf ($PropFlagsNoPropagate) {
            return [PSPM.Security.ContainerInheritanceFlags]::ContainerAndChildContainers
        }
    }
    ElseIf ($InheritanceFlags -eq [Security.AccessControl.InheritanceFlags]::ObjectInherit) {
        If ($PropFlagsInheritOnly) {
            return [PSPM.Security.ContainerInheritanceFlags]::Leaves
        }
        ElseIf ($PropFlagsInheritOnlyNoPropagate) {
            return [PSPM.Security.ContainerInheritanceFlags]::ChildLeaves
        }
        ElseIf ($PropFlagsNone) {
            return [PSPM.Security.ContainerInheritanceFlags]::ContainerAndLeaves
        }
        ElseIf ($PropFlagsNoPropagate) {
            return [PSPM.Security.ContainerInheritanceFlags]::ContainerAndChildLeaves
        }
    }
    ElseIf ($InheritanceFlags -eq ([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit)) {
        If ($PropFlagsInheritOnly) {
            return [PSPM.Security.ContainerInheritanceFlags]::SubContainersAndLeaves
        }
        ElseIf ($PropFlagsInheritOnlyNoPropagate) {
            return [PSPM.Security.ContainerInheritanceFlags]::ChildContainersAndChildLeaves
        }
        ElseIf ($PropFlagsNone) {
            return [PSPM.Security.ContainerInheritanceFlags]::ContainerAndSubContainersAndLeaves
        }
        ElseIf ($PropFlagsNoPropagate) {
            return [PSPM.Security.ContainerInheritanceFlags]::ContainerAndChildContainersAndChildLeaves
        }
    }
}


Function Get-PathProvider {
    <#
    .SYNOPSIS
        Returns a path's PowerShell provider
    .DESCRIPTION
        When you want to do something with a path that depends on its provider, use this Function. The path doesn't have to exist
        If you pass in a relative path, it is resolved relative to the current directory so make sure you're in the right place
    .PARAMETER Path
        The path whose provider to get
    .EXAMPLE
        Get-PathProvider -Path 'C:\Windows'
        Demonstrates how to get the path provider for an NTFS path
    .OUTPUTS
        System.Management.Automation.ProviderInfo
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Path
    )

    $PathQualifier = Split-Path -Qualifier $Path -ErrorAction SilentlyContinue
    If (-not $PathQualifier) {
        $Path = Join-Path -Path (Get-Location) -ChildPath $Path
        $PathQualifier = Split-Path -Qualifier $Path -ErrorAction SilentlyContinue
        If (-not $PathQualifier)  {
            Write-Error "Qualifier for path '$Path' not found."
            return
        }
    }

    $PathQualifier = $PathQualifier.Trim(':')
    $Drive = Get-PSDrive -Name $PathQualifier -ErrorAction Ignore
    If (-not $Drive) {
        $Drive = Get-PSDrive -PSProvider $PathQualifier -ErrorAction Ignore
    }

    If (-not $Drive) {
        Write-Error -Message ('Unable to determine the provider for path {0}.' -f $Path)
        return
    }

    $Drive  |
    Select-Object -First 1 |
    Select-Object -ExpandProperty 'Provider'

}


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


Function Resolve-Identity {
    <#
    .SYNOPSIS
        Gets domain, name, type, and SID information about a user or group
    .DESCRIPTION
        The 'Resolve-Identity' Function takes an identity name or security identifier (SID) and gets its canonical representation
        It returns a 'PSPM.Identity' object which contains the following information about the identity :
            * Domain - the domain the user was found in
            * FullName - the users full name, e.g. Domain\Name
            * Name - the user's username or the group's name
            * Type - the Sid type
            * Sid - the account's security identifier as a 'System.Security.Principal.SecurityIdentifier' object

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