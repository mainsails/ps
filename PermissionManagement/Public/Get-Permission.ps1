Function Get-Permission {
    <#
    .SYNOPSIS
        Gets the permissions (access control rules) for a file, directory, registry key, or certificate's private key/key container
    .DESCRIPTION
        Permissions for a specific identity can also be returned. Access control entries are for a path's discretionary access control list
        To return inherited permissions, use the 'Inherited' switch. Otherwise, only non-inherited (i.e. explicit) permissions are returned
        Certificate permissions are only returned if a certificate has a private key/key container. If a certificate doesn't have a private key, '$null' is returned
    .PARAMETER Path
        The path whose permissions (i.e. access control rules) to return
        File system, registry, or certificate paths supported
        Wildcards supported
    .PARAMETER Identity
        The user or group whose permissions (i.e. access control rules) to return
    .PARAMETER Inherited
        Return inherited permissions in addition to explicit permissions
    .EXAMPLE
        Get-Permission -Path 'C:\Windows'
        Returns 'System.Security.AccessControl.FileSystemAccessRule' objects for all the non-inherited rules on 'C:\Windows'
    .EXAMPLE
        Get-Permission -Path 'HKLM:\SOFTWARE' -Inherited
        Returns 'System.Security.AccessControl.RegistryAccessRule' objects for all the inherited and non-inherited rules on 'HKLM:\SOFTWARE'
    .EXAMPLE
        Get-Permission -Path 'C:\Windows' -Identity 'Administrators'
        Returns 'System.Security.AccessControl.FileSystemAccessRule' objects for all the 'Administrators' rules on 'C:\Windows'
    .EXAMPLE
        Get-Permission -Path 'Cert:\LocalMachine\1234567890ABCDEF1234567890ABCDEF12345678'
        Returns 'System.Security.AccessControl.CryptoKeyAccessRule' objects for certificate's 'Cert:\LocalMachine\1234567890ABCDEF1234567890ABCDEF12345678' private key/key container. If it doesn't have a private key, '$null' is returned
    .OUTPUTS
        System.Security.AccessControl.AccessRule
    .LINK
        Disable-AclInheritance
    .LINK
        Enable-AclInheritance
    .LINK
        Get-Permission
    .LINK
        Grant-Permission
    .LINK
        Revoke-Permission
    .LINK
        Test-Permission
    #>

    [CmdletBinding()]
    [OutputType([System.Security.AccessControl.AccessRule])]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Path,
        [string]$Identity,
        [switch]$Inherited
   )

    $Account = $null
    If ($Identity) {
        $Account = Test-Identity -Name $Identity -PassThru
        If ($Account) {
            $Identity = $Account.FullName
        }
    }

    If (-not (Test-Path -Path $Path)) {
        Write-Error ('Path ''{0}'' not found.' -f $Path)
        return
    }

    Invoke-Command -ScriptBlock {
        Get-Item -Path $Path -Force |
        ForEach-Object {
            If ($_.PSProvider.Name -eq 'Certificate') {
                If ($_.HasPrivateKey -and $_.PrivateKey) {
                    $_.PrivateKey.CspKeyContainerInfo.CryptoKeySecurity
                }
            }
            Else {
                $_.GetAccessControl([Security.AccessControl.AccessControlSections]::Access)
            }
        }
    } |
    Select-Object -ExpandProperty Access |
    Where-Object {
        If ($Inherited) {
            return $true
        }
        return (-not $_.IsInherited)
    } |
    Where-Object {
        If ($Identity) {
            return ($_.IdentityReference.Value -eq $Identity)
        }
        return $true
    }
}