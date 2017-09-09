Function Revoke-Permission {
    <#
    .SYNOPSIS
        Revokes *explicit* permissions on a file, directory, registry key, or certificate's private key/key container
    .DESCRIPTION
        Revokes all of an identity's *explicit* permissions on a file, directory, registry key, or certificate's private key/key container. Only explicit permissions are considered; inherited permissions are ignored
        If the identity doesn't have permission, nothing happens, not even errors written out
    .PARAMETER Path
        The path on which the permissions should be revoked
        Can be a file system, registry, or certificate path
    .PARAMETER Identity
        The user or group to have permissions revoked
    .EXAMPLE
        Revoke-Permission -Identity 'DOMAIN\Engineers' -Path 'C:\Test'
        Demonstrates how to revoke all of the 'DOMAIN\Engineers' permissions on the 'C:\Test' directory
    .EXAMPLE
        Revoke-Permission -Identity 'DOMAIN\Users' -Path 'HKLM:\SOFTWARE\Test'
        Demonstrates how to revoke permission on a registry key
    .EXAMPLE
        Revoke-Permission -Identity 'DOMAIN\Users' -Path 'Cert:\LocalMachine\My\1234567890ABCDEF1234567890ABCDEF12345678'
        Demonstrates how to revoke the 'DOMAIN\Users' permission to the 'Cert:\LocalMachine\My\1234567890ABCDEF1234567890ABCDEF12345678' certificate's private key/key container
    .LINK
        Disable-AclInheritance
    .LINK
        Enable-AclInheritance
    .LINK
        Get-Permission
    .LINK
        Grant-Permission
    .LINK
        Test-Permission
    #>

    [CmdletBinding(SupportsShouldProcess=$true)]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Path,
        [Parameter(Mandatory=$true)]
        [string]$Identity
   )


    $Path = Resolve-Path -Path $Path
    If (-not $Path) {
        return
    }

    $ProviderName = Get-PathProvider -Path $Path | Select-Object -ExpandProperty 'Name'
    If ($ProviderName -eq 'Certificate') {
        $ProviderName = 'CryptoKey'
    }

    $RulesToRemove = Get-Permission -Path $Path -Identity $Identity
    If ($RulesToRemove) {
        $Identity = Resolve-IdentityName -Name $Identity
        $RulesToRemove | ForEach-Object { Write-Verbose ('[{0}] [{1}]  {2} -> ' -f $Path,$Identity,$_."$($ProviderName)Rights") }

        Get-Item $Path -Force |
        ForEach-Object {
            If ($_.PSProvider.Name -eq 'Certificate') {
                [Security.Cryptography.X509Certificates.X509Certificate2]$Certificate = $_
                [Security.AccessControl.CryptoKeySecurity]$KeySecurity = $Certificate.PrivateKey.CspKeyContainerInfo.CryptoKeySecurity

                $RulesToRemove | ForEach-Object { [void]$KeySecurity.RemoveAccessRule($_) }
                Set-CryptoKeySecurity -Certificate $Certificate -CryptoKeySecurity $KeySecurity -Action ('revoke {0}''s permissions' -f $Identity)
            }
            Else {
                # We don't use Get-Acl because it returns the whole security descriptor, which includes owner information.
                # When passed to Set-Acl, this causes intermittent errors.  So, we just grab the ACL portion of the security descriptor.
                # See http://www.bilalaslam.com/2010/12/14/powershell-workaround-for-the-security-identifier-is-not-allowed-to-be-the-owner-of-this-object-with-set-acl/
                $CurrentAcl = $_.GetAccessControl('Access')
                $RulesToRemove | ForEach-Object { [void]$CurrentAcl.RemoveAccessRule($_) }
                If ($PSCmdlet.ShouldProcess($Path, ('revoke {0}''s permissions' -f $Identity))) {
                    Set-Acl -Path $Path -AclObject $CurrentAcl
                }
            }
        }
    }
}