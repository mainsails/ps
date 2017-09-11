Function Test-Permission {
    <#
    .SYNOPSIS
        Tests if permissions are set on a file, directory, registry key, or certificate's private key/key container
    .DESCRIPTION
        Sometimes, you don't want to use 'Grant-Permission' on a big tree. In these situations, use 'Test-Permission' to see if permissions are set on a given path
        This Function supports file system, registry, and certificate private key/key container permissions. You can also test the inheritance and propogation flags on containers, in addition to the permissions, with the 'ApplyTo' parameter. See 'Grant-Permission' documentation for an explanation of the 'ApplyTo' parameter
        Inherited permissions are *not* checked by default. To check inherited permission, use the '-Inherited' switch
        By default, the permission check is not exact, i.e. the user may have additional permissions to what you're checking. If you want to make sure the user has *exactly* the permission you want, use the '-Exact' switch. Please note that by default, NTFS will automatically add/grant 'Synchronize' permission on an item, which is handled by this Function
        When checking for permissions on certificate private keys/key containers, if a certificate doesn't have a private key, '$true' is returned
    .PARAMETER Path
        The path on which the permissions should be checked
        Can be a file system or registry path
    .PARAMETER Identity
        The user or group whose permissions to check
    .PARAMETER Permission
        The permission to test for: e.g. FullControl, Read, etc.
        For file system items, use values from [System.Security.AccessControl.FileSystemRights](http://msdn.microsoft.com/en-us/library/system.security.accesscontrol.filesystemrights.aspx)
        For registry items, use values from [System.Security.AccessControl.RegistryRights](http://msdn.microsoft.com/en-us/library/system.security.accesscontrol.registryrights.aspx)
    .PARAMETER ApplyTo
        The container and inheritance flags to check. Ignored if 'Path' is a file. These are ignored if not supplied
        This controls the inheritance and propagation flags
        Default is full inheritance, e.g. 'ContainersAndSubContainersAndLeaves'
        This parameter is ignored if 'Path' is to a leaf item
        See 'Grant-Permission' help for detailed explanation of this parameter
    .PARAMETER Inherited
        Include inherited permissions in the check
    .PARAMETER Exact
        Check for the exact permissions, inheritance flags, and propagation flags, i.e. make sure the identity has *only* the permissions you specify
    .EXAMPLE
        Test-Permission -Identity 'DOMAIN\UserName' -Permission 'FullControl' -Path 'C:\Test'
        Demonstrates how to check that 'DOMAIN\UserName' has 'FullControl' permission on the 'C:\Test' directory
    .EXAMPLE
        Test-Permission -Identity 'DOMAIN\UserName' -Permission 'WriteKey' -Path 'HKLM:\SOFTWARE\Test'
        Demonstrates how to check that 'DOMAIN\UserName' can write registry keys to 'HKLM:\SOFTWARE\Test'
    .EXAMPLE
        Test-Permission -Identity 'DOMAIN\UserName' -Permission 'Write' -ApplyTo 'Container' -Path 'C:\Test'
        Demonstrates how to test for inheritance/propogation flags, in addition to permissions
    .EXAMPLE
        Test-Permission -Identity 'DOMAIN\UserName' -Permission 'GenericWrite' -Path 'Cert:\LocalMachine\My\1234567890ABCDEF1234567890ABCDEF12345678'
        Demonstrates how to test for permissions on a certificate's private key/key container. If the certificate doesn't have a private key, returns '$true'
    .OUTPUTS
        System.Boolean
    .LINK
        ConvertTo-ContainerInheritanceFlags
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
        http://msdn.microsoft.com/en-us/library/system.security.accesscontrol.filesystemrights.aspx
    .LINK
        http://msdn.microsoft.com/en-us/library/system.security.accesscontrol.registryrights.aspx
    .LINK
        http://msdn.microsoft.com/en-us/library/system.security.accesscontrol.cryptokeyrights.aspx
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Path,
        [Parameter(Mandatory=$true)]
        [string]$Identity,
        [Parameter(Mandatory=$true)]
        [string[]]$Permission,
        [PSPM.Security.ContainerInheritanceFlags]$ApplyTo,
        [switch]$Inherited,
        [switch]$Exact
   )

    $OriginalPath = $Path
    $Path = Resolve-Path -Path $Path -ErrorAction 'SilentlyContinue'
    If (-not $Path -or -not (Test-Path -Path $Path)) {
        If (-not $Path) {
            $Path = $OriginalPath
        }
        Write-Error ('Unable to test {0}''s {1} permissions: path ''{2}'' not found.' -f $Identity,($Permission -join ','),$Path)
        return
    }

    $ProviderName = Get-PathProvider -Path $Path | Select-Object -ExpandProperty 'Name'
    If ($ProviderName -eq 'Certificate') {
        $ProviderName = 'CryptoKey'
    }

    If (($ProviderName -eq 'FileSystem' -or $ProviderName -eq 'CryptoKey') -and $Exact) {
        # Synchronize is always on and can't be turned off
        $Permission += 'Synchronize'
    }
    $Rights = $Permission | ConvertTo-ProviderAccessControlRights -ProviderName $ProviderName
    If (-not $Rights) {
        Write-Error ('Unable to test {0}''s {1} permissions on {2}: received an unknown permission.' -f $Identity,$Permission,$Path)
        return
    }

    $Account = Resolve-Identity -Name $Identity
    If (-not $Account) {
        return
    }

    $RightsPropertyName = '{0}Rights' -f $ProviderName
    $InheritanceFlags = [Security.AccessControl.InheritanceFlags]::None
    $PropagationFlags = [Security.AccessControl.PropagationFlags]::None
    $TestApplyTo = $false
    If ($PSBoundParameters.ContainsKey('ApplyTo')) {
        If ((Test-Path -Path $Path -PathType Leaf)) {
            Write-Warning "Can't test inheritance/propagation rules on a leaf. Please omit 'ApplyTo' parameter when 'Path' is a leaf"
        }
        Else {
            $TestApplyTo = $true
            $InheritanceFlags = ConvertTo-InheritanceFlag -ContainerInheritanceFlag $ApplyTo
            $PropagationFlags = ConvertTo-PropagationFlag -ContainerInheritanceFlag $ApplyTo
        }
    }

    If ($ProviderName -eq 'CryptoKey') {
        # If the certificate doesn't have a private key, return $true
        If ((Get-Item -Path $Path | Where-Object { -not $_.HasPrivateKey })) {
            return $true
        }
    }

    $ACL = Get-Permission -Path $Path -Identity $Identity -Inherited:$Inherited |
           Where-Object { $_.AccessControlType -eq 'Allow' } |
           Where-Object { $_.IsInherited -eq $Inherited } |
           Where-Object {
               If ($Exact) {
                   return ($_.$RightsPropertyName -eq $Rights)
               }
               Else {
                   return ($_.$RightsPropertyName -band $Rights) -eq $Rights
               }
           } |
           Where-Object {
               If (-not $TestApplyTo) {
                   return $true
               }

               If ($Exact) {
                   return ($_.InheritanceFlags -eq $InheritanceFlags) -and ($_.PropagationFlags -eq $PropagationFlags)
               }
               Else {
                   return (($_.InheritanceFlags -band $InheritanceFlags) -eq $InheritanceFlags) -and (($_.PropagationFlags -and $PropagationFlags) -eq $PropagationFlags)
               }
           }
    If ($ACL) {
        return $true
    }
    Else {
        return $false
    }
}