Function Grant-Permission {
    <#
    .SYNOPSIS
        Grants permission on a file, directory, registry key, or certificate's private key/key container
    .DESCRIPTION
        The 'Grant-Permission' Function grants permissions to files, directories, registry keys, and certificate private key/key containers. It detects what you are setting permissions on by inspecting the path of the item. If the path is relative, it uses the current location to determine if file system, registry, or private keys permissions should be set
        The 'Permissions' attribute should be a list of [FileSystemRights](http://msdn.microsoft.com/en-us/library/system.security.accesscontrol.filesystemrights.aspx), [RegistryRights](http://msdn.microsoft.com/en-us/library/system.security.accesscontrol.registryrights.aspx), or [CryptoKeyRights](http://msdn.microsoft.com/en-us/library/system.security.accesscontrol.cryptokeyrights.aspx), for files/directories, registry keys, and certificate private keys, respectively. These commands will show you the values for the appropriate permissions for your object :
          [Enum]::GetValues([Security.AccessControl.FileSystemRights])
          [Enum]::GetValues([Security.AccessControl.RegistryRights])
          [Enum]::GetValues([Security.AccessControl.CryptoKeyRights])
        Permissions are only granted if they don't exist on an item (inherited permissions are ignored). If you always want to grant permissions, use the 'Force' switch
        Use the 'PassThru' switch to get an access rule object back (you'll always get one regardless if the permissions changed or not)
        By default, permissions allowing access are granted. You can grant permissions denying access by passing 'Deny' as the value of the 'Type' parameter

        -- Directories and Registry Keys :

        When setting permissions on a container (directory/registry key) you can control inheritance and propagation flags using the 'ApplyTo' parameter. This parameter is designed to hide the complexities of Windows' inheritance and propagation flags. There are 13 possible combinations
        Given this tree :

              C
             / \
            CC CL
           /  \
          GC  GL

        Where :

          * C is the **C**ontainer permissions are getting set on
          * CC is a **C**hild **C**ontainer
          * CL is a **C**hild **L**eaf
          * GC is a **G**randchild **C**ontainer and includes all sub-containers below it
          * GL is a **G**randchild **L**eaf

        The 'ApplyTo' parameter takes one of the following 13 values and applies permissions to :

          * **Container** - The container itself and nothing below it
          * **SubContainers** - All sub-containers under the container, e.g. CC and GC
          * **Leaves** - All leaves under the container, e.g. CL and GL
          * **ChildContainers** - Just the container's child containers, e.g. CC
          * **ChildLeaves** - Just the container's child leaves, e.g. CL
          * **ContainerAndSubContainers** - The container and all its sub-containers, e.g. C, CC, and GC
          * **ContainerAndLeaves** - The container and all leaves under it, e.g. C and CL
          * **SubContainerAndLeaves** - All sub-containers and leaves, but not the container itself, e.g. CC, CL, GC, and GL
          * **ContainerAndChildContainers** - The container and all just its child containers, e.g. C and CC
          * **ContainerAndChildLeaves** - The container and just its child leaves, e.g. C and CL
          * **ContainerAndChildContainersAndChildLeaves** - The container and just its child containers/leaves, e.g. C, CC, and CL
          * **ContainerAndSubContainersAndLeaves** - Everything, full inheritance/propogation, e.g. C, CC, GC, GL.  **This is the default**
          * **ChildContainersAndChildLeaves**  - Just the container's child containers/leaves, e.g. CC and CL

        The following table maps 'ContainerInheritanceFlags' values to the actual 'InheritanceFlags' and 'PropagationFlags' values used :

          ContainerInheritanceFlags                   InheritanceFlags                 PropagationFlags
          -------------------------                   ----------------                 ----------------
          Container                                   None                             None
          SubContainers                               ContainerInherit                 InheritOnly
          Leaves                                      ObjectInherit                    InheritOnly
          ChildContainers                             ContainerInherit                 InheritOnly,
                                                                                       NoPropagateInherit
          ChildLeaves                                 ObjectInherit                    InheritOnly
          ContainerAndSubContainers                   ContainerInherit                 None
          ContainerAndLeaves                          ObjectInherit                    None
          SubContainerAndLeaves                       ContainerInherit,ObjectInherit   InheritOnly
          ContainerAndChildContainers                 ContainerInherit                 None
          ContainerAndChildLeaves                     ObjectInherit                    None
          ContainerAndChildContainersAndChildLeaves   ContainerInherit,ObjectInherit   NoPropagateInherit
          ContainerAndSubContainersAndLeaves          ContainerInherit,ObjectInherit   None
          ChildContainersAndChildLeaves               ContainerInherit,ObjectInherit   InheritOnly

        The above information was adapated from [Manage Access to Windows Objects with ACLs and the .NET Framework](http://msdn.microsoft.com/en-us/magazine/cc163885.aspx#S3)
        If you prefer to speak in 'InheritanceFlags' or 'PropagationFlags', you can use the 'ConvertTo-ContainerInheritanceFlags' Function to convert your flags into PSPM flags

        -- Certificate Private Keys/Key Containers :
        When setting permissions on a certificate's private key/key container, if a certificate doesn't have a private key, it is ignored and no permissions are set. Since certificates are always leaves, the 'ApplyTo' parameter is ignored
        When using the '-Clear' switch, note that the local 'Administrators' account will always remain to avoid not being able to read the key anymore
    .PARAMETER Path
        The path on which the permissions should be granted
        Can be a file system, registry, or certificate path
    .PARAMETER Identity
        The user or group getting the permissions
    .PARAMETER Permission
        The permission: e.g. FullControl, Read, etc.
        For file system items, use values from [System.Security.AccessControl.FileSystemRights](http://msdn.microsoft.com/en-us/library/system.security.accesscontrol.filesystemrights.aspx)
        For registry items, use values from [System.Security.AccessControl.RegistryRights](http://msdn.microsoft.com/en-us/library/system.security.accesscontrol.registryrights.aspx)
    .PARAMETER ApplyTo
        How to apply container permissions. This controls the inheritance and propagation flags
        Default is full inheritance, e.g. 'ContainersAndSubContainersAndLeaves'
        This parameter is ignored if 'Path' is a leaf item
    .PARAMETER Type
        The type of rule to apply, either 'Allow' or 'Deny'
        The default is 'Allow', which will allow access to the item
        The other option is 'Deny', which will deny access to the item
    .PARAMETER Clear
        Removes all non-inherited permissions on the item
    .PARAMETER PassThru
        Returns an object representing the permission created or set on the 'Path'
        The returned object will have a 'Path' property added to it so it can be piped to any cmdlet that uses a path
    .PARAMETER Force
        Grants permissions, even if they are already present
    .EXAMPLE
        Grant-Permission -Identity 'DOMAIN\Engineers' -Permission 'FullControl' -Path 'C:\Test'
        Grants the 'DOMAIN\Engineers' group full control on 'C:\Test'
    .EXAMPLE
        Grant-Permission -Identity 'DOMAIN\Interns' -Permission 'ReadKey,QueryValues,EnumerateSubKeys' -Path 'HKLM:\SOFTWARE\Test'
        Grants the 'DOMAIN\Interns' group access to read 'HKLM:\SOFTWARE\Test'
    .EXAMPLE
        Grant-Permission -Identity 'DOMAIN\Engineers' -Permission 'FullControl' -Path 'C:\Test' -Clear
        Grants the 'DOMAIN\Engineers' group full control on 'C:\Test'. Any non-inherited, existing access rules are removed from 'C:\Test'
    .EXAMPLE
        Grant-Permission -Identity 'DOMAIN\Engineers' -Permission 'FullControl' -Path 'Cert:\LocalMachine\My\1234567890ABCDEF1234567890ABCDEF12345678'
        Grants the 'DOMAIN\Engineers' group full control on the '1234567890ABCDEF1234567890ABCDEF12345678' certificate's private key/key container
    .EXAMPLE
        Grant-Permission -Identity 'DOMAIN\Users' -Permission 'FullControl' -Path 'C:\Test' -Type Deny
        Demonstrates how to grant deny permissions on an object with the 'Type' parameter
    .OUTPUTS
        System.Security.AccessControl.AccessRule
        When setting permissions on a file or directory, a 'System.Security.AccessControl.FileSystemAccessRule' object is returned
        When setting permissions on a registry key, a 'System.Security.AccessControl.RegistryAccessRule' object is returned
        When setting permissions on a private key, a 'System.Security.AccessControl.CryptoKeyAccessRule' object is returned
    .LINK
        ConvertTo-ContainerInheritanceFlags
    .LINK
        Disable-AclInheritance
    .LINK
        Enable-AclInheritance
    .LINK
        Get-Permission
    .LINK
        Revoke-Permission
    .LINK
        Test-Permission
    .LINK
        http://msdn.microsoft.com/en-us/library/system.security.accesscontrol.filesystemrights.aspx
    .LINK
        http://msdn.microsoft.com/en-us/library/system.security.accesscontrol.registryrights.aspx
    .LINK
        http://msdn.microsoft.com/en-us/library/system.security.accesscontrol.cryptokeyrights.aspx
    #>

    [CmdletBinding(SupportsShouldProcess=$true)]
    [OutputType([Security.AccessControl.AccessRule])]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Path,
        [Parameter(Mandatory=$true)]
        [string]$Identity,
        [Parameter(Mandatory=$true)]
        [Alias('Permissions')]
        [string[]]$Permission,
        [PSPM.Security.ContainerInheritanceFlags]$ApplyTo = ([PSPM.Security.ContainerInheritanceFlags]::ContainerAndSubContainersAndLeaves),
        [Security.AccessControl.AccessControlType]$Type = [Security.AccessControl.AccessControlType]::Allow,
        [switch]$Clear,
        [switch]$PassThru,
        [switch]$Force
   )

    $Path = Resolve-Path -Path $Path
    If (-not $Path) {
        return
    }

    $ProviderName = Get-PathProvider -Path $Path | Select-Object -ExpandProperty 'Name'
    If ($ProviderName -eq 'Certificate') {
        $ProviderName = 'CryptoKey'
    }

    If ($ProviderName -ne 'Registry' -and $ProviderName -ne 'FileSystem' -and $ProviderName -ne 'CryptoKey') {
        Write-Error "Unsupported path: '$Path' belongs to the '$ProviderName' provider. Only file system, registry, and certificate paths are supported"
        return
    }

    $Rights = $Permission | ConvertTo-ProviderAccessControlRights -ProviderName $ProviderName
    If (-not $Rights) {
        Write-Error ('Unable to grant {0} {1} permissions on {2}: received an unknown permission.' -f $Identity,($Permission -join ','),$Path)
        return
    }

    If (-not (Test-Identity -Name $Identity)) {
        Write-Error ('Identity ''{0}'' not found.' -f $Identity)
        return
    }

    $Identity = Resolve-IdentityName -Name $Identity

    If ($ProviderName -eq 'CryptoKey') {
        Get-Item -Path $Path |
        ForEach-Object {
            [Security.Cryptography.X509Certificates.X509Certificate2]$Certificate = $_

            If (-not $Certificate.HasPrivateKey) {
                Write-Warning ('Certificate {0} ({1}; {2}) does not have a private key.' -f $Certificate.Thumbprint,$Certificate.Subject,$Path)
                return
            }

            If (-not $Certificate.PrivateKey) {
                Write-Error ('Access is denied to private key of certificate {0} ({1}; {2}).' -f $Certificate.Thumbprint,$Certificate.Subject,$Path)
                return
            }

            [Security.AccessControl.CryptoKeySecurity]$KeySecurity = $Certificate.PrivateKey.CspKeyContainerInfo.CryptoKeySecurity
            If (-not $KeySecurity) {
                Write-Error ('Private key ACL not found for certificate {0} ({1}; {2}).' -f $Certificate.Thumbprint,$Certificate.Subject,$Path)
                return
            }

            $RulesToRemove = @()
            If ($Clear) {
                $RulesToRemove = $KeySecurity.Access |
                                 Where-Object { $_.IdentityReference.Value -ne $Identity } |
                                 # Don't remove Administrators access
                                 Where-Object { $_.IdentityReference.Value -ne 'BUILTIN\Administrators' }
                If ($RulesToRemove) {
                    $RulesToRemove |
                    ForEach-Object {
                        Write-Verbose ('[{0} {1}] [{1}]  {2} -> ' -f $Certificate.IssuedTo,$Path,$_.IdentityReference,$_.CryptoKeyRights)
                        If (-not $KeySecurity.RemoveAccessRule($_)) {
                            Write-Error ('Failed to remove {0}''s {1} permissions on ''{2}'' (3) certificate''s private key.' -f $_.IdentityReference,$_.CryptoKeyRights,$Certificate.Subject,$Certificate.Thumbprint)
                        }
                    }
                }
            }

            $CertPath = Join-Path -Path 'cert:' -ChildPath (Split-Path -NoQualifier -Path $Certificate.PSPath)

            $AccessRule = New-Object 'Security.AccessControl.CryptoKeyAccessRule' ($Identity,$Rights,$Type) |
                          Add-Member -MemberType NoteProperty -Name 'Path' -Value $CertPath -PassThru

            If ($Force -or $RulesToRemove -or -not (Test-Permission -Path $CertPath -Identity $Identity -Permission $Permission -Exact)) {
                $CurrentPerm = Get-Permission -Path $CertPath -Identity $Identity
                If ($CurrentPerm) {
                    $CurrentPerm = $CurrentPerm."$($ProviderName)Rights"
                }
                Write-Verbose -Message ('[{0} {1}] [{2}]  {3} -> {4}' -f $Certificate.IssuedTo,$CertPath,$AccessRule.IdentityReference,$CurrentPerm,$AccessRule.CryptoKeyRights)
                $KeySecurity.SetAccessRule($AccessRule)
                Set-CryptoKeySecurity -Certificate $Certificate -CryptoKeySecurity $KeySecurity -Action ('grant {0} {1} permission(s)' -f $Identity,($Permission -join ','))
            }

            If ($PassThru) {
                return $AccessRule
            }
        }
    }
    Else {
        # We don't use Get-Acl because it returns the whole security descriptor, which includes owner information
        # When passed to Set-Acl, this can cause intermittent errors. So we just grab the ACL portion of the security descriptor
        # See http://www.bilalaslam.com/2010/12/14/powershell-workaround-for-the-security-identifier-is-not-allowed-to-be-the-owner-of-this-object-with-set-acl/
        $CurrentAcl = (Get-Item $Path -Force).GetAccessControl('Access')

        $InheritanceFlags = [Security.AccessControl.InheritanceFlags]::None
        $PropagationFlags = [Security.AccessControl.PropagationFlags]::None
        $TestPermissionParams = @{}
        If (Test-Path -Path $Path -PathType Container) {
            $InheritanceFlags = ConvertTo-InheritanceFlag -ContainerInheritanceFlag $ApplyTo
            $PropagationFlags = ConvertTo-PropagationFlag -ContainerInheritanceFlag $ApplyTo
            $TestPermissionParams.ApplyTo = $ApplyTo
        }
        Else {
            If ($PSBoundParameters.ContainsKey('ApplyTo')) {
                Write-Warning "Can't apply inheritance/propagation rules to a leaf. Please omit 'ApplyTo' parameter when 'Path' is a leaf"
            }
        }

        $RulesToRemove = $null
        $Identity = Resolve-Identity -Name $Identity
        If ($Clear) {
            $RulesToRemove = $CurrentAcl.Access |
                             Where-Object { $_.IdentityReference.Value -ne $Identity } |
                             Where-Object { -not $_.IsInherited }

            If ($RulesToRemove) {
                ForEach ($RuleToRemove in $RulesToRemove) {
                    Write-Verbose ('[{0}] [{1}]  {2} -> ' -f $Path,$Identity,$RuleToRemove."$($ProviderName)Rights")
                    [void]$CurrentAcl.RemoveAccessRule($RuleToRemove)
                }
            }
        }

        $AccessRule = New-Object "Security.AccessControl.$($ProviderName)AccessRule" $Identity,$Rights,$InheritanceFlags,$PropagationFlags,$Type |
                      Add-Member -MemberType NoteProperty -Name 'Path' -Value $Path -PassThru

        $MissingPermission = -not (Test-Permission -Path $Path -Identity $Identity -Permission $Permission @testPermissionParams -Exact)

        $SetAccessRule = ($Force -or $MissingPermission)
        If ($SetAccessRule) {
            $CurrentAcl.SetAccessRule($AccessRule)
        }

        If ($RulesToRemove -or $SetAccessRule) {
            $CurrentPerm = Get-Permission -Path $Path -Identity $Identity
            If ($CurrentPerm) {
                $CurrentPerm = $CurrentPerm."$($ProviderName)Rights"
            }
            Write-Verbose -Message ('[{0}] [{1}]  {2} -> {3}' -f $Path,$AccessRule.IdentityReference,$CurrentPerm,$AccessRule."$($ProviderName)Rights")
            Set-Acl -Path $Path -AclObject $CurrentAcl
        }

        If ($PassThru) {
            return $AccessRule
        }
    }
}