#Requires -Version 4.0
#Requires -RunAsAdministrator


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
        Returns 'System.Security.AccessControl.CryptoKeyAccesRule' objects for certificate's 'Cert:\LocalMachine\1234567890ABCDEF1234567890ABCDEF12345678' private key/key container. If it doesn't have a private key, '$null' is returned
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


Function Disable-AclInheritance {
    <#
    .SYNOPSIS
        Protects an ACL so that changes to its parent can't be inherited to it
    .DESCRIPTION
        Items in the registry or file system will inherit permissions from its parent. The 'Disable-AclInheritance' Function disables inheritance, removing all inherited permissions. You can optionally preserve the currently inherited permission as explicit permissions using the '-Preserve' switch
        This Function will only disable inheritance if it is currently enabled
    .PARAMETER Path
        The file system or registry path whose access rule should stop inheriting from its parent
    .PARAMETER Preserve
        Keep the inherited access rules on this item
    .EXAMPLE
        Disable-AclInheritance -Path 'C:\Test'
        Removes all inherited access rules from the 'C:\Test' directory. Non-inherited rules are preserved
    .EXAMPLE
        Disable-AclInheritance -Path 'HKLM:\SOFTWARE\Test' -Preserve
        Stops 'HKLM:\SOFTWARE\Test' from inheriting acces rules from its parent, but preserves the existing inheritied access rules
    .LINK
        Disable-AclInheritance
    .LINK
        Get-Permission
    .LINK
        Grant-Permission
    .LINK
        Revoke-Permission
    #>

    [CmdletBinding(SupportsShouldProcess=$true)]
    Param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [Alias('PSPath')]
        [string]$Path,
        [switch]$Preserve
   )

    $ACL = Get-Acl -Path $Path
    If (-not $ACL.AreAccessRulesProtected) {
        Write-Verbose -Message ("[{0}] Disabling access rule inheritance." -f $Path)
        $ACL.SetAccessRuleProtection($true, $Preserve)
        $ACL | Set-Acl -Path $Path
    }
}


Function Enable-AclInheritance {
    <#
    .SYNOPSIS
        Enables ACL inheritance on an item
    .DESCRIPTION
        Items in the registry or file system will usually inherit ACLs from their parent. This inheritance can be disabled, either via the 'Disable-AclInheritance' Function or using .NET's secure API. The 'Enable-AclInheritance' Function re-enables inheritance on containers where it has been disabled. By default, any explicit permissions on the item are removed. Use the '-Preserve' switch to keep any existing, explicit permissions on the item
    .PARAMETER Path
        The file system or registry path who should start inheriting ACLs from its parent
    .PARAMETER Preserve
        Keep the explicit access rules defined on the item
    .EXAMPLE
        Enable-AclInheritance -Path 'C:\Test'
        Re-enables ACL inheritance on 'C:\Test'. ACLs on 'C:\' will be inherited to and affect 'C:\Test'. Any explicit ACLs on 'C:\Test' are removed
    .EXAMPLE
        Enable-AclInheritance -Path 'HKLM:\SOFTWARE\Test' -Preserve
        Re-enables ACL inheritance on 'HKLM:\SOFTWARE\Test'. ACLs on 'HKLM:\SOFTWARE' will be inherited to and affect 'HKLM:\SOFTWARE\Test'. Any explicit ACLs on ':\SOFTWARE\Test' are kept
    .LINK
        Disable-AclInheritance
    .LINK
        Get-Permission
    .LINK
        Grant-Permission
    .LINK
        Revoke-Permission
    #>

    [CmdletBinding(SupportsShouldProcess=$true)]
    Param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [Alias('PSPath')]
        [string]$Path,
        [switch]$Preserve
   )

    $ACL = Get-Acl -Path $Path
    If ($ACL.AreAccessRulesProtected) {
        Write-Verbose -Message ('[{0}] Enabling access rule inheritance.' -f $Path)
        $ACL.SetAccessRuleProtection($false, $Preserve)
        $ACL | Set-Acl -Path $Path

        If (-not $Preserve) {
            Get-Permission -Path $Path | ForEach-Object { Revoke-Permission -Path $Path -Identity $_.IdentityReference }
        }
    }
}


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
        If you prefer to speak in 'InheritanceFlags' or 'PropagationFlags', you can use the 'ConvertTo-ContainerInheritanceFlags' Function to convert your flags into PSSM flags

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
        [PSSM.Security.ContainerInheritanceFlags]$ApplyTo = ([PSSM.Security.ContainerInheritanceFlags]::ContainerAndSubContainersAndLeaves),
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
        [PSSM.Security.ContainerInheritanceFlags]$ApplyTo,
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


Function Set-CryptoKeySecurity {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory=$true)]
        [Security.AccessControl.CryptoKeySecurity]$CryptoKeySecurity,
        [Parameter(Mandatory=$true)]
        [string]$Action
   )


    $KeyContainerInfo = $Certificate.PrivateKey.CspKeyContainerInfo
    $CspParams = New-Object 'Security.Cryptography.CspParameters' ($KeyContainerInfo.ProviderType, $KeyContainerInfo.ProviderName, $KeyContainerInfo.KeyContainerName)
    $CspParams.Flags = [Security.Cryptography.CspProviderFlags]::UseExistingKey
    $CspParams.KeyNumber = $KeyContainerInfo.KeyNumber
    If ((Split-Path -NoQualifier -Path $Certificate.PSPath) -like 'LocalMachine\*') {
        $CspParams.Flags = $CspParams.Flags -bor [Security.Cryptography.CspProviderFlags]::UseMachineKeyStore
    }
    $CspParams.CryptoKeySecurity = $CryptoKeySecurity

    Try {
        # Persist the rule change
        If ($PSCmdlet.ShouldProcess(('{0} ({1})' -f $Certificate.Subject,$Certificate.Thumbprint), $Action)) {
            $null = New-Object 'Security.Cryptography.RSACryptoServiceProvider' ($CspParams)
        }
    }
    Catch {
        $ActualException = $_.Exception
        While ($ActualException.InnerException) {
            $ActualException = $ActualException.InnerException
        }
        Write-Error ('Failed to {0} to ''{1}'' ({2}) certificate''s private key: {3}: {4}' -f $Action,$Certificate.Subject,$Certificate.Thumbprint,$ActualException.GetType().FullName,$ActualException.Message)
    }
}


Function ConvertTo-ContainerInheritanceFlags {
    <#
    .SYNOPSIS
        Converts a combination of InheritanceFlags Propagation Flags into a 'PSSM.Security.ContainerInheritanceFlags' enumeration value
    .DESCRIPTION
        'Grant-Permission', 'Test-Permission', and 'Get-Permission' all take an 'ApplyTo' parameter, which is a 'PSSM.Security.ContainerInheritanceFlags' enumeration value. This enumeration is then converted to the appropriate 'System.Security.AccessControl.InheritanceFlags' and 'System.Security.AccessControl.PropagationFlags' values for getting/granting/testing permissions
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
        In this case, '[PSSM.Security.ContainerInheritanceFlags]::ContainerAndSubContainers' is returned
    .OUTPUTS
        PSSM.Security.ContainerInheritanceFlags
    .LINK
        Grant-Permission
    .LINK
        Test-Permission
    #>

    [CmdletBinding()]
    [OutputType([PSSM.Security.ContainerInheritanceFlags])]
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
        return [PSSM.Security.ContainerInheritanceFlags]::Container
    }
    ElseIf ($InheritanceFlags -eq [Security.AccessControl.InheritanceFlags]::ContainerInherit) {
        If ($PropFlagsInheritOnly) {
            return [PSSM.Security.ContainerInheritanceFlags]::SubContainers
        }
        ElseIf ($PropFlagsInheritOnlyNoPropagate) {
            return [PSSM.Security.ContainerInheritanceFlags]::ChildContainers
        }
        ElseIf ($PropFlagsNone) {
            return [PSSM.Security.ContainerInheritanceFlags]::ContainerAndSubContainers
        }
        ElseIf ($PropFlagsNoPropagate) {
            return [PSSM.Security.ContainerInheritanceFlags]::ContainerAndChildContainers
        }
    }
    ElseIf ($InheritanceFlags -eq [Security.AccessControl.InheritanceFlags]::ObjectInherit) {
        If ($PropFlagsInheritOnly) {
            return [PSSM.Security.ContainerInheritanceFlags]::Leaves
        }
        ElseIf ($PropFlagsInheritOnlyNoPropagate) {
            return [PSSM.Security.ContainerInheritanceFlags]::ChildLeaves
        }
        ElseIf ($PropFlagsNone) {
            return [PSSM.Security.ContainerInheritanceFlags]::ContainerAndLeaves
        }
        ElseIf ($PropFlagsNoPropagate) {
            return [PSSM.Security.ContainerInheritanceFlags]::ContainerAndChildLeaves
        }
    }
    ElseIf ($InheritanceFlags -eq ([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit)) {
        If ($PropFlagsInheritOnly) {
            return [PSSM.Security.ContainerInheritanceFlags]::SubContainersAndLeaves
        }
        ElseIf ($PropFlagsInheritOnlyNoPropagate) {
            return [PSSM.Security.ContainerInheritanceFlags]::ChildContainersAndChildLeaves
        }
        ElseIf ($PropFlagsNone) {
            return [PSSM.Security.ContainerInheritanceFlags]::ContainerAndSubContainersAndLeaves
        }
        ElseIf ($PropFlagsNoPropagate) {
            return [PSSM.Security.ContainerInheritanceFlags]::ContainerAndChildContainersAndChildLeaves
        }
    }
}


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


Function ConvertTo-InheritanceFlag {
    <#
    .SYNOPSIS
        Converts a 'PSSM.Security.ContainerInheritanceFlags' value to a 'System.Security.AccessControl.InheritanceFlags' value
    .DESCRIPTION
        The 'PSSM.Security.ContainerInheritanceFlags' enumeration encapsulates oth 'System.Security.AccessControl.InheritanceFlags' and 'System.Security.AccessControl.PropagationFlags'
        Make sure you also call 'ConvertTo-PropagationFlag' to get the propagation value
    .PARAMETER ContainerInheritanceFlag
        The value to convert to an 'InheritanceFlags' value
    .EXAMPLE
        ConvertTo-InheritanceFlag -ContainerInheritanceFlag ContainerAndSubContainersAndLeaves
        Returns 'InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit'
    .OUTPUTS
        System.Security.AccessControl.InheritanceFlags
    .LINK
        ConvertTo-PropagationFlag
    .LINK
        Grant-Permission
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [Alias('ContainerInheritanceFlags')]
        [PSSM.Security.ContainerInheritanceFlags]$ContainerInheritanceFlag
    )

    $Flags = [Security.AccessControl.InheritanceFlags]
    $Map = @{
        'Container' =                                  $Flags::None;
        'SubContainers' =                              $Flags::ContainerInherit;
        'Leaves' =                                     $Flags::ObjectInherit;
        'ChildContainers' =                            $Flags::ContainerInherit;
        'ChildLeaves' =                                $Flags::ObjectInherit;
        'ContainerAndSubContainers' =                  $Flags::ContainerInherit;
        'ContainerAndLeaves' =                         $Flags::ObjectInherit;
        'SubContainersAndLeaves' =                    ($Flags::ContainerInherit -bor $Flags::ObjectInherit);
        'ContainerAndChildContainers' =                $Flags::ContainerInherit;
        'ContainerAndChildLeaves' =                    $Flags::ObjectInherit;
        'ContainerAndChildContainersAndChildLeaves' = ($Flags::ContainerInherit -bor $Flags::ObjectInherit);
        'ContainerAndSubContainersAndLeaves' =        ($Flags::ContainerInherit -bor $Flags::ObjectInherit);
        'ChildContainersAndChildLeaves' =             ($Flags::ContainerInherit -bor $Flags::ObjectInherit);
    }
    $Key = $ContainerInheritanceFlag.ToString()
    If ($Map.ContainsKey($key)) {
        return $Map[$Key]
    }

    Write-Error ('Unknown PSSM.Security.ContainerInheritanceFlags enumeration value {0}.' -f $ContainerInheritanceFlag)
}


Function ConvertTo-PropagationFlag {
    <#
    .SYNOPSIS
        Converts a 'PSSM.Security.ContainerInheritanceFlags' value to a 'System.Security.AccessControl.PropagationFlags' value
    .DESCRIPTION
        The 'PSSM.Security.ContainerInheritanceFlags' enumeration encapsulates both 'System.Security.AccessControl.PropagationFlags' and 'System.Security.AccessControl.InheritanceFlags'
        Make sure you also call 'ConvertTo-InheritancewFlags' to get the inheritance value
    .PARAMETER ContainerInheritanceFlag
        The value to convert to an 'PropagationFlags' value
    .EXAMPLE
        ConvertTo-PropagationFlag -ContainerInheritanceFlag ContainerAndSubContainersAndLeaves
        Returns 'PropagationFlags.None'
    .OUTPUTS
        System.Security.AccessControl.PropagationFlags
    .LINK
        ConvertTo-InheritanceFlag
    .LINK
        Grant-Permission
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [Alias('ContainerInheritanceFlags')]
        [PSSM.Security.ContainerInheritanceFlags]$ContainerInheritanceFlag
    )

    $Flags = [Security.AccessControl.PropagationFlags]
    $Map = @{
        'Container'                                 =  $Flags::None;
        'SubContainers'                             =  $Flags::InheritOnly;
        'Leaves'                                    =  $Flags::InheritOnly;
        'ChildContainers'                           = ($Flags::InheritOnly -bor $Flags::NoPropagateInherit);
        'ChildLeaves'                               = ($Flags::InheritOnly -bor $Flags::NoPropagateInherit);
        'ContainerAndSubContainers'                 =  $Flags::None;
        'ContainerAndLeaves'                        =  $Flags::None;
        'SubContainersAndLeaves'                    =  $Flags::InheritOnly;
        'ContainerAndChildContainers'               =  $Flags::NoPropagateInherit;
        'ContainerAndChildLeaves'                   =  $Flags::NoPropagateInherit;
        'ContainerAndChildContainersAndChildLeaves' =  $Flags::NoPropagateInherit;
        'ContainerAndSubContainersAndLeaves'        =  $Flags::None;
        'ChildContainersAndChildLeaves'             = ($Flags::InheritOnly -bor $Flags::NoPropagateInherit);
    }
    $Key = $ContainerInheritanceFlag.ToString()
    If ($Map.ContainsKey($Key)) {
        return $Map[$Key]
    }

    Write-Error ('Unknown PSSM.Security.ContainerInheritanceFlags enumeration value {0}.' -f $ContainerInheritanceFlag)
}


Function ConvertTo-SecurityIdentifier {
    <#
    .SYNOPSIS
        Converts a string or byte array security identifier into a 'System.Security.Principal.SecurityIdentifier' object
    .DESCRIPTION
        'ConvertTo-SecurityIdentifier' converts a SID in SDDL form (as a string), in binary form (as a byte array) into a 'System.Security.Principal.SecurityIdentifier' object
        It also accepts 'System.Security.Principal.SecurityIdentifier' objects, and returns them back to you
        If the string or byte array don't represent a SID, an error is written and nothing is returned
    .PARAMETER SID
        The SID to convert to a 'System.Security.Principal.SecurityIdentifier'
        Accepts a SID in SDDL form as a 'string', a 'System.Security.Principal.SecurityIdentifier' object or a SID in binary form as an array of bytes
    .EXAMPLE
        ConvertTo-SecurityIdentifier -SID 'S-1-5-32-544'
        Demonstrates how to convert a SID in SDDL form into a 'System.Security.Principal.SecurityIdentifier' object
    .EXAMPLE
        ConvertTo-SecurityIdentifier -SID (New-Object 'Security.Principal.SecurityIdentifier' 'S-1-5-32-544')
        Demonstrates that you can pass a 'SecurityIdentifier' object as the value of the SID parameter
        The SID you passed in will be returned to you unchanged
    .EXAMPLE
        ConvertTo-SecurityIdentifier -SID $SIDBytes
        Demonstrates that you can use a byte array that represents a SID as the value of the 'SID' parameter.
    .LINK
        Resolve-Identity
    .LINK
        Resolve-IdentityName
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        $SID
    )

    Try {
        If ($SID -is [string]) {
            New-Object 'Security.Principal.SecurityIdentifier' $SID
        }
        Elseif ($SID -is [byte[]]) {
            New-Object 'Security.Principal.SecurityIdentifier' $SID,0
        }
        Elseif ($SID -is [Security.Principal.SecurityIdentifier]) {
            $SID
        }
        Else {
            Write-Error ('Invalid SID. The 'SID' parameter accepts a 'System.Security.Principal.SecurityIdentifier' object, a SID in SDDL form as a 'string', or a SID in binary form as byte array. You passed a ''{0}''.' -f $SID.GetType())
            return
        }
    }
    Catch {
        Write-Error ('Exception converting SID parameter to a 'SecurityIdentifier' object. This usually means you passed an invalid SID in SDDL form (as a string) or an invalid SID in binary form (as a byte array): {0}' -f $_.Exception.Message)
        return
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
        Use the 'PassThru' switch to return a 'PSSM.Identity' object (instead of '$true' if the identity exists)
    .PARAMETER Name
        The name of the identity to test
    .PARAMETER PassThru
        Returns a 'PSSM.Identity' object if the identity exists
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

    $Identity = [PSSM.Identity]::FindByName($Name)
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
        It returns a 'PSSM.Identity' object which contains the following information about the identity :
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
        PSSM.Identity
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
    [OutputType([PSSM.Identity])]
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

        $ID = [PSSM.Identity]::FindBySid($SID)
        If (-not $ID) {
            Write-Error ('Identity ''{0}'' not found.' -f $SID) -ErrorAction $ErrorActionPreference
        }
        return $ID
    }

    If (-not (Test-Identity -Name $Name)) {
        Write-Error ('Identity ''{0}'' not found.' -f $Name) -ErrorAction $ErrorActionPreference
        return
    }

    return [PSSM.Identity]::FindByName($Name)
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

        $ID = [PSSM.Identity]::FindBySid($SID)
        If ($ID) {
            return $ID.FullName
        }
        Else {
            return $SID.ToString()
        }
    }
}


# Load C# Namespace if required
If ((-not ([Management.Automation.PSTypeName]'PSSM.Identity').Type) -or (-not ([Management.Automation.PSTypeName]'PSSM.IdentityType').Type) -or (-not ([Management.Automation.PSTypeName]'PSSM.Security.ContainerInheritanceFlags').Type)) {
    $CSSourceCode = @"
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace PSSM
{
  internal static class Win32ErrorCodes
  {
    internal const int Ok                       = 0x000;
    internal const int NERR_Success             = 0x000;
    internal const int AccessDenied             = 0x005;
    internal const int InvalidHandle            = 0x006;
    internal const int InvalidParameter         = 0x057;
    internal const int InsufficientBuffer       = 0x07A;
    internal const int AlreadyExists            = 0x0B7;
    internal const int NoMoreItems              = 0x103;
    internal const int InvalidFlags             = 0x3EC;
    internal const int ServiceMarkedForDelete   = 0x430;
    internal const int NoneMapped               = 0x534;
    internal const int MemberNotInAlias         = 0x561;
    internal const int MemberInAlias            = 0x562;
    internal const int NoSuchMember             = 0x56B;
    internal const int InvalidMember            = 0x56C;
    internal const int NERR_GroupNotFound       = 0x8AC;
  }
  namespace Security
  {
    [Flags]
    public enum ContainerInheritanceFlags
    {
      /// <summary>
      /// Apply permission to the container.
      /// </summary>
      Container = 1,
      /// <summary>
      /// Apply permissions to all sub-containers.
      /// </summary>
      SubContainers = 2,
      /// <summary>
      /// Apply permissions to all leaves.
      /// </summary>
      Leaves = 4,
      /// <summary>
      /// Apply permissions to child containers.
      /// </summary>
      ChildContainers = 8,
      /// <summary>
      /// Apply permissions to child leaves.
      /// </summary>
      ChildLeaves = 16,

      /// <summary>
      /// Apply permission to the container and all sub-containers.
      /// </summary>
      ContainerAndSubContainers = Container|SubContainers,
      /// <summary>
      /// Apply permissionto the container and all leaves.
      /// </summary>
      ContainerAndLeaves = Container|Leaves,
      /// <summary>
      /// Apply permission to all sub-containers and all leaves.
      /// </summary>
      SubContainersAndLeaves = SubContainers | Leaves,
      /// <summary>
      /// Apply permission to container and child containers.
      /// </summary>
      ContainerAndChildContainers = Container|ChildContainers,
      /// <summary>
      /// Apply permission to container and child leaves.
      /// </summary>
      ContainerAndChildLeaves = Container|ChildLeaves,
      /// <summary>
      /// Apply permission to container, child containers, and child leaves.
      /// </summary>
      ContainerAndChildContainersAndChildLeaves = Container|ChildContainers|ChildLeaves,
      /// <summary>
      /// Apply permission to container, all sub-containers, and all leaves.
      /// </summary>
      ContainerAndSubContainersAndLeaves = Container|SubContainers|Leaves,
      /// <summary>
      /// Apply permission to child containers and child leaves.
      /// </summary>
      ChildContainersAndChildLeaves = ChildContainers|ChildLeaves
    }
  }

  // http://msdn.microsoft.com/en-us/library/windows/desktop/aa379601.aspx
  public enum IdentityType
  {
    User = 1,
    Group,
    Domain,
    Alias,
    WellKnownGroup,
    DeletedAccount,
    Invalid,
    Unknown,
    Computer,
    Label
  }

  public sealed class Identity
  {
    // ReSharper disable InconsistentNaming
    [DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern bool ConvertSidToStringSid(
      [MarshalAs(UnmanagedType.LPArray)] byte[] pSID,
      out IntPtr ptrSid);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr hMem);

    [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern bool LookupAccountName(
      string lpSystemName,
      string lpAccountName,
      [MarshalAs(UnmanagedType.LPArray)] byte[] Sid,
      ref uint cbSid,
      StringBuilder referencedDomainName,
      ref uint cchReferencedDomainName,
      out IdentityType peUse);

    [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    static extern bool LookupAccountSid(
      string lpSystemName,
      [MarshalAs(UnmanagedType.LPArray)] byte[] Sid,
      StringBuilder lpName,
      ref uint cchName,
      StringBuilder referencedDomainName,
      ref uint cchReferencedDomainName,
      out IdentityType peUse);

    [DllImport("NetApi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern int NetLocalGroupAddMembers(
      string servername, //server name
      string groupname, //group name
      UInt32 level, //info level
      ref LOCALGROUP_MEMBERS_INFO_0 buf, //Group info structure
      UInt32 totalentries //number of entries
      );

    [DllImport("NetApi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern int NetLocalGroupDelMembers(
      string servername, //server name
      string groupname, //group name
      UInt32 level, //info level
      ref LOCALGROUP_MEMBERS_INFO_0 buf, //Group info structure
      UInt32 totalentries //number of entries
      );

    [DllImport("NetAPI32.dll", CharSet = CharSet.Unicode)]
    private extern static int NetLocalGroupGetMembers(
      [MarshalAs(UnmanagedType.LPWStr)] string servername,
      [MarshalAs(UnmanagedType.LPWStr)] string localgroupname,
      int level,
      out IntPtr bufptr,
      int prefmaxlen,
      out int entriesread,
      out int totalentries,
      IntPtr resume_handle);

    [DllImport("Netapi32.dll", SetLastError = true)]
    private static extern int NetApiBufferFree(IntPtr buffer);

    [StructLayout(LayoutKind.Sequential)]
    private struct LOCALGROUP_MEMBERS_INFO_0
    {
      [MarshalAs(UnmanagedType.SysInt)]
      public IntPtr pSID;
    }

    // ReSharper restore InconsistentNaming
    private Identity(string domain, string name, SecurityIdentifier sid, IdentityType type)
    {
      Domain = domain;
      Name = name;
      Sid = sid;
      Type = type;
    }

    public string Domain { get; private set; }

    public string FullName
    {
      get
      {
        return (string.IsNullOrEmpty(Domain))
        ? Name
        : string.Format("{0}\\{1}", Domain, Name);
      }
    }

    public string Name { get; private set; }

    public SecurityIdentifier Sid { get; private set; }

    public IdentityType Type { get; private set; }

    public override bool Equals(object obj)
    {
      if (obj == null || typeof (Identity) != obj.GetType())
      {
        return false;
      }
        return Sid.Equals(((Identity) obj).Sid);
    }

    public void AddToLocalGroup(string groupName)
    {
      var sidBytes = new byte[Sid.BinaryLength];
      Sid.GetBinaryForm(sidBytes, 0);

      var info3 = new LOCALGROUP_MEMBERS_INFO_0
      {
        pSID = Marshal.AllocHGlobal(sidBytes.Length)
      };

      try
      {
        Marshal.Copy(sidBytes, 0, info3.pSID, sidBytes.Length);
        var result = NetLocalGroupAddMembers(null, groupName, 0, ref info3, 1);
        if (result == Win32ErrorCodes.NERR_Success || result == Win32ErrorCodes.MemberInAlias)
        {
          return;
        }
        throw new Win32Exception(result);
      }
      finally
      {
        Marshal.FreeHGlobal(info3.pSID);
      }
    }

    public static Identity FindByName(string name)
    {
      byte[] rawSid = null;
      uint cbSid = 0;
      var referencedDomainName = new StringBuilder();
      var cchReferencedDomainName = (uint) referencedDomainName.Capacity;
      IdentityType sidUse;

      if (name.StartsWith(".\\"))
      {
        var username = name.Substring(2);
        name = string.Format("{0}\\{1}", Environment.MachineName, username);
        var identity = FindByName(name);
        if (identity == null)
        {
          name = string.Format("BUILTIN\\{0}", username);
          identity = FindByName(name);
        }
        return identity;
      }

      if (name.Equals("LocalSystem", StringComparison.InvariantCultureIgnoreCase))
      {
        name = "NT AUTHORITY\\SYSTEM";
      }
      if (LookupAccountName(null, name, rawSid, ref cbSid, referencedDomainName, ref cchReferencedDomainName, out sidUse))
      {
        throw new Win32Exception();
      }
      var err = Marshal.GetLastWin32Error();
      if (err == Win32ErrorCodes.InsufficientBuffer || err == Win32ErrorCodes.InvalidFlags)
      {
          rawSid = new byte[cbSid];
          referencedDomainName.EnsureCapacity((int) cchReferencedDomainName);
          if (!LookupAccountName(null, name, rawSid, ref cbSid, referencedDomainName, ref cchReferencedDomainName, out sidUse))
          {
            throw new Win32Exception();
          }
      }
      else if (err == Win32ErrorCodes.NoneMapped)
      {
        // Couldn't find the account.
        return null;
      }
      else
      {
        throw new Win32Exception();
      }
      IntPtr ptrSid;
      if (!ConvertSidToStringSid(rawSid, out ptrSid))
      {
        throw new Win32Exception();
      }
      var sid = new SecurityIdentifier(rawSid, 0);
      LocalFree(ptrSid);
      var ntAccount = sid.Translate(typeof (NTAccount));
      var domainName = referencedDomainName.ToString();
      var accountName = ntAccount.Value;
      if (!string.IsNullOrEmpty(domainName))
      {
        var domainPrefix = string.Format("{0}\\", domainName);
        if (accountName.StartsWith(domainPrefix))
        {
          accountName = accountName.Replace(domainPrefix, "");
        }
      }
      return new Identity(domainName, accountName, sid, sidUse);
    }

    /// <summary>
    /// Searches for an identity by SID. If the SID is invalid, or the identity doesn't exist, null is returned.
    /// </summary>
    /// <param name="sid"></param>
    /// <returns>Null if the identity isn't found or the SID is invalid. Otherwise, a 'PSSM.Identity' object.</returns>
    public static Identity FindBySid(SecurityIdentifier sid)
    {
      const int ok = 0;
      var sidBytes = new byte[sid.BinaryLength];
      sid.GetBinaryForm(sidBytes, 0);
      var name = new StringBuilder();
      var cchName = (uint) name.Capacity;
      var referencedDomainName = new StringBuilder();
      var cchReferencedDomainName = (uint) referencedDomainName.Capacity;
      IdentityType identityType;
      var err = ok;
      if ( !LookupAccountSid(null, sidBytes, name, ref cchName, referencedDomainName, ref cchReferencedDomainName, out identityType))
      {
        err = Marshal.GetLastWin32Error();
        if( err == Win32ErrorCodes.InsufficientBuffer )
        {
          name.EnsureCapacity((int) cchName);
          referencedDomainName.EnsureCapacity((int) cchReferencedDomainName);
          err = ok;
          if ( !LookupAccountSid(null, sidBytes, name, ref cchName, referencedDomainName, ref cchReferencedDomainName, out identityType))
            err = Marshal.GetLastWin32Error();
        }
      }
      switch (err)
      {
          case ok:
              return new Identity(referencedDomainName.ToString(), name.ToString(), sid, identityType);
          case Win32ErrorCodes.NoneMapped:
              return null;
          default:
              throw new Win32Exception(err, string.Format("Failed to lookup account SID for '{0}'.", sid));
      }
    }

    public override int GetHashCode()
    {
      return Sid.GetHashCode();
    }

    public bool IsMemberOfLocalGroup(string groupName)
    {
      int entriesRead;
      int totalEntries;
      var resume = IntPtr.Zero;
      IntPtr buffer;
      var result = NetLocalGroupGetMembers(null, groupName, 0, out buffer, -1, out entriesRead, out totalEntries, resume);
      try
      {
        if (result != Win32ErrorCodes.NERR_Success)
        {
          throw new Win32Exception(result);
        }

        if (entriesRead == 0)
        {
          return false;
        }
        var iter = buffer;
        for (var i = 0; i < entriesRead; i++)
        {
          var memberPtr = iter + (Marshal.SizeOf(typeof(LOCALGROUP_MEMBERS_INFO_0)) * i);
          var memberInfo = (LOCALGROUP_MEMBERS_INFO_0)Marshal.PtrToStructure(memberPtr, typeof(LOCALGROUP_MEMBERS_INFO_0));
          var sid = new SecurityIdentifier(memberInfo.pSID);
          if (sid.Value == Sid.Value)
          {
            return true;
          }
        }
      }
      finally
      {
        NetApiBufferFree(buffer);
      }
      return false;
    }

    public void RemoveFromLocalGroup(string groupName)
    {
      var sidBytes = new byte[Sid.BinaryLength];
      Sid.GetBinaryForm(sidBytes, 0);

      var info3 = new LOCALGROUP_MEMBERS_INFO_0
      {
        pSID = Marshal.AllocHGlobal(sidBytes.Length)
      };
      try
      {
        Marshal.Copy(sidBytes, 0, info3.pSID, sidBytes.Length);

        var result = NetLocalGroupDelMembers(null, groupName, 0, ref info3, 1);
        if (result == Win32ErrorCodes.NERR_Success || result == Win32ErrorCodes.MemberNotInAlias)
        {
          return;
        }
        throw new Win32Exception(result);
      }
      finally
      {
        Marshal.FreeHGlobal(info3.pSID);
      }
    }

    public override string ToString()
    {
      return FullName;
    }
  }
}

"@
    Write-Verbose -Message 'Loading C# Namespace'
    Add-Type -TypeDefinition $CSSourceCode -Language CSharp -ErrorAction Stop
}
