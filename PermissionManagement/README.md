# Permission Management PowerShell Module

## Description
The Permission Management module was designed to assist with common file system, registry, and certificate permission tasks.
It can grant or revoke permissions on a file, a directory, a registry key, or a certificate's private key


## Requirements
* All Windows Client Operating Systems are supported  
   Windows 7 SP1 and Windows Server 2008R2 through to Windows 10 Build 1703 and Windows Server 2016
* PowerShell Version 4


## Usage
### Grant Permissions
```powershell
Grant-Permission -Identity 'DOMAIN\Engineers' -Permission 'FullControl' -Path 'C:\Test'
# Grants the 'DOMAIN\Engineers' group full control on 'C:\Test'

Grant-Permission -Identity 'DOMAIN\Interns' -Permission 'ReadKey,QueryValues,EnumerateSubKeys' -Path 'HKLM:\SOFTWARE\Test'
# Grants the 'DOMAIN\Interns' group access to read 'HKLM:\SOFTWARE\Test'

Grant-Permission -Identity 'DOMAIN\Engineers' -Permission 'FullControl' -Path 'C:\Test' -Clear
# Grants the 'DOMAIN\Engineers' group full control on 'C:\Test'
# Any non-inherited, existing access rules are removed from 'C:\Test'
```

### Revoke Permissions
```powershell
Revoke-Permission -Identity 'DOMAIN\Engineers' -Path 'C:\Test'
# Demonstrates how to revoke all of the 'DOMAIN\Engineers' permissions on the 'C:\Test' directory

Revoke-Permission -Identity 'DOMAIN\Users' -Path 'Cert:\LocalMachine\My\1234567890ABCDEF1234567890ABCDEF12345678'
# Demonstrates how to revoke the 'DOMAIN\Users' permission to the 'Cert:\LocalMachine\My\1234567890ABCDEF1234567890ABCDEF12345678' certificate's private key/key container
```

### Get Permissions
```powershell
Get-Permission -Path 'C:\Windows'
# Returns 'System.Security.AccessControl.FileSystemAccessRule' objects for all the non-inherited rules on 'C:\Windows'

Get-Permission -Path 'HKLM:\SOFTWARE' -Inherited
# Returns 'System.Security.AccessControl.RegistryAccessRule' objects for all the inherited and non-inherited rules on 'HKLM:\SOFTWARE'

Get-Permission -Path 'C:\Windows' -Identity 'Administrators'
# Returns 'System.Security.AccessControl.FileSystemAccessRule' objects for all the 'Administrators' rules on 'C:\Windows'
```

### Test Permissions
```powershell
Test-Permission -Identity 'DOMAIN\UserName' -Permission 'FullControl' -Path 'C:\Test'
# Demonstrates how to check that 'DOMAIN\UserName' has 'FullControl' permission on the 'C:\Test' directory

Test-Permission -Identity 'DOMAIN\UserName' -Permission 'WriteKey' -Path 'HKLM:\SOFTWARE\Test'
# Demonstrates how to check that 'DOMAIN\UserName' can write registry keys to 'HKLM:\SOFTWARE\Test'

Test-Permission -Identity 'DOMAIN\UserName' -Permission 'Write' -ApplyTo 'Container' -Path 'C:\Test'
# Demonstrates how to test for inheritance/propogation flags, in addition to permissions
```

### Enable ACL Inheritance
```powershell
Enable-AclInheritance -Path 'C:\Test'
# Re-enables ACL inheritance on 'C:\Test'
# ACLs on 'C:\' will be inherited to and affect 'C:\Test'. Any explicit ACLs on 'C:\Test' are removed

Enable-AclInheritance -Path 'HKLM:\SOFTWARE\Test' -Preserve
# Re-enables ACL inheritance on 'HKLM:\SOFTWARE\Test'. ACLs on 'HKLM:\SOFTWARE' will be inherited to and affect 'HKLM:\SOFTWARE\Test'. Any explicit ACLs on ':\SOFTWARE\Test' are kept
```

### Disable ACL Inheritance
```powershell
Disable-AclInheritance -Path 'C:\Test'
# Removes all-  inherited access rules from the 'C:\Test' directory
# Non-inherited rules are preserved

Disable-AclInheritance -Path 'HKLM:\SOFTWARE\Test' -Preserve
# Stops 'HKLM:\SOFTWARE\Test' from inheriting acces rules from its parent, but preserves the existing inheritied access rules
```