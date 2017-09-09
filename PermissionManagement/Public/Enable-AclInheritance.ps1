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