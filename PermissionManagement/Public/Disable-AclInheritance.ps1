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