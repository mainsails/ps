Function Get-NestedGroup {

    <#
    .SYNOPSIS
        Gets a list of nested groups inside an Active Directory group.

    .DESCRIPTION
        Gets a list of nested groups inside an Active Directory group using LDAPFilter. Checks for two levels of nested groups from the parent group.

    .PARAMETER Group
        The name of an Active Directory group

    .PARAMETER Server
        The name of a Domain Controller to use for query. Valid entries are a server name or ServerName:3268 for a Global Catalog query.

    .EXAMPLE
        PS C:\> Get-NestedGroup "Server Admins"

        ParentGroup            : Server Admins
        NestedGroup            : SiteA Server Admins
        NestedGroupMemberCount : 8
        ObjectClass            : group
        ObjectPath             : contoso.com/Groups/SiteA Server Adminss
        DistinguishedName      : CN=SiteA Server Admins,OU=Groups,DC=contoso,DC=com

        Returns the nested groups that are inside the group named "Server Admins".

        NOTE: NestedGroupMemberCount is the number of objects (aka members) inside the nested group.
        In this example, "SiteA Server Admins" contains 8 objects. This number is NOT the number of nested groups inside NYC Server Admins.

    .EXAMPLE
        PS C:\> Get-NestedGroup $Groups | Format-Table

        There are no nested groups inside SiteA-Desktops
        There are no nested groups inside SiteA-Servers
        There are no nested groups inside SiteA-Laptops
        There are no nested groups inside SiteA-Admins
        There are no nested groups inside SiteA-SupportDesk

        Checks the five groups saved in the variable $Groups for nested groups. In this example, none of five groups have any nested groups.
    #>

    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipelineByPropertyName, Mandatory = $true)]
        [String[]]$Group,

        [Parameter()]
        [String]$Server = (Get-ADReplicationsite | Get-ADDomainController -SiteName $_.Name -Discover -ErrorAction SilentlyContinue).Name
    )

    Begin {}

    Process {
        ForEach ($Item in $Group) {
            $ADGrp = Get-ADGroup -Identity $Item -Server $Server
            $QueryResult = Get-ADGroup -LDAPFilter "(&(objectCategory=group)(memberof=$($ADGrp.DistinguishedName)))" -Properties CanonicalName -Server $Server
            If ($null -ne $QueryResult) {
                foreach ($Grp in $QueryResult) {
                    $GrpLookup = Get-ADGroup -Identity "$($Grp.DistinguishedName)" -Properties Members,CanonicalName -Server $Server

                    $NestedGroupInfo = [PSCustomObject]@{
                        'ParentGroup'            = $Item
                        'NestedGroup'            = $Grp.Name
                        'NestedGroupMemberCount' = $GrpLookup.Members.Count
                        'ObjectClass'            = $Grp.ObjectClass
                        'ObjectPath'             = $GrpLookup.CanonicalName
                        'DistinguishedName'      = $GrpLookup.DistinguishedName
                    }
                    $NestedGroupInfo
                }
            }
            Else {
                Write-Information "There are no nested groups inside [$Item]" -InformationAction Continue
            }

            ForEach ($NestedGrp in $QueryResult) {
                $NestedADGrp = Get-ADGroup -Identity $NestedGrp -Server $Server
                $NestedQueryResult = Get-ADGroup -LDAPFilter "(&(objectCategory=group)(memberof=$($NestedADGrp.DistinguishedName)))" -Properties CanonicalName -Server $Server

                If ($null -ne $NestedQueryResult) {
                    ForEach ($SubGrp in $NestedQueryResult) {
                        $SubGrpLookup = Get-ADGroup -Identity "$($SubGrp.DistinguishedName)" -Properties Members, CanonicalName -Server $Server
                    }

                    $SubNestedGroupInfo = [PSCustomObject]@{
                        'ParentGroup'            = $NestedADGrp.Name
                        'NestedGroup'            = $SubGrp.Name
                        'NestedGroupMemberCount' = $SubGrpLookup.Members.Count
                        'ObjectClass'            = $SubGrp.ObjectClass
                        'ObjectPath'             = $SubGrpLookup.CanonicalName
                        'DistinguishedName'      = $SubGrpLookup.DistinguishedName
                    }
                    $SubNestedGroupInfo
                }
            }
        }
    }

    End {}
}
