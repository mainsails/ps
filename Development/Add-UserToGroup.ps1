Function Add-UserToGroup {
    <#
    .Synopsis
        Adds one or more users to a Group
    .Description
        Adds one or more users to an Active Directory Group
    .Parameter Username
        List of usernames to add to the Group
    .Parameter Username
        List of usernames to add to the Group
    .Example
        Add-UserToGroup -UserName "UserName1", "UserName2", "UserName3"
    .Example
        Get-Clipboard | Add-UserToGroup
    #>
    #Requires -Module ActiveDirectory

    Param (
        [Parameter(ValueFromPipeline=$true)]
        [String[]]$UserName,
        [Parameter(Mandatory=$true)]
        [ValidateScript({ Get-ADGroup -Identity $_ })]
        $Group
    )

    Begin {
        ## Set Group
        $Group = Get-ADGroup -Identity $Group
        # Create ArrayList for Users
        $UserList = New-Object -TypeName System.Collections.ArrayList
    }
    Process {
        # Build list of Users
        $UserList.AddRange($UserName)
    }
    End {
        ## Get AD Users
        # Trim whitespace, remove duplicates
        $UserList = $UserList | ForEach-Object { If ($_) { $_.Trim() | Sort-Object -Unique }}
        # Build AD Filter
        $Filter = ($UserList | ForEach-Object { "(SamAccountName -eq '$_' -and MemberOf -ne '$($Group.DistinguishedName)')" }) -join ' -or '
        # Get AD Users that aren't a member of the Group
        $Users = Get-ADUser -Filter $Filter
        ## Add Users to Group
        If ($Users) { Add-ADGroupMember -Identity $Group -Members $Users }
        # Not Added
        $UserList | Where-Object -FilterScript { ($Users | Select-Object -ExpandProperty 'SamAccountName') -notcontains $_ } | ForEach-Object { Write-Warning -Message "$_ Not Added" }
    }
}