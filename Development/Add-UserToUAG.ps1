Function Add-UserToUAG {
    <#
    .Synopsis
        Adds one or more users to the UAG Group
    .Description
        Adds one or more users to the UAG Group - 'UAG - Portal Pilot Users'
    .Parameter Username
        List of usernames to add to the UAG Group
    .Example
        Add-UserToUAG -UserName "UserName1", "UserName2", "UserName3"
    .Example
        Get-Clipboard | Add-UserToUAG
    #>
    #Requires -Module ActiveDirectory

    Param (
        [Parameter(ValueFromPipeline=$true)]
        [String[]]$UserName
    )

    Begin {
        ## Set Group
        $Group = 'UAG Group'
        $Group = Get-ADGroup $Group
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
        $UserList = $UserList | ForEach-Object { $_.Trim() } | Sort-Object -Unique
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