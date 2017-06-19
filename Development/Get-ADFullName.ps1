Function Get-ADFullName {

    <#
    .Synopsis
        Gets one or more Active Directory users
    .Description
        Gets one or more Active Directory users using "Forename Surname" format
    .Parameter FullName
        List of Names to check against Active Directory using "Forename Surname" format
    .Example
        Get-ADFullName -FullName "Sam Shaw", "Matt Winter", "Yasir Ali"
    .Example
        Get-Clipboard | Get-ADFullName
    #>
    #Requires -Module ActiveDirectory

    Param (
        [Parameter(ValueFromPipeline=$true)]
        [String[]]$FullName
    )

    Begin {
        # Create ArrayList for Full Names
        $NameList    = New-Object -TypeName System.Collections.ArrayList
        $UsersObject = New-Object -TypeName System.Collections.ArrayList
    }

    Process {
        # Build ArrayList of Full Names
        $NameList.AddRange($FullName)
    }

    End {
        # Build User Object
        ForEach ($FullName in $NameList) {
            $Object = New-Object System.Object
            $Object | Add-Member -MemberType NoteProperty -Name 'FullName' -Value $FullName
            $Object | Add-Member -MemberType NoteProperty -Name 'Names'    -Value $FullName.Split(' ')
            $Object | Add-Member -MemberType NoteProperty -Name 'Forename' -Value $Object.Names[0]
            $Object | Add-Member -MemberType NoteProperty -Name 'Surname'  -Value $Object.Names[-1]
            $Object | Add-Member -MemberType NoteProperty -Name 'Initial'  -Value $Object.Forename.Substring(0,1)
            $Object | Add-Member -MemberType NoteProperty -Name 'UNGuess'  -Value $($Object.Surname + $Object.Initial)
            $Object | Add-Member -MemberType NoteProperty -Name 'Filter'   -Value "(SamAccountName -eq '$($Object.UNGuess)' -and Surname -eq '$($Object.Surname)' -and GivenName -eq '$($Object.Forename)')"
            $UsersObject.Add($Object) | Out-Null
        }

        # Build AD Filter
        $Filter = ($UsersObject | ForEach-Object { $_.Filter }) -join ' -or '
        # Get AD Users matching Names
        $Matched   = Get-ADUser -Filter $Filter
        # Get unmatched Names
        $UnMatched = ($UsersObject | Where-Object -FilterScript { ($Matched | Select-Object -ExpandProperty 'SamAccountName') -notcontains $_.UnGuess }).FullName

        #Output
        If ($UnMatched) { $UnMatched | ForEach-Object { Write-Warning -Message "Not Matched : $_" } }
        Write-Output $Matched
    }

}