Function Get-LoggedOnUser {
    <#
    .SYNOPSIS
        Get session details for all local and RDP logged on users
    .DESCRIPTION
        Get session details for all local and RDP logged on users using Win32 APIs
    .EXAMPLE
        Get-LoggedOnUser
    .EXAMPLE
        Get-LoggedOnUser -ComputerName 'Computer1'
    .NOTES
        Description of the ConnectState property :
        Value         Description
        -----         -----------
        Active        A user is logged on to the session.
        ConnectQuery  The session is in the process of connecting to a client
        Connected	    A client is connected to the session
        Disconnected  The session is active, but the client has disconnected from it
        Down          The session is down due to an error
        Idle          The session is waiting for a client to connect
        Initializing  The session is initializing
        Listening     The session is listening for connections
        Reset         The session is being reset
        Shadowing     This session is shadowing another session

        Description of IsActiveUserSession property :
        If a console user exists, then that will be the active user session
        If no console user exists but users are logged in, then the first logged-in non-console user that is either 'Active' or 'Connected' is the active user

        Description of IsRdpSession property :
        Boolean value indicating whether the user is associated with an RDP client session
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false)]
        [string[]]$ComputerName = $env:ComputerName
    )

    Begin {
        # Verbose Logging
        [string]$CmdletName  = $MyInvocation.MyCommand.Name
        [string]$CmdletParam = $PSBoundParameters | Format-Table -Property @{ Label = 'Parameter'; Expression = { "[-$($_.Key)]" } }, @{ Label = 'Value'; Expression = { $_.Value }; Alignment = 'Left' } -AutoSize -Wrap | Out-String
        Write-Verbose -Message "##### Calling : [$CmdletName]"
    }
    Process {
        Try {
            Write-Verbose -Message "Get session information for all logged on users on [$ComputerName]"
            Write-Output -InputObject ([PSSM.QueryUser]::GetUserSessionInfo("$ComputerName"))
        }
        Catch {
            Write-Warning -Message "Failed to get session information for logged on users on [$ComputerName]"
        }
    }
    End {
        # Verbose Logging
        Write-Verbose -Message "##### Ending : [$CmdletName]"
    }
}