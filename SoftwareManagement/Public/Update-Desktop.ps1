Function Update-Desktop {
    <#
    .SYNOPSIS
        Refresh the Windows Explorer Shell
    .DESCRIPTION
        Refresh the Windows Explorer Shell, causing the desktop icons and the environment variables to be reloaded
    .EXAMPLE
        Update-Desktop
    #>

    [CmdletBinding()]
    Param ()

    Begin {
        # Verbose Logging
        [string]$CmdletName  = $MyInvocation.MyCommand.Name
        [string]$CmdletParam = $PSBoundParameters | Format-Table -Property @{ Label = 'Parameter'; Expression = { "[-$($_.Key)]" } }, @{ Label = 'Value'; Expression = { $_.Value }; Alignment = 'Left' } -AutoSize -Wrap | Out-String
        Write-Verbose -Message "##### Calling : [$CmdletName]"
    }
    Process {
        Try {
            Write-Verbose -Message 'Refresh the Desktop and the Windows Explorer environment process block'
            [PSSM.Explorer]::RefreshDesktopAndEnvironmentVariables()
        }
        Catch {
            Write-Warning -Message 'Failed to refresh the Desktop and the Windows Explorer environment process block'
        }
    }
    End {
        # Verbose Logging
        Write-Verbose -Message "##### Ending : [$CmdletName]"
    }
}