Function Update-GroupPolicy {
    <#
    .SYNOPSIS
        Performs a gpupdate command to refresh Group Policies on the local machine
    .DESCRIPTION
        Performs a gpupdate command to refresh Group Policies on the local machine
    .EXAMPLE
        Update-GroupPolicy
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
        [string[]]$GPUpdateCmds = '/C echo N | gpupdate.exe /Target:Computer /Force', '/C echo N | gpupdate.exe /Target:User /Force'
        [int32]$InstallCount = 0
        ForEach ($GPUpdateCmd in $GPUpdateCmds) {
            Try {
                If ($InstallCount -eq 0) {
                    [string]$InstallMsg = 'Update Group Policies for the Machine'
                    Write-Verbose -Message "$($InstallMsg)..."
                }
                Else {
                    [string]$InstallMsg = 'Update Group Policies for the User'
                    Write-Verbose -Message "$($InstallMsg)..."
                }
                [psobject]$ExecuteResult = Start-EXE -Path "$env:windir\system32\cmd.exe" -Parameters $GPUpdateCmd -PassThru

                If ($ExecuteResult.ExitCode -ne 0) {
                    If ($ExecuteResult.ExitCode -eq 60002) {
                        Throw "Start-EXE function failed with exit code [$($ExecuteResult.ExitCode)]"
                    }
                    Else {
                        Throw "gpupdate.exe failed with exit code [$($ExecuteResult.ExitCode)]"
                    }
                }
                $InstallCount++
            }
            Catch {
                Write-Warning -Message "Failed to $($InstallMsg)"
                Continue
            }
        }
    }
    End {
        # Verbose Logging
        Write-Verbose -Message "##### Ending : [$CmdletName]"
    }
}