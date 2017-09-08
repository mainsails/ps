Function Get-MSIErrorCodeMessage {
    <#
    .SYNOPSIS
        Get message for MSI error code
    .DESCRIPTION
        Get message for MSI error code
    .PARAMETER MSIErrorCode
        MSI error code
    .EXAMPLE
        Get-MSIErrorCodeMessage -MSIErrorCode 1618

        Another program is being installed. Please wait until that installation is complete, and then try installing this software again.

        Retrieves the description string for MSI error code 1618
    #>

    [CmdletBinding()]
    Param (
    [Parameter(Mandatory=$true)]
    [ValidateNotNullorEmpty()]
    [int32]$MSIErrorCode
    )

    Begin {
        # Verbose Logging
        [string]$CmdletName  = $MyInvocation.MyCommand.Name
        [string]$CmdletParam = $PSBoundParameters | Format-Table -Property @{ Label = 'Parameter'; Expression = { "[-$($_.Key)]" } }, @{ Label = 'Value'; Expression = { $_.Value }; Alignment = 'Left' } -AutoSize -Wrap | Out-String
        Write-Verbose -Message "##### Calling : [$CmdletName]"
    }
    Process {
        Try {
            Write-Verbose -Message "Get message for exit code [$MSIErrorCode]"
            $MSIErrorCodeMessage = [PSSM.Msi]::GetMessageFromMsiExitCode($MSIErrorCode)
            Write-Output -InputObject $MSIErrorCodeMessage
        }
        Catch {
            Write-Warning -Message "Failed to get message for exit code [$MSIErrorCode]"
        }
    }
    End {
        # Verbose Logging
        Write-Verbose -Message "##### Ending : [$CmdletName]"
    }
}