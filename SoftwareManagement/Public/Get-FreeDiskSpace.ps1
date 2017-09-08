Function Get-FreeDiskSpace {
    <#
    .SYNOPSIS
        Retrieves the free disk space in MB on a particular drive (defaults to system drive)
    .DESCRIPTION
        Retrieves the free disk space in MB on a particular drive (defaults to system drive)
    .PARAMETER Drive
        Drive to check free disk space on
    .PARAMETER ContinueOnError
        Continue if an error is encountered. Default is: $true
    .EXAMPLE
        Get-FreeDiskSpace -Drive 'C:'
        223335

        Retrieves the remaining disk space on drive 'C:' in MB
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [string]$Drive = $env:SystemDrive,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [boolean]$ContinueOnError = $true
    )

    Begin {
        # Verbose Logging
        [string]$CmdletName  = $MyInvocation.MyCommand.Name
        [string]$CmdletParam = $PSBoundParameters | Format-Table -Property @{ Label = 'Parameter'; Expression = { "[-$($_.Key)]" } }, @{ Label = 'Value'; Expression = { $_.Value }; Alignment = 'Left' } -AutoSize -Wrap | Out-String
        Write-Verbose -Message "##### Calling : [$CmdletName]"
    }
    Process {
        Try {
            Write-Verbose -Message "Retrieve free disk space for drive [$Drive]"
            $Disk = Get-WmiObject -Class 'Win32_LogicalDisk' -Filter "DeviceID='$Drive'" -ErrorAction 'Stop'
            [double]$FreeDiskSpace = [math]::Round($Disk.FreeSpace / 1MB)

            Write-Verbose -Message "Free disk space for drive [$Drive]: [$FreeDiskSpace MB]"
            Write-Output -InputObject $FreeDiskSpace
        }
        Catch {
            Write-Warning -Message "Failed to retrieve free disk space for drive [$Drive]"
            If (-not $ContinueOnError) {
                Throw "Failed to retrieve free disk space for drive [$Drive]: $($_.Exception.Message)"
            }
        }
    }
    End {
        # Verbose Logging
        Write-Verbose -Message "##### Ending : [$CmdletName]"
    }
}