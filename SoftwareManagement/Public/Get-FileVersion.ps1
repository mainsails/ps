Function Get-FileVersion {
    <#
    .SYNOPSIS
        Gets the version of the specified file
    .DESCRIPTION
        Gets the version of the specified file
    .PARAMETER File
        Path of the file
    .EXAMPLE
        Get-FileVersion -File 'C:\Path\To\File\7z1604-x64.exe'
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [string]$File
    )

    Begin {
        # Verbose Logging
        [string]$CmdletName  = $MyInvocation.MyCommand.Name
        [string]$CmdletParam = $PSBoundParameters | Format-Table -Property @{ Label = 'Parameter'; Expression = { "[-$($_.Key)]" } }, @{ Label = 'Value'; Expression = { $_.Value }; Alignment = 'Left' } -AutoSize -Wrap | Out-String
        Write-Verbose -Message "##### Calling : [$CmdletName]"
    }
    Process {
        Try {
            Write-Verbose -Message "Get file version information for file [$File]"
            If (Test-Path -LiteralPath $File -PathType 'Leaf') {
                # Get file version
                $FileVersion = (Get-Command -Name $File -ErrorAction 'Stop').FileVersionInfo.FileVersion
                If ($FileVersion) {
                    # Remove product information
                    $FileVersion = ($FileVersion -split ' ' | Select-Object -First 1)
                    Write-Verbose -Message "File version is [$FileVersion]"
                    Write-Output -InputObject $FileVersion
                }
                Else {
                    Write-Verbose -Message 'No file version information found'
                }
            }
        }
        Catch {
            Write-Warning -Message 'Failed to get file version info'
        }
    }
    End {
        # Verbose Logging
        Write-Verbose -Message "##### Ending : [$CmdletName]"
    }
}