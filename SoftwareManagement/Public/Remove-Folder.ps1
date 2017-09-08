Function Remove-Folder {
    <#
    .SYNOPSIS
        Remove folder and files if they exist
    .DESCRIPTION
        Remove folder and all files recursively in a given path
    .PARAMETER Path
        Path to the folder to remove
    .PARAMETER ContinueOnError
        Continue if an error is encountered. Default is: $true
    .EXAMPLE
        Remove-Folder -Path 'C:\Path\To\Folder'
    .LINK
        New-Folder
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [string]$Path,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [boolean]$ContinueOnError = $true
    )

    Begin {
        # Verbose Logging
        [string]$CmdletName  = $MyInvocation.MyCommand.Name
        [string]$CmdletParam = $PSBoundParameters | Format-Table -Property @{ Label = 'Parameter'; Expression = { "[-$($_.Key)]" } }, @{ Label = 'Value'; Expression = { $_.Value }; Alignment = 'Left' } -AutoSize -Wrap | Out-String
        Write-Verbose -Message "##### Calling : [$CmdletName]"
    }
    Process {
        If (Test-Path -LiteralPath $Path -PathType 'Container') {
            Try {
                Remove-Item -LiteralPath $Path -Force -Recurse -ErrorAction 'Stop'
            }
            Catch {
                Write-Warning -Message "Failed to delete folder(s) and file(s) recursively from path [$Path]"
                If (-not $ContinueOnError) {
                    Throw "Failed to delete folder(s) and file(s) recursively from path [$Path]: $($_.Exception.Message)"
                }
            }
        }
        Else {
            Write-Verbose -Message "Folder [$Path] does not exist"
        }
    }
    End {
        # Verbose Logging
        Write-Verbose -Message "##### Ending : [$CmdletName]"
    }
}