Function New-Folder {
    <#
    .SYNOPSIS
        Create a new folder
    .DESCRIPTION
        Create a new folder if it does not exist
    .PARAMETER Path
        Path to the new folder to create
    .PARAMETER ContinueOnError
        Continue if an error is encountered. Default is: $true
    .EXAMPLE
        New-Folder -Path 'C:\Path\To\Folder'
    .LINK
        Remove-Folder
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
        Try {
            If (-not (Test-Path -LiteralPath $Path -PathType 'Container')) {
                Write-Verbose -Message "Create folder [$Path]"
                $null = New-Item -Path $Path -ItemType 'Directory' -ErrorAction 'Stop'
            }
            Else {
                Write-Verbose -Message "Folder [$Path] already exists"
            }
        }
        Catch {
            Write-Warning -Message "Failed to create folder [$Path]"
            If (-not $ContinueOnError) {
                Throw "Failed to create folder [$Path]: $($_.Exception.Message)"
            }
        }
    }
    End {
        # Verbose Logging
        Write-Verbose -Message "##### Ending : [$CmdletName]"
    }
}