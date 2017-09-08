Function Copy-File {
    <#
    .SYNOPSIS
        Copy a file or group of files to a destination path
    .DESCRIPTION
        Copy a file or group of files to a destination path
    .PARAMETER Path
        Path of the file to copy
    .PARAMETER Destination
        Destination Path of the file to copy
    .PARAMETER Recurse
        Copy files in subdirectories
    .PARAMETER ContinueOnError
        Continue if an error is encountered. Default is: $true
    .EXAMPLE
        Copy-File -Path 'C:\Path\To\File\File01.txt' -Destination 'C:\Path\To\File\File01-Copy.txt'
    .EXAMPLE
        Copy-File -Path 'C:\Path\To\File\File01.txt' -Destination 'C:\Path\To\Another\File\Test2'
    .EXAMPLE
        Copy-File -Path 'C:\Path\To\File\*' -Destination 'C:\Path\To\Another\File' -Recurse
        Copy all files and folders to a destination folder
    .LINK
        Remove-File
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [string]$Path,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [string]$Destination,
        [Parameter(Mandatory=$false)]
        [switch]$Recurse = $false,
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
            If ((-not ([IO.Path]::HasExtension($Destination))) -and (-not (Test-Path -LiteralPath $Destination -PathType 'Container'))) {
                Write-Verbose -Message "Creating destination folder [$Destination]"
                $null = New-Item -Path $Destination -Type 'Directory' -Force -ErrorAction 'Stop'
            }
            If (([IO.Path]::HasExtension($Destination)) -and (-not (Test-Path -LiteralPath (Split-Path -Parent $Destination)))) {
                Write-Verbose -Message "Creating destination folder [$(Split-Path -Parent $Destination)]"
                $null = New-Item -Path (Split-Path -Parent $Destination) -Type 'Directory' -Force -ErrorAction 'Stop'
            }
            If ($Recurse) {
                Write-Verbose -Message "Copy file(s) recursively from path [$Path] to destination [$Destination]"
                $null = Copy-Item -Path $Path -Destination $Destination -Force -Recurse -ErrorAction 'Stop'
            }
            Else {
                Write-Verbose -Message "Copy file from path [$Path] to destination [$Destination]"
                $null = Copy-Item -Path $Path -Destination $Destination -Force -ErrorAction 'Stop'
            }
        }
        Catch {
            Write-Warning -Message "Failed to copy file(s) from path [$Path] to destination [$Destination]"
            If (-not $ContinueOnError) {
                Throw "Failed to copy file(s) from path [$Path] to destination [$Destination]: $($_.Exception.Message)"
            }
        }
    }
    End {
        # Verbose Logging
        Write-Verbose -Message "##### Ending : [$CmdletName]"
    }
}