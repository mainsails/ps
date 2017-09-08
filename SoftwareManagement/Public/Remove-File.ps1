Function Remove-File {
    <#
    .SYNOPSIS
        Removes one or more items from a given path on the filesystem
    .DESCRIPTION
        Removes one or more items from a given path on the filesystem
    .PARAMETER Path
        Specifies the path on the filesystem to be resolved. The value of Path will accept wildcards. Will accept an array of values
    .PARAMETER LiteralPath
        Specifies the path on the filesystem to be resolved. The value of LiteralPath is used exactly as it is typed; no characters are interpreted as wildcards. Will accept an array of values
    .PARAMETER Recurse
        Deletes the files in the specified location(s) and in all child items of the location(s)
    .PARAMETER ContinueOnError
        Continue if an error is encountered. Default is: $true
    .EXAMPLE
        Remove-File -Path 'C:\Path\To\File\File01.txt'
    .EXAMPLE
        Remove-File -LiteralPath 'C:\Path\To\File' -Recurse
        Remove the folder and all contents
    .LINK
        Copy-File
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true,ParameterSetName='Path')]
        [ValidateNotNullorEmpty()]
        [string[]]$Path,
        [Parameter(Mandatory=$true,ParameterSetName='LiteralPath')]
        [ValidateNotNullorEmpty()]
        [string[]]$LiteralPath,
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
        # Build hashtable of parameters/value pairs to be passed to Remove-Item cmdlet
        [hashtable]$RemoveFileSplat =  @{ 'Recurse' = $Recurse
                                          'Force' = $true
                                          'ErrorVariable' = '+ErrorRemoveItem'
                                        }
        If ($ContinueOnError) {
            $RemoveFileSplat.Add('ErrorAction','SilentlyContinue')
        }
        Else {
            $RemoveFileSplat.Add('ErrorAction','Stop')
        }

        # Resolve the specified path, if the path does not exist, display a warning instead of an error
        If ($PSCmdlet.ParameterSetName -eq 'Path') {
            [string[]]$SpecifiedPath = $Path }
        Else {
            [string[]]$SpecifiedPath = $LiteralPath
        }
        ForEach ($Item in $SpecifiedPath) {
            Try {
                If ($PSCmdlet.ParameterSetName -eq 'Path') {
                    [string[]]$ResolvedPath += Resolve-Path -Path $Item -ErrorAction 'Stop' | Where-Object { $_.Path } | Select-Object -ExpandProperty 'Path' -ErrorAction 'Stop'
                }
                Else {
                    [string[]]$ResolvedPath += Resolve-Path -LiteralPath $Item -ErrorAction 'Stop' | Where-Object { $_.Path } | Select-Object -ExpandProperty 'Path' -ErrorAction 'Stop'
                }
            }
            Catch [System.Management.Automation.ItemNotFoundException] {
                Write-Warning -Message "Unable to resolve file(s) for deletion from path [$Item] because the path does not exist"
            }
            Catch {
                Write-Warning -Message "Failed to resolve file(s) for deletion from path [$Item]"
                If (-not $ContinueOnError) {
                    Throw "Failed to resolve file(s) for deletion from path [$Item]: $($_.Exception.Message)"
                }
            }
        }

        # Delete specified path if it was successfully resolved
        If ($ResolvedPath) {
            ForEach ($Item in $ResolvedPath) {
                Try {
                    If (($Recurse) -and (Test-Path -LiteralPath $Item -PathType 'Container')) {
                        Write-Verbose -Message "Delete file(s) recursively from path [$Item]"
                    }
                    Else {
                        Write-Verbose -Message "Delete file from path [$Item]"
                    }
                    $null = Remove-Item @RemoveFileSplat -LiteralPath $Item
                }
                Catch {
                    Write-Warning -Message "Failed to delete file(s) from path [$Item]"
                    If (-not $ContinueOnError) {
                        Throw "Failed to delete file(s) from path [$Item]: $($_.Exception.Message)"
                    }
                }
            }
        }
        If ($ErrorRemoveItem) {
            $ErrorRemoveItem | Write-Warning
        }
    }
    End {
        # Verbose Logging
        Write-Verbose -Message "##### Ending : [$CmdletName]"
    }
}