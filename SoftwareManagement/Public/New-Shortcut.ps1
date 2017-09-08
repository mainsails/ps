Function New-Shortcut {
    <#
    .SYNOPSIS
        Creates a new .lnk or .url shortcut
    .DESCRIPTION
        Creates a new .lnk or .url shortcut
    .PARAMETER Path
        Path to save the shortcut
    .PARAMETER TargetPath
        Target path or URL that the shortcut launches
    .PARAMETER Arguments
        Arguments to be passed
    .PARAMETER IconLocation
        Location of the icon used for the shortcut
    .PARAMETER IconIndex
        Executables, DLLs and ICO files with multiple icons need the index to be specified
    .PARAMETER Description
        Description of the shortcut (Comment)
    .PARAMETER WorkingDirectory
        Working Directory to be used for the shortcut
    .PARAMETER WindowStyle
        Window style of the application. Options: Normal, Maximized, Minimized. Default is: Normal
    .PARAMETER RunAsAdmin
        Set shortcut to run program as administrator. This option will prompt user to elevate when executing shortcut
    .PARAMETER ContinueOnError
        Continue if an exit code is returned by msiexec that is not recognized. Default is: $true
    .EXAMPLE
        New-Shortcut -Path 'C:\Path\To\File\TestProgram.lnk' -TargetPath "$env:windir\System32\notepad.exe" -IconLocation "$env:windir\system32\notepad.exe" -Description 'Notepad Shortcut'
    .EXAMPLE
        New-Shortcut -Path 'C:\Path\To\File\TestURL.url' -TargetPath "www.google.co.uk"
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [string]$Path,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [string]$TargetPath,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$Arguments,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [string]$IconLocation,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [string]$IconIndex,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$Description,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$WorkingDirectory,
        [Parameter(Mandatory=$false)]
        [ValidateSet('Normal','Maximized','Minimized')]
        [string]$WindowStyle,
        [Parameter(Mandatory=$false)]
        [switch]$RunAsAdmin,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [boolean]$ContinueOnError = $true
    )

    Begin {
        # Verbose Logging
        [string]$CmdletName  = $MyInvocation.MyCommand.Name
        [string]$CmdletParam = $PSBoundParameters | Format-Table -Property @{ Label = 'Parameter'; Expression = { "[-$($_.Key)]" } }, @{ Label = 'Value'; Expression = { $_.Value }; Alignment = 'Left' } -AutoSize -Wrap | Out-String
        Write-Verbose -Message "##### Calling : [$CmdletName]"

        If (-not $Shell) { [__comobject]$Shell = New-Object -ComObject 'WScript.Shell' -ErrorAction 'Stop' }
    }
    Process {
        Try {
            # Create path to shortcut
            Try {
                [IO.FileInfo]$Path = [IO.FileInfo]$Path
                [string]$PathDirectory = $Path.DirectoryName
                If (-not (Test-Path -LiteralPath $PathDirectory -PathType 'Container' -ErrorAction 'Stop')) {
                    Write-Verbose -Message "Create shortcut directory [$PathDirectory]"
                    $null = New-Item -Path $PathDirectory -ItemType 'Directory' -Force -ErrorAction 'Stop'
                }
            }
            Catch {
                Write-Warning -Message "Failed to create shortcut directory [$PathDirectory]"
                Throw
            }

            Write-Verbose -Message "Create shortcut [$($Path.FullName)]"
            # Create URL shortcut
            If (($Path.FullName).EndsWith('.url')) {
                [string[]]$URLFile = '[InternetShortcut]'
                $URLFile += "URL=$TargetPath"
                If ($IconIndex)    { $URLFile += "IconIndex=$IconIndex" }
                If ($IconLocation) { $URLFile += "IconFile=$IconLocation" }
                $URLFile | Out-File -FilePath $Path.FullName -Force -Encoding 'default' -ErrorAction 'Stop'
            }
            # Create LNK shortcut
            ElseIf (($Path.FullName).EndsWith('.lnk')) {
                If (($IconLocation -and $IconIndex) -and (-not ($IconLocation.Contains(',')))) {
                    $IconLocation = $IconLocation + ",$IconIndex"
                }
                Switch ($WindowStyle) {
                    'Normal'    { $WindowStyleInt = 1 }
                    'Maximized' { $WindowStyleInt = 3 }
                    'Minimized' { $WindowStyleInt = 7 }
                    Default     { $windowStyleInt = 1 }
                }
                $Shortcut = $Shell.CreateShortcut($Path.FullName)
                $Shortcut.TargetPath       = $TargetPath
                $Shortcut.Arguments        = $Arguments
                $Shortcut.Description      = $Description
                $Shortcut.WorkingDirectory = $WorkingDirectory
                $Shortcut.WindowStyle      = $WindowStyleInt
                If ($IconLocation) { $Shortcut.IconLocation = $IconLocation }
                $Shortcut.Save()

                # Set shortcut to run as administrator
                If ($RunAsAdmin) {
                    Write-Verbose -Message 'Set shortcut to run program as administrator'
                    $TempFileName = [IO.Path]::GetRandomFileName()
                    $TempFile     = [IO.FileInfo][IO.Path]::Combine($Path.Directory, $TempFileName)
                    $Writer       = New-Object -TypeName 'System.IO.FileStream' -ArgumentList ($TempFile, ([IO.FileMode]::Create)) -ErrorAction 'Stop'
                    $Reader       = $Path.OpenRead()
                    While ($Reader.Position -lt $Reader.Length) {
                        $Byte = $Reader.ReadByte()
                        If ($Reader.Position -eq 22) { $Byte = 34 }
                        $Writer.WriteByte($Byte)
                    }
                    $Reader.Close()
                    $Writer.Close()
                    $Path.Delete()
                    $null = Rename-Item -LiteralPath $TempFile -NewName $Path.Name -Force -ErrorAction 'Stop'
                }
            }
        }
        Catch {
            Write-Warning -Message "Failed to create shortcut [$($Path.FullName)]"
            If (-not $ContinueOnError) {
                Throw "Failed to create shortcut [$($Path.FullName)]: $($_.Exception.Message)"
            }
        }
    }
    End {
        # Verbose Logging
        Write-Verbose -Message "##### Ending : [$CmdletName]"
    }
}