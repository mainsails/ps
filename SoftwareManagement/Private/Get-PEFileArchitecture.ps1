Function Get-PEFileArchitecture {
    <#
    .SYNOPSIS
        Determine if a Portable Executable (PE) file is a 32-bit or a 64-bit file
    .DESCRIPTION
        Determine if a Portable Executable (PE) file is a 32-bit or a 64-bit file by examining the file's image file header
        PE file extensions: '.acm', '.ax', '.cpl', '.dll', '.exe', '.drv', '.efi', '.fon', '.mui', '.ocx', '.scr', '.sys', '.tsp'
    .PARAMETER Path
        Path to the PE file to examine
    .PARAMETER ContinueOnError
        Continue if an error is encountered. Default is: $true
    .PARAMETER PassThru
        Get the file object, attach a property indicating the file binary type, and write to pipeline
    .EXAMPLE
        Get-PEFileArchitecture -Path "$env:windir\notepad.exe"
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [ValidateScript({ Test-Path -LiteralPath $_ -PathType 'Leaf' })]
        [IO.FileInfo[]]$Path,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [boolean]$ContinueOnError = $true,
        [Parameter(Mandatory=$false)]
        [switch]$PassThru
    )

    Begin {
        # Verbose Logging
        [string]$CmdletName  = $MyInvocation.MyCommand.Name
        [string]$CmdletParam = $PSBoundParameters | Format-Table -Property @{ Label = 'Parameter'; Expression = { "[-$($_.Key)]" } }, @{ Label = 'Value'; Expression = { $_.Value }; Alignment = 'Left' } -AutoSize -Wrap | Out-String
        Write-Verbose -Message "##### Calling : [$CmdletName]"

        [string[]]$PEFileExtensions = '.acm','.ax','.cpl','.dll','.exe','.drv','.efi','.fon','.mui','.ocx','.scr','.sys','.tsp'
        [int32]$MACHINE_OFFSET      = 4
        [int32]$PE_POINTER_OFFSET   = 60
    }
    Process {
        ForEach ($File in $Path) {
            Try {
                If ($PEFileExtensions -notcontains $File.Extension) {
                    Throw "Invalid file type. Please specify one of the following PE file types: $($PEFileExtensions -join ', ')"
                }

                [byte[]]$Data = New-Object -TypeName 'System.Byte[]' -ArgumentList 4096
                $Stream = New-Object -TypeName 'System.IO.FileStream' -ArgumentList ($File.FullName, 'Open', 'Read')
                $null = $Stream.Read($Data, 0, 4096)
                $Stream.Flush()
                $Stream.Close()

                [int32]$PE_HEADER_ADDR        = [BitConverter]::ToInt32($Data, $PE_POINTER_OFFSET)
                [uint16]$PE_IMAGE_FILE_HEADER = [BitConverter]::ToUInt16($Data, $PE_HEADER_ADDR + $MACHINE_OFFSET)
                Switch ($PE_IMAGE_FILE_HEADER) {
                    0       { $PEArchitecture = 'Native' }      # The contents of this type are assumed to be applicable to any machine type
                    0x014c  { $PEArchitecture = '32bit' }       # I386 - Intel 386 or later processors and compatible processors
                    0x0200  { $PEArchitecture = 'Itanium-x64' } # IA64 - Intel Itanium processor family
                    0x8664  { $PEArchitecture = '64bit' }       # AMD64 - x64
                    Default { $PEArchitecture = 'Unknown' }
                }
                Write-Verbose -Message "File [$($File.FullName)] has a detected file architecture of [$PEArchitecture]"

                If ($PassThru) {
                    # Get the file object, attach a property indicating the type and write to pipeline
                    Get-Item -LiteralPath $File.FullName -Force | Add-Member -MemberType 'NoteProperty' -Name 'BinaryType' -Value $PEArchitecture -Force -PassThru | Write-Output
                }
                Else {
                    Write-Output -InputObject $PEArchitecture
                }
            }
            Catch {
                Write-Warning -Message 'Failed to get the PE file architecture'
                If (-not $ContinueOnError) {
                    Throw "Failed to get the PE file architecture: $($_.Exception.Message)"
                }
            }
        }
    }
    End {
        # Verbose Logging
        Write-Verbose -Message "##### Ending : [$CmdletName]"
    }
}