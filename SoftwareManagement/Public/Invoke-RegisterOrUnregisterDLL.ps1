Function Invoke-RegisterOrUnregisterDLL {
    <#
    .SYNOPSIS
        Register or unregister a DLL file
    .DESCRIPTION
        Register or unregister a DLL file using regsvr32.exe. Function can be invoked using alias: 'Register-DLL' or 'Unregister-DLL'
    .PARAMETER Path
        Path to the DLL file
    .PARAMETER Action
        Specify whether to Register or Unregister the DLL
    .PARAMETER ContinueOnError
        Continue if an error is encountered. Default is: $true
    .EXAMPLE
        Invoke-RegisterOrUnregisterDLL -Path 'C:\Path\To\File\My.dll' -Action 'Register'
        Register DLL file
    .EXAMPLE
        Invoke-RegisterOrUnregisterDLL -Path 'C:\Path\To\File\My.dll' -Action 'Unregister'
        Unregister DLL file
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [string]$Path,
        [Parameter(Mandatory=$true)]
        [ValidateSet('Register','Unregister')]
        [string]$Action,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [boolean]$ContinueOnError = $true
    )

    Begin {
        # Verbose Logging
        [string]$CmdletName  = $MyInvocation.MyCommand.Name
        [string]$CmdletParam = $PSBoundParameters | Format-Table -Property @{ Label = 'Parameter'; Expression = { "[-$($_.Key)]" } }, @{ Label = 'Value'; Expression = { $_.Value }; Alignment = 'Left' } -AutoSize -Wrap | Out-String
        Write-Verbose -Message "##### Calling : [$CmdletName]"

        # Set the DLL register/unregister action parameters
        [string]$Action = ((Get-Culture).TextInfo).ToTitleCase($Action.ToLower())
        Switch ($Action) {
            'Register'   { [string]$ActionParameters = "/s `"$Path`"" }
            'Unregister' { [string]$ActionParameters = "/s /u `"$Path`"" }
        }

        # Get OS Architecture
        [boolean]$Is64Bit = [boolean]((Get-WmiObject -Class 'Win32_Processor' -ErrorAction 'SilentlyContinue' | Where-Object { $_.DeviceID -eq 'CPU0' } | Select-Object -ExpandProperty 'AddressWidth') -eq 64)

        # Get Process architecture
        [boolean]$Is64BitProcess = [boolean]([IntPtr]::Size -eq 8)
    }
    Process {
        Try {
            Write-Verbose -Message "$Action DLL file [$Path]"
            If (-not (Test-Path -LiteralPath $Path -PathType 'Leaf')) {
                Throw "File [$Path] could not be found"
            }

            [string]$DLLFileArchitecture = Get-PEFileArchitecture -Path $Path -ContinueOnError $false -ErrorAction 'Stop'
            If (($DLLFileArchitecture -ne '64bit') -and ($DLLFileArchitecture -ne '32bit')) {
                Throw "File [$Path] has a detected file architecture of [$DLLFileArchitecture]. Only 32-bit or 64-bit DLL files can be $($Action.ToLower() + 'ed')"
            }

            If ($Is64Bit) {
                If ($DLLFileArchitecture -eq '64bit') {
                    If ($Is64BitProcess) {
                        [string]$RegSvr32Path = "$env:windir\System32\regsvr32.exe"
                    }
                    Else {
                        [string]$RegSvr32Path = "$env:windir\sysnative\regsvr32.exe"
                    }
                }
                ElseIf ($DLLFileArchitecture -eq '32bit') {
                    [string]$RegSvr32Path = "$env:windir\SysWOW64\regsvr32.exe"
                }
            }
            Else {
                If ($DLLFileArchitecture -eq '64bit') {
                    Throw "File [$Path] cannot be $($Action.ToLower()) because it is a 64-bit file on a 32-bit operating system"
                }
                ElseIf ($DLLFileArchitecture -eq '32bit') {
                    [string]$RegSvr32Path = "$env:windir\system32\regsvr32.exe"
                }
            }

            [psobject]$ExecuteResult = Start-EXE -Path $RegSvr32Path -Parameters $ActionParameters -PassThru

            If ($ExecuteResult.ExitCode -ne 0) {
                If ($ExecuteResult.ExitCode -eq 60002) {
                    Throw "Start-EXE function failed with exit code [$($ExecuteResult.ExitCode)]"
                }
                Else {
                    Throw "regsvr32.exe failed with exit code [$($ExecuteResult.ExitCode)]"
                }
            }
        }
        Catch {
            Write-Warning -Message "Failed to $($Action.ToLower()) DLL file"
            If (-not $ContinueOnError) {
                Throw "Failed to $($Action.ToLower()) DLL file: $($_.Exception.Message)"
            }
        }
    }
    End {
        # Verbose Logging
        Write-Verbose -Message "##### Ending : [$CmdletName]"
    }
}