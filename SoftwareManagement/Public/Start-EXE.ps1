Function Start-EXE {
    <#
    .SYNOPSIS
        Execute a process with optional arguments
    .DESCRIPTION
        Executes a process with optional arguments
    .PARAMETER Path
        Full path to the file to be executed
    .PARAMETER Parameters
        Arguments to be passed to the executable
    .PARAMETER IgnoreExitCodes
        List of exit codes to ignore
    .PARAMETER PassThru
        Returns ExitCode, STDOut, and STDErr output from the process
    .PARAMETER ContinueOnError
        Continue if an exit code is returned by msiexec that is not recognized. Default is: $false
    .EXAMPLE
        Start-EXE -Path 'C:\Path\To\File\7z1604-x64.exe' -Parameters "/S"
    .EXAMPLE
        Start-EXE -Path 'C:\Path\To\File\7z1604-x64.exe' -Parameters "/S" -IgnoreExitCodes '1,2'
    .EXAMPLE
        Start-EXE -Path 'C:\Path\To\File\setup.exe' -Parameters "/s /v`"ALLUSERS=1 /qn /L* \`"$LogDir\$LogName.log`"`""
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [string]$Path,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [string[]]$Parameters,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [string]$IgnoreExitCodes,
        [Parameter(Mandatory=$false)]
        [switch]$PassThru = $false,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [boolean]$ContinueOnError = $false
    )

    Begin {
        # Verbose Logging
        [string]$CmdletName  = $MyInvocation.MyCommand.Name
        [string]$CmdletParam = $PSBoundParameters | Format-Table -Property @{ Label = 'Parameter'; Expression = { "[-$($_.Key)]" } }, @{ Label = 'Value'; Expression = { $_.Value }; Alignment = 'Left' } -AutoSize -Wrap | Out-String
        Write-Verbose -Message "##### Calling : [$CmdletName]"

        # Set Time to wait for msiexec to finish
        [timespan]$MsiExecWaitTime = $(New-TimeSpan -Seconds 600)
    }
    Process {
        Try {
            $private:ReturnCode = $null

            # Validate and find the fully qualified path for the $Path variable
            If (([IO.Path]::IsPathRooted($Path)) -and ([IO.Path]::HasExtension($Path))) {
                If (-not (Test-Path -LiteralPath $Path -PathType 'Leaf' -ErrorAction 'Stop')) {
                    Throw "File [$Path] not found"
                }
                Write-Verbose -Message "[$Path] is a valid fully qualified path"
            }
            Else {
                # Add current location to PATH environmental variable
                [string]$CurrentFolder = (Get-Location -PSProvider 'FileSystem').Path
                [string]$envPATH       = $env:PATH
                $env:PATH              = $CurrentFolder + ';' + $env:PATH
                # Get the fully qualified path from and revert PATH environmental variable
                [string]$FullyQualifiedPath = Get-Command -Name $Path -CommandType 'Application' -TotalCount 1 -Syntax -ErrorAction 'Stop'
                $env:PATH = $envPATH
                If ($FullyQualifiedPath) {
                    Write-Verbose -Message "[$Path] successfully resolved to fully qualified path [$FullyQualifiedPath]"
                    $Path = $FullyQualifiedPath
                }
                Else {
                    Throw "[$Path] contains an invalid path or file name"
                }
            }

            # Set the working directory
            $WorkingDirectory = Split-Path -Path $Path -Parent -ErrorAction 'Stop'

            # If MSI install, check to see if the MSI installer service is available
            If ($Path -match 'msiexec') {
                [boolean]$MsiExecAvailable = Test-IsMutexAvailable -MutexName 'Global\_MSIExecute' -MutexWaitTimeInMilliseconds $MsiExecWaitTime.TotalMilliseconds
                Start-Sleep -Seconds 1
                If (-not $MsiExecAvailable) {
                    # Default MSI exit code for install already in progress
                    [int32]$returnCode = 1618
                    Throw 'Please complete in progress MSI installation before proceeding with this install'
                }
            }

            Try {
                # Disable Zone checking to prevent warnings when running executables
                $env:SEE_MASK_NOZONECHECKS = 1

                # Allow capture of exceptions from .NET methods
                $private:previousErrorActionPreference = $ErrorActionPreference
                $ErrorActionPreference = 'Stop'

                # Define process
                $ProcessStartInfo = New-Object -TypeName 'System.Diagnostics.ProcessStartInfo' -ErrorAction 'Stop'
                $ProcessStartInfo.FileName = $Path
                $ProcessStartInfo.WorkingDirectory = $WorkingDirectory
                $ProcessStartInfo.UseShellExecute = $false
                $ProcessStartInfo.ErrorDialog = $false
                $ProcessStartInfo.RedirectStandardOutput = $true
                $ProcessStartInfo.RedirectStandardError = $true
                $ProcessStartInfo.CreateNoWindow = $false
                $ProcessStartInfo.WindowStyle = 'Hidden'
                If ($Parameters)  { $ProcessStartInfo.Arguments = $Parameters }
                $Process = New-Object -TypeName 'System.Diagnostics.Process' -ErrorAction 'Stop'
                $Process.StartInfo = $ProcessStartInfo

                # Add event handler to capture process's standard output redirection
                [scriptblock]$ProcessEventHandler = { If (-not [string]::IsNullOrEmpty($EventArgs.Data)) { $Event.MessageData.AppendLine($EventArgs.Data) } }
                $stdOutBuilder = New-Object -TypeName 'System.Text.StringBuilder' -ArgumentList ''
                $stdOutEvent   = Register-ObjectEvent -InputObject $Process -Action $ProcessEventHandler -EventName 'OutputDataReceived' -MessageData $stdOutBuilder -ErrorAction 'Stop'

                # Log Initialisation
                Write-Verbose -Message "Working Directory : $WorkingDirectory"
                If ($Parameters) {
                    If ($Parameters -match '-Command \&') {
                        Write-Verbose -Message "Executing : $Path [PowerShell ScriptBlock]"
                    }
                    Else {
                        Write-Verbose -Message "Executing : $Path $Parameters"
                    }
                }
                Else {
                    Write-Verbose -Message "Executing : $Path"
                }
                # Start Process
                [boolean]$ProcessStarted = $Process.Start()
                $Process.BeginOutputReadLine()
                $stdErr = $($Process.StandardError.ReadToEnd()).ToString() -replace $null,''

                # Wait for the process to exit
                $Process.WaitForExit()
                While (-not ($Process.HasExited)) {
                    $Process.Refresh(); Start-Sleep -Seconds 1
                }

                # Get the exit code for the process
                Try {
                    [int32]$ReturnCode = $Process.ExitCode
                }
                Catch [System.Management.Automation.PSInvalidCastException] {
                    # Catch exit codes that are out of int32 range
                    [int32]$ReturnCode = 60013
                }

                # Unregister standard output event and retrieve process output
                If ($stdOutEvent) {
                    Unregister-Event -SourceIdentifier $stdOutEvent.Name -ErrorAction 'Stop'; $stdOutEvent = $null
                }
                $stdOut = $stdOutBuilder.ToString() -replace $null,''

                If ($stdErr.Length -gt 0) {
                    Write-Warning -Message "Error : $stdErr"
                }
            }
            Finally {
                ## Make sure the standard output event is unregistered
                If ($stdOutEvent) { Unregister-Event -SourceIdentifier $stdOutEvent.Name -ErrorAction 'Stop'}

                ## Free resources associated with the process
                If ($Process) { $Process.Close() }

                ## Enable Zone checking
                Remove-Item -LiteralPath 'env:SEE_MASK_NOZONECHECKS' -ErrorAction 'SilentlyContinue'

                If ($private:PreviousErrorActionPreference) {
                    $ErrorActionPreference = $private:PreviousErrorActionPreference
                }
            }

            # Check to see if exit codes should be ignored
            $ignoreExitCodeMatch = $false
            If ($ignoreExitCodes) {
                # Split the processes on a comma
                [int32[]]$ignoreExitCodesArray = $ignoreExitCodes -split ','
                ForEach ($ignoreCode in $ignoreExitCodesArray) {
                    If ($returnCode -eq $ignoreCode) { $ignoreExitCodeMatch = $true }
                }
            }
            If ($ContinueOnError) {
                $ignoreExitCodeMatch = $true
            }

            If ($PassThru) {
                Write-Verbose -Message "Execution completed with exit code [$returnCode]"
                [psobject]$ExecutionResults = New-Object -TypeName 'PSObject' -Property @{ ExitCode = $ReturnCode; StdOut = $stdOut; StdErr = $stdErr }
                Write-Output -InputObject $ExecutionResults
            }
            ElseIf ($ignoreExitCodeMatch) {
                Write-Verbose -Message "Execution complete and the exit code [$returncode] is being ignored"
            }
            ElseIf (($ReturnCode -eq 3010) -or ($ReturnCode -eq 1641)) {
                Write-Verbose -Message "Execution : Completed successfully with exit code [$ReturnCode]. A reboot is required"
                Set-Variable -Name 'msiRebootDetected' -Value $true -Scope 'Script'
            }
            ElseIf (($ReturnCode -eq 1605) -and ($Path -match 'msiexec')) {
                Write-Warning -Message "Execution : Failed with exit code [$ReturnCode] because the product is not currently installed"
            }
            ElseIf (($ReturnCode -eq -2145124329) -and ($Path -match 'wusa')) {
                Write-Warning -Message "Execution : Failed with exit code [$ReturnCode] because the Windows Update is not applicable to this system"
            }
            ElseIf (($ReturnCode -eq 17025) -and ($Path -match 'fullfile')) {
                Write-Warning -Message "Execution : Failed with exit code [$ReturnCode] because the Office Update is not applicable to this system"
            }
            ElseIf ($ReturnCode -eq 0) {
                Write-Verbose -Message "Execution : Completed successfully with exit code [$ReturnCode]"
            }
            Else {
                Write-Warning -Message "Execution : Failed with exit code [$ReturnCode]"
            }
        }
        Catch {
            Write-Warning -Message "Execution : Completed with exit code [$ReturnCode] - Function failed"
            If ($PassThru) {
                [psobject]$ExecutionResults = New-Object -TypeName 'PSObject' -Property @{ ExitCode = $returnCode; StdOut = If ($stdOut) { $stdOut } Else { '' }; StdErr = If ($stdErr) { $stdErr } Else { '' } }
                Write-Output -InputObject $ExecutionResults
            }
        }
    }
    End {
        # Verbose Logging
        Write-Verbose -Message "##### Ending : [$CmdletName]"
    }
}