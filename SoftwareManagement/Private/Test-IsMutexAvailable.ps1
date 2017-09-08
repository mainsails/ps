Function Test-IsMutexAvailable {
    <#
    .SYNOPSIS
        Wait, up to a timeout value, to check if current thread is able to acquire an exclusive lock on a system mutex
    .DESCRIPTION
        A mutex can be used to serialize applications and prevent multiple instances from being opened at the same time
        Wait, up to a timeout (default is 1 millisecond), for the mutex to become available for an exclusive lock
    .PARAMETER MutexName
        The name of the system mutex
    .PARAMETER MutexWaitTime
        The number of milliseconds the current thread should wait to acquire an exclusive lock of a named mutex. Default is: 1 millisecond
        A wait time of -1 milliseconds means to wait indefinitely. A wait time of zero does not acquire an exclusive lock but instead tests the state of the wait handle and returns immediately.
    .EXAMPLE
        Test-IsMutexAvailable -MutexName 'Global\_MSIExecute'
    .EXAMPLE
        Test-IsMutexAvailable -MutexName 'Global\_MSIExecute' -MutexWaitTimeInMilliseconds (New-TimeSpan -Seconds 60).TotalMilliseconds
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateLength(1,260)]
        [string]$MutexName,
        [Parameter(Mandatory=$false)]
        [ValidateScript({ ($_ -ge -1) -and ($_ -le [int32]::MaxValue) })]
        [int32]$MutexWaitTimeInMilliseconds = 1
    )

    Begin {
        # Verbose Logging
        [string]$CmdletName  = $MyInvocation.MyCommand.Name
        [string]$CmdletParam = $PSBoundParameters | Format-Table -Property @{ Label = 'Parameter'; Expression = { "[-$($_.Key)]" } }, @{ Label = 'Value'; Expression = { $_.Value }; Alignment = 'Left' } -AutoSize -Wrap | Out-String
        Write-Verbose -Message "##### Calling : [$CmdletName]"

        # Initialise Variables
        [timespan]$MutexWaitTime = [timespan]::FromMilliseconds($MutexWaitTimeInMilliseconds)
        If ($MutexWaitTime.TotalMinutes -ge 1) {
            [string]$WaitLogMsg = "$($MutexWaitTime.TotalMinutes) minute(s)"
        }
        ElseIf ($MutexWaitTime.TotalSeconds -ge 1) {
            [string]$WaitLogMsg = "$($MutexWaitTime.TotalSeconds) second(s)"
        }
        Else {
            [string]$WaitLogMsg = "$($MutexWaitTime.Milliseconds) millisecond(s)"
        }
        [boolean]$IsUnhandledException      = $false
        [boolean]$IsMutexFree               = $false
        [Threading.Mutex]$OpenExistingMutex = $null
    }
    Process {
        Write-Verbose -Message "Check to see if mutex [$MutexName] is available. Wait up to [$WaitLogMsg] for the mutex to become available."
        Try {
            # Allow capture of exceptions from .NET methods
            $private:PreviousErrorActionPreference = $ErrorActionPreference
            $ErrorActionPreference = 'Stop'

            # Open the specified named mutex, if it already exists, without acquiring an exclusive lock on it.
            [Threading.Mutex]$OpenExistingMutex = [Threading.Mutex]::OpenExisting($MutexName)
            # Attempt to acquire an exclusive lock on the mutex for specified timespan.
            $IsMutexFree = $OpenExistingMutex.WaitOne($MutexWaitTime, $false)
        }
        Catch [Threading.WaitHandleCannotBeOpenedException] {
            # The mutex does not exist
            $IsMutexFree = $true
        }
        Catch [ObjectDisposedException] {
            # Mutex was disposed between opening it and attempting to wait on it
            $IsMutexFree = $true
        }
        Catch [UnauthorizedAccessException] {
            # The named mutex exists, but the user does not have the security access required to use it
            $IsMutexFree = $false
        }
        Catch [Threading.AbandonedMutexException] {
            # The wait completed because a thread exited without releasing a mutex
            $IsMutexFree = $true
        }
        Catch {
            $IsUnhandledException = $true
            # Return $true, to signify that mutex is available, because function was unable to successfully complete a check due to an unhandled exception. Default is to err on the side of the mutex being available on a hard failure
            Write-Verbose -Message "Unable to check if mutex [$MutexName] is available due to an unhandled exception. Will default to return value of [$true]"
            $IsMutexFree = $true
        }
        Finally {
            If ($IsMutexFree) {
                If (-not $IsUnhandledException) {
                    Write-Verbose -Message "Mutex [$MutexName] is available for an exclusive lock."
                }
            }
            Else {
                If ($MutexName -eq 'Global\_MSIExecute') {
                    # Get the command line for the MSI installation in progress
                    Try {
                        [string]$msiInProgressCmdLine = Get-WmiObject -Class 'Win32_Process' -Filter "name = 'msiexec.exe'" -ErrorAction 'Stop' | Where-Object { $_.CommandLine } | Select-Object -ExpandProperty 'CommandLine' | Where-Object { $_ -match '\.msi' } | ForEach-Object { $_.Trim() }
                    }
                    Catch {}
                    Write-Verbose -Message "Mutex [$MutexName] is not available for an exclusive lock because the following MSI installation is in progress [$msiInProgressCmdLine]"
                }
                Else {
                    Write-Verbose -Message "Mutex [$MutexName] is not available because another thread already has an exclusive lock on it."
                }
            }
            If (($null -ne $OpenExistingMutex) -and ($IsMutexFree)) {
                # Release exclusive lock on the mutex
                $null = $OpenExistingMutex.ReleaseMutex()
                $OpenExistingMutex.Close()
            }
            If ($private:PreviousErrorActionPreference) { $ErrorActionPreference = $private:PreviousErrorActionPreference }
        }
    }
    End {
        Write-Output -InputObject $IsMutexFree

        # Verbose Logging
        Write-Verbose -Message "##### Ending : [$CmdletName]"
    }
}