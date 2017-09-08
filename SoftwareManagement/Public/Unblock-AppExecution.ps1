Function Unblock-AppExecution {
    <#
    .SYNOPSIS
        Unblocks the execution of applications performed by the Block-AppExecution function
    .DESCRIPTION
        Unblocks the execution of applications performed by the Block-AppExecution function
    .EXAMPLE
        Unblock-AppExecution
    .LINK
        Block-AppExecution
    #>

    [CmdletBinding()]
    Param ()

    Begin {
        # Verbose Logging
        [string]$CmdletName  = $MyInvocation.MyCommand.Name
        [string]$CmdletParam = $PSBoundParameters | Format-Table -Property @{ Label = 'Parameter'; Expression = { "[-$($_.Key)]" } }, @{ Label = 'Value'; Expression = { $_.Value }; Alignment = 'Left' } -AutoSize -Wrap | Out-String
        Write-Verbose -Message "##### Calling : [$CmdletName]"

        # Use built-in 'Get-ScheduledTask' function if available
        If (Get-Command -Name Get-ScheduledTask -CommandType Function -ErrorAction SilentlyContinue) {
            $GetSchTaskFunc = 'Get-ScheduledTask'
        }
        # Use 'Get-ScheduledTasks' function if not
        Else {
            $GetSchTaskFunc = 'Get-ScheduledTasks'
        }

        # IFEO Registry Location
        [string]$regKeyAppExecution = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
        # Task Scheduler Executable
        [string]$exeSchTasks = "$env:windir\System32\schtasks.exe"
    }
    Process {
        # Remove IEFO Debugger values to unblock processes
        [psobject[]]$unblockProcesses = $null
        [psobject[]]$unblockProcesses += (Get-ChildItem -LiteralPath $regKeyAppExecution -Recurse -ErrorAction 'SilentlyContinue' | ForEach-Object { Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction 'SilentlyContinue' })
        ForEach ($unblockProcess in ($unblockProcesses | Where-Object { $_.Debugger -like '*PSSM_BlockAppExecution*' })) {
            Write-Verbose -Message "Remove the Image File Execution Options registry key to unblock execution of [$($unblockProcess.PSChildName)]"
            $unblockProcess | Remove-ItemProperty -Name 'Debugger' -ErrorAction 'SilentlyContinue'
        }

        # Remove the scheduled task if it exists
        [string]$schTaskBlockedAppsName = "SoftwarePSM-BlockedApps"
        If (& $GetSchTaskFunc | Select-Object -Property 'TaskName' | Where-Object { $_.TaskName -eq "$schTaskBlockedAppsName" }) {
            Write-Verbose -Message "Delete Scheduled Task [$schTaskBlockedAppsName]"
            Start-Process -FilePath $exeSchTasks -ArgumentList "/Delete /TN $schTaskBlockedAppsName /F" -NoNewWindow -Wait
        }
    }
    End {
        # Verbose Logging
        Write-Verbose -Message "##### Ending : [$CmdletName]"
    }
}