Function Block-AppExecution {
    <#
    .SYNOPSIS
        Block the execution of an application(s)
    .DESCRIPTION
        Block the execution of an application(s) by :
        1. Checks for an existing scheduled task from a previous failed installation attempt where apps were blocked and if found, calls the Unblock-AppExecution function to restore the original IFEO registry keys
           This is to prevent the function from overriding the backup of the original IFEO options
        2. Creates a scheduled task to restore the IFEO registry key values in case the script is terminated uncleanly by calling a local temporary copy of the Unblock-AppExecution function
        3. Modifies the "Image File Execution Options" registry key for the specified process(s)
    .PARAMETER ProcessName
        Name of the process or processes separated by commas
    .EXAMPLE
        Block-AppExecution -ProcessName 'winword'
    .EXAMPLE
        Block-AppExecution -ProcessName 'excel','winword'
    .LINK
        Unblock-AppExecution
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [string[]]$ProcessName
    )

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

        # Create Temporary Script Folder
        $AppBlockScript = "$env:WinDir\Temp\SoftwarePSM\AppBlock"
        If (-not (Test-Path -LiteralPath $AppBlockScript -PathType 'Container')) {
            New-Item -Path $AppBlockScript -ItemType 'Directory' -Force -ErrorAction 'Stop' | Out-Null
        }
        # Write unblock script to machine
        $GetSchTaskScript = 'Function Get-ScheduledTasks' + '{' + (Get-Command -CommandType Function Get-ScheduledTasks).Definition + '}'
        $UnBlockScript    = 'Function Unblock-AppExecution' + '{' + (Get-Command -CommandType Function Unblock-AppExecution).Definition + '}' + 'Unblock-AppExecution'
        Out-File -InputObject $GetSchTaskScript,$UnBlockScript -FilePath "$AppBlockScript\Unblock-AppExecutionScript.ps1" -Force -Encoding 'default' -ErrorAction 'SilentlyContinue'

        [string]$schTaskUnblockAppsCommand += "-ExecutionPolicy Bypass -NoProfile -NoLogo -WindowStyle Hidden -File `"$AppBlockScript\Unblock-AppExecutionScript.ps1`""
        # Specify the scheduled task configuration in XML format
        [string]$xmlUnblockAppsSchTask = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo></RegistrationInfo>
  <Triggers>
    <BootTrigger>
      <Enabled>true</Enabled>
    </BootTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT1H</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>$schTaskUnblockAppsCommand</Arguments>
    </Exec>
  </Actions>
</Task>
"@
    }
    Process {
        [string]$schTaskBlockedAppsName = "SoftwarePSM-BlockedApps"

        # Set the debugger block value
        [string]$debuggerBlockValue = 'PSSM_BlockAppExecution'

        # Create a scheduled task to run on startup to call this script and clean up blocked applications in case the installation is interrupted, e.g. user shuts down during installation"
        Write-Verbose -Message 'Create scheduled task to cleanup blocked applications in case installation is interrupted'
        If (& $GetSchTaskFunc | Select-Object -Property 'TaskName' | Where-Object { $_.TaskName -eq "$schTaskBlockedAppsName" }) {
            Write-Verbose -Message "Scheduled task [$schTaskBlockedAppsName] already exists"
        }
        Else {
            # Export the scheduled task XML to file
            Try {
                # Specify the filename to export the XML to
                [string]$xmlSchTaskFilePath = "$AppBlockScript\SchTaskUnBlockApps.xml"
                [string]$xmlUnblockAppsSchTask | Out-File -FilePath $xmlSchTaskFilePath -Force -ErrorAction 'Stop'
            }
            Catch {
                Write-Warning -Message "Failed to export the scheduled task XML file [$xmlSchTaskFilePath]"
                Return
            }

            # Import the Scheduled Task XML file to create the Scheduled Task
            [psobject]$schTaskResult = Start-EXE -Path $exeSchTasks -Parameters "/create /f /tn $schTaskBlockedAppsName /xml `"$xmlSchTaskFilePath`"" -PassThru
            If ($schTaskResult.ExitCode -ne 0) {
                Write-Warning -Message "Failed to create the scheduled task [$schTaskBlockedAppsName] by importing the scheduled task XML file [$xmlSchTaskFilePath]"
                Return
            }
        }

        [string[]]$blockProcessName = $processName
        # Append .exe to match registry keys
        [string[]]$blockProcessName = $blockProcessName | ForEach-Object { $_ + '.exe' } -ErrorAction 'SilentlyContinue'

        # Enumerate each process and set the debugger value to block application execution
        ForEach ($blockProcess in $blockProcessName) {
            # Create/Set/Update Registry keys and values
            Write-Verbose -Message "Set the Image File Execution Option registry key to block execution of [$blockProcess]"
            Set-RegistryKey -Key (Join-Path -Path $regKeyAppExecution -ChildPath $blockProcess) -Name 'Debugger' -Value $debuggerBlockValue
        }
    }
    End {
        # Verbose Logging
        Write-Verbose -Message "##### Ending : [$CmdletName]"
    }
}