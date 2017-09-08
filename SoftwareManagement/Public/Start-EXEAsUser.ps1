Function Start-EXEAsUser {
    <#
    .SYNOPSIS
        Execute a process with a logged in user account, by using a scheduled task, to provide interaction with user in the SYSTEM context
    .DESCRIPTION
        Execute a process with a logged in user account, by using a scheduled task, to provide interaction with user in the SYSTEM context
    .PARAMETER UserName
        Logged in Username under which to run the process from. Default is: The active console user
    .PARAMETER Path
        Path to the file being executed
    .PARAMETER Parameters
        Arguments to be passed to the file being executed
    .PARAMETER RunLevel
        Specifies the level of user rights that Task Scheduler uses to run the task. The acceptable values for this parameter are:
        - HighestAvailable: Tasks run by using the highest available privileges (Admin privileges for Administrators). Default Value
        - LeastPrivilege: Tasks run by using the least-privileged user account (LUA) privileges
    .PARAMETER Wait
        Wait for the process, launched by the scheduled task, to complete execution before accepting more input. Default is $false
    .PARAMETER PassThru
        Returns ExitCode, STDOut, and STDErr output from the process
    .PARAMETER ContinueOnError
        Continue if an exit code is returned by msiexec that is not recognized. Default is: $true
    .EXAMPLE
        Start-EXEAsUser -UserName 'DOMAIN\User' -Path "$PSHOME\powershell.exe" -Parameters "-Command & { & `"C:\TestScript.ps1`"; Exit `$LastExitCode }" -Wait
        Execute process under a user account by specifying a username under which to execute it.
    .EXAMPLE
        Start-EXEAsUser -Path "$PSHOME\powershell.exe" -Parameters "-Command & { & `"C:\TestScript.ps1`"; Exit `$LastExitCode }" -Wait
        Execute process under a user account by using the default active logged in user that was detected when the function was launched
    .LINK
        Start-EXE
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [string]$UserName = (Get-LoggedOnUser | Select-Object -ExpandProperty NTAccount -First 1),
        [Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [string]$Path,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [string]$Parameters = '',
        [Parameter(Mandatory=$false)]
        [ValidateSet('HighestAvailable','LeastPrivilege')]
        [string]$RunLevel = 'HighestAvailable',
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [switch]$Wait = $false,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [switch]$PassThru = $false,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [boolean]$ContinueOnError = $true
    )

    Begin {
        # Verbose Logging
        [string]$CmdletName  = $MyInvocation.MyCommand.Name
        [string]$CmdletParam = $PSBoundParameters | Format-Table -Property @{ Label = 'Parameter'; Expression = { "[-$($_.Key)]" } }, @{ Label = 'Value'; Expression = { $_.Value }; Alignment = 'Left' } -AutoSize -Wrap | Out-String
        Write-Verbose -Message "##### Calling : [$CmdletName]"

        [string]$exeSchTasks = "$env:WinDir\System32\schtasks.exe"
    }
    Process {
        # Initialize exit code variable
        [int32]$executeProcessAsUserExitCode = 0

        # Confirm that the username field is not empty
        If (-not $UserName) {
            [int32]$executeProcessAsUserExitCode = 60009
            Write-Warning -Message "This function has a -UserName parameter that has an empty default value because no logged in users were detected"
            If (-not $ContinueOnError) {
                Throw "The function [$CmdletName] has a -UserName parameter that has an empty default value because no logged in users were detected"
            }
            Else {
                Return
            }
        }

        # Confirm if the function is running with administrator privileges
        If (($RunLevel -eq 'HighestAvailable') -and (-not [boolean](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match 'S-1-5-32-544'))) {
            [int32]$executeProcessAsUserExitCode = 60003
            Write-Warning -Message "This function requires Administrator privileges if the [-RunLevel] parameter is set to 'HighestAvailable'"
            If (-not $ContinueOnError) {
                Throw "The function [$CmdletName] requires Administrator privileges if the [-RunLevel] parameter is set to 'HighestAvailable'"
            }
            Else {
                Return
            }
        }

        ## Build the scheduled task XML name
        [string]$schTaskName = "SoftwarePSM-ExecuteAsUser"

        $tempDir = $(Get-UserProfiles | Where-Object -Property NTAccount -EQ $UserName | Select-Object -ExpandProperty ProfilePath) + "\AppData\Local\Temp"
        If (-not (Test-Path -LiteralPath $tempDir)) {
            Write-Warning -Message "Error finding User Profile [$UserName]"
            Return
        }

        ## If PowerShell.exe is being launched, then create a VBScript to launch PowerShell so that we can suppress the console window that flashes otherwise
        If ((Split-Path -Path $Path -Leaf) -eq 'PowerShell.exe') {
            [string]$executeProcessAsUserParametersVBS = 'chr(34) & ' + "`"$($Path)`"" + ' & chr(34) & ' + '" ' + ($Parameters -replace '"', "`" & chr(34) & `"" -replace ' & chr\(34\) & "$','') + '"'
            [string[]]$executeProcessAsUserScript = "strCommand = $executeProcessAsUserParametersVBS"
            $executeProcessAsUserScript += 'set oWShell = CreateObject("WScript.Shell")'
            $executeProcessAsUserScript += 'intReturn = oWShell.Run(strCommand, 0, true)'
            $executeProcessAsUserScript += 'WScript.Quit intReturn'
            $executeProcessAsUserScript | Out-File -FilePath "$tempDir\$($schTaskName).vbs" -Force -Encoding 'default' -ErrorAction 'SilentlyContinue'
            $Path = 'wscript.exe'
            $Parameters = "`"$tempDir\$($schTaskName).vbs`""
        }

        ## Specify the scheduled task configuration in XML format
        [string]$xmlSchTask = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo />
  <Triggers />
  <Settings>
  <MultipleInstancesPolicy>StopExisting</MultipleInstancesPolicy>
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
  <ExecutionTimeLimit>PT72H</ExecutionTimeLimit>
  <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
  <Exec>
    <Command>$Path</Command>
    <Arguments>$Parameters</Arguments>
  </Exec>
  </Actions>
  <Principals>
  <Principal id="Author">
    <UserId>$UserName</UserId>
    <LogonType>InteractiveToken</LogonType>
    <RunLevel>$RunLevel</RunLevel>
  </Principal>
  </Principals>
</Task>
"@
        ## Export the XML to file
        Try {
            # Specify the filename to export the XML to
            [string]$xmlSchTaskFilePath = "$tempDir\$schTaskName.xml"
            [string]$xmlSchTask | Out-File -FilePath $xmlSchTaskFilePath -Force -ErrorAction 'Stop'
        }
        Catch {
            [int32]$executeProcessAsUserExitCode = 60007
            Write-Warning -Message "Failed to export the scheduled task XML file [$xmlSchTaskFilePath]"
            If (-not $ContinueOnError) {
                Throw "Failed to export the scheduled task XML file [$xmlSchTaskFilePath]: $($_.Exception.Message)"
            }
            Else {
                Return
            }
        }

        ## Create Scheduled Task to run the process with a logged-on user account
        Write-Verbose -Message "Create scheduled task to run the process [$Path] with parameters [$Parameters] as the logged-on user [$UserName]"
        [psobject]$schTaskResult = Start-EXE -Path $exeSchTasks -Parameters "/create /f /tn $schTaskName /xml `"$xmlSchTaskFilePath`"" -PassThru
        If ($schTaskResult.ExitCode -ne 0) {
            [int32]$executeProcessAsUserExitCode = $schTaskResult.ExitCode
            Write-Warning -Message "Failed to create the scheduled task by importing the scheduled task XML file [$xmlSchTaskFilePath]"
            If (-not $ContinueOnError) {
                Throw "Failed to create the scheduled task by importing the scheduled task XML file [$xmlSchTaskFilePath]"
            }
            Else {
                Return
            }
        }

        ## Trigger the Scheduled Task
        Write-Verbose -Message "Trigger execution of scheduled task with command [$Path] using parameters [$Parameters] as the logged-on user [$UserName]"
        [psobject]$schTaskResult = Start-EXE -Path $exeSchTasks -Parameters "/run /i /tn $schTaskName" -PassThru
        If ($schTaskResult.ExitCode -ne 0) {
            [int32]$executeProcessAsUserExitCode = $schTaskResult.ExitCode
            Write-Warning -Message "Failed to trigger scheduled task [$schTaskName]"
            # Delete Scheduled Task
            Write-Verbose -Message 'Delete the scheduled task which did not trigger'
            $schTaskRemoval = Start-EXE -Path $exeSchTasks -Parameters "/delete /tn $schTaskName /f" -ContinueOnError $true
            If (-not $ContinueOnError) {
                Throw "Failed to trigger scheduled task [$schTaskName]."
            }
            Else {
                Return
            }
        }

        ## Wait for the process launched by the scheduled task to complete execution
        If ($Wait) {
            Write-Verbose -Message "Waiting for the process launched by the scheduled task [$schTaskName] to complete execution (this may take some time)"
            Start-Sleep -Seconds 1
            While ((($exeSchTasksResult = & $exeSchTasks /query /TN $schTaskName /V /FO CSV) | ConvertFrom-CSV | Select-Object -ExpandProperty 'Status' | Select-Object -First 1) -eq 'Running') {
                Start-Sleep -Seconds 5
            }
            # Get the exit code from the process launched by the scheduled task
            [int32]$executeProcessAsUserExitCode = ($exeSchTasksResult = & $exeSchTasks /query /TN $schTaskName /V /FO CSV) | ConvertFrom-CSV | Select-Object -ExpandProperty 'Last Result' | Select-Object -First 1
            Write-Verbose -Message "Exit code from process launched by scheduled task [$executeProcessAsUserExitCode]"
        }

        ## Delete scheduled task
        Try {
            Write-Verbose -Message "Delete scheduled task [$schTaskName]"
            $schTaskRemoval = Start-EXE -Path $exeSchTasks -Parameters "/delete /tn $schTaskName /f" -ErrorAction 'Stop' -PassThru
        }
        Catch {
            Write-Warning -Message "Failed to delete scheduled task [$schTaskName]"
        }
    }
    End {
        If ($PassThru) { Write-Output -InputObject $executeProcessAsUserExitCode }
        # Verbose Logging
        Write-Verbose -Message "##### Ending : [$CmdletName]"
    }
}