Function Write-CMTraceLog {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [int]$ProcessID = $PID,
        [Parameter()]
        [ValidateSet(1, 2, 3)]
        [int]$LogLevel = 1
    )
    $TimeGenerated = "$(Get-Date -Format HH:mm:ss).$((Get-Date).Millisecond)+000"
    $Line          = '<![LOG[{0}]LOG]!><time="{1}" date="{2}" component="{3}" context="" type="{4}" thread="{5}" file="">'
    $LineFormat    = $Message, $TimeGenerated, (Get-Date -Format MM-dd-yyyy), "$($MyInvocation.ScriptName | Split-Path -Leaf):$($MyInvocation.ScriptLineNumber)", $LogLevel, $ProcessID
    $Line          = $Line -f $LineFormat
    Add-Content -Value $Line -Path $Log
}

# Script Start
$TSEnv   = New-Object -COMObject Microsoft.SMS.TSEnvironment
$LogPath = $TSEnv.Value('LOGPATH')
$Log     = "$LogPath\$(([io.fileinfo]$MyInvocation.MyCommand.Definition).BaseName).log"

Write-CMTraceLog "BIOS Update Scan Starting"

$BIOSPassword  = 'm8E1StR0m'

$BIOSStructure = Split-Path $MyInvocation.MyCommand.Path -Parent
$SystemInfo    = Get-WmiObject -Class Win32_ComputerSystem
$BIOSInfo      = Get-WmiObject -Class Win32_BIOS
$Manufacturer  = $SystemInfo.Manufacturer
$Model         = $SystemInfo.Model
$BIOSvCurrent  = $BIOSInfo.SMBIOSBIOSVersion
$BIOSSource    = Get-ChildItem -Path $BIOSStructure -Include $Model -Recurse

Write-CMTraceLog "BIOS Update Folder Structure set to $BIOSStructure"
Write-CMTraceLog "WMI Lookup on Win32_ComputerSystem : $SystemInfo"
Write-CMTraceLog "WMI Lookup on Win32_BIOS : $BIOSInfo"
Write-CMTraceLog "Manufacturer Detected as $Manufacturer"
Write-CMTraceLog "Model Detected as $Model"
Write-CMTraceLog "Current BIOS Version Detected as $BIOSvCurrent"

If ($BIOSSource) {
    Write-CMTraceLog "BIOS Update Source set to $BIOSSource"
    Write-CMTraceLog "Scanning Update Source for BIOS versions"
    $BIOSvLatest = Get-ChildItem -Path $BIOSSource -Filter '*.ver' | Select -ExpandProperty BaseName
    Write-CMTraceLog "Archived BIOS Version Detected as : $BIOSvLatest"
    If ($BIOSvCurrent -ne $BIOSvLatest) {
        Write-CMTraceLog "Machine BIOS does not match Archived BIOS"
        Write-CMTraceLog "Updating BIOS from $BIOSvCurrent to $BIOSvLatest"
        Write-CMTraceLog "Scanning Update Source for BIOS executable"
        $UpdateExe = (Get-ChildItem -Path $BIOSSource -Filter *.exe).Name
        If ($UpdateExe.Count -ne 1) {
            Write-CMTraceLog "Multiple Executables found in $BIOSSource - Exiting" -LogLevel 3
            Break
        }
        Else {
            Write-CMTraceLog "BIOS Update Executable detected as : $UpdateExe"
        }
        Copy-Item -Path $BIOSSource -Destination $env:TEMP -Recurse -Force
        Set-Location -Path $env:TEMP\$Model
        Write-CMTraceLog "New BIOS copied from $BIOSSource to $env:TEMP\$Model)"
        Write-CMTraceLog "BIOS Executable Vendor detected as : $($BIOSSource.Parent.Name)"
        If ($BIOSSource.Parent.Name -eq 'Dell') {
            $UpdateArgs = "/s /f /p=$BIOSPassword"
        }
        ElseIf ($BIOSSource.Parent.Name -eq 'HP') {
            $UpdateArgs = 'TO DO'
        }
        Else {
            Write-CMTraceLog "No Executable Arguments for $($BIOSSource.Parent.Name) are defined -LogLevel 3"
        }
        Write-CMTraceLog "Launching BIOS Update : $UpdateEXE"
        $BIOSUpdate = Start-Process -FilePath $env:TEMP\$Model\$UpdateEXE -NoNewWindow -Wait -Passthru -ArgumentList $UpdateArgs
        Write-CMTraceLog "Stopped BIOS Update : $UpdateEXE with Return Code $($BIOSUpdate.ExitCode)" -ProcessID $($BIOSUpdate.Id)
        Write-CMTraceLog "Retrieving Return Codes for $($BIOSSource.Parent.Name) Update Executable"
        If ($BIOSSource.Parent.Name -eq 'Dell') {
            Switch ($BIOSUpdate.ExitCode) {
                '0' {
                    $BIOSUpdateRtnMsg  = 'SUCCESSFUL : The update was successful'
                    $BIOSUpdateSuccess = $true      
                }
                '1' {
                    $BIOSUpdateRtnMsg = 'UNSUCCESSFUL (FAILURE) : An error occurred during the update process; the update was not successful.'
                    $BIOSUpdateSuccess = $false
                }
                '2' {
                    $BIOSUpdateRtnMsg = 'REBOOT_REQUIRED : You must restart the system to apply the updates.'
                    $BIOSUpdateSuccess = $true
                }
                '3' {
                    $BIOSUpdateRtnMsg = 'DEP_SOFT_ERROR : You attempted to update to the same version of the software. / You tried to downgrade to a previous version of the software.'
                    $BIOSUpdateSuccess = $false
                }
                '4' {
                    $BIOSUpdateRtnMsg = 'DEP_HARD_ERROR : The update was unsuccessful because the system did not meet BIOS, driver, or firmware prerequisites for the update to be applied, or because no supported device was found on the target system.'
                    $BIOSUpdateSuccess = $false
                }
                '5' {
                    $BIOSUpdateRtnMsg = 'QUAL_HARD_ERROR : The operating system is not supported by the DUP. / The system is not supported by the DUP. / The DUP is not compatible with the devices found in your system.'
                    $BIOSUpdateSuccess = $false
                }
                '6' {
                    $BIOSUpdateRtnMsg = 'REBOOTING_SYSTEM : The system is being rebooted.'
                    $BIOSUpdateSuccess = $true
                }
            }
        }
        If ($BIOSUpdateSuccess -eq $true) {
            Write-CMTraceLog "BIOS Update Returned : $BIOSUpdateRtnMsg"
            $TSEnv.Value('BIOSUpdateRestart') = $true
        }
        ElseIf ($BIOSUpdateSuccess -eq $false) {
            Write-CMTraceLog "BIOS Update Returned : $BIOSUpdateRtnMsg" -LogLevel 3
        }
        Else {
            Write-CMTraceLog "BIOS Update Returned Unknown Result" -LogLevel 2
        }
    }
    Else {
        Write-CMTraceLog "Machine BIOS matches Archived BIOS : $BIOSvCurrent"
    }
}
Else {
    Write-CMTraceLog "No Archived BIOS Version Information available for this machine" -LogLevel 2
}
If ($TSEnv.Value('BIOSUpdateRestart') -eq $true) {
    Write-CMTraceLog "Restart required"
    Write-CMTraceLog "Task Sequence Variable set to enforce restart"
}
Write-CMTraceLog "BIOS Update Scan Finished"