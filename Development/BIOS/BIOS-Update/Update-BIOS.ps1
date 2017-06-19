    $BIOSStructure = Split-Path $MyInvocation.MyCommand.Path -Parent
    $SystemInfo    = Get-WmiObject -Class Win32_ComputerSystem
    $BIOSInfo      = Get-WmiObject -Class Win32_BIOS
    $Manufacturer  = $SystemInfo.Manufacturer
    $Model         = $SystemInfo.Model
    $BIOSvCurrent  = $BIOSInfo.SMBIOSBIOSVersion
    $BIOSSource    = Get-ChildItem -Path $BIOSStructure -Include $Model -Recurse

If ($BIOSSource) {
    $BIOSvLatest = Get-ChildItem -Path $BIOSSource -Filter '*.ver' | Select -ExpandProperty BaseName
    If ($BIOSvCurrent -ne $BIOSvLatest) {
        $UpdateExe = (Get-ChildItem -Path $BIOSSource -Filter *.exe).Name
        If ($UpdateExe.Count -ne 1) {Break}
        Copy-Item -Path $BIOSSource -Destination $env:TEMP -Recurse -Force
        Set-Location -Path $env:TEMP\$Model
        If ($BIOSSource.Parent.Name -eq 'Dell') {
            $UpdateArgs = '/s /f /p=m8obfuscated'
        }
        ElseIf ($BIOSSource.Parent.Name -eq 'HP') {
            $UpdateArgs = ''
        }
        Else {Break}
        $BIOSUpdate = Start-Process -FilePath $env:TEMP\$Model\$UpdateEXE -NoNewWindow -Wait -Passthru -ArgumentList $UpdateArgs
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
            # Success - Requires Reboot
        }
        ElseIf ($BIOSUpdateSuccess -eq $false) {
        }
        Else {
            # Unknown Result
        }
    }
    Else {
        # Machine BIOS matches Archived BIOS
    }
}
Else {
    # No Archived BIOS available for this machine
}