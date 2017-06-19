Function Uninstall-Application {
	
    <#
    .Synopsis
      Uninstalls an Application
    .Description
      Uninstalls an Application # TODO PIPELINE
    .Parameter Name
      Name/Array of Groups to Count
    .Example
      Uninstall-Application -Name '7-Zip','Java'
    #>

    [CmdLetBinding(SupportsShouldProcess=$true)]
    Param(
    [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
    [String[]]$Name
    )

    BEGIN {
        # Create Output Arrays
        $ApplicationsToRemove = @()
        $UninstallStatus      = @()

        # Scan for Installed Applications
        If ((Get-WmiObject -Class Win32_OperatingSystem).OSArchitecture -notlike '64-bit') {
            $InstalledApplications = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*')
        }
        Else {
            $InstalledApplications = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                                                             'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
        }

        # Build Uninstall List
        ForEach ($Application in $Name) {
            # Specify Applications to Remove
            $ApplicationsToRemove += $InstalledApplications | Where-Object -FilterScript {$_.DisplayName -like "*$Application*"}
        }
    }

    PROCESS {
        # Perform Uninstall
        ForEach ($ApplicationToRemove in $ApplicationsToRemove) {
            If ($PSCmdlet.ShouldProcess("$($ApplicationToRemove.DisplayName)","Uninstall")) {
                If ($ApplicationToRemove.UninstallString.ToLower().StartsWith("msiexec")) {
                    # Build Switches and Launch msi Uninstall
                    $UninstallProcess = Start-Process -Wait -PassThru -FilePath msiexec -ArgumentList "/x $($ApplicationToRemove.PSChildName)", "/norestart", "/qn"
                    # Populate Output Array
                    $Uninstall                   = 1 | Select ApplicationName, Status, ExitCode, UninstallCommand
                    $Uninstall.ApplicationName   = $ApplicationToRemove.DisplayName
                    $Uninstall.UninstallCommand  = $ApplicationToRemove.UninstallString
                    $Uninstall.ExitCode          = $UninstallProcess.ExitCode
                    If (($UninstallProcess.ExitCode -eq 0) -or
                        ($UninstallProcess.ExitCode -eq 1605)) {
                         $Uninstall.Status = 'Uninstalled'
                    }
                    Else {
                        $Uninstall.Status = 'Error'
                    }
                    $UninstallStatus += $Uninstall
                }
                Else {
                    # Build Switches and Launch exe Uninstall
                    $Length            = $ApplicationToRemove.UninstallString.IndexOf(".exe")
                    $UninstallCommand  = $ApplicationToRemove.UninstallString.Substring(0,$Length+4)
                    $UninstallSwitches = $($ApplicationToRemove.UninstallString.Substring($Length+4,$ApplicationToRemove.UninstallString.Length-$Length-4)).Trim()
                    $UninstallProcess  = Start-Process -Wait -PassThru -FilePath $UninstallCommand -ArgumentList $UninstallSwitches
                    # Populate Output Array
                    $Uninstall                   = 1 | Select ApplicationName, Status, ExitCode, UninstallCommand
                    $Uninstall.ApplicationName   = $ApplicationToRemove.DisplayName
                    $Uninstall.UninstallCommand  = $ApplicationToRemove.UninstallString
                    $Uninstall.ExitCode          = $UninstallProcess.ExitCode
                    If (($UninstallProcess.ExitCode -eq 0) -or
                        ($UninstallProcess.ExitCode -eq 1605)) {
                         $Uninstall.Status = 'Uninstalled'
                    }
                    Else {
                        $Uninstall.Status = 'Error'
                    }
                    $UninstallStatus += $Uninstall
                }
            }
        }
    }

    END {
        # Print the Output to Console
        $UninstallStatus
    }

}