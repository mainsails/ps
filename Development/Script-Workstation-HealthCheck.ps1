Clear-Host
Write-Progress -Activity "Performing Health Check" -Status "Checking"
$Health = @()
#### Installed Applications Scan ####
$InstalledApplications = @()
$RegKeyApplications = @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall","HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall")
ForEach ($RegKey in $RegKeyApplications) {
    If (Test-Path -LiteralPath $RegKey -ErrorAction 'SilentlyContinue' -ErrorVariable '+ErrorUninstallKeyPath') {
        $InstalledApps = Get-ChildItem -LiteralPath $RegKey -ErrorAction 'SilentlyContinue'
        ForEach ($InstalledApp in $InstalledApps) {
            Try {
                $RegKeyApplicationProps = Get-ItemProperty -LiteralPath $InstalledApp.PSPath -ErrorAction 'Stop'
                If ($RegKeyApplicationProps.DisplayName) {
                    $InstalledApplications += $RegKeyApplicationProps
                }
            }
            Catch {
                Continue
            }
        }
    }
}



#### Last Boot ####
# Compliant : Boot within 7 Days
Write-Progress -Activity "Performing Health Check" -Status "Checking" -CurrentOperation "Last Boot" -PercentComplete 10
$LastBoot = Get-CimInstance -ClassName win32_operatingsystem -ErrorAction SilentlyContinue | Select lastbootuptime

$Check          = 1 | Select Hostname, Product, Version, Information, Status
$Check.Hostname = $env:COMPUTERNAME
$Check.Product  = "LAST BOOT"
$Check.Version  = "N/A"

If ($LastBoot) {
    $Check.Information = "Booted : $($LastBoot.lastbootuptime)"
    If ((Get-Date) -gt ($LastBoot.lastbootuptime).adddays(7)) {
        $Check.Status = "ERROR"
    }
    Else {
        $Check.Status = "OK"
    }
}
Else {
    $Check.Information = "Unable to detect last boot time"
    $Check.Status      = "UNKNOWN"
}

$Health += $Check



#### Last Patch Installation ####
# Compliant : Patched within 7 Days
Write-Progress -Activity "Performing Health Check" -Status "Checking" -CurrentOperation "Last Patch" -PercentComplete 20 -Id 0
$Check          = 1 | Select Hostname, Product, Version, Information, Status
$Check.Hostname = $env:COMPUTERNAME
$Check.Product  = "LAST PATCH"
$Check.Version  = "N/A"

If (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Set-Service -Name wuauserv -StartupType Manual -Status Running -ErrorAction SilentlyContinue
    $Service = Get-Service -Name wuauserv
    If ($Service.Status -eq "Running") {
        $Session       = New-Object -ComObject Microsoft.Update.Session
        $Searcher      = $Session.CreateUpdateSearcher()
        $WindowsUpdate = $Searcher.QueryHistory(1,1) | Select -ExpandProperty Date

        If ($WindowsUpdate) {
            $Check.Information = "Updated : $($WindowsUpdate)"
            If ((Get-Date) -gt ($WindowsUpdate).adddays(7)) {
                $Check.Status = "ERROR"
            }
            Else {
                $Check.Status = "OK"
            }
        }
        Else {
            $Check.Information = "Unable to detect last patch time"
            $Check.Status      = "UNKNOWN"
        }
        Write-Progress -Activity "Stopping Service" -Status "Windows Update" -CurrentOperation "Stopping..." -Id 1 -ParentId 0
        Set-Service  -Name wuauserv -StartupType Disabled -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        Stop-Service -Name wuauserv -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    }
    Else {
        $Check.Information = "Error checking Patch Status"
        $Check.Status      = "ERROR"
    }
}
Else {
    $Check.Information = "Insufficient Permission to check Patch Status"
    $Check.Status      = "UNKNOWN"
}

$Health += $Check



#### Bitlocker ####
# Compliant : Encrypted
Write-Progress -Activity "Performing Health Check" -Status "Checking" -CurrentOperation "BitLocker" -PercentComplete 30

$Check          = 1 | Select Hostname, Product, Version, Information, Status
$Check.Hostname = $env:COMPUTERNAME
$Check.Product  = "BITLOCKER"

If (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    $Bitlocker = Get-WmiObject -Computer $env:COMPUTERNAME -Namespace root\CIMv2\Security\MicrosoftVolumeEncryption -Class Win32_EncryptableVolume -ErrorAction SilentlyContinue | Select -Expand ProtectionStatus
    If ($Bitlocker) {
        If ($Bitlocker -eq "2") {
            $Check.Information = "Status : System is Locked by BitLocker"
            $Check.Status      = "ERROR"
        }
        Elseif ($Bitlocker -eq "1") {
            $Check.Information = "Status : Encrypted"
            $Check.Status      = "OK"
        }
        Else {
            $Check.Information = "Status : UnEncrypted"
            $Check.Status      = "ERROR"
        }
    }
    Elseif ($Bitlocker -eq "0") {
            $Check.Information = "Status : System is Unlocked by BitLocker"
            $Check.Status      = "ERROR"
    }
    Else {
        $Check.Information = "Error checking BitLocker Status"
        $Check.Status      = "UNKNOWN"
    }
}
Else {
    $Check.Information = "Insufficient Permission to check BitLocker Status"
    $Check.Status      = "UNKNOWN"
}

$MBAM = $InstalledApplications | Where-Object -FilterScript {$_.DisplayName -like "*MBAM*"}
If ($MBAM) {
    $Check.Version  = $MBAM.DisplayVersion
}
Else {
    $Check.Version      = "N/A"
    $Check.Information  = "MBAM Client is Incorrect/Missing"
    $Check.Status       = "ERROR"
}

$Health += $Check



#### Sophos Version Check ####
# Compliant : Updated within 7 Days
Write-Progress -Activity "Performing Health Check" -Status "Checking" -CurrentOperation "Sophos" -PercentComplete 50

$Check          = 1 | Select Hostname, Product, Version, Information, Status
$Check.Hostname = $env:COMPUTERNAME
$Check.Product  = "SOPHOS"

$Sophos = $InstalledApplications | Where-Object -FilterScript {$_.DisplayName -like "*Sophos Anti-Virus*"}
If ($Sophos) {
    $Check.Version = $Sophos.DisplayVersion
    $SophosUpdateReg = @('HKLM:\SOFTWARE\Wow6432Node\Sophos\AutoUpdate\UpdateStatus','HKLM:\SOFTWARE\Sophos\AutoUpdate\UpdateStatus')
    ForEach ($RegKey in $SophosUpdateReg) {
        If (Test-Path -LiteralPath $RegKey -ErrorAction 'SilentlyContinue') {
            $Reg = Get-ItemProperty -Path $RegKey
            If ($Reg.Result -eq 0) {
                $LastSophosUpdate = [timezone]::CurrentTimeZone.ToLocalTime(([datetime]'1/1/1970').AddSeconds($Reg.LastUpdateTime))
                If ((Get-Date) -lt ($LastSophosUpdate).AddDays(7)) {
                    $Check.Information = "Updated : $($LastSophosUpdate)"
                    $Check.Status      = "OK"
                }
                Else {
                    $Check.Information = "Updated : $($LastSophosUpdate)"
                    $Check.Status      = "ERROR"
                }
            }
            Else {
                $FirstSophosFail = [timezone]::CurrentTimeZone.ToLocalTime(([datetime]'1/1/1970').AddSeconds($Reg.FirstFailedUpdateTime))
                $Check.Information = "Updates Failed Since : $($FirstSophosFail)"
                $Check.Status      = "ERROR"
            }
        }
    }
}
Else {
    $Check.Version     = "N/A"
    $Check.Information = "Unable to detect Sophos"
    $Check.Status      = "ERROR"
}

$Health += $Check



#### Internet Explorer Version Check ####
# Compliant : 11 and above
Write-Progress -Activity "Performing Health Check" -Status "Checking" -CurrentOperation "Internet Explorer" -PercentComplete 60
$HKLM = [UInt32] "0x80000002"            
$subkeyName = "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\IEXPLORE.EXE"            
$regProv = [WMIClass] "\\$env:COMPUTERNAME\root\default:StdRegProv"            
$iePath = ($regProv.GetStringValue($HKLM, $subkeyName, "")).sValue            
$iePath = $iePath -replace '\\', '\\'            
$dataFile = [WMI] "\\$env:COMPUTERNAME\root\CIMV2:CIM_DataFile.Name='$iePath'"

$Check          = 1 | Select Hostname, Product, Version, Information, Status
$Check.Hostname = $env:COMPUTERNAME
$Check.Product  = "IE"

If ($dataFile) {
    $Check.Version = $dataFile.Version
    If ([System.Version]$Check.Version -gt "11.0.0.0") {
        $Check.Information = "Version : $($Check.Version)"
        $Check.Status      = "OK"
    }
    Else {
        $Check.Information = "Version : $($Check.Version)"
        $Check.Status      = "ERROR"
    }
}
Else {
    $Check.Version = "N/A"
    $Check.Information = "Unable to detect IE"
    $Check.Status      = "ERROR"
}

$Health += $Check



#### Java Version Check ####
# Compliant : Java 1.6.0.31 Installed
Write-Progress -Activity "Performing Health Check" -Status "Checking" -CurrentOperation "Java" -PercentComplete 70
$Java = $InstalledApplications | Where-Object -FilterScript {$_.DisplayName -like "*Java(TM)*"}

$Check          = 1 | Select Hostname, Product, Version, Information, Status
$Check.Hostname = $env:COMPUTERNAME
$Check.Product  = "JAVA"

If ($Java) {
    $Check.Version = $Java[0].DisplayVersion
    If ($Check.Version -eq "6.0.310") {
        $Check.Information = "Version : $($Check.Version)"
        $Check.Status      = "OK"
    }
    Else {
        $Check.Information = "Version : $($Check.Version)"
        $Check.Status      = "ERROR"
    }
}
Else {
    $Check.Version     = "N/A"
    $Check.Information = "Unable to detect Java"
    $Check.Status      = "ERROR"
}

$Health += $Check



#### Identity Agent Version Check ####
# Compliant : Version 11.02.00a or 13.01.09
Write-Progress -Activity "Performing Health Check" -Status "Checking" -CurrentOperation "Identity Agent" -PercentComplete 80
$IA = $InstalledApplications | Where-Object -FilterScript {$_.DisplayName -like "*Identity Agent*"}

$Check          = 1 | Select Hostname, Product, Version, Information, Status
$Check.Hostname = $env:COMPUTERNAME
$Check.Product  = "IA"

If ($IA) {
    $Check.Version = $IA[0].DisplayVersion
    If ($Check.Version -eq "11.02.00a (11.2.0.24579)" -or $Check.Version -eq "13.01.09") {
        $Check.Information = "Version : $($Check.Version)"
        $Check.Status      = "OK"
    }
    Else {
        $Check.Information = "Version : $($Check.Version)"
        $Check.Status      = "ERROR"
    }
}
Else {
    $Check.Version = "N/A"
    $Check.Information = "Unable to detect an Identity Agent"
    $Check.Status      = "ERROR"
}

$Health += $Check



#### RiO DropZone Version Check ####
# Compliant : Version 2.0.0003
Write-Progress -Activity "Performing Health Check" -Status "Please Wait" -CurrentOperation "DropZone" -PercentComplete 90
$DropZone = $InstalledApplications | Where-Object -FilterScript {$_.DisplayName -like "*RiO Drop Zone*"}

$Check          = 1 | Select Hostname, Product, Version, Information, Status
$Check.Hostname = $env:COMPUTERNAME
$Check.Product  = "DROPZONE"

If ($DropZone) {
    $Check.Version = $DropZone[0].DisplayVersion
    If ([System.Version]$Check.Version -eq "2.0.0003") {
        $Check.Information = "Version : $($Check.Version)"
        $Check.Status      = "OK"
    }
    Else {
        $Check.Information = "Version : $($Check.Version)"
        $Check.Status      = "ERROR"
    }
}
Else {
    $Check.Version     = "N/A"
    $Check.Information = "Unable to detect DropZone"
    $Check.Status      = "ERROR"
}

$Health += $Check




##### Export Status to Network ####
#$ExportPath = "\\networkshare\WorkstationHealth.csv"
#
#While ($true) {
#    Try {
#        [IO.File]::OpenWrite($ExportPath).close()
#        $Health | Export-Csv -Path $ExportPath -Append -NoTypeInformation
#        Break
#    }
#    Catch {
#        Start-Sleep -Seconds (Get-Random -Minimum 1 -Maximum 5)
#    }
#}




#### Print Status to Console ####
$Health | ft
Write-Host
ForEach ($Check in $Health) {
   If ($Check.Status -eq "OK") {
       $Status = "Green"
   }
    Else {
       $Status = "Red"
   }
    Write-Host "$($Check.Hostname) : $($Check.Product) : $($Check.Information)" -ForegroundColor $Status
}