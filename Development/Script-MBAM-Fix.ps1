#### Installed Applications Check ####
$InstalledApplications = @()
$RegKeyApplications = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall')
ForEach ($RegKey in $RegKeyApplications) {
    If (Test-Path -LiteralPath $RegKey -ErrorAction 'SilentlyContinue') {
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
$MBAM = $InstalledApplications | Where-Object -FilterScript {$_.DisplayName -like '*MBAM*'}


#### Bitlocker / TPM Check ####
$TPM       = Get-WmiObject -Namespace 'ROOT\cimv2\Security\MicrosoftTpm' -Class 'Win32_Tpm'
$BitLocker = Get-WmiObject -Namespace 'ROOT\cimv2\Security\MicrosoftVolumeEncryption' -Class 'Win32_EncryptableVolume' -Filter "DriveLetter = 'C:'"

If ($TPM) {
    $TPMActivated        = $TPM.IsActivated().IsActivated
    $TPMEnabled          = $TPM.IsEnabled().IsEnabled
    $TPMOwnerShipAllowed = $TPM.IsOwnershipAllowed().IsOwnerShipAllowed
    $TPMOwned            = $TPM.IsOwned().IsOwned
}

$ProtectionState           = $BitLocker.GetConversionStatus()
$CurrentEncryptionProgress = $ProtectionState.EncryptionPercentage
Switch ($ProtectionState.Conversionstatus) {
    '0' {
        $Properties             = @{'EncryptionState'='FullyDecrypted';'CurrentEncryptionProgress'=$CurrentEncryptionProgress}
        $CurrentEncryptionState = New-Object -TypeName PSObject -Property $Properties
    }

    '1' {
        $Properties             = @{'EncryptionState'='FullyEncrypted';'CurrentEncryptionProgress'=$CurrentEncryptionProgress}
        $CurrentEncryptionState = New-Object -TypeName PSObject -Property $Properties
    }

    '2' {
        $Properties             = @{'EncryptionState'='EncryptionInProgress';'CurrentEncryptionProgress'=$CurrentEncryptionProgress}
        $CurrentEncryptionState = New-Object -TypeName PSObject -Property $Properties
    }

    '3' {
        $Properties             = @{'EncryptionState'='DecryptionInProgress';'CurrentEncryptionProgress'=$CurrentEncryptionProgress}
        $CurrentEncryptionState = New-Object -TypeName PSObject -Property $Properties
    }

    '4' {
        $Properties             = @{'EncryptionState'='EncryptionPaused';'CurrentEncryptionProgress'=$CurrentEncryptionProgress}
        $CurrentEncryptionState = New-Object -TypeName PSObject -Property $Properties
    }

    '5' {
        $Properties             = @{'EncryptionState'='DecryptionPaused';'CurrentEncryptionProgress'=$CurrentEncryptionProgress}
        $CurrentEncryptionState = New-Object -TypeName PSObject -Property $Properties
    }

    default {
        $Properties             = @{'EncryptionState'=$false;'CurrentEncryptionProgress'=$false}
        $CurrentEncryptionState = New-Object -TypeName PSObject -Property $Properties
    }
}

$ProtectionStatus = $BitLocker.GetProtectionStatus().ProtectionStatus
Switch ($ProtectionStatus) {
    '0'     {$ProtectionStatus = 'Unprotected'}
    '1'     {$ProtectionStatus = 'Protected'}
    '2'     {$ProtectionStatus = 'Unknown'}
    default {$ProtectionStatus = 'NoReturn'}
}

$EncryptMethod = $BitLocker.GetEncryptionMethod().EncryptionMethod
Switch ($EncryptMethod) {
    '0'     {$EncryptionMethod = 'None'}
    '1'     {$EncryptionMethod = 'AES_128_WITH_DIFFUSER'}
    '2'     {$EncryptionMethod = 'AES_256_WITH_DIFFUSER'}
    '3'     {$EncryptionMethod = 'AES_128'}
    '4'     {$EncryptionMethod = 'AES_256'}
    '5'     {$EncryptionMethod = 'HARDWARE_ENCRYPTION'}
    default {$EncryptionMethod = 'Unknown'}
}

$ProtectorIDs = $BitLocker.GetKeyProtectors('0').VolumeKeyProtectorID
$KeyProtectorTypeAndID = @()
Foreach ($ProtectorID in $ProtectorIDs) {
    $KeyProtectorType = $BitLocker.GetKeyProtectorType($ProtectorID).KeyProtectorType
    Switch ($KeyProtectorType) {
        '0'  {$KeyType = 'Unknown or other protector type'}
        '1'  {$KeyType = 'Trusted Platform Module (TPM)'}
        '2'  {$KeyType = 'External key'}
        '3'  {$KeyType = 'Numerical password'}
        '4'  {$KeyType = 'TPM And PIN'}
        '5'  {$KeyType = 'TPM And Startup Key'}
        '6'  {$KeyType = 'TPM And PIN And Startup Key'}
        '7'  {$KeyType = 'Public Key'}
        '8'  {$KeyType = 'Passphrase'}
        '9'  {$KeyType = 'TPM Certificate'}
        '10' {$KeyType = 'CryptoAPI Next Generation (CNG) Protector'}
    }
    $Properties = @{'KeyProtectorID'=$ProtectorID;'KeyProtectorType'=$KeyType}
    $KeyProtectorTypeAndID += New-Object -TypeName PSObject -Property $Properties
}


#### Build Object ####
$Properties = [Ordered]@{ 'Hostname'                    = $env:COMPUTERNAME
                          'ProtectionStatus'            = $ProtectionStatus
                          'EncryptionState'             = $CurrentEncryptionState.EncryptionState
                          'EncryptionMethod'            = $EncryptionMethod
                          'CurrentEncryptionPercentage' = $CurrentEncryptionState.CurrentEncryptionProgress
                          'KeyProtectorTypesAndIDs'     = $KeyProtectorTypeAndID
                          'IsTPMActivated'              = $TPMActivated
                          'IsTPMEnabled'                = $TPMEnabled
                          'IsTPMOwnerShipAllowed'       = $TPMOwnerShipAllowed
                          'IsTPMOwned'                  = $TPMOwned
                          'MBAMVersion'                 = $MBAM.DisplayVersion
                          'MBAMInstallDate'             = $MBAM.InstallDate
}
$BitlockerStatus = New-Object -TypeName PSObject -Property $Properties


##### Check / Fix MBAM Client ####
If (($BitlockerStatus.MBAMVersion) -lt '2.5.0252.0') {
    $Computer          = $env:COMPUTERNAME
    $MBAMFolder        = 'C:\Appstore\MBAM'
    $MBAM25x86         = '\\barsoftware\desktopcentral$\Microsoft\MBAMFIx\x86\MBAMClient.msi'
    $MBAM25x64         = '\\barsoftware\desktopcentral$\Microsoft\MBAMFIx\x64\MBAMClient.msi'
    $MBAMkbx86         = '\\barsoftware\desktopcentral$\Microsoft\MBAMFIx\x86\MBAM2.5-Client-KB2975636.exe'
    $MBAMkbx64         = '\\barsoftware\desktopcentral$\Microsoft\MBAMFIx\x64\MBAM2.5-Client-KB2975636.exe'
    $MBAMClientEXE     = "$MBAMFolder\MBAMClient.msi"
    $MBAMClientArgs    = '/qn /norestart'
    $MBAMUpdateEXE     = "$MBAMFolder\MBAM2.5-Client-KB2975636.exe"
    $MBAMUpdateArgs    = '/acceptEula=Yes /quiet /norestart'
    
    $LocalDirStructure = $MBAMFolder.TrimStart('C:\')
    New-Item -Path "\\$Computer\c$\$LocalDirStructure" -Type Directory -Force | Out-Null
    If ([Environment]::Is64BitOperatingSystem) {
        Copy-Item -Path $MBAM25x64 -Destination $MBAMFolder -Force
        Copy-Item -Path $MBAMkbx64 -Destination $MBAMFolder -Force
    }
    Else {
        Copy-Item -Path $MBAM25x86 -Destination $MBAMFolder -Force
        Copy-Item -Path $MBAMkbx86 -Destination $MBAMFolder -Force
    }
    If ($BitlockerStatus.MBAMVersion -eq '2.5.0244.0') {
        $MBAMUpdate = Start-Process -Wait -PassThru -FilePath $MBAMUpdateEXE -ArgumentList $MBAMUpdateArgs
    }
    If ($BitlockerStatus.MBAMVersion -lt '2.5.0244.0') {
        $MBAMClient = Start-Process -Wait -PassThru -FilePath $MBAMClientEXE -ArgumentList $MBAMClientArgs
        $MBAMUpdate = Start-Process -Wait -PassThru -FilePath $MBAMUpdateEXE -ArgumentList $MBAMUpdateArgs
    }
    Restart-Service -Name 'MBAMAgent' -ErrorAction SilentlyContinue
}