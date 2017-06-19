Function Update-BIOS {
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateSet('Dell','HP')]
        [string]$Manufacturer
    )

    Begin {
        ## Set Tool Vars
        $ScriptLocation = Split-Path $MyInvocation.MyCommand.Path -Parent
        $DellConfigEXE = $ScriptLocation + '\Tools\Dell\cctk\cctk.exe'
        $DellUpdateEXE = $ScriptLocation + '\Tools\Dell\Command\dcu-cli.exe'
        $DellUpdateSource = Split-Path $DellUpdateEXE -Parent
        $DellUpdatePolicy = $DellUpdateSource + '\Policy.xml'
        $UpdateArgs = "/policy $DellUpdatePolicy"

        # Clear BIOS Password and Pause BitLocker (resumed on reboot)
        Set-BIOSPassword -Manufacturer $Manufacturer -Action Clear
        Pause-BitLocker

    }
    Process {
        ## Update Dell BIOS
        If ($Manufacturer -eq 'Dell') {
            If (-not (Test-Path -Path $DellUpdatePolicy)) {
                Break
            }
            $BIOSUpdate = Start-Process -FilePath $DellUpdateEXE -NoNewWindow -Wait -Passthru -ArgumentList $UpdateArgs
            If ($BIOSUpdate.ExitCode -eq '0') {
            }
            If ($BIOSUpdate.ExitCode -eq '1') {
                $BIOSInfo = Get-WmiObject -Class Win32_BIOS
                $BIOSvUpdated = $BIOSInfo.SMBIOSBIOSVersion
            }
            Else {
            }
        }
    }
    End {
        # Set BIOS Password
        Set-BIOSPassword -Manufacturer $Manufacturer -Action Set
    }
}


Function Set-BIOSPassword {
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateSet('Dell','HP')]
        [string]$Manufacturer,
        [Parameter(Mandatory=$false)]
        [ValidateSet('Set','Clear')]
        [string]$Action = 'Set'
    )
    
    Begin {
        ## Set Function Vars
        $BIOSPassword    = 'm8obfuscated'
        $BIOSPasswordOld = 'zaobfuscated'

        ## Set Tool Vars
        $ScriptLocation = Split-Path $MyInvocation.MyCommand.Path -Parent
        $DellConfigEXE = $ScriptLocation + '\Tools\Dell\cctk\cctk.exe'
    }
    Process {
        ## Set Dell BIOS Password
        If ($Manufacturer -eq 'Dell') {
            # Clear Dell BIOS Password
            If ($Action -eq 'Clear') {
                $ConfigArgs = '--setuppwd='
                $BIOSConfiguration = Start-Process -FilePath $DellConfigEXE -NoNewWindow -Wait -Passthru -ArgumentList $ConfigArgs
                If ($BIOSConfiguration.ExitCode -eq '115') {
                    $ConfigArgs = "--setuppwd= --valsetuppwd=$BIOSPassword"
                    $BIOSConfiguration = Start-Process -FilePath $DellConfigEXE -NoNewWindow -Wait -Passthru -ArgumentList $ConfigArgs
                    If ($BIOSConfiguration.ExitCode -ne '0') {
                        $ConfigArgs = "--setuppwd=$BIOSPassword --valsetuppwd=$BIOSPasswordOld"
                        $BIOSConfiguration = Start-Process -FilePath $DellConfigEXE -NoNewWindow -Wait -Passthru -ArgumentList $ConfigArgs
                        If ($BIOSConfiguration.ExitCode -ne '0') {
                            Break
                        }
                    }
                }
                ElseIf ($BIOSConfiguration.ExitCode -eq '184') {
                }
                ElseIf ($BIOSConfiguration.ExitCode -ne '0') {
                    Break
                }
                Else {
                }
            }
            # Set Dell BIOS Password
            If ($Action -eq 'Set') {
                $ConfigArgs = "--setuppwd=$BIOSPassword"
                $BIOSConfiguration = Start-Process -FilePath $DellConfigEXE -NoNewWindow -Wait -Passthru -ArgumentList $ConfigArgs
                If ($BIOSConfiguration.ExitCode -ne '0') {
                    Break
                }
            }
        }
    }
    End {
    }
}


Function Pause-BitLocker {
    Begin {
        $EncryptedDisks = Get-BitLockerVolume | Where {
            $_.VolumeStatus     -eq 'FullyEncrypted' -and `
            $_.VolumeType       -eq 'OperatingSystem' -and `
            $_.ProtectionStatus -eq 'On'
            }
    }
    Process {
        If ($EncryptedDisks) {
            ForEach ($EncryptedDisk in $EncryptedDisks) {
                $BitlockerStatus = $EncryptedDisk | Suspend-BitLocker
            }
        }
        Else {
        }
    }
    End {
    }
}


Function Configure-BIOS {
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateSet('Dell','HP')]
        [string]$Manufacturer
    )

    Begin {
        ## Set Function Vars
        $SecureBootSupported  = @()
        #$SecureBootSupported += 'Latitude E7250'
        #$SecureBootSupported += 'Latitude E7270'

        ## Set Tool Vars
        $ScriptLocation = Split-Path $MyInvocation.MyCommand.Path -Parent
        $DellConfigEXE = $ScriptLocation + '\Tools\Dell\cctk\cctk.exe'

        # Clear BIOS Password and Pause BitLocker (resumed on reboot)
        Set-BIOSPassword -Manufacturer $Manufacturer -Action Clear
        Pause-BitLocker
    }
    Process {
        ## Configure Dell BIOS
        If ($Manufacturer -eq 'Dell') {
            # Configure Dell BIOS Options (Legacy)
            If ($SecureBoot -ne 'Supported') {
                $ConfigArgs = "bootorder --activebootlist=legacy"
                $BIOSConfiguration = Start-Process -FilePath $DellConfigEXE -NoNewWindow -Wait -Passthru -ArgumentList $ConfigArgs
            }
            # Configure Dell BIOS Options (Universal)
            $ConfigArgs = "bootorder --sequence=hdd.1,embnic --disabledevice=cdrom,floppy --embsataraid=ahci --controlwlanradio=enable --controlwwanradio=enable"
            $BIOSConfiguration = Start-Process -FilePath $DellConfigEXE -NoNewWindow -Wait -Passthru -ArgumentList $ConfigArgs
            If ($BIOSConfiguration.ExitCode -eq '0') {
            }
            Else {
            }

            # Configure Dell BIOS (Secure Boot)
            If ($SecureBoot -eq 'Supported') {
                $ConfigArgs = "bootorder --activebootlist=uefi --legacyorom=disable --secureboot=enable --uefinwstack=enable"
                $BIOSConfiguration = Start-Process -FilePath $DellConfigEXE -NoNewWindow -Wait -Passthru -ArgumentList $ConfigArgs
                If ($BIOSConfiguration.ExitCode -eq '0') {
                }
                Else {
                }
            }
        }
        # Set Task Sequence Variable to enforce UEFI Partitioning/Format
        If ($SecureBoot -eq 'Supported') {
            #$TSEnv.Value('ForceUEFI') = $true
        }
    }
    End {
        # Set BIOS Password
        Set-BIOSPassword -Manufacturer $Manufacturer -Action Set
    }
}