Function Get-PowerSupply {
    <#
    .SYNOPSIS
        Retrieve Power Supply information from the local machine
    .DESCRIPTION
        Retrieve Power Supply information from the local machine
    .EXAMPLE
        Get-PowerSupply
    .EXAMPLE
        (Get-PowerSupply).IsLaptop
        Determines if the current system is a laptop or not
    .EXAMPLE
        (Get-PowerSupply).IsUsingACPower
        Determines if the current system is currently connected to AC Power or not
    .NOTES
        IsLaptop - [Boolean]
        IsUsingACPower - [Boolean]
        ACPowerLineStatusBatteryChargeStatus :
                [Offline] : The system is not using AC power
                [Online]  : The system is using AC power
                [Unknown] : The power status of the system is unknown
        BatteryLifePercent - Get the approximate amount of full battery charge remaining
        BatteryLifeRemaining - Approximate number of seconds of battery life remaining
        BatteryFullLifetime - Reported number of seconds of battery life available when the battery is fully charged
    #>

    [CmdletBinding()]
    Param ()

    Begin {
        # Verbose Logging
        [string]$CmdletName  = $MyInvocation.MyCommand.Name
        [string]$CmdletParam = $PSBoundParameters | Format-Table -Property @{ Label = 'Parameter'; Expression = { "[-$($_.Key)]" } }, @{ Label = 'Value'; Expression = { $_.Value }; Alignment = 'Left' } -AutoSize -Wrap | Out-String
        Write-Verbose -Message "##### Calling : [$CmdletName]"

        # Add assembly for more reliable PowerStatus class in cases where the battery is failing
        Add-Type -Assembly 'System.Windows.Forms' -ErrorAction 'SilentlyContinue'

        # Initialize a hashtable to store information about system type and power status
        [hashtable]$SystemTypePowerStatus = @{}
    }
    Process {
        Write-Verbose -Message 'Check if system is using AC power or if it is running on battery...'

        [Windows.Forms.PowerStatus]$PowerStatus = [Windows.Forms.SystemInformation]::PowerStatus

        ## Get the system power status. Indicates whether the system is using AC power or if the status is unknown. Possible values:
        #  Offline : The system is not using AC power
        #  Online  : The system is using AC power
        #  Unknown : The power status of the system is unknown
        [string]$PowerLineStatus = $PowerStatus.PowerLineStatus
        $SystemTypePowerStatus.Add('ACPowerLineStatus', $PowerStatus.PowerLineStatus)

        # Get the current battery charge status. Possible values: High, Low, Critical, Charging, NoSystemBattery, Unknown
        [string]$BatteryChargeStatus = $PowerStatus.BatteryChargeStatus
        $SystemTypePowerStatus.Add('BatteryChargeStatus', $PowerStatus.BatteryChargeStatus)

        ## Get the approximate amount, from 0.00 to 1.0, of full battery charge remaining
        #  This property can report 1.0 when the battery is damaged and Windows can't detect a battery
        #  Therefore, this property is only indicative of battery charge remaining if 'BatteryChargeStatus' property is not reporting 'NoSystemBattery' or 'Unknown'
        [single]$BatteryLifePercent = $PowerStatus.BatteryLifePercent
        If (($BatteryChargeStatus -eq 'NoSystemBattery') -or ($BatteryChargeStatus -eq 'Unknown')) {
            [single]$BatteryLifePercent = 0.0
        }
        $SystemTypePowerStatus.Add('BatteryLifePercent', $($BatteryLifePercent.tostring("P")))

        # The reported approximate number of seconds of battery life remaining. It will report –1 if the remaining life is unknown because the system is on AC power
        [int32]$BatteryLifeRemaining = $PowerStatus.BatteryLifeRemaining
        $SystemTypePowerStatus.Add('BatteryLifeRemaining', $PowerStatus.BatteryLifeRemaining)

        ## Get the manufacturer reported full charge lifetime of the primary battery power source in seconds
        #  The reported number of seconds of battery life available when the battery is fully charged, or -1 if it is unknown
        #  This will only be reported if the battery supports reporting this information. You will most likely get -1, indicating unknown
        [int32]$BatteryFullLifetime = $PowerStatus.BatteryFullLifetime
        $SystemTypePowerStatus.Add('BatteryFullLifetime', $PowerStatus.BatteryFullLifetime)

        # Determine if the system is using AC power
        [boolean]$OnACPower = $false
        If ($PowerLineStatus -eq 'Online') {
            Write-Verbose -Message 'System is using AC power'
            $OnACPower = $true
        }
        ElseIf ($PowerLineStatus -eq 'Offline') {
            Write-Verbose -Message 'System is using battery power'
        }
        ElseIf ($PowerLineStatus -eq 'Unknown') {
            If (($BatteryChargeStatus -eq 'NoSystemBattery') -or ($BatteryChargeStatus -eq 'Unknown')) {
                Write-Verbose -Message  "System power status is [$PowerLineStatus] and battery charge status is [$BatteryChargeStatus]. This is likely due to a damaged battery - Reporting as using AC power"
                $OnACPower = $true
            }
            Else {
                Write-Verbose -Message "System power status is [$PowerLineStatus] and battery charge status is [$BatteryChargeStatus]. Reporting as using battery power"
            }
        }
        $SystemTypePowerStatus.Add('IsUsingACPower', $OnACPower)

        # Determine if the system is a laptop
        [boolean]$IsLaptop = $false
        If (($BatteryChargeStatus -eq 'NoSystemBattery') -or ($BatteryChargeStatus -eq 'Unknown')) {
            $IsLaptop = $false
        }
        Else {
            $IsLaptop = $true
        }
        # Chassis Types (https://msdn.microsoft.com/en-us/library/aa394474(v=vs.85).aspx)
        [int32[]]$ChassisTypes = Get-WmiObject -Class 'Win32_SystemEnclosure' | Where-Object { $_.ChassisTypes } | Select-Object -ExpandProperty 'ChassisTypes'
        Write-Verbose -Message "The following system chassis types were detected [$($ChassisTypes -join ',')]"
        ForEach ($ChassisType in $ChassisTypes) {
            Switch ($ChassisType) {
                { $_ -eq 9 -or $_ -eq 10 -or $_ -eq 14 } { $IsLaptop = $true } # 9=Laptop, 10=Notebook, 14=Sub Notebook
                { $_ -eq 3 } { $IsLaptop = $false } # 3=Desktop
            }
        }
        # Add IsLaptop property to hashtable
        $SystemTypePowerStatus.Add('IsLaptop', $IsLaptop)

        # Write Output
        Write-Output -InputObject $SystemTypePowerStatus
    }
    End {
        # Verbose Logging
        Write-Verbose -Message "##### Ending : [$CmdletName]"
    }
}