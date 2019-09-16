# Enable RDP
$ComputerName = 'ComputerName'
$UserName     = 'Domain Users'

Invoke-Command -Computername $ComputerName -ScriptBlock {
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 0
    Enable-NetFirewallRule -DisplayGroup 'Remote Desktop'
}

[string]$ADResolved = ([adsisearcher]"(SamAccountName=$UserName)").FindOne().Properties['SamAccountName']
$User = 'WinNT://',"$env:USERDOMAIN",'/',$ADResolved -join ''
([adsi]"WinNT://$ComputerName/Remote Desktop Users,group").add($User)