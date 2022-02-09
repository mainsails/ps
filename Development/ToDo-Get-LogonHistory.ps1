$UserProperty = @{ Name = 'User'; Expression = { (New-Object System.Security.Principal.SecurityIdentifier $_.Properties.Value[1]).Translate([System.Security.Principal.NTAccount]) } }
$TypeProperty = @{ Name = 'Action'; Expression = { if ($_.ID -eq 7001) { 'Logon' } else { 'Logoff' } } }
$TimeProperty = @{ Name = 'Time'; Expression = { $_.TimeCreated } }
Get-WinEvent -FilterHash @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Winlogon' } | Select-Object -Property $UserProperty, $TypeProperty, $TimeProperty, @{ Name = "Computer"; Expression = { $env:COMPUTERNAME } }
