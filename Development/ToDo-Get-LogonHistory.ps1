#todo
function get-logonhistory {
    Param (
        [string]$Computer = (Read-Host Remote computer name),
        [int]$Days = 10
    )
    
    $Result = @()
    Write-Host "Gathering Event Logs, this can take awhile..."
    $ELogs = Get-EventLog System -Source Microsoft-Windows-WinLogon -After (Get-Date).AddDays(-$Days) -ComputerName $Computer
    If ($ELogs) {
        Write-Host "Processing..."
        ForEach ($Log in $ELogs) {
            If ($Log.InstanceId -eq 7001) {
                $ET = "Logon"
            }   
            ElseIf ($Log.InstanceId -eq 7002) {
                $ET = "Logoff"
            }
            Else {
                Continue
            }
            $Result += New-Object PSObject -Property @{
                Time = $Log.TimeWritten
                'Event Type' = $ET
                User = (New-Object System.Security.Principal.SecurityIdentifier $Log.ReplacementStrings[1]).Translate([System.Security.Principal.NTAccount])
            }
        }
        $Result | Select Time,"Event Type",User | Sort Time -Descending | Out-GridView
    }
    Else {
        Write-Host "Problem with $Computer."
        Write-Host "'Network Path not found' error - try starting the Remote Registry service on that computer."
    }
}


get-logonhistory -Computer 'COMPUTERNAME' -Days "90"

#$Computer = "$Computer"
#Set-Service -Name RemoteRegistry -StartupType Automatic -ComputerName $Computer
#Get-Service -Name RemoteRegistry -ComputerName $Computer | Start-Service