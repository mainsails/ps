Function Wait-Network {
    <#
    .SYNOPSIS
        Wait for a live network connection
    .DESCRIPTION
        Wait for at least one DHCP enabled network adapter to become active before timeout threshold is reached
    .PARAMETER Timeout
        Number of seconds to wait before timing out
    .EXAMPLE
        Wait-Network -Timeout 60
    #>

    Param (
        [Parameter(ValueFromPipeline=$true)]
        [ValidateRange(0,[int]::MaxValue)]
        [int]$Timeout = 20
    )
    While ($true) {
        # Get a list of DHCP-enabled adapters that have a DefaultIPGateway property set
        $Adapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter DHCPEnabled=TRUE | Where-Object { $_.DefaultIPGateway -ne $null }
        # If one exists, exit
        If (($Adapters | Measure-Object).Count -gt 0) {
            Break
        }
        # Loop until timeout limit is reached
        If ($Timeout -gt 0 -and $Tried++ -ge $Timeout) {
            Break
        }
        Start-Sleep -Seconds 1
    }
}