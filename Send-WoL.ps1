Function Send-WoL {
    <#
    .SYNOPSIS
        Sends a Wake-on-LAN (WoL) magic packet using UDP broadcast
    .DESCRIPTION
        Sends a broadcast frame, magic packet to a MAC address in order to wake up a specific machine by physical address using UDP broadcast
    .PARAMETER MACAddress
        The MAC address of the machine to wake up
    .PARAMETER Broadcast
        The Broadcast address of the machine to wake up
    .PARAMETER Port
        The Port that the Wake-on-LAN packet will be sent to
    .EXAMPLE
        Send-WOL -MACAddress 4C-E6-DC-5C-49-E4 -Port 7
        Define an alternative UDP Port
    .EXAMPLE
        Send-WOL -MACAddress 88:1C:84:36:81:A1 -Broadcast 192.168.2.255
        Define a specific Broadcast Address
    #>

    Param (
        [CmdletBinding()]
        [Parameter(Mandatory=$True)]
        [ValidatePattern('(^([0-9a-fA-F]{2}[\.:-]{0,1}){5}[0-9a-fA-F]{2}$)|(^([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})$)')]
        [string]$MACAddress,
        [ipaddress]$Broadcast,
        [int]$Port = 9
    )

    Try {
        # Create broadcast address
        If ($Broadcast) {
            $Broadcast = [System.Net.IPAddress]::Parse($Broadcast)
        }
        Else {
            $Broadcast = [System.Net.IPAddress]::Broadcast
        }

        # Create UDP client instance
        $UdpClient = New-Object Net.Sockets.UdpClient

        # Create IP endpoint for port
        $IPEndPoint = New-Object Net.IPEndPoint $Broadcast, $Port

        # Construct physical address for the MAC address of the machine (string to byte array)
        $MACAddress = (($MACAddress.Replace(":","")).Replace("-","")).Replace(".","")
        $MAC        = [Net.NetworkInformation.PhysicalAddress]::Parse($MACAddress.ToUpper())

        # Construct the Magic Packet frame
        $Packet = [Byte[]](,0xFF*6)+($MAC.GetAddressBytes()*16)

        # Broadcast UDP packets to the IP endpoint of the machine
        $UdpClient.Send($Packet, $Packet.Length, $IPEndPoint) | Out-Null
        $UdpClient.Close()
        Write-Verbose "Wake on Lan request sent to Physical Address [$MACAddress] by Broadcast [$Broadcast] on Port [$Port]"
    }
    Catch {
        # Cleanup after error
        $UdpClient.Dispose()
        Write-Warning "Error sending Wake on Lan request to Physical Address [$MACAddress] by Broadcast [$Broadcast] on Port [$Port]"
    }
}