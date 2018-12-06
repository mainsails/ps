Function Get-IPv4Calculation {
    <#
    .SYNOPSIS
        Get-IPv4Calculation calculates the IP subnet information based upon the entered IP address and netmask.
    .DESCRIPTION
        Get-IPv4Calculation calculates the resulting broadcast, network, wildcard mask and host range based upon the entered IP address and netmask.
    .PARAMETER Address
        Enter the IP address with netmask in CIDR notation.
    .EXAMPLE
        Get-IPv4Calculation -Address 10.10.100.5/24

        Address   : 10.10.100.5
        Netmask   : 255.255.255.0
        Wildcard  : 0.0.0.255
        Network   : 10.10.100.0/24
        Broadcast : 10.10.100.255
        HostMin   : 10.10.100.1
        HostMax   : 10.10.100.254
        Hosts/Net : 254
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateScript({ [IPAddress]$_.Split('/')[0] -and (($_.Split('/')[1] -ge 0) -and ($_.Split('/')[1] -le 32)) })]
        [string]$Address
    )

    Begin {}
    Process {
        $IP       = $Address.Split('/')[0]
        $Prefix   = [System.Convert]::ToInt32($Address.Split('/')[1])
        $Netmask  = Convert-SubnetMask -CIDR $Prefix
        $IPBinary = ConvertTo-Binary -DottedDecimal $IP

        # Identify subnet boundaries
        $NetworkBinary   = $IPBinary.Substring(0,$($Netmask.CIDR)).PadRight(32,'0')
        $BroadCastBinary = $IPBinary.Substring(0,$($Netmask.CIDR)).PadRight(32,'1')
        $Network         = ConvertTo-DottedDecimal -Binary $NetworkBinary
        $BroadCast       = ConvertTo-DottedDecimal -Binary $BroadCastBinary
        $StartAddress    = ConvertTo-DottedDecimal -Binary $($IPBinary.Substring(0,$($Netmask.CIDR)).PadRight(31,'0') + '1')
        $EndAddress      = ConvertTo-DottedDecimal -Binary $($IPBinary.Substring(0,$($Netmask.CIDR)).PadRight(31,'1') + '0')
        $HostsPerNet     = ([System.Convert]::ToInt32($BroadCastBinary,2) - [System.Convert]::ToInt32($NetworkBinary,2)) - '1'

        [PSCustomObject]@{
            'Address'     = $IP
            'Netmask'     = $Netmask.Netmask
            'Wildcard'    = $Netmask.Wildcard
            'Network'     = "$Network/$($Netmask.CIDR)"
            'Broadcast'   = $BroadCast
            'HostMin'     = $StartAddress
            'HostMax'     = $EndAddress
            'HostsPerNet' = $HostsPerNet
        }
    }
    End {}
}