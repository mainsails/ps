Function Test-IPv4Address {
    <#
    .SYNOPSIS
        Tests one or more IP Addresses to determine if they are valid.
    .DESCRIPTION
        Tests one or more IP Addresses to determine if they are valid.
    .PARAMETER IPv4Address
        One or more IP Addresses to test.
    .INPUTS
        System.String
    .OUTPUTS
        System.Net.IPAddress
    .EXAMPLE
        Test-IPv4Address -IPv4Address 192.168.0.1

        Address            : 16820416
        AddressFamily      : InterNetwork
        ScopeId            :
        IsIPv6Multicast    : False
        IsIPv6LinkLocal    : False
        IsIPv6SiteLocal    : False
        IsIPv6Teredo       : False
        IsIPv4MappedToIPv6 : False
        IPAddressToString  : 192.168.0.1
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,Position=0)]
        [ValidateScript({ [IPAddress]$_ })]
        [string[]]$IPv4Address
    )

    Begin {
        $AddressList = New-Object -TypeName System.Collections.ArrayList
    }
    Process {
        If ($IPv4Address) {
            $AddressList.AddRange($IPv4Address)
        }
    }
    End {
        ForEach ($Address in $AddressList) {
            [IPAddress]$Address
        }
    }
}