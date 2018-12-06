Function Convert-SubnetMask {
    <#
    .SYNOPSIS
        Convert a subnet mask between a dotted decimal netmask, CIDR, wildcard mask and binary.
    .DESCRIPTION
        Convert a subnet mask between a quad-dotted decimal netmask (eg. '255.255.255.0'), a CIDR prefix (eg. '24'), a quad-dotted decimal wildcard mask (eg. '0.0.0.255') and a binary string (eg. '11111111111111111111111100000000').
    .PARAMETER Netmask
        The dotted decimal subnet mask to convert into a CIDR prefix, dotted decimal wildcard mask and binary string.
    .PARAMETER CIDR
        The CIDR prefix to convert into a dotted decimal subnet mask, dotted decimal wildcad mask and binary string.
    .PARAMETER Binary
        The binary string to convert into a dotted decimal subnet mask, CIDR prefix and dotted decimal wildcard mask.
    .PARAMETER Wildcard
        The dotted decimal wildcard mask to convert into a dotted decimal subnet mask and CIDR prefix.
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    .EXAMPLE
        Convert-SubnetMask -Netmask 255.255.0.0
        Netmask     CIDR Wildcard    Binary
        ----        ---- --------    ------
        255.255.0.0   16 0.0.255.255 11111111111111110000000000000000
    .EXAMPLE
        Convert-SubnetMask -CIDR 24

        Netmask       CIDR Wildcard  Binary
        ----          ---- --------  ------
        255.255.255.0   24 0.0.0.255 11111111111111111111111100000000
    .EXAMPLE
        Convert-SubnetMask -Binary 11111111111111111111111111111100

        Netmask         CIDR Wildcard Binary
        ----            ---- -------- ------
        255.255.255.252   30 0.0.0.3  11111111111111111111111111111100
    #>

    [CmdLetBinding(DefaultParameterSetName='Netmask')]
    Param (
        [Parameter(ParameterSetName='Netmask',Position=0,Mandatory=$true)]
        [ValidateScript({ $_ -match "^(254|252|248|240|224|192|128|0).0.0.0$|^255.(254|252|248|240|224|192|128|0).0.0$|^255.255.(254|252|248|240|224|192|128|0).0$|^255.255.255.(255|254|252|248|240|224|192|128|0)$" })]
        [Alias('Mask','DottedDecimal')]
        [string]$Netmask,
        [Parameter(ParameterSetName='CIDR',Position=0,Mandatory=$true)]
        [ValidateRange(0,32)]
        [Int32]$CIDR,
        [Parameter(ParameterSetName='Binary',Position=0,Mandatory=$true)]
        [ValidateScript({ ($_ -notmatch '01') -and ($_.Length -eq 32) -and ($_ -match '[01]') })]
        [string]$Binary,
        [Parameter(ParameterSetName='Wildcard',Position=0,Mandatory=$true)]
        [ValidateScript({ $_ -match "^(255|127|63|31|15|7|3|1).255.255.255$|^0.(255|127|63|31|15|7|3|1).255.255$|^0.0.(255|127|63|31|15|7|3|1).255$|^0.0.0.(255|127|63|31|15|7|3|1|0)$" })]
        [string]$Wildcard
    )

    Begin {}
    Process {
        Switch ($PSCmdlet.ParameterSetName) {
            'Netmask' {
                # Convert quad-dotted decimal netmask to binary string netmask
                $Binary = ConvertTo-Binary -DottedDecimal $Netmask
            }
            'CIDR' {
                # Convert CIDR prefix to binary string netmask
                $Binary = ('1' * $CIDR).PadRight(32,'0')
            }
            'Wildcard' {
                # Convert quad-dotted decimal wildcard mask to binary string netmask
                $Binary = ConvertTo-InverseBinary -Binary $(ConvertTo-Binary -DottedDecimal $Wildcard)
            }
        }
        # Convert binary string netmask to quad-dotted decimal netmask
        If (-not ($Netmask)) { $Netmask = ConvertTo-DottedDecimal -Binary $Binary }
        # Convert binary string netmask to CIDR prefix
        If (-not ($CIDR)) { $CIDR = ($Binary.TrimEnd('0')).Length }
        # Convert binary string netmask to quad-dotted decimal wildcard mask
        If (-not ($Wildcard)) { $Wildcard = ConvertTo-DottedDecimal -Binary $(ConvertTo-InverseBinary -Binary $Binary) }

        ## Build object and output
        [PSCustomObject]@{
            'Netmask'  = $Netmask
            'CIDR'     = $CIDR
            'Wildcard' = $Wildcard
            'Binary'   = $Binary
        }
    }
    End {}
}