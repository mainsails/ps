Function ConvertTo-InverseBinary {
    [OutputType([string])]
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Binary
    )

    # Invert binary string
    ForEach ($Bit in [char[]]$Binary) {
        If     ($Bit -eq "1") { $InverseBinary += '0' }
        ElseIf ($Bit -eq "0") { $InverseBinary += '1' }
    }
    return $InverseBinary
}