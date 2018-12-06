Function ConvertTo-DottedDecimal {
    [OutputType([string])]
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Binary
    )

    # Convert binary string to dotted decimal string
    Do { $DottedDecimal += '.' + [string]$([System.Convert]::ToInt32($Binary.Substring($i,8),2)); $i+=8 }
    While ($i -le 24)
    return $DottedDecimal.Substring(1)
}