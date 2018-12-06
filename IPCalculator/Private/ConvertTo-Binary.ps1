Function ConvertTo-Binary {
    [OutputType([string])]
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$DottedDecimal
    )

    # Convert dotted decimal string to binary string
    $DottedDecimal.Split('.') |
        ForEach-Object {
            $Binary = $Binary + $([System.Convert]::ToString($_,2).PadLeft(8,'0'))
        }
    return $Binary
}