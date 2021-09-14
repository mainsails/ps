Function ConvertFrom-SophosTimeOfClickURL {
    <#
    .SYNOPSIS
        Decode Sophos Time of Click URLs
    .DESCRIPTION
        Decode Sophos Time of Click URLs
    .PARAMETER URL
        Specifies the URL(s) to decode
    .EXAMPLE
        ConvertFrom-SophosTimeOfClickURL -URL 'https://eu-west-1.protection.sophos.com/?d=microsoft.com&u=aHR0cHM6Ly93d3cubWljcm9zb2Z0LmNvbS9saWNlbnNpbmcvc2VydmljZWNlbnRlci9kZWZhdWx0LmFzcHg=&'

        EncodedURL : https://eu-west-1.protection.sophos.com/?d=microsoft.com&u=aHR0cHM6Ly93d3cubWljcm9zb2Z0LmNvbS9saWNlbnNpbmcvc2VydmljZWNlbnRlci9kZWZhdWx0LmFzcHg=&
        DecodedURL : https://www.microsoft.com/licensing/servicecenter/default.aspx
    .EXAMPLE
        Get-Clipboard | ConvertFrom-SophosTimeOfClickURL
    #>
    #Requires -Version 3.0

    [CmdLetBinding()]
    Param (
        [Parameter(ValueFromPipeline=$true)]
        [String[]]$URL
    )

    Begin {
        $EncodedURLList = New-Object -TypeName System.Collections.ArrayList
    }
    Process {
        If ($URL) {
            $EncodedURLList.AddRange($URL)
        }
    }
    End {
        $Output = ForEach ($EncodedURL in $EncodedURLList) {
            [PSCustomObject] @{
                EncodedURL = $EncodedURL
                DecodedURL = Try {
                                 $EncodedString = (($EncodedURL -Split '&u=')[1]).Split('&')[0]
                                 [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($EncodedString))
                             }
                             Catch {
                                 Write-Output 'Failed to decode'
                             }
            }
        }
        Write-Output -InputObject $Output | Format-List
    }
}
