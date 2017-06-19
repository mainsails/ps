Function Convert-OutputForCSV {
    <#
    .SYNOPSIS
      Provides a way to expand collections in an object property prior
      to being sent to Export-Csv.

    .DESCRIPTION
      Provides a way to expand collections in an object property prior
      to being sent to Export-Csv. This helps to avoid the object type
      from being shown such as system.object[] in a spreadsheet.

    .PARAMETER InputObject
      The object that will be sent to Export-Csv

    .PARAMETER OutputPropertyType
      This determines whether the property that has the collection will be
      shown in the CSV as a comma delimited string or as a stacked string.

      Possible values:
      Stack
      Comma

    .EXAMPLE
      $Output = 'PSComputername','IPAddress','DNSServerSearchOrder'

      Get-WMIObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled='True'" |
      Select-Object $Output | Convert-OutputForCSV |
      Export-Csv -NoTypeInformation -Path NIC.csv

      Description
      -----------
      Using a predefined set of properties to display ($Output), data is collected from the
      Win32_NetworkAdapterConfiguration class and then passed to the Convert-OutputForCSV
      function which expands any property with a collection so it can be read properly prior
      to being sent to Export-Csv. Properties that had a collection will be viewed as a stack
      in the spreadsheet.

    #>
    #Requires -Version 3.0
    
    [Cmdletbinding()]
    Param (
        [parameter(ValueFromPipeline)]
        [psobject]$InputObject,
        [parameter()]
        [ValidateSet('Stack','Comma')]
        [string]$OutputPropertyType = 'Stack'
    )
    
    Begin {
        $PSBoundParameters.GetEnumerator() | ForEach {
            Write-Verbose "$($_)"
        }
        $FirstRun = $True
    }
    Process {
        If ($FirstRun) {
            $OutputOrder = $InputObject.psobject.properties.name
            Write-Verbose "Output Order:`n $($OutputOrder -join ', ' )"
            $FirstRun = $False
            #Get properties to process
            $Properties = Get-Member -InputObject $InputObject -MemberType *Property
            #Get properties that hold a collection
            $Properties_Collection = @(($Properties | Where-Object {
                $_.Definition -match "Collection|\[\]"
            }).Name)
            #Get properties that do not hold a collection
            $Properties_NoCollection = @(($Properties | Where-Object {
                $_.Definition -notmatch "Collection|\[\]"
            }).Name)
            Write-Verbose "Properties found that have collections:`n $(($Properties_Collection) -join ', ')"
            Write-Verbose "Properties found that have no collections:`n $(($Properties_NoCollection) -join ', ')"
        }

        $InputObject | ForEach {
            $Line = $_
            $stringBuilder = New-Object Text.StringBuilder
            $Null = $StringBuilder.AppendLine("[pscustomobject] @{")

            $OutputOrder | ForEach {
                If ($OutputPropertyType -eq 'Stack') {
                    $Null = $StringBuilder.AppendLine("`"$($_)`" = `"$(($line.$($_) | Out-String).Trim())`"")
                } ElseIf ($OutputPropertyType -eq "Comma") {
                    $Null = $StringBuilder.AppendLine("`"$($_)`" = `"$($line.$($_) -join ', ')`"")
                }
            }
            $Null = $StringBuilder.AppendLine("}")

            Invoke-Expression $StringBuilder.ToString()
        }
    }
    End {}
}