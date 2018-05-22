Function Import-ModuleFromGitHub {
    <#
    .SYNOPSIS
        Imports a PowerShell Module from a GitHub repository
    .DESCRIPTION
        Downloads and imports a PowerShell Module directly from a GitHub repository
    .PARAMETER Uri
        The Uri of the GitHub hosted PowerShell Module (raw psm1)
    .EXAMPLE
        Import-ModuleFromGitHub -Uri 'https://raw.githubusercontent.com/mainsails/ps/master/ClientConfigurationManager.psm1'
    .EXAMPLE
        $Uri = 'https://raw.githubusercontent.com/mainsails/ps/master/ApplicationManagement.psm1'
        Import-ModuleFromGitHub -Uri $Uri -Verbose
    #>
    #Requires -Version 3.0

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [ValidateScript({ ($_ -match '^https?') })]
        [Alias('Url')]
        [string[]]$Uri
    )

    Begin {
        # Verbose Logging
        [string]$CmdletName  = $MyInvocation.MyCommand.Name
        [string]$CmdletParam = $PSBoundParameters | Format-Table -Property @{ Label = 'Parameter'; Expression = { "[-$($_.Key)]" } }, @{ Label = 'Value'; Expression = { $_.Value }; Alignment = 'Left' } -AutoSize -Wrap | Out-String
        Write-Verbose -Message "##### Calling : [$CmdletName]"
    }
    Process {
        Foreach ($Address in $Uri) {
            Try {
                $Module = Split-Path -Path $Address -Leaf
                $Destination = $env:TEMP + '\' + $Module
                Try {
                    # Download PowerShell Module
                    Write-Verbose -Message "Downloading PowerShell Module [$Module] from Uri [$Address]"
                    Invoke-WebRequest -Uri $Address -UseBasicParsing -OutFile $Destination -ErrorAction Stop
                }
                Catch {
                    Write-Warning -Message "Failed to download module : $($_.Exception.Message)"
                    Continue
                }
                # Import PowerShell Module
                Write-Verbose -Message "Importing PowerShell Module [$Module] from File [$Destination]"
                Import-Module -Name $Destination -DisableNameChecking -Force -ErrorAction Stop
                # Remove PowerShell Module Source
                Write-Verbose -Message "Removing PowerShell Module Source [$Destination]"
                Remove-Item -Path $Destination -Force
            }
            Catch {
                Write-Warning -Message "Failed to import module : $($_.Exception.Message)"
            }
        }
    }
    End {
        # Verbose Logging
        Write-Verbose -Message "##### Ending : [$CmdletName]"
    }
}
