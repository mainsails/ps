Function Get-PathProvider {
    <#
    .SYNOPSIS
        Returns a path's PowerShell provider
    .DESCRIPTION
        When you want to do something with a path that depends on its provider, use this Function. The path doesn't have to exist
        If you pass in a relative path, it is resolved relative to the current directory so make sure you're in the right place
    .PARAMETER Path
        The path whose provider to get
    .EXAMPLE
        Get-PathProvider -Path 'C:\Windows'
        Demonstrates how to get the path provider for an NTFS path
    .OUTPUTS
        System.Management.Automation.ProviderInfo
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Path
    )

    $PathQualifier = Split-Path -Qualifier $Path -ErrorAction SilentlyContinue
    If (-not $PathQualifier) {
        $Path = Join-Path -Path (Get-Location) -ChildPath $Path
        $PathQualifier = Split-Path -Qualifier $Path -ErrorAction SilentlyContinue
        If (-not $PathQualifier)  {
            Write-Error "Qualifier for path '$Path' not found."
            return
        }
    }

    $PathQualifier = $PathQualifier.Trim(':')
    $Drive = Get-PSDrive -Name $PathQualifier -ErrorAction Ignore
    If (-not $Drive) {
        $Drive = Get-PSDrive -PSProvider $PathQualifier -ErrorAction Ignore
    }

    If (-not $Drive) {
        Write-Error -Message ('Unable to determine the provider for path {0}.' -f $Path)
        return
    }

    $Drive  |
    Select-Object -First 1 |
    Select-Object -ExpandProperty 'Provider'

}