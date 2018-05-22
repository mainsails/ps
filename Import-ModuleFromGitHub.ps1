Function Import-ModuleFromGitHub {
    <#
    .SYNOPSIS
        Imports a PowerShell Module from a GitHub repository
    .DESCRIPTION
        Downloads and imports a PowerShell Module directly from a GitHub repository
    .PARAMETER Uri
        The Uri of the GitHub hosted PowerShell Module
    .PARAMETER Branch
        The GitHub branch to download
    .EXAMPLE
        Import-ModuleFromGitHub -Uri 'https://github.com/mainsails/SoftwareManagement'
    .EXAMPLE
        $Uri = 'https://github.com/mainsails/PermissionManagement'
        Import-ModuleFromGitHub -Uri $Uri -Verbose
    #>
    #Requires -Version 3.0

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [ValidateScript({ ($_ -match '^https://github.com') })]
        [Alias('Url')]
        [uri[]]$Uri,
        [string]$Branch = 'master'
    )

    Process {
        ForEach ($Module in $Uri) {
            Try {
                $ModuleName    = $Module.AbsolutePath.split('/')[-1]
                $ModuleUri     = "{0}/archive/{1}.zip" -f $Module.AbsoluteUri, $Branch
                $ModulePath    = Join-Path -Path $env:TEMP -ChildPath $ModuleName
                $ModuleArchive = "$ModulePath.zip"

                Try {
                    # Download PowerShell Module
                    Write-Verbose -Message ("Downloading PowerShell Module [{0}] :: Branch [{1}] :: Source :: [{2}]" -f $Module.AbsolutePath, $Branch, $Host)
                    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
                    Invoke-RestMethod -Uri $ModuleUri -OutFile $ModuleArchive -ErrorAction Stop
                }
                Catch {
                    Write-Warning -Message "Failed to download module : $($_.Exception.Message)"
                    Continue
                }
                # Unblock downloaded archive
                Unblock-File -Path $ModuleArchive
                # Extract downloaded archive
                Write-Verbose -Message "Extracting PowerShell Module [$ModuleArchive]"
                Expand-Archive -Path $ModuleArchive -DestinationPath $env:TEMP -Force
                If (Test-Path -Path $ModulePath) { Remove-Item -Path $ModulePath -Recurse -Force }
                Rename-Item -Path "$($ModulePath)-$($Branch)" -NewName $ModuleName -Force
                # Import extracted module
                Import-Module -Name $ModulePath
            }
            Catch {
                Write-Warning -Message "Failed to import module : $($_.Exception.Message)"
            }
        }
    }
}