Function Get-InstalledApplication {
    <#
    .SYNOPSIS
        Retrieves information on installed applications
    .DESCRIPTION
        Retrieves information about installed applications by querying the registry. You can specify an application's name, a product code, or both
        Returns information about application's publisher, name & version, product code, uninstall string, install source, location, date, and application architecture
    .PARAMETER Name
        The name of the application to retrieve information on. Performs a regex match on the application display name by default
    .PARAMETER Exact
        Specifies that the named application must be matched using the exact name
    .PARAMETER ProductCode
        The product code of the application to retrieve information for
    .PARAMETER IncludeUpdatesAndHotfixes
        Include matches against updates and hotfixes in results
    .EXAMPLE
        Get-InstalledApplication -Name '7-Zip'
        InstallSource      : C:\Installers\
        UninstallString    : MsiExec.exe /I{23170F69-40C1-2702-1604-000001000000}
        UninstallSubkey    : {23170F69-40C1-2702-1604-000001000000}
        InstallLocation    :
        ProductCode        : {23170F69-40C1-2702-1604-000001000000}
        Is64BitApplication : True
        Publisher          : Igor Pavlov
        InstallDate        : 20170822
        DisplayVersion     : 16.04.00.0
        DisplayName        : 7-Zip 16.04 (x64 edition)

        This command returns all installed applications matching a wildcard product name search for '7-Zip'
    .EXAMPLE
        Get-InstalledApplication -ProductCode '{23170F69-40C1-2702-1604-000001000000}'
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [string[]]$Name,
        [Parameter(Mandatory=$false)]
        [switch]$Exact = $false,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [string[]]$ProductCode,
        [Parameter(Mandatory=$false)]
        [switch]$IncludeUpdatesAndHotfixes
    )

    Begin {
        # Verbose Logging
        [string]$CmdletName  = $MyInvocation.MyCommand.Name
        [string]$CmdletParam = $PSBoundParameters | Format-Table -Property @{ Label = 'Parameter'; Expression = { "[-$($_.Key)]" } }, @{ Label = 'Value'; Expression = { $_.Value }; Alignment = 'Left' } -AutoSize -Wrap | Out-String
        Write-Verbose -Message "##### Calling : [$CmdletName]"

        # RegEx Pattern
        [string]$MSIProductCodeRegExPattern = '^(\{{0,1}([0-9a-fA-F]){8}-([0-9a-fA-F]){4}-([0-9a-fA-F]){4}-([0-9a-fA-F]){4}-([0-9a-fA-F]){12}\}{0,1})$'
    }
    Process {
        # Enumerate installed applications from the registry for applications that have a "DisplayName" property
        $RegKeyApplication  = @()
        $RegKeyApplications = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall')
        ForEach ($RegKey in $RegKeyApplications) {
            If (Test-Path -LiteralPath $RegKey -ErrorAction 'SilentlyContinue') {
                $InstalledApps = Get-ChildItem -LiteralPath $RegKey -ErrorAction 'SilentlyContinue'
                ForEach ($InstalledApp in $InstalledApps) {
                    Try {
                        $RegKeyApplicationProps = Get-ItemProperty -LiteralPath $InstalledApp.PSPath -ErrorAction 'Stop'
                        If ($RegKeyApplicationProps.DisplayName) {
                            $RegKeyApplication += $RegKeyApplicationProps
                        }
                    }
                    Catch {
                        Continue
                    }
                }
            }
        }

        # Create a sanitised object with the desired properties for the installed applications
        $InstalledApplication = @()
        ForEach ($RegKeyApp in $RegKeyApplication) {
            # Bypass Updates
            If (-not $IncludeUpdatesAndHotfixes) {
                If ($RegKeyApp.DisplayName -match '(?i)kb\d+')         { Continue }
                If ($RegKeyApp.DisplayName -match 'Cumulative Update') { Continue }
                If ($RegKeyApp.DisplayName -match 'Security Update')   { Continue }
                If ($RegKeyApp.DisplayName -match 'Hotfix')            { Continue }
            }

            # Remove problematic characters
            [string]$AppDisplayName    = $RegKeyApp.DisplayName    -replace '[^\u001F-\u007F]',''
            [string]$AppDisplayVersion = $RegKeyApp.DisplayVersion -replace '[^\u001F-\u007F]',''
            [string]$AppPublisher      = $RegKeyApp.Publisher      -replace '[^\u001F-\u007F]',''

            ## Determine if application is a 64-bit application
            [boolean]$Is64BitApp = If (([Environment]::Is64BitOperatingSystem -eq $true) -and ($RegKeyApp.PSPath -notmatch '^Microsoft\.PowerShell\.Core\\Registry::HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node')) { $true } Else { $false }

            # Verify that there is a match with the product code passed to the script
            If ($ProductCode) {
                ForEach ($Application in $ProductCode) {
                    If ($RegKeyApp.PSChildName -match [regex]::Escape($Application)) {
                        Write-Verbose -Message "Found installed application [$AppDisplayName] version [$AppDisplayVersion] matching product code [$Application]"
                        $InstalledApplication += New-Object -TypeName 'PSObject' -Property @{
                            UninstallSubkey    = $RegKeyApp.PSChildName
                            ProductCode        = If ($RegKeyApp.PSChildName -match $MSIProductCodeRegExPattern) { $RegKeyApp.PSChildName } Else { [string]::Empty }
                            DisplayName        = $AppDisplayName
                            DisplayVersion     = $AppDisplayVersion
                            UninstallString    = $RegKeyApp.UninstallString
                            InstallSource      = $RegKeyApp.InstallSource
                            InstallLocation    = $RegKeyApp.InstallLocation
                            InstallDate        = $RegKeyApp.InstallDate
                            Publisher          = $AppPublisher
                            Is64BitApplication = $Is64BitApp
                        }
                    }
                }
            }

            # Verify that there is a match with the application name(s) passed to the script
            If ($Name) {
                ForEach ($Application in $Name) {
                    $ApplicationMatched = $false
                    If ($Exact) {
                        # Check for an exact application name match
                        If ($RegKeyApp.DisplayName -eq $Application) {
                            $ApplicationMatched = $true
                            Write-Verbose -Message "Found installed application [$AppDisplayName] version [$AppDisplayVersion] using exact name matching for search term [$Application]"
                        }
                    }
                    # Check for a regex application name match
                    ElseIf ($RegKeyApp.DisplayName -match [regex]::Escape($Application)) {
                        $ApplicationMatched = $true
                        Write-Verbose -Message "Found installed application [$AppDisplayName] version [$AppDisplayVersion] using regex matching for search term [$Application]"
                    }

                    If ($ApplicationMatched) {
                        $InstalledApplication += New-Object -TypeName 'PSObject' -Property @{
                            UninstallSubkey    = $RegKeyApp.PSChildName
                            ProductCode        = If ($RegKeyApp.PSChildName -match $MSIProductCodeRegExPattern) { $RegKeyApp.PSChildName } Else { [string]::Empty }
                            DisplayName        = $AppDisplayName
                            DisplayVersion     = $AppDisplayVersion
                            UninstallString    = $RegKeyApp.UninstallString
                            InstallSource      = $RegKeyApp.InstallSource
                            InstallLocation    = $RegKeyApp.InstallLocation
                            InstallDate        = $RegKeyApp.InstallDate
                            Publisher          = $AppPublisher
                            Is64BitApplication = $Is64BitApp
                        }
                    }
                }
            }

            # Verify that a full search is requested
            If ((-not $Name) -and (-not $ProductCode) -and (-not $Exact)) {
                $InstalledApplication += New-Object -TypeName 'PSObject' -Property @{
                    UninstallSubkey    = $RegKeyApp.PSChildName
                    ProductCode        = If ($RegKeyApp.PSChildName -match $MSIProductCodeRegExPattern) { $RegKeyApp.PSChildName } Else { [string]::Empty }
                    DisplayName        = $AppDisplayName
                    DisplayVersion     = $AppDisplayVersion
                    UninstallString    = $RegKeyApp.UninstallString
                    InstallSource      = $RegKeyApp.InstallSource
                    InstallLocation    = $RegKeyApp.InstallLocation
                    InstallDate        = $RegKeyApp.InstallDate
                    Publisher          = $AppPublisher
                    Is64BitApplication = $Is64BitApp
                }
            }
        }

        # Output Object
        Write-Output -InputObject $InstalledApplication
    }
    End {
        # Verbose Logging
        Write-Verbose -Message "##### Ending : [$CmdletName]"
    }
}