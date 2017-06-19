Function Get-InstalledApplication {

    <#
    .Synopsis
        Retrieves information about installed applications.
    .Description
        Retrieves information about installed applications by querying the registry. You can specify an application name, a product code, or both.
        Returns information about application publisher, name & version, product code, uninstall string, install source, location, date, and application architecture.
    .PARAMETER Name
        The name of the application to retrieve information for. Performs a contains match on the application display name by default.
    .PARAMETER Exact
        Specifies that the named application must be matched using the exact name.
    .Example
        Get-InstalledApplication -Name '7-Zip'
        InstallSource      : C:\Users\shaws\Desktop\
        UninstallString    : MsiExec.exe /I{23170F69-40C1-2702-1604-000001000000}
        UninstallSubkey    : {23170F69-40C1-2702-1604-000001000000}
        InstallLocation    : 
        ProductCode        : {23170F69-40C1-2702-1604-000001000000}
        Is64BitApplication : True
        Publisher          : Igor Pavlov
        InstallDate        : 20170112
        DisplayVersion     : 16.04.00.0
        DisplayName        : 7-Zip 16.04 (x64 edition)
    .Example
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
		[ValidateScript({$_ -match $MSIProductCodeRegExPattern})]
		[string[]]$ProductCode,
		[Parameter(Mandatory=$false)]
		[switch]$IncludeUpdatesAndHotfixes
	)

	Begin {
        # RegEx Pattern
        [string]$Script:MSIProductCodeRegExPattern = '^(\{{0,1}([0-9a-fA-F]){8}-([0-9a-fA-F]){4}-([0-9a-fA-F]){4}-([0-9a-fA-F]){4}-([0-9a-fA-F]){12}\}{0,1})$'

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
                        Write-Warning "Unable to enumerate properties from registry key path [$($InstalledApp.PSPath)]"
                        Continue
                    }
                }
            }
        }
    }

    Process {
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

            # Verify if there is a match with the product code passed to the script
            If ($ProductCode) {
                ForEach ($Application in $ProductCode) {
                    If ($RegKeyApp.PSChildName -match [regex]::Escape($Application)) {
                        Write-Verbose "Found installed application [$AppDisplayName] version [$AppDisplayVersion] matching product code [$Application]"
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

            # Verify if there is a match with the application name(s) passed to the script
            If ($Name) {
                ForEach ($Application in $Name) {
                    $ApplicationMatched = $false
                    If ($Exact) {
                        #  Check for an exact application name match
                        If ($RegKeyApp.DisplayName -eq $Application) {
                            $ApplicationMatched = $true
                            Write-Verbose "Found installed application [$AppDisplayName] version [$AppDisplayVersion] using exact name matching for search term [$Application]"
                        }
                    }

                    #  Check for a wildcard application name match
                    ElseIf ($RegKeyApp.DisplayName -match [regex]::Escape($Application)) {
                        $ApplicationMatched = $true
                        Write-Verbose "Found installed application [$AppDisplayName] version [$AppDisplayVersion] using regex matching for search term [$Application]"
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
        }
    }

    End {
        # Output to console
        Write-Output -InputObject $InstalledApplication
    }

}