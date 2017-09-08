Function Remove-MSI {
    <#
    .SYNOPSIS
        Removes all MSI applications matching the specified application name
    .DESCRIPTION
        Removes all MSI applications matching the specified application name
        Enumerates the registry for installed applications matching the specified application name and uninstalls that application using the product code, provided the uninstall string matches "msiexec"
    .PARAMETER Name
        The name of the application to uninstall. Performs a regex match on the application display name by default
    .PARAMETER Exact
        Specifies that the named application must be matched using the exact name
    .PARAMETER CustomParameters
        Overrides the default uninstall parameters. Uninstall default parameters are : "REBOOT=ReallySuppress /QN"
    .PARAMETER FilterApplication
        Two-dimensional array that contains one or more (property, value, match-type) sets that should be used to filter the list of results returned by Get-InstalledApplication to only those that should be uninstalled
        Properties that can be filtered upon: ProductCode, DisplayName, DisplayVersion, UninstallString, InstallSource, InstallLocation, InstallDate, Publisher, Is64BitApplication
    .PARAMETER ExcludeFromUninstall
        Two-dimensional array that contains one or more (property, value, match-type) sets that should be excluded from uninstall if found
        Properties that can be excluded: ProductCode, DisplayName, DisplayVersion, UninstallString, InstallSource, InstallLocation, InstallDate, Publisher, Is64BitApplication
    .PARAMETER PassThru
        Returns ExitCode, STDOut, and STDErr output from the process
    .PARAMETER ContinueOnError
        Continue if an exit code is returned by msiexec that is not recognized. Default is: $true
    .EXAMPLE
        Remove-MSI -Name 'Adobe Flash'
        Removes all versions of software that match the name "Adobe Flash"
    .EXAMPLE
        Remove-MSI -Name 'Adobe'
        Removes all versions of software that match the name "Adobe"
    .EXAMPLE
        Remove-MSI -Name 'Java 8' -FilterApplication ('Is64BitApplication', $false, 'Exact'),('Publisher', 'Oracle Corporation', 'Exact')
        Removes all versions of software that match the name "Java 8" where the software is 32-bits and the publisher is "Oracle Corporation"
    .EXAMPLE
        Remove-MSI -Name 'Java 8' -FilterApplication (,('Publisher', 'Oracle Corporation', 'Exact')) -ExcludeFromUninstall (,('DisplayName', 'Java 8 Update 45', 'RegEx'))
        Removes all versions of software that match the name "Java 8" and also have "Oracle Corporation" as the Publisher; however, it will not uninstall "Java 8 Update 45"
        NOTE: if only specifying a single row in the two-dimensional arrays, the array must have the extra parentheses and leading comma as per the example
    .EXAMPLE
        Remove-MSI -Name 'Java 8' -ExcludeFromUninstall (,('DisplayName', 'Java 8 Update 45', 'RegEx'))
        Removes all versions of software that match the name "Java 8"; however, it does not uninstall "Java 8 Update 45" of the software.
        NOTE: if only specifying a single row in the two-dimensional array, the array must have the extra parentheses and leading comma as in this example
    .EXAMPLE
        Remove-MSI -Name 'Java 8 Update' -ExcludeFromUninstall
            ('Is64BitApplication', $true, 'Exact'),
            ('DisplayName', 'Java 8 Update 45', 'Exact'),
            ('DisplayName', 'Java 8 Update 4*', 'WildCard'),
            ('DisplayName', 'Java 8 Update 45', 'RegEx')
        Removes all versions of software that match the name "Java 8 Update"; however, it does not uninstall 64-bit versions of the software, Update 45 of the software, or any Update that starts with 4.
    .NOTES
        Information on -FilterApplication or -ExcludeFromUninstall parameters: http://blogs.msdn.com/b/powershell/archive/2007/01/23/array-literals-in-powershell.aspx
    .LINK
        Start-MSI
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [string]$Name,
        [Parameter(Mandatory=$false)]
        [switch]$Exact = $false,
        [Parameter(Mandatory=$false)]
        [Alias('Arguments')]
        [ValidateNotNullorEmpty()]
        [string]$CustomParameters,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [array]$FilterApplication = @(@()),
        [Parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [array]$ExcludeFromUninstall = @(@()),
        [Parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [switch]$PassThru = $false,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [boolean]$ContinueOnError = $true
    )

    Begin {
        # Verbose Logging
        [string]$CmdletName  = $MyInvocation.MyCommand.Name
        [string]$CmdletParam = $PSBoundParameters | Format-Table -Property @{ Label = 'Parameter'; Expression = { "[-$($_.Key)]" } }, @{ Label = 'Value'; Expression = { $_.Value }; Alignment = 'Left' } -AutoSize -Wrap | Out-String
        Write-Verbose -Message "##### Calling : [$CmdletName]"
    }
    Process {
        # Build the hashtable with the options that will be passed to Get-InstalledApplication using splatting
        [hashtable]$GetInstalledApplicationSplat = @{ Name = $Name }
        If ($Exact) { $GetInstalledApplicationSplat.Add( 'Exact', $Exact) }
        [psobject[]]$InstalledApplications = Get-InstalledApplication @GetInstalledApplicationSplat
        Write-Verbose -Message "Found [$($InstalledApplications.Count)] application(s) that matched the specified criteria [$Name]"

        # Filter the results from Get-InstalledApplication
        [Collections.ArrayList]$RemoveMSIApplications = New-Object -TypeName 'System.Collections.ArrayList'
        If (($null -ne $InstalledApplications) -and ($InstalledApplications.Count)) {
            ForEach ($InstalledApplication in $InstalledApplications) {
                If ($InstalledApplication.UninstallString -notmatch 'msiexec') {
                    Write-Warning -Message "Skipping removal of application [$($InstalledApplication.DisplayName)] because uninstall string [$($InstalledApplication.UninstallString)] does not match `"msiexec`""
                    Continue
                }
                If ([string]::IsNullOrEmpty($InstalledApplication.ProductCode)) {
                    Write-Warning -Message "Skipping removal of application [$($InstalledApplication.DisplayName)] because unable to discover MSI ProductCode from application's registry Uninstall subkey [$($InstalledApplication.UninstallSubkey)]"
                    Continue
                }

                # Filter the results from Get-InstalledApplication to only those that should be uninstalled
                If (($null -ne $FilterApplication) -and ($FilterApplication.Count)) {
                    Write-Verbose -Message "Filter the results to only those that should be uninstalled as specified in parameter [-FilterApplication]"
                    [boolean]$AddAppToRemoveList = $false
                    ForEach ($Filter in $FilterApplication) {
                        If ($Filter[2] -eq 'RegEx') {
                            If ($installedApplication.($Filter[0]) -match [regex]::Escape($Filter[1])) {
                                [boolean]$AddAppToRemoveList = $true
                                Write-Verbose -Message "Preserve removal of application [$($InstalledApplication.DisplayName) $($InstalledApplication.Version)] because of regex match against [-FilterApplication] criteria"
                            }
                        }
                        ElseIf ($Filter[2] -eq 'WildCard') {
                            If ($installedApplication.($Filter[0]) -like $Filter[1]) {
                                [boolean]$AddAppToRemoveList = $true
                                Write-Verbose -Message "Preserve removal of application [$($InstalledApplication.DisplayName) $($InstalledApplication.Version)] because of wildcard match against [-FilterApplication] criteria"
                            }
                        }
                        ElseIf ($Filter[2] -eq 'Exact') {
                            If ($installedApplication.($Filter[0]) -eq $Filter[1]) {
                                [boolean]$AddAppToRemoveList = $true
                                Write-Verbose -Message "Preserve removal of application [$($InstalledApplication.DisplayName) $($InstalledApplication.Version)] because of exact match against [-FilterApplication] criteria"
                            }
                        }
                    }
                }
                Else {
                    [boolean]$AddAppToRemoveList = $true
                }

                # Filter the results from Get-InstalledApplication to remove those that should never be uninstalled
                If (($null -ne $ExcludeFromUninstall) -and ($ExcludeFromUninstall.Count)) {
                    Write-Verbose -Message "Filter the results to only those that should be uninstalled as specified in parameter [-ExcludeFromUninstall]"
                    ForEach ($Exclude in $ExcludeFromUninstall) {
                        If ($Exclude[2] -eq 'RegEx') {
                            If ($installedApplication.($Exclude[0]) -match [regex]::Escape($Exclude[1])) {
                                [boolean]$AddAppToRemoveList = $false
                                Write-Verbose -Message "Skipping removal of application [$($InstalledApplication.DisplayName) $($InstalledApplication.Version)] because of regex match against [-ExcludeFromUninstall] criteria"
                            }
                        }
                        ElseIf ($Exclude[2] -eq 'WildCard') {
                            If ($installedApplication.($Exclude[0]) -like $Exclude[1]) {
                                [boolean]$AddAppToRemoveList = $false
                                Write-Verbose -Message "Skipping removal of application [$($InstalledApplication.DisplayName) $($InstalledApplication.Version)] because of wildcard match against [-ExcludeFromUninstall] criteria"
                            }
                        }
                        ElseIf ($Exclude[2] -eq 'Exact') {
                            If ($installedApplication.($Exclude[0]) -eq $Exclude[1]) {
                                [boolean]$AddAppToRemoveList = $false
                                Write-Verbose -Message "Skipping removal of application [$($InstalledApplication.DisplayName) $($InstalledApplication.Version)] because of exact match against [-ExcludeFromUninstall] criteria"
                            }
                        }
                    }
                }

                If ($AddAppToRemoveList) {
                    Write-Verbose -Message "Adding application to list for removal: [$($InstalledApplication.DisplayName) $($InstalledApplication.Version)]"
                    $RemoveMSIApplications.Add($InstalledApplication) | Out-Null
                }
            }
        }

        # Build the hashtable with the options that will be passed to Start-MSI using splatting
        [hashtable]$ExecuteMSISplat =  @{ Action = 'Uninstall'; Path = '' }
        If ($CustomParameters) { $ExecuteMSISplat.Add( 'CustomParameters', $CustomParameters) }
        If ($PassThru) { $ExecuteMSISplat.Add( 'PassThru', $PassThru) }
        If ($ContinueOnError) { $ExecuteMSISplat.Add( 'ContinueOnError', $ContinueOnError) }

        # Remove the MSI Applications
        If (($null -ne $RemoveMSIApplications) -and ($RemoveMSIApplications.Count)) {
            ForEach ($RemoveMSIApplication in $RemoveMSIApplications) {
                Write-Verbose -Message "Remove application [$($RemoveMSIApplication.DisplayName) $($RemoveMSIApplication.Version)]"
                $ExecuteMSISplat.Path = $RemoveMSIApplication.ProductCode
                If ($PassThru) {
                    [psobject[]]$ExecuteResults += Start-MSI @ExecuteMSISplat
                }
                Else {
                    Start-MSI @ExecuteMSISplat
                }
            }
        }
        Else {
            Write-Verbose -Message 'No applications found for removal'
        }
    }
    End {
        If ($PassThru) { Write-Output -InputObject $ExecuteResults }
        # Verbose Logging
        Write-Verbose -Message "##### Ending : [$CmdletName]"
    }
}