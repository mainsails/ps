Function Start-MSP {
    <#
    .SYNOPSIS
        Execute MSP Patch on applicable systems
    .DESCRIPTION
        Reads SummaryInfo targeted product codes in MSP file and determines if the MSP file applies to any installed products
        If a valid installed product is found, the Start-MSI function is triggered to patch the installation
    .PARAMETER Path
        The path to the MSP file
    .PARAMETER PassThru
        Returns ExitCode, STDOut, and STDErr output from the process
    .PARAMETER ContinueOnError
        Continue if an exit code is returned by msiexec that is not recognized. Default is: $true
    .EXAMPLE
        Start-MSP -Path 'C:\Path\To\File\Adobe_Acrobat_DC_x64_EN.msp'
    .LINK
        Start-MSI
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateScript({ ('.msp' -contains [IO.Path]::GetExtension($_))} )]
        [string]$Path,
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
        # Set the full path to the MSP
        If (Test-Path -LiteralPath $Path -ErrorAction 'SilentlyContinue') {
            [string]$mspFile = (Get-Item -LiteralPath $Path).FullName
        }
        Else {
            Throw "Failed to find MSP file [$Path]"
        }

        # Check MSP is applicable to the system
        Write-Verbose -Message 'Checking MSP file for valid product codes'
        [boolean]$IsMSPNeeded = $false
        $Installer = New-Object -ComObject WindowsInstaller.Installer
        $Database = $Installer.GetType().InvokeMember("OpenDatabase", "InvokeMethod", $Null, $Installer, $($mspFile,([int32]32)))
        [__comobject]$SummaryInformation = Get-ObjectProperty -InputObject $Database -PropertyName 'SummaryInformation'
        [hashtable]$SummaryInfoProperty = @{}
        $InstallerProperties = (Get-ObjectProperty -InputObject $SummaryInformation -PropertyName 'Property' -ArgumentList @(7)).Split(";")
        Write-Verbose -Message 'Checking System for MSP product codes'
        ForEach ($FormattedProductCode in $InstallerProperties) {
            [psobject]$MSIInstalled = Get-InstalledApplication -ProductCode $FormattedProductCode -Verbose:$False
            If ($MSIInstalled) {
                Write-Verbose -Message "Found Applicable Product : [$($MSIInstalled.ProductCode)] - [$($MSIInstalled.DisplayName)]"
                [boolean]$IsMSPNeeded = $true
            }
        }
        Try { $null = [Runtime.Interopservices.Marshal]::ReleaseComObject($SummaryInformation) } Catch {}
        Try { $null = [Runtime.Interopservices.Marshal]::ReleaseComObject($DataBase) } Catch {}
        Try { $null = [Runtime.Interopservices.Marshal]::ReleaseComObject($Installer) } Catch {}

        # Install MSP if required
        If ($IsMSPNeeded) {
            Start-MSI -Action Patch -Path $Path -PassThru $PassThru -ContinueOnError $ContinueOnError
        }
        Else {
            If ($ContinueOnError) {
                Write-Warning -Message "MSP is not applicable to this System : [$(Split-Path -Path $Path -Leaf)]"
            }
            Else {
                Throw "MSP is not applicable to this System : [$(Split-Path -Path $Path -Leaf)]"
            }
        }
    }
    End {
        # Verbose Logging
        Write-Verbose -Message "##### Ending : [$CmdletName]"
    }
}