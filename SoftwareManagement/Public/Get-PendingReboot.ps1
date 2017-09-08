Function Get-PendingReboot {
    <#
    .SYNOPSIS
        Get the pending reboot status on a local computer
    .DESCRIPTION
        Check WMI and the registry to determine if the system has a pending reboot operation from any of the following:
        a) Component Based Servicing
        b) Windows Update / Auto Update
        c) SCCM 2012 Clients (DetermineIfRebootPending WMI method)
        d) Pending File Rename Operations
    .EXAMPLE
        Get-PendingReboot

        Returns custom object with following properties:
        ComputerName, LastBootUpTime, IsSystemRebootPending, IsCBServicingRebootPending, IsWindowsUpdateRebootPending, IsSCCMClientRebootPending, IsFileRenameRebootPending, PendingFileRenameOperations, ErrorMsg

        *Notes: ErrorMsg only contains something if an error occurred
    .EXAMPLE
        (Get-PendingReboot).IsSystemRebootPending
        Returns boolean value determining whether or not there is a pending reboot operation.
    #>

    [CmdletBinding()]
    Param ()

    Begin {
        # Verbose Logging
        [string]$CmdletName  = $MyInvocation.MyCommand.Name
        [string]$CmdletParam = $PSBoundParameters | Format-Table -Property @{ Label = 'Parameter'; Expression = { "[-$($_.Key)]" } }, @{ Label = 'Value'; Expression = { $_.Value }; Alignment = 'Left' } -AutoSize -Wrap | Out-String
        Write-Verbose -Message "##### Calling : [$CmdletName]"

        ## Initialize variables
        [string]$ComputerName = ([Net.Dns]::GetHostEntry('')).HostName
        $PendRebootErrorMsg = $null
    }
    Process {
        Write-Verbose -Message "Get the pending reboot status on the local computer [$ComputerName]"

        ## Get the date/time that the system last booted up
        Try {
            [nullable[datetime]]$LastBootUpTime = (Get-Date -ErrorAction 'Stop') - ([timespan]::FromMilliseconds([math]::Abs([Environment]::TickCount)))
        }
        Catch {
            [nullable[datetime]]$LastBootUpTime = $null
            [string[]]$PendRebootErrorMsg += "Failed to get LastBootUpTime: $($_.Exception.Message)"
            Write-Warning -Message 'Failed to get LastBootUpTime'
        }

        ## Determine if the machine has a pending reboot from a Component Based Servicing (CBS) operation
        Try {
            If ([Environment]::OSVersion.Version.Major -ge 5) {
                If (Test-Path -LiteralPath 'HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending' -ErrorAction 'Stop') {
                    [nullable[boolean]]$IsCBServicingRebootPending = $true
                }
                Else {
                    [nullable[boolean]]$IsCBServicingRebootPending = $false
                }
            }
        }
        Catch {
            [nullable[boolean]]$IsCBServicingRebootPending = $null
            [string[]]$PendRebootErrorMsg += "Failed to get IsCBServicingRebootPending: $($_.Exception.Message)"
            Write-Warning -Message 'Failed to get IsCBServicingRebootPending'
        }

        ## Determine if there is a pending reboot from a Windows Update
        Try {
            If (Test-Path -LiteralPath 'HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired' -ErrorAction 'Stop') {
                [nullable[boolean]]$IsWindowsUpdateRebootPending = $true
            }
            Else {
                [nullable[boolean]]$IsWindowsUpdateRebootPending = $false
            }
        }
        Catch {
            [nullable[boolean]]$IsWindowsUpdateRebootPending = $null
            [string[]]$PendRebootErrorMsg += "Failed to get IsWindowsUpdateRebootPending: $($_.Exception.Message)"
            Write-Warning -Message 'Failed to get IsWindowsUpdateRebootPending'
        }

        ## Determine if there is a pending reboot from a pending file rename operation
        [boolean]$IsFileRenameRebootPending = $false
        $PendingFileRenameOperations = $null
        If (Get-ItemProperty -LiteralPath 'HKLM:SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'PendingFileRenameOperations' -ErrorAction SilentlyContinue) {
            # If PendingFileRenameOperations value exists, set $IsFileRenameRebootPending variable to $true
            [boolean]$IsFileRenameRebootPending = $true
            # Get the value of PendingFileRenameOperations
            Try {
                [string[]]$PendingFileRenameOperations = Get-ItemProperty -LiteralPath 'HKLM:SYSTEM\CurrentControlSet\Control\Session Manager' -ErrorAction 'Stop' | Select-Object -ExpandProperty 'PendingFileRenameOperations' -ErrorAction 'Stop'
            }
            Catch {
                [string[]]$PendRebootErrorMsg += "Failed to get PendingFileRenameOperations: $($_.Exception.Message)"
                Write-Warning -Message 'Failed to get PendingFileRenameOperations'
            }
        }

        ## Determine SCCM 2012 Client reboot pending status
        Try {
            Try {
                [boolean]$IsSccmClientNamespaceExists = [boolean](Get-WmiObject -Namespace 'ROOT\CCM\ClientSDK' -List -ErrorAction 'Stop' | Where-Object { $_.Name -eq 'CCM_ClientUtilities' })
            }
            Catch [System.Management.ManagementException] {
                $CmdException = $_
                If ($CmdException.FullyQualifiedErrorId -eq 'INVALID_NAMESPACE_IDENTIFIER,Microsoft.PowerShell.Commands.GetWmiObjectCommand') {
                    [boolean]$IsSccmClientNamespaceExists = $false
                }
            }

            If ($IsSccmClientNamespaceExists) {
                [psobject]$SCCMClientRebootStatus = Invoke-WmiMethod -ComputerName $ComputerName -NameSpace 'ROOT\CCM\ClientSDK' -Class 'CCM_ClientUtilities' -Name 'DetermineIfRebootPending' -ErrorAction 'Stop'
                If ($SCCMClientRebootStatus.ReturnValue -ne 0) {
                    Throw "'DetermineIfRebootPending' method of 'ROOT\CCM\ClientSDK\CCM_ClientUtilities' class returned error code [$($SCCMClientRebootStatus.ReturnValue)]"
                }
                Else {
                    [nullable[boolean]]$IsSCCMClientRebootPending = $false
                    If ($SCCMClientRebootStatus.IsHardRebootPending -or $SCCMClientRebootStatus.RebootPending) {
                        [nullable[boolean]]$IsSCCMClientRebootPending = $true
                    }
                }
            }
            Else {
                [nullable[boolean]]$IsSCCMClientRebootPending = $null
            }
        }
        Catch {
            [nullable[boolean]]$IsSCCMClientRebootPending = $null
            [string[]]$PendRebootErrorMsg += "Failed to get IsSCCMClientRebootPending: $($_.Exception.Message)"
            Write-Warning -Message 'Failed to get IsSCCMClientRebootPending'
        }

        ## Determine if there is a pending reboot for the system
        [boolean]$IsSystemRebootPending = $false
        If ($IsCBServicingRebootPending -or $IsWindowsUpdateRebootPending -or $IsSCCMClientRebootPending -or $IsFileRenameRebootPending) {
            [boolean]$IsSystemRebootPending = $true
        }

        ## Create a custom object containing pending reboot information for the system
        [psobject]$PendingRebootInfo = New-Object -TypeName 'PSObject' -Property @{
            ComputerName                 = $ComputerName
            LastBootUpTime               = $LastBootUpTime
            IsSystemRebootPending        = $IsSystemRebootPending
            IsCBServicingRebootPending   = $IsCBServicingRebootPending
            IsWindowsUpdateRebootPending = $IsWindowsUpdateRebootPending
            IsSCCMClientRebootPending    = $IsSCCMClientRebootPending
            IsFileRenameRebootPending    = $IsFileRenameRebootPending
            PendingFileRenameOperations  = $PendingFileRenameOperations
            ErrorMsg                     = $PendRebootErrorMsg
        }
    }
    End {
        Write-Output -InputObject ($PendingRebootInfo | Select-Object -Property 'ComputerName','LastBootUpTime','IsSystemRebootPending','IsCBServicingRebootPending','IsWindowsUpdateRebootPending','IsSCCMClientRebootPending','IsFileRenameRebootPending','PendingFileRenameOperations','ErrorMsg')

        # Verbose Logging
        Write-Verbose -Message "##### Ending : [$CmdletName]"
    }
}