Function Invoke-SCCMTask {
    <#
    .SYNOPSIS
        Triggers SCCM to invoke the requested schedule task id
    .DESCRIPTION
        Triggers SCCM to invoke the requested schedule task id
    .PARAMETER ScheduleId
        Name of the schedule id to trigger
        Options: HardwareInventory, SoftwareInventory, HeartbeatDiscovery, SoftwareInventoryFileCollection, RequestMachinePolicy, EvaluateMachinePolicy,
        LocationServicesCleanup, SoftwareMeteringReport, SourceUpdate, PolicyAgentCleanup, RequestMachinePolicy2, CertificateMaintenance, PeerDistributionPointStatus,
        PeerDistributionPointProvisioning, ComplianceIntervalEnforcement, SoftwareUpdatesAgentAssignmentEvaluation, UploadStateMessage, StateMessageManager,
        SoftwareUpdatesScan, AMTProvisionCycle, UpdateStorePolicy, StateSystemBulkSend, ApplicationManagerPolicyAction, PowerManagementStartSummarizer
    .EXAMPLE
        Invoke-SCCMTask 'SoftwareUpdatesScan'
    .EXAMPLE
        Invoke-SCCMTask
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateSet('HardwareInventory','SoftwareInventory','HeartbeatDiscovery','SoftwareInventoryFileCollection','RequestMachinePolicy','EvaluateMachinePolicy','LocationServicesCleanup','SoftwareMeteringReport','SourceUpdate','PolicyAgentCleanup','RequestMachinePolicy2','CertificateMaintenance','PeerDistributionPointStatus','PeerDistributionPointProvisioning','ComplianceIntervalEnforcement','SoftwareUpdatesAgentAssignmentEvaluation','UploadStateMessage','StateMessageManager','SoftwareUpdatesScan','AMTProvisionCycle','UpdateStorePolicy','StateSystemBulkSend','ApplicationManagerPolicyAction','PowerManagementStartSummarizer')]
        [string]$ScheduleID
    )

    Begin {
        # Verbose Logging
        [string]$CmdletName  = $MyInvocation.MyCommand.Name
        [string]$CmdletParam = $PSBoundParameters | Format-Table -Property @{ Label = 'Parameter'; Expression = { "[-$($_.Key)]" } }, @{ Label = 'Value'; Expression = { $_.Value }; Alignment = 'Left' } -AutoSize -Wrap | Out-String
        Write-Verbose "##### Calling : [$CmdletName]"
    }
    Process {
        Try {
            Write-Verbose "Invoke SCCM Schedule Task ID [$ScheduleId]..."

            ## Make sure SCCM client is installed and running
            Write-Verbose 'Check to see if SCCM Client service [ccmexec] is installed and running'
            If ($(Get-Service -Name 'ccmexec' -ErrorAction 'SilentlyContinue').Status -ne 'Running') {
                Throw "SCCM Client Service [ccmexec] exists but it is not in a 'Running' state"
            }
            If (-not $(Get-Service -Name 'ccmexec' -ErrorAction 'SilentlyContinue')) {
                Throw 'SCCM Client Service [ccmexec] does not exist. The SCCM Client may not be installed'
            }

            ## Determine the SCCM Client Version
            Try {
                [version]$SCCMClientVersion = Get-WmiObject -Namespace 'ROOT\CCM' -Class 'CCM_InstalledComponent' -ErrorAction 'Stop' | Where-Object { $_.Name -eq 'SmsClient' } | Select-Object -ExpandProperty 'Version' -ErrorAction 'Stop'
                Write-Verbose "Installed SCCM Client Version Number [$SCCMClientVersion]"
            }
            Catch {
                Throw 'Failed to determine the SCCM client version number.'
            }

            ## Create a hashtable of Schedule IDs compatible with SCCM Client 2007
            [hashtable]$ScheduleIds = @{
                HardwareInventory =                        '{00000000-0000-0000-0000-000000000001}'; # Hardware Inventory Collection Task
                SoftwareInventory =                        '{00000000-0000-0000-0000-000000000002}'; # Software Inventory Collection Task
                HeartbeatDiscovery =                       '{00000000-0000-0000-0000-000000000003}'; # Heartbeat Discovery Cycle
                SoftwareInventoryFileCollection =          '{00000000-0000-0000-0000-000000000010}'; # Software Inventory File Collection Task
                RequestMachinePolicy =                     '{00000000-0000-0000-0000-000000000021}'; # Request Machine Policy Assignments
                EvaluateMachinePolicy =                    '{00000000-0000-0000-0000-000000000022}'; # Evaluate Machine Policy Assignments
                RefreshDefaultMp =                         '{00000000-0000-0000-0000-000000000023}'; # Refresh Default MP Task
                RefreshLocationServices =                  '{00000000-0000-0000-0000-000000000024}'; # Refresh Location Services Task
                LocationServicesCleanup =                  '{00000000-0000-0000-0000-000000000025}'; # Location Services Cleanup Task
                SoftwareMeteringReport =                   '{00000000-0000-0000-0000-000000000031}'; # Software Metering Report Cycle
                SourceUpdate =                             '{00000000-0000-0000-0000-000000000032}'; # Source Update Manage Update Cycle
                PolicyAgentCleanup =                       '{00000000-0000-0000-0000-000000000040}'; # Policy Agent Cleanup Cycle
                RequestMachinePolicy2 =                    '{00000000-0000-0000-0000-000000000042}'; # Request Machine Policy Assignments
                CertificateMaintenance =                   '{00000000-0000-0000-0000-000000000051}'; # Certificate Maintenance Cycle
                PeerDistributionPointStatus =              '{00000000-0000-0000-0000-000000000061}'; # Peer Distribution Point Status Task
                PeerDistributionPointProvisioning =        '{00000000-0000-0000-0000-000000000062}'; # Peer Distribution Point Provisioning Status Task
                ComplianceIntervalEnforcement =            '{00000000-0000-0000-0000-000000000071}'; # Compliance Interval Enforcement
                SoftwareUpdatesAgentAssignmentEvaluation = '{00000000-0000-0000-0000-000000000108}'; # Software Updates Agent Assignment Evaluation Cycle
                UploadStateMessage =                       '{00000000-0000-0000-0000-000000000111}'; # Send Unsent State Messages
                StateMessageManager =                      '{00000000-0000-0000-0000-000000000112}'; # State Message Manager Task
                SoftwareUpdatesScan =                      '{00000000-0000-0000-0000-000000000113}'; # Force Update Scan
                AMTProvisionCycle =                        '{00000000-0000-0000-0000-000000000120}'; # AMT Provision Cycle
            }

            ## If SCCM 2012 Client or higher, modify hashtabe containing Schedule IDs so that it only has the ones compatible with this version of the SCCM client
            If ($SCCMClientVersion.Major -ge 5) {
                $ScheduleIds.Remove('PeerDistributionPointStatus')
                $ScheduleIds.Remove('PeerDistributionPointProvisioning')
                $ScheduleIds.Remove('ComplianceIntervalEnforcement')
                $ScheduleIds.Add('UpdateStorePolicy','{00000000-0000-0000-0000-000000000114}')              # Update Store Policy
                $ScheduleIds.Add('StateSystemBulkSend','{00000000-0000-0000-0000-000000000116}')            # State System Policy Bulk Send Low
                $ScheduleIds.Add('ApplicationManagerPolicyAction','{00000000-0000-0000-0000-000000000121}') # Application Manager Policy Action
                $ScheduleIds.Add('PowerManagementStartSummarizer','{00000000-0000-0000-0000-000000000131}') # Power Management Start Summarizer
            }

            ## Determine if the requested Schedule ID is available on this version of the SCCM Client
            If (-not ($ScheduleIds.ContainsKey($ScheduleId))) {
                Throw "The requested ScheduleId [$ScheduleId] is not available with this version of the SCCM Client [$SCCMClientVersion]."
            }

            ## Trigger SCCM task
            Write-Verbose "Trigger SCCM Task ID [$ScheduleId]"
            [Management.ManagementClass]$SmsClient = [WMIClass]'ROOT\CCM:SMS_Client'
            $null = $SmsClient.TriggerSchedule($ScheduleIds.$ScheduleID)
        }
        Catch {
            Write-Error "Failed to trigger SCCM Schedule Task ID [$($ScheduleIds.$ScheduleId)]"
            Throw "Failed to trigger SCCM Schedule Task ID [$($ScheduleIds.$ScheduleId)]: $($_.Exception.Message)"
        }
    }
    End {
        # Verbose Logging
        Write-Verbose "##### Ending : [$CmdletName]"
    }
}


Function Install-SCCMSoftwareUpdates {
    <#
    .SYNOPSIS
        Scans for outstanding SCCM updates to be installed and installs the pending updates
    .DESCRIPTION
        Scans for outstanding SCCM updates to be installed and installs the pending updates
        Only compatible with SCCM 2012 Client or higher. This function can take several minutes to run
    .PARAMETER SoftwareUpdatesScanWaitInSeconds
        The amount of time to wait in seconds for the software updates scan to complete. Default is: 180 seconds
    .PARAMETER WaitForPendingUpdatesTimeout
        The amount of time to wait for missing and pending updates to install before exiting the function. Default is: 45 minutes
    .EXAMPLE
        Install-SCCMSoftwareUpdates
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [int32]$SoftwareUpdatesScanWaitInSeconds = 180,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [timespan]$WaitForPendingUpdatesTimeout = $(New-TimeSpan -Minutes 45)
    )

    Begin {
        # Verbose Logging
        [string]$CmdletName  = $MyInvocation.MyCommand.Name
        [string]$CmdletParam = $PSBoundParameters | Format-Table -Property @{ Label = 'Parameter'; Expression = { "[-$($_.Key)]" } }, @{ Label = 'Value'; Expression = { $_.Value }; Alignment = 'Left' } -AutoSize -Wrap | Out-String
        Write-Verbose "##### Calling : [$CmdletName]"
    }
    Process {
        Try {
            Write-Verbose 'Scan for and install pending SCCM software updates'

            ## Make sure SCCM client is installed and running
            Write-Verbose 'Check to see if SCCM Client service [ccmexec] is installed and running'
            If ($(Get-Service -Name 'ccmexec' -ErrorAction 'SilentlyContinue').Status -ne 'Running') {
                Throw "SCCM Client Service [ccmexec] exists but it is not in a 'Running' state"
            }
            If (-not $(Get-Service -Name 'ccmexec' -ErrorAction 'SilentlyContinue')) {
                Throw 'SCCM Client Service [ccmexec] does not exist. The SCCM Client may not be installed'
            }

            ## Determine the SCCM Client Version
            Try {
                [version]$SCCMClientVersion = Get-WmiObject -Namespace 'ROOT\CCM' -Class 'CCM_InstalledComponent' -ErrorAction 'Stop' | Where-Object { $_.Name -eq 'SmsClient' } | Select-Object -ExpandProperty 'Version' -ErrorAction 'Stop'
                Write-Verbose "Installed SCCM Client Version Number [$SCCMClientVersion."
            }
            Catch {
                Throw 'Failed to determine the SCCM client version number.'
            }
            #  If SCCM 2007 Client or lower, exit function
            If ($SCCMClientVersion.Major -le 4) {
                Throw 'SCCM 2007 or lower, which is incompatible with this function, was detected on this system'
            }

            $StartTime = Get-Date
            ## Trigger SCCM client scan for Software Updates
            Write-Verbose 'Trigger SCCM client scan for Software Updates...'
            Invoke-SCCMTask -ScheduleId 'SoftwareUpdatesScan'

            Write-Verbose "The SCCM client scan for Software Updates has been triggered. The script is suspended for [$SoftwareUpdatesScanWaitInSeconds] seconds to let the update scan finish"
            Start-Sleep -Seconds $SoftwareUpdatesScanWaitInSeconds

            ## Find the number of missing updates
            Try {
                [Management.ManagementObject[]]$CMMissingUpdates = @(Get-WmiObject -Namespace 'ROOT\CCM\ClientSDK' -Query "SELECT * FROM CCM_SoftwareUpdate WHERE ComplianceState = '0'" -ErrorAction 'Stop')
            }
            Catch {
                Throw 'Failed to find the number of missing software updates.'
            }

            ## Install missing updates and wait for pending updates to finish installing
            If ($CMMissingUpdates.Count) {
                #  Install missing updates
                Write-Verbose "Install missing updates. The number of missing updates is [$($CMMissingUpdates.Count)]"
                $CMInstallMissingUpdates = (Get-WmiObject -Namespace 'ROOT\CCM\ClientSDK' -Class 'CCM_SoftwareUpdatesManager' -List).InstallUpdates($CMMissingUpdates)

                #  Wait for pending updates to finish installing or the timeout value to expire
                Do {
                    Start-Sleep -Seconds 60
                    [array]$CMInstallPendingUpdates = @(Get-WmiObject -Namespace "ROOT\CCM\ClientSDK" -Query "SELECT * FROM CCM_SoftwareUpdate WHERE EvaluationState = 6 or EvaluationState = 7")
                    Write-Verbose "The number of updates pending installation is [$($CMInstallPendingUpdates.Count)]"
                }
                While (($CMInstallPendingUpdates.Count -ne 0) -and ((New-TimeSpan -Start $StartTime -End $(Get-Date)) -lt $WaitForPendingUpdatesTimeout))
            }
            Else {
                Write-Verbose 'There are no missing updates'
            }
        }
        Catch {
            Write-Error "Failed to trigger installation of missing software updates"
                Throw "Failed to trigger installation of missing software updates: $($_.Exception.Message)"
        }
    }
    End {
        # Verbose Logging
        Write-Verbose "##### Ending : [$CmdletName]"
    }
}