return

# Define imaging infrastructure
[string]$DeploymentShare   = 'MDT-Production'
[string]$DeploymentAccount = 'ImagingAccount'
[string]$DeploymentServer  = 'ImagingServer'
[string[]]$SiteServers     = @(
    'SiteServer1',
    'SiteServer2',
    'SiteServer3'
)

# Prepare server roles
$WindowsFeatures = @(
    'FS-DFS-Replication',
    'WDS'
)
$SiteServers + $DeploymentServer |
    ForEach-Object -Process {
        Install-WindowsFeature -Name $WindowsFeatures -IncludeManagementTools -ComputerName $_
    }

# Create deployment share folder structure
$SiteServers |
    ForEach-Object -Process {
        If (-not (Test-Path "\\$_\C$\$DeploymentShare")) {
            New-Item -Path "\\$_\C$\$DeploymentShare" -Type Directory | Out-Null
        }
    }
# Create deployment SMB share
$SiteServers |
    ForEach-Object -Process {
        $Session = New-CimSession -ComputerName $_
        If (-not (Get-SmbShare -Name "$DeploymentShare$" -CimSession $Session -ErrorAction SilentlyContinue)) {
            New-SmbShare -Name "$DeploymentShare$" -Path "C:\$DeploymentShare" -FullAccess "$env:USERDOMAIN\$DeploymentAccount" -CimSession $Session | Out-Null
        }
        Remove-CimSession -CimSession $Session
    }

# Create DFSR replication group
New-DfsReplicationGroup -GroupName $DeploymentShare
# Create DFSR replication folder
New-DfsReplicatedFolder -GroupName $DeploymentShare -FolderName $DeploymentShare
Add-DfsrMember -GroupName $DeploymentShare -ComputerName $($SiteServers + $DeploymentServer)
$SiteServers |
    ForEach-Object -Process {
        Add-DfsrConnection -GroupName $DeploymentShare -SourceComputerName $DeploymentServer -DestinationComputerName $_
    }
# Set DFSR Schedule : [Full Bandwidth 20:00-08:00] [No replication 08:01-19:59]
$Schedule = 'FFFFFFFFFFFFFFFF0000000000000000000000000000000000000000000000000000000000000000FFFFFFFFFFFFFFFF'
Set-DfsrGroupSchedule -GroupName $DeploymentShare -Day Monday,Tuesday,Wednesday,Thursday,Friday,Saturday,Sunday -BandwidthDetail $Schedule
# Configure DFSR membership settings for the primary member of the replication group and set an appropriate quota/conflict size
Set-DfsrMembership -GroupName $DeploymentShare -FolderName $DeploymentShare -ContentPath "E:\$DeploymentShare" -ComputerName $DeploymentServer -PrimaryMember $true -StagingPathQuotaInMB 28672 -ConflictAndDeletedQuotaInMB 8192 -Force
# Configure DFSR membership settings for the receiving members of the replication group and set an appropriate quota/conflict size
$SiteServers |
    ForEach-Object -Process {
        Set-DfsrMembership -GroupName $DeploymentShare -FolderName $DeploymentShare -ContentPath "C:\$DeploymentShare" -ComputerName $_ -StagingPathQuotaInMB 28672 -ConflictAndDeletedQuotaInMB 8192 -Force
    }

# Configure WDS Role
$SiteServers |
    ForEach-Object -Process {
        Invoke-Command -ComputerName $_ -ArgumentList $DeploymentShare -ScriptBlock {
            Param ($DeploymentShare)
            WDSUTIL /Initialize-Server /Standalone /RemInst:'C:\RemoteInstall'
            WDSUTIL /Set-Server /AnswerClients:All
            WDSUTIL /Add-Image /ImageFile:"C:\$DeploymentShare\Boot\LiteTouchPE_x64.wim" /ImageType:Boot
            WDSUTIL /Set-TransportServer /EnableTftpVariableWindowExtension:No
            Restart-Service -Name WDSServer
        }
    }

# Restart DFSR service to remove 'One or more replicated folders have sharing violations' bug in health report
Get-Service -Name 'DFSR' -ComputerName $DeploymentServer | Restart-Service

return

# Maintenance
# Check replication backlog
$SiteServers |
    ForEach-Object -Process {
        Get-DfsrBacklog -GroupName $DeploymentShare -FolderName $DeploymentShare -SourceComputerName $DeploymentServer -DestinationComputerName $_ -Verbose
    }

# Force replication for 60 minutes
$SiteServers |
    ForEach-Object -Process {
        Sync-DfsReplicationGroup -GroupName $DeploymentShare -SourceComputerName $DeploymentServer -DestinationComputerName $_ -DurationInMinutes 60
    }

# Update WDS Boot Images
$SiteServers |
    ForEach-Object -Process {
        Invoke-Command -ComputerName $_ -ArgumentList $DeploymentShare -ScriptBlock {
            Param($DeploymentShare)
            WDSUTIL /Replace-Image /Image:$DeploymentShare /ImageType:Boot /Architecture:x64 /ReplacementImage /ImageFile:"C:\$DeploymentShare\Boot\LiteTouchPE_x64.wim"
        }
    }