Param (
    [Parameter(Mandatory=$true)]
    [ValidateSet('Install','Uninstall','Detect')]
    [string]$Mode = 'Install',
    [Parameter(Mandatory=$true)]
    [string]$WindowsOptionalFeatureName
)
 
If ($Mode -eq 'Install') {
    # Enable Windows Optional Feature
    $Result = Enable-WindowsOptionalFeature -Online -FeatureName $WindowsOptionalFeatureName -NoRestart
    If ($Result.RestartNeeded -eq $true) {
        exit 3010
    }
    Else {
        exit 0
    }
}
 
If ($Mode -eq 'Uninstall') {
    # Disable Windows Optional Feature
    $Result = Disable-WindowsOptionalFeature -Online -FeatureName $WindowsOptionalFeatureName -Remove -NoRestart
    If ($Result.RestartNeeded -eq $true) {
        exit 3010
    }
    Else {
        exit 0
    }
}

If ($Mode -eq 'Detect') {
    # Detect Windows Optional Feature
    $Result = Get-WindowsOptionalFeature -Online -FeatureName $WindowsOptionalFeatureName
    If ($Result.State -eq 'Enabled') {
        Write-Output "$WindowsOptionalFeatureName is enabled"
        exit 0
    }
    Else {
        exit 1
    }
}
