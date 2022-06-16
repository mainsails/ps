Param (
    [Parameter(Mandatory=$true)]
    [ValidateSet('Enable','Disable')]
    [string]$Action = 'Enable'
)

# Set Windows Optional Feature name
[string]$WindowsOptionalFeatureName = 'NetFx3'

If ($Action -eq 'Enable') {
    # Enable Windows Optional Feature
    $Result = Enable-WindowsOptionalFeature -Online -FeatureName $WindowsOptionalFeatureName -NoRestart
}

If ($Action -eq 'Disable') {
    # Disable Windows Optional Feature
    $Result = Disable-WindowsOptionalFeature -Online -FeatureName $WindowsOptionalFeatureName -NoRestart
}

If ($Result.RestartNeeded -eq $true) {
    # Set restart required exit code
    exit 3010
}
