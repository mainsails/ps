# Set Windows Optional Feature name
$WindowsOptionalFeatureName = 'NetFx3'

# Detect Windows Optional Feature
If ((Get-WindowsOptionalFeature -Online -FeatureName $WindowsOptionalFeatureName).State -eq 'Enabled') {
    Write-Host "$WindowsOptionalFeatureName is enabled" 
    Exit 0
}
Else {
    Write-Host "$WindowsOptionalFeatureName is not enabled"
    Exit 1
}
