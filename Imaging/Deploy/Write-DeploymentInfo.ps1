$RegistryPath = 'HKLM:\Software\Image'
$Time         = Get-Date -Format 'yyyyMMdd-HHmm'

$RegistrySite = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
$Site         = Get-ItemPropertyValue -Path $RegistrySite -Name 'DynamicSiteName'

If (!(Test-Path -Path $RegistryPath)) {
    New-Item -Path $RegistryPath -Force
}

If ($Time) { New-ItemProperty -Path $RegistryPath -Name 'DeployedOn' -Value $Time -PropertyType 'String' -Force }
If ($Site) { New-ItemProperty -Path $RegistryPath -Name 'DeploySite' -Value $Site -PropertyType 'String' -Force }