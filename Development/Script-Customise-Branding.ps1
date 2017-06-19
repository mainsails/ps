# Prepare Environment
$TSEnv = New-Object -COMObject Microsoft.SMS.TSEnvironment

# Media
$Avatar = "$TSEnv:DEPLOYROOT\Branding\Media\OEMLogo.bmp"

# Prep
$AvatarFile = Split-Path -Leaf -Path $Avatar

# Set OEM/System Information
$OEMInfo = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\OEMInformation'
$Model   = Get-WmiObject win32_computersystem

If ((Test-Path "$env:windir\System32\oobe\info") -eq $false) {
    New-Item "$env:windir\System32\oobe\info" -ItemType Directory
}
Copy-Item        -Path $Avatar  -Destination "$env:windir\System32\oobe\info\$AvatarFile"
Set-ItemProperty -Path $OEMInfo -Name Logo         -Value "$env:windir\System32\oobe\info\$AvatarFile"
Set-ItemProperty -Path $OEMInfo -Name Manufacturer -Value "Berkshire Healthcare NHS Foundation Trust"
Set-ItemProperty -Path $OEMInfo -Name SupportPhone -Value "0300 365 2438"
Set-ItemProperty -Path $OEMInfo -Name SupportURL   -Value "https://support.berkshire.nhs.uk"