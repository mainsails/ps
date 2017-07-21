# Windows 2008R2 Sysprep fix (after installing WMF 5.1)
# https://social.technet.microsoft.com/Forums/en-US/425bd101-8a87-488c-b2e2-9f2f8113a0d9/sysprep-fatal-error-occurred-while-trying-to-sysprep-the-machine?forum=w7itproinstall

$Key = 'HKLM:\SOFTWARE\Microsoft\Windows\StreamProvider'
$Name = 'LastFullPayloadTime'
$Value = 0
$PropertyType = 'DWORD'

# Create registry key if it doesn't exist
If (-not (Test-Path -LiteralPath $Key -ErrorAction 'Stop')) {
    $null = New-Item -Path $Key -ItemType 'Registry' -Force -ErrorAction 'Stop'
}
# Set registry value if it doesn't exist
 If (-not (Get-ItemProperty -LiteralPath $Key -Name $Name -ErrorAction 'SilentlyContinue')) {
    $null = New-ItemProperty -LiteralPath $Key -Name $Name -Value $Value -PropertyType $Type -Force
}
# Update registry value if it does exist
Else {
    [string]$RegistryValueWriteAction = 'update'
    $null = Set-ItemProperty -LiteralPath $Key -Name $Name -Value $Value
}