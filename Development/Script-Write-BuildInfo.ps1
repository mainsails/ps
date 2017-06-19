$Reg       = 'HKLM:\Software\BHFT'
$OSVersion = (Get-WmiObject -Class Win32_OperatingSystem).Caption
$OSBuild   = Get-Date -Format 'yyyyMMdd'

New-Item         -Path $Reg -Force
New-ItemProperty -Path $Reg -Name 'OSVersion' -Value $OSVersion -PropertyType 'String' -Force
New-ItemProperty -Path $Reg -Name 'OSBuild'   -Value $OSBuild   -PropertyType 'String' -Force