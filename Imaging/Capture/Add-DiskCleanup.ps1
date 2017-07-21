## Disk Cleanup
#  Add and create Disk Cleanup shortcut to Windows Desktop
#  Windows Server 2008 R2

# Copy Prerequisites
Copy-Item -Path "$env:windir\winsxs\amd64_microsoft-windows-cleanmgr_31bf3856ad364e35_6.1.7600.16385_none_c9392808773cd7da\cleanmgr.exe" -Destination "$env:windir\System32"
Copy-Item -Path "$env:windir\winsxs\amd64_microsoft-windows-cleanmgr.resources_31bf3856ad364e35_6.1.7600.16385_en-us_b9cb6194b257cc63\cleanmgr.exe.mui" -Destination "$env:windir\System32\en-US"

# Create Shortcut
$WshShell = New-Object -comObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("$env:PUBLIC\Desktop\Disk Cleanup.lnk")
$Shortcut.TargetPath = "$env:windir\System32\cleanmgr.exe"
$Shortcut.Save()