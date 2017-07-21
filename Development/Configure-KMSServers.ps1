#Requires -Version 5.1

# Legitimate KMS Server
$KMSServer = 'KMSServer'

# Check / Activate ScriptBlock
$ScriptBlock = {
    # Get KMS Details for the computer
    $KMSservice = Get-WmiObject -Query 'select * from SoftwareLicensingService'
    # Check computer is running as a KMS Server
    If ($KMSservice.IsKeyManagementServiceMachine -eq 1) {
        # Get OS and set default KMS Key
        $OSVersion = (Get-WmiObject -Class Win32_OperatingSystem).Caption
        Switch -Regex -Exact ($OSVersion.Trim()) {
            'Microsoft Windows 7 Enterprise'  { $KMSKey = '33PXH-7Y6KF-2VJC9-XBBR8-HVTHH' }
            'Microsoft Windows 10 Enterprise' { $KMSKey = 'NPPR9-FWDCX-D2C8J-H872K-2YT43' }
        }
        # Stop if KMS Server is not running our standard client OS
        If (-not $KMSKey) {
            Write-Warning "[$env:COMPUTERNAME] Invalid OS for KMS Removal [$OSVersion]"
            return
        }
        # Activate
        Write-Output "[$env:COMPUTERNAME] Activating Windows"
        $null = $KMSservice.InstallProductKey($KMSKey)
        $null = $KMSservice.RefreshLicenseStatus()
        # Remove DNS entry
        # ToDo (manually?)
    }
    Else { Write-Warning "[$env:COMPUTERNAME] Not running as a KMS Server" }
}

Try {
    # Validate KMS Server
    $KMSServer = [System.Net.Dns]::GetHostEntry($KMSServer).Hostname

    # Get Domain
    $KMSDomain = $KMSServer.Substring($KMSServer.IndexOf('.') + 1)

    # Get Invalid KMS Servers on the domain and filter object
    $KMSServers = Resolve-DnsName -Type SRV -Name "_vlmcs._tcp.$KMSDomain" | Where-Object { ($_.Name -ne $KMSServer) -and ($_.Name -notmatch '_vlmcs._tcp') }
}
Catch {
    Throw 'Error Checking DNS'
}

# Run Check / Activate ScriptBlock
Foreach ($KMSServer in $KMSServers) {
    Try { Invoke-Command -ComputerName $KMSServer.Name -ScriptBlock $ScriptBlock -ErrorAction Stop }
    Catch { Write-Warning "[$($KMSServer.Name)] Connection Error" }
}
