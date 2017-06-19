# Create Working Directory
$CertPath = "$env:TEMP\CertReq"
If (Test-Path -Path $CertPath) { Remove-Item -Path $CertPath -Recurse -Force | Out-Null }
New-Item -Path $CertPath -ItemType Directory | Out-Null

# Certificate INF Contents
$CertInf = @()
$CertInf += '[Version]'
$CertInf += '"$Windows NT$"'
$CertInf += ''
$CertInf += '[NewRequest]'
$CertInf += "Subject = `"CN=$($env:COMPUTERNAME).Berkshire.nhs.uk`""
$CertInf += 'Exportable = FALSE'
$CertInf += 'KeyLength = 2048'
$CertInf += 'KeySpec = 1'
$CertInf += 'KeyUsage = 0xA0'
$CertInf += 'MachineKeySet = True'
$CertInf += 'ProviderName = "Microsoft Enhanced Cryptographic Provider v1.0"'
$CertInf += 'SMIME = False'
$CertInf += 'RequestType = PKCS10'
$CertInf += 'Silent = True'
# Generate INF
$CertInf | Out-File -FilePath "$CertPath\ComputerCert.inf"

# SHA1
# Check and Wait for Connection to CA (KEVCA)
Do { $TestConnection = Test-Connection -ComputerName 'KEVCA.Berkshire.nhs.uk' -Quiet -Count 1 } Until ($TestConnection)
# Create a New Request
CertReq -New "$CertPath\ComputerCert.inf" "$CertPath\ComputerCert.csr" | Out-Null
# Submit Request to CA
CertReq -Submit -attrib 'CertificateTemplate:BerkshireComputer' -config 'KEVCA.Berkshire.nhs.uk\Berkshire-KEVCA-CA' -AdminForceMachine "$CertPath\ComputerCert.csr" "$CertPath\ComputerCert.cer" | Out-Null
# Install the Certificate
CertReq -Accept "$CertPath\ComputerCert.cer" | Out-Null
# Clean Up
If (Test-Path -Path $CertPath) { Remove-Item -Path "$CertPath\*" -Recurse -Exclude 'ComputerCert.inf' -Force | Out-Null }

# SHA256
# Check and Wait for Connection to CA (CA1)
Do { $TestConnection = Test-Connection -ComputerName 'CA1.Berkshire.nhs.uk' -Quiet -Count 1 } Until ($TestConnection)
# Create a New Request
CertReq -New "$CertPath\ComputerCert.inf" "$CertPath\ComputerCert.csr" | Out-Null
# Submit Request to CA
CertReq -Submit -attrib 'CertificateTemplate:DA Computer' -config 'CA1.Berkshire.nhs.uk\Berkshire Issuing CA1' -AdminForceMachine "$CertPath\ComputerCert.csr" "$CertPath\ComputerCert.cer" | Out-Null
# Install the Certificate
CertReq -Accept "$CertPath\ComputerCert.cer" | Out-Null
# Clean Up
If (Test-Path -Path $CertPath) { Remove-Item -Path "$CertPath\*" -Recurse -Exclude 'ComputerCert.inf' -Force | Out-Null }