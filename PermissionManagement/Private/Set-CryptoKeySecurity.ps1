Function Set-CryptoKeySecurity {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory=$true)]
        [Security.AccessControl.CryptoKeySecurity]$CryptoKeySecurity,
        [Parameter(Mandatory=$true)]
        [string]$Action
   )

    $KeyContainerInfo = $Certificate.PrivateKey.CspKeyContainerInfo
    $CspParams = New-Object 'Security.Cryptography.CspParameters' ($KeyContainerInfo.ProviderType, $KeyContainerInfo.ProviderName, $KeyContainerInfo.KeyContainerName)
    $CspParams.Flags = [Security.Cryptography.CspProviderFlags]::UseExistingKey
    $CspParams.KeyNumber = $KeyContainerInfo.KeyNumber
    If ((Split-Path -NoQualifier -Path $Certificate.PSPath) -like 'LocalMachine\*') {
        $CspParams.Flags = $CspParams.Flags -bor [Security.Cryptography.CspProviderFlags]::UseMachineKeyStore
    }
    $CspParams.CryptoKeySecurity = $CryptoKeySecurity

    Try {
        # Persist the rule change
        If ($PSCmdlet.ShouldProcess(('{0} ({1})' -f $Certificate.Subject,$Certificate.Thumbprint), $Action)) {
            $null = New-Object 'Security.Cryptography.RSACryptoServiceProvider' ($CspParams)
        }
    }
    Catch {
        $ActualException = $_.Exception
        While ($ActualException.InnerException) {
            $ActualException = $ActualException.InnerException
        }
        Write-Error ('Failed to {0} to ''{1}'' ({2}) certificate''s private key: {3}: {4}' -f $Action,$Certificate.Subject,$Certificate.Thumbprint,$ActualException.GetType().FullName,$ActualException.Message)
    }
}