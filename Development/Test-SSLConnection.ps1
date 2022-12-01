Function Test-SSLConnection($FQDN,$Port=443) {
    Try {
        $TCPSocket = New-Object Net.Sockets.TcpClient($FQDN, $Port)
    }
    Catch {
        Write-Warning "$($_.Exception.Message) / $FQDN"
        break
    }
    $TCPStream = $TCPSocket.GetStream()
    ""; "-- Target: $fqdn / " + $tcpSocket.Client.RemoteEndPoint.Address.IPAddressToString
    $SSLStream = New-Object -TypeName Net.Security.SslStream($TCPStream,$false)
    $SSLStream.AuthenticateAsClient($FQDN)
    $certinfo = New-Object -TypeName Security.Cryptography.X509Certificates.X509Certificate2($SSLStream.RemoteCertificate)
    $SSLStream | Select-Object | Format-List -Property SslProtocol,CipherAlgorithm,HashAlgorithm,KeyExchangeAlgorithm,IsAuthenticated,IsEncrypted,IsSigned,CheckCertRevocationStatus
    $CertInfo | Format-List -Property Subject,Issuer,FriendlyName,NotBefore,NotAfter,Thumbprint
    $CertInfo.Extensions | Where-Object -FilterScript { $_.Oid.FriendlyName -like 'subject alt*' } | ForEach-Object -Process { $_.Oid.FriendlyName; $_.Format($true) }
    $TCPSocket.Close()
}
