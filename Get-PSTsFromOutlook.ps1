$Outlook   = New-Object -ComObject Outlook.Application
$Namespace = $Outlook.GetNamespace('MAPI')
$PSTs      = $Namespace.Stores | Where-Object { ($_.ExchangeStoreType -eq '3') -and ($_.FilePath -like '*.pst') -and ($_.IsDataFileStore -eq $true) }
ForEach ($PST in $PSTs) {
    $PSTFile = Get-Item -Path $PST.FilePath
    [PSCustomObject]@{
        ComputerName  = $env:COMPUTERNAME
        User          = $env:USERNAME
        PSTPath       = $PSTFile.FullName
        PSTSize       = $PSTFile.Length
        PSTLastAccess = $PSTFile.LastAccessTime
        PSTLastWrite  = $PSTFile.LastWriteTime
    }
}