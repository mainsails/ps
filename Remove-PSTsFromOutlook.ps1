$Outlook   = New-Object -ComObject Outlook.Application
$Namespace = $Outlook.GetNamespace('MAPI')
$PSTs      = $Namespace.Stores | Where-Object { ($_.ExchangeStoreType -eq '3') -and ($_.FilePath -like '*.pst') -and ($_.IsDataFileStore -eq $true) }
ForEach ($PST in $PSTs) {
    $Outlook.Session.RemoveStore($PST.GetRootFolder())
}