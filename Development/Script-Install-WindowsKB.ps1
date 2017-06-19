$KBArticle = "KB3102433","KB2952664","KB3142037","KB3118401","KB3114410","KB3123862"

# Update Service
Write-Host "Configuring Update Service" -ForegroundColor Green
Set-Service wuauserv -StartupType Manual -Status Running
$WUServiceManager = New-Object -ComObject 'Microsoft.Update.ServiceManager'
$WUSession        = New-Object -ComObject 'Microsoft.Update.Session'
$WUSearcher       = $WUSession.CreateUpdateSearcher()
Foreach ($WUService in $WUServiceManager.Services) {
    If ($WUService.Name -eq "Microsoft Update") {
        $WUSearcher.ServerSelection = 3
        $WUSearcher.ServiceID       = $WUService.ServiceID
        $ServiceName                = $WUService.Name
    }
}

# Update Search
Write-Host "Searching for Updates" -ForegroundColor Green
$Search       = 'IsInstalled = 0 and RebootRequired = 0'
$SearchResult = $WUSearcher.Search($Search)

# Update Choose
$UpdateCollection = New-Object -ComObject 'Microsoft.Update.UpdateColl'
Foreach($Update in $SearchResult.Updates) {
    Foreach($KB in $KBArticle) {
        If ($KB.TrimStart('KB') -eq $Update.KBArticleIDs)  {
            If ($Update.EulaAccepted -ne $true) {
                $Update.AcceptEula()
            }
            Write-Host "Matched : $($Update.Title)"  -ForegroundColor Yellow
            $UpdateCollection.Add($Update) | Out-Null
        }
    }
}

If ($UpdateCollection.Count -ne '0') {
    # Update Download
    Write-Host "Downloading Updates" -ForegroundColor Green
    $Downloader         = $WUSession.CreateUpdateDownloader()
    $Downloader.Updates = $UpdateCollection
    $DownloadResult     = $Downloader.Download()

    # Update Install
    Write-Host "Installing Updates" -ForegroundColor Green
    Foreach ($Update in $UpdateCollection) {
        $UpdateInstall           = New-Object -ComObject 'Microsoft.Update.UpdateColl'
        $UpdateInstall.Add($Update) | Out-Null
        $UpdateInstaller         = $WUSession.CreateUpdateInstaller()
        $UpdateInstaller.Updates = $UpdateInstall
        Write-Host "Installing : $($Update.Title)" -ForegroundColor Yellow
        $InstallResult = $UpdateInstaller.Install()
    }
}