# List of Applications to Remove
$AppPackages  = @()
$AppPackages += 'Microsoft.3DBuilder'
$AppPackages += 'Microsoft.Appconnector'
$AppPackages += 'Microsoft.BingFinance'
$AppPackages += 'Microsoft.BingFoodAndDrink'
$AppPackages += 'Microsoft.BingHealthAndFitness'
$AppPackages += 'Microsoft.BingNews'
$AppPackages += 'Microsoft.BingSports'
$AppPackages += 'Microsoft.BingTravel'
$AppPackages += 'Microsoft.CommsPhone'
$AppPackages += 'Microsoft.ConnectivityStore'
$AppPackages += 'Microsoft.Getstarted'
$AppPackages += 'Microsoft.Messaging'
$AppPackages += 'Microsoft.Microsoft3DViewer'
$AppPackages += 'Microsoft.MicrosoftOfficeHub'
$AppPackages += 'Microsoft.MicrosoftSolitaireCollection'
$AppPackages += 'Microsoft.MinecraftUWP'
$AppPackages += 'Microsoft.Office.OneNote'
$AppPackages += 'Microsoft.Office.Sway'
$AppPackages += 'Microsoft.OneConnect'
$AppPackages += 'Microsoft.People'
$AppPackages += 'Microsoft.SkypeApp'
$AppPackages += 'microsoft.windowscommunicationsapps'
$AppPackages += 'Microsoft.WindowsFeedbackHub'
$AppPackages += 'Microsoft.WindowsPhone'
$AppPackages += 'Microsoft.WindowsReadingList'
$AppPackages += 'Microsoft.XboxApp'
$AppPackages += 'Microsoft.ZuneMusic'
$AppPackages += 'Microsoft.ZuneVideo'

# List of Core Applications to Remove (Core Applications that may not be removable)
$AppPackages += 'Microsoft.MicrosoftEdge'
$AppPackages += 'Microsoft.Windows.ParentalControls'
$AppPackages += 'Microsoft.WindowsFeedback'
$AppPackages += 'Microsoft.XboxGameCallableUI'
$AppPackages += 'Microsoft.XboxIdentityProvider'
$AppPackages += 'Windows.ContactSupport'
$AppPackages += 'Windows.PurchaseDialog'

# List of Applications to Consider Removing
#$AppPackages += 'Microsoft.BingWeather'
#$AppPackages += 'Microsoft.MicrosoftStickyNotes'
#$AppPackages += 'Microsoft.Windows.Photos'
#$AppPackages += 'Microsoft.WindowsCalculator'
#$AppPackages += 'Microsoft.WindowsCamera'
#$AppPackages += 'Microsoft.WindowsMaps'
#$AppPackages += 'Microsoft.WindowsSoundRecorder'
#$AppPackages += 'Microsoft.WindowsStore'
#$AppPackages += 'WindowsAlarms'

# Non-Microsoft Applications
$AppPackages += '2FE3CB00.PicsArt-PhotoStudio'
$AppPackages += '4DF9E0F8.Netflix'
$AppPackages += '6Wunderkinder.Wunderlist'
$AppPackages += '9E2F88E3.Twitter'
$AppPackages += 'ClearChannelRadioDigital.iHeartRadio'
$AppPackages += 'D52A8D61.FarmVille2CountryEscape'
$AppPackages += 'DB6EA5DB.CyberLinkMediaSuiteEssentials'
$AppPackages += 'Drawboard.DrawboardPDF'
$AppPackages += 'Flipboard.Flipboard'
$AppPackages += 'GAMELOFTSA.Asphalt8Airborne'
$AppPackages += 'king.com.CandyCrushSaga'
$AppPackages += 'king.com.CandyCrushSodaSaga'
$AppPackages += 'PandoraMediaInc.29680B314EFC2'
$AppPackages += 'ShazamEntertainmentLtd.Shazam'
$AppPackages += 'TheNewYorkTimes.NYTCrossword'
$AppPackages += 'TuneIn.TuneInRadio'

# Application Removal
ForEach ($App In $AppPackages) {

    $Package = Get-AppxPackage -AllUsers | Where-Object { $_.Name -eq $App }
    If ($Package -ne $null) {
        Write-Host "Removing Package : $App"
        Remove-AppxPackage -Package $Package.PackageFullName -ErrorAction SilentlyContinue
    }
    Else {
        Write-Host "Requested Package is not installed : $App"
    }

    $ProvisionedPackage = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -eq $App }
        If ($ProvisionedPackage -ne $null) {
        Write-Host "Removing Provisioned Package : $App"
        Remove-AppxProvisionedPackage -Online -PackageName $ProvisionedPackage.PackageName -ErrorAction SilentlyContinue
    }
    Else {
        Write-Host "Requested Provisioned Package is not installed : $App"
    }

}