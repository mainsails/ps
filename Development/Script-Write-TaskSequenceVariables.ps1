# Determine where to do the logging 
$TSEnv   = New-Object -COMObject Microsoft.SMS.TSEnvironment
$LogPath = $TSEnv.Value("LOGPATH") 
$Log = "$LogPath\$($MyInvocation.MyCommand).log"

# Start the logging 
Start-Transcript $Log

# Write all the variables and their values 
$TSEnv.GetVariables() | % { Write-Host "$_ = $($TSEnv.Value($_))" }

# Stop logging 
Stop-Transcript