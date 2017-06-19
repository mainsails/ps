Function Write-CMTraceLog {
    Param (
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [int]$ProcessID = $PID,
        [Parameter()]
        [ValidateSet(1, 2, 3)]
        [int]$LogLevel = 1
    )
    $TimeGenerated = "$(Get-Date -Format HH:mm:ss).$((Get-Date).Millisecond)+000"
    $Line          = '<![LOG[{0}]LOG]!><time="{1}" date="{2}" component="{3}" context="" type="{4}" thread="{5}" file="">'
    $LineFormat    = $Message, $TimeGenerated, (Get-Date -Format MM-dd-yyyy), "$($MyInvocation.ScriptName | Split-Path -Leaf):$($MyInvocation.ScriptLineNumber)", $LogLevel, $ProcessID
    $Line          = $Line -f $LineFormat
    While ($Attempt -le 10) {
        Try {
            [IO.File]::OpenWrite($Log).Close()
            Add-Content -Value $Line -Path $Log
            Break
        }
        Catch {
            Start-Sleep -Seconds (Get-Random -Minimum 1 -Maximum 5)
            $Attempt++
        }
    }
}

## Script Start
#$TSEnv   = New-Object -COMObject Microsoft.SMS.TSEnvironment
#$LogPath = $TSEnv.Value('LOGPATH')        # Log Location - MDT
##$LogPath = $TSEnv.Value('_SMSTSLOGPATH')  # Log Location - SCCM
#$Log     = "$LogPath\$(([io.fileinfo]$MyInvocation.MyCommand.Definition).BaseName).log"

#Write-CMTraceLog "Log Starting"