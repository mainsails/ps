Function Enable-PowershellRemoting {

    <#
    .Synopsis
       Enable PowerShell Remoting
    .Description
       Enable PowerShell Remoting using PSExec
    .Parameter ComputerName
       Hostname of Remote Computers for PowerShell Remoting
    .Example
       Enable-PowershellRemoting -ComputerName "RWX41999"
    .Example
       $ListOfComputers = "Computer1","Computer2","Computer3"
       Enable-PowershellRemoting $ListOfComputers
    .Example
       "Computer1","Computer2" | Enable-PowershellRemoting
    #>

    [CmdLetBinding()]
    Param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
        [String[]]$ComputerName
    )

    Begin {
        $ComputerList             = New-Object -TypeName System.Collections.ArrayList
        $PSExec                   = 'C:\Program Files (x86)\PSTools\PsExec.exe'
        $EnablePSRemotingSwitch   = '-s powershell Enable-PSRemoting -Force'
        $RegisterPSRemotingSwitch = '-s powershell Register-PSSessionConfiguration -Name Microsoft.PowerShell'
    }
    Process {
        $ComputerList.AddRange($ComputerName)
    }
    End {
        Foreach ($Computer in $ComputerList) {
            If (!(Test-Connection -Computername $Computer -Count 2 -Quiet -ErrorAction SilentlyContinue)) {
                Write-Host "$Computer is not pingable" -ForegroundColor Red
                continue
            }
            Try {
               $RemoteSession = New-PSSession -ComputerName $Computer -ErrorAction Stop
            }
            Catch {
                Write-Host "Enabling PowerShell Remoting on $Computer" -ForegroundColor Yellow
                $EnablePS = Start-Process -Wait -PassThru -WindowStyle Hidden -FilePath $PSExec -ArgumentList "\\$Computer $EnablePSRemotingSwitch"
                If (($EnablePS.ExitCode) -ne 0) {
                    Write-Host "Registering PowerShell Remoting on $Computer" -ForegroundColor Yellow
                    $RegisterPS = Start-Process -Wait -PassThru -WindowStyle Hidden -FilePath $PSExec -ArgumentList "\\$Computer $RegisterPSRemotingSwitch"
                }
            }
            Finally {
                Write-Host "PowerShell Remoting enabled on $Computer" -ForegroundColor Green
                If ($RemoteSession) {
                    Remove-PSSession -Session $RemoteSession
                }
            }
        }
    }

}