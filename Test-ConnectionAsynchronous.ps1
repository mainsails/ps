Function Test-ConnectionAsynchronous {
    <#
    .SYNOPSIS
        Performs an asynchronous ping test
    .DESCRIPTION
        Performs an asynchronous ping test against multiple machines
    .PARAMETER ComputerName
        List of computers for connection test
    .EXAMPLE
        Test-ConnectionAsynchronous -ComputerName "Computer1", "Computer2", "Computer3"

        ComputerName                Result
        ------------                ------
        Computer1                   Success
        Computer2                   TimedOut
        Computer3                   No such host is known
    .EXAMPLE
        Get-Clipboard | Test-ConnectionAsynchronous
    #>
    #Requires -Version 3.0

    [OutputType('Net.AsyncPingResult')]
    [CmdLetBinding()]
    Param (
        [Parameter(ValueFromPipeline=$true)]
        [String[]]$ComputerName
    )

    Begin {
        $ComputerList = New-Object -TypeName System.Collections.ArrayList
    }
    Process {
        If ($ComputerName) {
            $ComputerList.AddRange($ComputerName)
        }
    }
    End {
        $Task = ForEach ($Computer in $ComputerList) {
            [PSCustomObject] @{
                ComputerName = $Computer
                Task = (New-Object -TypeName System.Net.NetworkInformation.Ping).SendPingAsync($Computer)
            }
        }
        Try {
            [Threading.Tasks.Task]::WaitAll($Task.Task)
        }
        Catch {}

        $Task | ForEach {
            If ($_.Task.IsFaulted) {
                $Result    = $_.Task.Exception.InnerException.InnerException.Message
                $IPAddress = $null
            }
            Else {
                $Result    = $_.Task.Result.Status
                $IPAddress = $_.Task.Result.Address.ToString()
            }
            $Object = [PSCustomObject] @{
                ComputerName = $_.ComputerName
                IPAddress    = $IPAddress
                Result       = $Result
            }
            $Object.PSTypeNames.Insert(0,'Net.AsyncPingResult')
            Write-Output -InputObject $Object
        }
    }
}