Function Test-ConnectionAsynchronous {
    <#
    .SYNOPSIS
        Asynchronously attempts to sends ICMP echo request packets ("pings") to one or more computers
    .DESCRIPTION
        Asynchronously attempts to send and receive the corresponding Internet Control Message Protocol (ICMP) echo message to a specified Computer or IP Address
    .PARAMETER ComputerName
        Specifies the computers to ping. Accepts computer names or IP addresses in IPv4 or IPv6 format. Wildcard characters are not permitted
    .EXAMPLE
        Test-ConnectionAsynchronous -ComputerName "Computer1", "Computer2", "Computer3"

        ComputerName  IPAddress     Result
        ------------  ---------     ------
        Computer1     192.168.0.10  Success
        Computer2     192.168.1.20  TimedOut
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
                Task = Try   { (New-Object -TypeName System.Net.NetworkInformation.Ping).SendPingAsync($Computer) }
                       Catch {
                          Write-Warning -Message "Invalid Hostname/IP : [$Computer]"
                          Continue
                       }
            }
        }
        Try {
            [Threading.Tasks.Task]::WaitAll($Task.Task)
        }
        Catch {}

        $Task | ForEach-Object -Process {
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
