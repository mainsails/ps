Function Get-PSRemoteSession {
    <#
    .SYNOPSIS
        Query a computer for running PSSessions.
    .DESCRIPTION
        This command uses CIM to retrieve 'wsmprovhost.exe' processes running on a remote computer.
    .PARAMETER ComputerName
        Specifies the computer to query for session details
    .PARAMETER UserName
        Specifies a username to filter the PSSession results by.
    .OUTPUTS
        Microsoft.Management.Infrastructure.CimInstance#root/cimv2/Win32_Process
    .EXAMPLE
        Get-PSRemoteSession -ComputerName Computer1

        ProcessId Name            HandleCount WorkingSetSize VirtualSize   PSComputerName
        --------- ----            ----------- -------------- -----------   --------------
        5040      wsmprovhost.exe 372         51142656       2199646494720 Computer1

        This command queries the specified computer and displays the process information.
    .EXAMPLE
        Get-PSRemoteSession Computer1 | Select-Object -Property ProcessID,VM,WS,Runtime,Owner

        ProcessID : 5040
        VM        : 2199646494720
        WS        : 51154944
        Runtime   : 00:09:01.7107569
        Owner     : UserA

        ProcessID : 3680
        VM        : 2199658749952
        WS        : 53805056
        Runtime   : 00:49:29.8899602
        Owner     : UserB

        This command retrieves process information and selects some specific properties.
    .EXAMPLE
        Get-PSRemoteSession Computer1,Computer2 | Select-Object -Property PSComputerName,Owner

        PSComputerName Owner
        -------------- -----
        Computer1      UserA
        Computer1      UserB
        Computer2      UserA

        This command displays the users that are running remote sessions on the specified computers.
    .EXAMPLE
        Get-PSRemoteSession Computer1,Computer2 -UserName UserA | Invoke-CimMethod -MethodName Terminate

        This command queries the specified computers and terminates all remote sessions for the specied user.
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Position=0,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullorEmpty()]
        [Alias('PSComputerName','Computer','CN')]
        [string[]]$ComputerName,
        [string]$UserName
    )

    Begin {
        Write-Verbose "Calling $($MyInvocation.MyCommand.Name)"
    }

    Process {
        ForEach ($Computer in $ComputerName) {
            Write-Verbose -Message "Querying session(s) on [$Computer]"
            Try {
                # Query the computer for running 'wsmprovhost.exe' process
                $Data = Get-CimInstance -ClassName Win32_Process -Filter "Name='wsmprovhost.exe'" -ComputerName $Computer -ErrorAction Stop

                If ($Data) {
                    Write-Verbose -Message "Found session(s) on [$Computer]"

                    # Add custom property : Runtime
                    $Data | Add-Member -MemberType ScriptProperty -Name Runtime -Value {
                        (Get-Date) - $This.CreationDate
                    }
                    # Add custom property : Owner
                    $Data | Add-Member -MemberType ScriptProperty -Name Owner -Value {
                        $This | Invoke-CimMethod -MethodName GetOwner | Select-Object -ExpandProperty User
                    }

                    # Filter sessions by user
                    If ($UserName) {
                        Write-Verbose -Message "Filtering on user [$UserName]"
                        $Data = $Data | Where-Object -FilterScript {
                            ($Data.Owner -eq $UserName)
                        }
                    }

                    # Output Object
                    Write-Output -InputObject $Data
                }
            }
            Catch {
                Write-Warning -Message $_.Exception.Message
            }
        }
    }

    End {
        Write-Verbose -Message "Ending $($MyInvocation.MyCommand.Name)"
    }

}