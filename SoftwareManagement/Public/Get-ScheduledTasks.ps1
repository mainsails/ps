Function Get-ScheduledTasks {
    <#
    .SYNOPSIS
        Retrieve all details for scheduled tasks on the local computer
    .DESCRIPTION
        Retrieve all details for scheduled tasks on the local computer using schtasks.exe. All property names have spaces and colons removed
    .PARAMETER TaskName
        Specify the name of the scheduled task to retrieve details for. Uses regex match to find scheduled task
    .PARAMETER ContinueOnError
        Continue if an error is encountered. Default: $true.
    .EXAMPLE
        Get-ScheduledTasks
        To display a list of all scheduled task properties
    .EXAMPLE
        Get-ScheduledTasks | Out-GridView
        To display a grid view of all scheduled task properties.
    .EXAMPLE
        Get-ScheduledTasks | Select-Object -Property TaskName
        To display a list of all scheduled task names
    .NOTES
        'Get-ScheduledTasks' can be replaced with the built-in cmdlet 'Get-ScheduledTask' in Windows 8.1+
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$TaskName,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [boolean]$ContinueOnError = $true
    )

    Begin {
        # Verbose Logging
        [string]$CmdletName  = $MyInvocation.MyCommand.Name
        [string]$CmdletParam = $PSBoundParameters | Format-Table -Property @{ Label = 'Parameter'; Expression = { "[-$($_.Key)]" } }, @{ Label = 'Value'; Expression = { $_.Value }; Alignment = 'Left' } -AutoSize -Wrap | Out-String
        Write-Verbose -Message "##### Calling : [$CmdletName]"

        [string]$exeSchTasks = "$env:WINDIR\system32\schtasks.exe"
        [psobject[]]$ScheduledTasks = @()
    }
    Process {
        Try {
            Write-Verbose 'Retrieve Scheduled Tasks...'
            [string[]]$exeSchtasksResults = & $exeSchTasks /Query /V /FO CSV
            If ($Global:LastExitCode -ne 0) {
                Throw "Failed to retrieve scheduled tasks using [$exeSchTasks]"
            }
            [psobject[]]$SchtasksResults = $exeSchtasksResults | ConvertFrom-CSV -Header 'HostName', 'TaskName', 'Next Run Time', 'Status', 'Logon Mode', 'Last Run Time', 'Last Result', 'Author', 'Task To Run', 'Start In', 'Comment', 'Scheduled Task State', 'Idle Time', 'Power Management', 'Run As User', 'Delete Task If Not Rescheduled', 'Stop Task If Runs X Hours and X Mins', 'Schedule', 'Schedule Type', 'Start Time', 'Start Date', 'End Date', 'Days', 'Months', 'Repeat: Every', 'Repeat: Until: Time', 'Repeat: Until: Duration', 'Repeat: Stop If Still Running' -ErrorAction 'Stop'

            If ($SchtasksResults) {
                ForEach ($SchtasksResult in $SchtasksResults) {
                    If ($SchtasksResult.TaskName -match $TaskName) {
                        $SchtasksResult | Get-Member -MemberType 'Properties' |
                        ForEach -Begin {
                            [hashtable]$Task = @{}
                        } -Process {
                            # Remove spaces and colons in property names. Do not set property value if line being processed is a column header
                            ($Task.($($_.Name).Replace(' ','').Replace(':',''))) = If ($_.Name -ne $SchtasksResult.($_.Name)) { $SchtasksResult.($_.Name) }
                        } -End {
                            ## Only add task to the custom object if all property values are not empty
                            If (($Task.Values | Select-Object -Unique | Measure-Object).Count) {
                                $ScheduledTasks += New-Object -TypeName 'PSObject' -Property $Task
                            }
                        }
                    }
                }
            }
        }
        Catch {
            Write-Warning -Message 'Failed to retrieve scheduled tasks'
            If (-not $ContinueOnError) {
                Throw "Failed to retrieve scheduled tasks: $($_.Exception.Message)"
            }
        }
    }
    End {
        Write-Output -InputObject $ScheduledTasks

        # Verbose Logging
        Write-Verbose -Message "##### Ending : [$CmdletName]"
    }
}