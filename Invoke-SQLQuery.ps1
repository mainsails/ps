Function Invoke-SQLQuery {
    <#
    .SYNOPSIS
        Performs a SQL Query and returns an array of PSObjects
    .DESCRIPTION
        Performs a SQL Query and returns an array of PSObjects
    .PARAMETER Server
        A server name for the instance of the Database Engine
    .PARAMETER Database
        A character string specifying the name of a database
    .PARAMETER Username
        Specifies the login ID for making a SQL Server Authentication connection to an instance of the Database Engine. The password must be specified using -Password. If -Username and -Password are not specified, Invoke-SQLQuery attempts a Windows Authentication connection using the Windows account running the PowerShell session
    .PARAMETER Password
        Specifies the password for the SQL Server Authentication login ID that was specified in -Username
    .PARAMETER UseWindowsAuthentication
        Specifies a Windows Authentication connection using the Windows account running the PowerShell session
    .PARAMETER Query
        Specifies one or more queries to be run
    .PARAMETER CommandTimeout
        Specifies the number of seconds before the queries time out. If a timeout value is not specified, the queries do not time out
    .EXAMPLE
        Invoke-SQLQuery -Server ServerName -Database DatabaseName -UseWindowsAuthentication -Query 'SELECT * FROM Table'
    #>

    [CmdletBinding(DefaultParameterSetName = 'Auth_SSPI')]
    Param (
        [Parameter(Mandatory=$true)]
        [Alias('ServerInstance')]
        [string]$Server,
        [Parameter(Mandatory=$true)]
        [string]$Database,
        [Parameter(Mandatory=$false, ParameterSetName = 'Auth_SSPI')]
        [switch]$UseWindowsAuthentication = $true,
        [Parameter(Mandatory=$true, ParameterSetName = 'Auth_UID')]
        [string]$Username,
        [Parameter(Mandatory=$true, ParameterSetName = 'Auth_UID')]
        [string]$Password,
        [Parameter(Mandatory=$true)]
        [string]$Query,
        [Parameter(Mandatory=$false)]
        [int]$CommandTimeout = 0
    )

    # Build connection string
    $ConnectionString = "Server=$Server; Database=$Database;"
    If     ($PSCmdlet.ParameterSetName -eq 'Auth_UID')  { $ConnectionString += "User ID=$Username; Password=$Password;" }
    ElseIf ($PSCmdlet.ParameterSetName -eq 'Auth_SSPI') { $ConnectionString += 'Trusted_Connection=Yes; Integrated Security=SSPI;' }

    # Connect to database
    $Connection = New-Object -TypeName System.Data.SqlClient.SqlConnection($ConnectionString)
    $Connection.Open()

    # Build query object
    $Command                = $Connection.CreateCommand()
    $Command.CommandText    = $Query
    $Command.CommandTimeout = $CommandTimeout

    # Run query
    $Adapter = New-Object -TypeName System.Data.SqlClient.SqlDataAdapter $Command
    $DataSet = New-Object -TypeName System.Data.DataSet
    $Adapter.Fill($DataSet) | Out-Null

    # Return the first collection of results or an empty array
    If     ($DataSet.Tables[0] -ne $null) { $Table = $DataSet.Tables[0] }
    ElseIf ($Table.Rows.Count -eq 0)      { $Table = New-Object -TypeName System.Collections.ArrayList }

    $Connection.Close()
    return $Table
}