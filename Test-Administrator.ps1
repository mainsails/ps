Function Test-Administrator {
    <#
    .SYNOPSIS
        Determines whether the specified user is an administrator.
    .DESCRIPTION
        Determines whether the specified user is an administrator.
        Note: Requires .NET 3.5 or later.
    .PARAMETER UserName
        One or more usernames to test.
        Defaults to the current PowerShell user ($env:USERNAME).
    .INPUTS
        System.String
    .OUTPUTS
        System.Boolean
    .EXAMPLE
        Test-Administrator -UserName JohnSmith
        Test if JohnSmith is an admin on this computer.
    #>

    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [string[]]$UserName = $env:USERNAME
    )

    Begin {
        Try   { Add-Type -AssemblyName System.DirectoryServices.AccountManagement -ErrorAction Stop }
        Catch { Throw }
    }
    Process {
        ForEach ($User in $UserName) {
            # Query locally for user
            If ($User -eq $env:USERNAME) {
                Write-Verbose -Message "Query Local Machine : [$User]"
                $Identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            }
            # Query AD for user
            Else {
                Write-Verbose -Message "Query AD : [$User]"
                Try {
                    $ContextType = [System.DirectoryServices.AccountManagement.ContextType]::Domain
                    $UPN         = [System.DirectoryServices.AccountManagement.UserPrincipal]::FindByIdentity($ContextType,$User) | Select-Object -ExpandProperty 'UserPrincipalName'
                    $Identity    = New-Object -TypeName System.Security.Principal.WindowsIdentity($UPN) -ErrorAction Stop
                }
                Catch {
                    Write-Warning -Message "Could not find user [$User]"
                    Continue
                }
            }

            # Output
            $Principal = New-Object -TypeName System.Security.Principal.WindowsPrincipal($Identity)
            $Principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
        }
    }
    End {}
}