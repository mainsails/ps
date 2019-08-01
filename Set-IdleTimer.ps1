Function Set-IdleTimer {
    <#
    .SYNOPSIS
        Function to prevent the system from entering sleep, locking or turning off the display while the application is running.
    .DESCRIPTION
        Function to prevent the system from entering sleep, locking or turning off the display while the application is running.
        This function uses SetThreadExecutionState to notify the system that the application (PowerShell in this instance) is busy.
        If set to 'Disabled', the PowerShell session will remain busy until closed or the Set-IdleTimer function is called with the 'Default' option.
    .PARAMETER Option
        Specifies the idle timer state. Acceptable values are :
        - Default : Return the idle timer settings to default.
        - Disabled : Disable the idle timer.
    .INPUTS
        System.String
    .OUTPUTS
        None
    .EXAMPLE
        Set-IdleTimer -Option Disabled

        Prevents the system from entering sleep, locking or turning off the display.
    .EXAMPLE
        Set-IdleTimer -Option Default

        Returns the idle timer settings to default (allowing the system to enter sleep, lock and turn off the display).
    .LINK
        https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-setthreadexecutionstate
    #>

    [CmdletBinding()]
    Param (
        [ValidateSet('Default','Disabled')]
        [string]$Option = 'Default'
    )

    Begin {
        $CSSource = @"
[DllImport("kernel32.dll", CharSet = CharSet.Auto,SetLastError = true)]
public static extern void SetThreadExecutionState(uint esFlags);
"@

        $SetThreadExecutionState = Add-Type -MemberDefinition $CSSource -Language CSharp -Name IdleTimer -Namespace PSSM -PassThru
        $ES_CONTINUOUS           = [uint32]'0x80000000' # Informs the system that the state being set should remain in effect until the next call that uses ES_CONTINUOUS and one of the other state flags is cleared.
        $ES_SYSTEM_REQUIRED      = [uint32]'0x00000001' # Forces the system to be in the working state by resetting the system idle timer.
        $ES_DISPLAY_REQUIRED     = [uint32]'0x00000002' # Forces the display to be on by resetting the display idle timer.
    }
    Process {
        Switch ($Option) {
            'Disabled' { $ExecutionState = $ES_CONTINUOUS -bor $ES_SYSTEM_REQUIRED -bor $ES_DISPLAY_REQUIRED }
            default    { $ExecutionState = $ES_CONTINUOUS }
        }
        Write-Verbose "System idle timer set to : [$((Get-Culture).TextInfo.ToTitleCase($Option.ToLower()))]"
        [PSSM.IdleTimer]::SetThreadExecutionState($ExecutionState)
    }
}