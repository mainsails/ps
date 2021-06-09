Function Get-BitlockerRecoveryKey {

    <#
    .SYNOPSIS
        Gets Bitlocker Recovery info stored in Active Directory.
    .DESCRIPTION
        This function retrieves the Bitlocker Recovery information stored in Active Directory.
        You must be a Domain Administrator or have the permissions delegated to your account in order to retrieve the information from AD.
    .PARAMETER ComputerName
        Specifies the computer to query for Bitlocker Recovery Key.
    .EXAMPLE
        Get-BitLockerRecoveryKey -ComputerName DESKTOP-AOC9281

        DistinguishedName      : CN=2017-10-20T09:38:39-00:00{C5E9D00C-C2E8-47B0-BCBD-7018AE458B49},CN=DESKTOP-AOC9281,OU=WindowsComputers,OU=Computers,DC=contoso,DC=com
        msFVE-RecoveryPassword : 308759-537889-346709-202037-428461-654148-020262-248600
        Name                   : 2017-10-20T09:38:39-00:00{C5E9D00C-C2E8-47B0-BCBD-7018AE458B49}
        ObjectClass            : msFVE-RecoveryInformation
        ObjectGUID             : b1b5d91d-0755-4101-458e-768c4fcab59a
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    # Get computer from Active Directory
    $objComputer = Get-ADComputer $ComputerName

    # Get all BitLocker Recovery Keys for that Computer
    $BitLockerObjects = Get-ADObject -Filter { ObjectClass -eq 'msFVE-RecoveryInformation' } -SearchBase $objComputer.DistinguishedName -Properties 'msFVE-RecoveryPassword'

    # Output the result
    $BitLockerObjects

}
