Function Import-PSCredential {
    <#
    .SYNOPSIS
        Import credentials from a file.
    .DESCRIPTION
        Import credentials from a file.
        A credential can only be decrypted by the user who encryped it on the computer where the command was invoked.
    .PARAMETER Path
        Path to credential file.
    .PARAMETER GlobalVariable
        If specified, store the imported credential in a global variable with this name.
    .EXAMPLE
        # Create a credential and save it to disk
        $Credential = Get-Credential
        Export-PSCredential -Path C:\SavedCredential.xml -Credential $Credential

        # Import the credential
        $ImportedCredential = Import-PSCredential -Path C:\SavedCredential.xml
    .NOTES
        These functions allow you to save network credentials to disk in a relatively secure manner.
        The resulting credential file can be programatically read but only decrypted by the same user account which performed the encryption.
        For more details see the help files for ConvertFrom-SecureString and ConvertTo-SecureString as well as MSDN pages about Windows Data Protection API.
    .LINK
        Export-PSCredential
    #>

    [CmdletBinding()]
    Param(
        [ValidateScript({ Test-Path -Path $_ })]
        [string]$Path = "Credentials.$env:COMPUTERNAME.xml",
        [string]$GlobalVariable
    )

    # Import credential file
    $Import = Import-Clixml -Path $Path -ErrorAction Stop

    # Test for valid import
    If ((-not $Import.UserName) -or (-not $Import.EncryptedPassword)) {
        Throw 'Input is not a valid ExportedPSCredential object'
    }

    # Build the new credential object
    $Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $Import.Username,$($Import.EncryptedPassword | ConvertTo-SecureString)

    If ($OutVariable) {
        New-Variable -Name $GlobalVariable -Scope Global -Value $Credential -Force
    }
    Else {
        return $Credential
    }
}