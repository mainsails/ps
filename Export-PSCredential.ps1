Function Export-PSCredential {
    <#
    .SYNOPSIS
        Export credentials to a file.
    .DESCRIPTION
        Export credentials to a file.
        A credential can only be decrypted by the user who encryped it on the computer where the command was invoked.
    .PARAMETER Credential
        Credential to export.
    .PARAMETER Path
        File to export to. Parent folder must exist.
    .PARAMETER PassThru
        Return FileInfo object for the credential file.
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
        Import-PSCredential
    #>

    [CmdletBinding()]
	Param(
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.PSCredential]$Credential = $(Get-Credential),
        [Parameter()]
        [ValidateScript({ Test-Path -Path (Split-Path -Path $_ -Parent) })]
        [string]$Path = "Credentials.$env:COMPUTERNAME.xml",
        [switch]$PassThru
    )

    # Create credential object
    $Export = New-Object -TypeName PSObject -Property @{
        UserName          = $Credential.UserName
        EncryptedPassword = $Credential.Password | ConvertFrom-SecureString
    }

    # Export credential object
    Try {
        Write-Verbose -Message "Saving credentials for [$($Export.UserName)] to [$Path]"
        $Export | Export-Clixml -Path $Path -ErrorAction Stop

        If ($PassThru) {
            # Return FileInfo object referring to saved credentials
            Get-Item $Path -ErrorAction Stop
        }
    }
    Catch {
        Write-Error "Error saving credentials to [$Path]: $_"
    }
}