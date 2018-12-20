Function Export-PSCredential { 
    <#
    .SYNOPSIS
        Export credentials to a file
    .DESCRIPTION
        Export credentials to a file
        For use with Import-PSCredential
        A credential can only be decrypted by the user who encryped it, on the computer where the command was invoked
    .PARAMETER Credential
        Credential to export
    .PARAMETER Path
        File to export to. Parent folder must exist
    .PARAMETER PassThru
        Return FileInfo object for the credential file
    .EXAMPLE
        #Creates a credential, saves it to disk
        $Credential = Get-Credential
        Export-PSCredential -Path C:\File.xml -Credential $Credential
    
        #Later on, import the credential!
        $ImportedCred = Import-PSCredential -Path C:\File.xml
    .NOTES
        Purpose:    These functions allow one to easily save network credentials to disk in a relatively
                    secure manner. The resulting on-disk credential file can only be decrypted
                    by the same user account which performed the encryption. For more details, see
                    the help files for ConvertFrom-SecureString and ConvertTo-SecureString as well as
                    MSDN pages about Windows Data Protection API.
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
        UserName = $Credential.UserName
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






Function Import-PSCredential { 
    <#
    .SYNOPSIS
        Import credentials from a file
    .DESCRIPTION
        Export credentials to a file
        For use with Import-PSCredential
        A credential can only be decrypted by the user who encryped it, on the computer where the command was invoked.
    .PARAMETER Path
        Path to credential file
    .PARAMETER GlobalVariable
        If specified, store the imported credential in a global variable with this name
    .EXAMPLE
        #Creates a credential, saves it to disk
        $Credential = Get-Credential
        Export-PSCredential -path C:\File.xml -credential $Credential
    
        #Later on, import the credential!
        $ImportedCred = Import-PSCredential -path C:\File.xml
    .NOTES
        Purpose:    These functions allow one to easily save network credentials to disk in a relatively
		            secure manner.  The resulting on-disk credential file can only [1] be decrypted
		            by the same user account which performed the encryption.  For more details, see
		            the help files for ConvertFrom-SecureString and ConvertTo-SecureString as well as
		            MSDN pages about Windows Data Protection API.
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
