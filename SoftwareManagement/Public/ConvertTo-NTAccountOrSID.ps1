Function ConvertTo-NTAccountOrSID {
    <#
    .SYNOPSIS
        Convert between NT Account names and their security identifiers (SIDs)
    .DESCRIPTION
        Specify either the NT Account name or the SID and get the other. Can also convert WellKnownSidType
    .PARAMETER AccountName
        The Windows NT Account name specified in <domain>\<username> format
    .PARAMETER SID
        The Windows NT Account SID
    .PARAMETER WellKnownSIDName
        Specify the Well Known SID name to translate to the actual SID (e.g. LocalServiceSid).
        To enumerate all well known SIDs available on system: [enum]::GetNames([Security.Principal.WellKnownSidType])
    .PARAMETER WellKnownToNTAccount
        Convert the Well Known SID to an NTAccount name
    .EXAMPLE
        ConvertTo-NTAccountOrSID -AccountName '<domain>\UserName'
        Converts a Windows NT Account name to the corresponding SID
    .EXAMPLE
        ConvertTo-NTAccountOrSID -SID 'S-1-5-32-544'
        Converts a Windows NT Account SID to the corresponding NT Account Name
    .EXAMPLE
        ConvertTo-NTAccountOrSID -WellKnownSIDName 'NetworkServiceSid'
        Converts a Well Known SID name to a SID
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true,ParameterSetName='NTAccountToSID',ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$AccountName,
        [Parameter(Mandatory=$true,ParameterSetName='SIDToNTAccount',ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$SID,
        [Parameter(Mandatory=$true,ParameterSetName='WellKnownName',ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$WellKnownSIDName,
        [Parameter(Mandatory=$false,ParameterSetName='WellKnownName')]
        [ValidateNotNullOrEmpty()]
        [switch]$WellKnownToNTAccount
    )

    Begin {}
    Process {
        Try {
            Switch ($PSCmdlet.ParameterSetName) {
                'SIDToNTAccount' {
                    $NTAccountSID = New-Object -TypeName 'System.Security.Principal.SecurityIdentifier' -ArgumentList $SID
                    $NTAccount = $NTAccountSID.Translate([Security.Principal.NTAccount])
                    Write-Output -InputObject $NTAccount
                }
                'NTAccountToSID' {
                    $NTAccount = New-Object -TypeName 'System.Security.Principal.NTAccount' -ArgumentList $AccountName
                    $NTAccountSID = $NTAccount.Translate([Security.Principal.SecurityIdentifier])
                    Write-Output -InputObject $NTAccountSID
                }
                'WellKnownName' {
                    If ($WellKnownToNTAccount) {
                        [string]$ConversionType = 'NTAccount'
                    }
                    Else {
                        [string]$ConversionType = 'SID'
                    }
                    # Get the SID for the root domain
                    Try {
                        $MachineRootDomain = (Get-WmiObject -Class 'Win32_ComputerSystem' -ErrorAction 'Stop').Domain.ToLower()
                        $ADDomainObj = New-Object -TypeName 'System.DirectoryServices.DirectoryEntry' -ArgumentList "LDAP://$MachineRootDomain"
                        $DomainSidInBinary = $ADDomainObj.ObjectSid
                        $DomainSid = New-Object -TypeName 'System.Security.Principal.SecurityIdentifier' -ArgumentList ($DomainSidInBinary[0], 0)
                    }
                    Catch {
                        Write-Warning -Message 'Unable to get Domain SID from Active Directory. Setting Domain SID to $null'
                        $DomainSid = $null
                    }

                    # Get the SID for the well known SID name
                    $WellKnownSidType = [Security.Principal.WellKnownSidType]::$WellKnownSIDName
                    $NTAccountSID = New-Object -TypeName 'System.Security.Principal.SecurityIdentifier' -ArgumentList ($WellKnownSidType, $DomainSid)

                    If ($WellKnownToNTAccount) {
                        $NTAccount = $NTAccountSID.Translate([Security.Principal.NTAccount])
                        Write-Output -InputObject $NTAccount
                    }
                    Else {
                        Write-Output -InputObject $NTAccountSID
                    }
                }
            }
        }
        Catch {
            Write-Warning -Message "Failed to convert $Message. It may not be a valid account anymore or there is some other problem"
        }
    }
    End {}
}