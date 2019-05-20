Function Get-BitLockerRecoveryInformation {
    <#
    .SYNOPSIS
        Gets BitLocker recovery information for one or more Active Directory computer objects.
    .DESCRIPTION
        Gets BitLocker recovery information for one or more Active Directory computer objects.
    .PARAMETER Name
        Specifies one or more computer names. Wildcards are not supported.
    .PARAMETER PasswordID
        Gets the BitLocker recovery password for this password ID (first 8 characters). This parameter must be exactly 8 characters long and must contain only the characters 0 through 9 and A through F. If you get no output when using this parameter with a correct password ID, the current user does not have sufficient permission to read BitLocker recovery information. If you do not have sufficient permission to read BitLocker recovery information, you can either 1) use the -Credential parameter to specify an account with sufficient permissions, or 2) start your PowerShell session using an account with sufficient permissions.
    .PARAMETER Domain
        Gets BitLocker recovery information from computer objects in the specified domain.
    .PARAMETER Server
        Specifies a domain server.
    .PARAMETER Credential
        Specifies credentials that have sufficient permission to read BitLocker recovery information.
    .OUTPUTS
        PSobjects with the following properties:
          DistinguishedName - The distinguished name of the computer
          Name - The computer name
          TPMRecoveryInformation - $true if TPM recovery information stored in AD
          Date - The Date/time the BitLocker recovery information was stored
          PasswordID - The ID for the recovery password
          RecoveryPassword - The recovery password
        The TPMRecoveryInformation, Date, PasswordID, and RecoveryPassword properties will be "N/A" if BitLocker recovery information exists but the current user does not have sufficient permission to read it. If you do not have sufficient permission to read BitLocker recovery information, you can either 1) use the -Credential parameter to specify an account with sufficient permissions, or 2) start your PowerShell session using an account with sufficient permissions.
    .LINK
        http://technet.microsoft.com/en-us/library/dd875529.aspx
    #>

    [CmdletBinding(DefaultParameterSetName='Name')]
    Param (
        [Parameter(ParameterSetName='Name',Position=0,Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [Alias('ComputerName')]
        [String[]]$Name,
        [Parameter(ParameterSetName='PasswordID',Mandatory=$true)]
        [ValidateScript({ ($_ -match '^[0-9A-F]{8}$') })]
        [String]$PasswordID,
        [String]$Domain,
        [String]$Server,
        [Management.Automation.PSCredential]$Credential
    )

    Begin {

        # Pathname object constants
        $ADS_SETTYPE_DN         = 4
        $ADS_FORMAT_X500_PARENT = 8
        $ADS_DISPLAY_VALUE_ONLY = 2

        # Pathname object used by Get-ParentPath function
        $Pathname = New-Object -ComObject 'Pathname'

        # Returns the parent path of a distinguished name
        Function Get-ParentPath {
            Param ([String]$DistinguishedName)
            [void]$Pathname.GetType().InvokeMember('Set','InvokeMethod',$null,$Pathname,($DistinguishedName,$ADS_SETTYPE_DN))
            $Pathname.GetType().InvokeMember('Retrieve','InvokeMethod',$null,$Pathname,$ADS_FORMAT_X500_PARENT)
        }

        # Returns only the name of the first element of a distinguished name
        Function Get-NameElement {
            Param ([String]$DistinguishedName)
            [void]$Pathname.GetType().InvokeMember('Set','InvokeMethod',$null,$Pathname,($DistinguishedName,$ADS_SETTYPE_DN))
            [void]$Pathname.GetType().InvokeMember('SetDisplayType','InvokeMethod',$null,$Pathname,$ADS_DISPLAY_VALUE_ONLY)
            $Pathname.GetType().InvokeMember('GetElement','InvokeMethod',$null,$Pathname,0)
        }

        # Outputs a custom object based on a list of hash tables
        Function Out-Object {
            Param ([System.Collections.Hashtable[]]$HashData)
            $Order  = @()
            $Result = @{}
            $HashData | ForEach-Object -Process {
                $Order  += ($_.Keys -as [Array])[0]
                $Result += $_
            }
            New-Object -TypeName PSObject -Property $Result | Select-Object -Property $Order
        }

        # Create and initialize DirectorySearcher object that finds computers
        $ComputerSearcher = [ADSISearcher] ""
        Function Initialize-ComputerSearcher {
            If ($Domain) {
                If ($Server) {
                    $Path = "LDAP://$Server/$Domain"
                }
                Else {
                    $Path = "LDAP://$Domain"
                }
            }
            Else {
                If ($Server) {
                    $Path = "LDAP://$Server"
                }
                Else {
                    $Path = ''
                }
            }
            If ($Credential) {
                $networkCredential = $Credential.GetNetworkCredential()
                $DirEntry = New-Object DirectoryServices.DirectoryEntry(
                    $Path,
                    $NetworkCredential.UserName,
                    $NetworkCredential.Password
                )
            }
            Else {
                $DirEntry = [ADSI]$Path
            }
            $ComputerSearcher.SearchRoot = $DirEntry
            $ComputerSearcher.Filter     = '(objectClass=domain)'
            Try {
                [void]$ComputerSearcher.FindOne()
            }
            Catch [Management.Automation.MethodInvocationException] {
                throw $_.Exception.InnerException
            }
        }

        Initialize-ComputerSearcher

        # Create and initialize DirectorySearcher for finding msFVE-RecoveryInformation objects
        $RecoverySearcher  = [ADSISearcher] ''
        $RecoverySearcher.PageSize = 100
        $RecoverySearcher.PropertiesToLoad.AddRange(@('DistinguishedName','msFVE-RecoveryGuid','msFVE-RecoveryPassword','Name'))

        # Gets the DirectoryEntry object for a specified computer
        Function Get-ComputerDirectoryEntry {
            Param ([String]$Name)
            $ComputerSearcher.Filter = "(&(objectClass=computer)(name=$Name))"
            Try {
                $SearchResult = $ComputerSearcher.FindOne()
                If ($SearchResult) {
                    $SearchResult.GetDirectoryEntry()
                }
            }
            Catch [Management.Automation.MethodInvocationException] {
                Write-Error -Exception $_.Exception.InnerException
            }
        }

        # Outputs $true if the piped DirectoryEntry has the specified property set or $false otherwise
        Function Test-DirectoryEntryProperty {
            Param ([String]$Property)
            Process {
                Try {
                    $_.Get($Property) -ne $null
                }
                Catch [Management.Automation.MethodInvocationException] {
                    $false
                }
            }
        }

        # Gets a property from a ResultPropertyCollection
        Function Get-SearchResultProperty {
            Param (
                [DirectoryServices.ResultPropertyCollection]$Properties,
                [String]$PropertyName
            )
            If ($Properties[$PropertyName]) {
                $Properties[$PropertyName][0]
            }
        }

        # Gets BitLocker recovery information for the specified computer
        Function GetBitLockerRecovery {
            Param ($Name)
            $DomainName = $ComputerSearcher.SearchRoot.dc
            $ComputerDirEntry = Get-ComputerDirectoryEntry $Name
            If (-not $computerDirEntry) {
                Write-Error "Unable to find computer [$Name] in domain [$DomainName]" -Category ObjectNotFound
                return
            }
            # If the msTPM-OwnerInformation (Vista/Server 2008/7/Server 2008 R2) or msTPM-TpmInformationForComputer (Windows 8/Server 2012 or later) attribute is set, then TPM recovery information is stored in AD
            $TPMRecoveryInformation = $ComputerDirEntry | Test-DirectoryEntryProperty -Property 'msTPM-OwnerInformation'
            If (-not $TPMRecoveryInformation) {
                $TPMRecoveryInformation = $ComputerDirEntry | Test-DirectoryEntryProperty -Property 'msTPM-TpmInformationForComputer'
            }
            $RecoverySearcher.SearchRoot = $ComputerDirEntry
            $SearchResults = $RecoverySearcher.FindAll()
            Foreach ($SearchResult in $SearchResults) {
                $Properties = $SearchResult.Properties
                $RecoveryPassword = Get-SearchResultProperty $Properties 'msfve-recoverypassword'
                If ($RecoveryPassword) {
                    $RecoveryDate = ([DateTimeOffset]((Get-SearchResultProperty $Properties 'name') -split '{')[0]).DateTime
                    $PasswordID   = ([Guid][Byte[]](Get-SearchResultProperty $Properties 'msfve-recoveryguid')).Guid
                }
                Else {
                    $TPMRecoveryInformation = $RecoveryDate = $PasswordID = $RecoveryPassword = 'N/A'
                }
                Out-Object `
                @{ 'DistinguishedName'      = $ComputerDirEntry.Properties['DistinguishedName'][0] },
                @{ 'Name'                   = $ComputerDirEntry.Properties['Name'][0] },
                @{ 'TPMRecoveryInformation' = $TPMRecoveryInformation },
                @{ 'Date'                   = $RecoveryDate },
                @{ 'PasswordID'             = $PasswordID.ToUpper() },
                @{ 'RecoveryPassword'       = $RecoveryPassword.ToUpper() }
            }
            $SearchResults.Dispose()
        }

        # Searches for BitLocker recovery information for the specified password ID
        Function SearchBitLockerRecoveryByPasswordID {
        Param ([String] $passwordID)
        $RecoverySearcher.Filter = "(&(objectClass=msFVE-RecoveryInformation)(name=*{$passwordID-*}))"
        $SearchResults           = $RecoverySearcher.FindAll()
        Foreach ($SearchResult in $SearchResults) {
            $Properties              = $SearchResult.Properties
            $ComputerName            = Get-NameElement (Get-ParentPath (Get-SearchResultProperty $Properties 'DistinguishedName'))
            $RecoverySearcher.Filter = '(objectClass=msFVE-RecoveryInformation)'
            GetBitLockerRecovery $ComputerName | Where-Object { $_.PasswordID -match "^$passwordID-" }
        }
        $SearchResults.Dispose()
        }
    }

    Process {

        If ($PSCmdlet.ParameterSetName -eq 'Name') {
            $RecoverySearcher.Filter = '(objectClass=msFVE-RecoveryInformation)'
            Foreach ($NameItem in $Name) {
                GetBitLockerRecovery $NameItem
            }
        }
        ElseIf ($PSCmdlet.ParameterSetName -eq 'PasswordID') {
            SearchBitLockerRecoveryByPasswordID $PasswordID
        }

    }
}