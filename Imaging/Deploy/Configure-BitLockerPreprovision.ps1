# Set Encryption Method Based on Target Operating System
If ($TSEnv.Value('TASKSEQUENCENAME') -like '*Windows 10*') {
    $EncryptionMethod = '7'
}
Else {
    $EncryptionMethod = '4'
}

# Create Registry Object
$RegistryPath    = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
$RegistryEntries = @(
    @{ 'Path' = $RegistryPath ; 'Name' = 'EncryptionMethodWithXtsFdv'   ; 'Value' = $EncryptionMethod ; 'Type' = 'DWORD'  }
    @{ 'Path' = $RegistryPath ; 'Name' = 'EncryptionMethodWithXtsOs'    ; 'Value' = $EncryptionMethod ; 'Type' = 'DWORD'  }
    @{ 'Path' = $RegistryPath ; 'Name' = 'EncryptionMethodWithXtsRdv'   ; 'Value' = $EncryptionMethod ; 'Type' = 'DWORD'  }
    @{ 'Path' = $RegistryPath ; 'Name' = 'IdentificationField'          ; 'Value' = '1'               ; 'Type' = 'DWORD'  }
    @{ 'Path' = $RegistryPath ; 'Name' = 'IdentificationFieldString'    ; 'Value' = 'BLIFS'           ; 'Type' = 'String' }
    @{ 'Path' = $RegistryPath ; 'Name' = 'SecondaryIdentificationField' ; 'Value' = 'BLSIF'           ; 'Type' = 'String' }
)

# Create Registry Key
If (!(Test-Path -Path $RegistryPath)) {
    New-Item -Path $RegistryPath -Force
}
# Set Registry Values
ForEach ($RegistryEntry in $RegistryEntries) {
    New-ItemProperty -Path $RegistryEntry.Path -Name $RegistryEntry.Name -Value $RegistryEntry.Value -PropertyType $RegistryEntry.Type -Force
}
