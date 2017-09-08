# Import C#
Add-Type -Path "C:\Users\shaws\Desktop\SoftwareManagement\TypeData\PSSM-Msi.cs"
Add-Type -Path "C:\Users\shaws\Desktop\SoftwareManagement\TypeData\PSSM-Explorer.cs"
$ReferencedAssemblies = ('System.DirectoryServices, Version=2.0.0.0, Culture=neutral, PublicKeyToken=B03F5F7F11D50A3A')
Add-Type -Path "C:\Users\shaws\Desktop\SoftwareManagement\TypeData\PSSM-QueryUser.cs" -ReferencedAssemblies $ReferencedAssemblies

# Get public and private function definition files
$Public  = @( Get-ChildItem -Path $PSScriptRoot\*.ps1 -ErrorAction SilentlyContinue )
$Private = @( Get-ChildItem -Path $PSScriptRoot\Private\*.ps1 -ErrorAction SilentlyContinue )

# Dot source the files
ForEach ($Import in @($Public + $Private)) {
    Try {
        . $Import.fullname
    }
    Catch {
        Write-Error -Message "Failed to import function $($Import.fullname): $_"
    }
}

Export-ModuleMember -Function $Public.Basename -Verbose