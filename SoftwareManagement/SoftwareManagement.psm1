# Import required C#
Add-Type -Path "$PSScriptRoot\TypeData\PSSM-Msi.cs"
Add-Type -Path "$PSScriptRoot\TypeData\PSSM-Explorer.cs"
$ReferencedAssemblies = ('System.DirectoryServices, Version=2.0.0.0, Culture=neutral, PublicKeyToken=B03F5F7F11D50A3A')
Add-Type -Path "$PSScriptRoot\TypeData\PSSM-QueryUser.cs" -ReferencedAssemblies $ReferencedAssemblies

# Get Public and Private Function definition files
$Public  = @(Get-ChildItem -Path "$PSScriptRoot\Public"  -Filter '*.ps1')
$Private = @(Get-ChildItem -Path "$PSScriptRoot\Private" -Filter '*.ps1')

# Dot source the Functions
ForEach ($Import in @($Public + $Private)) {
    Try {
        . $Import.FullName
    }
    Catch {
        Write-Error -Message "Failed to import Function : [$($Import.BaseName)] : $_"
    }
}