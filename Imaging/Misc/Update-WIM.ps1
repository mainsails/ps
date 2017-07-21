$OSEdition        = 'Windows Server 2008 R2 SERVERSTANDARD'
$OSSourceLocation = 'C:\ostemp\SW_DVD5_Windows_Svr_DC_EE_SE_Web_2008_R2_64Bit_English_w_SP1_MLF_X17-22580'
$OSMountLocation  = 'C:\ostemp\mount'
$OSUpdateLocation = '\\WindowsUpdateLocation'

## Get Windows Edition Index
$OSIndexes = Get-WindowsImage -ImagePath "$OSSourceLocation\sources\install.wim"
foreach ($OSIndex in $OSIndexes) {
    If ($OSIndex.ImageName -like $OSEdition) {
            $OSEditionIndex = $OSIndex.ImageIndex
    }
}

## Mount Windows Edition
If (-not (Test-Path -LiteralPath $OSMountLocation -PathType 'Container')) {
    New-Item -Path $OSMountLocation -ItemType 'Directory' -Force -ErrorAction 'Stop' | Out-Null
}
Mount-WindowsImage -ImagePath "$OSSourceLocation\sources\install.wim" -Index $OSEditionIndex -Path $OSMountLocation -ErrorAction Stop | Out-Null

## Get Updates
$OSUpdates = Get-ChildItem -Path $OSUpdateLocation -Recurse -Include *.cab -ErrorAction Stop | Sort-Object -Property 'LastWriteTime'

## Process Updates
foreach ($Update in $OSUpdates) {
    Add-WindowsPackage -Path $OSMountLocation -PackagePath $Update.FullName | Out-Null
    If ($? -eq $true) {
        Write-Host "Success : $Update.Name" -ForegroundColor Green
    }
    Else {
        Write-Host "Failed : $Update.Name" -ForegroundColor Red
    }
}

## Unmount with changes
Dismount-WindowsImage -Path $OSMountLocation -Save