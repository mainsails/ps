#Requires -Version 5
#Requires -PSSnapin 'Microsoft.BDD.PSSnapIn'
#Requires -Modules 'Hyper-V'
#Requires -RunAsAdministrator

# VM Resource Allocation
$VMCaptureClientRAM  = 4GB
$VMCaptureClientDisk = 50GB
# OS Capture Server Details
$OSCaptureServer = 'MDT'
$OSCaptureDS     = 'MDT Build Lab'


# Build Capture Server Variables
Add-PSSnapin -Name 'Microsoft.BDD.PSSnapIn'
Restore-MDTPersistentDrive | Out-Null
$OSCaptureDSProp   = Get-MDTPersistentDrive | ForEach-Object { Get-ItemProperty -Path ($_.Name + ':') | Where-Object { $_.Description -eq $OSCaptureDS } | Select-Object -First 1 }
$OSCaptureDSPath   = $OSCaptureDSProp | Select-Object -ExpandProperty 'UNCPath'
$OSCaptureISO      = $OSCaptureDSPath + '\' + ($OSCaptureDSProp | Select-Object -ExpandProperty 'Boot.x64.LiteTouchISOName')
$OSCaptureLocation = $OSCaptureDSPath + '\' + 'Captures'
$OSCaptureTSs      = Get-ChildItem -Path ($OSCaptureDSProp.PSChildName + '\' + 'Task Sequences')

ForEach ($OSCaptureTS in $OSCaptureTSs) {
    # VM Resources
    $VMCaptureClientName    = $OSCaptureTS.Name -replace '\s'
    $VMCaptureClientVSwitch = 'VMCaptureVSwitch' + '-' + -join (([char]'A'..[char]'Z') | Get-Random -Count 3 | ForEach-Object { [char]$_ })
    
    # Check if the Capture Sequence is already running
    If (Get-VM -ComputerName $env:COMPUTERNAME -Name $VMCaptureClientName -ErrorAction SilentlyContinue) {
        Throw 'Capture Sequence is already running'
    }

    # Create Virtual Switch
    $EthernetAdapter = Get-NetAdapter -Name Ethernet -Physical | Where-Object { $_.Status -eq 'Up' } | Select-Object -First 1
    $VirtualSwitch   = New-VMSwitch -Name $VMCaptureClientVSwitch -NetAdapterName $EthernetAdapter.Name -AllowManagementOS $true -Notes 'Temp-OSCapture-Switch'

    # Create and Configure VM Client
    $VirtualMachine = New-VM -ComputerName $env:COMPUTERNAME -Name $VMCaptureClientName -Generation 2 -MemoryStartupBytes $VMCaptureClientRAM -NewVHDPath "$VMCaptureClientName.VHDX" -NewVHDSizeBytes $VMCaptureClientDisk -SwitchName $VMCaptureClientVSwitch
    # Add Virtual DVD Drive
    $VirtualMachineDisc = Add-VMDvdDrive $VirtualMachine -Path $OSCaptureISO -Passthru
    # Set Boot Order
    $BootOrder = Get-VMFirmware $VirtualMachine | Select-Object -ExpandProperty 'BootOrder' | Where-Object { $_.BootType -ne 'Network' }
    Set-VMFirmware $VirtualMachine -BootOrder $BootOrder
    # Configure BIOS
    Set-VMFirmware $VirtualMachine -EnableSecureBoot Off -FirstBootDevice $VirtualMachineDisc

    # Start Virtual Machine
    Start-VM -ComputerName $env:COMPUTERNAME -Name $VMCaptureClientName

    # Wait for Capture to complete
    While ((Get-VM -ComputerName $env:COMPUTERNAME -Name $VMCaptureClientName).State -ne "Off") {
        Write-Progress -Activity 'Image Capture In Progress' -PercentComplete -1
        Start-Sleep -Seconds 30
    }


    #ToDo
    #Sanity Check, import and confirm Image


    # Delete Virtual Machine Snapshots/Checkpoints
    Get-VMSnapshot $VirtualMachine | Remove-VMSnapshot
    # Delete Virtual Machine Disks
    Get-VMHardDiskDrive $VirtualMachine | ForEach-Object { Remove-Item -Path $_.Path -Force }
    # Delete Virtual Machine
    Remove-VM $VirtualMachine -Force
    # Delete Virtual Switch
    Remove-VMSwitch $VirtualSwitch -Force
}