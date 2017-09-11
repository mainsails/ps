Function ConvertTo-ContainerInheritanceFlags {
    <#
    .SYNOPSIS
        Converts a combination of InheritanceFlags Propagation Flags into a 'PSPM.Security.ContainerInheritanceFlags' enumeration value
    .DESCRIPTION
        'Grant-Permission', 'Test-Permission', and 'Get-Permission' all take an 'ApplyTo' parameter, which is a 'PSPM.Security.ContainerInheritanceFlags' enumeration value. This enumeration is then converted to the appropriate 'System.Security.AccessControl.InheritanceFlags' and 'System.Security.AccessControl.PropagationFlags' values for getting/granting/testing permissions
        If you prefer to speak in terms of 'InheritanceFlags' and 'PropagationFlags', use this Function to convert them to a 'ContainerInheritanceFlags' value
        If your combination doesn't result in a valid combination, '$null' is returned
        For detailed description of inheritance and propagation flags, see the help for 'Grant-Permission'
    .PARAMETER InheritanceFlags
        The inheritance flags to convert
    .PARAMETER PropagationFlags
        The propagation flags to convert
    .EXAMPLE
        ConvertTo-ContainerInheritanceFlags -InheritanceFlags 'ContainerInherit' -PropagationFlags 'None'
        Demonstrates how to convert 'InheritanceFlags' and 'PropagationFlags' enumeration values into a 'ContainerInheritanceFlags'
        In this case, '[PSPM.Security.ContainerInheritanceFlags]::ContainerAndSubContainers' is returned
    .OUTPUTS
        PSPM.Security.ContainerInheritanceFlags
    .LINK
        Grant-Permission
    .LINK
        Test-Permission
    #>

    [CmdletBinding()]
    [OutputType([PSPM.Security.ContainerInheritanceFlags])]
    Param(
        [Parameter(Mandatory=$true,Position=0)]
        [Security.AccessControl.InheritanceFlags]$InheritanceFlags,
        [Parameter(Mandatory=$true,Position=1)]
        [Security.AccessControl.PropagationFlags]$PropagationFlags
   )

    $PropFlagsNone = $PropagationFlags -eq [Security.AccessControl.PropagationFlags]::None
    $PropFlagsInheritOnly = $PropagationFlags -eq [Security.AccessControl.PropagationFlags]::InheritOnly
    $PropFlagsInheritOnlyNoPropagate = $PropagationFlags -eq ([Security.AccessControl.PropagationFlags]::InheritOnly -bor [Security.AccessControl.PropagationFlags]::NoPropagateInherit)
    $PropFlagsNoPropagate = $PropagationFlags -eq [Security.AccessControl.PropagationFlags]::NoPropagateInherit

    If ($InheritanceFlags -eq [Security.AccessControl.InheritanceFlags]::None) {
        return [PSPM.Security.ContainerInheritanceFlags]::Container
    }
    ElseIf ($InheritanceFlags -eq [Security.AccessControl.InheritanceFlags]::ContainerInherit) {
        If ($PropFlagsInheritOnly) {
            return [PSPM.Security.ContainerInheritanceFlags]::SubContainers
        }
        ElseIf ($PropFlagsInheritOnlyNoPropagate) {
            return [PSPM.Security.ContainerInheritanceFlags]::ChildContainers
        }
        ElseIf ($PropFlagsNone) {
            return [PSPM.Security.ContainerInheritanceFlags]::ContainerAndSubContainers
        }
        ElseIf ($PropFlagsNoPropagate) {
            return [PSPM.Security.ContainerInheritanceFlags]::ContainerAndChildContainers
        }
    }
    ElseIf ($InheritanceFlags -eq [Security.AccessControl.InheritanceFlags]::ObjectInherit) {
        If ($PropFlagsInheritOnly) {
            return [PSPM.Security.ContainerInheritanceFlags]::Leaves
        }
        ElseIf ($PropFlagsInheritOnlyNoPropagate) {
            return [PSPM.Security.ContainerInheritanceFlags]::ChildLeaves
        }
        ElseIf ($PropFlagsNone) {
            return [PSPM.Security.ContainerInheritanceFlags]::ContainerAndLeaves
        }
        ElseIf ($PropFlagsNoPropagate) {
            return [PSPM.Security.ContainerInheritanceFlags]::ContainerAndChildLeaves
        }
    }
    ElseIf ($InheritanceFlags -eq ([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit)) {
        If ($PropFlagsInheritOnly) {
            return [PSPM.Security.ContainerInheritanceFlags]::SubContainersAndLeaves
        }
        ElseIf ($PropFlagsInheritOnlyNoPropagate) {
            return [PSPM.Security.ContainerInheritanceFlags]::ChildContainersAndChildLeaves
        }
        ElseIf ($PropFlagsNone) {
            return [PSPM.Security.ContainerInheritanceFlags]::ContainerAndSubContainersAndLeaves
        }
        ElseIf ($PropFlagsNoPropagate) {
            return [PSPM.Security.ContainerInheritanceFlags]::ContainerAndChildContainersAndChildLeaves
        }
    }
}