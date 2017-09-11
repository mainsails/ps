Function ConvertTo-PropagationFlag {
    <#
    .SYNOPSIS
        Converts a 'PSPM.Security.ContainerInheritanceFlags' value to a 'System.Security.AccessControl.PropagationFlags' value
    .DESCRIPTION
        The 'PSPM.Security.ContainerInheritanceFlags' enumeration encapsulates both 'System.Security.AccessControl.PropagationFlags' and 'System.Security.AccessControl.InheritanceFlags'
        Make sure you also call 'ConvertTo-InheritancewFlags' to get the inheritance value
    .PARAMETER ContainerInheritanceFlag
        The value to convert to an 'PropagationFlags' value
    .EXAMPLE
        ConvertTo-PropagationFlag -ContainerInheritanceFlag ContainerAndSubContainersAndLeaves
        Returns 'PropagationFlags.None'
    .OUTPUTS
        System.Security.AccessControl.PropagationFlags
    .LINK
        ConvertTo-InheritanceFlag
    .LINK
        Grant-Permission
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [Alias('ContainerInheritanceFlags')]
        [PSPM.Security.ContainerInheritanceFlags]$ContainerInheritanceFlag
    )

    $Flags = [Security.AccessControl.PropagationFlags]
    $Map = @{
        'Container'                                 =  $Flags::None;
        'SubContainers'                             =  $Flags::InheritOnly;
        'Leaves'                                    =  $Flags::InheritOnly;
        'ChildContainers'                           = ($Flags::InheritOnly -bor $Flags::NoPropagateInherit);
        'ChildLeaves'                               = ($Flags::InheritOnly -bor $Flags::NoPropagateInherit);
        'ContainerAndSubContainers'                 =  $Flags::None;
        'ContainerAndLeaves'                        =  $Flags::None;
        'SubContainersAndLeaves'                    =  $Flags::InheritOnly;
        'ContainerAndChildContainers'               =  $Flags::NoPropagateInherit;
        'ContainerAndChildLeaves'                   =  $Flags::NoPropagateInherit;
        'ContainerAndChildContainersAndChildLeaves' =  $Flags::NoPropagateInherit;
        'ContainerAndSubContainersAndLeaves'        =  $Flags::None;
        'ChildContainersAndChildLeaves'             = ($Flags::InheritOnly -bor $Flags::NoPropagateInherit);
    }
    $Key = $ContainerInheritanceFlag.ToString()
    If ($Map.ContainsKey($Key)) {
        return $Map[$Key]
    }

    Write-Error ('Unknown PSPM.Security.ContainerInheritanceFlags enumeration value {0}.' -f $ContainerInheritanceFlag)
}