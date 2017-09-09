Function ConvertTo-InheritanceFlag {
    <#
    .SYNOPSIS
        Converts a 'PSPM.Security.ContainerInheritanceFlags' value to a 'System.Security.AccessControl.InheritanceFlags' value
    .DESCRIPTION
        The 'PSPM.Security.ContainerInheritanceFlags' enumeration encapsulates both 'System.Security.AccessControl.InheritanceFlags' and 'System.Security.AccessControl.PropagationFlags'
        Make sure you also call 'ConvertTo-PropagationFlag' to get the propagation value
    .PARAMETER ContainerInheritanceFlag
        The value to convert to an 'InheritanceFlags' value
    .EXAMPLE
        ConvertTo-InheritanceFlag -ContainerInheritanceFlag ContainerAndSubContainersAndLeaves
        Returns 'InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit'
    .OUTPUTS
        System.Security.AccessControl.InheritanceFlags
    .LINK
        ConvertTo-PropagationFlag
    .LINK
        Grant-Permission
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [Alias('ContainerInheritanceFlags')]
        [PSPM.Security.ContainerInheritanceFlags]$ContainerInheritanceFlag
    )

    $Flags = [Security.AccessControl.InheritanceFlags]
    $Map = @{
        'Container' =                                  $Flags::None;
        'SubContainers' =                              $Flags::ContainerInherit;
        'Leaves' =                                     $Flags::ObjectInherit;
        'ChildContainers' =                            $Flags::ContainerInherit;
        'ChildLeaves' =                                $Flags::ObjectInherit;
        'ContainerAndSubContainers' =                  $Flags::ContainerInherit;
        'ContainerAndLeaves' =                         $Flags::ObjectInherit;
        'SubContainersAndLeaves' =                    ($Flags::ContainerInherit -bor $Flags::ObjectInherit);
        'ContainerAndChildContainers' =                $Flags::ContainerInherit;
        'ContainerAndChildLeaves' =                    $Flags::ObjectInherit;
        'ContainerAndChildContainersAndChildLeaves' = ($Flags::ContainerInherit -bor $Flags::ObjectInherit);
        'ContainerAndSubContainersAndLeaves' =        ($Flags::ContainerInherit -bor $Flags::ObjectInherit);
        'ChildContainersAndChildLeaves' =             ($Flags::ContainerInherit -bor $Flags::ObjectInherit);
    }
    $Key = $ContainerInheritanceFlag.ToString()
    If ($Map.ContainsKey($key)) {
        return $Map[$Key]
    }

    Write-Error ('Unknown PSPM.Security.ContainerInheritanceFlags enumeration value {0}.' -f $ContainerInheritanceFlag)
}