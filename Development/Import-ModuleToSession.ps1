﻿Function Import-ModuleToSession {
    Param (
        [string]$ModuleName,
        [System.Management.Automation.Runspaces.PSSession]$Session
    )

    $LocalModule = Get-Module -Name $ModuleName
    If (-not ($LocalModule)) {
        Write-Warning -Message "Module [$ModuleName] does not exist"
        return
    }

    Function Export {
        Param (
            [string]$ParamName,
            $Dictionary
        )

        If ($Dictionary.Keys.Count -gt 0) {
            $Keys = $Dictionary.Keys -join ','
            return " -$ParamName $Keys"
        }
    }

    $Functions = Export 'Function' $LocalModule.ExportedFunctions
    $Aliases   = Export 'Alias'    $LocalModule.ExportedAliases
    $Cmdlets   = Export 'Cmdlet'   $LocalModule.ExportedCmdlets
    $Vars      = Export 'Variable' $LocalModule.ExportedVariables
    $Exports   = "Export-ModuleMember -Function $Functions -Alias $Aliases -Cmdlet $Cmdlets -Variable $Vars"

    $ModuleString = @"
If (Get-Module -Name $ModuleName) {
    Remove-Module -Name $ModuleName
}
New-Module -Name $ModuleName {
    $($LocalModule.Definition)
    $Exports
} | Import-Module
"@
    $ScriptBlock = [ScriptBlock]::Create($ModuleString)
    Invoke-Command -Session $Session -ScriptBlock $ScriptBlock
}