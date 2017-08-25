Function Import-ModuleToSession {
    Param (
        [string]$Name,
        [System.Management.Automation.Runspaces.PSSession]$Session
    )

    If (-not ($LocalModule = Get-Module -Name $Name)) {
        Write-Warning -Message "Module [$Name] does not exist"
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
If (Get-Module -Name $LocalModule.Name) {
    Remove-Module -Name $LocalModule.Name
}
New-Module -Name $LocalModule.Name {
    $($LocalModule.Definition)
    $Exports
} | Import-Module
"@
    $ScriptBlock = [ScriptBlock]::Create($ModuleString)
    Invoke-Command -Session $Session -ScriptBlock $ScriptBlock
}