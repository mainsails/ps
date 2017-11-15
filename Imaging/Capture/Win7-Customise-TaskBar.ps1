Function Set-PinnedApplication {
    <#
    .SYNOPSIS
        Needs tidy/rewrite
        Needs comments
        This function is used to Pin and Unpin programs from the taskbar and Start-menu in Windows 7 and Windows Server 2008 R2
    .DESCRIPTION
        The function has mandatory parameters :
        Action: PinToTaskbar, PinToStartMenu, UnPinFromTaskbar, UnPinFromStartMenu
        FilePath: The path to the program to perform the action on
    .EXAMPLE
        Set-PinnedApplication -Action PinToTaskbar -FilePath "C:\WINDOWS\system32\notepad.exe"
    .EXAMPLE
        Set-PinnedApplication -Action UnPinFromTaskbar -FilePath "C:\WINDOWS\system32\notepad.exe"
    .EXAMPLE
        Set-PinnedApplication -Action PinToStartMenu -FilePath "C:\WINDOWS\system32\notepad.exe"
    .EXAMPLE
        Set-PinnedApplication -Action UnPinFromStartMenu -FilePath "C:\WINDOWS\system32\notepad.exe"
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)][string]$Action,
        [Parameter(Mandatory=$true)][string]$FilePath
    )
    If(-not (Test-Path $FilePath)) {
        Throw "FilePath does not exist."
    }

    Function InvokeVerb {
        Param(
          [string]$FilePath,$verb
        )
        
        $verb = $verb.Replace("&","")
        $path= split-path $FilePath
        $shell=new-object -com "Shell.Application"
        $folder=$shell.Namespace($path)
        $item = $folder.Parsename((split-path $FilePath -leaf))
        $itemVerb = $item.Verbs() | ? {$_.Name.Replace("&","") -eq $verb}
        If ($itemVerb -eq $null) {
            Throw "Verb $verb not found."
        }
        Else {
            $itemVerb.DoIt()
        }

    }
    Function GetVerb {
        Param([int]$verbId)
            Try {
                $t = [type]"CosmosKey.Util.MuiHelper"
            }
            Catch {
                $def = [Text.StringBuilder]""
                [void]$def.AppendLine('[DllImport("user32.dll")]')
                [void]$def.AppendLine('public static extern int LoadString(IntPtr h,uint id, System.Text.StringBuilder sb,int maxBuffer);')
                [void]$def.AppendLine('[DllImport("kernel32.dll")]')
                [void]$def.AppendLine('public static extern IntPtr LoadLibrary(string s);')
                add-type -MemberDefinition $def.ToString() -name MuiHelper -namespace CosmosKey.Util
            }
            If ($global:CosmosKey_Utils_MuiHelper_Shell32 -eq $null) {
                $global:CosmosKey_Utils_MuiHelper_Shell32 = [CosmosKey.Util.MuiHelper]::LoadLibrary("shell32.dll")
            }
            $maxVerbLength=255
            $verbBuilder = new-object Text.StringBuilder "",$maxVerbLength
            [void][CosmosKey.Util.MuiHelper]::LoadString($CosmosKey_Utils_MuiHelper_Shell32,$verbId,$verbBuilder,$maxVerbLength)
            return $verbBuilder.ToString()
    }

    $verbs = @{
        "PintoStartMenu"=5381
        "UnpinfromStartMenu"=5382
        "PintoTaskbar"=5386
        "UnpinfromTaskbar"=5387
    }

    If ($verbs.$Action -eq $null) {
        Throw "Action $action not supported`nSupported actions are:`n`tPintoStartMenu`n`tUnpinfromStartMenu`n`tPintoTaskbar`n`tUnpinfromTaskbar"
    }
    InvokeVerb -FilePath $FilePath -Verb $(GetVerb -VerbId $verbs.$action)
}


# Customise
Set-PinnedApplication -Action PinToTaskbar   -FilePath "C:\Program Files (x86)\Microsoft Office\Office14\OUTLOOK.EXE"
Set-PinnedApplication -Action PinToStartMenu -FilePath "C:\Program Files (x86)\Microsoft Office\Office14\OUTLOOK.EXE"
Set-PinnedApplication -Action PinToStartMenu -FilePath "C:\Program Files (x86)\Microsoft Office\Office14\WINWORD.EXE"
Set-PinnedApplication -Action PinToStartMenu -FilePath "C:\Program Files (x86)\Microsoft Office\Office14\EXCEL.EXE"
Set-PinnedApplication -Action PinToStartMenu -FilePath "C:\Program Files (x86)\Microsoft Office\Office14\POWERPNT.EXE"
Set-PinnedApplication -Action PinToStartMenu -FilePath "C:\Program Files (x86)\Microsoft Office\Office14\ONENOTE.EXE"
Set-PinnedApplication -Action PinToStartMenu -FilePath "C:\Program Files (x86)\Microsoft Office\Office14\MSPUB.EXE"






