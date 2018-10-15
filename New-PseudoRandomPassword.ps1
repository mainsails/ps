Function New-PseudoRandomPassword {
    <#
    .SYNOPSIS
        Password Generator
    .DESCRIPTION
        A Password Generator that creates a random password of the specified length using the .NET GeneratePassword method.
        The generated password only contains alphanumeric characters and the following punctuation marks: !@#$%^&*()_-+=[{]};:<>|./?.
        No hidden or non-printable control characters are included in the generated password.
    .PARAMETER PasswordLength
        The number of characters in the generated password. The length must be between 1 and 128 characters.
    .PARAMETER MinSpecialCharCount
        The minimum number of non-alphanumeric characters (such as @, #, !, %, &, and so on) in the generated password.
    .EXAMPLE
        New-PseudoRandomPassword -PasswordLength 12 -MinSpecialCharCount 2
        Generates a new 12-character password with at least 2 non-alphanumeric characters.
    .OUTPUTS
        System.String
    .LINK
        https://docs.microsoft.com/en-us/dotnet/api/system.web.security.membership.generatepassword
    #>

    [Cmdletbinding()]
    Param(
        [ValidateRange(1,128)]
        [int]$PasswordLength = 15,
        [int]$MinSpecialCharCount = 1
    )

    Begin {
        # Add the System.Web assembly
        Add-Type -AssemblyName System.Web
    }
    Process {
        # Generate password using the .NET GeneratePassword method
        [System.Web.Security.Membership]::GeneratePassword($PasswordLength,$MinSpecialCharCount)
    }
    End {}
}