Function Invoke-ConnectToAzureAD
{
    try
    {
        Import-Module AzureAD
        $test = Get-AzureADTenantDetail
    }
    catch [System.IO.FileNotFoundException]
    {
        Write-Verbose "Please install the module using Install-Module AzureAD"
        Write-Error $error[0].exception -ErrorAction Stop
    }
    catch [System.Management.Automation.ErrorRecord]
    {
        Write-Error $error.exception -ErrorAction Inquire
    }
    catch [Microsoft.Open.Azure.AD.CommonLibrary.AadNeedAuthenticationException]
    {
        Write-Verbose "Please login to Azure AD"
        Connect-AzureAD
    }
}
