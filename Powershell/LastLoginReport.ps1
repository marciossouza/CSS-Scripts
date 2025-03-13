Connect-AzureAD

Import-Module AzureADPreview

$Users = Get-AzureADUser -All $true
$Report = @()

foreach ($User in $Users) {
    $SignInLogs = Get-AzureADAuditSignInLogs -Filter "UserPrincipalName eq '$($User.UserPrincipalName)'" -Top 1
    $Report += [PSCustomObject]@{
        UserPrincipalName = $User.UserPrincipalName
        LastSignInDate    = $SignInLogs.CreatedDateTime
    }
}

$Report | Export-Csv -Path "C:\Temp\LastLoginReport.csv" -NoTypeInformation
