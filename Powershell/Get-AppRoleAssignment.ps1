#$credential = Get-Credential

# Your tenant id (in Azure Portal, under Azure Active Directory -> Overview )
$TenantID="75ad7be9-0795-4cfb-98f9-6c9218da0548"
# Microsoft Graph App ID (DON'T CHANGE)
$GraphAppId = "00000003-0000-0000-c000-000000000000"
# Name of the manage identity (same as the Logic App name)
$DisplayNameOfMSI="Sharepoint-App" 
# Check the Microsoft Graph documentation for the permission you need for the operation
$PermissionName = "Sites.FullControl.All" 

# Install the module (You need admin on the machine)
#Install-Module AzureAD 

Connect-AzureAD -TenantId $TenantID -Credential $credential
$MSI = (Get-AzureADServicePrincipal -Filter "displayName eq '$DisplayNameOfMSI'")
Start-Sleep -Seconds 10
$GraphServicePrincipal = Get-AzureADServicePrincipal -Filter "appId eq '$GraphAppId'"
$AppRole = $GraphServicePrincipal.AppRoles | `
Where-Object {$_.Value -eq $PermissionName -and $_.AllowedMemberTypes -contains "Application"}
Start-Sleep -Seconds 10

Get-AzureADServiceAppRoleAssignedTo -ObjectId $MSI.ObjectId
Import-Module Microsoft.Graph.Applications
Connect-MgGraph -TenantId $TenantID 

Get-MgServicePrincipal -Filter "displayName eq $DisplayNameOfMSI" -Property "id,displayName,appId,appRoles"
Get-MgServicePrincipal -All -Property "id,displayName,appId,appRoles" | Where-Object {"displayName -eq Portifolios"}