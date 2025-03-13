$DestinationTenantId = "75ad7be9-0795-4cfb-98f9-6c9218da0548"
$MsiName = "Sharepoint-App" # Name of system-assigned or user-assigned managed service identity. (System-assigned use same name as resource).

#Sites.FullControl.All	Application	a82116e5-55eb-4c41-a434-62fe8a61c773 

$oPermissions = @(
  "Sites.FullControl.All"
)

$GraphAppId = "00000003-0000-0000-c000-000000000000" # Don't change this.

$oMsi = Get-AzADServicePrincipal -Filter "displayName eq '$MsiName'"
$oGraphSpn = Get-AzADServicePrincipal -Filter "appId eq '$GraphAppId'"

$oAppRole = $oGraphSpn.AppRole | Where-Object {($_.Value -in $oPermissions) -and ($_.AllowedMemberType -contains "Application")}

Connect-MgGraph -TenantId $TenantID -Scopes 'Application.Read.All','Application.ReadWrite.All','AppRoleAssignment.ReadWrite.All','Directory.AccessAsUser.All','Directory.Read.All','Directory.ReadWrite.All'

foreach($AppRole in $oAppRole)
{
  $oAppRoleAssignment = @{
    "PrincipalId" = $oMSI.Id
    #"ResourceId" = $GraphAppId
    "ResourceId" = $oGraphSpn.Id
    "AppRoleId" = $AppRole.Id
  }
  
  (Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $oAppRoleAssignment.PrincipalId).AppRoleId
  (Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $oAppRoleAssignment.PrincipalId).Id

}
