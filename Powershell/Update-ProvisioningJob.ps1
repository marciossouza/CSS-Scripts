# Variables
$EnterpriseAppId = "0a5fa3a3-450c-406f-8e27-92c898ca0d14"  # Replace with the app's Service Principal ID
$SynchronizationJobId = "gsuite.ffedfa21ac424d17bcf92618e89d9545.e6070b5a-0678-412d-b84c-158195f2b14a"  # Replace with your synchronization job ID
$CsvFilePath = "c:\temp\groups.csv"  # Replace with the path to your CSV file

# Read group names from CSV
$GroupsToAdd = Import-Csv -Path $CsvFilePath | Select-Object -ExpandProperty GroupName

# Fetch Group IDs
$GroupIds = @()
foreach ($GroupName in $GroupsToAdd) {
    $Group = Get-MgGroup -Filter "displayName eq '$GroupName'"
    if ($Group) {
        $GroupIds += @{ objectId = $Group.Id }
        Write-Host "Group '$GroupName' added to the provisioning list."
    } else {
        Write-Host "Group '$GroupName' not found." -ForegroundColor Red
    }
}

# Build the SCIM Scoping Payload
$Payload = @{
    scoping = @{
        groupFilter = $GroupIds
    }
}


Connect-MgGraph

# Update Provisioning Scope in Enterprise App

Update-MgServicePrincipalSynchronizationJob -ServicePrincipalId $EnterpriseAppId -SynchronizationJobId $SynchronizationJobId -BodyParameter $Payload
Write-Host "Provisioning scope updated successfully."

