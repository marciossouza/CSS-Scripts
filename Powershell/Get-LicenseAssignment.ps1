# Connect to Microsoft Graph using Connect-MgGraph
Connect-MgGraph -Scopes "User.Read.All"

Import-Module -Name Microsoft.Graph.Authentication

# Get all users using Get-MgUser with a filter
$users = Get-Mguser -All -Property AssignedLicenses, LicenseAssignmentStates, DisplayName | Select-Object DisplayName, AssignedLicenses -ExpandProperty LicenseAssignmentStates | Select-Object DisplayName, AssignedByGroup, State, Error, SkuId


$translationTable = Invoke-RestMethod -Method Get -Uri "https://download.microsoft.com/download/e/3/e/e3e9faf2-f28b-490a-9ada-c6089a1fc5b0/Product%20names%20and%20service%20plan%20identifiers%20for%20licensing.csv" | ConvertFrom-Csv

$output = @()


# Loop through all users and get the AssignedByGroup Details which will list the groupId
foreach ($user in $users) {
    # Get the group ID if AssignedByGroup is not empty
    $skuNamePretty = ($translationTable | Where-Object {$_.GUID -eq $user.SkuId} | Sort-Object Product_Display_Name -Unique).Product_Display_Name
    if ($user.AssignedByGroup -ne $null)
    {
        $groupId = $user.AssignedByGroup
        $groupName = Get-MgGroup -GroupId $groupId | Select-Object -ExpandProperty DisplayName
        Write-Host "$($user.DisplayName) is assigned by group - $($groupName)" -ErrorAction SilentlyContinue -ForegroundColor Yellow
        $result = [pscustomobject]@{
            User=$user.DisplayName
            AssignedByGroup=$true
            GroupName=$groupName
            License=$skuNamePretty
        }
        $output += $result
    }

    else {
    $result = [pscustomobject]@{
            User=$user.DisplayName
            AssignedByGroup=$false
            GroupName="NA"
            License=$skuNamePretty
        }
        $output += $result
        Write-Host "$($user.DisplayName) is Not assigned by group" -ErrorAction SilentlyContinue -ForegroundColor Cyan
    }
        
    
}

# Display the result
$output | ft