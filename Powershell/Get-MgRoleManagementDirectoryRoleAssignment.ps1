﻿Connect-MgGraph -Scopes RoleManagement.Read.Directory,Directory.Read.All

Select-MgProfile -Name beta

$EligiblePIMRoles = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -All -ExpandProperty *
$AssignedPIMRoles = Get-MgRoleManagementDirectoryRoleAssignmentSchedule -All -ExpandProperty *

$PIMRoles = $EligiblePIMRoles + $AssignedPIMRoles

$Report = [System.Collections.Generic.List[Object]]::new()

foreach ($a in $PIMRoles) {
    $regex = "^([^.]+)\.([^.]+)\.(.+)$"
    $a.Principal.AdditionalProperties.'@odata.type' -match $regex | out-null

    $obj = [pscustomobject][ordered]@{
        Assigned                 = $a.Principal.AdditionalProperties.displayName
        "Assigned Type"          = $matches[3]
        "Assigned Role"          = $a.RoleDefinition.DisplayName
        "Assigned Role Scope"    = $a.directoryScopeId
        "Assignment Type"        = (&{if ($a.AssignmentType -eq "Assigned") {"Active"} else {"Eligible"}})
        "Is Built In"            = $a.roleDefinition.isBuiltIn
        "Created Date"           = $a.CreatedDateTime
        "Expiration type"        = $a.ScheduleInfo.Expiration.type
        "Expiration Date"        = switch ($a.ScheduleInfo.Expiration.EndDateTime) {
            {$a.ScheduleInfo.Expiration.EndDateTime -match '20'} {$a.ScheduleInfo.Expiration.EndDateTime}
            {$a.ScheduleInfo.Expiration.EndDateTime -notmatch '20'} {"N/A"}
        }
    }
    $report.Add($obj)
}

$Report | Export-CSV -path C:\temp\AllPIMRolesExport.csv