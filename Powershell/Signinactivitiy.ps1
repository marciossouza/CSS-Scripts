<#
Written by Derrick Baxter
4/11/2023
Retrieves by graphapi the last signin audit logs
pick the signin activity below (unrem) and run
Update the $outputfile location from c:\temp\name as wanted - date and .csv are automatically added to avoid overwritting  

IMPORTANT!!!

To consent for users to run this script a global admin will need to run the following

$sp = Get-MgServicePrincipal | ?{$_.displayname -eq "Microsoft Graph"}
$resource = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"
$principalid = "c65e71cf-e7d7-46de-b3f4-4592a46e9ac3"
$scope1 ="auditlog.read.all"
$scope2 ="directory.read.all"
$scope3 ="user.read.all"
$today = Get-Date -Format "yyyy-MM-dd"
$expiredate1 = get-date
$expiredate2 = $expiredate1.AddDays(365).ToString("yyyy-MM-dd")
$params = @{
    ClientId = $sp.id
    ConsentType = "Principal"
    ResourceId = $resource.id
    principalId = $principalid
    Scope = "$scope1" + " " + "$scope2"+ " " + "$scope3"
    startTime = "$today"
    expiryTime = "$expiredate2"
    
}

$InitialConsented = New-MgOauth2PermissionGrant -BodyParameter $params

You may need to update the connect-mggraph to have the -environment USGov or as needed -tenantid <tenantid> can be added as needed.
#>

Connect-MgGraph -scopes "directory.read.all, auditlog.read.all, user.read.all" #-TenantId 'ffedfa21-ac42-4d17-bcf9-2618e89d9545'  

#Change this date if you wanna filter by date. Keep the format as 'yyyy-MM-ddT00:00:00Z'
$filterDate = "2024-09-10T00:00:00Z"

#by UPN
#$ApiUrl = "https://graph.microsoft.com/v1.0/users?`$filter=startswith(userprincipalname,'derrick.baxter@tenant.onmicrosoft.com')&`$select=displayName,userprincipalname,signInActivity"

#by date
$ApiUrl = "https://graph.microsoft.com/v1.0/users?`$filter=signInActivity/lastSignInDateTime+le+" + $filterDate + "&`$select=signInActivity,displayName,userprincipalname,CreatedDateTime,userprincipalname,accountEnabled"


#Successfull sign-in by date - Beta
#$ApiUrl = "https://graph.microsoft.com/beta/users?`$filter=signInActivity/lastSuccessfulSignInDateTime+le+" + $filterDate + "&`$select=displayName,userprincipalname,signInActivity,CreatedDateTime,userprincipalname,accountEnabled"

#users
#$ApiUrl = "https://graph.microsoft.com/v1.0/users?`$select=displayName,signInActivity,CreatedDateTime,userprincipalname,accountEnabled"

Write-Host "Query " $ApiUrl

$SigninLogProperties =@()
$auditlog = Invoke-MgGraphRequest -Uri $ApiUrl -method get
$checkformorelogs = $auditlogusers.'@odata.nextlink'
do
{
    foreach ($item in $auditlog.value){
     $dn = $item.Displayname
     $upn = $item.userprincipalname 
     $sidate = $item.signinactivity.lastSignInDateTime
     $nidate = $item.signinactivity.lastNonInteractiveSignInDateTime
     $sucSignIn = $item.signinactivity.lastSuccessfulSignInDateTime
     $createdDate =  $item.CreatedDateTime
     $enabled = $item.accountEnabled

     $SigninLogProperties += New-Object Object |
                                Add-Member -NotePropertyName DisplayName -NotePropertyValue $dn -PassThru |
                                Add-Member -NotePropertyName UserprincipalName -NotePropertyValue $upn -PassThru |
                                Add-Member -NotePropertyName ObjectID -NotePropertyValue $item.id -PassThru |
                                Add-Member -NotePropertyName LastSignin_Date -NotePropertyValue $sidate -PassThru |
                                Add-Member -NotePropertyName LastNonInteractiveSignin_Date -NotePropertyValue $nidate -PassThru|
                                Add-Member -NotePropertyName lastSuccessfulSignIn_Date  -NotePropertyValue $sucSignIn -PassThru|
                                Add-Member -NotePropertyName createdDateTime  -NotePropertyValue $createdDate -PassThru|
                                Add-Member -NotePropertyName acccountEnabled  -NotePropertyValue $enabled -PassThru
    }
    $checkformorelogs = $auditlog.'@odata.nextlink'
    
    if($checkformorelogs -ne $null)
    {write-host "getting more logs"
    $counter++
    if($counter = 2000)
    {
        $counter = 0
        start-sleep 5
        $auditlog = Invoke-MgGraphRequest -Uri $checkformorelogs -method get
    }
    
    }
}
while ($checkformorelogs -ne $null)
$tdy = get-date -Format "MM-dd-yyyy_hh.mm.ss"
$outputfile = "c:\temp\signinactivity_"+$tdy+".csv"
$SigninLogProperties | export-csv -Path $outputfile -NoTypeInformation -Encoding UTF8
Disconnect-MgGraph 