$localuser = "sarah"
$ADUser = "446682de-69d4-40dd-88ae-fcfcc89a42ca" 

$guid = [guid]((Get-ADUser -Identity "$localuser").objectGuid)

$immutableId = [System.Convert]::ToBase64String($guid.ToByteArray())


Connect-AzureAD

Set-AzureADUser -ObjectId $ADUser -ImmutableId $immutableID