# Import the Microsoft Graph module 
Import-Module Microsoft.Graph

# Authenticate to Microsoft Graph (you may need to provide your credentials) 
Connect-MgGraph  -Scopes "User.Read.All" -TenantId 'ffedfa21-ac42-4d17-bcf9-2618e89d9545'



# Get all users using Get-MgUser 
Write-Host "Get all users..."
$users = Get-MgUser -All -ConsistencyLevel eventual -Property Id, DisplayName, UserPrincipalName,UserType,OnPremisesSyncEnabled,CompanyName, Identities, CreationType


# Specify the output CSV file path 
$outputCsvPath = "C:\\Temp\\Users.csv"

# Create a custom object to store user data 
$userData = @()

# Loop through each user and collect relevant data 
Write-Host "Loop through each user and collect relevant data"

foreach ($user in $users) { 
    $Ids = $user.Identities

    $email = "" 
    $cpf = ""

    foreach($id in $Ids){

       if ($id.SignInType.ToString() -eq 'emailAddress') 
       {
            $email = $id.IssuerAssignedId.ToString()
        }

       if ($id.SignInType.ToString() -eq 'userName') 
       {
            $cpf = $id.IssuerAssignedId.ToString()
        }
    }
    
    
    $userObject = [PSCustomObject]@{ 
        Id = $user.Id 
        DisplayName = $user.DisplayName 
        UserPrincipalName = $user.UserPrincipalName 
        UserType = $user.UserType 
        OnPremisesSyncEnabled = $user.OnPremisesSyncEnabled 
        CompanyName = $user.CompanyName 
        CreationType = $user.CreationType     
        CPF =  $cpf
        Email = $email
        
    } 
    $userData += $userObject 
    
}


# Export user data to a CSV file 
$userData | Export-Csv -Path $outputCsvPath -NoTypeInformation

# Disconnect from Microsoft Graph 
Disconnect-MgGraph

Write-Host "User data exported to $outputCsvPath"