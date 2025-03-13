Import-Module ActiveDirectory

$csvPath = "C:\path\to\users.csv"  # Update with your actual CSV file path

Import-Csv $csvPath | ForEach-Object {
    $username = $_.username
    $password = $_.password
    $firstName = $_.first_name
    $lastName = $_.last_name
    $email = $_.email

    New-ADUser -Name "$firstName $lastName" `
               -GivenName $firstName `
               -Surname $lastName `
               -SamAccountName $username `
               -UserPrincipalName $email `
               -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) `
               -Enabled $true
}
