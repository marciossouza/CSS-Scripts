
Connect-AzureAD
$UPN = "dillard@marcit0.onmicrosoft.com"
$id = (Get-AzureADUser -ObjectId $UPN).immutableid
$hex=([system.convert]::FromBase64String("$id") | ForEach-Object ToString X2) -join ' '
Write-Host $hex