Import-Module Microsoft.Graph.Users.Actions

$authenticationMethodId = "28c10230-6103-485e-b985-444c60001490"

$userId = "31c7d221-8d68-40f0-826e-555417d8e4ba"

Connect-MgGraph -Scopes "UserAuthenticationMethod.ReadWrite.All"

$params = @{
	newPassword = "Cuyo5459"
}

Reset-MgUserAuthenticationMethodPassword -UserId $userId -AuthenticationMethodId $authenticationMethodId -BodyParameter $params