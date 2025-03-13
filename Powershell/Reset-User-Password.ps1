$tenant = '75ad7be9-0795-4cfb-98f9-6c9218da0548' 
Connect-MgGraph -TenantId $tenant -scope UserAuthenticationMethod.Read.All, UserAuthenticationMethod.ReadWrite.All
Select-MgProfile -Name beta
$user = 'itguy@marciosouza.online'
$method = Get-MgUserAuthenticationPasswordMethod -UserId $user
  
Reset-MgUserAuthenticationMethodPassword -UserId $user -AuthenticationMethodId $method.id -NewPassword "zQ7!Ra3MM6hb" 
