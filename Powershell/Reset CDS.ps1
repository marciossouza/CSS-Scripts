Install-Module Microsoft.Graph -Scope CurrentUser

$servicePrincipalId = "abdcdc36-9877-4177-beca-29c2447d6703" 
$synchronizationJobId = "ServiceNowOutDelta.75ad7be907954cfb98f96c9218da0548.ac414a60-a804-48fc-b2e0-e0b9c74a1a67" 


Connect-AzureAD

$params = @{
	Criteria = @{
		ResetScope = "Full"
	}
}

Restart-MgServicePrincipalSynchronizationJob -ServicePrincipalId $servicePrincipalId -SynchronizationJobId $synchronizationJobId -BodyParameter $params