####################################################
#Expose default mappings for enterprise app
####################################################

# To install Microsoft.Graph if not installed run:
#Install-Module Microsoft.Graph -Scope CurrentUser
#Update-Module Microsoft.Graph

#Get-InstalledModule Microsoft.Graph

# To start the process of exposing the attriutes use:
$appObjectID = '0a5fa3a3-450c-406f-8e27-92c898ca0d14' #replace with your newly created app OBJECT ID

#Authenticate to your lab tenant and provide consent to Graph to these scopes.
Connect-MgGraph -Scopes Directory.ReadWrite.All, Application.Read.All
#Select-MgProfile -Name beta

#Retrieving template ID of the Enterprise application
$url = 'https://graph.microsoft.com/beta/servicePrincipals/'+$appObjectID+'/synchronization/templates'
$applicationTemplate = Invoke-MgGraphRequest -Method GET -Uri $url

#Building the body based on the templateId of the app
$body = '{
    "templateId": "'+$applicationTemplate.value.id[1]+'"
}'

#Creating synchronization job for this application, taking the templateId in the body
$url = 'https://graph.microsoft.com/beta/servicePrincipals/'+$appObjectID+'/synchronization/jobs'
Invoke-MgGraphRequest -Method POST -Uri $url -Body $body 