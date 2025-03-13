# Connect to your Tenant 
Connect-AzureAD
Import-Module ADSync
Get-Command -Module AdSyncConfig
# review the current intervals AzureAD Connect
Get-ADSyncScheduler

# Run the following command to force a complete sync
Start-ADSyncSyncCycle -PolicyType Initial

# initialize the AzureAD Sync immediately
Start-ADSyncSyncCycle -PolicyType Delta

# Run Profile Results including Status
Get-ADSyncRunProfileResult | Format-List ConnectorId,ConnectorName,Result,StartDate,EndDate

Get-ADSyncServerConfiguration

# If you need to make configuration changes, then you want to disable the scheduler. For example, when you configure filtering or
Set-ADSyncScheduler -SyncCycleEnabled $false
Set-ADSyncScheduler -SyncCycleEnabled $true

Test-AzureADConnectHealthConnectivity -Role Sync

# The following command manually registers the Azure AD Connect Health Sync Agent. 
Register-AzureADConnectHealthSyncAgent -AttributeFiltering $false -StagingMode $False

Enable-ADSyncExportDeletionThreshold -DeletionThreshold 500

Register-AzureADConnectHealthSyncAgent
userGAAccount@yorudomain.onmicrosoft.com

Set-ADSyncScheduler -PurgeRunHistoryInterval
Get-ADSyncScheduler

# Test if Joined to Domain
dsregcmd.exe /status shows


Import-Module "C:\Program Files\Microsoft Azure Active Directory Connect\Tools\AdSyncTools.psm1"

Invoke-ADSyncSingleObjectSync