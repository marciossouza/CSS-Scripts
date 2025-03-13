Get-ADForest DOMAINNAME | Format-Table
Get-ADDomain DOMAINNAME  | fl PDCEmulator,RIDMaster,InfrastructureMaster,SchemaMaster,DomainNamingMaster
--------------
Example:
# PowerShell ADDomain and ADForst
Get-ADDomain raidbighead.com | format-table PDCEmulator,RIDMaster,InfrastructureMaster | fl
Get-ADDomain raidbighead.com | Select-Object PDCEmulator,RIDMaster,InfrastructureMaster | fl
Get-ADForest | Select-Object DomainNamingMaster, SchemaMaster | fl
=======================
# command Line to find FSMO roles
netdom query fsmo
-------------
Currently in Windows there are five FSMO roles:
Schema master
Domain naming master
RID master
PDC emulator
Infrastructure master
https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/find-servers-holding-fsmo-role
------------
=====================
Install LDP
dism /online /enable-feature /featurename:Printing-LPDPrintService
-----------
ldp.exe

Recover Deleted User
https://social.technet.microsoft.com/wiki/contents/articles/5549.recover-active-directory-deleted-items-using-ldp-exe.aspx
-----------
=====================
DCDiag
https://activedirectorypro.com/dcdiag-check-domain-controller-health/
-----------
Example:
#Example: Dcdiag results looking at Server health
dcdiag /s:Win2019DC /v
dcdiag /s:Win2019DC /c /v /f:C:\Scripts\NewHireTraining\dcdiag.txt

# Looking at RID Pool just for Fun
Dcdiag.exe /TEST:RidManager /v | find /i "Available RID Pool for the Domain"

#Check DNS Health
dcdiag /s:Win2019DC /test:dns
===================
# looking at DC that have GC enabled
Get-ADDomainController -Filter {IsGlobalCatalog -eq $true} | Format-Table HostName,IsGlobalCatalog
===================
# Replication issues and Troubleshooting
repadmin /showrepl
===================
Finding the location of FSMO Roles
Netdom Query FSMO
dcdiag /test:knowsofroleholders /v
===================
Seizing Operation Master Roles or FSMO Roles.
 NTDSUTIL
 Ntdsutil: roles
 FSMO Roles: Connections
 Server Connections: Connect to Server “server name”