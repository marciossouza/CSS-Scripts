<#  
.SYNOPSIS 
    This script collects generic data about the installed MIM component(s), event logs and MsInfo
.DESCRIPTION 
    This script collects generic data:
        - relevant registry keys
        - installed .Net Version
        - installed softwares
        - Windows Application Event Log
        - Windows System Event Log
        - Windows Security Event Log
        - Forefront Identity Manager Event Log
        - Forefront Identity Manager Management Agent Event Log
        - Forefromt Idenityt Manager Server Export

.EXAMPLE
    MIM_DataCollector.ps1

.NOTES
- 2024-10-09    Initial Release             
- 2024-11-27    Fixing issue with MsInfo
- 2025-01-15    Added collecting Sync Server Export
- 2025-02-26    Added collecting Service realted information and made the script more generic, retrieveing config from reg
#>

$ErrorActionPreference = "SilentlyContinue"
Write-Host -BackgroundColor DarkYellow -ForegroundColor red "***********************************************************************************************"
Write-Host -BackgroundColor DarkYellow -ForegroundColor red "Starting data collection and Happy Troubleshooting!"
Write-Host -BackgroundColor DarkYellow -ForegroundColor red "***********************************************************************************************"
#create new folder for traces
set-location c:\temp
New-Item -Path "c:\temp\" -Name "msTrace" -ItemType Directory
$traceDir = "C:\temp\msTrace"

#get MSInfo
Write-Host -BackgroundColor DarkYellow -ForegroundColor red "Collecting MS Info"
write-host "collecting info via MSinfo." 
$param ="Msinfo32 /nfo $traceDir\%COMPUTERNAME%-msinfo32.nfo"
invoke-expression -Command $param

Write-Host -BackgroundColor DarkYellow -ForegroundColor red "Collecting RegKeys"
# check if service is installed and get config data
if (Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FIMService\")
{
    Get-Item -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FIMService*" | out-file -filepath $traceDir\$env:ComputerName-RegMIMSrvSvc.txt
    # collect config files
    $svcconfig = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\services\FIMService').Imagepath -replace '"'
    Copy-Item  ($svcconfig + '.config') -Destination ("$traceDir\$env:computername-Microsoft.ResourceManagement.Service.exe.config")
    $portalconfig = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\InetStp').PathWWWRoot -replace '"'
    Copy-Item  ($portalconfig +'\wss\VirtualDirectories\80\web.config') -Destination ("$traceDir\$env:computername-MIM_portal_HTTP_web.config")
    Copy-Item  ($portalconfig +'\wss\VirtualDirectories\443\web.config') -Destination ("$traceDir\$env:computername-MIM_portal_HTTPS_web.config")
 
    # collect IIS MIM Website authentication setting, as I don't know the Portal Name, I guess for HTTP
    $IISPortal =  (Get-WebSite | Where-Object {$_.physicalpath -like "*\inetpub\wwwroot\wss\VirtualDirectories\80"}).name
    if ($IISPortal)
    {  
        ("`nMIM Website: http://" + $IISPortal +':80') | Out-File $traceDir\$env:computername-MIMWebSite.txt -append
        ('                                    Should be  |  is value') | Out-File $traceDir\$env:computername-MIMWebSite.txt -append
        ('-----------------------------------------------------------') | Out-File $traceDir\$env:computername-MIMWebSite.txt -append
        $IISconf = Get-WebConfiguration -filter /system.webServer/security/authentication/windowsAuthentication ('IIS:\Sites\' + $IISPortal +'\')
        ('MIM Website: authPersistNonNTLM        (False) => ' + $IISconf.authPersistNonNTLM) | Out-File $traceDir\$env:computername-MIMWebSite.txt -append
        ('MIM Website: authPersistSingleRequest  (False) => ' + $IISconf.authPersistSingleRequest) | Out-File $traceDir\$env:computername-MIMWebSite.txt -append
        ('MIM Website: useAppPoolCredentials      (True) => ' + $IISconf.useAppPoolCredentials) | Out-File $traceDir\$env:computername-MIMWebSite.txt -append
        ('MIM Website: useKernelMode             (False) => ' + $IISconf.useKernelMode) | Out-File $traceDir\$env:computername-MIMWebSite.txt -append
    }
    # collect IIS MIM Website authentication setting, as I don't know the Portal Name, I guess for HTTPS
    $IISPortal =  (Get-WebSite | Where-Object {$_.physicalpath -like "*\inetpub\wwwroot\wss\VirtualDirectories\443"}).name
    if ($IISPortal)
    {  
        ("`nMIM Website: https://" + $IISPortal + ':443') | Out-File $traceDir\$env:computername-MIMWebSite.txt -append
        ("                                    Should be  |  is value") | Out-File $traceDir\$env:computername-MIMWebSite.txt -append
        ('-----------------------------------------------------------') | Out-File $traceDir\$env:computername-MIMWebSite.txt -append
        $IISconf = Get-WebConfiguration -filter /system.webServer/security/authentication/windowsAuthentication ('IIS:\Sites\' + $IISPortal +'\')
        ('MIM Website: authPersistNonNTLM        (False) => ' + $IISconf.authPersistNonNTLM) | Out-File $traceDir\$env:computername-MIMWebSite.txt -append
        ('MIM Website: authPersistSingleRequest  (False) => ' + $IISconf.authPersistSingleRequest) | Out-File $traceDir\$env:computername-MIMWebSite.txt -append
        ('MIM Website: useAppPoolCredentials      (True) => ' + $IISconf.useAppPoolCredentials) | Out-File $traceDir\$env:computername-MIMWebSite.txt -append
        ('MIM Website: useKernelMode             (False) => ' + $IISconf.useKernelMode) | Out-File $traceDir\$env:computername-MIMWebSite.txt -append
    }
}
# check if sync server is installed and get sync server data
if (Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FIMSynchronizationService\")
{
    Get-ChildItem -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FIMSynchronizationService\*" | Out-File -filePath $traceDir\$env:ComputerName-RegMIMSyncSvc.txt
    New-Item -Path $traceDir  -Name "srvExport" -ItemType Directory
    
    # collect Server Configuration Export
    $svrexp = '& ' + ((Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\FIMSynchronizationService).ImagePath  -replace 'miiserver.exe"','svrexport.exe" ') + $traceDir + '\srvExport'
    Invoke-Expression -Command $svrexp 
    
    # collect sync server config file
    $syncconfig = (Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\services\FIMSynchronizationService).Imagepath -replace '"'
    Copy-Item ($syncconfig + '.config') -Destination ("$traceDir\$env:computername-Miiserver.exe.config")
    # collect extensions
    $ExtFolder = (Get-ItemPropertyValue -Path HKLM:\SYSTEM\CurrentControlSet\services\FIMSynchronizationService\Parameters -Name Path) + '\Extensions'
    Copy-Item $ExtFolder $traceDir\$env:computername-Extensions
} 

# collect all important http and FIMService SPNs
$search = New-Object DirectoryServices.DirectorySearcher([ADSI]"")
$search.filter = "(|((servicePrincipalName=FIM*)(servicePrincipalName=http*)(servicePrincipalName=PCNS*)))"
$results = $search.Findall()
$MIMSpnsFilePath = "$traceDir\$env:COMPUTERNAME-MIMspns.txt"
foreach( $result in $results ) {
    $userEntry = $result.GetDirectoryEntry()
    Add-Content -Path $MIMSpnsFilePath -Value ("Object Name    = " +    $userEntry.name )
    Add-Content -Path $MIMSpnsFilePath -Value ("DN        = " + $userEntry.distinguishedName)
    Add-Content -Path $MIMSpnsFilePath -Value ("Object Cat.    = " + $userEntry.objectCategory)
    Add-Content -Path $MIMSpnsFilePath -Value "servicePrincipalNames:"
    $i=1
    foreach( $SPN in $userEntry.servicePrincipalName ) {
        if ( ($SPN -like 'http/*') -or ($SPN -like 'FIMSERVICE/*') -or ($SPN -like 'pcns*') ) {
            Add-Content -Path $MIMSpnsFilePath -Value  "    SPN ${i}     = $SPN"
            $i+=1
        }
    }
    Add-Content -Path $MIMSpnsFilePath -Value  "----------------------------------------------"
}

if (Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Forefront Identity Manager\2010")
{
    Get-ChildItem -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Forefront Identity Manager\2010\*" | out-file -filePath $traceDir\$env:ComputerName-RegSwMIM.txt
    
}

# Get .Net Version
Write-Host -BackgroundColor DarkYellow -ForegroundColor red "Collecting .Net Version"
Get-ChildItem -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" | out-file -filePath $traceDir\$env:ComputerName-DotNetVer.txt

# Get installed softwares
Write-Host -BackgroundColor DarkYellow -ForegroundColor red "Collecting Installed Software"
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table -AutoSize | out-file -filePath $traceDir\$env:ComputerName-swlist.txt

#export eventlogs
Write-Host -BackgroundColor DarkYellow -ForegroundColor red "Export Eventlogs"
wevtutil.exe export-log Application $traceDir\$env:ComputerName-Application.evtx /overwrite:true
wevtutil.exe export-log System $traceDir\$env:ComputerName-System.evtx /overwrite:true
wevtutil.exe export-log Security $traceDir\$env:ComputerName-Security.evtx /overwrite:true
wevtutil.exe export-log "Forefront Identity Manager" $traceDir\$env:ComputerName-EvtFIM.evtx /overwrite:true
wevtutil.exe export-log "Forefront Identity Manager Management Agent" $traceDir\$env:ComputerName-EvtFIMMA.evtx /overwrite:true

Write-Host -BackgroundColor DarkYellow -ForegroundColor red "Compress logs"
Compress-Archive $traceDir c:\temp\MicrosoftTraceLogs.zip -force

Write-Host -BackgroundColor Green -ForegroundColor Black "***********************************************************************************************"
Write-Host -BackgroundColor Green -ForegroundColor Black "zipping completed. Please provide the support engineer the file: c:\temp\MicrosoftTraceLogs.zip"
Write-Host -BackgroundColor Green -ForegroundColor Black " "
Write-Host -BackgroundColor Green -ForegroundColor Black "thank you for your help here! "
Write-Host -BackgroundColor Green -ForegroundColor Black "***********************************************************************************************"