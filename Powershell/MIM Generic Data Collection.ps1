
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

#ToDo: export run history

.NOTES
- 2024-10-09    Initial Release             
- 2024-11-27    Fixing issue with MsInfo
- 2025-01-15    Added collecting Sync Server Export
#>

$ErrorActionPreference = "SilentlyContinue"
Write-Host -BackgroundColor DarkYellow -ForegroundColor red "***********************************************************************************************"
Write-Host -BackgroundColor DarkYellow -ForegroundColor red "Starting data collection and Happy Troubleshooting!"
Write-Host -BackgroundColor DarkYellow -ForegroundColor red "***********************************************************************************************"
#create new folder for traces
set-location c:\temp
New-Item -Path "c:\temp\" -Name "msTrace" -ItemType Directory

#get MSInfo
Write-Host -BackgroundColor DarkYellow -ForegroundColor red "Collecting MS Info"
write-host "collecting info via MSinfo." 
$param ='Msinfo32 /nfo C:\temp\msTrace\%COMPUTERNAME%-msinfo32.nfo'
cmd.exe /c $param

Write-Host -BackgroundColor DarkYellow -ForegroundColor red "Collecting RegKeys"
# check if service is installed and get config data
if (Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FIMService\")
{
    Get-Item -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FIMService*" > c:\temp\msTrace\$env:ComputerName-RegMIMSrvSvc.txt
}
# check if sync server is installed and get sync server data
if (Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FIMSynchronizationService\")
{
    Get-ChildItem -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FIMSynchronizationService\*" > c:\temp\msTrace\$env:ComputerName-RegMIMSyncSvc.txt
    New-Item -Path "c:\temp\msTrace\"  -Name "srvExport" -ItemType Directory
    sl "C:\Program Files\Microsoft Forefront Identity Manager\2010\Synchronization Service\Bin"
    $param ='svrexport.exe c:\temp\msTrace\srvExport\'
    cmd.exe /c $param
}

if (Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Forefront Identity Manager\2010")
{
    Get-ChildItem -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Forefront Identity Manager\2010\*" > c:\temp\msTrace\$env:ComputerName-RegSwMIM.txt
    
}

# Get .Net Version
Write-Host -BackgroundColor DarkYellow -ForegroundColor red "Collecting .Net Version"
Get-ChildItem -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" > c:\temp\msTrace\$env:ComputerName-DotNetVer.txt

# Get installed softwares
Write-Host -BackgroundColor DarkYellow -ForegroundColor red "Collecting Installed Software"
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table -AutoSize > c:\temp\msTrace\$env:ComputerName-swlist.txt

#export eventlogs
Write-Host -BackgroundColor DarkYellow -ForegroundColor red "Export Eventlogs"
wevtutil.exe export-log Application c:\temp\msTrace\$env:ComputerName-Application.evtx /overwrite:true
wevtutil.exe export-log System c:\temp\msTrace\$env:ComputerName-System.evtx /overwrite:true
wevtutil.exe export-log Security c:\temp\msTrace\$env:ComputerName-Security.evtx /overwrite:true
wevtutil.exe export-log "Forefront Identity Manager" c:\temp\msTrace\$env:ComputerName-EvtFIM.evtx /overwrite:true
wevtutil.exe export-log "Forefront Identity Manager Management Agent" c:\temp\msTrace\$env:ComputerName-EvtFIMMA.evtx /overwrite:true

Write-Host -BackgroundColor DarkYellow -ForegroundColor red "Compress logs"
Compress-Archive c:\temp\msTrace c:\temp\MicrosoftTraceLogs.zip -force

Write-Host -BackgroundColor Green -ForegroundColor Black "***********************************************************************************************"
Write-Host -BackgroundColor Green -ForegroundColor Black "zipping completed. Please provide the support engineer the file: c:\temp\MicrosoftTraceLogs.zip"
Write-Host -BackgroundColor Green -ForegroundColor Black " "
Write-Host -BackgroundColor Green -ForegroundColor Black "thank you for your help here! "
Write-Host -BackgroundColor Green -ForegroundColor Black "***********************************************************************************************"
