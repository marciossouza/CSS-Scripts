echo off 

cls 

color 30 

echo **************************************** 

echo. 

echo start script and happy troubleshooting! 

echo. 

echo **************************************** 

echo. 

echo. 

 

cd c:\temp 

 

set KdcDebugFlags=0xfffff 

set ldapDebugFlags=0x1FFFDFF3 

set NtlmDebugFlags=0x1ffDf 

set SslDebugFlags=0xffffffff 

set KerbDebugFlags=0x6ffffff 

 

echo Configrure Trace Level 

reg ADD HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\ldap\Tracing\miiserver.exe /f 

reg add HKLM\SYSTEM\CurrentControlSet\Control\LSA /v SPMInfoLevel /t REG_DWORD /d 0xC03E3F /f 

reg add HKLM\SYSTEM\CurrentControlSet\Control\LSA /v LogToFile /t REG_DWORD /d 1 /f 

reg add HKLM\SYSTEM\CurrentControlSet\Control\LSA /v NegEventMask /t REG_DWORD /d 0xF /f 

 

mkdir .\logs 

del /f /q .\logs\*.* 

 

 

echo setup tracing 

logman.exe start kdc -p {1BBA8B19-7F31-43c0-9643-6E911F79A06B} %KdcDebugFlags% -o .\logs\kdc.etl -ets 

logman.exe start kerb -p {6B510852-3583-4e2d-AFFE-A67F9F223438} %KerbDebugFlags% -o .\logs\kerb.etl -ets 

logman.exe start ldap -p {099614A5-5DD7-4788-8BC9-E29F43DB28FC} %ldapDebugFlags% -o .\logs\ldap.etl -ets 

logman.exe start ntlm -p {5BBB6C18-AA45-49b1-A15F-085F7ED0AA90} %NtlmDebugFlags% -o .\logs\ntlm.etl -ets 

logman.exe start ssl -p {37D2C3CD-C5D4-4587-8531-4696C44244C8} %SslDebugFlags% -o .\logs\ssl.etl -ets 

 

nltest /dbflag:0x2fffffff 

 

wevtutil.exe set-log Microsoft-Windows-CAPI2/Operational /enabled:true 

wevtutil.exe clear-log Microsoft-Windows-CAPI2/Operational 

wevtutil.exe set-log Microsoft-Windows-Kerberos/Operational /enabled:true 

wevtutil.exe clear-log Microsoft-Windows-Kerberos/Operational 

 

REM netsh wfp capture start file=.\logs\wfpdiag.cab 

netsh trace start traceFile=.\logs\netmon.etl capture=yes 

ipconfig /flushdns 

klist purge 

klist -li 0x3e7 purge 

whoami /all > .\logs\whoami.txt 

netsh winhttp show proxy > .\logs\winhttp.txt 

 

 

tasklist /svc > .\logs\start-tasklist.txt 

color 20 

echo.  

echo.    

echo. 

echo ********************************* 

echo please reproduce the issue now... 

echo ********************************* 

echo. 

TIMEOUT /T 30 /NOBREAK 

 

Echo If the issue was reproduced successfully, please press any key to stop the tracing. 

Pause 

 

color 60 

echo. 

echo. 

echo. 

echo. 

echo ******************************************************* 

echo stop tracing. Please wait until all logs are collected. 

echo ******************************************************* 

logman.exe stop kerb -ets 

logman.exe stop kdc -ets 

logman.exe stop ldap -ets 

logman.exe stop ntlm -ets 

logman.exe stop ssl -ets 

  

echo deleting reg keys 

reg delete HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\ldap\Tracing\miiserver.exe /f 

 

reg delete HKLM\SYSTEM\CurrentControlSet\Control\LSA /v SPMInfoLevel /f 

reg delete HKLM\SYSTEM\CurrentControlSet\Control\LSA /v LogToFile /f 

reg delete HKLM\SYSTEM\CurrentControlSet\Control\LSA /v NegEventMask /f 

nltest /dbflag:0x0  

 

echo collecting log files: event viewer logs 

wevtutil.exe export-log Application .\logs\Application.evtx /overwrite:true 

wevtutil.exe export-log System .\logs\System.evtx /overwrite:true 

wevtutil.exe export-log Security .\logs\Security.evtx /overwrite:true 

wevtutil.exe set-log Microsoft-Windows-Kerberos/Operational /enabled:false 

wevtutil.exe export-log Microsoft-Windows-Kerberos/Operational .\logs\kerb.evtx /overwrite:true 

wevtutil.exe export-log Microsoft-Windows-CAPI2/Operational .\logs\CAPI2.evtx /overwrite:true 

wevtutil.exe export-log "Forefront Identity Manager" .\logs\EvtFIM.evtx /overwrite:true 

wevtutil.exe export-log "Forefront Identity Manager Management Agent" .\logs\EvtFIMMA.evtx /overwrite:true 

 

 

echo collecting log files: certificate store information 

certutil.exe -silent -v -store my > .\logs\machine-store.txt 

certutil.exe -silent -v -user -store my > .\logs\user-store.txt 

 

echo collecting log files: network related information" 

cmdkey.exe /list > .\logs\credman.txt 

 

ipconfig /all > .\logs\ipconfig-info.txt 

 

REM netsh wfp capture stop 

netsh trace stop 

 

copy /y %windir%\debug\netlogon.log .\logs 

copy /y %windir%\debug\netlogon.bak .\logs 

copy /y %windir%\system32\lsass.log .\logs 

copy /y %windir%\debug\netsetup.log .\logs 

copy /y %windir%\Microsoft.NET\Framework\v2.0.50727\CONFIG\machine.config .\logs 

set > .\logs\env.txt 

reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v BuildLabEx > .\logs\build.txt 

 

reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /s > .\logs\lsa-key.txt 

reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies" /s > .\logs\Policies-key.txt 

reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer" /s > .\logs\lanmanserver-key.txt 

reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation" /s > .\logs\lanmanworkstation-key.txt 

reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon" /s > .\logs\Netlogon-key.txt 

reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\NTDS" /s > .\logs\NTDS.txt 

reg query  "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" /s >  .\logs\schannel-key.txt 

 

wmic datafile where "name='%SystemDrive%\\Windows\\System32\\kerberos.dll' or name='%SystemDrive%\\Windows\\System32\\lsasrv.dll' or name='%SystemDrive%\\Windows\\System32\\netlogon.dll' or name='%SystemDrive%\\Windows\\System32\\kdcsvc.dll' or name='%SystemDrive%\\Windows\\System32\\msv1_0.dll' or name='%SystemDrive%\\Windows\\System32\\schannel.dll' or name='%SystemDrive%\\Windows\\System32\\dpapisrv.dll' or name='%SystemDrive%\\Windows\\System32\\basecsp.dll' or name='%SystemDrive%\\Windows\\System32\\scksp.dll' or name='%SystemDrive%\\Windows\\System32\\bcrypt.dll' or name='%SystemDrive%\\Windows\\System32\\bcryptprimitives.dll' or name='%SystemDrive%\\Windows\\System32\\ncrypt.dll' or name='%SystemDrive%\\Windows\\System32\\ncryptprov.dll' or name='%SystemDrive%\\Windows\\System32\\cryptsp.dll' or name='%SystemDrive%\\Windows\\System32\\rsaenh.dll'  or name='%SystemDrive%\\Windows\\System32\\Cryptdll.dll'" get Filename, Version | more >> .\logs\build.txt 

 

tasklist /svc > .\logs\stop-tasklist.txt 

Msinfo32 /nfo .\logs\msinfo32.nfo 

 

 

echo collecting of logs finished. 

 

echo zipping files 

powershell.exe Compress-Archive c:\temp\logs c:\temp\MicrosoftTraceLogs.zip -force 

echo. 

echo. 

echo. 

echo ************************************************************************************************ 

echo zipping completed. Please provide the support engineer the file: c:\temp\MicrosoftTraceLogs.zip 

Echo.   

echo thank you for your help here! 

echo ************************************************************************************************ 

color 02 