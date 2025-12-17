@echo off
setlocal enabledelayedexpansion

:: Evasive execution - minimize footprint
title Windows Update Helper
mode con:cols=80 lines=25
color 0A

echo [*] Starting System Diagnostics...

:: Check admin privileges
net session >nul 2>&1
if %errorlevel% eq 0 (
    echo [!] ALREADY RUNNING AS ADMINISTRATOR
) else (
    echo [*] Running as limited user
)

:: System Info Collection
echo ========================================
echo [1] SYSTEM INFORMATION
echo ========================================
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
hostname
whoami /all | findstr /B /C:"User Name" /C:"Group Name" /C:"Privileges"

:: Check for AlwaysInstallElevated
echo ========================================
echo [2] REGISTRY CHECKS
echo ========================================
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2>nul
if %errorlevel% equ 0 echo [+] AlwaysInstallElevated enabled for current user
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2>nul
if %errorlevel% equ 0 echo [+] AlwaysInstallElevated enabled system-wide

:: Check for unattend/sysprep files
echo ========================================
echo [3] PASSWORD FILE SEARCH
echo ========================================
for %%A in (c d e f g) do (
    if exist %%A:\ (
        echo [*] Searching drive %%A: for credential files...
        dir %%A:\unattend.xml /s /b 2>nul
        dir %%A:\sysprep.inf /s /b 2>nul
        dir %%A:\sysprep\sysprep.xml /s /b 2>nul
        dir %%A:\Windows\Panther\Unattend.xml /s /b 2>nul
        dir %%A:\Windows\Panther\Unattend\Unattend.xml /s /b 2>nul
    )
)

:: Service checks - looking for weak permissions
echo ========================================
echo [4] SERVICE PERMISSIONS
echo ========================================
sc query state= all | findstr /B /C:"SERVICE_NAME:" > services.tmp
for /f "tokens=2 delims=:" %%A in (services.tmp) do (
    set "service=%%A"
    set "service=!service:~1!"
    sc qc "!service!" | findstr /I "BINARY_PATH_NAME"
)
del services.tmp 2>nul

:: Check for writable service paths
echo ========================================
echo [5] WRITABLE SERVICE PATHS
echo ========================================
for /f "tokens=2 delims=:" %%A in ('sc query state^= all ^| findstr /B /C:"SERVICE_NAME:"') do (
    set "service=%%A"
    set "service=!service:~1!"
    for /f "tokens=2 delims=:" %%B in ('sc qc "!service!" 2^>nul ^| findstr /B /C:"BINARY_PATH_NAME"') do (
        set "path=%%B"
        set "path=!path:~1!"
        for /f "tokens=1 delims= " %%C in ("!path!") do (
            set "exepath=%%C"
            if exist "!exepath!" (
                cacls "!exepath!" 2>nul | findstr /i "(W)" >nul
                if !errorlevel! equ 0 (
                    echo [!] Writable service executable: !service! - !exepath!
                )
            )
        )
    )
)

:: Scheduled Tasks checks
echo ========================================
echo [6] SCHEDULED TASKS
echo ========================================
schtasks /query /fo LIST /v | findstr /I "TaskName\|Run As User\|Author\|Task To Run" | findstr /v /i "Microsoft"

:: Check for AutoLogon credentials
echo ========================================
echo [7] AUTOLOGON CHECK
echo ========================================
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName 2>nul
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword 2>nul
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon 2>nul

:: Check for vulnerable drivers
echo ========================================
echo [8] DRIVER INFORMATION
echo ========================================
driverquery /v | findstr /I "Running\|Kernel"

:: Network information
echo ========================================
echo [9] NETWORK INFORMATION
echo ========================================
ipconfig /all | findstr /C:"IPv4" /C:"Physical"
netstat -ano | findstr /I "LISTENING" | findstr /V "\[::\]"

:: User and group information
echo ========================================
echo [10] USER AND GROUP ENUMERATION
echo ========================================
net user
echo.
net localgroup administrators

:: Check for unquoted service paths
echo ========================================
echo [11] UNQUOTED SERVICE PATHS
echo ========================================
wmic service get name,displayname,pathname,startmode 2>nul | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i "\.[exe|com|bat]"

:: Check for recent files (potential credentials)
echo ========================================
echo [12] RECENT FILES CHECK
echo ========================================
dir "%USERPROFILE%\Recent\*.lnk" /b 2>nul
dir "%APPDATA%\Microsoft\Windows\Recent\*.lnk" /b 2>nul

:: Check for saved RDP credentials
echo ========================================
echo [13] RDP CREDENTIALS CHECK
echo ========================================
dir "%USERPROFILE%\*.rdp" /b 2>nul
dir "%USERPROFILE%\Documents\*.rdp" /b 2>nul

:: Check for PuTTY saved sessions
echo ========================================
echo [14] PUTTY SAVED SESSIONS
echo ========================================
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" 2>nul

:: Check for Always Elevated COM objects
echo ========================================
echo [15] COM OBJECT PERMISSIONS
echo ========================================
reg query "HKCU\Software\Classes\CLSID" /s /f "Elevation" /d 2>nul | findstr /i "elevation"
reg query "HKLM\Software\Classes\CLSID" /s /f "Elevation" /d 2>nul | findstr /i "elevation"

:: Check for AppLocker/Device Guard policies
echo ========================================
echo [16] APPLOCKER/SRP POLICIES
echo ========================================
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\SrpV2" 2>nul
if %errorlevel% equ 0 echo [!] AppLocker/SRP policies found

:: Check for vulnerable software versions
echo ========================================
echo [17] INSTALLED SOFTWARE
echo ========================================
wmic product get name,version 2>nul | findstr /v /i "Security Update\|Update for\|Hotfix\|KB"

:: Check PATH for writable directories
echo ========================================
echo [18] PATH VARIABLE CHECK
echo ========================================
echo %PATH%
echo.
for %%A in (%PATH%) do (
    cacls "%%A" 2>nul | findstr /i "(W)" >nul
    if !errorlevel! equ 0 echo [!] Writable directory in PATH: %%A
)

:: Check for interesting files
echo ========================================
echo [19] INTERESTING FILE SEARCH
echo ========================================
for %%A in (c d e f g) do (
    if exist %%A:\ (
        echo [*] Quick search on drive %%A:...
        dir %%A:\*.txt /s /b 2>nul | findstr /i "pass\|cred\|config" | head -5
        dir %%A:\*.xml /s /b 2>nul | findstr /i "pass\|cred" | head -5
        dir %%A:\*.config /s /b 2>nul | findstr /i "connection\|pass" | head -5
    )
)

:: Check for stored credentials in Credential Manager
echo ========================================
echo [20] CREDENTIAL MANAGER
echo ========================================
cmdkey /list 2>nul

:: Clean up and finish
echo ========================================
echo [*] Diagnostics complete. Check results above.
echo ========================================
timeout /t 5 >nul

endlocal
