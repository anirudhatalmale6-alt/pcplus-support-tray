@echo off
echo ==========================================
echo   PC Plus Computing - Support Utility
echo   Installation Script
echo ==========================================
echo.

:: Check for admin rights
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Please run this installer as Administrator.
    echo Right-click and select "Run as administrator"
    pause
    exit /b 1
)

:: Set install directory
set INSTALLDIR=%ProgramFiles%\PCPlusSupport
set DATADIR=%ProgramData%\PCPlusSupport

echo Installing to: %INSTALLDIR%
echo.

:: Create directories
mkdir "%INSTALLDIR%" 2>nul
mkdir "%DATADIR%" 2>nul
mkdir "%DATADIR%\Screenshots" 2>nul
mkdir "%DATADIR%\Tickets" 2>nul

:: Copy files
echo Copying files...
copy /Y "PCPlusSupportTray.exe" "%INSTALLDIR%\" >nul
if exist "icon.ico" copy /Y "icon.ico" "%INSTALLDIR%\" >nul

:: Create default config if not exists
if not exist "%DATADIR%\config.json" (
    echo Creating default configuration...
    (
    echo {
    echo   "CompanyName": "PC Plus Computing",
    echo   "RmmUrl": "https://rmm.pcpluscomputing.com",
    echo   "RmmApiKey": "",
    echo   "SupportPhone": "16047601662",
    echo   "SupportEmail": "pcpluscomputing@gmail.com",
    echo   "SupportChatUrl": "",
    echo   "ChatServerUrl": "184.68.146.18:3456",
    echo   "TicketPortalUrl": ""
    echo }
    ) > "%DATADIR%\config.json"
)

:: Add to startup (all users)
echo Setting up auto-start...
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "PCPlusSupport" /t REG_SZ /d "\"%INSTALLDIR%\PCPlusSupportTray.exe\"" /f >nul

:: Create Start Menu shortcut
set SHORTCUTDIR=%ProgramData%\Microsoft\Windows\Start Menu\Programs\PC Plus Computing
mkdir "%SHORTCUTDIR%" 2>nul
powershell -Command "$ws = New-Object -ComObject WScript.Shell; $s = $ws.CreateShortcut('%SHORTCUTDIR%\PC Plus Support.lnk'); $s.TargetPath = '%INSTALLDIR%\PCPlusSupportTray.exe'; $s.Description = 'PC Plus Computing Support Utility'; $s.Save()"

echo.
echo ==========================================
echo   Installation Complete!
echo ==========================================
echo.
echo The support icon will appear in your
echo system tray next to the clock.
echo.
echo Starting the utility now...
start "" "%INSTALLDIR%\PCPlusSupportTray.exe"
echo.
pause
