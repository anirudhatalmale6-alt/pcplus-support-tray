@echo off
echo ==========================================
echo   PC Plus Support - Uninstall
echo ==========================================
echo.

:: Check for admin rights
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Please run as Administrator.
    pause
    exit /b 1
)

:: Kill running process
taskkill /F /IM PCPlusSupportTray.exe 2>nul

:: Remove from startup
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "PCPlusSupport" /f 2>nul

:: Remove Start Menu shortcut
rmdir /S /Q "%ProgramData%\Microsoft\Windows\Start Menu\Programs\PC Plus Computing" 2>nul

:: Remove install directory
rmdir /S /Q "%ProgramFiles%\PCPlusSupport" 2>nul

echo.
echo Uninstalled successfully.
echo Note: User data in %ProgramData%\PCPlusSupport was preserved.
echo Delete it manually if no longer needed.
echo.
pause
