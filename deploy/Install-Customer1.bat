@echo off
:: PC Plus Endpoint Protection - One-Click Installer
:: To create installer for a new customer:
::   1. Copy this file and rename (e.g. Install-SmithLaw.bat)
::   2. Change CUSTOMER_NAME below to the customer's company name
::   3. Give the .bat file to the customer or run it on their PCs

:: ========== CHANGE THIS FOR EACH CUSTOMER ==========
set "CUSTOMER_NAME=Customer1"
:: ====================================================

:: Request admin elevation
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator privileges...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

echo ============================================
echo  PC Plus Endpoint Protection - Installer
echo  Customer: %CUSTOMER_NAME%
echo ============================================
echo.

:: Create temp directory
if not exist "C:\temp" mkdir "C:\temp"

:: Download the installer script
echo Downloading installer...
powershell -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri 'https://github.com/anirudhatalmale6-alt/pcplus-support-tray/releases/latest/download/Install-PCPlusEndpoint.ps1' -OutFile 'C:\temp\Install-PCPlusEndpoint.ps1' -UseBasicParsing"

if not exist "C:\temp\Install-PCPlusEndpoint.ps1" (
    echo ERROR: Failed to download installer script.
    pause
    exit /b 1
)

:: Run the installer
echo Running installer...
powershell -ExecutionPolicy Bypass -File "C:\temp\Install-PCPlusEndpoint.ps1" -CustomerName "%CUSTOMER_NAME%"

echo.
echo Done! Press any key to close.
pause >nul
