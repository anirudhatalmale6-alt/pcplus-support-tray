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
    powershell -Command "Start-Process cmd -ArgumentList '/c \"\"%~f0\"\"' -Verb RunAs"
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
echo Please wait, this may take a minute...
echo.
powershell -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; try { Invoke-WebRequest -Uri 'https://github.com/anirudhatalmale6-alt/pcplus-support-tray/releases/latest/download/Install-PCPlusEndpoint.ps1' -OutFile 'C:\temp\Install-PCPlusEndpoint.ps1' -UseBasicParsing } catch { Write-Host 'Download failed:' $_.Exception.Message; exit 1 }"

if %errorlevel% neq 0 (
    echo.
    echo ERROR: Download failed. Check internet connection.
    echo.
    pause
    exit /b 1
)

if not exist "C:\temp\Install-PCPlusEndpoint.ps1" (
    echo.
    echo ERROR: Failed to download installer script.
    echo Check internet connection and try again.
    echo.
    pause
    exit /b 1
)

:: Run the installer
echo Running installer...
echo.
powershell -ExecutionPolicy Bypass -File "C:\temp\Install-PCPlusEndpoint.ps1" -CustomerName "%CUSTOMER_NAME%"

if %errorlevel% neq 0 (
    echo.
    echo ERROR: Installation encountered an issue.
    echo.
    pause
    exit /b 1
)

echo.
echo ============================================
echo  Installation complete!
echo  Customer: %CUSTOMER_NAME%
echo ============================================
echo.
echo Press any key to close.
pause >nul
