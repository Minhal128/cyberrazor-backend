@echo off
echo Installing CyberRazor Threat Detection Agent as Windows Service...

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% == 0 (
    echo Running as administrator - proceeding with installation
) else (
    echo This script must be run as administrator
    pause
    exit /b 1
)

REM Set paths
set SERVICE_NAME=CyberRazorAgent
set PYTHON_PATH=C:\Python39\python.exe
set SCRIPT_PATH=%~dp0threat_agent.py
set WORKING_DIR=%~dp0

REM Check if Python is installed
if not exist "%PYTHON_PATH%" (
    echo Python not found at %PYTHON_PATH%
    echo Please install Python 3.9+ and update the path in this script
    pause
    exit /b 1
)

REM Check if NSSM is available (download if not)
if not exist "nssm.exe" (
    echo Downloading NSSM...
    powershell -Command "Invoke-WebRequest -Uri 'https://nssm.cc/release/nssm-2.24.zip' -OutFile 'nssm.zip'"
    powershell -Command "Expand-Archive -Path 'nssm.zip' -DestinationPath '.' -Force"
    copy "nssm-2.24\win64\nssm.exe" "nssm.exe"
    rmdir /s /q "nssm-2.24"
    del "nssm.zip"
)

REM Remove existing service if it exists
nssm.exe stop %SERVICE_NAME% >nul 2>&1
nssm.exe remove %SERVICE_NAME% confirm >nul 2>&1

REM Install the service
echo Installing service...
nssm.exe install %SERVICE_NAME% "%PYTHON_PATH%" "%SCRIPT_PATH%"
nssm.exe set %SERVICE_NAME% AppDirectory "%WORKING_DIR%"
nssm.exe set %SERVICE_NAME% DisplayName "CyberRazor Threat Detection Agent"
nssm.exe set %SERVICE_NAME% Description "Real-time threat detection and monitoring service"
nssm.exe set %SERVICE_NAME% Start SERVICE_AUTO_START

REM Set environment variables
nssm.exe set %SERVICE_NAME% AppEnvironmentExtra "CYBERRAZOR_API_KEY=your-api-key-here"
nssm.exe set %SERVICE_NAME% AppEnvironmentExtra "CYBERRAZOR_BACKEND_URL=http://localhost:8000"
nssm.exe set %SERVICE_NAME% AppEnvironmentExtra "WAZUH_URL=http://localhost:55000"
nssm.exe set %SERVICE_NAME% AppEnvironmentExtra "WAZUH_USERNAME=wazuh"
nssm.exe set %SERVICE_NAME% AppEnvironmentExtra "WAZUH_PASSWORD=wazuh"

REM Set service dependencies
nssm.exe set %SERVICE_NAME% DependOnService Tcpip

REM Set failure actions
nssm.exe set %SERVICE_NAME% AppStopMethodSkip 0
nssm.exe set %SERVICE_NAME% AppStopMethodConsole 1500
nssm.exe set %SERVICE_NAME% AppStopMethodWindow 1500
nssm.exe set %SERVICE_NAME% AppStopMethodThreads 1500

REM Start the service
echo Starting service...
net start %SERVICE_NAME%

if %errorLevel% == 0 (
    echo.
    echo CyberRazor Threat Detection Agent installed successfully!
    echo Service name: %SERVICE_NAME%
    echo.
    echo To manage the service:
    echo   Start: net start %SERVICE_NAME%
    echo   Stop:  net stop %SERVICE_NAME%
    echo   Status: sc query %SERVICE_NAME%
    echo.
    echo Service logs can be viewed in Event Viewer under Windows Logs > Application
) else (
    echo.
    echo Failed to start the service. Check the logs for details.
    echo You can try starting it manually with: net start %SERVICE_NAME%
)

pause 