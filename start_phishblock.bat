@echo off
echo ========================================
echo    PhishBlock-DNS Server Starter
echo ========================================
echo.

REM Check if Python is available
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Python not found in PATH. Trying virtual environment...
    if exist "myenv\bin\python.exe" (
        echo Using virtual environment Python...
        myenv\bin\python.exe phishblock_dns.py
        goto :end
    ) else (
        echo ERROR: Python not found!
        echo Please install Python or ensure it's in your PATH.
        pause
        goto :end
    )
) else (
    echo Python found. Starting PhishBlock-DNS...
    python phishblock_dns.py
)

:end
echo.
echo Press any key to exit...
pause >nul 