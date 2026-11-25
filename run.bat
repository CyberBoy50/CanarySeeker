@echo off
REM CanarySeeker launcher for Windows — setup, check, test, doctor,
REM build-bins, build-pe, menu. Pure Python, standard library only.
REM Usage:
REM   run.bat setup
REM   run.bat check test_bins\hardened
REM   run.bat test
REM   run.bat doctor
REM   run.bat build-bins
REM   run.bat build-pe
REM   run.bat menu
setlocal
cd /d "%~dp0"
if "%1"=="" (
    python run.py
    exit /b %ERRORLEVEL%
)
python run.py %*
exit /b %ERRORLEVEL%
