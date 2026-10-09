@echo off
REM ===================================================================
REM  AstraSec - one-command setup and launch for Windows.
REM
REM    scripts\run.bat            train (if needed), then serve on :8000
REM    scripts\run.bat --retrain  force a fresh training run
REM    scripts\run.bat --check    install, then check the environment and stop
REM
REM  Uses .venv when it has a working pip, and falls back to the system
REM  Python otherwise - some Windows Python installs fail at the
REM  `ensurepip` step and leave a half-built venv behind, which should
REM  not stop the project from running.
REM ===================================================================
setlocal enabledelayedexpansion
cd /d "%~dp0.."

set RETRAIN=0
set CHECK=0
if /i "%~1"=="--retrain" set RETRAIN=1
if /i "%~1"=="--check" set CHECK=1

echo.
echo ==^> Checking Python
python --version
if errorlevel 1 (
  echo.
  echo ERROR: Python is not on your PATH.
  echo Install Python 3.11+ from https://www.python.org/downloads/
  echo and tick "Add python.exe to PATH" during setup.
  exit /b 1
)

REM ---- pick an interpreter --------------------------------------------
set PY=python
if not exist ".venv\Scripts\python.exe" (
  echo ==^> Creating virtual environment
  python -m venv .venv >nul 2>&1
)
if exist ".venv\Scripts\python.exe" (
  ".venv\Scripts\python.exe" -m pip --version >nul 2>&1
  if not errorlevel 1 (
    set PY=.venv\Scripts\python.exe
    echo     using virtual environment
  ) else (
    echo     venv has no working pip - using system Python instead
  )
) else (
  echo     venv unavailable - using system Python
)

REM ---- dependencies ----------------------------------------------------
echo.
echo ==^> Installing dependencies ^(a few minutes the first time^)
"%PY%" -m pip install --upgrade pip
"%PY%" -m pip install -r backend\requirements.txt
if errorlevel 1 (
  echo.
  echo ERROR: dependency installation failed.
  echo If pip could not find matching versions, your Python is probably
  echo older than 3.11. Check with: python --version
  exit /b 1
)

REM ---- health check ------------------------------------------------------
if "%CHECK%"=="1" (
  REM Pick the interpreter path once. The doctor exits 1 when it finds a
  REM problem, so an "if errorlevel 1, try again" fallback would print the
  REM whole report twice precisely when something is wrong.
  pushd backend
  if "%PY%"=="python" (
    python -m astrasec.doctor
  ) else (
    "..\%PY%" -m astrasec.doctor
  )
  popd
  exit /b
)

REM ---- models ----------------------------------------------------------
echo.
if "%RETRAIN%"=="1" goto :train
set MODELVER=
if exist "artifacts\models\model_version.txt" set /p MODELVER=<"artifacts\models\model_version.txt"
if exist "artifacts\models\threat_prediction.joblib" if "%MODELVER%"=="2026.09-assistant" (
  echo ==^> Trained models found - skipping training ^(use --retrain to force^)
  goto :serve
)
if exist "artifacts\models\threat_prediction.joblib" (
  echo ==^> This version brings improved models - retraining once
)

:train
echo ==^> Training the immune system
echo     This takes 10-15 minutes and only happens once.
echo     You will see progress for Module 1 and Module 3 as it goes.
echo.
pushd backend
"..\%PY%" -m astrasec.train --samples 30000
if errorlevel 1 (
  "%PY%" -m astrasec.train --samples 30000
)
popd

:serve
echo.
echo ==^> Starting AstraSec
echo.
echo     AstraBot (the chatbot)   : http://localhost:8000/bot
echo     Security Center (owner)  : http://localhost:8000
echo.
echo     Open the Security Center first and set your owner password
echo     under Settings. Alerts appear there the moment AstraBot
echo     blocks a message or a file.
echo.
echo     Something not working?  Run:  scripts\run.bat --check
echo.
echo     Press Ctrl+C to stop.
echo.
pushd backend
"..\%PY%" -m uvicorn astrasec.api:app --host 0.0.0.0 --port 8000 2>nul
if errorlevel 1 (
  "%PY%" -m uvicorn astrasec.api:app --host 0.0.0.0 --port 8000
)
popd
endlocal
