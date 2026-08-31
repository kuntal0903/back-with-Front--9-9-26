@echo off
setlocal
set "ENGINE_DIR=%~dp0backend"
if not exist "%ENGINE_DIR%\.venv" set "ENGINE_DIR=%~dp0"
cd /d "%ENGINE_DIR%"
"%ENGINE_DIR%\.venv\Scripts\python.exe" "%ENGINE_DIR%\scripts\scan.py" %*
