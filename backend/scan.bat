@echo off
setlocal
cd /d "%~dp0"
if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" "scripts\scan.py" %*
) else (
    python "scripts\scan.py" %*
)
