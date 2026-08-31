# PowerShell script wrapper for Attack Surface Engine
param(
    [Parameter(Position=0, Mandatory=$true)]
    [string]$ToolOrMode,

    [Parameter(Position=1, Mandatory=$true)]
    [string]$Target
)

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $ScriptDir

$VenvPython = Join-Path $ScriptDir ".venv\Scripts\python.exe"

if (Test-Path $VenvPython) {
    & $VenvPython "scripts\scan.py" $ToolOrMode $Target
} else {
    python "scripts\scan.py" $ToolOrMode $Target
}
