# Root PowerShell wrapper for Attack Surface Engine
param(
    [Parameter(Position=0, Mandatory=$true)]
    [string]$ToolOrMode,

    [Parameter(Position=1, Mandatory=$true)]
    [string]$Target
)

$RootDir = Join-Path $PSScriptRoot "backend"
Set-Location $RootDir

$VenvPython = Join-Path $RootDir ".venv\Scripts\python.exe"

if (Test-Path $VenvPython) {
    & $VenvPython "scripts\scan.py" $ToolOrMode $Target
} else {
    python "scripts\scan.py" $ToolOrMode $Target
}
