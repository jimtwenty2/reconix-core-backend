# Reconix static TUI: one-time setup on Windows 10 / 11 (PowerShell, in Windows Terminal).
# Run from the repo root:  powershell -ExecutionPolicy Bypass -File apps\tui\scripts\setup-windows.ps1
# Creates apps\tui\.venv, installs the TUI into it, and checks Node.js for the local web.
$ErrorActionPreference = "Stop"

$TuiDir = Split-Path -Parent $PSScriptRoot
Set-Location $TuiDir

function Say($text) { Write-Host ""; Write-Host "==> $text" -ForegroundColor Cyan }

Say "Checking Python (3.9 or newer)"
$Py = $null
foreach ($candidate in @("py", "python")) {
    if (Get-Command $candidate -ErrorAction SilentlyContinue) { $Py = $candidate; break }
}
if (-not $Py) {
    Write-Host "Python not found. Install it:  winget install -e --id Python.Python.3.12"
    Write-Host "(then close and reopen the terminal)"
    exit 1
}
& $Py -c "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)"
if ($LASTEXITCODE -ne 0) {
    Write-Host "Your Python is older than 3.9. Install 3.12:  winget install -e --id Python.Python.3.12"
    exit 1
}
Write-Host ("OK: " + (& $Py -V))

Say "Creating the virtual environment (apps\tui\.venv)"
if (-not (Test-Path ".venv")) { & $Py -m venv .venv }
$VenvPy = Join-Path $TuiDir ".venv\Scripts\python.exe"
& $VenvPy -m pip install --quiet --upgrade pip
Say "Installing the Reconix TUI (a few minutes the first time)"
& $VenvPy -m pip install --quiet -e .
if ($LASTEXITCODE -ne 0) { Write-Host "pip install failed (see above)."; exit 1 }

Say "Checking Node.js 20+ and npm (only needed for /web, Flow 4)"
if ((Get-Command node -ErrorAction SilentlyContinue) -and (Get-Command npm -ErrorAction SilentlyContinue)) {
    $major = [int]((node -p "process.versions.node.split('.')[0]"))
    if ($major -ge 20) { Write-Host ("OK: node " + (node -v) + ", npm " + (npm -v)) }
    else { Write-Host ("WARNING: node " + (node -v) + " is older than 20; /web may not start. The TUI works.") }
} else {
    Write-Host "Not found: the TUI works without it; /web (Flow 4) needs Node.js 20+ and npm."
    Write-Host "Install:  winget install -e --id OpenJS.NodeJS.LTS"
}

Say "Done. Start Reconix for the evaluation (its data stays in `$HOME\.reconix-eval):"
Write-Host "    powershell -ExecutionPolicy Bypass -File apps\tui\scripts\run-eval.ps1   (add -Reset to start over)"
Write-Host "Then type /tests for the checklist. Guide: apps\tui\docs\evaluator\README-WINDOWS.md"
