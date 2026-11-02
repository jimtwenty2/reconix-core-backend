# Start the Reconix static TUI for an evaluation on Windows, with every file it writes kept in
# $HOME\.reconix-eval (assessments, provider keys, knowledge, the web assistant, /tests results),
# so your own $HOME\.reconix is never read or changed.
#   powershell -ExecutionPolicy Bypass -File apps\tui\scripts\run-eval.ps1            start
#   powershell -ExecutionPolicy Bypass -File apps\tui\scripts\run-eval.ps1 -Reset     delete $HOME\.reconix-eval first
param([switch]$Reset)
$ErrorActionPreference = "Stop"

$TuiDir = Split-Path -Parent $PSScriptRoot
$Eval = if ($env:RECONIX_EVAL_DIR) { $env:RECONIX_EVAL_DIR } else { Join-Path $HOME ".reconix-eval" }

if ($Reset -and (Test-Path $Eval)) {
    Remove-Item -Recurse -Force $Eval
    Write-Host "Removed ${Eval}: Reconix starts fresh and asks for a provider again."
}
$Reconix = Join-Path $TuiDir ".venv\Scripts\reconix.exe"
if (-not (Test-Path $Reconix)) {
    Write-Host "Not set up yet: run  powershell -ExecutionPolicy Bypass -File apps\tui\scripts\setup-windows.ps1  first."
    exit 1
}
New-Item -ItemType Directory -Force -Path $Eval | Out-Null

$env:RECONIX_DATA_DIR = Join-Path $Eval "assessments"
$env:LLM_DB = Join-Path $Eval "llm.db"
$env:LLM_KEY_FILE = Join-Path $Eval "llm.key"
$env:RECONIX_KNOWLEDGE_DIR = Join-Path $Eval "knowledge"
$env:RECONIX_KNOWLEDGE_KEY_FILE = Join-Path $Eval "knowledge.key"
$env:RECONIX_ASSISTANT_DIR = Join-Path $Eval "assistant"
$env:RECONIX_TEST_RESULTS_DIR = Join-Path $Eval "test-results"
$env:RECONIX_WEB_URL_FILE = Join-Path $Eval "web.url"
$env:RECONIX_WEB_LOG = Join-Path $Eval "web.log"

Set-Location $TuiDir              # reports are saved in apps\tui\reports\
& $Reconix
