<#
.SYNOPSIS
    Installs TRACE and its dependencies on Windows.

.DESCRIPTION
    Checks for Python 3.10 or newer, creates a virtual environment, and
    installs the requirements. Every package -- including the forensic
    engines pytsk3 and libewf-python -- installs from a pre-built wheel, so
    no compiler or Visual Studio Build Tools are needed.

.PARAMETER Yes
    Non-interactive: accept defaults (reuse an existing venv). Used by CI.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File install_windows.ps1
#>

param([switch]$Yes)

$ErrorActionPreference = 'Stop'

function Write-Step  { param($m) Write-Host "`n$m" -ForegroundColor Cyan }
function Write-Ok    { param($m) Write-Host "  $m" -ForegroundColor Green }
function Write-Warn  { param($m) Write-Host "  $m" -ForegroundColor Yellow }
function Write-Fail  { param($m) Write-Host "  $m" -ForegroundColor Red }

Write-Host @"
+------------------------------------------------------------------+
|                  TRACE Forensic Toolkit Installer                |
|                            Windows                               |
+------------------------------------------------------------------+
"@ -ForegroundColor Cyan

# --- Locate a suitable Python ---------------------------------------------
Write-Step "Looking for Python..."

$python = $null
foreach ($candidate in @('python', 'python3', 'py')) {
    $cmd = Get-Command $candidate -ErrorAction SilentlyContinue
    if (-not $cmd) { continue }
    try {
        $ver = & $candidate -c "import sys; print('%d.%d' % sys.version_info[:2])" 2>$null
    } catch { continue }
    if (-not $ver) { continue }
    $parts = $ver.Split('.')
    if ([int]$parts[0] -eq 3 -and [int]$parts[1] -ge 10) {
        $python = $candidate
        Write-Ok "Found $candidate (Python $ver)"
        break
    } else {
        Write-Warn "$candidate is Python $ver - TRACE needs 3.10 or newer"
    }
}

if (-not $python) {
    Write-Fail "No suitable Python found."
    Write-Host "  Install Python 3.11 or newer from https://www.python.org/downloads/"
    Write-Host "  and tick 'Add python.exe to PATH' during setup."
    exit 1
}

# --- Virtual environment ---------------------------------------------------
Write-Step "Creating virtual environment..."
if (Test-Path 'venv') {
    Write-Warn "A venv directory already exists."
    $reply = if ($Yes) { 'n' } else { Read-Host "  Recreate it? Existing packages will be lost. (y/n)" }
    if ($reply -match '^[Yy]') {
        Remove-Item -Recurse -Force venv
        & $python -m venv venv
        Write-Ok "Recreated."
    } else {
        Write-Ok "Reusing the existing environment."
    }
} else {
    & $python -m venv venv
    Write-Ok "Created."
}

# --- Dependencies ----------------------------------------------------------
Write-Step "Installing Python packages (this can take a few minutes)..."
$venvPy = Join-Path (Resolve-Path 'venv') 'Scripts\python.exe'
& $venvPy -m pip install --upgrade pip
# --only-binary for the two forensic engines: if no wheel exists for this
# Python, say so plainly rather than attempt a C build that will fail.
& $venvPy -m pip install --only-binary=pytsk3,libewf-python -r requirements.txt

if ($LASTEXITCODE -ne 0) {
    Write-Fail "Dependency installation failed."
    Write-Host "  pytsk3 and libewf-python have pre-built wheels for Python 3.10-3.14"
    Write-Host "  on x64, x86 and ARM64 Windows. Check that '$python' is one of"
    Write-Host "  those versions."
    exit 1
}

Write-Host "`nInstallation complete." -ForegroundColor Green
Write-Host "`nStart TRACE with:"
Write-Host "   venv\Scripts\activate" -ForegroundColor Yellow
Write-Host "   python main.py" -ForegroundColor Yellow
Write-Host "`nType 'deactivate' when you are finished.`n"
