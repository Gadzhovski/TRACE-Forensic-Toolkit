<#
.SYNOPSIS
    Installs TRACE and its dependencies on Windows.

.DESCRIPTION
    Checks for a supported Python, warns clearly if the Microsoft C++ Build
    Tools are missing (pytsk3 and libewf-python are source distributions and
    cannot build without them), creates a virtual environment, and installs
    the requirements.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File install_windows.ps1
#>

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
    if ([int]$parts[0] -eq 3 -and [int]$parts[1] -ge 9) {
        $python = $candidate
        Write-Ok "Found $candidate (Python $ver)"
        break
    } else {
        Write-Warn "$candidate is Python $ver - TRACE needs 3.9 or newer"
    }
}

if (-not $python) {
    Write-Fail "No suitable Python found."
    Write-Host "  Install Python 3.11 or newer from https://www.python.org/downloads/"
    Write-Host "  and tick 'Add python.exe to PATH' during setup."
    exit 1
}

# --- Check for a C++ toolchain --------------------------------------------
# pytsk3 and libewf-python ship as source only. Without the Build Tools, pip
# fails partway through with a long and fairly cryptic compiler error, so warn
# up front instead.
Write-Step "Checking for Microsoft C++ Build Tools..."

$hasBuildTools = $false
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (Test-Path $vswhere) {
    $installed = & $vswhere -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null
    if ($installed) { $hasBuildTools = $true }
}

if ($hasBuildTools) {
    Write-Ok "C++ build tools detected."
} else {
    Write-Warn "Microsoft C++ Build Tools were not detected."
    Write-Host "  pytsk3 and libewf-python are compiled from source and need them."
    Write-Host "  If a prebuilt wheel exists for your Python version the install"
    Write-Host "  may still succeed; otherwise download them from:"
    Write-Host "    https://visualstudio.microsoft.com/visual-cpp-build-tools/" -ForegroundColor White
    Write-Host "  and select 'Desktop development with C++'."
    $reply = Read-Host "  Continue anyway? (y/n)"
    if ($reply -notmatch '^[Yy]') { exit 1 }
}

# --- Virtual environment ---------------------------------------------------
Write-Step "Creating virtual environment..."
if (Test-Path 'venv') {
    Write-Warn "A venv directory already exists."
    $reply = Read-Host "  Recreate it? Existing packages will be lost. (y/n)"
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
& $venvPy -m pip install --upgrade pip setuptools wheel
& $venvPy -m pip install -r requirements.txt

if ($LASTEXITCODE -ne 0) {
    Write-Fail "Dependency installation failed."
    Write-Host "  The most common cause is the missing C++ Build Tools described above."
    exit 1
}

Write-Host "`nInstallation complete." -ForegroundColor Green
Write-Host "`nStart TRACE with:"
Write-Host "   venv\Scripts\activate" -ForegroundColor Yellow
Write-Host "   python main.py" -ForegroundColor Yellow
Write-Host "`nType 'deactivate' when you are finished.`n"
