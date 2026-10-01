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

# === Output ===============================================================
# Kept identical in look to install.sh.
#
# This file stays pure ASCII: Windows PowerShell 5.1 reads a script without a
# byte-order mark in the ANSI code page, which would garble any other
# character. Every symbol below is built from its code point instead.
function U([int]$CodePoint) { [string][char]$CodePoint }

$Esc = [char]27
# ANSI colour where the console understands it (Windows Terminal, and the
# classic console on Windows 10+); console colours otherwise; none when
# NO_COLOR is set (no-color.org). 256-colour codes, the same as install.sh.
$script:Vt = [bool]$Host.UI.SupportsVirtualTerminal -and -not $env:NO_COLOR
$script:Plain = [bool]$env:NO_COLOR

# The classic console's fonts (Consolas, Lucida) have the box-drawing and
# block characters but not check marks; Windows Terminal and VS Code have all.
if ($env:WT_SESSION -or $env:TERM_PROGRAM -eq 'vscode') {
    $G = @{ Step = (U 0x25B8); Ok = (U 0x2713); Warn = '!'; Fail = (U 0x2717) }
} else {
    $G = @{ Step = '>'; Ok = '+'; Warn = '!'; Fail = 'x' }
}
$G.Rule = U 0x2500
$G.Dot = U 0x00B7

function Write-Seg {
    param([string]$Text, [int]$Color = -1, [string]$Fallback = '',
          [switch]$Bold, [switch]$Dim, [switch]$NoNewline)
    if ($script:Vt) {
        $codes = @()
        if ($Bold) { $codes += '1' }
        if ($Dim) { $codes += '2' }
        if ($Color -ge 0) { $codes += "38;5;$Color" }
        if ($codes) { $Text = "$Esc[" + ($codes -join ';') + "m$Text$Esc[0m" }
        Write-Host $Text -NoNewline:$NoNewline
    } elseif ($Fallback -and -not $script:Plain) {
        Write-Host $Text -ForegroundColor $Fallback -NoNewline:$NoNewline
    } else {
        Write-Host $Text -NoNewline:$NoNewline
    }
}

function Write-Step { param($m) Write-Host ''; Write-Seg "$($G.Step) $m" -Color 39 -Fallback Cyan -Bold }
function Write-Ok   { param($m) Write-Seg "  $($G.Ok)" -Color 42 -Fallback Green -NoNewline; Write-Host " $m" }
function Write-Warn { param($m) Write-Seg "  $($G.Warn) $m" -Color 214 -Fallback Yellow }
function Write-Fail { param($m) Write-Seg "  $($G.Fail) $m" -Color 203 -Fallback Red }
function Write-Note { param($m) Write-Host "    $m" }

function Get-Width {
    try { $w = $Host.UI.RawUI.WindowSize.Width } catch { $w = 0 }
    if (-not $w -or $w -le 0) { $w = 80 }
    $w
}

# The logo, written in ASCII stand-ins so both installers carry the same
# template: # full block, = | [ ] { } double-line box pieces, ^ _ half blocks.
$Logo = @(
    '########]######]  #####]  ######]#######]'
    '{==##[==}##[==##]##[==##]##[====}##[====}'
    '   ##|   ######[}#######|##|     #####]  '
    '   ##|   ##[==##]##[==##|##|     ##[==}  '
    '   ##|   ##|  ##|##|  ##|{######]#######]'
    '   {=}   {=}  {=}{=}  {=} {=====}{======}'
)
$LogoSmall = @(
    '^#^ #^# _^# #^^ #^^'
    ' #  #^_ #^# #__ ##_'
)
$Gradient = @(27, 33, 39, 45, 51, 87)       # blue to cyan, top to bottom

function Convert-Glyphs([string]$s) {
    $map = [ordered]@{ '#' = 0x2588; '=' = 0x2550; '|' = 0x2551; '[' = 0x2554; ']' = 0x2557
                       '{' = 0x255A; '}' = 0x255D; '^' = 0x2580; '_' = 0x2584 }
    foreach ($k in $map.Keys) { $s = $s.Replace($k, (U $map[$k])) }
    $s
}

# Sized to the window: the full logo where it fits, a compact one where it
# does not, plain text in a very narrow window.
function Show-Banner {
    $width = Get-Width
    $version = $null
    try {
        $init = Join-Path $PSScriptRoot 'trace_app\__init__.py'
        $hit = Select-String -Path $init -Pattern '^__version__ = "(.*)"' | Select-Object -First 1
        if ($hit) { $version = $hit.Matches[0].Groups[1].Value }
    } catch { }

    Write-Host ''
    if ($width -ge 56) {
        for ($i = 0; $i -lt $Logo.Count; $i++) {
            Write-Seg ('  ' + (Convert-Glyphs $Logo[$i])) -Color $Gradient[$i] -Fallback Cyan
            if (-not $Yes) { Start-Sleep -Milliseconds 30 }
        }
        Write-Host ''
        Write-Seg '  Toolkit for Retrieval and Analysis of Cyber Evidence' -Dim -Fallback DarkGray
        $ruleWidth = 52
    } elseif ($width -ge 24) {
        Write-Seg ('  ' + (Convert-Glyphs $LogoSmall[0])) -Color $Gradient[1] -Fallback Cyan
        Write-Seg ('  ' + (Convert-Glyphs $LogoSmall[1])) -Color $Gradient[3] -Fallback Cyan
        Write-Host ''
        Write-Seg '  Forensic Toolkit' -Dim -Fallback DarkGray
        $ruleWidth = 26
    } else {
        Write-Seg '  TRACE' -Color 39 -Fallback Cyan -Bold -NoNewline
        Write-Seg ' Forensic Toolkit' -Dim -Fallback DarkGray
        $ruleWidth = 26
    }
    $detail = " $($G.Dot) Windows"
    # The version is dropped where it would wrap the line.
    if ($version -and $width -ge 32) { $detail += " $($G.Dot) v$version" }
    Write-Seg '  Installer' -Color 39 -Fallback Cyan -NoNewline
    Write-Seg $detail -Dim -Fallback DarkGray
    $ruleWidth = [Math]::Min($ruleWidth, $width - 4)
    if ($ruleWidth -gt 0) { Write-Seg ('  ' + ($G.Rule * $ruleWidth)) -Dim -Fallback DarkGray }
}

Show-Banner

# --- Locate a suitable Python ---------------------------------------------
Write-Step "Looking for Python 3.10 or newer"

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
        Write-Ok "Using $candidate (Python $ver)"
        break
    } else {
        Write-Warn "$candidate is Python $ver - TRACE needs 3.10 or newer"
    }
}

if (-not $python) {
    Write-Fail "No suitable Python found. TRACE needs Python 3.10 or newer."
    Write-Note "Install it from https://www.python.org/downloads/windows/"
    Write-Note "and tick 'Add python.exe to PATH' during setup."
    exit 1
}

# --- Virtual environment ---------------------------------------------------
Write-Step "Creating virtual environment"
if (Test-Path 'venv') {
    Write-Warn "A venv directory already exists."
    $reply = if ($Yes) { 'n' } else { Read-Host "    Recreate it? Existing packages will be lost. [y/N]" }
    if ($reply -match '^[Yy]') {
        Remove-Item -Recurse -Force venv
        & $python -m venv venv
        Write-Ok "venv recreated"
    } else {
        Write-Ok "Reusing the existing venv"
    }
} else {
    & $python -m venv venv
    Write-Ok "venv ready"
}

# --- Dependencies ----------------------------------------------------------
Write-Step "Installing Python packages (this can take a few minutes)"
$venvPy = Join-Path (Resolve-Path 'venv') 'Scripts\python.exe'
& $venvPy -m pip install --upgrade pip
# --only-binary for the two forensic engines: if no wheel exists for this
# Python, say so plainly rather than attempt a C build that will fail.
& $venvPy -m pip install --only-binary=pytsk3,libewf-python -r requirements.txt

if ($LASTEXITCODE -ne 0) {
    Write-Fail "Dependency installation failed."
    Write-Note "pytsk3 and libewf-python have pre-built wheels for Python 3.10-3.14"
    Write-Note "on x64, x86 and ARM64 Windows. Check that '$python' is one of"
    Write-Note "those versions."
    exit 1
}

Write-Host ''
Write-Seg "  $($G.Ok) TRACE is installed." -Color 42 -Fallback Green -Bold
Write-Host ''
Write-Host '  Start it with:'
Write-Seg '    venv\Scripts\activate' -Color 39 -Fallback Cyan
Write-Seg '    python main.py' -Color 39 -Fallback Cyan
Write-Host ''
Write-Seg '  Type deactivate when you are finished.' -Dim -Fallback DarkGray
Write-Host ''
