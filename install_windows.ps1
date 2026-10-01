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

# Redirected output (a CI log, a file) is written in the console's code page;
# unless that is UTF-8, anything outside ASCII arrives garbled, so the banner
# and symbols fall back to plain text, as install.sh does without a UTF-8
# locale.
$script:Unicode = (-not [Console]::IsOutputRedirected) -or
                  ([Console]::OutputEncoding.CodePage -eq 65001)

# The classic console's fonts (Consolas, Lucida) have the box-drawing and
# block characters but not check marks; Windows Terminal and VS Code have all.
if ($script:Unicode -and ($env:WT_SESSION -or $env:TERM_PROGRAM -eq 'vscode')) {
    $G = @{ Step = (U 0x25B8); Ok = (U 0x2713); Warn = '!'; Fail = (U 0x2717) }
} else {
    $G = @{ Step = '>'; Ok = '+'; Warn = '!'; Fail = 'x' }
}
if ($script:Unicode) {
    $G.Rule = U 0x2500
    $G.Dot = U 0x00B7
} else {
    $G.Rule = '-'
    $G.Dot = '-'
}

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
    if ($script:Unicode -and $width -ge 56) {
        for ($i = 0; $i -lt $Logo.Count; $i++) {
            Write-Seg ('  ' + (Convert-Glyphs $Logo[$i])) -Color $Gradient[$i] -Fallback Cyan
            if (-not $Yes) { Start-Sleep -Milliseconds 30 }
        }
        Write-Host ''
        Write-Seg '  Toolkit for Retrieval and Analysis of Cyber Evidence' -Dim -Fallback DarkGray
        $ruleWidth = 52
    } elseif ($script:Unicode -and $width -ge 24) {
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

# === Progress =============================================================
# Long commands write everything to install.log. In a console one line,
# rewritten in place, says what is happening now; the log is shown only if a
# step fails. Redirected (CI), only the steps' results are printed.
$LogFile = Join-Path $PSScriptRoot 'install.log'
Set-Content -Path $LogFile -Value '' -Encoding UTF8
$script:Live = -not [Console]::IsOutputRedirected
if ($G.Ok -ne '+') {
    $Frames = @(0x280B, 0x2819, 0x2839, 0x2838, 0x283C, 0x2834, 0x2826, 0x2827,
                0x2807, 0x280F) | ForEach-Object { U $_ }
} else {
    $Frames = @('|', '/', '-', '\')
}
$script:Frame = 0

# What a line of pip output means, in a few words; nothing for noise.
function Get-Status([string]$Line) {
    $Line = $Line.Trim()
    if ($Line -match '^Collecting ([A-Za-z0-9_.\-]+)') { return "Resolving $($Matches[1])" }
    if ($Line -match '^(Downloading|Using cached) (\S+)(?: \((.+)\))?$') {
        # pyside6_addons-6.11.2-cp310-abi3-win_amd64.whl (175.1 MB)
        #   -> Downloading pyside6_addons 6.11.2 (175.1 MB)
        $verb = if ($Matches[1] -eq 'Using cached') { 'Cached' } else { 'Downloading' }
        $size = if ($Matches[3]) { " ($($Matches[3]))" } else { '' }
        $file = ($Matches[2] -split '/')[-1]
        $bits = $file -split '-'
        $version = if ($bits.Count -gt 1) { $bits[1] -replace '\.tar\.gz$|\.zip$', '' } else { '' }
        if ($file.EndsWith('.metadata')) { return "Checking $($bits[0]) $version" }
        return "$verb $($bits[0]) $version$size"
    }
    if ($Line -match '^Requirement already satisfied: ([A-Za-z0-9_.\-]+)') {
        return "Already installed $($Matches[1])"
    }
    if ($Line -match '^Installing collected packages: (.+)$') {
        $n = ($Matches[1] -split ',').Count
        if ($n -eq 1) { return 'Installing 1 package' }
        return "Installing $n packages"
    }
    return $null
}

function Show-Live([string]$Text) {
    $width = [Math]::Max(10, (Get-Width) - 6)
    if ($Text.Length -gt $width) { $Text = $Text.Substring(0, $width) }
    Write-Host "`r  " -NoNewline
    Write-Seg $Frames[$script:Frame] -Color 39 -Fallback Cyan -NoNewline
    Write-Host (' ' + $Text.PadRight($width)) -NoNewline
    $script:Frame = ($script:Frame + 1) % $Frames.Count
}

function Clear-Live {
    if ($script:Live) { Write-Host ("`r" + (' ' * ((Get-Width) - 1)) + "`r") -NoNewline }
}

# Run a command into the log, showing progress. Returns its exit status.
function Invoke-Quietly {
    param([string]$Label, [string]$Exe, [string[]]$Arguments)
    Add-Content -Path $LogFile -Value "`n> $Exe $($Arguments -join ' ')" -Encoding UTF8
    if ($script:Live) { Show-Live $Label }
    # pip's warnings arrive on stderr; they are log lines, not failures.
    $saved = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & $Exe @Arguments 2>&1 | ForEach-Object {
            $line = "$_"
            Add-Content -Path $LogFile -Value $line -Encoding UTF8
            if ($script:Live) {
                $status = Get-Status $line
                if ($status) { Show-Live $status }
            }
        }
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $saved
    }
    Clear-Live
    return $code
}

function Write-LogTail {
    Write-Note "Last lines of ${LogFile}:"
    Get-Content $LogFile -Tail 25 | ForEach-Object { Write-Host "      $_" }
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
        if ((Invoke-Quietly 'Creating venv' $python @('-m', 'venv', 'venv')) -ne 0) {
            Write-Fail "Could not create the virtual environment."; Write-LogTail; exit 1
        }
        Write-Ok "venv recreated"
    } else {
        Write-Ok "Reusing the existing venv"
    }
} else {
    if ((Invoke-Quietly 'Creating venv' $python @('-m', 'venv', 'venv')) -ne 0) {
        Write-Fail "Could not create the virtual environment."; Write-LogTail; exit 1
    }
    Write-Ok "venv ready"
}

# --- Dependencies ----------------------------------------------------------
Write-Step "Installing Python packages (this can take a few minutes)"
$venvPy = Join-Path (Resolve-Path 'venv') 'Scripts\python.exe'
if ((Invoke-Quietly 'Updating pip' $venvPy @('-m', 'pip', 'install', '--upgrade', 'pip')) -ne 0) {
    Write-Fail "Could not update pip."; Write-LogTail; exit 1
}
$before = (Get-Content $LogFile).Count
# --only-binary for the two forensic engines: if no wheel exists for this
# Python, say so plainly rather than attempt a C build that will fail.
$code = Invoke-Quietly 'Installing packages' $venvPy @('-m', 'pip', 'install',
    '--only-binary=pytsk3,libewf-python', '-r', 'requirements.txt')

if ($code -ne 0) {
    Write-Fail "Dependency installation failed."
    Write-LogTail
    Write-Note ""
    Write-Note "pytsk3 and libewf-python have pre-built wheels for Python 3.10-3.14"
    Write-Note "on x64, x86 and ARM64 Windows. Check that '$python' is one of"
    Write-Note "those versions."
    exit 1
}
$installed = Get-Content $LogFile | Select-Object -Skip $before |
    Where-Object { $_ -like 'Successfully installed *' } | Select-Object -Last 1
if ($installed) {
    Write-Ok "$(($installed -split ' ').Count - 2) packages installed"
} else {
    Write-Ok "Every package already installed"
}
Write-Seg '    Full log: install.log' -Dim -Fallback DarkGray

Write-Host ''
Write-Seg "  $($G.Ok) TRACE is installed." -Color 42 -Fallback Green -Bold
Write-Host ''
Write-Host '  Start it with:'
Write-Seg '    venv\Scripts\activate' -Color 39 -Fallback Cyan
Write-Seg '    python main.py' -Color 39 -Fallback Cyan
Write-Host ''
Write-Seg '  Type deactivate when you are finished.' -Dim -Fallback DarkGray
Write-Host ''
