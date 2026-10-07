#!/bin/bash
set -e

# --yes: answer every prompt with the default and skip the animation, so the
# script can run unattended (CI runs this exact script on every platform).
ASSUME_YES=0
for arg in "$@"; do
    case "$arg" in
        -y|--yes) ASSUME_YES=1 ;;
        -h|--help)
            echo "Usage: ./install.sh [--yes]"
            echo "  --yes   non-interactive: accept the detected platform and defaults"
            exit 0 ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# === Output ===============================================================
# Kept identical in look to install_windows.ps1.
#
# Colour only on a terminal, and never with NO_COLOR set (no-color.org).
# 256-colour codes rather than 24-bit: macOS Terminal.app has no 24-bit.
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    ESC=$'\033'
    R="${ESC}[0m"; BOLD="${ESC}[1m"; DIM="${ESC}[2m"
    ACCENT="${ESC}[38;5;39m"; GREEN="${ESC}[38;5;42m"
    YELLOW="${ESC}[38;5;214m"; RED="${ESC}[38;5;203m"
    GRADIENT=(27 33 39 45 51 87)       # blue to cyan, top to bottom
else
    ESC=""; R=""; BOLD=""; DIM=""; ACCENT=""; GREEN=""; YELLOW=""; RED=""
    GRADIENT=()
fi

# Block letters and symbols need a UTF-8 terminal; anything else gets ASCII.
UNICODE=0
case "${LC_ALL:-${LC_CTYPE:-${LANG:-}}}" in
    *[Uu][Tt][Ff]-8*|*[Uu][Tt][Ff]8*) UNICODE=1 ;;
esac
if [[ "$UNICODE" -eq 1 ]]; then
    G_STEP="▸"; G_OK="✓"; G_WARN="!"; G_FAIL="✗"; G_RULE="─"; G_DOT="·"
else
    G_STEP=">"; G_OK="+"; G_WARN="!"; G_FAIL="x"; G_RULE="-"; G_DOT="-"
fi

step() { printf '\n%s%s %s%s\n' "$ACCENT$BOLD" "$G_STEP" "$1" "$R"; }
ok()   { printf '  %s%s%s %s\n' "$GREEN" "$G_OK" "$R" "$1"; }
warn() { printf '  %s%s %s%s\n' "$YELLOW" "$G_WARN" "$1" "$R"; }
fail() { printf '  %s%s %s%s\n' "$RED" "$G_FAIL" "$1" "$R"; }
note() { printf '    %s\n' "$1"; }

term_width() {
    local w="${COLUMNS:-}" size=""
    if [[ ! "$w" =~ ^[0-9]+$ ]]; then
        # Grouped: a failed "< /dev/tty" (no terminal, as in CI) is the
        # shell's own error, outside the command's 2>/dev/null.
        size=$( { stty size < /dev/tty; } 2>/dev/null || true)
        w="${size##* }"
    fi
    if [[ ! "$w" =~ ^[0-9]+$ ]]; then
        w=$(tput cols 2>/dev/null || true)
    fi
    [[ "$w" =~ ^[0-9]+$ && "$w" -gt 0 ]] || w=80
    echo "$w"
}

# The logo, written in ASCII stand-ins so both installers carry the same
# template: # full block, = | [ ] { } double-line box pieces, ^ _ half blocks.
LOGO=(
    "########]######]  #####]  ######]#######]"
    "{==##[==}##[==##]##[==##]##[====}##[====}"
    "   ##|   ######[}#######|##|     #####]  "
    "   ##|   ##[==##]##[==##|##|     ##[==}  "
    "   ##|   ##|  ##|##|  ##|{######]#######]"
    "   {=}   {=}  {=}{=}  {=} {=====}{======}"
)
LOGO_SMALL=(
    "^#^ #^# _^# #^^ #^^"
    " #  #^_ #^# #__ ##_"
)

glyphs() {
    local s="$1"
    s="${s//\#/█}"; s="${s//=/═}"; s="${s//|/║}"
    s="${s//\[/╔}"; s="${s//\]/╗}"; s="${s//\{/╚}"; s="${s//\}/╝}"
    s="${s//^/▀}";  s="${s//_/▄}"
    printf '%s' "$s"
}

shade() {
    if [[ ${#GRADIENT[@]} -gt 0 ]]; then
        printf '%s[38;5;%sm' "$ESC" "${GRADIENT[$1]}"
    fi
}

rule() {
    local n="$1" line="" i
    for ((i = 0; i < n; i++)); do line="$line$G_RULE"; done
    printf '  %s%s%s\n' "$DIM" "$line" "$R"
}

# Sized to the window: the full logo where it fits, a compact one where it
# does not, plain text in a very narrow window or a terminal without UTF-8.
banner() {
    local platform="$1" width version delay=0 i line rule_width
    width=$(term_width)
    version=$(sed -n 's/^__version__ = "\(.*\)"/\1/p' \
        "$SCRIPT_DIR/trace_app/__init__.py" 2>/dev/null || true)
    [[ "$ASSUME_YES" -eq 0 && -t 1 ]] && delay=0.03

    echo
    if [[ "$UNICODE" -eq 1 && "$width" -ge 56 ]]; then
        for i in "${!LOGO[@]}"; do
            printf '  %s%s%s\n' "$(shade "$i")" "$(glyphs "${LOGO[$i]}")" "$R"
            [[ "$delay" != 0 ]] && sleep "$delay"
        done
        printf '\n  %sToolkit for Retrieval and Analysis of Cyber Evidence%s\n' "$DIM" "$R"
        rule_width=52
    elif [[ "$UNICODE" -eq 1 && "$width" -ge 24 ]]; then
        printf '  %s%s%s\n' "$(shade 1)" "$(glyphs "${LOGO_SMALL[0]}")" "$R"
        printf '  %s%s%s\n' "$(shade 3)" "$(glyphs "${LOGO_SMALL[1]}")" "$R"
        printf '\n  %sForensic Toolkit%s\n' "$DIM" "$R"
        rule_width=26
    else
        printf '  %sTRACE%s %sForensic Toolkit%s\n' "$ACCENT$BOLD" "$R" "$DIM" "$R"
        rule_width=26
    fi
    line="${ACCENT}Installer${R}${DIM} $G_DOT $platform"
    # The version is dropped where it would wrap the line.
    [[ -n "$version" && "$width" -ge 32 ]] && line="$line $G_DOT v$version"
    printf '  %s%s\n' "$line" "$R"
    (( rule_width > width - 4 )) && rule_width=$((width - 4))
    (( rule_width > 0 )) && rule "$rule_width"
    return 0
}

# === Progress =============================================================
# Long commands write everything to install.log. On a terminal one line,
# rewritten in place, says what is happening now; the log is shown only if a
# step fails. Off a terminal (CI) the steps' results are all that is printed.
LOG="$SCRIPT_DIR/install.log"
: > "$LOG"
LIVE=0
[[ -t 1 ]] && LIVE=1
if [[ "$UNICODE" -eq 1 ]]; then
    FRAMES=("⠋" "⠙" "⠹" "⠸" "⠼" "⠴" "⠦" "⠧" "⠇" "⠏")
else
    FRAMES=("|" "/" "-" "\\")
fi
FRAME=0
TERM_COLS=80

# What a line of pip or apt output means, in a few words; nothing for noise.
describe() {
    local line="$1" rest
    line="${line#"${line%%[![:space:]]*}"}"          # leading blanks
    case "$line" in
        "Collecting "*)
            rest="${line#Collecting }"; echo "Resolving ${rest%%[ <>=;\[]*}" ;;
        "Downloading "*|"Using cached "*)
            # pyside6_addons-6.11.2-cp310-abi3-manylinux_2_34_x86_64.whl (175.1 MB)
            #   -> Downloading pyside6_addons 6.11.2 (175.1 MB)
            rest="${line#Downloading }"; rest="${rest#Using cached }"
            local file="${rest%% *}" size="" name version verb="Downloading"
            file="${file##*/}"
            [[ "$rest" == *" ("*")" ]] && size=" (${rest##* (}"
            name="${file%%-*}"; version="${file#*-}"; version="${version%%-*}"
            version="${version%.tar.gz}"; version="${version%.zip}"
            [[ "$line" == "Using cached "* ]] && verb="Cached"
            if [[ "$file" == *.metadata ]]; then
                echo "Checking $name $version"
            else
                echo "$verb $name $version$size"
            fi ;;
        "Requirement already satisfied: "*)
            rest="${line#Requirement already satisfied: }"
            echo "Already installed ${rest%%[ <>=;\[]*}" ;;
        "Installing collected packages: "*)
            rest="${line#Installing collected packages: }"
            local n=$(( $(printf '%s' "$rest" | tr -cd ',' | wc -c) + 1 ))
            if [[ "$n" -eq 1 ]]; then echo "Installing 1 package"
            else echo "Installing $n packages"; fi ;;
        "Get:"*)
            echo "Downloading $(echo "$line" | awk '{print $5}')" ;;
        "Unpacking "*|"Setting up "*)
            rest="${line%% (*}"; echo "${rest%%:*}" ;;
        "Reading package lists"*|"Building dependency tree"*|"Hit:"*)
            echo "Reading package lists" ;;
        *) return 1 ;;
    esac
}

live() {
    local text="$1" width=$(( TERM_COLS - 6 ))
    (( width < 10 )) && width=10
    printf '\r  %s%s%s %-*s' "$ACCENT" "${FRAMES[$FRAME]}" "$R" "$width" "${text:0:$width}"
    FRAME=$(( (FRAME + 1) % ${#FRAMES[@]} ))
}

clear_live() {
    [[ "$LIVE" -eq 1 ]] && printf '\r%*s\r' "$(( TERM_COLS - 1 ))" ''
    return 0
}

# quietly LABEL COMMAND...: run COMMAND into the log, showing progress.
quietly() {
    local label="$1" rc line text
    shift
    printf '\n$ %s\n' "$*" >> "$LOG"
    if [[ "$LIVE" -eq 1 ]]; then
        TERM_COLS=$(term_width)
        live "$label"
        set +e
        "$@" 2>&1 | while IFS= read -r line; do
            printf '%s\n' "$line" >> "$LOG"
            text=$(describe "$line") && live "$text"
        done
        rc=${PIPESTATUS[0]}
        set -e
        clear_live
    else
        set +e
        "$@" >> "$LOG" 2>&1
        rc=$?
        set -e
    fi
    return "$rc"
}

log_tail() {
    note "Last lines of $LOG:"
    tail -n 25 "$LOG" | sed 's/^/      /'
}

# === Detect OS type =======================================================
OS_TYPE=$(uname)
if [[ "$OS_TYPE" == "Darwin" ]]; then
    DETECTED_OS="macOS"
elif [[ "$OS_TYPE" == "Linux" ]]; then
    if grep -qi "microsoft" /proc/version 2>/dev/null; then
        DETECTED_OS="WSL"
    else
        DETECTED_OS="Linux"
    fi
else
    banner "$OS_TYPE"
    fail "Unsupported OS: $OS_TYPE"
    note "This installer supports macOS, Linux and WSL."
    note "On Windows, run install_windows.ps1 in PowerShell instead."
    exit 1
fi

banner "$DETECTED_OS"

if [[ "$ASSUME_YES" -eq 1 ]]; then
    USER_INPUT="y"
else
    echo
    read -r -p "  Install for $DETECTED_OS? [Y/n, or macos / linux / wsl to override] " USER_INPUT
fi
USER_INPUT=$(echo "$USER_INPUT" | tr '[:upper:]' '[:lower:]')

case "$USER_INPUT" in
    n|no)   warn "Installation cancelled."; exit 0 ;;
    macos)  USER_OS="macOS" ;;
    linux)  USER_OS="Linux" ;;
    wsl)    USER_OS="WSL" ;;
    *)      USER_OS="$DETECTED_OS" ;;
esac

# --- Pick a Python interpreter -------------------------------------------
# Python 3.10 or newer: pytsk3 and libewf-python publish pre-built wheels for
# 3.10+ on every platform, so nothing is compiled. (3.9 is end-of-life and
# would need a C toolchain for both.)
find_python() {
    step "Looking for Python 3.10 or newer"
    # TRACE_PYTHON names the interpreter explicitly -- CI sets it so each
    # job installs with the Python it is meant to test, not whichever newer
    # one the runner also has.
    for candidate in ${TRACE_PYTHON:-} python3.14 python3.13 python3.12 python3.11 python3.10 python3; do
        if command -v "$candidate" &> /dev/null; then
            PY="$candidate"
            PY_VER=$("$PY" -c 'import sys; print("%d.%d" % sys.version_info[:2])')
            MAJOR=${PY_VER%%.*}
            MINOR=${PY_VER##*.}
            if [[ "$MAJOR" -eq 3 && "$MINOR" -ge 10 ]]; then
                ok "Using $PY (Python $PY_VER)"
                return 0
            fi
        fi
    done
    fail "No suitable Python found. TRACE needs Python 3.10 or newer."
    note "macOS:          the installer from https://www.python.org/downloads/macos/"
    note "                (or: brew install python@3.12)"
    note "Debian/Ubuntu:  sudo apt install python3.12 python3.12-venv"
    note "                (older releases: python.org or pyenv)"
    exit 1
}

# --- System dependencies --------------------------------------------------
install_macos_deps() {
    # Nothing to install outside Python: every library comes as a wheel --
    # The Sleuth Kit (pytsk3), libewf, and libmagic (pylibmagic). No
    # Homebrew, no Xcode. Only Python 3.10+ is needed (macOS's own python3
    # is 3.9).
    step "System packages"
    ok "None needed on macOS: every library installs as a wheel"
}

install_linux_deps() {
    step "Installing system packages"
    if ! command -v apt &> /dev/null; then
        warn "This script automates apt-based distributions only."
        note "Install the equivalents of these, then rerun:"
        note "  python3 (3.10+) with venv and pip"
        note "  libmagic (file-type detection)"
        note "  libxcb-cursor0 libegl1 libxkbcommon-x11-0 libgl1 (Qt runtime)"
        note "  libpulse (Qt Multimedia) and gssapi/krb5 (Qt Network)"
        if [[ "$ASSUME_YES" -eq 0 ]]; then
            read -r -p "    Continue anyway? [y/N] " cont
            [[ "$cont" =~ ^[Yy]$ ]] || exit 1
        fi
        return
    fi

    # No compiler or -dev packages: pytsk3 and libewf-python come as
    # pre-built wheels with The Sleuth Kit and libewf inside.
    # libmagic1: file-type detection (python-magic loads it at runtime).
    # libxcb-cursor0 and friends: the Qt 6 platform plugins.
    SUDO=""
    if [[ "$(id -u)" -ne 0 ]]; then
        SUDO="sudo"
        # Ask for the password now, in plain sight: with apt's output going
        # to the log, a prompt from inside it would never be seen.
        sudo -v
    fi
    if ! quietly "Reading package lists" $SUDO apt-get update; then
        fail "apt-get update failed."; log_tail; exit 1
    fi
    # libpulse0: Qt Multimedia (the audio/video player) fails to import
    #   without it, which stops the whole window opening.
    # libgssapi-krb5-2: Qt Network.
    # --no-install-recommends: python3-pip otherwise pulls in a C/C++
    #   compiler that nothing here needs.
    local before count
    before=$(wc -l < "$LOG")
    if ! quietly "Installing system packages" \
        $SUDO apt-get install -y --no-install-recommends \
        python3 python3-venv python3-pip \
        libmagic1 \
        libxcb-cursor0 libxcb-xinerama0 libegl1 libxkbcommon-x11-0 libgl1 \
        libglib2.0-0 libfontconfig1 libdbus-1-3 \
        libpulse0 libgssapi-krb5-2; then
        fail "Installing system packages failed."; log_tail; exit 1
    fi
    count=$(tail -n +"$((before + 1))" "$LOG" | grep -c '^Setting up ' || true)
    if [[ "$count" -gt 0 ]]; then
        ok "$count system packages installed"
    else
        ok "System packages already installed"
    fi
}

install_wsl_deps() {
    install_linux_deps
    warn "WSL needs a working X/Wayland display (WSLg on Windows 11)."
}

# --- Run ------------------------------------------------------------------
case "$USER_OS" in
    macOS) install_macos_deps ;;
    Linux) install_linux_deps ;;
    WSL)   install_wsl_deps ;;
esac

find_python

step "Creating virtual environment"
if ! quietly "Creating venv" "$PY" -m venv venv; then
    fail "Could not create the virtual environment."; log_tail; exit 1
fi
ok "venv ready"

step "Installing Python packages (this can take a few minutes)"
VENV_PY="venv/bin/python"
if ! quietly "Updating pip" "$VENV_PY" -m pip install --upgrade pip; then
    fail "Could not update pip."; log_tail; exit 1
fi
BEFORE=$(wc -l < "$LOG")
# --only-binary for the two forensic engines: if no wheel exists for this
# platform, say so plainly rather than attempt a C build that will fail.
if ! quietly "Installing packages" \
    "$VENV_PY" -m pip install --only-binary=pytsk3,libewf-python -r requirements.txt; then
    fail "Dependency installation failed."
    log_tail
    note ""
    note "pytsk3 and libewf-python have pre-built wheels for Python 3.10-3.14"
    note "on Windows, macOS (Apple Silicon and Intel) and Linux (x86_64 and"
    note "aarch64). Check that $PY is one of those versions and this machine"
    note "one of those platforms."
    exit 1
fi
INSTALLED=$(tail -n +"$((BEFORE + 1))" "$LOG" | grep '^Successfully installed' | wc -w || true)
if [[ "$INSTALLED" -gt 2 ]]; then
    ok "$((INSTALLED - 2)) packages installed"
else
    ok "Every package already installed"
fi
note "${DIM}Full log: install.log${R}"

echo
printf '  %s%s TRACE is installed.%s\n\n' "$GREEN$BOLD" "$G_OK" "$R"
printf '  Start it with:\n'
printf '    %ssource venv/bin/activate%s\n' "$ACCENT" "$R"
printf '    %spython main.py%s\n\n' "$ACCENT" "$R"
printf '  %sType deactivate when you are finished.%s\n\n' "$DIM" "$R"
