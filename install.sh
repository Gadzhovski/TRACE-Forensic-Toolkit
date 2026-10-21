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
# venv, requirements.txt and the launcher are this checkout's, wherever the
# script was started from ("bash ~/TRACE/install.sh" in another folder made
# a venv there and could not find requirements.txt).
cd "$SCRIPT_DIR"

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
        # dnf "Installing : glib2-2.82.x86_64 3/52", dnf5 "[ 3/52]
        # Installing glib2-0:2.82...", pacman "(3/52) installing glib2",
        # zypper "(3/52) Installing: glib2-2.82...".
        *[Ii]"nstalling"*)
            rest="${line#*nstalling}"; rest="${rest#*[: ]}"
            rest="${rest#"${rest%%[![:space:]:]*}"}"
            echo "Installing ${rest%% *}" ;;
        "Retrieving"*|"Downloading Packages"*|"downloading "*)
            rest="${line#Retrieving}"; rest="${rest#: }"; rest="${rest# package }"
            rest="${rest#downloading }"
            echo "Downloading ${rest%% *}" ;;
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

# --- Python ------------------------------------------------------------------
# Python 3.10 or newer: pytsk3 and libewf-python publish pre-built wheels for
# 3.10+ on every platform, so nothing is compiled. (3.9 is end-of-life and
# would need a C toolchain for both.)

# python_version EXE: "3.12" if EXE runs, else nothing.
python_version() {
    "$1" -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null \
        || true
}

# new_enough VERSION: whether VERSION ("3.12") is 3.10 or newer.
new_enough() {
    [[ "$1" =~ ^3\.([0-9]+)$ ]] && [[ "${BASH_REMATCH[1]}" -ge 10 ]]
}

# pick_python: set PY and PY_VER to the newest suitable interpreter, or
# return 1. TRACE_PYTHON names it explicitly -- CI sets it so each job
# installs with the Python it is meant to test.
pick_python() {
    local candidate version
    for candidate in ${TRACE_PYTHON:-} python3.14 python3.13 python3.12 \
            python3.11 python3.10 python3; do
        command -v "$candidate" &> /dev/null || continue
        version=$(python_version "$candidate")
        if new_enough "$version"; then
            PY="$candidate"; PY_VER="$version"
            return 0
        fi
    done
    return 1
}

no_python() {
    fail "No suitable Python found. TRACE needs Python 3.10 or newer."
    note "macOS:          the installer from https://www.python.org/downloads/macos/"
    note "                (or: brew install python@3.12)"
    note "Debian/Ubuntu:  sudo apt install python3.12 python3.12-venv"
    note "Fedora/RHEL:    sudo dnf install python3.12"
    note "openSUSE Leap:  sudo zypper install python312"
    note "                (older releases: python.org or pyenv)"
    exit 1
}

# --- System packages -----------------------------------------------------------
# What TRACE needs from the system on Linux, per package manager. No
# compiler or -dev packages: pytsk3 and libewf-python come as pre-built
# wheels with The Sleuth Kit and libewf inside.
#   libmagic: file-type detection (python-magic loads it at run time)
#   xcb-cursor, xcb-icccm, xcb-keysyms, xcb-shape, xkbcommon-x11, EGL, GL,
#     glib, fontconfig, dbus: the Qt 6 platform plugin and its libraries
#     (a minimal Ubuntu lacks icccm, keysyms and shape: ldd on libqxcb.so)
#   pulse: Qt Multimedia -- without it the window cannot open
#   krb5 / gssapi: Qt Network
PKG=""
for manager in apt-get dnf pacman zypper; do
    if command -v "$manager" &> /dev/null; then PKG="$manager"; break; fi
done

packages_for() {
    case "$PKG" in
        apt-get)
            echo python3 python3-venv python3-pip libmagic1 \
                libxcb-cursor0 libxcb-xinerama0 libxcb-icccm4 libxcb-keysyms1 \
                libxcb-shape0 libegl1 libxkbcommon-x11-0 \
                libgl1 libglib2.0-0 libfontconfig1 libdbus-1-3 \
                libpulse0 libgssapi-krb5-2 ;;
        dnf)
            echo python3 python3-pip file-libs \
                xcb-util-cursor xcb-util-wm xcb-util-keysyms mesa-libEGL \
                libxkbcommon-x11 mesa-libGL \
                glib2 fontconfig dbus-libs pulseaudio-libs krb5-libs ;;
        pacman)
            echo python python-pip file \
                xcb-util-cursor xcb-util-wm xcb-util-keysyms libglvnd \
                libxkbcommon-x11 \
                glib2 fontconfig dbus libpulse krb5 ;;
        zypper)
            echo python3 python3-pip libmagic1 \
                libxcb-cursor0 libxcb-icccm4 libxcb-keysyms1 libxcb-shape0 \
                libglvnd libxkbcommon-x11-0 \
                libglib-2_0-0 libgthread-2_0-0 fontconfig libdbus-1-3 \
                libpulse0 krb5 ;;
    esac
}

# A newer Python where the distribution's own python3 is too old (RHEL /
# Rocky 9: 3.9; openSUSE Leap 15: 3.6; Ubuntu 20.04: 3.8).
newer_python_packages() {
    case "$PKG" in
        apt-get) echo python3.12 python3.12-venv ;;
        dnf)     echo python3.12 python3.12-pip ;;
        zypper)  echo python312 python312-pip ;;
    esac
}

SUDO=""
need_root() {
    if [[ -z "$SUDO" && "$(id -u)" -ne 0 ]]; then
        SUDO="sudo"
        # Ask for the password now, in plain sight: with the package
        # manager's output going to the log, a prompt from inside it would
        # never be seen.
        sudo -v
    fi
}

# pkg_install LABEL PACKAGE...: install with the distribution's manager.
pkg_install() {
    local label="$1"
    shift
    case "$PKG" in
        # --no-install-recommends: python3-pip otherwise pulls in a C/C++
        # compiler that nothing here needs.
        apt-get) quietly "$label" $SUDO env DEBIAN_FRONTEND=noninteractive \
                     apt-get install -y --no-install-recommends "$@" ;;
        dnf)     quietly "$label" $SUDO dnf install -y \
                     --setopt=install_weak_deps=False "$@" ;;
        # --needed: what is installed stays. No -y: a partial upgrade breaks
        # Arch; a stale package database says so and is the examiner's to
        # refresh (pacman -Syu).
        pacman)  quietly "$label" $SUDO pacman -S --needed --noconfirm "$@" ;;
        zypper)  quietly "$label" $SUDO zypper --non-interactive install \
                     --no-recommends "$@" ;;
    esac
}

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
    if [[ -z "$PKG" ]]; then
        warn "This script installs packages with apt, dnf, pacman or zypper only."
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
    need_root
    case "$PKG" in
        apt-get)
            if ! quietly "Reading package lists" $SUDO apt-get update; then
                fail "apt-get update failed."; log_tail; exit 1
            fi ;;
        zypper)
            if ! quietly "Reading package lists" \
                    $SUDO zypper --non-interactive refresh; then
                fail "zypper refresh failed."; log_tail; exit 1
            fi ;;
    esac
    local before count
    before=$(wc -l < "$LOG")
    # shellcheck disable=SC2046  # one word per package
    if ! pkg_install "Installing system packages" $(packages_for); then
        fail "Installing system packages failed."; log_tail
        [[ "$PKG" == pacman ]] && \
            note "If a package was not found, refresh first: sudo pacman -Syu"
        exit 1
    fi
    count=$(tail -n +"$((before + 1))" "$LOG" |
        grep -ciE '^(Setting up |[[:space:]]*Installing[[:space:]]*:|\[ *[0-9]+/[0-9]+\] Installing|\([0-9]+/[0-9]+\) installing|installing [^ ]+\.\.\.$)' \
        || true)
    if [[ "$count" -gt 0 ]]; then
        ok "$count system packages installed"
    else
        ok "System packages already installed"
    fi
}

install_wsl_deps() {
    install_linux_deps
    if [[ -z "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]]; then
        warn "WSL needs a display for TRACE's window: WSLg (Windows 11) or an X server."
    fi
}

find_python() {
    step "Looking for Python 3.10 or newer"
    if ! pick_python; then
        local newer
        newer=$(newer_python_packages)
        if [[ "$USER_OS" != "macOS" && -n "$newer" ]]; then
            note "The system's python3 is older than 3.10: installing $newer"
            need_root
            # shellcheck disable=SC2086
            pkg_install "Installing a newer Python" $newer || true
        fi
        pick_python || no_python
    fi
    ok "Using $PY (Python $PY_VER)"
    # Debian and Ubuntu keep venv's pip (ensurepip) in a package of its own,
    # one per Python version: python3-venv is only the default python3's.
    if ! "$PY" -c 'import ensurepip, venv' &> /dev/null; then
        if [[ "$PKG" == apt-get ]]; then
            need_root
            if pkg_install "Installing python$PY_VER-venv" "python$PY_VER-venv" &&
                    "$PY" -c 'import ensurepip, venv' &> /dev/null; then
                ok "python$PY_VER-venv installed"
                return 0
            fi
        fi
        fail "$PY cannot make a virtual environment (no venv / ensurepip)."
        note "Debian/Ubuntu:  sudo apt install python$PY_VER-venv"
        note "Fedora/RHEL:    sudo dnf install python3-pip"
        exit 1
    fi
}

# --- Virtual environment -------------------------------------------------------
# An existing venv is reused only if its own Python runs and is new enough:
# one made by an older Python, on another system, or whose Python has since
# been removed fails inside pip with nothing saying why.
make_venv() {
    step "Creating virtual environment"
    if [[ -e venv ]]; then
        local version why reply
        version=$(python_version venv/bin/python)
        if new_enough "$version"; then
            ok "Reusing the existing venv (Python $version)"
            return 0
        fi
        if [[ -n "$version" ]]; then
            why="it was made with Python $version"
        else
            why="its Python does not run (moved, made on another system, or removed)"
        fi
        warn "The existing venv cannot be used: $why."
        if [[ "$ASSUME_YES" -eq 1 ]]; then
            reply=y
        else
            read -r -p "    Rebuild it with $PY? [Y/n] " reply
        fi
        if [[ "$reply" =~ ^[Nn] ]]; then
            fail "TRACE needs a venv with Python 3.10 or newer."; exit 1
        fi
        rm -rf venv
    fi
    if ! quietly "Creating venv" "$PY" -m venv venv; then
        fail "Could not create the virtual environment."; log_tail; exit 1
    fi
    ok "venv ready"
}

install_packages() {
    step "Installing Python packages (this can take a few minutes)"
    if ! quietly "Updating pip" "$VENV_PY" -m pip install --upgrade pip; then
        fail "Could not update pip."; log_tail; exit 1
    fi
    local before installed
    before=$(wc -l < "$LOG")
    # --only-binary for the two forensic engines: if no wheel exists for
    # this platform, say so plainly rather than attempt a C build that will
    # fail.
    if ! quietly "Installing packages" "$VENV_PY" -m pip install \
            --only-binary=pytsk3,libewf-python -r requirements.txt; then
        fail "Dependency installation failed."
        log_tail
        note ""
        note "pytsk3 and libewf-python have pre-built wheels for Python 3.10-3.14"
        note "on Windows, macOS (Apple Silicon and Intel) and Linux (x86_64 and"
        note "aarch64). Check that $PY is one of those versions and this machine"
        note "one of those platforms."
        exit 1
    fi
    installed=$(tail -n +"$((before + 1))" "$LOG" |
        grep '^Successfully installed' | wc -w || true)
    if [[ "$installed" -gt 2 ]]; then
        ok "$((installed - 2)) packages installed"
    else
        ok "Every package already installed"
    fi
}

# --- Checking the install ------------------------------------------------------
# What a missing system library looks like only at the first start -- the
# forensic engines, Qt, libmagic -- tried now, while the installer can still
# say which package it is (trace_app/infra/install_check.py, shared with
# install_windows.ps1).

# The package holding a library, for the distribution's manager.
package_of() {
    local soname="$1"
    # Debian and openSUSE name a library's package by its name and major
    # version: libxcb-icccm.so.4 -> libxcb-icccm4.
    local by_major="${soname%%.so*}${soname##*.so.}"
    by_major="${by_major%%.*}"
    case "$PKG:$soname" in
        apt-get:libxcb-cursor*)    echo libxcb-cursor0 ;;
        apt-get:libEGL*)           echo libegl1 ;;
        apt-get:libGL.so*|apt-get:libOpenGL*) echo libgl1 ;;
        apt-get:libfontconfig*)    echo libfontconfig1 ;;
        apt-get:libdbus*)          echo libdbus-1-3 ;;
        apt-get:libxcb-*|apt-get:libxkbcommon*|apt-get:libX11-xcb*)
            echo "$by_major" | tr "[:upper:]" "[:lower:]" ;;
        apt-get:libSM*)            echo libsm6 ;;
        apt-get:libICE*)           echo libice6 ;;
        dnf:libxcb-cursor*)        echo xcb-util-cursor ;;
        dnf:libxcb-icccm*)         echo xcb-util-wm ;;
        dnf:libxcb-image*)         echo xcb-util-image ;;
        dnf:libxcb-keysyms*)       echo xcb-util-keysyms ;;
        dnf:libxcb-render-util*)   echo xcb-util-renderutil ;;
        dnf:libxkbcommon-x11*)     echo libxkbcommon-x11 ;;
        dnf:libEGL*)               echo mesa-libEGL ;;
        dnf:libGL.so*|dnf:libOpenGL*) echo mesa-libGL ;;
        pacman:libxcb-cursor*)     echo xcb-util-cursor ;;
        pacman:libxcb-icccm*)      echo xcb-util-wm ;;
        pacman:libxcb-image*)      echo xcb-util-image ;;
        pacman:libxcb-keysyms*)    echo xcb-util-keysyms ;;
        pacman:libxcb-render-util*) echo xcb-util-renderutil ;;
        pacman:libxkbcommon-x11*)  echo libxkbcommon-x11 ;;
        pacman:libEGL*|pacman:libGL.so*|pacman:libOpenGL*) echo libglvnd ;;
        zypper:libxcb-*)           echo "$by_major" ;;
        zypper:libxkbcommon-x11*)  echo libxkbcommon-x11-0 ;;
        zypper:libEGL*|zypper:libGL.so*|zypper:libOpenGL*) echo libglvnd ;;
    esac
}

check_install() {
    step "Checking the install"
    local problems missing qxcb lib package
    if ! problems=$("$VENV_PY" -m trace_app.infra.install_check 2>&1); then
        fail "TRACE's libraries do not all load:"
        printf '%s\n' "$problems" | sed 's/^/      /'
        printf '\n$ check\n%s\n' "$problems" >> "$LOG"
        exit 1
    fi
    ok "The forensic engines, Qt and libmagic load"
    if [[ "$USER_OS" == "macOS" ]] || ! command -v ldd &> /dev/null; then
        return 0
    fi
    # The window's platform plugin loads its libraries only when the window
    # opens: ask the loader now which of them are not on this system.
    qxcb=$("$VENV_PY" -c 'import os, PySide6
print(os.path.join(os.path.dirname(PySide6.__file__), "Qt", "plugins",
                   "platforms", "libqxcb.so"))' 2>/dev/null || true)
    [[ -f "$qxcb" ]] || return 0
    # sed, not awk: openSUSE Tumbleweed has no awk, and the check then said
    # nothing was missing.
    missing=$(ldd "$qxcb" 2>/dev/null |
        sed -n 's/^[[:space:]]*\([^[:space:]]*\) => not found.*/\1/p' | sort -u)
    if [[ -z "$missing" ]]; then
        ok "Qt's window libraries are present"
        return 0
    fi
    warn "TRACE's window needs libraries this system does not have:"
    for lib in $missing; do
        package=$(package_of "$lib")
        if [[ -n "$package" ]]; then
            note "  $lib  (package $package)"
        else
            note "  $lib"
        fi
    done
    note "Install them, then start TRACE. Without them its window cannot open."
}

# --- Launcher ------------------------------------------------------------------
# ./trace starts TRACE with this checkout's venv, from any folder, with no
# venv to activate. Links to it (in ~/bin) are followed back here.
write_launcher() {
    cat > trace <<'LAUNCHER'
#!/bin/sh
# Starts TRACE with its own Python (written by install.sh).
self=$0
while [ -h "$self" ]; do
    link=$(readlink "$self")
    case $link in
        /*) self=$link ;;
        *) self=$(dirname "$self")/$link ;;
    esac
done
here=$(cd "$(dirname "$self")" && pwd)
exec "$here/venv/bin/python" "$here/main.py" "$@"
LAUNCHER
    chmod +x trace
}

# --- Run -----------------------------------------------------------------------
case "$USER_OS" in
    macOS) install_macos_deps ;;
    Linux) install_linux_deps ;;
    WSL)   install_wsl_deps ;;
esac

find_python
make_venv
VENV_PY="venv/bin/python"
install_packages
check_install
write_launcher
note "${DIM}Full log: install.log${R}"

echo
printf '  %s%s TRACE is installed.%s\n\n' "$GREEN$BOLD" "$G_OK" "$R"
printf '  Start it with:\n'
printf '    %s./trace%s\n' "$ACCENT" "$R"
printf '  %sor: source venv/bin/activate, then python main.py%s\n\n' "$DIM" "$R"

if [[ "$ASSUME_YES" -eq 0 && -t 0 && -t 1 ]]; then
    read -r -p "  Start TRACE now? [Y/n] " reply
    if [[ ! "$reply" =~ ^[Nn] ]]; then
        # Detached, its output to its own log (user_data_dir()/trace.log):
        # closing this terminal leaves TRACE running.
        nohup ./trace > /dev/null 2>&1 &
        ok "TRACE is starting"
        echo
    fi
fi
