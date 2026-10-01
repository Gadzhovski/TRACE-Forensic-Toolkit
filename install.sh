#!/bin/bash
set -e

# === COLORS ===
RED="\033[1;31m"
GREEN="\033[1;32m"
LIGHT_GREEN="\033[38;5;82m"
CYAN="\033[1;36m"
MAGENTA="\033[1;35m"
YELLOW="\033[1;33m"
R="\033[0m"

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

[[ "$ASSUME_YES" -eq 1 ]] || clear

# === Animated intro ===
animate_intro() {
    local frames=("⣾" "⣷" "⣯" "⣟" "⡿" "⢿" "⣻" "⣽")
    echo -ne "${MAGENTA}Launching TRACE Installer "
    for i in {1..20}; do
        printf "\b%s" "${frames[$((i % 8))]}"
        sleep 0.08
    done
    echo -e "${R}\n"
}

# === Pulsing TRACE logo (with aligned borders) ===
print_banner() {
    local colors=("\033[38;5;48m" "\033[38;5;118m" "\033[38;5;83m" "\033[38;5;77m")
    for i in {0..3}; do
        clear
        echo -e "${CYAN}┌────────────────────────────────────────────────────────────────────┐${R}"
        echo -e "${CYAN}│                                                                    │${R}"
        echo -e "${CYAN}│${R}           ${colors[$i]}████████╗██████╗  █████╗ ██████╗███████╗${R}                 ${CYAN}│${R}"
        echo -e "${CYAN}│${R}           ${colors[$i]}╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝${R}                ${CYAN}│${R}"
        echo -e "${CYAN}│${R}              ${colors[$i]}██║   ██████╔╝███████║██║     █████╗${R}                  ${CYAN}│${R}"
        echo -e "${CYAN}│${R}              ${colors[$i]}██║   ██╔══██╗██╔══██║██║     ██╔══╝${R}                  ${CYAN}│${R}"
        echo -e "${CYAN}│${R}              ${colors[$i]}██║   ██║  ██║██║  ██║╚██████╗███████╗${R}                ${CYAN}│${R}"
        echo -e "${CYAN}│${R}              ${colors[$i]}╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝${R}                ${CYAN}│${R}"
        echo -e "${CYAN}│                                                                    │${R}" 
        echo -e "${CYAN}│${R}                ${MAGENTA}TRACE Forensic Toolkit Installer${R}                    ${CYAN}│${R}"
        echo -e "${CYAN}│${R}                ${YELLOW}Compatible with macOS • Linux • WSL${R}                 ${CYAN}│${R}"
        echo -e "${CYAN}└────────────────────────────────────────────────────────────────────┘${R}\n"
        sleep 0.12
    done
}

# === Run intro and banner ===
if [[ "$ASSUME_YES" -eq 0 ]]; then
    animate_intro
    print_banner
fi

# === Detect OS type ===
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
    echo -e "${RED}Unsupported OS: $OS_TYPE${R}"
    echo "This installer supports macOS, Linux, and WSL only."
    echo "On Windows, run install_windows.ps1 in PowerShell instead."
    exit 1
fi

echo -e "${CYAN}Detected operating system:${R} ${YELLOW}$DETECTED_OS${R}\n"

if [[ "$ASSUME_YES" -eq 1 ]]; then
    USER_INPUT="y"
else
    read -p "Proceed with $DETECTED_OS installation? (y/n or type 'macos'/'linux'/'wsl' to override): " USER_INPUT
fi
USER_INPUT=$(echo "$USER_INPUT" | tr '[:upper:]' '[:lower:]')

case "$USER_INPUT" in
    n|no)   echo -e "${RED}Installation cancelled.${R}"; exit 0 ;;
    macos)  USER_OS="macOS" ;;
    linux)  USER_OS="Linux" ;;
    wsl)    USER_OS="WSL" ;;
    *)      USER_OS="$DETECTED_OS" ;;
esac

echo -e "\n${MAGENTA}Installing for:${R} ${YELLOW}$USER_OS${R}"
echo "------------------------------------------------------------"

# --- Pick a Python interpreter -------------------------------------------
# Python 3.10 or newer: pytsk3 and libewf-python publish pre-built wheels for
# 3.10+ on every platform, so nothing is compiled. (3.9 is end-of-life and
# would need a C toolchain for both.)
find_python() {
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
                echo -e "${GREEN}Using $PY (Python $PY_VER)${R}"
                return 0
            fi
        fi
    done
    echo -e "${RED}No suitable Python found. TRACE needs Python 3.10 or newer.${R}"
    echo "  macOS:          the installer from https://www.python.org/downloads/macos/"
    echo "                  (or: brew install python@3.12)"
    echo "  Debian/Ubuntu:  sudo apt install python3.12 python3.12-venv"
    echo "                  (older releases: python.org or pyenv)"
    exit 1
}

# --- System dependencies --------------------------------------------------
install_macos_deps() {
    # Nothing to install outside Python: every library comes as a wheel --
    # The Sleuth Kit (pytsk3), libewf, and libmagic (pylibmagic). No
    # Homebrew, no Xcode. Only Python 3.10+ is needed (macOS's own python3
    # is 3.9).
    echo -e "${CYAN}macOS: no system packages needed.${R}"
}

install_linux_deps() {
    echo -e "${CYAN}Installing Linux system dependencies...${R}"
    if ! command -v apt &> /dev/null; then
        echo -e "${YELLOW}This script automates apt-based distributions only.${R}"
        echo "Install the equivalents of these manually, then rerun:"
        echo "  python3 (3.10+) with venv and pip"
        echo "  libmagic (file-type detection)"
        echo "  libxcb-cursor0 libegl1 libxkbcommon-x11-0 libgl1 (Qt runtime)"
        echo "  libpulse (Qt Multimedia) and gssapi/krb5 (Qt Network)"
        if [[ "$ASSUME_YES" -eq 0 ]]; then
            read -p "Continue anyway? (y/n): " cont
            [[ "$cont" =~ ^[Yy]$ ]] || exit 1
        fi
        return
    fi

    # No compiler or -dev packages: pytsk3 and libewf-python come as
    # pre-built wheels with The Sleuth Kit and libewf inside.
    # libmagic1: file-type detection (python-magic loads it at runtime).
    # libxcb-cursor0 and friends: the Qt 6 platform plugins.
    SUDO=""
    [[ "$(id -u)" -ne 0 ]] && SUDO="sudo"
    $SUDO apt-get update
    # libpulse0: Qt Multimedia (the audio/video player) fails to import
    #   without it, which stops the whole window opening.
    # libgssapi-krb5-2: Qt Network.
    # --no-install-recommends: python3-pip otherwise pulls in a C/C++
    #   compiler that nothing here needs.
    $SUDO apt-get install -y --no-install-recommends \
        python3 python3-venv python3-pip \
        libmagic1 \
        libxcb-cursor0 libxcb-xinerama0 libegl1 libxkbcommon-x11-0 libgl1 \
        libglib2.0-0 libfontconfig1 libdbus-1-3 \
        libpulse0 libgssapi-krb5-2
}

install_wsl_deps() {
    echo -e "${CYAN}Installing WSL (Ubuntu) dependencies...${R}"
    install_linux_deps
    echo -e "${YELLOW}Note: WSL needs a working X/Wayland display (WSLg on Windows 11).${R}"
}

# --- Run ------------------------------------------------------------------
case "$USER_OS" in
    macOS) install_macos_deps ;;
    Linux) install_linux_deps ;;
    WSL)   install_wsl_deps ;;
esac

find_python

echo -e "\n${CYAN}Creating virtual environment...${R}"
"$PY" -m venv venv

echo -e "\n${CYAN}Installing Python packages...${R}"
# shellcheck disable=SC1091
source venv/bin/activate
pip install --upgrade pip
# --only-binary for the two forensic engines: if no wheel exists for this
# platform, say so plainly rather than attempt a C build that will fail.
if ! pip install --only-binary=pytsk3,libewf-python -r requirements.txt; then
    deactivate
    echo -e "\n${RED}Dependency installation failed.${R}"
    echo "pytsk3 and libewf-python have pre-built wheels for Python 3.10-3.14"
    echo "on Windows, macOS (Apple Silicon and Intel) and Linux (x86_64 and"
    echo "aarch64). Check that $PY is one of those versions and this machine"
    echo "one of those platforms."
    exit 1
fi
deactivate

echo -e "\n${GREEN}Installation complete.${R}"
echo -e "\nStart TRACE with:"
echo -e "   ${YELLOW}source venv/bin/activate${R}"
echo -e "   ${YELLOW}python main.py${R}\n"
echo "Type 'deactivate' when you are finished."
