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

clear

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
animate_intro
print_banner

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

read -p "Proceed with $DETECTED_OS installation? (y/n or type 'macos'/'linux'/'wsl' to override): " USER_INPUT
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
# pytsk3 and libewf-python are source distributions, so the version matters:
# they must be able to build (or find a wheel) for whichever Python is used.
find_python() {
    for candidate in python3.12 python3.11 python3.10 python3; do
        if command -v "$candidate" &> /dev/null; then
            PY="$candidate"
            PY_VER=$("$PY" -c 'import sys; print("%d.%d" % sys.version_info[:2])')
            MAJOR=${PY_VER%%.*}
            MINOR=${PY_VER##*.}
            if [[ "$MAJOR" -eq 3 && "$MINOR" -ge 9 ]]; then
                echo -e "${GREEN}Using $PY (Python $PY_VER)${R}"
                return 0
            fi
        fi
    done
    echo -e "${RED}No suitable Python found. TRACE needs Python 3.9 or newer.${R}"
    exit 1
}

# --- System dependencies --------------------------------------------------
install_macos_deps() {
    echo -e "${CYAN}Installing macOS system dependencies...${R}"

    if ! xcode-select -p &> /dev/null; then
        echo -e "${YELLOW}Xcode Command Line Tools are required to build pytsk3.${R}"
        echo "Launching the installer - rerun this script once it finishes."
        xcode-select --install || true
        exit 1
    fi

    if ! command -v brew &> /dev/null; then
        echo -e "${YELLOW}Homebrew not found.${R}"
        read -p "Install Homebrew now? (y/n): " install_brew
        if [[ "$install_brew" =~ ^[Yy]$ ]]; then
            /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        else
            echo -e "${RED}Homebrew is required. Exiting.${R}"
            exit 1
        fi
    fi

    # libmagic: file-type detection in the Metadata tab.
    # libewf/sleuthkit: headers for the libewf-python and pytsk3 builds.
    brew install libmagic libewf sleuthkit
}

install_linux_deps() {
    echo -e "${CYAN}Installing Linux system dependencies...${R}"
    if ! command -v apt &> /dev/null; then
        echo -e "${YELLOW}This script automates apt-based distributions only.${R}"
        echo "Install the equivalents of these manually, then rerun:"
        echo "  python3-venv python3-dev build-essential"
        echo "  libmagic1 libewf-dev libtsk-dev"
        echo "  libxcb-cursor0 libegl1 libxkbcommon-x11-0"
        read -p "Continue anyway? (y/n): " cont
        [[ "$cont" =~ ^[Yy]$ ]] || exit 1
        return
    fi

    sudo apt update
    # build-essential/python3-dev + libewf-dev/libtsk-dev: required to compile
    #   pytsk3 and libewf-python. Without these pip fails on a clean system.
    # libmagic1: the Metadata tab raises ImportError without it.
    # libxcb-cursor0 and friends: Qt6 xcb platform plugin.
    sudo apt install -y \
        python3 python3-venv python3-pip python3-dev build-essential \
        libmagic1 libewf-dev libtsk-dev \
        libxcb-cursor0 libxcb-xinerama0 libegl1 libxkbcommon-x11-0 libgl1
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
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
deactivate

echo -e "\n${GREEN}Installation complete.${R}"
echo -e "\nStart TRACE with:"
echo -e "   ${YELLOW}source venv/bin/activate${R}"
echo -e "   ${YELLOW}python main.py${R}\n"
echo "Type 'deactivate' when you are finished."
