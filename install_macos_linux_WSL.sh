#!/bin/bash
set -e

# === COLORS ===
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
    if grep -qi "microsoft" /proc/version; then
        DETECTED_OS="WSL"
    else
        DETECTED_OS="Linux"
    fi
else
    echo -e "${RED}❌ Unsupported OS: $OS_TYPE${R}"
    echo "This installer supports macOS, Linux, and WSL only."
    exit 1
fi

echo -e "${CYAN}Detected operating system:${R} ${YELLOW}$DETECTED_OS${R}\n"

# === Confirm OS or override ===
read -p "Proceed with $DETECTED_OS installation? (y/n or type 'macos'/'linux'/'wsl' to override): " USER_INPUT
USER_INPUT=$(echo "$USER_INPUT" | tr '[:upper:]' '[:lower:]')

if [[ "$USER_INPUT" == "n" ]]; then
    echo -e "${RED}Installation cancelled.${R}"
    exit 0
elif [[ "$USER_INPUT" == "macos" ]]; then
    USER_OS="macOS"
elif [[ "$USER_INPUT" == "linux" ]]; then
    USER_OS="Linux"
elif [[ "$USER_INPUT" == "wsl" ]]; then
    USER_OS="WSL"
else
    USER_OS="$DETECTED_OS"
fi

echo -e "\n${MAGENTA}➡ Proceeding with installation for:${R} ${YELLOW}$USER_OS${R}"
echo "------------------------------------------------------------"
echo ""

# ------------------------------------------------------------------------------
# macOS INSTALLATION
# ------------------------------------------------------------------------------
if [[ "$USER_OS" == "macOS" ]]; then
    echo -e "${CYAN}🍏 Installing macOS system dependencies...${R}"

    if ! command -v brew &> /dev/null; then
        echo -e "${YELLOW}Homebrew not found.${R}"
        read -p "Would you like to install Homebrew now? (y/n): " install_brew
        if [[ "$install_brew" == "y" || "$install_brew" == "Y" ]]; then
            /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
            echo -e "${GREEN}✅ Homebrew installed successfully.${R}"
        else
            echo -e "${RED}❌ Homebrew is required. Exiting.${R}"
            exit 1
        fi
    fi

    brew update
    brew install ffmpeg poppler libmagic

    echo -e "\n${CYAN}📦 Creating Python virtual environment...${R}"
    python3 -m venv venv

    echo -e "\n${CYAN}📥 Installing Python packages...${R}"
    source venv/bin/activate
    pip install --upgrade pip setuptools wheel
    pip install --no-cache-dir -r requirements_macos_silicon.txt
    deactivate

    echo -e "\n${GREEN}✅ Installation complete!${R}"
    echo -e "\nTo use ${MAGENTA}TRACE${R}, activate the environment first:"
    echo -e "   ${YELLOW}source venv/bin/activate${R}"
    echo -e "Then start the tool with:"
    echo -e "   ${YELLOW}python main.py${R}\n"
    echo "When finished, type 'deactivate'."
    exit 0
fi

# ------------------------------------------------------------------------------
# LINUX INSTALLATION
# ------------------------------------------------------------------------------
if [[ "$USER_OS" == "Linux" ]]; then
    echo -e "${CYAN}🐧 Installing Linux system dependencies...${R}"
    sudo apt update
    sudo apt install -y python3 python3-venv python3-pip libxcb-cursor0 libva-dev libva-drm2 ewf-tools

    echo -e "\n${CYAN}📦 Creating Python virtual environment...${R}"
    python3 -m venv venv

    echo -e "\n${CYAN}📥 Installing Python packages...${R}"
    source venv/bin/activate
    pip install --upgrade pip setuptools wheel
    pip install --no-cache-dir -r requirements_macos_silicon.txt
    deactivate

    echo -e "\n${GREEN}✅ Installation complete!${R}"
    echo -e "\nTo use ${MAGENTA}TRACE${R}, activate the environment first:"
    echo -e "   ${YELLOW}source venv/bin/activate${R}"
    echo -e "Then start the tool with:"
    echo -e "   ${YELLOW}python main.py${R}\n"
    echo "When finished, type 'deactivate'."
    exit 0
fi

# ------------------------------------------------------------------------------
# WSL INSTALLATION
# ------------------------------------------------------------------------------
if [[ "$USER_OS" == "WSL" ]]; then
    echo -e "${CYAN}🐧 Installing WSL (Ubuntu) dependencies...${R}"
    sudo apt update
    sudo apt install -y git python3-pip python3-venv libgl1-mesa-glx libxkbcommon0 libxkbcommon-x11-0 libegl1 \
                        libxcb-xinerama0 qt5dxcb-plugin qt5-wayland \
                        libqt5dbus5 libqt5widgets5 libqt5network5 libqt5gui5 libqt5core5a libqt5svg5 qtwayland5 \
                        nvidia-cuda-toolkit pulseaudio

    echo -e "\n${CYAN}📦 Creating Python virtual environment...${R}"
    python3 -m venv venv

    echo -e "\n${CYAN}📥 Installing Python packages...${R}"
    source venv/bin/activate
    pip install --upgrade pip setuptools wheel
    pip install --no-cache-dir -r requirements_macos_silicon.txt
    deactivate

    echo -e "\n${GREEN}✅ Installation complete!${R}"
    echo -e "\nTo use ${MAGENTA}TRACE${R}, activate the environment first:"
    echo -e "   ${YELLOW}source venv/bin/activate${R}"
    echo -e "Then start the tool with:"
    echo -e "   ${YELLOW}python main.py${R}\n"
    echo "When finished, type 'deactivate'."
    exit 0
fi