#!/bin/bash
set -e  # Exit immediately if a command fails

echo "=============================================="
echo " TRACE-Forensic-Toolkit - macOS/Linux/WSL Installer"
echo "=============================================="
echo ""

# Detect OS type
OS_TYPE=$(uname)
if [[ "$OS_TYPE" == "Darwin" ]]; then
    DETECTED_OS="macOS"
elif [[ "$OS_TYPE" == "Linux" ]]; then
    # Detect if running under WSL
    if grep -qi "microsoft" /proc/version; then
        DETECTED_OS="WSL"
    else
        DETECTED_OS="Linux"
    fi
else
    echo "❌ Unsupported OS: $OS_TYPE"
    echo "This installer only supports macOS, Linux, and WSL."
    exit 1
fi

echo "Detected operating system: $DETECTED_OS"
echo ""

# Ask user to confirm or override detected OS
read -p "Proceed with $DETECTED_OS installation? (y/n or type 'macos'/'linux'/'wsl' to override): " USER_INPUT
USER_INPUT=$(echo "$USER_INPUT" | tr '[:upper:]' '[:lower:]')

if [[ "$USER_INPUT" == "n" ]]; then
    echo "Installation cancelled."
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

echo ""
echo "➡ Proceeding with installation for: $USER_OS"
echo "----------------------------------------------"
echo ""

# ------------------------------------------------------------------------------
# macOS INSTALLATION
# ------------------------------------------------------------------------------
if [[ "$USER_OS" == "macOS" ]]; then
    echo "🍏 Installing macOS system dependencies..."

    if ! command -v brew &> /dev/null; then
        echo "Homebrew is not installed."
        read -p "Would you like to install Homebrew now? (y/n): " install_brew
        if [[ "$install_brew" == "y" || "$install_brew" == "Y" ]]; then
            /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
            echo "✅ Homebrew installed successfully."
        else
            echo "❌ Homebrew is required for dependency installation. Exiting."
            exit 1
        fi
    fi

    brew update
    brew install ffmpeg poppler libmagic

    echo ""
    echo "📦 Creating Python virtual environment..."
    python3 -m venv venv
    source venv/bin/activate

    echo ""
    echo "📥 Installing Python packages..."
    pip install --upgrade pip
    pip install -r requirements_macos_silicon.txt

    echo ""
    echo "✅ Installation complete!"
    echo "Your virtual environment is now active."
    echo ""
    echo "To run the tool, simply type:"
    echo "   python main.py"
    echo ""
    echo "When finished, type 'deactivate' to exit the virtual environment."
    exit 0
fi

# ------------------------------------------------------------------------------
# LINUX INSTALLATION
# ------------------------------------------------------------------------------
if [[ "$USER_OS" == "Linux" ]]; then
    echo "🐧 Installing Linux system dependencies..."
    sudo apt update
    sudo apt install -y python3 python3-venv python3-pip libxcb-cursor0 libva-dev libva-drm2 ewf-tools

    echo ""
    echo "📦 Creating Python virtual environment..."
    python3 -m venv venv
    source venv/bin/activate

    echo ""
    echo "📥 Installing Python packages..."
    pip install --upgrade pip
    pip install -r requirements.txt

    echo ""
    echo "✅ Installation complete!"
    echo "Your virtual environment is now active."
    echo ""
    echo "To run the tool, simply type:"
    echo "   python main.py"
    echo ""
    echo "When finished, type 'deactivate' to exit the virtual environment."
    exit 0
fi

# ------------------------------------------------------------------------------
# WSL INSTALLATION
# ------------------------------------------------------------------------------
if [[ "$USER_OS" == "WSL" ]]; then
    echo "🐧 Installing WSL (Ubuntu) dependencies..."
    sudo apt update
    sudo apt install -y git python3-pip python3-venv libgl1-mesa-glx libxkbcommon0 libxkbcommon-x11-0 libegl1 \
                        libxcb-xinerama0 qt5dxcb-plugin qt5-wayland \
                        libqt5dbus5 libqt5widgets5 libqt5network5 libqt5gui5 libqt5core5a libqt5svg5 qtwayland5 \
                        nvidia-cuda-toolkit pulseaudio

    echo ""
    echo "📦 Creating Python virtual environment..."
    python3 -m venv venv
    source venv/bin/activate

    echo ""
    echo "📥 Installing Python packages..."
    pip install --upgrade pip
    pip install -r requirements_macos_silicon.txt  # using same as macOS (includes compatible packages)

    echo ""
    echo "✅ Installation complete!"
    echo "Your virtual environment is now active."
    echo ""
    echo "To run the tool, simply type:"
    echo "   python main.py"
    echo ""
    echo "When finished, type 'deactivate' to exit the virtual environment."
    exit 0
fi
