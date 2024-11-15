#!/bin/bash

echo "Starting the installation process for TRACE-Forensic-Toolkit on macOS M1..."

# Check for Homebrew installation
if ! command -v brew &> /dev/null
then
    echo "Homebrew is not installed on your system."
    read -p "Do you want to install Homebrew? (y/n): " install_brew

    if [ "$install_brew" == "y" ] || [ "$install_brew" == "Y" ]; then
        echo "Installing Homebrew..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        echo "Homebrew installed successfully."
    else
        echo "Homebrew is required for this installation. Exiting the setup."
        exit 1
    fi
else
    echo "Homebrew is already installed."
fi

# Update Homebrew and install system dependencies
echo "Updating Homebrew..."
brew update

echo "Installing system dependencies (ffmpeg and poppler)..."
brew install ffmpeg poppler libmagic

echo "System dependencies installed successfully."

# Install Python dependencies
echo "Installing Python dependencies from requirements_macos_silicon.txt..."
pip install -r requirements_macos_silicon.txt

echo "Python dependencies installed successfully."

echo ""
echo "Installation completed successfully!"
echo "You can now run your application as needed."
