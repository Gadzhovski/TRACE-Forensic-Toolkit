#!/bin/bash

# Update package lists
sudo apt update

# Install necessary packages
sudo apt install -y git python3-pip libgl1-mesa-glx libxkbcommon0 libxkbcommon-x11-0 libegl1 \
                    libxcb-xinerama0 qt5dxcb-plugin qt5-wayland \
                    libqt5dbus5 libqt5widgets5 libqt5network5 libqt5gui5 libqt5core5a libqt5dbus5 libqt5svg5 qtwayland5 \
                    nvidia-cuda-toolkit pulseaudio


# Install Python dependencies
pip install -r requirements_macos_silicon.txt  # Same as for macos


