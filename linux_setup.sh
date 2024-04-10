#!/bin/bash


#Might need to run this script if requirements.txt does not install all dependencies


# Update package lists
sudo apt update

# Install pip3 (if not already installed)
sudo apt install python3-pip

# Install Python packages from requirements.txt
sudo pip3 install -r requirements.txt

# Install additional system dependencies
sudo apt install libxcb-cursor0
sudo apt-get install libva-dev libva-drm2

# Install individual Python packages
pip3 install PySide6
pip3 install Registry
pip3 install python-registry
pip3 install libewf-python
pip3 install pytsk3
pip3 install moviepy
pip3 install pdf2image
pip3 install PyMuPDF
pip3 install PyMuPDF2
pip3 install PyPDF2
pip3 install pypdf
