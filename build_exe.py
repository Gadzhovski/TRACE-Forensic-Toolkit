"""
TRACE Forensic Toolkit - Windows Executable Builder
This script builds a standalone Windows .exe file for distribution.

Usage:
    python build_exe.py

Requirements:
    pip install pyinstaller
"""

import os
import sys
import shutil
import subprocess
from pathlib import Path

# Configuration
APP_NAME = "TRACE"
MAIN_SCRIPT = "main.py"
ICON_FILE = "Icons/logo_prev_ui.ico"  # optional; generate from the PNG if wanted
VERSION = "1.2.0"

# Build type: 'onefile' or 'onedir'
BUILD_TYPE = "onedir"  # "onedir" (folder build) or "onefile" (single exe)

def clean_build_folders():
    """Remove previous build artifacts."""
    print("Cleaning previous build artifacts...")
    folders_to_remove = ["build", "dist", "__pycache__"]

    for folder in folders_to_remove:
        if os.path.exists(folder):
            shutil.rmtree(folder)
            print(f"  Removed: {folder}")

    spec_file = f"{APP_NAME}.spec"
    if os.path.exists(spec_file):
        os.remove(spec_file)
        print(f"  Removed: {spec_file}")

    print("Cleanup complete.\n")

def check_pyinstaller():
    """Check if PyInstaller is installed."""
    try:
        import PyInstaller
        print(f"PyInstaller version: {PyInstaller.__version__}")
        return True
    except ImportError:
        print("ERROR: PyInstaller is not installed!")
        print("Please install it with: pip install pyinstaller")
        return False

def build_executable():
    """Build the Windows executable."""
    print(f"\nBuilding {APP_NAME} executable...")
    print(f"Build type: {BUILD_TYPE}\n")

    cmd = [
        "pyinstaller",
        "--name", APP_NAME,
        "--windowed",
        "--clean",
    ]

    if BUILD_TYPE == "onefile":
        cmd.append("--onefile")
    else:
        cmd.append("--onedir")

    # Add icon (only if .ico and exists)
    if ICON_FILE.lower().endswith(".ico") and os.path.exists(ICON_FILE):
        cmd.extend(["--icon", ICON_FILE])
    else:
        print(f"⚠️  Icon not found or not .ico format: {ICON_FILE} — building without icon.\n")

    # Add data folders and specific files
    data_items = [
        ("Icons", "Icons"),
        ("styles", "styles"),
        ("tools/new_database_mappings.db", "tools"),
    ]

    # PyInstaller's --add-data separator is platform-specific: ';' on Windows,
    # ':' everywhere else. Hardcoding ';' meant this script could not produce a
    # macOS or Linux build at all.
    separator = ";" if os.name == "nt" else ":"

    for src, dst in data_items:
        if os.path.exists(src):
            # dst is the destination *directory* inside the bundle. Passing '.'
            # for a directory source flattens its contents into the bundle root,
            # so 'Icons/logo.png' would become 'logo.png' and every lookup would
            # fail.
            cmd.extend(["--add-data", f"{src}{separator}{dst}"])
            print(f"Including data: {src} -> {dst}")
        else:
            print(f"Warning: Data '{src}' not found, skipping.")

    # Hidden imports
    hidden_imports = [
        "PySide6.QtCore",
        "PySide6.QtGui",
        "PySide6.QtWidgets",
        "PySide6.QtMultimedia",
        "PySide6.QtMultimediaWidgets",
        "pytsk3",
        "pyewf",
        "PIL",
        "PIL.Image",
        "requests",
        "Registry",
        "fitz",
        "magic",
        "chardet",
    ]

    for module in hidden_imports:
        cmd.extend(["--hidden-import", module])

    # main.py is a thin launcher; make sure the package next to it is found
    # and fully collected.
    cmd.extend(["--paths", ".", "--collect-submodules", "trace_app"])

    cmd.extend(["--noconfirm", "--log-level", "INFO", MAIN_SCRIPT])

    print("\nRunning PyInstaller with command:")
    print(" ".join(cmd))
    print("\nThis may take several minutes...\n")

    try:
        result = subprocess.run(cmd, check=True)
        return result.returncode == 0
    except subprocess.CalledProcessError as e:
        print(f"\nERROR: Build failed with return code {e.returncode}")
        return False
    except Exception as e:
        print(f"\nERROR: {str(e)}")
        return False

def copy_additional_files():
    """Copy additional files needed for the application."""
    print("\nCopying additional files...")

    dist_folder = os.path.join("dist", APP_NAME)
    files_to_copy = ["README.md", "LICENSE"]

    if BUILD_TYPE == "onedir" and os.path.exists(dist_folder):
        for file in files_to_copy:
            if os.path.exists(file):
                shutil.copy2(file, dist_folder)
                print(f"  Copied: {file}")

def create_readme():
    """Create a README file for the distribution."""
    print("\nCreating distribution README...")

    readme_content = f"""# {APP_NAME} - Forensic Toolkit

Version {VERSION}

TRACE (Toolkit for Retrieval and Analysis of Cyber Evidence) is a digital forensic tool
for analyzing disk images, registry hives, and various evidence types.

System Requirements:
- Windows 10 or later
- 4GB RAM minimum
- 500MB free space

Usage:
1. Run TRACE.exe
2. Open a disk image using File > Open Image
3. Analyze and export results
"""

    dist_folder = "dist"
    if BUILD_TYPE == "onedir":
        dist_folder = os.path.join("dist", APP_NAME)

    readme_path = os.path.join(dist_folder, "README.txt")

    if os.path.exists(dist_folder):
        with open(readme_path, "w", encoding="utf-8") as f:
            f.write(readme_content)
        print(f"  Created: {readme_path}")

def print_success_message():
    print("\n" + "=" * 60)
    print("✅ BUILD SUCCESSFUL!")
    print("=" * 60)

    if BUILD_TYPE == "onefile":
        exe_path = os.path.join("dist", f"{APP_NAME}.exe")
    else:
        exe_path = os.path.join("dist", APP_NAME, f"{APP_NAME}.exe")

    print(f"\nExecutable created at:\n  {exe_path}")
    print("\nDistribute the entire folder to users (if onedir build).")
    print("=" * 60 + "\n")

def main():
    print("=" * 60)
    print(f"{APP_NAME} - Windows Executable Builder")
    print("=" * 60 + "\n")

    if not os.path.exists(MAIN_SCRIPT):
        print(f"ERROR: {MAIN_SCRIPT} not found! Run this from project root.")
        return 1

    if not check_pyinstaller():
        return 1

    clean_build_folders()

    if not build_executable():
        print("\nBuild failed! Check errors above.")
        return 1

    copy_additional_files()
    create_readme()
    print_success_message()
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nBuild interrupted by user.")
        sys.exit(1)
