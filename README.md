<h1 align="center">Toolkit for Retrieval and Analysis of Cyber Evidence (TRACE)</h1>

<p align="center">
  TRACE is a digital forensic tool I developed as my final year project. It provides an intuitive interface for analyzing disk images and includes a range of functionalities to assist forensic examiners in extracting and viewing the contents of various image file formats.
</p>

<p align="center">
  <img src="Icons/logo_prev_ui.png" alt="TRACE Logo" width="400"/>
</p>

## Navigation 🧭 

- [Preview 👀](#preview-)
- [Features 🌟](#features-)
- [Screenshots 📸](#screenshots-)
- [Supported Image Formats 💾](#supported-image-formats-)
- [Tested File Systems 🗂️](#tested-file-systems-%EF%B8%8F)
- [Cross-Platform Compatibility 🖥️💻](#cross-platform-compatibility-%EF%B8%8F)
- [Getting Started 🚀](#getting-started-)
  - [Prerequisites 🛠️](#prerequisites-)
  - [Configuration ⚙️](#configuration-%EF%B8%8F)
  - [Running the Tool ▶️](#running-the-tool-%EF%B8%8F)
- [Built With 🧱](#built-with-)
- [Work in Progress 🛠️](#work-in-progress-)
- [Testing & Feedback 🧪](#testing--feedback-)
- [Contributing 🤝](#contributing-)
- [Socials 👨‍💻](#socials-)


## Preview 👀 &nbsp;&nbsp;&nbsp;&nbsp; [⬆️](#toolkit-for-retrieval-and-analysis-of-cyber-evidence-trace)

<p>
  <br/>
  <img src="Icons/readme/Preview_Dark.png" alt="TRACE Preview" width="100%"/>
  <br/>
</p>

<br>

## Features 🌟 &nbsp;&nbsp;&nbsp;&nbsp; [⬆️](#toolkit-for-retrieval-and-analysis-of-cyber-evidence-trace)

✅ **Tree Viewer**: Navigate through the disk image structure, including partitions and files.\
✅ **Detailed File Analysis**: View file content in different formats, such as HEX, text, and application-specific views.\
✅ **EXIF Data Extraction**: Extract and display EXIF metadata from photos.\
✅ **Registry Viewer**: View and examine Windows registry files.\
✅ **Basic File Carving**: Recover deleted files from disk images.\
✅ **Virus Total API Integration**: Check files for malware using the Virus Total API.\
✅ **E01 Image Verification**: Verify the integrity of E01 disk images.\
✅ **Convert E01 to Raw**: Convert E01 disk images to raw format.\
✅ **Message Decoding**: Decode messages from base64, binary, and other encodings.

<br>

## Screenshots 📸 &nbsp;&nbsp;&nbsp;&nbsp; [⬆️](#toolkit-for-retrieval-and-analysis-of-cyber-evidence-trace)

### Registry Browser 🗂️

<p>
  <br/>
  <img src="Icons/readme/registry.png" alt="Registry Browser" width="90%"/>
  <br/>
</p>


### File Carving 🔪

<p>
  <br/>
  <img src="Icons/readme/carving.png" alt="File Carving" width="90%"/>
  <br/>
</p>

### File Search 🔍
<p>
  <br/>
  <img src="Icons/readme/file_search.png" alt="Image Verification" width="80%"/>
  <br/>
</p>

### Image Verification ✅

<p>
  <br/>
  <img src="Icons/readme/trace_verify.png" alt="Image Verification" width="70%"/>
  <br/>
</p>

<br>



## Supported Image Formats 💾 &nbsp;&nbsp;&nbsp;&nbsp; [⬆️](#toolkit-for-retrieval-and-analysis-of-cyber-evidence-trace)

| Image Format                                   | Extensions             | Split   |  Unsplit |
|------------------------------------------------|------------------------|---------|----------|
| EnCase® Image File (EVF / Expert Witness Format)| `*.E01` `*.Ex01`       | ✔️      | ✔️       |
| SMART/Expert Witness Image File                | `*.s01`                | ✔️      | ✔️       |
| Single Image Unix / Linux DD / Raw             | `*.dd`, `*.img`, `*.raw` | ✔️      | ✔️       |
| ISO Image File                                 | `*.iso`                |         | ✔️       |
| AccessData Image File                          | `*.ad1`                | ✔️       | ✔️        |

<br>

## Tested File Systems 🗂️ &nbsp;&nbsp;&nbsp;&nbsp; [⬆️](#toolkit-for-retrieval-and-analysis-of-cyber-evidence-trace)

| File System | Tested |
|-------------|--------|
| NTFS        | ✔️     |
| FAT32       |        |
| exFAT       |        |
| HFS+        |        |
| APFS        |        |
| EXT2,3,4    |        |

<br>


## Cross-Platform Compatibility 🍏🐧🗔  &nbsp;&nbsp;&nbsp;&nbsp; [⬆️](#toolkit-for-retrieval-and-analysis-of-cyber-evidence-trace)

| Operating System                   | Screenshot                                                                                                           |
|------------------------------------|----------------------------------------------------------------------------------------------------------------------|
| **macOS Sonoma** 🍏                | <a href="Icons/readme/macos.png"><img src="Icons/readme/macos.png" alt="macOS Screenshot" width="900"/></a>          |
| **Kali Linux 2024** 🐧             | <a href="Icons/readme/kali.png"><img src="Icons/readme/kali.png" alt="Kali Linux Screenshot" width="900"/></a>       |
| **\*WSL2 - Ubuntu 22.04.3 LTS** 🐧 | <a href="Icons/readme/wsl3.png"><img src="Icons/readme/wsl3.png" alt="Kali Linux Screenshot" width="900"/></a>        |
| **Windows 10** 🗔                  | <a href="Icons/readme/windows10.png"><img src="Icons/readme/windows10.png" alt="Windows Screenshot" width="900"/></a> |



## Getting Started 🚀 &nbsp;&nbsp;&nbsp;&nbsp; [⬆️](#toolkit-for-retrieval-and-analysis-of-cyber-evidence-trace)

### Installation ⚙️

TRACE needs **Python 3.9 or newer**. The installer scripts handle the system
libraries, the virtual environment and the Python packages for you.

#### **Windows:**

1.  Install Python from [python.org](https://www.python.org/downloads/), ticking
    **"Add python.exe to PATH"** during setup.

2.  Run the installer from PowerShell in the project folder:

    ```powershell
    powershell -ExecutionPolicy Bypass -File install_windows.ps1
    ```

    It checks your Python version, warns if the
    [Microsoft C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/)
    are missing (`pytsk3` and `libewf-python` are compiled from source and need
    them), creates the virtual environment, and installs everything.

3.  Start the tool:

    ```powershell
    venv\Scriptsctivate
    python main.py
    ```

#### **macOS & Linux (including WSL):**

1.  Make the installer executable and run it:

    ```bash
    chmod +x install.sh
    ./install.sh
    ```

    It detects your platform and installs the system dependencies
    (`libmagic`, plus the `libewf`/`sleuthkit` headers and a compiler needed to
    build `pytsk3`), creates the virtual environment, and installs the Python
    packages.

2.  Start the tool:

    ```bash
    source venv/bin/activate
    python main.py
    ```

Type `deactivate` when you are finished.


### Configuration ⚙️ 

**API Keys Configuration**: The tool integrates with the VirusTotal API, and you will need to provide your own API key to use that feature. To set the key, go to the Options menu and select the API Keys submenu.




## Built With 🧱  &nbsp;&nbsp;&nbsp;&nbsp; [⬆️](#toolkit-for-retrieval-and-analysis-of-cyber-evidence-trace)

- [pytsk3](https://pypi.org/project/pytsk3/) - Python bindings for the SleuthKit
- [libewf-python](https://github.com/libyal/libewf) - Library to access the Expert Witness Compression Format (EWF)
- [PySide6](https://pypi.org/project/PySide6/) - Used for the GUI components.


## Work in Progress 🧑‍🔧  &nbsp;&nbsp;&nbsp;&nbsp; [⬆️](#toolkit-for-retrieval-and-analysis-of-cyber-evidence-trace)

- **File Carving**: The verification of carved files needs improvement, as it may carve data fragments that are not actual files.
- **Color Issues in Dark Mode**: The software currently has some colour display issues on Linux and macOS systems when using dark mode. Certain UI elements may not be clearly visible or may appear incorrectly.


## Contributing 🤝 &nbsp;&nbsp;&nbsp;&nbsp; [⬆️](#toolkit-for-retrieval-and-analysis-of-cyber-evidence-trace)

I welcome contributions from the community to help improve TRACE! If you're interested in contributing, here’s how you can get involved:


1. **Report Issues**: If you find any bugs or have suggestions for improvements, please [open an issue](https://github.com/Gadzhovski/TRACE-Forensic-Toolkit/issues) on GitHub. Provide as much detail as possible to help address the issue effectively.
2. **Submit a Pull Request**: If you have a fix or feature you’d like to contribute, please [fork the repository](https://github.com/Gadzhovski/TRACE-Forensic-Toolkit/fork), make your changes, and submit a pull request. Ensure your code adheres to the coding standards and includes tests where applicable.


## Socials 👨‍💻 &nbsp;&nbsp;&nbsp;&nbsp; [⬆️](#toolkit-for-retrieval-and-analysis-of-cyber-evidence-trace)


[![LinkedIn](https://img.shields.io/badge/LinkedIn-%230077B5.svg?logo=linkedin&logoColor=white)](https://linkedin.com/in/radoslav-gadzhovski)

<br>

![Version](https://img.shields.io/badge/version-1.2.0-purple.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)


