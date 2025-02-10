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

✅ ***Image Mounting**: Mount forensic disk images. (Windows only) \
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


## Cross-Platform Compatibility 💻🖥️  &nbsp;&nbsp;&nbsp;&nbsp; [⬆️](#toolkit-for-retrieval-and-analysis-of-cyber-evidence-trace)

| Operating System                   | Screenshot                                                                                                           |
|------------------------------------|----------------------------------------------------------------------------------------------------------------------|
| **macOS Sonoma** 🍏                | <a href="Icons/readme/macos.png"><img src="Icons/readme/macos.png" alt="macOS Screenshot" width="900"/></a>          |
| **Kali Linux 2024** 🐧             | <a href="Icons/readme/kali.png"><img src="Icons/readme/kali.png" alt="Kali Linux Screenshot" width="900"/></a>       |
| **\*WSL2 - Ubuntu 22.04.3 LTS** 🐧 | <a href="Icons/readme/wsl3.png"><img src="Icons/readme/wsl3.png" alt="Kali Linux Screenshot" width="900"/></a>        |
| **Windows 10** 🗔                  | <a href="Icons/readme/windows10.png"><img src="Icons/readme/windows10.png" alt="Windows Screenshot" width="900"/></a> |



## Getting Started 🚀 &nbsp;&nbsp;&nbsp;&nbsp; [⬆️](#toolkit-for-retrieval-and-analysis-of-cyber-evidence-trace)

### Prerequisites 🔧


#### For Windows:
*There's a compatibility issue with Python 3.12. Please install Python 3.11 from the official Python website: https://www.python.org/downloads/release/python-3110/
<br>

If you don't already have Microsoft C++ Build Tools installed, you'll need to install them to compile required packages like libewf-python and pytsk3.

```bash
*If you encounter this error while installing dependencies:

"Microsoft Visual C++ 14.0 or greater is required"
It means your C++ Build Tools are missing or outdated.
Please follow the steps below to install the latest version of "C++ Build Tools".
```

Step 1: Download and Install Microsoft C++ Build Tools - https://visualstudio.microsoft.com/visual-cpp-build-tools/
During the installation, make sure to select the following workloads:
  - Desktop development with C++
  - C++ build tools
  
Step 2: Install the Dependencies
```bash
pip install -r requirements.txt
  ```


#### For macOS - Apple Silicon:

Create a virtual environment with python 3.11

```bash
python3.11 -m venv venv
source venv/bin/activate
```

```bash
chmod +x install_macos_silicon.sh
 ```

```bash
./install_macos_silicon.sh
 ```
**This script will:**
- Check if Homebrew is installed and offer to install it if it’s not.
- Install necessary system dependencies (ffmpeg and poppler) using Homebrew.
- Install all Python dependencies specified in requirements_macos_silicon.txt using pip.


#### For Ubuntu on WSL:
```bash
chmod +x WSL_Ubuntu_install.sh
```

```bash
./WSL_Ubuntu_install.sh
```

**This script will:**

- Update package lists and install necessary system packages including graphics libraries and sound management tools.
- Install necessary Python dependencies from requirements_macos_silicon.txt (same requirements for Ubuntu).


### Configuration ⚙️

**API Keys Configuration**:The tool integrates with VirusTotal and Veriphone APIs, and you will need to provide your own API keys to use these features. To update the API keys, go to the Options menu and select API Keys submenu.



### Running the Tool ▶️


```bash
python main.py
```
<br>

## Built With 🧱  &nbsp;&nbsp;&nbsp;&nbsp; [⬆️](#toolkit-for-retrieval-and-analysis-of-cyber-evidence-trace)

- [pytsk3](https://pypi.org/project/pytsk3/) - Python bindings for the SleuthKit
- [libewf-python](https://github.com/libyal/libewf) - Library to access the Expert Witness Compression Format (EWF)
- [PySide6](https://pypi.org/project/PySide6/) - Used for the GUI components.
- [Arsenal Image Mounter](https://arsenalrecon.com/products/image-mounter/) - For mounting forensic disk images.


## Work in Progress 🧑‍🔧  &nbsp;&nbsp;&nbsp;&nbsp; [⬆️](#toolkit-for-retrieval-and-analysis-of-cyber-evidence-trace)

- **Direct Video/Audio Playback**: Currently, the video and audio player saves files temporarily before playing them, which can cause delays. The goal is to enable direct playback for faster performance.
- **Integrated File Search and Viewer**: The file search functionality is not yet connected to the "Viewer Tab," which displays HEX, text, application-specific views, metadata, and other details. This integration needs to be implemented.
- **Cross-Platform Image Mounting**: Image mounting currently works only on Windows using the Arsenal Image Mounter executable. The aim is to make this feature work across all platforms without relying on external executables.
- **File Carving and Viewer Integration**: The file carving functionality is not yet connected to the "Viewer Tab," where users can view HEX, text, application-specific views, and metadata. Additionally, the current file carving process does not distinguish between deleted and non-deleted files; it will "carve" all files of the selected type from the disk image.
- **Color Issues in Dark Mode**: The software currently has some colour display issues on Linux and macOS systems when using dark mode. Certain UI elements may not be clearly visible or may appear incorrectly.

## Testing & Feedback 🧪  &nbsp;&nbsp;&nbsp;&nbsp; [⬆️](#toolkit-for-retrieval-and-analysis-of-cyber-evidence-trace)

- **Tested Formats**: The tool has primarily been tested with `dd` and `E01` files. While these formats are well-supported, additional testing with other formats, such as `Ex01`, `Lx01`, `s01`, and others, is needed.
- **Tested File Systems**: Currently, the tool has only been tested on the NTFS file system. Testing on additional file systems like FAT32, exFAT, HFS+, APFS, EXT4, and others is needed to ensure broader compatibility.
- **Call for Samples**: If you have disk images in formats that are less tested (`Ex01`, `Lx01`, `s01`, etc.), your contributions would be greatly appreciated to help improve the tool's compatibility and robustness.
- **Feedback Welcome**: Please report any issues or unexpected behaviour to help improve the tool. Contributions and testing feedback are encouraged and welcomed.

## Contributing 🤝 &nbsp;&nbsp;&nbsp;&nbsp; [⬆️](#toolkit-for-retrieval-and-analysis-of-cyber-evidence-trace)

I welcome contributions from the community to help improve TRACE! If you're interested in contributing, here’s how you can get involved:

### How to Contribute

1. **Report Issues**: If you find any bugs or have suggestions for improvements, please [open an issue](https://github.com/Gadzhovski/TRACE-Forensic-Toolkit/issues) on GitHub. Provide as much detail as possible to help address the issue effectively.
2. **Submit a Pull Request**: If you have a fix or feature you’d like to contribute, please [fork the repository](https://github.com/Gadzhovski/TRACE-Forensic-Toolkit/fork), make your changes, and submit a pull request. Ensure your code adheres to the coding standards and includes tests where applicable.
3. **Provide Testing Samples**: If you have disk images in formats that are less tested (`Ex01`, `Lx01`, `s01`, etc.), your contributions would be greatly appreciated to help improve the tool’s compatibility and robustness. You can share these samples by [contacting me](https://gadzhovski.com/).
4. **Review and Feedback**: Review the changes submitted by others and provide feedback to help refine and enhance the tool.


## Socials 👨‍💻 &nbsp;&nbsp;&nbsp;&nbsp; [⬆️](#toolkit-for-retrieval-and-analysis-of-cyber-evidence-trace)


[![LinkedIn](https://img.shields.io/badge/LinkedIn-%230077B5.svg?logo=linkedin&logoColor=white)](https://linkedin.com/in/radoslav-gadzhovski)

<br>

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)


