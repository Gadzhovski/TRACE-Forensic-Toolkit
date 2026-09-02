<div align="center">

<img src="Icons/logo_prev_ui.png" alt="TRACE" width="300"/>

# TRACE

**Toolkit for Retrieval and Analysis of Cyber Evidence**

Browse the file system of a forensic disk image, inspect file contents and metadata,<br/>
recover deleted files, and read Windows registry hives — read-only, without mounting.

<p>
  <img src="https://img.shields.io/badge/version-2.0.0-4c8eda?style=flat-square" alt="Version"/>
  <img src="https://img.shields.io/badge/python-3.9%2B-4c8eda?style=flat-square&logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/Qt-PySide6-41cd52?style=flat-square&logo=qt&logoColor=white" alt="PySide6"/>
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-6e7781?style=flat-square" alt="Platforms"/>
  <img src="https://img.shields.io/badge/license-MIT-3fb950?style=flat-square" alt="License"/>
</p>

<a href="#installation"><b>Install</b></a> ·
<a href="#features"><b>Features</b></a> ·
<a href="#screenshots"><b>Screenshots</b></a> ·
<a href="#supported-formats"><b>Formats</b></a> ·
<a href="#configuration"><b>Configuration</b></a>

<br/>

<img src="Icons/readme/Preview_Dark.png" alt="TRACE main window" width="100%"/>

</div>

<br/>

## Overview

TRACE reads disk images directly through [The Sleuth Kit](https://www.sleuthkit.org/)
(via `pytsk3`) and [libewf](https://github.com/libyal/libewf). Evidence is opened
read-only and is never mounted, so the image is not modified and no write-blocker
configuration is required.

It began as a final-year project and is intended for learning, lab work, and
triage rather than as a replacement for a commercial forensic suite.

> [!NOTE]
> Only **NTFS** and **E01 / raw** images have been tested. Other file systems and
> formats are handled by the underlying libraries but are not independently
> verified here. Carving is signature-based and can recover fragments that are
> not complete files, so verify anything it produces.

<br/>

## Features

<table>
<tr>
<td width="50%" valign="top">

### 🗂 File system browsing

Tree view of partitions and directories with a listing pane showing inode, size
and the full MAC timestamps. Back / forward / up navigation and wildcard search
(`*.pdf`) across the whole image.

</td>
<td width="50%" valign="top">

### 🔍 File carving

Recovers deleted files from unallocated space by signature — PDF, JPG, PNG, GIF,
BMP, WAV, MOV, WMV, ZIP. An allocation map skips space already occupied by live
files. Shown as a list or thumbnail gallery.

</td>
</tr>
<tr>
<td width="50%" valign="top">

### 🪟 Registry viewer

Extracts Windows registry hives straight from the image and browses the key tree
with value names, types and data.

</td>
<td width="50%" valign="top">

### ✅ Image verification

Recomputes MD5 and SHA-1 for an E01 and compares them with the hashes stored in
the EWF metadata, reporting whether the acquisition still verifies.

</td>
</tr>
<tr>
<td width="50%" valign="top">

### 📤 Export

Files and entire directory trees can be extracted from the image to disk, with
progress reporting and cancellation.

</td>
<td width="50%" valign="top">

### 🦠 VirusTotal

Look up a file's hash or submit the file itself through the VirusTotal API,
with the per-minute and daily request limits enforced client-side.

</td>
</tr>
</table>

### Content viewers

Any selected file can be examined through six tabs:

| Tab | What it shows |
|:--|:--|
| **Hex** | Paginated hex and ASCII view with search and an address bar |
| **Text** | Text extraction with encoding detection; decodes Base64, hex, URL, HTML, octal and binary from a selection |
| **Application** | Renders images, PDFs, audio and video — large media streams from the image instead of loading into memory |
| **File Metadata** | Timestamps, size, MD5 / SHA-256, MIME type, and low-level detail (MFT entry, attributes, resident vs. non-resident sizes) |
| **Exif Data** | EXIF metadata from photographs |
| **VirusTotal** | Detection results for the selected file |

<br/>

## Screenshots

<table>
<tr>
<td width="50%"><img src="Icons/readme/registry.png" alt="Registry viewer"/></td>
<td width="50%"><img src="Icons/readme/carving.png" alt="File carving"/></td>
</tr>
<tr>
<td align="center"><sub><b>Registry viewer</b> — browsing a hive extracted from the image</sub></td>
<td align="center"><sub><b>File carving</b> — recovered files as a thumbnail gallery</sub></td>
</tr>
<tr>
<td><img src="Icons/readme/file_search.png" alt="File search"/></td>
<td><img src="Icons/readme/trace_verify.png" alt="Image verification"/></td>
</tr>
<tr>
<td align="center"><sub><b>Search</b> — wildcard search across the image</sub></td>
<td align="center"><sub><b>Verification</b> — stored vs. recomputed hashes</sub></td>
</tr>
</table>

<details>
<summary><b>Light theme</b></summary>
<br/>
<img src="Icons/readme/Preview_Light.png" alt="TRACE in light theme" width="100%"/>
</details>

<details>
<summary><b>Running on macOS, Linux and WSL</b></summary>
<br/>

| macOS | Kali Linux |
|:--:|:--:|
| <img src="Icons/readme/macos.png" alt="TRACE on macOS"/> | <img src="Icons/readme/kali.png" alt="TRACE on Kali Linux"/> |

| Windows | WSL2 (Ubuntu) |
|:--:|:--:|
| <img src="Icons/readme/windows10.png" alt="TRACE on Windows"/> | <img src="Icons/readme/wsl3.png" alt="TRACE on WSL2"/> |

</details>

<br/>

## Supported formats

<table>
<tr><th align="left">Format</th><th align="left">Extensions</th><th align="left">Notes</th></tr>
<tr><td>EnCase / Expert Witness</td><td><code>.E01</code> <code>.Ex01</code> <code>.s01</code> <code>.L01</code></td><td>Split segments supported</td></tr>
<tr><td>Raw / dd</td><td><code>.dd</code> <code>.raw</code> <code>.img</code> <code>.001</code></td><td></td></tr>
<tr><td>ISO</td><td><code>.iso</code></td><td></td></tr>
<tr><td>Apple Disk Image</td><td><code>.dmg</code> <code>.sparse</code> <code>.sparseimage</code></td><td>Read as raw</td></tr>
<tr><td>AccessData</td><td><code>.ad1</code></td><td>Read as raw</td></tr>
</table>

File system support comes from The Sleuth Kit — NTFS, FAT12/16/32, exFAT,
Ext2/3/4, HFS+, APFS, UFS, ISO 9660 and YAFFS2. Only NTFS has been tested here.

<br/>

## Installation

Requires **Python 3.9 or newer**. The install scripts handle the system
libraries, the virtual environment and the Python packages.

`pytsk3` and `libewf-python` are distributed as source and compile during
installation, so a C/C++ toolchain is needed unless a prebuilt wheel exists for
your platform. The scripts check for this and tell you what is missing.

<details open>
<summary><b>Windows</b></summary>
<br/>

```powershell
git clone https://github.com/Gadzhovski/TRACE-Forensic-Toolkit.git
cd TRACE-Forensic-Toolkit
powershell -ExecutionPolicy Bypass -File install_windows.ps1
```

If the installer reports that the Microsoft C++ Build Tools are missing, install
them from [visualstudio.microsoft.com](https://visualstudio.microsoft.com/visual-cpp-build-tools/)
— select **Desktop development with C++** — then run the script again.

```powershell
venv\Scripts\activate
python main.py
```

</details>

<details open>
<summary><b>macOS, Linux and WSL</b></summary>
<br/>

```bash
git clone https://github.com/Gadzhovski/TRACE-Forensic-Toolkit.git
cd TRACE-Forensic-Toolkit
chmod +x install.sh
./install.sh
```

The script detects the platform and installs what it needs — Xcode Command Line
Tools and Homebrew packages on macOS, or `build-essential`, `libewf-dev`,
`libtsk-dev`, `libmagic1` and the Qt runtime libraries on Debian-based Linux.

```bash
source venv/bin/activate
python main.py
```

</details>

<details>
<summary><b>Manual installation</b></summary>
<br/>

With a virtual environment already active:

```bash
pip install -r requirements.txt
```

A single `requirements.txt` covers every platform; Windows-only packages carry
environment markers.

</details>

Run `deactivate` when you are finished.

<br/>

## Configuration

**VirusTotal API key** — set it under **Options → API Keys**. Without a key that
tab reports one is required; nothing else is affected.

Settings and application data live outside the source tree:

| | Configuration | Data (carved files, log) |
|:--|:--|:--|
| **Windows** | `%APPDATA%\TRACE` | `%LOCALAPPDATA%\TRACE` |
| **macOS** | `~/Library/Application Support/TRACE` | `~/Library/Application Support/TRACE` |
| **Linux** | `$XDG_CONFIG_HOME/TRACE` | `$XDG_DATA_HOME/TRACE` |

Diagnostics are written to `trace.log` in the data directory — include it when
reporting a bug.

<br/>

## Built with

[PySide6](https://pypi.org/project/PySide6/) ·
[pytsk3](https://pypi.org/project/pytsk3/) ·
[libewf-python](https://github.com/libyal/libewf) ·
[python-registry](https://github.com/williballenthin/python-registry) ·
[PyMuPDF](https://pymupdf.readthedocs.io/) ·
[Pillow](https://python-pillow.org/)

<br/>

---

<div align="center">

Released under the [MIT License](LICENSE)

Developed by [**Radoslav Gadzhovski**](https://linkedin.com/in/radoslav-gadzhovski)

</div>
