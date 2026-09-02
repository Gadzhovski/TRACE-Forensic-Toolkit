<h1 align="center">TRACE</h1>

<p align="center">
  <strong>Toolkit for Retrieval and Analysis of Cyber Evidence</strong>
</p>

<p align="center">
  A cross-platform desktop tool for examining forensic disk images — browse the
  file system of an acquired image, inspect file contents and metadata, recover
  deleted files from unallocated space, and read Windows registry hives, without
  mounting or altering the evidence.
</p>

<p align="center">
  <img src="Icons/logo_prev_ui.png" alt="TRACE" width="360"/>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-1.2.0-blue.svg" alt="Version"/>
  <img src="https://img.shields.io/badge/python-3.9%2B-blue.svg" alt="Python"/>
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License"/>
</p>

---

## Contents

- [Overview](#overview)
- [Features](#features)
- [Screenshots](#screenshots)
- [Supported formats](#supported-formats)
- [Installation](#installation)
- [Configuration](#configuration)
- [How it works](#how-it-works)
- [Limitations](#limitations)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

TRACE reads disk images directly through [The Sleuth Kit](https://www.sleuthkit.org/)
(via `pytsk3`) and [libewf](https://github.com/libyal/libewf). Evidence is opened
read-only and is never mounted, so the image is not modified and no write-blocker
configuration is required.

It began as a final-year project and is intended for learning, lab work, and
triage rather than as a replacement for a commercial forensic suite. See
[Limitations](#limitations) before relying on it for casework.

<p align="center">
  <img src="Icons/readme/Preview_Dark.png" alt="TRACE main window" width="100%"/>
</p>

---

## Features

**File system browsing**
Navigate partitions and directories in a tree view with a detailed listing pane
showing inode, size, and the MAC timestamps (modified, accessed, created,
changed). Includes back/forward/up navigation and wildcard search (`*.pdf`)
across the image.

**Content viewers**
Selected files can be examined through six tabs:

| Tab | Purpose |
|---|---|
| Hex | Paginated hex and ASCII view with search and an address bar |
| Text | Text extraction with automatic encoding detection; decodes Base64, hex, URL, HTML, octal and binary from a selection |
| Application | Renders images, PDFs, audio and video. Large media streams directly from the image rather than being loaded into memory |
| File Metadata | Timestamps, size, MD5 and SHA-256, MIME type, and low-level filesystem detail (MFT entry, attributes, resident/non-resident sizes) |
| Exif Data | EXIF metadata from photographs |
| VirusTotal | Hash lookup and file submission via the VirusTotal API |

**File carving**
Recovers deleted files from unallocated space by signature: PDF, JPG, PNG, GIF,
BMP, WAV, MOV, WMV and ZIP. An allocation map built from the file system is used
to skip space occupied by existing files, so carving covers only genuinely
unallocated regions. Results are shown as a list or a thumbnail gallery.

**Registry viewer**
Extracts and browses Windows registry hives from the image, showing the key tree
alongside value names, types and data.

**Image verification**
Recomputes MD5 and SHA-1 for an E01 image and compares them against the hashes
stored in the EWF metadata, reporting whether the acquisition still verifies.

**Export**
Files and whole directory trees can be exported out of the image to a chosen
destination, with progress reporting and cancellation.

---

## Screenshots

<table>
  <tr>
    <td width="50%"><img src="Icons/readme/registry.png" alt="Registry viewer"/><br/><sub><b>Registry viewer</b> — browsing a hive extracted from the image</sub></td>
    <td width="50%"><img src="Icons/readme/carving.png" alt="File carving"/><br/><sub><b>File carving</b> — recovered files as a thumbnail gallery</sub></td>
  </tr>
  <tr>
    <td><img src="Icons/readme/file_search.png" alt="File search"/><br/><sub><b>Search</b> — wildcard search across the image</sub></td>
    <td><img src="Icons/readme/trace_verify.png" alt="Image verification"/><br/><sub><b>Verification</b> — stored vs. recomputed hashes</sub></td>
  </tr>
</table>

---

## Supported formats

### Image formats

| Format | Extensions | Notes |
|---|---|---|
| EnCase / Expert Witness | `.E01`, `.Ex01`, `.s01`, `.L01` | Split segments supported |
| Raw / dd | `.dd`, `.raw`, `.img`, `.001` | |
| ISO | `.iso` | |
| Apple Disk Image | `.dmg`, `.sparse`, `.sparseimage` | Read as raw |
| AccessData | `.ad1` | Read as raw |

### File systems

File system support comes from The Sleuth Kit, which handles NTFS, FAT12/16/32,
exFAT, Ext2/3/4, HFS+, APFS, UFS, ISO 9660 and YAFFS2.

**NTFS is the only file system this project has been tested against.** Others
should work through TSK but have not been verified here — see
[Limitations](#limitations).

---

## Installation

TRACE requires **Python 3.9 or newer**. The install scripts handle the system
libraries, the virtual environment and the Python packages.

`pytsk3` and `libewf-python` are distributed as source and are compiled during
installation, so a C/C++ toolchain is needed unless a prebuilt wheel is available
for your platform. The scripts check for this and tell you what is missing.

### Windows

```powershell
git clone https://github.com/Gadzhovski/TRACE-Forensic-Toolkit.git
cd TRACE-Forensic-Toolkit
powershell -ExecutionPolicy Bypass -File install_windows.ps1
```

If the installer reports that the Microsoft C++ Build Tools are missing, install
them from [visualstudio.microsoft.com](https://visualstudio.microsoft.com/visual-cpp-build-tools/),
selecting **Desktop development with C++**, then run the script again.

Then:

```powershell
venv\Scripts\activate
python main.py
```

### macOS, Linux and WSL

```bash
git clone https://github.com/Gadzhovski/TRACE-Forensic-Toolkit.git
cd TRACE-Forensic-Toolkit
chmod +x install.sh
./install.sh
```

The script detects the platform and installs the required system packages —
Xcode Command Line Tools and Homebrew packages on macOS, or `build-essential`,
`libewf-dev`, `libtsk-dev`, `libmagic1` and the Qt runtime libraries on
Debian-based Linux.

Then:

```bash
source venv/bin/activate
python main.py
```

Run `deactivate` when finished.

### Manual installation

With a virtual environment already active:

```bash
pip install -r requirements.txt
```

A single `requirements.txt` covers all platforms; Windows-only packages carry
environment markers.

---

## Configuration

**VirusTotal API key.** Set it under **Options → API Keys**. Without a key, the
VirusTotal tab reports that one is required and the rest of the application is
unaffected.

Settings and application data are stored outside the source tree:

| | Configuration | Data (carved files, log) |
|---|---|---|
| Windows | `%APPDATA%\TRACE` | `%LOCALAPPDATA%\TRACE` |
| macOS | `~/Library/Application Support/TRACE` | `~/Library/Application Support/TRACE` |
| Linux | `$XDG_CONFIG_HOME/TRACE` | `$XDG_DATA_HOME/TRACE` |

Diagnostics are written to `trace.log` in the data directory.

---

## How it works

| Layer | Module | Responsibility |
|---|---|---|
| Image access | `modules/image_handler.py` | Opens EWF and raw images, enumerates partitions, walks file systems, reads file content, builds the allocation map |
| Viewers | `modules/viewer_registry.py` | Adapts each viewer tab to a common `display` / `clear` interface |
| Carving | `modules/file_carving.py` | Signature scanning of unallocated space, thumbnail generation |
| Background work | `modules/workers.py` | Export and file-read threads |
| Paths | `modules/paths.py` | Resolves bundled resources and per-user data directories |

Large media files are streamed to the player through a custom `QIODevice` that
reads on demand from the image, so playback does not require loading the whole
file into memory.

Built with [PySide6](https://pypi.org/project/PySide6/),
[pytsk3](https://pypi.org/project/pytsk3/),
[libewf-python](https://github.com/libyal/libewf),
[python-registry](https://github.com/williballenthin/python-registry) and
[PyMuPDF](https://pymupdf.readthedocs.io/).

---

## Limitations

Worth knowing before you rely on it:

- **Only NTFS has been tested.** Other file systems are supported by The Sleuth
  Kit and should work, but have not been verified in this project.
- **Only E01 and raw/dd images have been tested.** The other listed formats are
  accepted and handled by the underlying libraries, not independently verified.
- **Carving produces false positives.** Signature-based recovery cannot always
  determine where a file ends, so carved output may include fragments that are
  not complete files. Verify anything recovered this way.
- **No image mounting or acquisition.** TRACE reads existing images; it does not
  create them and does not mount them as drives.
- **Not validated for evidentiary use.** This is a learning and triage tool. It
  has not been through the validation a court-admissible workflow requires.

---

## Contributing

Bug reports and pull requests are welcome.

- **Issues** — [open an issue](https://github.com/Gadzhovski/TRACE-Forensic-Toolkit/issues)
  describing what you did, what happened, and what you expected. Include your OS,
  Python version, the image format involved, and the relevant part of `trace.log`.
- **Pull requests** — keep changes focused, match the surrounding style, and
  describe how you verified the change. Testing against a file system other than
  NTFS is especially useful.

---

## License

Released under the [MIT License](LICENSE).

Developed by [Radoslav Gadzhovski](https://linkedin.com/in/radoslav-gadzhovski).
