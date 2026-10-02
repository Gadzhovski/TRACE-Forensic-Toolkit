<div align="center">

<img src="Icons/logo_prev_ui.png" alt="TRACE" width="300"/>

# TRACE

**Toolkit for Retrieval and Analysis of Cyber Evidence**

Open forensic disk images read-only, organise an investigation into a case,<br/>
triage what stands out, search inside the evidence, and recover deleted files — without mounting anything.

<p>
  <img src="https://img.shields.io/badge/version-2.0.0-4c8eda?style=flat-square" alt="Version"/>
  <img src="https://img.shields.io/badge/python-3.10%2B-4c8eda?style=flat-square&logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/Qt-PySide6-41cd52?style=flat-square&logo=qt&logoColor=white" alt="PySide6"/>
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-6e7781?style=flat-square" alt="Platforms"/>
  <img src="https://img.shields.io/badge/license-MIT-3fb950?style=flat-square" alt="License"/>
  <a href="https://github.com/Gadzhovski/TRACE-Forensic-Toolkit/actions/workflows/tests.yml"><img src="https://github.com/Gadzhovski/TRACE-Forensic-Toolkit/actions/workflows/tests.yml/badge.svg?branch=refactor%2Fcleanup-crossplatform" alt="Tests"/></a>
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

Work is organised into **cases**. A case is one investigation and can hold disk
images from several devices; every file, finding and bookmark is always shown
with the image it came from. A case is a folder holding a SQLite database plus
its carved files, exports and search index; the evidence itself is referenced by
path and hash, never copied.

It began as a final-year project and is intended for learning, lab work, and
triage rather than as a replacement for a commercial forensic suite.

> [!NOTE]
> Tested on **E01** and **raw** images with **NTFS** (including compressed and
> EFS-encrypted files), **FAT12/16/32**, **exFAT**, **Ext2/3/4**, **HFS+** and
> **ISO 9660**, against the DFTT, DFRWS, NPS and NIST test corpora. Carving is
> signature-based and scored against published answer keys (see
> [Testing](#testing)); verify anything it recovers.

<br/>

## Features

<table>
<tr>
<td width="50%" valign="top">

### 📁 Cases across devices

Start with **New Case**, **Open Case** or **Quick Triage** (no case). A case
remembers its evidence and reopens it; several images — a laptop, a phone, a USB
stick — live in one case, each kept open and clearly named. Every view says which
image a file belongs to, and opening anything reads its own image.

</td>
<td width="50%" valign="top">

### ✅ Evidence integrity

Recomputes MD5 / SHA-1 for E01 images and compares them with the acquisition
hashes. Verification is kept as a **history**, not a current value, and every
check, hash sent out and evidence change is written to the case's audit log.

</td>
</tr>
<tr>
<td width="50%" valign="top">

### 🩺 Triage analysis

One pass over every file, whichever modules are chosen:

- **File type** from content — flags an executable named `.jpg`
- **Entropy** (mean and peak) — packed or encrypted data
- **Hashes and duplicates** — MD5 / SHA-256, copies across devices
- **Hidden data** — `invoice.pdf.exe`, reversed-text names, data appended after
  the end of a JPEG / PNG / PDF, password-protected archives / Office / PDFs,
  and files that look like encrypted (VeraCrypt-style) volumes
- **Photo metadata** — camera, capture time, software, GPS position
- **Document authors** — author, last saved by, company, application, dates
- **Search index and indicators** — every file's text indexed for search,
  and the indicators in it listed (right)
- **File carving** — deleted files recovered from the raw image (below)

Run against every image in the case or one. Findings are graded (suspicious /
notable) and appear in the listing, a Triage tab with a sub-tab each, and a
Findings node in the tree grouped by device — photos, authors, carved files
and indicators included.

</td>
<td width="50%" valign="top">

### 🔎 Universal search

A per-case full-text index over file contents — PDFs, Office documents, registry
hives, plain text in ASCII and UTF-16 — built as an analysis module on the
background queue, for every image or one. Supports `"phrases"`, `prefix*`,
`AND` / `OR` / `NOT`, `/regex/` and field prefixes such as `email:` and `name:`.

**Indicators** are pulled out as it indexes: **emails, URLs, domains,
IPv4/IPv6 addresses, phone numbers, card numbers, IBANs, Bitcoin addresses and
hashes**. Card numbers must pass the Luhn check under a real scheme's prefix,
and IBANs their country's length and mod-97 check digits, so a run of digits
is not reported as one. Triage ▸ Indicators lists every distinct value — by
kind, per image — and the files holding each, with the text around it;
Findings ▸ Indicators in the tree counts them by kind.

</td>
</tr>
<tr>
<td width="50%" valign="top">

### 🔖 Bookmarks and notes

Bookmark any file, byte range or registry key and come back to it after
reopening the case. Write notes against files and bookmarks; notes outlive what
they describe. Bookmarks sit beside the findings in Triage and in the tree.

</td>
<td width="50%" valign="top">

### 🗜 Archives without extracting

ZIP, TAR, GZIP, BZIP2, XZ, 7z and RAR are browsed like folders straight from
the image — nested archives too — and their members open in the viewers.
Nothing is written to disk; encrypted members are reported as encrypted, and
decompression bombs are refused. RAR is listed in full, but only its stored
(uncompressed) members can be opened: decompressing RAR needs the proprietary
unrar tool, and evidence is never handed to an outside program.

</td>
</tr>
<tr>
<td width="50%" valign="top">

### 🔍 File carving

Recovers deleted files by signature — **59 types** in nine groups:

- **Pictures:** JPG, PNG, GIF, BMP, TIFF, WEBP, HEIC, AVIF, PSD
- **Documents:** PDF, DOCX/XLSX/PPTX/VSDX, ODT/ODS/ODP/ODG, EPUB, OLE
  (doc/xls/ppt/msg), RTF, HTML
- **Email:** PST, OST, mbox, EML
- **Databases & logs:** SQLite, EVTX, registry hives
- **Windows artifacts:** LNK
- **Executables:** EXE/DLL/SYS, ELF, Mach-O, APK, JAR
- **Archives:** ZIP, GZ, BZ2, XZ, TAR, RAR, 7Z
- **Audio:** WAV, MP3, OGG, Opus, M4A
- **Video:** MP4, MOV, M4V, 3GP, AVI, WMV, FLV, MPG, MKV, WebM

A file's extent comes from its own structure — a size in its header or a walk
of its blocks — never a guess, and every carve is validated before it is kept.
Files sized by their header are read whole from the image, however large, so a
big SQLite database or PST is not cut off. A ZIP is named for what it is (a
.docx, .apk...), and a carved archive opens like a folder. Embedded dates are
kept with their source: LNK target times, EVTX first event, hive last write,
Office core.xml, RTF \creatim, a PE's linker time (labelled as forgeable).
**Files split in two are rebuilt** where their own structure proves the split:
a ZIP's central directory or a PDF's cross-reference table gives the gap, and
a checksum (the member's CRC-32, the stream's Adler-32) confirms where it
falls. Each rebuilt file is listed with the pieces it was joined from.
Carve one image or all of them, from unallocated space
(an allocation map skips live files) or the whole image, from the Triage tab or
as an analysis module. In a case each file is recorded with its image, offset,
SHA-256 and embedded date, saved per image, audited and listed under Findings;
without a case, carving still works for the session. Previews read the bytes
back from the image, not the copy.

</td>
<td width="50%" valign="top">

### 🦠 VirusTotal, on demand

Right-click any file(s) → **VirusTotal ▸ Look Up Hash** (only the SHA-256 leaves
the machine) or **Upload File…** (after a warning that uploads are shared with
VirusTotal's subscribers). Lookups queue within the free-tier rate limit, results
are kept per file in the case and shown in the listing, and every request is
audited.

</td>
</tr>
<tr>
<td width="50%" valign="top">

### 🗂 File system browsing

Tree view of partitions and directories with a listing pane showing inode, size,
full MAC timestamps and analysis results. Back / forward / up navigation and a
listing filter (`*.pdf`).

</td>
<td width="50%" valign="top">

### 🪟 Registry viewer

Extracts Windows registry hives straight from the image and browses the key tree
with value names, types and data.

</td>
</tr>
</table>

### Reviewing findings

Clicking a finding, bookmark or search result **shows the file in the viewers
and leaves you where you are**, so a list can be worked down with the arrow keys.
Double-click — or **Show in Listing** — goes to the file's folder.

### Content viewers

Any selected file can be examined through these tabs:

| Tab | What it shows |
|:--|:--|
| **Hex** | Paginated hex and ASCII view with search and an address bar |
| **Text** | Text extraction with encoding detection; decodes Base64, hex, URL, HTML, octal and binary from a selection |
| **Application** | Renders the file by what it **is**, not what it is called — see below |
| **File Metadata** | Timestamps, size, MD5 / SHA-256, MIME type, low-level detail (MFT entry, attributes), and — when present — photo EXIF with GPS, document authorship and hidden-data findings |
| **Case** / **Notes** | The case's evidence and integrity status; notes on the selected file |
| **VirusTotal** | Appears when a lookup is made; history of every lookup with the full report |

The **Application** tab identifies a file from its content as well as its name:
a JPEG saved as `.txt` is shown as a JPEG, with a notice saying the extension
does not match.

| Kind | Formats |
|:--|:--|
| Images | JPEG, PNG, GIF, BMP, WebP, TIFF, ICO, SVG, TGA, PBM/PGM/PPM, **AVIF**, JPEG 2000, PSD, PCX |
| Paged documents | PDF, EPUB, XPS, CBZ, FB2, MOBI |
| Office | DOCX, XLSX, PPTX, ODT/ODS/ODP as structured text — **tracked-change deletions, comments, speaker notes and hidden sheets are shown and flagged**; legacy DOC/XLS/PPT as readable text |
| Web | HTML, rendered **offline**: scripts never run and nothing is fetched from the network or disk (a fetch would tell a page's owner it was opened, and from where) |
| Media | MP3, WAV, OGG, AAC, M4A, FLAC, WMA, MP4, M4V, MKV, WebM, AVI, MOV, WMV — large media streams from the image |

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
<td align="center"><sub><b>Search</b> — searching across the image</sub></td>
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
Ext2/3/4, HFS+, APFS, UFS, ISO 9660 and YAFFS2. NTFS, FAT, exFAT, Ext2/3/4, HFS+
and ISO 9660 have been tested here.

<br/>

## Installation

Requires **Python 3.10 or newer** (3.10 – 3.14). **No compiler is needed on
any platform**: every package — including the forensic engines, The Sleuth Kit
(`pytsk3`) and libewf (`libewf-python`) — installs as a pre-built wheel on
Windows (x64, ARM64), macOS (Apple Silicon and Intel) and Linux (x86_64,
aarch64). The install scripts create the virtual environment and install
everything; on macOS and Linux they also add the few system libraries Qt and
file-type detection need.

<details open>
<summary><b>Windows</b></summary>
<br/>

```powershell
git clone https://github.com/Gadzhovski/TRACE-Forensic-Toolkit.git
cd TRACE-Forensic-Toolkit
powershell -ExecutionPolicy Bypass -File install_windows.ps1
```

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

**macOS** needs nothing but Python 3.10 or newer — the
[python.org installer](https://www.python.org/downloads/macos/) is the simplest
way (the `python3` macOS ships is 3.9). No Homebrew, no Xcode: everything,
including libmagic for file-type detection, installs as a wheel.
On **Debian/Ubuntu** the script adds `libmagic1` and the Qt runtime libraries
(display, audio, networking) with apt. `./install.sh --yes` runs it without
prompts.

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

A single `requirements.txt` lists every library TRACE uses, on every platform;
Windows-only packages carry environment markers. Everything installs from
pre-built wheels — no compiler needed. **Upgrading an existing install?** Run
it again: the forensic engines moved to their first wheel-built releases
(The Sleuth Kit 4.15), AVIF needs Pillow 11.3+, and 7z archives need `py7zr`.

</details>

Run `deactivate` when you are finished.

<details>
<summary><b>Standalone application (Windows .zip, macOS .dmg)</b></summary>
<br/>

To build TRACE as an application that needs no Python, use an installed TRACE
environment (with the venv active):

```bash
python tools/fetch_test_images.py   # public images the build is tested on
python build_app.py
```

| Platform | Result in `dist/` |
|---|---|
| Windows | `TRACE-<version>-windows-x64.zip`, holding `TRACE\TRACE.exe` |
| macOS | `TRACE-<version>-macos-arm64.dmg` or `-x86_64.dmg`, holding `TRACE.app` |

Each comes with a `.sha256`. **A build is only kept once it has been shown
to work.** The script unpacks the zip into a folder whose name has spaces and
an accented letter, or mounts the DMG read-only. It then starts the packaged
app with `--self-test` against six public images (E01/NTFS, FAT, exFAT,
ext3, HFS+, ISO 9660). The self-test opens each image and builds a full case:
verify, analyse, index, search, reopen, and the main window on top. What the
packaged app reads from every image must match the test suite's reviewed
manifests exactly. Every push builds and checks all three packages on GitHub
Actions ([`build.yml`](.github/workflows/build.yml)), and they can be
downloaded from the run.

A macOS build is for the architecture it was built on (Apple Silicon or
Intel). Neither package is signed by a publisher, so Windows SmartScreen and
macOS Gatekeeper ask once before the first launch. The README inside each
package explains how to allow it.

An installed copy can be checked the same way at any time:
`TRACE --self-test report.json path/to/image.E01`.

</details>

<br/>

## Configuration

**VirusTotal API key** — set it under **Options → API Keys**. A free key allows
four lookups a minute; TRACE queues requests to stay within it. Without a key,
nothing else is affected.

**Analysis modules** are offered when a case is opened and can be run any time
from **Run Analysis** in the Triage tab. They run in the background; the status
bar shows progress and can cancel, and a cancelled run resumes where it stopped.

Settings and application data live outside the source tree:

| | Configuration | Data (log; carved files without a case) |
|:--|:--|:--|
| **Windows** | `%APPDATA%\TRACE` | `%LOCALAPPDATA%\TRACE` |
| **macOS** | `~/Library/Application Support/TRACE` | `~/Library/Application Support/TRACE` |
| **Linux** | `$XDG_CONFIG_HOME/TRACE` | `$XDG_DATA_HOME/TRACE` |

With a case open, carved files, exports and the search index are kept in the
case folder. Opening a case written by an older version upgrades it in place;
older builds cannot open it afterwards.

Diagnostics are written to `trace.log` in the data directory — include it when
reporting a bug.

<br/>

## Testing

Every push is installed from scratch and tested on **Windows, macOS (Apple
Silicon and Intel) and Linux, on Python 3.10, 3.12 and 3.14**, by GitHub
Actions ([`tests.yml`](.github/workflows/tests.yml)). The same suite runs
locally:

```bash
python tools/fetch_test_images.py   # public test images, checksum-verified
python -m pytest                    # image handling, core logic, the UI
```

- **Image handling** — every partition, file, deleted flag, timestamp and
  content hash TRACE reads from the public DFTT, NPS and NIST images is
  compared with a reviewed manifest (`tests/manifests/`), and every file is
  read back byte for byte. A change in what an examiner would be told fails
  the build.
- **Times are machine-independent** — FAT and exFAT store local time with no
  zone; TRACE shows the stored digits whatever zone the examining machine is
  in, and a test runs that check under a foreign time zone.
- **The UI** — the real window, run headlessly on a two-device case: browsing,
  Triage, previews from the right image, the Application tab's formats
  (including offline HTML that is proven to make no network request), and
  VirusTotal against a faked network.

Only public images are used, downloaded from their publishers and verified
against recorded SHA-256s; no evidence is stored in the repository.

### Carving

Carving is scored rather than eyeballed: `tools/carve_score.py` runs the real
carvers over the DFTT and DFRWS test images and compares the result with the
answer keys their authors published.

```bash
python tools/carve_score.py                  # every image with a known key
python tools/carve_score.py 11-carve-fat.dd  # one image
```

| Image | Files located | Byte-exact |
|:--|:--:|:--:|
| `11-carve-fat.dd` | 15 / 15 | — |
| `12-carve-ext2.dd` | 10 / 10 | 2 / 2 (1 rebuilt) |
| `dfrws-2006-challenge.raw` | 27 / 27 | 12 / 12 (2 rebuilt) |
| `dfrws-2007-challenge.img` | 78 / 114 | 16 / 16 (4 rebuilt) |
| `carve-corpus.dd` | 51 / 51 | 51 / 51 |

DFRWS 2007 is scored against its full official key — MP3, MPG, AVI, FLV, EXE,
ELF and mail as well as the original types. The DFRWS images deliberately
store most files fragmented. TRACE rebuilds ZIPs and PDFs stored in two
fragments, in order — the two ZIPs DFRWS 2006 split, four of the DFRWS 2007
PDFs, and a PDF on ext2 interrupted by its indirect block — byte-exact
against the published MD5s. Anything else fragmented is located but not
rebuilt: three or more pieces, pieces out of order, an encrypted PDF (its
checksum is under the encryption), and formats without a structure that
proves the split (JPEG, MP3, video). Every miss is a fragmented or
incomplete file.

`carve-corpus.dd` covers the formats those images do not hold. It is built by
`tools/carve_corpus.py` from 51 real published files — test files from
Pillow, pillow-heif, python-docx, python-evtx, yarp, LnkParse3, java-libpst,
rarfile, py7zr, CPython and the Matroska working group; release files of
PuTTY, SQLite, BusyBox, ripgrep, JUnit and GNU hello (a pre-POSIX tar);
sample media — each pinned by SHA-256 and laid among
random filler with a decoy for every signature. Every file comes back
byte-exact and no decoy is carved. CI builds and scores it on every push.
Test images are not included — see `test_images/README.md` for sources and
checksums.

<br/>

## Built with

[PySide6](https://pypi.org/project/PySide6/) ·
[pytsk3](https://pypi.org/project/pytsk3/) ·
[libewf-python](https://github.com/libyal/libewf) ·
[python-registry](https://github.com/williballenthin/python-registry) ·
[PyMuPDF](https://pymupdf.readthedocs.io/) ·
[Pillow](https://python-pillow.org/) ·
[python-magic](https://github.com/ahupp/python-magic) ·
[pylibmagic](https://github.com/kratsg/pylibmagic) ·
[olefile](https://github.com/decalage2/olefile) ·
[py7zr](https://github.com/miurahr/py7zr) ·
[rarfile](https://github.com/markokr/rarfile) ·
[pi-heif](https://github.com/bigcat88/pillow_heif) ·
[Tabler Icons](https://tabler.io/icons)

<br/>

---

<div align="center">

Released under the [MIT License](LICENSE)

Developed by [**Radoslav Gadzhovski**](https://linkedin.com/in/radoslav-gadzhovski)

</div>
