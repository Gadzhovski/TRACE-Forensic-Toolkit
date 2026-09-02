# TRACE — Architecture Cleanup & Cross-Platform Hardening

## Context

TRACE works, but it has accumulated the debt of a project that grew organically from a final-year
project into a real tool. Three things are now holding it back:

1. **It isn't genuinely cross-platform.** The intent is there — `ImageManager` branches on
   `platform.system()`, there's a macOS/Linux install script — but the non-Windows paths are
   largely untested and several break at install or first use. `pip install -r requirements.txt`
   *fails outright on Linux* (Windows-only packages, no environment markers). The Linux installer
   omits `libmagic`, `poppler`, and `ffmpeg`, so the Metadata tab and carving thumbnails hard-fail.
   `converter.py` checks `os.name == "darwin"`, which is never true, so macOS drive listing has
   never worked. Windows silently gets a richer Metadata tab than everyone else.

2. **Installation is hostile to non-technical users.** It requires exactly Python 3.11, a C++
   compiler (pytsk3 and libewf-python are source-only sdists), and system libraries installed by
   hand. The requirements files are `pip freeze` dumps: ~57 of 77 packages are never imported,
   including the entire Pyramid web framework.

3. **It's hard to maintain.** `mainwindow.py` is 4,623 lines — 45% of the codebase — and the
   `MainWindow` class alone is ~3,070 lines with 79 methods, mixing GUI, forensic image I/O, disk
   mounting, SQLite access, and three worker threads nested inside the class body. Adding a viewer
   tab means editing five separate places, one of which is a dispatch on a magic tab index.

**Intended outcome:** the same tool, with identical behaviour on Windows, macOS, and Linux; a
one-command install that works on a clean machine; and a codebase where a feature lives in one file.

**Decisions taken:** primary install stays source-based via a hardened one-command script (not
prebuilt binaries); the 138 MB of vendored Windows binaries come out of the repo; the heavy
thumbnail dependencies get replaced; `mainwindow.py` is split incrementally; **image mounting is
removed entirely**; **no test/CI scaffolding in this plan**.

> Removing mounting is the one item worth a second thought: it's a listed README feature. It's
> included because TRACE reads images directly through pytsk3 — mounting is a convenience, not a
> dependency of any other feature — and it is the single largest source of platform-specific
> breakage (Arsenal's 63 MB + EULA, `sudo` in a GUI thread, `hdiutil` parsing). Removing it deletes
> ~420 lines and an entire class of bugs. Phase 1 is ordered so this is reversible if you change
> your mind: the code is deleted in one commit that can be reverted on its own.

**Verification is manual throughout** (per decision). Each phase below ends with an explicit
"check this still works" list. Keep a disk image handy — the repo root already has
`2020JimmyWilson.E01`, `BXS-1.E01`, `11-carve-fat.dd`, `12-carve-ext2.dd`.

---

## Phase 0 — Repo hygiene (do this first, it's fast and makes everything else easier)

The working tree currently carries ~1.4 GB that shouldn't be there.

- [x] `tools/Arsenal-Image-Mounter-v3.10.257/` and `tools/sleuthkit-4.12.1-win32/` are **tracked in
      git** (246 files, 138 MB). Remove from tracking (`git rm -r --cached`) and add to
      `.gitignore`. Arsenal ships its own EULA — redistributing it in the repo is a licensing
      question you don't need to carry. (Phases 1 and 2 remove the code that uses them.)
- [x] `.gitignore` currently ignores `*.spec` and `build_exe.py`, yet `TRACE.spec` and
      `build_exe.py` are committed. Resolve the contradiction: keep both files tracked (they're
      real build inputs) and drop those two ignore lines.
- [x] `dist/` (520 MB) and `build/` (33 MB) are stale PyInstaller output in the working tree.
      Delete locally; already gitignored.
- [x] `carved_files/` (152 MB) is app output sitting in the repo root. Already gitignored — see
      Phase 3, which moves the write location out of the repo entirely.
- [x] `requirements.txt` starts with a UTF-8 BOM, which breaks `pip install -r` on some setups.
      Rewrite without it.
- [x] Note: `.git` is already 80 MB because the `tools/` binaries are in history. Un-tracking them
      stops it growing; actually shrinking it needs a history rewrite (`git filter-repo`), which is
      **out of scope** — it breaks every existing clone and fork. Flagging it, not doing it.

**Verify:** `git status` clean, `python main.py` still launches, `git count-objects -vH` unchanged
(expected — history rewrite is out of scope).

---

## Phase 1 — Remove dead and unused features

Smallest-risk phase; it shrinks the surface area everything later has to move.

### 1a. Remove Veriphone

Cleanly isolated — one self-contained module, one import, one menu entry, one settings key.

- [x] Delete `modules/veriphone_api.py` (133 lines) and `Icons/logo_veriphone.png`.
- [x] `modules/mainwindow.py`: remove the import (`:38`), the Tools-menu entry (`:1712-1714`), and
      the lazy-init slot `show_veriphone_widget` (`:2041-2048`).
- [x] `modules/mainwindow.py:1980-2034`: drop the Veriphone row from the API-key dialog and change
      `save_api_keys(virus_total_key, veriphone_key, dialog)` to take only the VirusTotal key.
      Remove the `[API_KEYS] veriphone` read/write (`:2001`, `:2022`, `:2046`).
- [x] Update `README.md:202` and `CLAUDE.md:164`, which both still document it.

### 1b. Remove image mounting

- [x] Delete `class ImageManager(QThread)` — `modules/mainwindow.py:1020-1438`, all six
      `_mount_*`/`_dismount_*` methods (~420 lines).
- [x] Remove the File-menu "Image Mounting"/"Image Unmounting" entries and the two toolbar buttons
      (`:1650-1657`, `:1743-1749`), plus `_handle_mount_operation_complete` (`:1504`) and
      `_handle_dismount_if_needed` (`:1536`), and the mount-related bits of `closeEvent`/
      `cleanup_resources`.
- [x] Delete `tools/Arsenal-Image-Mounter-v3.10.257/` from disk.
- [x] Update README: remove the "Image Mounting (Windows only)" feature bullet, the Arsenal entry
      under *Built With*, and the "Cross-Platform Image Mounting" work-in-progress item.

### 1c. Delete confirmed dead code

- [x] **`on_listing_table_item_clicked` is defined twice in `MainWindow`** — `:3946` and `:4432`,
      with no class boundary between them. Python keeps the second, so the ~486-line first
      definition is unreachable. It handles *search-mode tree navigation*, so that behaviour is
      silently missing today. **Decide deliberately:** either delete `:3946-4051`, or merge its
      search-mode branch into the live `:4432` handler to restore the feature. Recommend merging —
      the code was clearly written on purpose.
- [x] Remove never-referenced symbols: `use_api_key` (`virus_total_tab.py:73`),
      `_format_partition_text` (`mainwindow.py:1519`), `_get_partition_info` (`:3728`),
      `apply_browse_filter` (`:4333`), `clear_listing_search` (`:4085`),
      `setup_buttons` (`file_carving.py:479`), `update_total_pages_label`
      (`hex_tab.py:635`).
      **Correction (verified during implementation):** `SizeTableWidgetItem` and
      `FileSystemUtils.get_readable_size` are NOT dead — the former is used by the
      search-results row builder, the latter has six callers. Both kept.
- [x] `file_carving.py` has **two parallel sets of button handlers** — `start_carving`/
      `stop_carving` (`:278`/`:329`) and `start_carving_thread`/`stop_carving_thread` (`:485`/
      `:491`) — wired in two places with *different* `shutdown(wait=)` semantics. This is a
      half-finished refactor. Keep one set (the `:278`/`:329` pair, which `init_ui` wires), delete
      the other.
- [x] Unused imports: `Tuple` and `QPieSlice` (`mainwindow.py:12`, `:21`), `sqlite3`
      (`text_tab.py:4`), `WeakValueDictionary` and `QSpacerItem`
      (`unified_application_manager.py:3`, `:14`).

**Verify:** app launches; Tools menu has no Veriphone; File menu has no mount entries; API-key
dialog saves a VirusTotal key and it persists across restart; load an image and browse the tree.

---

## Phase 2 — Cross-platform correctness

The heart of the "works everywhere" goal. Every item here is a confirmed defect.

### 2a. Resource paths — the single highest-impact fix

**There is no use of `__file__` or `sys._MEIPASS` anywhere in the codebase.** Every icon, both
stylesheets, the icon database, and `config.ini` are bare relative paths resolved against the
*current working directory*. This works only when launched as `cd <repo> && python main.py`. From a
desktop launcher, a macOS `.app` (CWD is `/`), or any packaged build, the app opens unthemed with
blank icons — and file carving can't even create its output directory.

- [x] Add `modules/paths.py` with two helpers:
      - `resource_path(rel)` → `os.path.join(getattr(sys, '_MEIPASS', <project root>), rel)`,
        where project root is derived from `os.path.dirname(os.path.abspath(__file__))`.
      - `user_data_dir()` / `user_config_dir()` → per-OS standard locations
        (`%APPDATA%\TRACE`, `~/Library/Application Support/TRACE`,
        `$XDG_CONFIG_HOME`-or-`~/.config/TRACE`). Create on demand.
- [x] Route every resource literal through `resource_path()`. There are ~100 across
      `mainwindow.py` (icons at `:1635`, `:1737-1749`, `:1806-1837`; stylesheets at `:1969-1971`;
      icon DB at `:1456`), `unified_application_manager.py` (~43 sites), `file_carving.py`,
      `hex_tab.py`, `registry.py`, `about.py`, `converter.py`, `virus_total_tab.py`.
      Same pattern each time — mechanical, but touch every file.
- [x] `DatabaseManager.get_icon_path` (`mainwindow.py:968-1013`) returns paths **stored as data in
      the SQLite DB** (e.g. `Icons/mimetypes/application-7zip.svg`). Wrap the return value in
      `resource_path()` rather than rewriting 308 DB rows. Its four hardcoded fallbacks
      (`:978`, `:995`, `:1003`, `:1013`) need the same.
- [x] Move `config.ini` to `user_config_dir()` (`mainwindow.py:1484`, `:2024`) and wrap the write
      in try/except — today a `PermissionError` propagates unhandled out of a Qt slot.
      Also set `setEchoMode(QLineEdit.Password)` on the key field, which currently shows in clear.

### 2b. Fix the platform bugs

- [x] **`converter.py:22`** — `elif os.name == "darwin"` is never true (`os.name` is `'posix'` on
      macOS; `'darwin'` is a `sys.platform` value). macOS falls through to
      `raise Exception("Unsupported OS")`. Switch this function to `sys.platform`/
      `platform.system()` and add a real Linux branch (`lsblk -o NAME,MODEL,SIZE`).
      Also replace the deprecated `Get-WmiObject` with `Get-CimInstance`.
- [x] **`metadata_tab.py:117-157`** — the Metadata tab shells out to the bundled
      `tools/sleuthkit-4.12.1-win32/bin/istat.exe`, gated on `os.name == 'nt'`. macOS/Linux users
      silently get a lesser tab with no explanation. **Replace `run_istat` with native pytsk3
      calls** — the same attribute/run-list data is available from the `pytsk3.File` object the
      code already holds. This deletes the 75 MB binary bundle *and* makes the tab identical on
      all three platforms. This is the main reason `tools/sleuthkit-4.12.1-win32/` can go.
- [x] Delete `tools/sleuthkit-4.12.1-win32/` once the above lands.
- [x] `unified_application_manager.py:2` — move `from ctypes import cast, POINTER` inside the
      existing `os.name == "nt"` guard at `:19`; the symbols are only used in the Windows-only
      volume path at `:1295`.

### 2c. Rebuild the dependency story

Current state: 77 declared packages, ~15 actually imported. The entire Pyramid web stack
(`pyramid`, `PasteDeploy`, `plaster`, `venusian`, `WebOb`, `hupper`, `translationstring`), dev
tools (`line-profiler`, `line-profiler-pycharm`, `vulture`, `yarg`), and an unused office-document
stack (`openpyxl`, `python-docx`, `python-pptx`, `xlrd`, `XlsxWriter`) are all dead weight.
`docx` **and** `python-docx` conflict (both provide the `docx` package); `pypdf` and `PyPDF2` are
both declared, only `PyPDF2` used; `PyMuPDF`/`PyMuPDFb` are pinned to *mismatched* versions.

- [x] **Replace the four heavy thumbnail-only dependencies.** `opencv-python` (~90 MB), `moviepy`,
      `pdf2image`, and `PyPDF2` are used *only* in `file_carving.py`, and only for thumbnails and
      PDF validation:
      - `pdf2image.convert_from_path` (`:1007`) → **PyMuPDF**, already a dependency. Also drops
        the **poppler** system requirement.
      - `moviepy.VideoFileClip` (`:1001`) + `cv2.VideoCapture` (`:1014-1019`) → Qt's
        `QMediaPlayer`/`QVideoSink` frame grab, or simply skip video thumbnails with a generic
        icon. Drops the **ffmpeg** system requirement.
      - `PyPDF2.PdfReader` validation (`:500`, `:910`) → PyMuPDF's parser.
      Poppler and ffmpeg are the two most common install failures for non-technical users; this
      removes both, plus ~100 MB of wheels.
- [x] **Collapse to one `requirements.txt` using environment markers**, replacing both files
      (`install_macos_linux_WSL.sh` currently uses the *macOS* file for Linux and WSL too, which
      contradicts the README):
      ```
      PySide6==<pin>            # + PySide6-Addons: QtCharts, QtSvg, QtMultimedia, QtPrintSupport
      pytsk3
      libewf-python
      python-registry
      Pillow
      PyMuPDF
      chardet
      requests
      python-magic-bin ; sys_platform == 'win32'
      python-magic     ; sys_platform != 'win32'
      pycaw            ; sys_platform == 'win32'
      comtypes         ; sys_platform == 'win32'
      ```
      Markers are the fix for the "`pip install` fails on Linux" bug — `pycaw`, `comtypes`, and
      `python-magic-bin` are currently declared unconditionally, and `pycaw`/`comtypes` are even
      in the macOS file.
- [x] Bump `PySide6` off `6.5.2`. That pin is *why* the README says Python 3.12 is unsupported;
      a current PySide6 has wheels for 3.12/3.13 and widens the supported Python range
      considerably. Test the media player and QtCharts after bumping — those are the two areas
      most likely to shift.
- [x] Add `pyinstaller` as a documented build-time dependency (`build_exe.py` needs it; it's in no
      requirements file).

### 2d. Fix the installer

- [x] Rewrite `install_macos_linux_WSL.sh` package lists:
      - **Linux/WSL are missing** `libmagic1` (Metadata tab crashes without it),
        `build-essential`, `libewf-dev`, and `libtsk-dev`/`sleuthkit` — without the last three,
        `pip install pytsk3 libewf-python` *fails to compile on a clean Ubuntu*.
      - **Remove** `nvidia-cuda-toolkit` from the WSL branch — several GB, entirely unused.
      - **Remove** the Qt5 stack (`qt5dxcb-plugin`, `libqt5*`, `qt5-wayland`) from the WSL branch —
        the app is Qt6. The one actually needed is `libxcb-cursor0`, which the WSL branch omits.
      - `poppler`/`ffmpeg` drop out of the macOS list once Phase 2c lands.
      - `RED` is used at three points but never defined; those messages render uncolourless.
      - The script claims to create a Python 3.11 venv but just calls `python3 -m venv` — either
        enforce a version or stop claiming it.
- [x] Point all three branches at the single `requirements.txt`.
- [x] Add `install_windows.ps1` — there is **no Windows install script at all** today, despite
      Windows being the primary platform. Should check the Python version, warn clearly if MSVC
      Build Tools are missing (the biggest Windows install barrier), create the venv, and install.
- [x] Add a startup preflight: check for `libmagic` and other externals with `shutil.which` /
      import guards and show one clear dialog naming what's missing, instead of the current
      behaviour where a missing library surfaces as an unhandled exception inside a Qt slot.
      (`shutil.which` is used nowhere in the codebase today.)
- [x] Rewrite the README install section to match reality.

**Verify:** on each OS available to you — fresh clone, run the install script, launch from a
*different working directory* (`python "D:\path\to\TRACE\main.py"` from `C:\`), confirm the theme
and icons load, save an API key and confirm it persists, open the Metadata tab on a file and
confirm the istat-equivalent data now appears on macOS/Linux too, run a carve and confirm PDF
thumbnails still render.

---


### Phase 2 notes (discovered during implementation)

- The venv was already running **PySide6 6.8.3**, not the pinned 6.5.2, so the
  "Python 3.12 unsupported" claim was already stale. Pins are now lower bounds.
- `ensure_icons_directory()` (`unified_application_manager.py`) had a hardcoded
  relative `"Icons"` and created a stray folder with 5 placeholder PNGs in
  whatever directory the app was launched from. Reproduced (`C:\Icons`) and fixed.
- `file_carving.carve_files()` did `self.stop_carving = False`, overwriting the
  bound method with a bool — Stop raised `TypeError` after the first carve.
  Fixed alongside the executor bug (was scheduled for Phase 4).
- `save_file()` ignored its `file_path` argument and rebuilt the path, so most
  of the `'carved_files'` call-site strings were inert; only 3 sites mattered.
- The double `menu_bar.addMenu(view_menu)` is **benign** — Qt de-duplicates the
  same QMenu object, so "View" appears once. Left alone.

## Phase 3 — Structural refactor

Incremental, with the app runnable after each step. Do these in order; each is independently
committable.

### 3a. Extract the non-UI classes from `mainwindow.py`

Pure moves — no logic changes, so any breakage is an import error, not a subtle bug.

- [x] `EWFImgInfo`, `ImageHandler` → `modules/image_handler.py` (820 lines)
- [x] `DatabaseManager` → `modules/database.py`
- [x] `ExportWorker` → `modules/workers.py`
- [x] `FileSystemUtils`, `safe_datetime`, constants → `modules/utils.py`, `modules/constants.py`
- [ ] The 3 workers nested inside `MainWindow` — deferred to 3b, since they are
      called as `self.FileContentWorker(...)` and moving them is a behavioural
      change rather than a pure move.

**Result:** `mainwindow.py` 4,623 → 2,938 lines.

`FileContentWorker`, `MediaStreamWorker`, and `UnallocatedSpaceWorker` are currently **nested class
definitions inside `MainWindow`** (instantiated as `self.FileContentWorker(...)`). They take
`image_handler` as a plain argument and have no dependency on `MainWindow` — nesting them only
makes them un-importable and inflates the file.

### 3b. Introduce a viewer-tab interface

This is what actually makes the app maintainable. Today, showing content routes through a six-way
`if index == 0 / 1 / 2...` dispatch (`mainwindow.py:3109-3124`) keyed to `addTab()` call order, and
`display_content_for_active_tab` hardcodes `current_tab_index == 2` for media streaming
(`:3206`). Reordering a tab silently sends content to the wrong viewer. Meanwhile `clear_viewers`
(`:2131-2137`) calls three different method names because each tab named its own — `clear_content()`
on hex/text/exif, `clear()` on application/metadata/registry.

- [ ] Add `modules/viewers/base.py` with a `ViewerTab` interface: `display(content, data)`,
      `clear()`, and a `wants_stream(data) -> bool` hook so the Application tab can declare its own
      streaming preference instead of `mainwindow` hardcoding index 2.
- [ ] Adapt the six viewers to it (rename their clear/display methods to match).
- [ ] Replace both dispatches with a loop over registered tabs. Adding a tab becomes: write the
      class, register it — one place instead of five.

### 3c. Fix the coupling that reaches upward

- [ ] `file_carving.py:975` — `self.main_window.db_manager.get_icon_path(...)` reaches two levels
      up. Inject the `DatabaseManager` (or an icon-resolver) in the constructor instead.
- [ ] `file_carving.py:467-468` — reaches up to `self.main_window.update_viewer_with_file_content`
      guarded by `hasattr`. The widget already declares a `file_carved` Signal at `:43`; emit it
      and let `MainWindow` connect.
- [ ] `converter.py:203` — `self.parent().parent()` resolves to `Main` only by coincidence of
      current widget nesting; adding a wrapper widget silently breaks the Back button.
      `ConversionWidget` already declares `backRequested = Signal()` at `:157` but never emits it.
      Emit it, and connect it the way `DriveSelectionWidget` already does correctly at `:58`.
- [ ] `mainwindow.py:1926`/`:1942` — `RegistryExtractor` and `MetadataViewer` are constructed with
      `self.image_handler` while it is still `None`, then wired by direct attribute poke ~300 lines
      later at `:2263-2265`, using three different mechanisms (one setter, two attribute writes).
      Standardise on `set_image_handler()` on the `ViewerTab` interface.

### 3d. Split the UI construction

- [ ] `initialize_ui` is a single 336-line method (`mainwindow.py:1631-1966`). Split into
      `_build_menus()`, `_build_toolbars()`, `_build_docks()`, `_build_tabs()`.
- [ ] Extract the volume-info/chart block (`view_os_information` `:3325` through
      `_create_space_allocation_chart` `:3915`, ~590 lines) into `modules/volume_info.py`.
- [ ] Two menu-bar bugs found while mapping this: `menu_bar.addMenu(view_menu)` is called **twice**
      (`:1697` and `:1726`), so "View" appears twice; and the About action is connected to
      `help_menu.triggered` — the whole menu, not the action — so any Help item opens About.
      Also replace the deprecated `.exec_()` calls (`:1724`, `:2014`) with `.exec()`.

**Verify after each sub-phase:** app launches, image loads, tree browses, all six viewer tabs show
content for a selected file, carving runs, registry hive opens, export works.

---

## Phase 4 — Robustness

- [ ] **`mainwindow.py:532`** — `check_partition_contents` wraps `fs.open_dir(path="/")` in a bare
      `except: return False`. This is on the partition-detection hot path, and it turns *every*
      failure — corrupt image, unsupported filesystem, read error — into an indistinguishable
      "no filesystem here." For a forensic tool that's an evidentiary correctness problem, not just
      a style issue: a read error and an empty partition must not look the same. Catch specific
      exceptions and surface the difference.
- [ ] Fix the other bare `except:` blocks — 11 total, worst at `:2934` (`block_size = "N/A"`
      masking read errors) and `:3782` (volume-label walk → silent `pass`).
      `file_carving.py:904/917/928` swallow all timestamp-extraction failures.
- [ ] **`file_carving.py:329-332`** — `stop_carving` calls `executor.shutdown(wait=True)`, which
      does **not cancel** the running task; it blocks the UI thread until the full carve finishes,
      freezing the GUI for minutes on a large image. Worse, `shutdown()` is terminal, so Stop →
      Start afterwards raises `RuntimeError` on the next `submit()`. Replace with a cooperative
      cancellation flag checked inside the carve loop, and recreate the executor on start.
- [ ] **`mainwindow.py:3291`** — `progress_dialog.canceled.connect(self.export_worker.terminate)`
      uses `QThread.terminate()`, which can corrupt the pytsk3 handle mid-read, and directly
      contradicts this project's own `CLAUDE.md` guidance ("use `requestInterruption()` not
      `terminate()`"). Switch to cooperative interruption.
- [ ] **`mainwindow.py:3170-3190`** — workers are stored as `self.media_worker`/`self.file_worker`,
      so rapid file switching rebinds the attribute and drops the last reference to a still-running
      `QThread` — a known route to `RuntimeError: Internal C++ object already deleted`. Keep
      references until `finished` fires.
- [ ] **Replace 61 `print()` calls with the existing logger.** `mainwindow.py:100` already creates
      `logging.getLogger('TRACE.MainWindow')` but never configures a handler or level. The
      packaged build sets `console=False`, so `sys.stdout` is `None` and **all 61 diagnostics are
      discarded for end users** — a failed registry load currently looks identical to an empty
      hive. Configure logging in `main.py` writing to `user_data_dir()/trace.log`.
- [ ] `main.py`: pass `sys.argv` to `QApplication`, use `sys.exit(app.exec())` so the exit code
      isn't discarded, and set `setApplicationName`/`setOrganizationName`.
- [ ] Move `carved_files/` output from the CWD to `user_data_dir()` (`file_carving.py:286-288`,
      `:938`, `:993`) — on a macOS bundle the current code raises `PermissionError` trying to
      create it under `/`.
- [ ] Move the inline `setStyleSheet` calls into the theme files, per `CLAUDE.md`'s own rule —
      `file_carving.py:64-82`, `registry.py:31-49`, `mainwindow.py:1900`, `:3344`, `:3351-3357`,
      `:3364`.
- [ ] VirusTotal report uses the **retired v2 API** (`virus_total_tab.py:251-252`) with the key in
      the query string, while upload correctly uses v3. Migrate the report path to v3.

---

## Phase 5 — Packaging (optional follow-up)

Not the chosen primary install route, but the current build files are broken and worth fixing if
you ever want binaries.

- [ ] `build_exe.py:82` uses `--add-data f"{src};{dst}"`. The `;` separator is **Windows-only** —
      macOS/Linux need `:`. As written, the build script cannot produce a Mac or Linux build.
- [ ] `TRACE.spec:7` has `datas=[('Icons', '.'), ('styles', '.')]`. A `'.'` destination for a
      *directory* source flattens `Icons/*` into the bundle root, so `Icons/logo.png` becomes
      `logo.png` and every lookup breaks. `build_exe.py:80-88` computes the same wrong value.
      Should be `('Icons', 'Icons')`.
- [ ] Neither the spec nor `build_exe.py` bundles `tools/` — so in a packaged build the Metadata
      tab's istat call raises `FileNotFoundError` (unguarded). Phase 2b removes that dependency
      entirely, which fixes this by construction.
- [ ] `build_exe.py:21` points at `Icons/logo_prev_ui.ico`, which doesn't exist — only the `.png`.
      The exe currently ships with the default PyInstaller icon.
- [ ] Exclude `Icons/readme/` (2.3 MB of README screenshots) and `Icons/animations/` (referenced
      nowhere in code) from the bundle.
- [ ] Phase 2a's `resource_path()` is a prerequisite for any `--onefile` build to work at all.

---

## Critical files

| File | Role in this plan |
|---|---|
| `modules/mainwindow.py` (4,623) | Touched by every phase; source of all Phase 3 extractions |
| `modules/file_carving.py` (1,081) | Heavy-dep removal (2c), executor bug (4), coupling (3c) |
| `modules/metadata_tab.py` (160) | istat → pytsk3 (2b); unblocks deleting 75 MB |
| `modules/unified_application_manager.py` (1,630) | ~43 resource paths (2a), ViewerTab (3b) |
| `modules/converter.py` (252) | `os.name == "darwin"` bug (2b), `parent().parent()` (3c) |
| `requirements*.txt` | Collapsed to one file with markers (2c) |
| `install_macos_linux_WSL.sh` | Rewritten (2d); new `install_windows.ps1` |
| `modules/paths.py` *(new)* | `resource_path()` / `user_data_dir()` — dependency of 2a, 4, 5 |

## Reusable code already present

- `ImageHandler.get_readable_size` (`mainwindow.py:932`) — the live one; the `FileSystemUtils`
  copy at `:116` is dead.
- `ImageHandler.build_allocation_map` (`:214`) + binary-search allocation checking — already the
  carving optimisation described in `CLAUDE.md`.
- `PyTsk3StreamDevice` (`unified_application_manager.py:24`) — the streaming device to reuse for
  any new large-file reader.
- `FileCarvingWidget.file_carved` Signal (`file_carving.py:43`) and
  `ConversionWidget.backRequested` (`converter.py:157`) — both already declared, both unused;
  Phase 3c just emits them.
- `SearchWorker` (`hex_tab.py:12`) — the only correct worker+`moveToThread` pattern in the
  codebase; use it as the model when reworking the other threads.
- `MainWindow.create_menu` / `create_action` (`:2083`, `:3916`) — existing helpers for Phase 3d.

## Sequencing

Phases 0 → 1 → 2 → 3 → 4 as written. Phase 2 delivers the user-visible win (installs and runs
everywhere) and Phase 3 delivers the maintainability win, but **2a (`resource_path`) should land
early** — Phases 4 and 5 both depend on it. Phase 5 is optional.

Work on a branch off `update` (current HEAD `9b8503a`), committing each checkbox group separately
so anything can be reverted in isolation — particularly 1b, the mounting removal.
