# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller build of TRACE for Windows and macOS.

Run through build_app.py, which also packages the result and proves it works
(`python build_app.py`); `python -m PyInstaller TRACE.spec` builds alone.

    Windows: dist/TRACE/TRACE.exe     (a folder: Qt and the engines beside it)
    macOS:   dist/TRACE.app

What the bundle needs is found by analysis, not listed by hand: every
trace_app module is collected, and PyInstaller's hooks bring the Qt plugins,
libmagic (python-magic-bin's DLL on Windows, pylibmagic's dylib on macOS),
certifi's CA bundle and the rest. A hand-kept list of imports only goes stale;
the self-test is what checks nothing was left out.
"""

import os
import re
import sys
from importlib import metadata

from PyInstaller.utils.hooks import collect_submodules

ROOT = os.path.abspath(SPECPATH)
ASSETS = os.path.join(ROOT, 'build', 'assets')
os.makedirs(ASSETS, exist_ok=True)

with open(os.path.join(ROOT, 'trace_app', '__init__.py'), encoding='utf-8') as _f:
    VERSION = re.search(r'^__version__ = "([^"]+)"', _f.read(), re.M).group(1)


def _icon():
    """The application icon, made from Icons/logo.png (1024 px) at build
    time: .ico for Windows, .icns for macOS. Nothing generated is committed."""
    from PIL import Image
    logo = Image.open(os.path.join(ROOT, 'Icons', 'logo.png')).convert('RGBA')
    if sys.platform == 'darwin':
        path = os.path.join(ASSETS, 'TRACE.icns')
        logo.save(path)                         # every size, 16 to 1024 px
    else:
        path = os.path.join(ASSETS, 'TRACE.ico')
        logo.save(path, sizes=[(s, s) for s in (16, 20, 24, 32, 40, 48, 64,
                                                128, 256)])
    return path


def _windows_version_info():
    """The Details tab of TRACE.exe's properties: name, version, licence."""
    from PyInstaller.utils.win32.versioninfo import (
        FixedFileInfo, StringFileInfo, StringStruct, StringTable,
        VarFileInfo, VarStruct, VSVersionInfo)
    numbers = tuple((list(map(int, re.findall(r'\d+', VERSION))) + [0] * 4)[:4])
    strings = [
        StringStruct('CompanyName', 'TRACE'),
        StringStruct('FileDescription',
                     'TRACE - Toolkit for Retrieval and Analysis of Cyber Evidence'),
        StringStruct('FileVersion', VERSION),
        StringStruct('InternalName', 'TRACE'),
        StringStruct('LegalCopyright', 'MIT License'),
        StringStruct('OriginalFilename', 'TRACE.exe'),
        StringStruct('ProductName', 'TRACE Forensic Toolkit'),
        StringStruct('ProductVersion', VERSION),
    ]
    return VSVersionInfo(
        ffi=FixedFileInfo(filevers=numbers, prodvers=numbers),
        kids=[StringFileInfo([StringTable('040904B0', strings)]),
              VarFileInfo([VarStruct('Translation', [0x0409, 1200])])])


def _macos_minimum():
    """The oldest macOS every bundled native library supports.

    Each wheel's platform tag states it (PySide6's is macOS 13, for
    instance); claiming less in Info.plist would let the app start on a Mac
    where Qt then fails to load.
    """
    oldest = (11, 0)
    for dist in metadata.distributions():
        try:
            wheel = dist.read_text('WHEEL') or ''
        except Exception:
            continue
        for major, minor in re.findall(r'^Tag: \S*?macosx_(\d+)_(\d+)_', wheel,
                                       re.M):
            oldest = max(oldest, (int(major), int(minor)))
    return f'{oldest[0]}.{oldest[1]}'


ICON = _icon()

a = Analysis(
    ['main.py'],
    pathex=[ROOT],
    binaries=[],
    datas=[('Icons', 'Icons'), ('styles', 'styles')],
    hiddenimports=collect_submodules('trace_app'),
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    # Never imported by TRACE, but reachable through other libraries'
    # optional imports (PyMuPDF's tables, Pillow's array support): ~70 MB a
    # build would carry if they happen to be installed. The self-test shows
    # nothing TRACE needs went with them.
    excludes=['tkinter', 'pytest', '_pytest', 'IPython', 'numpy', 'pandas',
              'scipy', 'matplotlib', 'cv2', 'moviepy', 'imageio', 'docx',
              'pptx', 'lxml'],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='TRACE',
    icon=ICON,
    version=_windows_version_info() if sys.platform == 'win32' else None,
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    # UPX would shrink the download, but packed binaries are what antivirus
    # heuristics flag, and it corrupts some Qt libraries. Not for a tool an
    # examiner has to trust.
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    # A Developer ID, when there is one, signs a release; unset, PyInstaller
    # signs ad hoc, which Apple Silicon requires for anything to run at all.
    codesign_identity=os.environ.get('TRACE_CODESIGN_IDENTITY') or None,
    entitlements_file=None,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name='TRACE',
)

if sys.platform == 'darwin':
    app = BUNDLE(
        coll,
        name='TRACE.app',
        icon=ICON,
        bundle_identifier='io.github.gadzhovski.trace',
        version=VERSION,
        info_plist={
            'CFBundleName': 'TRACE',
            'CFBundleDisplayName': 'TRACE',
            'CFBundleShortVersionString': VERSION,
            'CFBundleVersion': VERSION,
            'LSMinimumSystemVersion': _macos_minimum(),
            'LSApplicationCategoryType': 'public.app-category.utilities',
            'NSHighResolutionCapable': True,
            # Follow the system's light/dark appearance for native dialogs.
            'NSRequiresAquaSystemAppearance': False,
            'NSHumanReadableCopyright': 'MIT License',
        },
    )
