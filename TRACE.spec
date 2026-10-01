# -*- mode: python ; coding: utf-8 -*-


import sys

from PyInstaller.utils.hooks import (
    collect_data_files, collect_dynamic_libs, collect_submodules)

# main.py is a thin launcher; the real code is imported from the
# trace_app package, so collect it explicitly.
_trace_modules = collect_submodules('trace_app')

# macOS: libmagic and its database come from the pylibmagic wheel, which
# trace_app imports by name; carry its dylib and magic.mgc into the bundle.
_magic_binaries, _magic_datas, _magic_imports = [], [], []
if sys.platform == 'darwin':
    _magic_binaries = collect_dynamic_libs('pylibmagic', destdir='pylibmagic')
    _magic_datas = collect_data_files('pylibmagic')
    _magic_imports = ['pylibmagic']

a = Analysis(
    ['main.py'],
    pathex=['.'],
    binaries=_magic_binaries,
    datas=[('Icons', 'Icons'), ('styles', 'styles')] + _magic_datas,
    hiddenimports=['PySide6.QtCore', 'PySide6.QtGui', 'PySide6.QtWidgets', 'PySide6.QtCharts',
                   'PySide6.QtSvg', 'PySide6.QtSvgWidgets', 'PySide6.QtMultimedia',
                   'PySide6.QtMultimediaWidgets', 'PySide6.QtPrintSupport', 'pytsk3', 'pyewf',
                   'PIL', 'PIL.Image', 'requests', 'Registry', 'pymupdf', 'magic',
                   'chardet'] + _magic_imports + _trace_modules,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
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
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='TRACE',
)
