"""Fonts the UI asks for by role.

Never QFont("Courier"): on Windows that name is a bitmap font, which
DirectWrite cannot render -- Qt fell back to the "8514oem" raster font and
logged "CreateFontFaceFromHDC() failed" each time a hex view opened.
"""

from PySide6.QtGui import QFont, QFontDatabase

#: Outline monospace faces, in order of preference, on every platform.
MONOSPACE = ['Consolas', 'Cascadia Mono', 'Menlo', 'SF Mono',
             'DejaVu Sans Mono', 'Liberation Mono', 'Courier New']


def monospace(point_size=None):
    """A fixed-width outline font: the first of MONOSPACE installed, else
    the platform's own fixed font."""
    font = QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)
    installed = set(QFontDatabase.families())
    families = [f for f in MONOSPACE if f in installed]
    if families:
        font.setFamilies(families)
    font.setStyleHint(QFont.StyleHint.Monospace)
    font.setFixedPitch(True)
    if point_size:
        font.setPointSize(point_size)
    return font
