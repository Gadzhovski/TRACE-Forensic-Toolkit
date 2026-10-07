"""Programs shown with their own icons in the tree and the Listing.

A Windows program (.exe, .scr, .cpl) carries its icon in its resources --
Discord's, a browser's, the malware's that copies Word's -- and an .ico
file is one. The file-type icon said only "program"; this reads the real
one (core/pe_icons.py: a few small reads, never the whole file) on the
thumbnail thread and sets it on every row showing that file as it
arrives. Read once per file per session; a program with no icon keeps its
file-type icon.
"""

import logging

from PySide6.QtCore import QObject
from PySide6.QtGui import QIcon, QPixmap

from trace_app.core.pe_icons import is_program, program_icon
from trace_app.ui.widgets import thumbnails as thumbs

logger = logging.getLogger('TRACE.ProgramIcons')

#: The size the small icons are made at (shown at 16, sharp at 2x).
SMALL = 32
#: An .ico file larger than this is not read for a row's icon.
MAX_ICO_BYTES = 1024 * 1024


def has_own_icon(name):
    """Whether a file named `name` may carry an icon of its own."""
    return is_program(name) or (name or '').lower().endswith('.ico')


def icon_bytes(name, read, size, file_size=None):
    """The icon of the file named `name` -- `read(offset, length)` reads it
    -- as bytes an image reader opens, or None."""
    if (name or '').lower().endswith('.ico'):
        if file_size is not None and file_size > MAX_ICO_BYTES:
            return None
        return read(0, file_size or MAX_ICO_BYTES)
    return program_icon(read, size)


class ProgramIcons(QObject):
    """Fetches and caches programs' icons for the window's rows."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._loader = thumbs.ThumbnailLoader(self)
        self._loader.ready.connect(self._ready)
        self._cache = {}            # key -> QIcon, or None: has none
        self._waiting = {}          # key -> [set_icon(QIcon)]

    def apply(self, key, name, read_factory, set_icon, file_size=None):
        """Give the row its file's own icon when there is one.
        `read_factory()` (run on the thumbnail thread) returns
        `read(offset, length)` for the file."""
        if not has_own_icon(name):
            return
        if key in self._cache:
            icon = self._cache[key]
            if icon is not None:
                self._set(set_icon, icon)
            return
        first = key not in self._waiting
        self._waiting.setdefault(key, []).append(set_icon)
        if first:
            self._loader.request(
                key, thumbs.PICTURE, SMALL,
                lambda: self._read(name, read_factory, file_size))

    @staticmethod
    def _read(name, read_factory, file_size):
        read = read_factory()
        if read is None:
            return None
        return icon_bytes(name, read, SMALL, file_size)

    def _ready(self, key, image):
        icon = QIcon(QPixmap.fromImage(image)) if not image.isNull() \
            else None
        self._cache[key] = icon
        for set_icon in self._waiting.pop(key, ()):
            if icon is not None:
                self._set(set_icon, icon)

    @staticmethod
    def _set(set_icon, icon):
        try:
            set_icon(icon)
        except RuntimeError:
            pass            # the row is gone: the folder was left

    def forget(self):
        """Forget every icon (evidence closed)."""
        self._cache.clear()
        self._waiting.clear()
        self._loader.clear()
