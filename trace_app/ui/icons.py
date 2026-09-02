"""Central icon registry.

Every icon used in the UI is named here once, so swapping icon sets is a change
to this file rather than a search-and-replace across a dozen modules. Call
sites refer to icons by meaning (``icons.BACK``) rather than by filename.

Two practical consequences:

* Changing the icon set — or reverting to the previous one — means editing the
  table below and nothing else.
* Monochrome SVGs can be tinted to suit the active theme, so a single set
  serves both light and dark. Raster icons are returned unchanged.
"""

import logging

from PySide6.QtCore import QSize, Qt
from PySide6.QtGui import QColor, QIcon, QPainter, QPixmap

from trace_app.infra.paths import resource_path

logger = logging.getLogger('TRACE.Icons')

# --- Application -----------------------------------------------------------
LOGO = "Icons/logo.png"
LOGO_LARGE = "Icons/logo_prev_ui.png"
VIRUSTOTAL_LOGO = "Icons/VirusTotal_logo.svg"

# --- Evidence --------------------------------------------------------------
EVIDENCE_ADD = "Icons/tabler/file-plus.svg"
EVIDENCE_REMOVE = "Icons/tabler/file-minus.svg"
VERIFY = "Icons/tabler/shield-check.svg"
VERIFY_OK = "Icons/tabler/shield-check-filled.svg"

# --- Navigation ------------------------------------------------------------
BACK = "Icons/tabler/arrow-left.svg"
FORWARD = "Icons/tabler/arrow-right.svg"
UP = "Icons/tabler/arrow-up.svg"
DOWN = "Icons/tabler/arrow-down.svg"

# --- Media transport -------------------------------------------------------
# The media player previously tried several filenames in turn and fell back to
# a text label, because names like "Icons/play.png" were referenced but had
# never existed in the repository. These point at the files that are actually
# present, so the buttons render.
PLAY = "Icons/tabler/player-play.svg"
PAUSE = "Icons/tabler/player-pause.svg"
STOP = "Icons/tabler/player-stop.svg"
VOLUME = "Icons/tabler/volume.svg"
MUTE = "Icons/tabler/volume-off.svg"
AUDIO = "Icons/tabler/music.svg"

# --- View / zoom -----------------------------------------------------------
ZOOM_IN = "Icons/tabler/zoom-in.svg"
ZOOM_OUT = "Icons/tabler/zoom-out.svg"
ZOOM_ACTUAL = "Icons/tabler/zoom-reset.svg"
FIT_WIDTH = "Icons/tabler/arrows-horizontal.svg"
FIT_WINDOW = "Icons/tabler/arrows-maximize.svg"
ICONS_SMALL = "Icons/tabler/layout-grid.svg"
ICONS_MEDIUM = "Icons/tabler/layout-grid.svg"
ICONS_LARGE = "Icons/tabler/layout-board.svg"

# --- Editing / actions -----------------------------------------------------
ROTATE_LEFT = "Icons/tabler/rotate-2.svg"
ROTATE_RIGHT = "Icons/tabler/rotate-clockwise-2.svg"
ROTATE_RESET = "Icons/tabler/rotate-rectangle.svg"
PRINT = "Icons/tabler/printer.svg"
SAVE_AS = "Icons/tabler/device-floppy.svg"
SEARCH_BROWSER = "Icons/tabler/world-search.svg"
PAN = "Icons/tabler/hand-move.svg"

# --- Domain ----------------------------------------------------------------
CARVING = "Icons/tabler/file-search.svg"
REGISTRY = "Icons/tabler/database.svg"
REGISTRY_HIVE = "Icons/tabler/folder.svg"
REGISTRY_KEY = "Icons/tabler/key.svg"
REGISTRY_VALUE = "Icons/tabler/tag.svg"

# --- Generic fallbacks (resolved through the icon database elsewhere) ------
FILE_UNKNOWN = "Icons/mimetypes/application-x-zerosize.svg"
FILE_ARCHIVE = "Icons/mimetypes/application-zip.svg"
FILE_AUDIO = "Icons/mimetypes/audio-x-generic.svg"
FILE_VIDEO = "Icons/mimetypes/video-x-generic.svg"
WEB_BROWSER = "Icons/apps/internet-web-browser.svg"


_cache = {}

# Foreground colour icons are tinted to, per theme. Monochrome SVGs (Tabler
# uses stroke="currentColor", which Qt renders as black) would otherwise be
# invisible on a dark background.
_THEME_TINTS = {
    'light': '#3C3C3C',
    'dark': '#D0D0D0',
}
_theme = 'light'


def set_theme(theme):
    """Tell the registry which theme is active, so tints follow it."""
    global _theme
    if theme != _theme:
        _theme = theme
        clear_cache()


def _auto_tint(name):
    """Tint for `name` under the current theme, or None to leave it alone.

    Only monochrome line art is tinted. Anything that carries its own colours
    -- logos, the file-type icons from the themed set -- is left as authored.
    """
    if not name.startswith('Icons/tabler/'):
        return None
    return _THEME_TINTS.get(_theme)


def path(name):
    """Absolute path for a registry entry."""
    return resource_path(name)


def icon(name, tint=None):
    """QIcon for a registry entry, optionally tinted.

    `tint` recolours the icon, which only makes sense for monochrome art. It is
    ignored for icons that carry their own colours. Results are cached, since
    the same icon is often requested for every row of a table.
    """
    if tint is None:
        tint = _auto_tint(name)

    key = (name, tint)
    if key in _cache:
        return _cache[key]

    resolved = resource_path(name)
    result = QIcon(resolved)
    if result.isNull():
        # A missing icon otherwise shows as a blank button with no clue why.
        logger.warning("Icon not found: %s", resolved)
    elif tint:
        result = _tinted(result, tint)

    _cache[key] = result
    return result


def _tinted(source, colour):
    """Recolour an icon's opaque pixels, preserving its alpha channel."""
    tinted = QIcon()
    for size in (16, 24, 32, 48, 64):
        pixmap = source.pixmap(QSize(size, size))
        if pixmap.isNull():
            continue
        out = QPixmap(pixmap.size())
        out.fill(Qt.transparent)
        painter = QPainter(out)
        painter.drawPixmap(0, 0, pixmap)
        painter.setCompositionMode(QPainter.CompositionMode_SourceIn)
        painter.fillRect(out.rect(), QColor(colour))
        painter.end()
        tinted.addPixmap(out)
    return tinted


def clear_cache():
    """Drop cached icons, e.g. after a theme change alters the tint."""
    _cache.clear()
