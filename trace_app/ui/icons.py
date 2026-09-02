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
EVIDENCE_ADD = "Icons/icons8-evidence-48.png"
EVIDENCE_REMOVE = "Icons/icons8-evidence-96.png"
VERIFY = "Icons/icons8-verify-blue.png"
VERIFY_OK = "Icons/icons8-verify-48_gren.png"

# --- Navigation ------------------------------------------------------------
BACK = "Icons/icons8-left-arrow-50.png"
FORWARD = "Icons/icons8-right-arrow-50.png"
UP = "Icons/icons8-thick-arrow-pointing-up-50.png"
DOWN = "Icons/icons8-down-50.png"

# --- Media transport -------------------------------------------------------
# The media player previously tried several filenames in turn and fell back to
# a text label, because names like "Icons/play.png" were referenced but had
# never existed in the repository. These point at the files that are actually
# present, so the buttons render.
PLAY = "Icons/icons8-circled-play-50.png"
PAUSE = "Icons/icons8-pause-button-50.png"
STOP = "Icons/icons8-stop-circled-50.png"
VOLUME = "Icons/icons8-low-volume-50.png"
MUTE = "Icons/icons8-mute-50.png"
AUDIO = "Icons/icons8-audio-50.png"

# --- View / zoom -----------------------------------------------------------
ZOOM_IN = "Icons/icons8-zoom-in-50.png"
ZOOM_OUT = "Icons/icons8-zoom-out-50.png"
ZOOM_ACTUAL = "Icons/icons8-zoom-to-actual-size-50.png"
FIT_WIDTH = "Icons/icons8-resize-horizontal-50.png"
FIT_WINDOW = "Icons/icons8-enlarge-50.png"
ICONS_SMALL = "Icons/icons8-small-icons-50.png"
ICONS_MEDIUM = "Icons/icons8-medium-icons-50.png"
ICONS_LARGE = "Icons/icons8-large-icons-50.png"

# --- Editing / actions -----------------------------------------------------
ROTATE_LEFT = "Icons/icons8-rotate-left-50.png"
ROTATE_RIGHT = "Icons/icons8-rotate-right-50.png"
ROTATE_RESET = "Icons/icons8-no-rotation-50.png"
PRINT = "Icons/icons8-print-50.png"
SAVE_AS = "Icons/icons8-save-as-50.png"
SEARCH_BROWSER = "Icons/icons8-search-in-browser-50.png"
PAN = "Icons/icons8-drag-50.png"

# --- Domain ----------------------------------------------------------------
CARVING = "Icons/icons8-carving-64.png"
REGISTRY = "Icons/icons8-registry-editor-96.png"
REGISTRY_HIVE = "Icons/icons8-hive-48.png"
REGISTRY_KEY = "Icons/icons8-key-48_blue.png"
REGISTRY_VALUE = "Icons/icons8-wasp-48.png"

# --- Generic fallbacks (resolved through the icon database elsewhere) ------
FILE_UNKNOWN = "Icons/mimetypes/application-x-zerosize.svg"
FILE_ARCHIVE = "Icons/mimetypes/application-zip.svg"
FILE_AUDIO = "Icons/mimetypes/audio-x-generic.svg"
FILE_VIDEO = "Icons/mimetypes/video-x-generic.svg"
WEB_BROWSER = "Icons/apps/internet-web-browser.svg"


_cache = {}


def path(name):
    """Absolute path for a registry entry."""
    return resource_path(name)


def icon(name, tint=None):
    """QIcon for a registry entry, optionally tinted.

    `tint` recolours the icon, which only makes sense for monochrome art. It is
    ignored for icons that carry their own colours. Results are cached, since
    the same icon is often requested for every row of a table.
    """
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
