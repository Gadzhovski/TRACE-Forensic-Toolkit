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
from weakref import WeakKeyDictionary

from PySide6.QtCore import QSize, Qt
from PySide6.QtGui import QAction, QColor, QIcon, QPainter, QPixmap

from trace_app.infra.paths import resource_path

logger = logging.getLogger('TRACE.Icons')

# --- Application -----------------------------------------------------------
LOGO = "Icons/logo.png"
LOGO_LARGE = "Icons/logo_prev_ui.png"
VIRUSTOTAL_LOGO = "Icons/tabler/virustotal-wordmark.svg"
HELP = "Icons/tabler/help-circle.svg"

# --- Dialogs ---------------------------------------------------------------
# Used by trace_app/ui/dialogs/message.py in place of Qt's own platform icons.
ALERT = "Icons/tabler/alert-triangle.svg"
ERROR = "Icons/tabler/alert-circle.svg"
INFO = "Icons/tabler/info-circle.svg"
SUCCESS = "Icons/tabler/circle-check.svg"

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


#: Widgets handed a tinted icon, so they can be re-tinted on a theme change.
#: Held weakly: registering a widget here must not keep it alive.
_tracked_actions = WeakKeyDictionary()
_tracked_labels = WeakKeyDictionary()
_tracked_svg = WeakKeyDictionary()


def set_theme(theme):
    """Switch themes: drop cached icons and re-tint everything already placed.

    Tinting happens when an icon is handed out, so a theme change has to reach
    back to the widgets already holding one. Tracking them here means a call
    site cannot forget to refresh -- using the registry is enough.
    """
    global _theme
    if theme == _theme:
        return
    _theme = theme
    clear_cache()

    for action, name in list(_tracked_actions.items()):
        try:
            action.setIcon(icon(name))
        except RuntimeError:
            pass  # the underlying C++ object is gone

    for label, (name, size) in list(_tracked_labels.items()):
        try:
            label.setPixmap(icon(name).pixmap(size, size))
        except RuntimeError:
            pass

    for widget, name in list(_tracked_svg.items()):
        try:
            widget.load(_recoloured_svg(name, foreground()))
        except RuntimeError:
            pass


def apply_to(action, name):
    """Set an action's icon and keep it in step with later theme changes."""
    action.setIcon(icon(name))
    _tracked_actions[action] = name
    return action


def apply_pixmap(label, name, size):
    """Set a label's pixmap and keep it in step with later theme changes."""
    label.setPixmap(icon(name).pixmap(size, size))
    _tracked_labels[label] = (name, size)
    return label


def action(name, text, parent=None):
    """Build a QAction whose icon follows the theme.

    Use this instead of ``QAction(icons.icon(NAME), ...)``: the action is
    registered, so its icon is re-tinted when the theme changes.
    """
    result = QAction(icon(name), text, parent)
    _tracked_actions[result] = name
    return result


def _auto_tint(name):
    """Tint for `name` under the current theme, or None to leave it alone.

    Only monochrome line art is tinted. Anything that carries its own colours
    -- logos, the file-type icons from the themed set -- is left as authored.
    """
    if not name.startswith('Icons/tabler/'):
        return None
    return _THEME_TINTS.get(_theme)


def foreground():
    """The colour monochrome art is tinted to under the current theme."""
    return _THEME_TINTS[_theme]


def _recoloured_svg(name, colour):
    """Read an SVG and substitute `currentColor`, returning raw bytes.

    Qt's SVG renderer does not resolve `currentColor` -- it paints it black,
    which is invisible on a dark background. Icons drawn as a QIcon get around
    this by compositing a tint over the alpha channel, but that path renders at
    square sizes and would squash a wide wordmark. Substituting the colour in
    the markup keeps the aspect ratio intact.
    """
    try:
        markup = open(resource_path(name), encoding='utf-8').read()
    except OSError:
        logger.warning("Icon not found: %s", name)
        return b''
    return markup.replace('currentColor', colour).encode('utf-8')


def apply_svg(widget, name):
    """Load a themed SVG into a QSvgWidget and keep it following the theme."""
    widget.load(_recoloured_svg(name, foreground()))
    _tracked_svg[widget] = name
    return widget


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


def badged(base_path, badge_name, size, gap=3):
    """A QIcon of `badge_name` followed by the image at `base_path`.

    The verification mark used to live in a second tree column, which put it
    after the row's text. Reading left to right, the state of a thing belongs
    before the thing, so the two are composited into one pixmap and drawn in
    column 0 -- the badge first, then the disk icon.

    `base_path` is a filesystem path (the tree gets its icons from the icon
    database, not this registry); `badge_name` is a registry entry, so the
    badge is tinted for the current theme.
    """
    badge = icon(badge_name).pixmap(size, size)
    base = QIcon(base_path).pixmap(size, size)

    width = size * 2 + gap
    canvas = QPixmap(width, size)
    canvas.fill(Qt.transparent)

    painter = QPainter(canvas)
    painter.drawPixmap(0, 0, badge)
    painter.drawPixmap(size + gap, 0, base)
    painter.end()

    result = QIcon()
    result.addPixmap(canvas)
    return result


def clear_cache():
    """Drop cached icons, e.g. after a theme change alters the tint."""
    _cache.clear()
