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

from PySide6.QtCore import QRectF, QSize, Qt
from PySide6.QtGui import (QAction, QColor, QIcon, QIconEngine, QImage,
                           QPainter, QPixmap)
from PySide6.QtSvg import QSvgRenderer

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
#: Legacy Office compound documents (.doc/.xls/.ppt) share one container, so a
#: carved OLE file cannot be attributed to a specific application -- the Word
#: glyph stands for the family.
FILE_DOC = "Icons/mimetypes/application-vnd.ms-word.svg"
FILE_HTML = "Icons/mimetypes/text-x-html.svg"
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


def current_theme():
    """The theme name the registry is currently tinting for."""
    return _theme


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
    if tint and name.lower().endswith('.svg'):
        # Scalable: rendered from the vector at whatever size is requested.
        result = QIcon(_TintedSvgEngine(resolved, tint))
    else:
        result = QIcon(resolved)
        if result.isNull():
            # A missing icon otherwise shows as a blank button with no clue why.
            logger.warning("Icon not found: %s", resolved)

    _cache[key] = result
    return result


class _TintedSvgEngine(QIconEngine):
    """Renders an SVG at whatever size is asked for, then tints it.

    The previous approach baked the icon into pixmaps at five fixed sizes
    (16/24/32/48/64) and let QIcon pick the nearest. Anything in between was a
    scaled bitmap rather than a fresh render -- an 18px toolbar glyph came from
    the 16px bitmap -- and anything above 64px was silently capped, so a 40px
    dialog icon on a hi-DPI screen was a 64px bitmap stretched to 80.

    Rendering from the vector on demand keeps every size sharp, including the
    fractional sizes a device pixel ratio asks for.
    """

    def __init__(self, path, colour):
        super().__init__()
        self._path = path
        self._colour = colour

    def clone(self):
        return _TintedSvgEngine(self._path, self._colour)

    def paint(self, painter, rect, mode, state):
        painter.drawPixmap(rect, self.pixmap(rect.size(), mode, state))

    def scaledPixmap(self, size, mode, state, scale):
        """Render for a display scale factor.

        Qt calls this instead of pixmap() when the screen is scaled -- 125% or
        150% on Windows, a Retina display on macOS. Without it Qt falls back to
        pixmap() at the logical size and stretches the result, so a 20px icon
        on a 150% display is a 20px raster blown up to 30: exactly the
        stair-stepped edges these icons were showing. This renders at the
        device resolution and labels the pixmap so Qt draws it at the right
        logical size.
        """
        return self._render(size.width(), size.height(), scale)

    def pixmap(self, size, mode, state):
        return self._render(size.width(), size.height(), 1.0)

    def _render(self, logical_width, logical_height, scale):
        # The pixmap is allocated in device pixels, but once it carries a
        # device pixel ratio QPainter addresses it in logical ones -- so
        # everything painted below works in logical units.
        width = max(1, logical_width)
        height = max(1, logical_height)

        out = QPixmap(max(1, int(round(width * scale))),
                      max(1, int(round(height * scale))))
        out.setDevicePixelRatio(scale)
        out.fill(Qt.transparent)

        renderer = QSvgRenderer(self._path)
        if not renderer.isValid():
            return out

        painter = QPainter(out)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.setRenderHint(QPainter.SmoothPixmapTransform)
        # Keep the aspect ratio and centre, as QIcon would. width and height
        # are already device pixels, so this fits the glyph to the full
        # rendered surface -- do not reuse the `scale` parameter here.
        bounds = renderer.viewBoxF()
        if bounds.width() > 0 and bounds.height() > 0:
            fit = min(width / bounds.width(), height / bounds.height())
            drawn_w = bounds.width() * fit
            drawn_h = bounds.height() * fit
            target = QRectF((width - drawn_w) / 2, (height - drawn_h) / 2,
                            drawn_w, drawn_h)
        else:
            target = QRectF(0, 0, width, height)
        renderer.render(painter, target)

        if self._colour:
            painter.setCompositionMode(QPainter.CompositionMode_SourceIn)
            painter.fillRect(QRectF(0, 0, width, height), QColor(self._colour))
        painter.end()
        return out


#: Hue applied to a disk image's icon once its hashes verify. Green rather
#: than a separate mark: the icon itself carries the state, so nothing is
#: added beside it to shift the row out of line.
VERIFIED_HUE = '#3FB950'

#: Hue for an image whose stored and computed hashes did not match. Amber, the
#: colour the property tables already use for [state="warning"].
UNVERIFIED_HUE = '#E3A008'


def recoloured(base_path, colour, size):
    """The image at `base_path` recoloured to `colour`, keeping its shading.

    Used to show that a disk image has been verified. An overlaid badge was
    tried first and read poorly at 16px -- a second glyph crammed into the
    corner of an already small icon. Recolouring the icon itself says the same
    thing with no extra marks and no change in size.

    The artwork is near-greyscale, so each pixel keeps its own lightness and
    takes the target hue and saturation. A flat fill would turn the icon into
    a silhouette; this keeps the disc readable as a disc.
    """
    source = QIcon(base_path).pixmap(size, size).toImage()
    source = source.convertToFormat(QImage.Format_ARGB32)
    target = QColor(colour)
    hue = target.hue()
    saturation = target.saturation()

    for x in range(source.width()):
        for y in range(source.height()):
            pixel = source.pixelColor(x, y)
            if pixel.alpha() == 0:
                continue
            recolour = QColor.fromHsv(hue, saturation, pixel.value(),
                                      pixel.alpha())
            source.setPixelColor(x, y, recolour)

    result = QIcon()
    result.addPixmap(QPixmap.fromImage(source))
    return result


def clear_cache():
    """Drop cached icons, e.g. after a theme change alters the tint."""
    _cache.clear()
