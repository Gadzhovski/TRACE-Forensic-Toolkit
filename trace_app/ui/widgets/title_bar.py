"""Windows' title bars in TRACE's theme.

Windows draws every window's title bar itself: grey, square on Windows 10,
white even on the dark theme. Windows 11 lets an application colour it
through DWM (DwmSetWindowAttribute): the caption in the menu bar's colour,
so title and menu bar read as one header; the title text and border in the
theme's; rounded corners asked for. Windows 10 takes the dark mode only
(it ignores the rest, harmlessly). The bar stays Windows' own, so snapping,
the snap-layouts flyout, double-click to maximise, accessibility and moves
between screens of different DPI all work as in any other program.

An application-wide event filter themes each top-level window as it is
shown (Qt sends Show before the native window appears, so it never flashes
white) and dims the title when the window loses focus, as Windows does;
`refresh()` re-themes every open window on a theme switch. Frameless
windows (splash, progress cards, popups) have no bar and are left alone.
Nothing happens off Windows.
"""

import ctypes
import logging
import sys

from PySide6.QtCore import QEvent, QObject, Qt, QTimer, Slot
from PySide6.QtWidgets import QApplication

logger = logging.getLogger('TRACE.TitleBar')

#: DwmSetWindowAttribute attributes (dwmapi.h).
DARK_MODE = 20                  # DWMWA_USE_IMMERSIVE_DARK_MODE
DARK_MODE_OLD = 19              # the same before Windows 10 build 18985
CORNERS = 33                    # DWMWA_WINDOW_CORNER_PREFERENCE
BORDER_COLOUR = 34              # DWMWA_BORDER_COLOR
CAPTION_COLOUR = 35             # DWMWA_CAPTION_COLOR
TEXT_COLOUR = 36                # DWMWA_TEXT_COLOR
ROUND = 2                       # DWMWCP_ROUND

#: Per theme: the caption is the menu bar's colour (both themes' QMenuBar
#: rule), the text the theme's foreground, dimmed while the window is not
#: the active one.
COLOURS = {
    'dark': {'caption': '#3C3C3C', 'text': '#E0E0E0',
             'inactive': '#9A9A9A', 'border': '#4A4A4A'},
    'light': {'caption': '#FFFFFF', 'text': '#1F1F1F',
              'inactive': '#8A8A8A', 'border': '#D0D0D0'},
}

_WATCHED = frozenset((QEvent.Show, QEvent.ActivationChange))
_filter = None
_dwm = None


def supported():
    """On Windows, with Windows' own windows (offscreen -- the tests --
    has no window handles to give DWM)."""
    if sys.platform != 'win32':
        return False
    from PySide6.QtGui import QGuiApplication
    return QGuiApplication.platformName() == 'windows'


def colorref(colour):
    """'#RRGGBB' as a Win32 COLORREF (0x00BBGGRR)."""
    value = colour.lstrip('#')
    red, green, blue = (int(value[i:i + 2], 16) for i in (0, 2, 4))
    return red | green << 8 | blue << 16


def _set(hwnd, attribute, value):
    """One DWM attribute; False when Windows refuses it (an older
    Windows that does not know it)."""
    global _dwm
    if _dwm is None:
        _dwm = ctypes.windll.dwmapi
    data = ctypes.c_int(value)
    result = _dwm.DwmSetWindowAttribute(
        ctypes.c_void_p(hwnd), ctypes.c_uint(attribute),
        ctypes.byref(data), ctypes.c_uint(ctypes.sizeof(data)))
    return result == 0


def has_bar(widget):
    """A top-level window Windows gives a title bar."""
    if not widget.isWidgetType() or not widget.isWindow():
        return False
    if widget.windowType() not in (Qt.Window, Qt.Dialog):
        return False
    return not widget.windowFlags() & Qt.FramelessWindowHint


def theme_window(widget, theme=None, active=None):
    """Colour `widget`'s title bar for `theme` (the icons' current theme
    by default). Never raises: a title bar is not worth an error."""
    if not supported() or not has_bar(widget):
        return
    if theme is None:
        from trace_app.ui import icons
        theme = icons.current_theme()
    colours = COLOURS.get(theme, COLOURS['light'])
    if active is None:
        active = widget.isActiveWindow()
    try:
        hwnd = int(widget.winId())
        dark = 1 if theme == 'dark' else 0
        if not _set(hwnd, DARK_MODE, dark):
            _set(hwnd, DARK_MODE_OLD, dark)
        _set(hwnd, CORNERS, ROUND)
        _set(hwnd, CAPTION_COLOUR, colorref(colours['caption']))
        _set(hwnd, BORDER_COLOUR, colorref(colours['border']))
        _set(hwnd, TEXT_COLOUR, colorref(
            colours['text'] if active else colours['inactive']))
    except Exception as exc:
        logger.debug("Title bar not themed: %s", exc)


def refresh(theme=None):
    """Every open window's title bar in `theme` (after a theme switch)."""
    if not supported():
        return
    for widget in QApplication.topLevelWidgets():
        if widget.isVisible():
            theme_window(widget, theme)


class _Themer(QObject):
    @Slot()
    def later(self, *_):
        QTimer.singleShot(0, refresh)

    def eventFilter(self, watched, event):
        # Sees every event of the application: anything else leaves at once.
        if event.type() not in _WATCHED:
            return False
        if has_bar(watched):
            theme_window(watched)
        return False


def install(app=None):
    """Theme every window's title bar from now on, once (Windows only)."""
    global _filter
    app = app or QApplication.instance()
    if _filter is None and app is not None and supported():
        _filter = _Themer(app)
        app.installEventFilter(_filter)
        # Qt sets each window's dark flag from the system's own scheme
        # when that changes: put TRACE's theme back once it has.
        app.styleHints().colorSchemeChanged.connect(_filter.later)
