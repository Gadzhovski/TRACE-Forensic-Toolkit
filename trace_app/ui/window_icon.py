"""TRACE's logo on the Windows taskbar, for every window, even a busy one.

A Windows window carries three icons: its own big and small ones (Qt sets
both from the application icon) and its window *class's* icon -- which Qt
leaves as its generic window picture. The taskbar asks a window for its
icon with a timeout and, when the window does not answer in time, takes the
class icon instead and keeps it. The launcher is idle and answers; the main
window is busy building itself and reopening the case's evidence just as
the taskbar asks, so its button showed the generic picture.

`apply` sets the class icons to the logo too, so even the fallback is
right, and sends the window's own icons again, which makes the taskbar
refresh what it cached. Nothing happens off Windows.
"""

import logging
import sys

from PySide6.QtCore import QSize
from PySide6.QtWidgets import QApplication

logger = logging.getLogger('TRACE.WindowIcon')

WM_SETICON = 0x0080
ICON_SMALL, ICON_BIG = 0, 1
GCLP_HICON, GCLP_HICONSM = -14, -34

#: HICONs handed to Windows are kept: the class and the window refer to
#: them for as long as the process runs.
_HANDLES = []


def _hicon(icon, side):
    image = icon.pixmap(QSize(side, side)).toImage()
    return image.toHICON() if not image.isNull() else None


def apply(widget, icon=None):
    """Give `widget`'s native window -- and its class -- TRACE's icon."""
    if sys.platform != 'win32':
        return False
    icon = icon or QApplication.windowIcon()
    if icon is None or icon.isNull():
        return False
    try:
        import ctypes
        from ctypes import wintypes
        user32 = ctypes.windll.user32
        user32.SendMessageW.restype = ctypes.c_void_p
        user32.SendMessageW.argtypes = [wintypes.HWND, ctypes.c_uint,
                                        ctypes.c_void_p, ctypes.c_void_p]
        user32.SetClassLongPtrW.restype = ctypes.c_void_p
        user32.SetClassLongPtrW.argtypes = [wintypes.HWND, ctypes.c_int,
                                            ctypes.c_void_p]
        metrics = user32.GetSystemMetrics
        big = _hicon(icon, max(32, metrics(11)))         # SM_CXICON
        small = _hicon(icon, max(16, metrics(49)))       # SM_CXSMICON
        if not big or not small:
            return False
        _HANDLES.extend((big, small))
        hwnd = int(widget.winId())
        user32.SetClassLongPtrW(hwnd, GCLP_HICON, big)
        user32.SetClassLongPtrW(hwnd, GCLP_HICONSM, small)
        user32.SendMessageW(hwnd, WM_SETICON, ICON_BIG, big)
        user32.SendMessageW(hwnd, WM_SETICON, ICON_SMALL, small)
        return True
    except Exception as exc:          # an icon must never stop the window
        logger.debug("Taskbar icon not set: %s", exc)
        return False
