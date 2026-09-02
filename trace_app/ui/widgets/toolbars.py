"""Toolbar construction helpers.

Keeping every toolbar the same height, with its controls the same height and
vertically centred, is fiddly in Qt: a stylesheet min-height applies to the
content box, so borders and padding are added on top, and each widget class
adds a different amount. QToolButton is worse -- it sizes from its icon and
ignores a stylesheet max-height entirely.

So the outer geometry is set here, in Python, from one constant.
"""

from PySide6.QtCore import QEvent, QObject, QSize, Qt, QTimer
from PySide6.QtGui import QFontMetrics
from PySide6.QtWidgets import (QComboBox, QLabel, QLineEdit, QPushButton, QSizePolicy,
                               QToolBar, QToolButton, QWidget)

from trace_app.infra.constants import (CONTROL_HEIGHT, CONTROL_SPACING, GROUP_SPACING,
                                       TOOLBAR_HEIGHT, TOOLBAR_ICON_SIZE)


class _ChildAligner(QObject):
    """Re-applies control geometry when a toolbar gains a child."""

    def eventFilter(self, watched, event):
        if event.type() == QEvent.ChildAdded:
            # Defer: the child is not laid out yet at ChildAdded time.
            QTimer.singleShot(0, lambda tb=watched: align_controls(tb))
        return False


_aligner = _ChildAligner()


def prepare_toolbar(toolbar):
    """Apply the shared height, icon size and spacing to a toolbar.

    Also watches for controls added later, so a toolbar built in stages ends
    up as consistent as one built in a single pass.
    """
    toolbar.setIconSize(QSize(TOOLBAR_ICON_SIZE, TOOLBAR_ICON_SIZE))
    toolbar.setFixedHeight(TOOLBAR_HEIGHT)
    toolbar.setMovable(False)
    toolbar.setFloatable(False)
    if not toolbar.property("_aligned"):
        toolbar.setProperty("_aligned", True)
        toolbar.installEventFilter(_aligner)
    align_controls(toolbar)
    return toolbar


def align_controls(toolbar):
    """Give every control in `toolbar` the same height, vertically centred.

    Safe to call more than once. Toolbars are populated at different points --
    some in a viewer's __init__, some later when a tab is first shown -- so
    this is also installed as an event filter by `prepare_toolbar` to catch
    widgets added after the initial pass.
    """
    button_size = CONTROL_HEIGHT + 4

    for child in toolbar.findChildren(QToolButton):
        if _is_icon_only(child):
            # Square, so the icon sits centred in its hover highlight.
            child.setFixedSize(button_size, button_size)
        else:
            # A button carrying a label -- and possibly a menu arrow -- needs
            # room for it. Squaring these clipped "Export" down to 28px.
            child.setFixedHeight(button_size)
            child.setFixedWidth(_text_button_width(child))

    for cls in (QLineEdit, QComboBox, QPushButton):
        for child in toolbar.findChildren(cls):
            child.setFixedHeight(CONTROL_HEIGHT)
            # Without a cap these expand to fill the toolbar, which is why the
            # File Carving and Registry bars looked nothing like the Listing
            # bar: their buttons and combo were rendering 640px wide.
            if child.maximumWidth() > 1000:
                child.setMaximumWidth(max(child.sizeHint().width() + 24, 120))

    for child in toolbar.findChildren(QLabel):
        child.setFixedHeight(CONTROL_HEIGHT)
        child.setAlignment(Qt.AlignVCenter | Qt.AlignLeft)
        # A QLabel in a toolbar expands to fill by default, which pushed the
        # controls after it apart -- a "of 12" label was rendering 640px wide.
        # Sizing to its content keeps every toolbar's spacing comparable.
        child.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        if child.pixmap() is not None and not child.pixmap().isNull():
            child.setFixedWidth(child.pixmap().width())
        else:
            child.adjustSize()
            child.setFixedWidth(child.sizeHint().width())


def _text_button_width(button):
    """Width a text tool button needs, including its menu arrow if it has one.

    sizeHint() under-reports for a MenuButtonPopup button, so the arrow area is
    added explicitly -- that shortfall is what clipped the "Export" label.
    """
    metrics = QFontMetrics(button.font())
    width = metrics.horizontalAdvance(button.text()) + 24  # text plus padding
    if button.menu() is not None:
        width += 20  # the drop-down arrow section
    return max(width, button.sizeHint().width())


def _is_icon_only(button):
    """True when a tool button shows an icon and no text or menu."""
    if button.toolButtonStyle() == Qt.ToolButtonTextOnly:
        return False
    if button.text() and button.toolButtonStyle() != Qt.ToolButtonIconOnly:
        return False
    if button.menu() is not None:
        return False
    return not button.icon().isNull()


def spacer(width=GROUP_SPACING):
    """A fixed-width gap between groups of controls."""
    widget = QWidget()
    widget.setFixedWidth(width)
    widget.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Preferred)
    return widget


def stretch():
    """An expanding gap that pushes what follows to the right."""
    widget = QWidget()
    widget.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
    return widget
