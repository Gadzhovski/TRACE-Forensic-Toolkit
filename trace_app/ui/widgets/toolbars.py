"""Toolbar construction helpers.

Keeping every toolbar the same height, with its controls the same height and
vertically centred, is fiddly in Qt: a stylesheet min-height applies to the
content box, so borders and padding are added on top, and each widget class
adds a different amount. QToolButton is worse -- it sizes from its icon and
ignores a stylesheet max-height entirely.

So the outer geometry is set here, in Python, from one constant.
"""

from PySide6.QtCore import QEvent, QObject, QSize, Qt, QTimer
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
    for child in toolbar.findChildren(QToolButton):
        if child.text() and child.toolButtonStyle() != Qt.ToolButtonIconOnly:
            # Carries a label, so it needs room for the text: fix the height
            # only and let the width follow the content.
            child.setFixedHeight(CONTROL_HEIGHT)
        else:
            # Icon only: square, so the glyph sits centred in its highlight.
            child.setFixedSize(CONTROL_HEIGHT + 4, CONTROL_HEIGHT + 4)

    for cls in (QLineEdit, QComboBox, QPushButton):
        for child in toolbar.findChildren(cls):
            child.setFixedHeight(CONTROL_HEIGHT)

    for child in toolbar.findChildren(QLabel):
        child.setFixedHeight(CONTROL_HEIGHT)
        child.setAlignment(Qt.AlignVCenter | Qt.AlignLeft)


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
