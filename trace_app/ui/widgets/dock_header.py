"""A dock headed by its tabs: no title strip above them, float and close at
the right end of the tab row.

Qt gives every dock a title strip ("Utils", "Tree View") above whatever the
dock holds -- for a dock of tabs that is a second row naming what the tabs
already name. The tree, the Utils tabs and the result panels' tab rows
(result_docks) all look one way: tabs on a white row, two small buttons at
its right end. Floating, a dock gets Qt's own strip back: it is what moves
the window, and a double-click on it docks it again.
"""

from PySide6.QtCore import QSize, Qt
from PySide6.QtWidgets import QHBoxLayout, QToolButton, QWidget

from trace_app.ui import icons

#: The buttons' glyph size.
ICON_SIZE = 14


def corner(parent, float_slot, close_slot, what):
    """The float and close buttons, in a row (objectName dockHeaderCorner;
    the buttons dockHeaderButton). `what` names the panel in the tips."""
    row_widget = QWidget(parent)
    row_widget.setObjectName('dockHeaderCorner')
    row = QHBoxLayout(row_widget)
    row.setContentsMargins(0, 0, 4, 0)
    row.setSpacing(2)
    for glyph, slot in ((icons.EXTERNAL_LINK, float_slot),
                        (icons.CLOSE, close_slot)):
        button = QToolButton(row_widget)
        button.setObjectName('dockHeaderButton')
        button.setIcon(icons.icon(glyph))
        button.setIconSize(QSize(ICON_SIZE, ICON_SIZE))
        button.setAutoRaise(True)
        button.clicked.connect(slot)
        row.addWidget(button)
    name(row_widget, what)
    return row_widget


def name(row_widget, what):
    """Say in the buttons' tips which panel they act on."""
    float_button, close_button = row_widget.findChildren(QToolButton)
    float_button.setToolTip(f"Float {what} in a window of its own")
    close_button.setToolTip(f"Close {what} (View ▸ Panels reopens it)")


def head_with_tabs(dock, tabs, what):
    """Make the QTabWidget `tabs` (the dock's widget) the dock's header:
    its row white edge to edge (property dockHeader, the themes), float and
    close in its top-right corner, Qt's title strip hidden while docked."""
    tabs.setProperty('dockHeader', True)
    # A QTabWidget paints the theme's background only when asked: without
    # this the dock's grey showed right of the tabs.
    tabs.setAttribute(Qt.WA_StyledBackground, True)
    # A property selector is read when the widget is polished, and adding
    # tabs polishes it: polished again, or the themes' general QTabWidget
    # frame stays and draws a faint box right of the tabs.
    tabs.style().unpolish(tabs)
    tabs.style().polish(tabs)
    buttons = corner(tabs, lambda: dock.setFloating(True), dock.close, what)
    tabs.setCornerWidget(buttons, Qt.TopRightCorner)

    def title(floating):
        hidden = dock.titleBarWidget() is not None
        if not floating and not hidden:
            strip = QWidget(dock)
            strip.setObjectName('hiddenDockTitle')
            dock.setTitleBarWidget(strip)
        elif floating and hidden:
            old = dock.titleBarWidget()
            dock.setTitleBarWidget(None)
            old.deleteLater()
        buttons.setVisible(not floating)

    dock.topLevelChanged.connect(title)
    title(dock.isFloating())
    return buttons
