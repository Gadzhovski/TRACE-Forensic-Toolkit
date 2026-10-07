"""One behaviour for every table, tree and list in TRACE.

Each view used to choose for itself, and most chose nothing: Qt's default
scrolls a whole column per click, so the Listing (set to per-pixel) slid
while Triage and the rest jumped a column at a time; and a table narrower
than its pane ended in a band of empty white after its last column. Set
once here, for every view as Qt polishes it -- a dialog's, a panel's, and
any added later -- rather than in each of the forty places that make one:

* scrolling by pixels, horizontally and vertically;
* a table's last column takes the space the others leave.

A view that wants otherwise can still set it after construction; polish
happens once, before the view is first shown.
"""

from PySide6.QtGui import QPalette
from PySide6.QtWidgets import (QAbstractItemView, QApplication, QHeaderView,
                               QProxyStyle, QTableView)


def configure(view):
    """The shared behaviour, on one view."""
    view.setHorizontalScrollMode(QAbstractItemView.ScrollPerPixel)
    view.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)
    if isinstance(view, QTableView):
        view.horizontalHeader().setStretchLastSection(True)


class ItemViewStyle(QProxyStyle):
    """The application's own style, with `configure` applied to every item
    view it polishes. Header views are item views too, and are left
    alone."""

    def polish(self, target):
        if isinstance(target, QPalette):
            return super().polish(target)
        super().polish(target)
        if isinstance(target, QAbstractItemView) and \
                not isinstance(target, QHeaderView):
            configure(target)
        return None


def install(app=None):
    """Put ItemViewStyle on the application, once. Views that already exist
    are polished again by Qt, so they get it too."""
    app = app or QApplication.instance()
    # Ctrl+C and a Copy menu for every list, table and tree.
    from trace_app.ui.widgets import context_menus
    context_menus.install(app)
    # Asked by a property, not by app.style(): with a stylesheet set, Qt
    # answers with its stylesheet wrapper rather than the style beneath.
    if app is None or app.property('traceItemViewStyle'):
        return
    app.setStyle(ItemViewStyle())
    app.setProperty('traceItemViewStyle', True)
