"""Preview a table's row on a single click or an arrow key.

Reviewing findings, search hits or bookmarks is a matter of stepping down a
list and reading each file. When opening one meant a double-click that also
switched to the Listing tab, every file cost two tab switches. These tables
now report the row the examiner lands on, and the host shows that file in the
viewers without leaving the tab; double-click keeps meaning "take me to its
folder".
"""

from PySide6.QtCore import Qt


def connect_row_preview(table, emit):
    """Call `emit(payload)` for the row the selection moves to or is clicked.

    The payload is what the row's first cell holds under Qt.UserRole. Both
    signals are needed: selection covers the arrow keys, and a click on the
    row that is already selected -- after looking at something else -- does
    not change the selection. The host ignores a repeat of what it is already
    showing, so a click that fires both costs one read, not two.
    """
    def fire(*_args):
        items = table.selectedItems()
        if not items:
            return
        cell = table.item(items[0].row(), 0)
        payload = cell.data(Qt.UserRole) if cell is not None else None
        if payload:
            emit(payload)

    table.itemSelectionChanged.connect(fire)
    table.itemClicked.connect(fire)
