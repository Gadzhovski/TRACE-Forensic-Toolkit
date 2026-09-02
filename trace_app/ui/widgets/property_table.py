"""A two-column key/value table.

Several panes (file metadata, EXIF tags, registry value details) previously
rendered their content as hand-built HTML strings inside a QTextEdit. Qt's rich
text does not inherit the application stylesheet, so those panes ignored the
theme entirely and were hard to read in dark mode. They also could not be
selected cleanly -- copying a single hash out of the metadata pane did not
work, which matters in a forensic tool.

A real table fixes all of that: it is styled by the theme like every other
widget, its cells are individually selectable and copyable, and the columns can
be resized.
"""

from PySide6.QtCore import Qt
from PySide6.QtGui import QGuiApplication, QKeySequence, QShortcut
from PySide6.QtWidgets import (QAbstractItemView, QHeaderView, QTableWidget,
                               QTableWidgetItem)


class PropertyTable(QTableWidget):
    """Read-only two-column table of name/value pairs."""

    def __init__(self, key_header="Property", value_header="Value", parent=None):
        super().__init__(0, 2, parent)
        self.setObjectName("propertyTable")
        self.setHorizontalHeaderLabels([key_header, value_header])

        self.verticalHeader().setVisible(False)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.setSelectionBehavior(QAbstractItemView.SelectItems)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setAlternatingRowColors(True)
        self.setWordWrap(False)
        self.setShowGrid(False)

        header = self.horizontalHeader()
        header.setObjectName("propertyTableHeader")
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        header.setHighlightSections(False)

        # Ctrl+C copies the selection as tab-separated text, so a hash or a
        # whole block of properties can be pasted into a report.
        copy = QShortcut(QKeySequence.Copy, self)
        copy.activated.connect(self.copy_selection)

    def set_rows(self, rows):
        """Replace the contents. `rows` is an iterable of (name, value) pairs.

        A row may instead be (name, value, tag) where tag names a QSS state,
        e.g. "warning", applied via a `state` property on both cells.
        """
        self.setRowCount(0)
        self.setRowCount(len(rows))
        for r, row in enumerate(rows):
            name, value = row[0], row[1]
            tag = row[2] if len(row) > 2 else None

            key_item = QTableWidgetItem(str(name))
            key_item.setToolTip(str(name))
            val_item = QTableWidgetItem("" if value is None else str(value))
            val_item.setToolTip(val_item.text())

            for item in (key_item, val_item):
                item.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
                if tag:
                    item.setData(Qt.UserRole + 1, tag)

            self.setItem(r, 0, key_item)
            self.setItem(r, 1, val_item)

    def copy_selection(self):
        """Copy selected cells as tab-separated rows."""
        ranges = self.selectedRanges()
        if not ranges:
            return
        lines = []
        for rng in ranges:
            for row in range(rng.topRow(), rng.bottomRow() + 1):
                cells = []
                for col in range(rng.leftColumn(), rng.rightColumn() + 1):
                    item = self.item(row, col)
                    cells.append(item.text() if item else "")
                lines.append("\t".join(cells))
        QGuiApplication.clipboard().setText("\n".join(lines))

    def clear_rows(self):
        self.setRowCount(0)
