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

The presentation is deliberately quiet. A properties pane is read, not
navigated, so it drops the column headers, the grid and the alternating row
stripes that a data table wants, and instead leans on a right-aligned label
column against a left-aligned value column. Long identifiers -- hashes,
offsets -- are shown in a monospaced font so digits line up and a mistyped
character is visible.
"""

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QFontDatabase, QGuiApplication, QKeySequence, QShortcut
from PySide6.QtWidgets import (QAbstractItemView, QHeaderView, QTableWidget,
                               QTableWidgetItem)

from trace_app.infra.constants import TABLE_ROW_HEIGHT

#: Values shown in a monospaced font: anything where character alignment helps.
MONO_LABELS = {
    'md5', 'sha-1', 'sha1', 'sha-256', 'sha256', 'disk offset', 'inode',
    'size', 'offset',
}


class PropertyTable(QTableWidget):
    """Read-only two-column table of name/value pairs."""

    def __init__(self, key_header="Property", value_header="Value", parent=None):
        super().__init__(0, 2, parent)
        self.setObjectName("propertyTable")

        # A properties pane reads as a list, not a spreadsheet: no headers, no
        # grid, no row stripes.
        self.horizontalHeader().setVisible(False)
        self.verticalHeader().setVisible(False)
        self.setShowGrid(False)
        self.setAlternatingRowColors(False)
        self.setFrameShape(QTableWidget.NoFrame)

        self.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.setSelectionBehavior(QAbstractItemView.SelectItems)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setWordWrap(False)
        self.setTextElideMode(Qt.ElideRight)

        header = self.horizontalHeader()
        header.setObjectName("propertyTableHeader")
        header.setSectionResizeMode(0, QHeaderView.Fixed)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        header.setHighlightSections(False)
        self.setColumnWidth(0, 160)

        self.verticalHeader().setDefaultSectionSize(TABLE_ROW_HEIGHT)
        self.verticalHeader().setSectionResizeMode(QHeaderView.Fixed)

        self._mono = QFontDatabase.systemFont(QFontDatabase.FixedFont)

        # Ctrl+C copies the selection as tab-separated text, so a hash or a
        # whole block of properties can be pasted into a report.
        copy = QShortcut(QKeySequence.Copy, self)
        copy.activated.connect(self.copy_selection)

    def set_rows(self, rows):
        """Replace the contents.

        `rows` is an iterable of (name, value) pairs. A row may instead be:

        * ``(name, value, tag)`` where tag names a QSS state such as
          ``"warning"``, applied via a ``state`` property on both cells; or
        * ``(None, heading)`` -- a section heading spanning both columns, used
          to group related properties.
        """
        self.clearSpans()
        self.setRowCount(0)
        self.setRowCount(len(rows))

        for index, row in enumerate(rows):
            name, value = row[0], row[1]
            tag = row[2] if len(row) > 2 else None

            # (None, "Heading") -> a full-width section heading.
            if name is None:
                heading = QTableWidgetItem(str(value))
                heading.setFlags(Qt.ItemIsEnabled)
                heading.setData(Qt.UserRole + 1, "section")
                font = QFont(self.font())
                font.setBold(True)
                heading.setFont(font)
                self.setItem(index, 0, heading)
                self.setSpan(index, 0, 1, 2)
                continue

            key_item = QTableWidgetItem(f"{name}")
            key_item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
            key_item.setData(Qt.UserRole + 1, tag or "label")
            key_item.setToolTip(str(name))

            text = "" if value is None else str(value)
            val_item = QTableWidgetItem(text)
            val_item.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)
            val_item.setToolTip(text)
            if str(name).strip().lower() in MONO_LABELS:
                val_item.setFont(self._mono)
            if tag:
                val_item.setData(Qt.UserRole + 1, tag)

            for item in (key_item, val_item):
                item.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)

            self.setItem(index, 0, key_item)
            self.setItem(index, 1, val_item)

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
        self.clearSpans()
        self.setRowCount(0)
