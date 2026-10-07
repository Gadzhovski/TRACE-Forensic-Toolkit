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
stripes that a data table wants. The label column is sized to its content and
both columns read left to right, which keeps each label beside the value it
names. Long identifiers -- hashes, offsets -- are shown in a monospaced font so
digits line up and a mistyped character is visible.
"""

from PySide6.QtCore import Qt
from PySide6.QtGui import (QFont, QFontDatabase, QFontMetrics, QGuiApplication,
                           QKeySequence, QShortcut)
from PySide6.QtWidgets import (QAbstractItemView, QHeaderView, QLineEdit,
                               QStyledItemDelegate, QTableWidget,
                               QTableWidgetItem)

from trace_app.infra.constants import TABLE_ROW_HEIGHT

#: Width added to the longest label. It has to cover the item padding the
#: themes give property cells (8px left + 12px right) and the style's own text
#: margin either side, or the longest labels lose their last letters to an
#: ellipsis -- 18 did exactly that to "SHA-256" and "Last analysed".
LABEL_PADDING = 30

#: Values shown in a monospaced font: anything where character alignment helps.
MONO_LABELS = {
    'md5', 'sha-1', 'sha1', 'sha-256', 'sha256', 'disk offset', 'inode',
    'size', 'offset',
}


class _ReadOnlyTextDelegate(QStyledItemDelegate):
    """Puts a selectable but unwritable line edit over a cell.

    A QTableWidget can only select whole cells, so copying half a hash out of
    the properties was impossible while the filesystem-detail view beside it
    allowed exactly that. Opening a read-only editor closes the gap without
    making the pane editable: the editor selects and copies like any text
    field, and setModelData does nothing, so no edit can reach the model.
    """

    def createEditor(self, parent, option, index):
        editor = QLineEdit(parent)
        editor.setReadOnly(True)
        editor.setFrame(False)
        editor.setObjectName("propertyCellEditor")
        return editor

    def setEditorData(self, editor, index):
        editor.setText(index.data() or "")
        editor.selectAll()

    def setModelData(self, editor, model, index):
        return  # read-only: never write back


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

        # Double-clicking a value opens a read-only editor over the cell, so
        # part of a hash or a timestamp can be dragged out -- the same freedom
        # the filesystem-detail view below gives, which a table's whole-cell
        # selection does not. The delegate below refuses to write anything
        # back, so the pane stays read-only.
        self.setEditTriggers(QAbstractItemView.DoubleClicked
                             | QAbstractItemView.SelectedClicked)
        self.setItemDelegate(_ReadOnlyTextDelegate(self))
        self.setSelectionBehavior(QAbstractItemView.SelectItems)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setWordWrap(False)
        self.setTextElideMode(Qt.ElideRight)

        header = self.horizontalHeader()
        header.setObjectName("propertyTableHeader")
        # The label column follows its longest label instead of sitting at a
        # fixed 160px. Fixed, it left "MD5" and "Name" stranded a long way from
        # their values, with a ragged channel of empty space down the middle of
        # the pane -- and it took width the values needed, so hashes were
        # elided while the gap beside them went unused.
        #
        # Sized in _size_label_column rather than by ResizeToContents: that
        # mode measures every cell in the column, and a section heading is put
        # in column 0 before it is spanned across both, so a long heading
        # widened the labels past anything they contain.
        header.setSectionResizeMode(0, QHeaderView.Fixed)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        header.setHighlightSections(False)

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
            key_item.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)
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

            key_item.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
            # Editable only so the read-only editor can open on it; the
            # delegate discards anything typed.
            val_item.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable
                              | Qt.ItemIsEditable)

            self.setItem(index, 0, key_item)
            self.setItem(index, 1, val_item)

        self._size_label_column(rows)

    def _size_label_column(self, rows):
        """Widen the label column to its longest label, and no further."""
        metrics = QFontMetrics(self.font())
        widest = 0
        for row in rows:
            if row[0] is None:
                continue          # a section heading spans both columns
            widest = max(widest, metrics.horizontalAdvance(str(row[0])))
        self.setColumnWidth(0, widest + LABEL_PADDING)

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
