"""The Bookmarks dock: every artifact the examiner marked worth returning to.

A bookmark is a fast way back, not a place to write things down -- that is what
notes are for. So this panel is a list you scan and double-click, and it stays
out of the way otherwise.

The list is the case's, so it survives closing the application. What makes that
work is `artifact_ref` (see trace_app/core/case.py): a bookmark records the
partition, inode and MFT sequence rather than a path, because a path can change
and an inode alone can come to mean a different file.
"""

import logging

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (QAbstractItemView, QHeaderView, QLabel, QMenu,
                               QTableWidget, QTableWidgetItem, QVBoxLayout,
                               QWidget)

from trace_app.core.case import parse_artifact_ref
from trace_app.infra.constants import TABLE_ROW_HEIGHT
from trace_app.ui.dialogs import message
from trace_app.ui.widgets.table_columns import fit_columns

logger = logging.getLogger('TRACE.Bookmarks')

#: How each artifact kind reads in the list.
KIND_TEXT = {
    'file': 'File',
    'span': 'Byte range',
    'registry': 'Registry',
    'unknown': 'Unknown',
}


class BookmarksPanel(QWidget):
    """Lists the case's bookmarks. Double-click jumps to the artifact."""

    #: Emitted with a bookmark row when the user wants to go there.
    jump_requested = Signal(dict)

    #: Emitted after the panel changes the list, so the tree can redraw.
    bookmarks_changed = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.case = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(6)

        self.empty_label = QLabel()
        self.empty_label.setObjectName("bookmarksEmpty")
        self.empty_label.setWordWrap(True)
        self.empty_label.setAlignment(Qt.AlignTop)
        layout.addWidget(self.empty_label)

        self.table = QTableWidget()
        self.table.setObjectName("bookmarksTable")
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(['Label', 'Kind', 'Name', 'Added'])
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(TABLE_ROW_HEIGHT)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.horizontalHeader().setSectionResizeMode(
            QHeaderView.Interactive)
        self.table.itemDoubleClicked.connect(self._jump)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._context_menu)
        layout.addWidget(self.table)

        self.set_case(None)

    # --- population -------------------------------------------------------

    def set_case(self, case):
        self.case = case
        self.refresh()

    def refresh(self):
        if self.case is None:
            self.empty_label.setText(
                "Quick triage — no case is open, so there is nowhere to keep "
                "bookmarks.")
            self.empty_label.setVisible(True)
            self.table.setVisible(False)
            return

        rows = self.case.bookmarks()
        if not rows:
            self.empty_label.setText(
                "No bookmarks yet. Right-click a file, a registry key, a "
                "carved file or a hex selection and choose Add Bookmark.")
            self.empty_label.setVisible(True)
            self.table.setVisible(False)
            return

        self.empty_label.setVisible(False)
        self.table.setVisible(True)
        self.table.setRowCount(len(rows))

        for index, row in enumerate(rows):
            kind = parse_artifact_ref(row.get('artifact_ref'))['kind']
            values = [
                row.get('label') or '(unlabelled)',
                KIND_TEXT.get(kind, kind),
                row.get('artifact_name') or row.get('artifact_path') or '—',
                (row.get('created_utc') or '')[:19].replace('T', ' '),
            ]
            for column, value in enumerate(values):
                cell = QTableWidgetItem(str(value))
                if column == 0:
                    # The whole row travels with the first cell, so a jump does
                    # not have to re-query the case by label.
                    cell.setData(Qt.UserRole, row)
                    if row.get('artifact_path'):
                        cell.setToolTip(row['artifact_path'])
                self.table.setItem(index, column, cell)

        fit_columns(self.table, {2: 300})

    # --- actions ----------------------------------------------------------

    def _selected_row(self):
        items = self.table.selectedItems()
        if not items:
            return None
        return self.table.item(items[0].row(), 0).data(Qt.UserRole)

    def _jump(self, _item=None):
        row = self._selected_row()
        if row:
            self.jump_requested.emit(row)

    def _context_menu(self, position):
        row = self._selected_row()
        if not row:
            return

        menu = QMenu(self)
        go = menu.addAction("Go to Artifact")
        rename = menu.addAction("Rename...")
        menu.addSeparator()
        remove = menu.addAction("Remove Bookmark")

        action = menu.exec(self.table.viewport().mapToGlobal(position))
        if action == go:
            self.jump_requested.emit(row)
        elif action == rename:
            self._rename(row)
        elif action == remove:
            self.case.remove_bookmark(row['id'])
            self.refresh()
            self.bookmarks_changed.emit()

    def _rename(self, row):
        from PySide6.QtWidgets import QInputDialog

        label, ok = QInputDialog.getText(
            self, "Rename bookmark", "Label:",
            text=row.get('label') or '')
        if ok and label.strip():
            self.case.update_bookmark(row['id'], label=label.strip())
            self.refresh()
            self.bookmarks_changed.emit()
