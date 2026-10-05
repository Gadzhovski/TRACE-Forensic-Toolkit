"""The Notes tab: what the examiner concluded, rather than what the tool found.

Notes are the one thing in a case a tool cannot produce. Everything else here
is derived from the evidence; a note is analysis, and it is what a report is
ultimately made of.

Two scopes share the panel. Notes on the selected artifact appear when
something is selected, and the case's own notes -- observations that belong to
the investigation rather than to any one file -- are always reachable. An
examiner should never have to select a file before recording a thought.
"""

import logging

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (QAbstractItemView, QHBoxLayout, QHeaderView,
                               QLabel, QMenu, QPushButton, QTableWidget,
                               QTableWidgetItem, QTextEdit, QVBoxLayout,
                               QWidget)

from trace_app.infra.constants import BUTTON_WIDTH, CONTROL_HEIGHT, TABLE_ROW_HEIGHT
from trace_app.ui.widgets.table_columns import fit_columns

logger = logging.getLogger('TRACE.Notes')


class NotesPanel(QWidget):
    """Notes for the selected artifact, and for the case as a whole."""

    notes_changed = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.case = None
        self._artifact = None       # (evidence_id, ref, name, path) or None

        layout = QVBoxLayout(self)
        # Tight, for the same reason as the Case panel: this dock is short and
        # padding costs rows of notes.
        layout.setContentsMargins(6, 4, 6, 4)
        layout.setSpacing(4)

        # The scope, the editor and the controls share one row. Stacked, they
        # took three lines of a panel that has about six.
        entry = QHBoxLayout()
        entry.setSpacing(6)

        self.editor = QTextEdit()
        self.editor.setObjectName("notesEditor")
        self.editor.setPlaceholderText("Write a note…  (Ctrl+Enter saves)")
        # Two lines tall, and it does not grow: the list of notes already
        # written is the more useful half of this panel.
        self.editor.setFixedHeight(CONTROL_HEIGHT * 2 + 6)
        self.editor.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        entry.addWidget(self.editor, 1)

        controls = QVBoxLayout()
        controls.setSpacing(3)
        self.save_button = QPushButton("Save")
        self.save_button.setFixedSize(BUTTON_WIDTH, CONTROL_HEIGHT)
        self.save_button.setToolTip("Save this note  (Ctrl+Enter)")
        self.save_button.clicked.connect(self._save)
        controls.addWidget(self.save_button)

        self.scope_button = QPushButton("On the case")
        self.scope_button.setFixedSize(BUTTON_WIDTH, CONTROL_HEIGHT)
        self.scope_button.setCheckable(True)
        self.scope_button.setToolTip(
            "Attach the note to the whole case instead of the selected file.")
        self.scope_button.toggled.connect(self._update_scope_label)
        controls.addWidget(self.scope_button)
        entry.addLayout(controls)
        layout.addLayout(entry)

        # What the note will be attached to, in the space a label costs rather
        # than a line of its own.
        self.scope_label = QLabel()
        self.scope_label.setObjectName("notesScope")
        self.scope_label.setWordWrap(False)
        layout.addWidget(self.scope_label)

        self.table = QTableWidget()
        self.table.setObjectName("notesTable")
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(['Note', 'About', 'Written'])
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(TABLE_ROW_HEIGHT)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.horizontalHeader().setSectionResizeMode(
            QHeaderView.Interactive)
        self.table.setMinimumHeight(TABLE_ROW_HEIGHT * 2)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._context_menu)
        self.table.itemDoubleClicked.connect(self._edit_selected)
        # All remaining height: the notes already written are what this panel
        # is for.
        layout.addWidget(self.table, 1)

        self.set_case(None)

    # --- state ------------------------------------------------------------

    def set_case(self, case):
        self.case = case
        self.refresh()

    def set_artifact(self, evidence_id, ref, name='', path=''):
        """Point the panel at the artifact currently selected."""
        self._artifact = (evidence_id, ref, name, path) if ref else None
        self.refresh()

    def display_for(self, data):
        """Adapter entry point: point the panel at whatever is selected.

        The host supplies `evidence_id` and `artifact_ref` on the data dict; a
        selection that has neither (a volume row, say) simply leaves the panel
        on case scope rather than refusing to show anything.
        """
        if not data:
            self.set_artifact(None, None)
            return
        self.set_artifact(data.get('evidence_id'), data.get('artifact_ref'),
                          data.get('name') or '', data.get('path') or '')

    def clear_content(self):
        # A note outlives the selection that prompted it, so changing files
        # does not clear what is on screen -- only what it is about.
        self._artifact = None
        self.refresh()

    # --- display ----------------------------------------------------------

    def refresh(self):
        enabled = self.case is not None
        self.editor.setEnabled(enabled)
        self.save_button.setEnabled(enabled)
        self.scope_button.setEnabled(enabled)

        if not enabled:
            self.scope_label.setText(
                "Quick triage — no case is open, so notes have nowhere to be "
                "kept.")
            self.table.setRowCount(0)
            return

        self._update_scope_label()
        self._fill()

    def _update_scope_label(self, *_):
        if self.case is None:
            return
        if self.scope_button.isChecked() or self._artifact is None:
            self.scope_label.setText("Writing a note about the case.")
        else:
            name = self._artifact[2] or self._artifact[1]
            self.scope_label.setText(f"Writing a note about {name}.")

    def _fill(self):
        rows = self.case.notes()
        self.table.setRowCount(len(rows))
        for index, row in enumerate(rows):
            body = (row.get('body') or '').replace('\n', ' ')
            about = row.get('artifact_name') or 'The case'
            written = (row.get('updated_utc') or row.get('created_utc') or '')
            for column, value in enumerate(
                    (body, about, written[:19].replace('T', ' '))):
                cell = QTableWidgetItem(str(value))
                if column == 0:
                    cell.setData(Qt.UserRole, row)
                    cell.setToolTip(row.get('body') or '')
                self.table.setItem(index, column, cell)
        fit_columns(self.table, {0: 420})

    # --- actions ----------------------------------------------------------

    def _save(self):
        body = self.editor.toPlainText().strip()
        if not body:
            return
        if self.case is None:
            return

        on_case = self.scope_button.isChecked() or self._artifact is None
        if on_case:
            self.case.add_note(body)
        else:
            evidence_id, ref, name, path = self._artifact
            self.case.add_note(body, evidence_id, ref, name, path)

        self.editor.clear()
        self.refresh()
        self.notes_changed.emit()

    def _selected_row(self):
        items = self.table.selectedItems()
        if not items:
            return None
        return self.table.item(items[0].row(), 0).data(Qt.UserRole)

    def _context_menu(self, position):
        row = self._selected_row()
        if not row:
            return
        menu = QMenu(self)
        edit = menu.addAction("Edit Note...")
        remove = menu.addAction("Delete Note")
        action = menu.exec(self.table.viewport().mapToGlobal(position))
        if action == edit:
            self._edit(row)
        elif action == remove:
            self.case.remove_note(row['id'])
            self.refresh()
            self.notes_changed.emit()

    def _edit_selected(self, _item=None):
        row = self._selected_row()
        if row:
            self._edit(row)

    def _edit(self, row):
        from PySide6.QtWidgets import QInputDialog

        body, ok = QInputDialog.getMultiLineText(
            self, "Edit note", "Note:", row.get('body') or '')
        if ok and body.strip():
            self.case.update_note(row['id'], body.strip())
            self.refresh()
            self.notes_changed.emit()
