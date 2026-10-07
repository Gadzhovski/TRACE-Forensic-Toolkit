"""The Notes tab: what the examiner concluded, rather than what the tool found.

Notes are the one thing in a case a tool cannot produce: everything else is
derived from the evidence; a note is analysis, and it is what a report is
made of.

Laid out for the short dock: the note being written on the left -- what it
is about (the file selected, or the case itself), the text, Save (Ctrl+Enter)
-- and the notes already written on the right, each in full (wrapped, not
cut to a line), with what it is about and when, filtered by scope or by
text. Double-click a note to edit it in place; "About" takes you to the
file; deleting asks first.
"""

import logging

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (QAbstractItemView, QApplication, QComboBox,
                               QFrame, QHBoxLayout, QHeaderView, QLabel,
                               QLineEdit, QMenu, QPushButton, QTableWidget,
                               QTableWidgetItem, QTextEdit, QVBoxLayout,
                               QWidget)

from trace_app.ui import icons
from trace_app.ui.dialogs import message
from trace_app.ui.viewers.case_panel import format_utc
from trace_app.ui.widgets.no_focus_delegate import NoFocusDelegate
from trace_app.ui.widgets.context_menus import show_menu

logger = logging.getLogger('TRACE.Notes')

SCOPE_ARTIFACT, SCOPE_CASE = 'artifact', 'case'
SHOW_ALL, SHOW_THIS, SHOW_CASE = 'all', 'this', 'case'
#: A note longer than this many lines is shown cut, in full on hover.
SHOWN_LINES = 4
ABOUT_COLUMN, NOTE_COLUMN = 1, 2


class NotesPanel(QWidget):
    """Notes for the selected artifact, and for the case as a whole."""

    notes_changed = Signal()
    #: A note's artifact, to show: {'evidence_id', 'artifact_ref',
    #: 'artifact_name', 'artifact_path'} -- what go_to_bookmark takes.
    open_artifact = Signal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("notesPanel")
        self.case = None
        self._artifact = None       # (evidence_id, ref, name, path) or None
        self._editing = None        # the note row being edited, or None

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # --- writing a note ---
        composer = QFrame()
        composer.setObjectName("notesComposer")
        composer.setFixedWidth(380)
        column = QVBoxLayout(composer)
        column.setContentsMargins(12, 8, 12, 8)
        column.setSpacing(6)
        top = QHBoxLayout()
        top.setSpacing(6)
        self.heading = QLabel("New note")
        self.heading.setObjectName("notesHeading")
        top.addWidget(self.heading)
        top.addStretch(1)
        top.addWidget(QLabel("About"))
        self.scope = QComboBox()
        self.scope.setObjectName("notesScopeChoice")
        self.scope.setMinimumWidth(180)
        self.scope.setMaximumWidth(220)
        top.addWidget(self.scope)
        column.addLayout(top)
        self.editor = QTextEdit()
        self.editor.setObjectName("notesEditor")
        self.editor.setAcceptRichText(False)
        self.editor.setPlaceholderText(
            "What does this show? What should be checked next?")
        column.addWidget(self.editor, 1)
        bottom = QHBoxLayout()
        bottom.setSpacing(6)
        hint = QLabel("Ctrl+Enter saves")
        hint.setObjectName("notesHint")
        bottom.addWidget(hint)
        bottom.addStretch(1)
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self._stop_editing)
        self.cancel_button.hide()
        bottom.addWidget(self.cancel_button)
        self.save_button = QPushButton("Save Note")
        self.save_button.setObjectName("notesSave")
        self.save_button.setToolTip("Save this note  (Ctrl+Enter)")
        self.save_button.clicked.connect(self._save)
        bottom.addWidget(self.save_button)
        column.addLayout(bottom)
        layout.addWidget(composer)
        # Ctrl+Enter saves, Escape leaves an edit: read from the editor's
        # own keys (a shortcut waits for its window to be active).
        self.editor.installEventFilter(self)

        # --- the notes written ---
        side = QWidget()
        side.setObjectName("notesList")
        rows = QVBoxLayout(side)
        rows.setContentsMargins(0, 0, 0, 0)
        rows.setSpacing(0)
        bar = QFrame()
        bar.setObjectName("notesBar")
        line = QHBoxLayout(bar)
        line.setContentsMargins(8, 4, 8, 4)
        line.setSpacing(6)
        line.addWidget(QLabel("Show"))
        self.show_filter = QComboBox()
        self.show_filter.setObjectName("notesShow")
        for key, label in ((SHOW_ALL, "All notes"),
                           (SHOW_THIS, "About the selected file"),
                           (SHOW_CASE, "About the case")):
            self.show_filter.addItem(label, key)
        self.show_filter.currentIndexChanged.connect(lambda _i: self._fill())
        line.addWidget(self.show_filter)
        self.search = QLineEdit()
        self.search.setObjectName("notesSearch")
        self.search.setPlaceholderText("Find in notes…")
        self.search.setClearButtonEnabled(True)
        self.search.setMaximumWidth(260)
        self.search.textChanged.connect(lambda _t: self._fill())
        line.addWidget(self.search, 1)
        line.addStretch(1)
        self.count_label = QLabel()
        self.count_label.setObjectName("notesCount")
        line.addWidget(self.count_label)
        rows.addWidget(bar)

        self.table = QTableWidget()
        self.table.setObjectName("notesTable")
        self.table.setColumnCount(3)
        # When, about what, then the note -- last, so it takes the width
        # (every table's last column stretches).
        self.table.setHorizontalHeaderLabels(['Written', 'About', 'Note'])
        header = self.table.horizontalHeader()
        header.setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.Interactive)
        header.setSectionResizeMode(2, QHeaderView.Stretch)
        self.table.setColumnWidth(1, 180)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setWordWrap(True)
        self.table.setTextElideMode(Qt.ElideRight)
        self.table.setItemDelegate(NoFocusDelegate(self.table))
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._context_menu)
        self.table.cellDoubleClicked.connect(self._double_clicked)
        rows.addWidget(self.table, 1)
        self.empty = QLabel()
        self.empty.setObjectName("notesEmpty")
        self.empty.setAlignment(Qt.AlignCenter)
        self.empty.setWordWrap(True)
        rows.addWidget(self.empty, 1)
        layout.addWidget(side, 1)

        # Kept for callers of the old layout.
        self.scope_label = self.heading

        self.set_case(None)

    def eventFilter(self, watched, event):
        from PySide6.QtCore import QEvent
        if watched is self.editor and event.type() == QEvent.KeyPress:
            if event.key() in (Qt.Key_Return, Qt.Key_Enter) and \
                    event.modifiers() & Qt.ControlModifier:
                self._save()
                return True
            if event.key() == Qt.Key_Escape and self._editing is not None:
                self._stop_editing()
                return True
        return super().eventFilter(watched, event)

    # --- state ------------------------------------------------------------

    def set_case(self, case):
        self.case = case
        self._editing = None
        self.refresh()

    def set_artifact(self, evidence_id, ref, name='', path=''):
        """Point the panel at the artifact currently selected."""
        artifact = (evidence_id, ref, name, path) if ref else None
        changed = artifact != self._artifact
        self._artifact = artifact
        # A new selection is what a new note is about, unless the
        # examiner picks the case; that choice holds for this selection.
        self._fill_scope(prefer_artifact=changed)
        if self.show_filter.currentData() == SHOW_THIS:
            self._fill()

    def display_for(self, data):
        """Adapter entry point: point the panel at whatever is selected.
        A selection with no reference (a volume row) leaves the note on
        the case."""
        if not data:
            self.set_artifact(None, None)
            return
        self.set_artifact(data.get('evidence_id'), data.get('artifact_ref'),
                          data.get('name') or '', data.get('path') or '')

    def clear_content(self):
        # A note outlives the selection that prompted it: changing files
        # changes only what a new note would be about.
        self.set_artifact(None, None)

    # --- display ----------------------------------------------------------

    def refresh(self):
        enabled = self.case is not None
        for widget in (self.editor, self.save_button, self.scope,
                       self.show_filter, self.search):
            widget.setEnabled(enabled)
        self._fill_scope()
        self._fill()

    def _fill_scope(self, prefer_artifact=False):
        """About: the selected file (when there is one) or the case."""
        keep = None if prefer_artifact else self.scope.currentData()
        self.scope.blockSignals(True)
        self.scope.clear()
        if self._artifact is not None and self._editing is None:
            name = self._artifact[2] or self._artifact[1]
            self.scope.addItem(icons.icon(icons.FINDINGS), name,
                               SCOPE_ARTIFACT)
            self.scope.setItemData(0, self._artifact[3] or name,
                                   Qt.ToolTipRole)
        self.scope.addItem(icons.icon(icons.CASE), "The case", SCOPE_CASE)
        index = self.scope.findData(keep)
        if keep == SCOPE_CASE and index >= 0:
            self.scope.setCurrentIndex(index)
        else:
            self.scope.setCurrentIndex(0)
        self.scope.setEnabled(self.case is not None and self._editing is None)
        self.scope.blockSignals(False)

    def _shown_notes(self):
        rows = self.case.notes()
        show = self.show_filter.currentData()
        if show == SHOW_CASE:
            rows = [r for r in rows if not r.get('artifact_ref')]
        elif show == SHOW_THIS:
            if self._artifact is None:
                return []
            evidence_id, ref = self._artifact[0], self._artifact[1]
            rows = [r for r in rows if r.get('artifact_ref') == ref and
                    r.get('evidence_id') == evidence_id]
        needle = self.search.text().strip().lower()
        if needle:
            rows = [r for r in rows if needle in (r.get('body') or '').lower()
                    or needle in (r.get('artifact_name') or '').lower()]
        return rows

    def _fill(self):
        if self.case is None:
            self.table.setRowCount(0)
            self.table.hide()
            self.empty.setText("Quick triage — no case is open, so notes "
                               "have nowhere to be kept.")
            self.empty.show()
            self.count_label.setText('')
            return
        rows = self._shown_notes()
        total = len(self.case.notes())
        self.count_label.setText(
            f"{len(rows):,} of {total:,}" if len(rows) != total
            else f"{total:,} note{'s' if total != 1 else ''}")
        self.table.setRowCount(len(rows))
        for index, row in enumerate(rows):
            body = row.get('body') or ''
            lines = body.splitlines() or ['']
            shown = '\n'.join(lines[:SHOWN_LINES]) + \
                (' …' if len(lines) > SHOWN_LINES else '')
            note = QTableWidgetItem(shown)
            note.setData(Qt.UserRole, row)
            note.setToolTip(body)
            ref = row.get('artifact_ref')
            about = QTableWidgetItem(row.get('artifact_name') or
                                     ('The case' if not ref else ref))
            about.setToolTip(row.get('artifact_path') or
                             ("Double-click to show the file" if ref else
                              "A note on the case itself"))
            changed = row.get('updated_utc') and \
                row.get('updated_utc') != row.get('created_utc')
            written = QTableWidgetItem(
                format_utc(row.get('updated_utc') or row.get('created_utc'))
                + (' (edited)' if changed else ''))
            written.setToolTip(f"Written {format_utc(row.get('created_utc'))}"
                               + (f"\nEdited {format_utc(row['updated_utc'])}"
                                  if changed else ''))
            note.setData(Qt.UserRole, row)
            for column, cell in enumerate((written, about, note)):
                cell.setTextAlignment(Qt.AlignLeft | Qt.AlignTop)
                self.table.setItem(index, column, cell)
        self.table.resizeRowsToContents()
        has_rows = bool(rows)
        self.table.setVisible(has_rows)
        self.empty.setVisible(not has_rows)
        if not has_rows:
            self.empty.setText(
                "No notes yet. Write what a file shows, or what the case "
                "needs next, on the left." if not total else
                "No note matches.")

    # --- actions ----------------------------------------------------------

    def _save(self):
        body = self.editor.toPlainText().strip()
        if not body or self.case is None:
            return
        if self._editing is not None:
            self.case.update_note(self._editing['id'], body)
            self._stop_editing()
        else:
            if self.scope.currentData() == SCOPE_ARTIFACT and \
                    self._artifact is not None:
                evidence_id, ref, name, path = self._artifact
                self.case.add_note(body, evidence_id, ref, name, path)
            else:
                self.case.add_note(body)
            self.editor.clear()
        self._fill()
        self.notes_changed.emit()

    def _selected_row(self):
        items = self.table.selectedItems()
        if not items:
            return None
        return self.table.item(items[0].row(), NOTE_COLUMN).data(Qt.UserRole)

    def _double_clicked(self, row_index, column):
        row = self.table.item(row_index, NOTE_COLUMN).data(Qt.UserRole)
        if column == ABOUT_COLUMN and row.get('artifact_ref'):
            self._open(row)
        else:
            self._edit(row)

    def _context_menu(self, position):
        row = self._selected_row()
        if not row:
            return
        menu = QMenu(self)
        edit = menu.addAction("Edit Note")
        edit.triggered.connect(lambda: self._edit(row))
        copy = menu.addAction("Copy Text")
        copy.triggered.connect(
            lambda: QApplication.clipboard().setText(row.get('body') or ''))
        if row.get('artifact_ref'):
            show = menu.addAction("Show File")
            show.triggered.connect(lambda: self._open(row))
        menu.addSeparator()
        remove = menu.addAction("Delete Note…")
        remove.triggered.connect(lambda: self._delete(row))
        show_menu(menu, self.table.viewport().mapToGlobal(position))

    def _open(self, row):
        self.open_artifact.emit({
            'evidence_id': row.get('evidence_id'),
            'artifact_ref': row.get('artifact_ref'),
            'artifact_name': row.get('artifact_name') or '',
            'artifact_path': row.get('artifact_path') or '',
            'label': row.get('artifact_name') or ''})

    def _delete(self, row):
        text = (row.get('body') or '').strip()
        if not message.question(
                self, "Delete note",
                "Delete this note? It is removed from the case; the "
                "activity log records that it was.",
                informative=text[:300] + ('…' if len(text) > 300 else '')):
            return
        if self._editing and self._editing['id'] == row['id']:
            self._stop_editing()
        self.case.remove_note(row['id'])
        self._fill()
        self.notes_changed.emit()

    def _edit(self, row):
        """Edit the note in the editor, where it was written."""
        self._editing = row
        self.editor.setPlainText(row.get('body') or '')
        self.heading.setText("Editing note")
        self.save_button.setText("Save Changes")
        self.cancel_button.show()
        self._fill_scope()
        self.scope.clear()
        self.scope.addItem(row.get('artifact_name') or 'The case')
        self.scope.setEnabled(False)
        self.editor.setFocus()

    def _stop_editing(self):
        if self._editing is None:
            return
        self._editing = None
        self.editor.clear()
        self.heading.setText("New note")
        self.save_button.setText("Save Note")
        self.cancel_button.hide()
        self._fill_scope()
