"""Tools > Keyword Lists: the examiner's term lists, and this case's use of
them (core/keywords.py).

Import a text file (one term a line) or a CSV, or type a list; terms are
words and phrases, prefixes (`term*`) and regular expressions (`/pattern/`,
grep's [[:alpha:]] classes included). A list whose terms do not all parse
is refused with the line of each problem. A list is graded *notable* or
*suspicious*; which lists a case uses is the case's setting. Searching
reads the case's search index, so an image must be indexed first.
"""

import logging
import os

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (QAbstractItemView, QCheckBox, QComboBox,
                               QDialog, QDialogButtonBox, QFileDialog,
                               QFormLayout, QHBoxLayout, QHeaderView, QLabel,
                               QLineEdit, QPlainTextEdit, QPushButton,
                               QTableWidget, QTableWidgetItem, QVBoxLayout)

from trace_app.core import keywords
from trace_app.ui import icons
from trace_app.ui.dialogs import message
from trace_app.ui.process_worker import ProcessWorker
from trace_app.ui.viewers.virustotal import verdict_brush
from trace_app.ui.widgets.no_focus_delegate import NoFocusDelegate

logger = logging.getLogger('TRACE.KeywordDialog')

GRADE_LABELS = {'notable': 'Notable (worth a look)',
                'suspicious': 'Suspicious (evidence of intent)'}

SYNTAX_HELP = (
    "One term a line. A word or phrase matches as written, in any case "
    "and with or without accents; <b>term*</b> matches words beginning "
    "with it; <b>/pattern/</b> or <b>re:pattern</b> is a regular "
    "expression (grep's [[:alpha:]] classes work). Lines starting with # "
    "are comments.")


class KeywordWorker(ProcessWorker):
    """Searches the case's index in a child process (core/background.py)."""

    progressed = Signal(int, int, str)
    finished_search = Signal(int, str)

    kind = 'keywords'

    def __init__(self, case_folder, library_folder, options, evidence_ids,
                 parent=None):
        super().__init__({'case_folder': case_folder,
                          'library': library_folder, 'options': options,
                          'evidence_ids': list(evidence_ids)}, parent)
        self.result = {}

    def on_progress(self, done, total, term):
        self.progressed.emit(done, total, term)

    def on_item(self, record):
        self.result = record

    def on_done(self, count, error):
        self.finished_search.emit(count, error)


class EditListDialog(QDialog):
    """A list's name, grade and terms, as text in the import syntax."""

    def __init__(self, entry=None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Edit Keyword List" if entry else
                           "New Keyword List")
        self.setObjectName("hashSetImportDialog")
        self.setWindowIcon(icons.icon(icons.KEYWORDS))
        self.setMinimumSize(560, 520)
        self.terms = []
        layout = QVBoxLayout(self)
        form = QFormLayout()
        self.name = QLineEdit(entry['name'] if entry else '')
        self.name.setPlaceholderText("Names in the Peterson matter")
        form.addRow("Name:", self.name)
        self.grade = QComboBox()
        for key, label in GRADE_LABELS.items():
            self.grade.addItem(label, key)
        if entry:
            self.grade.setCurrentIndex(self.grade.findData(entry['grade']))
        form.addRow("A hit is:", self.grade)
        self.description = QLineEdit(entry.get('description', '')
                                     if entry else '')
        form.addRow("Description:", self.description)
        layout.addLayout(form)
        help_label = QLabel(SYNTAX_HELP)
        help_label.setObjectName("analysisModulesIntro")
        help_label.setTextFormat(Qt.RichText)
        help_label.setWordWrap(True)
        layout.addWidget(help_label)
        self.editor = QPlainTextEdit()
        self.editor.setObjectName("keywordEditor")
        self.editor.setPlaceholderText("password\nproject falcon\n"
                                       "transfer*\n/\\b\\d{3}-\\d{2}-\\d{4}\\b/")
        if entry:
            self.editor.setPlainText('\n'.join(
                keywords.display(t) for t in entry['terms']))
        layout.addWidget(self.editor, 1)
        self.problems = QLabel()
        self.problems.setObjectName("bitlockerError")
        self.problems.setWordWrap(True)
        self.problems.hide()
        layout.addWidget(self.problems)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok |
                                   QDialogButtonBox.Cancel)
        buttons.accepted.connect(self._check)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _check(self):
        terms, problems = keywords.read_terms(
            self.editor.toPlainText().encode('utf-8'), 'typed.txt')
        if problems or not terms:
            self.problems.setText('\n'.join(problems) if problems else
                                  "Type at least one term.")
            self.problems.show()
            return
        self.terms = terms
        self.accept()


class KeywordListsDialog(QDialog):
    #: The examiner asked to search now (after the options were saved).
    search_requested = Signal()

    def __init__(self, case=None, library=None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Keyword Lists")
        self.setObjectName("hashSetsDialog")
        self.setWindowIcon(icons.icon(icons.KEYWORDS))
        self.setMinimumSize(860, 520)
        self.case = case
        self.library = library or keywords.Library()
        self.options = keywords.case_options(case, self.library)
        self._initial = dict(self.options, lists=dict(self.options['lists']))

        layout = QVBoxLayout(self)
        intro = QLabel(
            "A keyword list is a set of terms searched for across the whole "
            "case at once: every file, deleted ones included, every archive "
            "member, mailbox message and attachment that indexing read. "
            "Each term's hits are findings, in Triage ▸ Keywords and in the "
            "report. Lists are kept in your library and chosen per case.")
        intro.setObjectName("analysisModulesIntro")
        intro.setWordWrap(True)
        layout.addWidget(intro)

        self.use_box = QCheckBox("Search with keyword lists in this case")
        self.use_box.setObjectName("analysisModuleCheck")
        self.use_box.setChecked(bool(self.options.get('enabled')))
        layout.addWidget(self.use_box)

        self.table = QTableWidget()
        self.table.setObjectName("triageTable")
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(
            ['Use', 'Name', 'A hit is', 'Terms', 'Added', 'Source'])
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setItemDelegate(NoFocusDelegate(self.table))
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Interactive)
        header.setStretchLastSection(True)
        for column, width in enumerate((44, 260, 120, 60, 90)):
            self.table.setColumnWidth(column, width)
        self.table.itemChanged.connect(self._item_changed)
        self.table.itemSelectionChanged.connect(self._update_buttons)
        self.table.itemDoubleClicked.connect(lambda _item: self._edit())
        layout.addWidget(self.table, 1)

        row = QHBoxLayout()
        self.import_button = QPushButton("Import List…")
        self.import_button.clicked.connect(self._import)
        row.addWidget(self.import_button)
        self.new_button = QPushButton("New List…")
        self.new_button.clicked.connect(self._new)
        row.addWidget(self.new_button)
        self.edit_button = QPushButton("Edit…")
        self.edit_button.clicked.connect(self._edit)
        row.addWidget(self.edit_button)
        self.export_button = QPushButton("Export…")
        self.export_button.clicked.connect(self._export)
        row.addWidget(self.export_button)
        self.remove_button = QPushButton("Remove")
        self.remove_button.clicked.connect(self._remove)
        row.addWidget(self.remove_button)
        row.addStretch(1)
        layout.addLayout(row)

        self.status = QLabel()
        self.status.setObjectName("triageStatus")
        self.status.setWordWrap(True)
        layout.addWidget(self.status)

        buttons = QDialogButtonBox()
        self.search_button = buttons.addButton("Save and Search Now",
                                               QDialogButtonBox.ApplyRole)
        self.search_button.clicked.connect(self._search)
        close = buttons.addButton(QDialogButtonBox.Close)
        close.clicked.connect(self.accept)
        buttons.rejected.connect(self.accept)
        layout.addWidget(buttons)
        if case is None:
            self.use_box.setEnabled(False)
            self.search_button.setEnabled(False)
            self.search_button.setToolTip("Keyword searches are kept in a "
                                          "case.")
        self._fill()

    def _fill(self):
        self.table.blockSignals(True)
        self._entries = self.library.lists()
        self.table.setRowCount(len(self._entries))
        for row, entry in enumerate(self._entries):
            use = QTableWidgetItem()
            use.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled
                         | Qt.ItemIsSelectable)
            use.setCheckState(Qt.Checked if keywords.list_enabled_in(
                self.options, entry) else Qt.Unchecked)
            use.setData(Qt.UserRole, entry['id'])
            self.table.setItem(row, 0, use)
            source = entry.get('source') or ''
            values = (entry['name'],
                      GRADE_LABELS[entry['grade']].split(' (')[0],
                      f"{len(entry['terms']):,}",
                      (entry.get('added_utc') or '')[:10],
                      os.path.basename(source) if source else 'typed')
            tip = '\n'.join(p for p in (
                entry.get('description'),
                f"From {source}" if source else '',
                f"SHA-256 {entry['source_sha256']}"
                if entry.get('source_sha256') else '',
                ', '.join(keywords.display(t)
                          for t in entry['terms'][:40])) if p)
            for column, value in enumerate(values, start=1):
                cell = QTableWidgetItem(value)
                cell.setToolTip(tip)
                if column == 2:
                    cell.setForeground(verdict_brush(
                        'malicious' if entry['grade'] == 'suspicious'
                        else 'suspicious'))
                self.table.setItem(row, column, cell)
        self.table.blockSignals(False)
        self._update_buttons()
        self.status.setText(
            f"{len(self._entries)} list(s) in your library." if
            self._entries else "Your library is empty. Import a list or "
                               "type a new one to begin.")

    def _selected(self):
        row = self.table.currentRow()
        return self._entries[row] if 0 <= row < len(self._entries) else None

    def _update_buttons(self):
        has = self._selected() is not None
        for button in (self.edit_button, self.export_button,
                       self.remove_button):
            button.setEnabled(has)

    def _item_changed(self, item):
        if item.column() == 0:
            self.options.setdefault('lists', {})[item.data(Qt.UserRole)] = \
                item.checkState() == Qt.Checked

    def _audit(self, action, entry):
        if self.case is not None:
            self.case.record_event(
                action, f"name={entry['name']} grade={entry['grade']} "
                f"terms={len(entry['terms'])}"
                + (f" source={entry['source']} sha256="
                   f"{entry['source_sha256']}" if entry.get('source') else ''))

    def _import(self):
        source, _ = QFileDialog.getOpenFileName(
            self, "Keyword List", "", "Keyword lists (*.txt *.csv *.lst);;"
                                      "All files (*)")
        if not source:
            return
        try:
            entry = self.library.import_file(source)
        except (keywords.KeywordError, OSError) as exc:
            message.warning(self, "List not imported",
                            "Some lines are not valid terms, so nothing was "
                            "imported.", str(exc))
            return
        self._audit('keyword list imported', entry)
        self.use_box.setChecked(True)
        self._fill()
        self._select(entry['id'])

    def _new(self):
        dialog = EditListDialog(None, self)
        if dialog.exec() != QDialog.Accepted:
            return
        entry = self.library.create(dialog.name.text().strip(),
                                    dialog.terms, dialog.grade.currentData(),
                                    dialog.description.text().strip())
        self._audit('keyword list created', entry)
        self.use_box.setChecked(True)
        self._fill()
        self._select(entry['id'])

    def _edit(self):
        entry = self._selected()
        if entry is None:
            return
        dialog = EditListDialog(entry, self)
        if dialog.exec() != QDialog.Accepted:
            return
        entry = self.library.update(
            entry['id'], name=dialog.name.text().strip() or entry['name'],
            grade=dialog.grade.currentData(),
            description=dialog.description.text().strip(),
            terms=dialog.terms)
        self._audit('keyword list edited', entry)
        self._fill()
        self._select(entry['id'])

    def _export(self):
        entry = self._selected()
        if entry is None:
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Keyword List", f"{entry['name']}.txt",
            "Text (*.txt)")
        if not path:
            return
        try:
            self.library.export_text(entry['id'], path)
        except OSError as exc:
            message.warning(self, "Not exported", str(exc))

    def _remove(self):
        entry = self._selected()
        if entry is None or not message.question(
                self, "Remove keyword list",
                f"Remove \"{entry['name']}\" from your library?",
                "Hits already recorded stay until the case is searched "
                "again."):
            return
        self.library.remove(entry['id'])
        self.options.get('lists', {}).pop(entry['id'], None)
        self._fill()

    def _select(self, list_id):
        for row, entry in enumerate(self._entries):
            if entry['id'] == list_id:
                self.table.selectRow(row)

    def collected_options(self):
        return dict(self.options, enabled=self.use_box.isChecked())

    def save(self):
        if self.case is None:
            return False
        options = self.collected_options()
        if options == self._initial:
            return False
        self.case.set_setting('keywords', options)
        used = [e['name'] for e in self._entries
                if keywords.list_enabled_in(options, e)]
        self.case.record_event(
            'keyword options changed',
            f"enabled={options['enabled']} lists={', '.join(used) or 'none'}")
        self._initial = dict(options, lists=dict(options['lists']))
        return True

    def _search(self):
        self.save()
        self.search_requested.emit()
        self.accept()

    def accept(self):
        self.save()
        super().accept()
