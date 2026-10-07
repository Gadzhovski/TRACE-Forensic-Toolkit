"""Tools ▸ Hash Sets: the examiner's library, and what this case does with it.

Two halves. The library is the examiner's -- import a hash list (text or
CSV: VirusShare, md5sum output, NSRL 2.x NSRLFile.txt, a colleague's list),
link an NSRL RDS v3 database in place, edit a set's name and category,
export, remove. The options are the case's: whether hash sets are used at
all, which sets, which algorithms, whether known-good files are hidden,
whether a known-bad match warns, whether matching follows hashing.

Nothing here touches evidence. Importing reads the examiner's own files;
matching reads digests the analysis already stored.
"""

import logging
import os

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (QAbstractItemView, QCheckBox, QComboBox,
                               QDialog, QDialogButtonBox, QFileDialog,
                               QFormLayout, QGroupBox, QHBoxLayout,
                               QHeaderView, QLabel, QLineEdit, QListWidget,
                               QListWidgetItem, QProgressBar,
                               QPushButton, QTableWidget, QTableWidgetItem,
                               QVBoxLayout)

from trace_app.core import hashsets
from trace_app.core.hashsets import (ALGORITHM_LABELS, ALGORITHMS,
                                     CATEGORIES, KNOWN_BAD, KNOWN_GOOD)
from trace_app.ui import icons
from trace_app.ui.dialogs import message
from trace_app.ui.viewers.virustotal import verdict_brush
from trace_app.ui.widgets.no_focus_delegate import NoFocusDelegate

logger = logging.getLogger('TRACE.HashSetsDialog')

#: Colour of each category, in the verdict palette the app already uses.
CATEGORY_TONE = {KNOWN_BAD: 'malicious', hashsets.NOTABLE: 'suspicious',
                 KNOWN_GOOD: 'clean'}


def category_brush(category):
    return verdict_brush(CATEGORY_TONE.get(category, 'unknown'))


class _ImportThread(QThread):
    progressed = Signal(object, object)
    finished_import = Signal(object, str)

    def __init__(self, library, path, name, category, description, columns,
                 parent=None):
        super().__init__(parent)
        self.args = (library, path, name, category, description, columns)
        self._stop = False

    def stop(self):
        self._stop = True

    def run(self):
        library, path, name, category, description, columns = self.args
        try:
            entry = library.import_list(
                path, name, category, description, columns=columns,
                progress=lambda done, total: self.progressed.emit(done,
                                                                  total),
                should_stop=lambda: self._stop)
        except hashsets.ImportCancelled:
            self.finished_import.emit(None, '')
            return
        except Exception as exc:
            logger.error("Hash set import failed: %s", exc)
            self.finished_import.emit(None, str(exc) or type(exc).__name__)
            return
        self.finished_import.emit(entry, '')


class ImportDialog(QDialog):
    """Name, category and (for a CSV) columns of a list being imported."""

    def __init__(self, library, path, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Import Hash List")
        self.setObjectName("hashSetImportDialog")
        self.setWindowIcon(icons.icon(icons.LOGO))
        self.setMinimumWidth(520)
        self.library, self.path = library, path
        self.entry = None
        self._thread = None

        header = hashsets.read_export_header(path)
        layout = QVBoxLayout(self)
        intro = QLabel(f"<b>{os.path.basename(path)}</b> — "
                       f"{os.path.getsize(path):,} bytes. MD5, SHA-1 and "
                       "SHA-256 digests are read; anything else on a line is "
                       "ignored.")
        intro.setWordWrap(True)
        intro.setTextFormat(Qt.RichText)
        layout.addWidget(intro)

        form = QFormLayout()
        self.name = QLineEdit(header.get('name') or
                              os.path.splitext(os.path.basename(path))[0])
        form.addRow("Name:", self.name)
        self.category = QComboBox()
        for key, label in CATEGORIES.items():
            self.category.addItem(label, key)
        guess = header.get('category') or _guess_category(path)
        self.category.setCurrentIndex(max(0, self.category.findData(guess)))
        form.addRow("Category:", self.category)
        self.description = QLineEdit(header.get('description') or '')
        self.description.setPlaceholderText("Where it came from, what it is")
        form.addRow("Description:", self.description)
        layout.addLayout(form)

        self.columns = None
        names, found = hashsets.sniff_columns(path)
        if found:
            box = QGroupBox("Columns holding digests")
            box_layout = QVBoxLayout(box)
            self.columns = QListWidget()
            self.columns.setObjectName("hashSetColumns")
            for index, name in enumerate(names):
                algorithm = found.get(index)
                label = name + (f"  ({ALGORITHM_LABELS[algorithm]})"
                                if algorithm else '')
                item = QListWidgetItem(label)
                item.setData(Qt.UserRole, index)
                item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
                item.setCheckState(Qt.Checked if algorithm else Qt.Unchecked)
                self.columns.addItem(item)
            self.columns.setMaximumHeight(140)
            box_layout.addWidget(self.columns)
            layout.addWidget(box)

        self.progress = QProgressBar()
        self.progress.setVisible(False)
        layout.addWidget(self.progress)
        self.error = QLabel()
        self.error.setObjectName("bitlockerError")
        self.error.setWordWrap(True)
        self.error.setVisible(False)
        layout.addWidget(self.error)

        self.buttons = QDialogButtonBox()
        self.import_button = self.buttons.addButton(
            "Import", QDialogButtonBox.AcceptRole)
        self.buttons.addButton(QDialogButtonBox.Cancel)
        self.buttons.accepted.connect(self._start)
        self.buttons.rejected.connect(self._cancel)
        layout.addWidget(self.buttons)

    def selected_columns(self):
        if self.columns is None:
            return None
        return [self.columns.item(i).data(Qt.UserRole)
                for i in range(self.columns.count())
                if self.columns.item(i).checkState() == Qt.Checked]

    def _start(self):
        name = self.name.text().strip()
        if not name:
            self._show("Give the set a name.")
            return
        columns = self.selected_columns()
        if columns is not None and not columns:
            self._show("Tick at least one column.")
            return
        self.error.setVisible(False)
        self.import_button.setEnabled(False)
        self.progress.setVisible(True)
        self.progress.setRange(0, 0)
        self._thread = _ImportThread(
            self.library, self.path, name, self.category.currentData(),
            self.description.text().strip(), columns, self)
        self._thread.progressed.connect(self._progress)
        self._thread.finished_import.connect(self._done)
        self._thread.start()

    def _progress(self, done, total):
        if total:
            self.progress.setRange(0, 1000)
            self.progress.setValue(int(done * 1000 / total))

    def _done(self, entry, error):
        self._thread.wait()
        self._thread = None
        self.import_button.setEnabled(True)
        self.progress.setVisible(False)
        if error:
            self._show(error)
            return
        if entry is None:
            self.reject()
            return
        self.entry = entry
        self.accept()

    def _cancel(self):
        if self._thread is not None:
            self._thread.stop()
            return
        self.reject()

    def _show(self, text):
        self.error.setText(text)
        self.error.setVisible(True)


class EditDialog(QDialog):
    def __init__(self, entry, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Edit Hash Set")
        self.setObjectName("hashSetEditDialog")
        self.setWindowIcon(icons.icon(icons.LOGO))
        self.setMinimumWidth(460)
        layout = QVBoxLayout(self)
        form = QFormLayout()
        self.name = QLineEdit(entry.get('name') or '')
        form.addRow("Name:", self.name)
        self.category = QComboBox()
        for key, label in CATEGORIES.items():
            self.category.addItem(label, key)
        self.category.setCurrentIndex(
            max(0, self.category.findData(entry.get('category'))))
        form.addRow("Category:", self.category)
        self.description = QLineEdit(entry.get('description') or '')
        form.addRow("Description:", self.description)
        self.default = QCheckBox("Use in new cases")
        self.default.setChecked(entry.get('enabled_by_default', True))
        form.addRow("", self.default)
        layout.addLayout(form)
        buttons = QDialogButtonBox(QDialogButtonBox.Save
                                   | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def fields(self):
        return {'name': self.name.text().strip() or 'Unnamed',
                'category': self.category.currentData(),
                'description': self.description.text().strip(),
                'enabled_by_default': self.default.isChecked()}


class HashSetsDialog(QDialog):
    """The library and this case's use of it."""

    #: The examiner asked to match now (after the options were saved).
    match_requested = Signal()

    def __init__(self, case=None, library=None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Hash Sets")
        self.setObjectName("hashSetsDialog")
        self.setWindowIcon(icons.icon(icons.HASH_SETS))
        self.setMinimumSize(860, 560)
        self.case = case
        self.library = library or hashsets.Library()
        self.options = hashsets.case_options(case, self.library)
        self._initial = dict(self.options, sets=dict(self.options['sets']))

        layout = QVBoxLayout(self)
        intro = QLabel(
            "Hash sets mark files by their digest: <b>known good</b> files "
            "(NSRL: operating systems and applications) can be hidden, "
            "<b>known bad</b> and <b>notable</b> ones become findings. Sets "
            "are kept in your library and serve every case; which ones a "
            "case uses is set here, per case.")
        intro.setWordWrap(True)
        intro.setTextFormat(Qt.RichText)
        intro.setObjectName("analysisModulesIntro")
        layout.addWidget(intro)

        self.use_box = QCheckBox("Use hash sets in this case")
        self.use_box.setObjectName("analysisModuleCheck")
        self.use_box.setChecked(bool(self.options.get('enabled')))
        self.use_box.toggled.connect(self._use_toggled)
        layout.addWidget(self.use_box)

        self.table = QTableWidget()
        self.table.setObjectName("triageTable")
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels(
            ['Use', 'Name', 'Category', 'Digests', 'Algorithms', 'Source',
             'Added'])
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setItemDelegate(NoFocusDelegate(self.table))
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Interactive)
        header.setStretchLastSection(True)
        for column, width in enumerate((44, 220, 100, 110, 150, 200)):
            self.table.setColumnWidth(column, width)
        self.table.itemChanged.connect(self._item_changed)
        self.table.itemSelectionChanged.connect(self._update_buttons)
        self.table.itemDoubleClicked.connect(lambda _item: self._edit())
        layout.addWidget(self.table, 1)

        library_row = QHBoxLayout()
        import_button = QPushButton("Import Hash List…")
        import_button.setToolTip(
            "A text or CSV file: one digest per line, md5sum/sha256sum "
            "output, VirusShare lists, NSRL 2.x NSRLFile.txt, or a set "
            "exported from TRACE.")
        import_button.clicked.connect(self._import)
        library_row.addWidget(import_button)
        link_button = QPushButton("Link NSRL Database…")
        link_button.setToolTip(
            "An NSRL RDS v3 SQLite release, used in place and read-only -- "
            "it is too large to copy.")
        link_button.clicked.connect(self._link)
        library_row.addWidget(link_button)
        self.edit_button = QPushButton("Edit…")
        self.edit_button.clicked.connect(self._edit)
        library_row.addWidget(self.edit_button)
        self.export_button = QPushButton("Export…")
        self.export_button.clicked.connect(self._export)
        library_row.addWidget(self.export_button)
        self.remove_button = QPushButton("Remove")
        self.remove_button.clicked.connect(self._remove)
        library_row.addWidget(self.remove_button)
        library_row.addStretch(1)
        layout.addLayout(library_row)

        self.options_box = QGroupBox("How this case uses them")
        options = QVBoxLayout(self.options_box)
        algorithms = QHBoxLayout()
        algorithms.addWidget(QLabel("Match by:"))
        self.algorithm_boxes = {}
        for algorithm in ALGORITHMS:
            box = QCheckBox(ALGORITHM_LABELS[algorithm])
            box.setChecked(algorithm in self.options.get('algorithms', ()))
            self.algorithm_boxes[algorithm] = box
            algorithms.addWidget(box)
        algorithms.addStretch(1)
        options.addLayout(algorithms)
        self.hide_box = QCheckBox(
            "Hide known-good files in the Listing and the Timeline")
        self.hide_box.setChecked(bool(self.options.get('hide_known_good')))
        options.addWidget(self.hide_box)
        self.alert_box = QCheckBox("Warn me when a file matches a known-bad "
                                   "set")
        self.alert_box.setChecked(bool(self.options.get('alert_known_bad')))
        options.addWidget(self.alert_box)
        self.auto_box = QCheckBox(
            "Match automatically when file hashing finishes")
        self.auto_box.setChecked(bool(self.options.get('auto_match')))
        options.addWidget(self.auto_box)
        self.carved_box = QCheckBox("Include carved files")
        self.carved_box.setChecked(bool(self.options.get('include_carved')))
        options.addWidget(self.carved_box)
        note = QLabel("Matching uses the MD5, SHA-1 and SHA-256 the \"File "
                      "hashes\" analysis module records; run it first.")
        note.setObjectName("analysisModuleNote")
        note.setWordWrap(True)
        options.addWidget(note)
        layout.addWidget(self.options_box)

        self.status = QLabel()
        self.status.setObjectName("triageStatus")
        self.status.setWordWrap(True)
        layout.addWidget(self.status)

        buttons = QDialogButtonBox()
        self.match_button = buttons.addButton("Save and Match Now",
                                              QDialogButtonBox.ApplyRole)
        self.match_button.clicked.connect(self._match)
        close = buttons.addButton(QDialogButtonBox.Close)
        close.clicked.connect(self.accept)
        buttons.rejected.connect(self.accept)
        layout.addWidget(buttons)

        if case is None:
            for widget in (self.use_box, self.options_box, self.match_button):
                widget.setEnabled(False)
            self.use_box.setToolTip("Quick triage: no case is open. The "
                                    "library can still be managed.")
        self._fill()
        self._use_toggled(self.use_box.isChecked())

    # --- the table --------------------------------------------------------

    def _fill(self):
        self.table.blockSignals(True)
        entries = self.library.sets()
        self._entries = entries
        self.table.setRowCount(len(entries))
        for row, entry in enumerate(entries):
            use = QTableWidgetItem()
            use.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled
                         | Qt.ItemIsSelectable)
            use.setCheckState(Qt.Checked if hashsets.set_enabled_in(
                self.options, entry) else Qt.Unchecked)
            use.setData(Qt.UserRole, entry['id'])
            self.table.setItem(row, 0, use)
            count = entry.get('count')
            linked = entry.get('kind') == 'linked'
            values = [
                entry['name'],
                CATEGORIES.get(entry['category'], entry['category']),
                (f"{count:,}" if count is not None else '—')
                + (' (linked)' if linked else ''),
                ', '.join(ALGORITHM_LABELS[a]
                          for a in entry.get('algorithms') or ()),
                entry.get('source') or '',
                (entry.get('added_utc') or '')[:10],
            ]
            for column, value in enumerate(values, start=1):
                cell = QTableWidgetItem(value)
                cell.setData(Qt.UserRole, entry['id'])
                tip = [entry.get('description') or '']
                if linked:
                    tip.append(f"Read in place: {entry.get('path')}")
                elif entry.get('source_sha256'):
                    tip.append(f"Source SHA-256: {entry['source_sha256']}")
                if not entry.get('available'):
                    tip.append("MISSING: the file this set reads is gone.")
                cell.setToolTip('\n'.join(t for t in tip if t))
                if column == 2:
                    cell.setForeground(category_brush(entry['category']))
                if not entry.get('available'):
                    cell.setForeground(verdict_brush('malicious'))
                self.table.setItem(row, column, cell)
        self.table.blockSignals(False)
        self._update_buttons()
        self._update_status()

    def _selected(self):
        row = self.table.currentRow()
        if 0 <= row < len(self._entries):
            return self._entries[row]
        return None

    def _update_buttons(self):
        has = self._selected() is not None
        for button in (self.edit_button, self.export_button,
                       self.remove_button):
            button.setEnabled(has)

    def _update_status(self):
        if not self._entries:
            self.status.setText("Your library is empty. Import a hash list "
                                "or link an NSRL database to begin.")
            return
        used = sum(1 for e in self._entries
                   if hashsets.set_enabled_in(self.options, e))
        state = ("used in this case" if self.use_box.isChecked()
                 else "hash sets are switched off for this case")
        self.status.setText(f"{len(self._entries)} set(s) in your library; "
                            f"{used} ticked — {state}.")

    def _item_changed(self, item):
        if item.column() != 0:
            return
        self.options.setdefault('sets', {})[item.data(Qt.UserRole)] = \
            item.checkState() == Qt.Checked
        self._update_status()

    def _use_toggled(self, on):
        self.table.setEnabled(True)
        for column_item in range(self.table.rowCount()):
            cell = self.table.item(column_item, 0)
            if cell is not None:
                flags = cell.flags()
                cell.setFlags(flags | Qt.ItemIsEnabled if on or
                              self.case is None else flags & ~Qt.ItemIsEnabled)
        if self.case is not None:
            self.options_box.setEnabled(on)
        self._update_status()

    # --- library actions -------------------------------------------------

    def _import(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Import Hash List", "",
            "Hash lists (*.txt *.csv *.tsv *.md5 *.sha1 *.sha256 *.hash "
            "*.hashes *.lst);;All files (*)")
        if not path:
            return
        if hashsets.is_nsrl_database(path):
            self._link_path(path)
            return
        dialog = ImportDialog(self.library, path, self)
        if dialog.exec() == QDialog.Accepted and dialog.entry:
            entry = dialog.entry
            self._audit('hash set imported', entry)
            self._fill()
            self.status.setText(
                f"Imported {entry['count']:,} digest(s) as "
                f"\"{entry['name']}\"."
                + (f" {entry['skipped_lines']:,} line(s) held none."
                   if entry.get('skipped_lines') else ''))

    def _link(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Link NSRL RDS Database", "",
            "NSRL RDS v3 (*.db *.sqlite *.sqlite3);;All files (*)")
        if path:
            self._link_path(path)

    def _link_path(self, path):
        try:
            entry = self.library.link_nsrl(path, category=KNOWN_GOOD)
        except hashsets.HashSetError as exc:
            message.warning(self, "Cannot link", str(exc))
            return
        self._audit('hash set linked', entry)
        self._fill()
        self.status.setText(
            f"Linked \"{entry['name']}\" as known good, matched by "
            + ', '.join(ALGORITHM_LABELS[a] for a in entry['algorithms'])
            + ". The database stays where it is and is opened read-only.")

    def _edit(self):
        entry = self._selected()
        if entry is None:
            return
        dialog = EditDialog(entry, self)
        if dialog.exec() == QDialog.Accepted:
            self.library.update(entry['id'], **dialog.fields())
            self._fill()

    def _export(self):
        entry = self._selected()
        if entry is None:
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Hash Set", f"{entry['name']}.txt",
            "Text (*.txt)")
        if not path:
            return
        try:
            written = self.library.export(entry['id'], path)
        except (OSError, hashsets.HashSetError) as exc:
            message.warning(self, "Export failed", str(exc))
            return
        self.status.setText(f"Exported {written:,} digest(s) to {path}.")

    def _remove(self):
        entry = self._selected()
        if entry is None:
            return
        linked = entry.get('kind') == 'linked'
        if not message.question(
                self, "Remove hash set",
                f"Remove \"{entry['name']}\" from your library?",
                "The linked database itself is not touched." if linked else
                "Its imported digests are deleted; the file it was imported "
                "from is not touched. Matches already recorded in cases "
                "stay until those cases match again."):
            return
        self.library.remove(entry['id'])
        self.options.get('sets', {}).pop(entry['id'], None)
        self._audit('hash set removed from library', entry)
        self._fill()

    def _audit(self, action, entry):
        if self.case is None:
            return
        detail = (f"name={entry['name']} category={entry['category']} "
                  f"digests={entry.get('count')} source={entry.get('source')}")
        if entry.get('source_sha256'):
            detail += f" source sha256={entry['source_sha256']}"
        self.case.record_event(action, detail)

    # --- saving -----------------------------------------------------------

    def collected_options(self):
        options = dict(self.options)
        options['enabled'] = self.use_box.isChecked()
        options['algorithms'] = [a for a, box in self.algorithm_boxes.items()
                                 if box.isChecked()] or list(ALGORITHMS)
        options['hide_known_good'] = self.hide_box.isChecked()
        options['alert_known_bad'] = self.alert_box.isChecked()
        options['auto_match'] = self.auto_box.isChecked()
        options['include_carved'] = self.carved_box.isChecked()
        return options

    def save(self):
        """Store the case's options; True if they changed."""
        if self.case is None:
            return False
        options = self.collected_options()
        if options == self._initial:
            return False
        self.case.set_setting('hashsets', options)
        used = [e['name'] for e in self._entries
                if hashsets.set_enabled_in(options, e)]
        self.case.record_event(
            'hash set options changed',
            f"enabled={options['enabled']} sets={', '.join(used) or 'none'} "
            f"algorithms={','.join(options['algorithms'])} "
            f"hide known good={options['hide_known_good']} "
            f"warn known bad={options['alert_known_bad']} "
            f"auto match={options['auto_match']}")
        self._initial = dict(options, sets=dict(options['sets']))
        return True

    def _match(self):
        self.save()
        self.match_requested.emit()
        self.accept()

    def accept(self):
        self.save()
        super().accept()


def _guess_category(path):
    name = os.path.basename(path).lower()
    if 'nsrl' in name or 'known' in name and 'good' in name:
        return KNOWN_GOOD
    if any(word in name for word in ('virusshare', 'malware', 'bad',
                                     'malicious', 'ioc')):
        return KNOWN_BAD
    return hashsets.NOTABLE

