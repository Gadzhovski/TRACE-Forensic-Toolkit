"""Tools > YARA Rules: the examiner's rule library, and this case's use of it.

Import a rule file or a whole folder (includes kept); each is compiled on
import, so a broken rule is reported with its file, line and column and
nothing is kept. A set is graded *suspicious* (malware, tools) or
*notable* (anything worth seeing); a rule's own severity metadata can raise
a match. Which sets a case uses, whether carved files are scanned and how
much of a large file is read are the case's settings.

Where yara-x is not available (Windows on ARM), the dialog says so and
offers nothing it cannot do.
"""

import logging
import os

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (QAbstractItemView, QCheckBox, QComboBox,
                               QDialog, QDialogButtonBox, QFileDialog,
                               QFormLayout, QGroupBox, QHBoxLayout,
                               QHeaderView, QLabel, QLineEdit, QPushButton,
                               QSpinBox, QTableWidget, QTableWidgetItem,
                               QVBoxLayout)

from trace_app.core import yara_rules
from trace_app.ui import icons
from trace_app.ui.dialogs import message
from trace_app.ui.process_worker import ProcessWorker
from trace_app.ui.viewers.virustotal import verdict_brush
from trace_app.ui.widgets.no_focus_delegate import NoFocusDelegate

logger = logging.getLogger('TRACE.YaraDialog')

GRADE_LABELS = {'suspicious': 'Suspicious (malware, tools)',
                'notable': 'Notable (worth a look)'}


class YaraWorker(ProcessWorker):
    """Scans one image in a child process (core/background.py)."""

    progressed = Signal(int, int, str)
    finished_scan = Signal(int, str)

    kind = 'yara'

    def __init__(self, image_path, case_folder, evidence_id, library_folder,
                 options, parent=None):
        super().__init__({'image_path': image_path,
                          'case_folder': case_folder,
                          'evidence_id': evidence_id,
                          'library': library_folder, 'options': options},
                         parent)

    def on_progress(self, done, total, path):
        self.progressed.emit(done, total, path)

    def on_done(self, count, error):
        self.finished_scan.emit(count, error)


class ImportRulesDialog(QDialog):
    def __init__(self, source, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Import YARA Rules")
        self.setObjectName("hashSetImportDialog")
        self.setWindowIcon(icons.icon(icons.LOGO))
        self.setMinimumWidth(520)
        layout = QVBoxLayout(self)
        count = len(yara_rules._rule_files(source))
        intro = QLabel(f"<b>{os.path.basename(source.rstrip('/'))}</b> — "
                       f"{count} rule file(s). They are copied into your "
                       f"library and compiled now.")
        intro.setTextFormat(Qt.RichText)
        intro.setWordWrap(True)
        layout.addWidget(intro)
        form = QFormLayout()
        self.name = QLineEdit(os.path.splitext(os.path.basename(
            source.rstrip('/\\')))[0])
        form.addRow("Name:", self.name)
        self.grade = QComboBox()
        for key, label in GRADE_LABELS.items():
            self.grade.addItem(label, key)
        form.addRow("A match is:", self.grade)
        self.description = QLineEdit()
        self.description.setPlaceholderText("Where the rules came from")
        form.addRow("Description:", self.description)
        layout.addLayout(form)
        buttons = QDialogButtonBox()
        buttons.addButton("Import", QDialogButtonBox.AcceptRole)
        buttons.addButton(QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)


class YaraRulesDialog(QDialog):
    #: The examiner asked to scan now (after the options were saved).
    scan_requested = Signal()

    def __init__(self, case=None, library=None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("YARA Rules")
        self.setObjectName("hashSetsDialog")
        self.setWindowIcon(icons.icon(icons.FINDING_YARA))
        self.setMinimumSize(860, 540)
        self.case = case
        self.usable = yara_rules.available()
        self.library = library or yara_rules.Library()
        self.options = yara_rules.case_options(case, self.library)
        self._initial = dict(self.options, sets=dict(self.options['sets']))

        layout = QVBoxLayout(self)
        intro = QLabel(
            "YARA rules describe files by their content: malware families, "
            "tools, documents of interest. Every file and carved file of "
            "the images is scanned; a match is a finding with the rule and "
            "the strings it matched. Rules are kept in your library and "
            "chosen per case.")
        intro.setObjectName("analysisModulesIntro")
        intro.setWordWrap(True)
        layout.addWidget(intro)
        if not self.usable:
            warning = QLabel("YARA is unavailable on this system: "
                             + yara_rules.unavailable_reason())
            warning.setObjectName("bitlockerError")
            warning.setWordWrap(True)
            layout.addWidget(warning)

        self.use_box = QCheckBox("Scan with YARA rules in this case")
        self.use_box.setObjectName("analysisModuleCheck")
        self.use_box.setChecked(bool(self.options.get('enabled')))
        layout.addWidget(self.use_box)

        self.table = QTableWidget()
        self.table.setObjectName("triageTable")
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(
            ['Use', 'Name', 'A match is', 'Rules', 'Files', 'Added'])
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setItemDelegate(NoFocusDelegate(self.table))
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Interactive)
        header.setStretchLastSection(True)
        for column, width in enumerate((44, 260, 150, 70, 70)):
            self.table.setColumnWidth(column, width)
        self.table.itemChanged.connect(self._item_changed)
        self.table.itemSelectionChanged.connect(self._update_buttons)
        layout.addWidget(self.table, 1)

        row = QHBoxLayout()
        self.import_file = QPushButton("Import Rule File…")
        self.import_file.clicked.connect(lambda: self._import(folder=False))
        row.addWidget(self.import_file)
        self.import_folder = QPushButton("Import Rule Folder…")
        self.import_folder.clicked.connect(lambda: self._import(folder=True))
        row.addWidget(self.import_folder)
        self.grade_button = QPushButton("Change Grade")
        self.grade_button.clicked.connect(self._toggle_grade)
        row.addWidget(self.grade_button)
        self.remove_button = QPushButton("Remove")
        self.remove_button.clicked.connect(self._remove)
        row.addWidget(self.remove_button)
        row.addStretch(1)
        layout.addLayout(row)

        self.options_box = QGroupBox("How this case uses them")
        form = QFormLayout(self.options_box)
        self.carved_box = QCheckBox("Scan carved files too")
        self.carved_box.setChecked(bool(self.options.get('include_carved')))
        form.addRow(self.carved_box)
        self.max_size = QSpinBox()
        self.max_size.setRange(1, 4096)
        self.max_size.setSuffix(" MB")
        self.max_size.setValue(int(self.options.get('max_bytes')
                                   or yara_rules.DEFAULT_MAX_BYTES)
                               // (1024 * 1024))
        self.max_size.setToolTip("Larger files are scanned in their first "
                                 "part")
        form.addRow("Read at most per file:", self.max_size)
        layout.addWidget(self.options_box)

        self.status = QLabel()
        self.status.setObjectName("triageStatus")
        self.status.setWordWrap(True)
        layout.addWidget(self.status)

        buttons = QDialogButtonBox()
        self.scan_button = buttons.addButton("Save and Scan Now",
                                             QDialogButtonBox.ApplyRole)
        self.scan_button.clicked.connect(self._scan)
        close = buttons.addButton(QDialogButtonBox.Close)
        close.clicked.connect(self.accept)
        buttons.rejected.connect(self.accept)
        layout.addWidget(buttons)

        for widget in (self.import_file, self.import_folder, self.use_box,
                       self.options_box, self.scan_button):
            widget.setEnabled(self.usable)
            if not self.usable:
                widget.setToolTip(yara_rules.unavailable_reason())
        if case is None:
            for widget in (self.use_box, self.options_box, self.scan_button):
                widget.setEnabled(False)
        self._fill()

    def _fill(self):
        self.table.blockSignals(True)
        self._entries = self.library.sets()
        self.table.setRowCount(len(self._entries))
        for row, entry in enumerate(self._entries):
            use = QTableWidgetItem()
            use.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled
                         | Qt.ItemIsSelectable)
            use.setCheckState(Qt.Checked if yara_rules.set_enabled_in(
                self.options, entry) else Qt.Unchecked)
            use.setData(Qt.UserRole, entry['id'])
            self.table.setItem(row, 0, use)
            values = (entry['name'], GRADE_LABELS[entry['grade']].split(' (')[0],
                      str(entry.get('rule_count', '')),
                      str(len(entry.get('sha256') or entry['files'])),
                      (entry.get('added_utc') or '')[:10])
            for column, value in enumerate(values, start=1):
                cell = QTableWidgetItem(value)
                cell.setToolTip('\n'.join(p for p in (
                    entry.get('description'), f"From {entry.get('source')}",
                    *(f"{name}  {digest[:16]}…" for name, digest in sorted(
                        (entry.get('sha256') or {}).items())[:20])) if p))
                if column == 2:
                    cell.setForeground(verdict_brush(
                        'malicious' if entry['grade'] == 'suspicious'
                        else 'suspicious'))
                self.table.setItem(row, column, cell)
        self.table.blockSignals(False)
        self._update_buttons()
        self.status.setText(
            f"{len(self._entries)} rule set(s) in your library." if
            self._entries else "Your library is empty. Import a rule file "
                               "or a folder of rules to begin.")

    def _selected(self):
        row = self.table.currentRow()
        return self._entries[row] if 0 <= row < len(self._entries) else None

    def _update_buttons(self):
        has = self._selected() is not None
        self.grade_button.setEnabled(has)
        self.remove_button.setEnabled(has)

    def _item_changed(self, item):
        if item.column() == 0:
            self.options.setdefault('sets', {})[item.data(Qt.UserRole)] = \
                item.checkState() == Qt.Checked

    def _import(self, folder):
        if folder:
            source = QFileDialog.getExistingDirectory(self, "Rule Folder")
        else:
            source, _ = QFileDialog.getOpenFileName(
                self, "Rule File", "", "YARA rules (*.yar *.yara *.rule "
                                       "*.rules *.yr);;All files (*)")
        if not source:
            return
        dialog = ImportRulesDialog(source, self)
        if dialog.exec() != QDialog.Accepted:
            return
        try:
            entry = self.library.import_rules(
                source, dialog.name.text().strip() or None,
                dialog.grade.currentData(),
                dialog.description.text().strip())
        except (yara_rules.YaraError, OSError) as exc:
            message.warning(self, "Rules not imported",
                            "The rules did not compile, so nothing was "
                            "imported.", str(exc))
            return
        if self.case is not None:
            self.case.record_event(
                'yara rules imported',
                f"name={entry['name']} files={len(entry['sha256'])} "
                f"rules={entry.get('rule_count')} source={entry['source']} "
                + ' '.join(f"{n}={d}" for n, d in sorted(
                    entry['sha256'].items())))
        self.use_box.setChecked(True)
        self._fill()

    def _toggle_grade(self):
        entry = self._selected()
        if entry is None:
            return
        grade = 'notable' if entry['grade'] == 'suspicious' else 'suspicious'
        self.library.update(entry['id'], grade=grade)
        self._fill()

    def _remove(self):
        entry = self._selected()
        if entry is None or not message.question(
                self, "Remove rule set",
                f"Remove \"{entry['name']}\" from your library?",
                "Its copied rule files are deleted; the originals are not "
                "touched. Matches already recorded stay until the case is "
                "scanned again."):
            return
        self.library.remove(entry['id'])
        self.options.get('sets', {}).pop(entry['id'], None)
        self._fill()

    def collected_options(self):
        return dict(self.options, enabled=self.use_box.isChecked(),
                    include_carved=self.carved_box.isChecked(),
                    max_bytes=self.max_size.value() * 1024 * 1024)

    def save(self):
        if self.case is None:
            return False
        options = self.collected_options()
        if options == self._initial:
            return False
        self.case.set_setting('yara', options)
        used = [e['name'] for e in self._entries
                if yara_rules.set_enabled_in(options, e)]
        self.case.record_event(
            'yara options changed',
            f"enabled={options['enabled']} sets={', '.join(used) or 'none'} "
            f"carved={options['include_carved']} "
            f"max MB={options['max_bytes'] // (1024 * 1024)}")
        self._initial = dict(options, sets=dict(options['sets']))
        return True

    def _scan(self):
        self.save()
        self.scan_requested.emit()
        self.accept()

    def accept(self):
        self.save()
        super().accept()
