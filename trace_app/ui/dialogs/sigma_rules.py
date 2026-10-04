"""Tools > Sigma Rules: the examiner's Sigma rule library, and this case's
use of it.

Import a rule file, a folder of rules, or a SigmaHQ release zip; each rule
is compiled on import, and what TRACE cannot run on Windows event logs (a
Linux or cloud rule, an aggregation) is counted with its reason rather
than run wrongly. Which sets a case uses, and the lowest level reported,
are the case's settings.
"""

import logging
import os

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (QAbstractItemView, QCheckBox, QComboBox,
                               QDialog, QDialogButtonBox, QFileDialog,
                               QFormLayout, QGroupBox, QHBoxLayout,
                               QHeaderView, QLabel, QLineEdit, QPushButton,
                               QTableWidget, QTableWidgetItem, QVBoxLayout)

from trace_app.core import sigma
from trace_app.ui import icons
from trace_app.ui.dialogs import message
from trace_app.ui.process_worker import ProcessWorker
from trace_app.ui.widgets.no_focus_delegate import NoFocusDelegate

logger = logging.getLogger('TRACE.SigmaDialog')

LEVEL_LABELS = {'informational': 'Informational and above',
                'low': 'Low and above', 'medium': 'Medium and above',
                'high': 'High and above', 'critical': 'Critical only'}


class SigmaWorker(ProcessWorker):
    """Runs the rules over one image's event logs in a child process."""

    progressed = Signal(int, int, str)
    finished_scan = Signal(int, str)

    kind = 'sigma'

    def __init__(self, image_path, case_folder, evidence_id, library_folder,
                 options, parent=None, unlock=None):
        super().__init__({'image_path': image_path,
                          'case_folder': case_folder,
                          'evidence_id': evidence_id,
                          'library': library_folder, 'options': options,
                          'unlock': unlock}, parent)

    def on_progress(self, done, total, path):
        self.progressed.emit(done, total, path)

    def on_done(self, count, error):
        self.finished_scan.emit(count, error)


class ImportSigmaDialog(QDialog):
    def __init__(self, source, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Import Sigma Rules")
        self.setObjectName("hashSetImportDialog")
        self.setWindowIcon(icons.icon(icons.LOGO))
        self.setMinimumWidth(520)
        layout = QVBoxLayout(self)
        count = len(sigma._rule_sources(source))
        intro = QLabel(f"<b>{os.path.basename(source.rstrip('/'))}</b> — "
                       f"{count:,} rule file(s). They are copied into your "
                       f"library and compiled now.")
        intro.setTextFormat(Qt.RichText)
        intro.setWordWrap(True)
        layout.addWidget(intro)
        form = QFormLayout()
        self.name = QLineEdit(os.path.splitext(os.path.basename(
            source.rstrip('/\\')))[0])
        form.addRow("Name:", self.name)
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


class SigmaRulesDialog(QDialog):
    #: The examiner asked to scan now (after the options were saved).
    scan_requested = Signal()

    def __init__(self, case=None, library=None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Sigma Rules")
        self.setObjectName("hashSetsDialog")
        self.setWindowIcon(icons.icon(icons.SIGMA))
        self.setMinimumSize(860, 540)
        self.case = case
        self.usable = sigma.available()
        self.library = library or sigma.Library()
        self.options = sigma.case_options(case, self.library)
        self._initial = dict(self.options, sets=dict(self.options['sets']))

        layout = QVBoxLayout(self)
        intro = QLabel(
            "Sigma rules describe suspicious activity in Windows event logs "
            "— log clearing, credential dumping, lateral movement, "
            "malicious services. Every event log on the images (wherever "
            "it is, a triage collection included) is checked; each event a "
            "rule matches is a finding with the rule's level and ATT&CK "
            "techniques. Import SigmaHQ's rules (a release zip) or your "
            "own.")
        intro.setObjectName("analysisModulesIntro")
        intro.setWordWrap(True)
        layout.addWidget(intro)
        if not self.usable:
            warning = QLabel("Sigma is unavailable on this system: "
                             + sigma.unavailable_reason())
            warning.setObjectName("bitlockerError")
            warning.setWordWrap(True)
            layout.addWidget(warning)

        self.use_box = QCheckBox("Check event logs with Sigma rules in this "
                                 "case")
        self.use_box.setObjectName("analysisModuleCheck")
        self.use_box.setChecked(bool(self.options.get('enabled')))
        layout.addWidget(self.use_box)

        self.table = QTableWidget()
        self.table.setObjectName("triageTable")
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(
            ['Use', 'Name', 'Rules run', 'Not run', 'Files', 'Added'])
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setItemDelegate(NoFocusDelegate(self.table))
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Interactive)
        header.setStretchLastSection(True)
        for column, width in enumerate((44, 260, 90, 90, 70)):
            self.table.setColumnWidth(column, width)
        self.table.itemChanged.connect(self._item_changed)
        self.table.itemSelectionChanged.connect(self._update_buttons)
        layout.addWidget(self.table, 1)

        row = QHBoxLayout()
        self.import_file = QPushButton("Import Rule File or Zip…")
        self.import_file.clicked.connect(lambda: self._import(folder=False))
        row.addWidget(self.import_file)
        self.import_folder = QPushButton("Import Rule Folder…")
        self.import_folder.clicked.connect(lambda: self._import(folder=True))
        row.addWidget(self.import_folder)
        self.remove_button = QPushButton("Remove")
        self.remove_button.clicked.connect(self._remove)
        row.addWidget(self.remove_button)
        row.addStretch(1)
        layout.addLayout(row)

        self.options_box = QGroupBox("How this case uses them")
        form = QFormLayout(self.options_box)
        self.level = QComboBox()
        for key, label in LEVEL_LABELS.items():
            self.level.addItem(label, key)
        index = self.level.findData(self.options.get('min_level') or 'low')
        self.level.setCurrentIndex(max(0, index))
        form.addRow("Report rules of level:", self.level)
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
                widget.setToolTip(sigma.unavailable_reason())
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
            use.setCheckState(Qt.Checked if sigma.set_enabled_in(
                self.options, entry) else Qt.Unchecked)
            use.setData(Qt.UserRole, entry['id'])
            self.table.setItem(row, 0, use)
            reasons = entry.get('unsupported_reasons') or {}
            values = (entry['name'], f"{entry.get('rule_count', 0):,}",
                      f"{entry.get('unsupported', 0):,}",
                      f"{len(entry.get('files') or []):,}",
                      (entry.get('added_utc') or '')[:10])
            for column, value in enumerate(values, start=1):
                cell = QTableWidgetItem(value)
                tip = [entry.get('description') or '',
                       f"From {entry.get('source')}"]
                if column == 3 and reasons:
                    tip = ["Not run on Windows event logs:"] + [
                        f"  {count:,}  {reason}" for reason, count in
                        sorted(reasons.items(), key=lambda kv: -kv[1])[:15]]
                cell.setToolTip('\n'.join(t for t in tip if t))
                self.table.setItem(row, column, cell)
        self.table.blockSignals(False)
        self._update_buttons()
        self.status.setText(
            f"{len(self._entries)} rule set(s) in your library." if
            self._entries else "Your library is empty. Import SigmaHQ's "
                               "release zip, a rule folder or a rule file "
                               "to begin.")

    def _selected(self):
        row = self.table.currentRow()
        return self._entries[row] if 0 <= row < len(self._entries) else None

    def _update_buttons(self):
        self.remove_button.setEnabled(self._selected() is not None)

    def _item_changed(self, item):
        if item.column() == 0:
            self.options.setdefault('sets', {})[item.data(Qt.UserRole)] = \
                item.checkState() == Qt.Checked

    def _import(self, folder):
        if folder:
            source = QFileDialog.getExistingDirectory(self, "Rule Folder")
        else:
            source, _ = QFileDialog.getOpenFileName(
                self, "Rule File or Zip", "",
                "Sigma rules (*.yml *.yaml *.zip);;All files (*)")
        if not source:
            return
        dialog = ImportSigmaDialog(source, self)
        if dialog.exec() != QDialog.Accepted:
            return
        try:
            entry = self.library.import_rules(
                source, dialog.name.text().strip() or None,
                dialog.description.text().strip())
        except (sigma.SigmaError, OSError, ValueError) as exc:
            message.warning(self, "Rules not imported",
                            "Nothing was imported.", str(exc))
            return
        if self.case is not None:
            self.case.record_event(
                'sigma rules imported',
                f"name={entry['name']} files={len(entry['sha256'])} "
                f"rules={entry['rule_count']} not run="
                f"{entry['unsupported']} source={entry['source']}")
        self.use_box.setChecked(True)
        self._fill()

    def _remove(self):
        entry = self._selected()
        if entry is None or not message.question(
                self, "Remove rule set",
                f"Remove \"{entry['name']}\" from your library?",
                "Its copied rule files are deleted; the originals are not "
                "touched. Detections already recorded stay until the case "
                "is scanned again."):
            return
        self.library.remove(entry['id'])
        self.options.get('sets', {}).pop(entry['id'], None)
        self._fill()

    def collected_options(self):
        return dict(self.options, enabled=self.use_box.isChecked(),
                    min_level=self.level.currentData())

    def save(self):
        if self.case is None:
            return False
        options = self.collected_options()
        if options == self._initial:
            return False
        self.case.set_setting('sigma', options)
        used = [e['name'] for e in self._entries
                if sigma.set_enabled_in(options, e)]
        self.case.record_event(
            'sigma options changed',
            f"enabled={options['enabled']} sets={', '.join(used) or 'none'} "
            f"min level={options['min_level']}")
        self._initial = dict(options, sets=dict(options['sets']))
        return True

    def _scan(self):
        self.save()
        self.scan_requested.emit()
        self.accept()

    def accept(self):
        self.save()
        super().accept()
