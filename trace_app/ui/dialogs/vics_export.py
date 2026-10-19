"""Case ▸ Export for Other Tools ▸ Project VICS: which evidence, where,
the case details the JSON carries, and what to include (core/vics.py).

Works in quick triage too -- the export reads the evidence itself, so an
at-scene triage can hand its pictures to Griffeye with no case made. The
export runs as a job (`VicsWorker`, a child process)."""

import os

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (QCheckBox, QComboBox, QDialog,
                               QDialogButtonBox, QFileDialog, QFormLayout,
                               QHBoxLayout, QLabel, QLineEdit, QListWidget,
                               QListWidgetItem, QPushButton, QSpinBox,
                               QVBoxLayout)

from trace_app.core import vics
from trace_app.ui.process_worker import ProcessWorker

#: (key in the JSON, label) for the case details the dialog asks.
CONTACT_FIELDS = (('ContactName', "Contact name"),
                  ('ContactOrganization', "Organisation"),
                  ('ContactTitle', "Title"),
                  ('ContactPhone', "Phone"),
                  ('ContactEmail', "Email"))


class VicsExportDialog(QDialog):
    """`evidence` is [{'key', 'name', 'source_id', 'path'}]; `defaults`
    may hold 'folder', 'case_number', 'ContactName', 'ContactOrganization'
    and 'scope' (a description of the case's analysis scope, or '')."""

    def __init__(self, evidence, defaults=None, parent=None):
        super().__init__(parent)
        defaults = defaults or {}
        self.setWindowTitle("Export Project VICS")
        self.setObjectName("vicsExportDialog")
        self.setMinimumWidth(520)
        layout = QVBoxLayout(self)
        intro = QLabel(
            "The pictures and videos on the evidence -- found by content, "
            "not by name -- copied out with a Project VICS 2.0 JSON file, "
            "for Griffeye, AXIOM and other media review tools.")
        intro.setObjectName("settingsHint")
        intro.setWordWrap(True)
        layout.addWidget(intro)

        layout.addWidget(QLabel("Evidence"))
        self.evidence_list = QListWidget()
        self.evidence_list.setObjectName("vicsEvidenceList")
        for row in evidence:
            entry = QListWidgetItem(row['name'])
            entry.setFlags(entry.flags() | Qt.ItemIsUserCheckable)
            entry.setCheckState(Qt.Checked)
            entry.setData(Qt.UserRole, row)
            entry.setToolTip(row.get('path') or '')
            self.evidence_list.addItem(entry)
        self.evidence_list.setMaximumHeight(
            max(60, min(6, len(evidence)) * 26))
        self.evidence_list.itemChanged.connect(self._update_ok)
        layout.addWidget(self.evidence_list)

        form = QFormLayout()
        folder_row = QHBoxLayout()
        self.folder_field = QLineEdit(defaults.get('folder') or '')
        self.folder_field.textChanged.connect(self._update_ok)
        browse = QPushButton("Browse…")
        browse.clicked.connect(self._browse)
        folder_row.addWidget(self.folder_field, 1)
        folder_row.addWidget(browse)
        form.addRow("Save in", folder_row)
        # Required: Griffeye shows it as the case, and it names the JSON
        # and the Files.<case> folder.
        self.case_number = QLineEdit(defaults.get('case_number') or '')
        self.case_number.setPlaceholderText("required")
        self.case_number.textChanged.connect(self._update_ok)
        form.addRow("Case number", self.case_number)
        self.contact = {}
        for key, label in CONTACT_FIELDS:
            field = QLineEdit(defaults.get(key) or '')
            self.contact[key] = field
            form.addRow(label, field)
        self.model_combo = QComboBox()
        for model in vics.MODELS:
            self.model_combo.addItem(f"VICS 2.0 ({model})", model)
        self.model_combo.setToolTip(
            "The model's profile in the JSON header. US is Project VIC's; "
            "Griffeye writes CUSTOM in its own exports.")
        form.addRow("Data model", self.model_combo)
        self.min_size = QSpinBox()
        self.min_size.setRange(0, 1024 * 1024)
        self.min_size.setSuffix(" KB")
        self.min_size.setValue(int(defaults.get('min_size_kb') or 0))
        self.min_size.setToolTip("Leave out smaller files (icons, web "
                                 "graphics). 0 exports everything.")
        form.addRow("Smallest file", self.min_size)
        layout.addLayout(form)

        self.deleted_box = QCheckBox("Include deleted files")
        self.deleted_box.setChecked(True)
        layout.addWidget(self.deleted_box)
        self.carved_box = QCheckBox("Include carved files")
        self.carved_box.setChecked(True)
        self.carved_box.setToolTip("Pictures and videos carving found; "
                                   "marked Unallocated, with their offset")
        layout.addWidget(self.carved_box)

        notes = ["Each picture is copied once, named by its MD5; every place "
                 "it was found is listed under it.",
                 "Nothing is categorised. PhotoDNA is not written -- the "
                 "reviewing tool computes it.",
                 "FAT times record local time with no zone: they are left "
                 "out of the JSON and kept in the export's manifest."]
        if defaults.get('scope'):
            notes.insert(0, f"Scope: {defaults['scope']}")
        hint = QLabel('\n'.join(notes))
        hint.setObjectName("settingsHint")
        hint.setWordWrap(True)
        layout.addWidget(hint)

        self.buttons = QDialogButtonBox(QDialogButtonBox.Ok |
                                        QDialogButtonBox.Cancel)
        self.buttons.button(QDialogButtonBox.Ok).setText("Export")
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        layout.addWidget(self.buttons)
        self._update_ok()

    def _browse(self):
        chosen = QFileDialog.getExistingDirectory(
            self, "Save the VICS export in", self.folder_field.text())
        if chosen:
            self.folder_field.setText(chosen)

    def chosen_evidence(self):
        out = []
        for index in range(self.evidence_list.count()):
            entry = self.evidence_list.item(index)
            if entry.checkState() == Qt.Checked:
                out.append(entry.data(Qt.UserRole))
        return out

    def _update_ok(self, *_args):
        folder = self.folder_field.text().strip()
        self.buttons.button(QDialogButtonBox.Ok).setEnabled(
            bool(self.chosen_evidence()) and bool(folder)
            and os.path.isdir(folder)
            and bool(self.case_number.text().strip()))

    @property
    def options(self):
        return {'evidence': self.chosen_evidence(),
                'parent_folder': self.folder_field.text().strip(),
                'case_number': self.case_number.text().strip(),
                'contact': {key: field.text().strip()
                            for key, field in self.contact.items()},
                'model': self.model_combo.currentData(),
                'include_deleted': self.deleted_box.isChecked(),
                'include_carved': self.carved_box.isChecked(),
                'min_size': self.min_size.value() * 1024}


class VicsWorker(ProcessWorker):
    """The export in a child process (core/background.job_vics)."""

    progressed = Signal(object, object, str)
    summary_ready = Signal(dict)
    finished_export = Signal(int, str)

    kind = 'vics'

    def on_progress(self, examined, copied, what):
        self.progressed.emit(examined, copied, what)

    def on_item(self, record):
        self.summary_ready.emit(record)

    def on_done(self, count, error):
        self.finished_export.emit(count, error)
