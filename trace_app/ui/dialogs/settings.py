"""Options > Settings: the examiner's preferences and this case's settings.

The pages are built from `core.settings.USER` / `CASE` (label and help
come from there), so a setting is described in one place. User settings
go to config.ini; case settings to the case, where each change is
audited (`settings.save_case`). With no case open -- quick triage -- the
case pages show the defaults in use and cannot be changed.
"""

import os

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (QCheckBox, QComboBox, QCompleter, QDialog,
                               QDialogButtonBox, QDoubleSpinBox, QFileDialog,
                               QFormLayout, QGridLayout, QHBoxLayout, QLabel,
                               QLineEdit, QPushButton, QSpinBox, QTabWidget,
                               QVBoxLayout, QWidget)

from trace_app.core import settings
from trace_app.ui import icons

#: page title -> (scope, keys). Order is the dialog's.
PAGES = (
    ("General", 'user', ('examiner', 'organisation', 'case_folder',
                         'size_units', 'verify_order', 'debug_log')),
    ("Display", 'mixed', (('user', 'show_deleted'), ('user', 'show_system'),
                          ('case', 'display_zone'))),
    ("Privacy && Network", 'case', ('offline', 'vt_uploads')),
    ("Analysis", 'case', ('hash_md5', 'hash_sha1', 'max_analysis_mb',
                          'max_inspect_mb', 'high_entropy', 'archive_depth',
                          'archive_member_mb', 'indicators')),
    ("Carving && Exports", 'case', ('carve_source', 'carve_min_kb',
                                    'analyse_carves', 'carve_write_copies',
                                    'carved_folder',
                                    'export_folder')),
)

#: Number ranges: key -> (lowest, highest, step or None for whole numbers).
RANGES = {
    'max_analysis_mb': (1, 1024 * 1024, None),
    'max_inspect_mb': (1, 4096, None),
    'high_entropy': (1.0, 8.0, 0.05),
    'archive_depth': (0, 32, None),
    'archive_member_mb': (1, 4096, None),
    'carve_min_kb': (0, 1024 * 1024, None),
}

CHOICES = {
    'size_units': settings.SIZE_UNITS,
    'carve_source': settings.CARVE_SOURCES,
    'verify_order': settings.VERIFY_ORDERS,
}

FOLDERS = ('case_folder', 'carved_folder', 'export_folder')

INDICATOR_LABELS = {
    'email': "E-mail addresses", 'url': "URLs", 'domain': "Domains",
    'ip': "IPv4 addresses", 'ipv6': "IPv6 addresses",
    'phone': "Phone numbers", 'card': "Payment cards", 'iban': "IBANs",
    'btc': "Bitcoin addresses", 'hash': "Hashes",
}


class SettingsDialog(QDialog):
    def __init__(self, case=None, parent=None):
        super().__init__(parent)
        self.case = case
        self.setWindowTitle("Settings")
        self.setObjectName("settingsDialog")
        self.setWindowIcon(icons.icon(icons.LOGO))
        self.setMinimumWidth(620)
        self.user_values = settings.read_user()
        self.case_values = settings.for_case(case)
        self.editors = {}          # (scope, key) -> (widget, read function)
        self.changed = {}          # filled on accept: case keys changed

        layout = QVBoxLayout(self)
        self.tabs = QTabWidget()
        self.tabs.setObjectName("settingsTabs")
        layout.addWidget(self.tabs)
        for title, scope, keys in PAGES:
            self.tabs.addTab(self._page(scope, keys), title.replace('&&', '&'))

        buttons = QDialogButtonBox(QDialogButtonBox.Ok |
                                   QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    # --- building ---------------------------------------------------------

    def _page(self, scope, keys):
        page = QWidget()
        outer = QVBoxLayout(page)
        form = QFormLayout()
        form.setFieldGrowthPolicy(QFormLayout.ExpandingFieldsGrow)
        outer.addLayout(form)
        has_case_settings = False
        for item in keys:
            item_scope, key = item if isinstance(item, tuple) else (scope, item)
            spec = (settings.USER if item_scope == 'user' else
                    settings.CASE)[key]
            values = (self.user_values if item_scope == 'user' else
                      self.case_values)
            widget, read = self._editor(key, spec, values[key])
            widget.setToolTip(spec[2])
            if item_scope == 'case':
                has_case_settings = True
                widget.setEnabled(self.case is not None)
            self.editors[(item_scope, key)] = (widget, read)
            if isinstance(widget, QCheckBox):
                form.addRow(widget)
            else:
                form.addRow(spec[1], widget)
            hint = QLabel(spec[2])
            hint.setObjectName("settingsHint")
            hint.setWordWrap(True)
            form.addRow('', hint)
        if scope == 'user' and 'debug_log' in keys:
            open_log = QPushButton("Open Log Folder")
            open_log.clicked.connect(self._open_log_folder)
            form.addRow('', open_log)
        if has_case_settings:
            note = QLabel(
                "Kept in this case and written to its audit trail when "
                "changed; the report states them." if self.case is not None
                else "No case is open (quick triage): these are the "
                     "defaults in use. Open a case to change them.")
            note.setObjectName("settingsScopeNote")
            note.setWordWrap(True)
            outer.addWidget(note)
        outer.addStretch(1)
        return page

    def _editor(self, key, spec, value):
        default = spec[0]
        if key == 'indicators':
            return self._indicators(value)
        if key in FOLDERS:
            return self._folder(key, value)
        if key in CHOICES:
            combo = QComboBox()
            for choice in CHOICES[key]:
                combo.addItem(choice, choice)
            combo.setCurrentIndex(max(0, combo.findData(value)))
            return combo, combo.currentData
        if isinstance(default, bool):
            box = QCheckBox(spec[1])
            box.setChecked(bool(value))
            return box, box.isChecked
        if key in RANGES:
            low, high, step = RANGES[key]
            if step is None:
                spin = QSpinBox()
                spin.setRange(low, high)
                spin.setGroupSeparatorShown(True)
                spin.setValue(int(value))
            else:
                spin = QDoubleSpinBox()
                spin.setRange(low, high)
                spin.setSingleStep(step)
                spin.setDecimals(2)
                spin.setValue(float(value))
            return spin, spin.value
        edit = QLineEdit(str(value or ''))
        if key == 'display_zone':
            edit.setPlaceholderText("UTC only (e.g. Europe/Sofia)")
            completer = QCompleter(settings.zones(), edit)
            completer.setCaseSensitivity(Qt.CaseInsensitive)
            completer.setFilterMode(Qt.MatchContains)
            edit.setCompleter(completer)
        return edit, lambda: edit.text().strip()

    def _folder(self, key, value):
        holder = QWidget()
        row = QHBoxLayout(holder)
        row.setContentsMargins(0, 0, 0, 0)
        edit = QLineEdit(value or '')
        edit.setPlaceholderText("Default" if key == 'case_folder' else
                                "The case's own folder")
        browse = QPushButton("Browse...")

        def choose():
            folder = QFileDialog.getExistingDirectory(
                self, settings.USER.get(key, settings.CASE.get(key))[1],
                edit.text() or os.path.expanduser('~'))
            if folder:
                edit.setText(os.path.normpath(folder))
        browse.clicked.connect(choose)
        row.addWidget(edit, 1)
        row.addWidget(browse)
        holder.line_edit = edit
        return holder, lambda: edit.text().strip()

    def _indicators(self, value):
        holder = QWidget()
        grid = QGridLayout(holder)
        grid.setContentsMargins(0, 0, 0, 0)
        boxes = {}
        for index, kind in enumerate(settings.INDICATORS):
            box = QCheckBox(INDICATOR_LABELS.get(kind, kind))
            box.setChecked(kind in value)
            boxes[kind] = box
            grid.addWidget(box, index // 2, index % 2)
        holder.boxes = boxes
        return holder, lambda: [kind for kind, box in boxes.items()
                                if box.isChecked()]

    def _open_log_folder(self):
        from trace_app.infra.paths import log_file
        QDesktopServices.openUrl(
            QUrl.fromLocalFile(os.path.dirname(log_file())))

    # --- saving -----------------------------------------------------------

    def values(self, scope):
        return {key: read() for (item_scope, key), (_, read)
                in self.editors.items() if item_scope == scope}

    def problem(self):
        """Why the values cannot be saved, or None."""
        chosen = self.values('case')
        zone = chosen.get('display_zone', '')
        if self.case is not None and not settings.valid_zone(zone):
            return (f"'{zone}' is not a time zone this system knows. Use a "
                    "name such as Europe/Sofia or America/New_York, or leave "
                    "it empty for UTC only.")
        for key in ('carved_folder', 'export_folder'):
            folder = chosen.get(key)
            if self.case is not None and folder and not os.path.isdir(folder):
                return (f"{settings.CASE[key][1]}: {folder} does not exist.")
        return None

    def accept(self):
        problem = self.problem()
        if problem:
            from trace_app.ui.dialogs import message
            message.warning(self, "Settings not saved", problem)
            return
        user_values = dict(self.user_values)
        user_values.update(self.values('user'))
        settings.save_user(user_values)
        if self.case is not None:
            self.changed = settings.save_case(self.case, self.values('case'))
        super().accept()
