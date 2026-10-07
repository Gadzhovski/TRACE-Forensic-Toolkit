"""Options > Settings: the examiner's preferences and this case's settings.

The pages are built from `core.settings.USER` / `CASE` (label and help
come from there), so a setting is described in one place. User settings
go to config.ini; case settings to the case, where each change is
audited (`settings.save_case`). With no case open -- quick triage -- the
case pages show the defaults in use and cannot be changed.
"""

import os

from PySide6.QtCore import QSize, Qt, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (QCheckBox, QComboBox, QCompleter, QDialog,
                               QDialogButtonBox, QDoubleSpinBox, QFileDialog,
                               QFrame, QGridLayout, QHBoxLayout, QLabel,
                               QLineEdit, QListWidget, QListWidgetItem,
                               QPushButton, QScrollArea, QSpinBox,
                               QStackedWidget, QVBoxLayout, QWidget)

from trace_app.core import settings
from trace_app.ui import icons

#: The pages, in order: (title, icon, introduction, sections), each
#: section (heading or None, scope, keys).
PAGES = (
    ("General", icons.SETTINGS,
     "Who you are, where cases start, how sizes read. Kept for you on this "
     "computer, in every case.",
     ((None, 'user', ('examiner', 'organisation', 'case_folder')),
      ("Working", 'user', ('size_units', 'verify_order')),
      ("Troubleshooting", 'user', ('debug_log',)))),
    ("Display", icons.DISPLAY,
     "What the Listing shows, and the time zone shown beside UTC.",
     (("Listing", 'user', ('show_deleted', 'show_system')),
      ("Times", 'case', ('display_zone',)))),
    ("Privacy & Network", icons.VOLUME_LOCKED,
     "Whether anything from this case may leave this computer.",
     ((None, 'case', ('offline', 'vt_uploads')),)),
    ("Analysis", icons.TRIAGE,
     "What the analysis modules hash, read and extract.",
     (("Hashes", 'case', ('hash_md5', 'hash_sha1')),
      ("Limits", 'case', ('max_analysis_mb', 'max_inspect_mb',
                          'high_entropy')),
      ("Archives", 'case', ('archive_depth', 'archive_member_mb')),
      ("Indicators", 'case', ('indicators',)))),
    ("Carving & Exports", icons.FINDING_CARVED,
     "How files are carved, and where copies and exports are written.",
     (("Carving", 'case', ('carve_source', 'carve_min_kb', 'analyse_carves',
                           'carve_write_copies')),
      ("Folders", 'case', ('carved_folder', 'export_folder')))),
)

#: How far a checkbox's explanation is indented: past its box, so it lines
#: up with the label's text.
SETTING_INDENT = 24

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
        self.resize(820, 600)
        self.setMinimumSize(680, 460)
        self.user_values = settings.read_user()
        self.case_values = settings.for_case(case)
        self.editors = {}          # (scope, key) -> (widget, read function)
        self.changed = {}          # filled on accept: case keys changed

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        body = QHBoxLayout()
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(0)
        layout.addLayout(body, 1)

        # The pages down the side; one at a time beside them.
        self.nav = QListWidget()
        self.nav.setObjectName("settingsNav")
        self.nav.setIconSize(QSize(16, 16))
        self.nav.setFixedWidth(190)
        self.pages = QStackedWidget()
        self.pages.setObjectName("settingsPages")
        for title, icon_name, intro, sections in PAGES:
            QListWidgetItem(icons.icon(icon_name), title, self.nav)
            self.pages.addWidget(self._page(title, intro, sections))
        self.nav.currentRowChanged.connect(self.pages.setCurrentIndex)
        self.nav.setCurrentRow(0)
        body.addWidget(self.nav)
        body.addWidget(self.pages, 1)

        footer = QFrame()
        footer.setObjectName("settingsFooter")
        row = QHBoxLayout(footer)
        row.setContentsMargins(16, 10, 12, 10)
        where = QLabel(
            "Your settings are kept on this computer; Case settings in the "
            "case." if case is not None else
            "Quick triage: Case settings show the defaults in use.")
        where.setObjectName("settingsHint")
        row.addWidget(where, 1)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok |
                                   QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        row.addWidget(buttons)
        layout.addWidget(footer)

    def page_count(self):
        return self.pages.count()

    def show_page(self, index):
        self.nav.setCurrentRow(index)

    # --- building ---------------------------------------------------------

    def _page(self, title, intro, sections):
        """One page: its title, what it is for, then each setting with its
        explanation beneath it -- in a scroll area, so a long page never
        squeezes its rows."""
        content = QWidget()
        content.setObjectName("settingsPage")
        column = QVBoxLayout(content)
        column.setContentsMargins(24, 18, 24, 18)
        column.setSpacing(0)
        heading = QLabel(title)
        heading.setObjectName("settingsPageTitle")
        column.addWidget(heading)
        about = QLabel(intro)
        about.setObjectName("settingsPageIntro")
        about.setWordWrap(True)
        column.addWidget(about)

        if any(scope == 'case' for _heading, scope, _keys in sections):
            note = QLabel(
                "Settings marked Case are kept in this case and written to "
                "its audit trail when changed; the report states them."
                if self.case is not None else
                "No case is open (quick triage): settings marked Case show "
                "the defaults in use. Open a case to change them.")
            note.setObjectName("settingsScopeNote")
            note.setWordWrap(True)
            column.addWidget(note)

        for section, scope, keys in sections:
            if section:
                label = QLabel(section)
                label.setObjectName("settingsSection")
                column.addWidget(label)
            for key in keys:
                column.addWidget(self._row(scope, key))
            if 'debug_log' in keys:
                open_log = QPushButton("Open Log Folder")
                open_log.clicked.connect(self._open_log_folder)
                holder = QHBoxLayout()
                holder.setContentsMargins(SETTING_INDENT - 8, 6, 0, 0)
                holder.addWidget(open_log)
                holder.addStretch(1)
                column.addLayout(holder)
        column.addStretch(1)

        scroll = QScrollArea()
        scroll.setObjectName("settingsScroll")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setWidget(content)
        return scroll

    def _row(self, scope, key):
        """A setting: its label (or the checkbox itself), the editor, and
        its explanation in the page's full width under it."""
        spec = (settings.USER if scope == 'user' else settings.CASE)[key]
        values = self.user_values if scope == 'user' else self.case_values
        widget, read = self._editor(key, spec, values[key])
        widget.setToolTip(spec[2])
        if scope == 'case':
            widget.setEnabled(self.case is not None)
        self.editors[(scope, key)] = (widget, read)

        row = QWidget()
        row.setObjectName("settingsRow")
        lines = QVBoxLayout(row)
        lines.setContentsMargins(0, 12, 0, 0)
        lines.setSpacing(5)
        top = QHBoxLayout()
        top.setSpacing(8)
        if isinstance(widget, QCheckBox):
            top.addWidget(widget)
            indent = SETTING_INDENT
        else:
            name = QLabel(spec[1])
            name.setObjectName("settingsLabel")
            name.setBuddy(widget)
            top.addWidget(name)
            indent = 0
        if scope == 'case':
            tag = QLabel("Case")
            tag.setObjectName("settingsScopeTag")
            tag.setToolTip("Kept in this case and audited when changed")
            top.addWidget(tag)
        top.addStretch(1)
        lines.addLayout(top)
        if not isinstance(widget, QCheckBox):
            field = QHBoxLayout()
            stretches = self._stretches(widget)
            field.addWidget(widget, 1 if stretches else 0)
            if not stretches:
                field.addStretch(1)
            lines.addLayout(field)
        hint = QLabel(spec[2])
        hint.setObjectName("settingsHint")
        hint.setWordWrap(True)
        hint.setContentsMargins(indent, 0, 0, 0)
        lines.addWidget(hint)
        return row

    @staticmethod
    def _stretches(widget):
        """Text and folder fields take the page's width; numbers and
        choices keep their own."""
        return isinstance(widget, QLineEdit) or \
            hasattr(widget, 'line_edit') or hasattr(widget, 'boxes')

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
            combo.setMinimumWidth(220)
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
            spin.setMinimumWidth(140)
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
        grid.setContentsMargins(0, 2, 0, 2)
        grid.setHorizontalSpacing(24)
        grid.setVerticalSpacing(8)
        boxes = {}
        for index, kind in enumerate(settings.INDICATORS):
            box = QCheckBox(INDICATOR_LABELS.get(kind, kind))
            box.setChecked(kind in value)
            boxes[kind] = box
            grid.addWidget(box, index // 3, index % 3)
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
