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
from trace_app.infra import ui_scale
from trace_app.ui import icons

#: The pages, in order: (title, icon, introduction, sections), each
#: section (heading or None, scope, keys).
PAGES = (
    ("General", icons.SETTINGS,
     "Who you are, where cases start, how sizes read. Kept for you on this "
     "computer, in every case.",
     ((None, 'user', ('examiner', 'organisation', 'case_folder',
                      'modules_folder')),
      ("Working", 'user', ('size_units', 'verify_order',
                           'worker_processes')),
      ("Troubleshooting", 'user', ('debug_log',)))),
    ("Display", icons.DISPLAY,
     "What the Listing shows, and the time zone shown beside UTC.",
     (("Interface", 'user', ('ui_scale',)),
      ("Listing", 'user', ('show_deleted', 'show_system')),
      ("Times", 'case', ('display_zone',)))),
    ("Privacy & Network", icons.VOLUME_LOCKED,
     "Whether anything from this case may leave this computer.",
     ((None, 'case', ('offline', 'vt_uploads')),
      ("This computer", 'user', ('check_updates', 'check_updates_at_start')))),
    ("API Keys", icons.API_KEYS,
     "Your own keys for the online services TRACE can use. Kept for you on "
     "this computer -- never in a case, a report or the log.",
     ((None, 'keys', ('virustotal', 'google_maps')),)),
    ("Analysis", icons.TRIAGE,
     "What the analysis modules hash, read and extract.",
     (("Hashes", 'case', ('hash_md5', 'hash_sha1')),
      ("Limits", 'case', ('max_analysis_mb', 'max_inspect_mb',
                          'high_entropy')),
      ("Archives", 'case', ('archive_depth', 'archive_member_mb')),
      ("Search index", 'case', ('index_unallocated',
                                'index_memory_files')),
      ("Indicators", 'case', ('indicators',)))),
    ("Results", icons.TIMELINE_FILTER,
     "What TRACE keeps and where it shows it: the Activity tab and Triage, "
     "the Timeline, Search and the report. On a large phone or Mac "
     "extraction, keeping out what you do not need is also what keeps "
     "TRACE quick.",
     (("TRACE's own results", 'case', ('activity_categories',
                                       'timeline_activity_categories',
                                       'timeline_sources')),
      ("External tools (iLEAPP, aLEAPP, ...)", 'case', (
          'module_destinations', 'module_import_rows',
          'module_link_readings')))),
    ("Carving & Exports", icons.FINDING_CARVED,
     "How files are carved, and where copies and exports are written.",
     (("Carving", 'case', ('carve_source', 'carve_min_kb',
                           'carve_unaligned_pictures', 'analyse_carves',
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
    'worker_processes': (0, 64, None),
    'module_import_rows': (0, 100_000_000, None),
}

CHOICES = {
    'size_units': settings.SIZE_UNITS,
    'carve_source': settings.CARVE_SOURCES,
    'verify_order': settings.VERIFY_ORDERS,
    'ui_scale': ui_scale.SCALES,
}

FOLDERS = ('case_folder', 'modules_folder', 'carved_folder',
           'export_folder')


def _activity_kinds():
    from trace_app.core.activity import CATEGORIES
    return list(CATEGORIES)


def _timeline_sources():
    from trace_app.core import timeline
    return [(key, label) for key, label, _colour in timeline.SOURCES]


#: List settings shown as ticks: key -> (options as [(value, label)],
#: columns). Every option ticked is stored as [] -- "all", which takes in
#: what a later TRACE adds (settings.ALL_WHEN_EMPTY).
TICK_LISTS = {
    'activity_categories': (_activity_kinds, 2),
    'timeline_activity_categories': (_activity_kinds, 2),
    'timeline_sources': (_timeline_sources, 3),
}

#: The API Keys page's keys (infra/api_keys.py names): label and help.
API_KEYS = {
    'virustotal': (
        "VirusTotal API key",
        "Used for VirusTotal ▸ Look Up Hash and Upload File on a file's "
        "menu. A free key allows four lookups a minute and 500 a day."),
    'google_maps': (
        "Google Maps API key",
        "A Google Maps Platform key with the Map Tiles API enabled (Google "
        "Cloud console). Used only for the Map's Google styles, and only "
        "after you agree to fetch tiles; Google bills the key's project "
        "past its free monthly allowance."),
}

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
        #: Filled on accept: the API keys changed, {name: new key}.
        self.keys_changed = {}

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

    def show_page_named(self, title):
        """Open on the page called `title` (Options ▸ API Keys did)."""
        for index, page in enumerate(PAGES):
            if page[0] == title:
                self.show_page(index)
                return True
        return False

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
        if any(scope == 'keys' for _heading, scope, _keys in sections):
            column.addWidget(self._keys_note())

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

    def _key_row(self, key):
        """An API key: its name, a hidden field with Show beside it, what
        it is for -- laid out as every other setting."""
        from trace_app.infra import api_keys
        label, help_text = API_KEYS[key]
        edit = QLineEdit(api_keys.get(key))
        edit.setObjectName("apiKeyField")
        edit.setEchoMode(QLineEdit.Password)
        edit.setPlaceholderText("Not set")
        edit.setToolTip(help_text)
        show = QPushButton("Show")
        show.setCheckable(True)
        show.setToolTip("Show or hide the key")

        def shown(on):
            edit.setEchoMode(QLineEdit.Normal if on else QLineEdit.Password)
            show.setText("Hide" if on else "Show")
        show.toggled.connect(shown)
        self.editors[('keys', key)] = (edit, lambda: edit.text().strip())

        row = QWidget()
        row.setObjectName("settingsRow")
        lines = QVBoxLayout(row)
        lines.setContentsMargins(0, 12, 0, 0)
        lines.setSpacing(5)
        name = QLabel(label)
        name.setObjectName("settingsLabel")
        name.setBuddy(edit)
        lines.addWidget(name)
        field = QHBoxLayout()
        field.addWidget(edit, 1)
        field.addWidget(show)
        lines.addLayout(field)
        hint = QLabel(help_text)
        hint.setObjectName("settingsHint")
        hint.setWordWrap(True)
        lines.addWidget(hint)
        return row

    def _keys_note(self):
        from trace_app.infra import api_keys
        note = QLabel(f"Keys are kept in {api_keys.store_name()}. Leave a "
                      "field empty to remove its key.")
        note.setObjectName("settingsScopeNote")
        note.setWordWrap(True)
        return note

    def _row(self, scope, key):
        """A setting: its label (or the checkbox itself), the editor, and
        its explanation in the page's full width under it."""
        if scope == 'keys':
            return self._key_row(key)
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
        if key in TICK_LISTS:
            return self._ticks(key, value)
        if key == 'module_destinations':
            return self._destinations(value)
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
        edit.setPlaceholderText("Default" if key in ('case_folder',
                                                    'modules_folder') else
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

    def _ticks(self, key, value):
        """Ticks for a list setting whose empty value means all (Results
        page): All / None beside them."""
        options, columns = TICK_LISTS[key]
        options = options()
        every = not value
        if key == 'timeline_sources' and every:
            from trace_app.core import timeline
            value = timeline.default_sources()
            every = False
        holder = QWidget()
        lines = QVBoxLayout(holder)
        lines.setContentsMargins(0, 2, 0, 2)
        lines.setSpacing(6)
        grid = QGridLayout()
        grid.setHorizontalSpacing(24)
        grid.setVerticalSpacing(8)
        boxes = {}
        rows = (len(options) + columns - 1) // columns
        for index, (option, label) in enumerate(options):
            box = QCheckBox(label)
            box.setChecked(every or option in value)
            boxes[option] = box
            # Down the columns, as a list reads.
            grid.addWidget(box, index % rows, index // rows)
        lines.addLayout(grid)
        quick = QHBoxLayout()
        quick.setSpacing(6)
        for text, state in (("All", True), ("None", False)):
            button = QPushButton(text)
            button.setObjectName("settingsSmallButton")
            button.clicked.connect(
                lambda _c=False, s=state: [b.setChecked(s)
                                           for b in boxes.values()])
            quick.addWidget(button)
        quick.addStretch(1)
        lines.addLayout(quick)
        holder.boxes = boxes

        def read():
            ticked = [option for option, box in boxes.items()
                      if box.isChecked()]
            if key == 'timeline_sources':
                from trace_app.core import timeline
                default = [k for k, _l, _c in timeline.SOURCES if k != 'case']
                return [] if ticked == default else ticked
            return [] if len(ticked) == len(boxes) else ticked
        return holder, read

    def _destinations(self, value):
        """Where an external tool's results go: a role per row (evidence,
        other records, telemetry), a place per column (Activity & Triage,
        Timeline, Search, Report), and what the case holds of each."""
        from trace_app.core.modules import destinations
        value = destinations.normalise(value)
        holder = QWidget()
        holder.boxes = {}
        lines = QVBoxLayout(holder)
        lines.setContentsMargins(0, 2, 0, 2)
        lines.setSpacing(6)
        grid = QGridLayout()
        grid.setHorizontalSpacing(18)
        grid.setVerticalSpacing(6)
        for column, (_place, label) in enumerate(destinations.PLACES,
                                                 start=1):
            head = QLabel(label)
            head.setObjectName("settingsLabel")
            grid.addWidget(head, 0, column, Qt.AlignCenter)
        held = self._module_rows()
        place_help = {
            'activity': "Evidence: a row per record in Activity, "
                        "Conversations and the Map. Others: the Activity ▸ "
                        "Others tabs, read from the tool's database.",
            'timeline': "An event per timestamp of each row -- copied "
                        "into the case.",
            'search': "Each row's text in the search index, its phones, "
                      "addresses and links in Indicators -- copied into "
                      "the case.",
            'report': "Evidence: the tool's records in the report's "
                      "Activity and Conversations. Others: listed among "
                      "the run's artifacts.",
        }
        for row, (role, label, about) in enumerate(destinations.ROLES,
                                                   start=1):
            name = QLabel(label)
            name.setObjectName("settingsLabel")
            count = held.get(role)
            name.setToolTip(about + (
                f"\nIn this case: {count[1]:,} rows in {count[0]:,} "
                f"artifacts." if count else ''))
            grid.addWidget(name, row * 2 - 1, 0)
            words = QLabel(about + (
                f" In this case: {count[1]:,} rows in {count[0]:,} "
                f"artifact(s)." if count else ''))
            words.setObjectName("settingsHint")
            words.setWordWrap(True)
            grid.addWidget(words, row * 2, 0, 1, len(destinations.PLACES) + 1)
            for column, (place, place_label) in enumerate(
                    destinations.PLACES, start=1):
                box = QCheckBox()
                box.setObjectName("settingsMatrixBox")
                box.setChecked(place in value[role])
                box.setToolTip(f"{label} -> {place_label}: "
                               f"{place_help[place]}")
                box.setAccessibleName(f"{label}: {place_label}")
                holder.boxes[(role, place)] = box
                grid.addWidget(box, row * 2 - 1, column, Qt.AlignCenter)
        grid.setColumnStretch(0, 1)
        lines.addLayout(grid)

        def read():
            return {role: [place for place in destinations.PLACE_KEYS
                           if holder.boxes[(role, place)].isChecked()]
                    for role in destinations.ROLE_KEYS}
        return holder, read

    def _module_rows(self):
        """{role: (artifacts, rows)} the case's complete runs hold, not
        superseded -- what each choice above concerns."""
        if self.case is None:
            return {}
        try:
            found = self.case._db.execute(
                "SELECT COALESCE(NULLIF(a.role, ''), 'other'), COUNT(*), "
                "COALESCE(SUM(a.row_count), 0) FROM module_artifacts a "
                "JOIN module_runs r ON r.id = a.run_id "
                "WHERE r.status = 'complete' AND a.superseded_by IS NULL "
                "AND a.row_count > 0 GROUP BY 1").fetchall()
        except Exception:
            return {}
        return {role: (artifacts, rows) for role, artifacts, rows in found}

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
        self._save_keys()
        super().accept()

    def _save_keys(self):
        """Store the API keys that changed (infra/api_keys.py: the system's
        protected store; nothing else in config.ini is touched). A key
        the store refuses is used for this session and the examiner told."""
        from trace_app.infra import api_keys
        self.keys_changed = {
            key: value for key, value in self.values('keys').items()
            if value != api_keys.get(key)}
        if not self.keys_changed:
            return
        problem = api_keys.save(self.keys_changed)
        if problem:
            from trace_app.ui.dialogs import message
            message.warning(
                self, "Could not save API key",
                f"The API key could not be stored:\n{problem}\n\n"
                "It will be used for this session only.")
