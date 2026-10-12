"""Choosing what a run covers (core/scope.py): a preset to start from, then
folders in or out, file names, types, sizes, dates and deleted files.

The analysis, the search index, YARA and the deleted-file check honour it;
the modules that read set places (activity, persistence, NTFS, Sigma's
event logs, thumbnail caches) or raw space (carving) do not, and the
dialog says so.
"""

from PySide6.QtCore import QDate, Qt, QTimer, Signal
from PySide6.QtWidgets import (QCheckBox, QComboBox, QDateEdit, QDialog,
                               QDialogButtonBox, QFrame, QGridLayout,
                               QHBoxLayout, QLabel, QLineEdit,
                               QPlainTextEdit, QPushButton, QScrollArea,
                               QSpinBox,
                               QVBoxLayout, QWidget)

from trace_app.core.scope import (CUSTOM, DELETED_EXCLUDE, DELETED_INCLUDE,
                                  DELETED_ONLY, PRESETS, TYPE_GROUPS, Scope)
from trace_app.ui import icons
from trace_app.ui.process_worker import ProcessWorker
from trace_app.ui.widgets import date_fields

#: What honours a scope, and what does not -- shown in the dialog.
COVERED = ("Applies to: file analysis, the search index, YARA and the "
           "deleted-file check. Not to activity, persistence, NTFS, "
           "file-system times, Sigma, thumbnail caches or carving: they "
           "read set places or raw space.")

RULE_HELP = ("One rule per line. ~/usr is at the top of the system "
             "(wherever it is: / on Windows, /root in Fedora's Btrfs "
             "layout); /home/alex is from the root of the volume; a bare "
             "name such as node_modules matches anywhere. * and ? are "
             "wildcards; case is ignored.")

_DELETED = ((DELETED_INCLUDE, "Included"), (DELETED_EXCLUDE, "Left out"),
            (DELETED_ONLY, "Only deleted files"))
#: Sizes are entered in megabytes.
_MB = 1024 * 1024


class _Rows:
    """QFormLayout's addRow over a QGridLayout: labels right-aligned at
    the top of their row, a label '' for a field's help line."""

    def __init__(self):
        self.grid = QGridLayout()
        self.grid.setHorizontalSpacing(12)
        self.grid.setVerticalSpacing(8)
        self.grid.setColumnStretch(1, 1)
        self._row = 0

    def addRow(self, label, field):
        if label:
            text = QLabel(label)
            self.grid.addWidget(text, self._row, 0,
                                Qt.AlignRight | Qt.AlignTop)
        if isinstance(field, QWidget):
            self.grid.addWidget(field, self._row, 1)
        else:
            self.grid.addLayout(field, self._row, 1)
        self._row += 1


class _CountWorker(ProcessWorker):
    """core/background.job_scope_count: files in scope, per image."""

    counted = Signal(object, object, str)        # in scope, total, error
    progressed = Signal(str)

    kind = 'scope_count'

    def __init__(self, params, parent=None):
        super().__init__(params, parent)
        self._kept = self._total = 0

    def on_progress(self, _done, _total, text):
        self.progressed.emit(text)

    def on_item(self, record):
        self._kept += record['in_scope']
        self._total += record['total']

    def on_done(self, count, error):
        if self._stop.is_set():
            return
        self.counted.emit(self._kept, self._total,
                          error or ('' if count else 'nothing could be '
                                    'listed'))


def preset_items():
    """[(key, label)] for a preset drop-down, Custom last."""
    return [(key, PRESETS[key][0]) for key in PRESETS] + [(CUSTOM, "Custom")]


class ScopeEditor(QDialog):
    """Edit a Scope; `scope()` is the result once accepted."""

    def __init__(self, scope=None, parent=None, evidence=None):
        """`evidence`: [{'name', 'path', 'unlock', 'handler'}] -- what the
        estimate counts (by path, in a background process) and Browse lists
        (open images: a 'handler'). None or []: neither is offered."""
        super().__init__(parent)
        self.evidence = list(evidence or [])
        self._counter = None
        self._count_timer = QTimer(self)
        self._count_timer.setSingleShot(True)
        self._count_timer.setInterval(600)
        self._count_timer.timeout.connect(self._count)
        self.setWindowTitle("What to Examine")
        self.setObjectName("scopeEditor")
        self.setWindowIcon(icons.icon(icons.LOGO))
        self.setMinimumWidth(620)
        self._loading = False

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(10)

        top = QHBoxLayout()
        top.addWidget(QLabel("Start from"))
        self.preset_combo = QComboBox()
        self.preset_combo.setObjectName("scopePresetCombo")
        for key, label in preset_items():
            self.preset_combo.addItem(label, key)
        self.preset_combo.currentIndexChanged.connect(self._preset_chosen)
        top.addWidget(self.preset_combo)
        self.preset_note = QLabel()
        self.preset_note.setObjectName("scopeNote")
        self.preset_note.setWordWrap(True)
        top.addWidget(self.preset_note, 1)
        layout.addLayout(top)

        # A grid, not a QFormLayout: the form mis-measured its wrapped help
        # lines, and the dialog came out shorter than its fields.
        form = _Rows()

        self.include_edit = self._rules_edit(
            "Empty: every folder.\n~/home\n~/Users")
        form.addRow("Only in folders",
                    self._with_browse(self.include_edit,
                                      "Folders to Examine"))
        self.exclude_edit = self._rules_edit(
            "~/usr\n~/Windows/WinSxS\nnode_modules")
        form.addRow("Leave out folders",
                    self._with_browse(self.exclude_edit,
                                      "Folders to Leave Out"))
        rules_help = QLabel(RULE_HELP)
        rules_help.setObjectName("scopeNote")
        rules_help.setWordWrap(True)
        form.addRow("", rules_help)

        self.names_edit = QLineEdit()
        self.names_edit.setObjectName("scopeNames")
        self.names_edit.setPlaceholderText("*.so, *.ko.xz, *.mui")
        self.names_edit.setToolTip("File names to leave out, separated by "
                                   "commas; * and ? are wildcards.")
        self.names_edit.textChanged.connect(self._edited)
        form.addRow("Leave out files named", self.names_edit)

        types = QWidget()
        grid = QGridLayout(types)
        grid.setContentsMargins(0, 0, 0, 0)
        grid.setHorizontalSpacing(16)
        self.type_boxes = {}
        for index, (key, (label, extensions)) in enumerate(
                TYPE_GROUPS.items()):
            box = QCheckBox(label)
            box.setToolTip(', '.join(extensions))
            box.toggled.connect(self._edited)
            grid.addWidget(box, index // 3, index % 3)
            self.type_boxes[key] = box
        form.addRow("Only file types", types)
        types_help = QLabel("None ticked: every type. Judged by the "
                            "name's extension; a program without one (as "
                            "on Linux) is not a type here.")
        types_help.setObjectName("scopeNote")
        types_help.setWordWrap(True)
        form.addRow("", types_help)

        sizes = QHBoxLayout()
        self.min_box, self.min_spin = self._size_pair("At least")
        self.max_box, self.max_spin = self._size_pair("At most")
        for widget in (self.min_box, self.min_spin, self.max_box,
                       self.max_spin):
            sizes.addWidget(widget)
        sizes.addStretch(1)
        form.addRow("Size", sizes)

        dates = QHBoxLayout()
        self.after_box, self.after_edit = self._date_pair("From")
        self.before_box, self.before_edit = self._date_pair("To")
        for widget in (self.after_box, self.after_edit, self.before_box,
                       self.before_edit):
            dates.addWidget(widget)
        dates.addStretch(1)
        form.addRow("Modified (UTC)", dates)

        self.deleted_combo = QComboBox()
        self.deleted_combo.setObjectName("scopeDeleted")
        for key, label in _DELETED:
            self.deleted_combo.addItem(label, key)
        self.deleted_combo.currentIndexChanged.connect(self._edited)
        form.addRow("Deleted files", self.deleted_combo)
        # Scrolling where the screen is short, never squeezed: Qt keeps a
        # dialog within the screen and overlapped the fields to fit.
        fields = QWidget()
        fields.setObjectName("scopeFields")
        fields.setLayout(form.grid)
        form.grid.setContentsMargins(0, 0, 8, 0)
        scroll = QScrollArea()
        scroll.setObjectName("scopeScroll")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setWidget(fields)
        layout.addWidget(scroll, 1)

        self.summary = QLabel()
        self.summary.setObjectName("scopeSummary")
        self.summary.setWordWrap(True)
        layout.addWidget(self.summary)
        # How many files that leaves, counted in a background process
        # (core/background.job_scope_count) a moment after each change.
        self.estimate = QLabel()
        self.estimate.setObjectName("scopeEstimate")
        self.estimate.setWordWrap(True)
        layout.addWidget(self.estimate)
        covered = QLabel(COVERED)
        covered.setObjectName("scopeNote")
        covered.setWordWrap(True)
        layout.addWidget(covered)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok
                                   | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self.set_scope(scope or Scope())
        screen = self.screen().availableGeometry().height()             if self.screen() is not None else 800
        self.resize(self.sizeHint().width(),
                    min(fields.sizeHint().height() + 260, int(screen * 0.9)))

    # --- building -----------------------------------------------------------

    def _with_browse(self, edit, title):
        """A rules box with a Browse button that ticks folders of the open
        evidence into it."""
        row = QHBoxLayout()
        row.setSpacing(6)
        row.addWidget(edit, 1)
        button = QPushButton("Browse…")
        button.setObjectName("scopeBrowse")
        button.setToolTip("Choose folders from the open evidence")
        icons.apply_to(button, icons.OPEN_FOLDER)
        opened = [e for e in self.evidence if e.get('handler') is not None]
        button.setEnabled(bool(opened))
        if not opened:
            button.setToolTip("Folders can be chosen once the evidence is "
                              "open; type rules here meanwhile.")
        button.clicked.connect(lambda _=False, e=edit, t=title:
                               self._browse(e, t))
        row.addWidget(button, 0, Qt.AlignTop)
        return row

    def _browse(self, edit, title):
        from trace_app.ui.dialogs.folder_picker import pick_folders
        opened = [e for e in self.evidence if e.get('handler') is not None]
        rules = pick_folders(opened, title, self)
        if not rules:
            return
        have = [line.strip() for line in edit.toPlainText().splitlines()
                if line.strip()]
        edit.setPlainText('\n'.join(have + [r for r in rules
                                             if r not in have]))

    def _rules_edit(self, placeholder):
        edit = QPlainTextEdit()
        edit.setObjectName("scopeRules")
        edit.setPlaceholderText(placeholder)
        edit.setTabChangesFocus(True)
        edit.setFixedHeight(edit.fontMetrics().lineSpacing() * 4 + 14)
        edit.textChanged.connect(self._edited)
        return edit

    def _size_pair(self, label):
        box = QCheckBox(label)
        spin = QSpinBox()
        spin.setRange(0, 1024 * 1024)
        spin.setSuffix(" MB")
        spin.setEnabled(False)
        box.toggled.connect(spin.setEnabled)
        box.toggled.connect(self._edited)
        spin.valueChanged.connect(self._edited)
        return box, spin

    def _date_pair(self, label):
        box = QCheckBox(label)
        edit = QDateEdit()
        edit.setObjectName("scopeDate")
        edit.setDisplayFormat("yyyy-MM-dd")
        edit.setCalendarPopup(True)
        edit.setDate(QDate.currentDate())
        date_fields.tidy_calendar(edit)
        edit.setEnabled(False)
        box.toggled.connect(edit.setEnabled)
        box.toggled.connect(self._edited)
        edit.dateChanged.connect(self._edited)
        return box, edit

    # --- the scope in and out ----------------------------------------------------

    def set_scope(self, scope):
        scope = Scope.from_dict(scope)
        self._loading = True
        try:
            index = self.preset_combo.findData(
                scope.preset if scope.preset in PRESETS else CUSTOM)
            self.preset_combo.setCurrentIndex(max(index, 0))
            self.include_edit.setPlainText('\n'.join(scope.include))
            self.exclude_edit.setPlainText('\n'.join(scope.exclude))
            self.names_edit.setText(', '.join(scope.exclude_names))
            for key, box in self.type_boxes.items():
                box.setChecked(key in scope.types)
            for box, spin, value in ((self.min_box, self.min_spin,
                                      scope.min_size),
                                     (self.max_box, self.max_spin,
                                      scope.max_size)):
                box.setChecked(bool(value))
                spin.setValue(int((value or 0) // _MB))
            for box, edit, value in ((self.after_box, self.after_edit,
                                      scope.modified_after),
                                     (self.before_box, self.before_edit,
                                      scope.modified_before)):
                box.setChecked(bool(value))
                if value:
                    edit.setDate(QDate.fromString(value[:10], 'yyyy-MM-dd'))
            self.deleted_combo.setCurrentIndex(max(0, self.deleted_combo
                                                   .findData(scope.deleted)))
        finally:
            self._loading = False
        self._show_preset_note()
        self._refresh_summary()

    def scope(self):
        """The Scope the fields describe."""
        def lines(edit):
            return [line.strip() for line in edit.toPlainText().splitlines()
                    if line.strip()]
        names = [n.strip() for n in self.names_edit.text().split(',')
                 if n.strip()]
        return Scope(
            preset=self.preset_combo.currentData() or CUSTOM,
            include=lines(self.include_edit),
            exclude=lines(self.exclude_edit), exclude_names=names,
            types=[k for k, box in self.type_boxes.items()
                   if box.isChecked()],
            min_size=self.min_spin.value() * _MB
            if self.min_box.isChecked() else None,
            max_size=self.max_spin.value() * _MB
            if self.max_box.isChecked() else None,
            modified_after=self.after_edit.date().toString('yyyy-MM-dd')
            if self.after_box.isChecked() else None,
            modified_before=self.before_edit.date().toString('yyyy-MM-dd')
            if self.before_box.isChecked() else None,
            deleted=self.deleted_combo.currentData())

    # --- reacting ------------------------------------------------------------------

    def _preset_chosen(self, _index):
        if self._loading:
            return
        key = self.preset_combo.currentData()
        if key in PRESETS:
            self.set_scope(Scope.preset_scope(key))
        self._show_preset_note()

    def _edited(self, *_args):
        if self._loading:
            return
        # Any change of a preset's rules makes it the examiner's own.
        current = self.scope()
        key = self.preset_combo.currentData()
        if key in PRESETS:
            base = Scope.preset_scope(key).to_dict()
            mine = current.to_dict()
            mine['preset'] = key
            if mine != base:
                self._loading = True
                self.preset_combo.setCurrentIndex(
                    self.preset_combo.findData(CUSTOM))
                self._loading = False
                self._show_preset_note()
        self._refresh_summary()

    def _show_preset_note(self):
        key = self.preset_combo.currentData()
        self.preset_note.setText(PRESETS[key][1] if key in PRESETS else
                                 "Your own rules.")

    def _refresh_summary(self):
        scope = self.scope()
        self.summary.setText(scope.describe(short=True))
        self.summary.setToolTip(scope.describe())
        if self.evidence:
            self._count_timer.start()       # counted once the edits pause
        else:
            self.estimate.setText(
                "Add evidence to see how many files this leaves.")

    # --- the estimate ------------------------------------------------------------

    def _count(self):
        if self._counter is not None:
            # A later scope wins: the running count is stopped, its result
            # dropped.
            try:
                self._counter.counted.disconnect()
            except (RuntimeError, TypeError):
                pass
            self._counter.stop()
        images = [{'path': e['path'], 'unlock': e.get('unlock') or {}}
                  for e in self.evidence]
        worker = _CountWorker({'images': images,
                               'scope': self.scope().to_dict()}, self)
        worker.counted.connect(self._counted)
        worker.progressed.connect(self._counting)
        worker.finished.connect(lambda w=worker: self._count_ended(w))
        self._counter = worker
        self.estimate.setText("Counting the files this leaves…")
        worker.start()

    def _counting(self, text):
        self.estimate.setText(f"Counting the files this leaves… ({text}; "
                              f"the first count of an image lists it once)")

    def _counted(self, kept, total, error):
        if error and not total:
            self.estimate.setText(f"Could not count the files: {error}")
            return
        share = f" ({kept * 100 / total:.1f}%)" if total else ''
        self.estimate.setText(
            f"In scope: {kept:,} of {total:,} files{share}"
            + (" -- free space and file slack are not searched"
               if not self.scope().covers_free_space else ''))

    def _count_ended(self, worker):
        if self._counter is worker:
            self._counter = None
        worker.deleteLater()

    def done(self, result):
        # A count still running is stopped, not left behind the dialog.
        self._count_timer.stop()
        if self._counter is not None:
            try:
                self._counter.counted.disconnect()
            except (RuntimeError, TypeError):
                pass
            self._counter.stop()
            self._counter.wait(3000)
        super().done(result)


def edit_scope(scope=None, parent=None, evidence=None):
    """Ask; the edited Scope, or None when cancelled. `evidence` as
    ScopeEditor takes it."""
    dialog = ScopeEditor(scope, parent, evidence)
    if dialog.exec() == QDialog.Accepted:
        return dialog.scope()
    return None

